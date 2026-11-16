#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]
//! x86-64 privileged ONE-CPU GDT/TSS/IDT installer for the K2 kernel gate.
//! This code executes LGDT, LTR, LIDT and a far return to reload CS.
//! NOT linked to the boot kernel yet. Trap assembly and ring3 still require
//! review, integration and exact-source QEMU guest evidence.
#[cfg(not(target_arch = "x86_64"))]
compile_error!("x86_64 only");

pub mod traps;

use core::arch::asm;
use core::mem::size_of;
use core::ptr::{addr_of, addr_of_mut};
use core::sync::atomic::{AtomicU8, Ordering};

pub const KERNEL_CS: u16 = 0x08;
pub const KERNEL_DS: u16 = 0x10;
pub const USER_DS: u16 = 0x1b;
pub const USER_CS: u16 = 0x23;
pub const TSS_SELECTOR: u16 = 0x38;
pub const DF_IST: u8 = 1;
const DF_STACK_BYTES: usize = 16 * 1024;
const GDT_LEN: usize = 9;
const IDT_LEN: usize = 256;

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct DescriptorPointer { limit: u16, base: u64 }
impl DescriptorPointer {
    fn new(base: u64, bytes: usize) -> Self {
        Self { limit: (bytes - 1) as u16, base }
    }
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct Tss {
    reserved0: u32,
    rsp: [u64; 3],
    reserved1: u64,
    ist: [u64; 7],
    reserved2: u64,
    reserved3: u16,
    io_bitmap_base: u16,
}
impl Tss {
    const fn new(rsp0: u64, df_top: u64, nmi: u64, mc: u64) -> Self {
        Self {
            reserved0: 0, rsp: [rsp0, 0, 0], reserved1: 0,
            ist: [df_top, nmi, mc, 0, 0, 0, 0],
            reserved2: 0, reserved3: 0,
            io_bitmap_base: size_of::<Self>() as u16,
        }
    }
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct IdtGate {
    low: u16, selector: u16, ist: u8, attrs: u8,
    mid: u16, high: u32, zero: u32,
}
impl IdtGate {
    const EMPTY: Self = Self {
        low: 0, selector: 0, ist: 0, attrs: 0,
        mid: 0, high: 0, zero: 0,
    };
    fn interrupt(handler: u64, ist: u8) -> Self {
        Self {
            low: handler as u16, selector: KERNEL_CS,
            ist, attrs: 0x8e, mid: (handler >> 16) as u16,
            high: (handler >> 32) as u32, zero: 0,
        }
    }
    #[cfg(test)]
    fn address(self) -> u64 {
        self.low as u64 | ((self.mid as u64) << 16) | ((self.high as u64) << 32)
    }
}

#[repr(align(16))]
struct EmergencyStack([u8; DF_STACK_BYTES]);

#[repr(C, align(16))]
struct Tables {
    gdt: [u64; GDT_LEN],
    tss: Tss,
    idt: [IdtGate; IDT_LEN],
    df_stack: EmergencyStack,
}
impl Tables {
    const EMPTY: Self = Self {
        gdt: [0; GDT_LEN], tss: Tss::new(0, 0, 0, 0),
        idt: [IdtGate::EMPTY; IDT_LEN],
        df_stack: EmergencyStack([0; DF_STACK_BYTES]),
    };
}
// All tables must remain mapped for their entire live CPU lifetime.
// Caller guarantees one core, no reentrant initialization or concurrent RSP0.
static mut TABLES: Tables = Tables::EMPTY;
// 0 fresh, 1 installing/failed closed, 2 installed.
static STATE: AtomicU8 = AtomicU8::new(0);

const _: () = assert!(size_of::<Tss>() == 104);
const _: () = assert!(size_of::<IdtGate>() == 16);
const _: () = assert!(size_of::<DescriptorPointer>() == 10);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EntryError {
    WrongCpl, InterruptsEnabled, InvalidStack, InvalidHandler,
    NonCanonical, Overflow, AlreadyStarted,
}

/// Every address MUST denote a correct x86 interrupt entry stub, not a normal
/// C/Rust function. Error-code vectors (8,10-14,17,21,29,30) have different
/// hardware stack shapes from no-error vectors. These pointers do not confer
/// capability or prove that handler assembly is correct.
/// All vectors 32..255 route to external_fallback while IF stays disabled.
#[derive(Clone, Copy)]
pub struct TrapTargets {
    pub exceptions: [u64; 32],
    pub external_fallback: u64,
}
impl TrapTargets {
    fn check(self, width: u8) -> Result<(), EntryError> {
        for address in self.exceptions.into_iter().chain([self.external_fallback]) {
            if address == 0 || !canonical(address, width) {
                return Err(EntryError::InvalidHandler);
            }
        }
        Ok(())
    }
}

fn canonical(address: u64, width: u8) -> bool {
    let hi = address >> width;
    let sign = (address >> (width - 1)) & 1;
    hi == if sign == 0 { 0 } else { u64::MAX >> width }
}

fn tss_descriptor(base: u64, limit: u32) -> (u64, u64) {
    let lo = (limit as u64 & 0xffff)
        | ((base & 0xffff) << 16)
        | ((base & 0xff0000) << 16)
        | (0x89u64 << 40)
        | (((limit as u64 >> 16) & 0xf) << 48)
        | (((base >> 24) & 0xff) << 56);
    (lo, base >> 32)
}

/// Actual hardware snapshot, only callable with CPL0 and a valid stack.
/// NOT a simulated trap frame. The caller must guarantee no concurrent CPU
/// setup and a live, mapped writable pointer for SIDT.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CpuSnapshot {
    pub cs: u16, pub ss: u16, pub tr: u16,
    pub rsp: u64, pub cr3: u64, pub idt_base: u64,
    pub gdtr_limit: u16, pub idtr_limit: u16, pub owned_tables: bool,
}

pub unsafe fn snapshot_cpu() -> CpuSnapshot {
    let (cs, ss, tr): (u16, u16, u16);
    let (rsp, cr3): (u64, u64);
    let mut gdtr = DescriptorPointer::new(0, 1);
    let mut idtr = DescriptorPointer::new(0, 1);
    unsafe {
        asm!("mov {0:x}, cs", out(reg) cs, options(nomem, nostack, preserves_flags));
        asm!("mov {0:x}, ss", out(reg) ss, options(nomem, nostack, preserves_flags));
        asm!("str {0:x}", out(reg) tr, options(nomem, nostack, preserves_flags));
        asm!("mov {}, rsp", out(reg) rsp, options(nomem, nostack, preserves_flags));
        asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags));
        asm!("sgdt [{ptr}]", ptr = in(reg) &mut gdtr, options(nostack, preserves_flags));
        asm!("sidt [{ptr}]", ptr = in(reg) &mut idtr, options(nostack, preserves_flags));
    }
    let owned_tables = gdtr.base == unsafe { addr_of!(TABLES.gdt) as u64 }
        && idtr.base == unsafe { addr_of!(TABLES.idt) as u64 }
        && usize::from(gdtr.limit) + 1 == size_of::<[u64; GDT_LEN]>()
        && usize::from(idtr.limit) + 1 == size_of::<[IdtGate; IDT_LEN]>()
        && tr == TSS_SELECTOR && is_installed();
    CpuSnapshot { cs, ss, tr, rsp, cr3, idt_base: idtr.base,
        gdtr_limit: gdtr.limit, idtr_limit: idtr.limit, owned_tables }
}

/// Replace boot-CPU descriptors, leave interrupts OFF, and assign IST1 to #DF.
/// No ring3 transition, real trapframe translation, syscall, or IPI is supplied.
/// All kernel/stack/handler memory must be owned, supervisor-mapped and pinned.
///
/// # Safety
/// Called once at CPL0 in long mode and IF=0, on one CPU, with a mapped kernel
/// stack and no concurrent IDT/GDT users. rsp0 is a 16-byte-aligned, mapped,
/// supervisor-only kernel stack, alive for the TSS lifetime. Each trap target
/// is reviewed executable assembly with correct hardware error-code, privilege,
/// stack switch, nested exception and IRETQ/fatal conventions. The caller
/// must keep static BSS writable/mapped, avoid Limine reclaim and validate the
/// CPU entry state with the BOOT/MEMORY/PROCESS owners. No physical PC testing.
pub unsafe fn install_boot_cpu(rsp0: u64, traps: TrapTargets) -> Result<(), EntryError> {
    unsafe { install_cpu(rsp0, traps, None) }
}

#[derive(Clone, Copy)]
pub struct UserEntry {
    pub user_gate: u64, pub df: u64, pub nmi: u64, pub mc: u64,
}

/// # Safety
/// As for install_boot_cpu. All IST stacks must be distinct, guarded, pinned
/// and supervisor mapped in every root. NMI, #DF and #MC are terminal paths.
pub unsafe fn install_user_cpu(
    rsp0: u64, traps: TrapTargets, user: UserEntry,
) -> Result<(), EntryError> {
    unsafe { install_cpu(rsp0, traps, Some(user)) }
}

unsafe fn install_cpu(
    rsp0: u64, traps: TrapTargets, user: Option<UserEntry>,
) -> Result<(), EntryError> {
    let (cs, rflags, cr4): (u16, u64, u64);
    unsafe {
        asm!("mov {0:x}, cs", out(reg) cs, options(nomem, nostack, preserves_flags));
        asm!("pushfq; pop {}", out(reg) rflags, options(preserves_flags));
        asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
    }
    if cs & 3 != 0 { return Err(EntryError::WrongCpl); }
    if rflags & (1 << 9) != 0 { return Err(EntryError::InterruptsEnabled); }
    let width = if cr4 & (1 << 12) != 0 { 57 } else { 48 };
    if rsp0 == 0 || rsp0 & 15 != 0 { return Err(EntryError::InvalidStack); }
    if !canonical(rsp0, width) { return Err(EntryError::NonCanonical); }
    traps.check(width)?;
    if cs != 0x28 && cs != KERNEL_CS { return Err(EntryError::InvalidHandler); }
    if let Some(u) = user {
        if u.user_gate == 0 || !canonical(u.user_gate, width) {
            return Err(EntryError::InvalidHandler);
        }
        let stacks = [rsp0, u.df, u.nmi, u.mc];
        for (i, &sp) in stacks.iter().enumerate() {
            if sp >> 63 == 0 || sp & 4095 != 0 || !canonical(sp, width)
                || stacks[..i].contains(&sp)
            { return Err(EntryError::InvalidStack); }
        }
    }

    let tables = addr_of_mut!(TABLES);
    // SAFETY: `tables` is the stable address of the kernel-owned static TABLES;
    // constructing the field pointer does not dereference its memory.
    let df_base = unsafe { addr_of!((*tables).df_stack) as u64 };
    let df_top = df_base.checked_add(DF_STACK_BYTES as u64).ok_or(EntryError::Overflow)?;
    if !canonical(df_base, width) || !canonical(df_top - 1, width) {
        return Err(EntryError::NonCanonical);
    }
    if STATE.compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire).is_err() {
        return Err(EntryError::AlreadyStarted);
    }
    let (tss_lo, tss_hi) = tss_descriptor(
        // SAFETY: project a field address from the static TABLES raw pointer.
        unsafe { addr_of!((*tables).tss) as u64 },
        (size_of::<Tss>() - 1) as u32,
    );
    unsafe {
        addr_of_mut!((*tables).gdt).write([
            0,
            0x00af_9a00_0000_ffff, // kernel long code, 0x08
            0x00cf_9200_0000_ffff, // kernel data, 0x10
            0x00cf_f200_0000_ffff, // user data,   0x18|3
            0x00af_fa00_0000_ffff, // user long code, 0x20|3
            0x00af_9a00_0000_ffff, // preserve Limine CS until LIDT
            0x00cf_9200_0000_ffff, // preserve Limine SS until LIDT
            tss_lo, tss_hi,        // TSS, 0x38
        ]);
        let (df, nmi, mc) = user.map_or((df_top, 0, 0), |u| (u.df, u.nmi, u.mc));
        addr_of_mut!((*tables).tss).write(Tss::new(rsp0, df, nmi, mc));
    }
    for vector in 0..IDT_LEN {
        let soft = user.filter(|_| vector == 128);
        let target = if let Some(u) = soft {
            u.user_gate
        } else if vector < 32 {
            traps.exceptions[vector]
        } else {
            traps.external_fallback
        };
        let ist = match vector {
            8 => DF_IST,
            2 if user.is_some() => 2,
            18 if user.is_some() => 3,
            _ => 0,
        };
        let mut gate = IdtGate::interrupt(target, ist);
        if soft.is_some() { gate.attrs = 0xee; }
        unsafe {
            addr_of_mut!((*tables).idt)
                .cast::<IdtGate>()
                .add(vector)
                .write(gate);
        }
    }
    let gdtr = DescriptorPointer::new(
        // SAFETY: project a field address from the static TABLES raw pointer.
        unsafe { addr_of!((*tables).gdt) as u64 },
        size_of::<[u64; GDT_LEN]>(),
    );
    let idtr = DescriptorPointer::new(
        // SAFETY: project a field address from the static TABLES raw pointer.
        unsafe { addr_of!((*tables).idt) as u64 },
        size_of::<[IdtGate; IDT_LEN]>(),
    );
    // The only privileged state mutation. Do not call with live IRQs or
    // without correctly mapped TSS/IDT and caller-supplied assembly stubs.
    unsafe {
        asm!(
            "lgdt [{gdt}]",
            "mov ax, 0x10",
            "mov ds, ax",
            "mov es, ax",
            "mov ss, ax",
            "push 0x08",
            "lea rax, [rip + 2f]",
            "push rax",
            "retfq",
            "2:",
            gdt = in(reg) &gdtr,
            out("rax") _,
        );
        asm!("ltr ax", in("ax") TSS_SELECTOR, options(nostack, preserves_flags));
        asm!("lidt [{idt}]", idt = in(reg) &idtr, options(nostack, preserves_flags));
    }
    STATE.store(2, Ordering::Release);
    Ok(())
}

/// Update RSP0 at a reviewed process switch. Does not itself switch CR3 or
/// prevent a concurrent user trap. Only valid with IF=0 and one CPU.
///
/// # Safety
/// Caller must guarantee no live privilege transition is consuming the old
/// RSP0, the replacement stack is supervisor-owned/pinned, and the operation
/// is serialized with ARCH+PROCESS scheduling. Not SMP-safe.
pub unsafe fn update_rsp0(rsp0: u64) -> Result<(), EntryError> {
    if STATE.load(Ordering::Acquire) != 2 { return Err(EntryError::AlreadyStarted); }
    let (cr4, rflags): (u64, u64);
    unsafe {
        asm!("pushfq; pop {}", out(reg) rflags, options(preserves_flags));
        asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
    }
    if rflags & (1 << 9) != 0 { return Err(EntryError::InterruptsEnabled); }
    let width = if cr4 & (1 << 12) != 0 { 57 } else { 48 };
    if rsp0 == 0 || rsp0 & 15 != 0 { return Err(EntryError::InvalidStack); }
    if !canonical(rsp0, width) { return Err(EntryError::NonCanonical); }
    // SAFETY: only the boot CPU mutates its live TSS while IF=0;
    // no references to the mutable static are constructed.
    let pointer = unsafe { addr_of_mut!(TABLES.tss.rsp).cast::<u64>() };
    unsafe { pointer.write_unaligned(rsp0); }
    Ok(())
}

pub fn is_installed() -> bool { STATE.load(Ordering::Acquire) == 2 }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptor_layout_and_selectors() {
        assert_eq!(size_of::<Tss>(), 104);
        assert_eq!(size_of::<IdtGate>(), 16);
        assert_eq!(size_of::<DescriptorPointer>(), 10);
        assert_eq!(USER_CS & 3, 3);
        assert_eq!(USER_DS & 3, 3);
        assert_eq!(TSS_SELECTOR, 0x38);
    }

    #[test]
    fn tss_and_ist_stacks_are_distinct() {
        let tss = Tss::new(0x10000, 0x20000, 0, 0);
        let rsp0 = unsafe { addr_of!(tss.rsp).cast::<u64>().read_unaligned() };
        let ist1 = unsafe { addr_of!(tss.ist).cast::<u64>().read_unaligned() };
        let iomap = tss.io_bitmap_base;
        assert_eq!(rsp0, 0x10000);
        assert_eq!(ist1, 0x20000);
        assert_eq!(iomap, 104);
    }

    #[test]
    fn interrupt_gate_encodes_full_address_and_df_ist() {
        let gate = IdtGate::interrupt(0xffff_8000_1234_9876, DF_IST);
        assert_eq!(gate.address(), 0xffff_8000_1234_9876);
        let cs = gate.selector;
        let ist = gate.ist;
        let attrs = gate.attrs;
        assert_eq!((cs, ist, attrs), (KERNEL_CS, 1, 0x8e));
    }

    #[test]
    fn tss_descriptor_preserves_64bit_base_and_limit() {
        let base: u64 = 0xffff_8000_1234_5678;
        let (lo, hi) = tss_descriptor(base, 103);
        assert_eq!(lo & 0xffff, 103);
        assert_eq!((lo >> 40) & 0xff, 0x89);
        assert_eq!(hi, base >> 32);
    }

    #[test]
    fn rejects_bad_handler_or_wrong_canonical_width() {
        let good = TrapTargets {
            exceptions: [0xffff_8000_0000_1000; 32],
            external_fallback: 0xffff_8000_0000_3000,
        };
        assert!(good.check(48).is_ok());
        assert_eq!(TrapTargets { external_fallback: 0, ..good }.check(48),
                   Err(EntryError::InvalidHandler));
        assert!(!canonical(0x0000_8000_0000_0000, 48));
        assert!(canonical(0x0000_8000_0000_0000, 57));
    }
}
