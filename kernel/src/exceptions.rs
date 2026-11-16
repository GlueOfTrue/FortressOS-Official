//! Early terminal exception entry on the boot CPU.
//!
//! The IDT is kernel-owned. Its gates still refer to the loader's retained
//! 64-bit code selector and use the current kernel boot stack. There is no
//! TSS/IST yet, so a fault that prevents a stack push, including a double
//! fault caused by that failure, may prevent the diagnostic from running.
//! NMI and machine checks are terminal if the CPU can deliver them.

use core::{
    arch::{asm, global_asm},
    mem::size_of,
    ptr::addr_of_mut,
};

const EXCEPTION_COUNT: usize = 32;

global_asm!(
    r#"
    .section .text.early_exceptions,"ax"
.Lfortress_exception_common:
    cld
    and rsp, -16
    call {report}
1:
    cli
    hlt
    jmp 1b

    .section .rodata.early_exception_vectors,"a"
    .balign 4
    .global fortress_early_exception_vectors
fortress_early_exception_vectors:
    .macro exception vector, has_error=0
        .pushsection .text.early_exceptions,"ax"
    .Lfortress_exception_\vector:
        mov edi, \vector
        .if \has_error
            mov esi, dword ptr [rsp]
        .else
            xor esi, esi
        .endif
        jmp .Lfortress_exception_common
        .popsection
        .long .Lfortress_exception_\vector - fortress_early_exception_vectors
    .endm

    exception 0
    exception 1
    exception 2
    exception 3
    exception 4
    exception 5
    exception 6
    exception 7
    exception 8, 1
    exception 9
    exception 10, 1
    exception 11, 1
    exception 12, 1
    exception 13, 1
    exception 14, 1
    exception 15
    exception 16
    exception 17, 1
    exception 18
    exception 19
    exception 20
    exception 21, 1
    exception 22
    exception 23
    exception 24
    exception 25
    exception 26
    exception 27
    exception 28
    exception 29, 1
    exception 30, 1
    exception 31
    "#,
    report = sym crate::cpu_fault,
);

#[derive(Clone, Copy)]
#[repr(C, align(16))]
struct InterruptGate {
    offset_low: u16,
    selector: u16,
    attributes: u16,
    offset_mid: u16,
    offset_high: u32,
    reserved: u32,
}

impl InterruptGate {
    const EMPTY: Self = Self {
        offset_low: 0,
        selector: 0,
        attributes: 0,
        offset_mid: 0,
        offset_high: 0,
        reserved: 0,
    };

    fn new(handler: usize, selector: u16) -> Self {
        Self {
            offset_low: handler as u16,
            selector,
            attributes: 0x8e00, // present, DPL 0, interrupt gate, IST 0
            offset_mid: (handler >> 16) as u16,
            offset_high: (handler >> 32) as u32,
            reserved: 0,
        }
    }
}

#[repr(C, packed)]
struct IdtPointer {
    limit: u16,
    base: u64,
}

const _: () = assert!(size_of::<InterruptGate>() == 16);
const _: () = assert!(size_of::<IdtPointer>() == 10);

static mut IDT: [InterruptGate; EXCEPTION_COUNT] = [InterruptGate::EMPTY; EXCEPTION_COUNT];

extern "C" {
    static fortress_early_exception_vectors: [i32; EXCEPTION_COUNT];
}

/// Install the early, terminal exception handlers.
///
/// # Safety
///
/// Call once on the boot CPU at CPL 0 with interrupts disabled, a mapped
/// stack and a valid 64-bit code descriptor for the current CS. Keep that
/// GDT and the IDT mapped while these gates are active. Maskable interrupts
/// must stay disabled. Do not synthesize an error-code exception with INT.
pub unsafe fn install() {
    let selector: u16;
    unsafe {
        asm!(
            "mov {selector:x}, cs",
            selector = out(reg) selector,
            options(nomem, nostack, preserves_flags),
        );
    }

    let gates = addr_of_mut!(IDT).cast::<InterruptGate>();
    // Hardware exceptions that push an error code enter the matching stub
    // above. That stub reads the error slot before realigning RSP for SysV.
    for (index, handler) in handler_addresses().enumerate() {
        unsafe { gates.add(index).write(InterruptGate::new(handler as usize, selector)) };
    }
    let pointer = IdtPointer {
        limit: (size_of::<[InterruptGate; EXCEPTION_COUNT]>() - 1) as u16,
        base: gates as u64,
    };
    unsafe {
        asm!(
            "lidt [{pointer}]",
            pointer = in(reg) &pointer,
            options(nostack, preserves_flags),
        );
    }
}

pub(super) fn handler_addresses() -> impl Iterator<Item = u64> {
    // SAFETY: the assembly vector table contains exactly 32 read-only offsets
    // relative to its own base, all targeting its terminal entry stubs.
    let handlers = unsafe { &fortress_early_exception_vectors };
    let base = handlers.as_ptr() as usize;
    handlers.iter().map(move |&offset| base.wrapping_add_signed(offset as isize) as u64)
}
