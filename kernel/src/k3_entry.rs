//! Test-only single CPU gate. Only validated CPL3 frames can return.
use core::arch::{asm, global_asm};
use fortress_arch_x86_entry::{snapshot_cpu, USER_CS, USER_DS, KERNEL_CS, TSS_SELECTOR};

pub const INT: u64 = 128;
pub const DF: u64 = 1 << 10;
const DANGEROUS: u64 = (1 << 8) | (1 << 9) | DF | (1 << 14) | (1 << 18);

#[repr(C)]
pub struct Frame {
    pub r15: u64, pub r14: u64, pub r13: u64, pub r12: u64,
    pub r11: u64, pub r10: u64, pub r9: u64, pub r8: u64,
    pub rdi: u64, pub rsi: u64, pub rbp: u64, pub rbx: u64,
    pub rdx: u64, pub rcx: u64, pub rax: u64,
    pub vector: u64, pub error: u64,
    pub rip: u64, pub cs: u64, pub flags: u64, pub rsp: u64, pub ss: u64,
}
const _: () = assert!(core::mem::size_of::<Frame>() == 176);

#[derive(Clone, Copy)]
pub struct Active {
    pub cr3: u64,
    pub rsp0: u64,
    pub entry: u64,
    pub end: u64,
    pub user_rsp: u64,
}
pub struct Observed {
    pub vector: u64, pub error: u64, pub rip: u64, pub cs: u64, pub flags: u64,
    pub rsp: u64, pub ss: u64, pub rax: u64, pub cr2: u64, pub cr3: u64,
    pub live_flags: u64, pub rdi: u64, pub rsi: u64,
}
struct Context {
    active: Active,
    reply: Option<(u64, u64)>,
    trap: Option<Observed>,
    step: usize,
}
static mut CONTEXT: Option<Context> = None;

global_asm!(
    r#"
    .section .bss.k3_context,"aw",@nobits
    .balign 8
.Lk3_host_rsp: .zero 8
    .section .text.k3,"ax"
    .global fortress_k3_enter
fortress_k3_enter:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov [rip + .Lk3_host_rsp], rsp
    push {user_ds}
    push rsi
    push 2
    push {user_cs}
    push rdi
    mov rdi, rdx
    mov rsi, rcx
    xor eax, eax
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    xor ebx, ebx
    xor ecx, ecx
    xor edx, edx
    xor ebp, ebp
    xor r8d, r8d
    xor r9d, r9d
    xor r10d, r10d
    xor r11d, r11d
    xor r12d, r12d
    xor r13d, r13d
    xor r14d, r14d
    xor r15d, r15d
    iretq

    .global fortress_k3_ud
fortress_k3_ud:
    push 0
    push 6
    jmp .Lk3_normalized
    .global fortress_k3_pf
fortress_k3_pf:
    push 14
    jmp .Lk3_normalized
    .global fortress_k3_int
fortress_k3_int:
    push 0
    push 128
.Lk3_normalized:
    push rax
    push rcx
    push rdx
    push rbx
    push rbp
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    // Never let a nested CPL0 fault enter the Rust user trap handler.
    mov eax, dword ptr [rsp + 18 * 8]
    and eax, 3
    cmp eax, 3
    jne fortress_k3_terminal
    mov rdi, rsp
    mov rsi, cr2
    mov rdx, cr3
    pushfq
    and qword ptr [rsp], {clean_mask}
    popfq
    pushfq
    pop rcx
    and rsp, -16
    call {handle}
    test rax, rax
    jnz .Lk3_leave
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    pop rdx
    pop rcx
    pop rax
    add rsp, 16
    iretq

.Lk3_leave:
    mov rsp, [rip + .Lk3_host_rsp]
    mov qword ptr [rip + .Lk3_host_rsp], 0
    mov ax, {kernel_ds}
    mov ds, ax
    mov es, ax
    mov ss, ax
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

    // Terminal exception paths run on independent ISTs for NMI/DF/MC.
    // No Rust or shared logging state: emit the failure exit directly.
    .global fortress_k3_terminal
fortress_k3_terminal:
    mov dx, 0xf4
    mov al, 0x12
    out dx, al
1:  cli
    hlt
    jmp 1b
    "#,
    user_ds = const USER_DS,
    user_cs = const USER_CS,
    kernel_ds = const fortress_arch_x86_entry::KERNEL_DS,
    clean_mask = const !(DANGEROUS as i32),
    handle = sym handle,
);

extern "C" {
    fn fortress_k3_enter(entry: u64, rsp: u64, arg: u64, mode: u64);
    fn fortress_k3_ud();
    fn fortress_k3_pf();
    fn fortress_k3_int();
    fn fortress_k3_terminal();
}

fn fail(reason: &str) -> ! { super::k3::fail(reason) }

extern "C" fn handle(pointer: *mut Frame, cr2: u64, cr3: u64, live_flags: u64) -> usize {
    // No maskable interrupt or multi-CPU use. NMI/#DF/#MC never access CONTEXT.
    let ctx = unsafe { (&mut *core::ptr::addr_of_mut!(CONTEXT)).as_mut() }
        .unwrap_or_else(|| fail("TRAP_WITHOUT_ACTIVE_DOMAIN"));
    let a = ctx.active;
    if pointer as u64 != a.rsp0 - core::mem::size_of::<Frame>() as u64 {
        fail("TRAP_WRONG_RSP0");
    }
    let f = unsafe { &mut *pointer };
    // RF is set by hardware in the saved flags on faults. Only ordinary
    // arithmetic flags, fixed 1, DF and RF are accepted in this fixture.
    if cr3 != a.cr3 || f.cs != USER_CS as u64 || f.ss != USER_DS as u64
        || !(a.entry..a.end).contains(&f.rip) || f.rsp != a.user_rsp
        || f.flags & 2 == 0 || f.flags & !0x1_0cd7 != 0 || live_flags & DANGEROUS != 0
    {
        fail("BAD_TRAP_FRAME");
    }
    let observed = Observed { vector: f.vector, error: f.error, rip: f.rip,
        cs: f.cs, flags: f.flags, rsp: f.rsp, ss: f.ss, rax: f.rax, cr2, cr3, live_flags, rdi: f.rdi, rsi: f.rsi };
    if f.vector == INT && ctx.step == 0 {
        if let Some((request, reply)) = ctx.reply {
            if f.error != 0 || f.rax != request || f.flags & DF == 0 {
                fail("BAD_RETURN_HANDSHAKE");
            }
            super::k3::log_b(1, &observed);
            ctx.step = 1;
            f.rax = reply;
            f.flags = 2;
            // For the accepted user frame the pointer is already 16-byte
            // aligned (176 bytes from a 16-byte-aligned RSP0).
            return 0;
        }
    }
    ctx.trap = Some(observed);
    1
}

/// # Safety
/// Matches the live CR3 and programmed RSP0, both fully prepared before entry.
pub unsafe fn run(active: Active, arg: u64, mode: u64, reply: Option<(u64, u64)>) -> Observed {
    let slot = core::ptr::addr_of_mut!(CONTEXT);
    if unsafe { (&*slot).is_some() } { fail("REENTRANT_DOMAIN"); }
    unsafe {
        slot.write(Some(Context { active, reply, trap: None, step: 0 }));
        fortress_k3_enter(active.entry, active.user_rsp, arg, mode);
        let ctx = slot.replace(None).unwrap_or_else(|| fail("LOST_CONTEXT"));
        if ctx.reply.is_some() && ctx.step != 1 { fail("DID_NOT_RETURN_TO_USER"); }
        ctx.trap.unwrap_or_else(|| fail("MISSING_TRAP"))
    }
}

pub fn install(rsp0: u64, df: u64, nmi: u64, mc: u64) {
    let terminal = fortress_k3_terminal as usize as u64;
    let mut exceptions = [terminal; 32];
    exceptions[6] = fortress_k3_ud as usize as u64;
    exceptions[14] = fortress_k3_pf as usize as u64;
    let options = fortress_arch_x86_entry::UserEntry {
        user_gate: fortress_k3_int as usize as u64, df, nmi, mc,
    };
    unsafe {
        let before = snapshot_cpu();
        fortress_arch_x86_entry::install_user_cpu(rsp0, fortress_arch_x86_entry::TrapTargets {
            exceptions, external_fallback: terminal,
        }, options).unwrap_or_else(|_| fail("DESCRIPTOR_INSTALL"));
        let after = snapshot_cpu();
        if !after.owned_tables || before.owned_tables || after.cs != KERNEL_CS || after.tr != TSS_SELECTOR || after.idt_base == before.idt_base
            || before.cr3 != after.cr3
        { fail("DESCRIPTOR_READBACK"); }

        // No untrusted FP/SIMD access or inherited FS/GS bases in this
        // integer-only no_std fixture. All #NM and #GP are terminal.
        let mut cr0: u64;
        let mut cr4: u64;
        asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack, preserves_flags));
        asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
        cr0 |= (1 << 3) | (1 << 16); // TS + supervisor write protection
        cr4 &= !(1 << 16); // FSGSBASE
        asm!("mov cr0, {}", in(reg) cr0, options(nostack, preserves_flags));
        asm!("mov cr4, {}", in(reg) cr4, options(nostack, preserves_flags));
        let (efer_lo, efer_hi): (u32, u32);
        asm!("rdmsr", in("ecx") 0xc000_0080u32,
             out("eax") efer_lo, out("edx") efer_hi, options(nostack));
        asm!("wrmsr", in("ecx") 0xc000_0080u32,
             in("eax") efer_lo & !1, in("edx") efer_hi, options(nostack));
        for msr in [0x174u32, 0xc000_0100, 0xc000_0101, 0xc000_0102] {
            asm!("wrmsr", in("ecx") msr, in("eax") 0u32, in("edx") 0u32, options(nostack));
        }
    }
}
