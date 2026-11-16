//! Real x86-64 terminal exception stubs, not host-generated fault reports.
//! Each stub normalizes a hardware error-code/no-error frame to:
//!   [vector, error, RIP, CS, RFLAGS, optional old RSP, optional old SS]
//! The last two are only valid when the CPU actually switched privilege/stack;
//! the reporter must not assume they exist on a same-CPL non-IST exception.
//! These stubs NEVER return to user or kernel code. They are preparatory K2,
//! not isolated-process fault containment or safe iretq/SYSCALL entry.

use core::{
    arch::{asm, global_asm},
    ptr::{addr_of, addr_of_mut},
    sync::atomic::{AtomicBool, Ordering},
};

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TerminalTrapHead {
    pub vector: u64,
    pub error: u64,
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
}

pub type TrapReporter = extern "C" fn(*const TerminalTrapHead) -> !;

// Initialized once before installing the IDT. Read only on the boot CPU's
// terminal trap path; callbacks cannot safely return or use a reclaimed stack.
static mut REPORTER: Option<TrapReporter> = None;
static REPORTER_PRESENT: AtomicBool = AtomicBool::new(false);

/// # Safety
/// Called once at boot with IRQs disabled before IDT gates become accessible.
/// Callback must be executable, pinned, and non-returning, must not assume
/// dynamic allocation or an intact framebuffer, and must handle nested faults.
pub unsafe fn install_terminal_reporter(reporter: TrapReporter) -> bool {
    if REPORTER_PRESENT.swap(true, Ordering::AcqRel) { return false; }
    unsafe { addr_of_mut!(REPORTER).write(Some(reporter)); }
    true
}

#[inline(never)]
extern "C" fn terminal_report(frame: *const TerminalTrapHead) -> ! {
    let reporter = unsafe { addr_of!(REPORTER).read() };
    if let Some(f) = reporter {
        f(frame);
    }
    halt_forever()
}

fn halt_forever() -> ! {
    loop {
        unsafe {
            asm!("cli; hlt", options(nomem, nostack));
        }
    }
}

global_asm!(
    r#"
    .section .text.fortress_k2_traps,"ax"
    .global fortress_k2_ud_stub
fortress_k2_ud_stub:
    push 0
    push 6
    jmp fortress_k2_common_stub

    .global fortress_k2_gp_stub
fortress_k2_gp_stub:
    push 13
    jmp fortress_k2_common_stub

    .global fortress_k2_pf_stub
fortress_k2_pf_stub:
    push 14
    jmp fortress_k2_common_stub

    .global fortress_k2_df_stub
fortress_k2_df_stub:
    push 8
    jmp fortress_k2_common_stub

fortress_k2_common_stub:
    cld
    mov rdi, rsp
    and rsp, -16
    call {report}
1:
    cli
    hlt
    jmp 1b
    "#,
    report = sym terminal_report,
);

extern "C" {
    fn fortress_k2_ud_stub();
    fn fortress_k2_gp_stub();
    fn fortress_k2_pf_stub();
    fn fortress_k2_df_stub();
}

/// Returns a real assembly stub address for the four initial K2 exceptions.
/// The caller installs the gate with an interrupt gate and DF on IST1.
/// #GP/#PF/#DF already have a hardware error code; #UD pushes synthetic 0.
/// No user-mode recovery, APIC EOI, scheduler dispatch or TLB flush is done.
pub fn terminal_stub_address(vector: u8) -> Option<u64> {
    match vector {
        6 => Some(fortress_k2_ud_stub as usize as u64),
        8 => Some(fortress_k2_df_stub as usize as u64),
        13 => Some(fortress_k2_gp_stub as usize as u64),
        14 => Some(fortress_k2_pf_stub as usize as u64),
        _ => None,
    }
}

/// Actual CR2, only meaningful when observing a real #PF on the CPU.
/// # Safety
/// Kernel CPL0 and valid exception context required. The value is per-CPU,
/// and may change during nested page faults; capture promptly before logging.
pub unsafe fn read_cr2() -> u64 {
    let cr2: u64;
    unsafe {
        asm!("mov {}, cr2", out(reg) cr2, options(nostack, nomem, preserves_flags));
    }
    cr2
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_frame_prefix_is_five_qwords() {
        assert_eq!(core::mem::size_of::<TerminalTrapHead>(), 40);
        assert_eq!(core::mem::align_of::<TerminalTrapHead>(), 8);
    }

    #[test]
    fn only_explicitly_supported_real_trap_stubs_are_exported() {
        for vector in [6, 8, 13, 14] {
            assert!(terminal_stub_address(vector).is_some());
        }
        for vector in [0, 2, 7, 10, 17, 32] {
            assert!(terminal_stub_address(vector).is_none());
        }
    }
}
