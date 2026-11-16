//! Single-vCPU QEMU descriptor installation and real terminal #UD check.

use core::{arch::global_asm, ptr::addr_of};
use fortress_arch_x86_entry::{
    install_boot_cpu, snapshot_cpu,
    traps::{install_terminal_reporter, terminal_stub_address, TerminalTrapHead},
    TrapTargets, KERNEL_CS, KERNEL_DS, TSS_SELECTOR,
};

const RSP0_BYTES: usize = 16 * 1024;

#[repr(align(16))]
struct Rsp0Stack([u8; RSP0_BYTES]);

static mut RSP0_STACK: Rsp0Stack = Rsp0Stack([0; RSP0_BYTES]);

global_asm!(
    r#"
    .section .text.fortress_k2_fixture,"ax"
    .global fortress_k2_fixture_ud
fortress_k2_fixture_ud:
    ud2

    .global fortress_k2_external_fallback
fortress_k2_external_fallback:
    cld
    and rsp, -16
    call {unexpected}
1:
    cli
    hlt
    jmp 1b
    "#,
    unexpected = sym unexpected_interrupt,
);

extern "C" {
    fn fortress_k2_fixture_ud() -> !;
    fn fortress_k2_external_fallback();
}

extern "C" fn unexpected_interrupt() -> ! {
    crate::fatal("K2_UNEXPECTED_INTERRUPT")
}

extern "C" fn report(frame: *const TerminalTrapHead) -> ! {
    // SAFETY: ARCH passes the normalized prefix of the live trap stack.
    let frame = unsafe { frame.read() };
    if frame.vector != 6
        || frame.error != 0
        || frame.cs != u64::from(KERNEL_CS)
        || frame.rip != fortress_k2_fixture_ud as usize as u64
    {
        crate::fatal("K2_UNEXPECTED_TRAP");
    }
    crate::serial::log(format_args!(
        "FORTRESS_K2_FAULT vector={} error={} cpl={}\n",
        frame.vector, frame.error, frame.cs & 3,
    ));
    crate::fortress_g1_debug_exit(0x11);
    crate::halt()
}

pub fn exercise_ud() -> ! {
    let mut exceptions = [0; 32];
    for (address, handler) in exceptions.iter_mut().zip(crate::exceptions::handler_addresses()) {
        *address = handler;
    }
    for vector in [6, 8, 13, 14] {
        exceptions[usize::from(vector)] =
            terminal_stub_address(vector).unwrap_or_else(|| crate::fatal("K2_MISSING_STUB"));
    }
    let targets = TrapTargets {
        exceptions,
        external_fallback: fortress_k2_external_fallback as usize as u64,
    };

    // SAFETY: this fixture is entered once at CPL0 with IRQs disabled, a
    // mapped boot stack and the early non-IST IDT. The static RSP0 stack
    // stays mapped, separate from the boot and IST stacks.
    let (before, after) = unsafe {
        let rsp0_base = addr_of!(RSP0_STACK.0) as u64;
        let rsp0 = rsp0_base + RSP0_BYTES as u64;
        let before = snapshot_cpu();
        if !install_terminal_reporter(report) {
            crate::fatal("K2_REPORTER_ALREADY_INSTALLED");
        }
        if install_boot_cpu(rsp0, targets).is_err() {
            crate::fatal("K2_INSTALL_FAILED");
        }
        (before, snapshot_cpu())
    };

    if !after.owned_tables
        || before.owned_tables
        || before.idt_base == after.idt_base
        || before.cr3 != after.cr3
        || after.cs != KERNEL_CS
        || after.ss != KERNEL_DS
        || after.tr != TSS_SELECTOR
        || after.gdtr_limit != 71
        || after.idtr_limit != 4095
    {
        crate::fatal("K2_DESCRIPTOR_READBACK_FAILED");
    }

    crate::serial::log(format_args!(
        "FORTRESS_K2_CPU_OK cs={} ss={} tr={} gdtr_limit={} idtr_limit={}\n",
        after.cs, after.ss, after.tr, after.gdtr_limit, after.idtr_limit
    ));

    // SAFETY: the label executes UD2, and the installed handler terminates.
    unsafe { fortress_k2_fixture_ud() }
}
