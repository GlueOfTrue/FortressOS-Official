//! G0 diagnostic only: a freestanding UEFI application, NOT a kernel/bootloader.
//! Deliberately does NOT call ExitBootServices or define a BootInfo ABI.
#![no_std]
#![no_main]

use core::arch::asm;
use core::panic::PanicInfo;

const COM1: u16 = 0x3f8;
const QEMU_EXIT: u16 = 0xf4;
const SUCCESS: u32 = 0x10;
const FAILURE: u32 = 0x11;

#[inline]
unsafe fn outb(port: u16, value: u8) {
    // SAFETY: Privileged I/O in x86-64 UEFI boot context; QEMU-only fixture.
    unsafe {
        asm!("out dx, al", in("dx") port, in("al") value, options(nomem, nostack, preserves_flags));
    }
}

#[inline]
unsafe fn inb(port: u16) -> u8 {
    let value: u8;
    // SAFETY: Reading emulated 16550 COM1 status in privileged UEFI context.
    unsafe {
        asm!("in al, dx", out("al") value, in("dx") port, options(nomem, nostack, preserves_flags));
    }
    value
}

fn serial_init() {
    // SAFETY: QEMU emulates COM1 at 0x3f8; no hardware deployment supported.
    unsafe {
        outb(COM1 + 1, 0x00);
        outb(COM1 + 3, 0x80);
        outb(COM1, 0x01);
        outb(COM1 + 1, 0x00);
        outb(COM1 + 3, 0x03);
        outb(COM1 + 2, 0xc7);
        outb(COM1 + 4, 0x0b);
    }
}

fn serial_write(message: &str) {
    for byte in message.bytes() {
        // SAFETY: COM1 LSR/THR access in QEMU-only fixture.
        unsafe {
            for _ in 0..100_000 {
                if inb(COM1 + 5) & 0x20 != 0 {
                    break;
                }
                core::hint::spin_loop();
            }
            outb(COM1, byte);
        }
    }
}

fn exit_qemu(value: u32) -> ! {
    // SAFETY: The isa-debug-exit device is only attached to the QEMU guest;
    // never used for host/physical IO. QEMU process status = (value << 1) | 1.
    unsafe {
        asm!("out dx, eax", in("dx") QEMU_EXIT, in("eax") value, options(nomem, nostack, preserves_flags));
    }
    loop {
        core::hint::spin_loop();
    }
}

#[no_mangle]
pub extern "efiapi" fn efi_main(_image_handle: usize, _system_table: usize) -> usize {
    serial_init();
    serial_write("FORTRESSOS_G0_DIAG_V1 START\n");
    #[cfg(feature = "fault-probe")]
    {
        serial_write("FORTRESSOS_G0_DIAG_V1 BOOT_FAIL\n");
        exit_qemu(FAILURE);
    }
    #[cfg(not(feature = "fault-probe"))]
    {
        serial_write("FORTRESSOS_G0_DIAG_V1 BOOT_OK\n");
        exit_qemu(SUCCESS);
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    serial_init();
    serial_write("FORTRESSOS_G0_DIAG_V1 PANIC\n");
    exit_qemu(FAILURE)
}
