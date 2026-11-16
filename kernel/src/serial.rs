//! COM1 (0x3f8) polling console. QEMU: -serial stdio.
use core::arch::asm;
use core::fmt::{self, Write};

const COM1: u16 = 0x3f8;

#[cfg(feature = "g1-fixture-console")]
use core::sync::atomic::{AtomicBool, Ordering};
#[cfg(feature = "g1-fixture-console")]
static RX_FAULT: AtomicBool = AtomicBool::new(false);

fn line_status() -> u8 {
    let status = unsafe { input(COM1 + 5) };
    // Reading the 16550 LSR may clear sticky RX errors even during TX.
    // Latch them until the line editor can poison the affected input line.
    #[cfg(feature = "g1-fixture-console")]
    if status & 0x9e != 0 {
        RX_FAULT.store(true, Ordering::Relaxed);
    }
    status
}

#[cfg(feature = "g1-fixture-console")]
pub enum Receive { Empty, Byte(u8), Fault, Unavailable }

#[cfg(feature = "g1-fixture-console")]
pub fn clear_receive() {
    // Clear pre-prompt bytes without resetting transmit.
    unsafe { out(COM1 + 2, 0x03); }
    RX_FAULT.store(false, Ordering::Relaxed);
}

#[cfg(feature = "g1-fixture-console")]
pub fn receive() -> Receive {
    let status = line_status();
    if status == 0xff { return Receive::Unavailable; }
    if RX_FAULT.load(Ordering::Relaxed) {
        // An overrun or FIFO summary can refer to a later byte. Flush the
        // queue so an earlier queued newline cannot clear parser poison first.
        clear_receive();
        return Receive::Fault;
    }
    if status & 1 == 0 { return Receive::Empty; }
    Receive::Byte(unsafe { input(COM1) })
}

unsafe fn out(port: u16, value: u8) {
    unsafe { asm!("out dx, al", in("dx") port, in("al") value, options(nomem, nostack, preserves_flags)); }
}
unsafe fn input(port: u16) -> u8 {
    let v: u8;
    unsafe { asm!("in al, dx", in("dx") port, out("al") v, options(nomem, nostack, preserves_flags)); }
    v
}
pub fn init() {
    unsafe {
        out(COM1 + 1, 0x00); // disable interrupts
        out(COM1 + 3, 0x80); // DLAB
        out(COM1, 0x01);     // 115200 baud divisor
        out(COM1 + 1, 0x00);
        out(COM1 + 3, 0x03); // 8N1
        out(COM1 + 2, 0x07); // FIFO enabled, clear RX/TX
        out(COM1 + 4, 0x03); // DTR + RTS; no UART IRQ
    }
}
pub struct Console;
impl Write for Console {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        for byte in text.bytes() {
            if byte == b'\n' { self.byte(b'\r'); }
            self.byte(byte);
        }
        Ok(())
    }
}
impl Console {
    fn byte(&mut self, v: u8) {
        // Bound the spin so a missing UART cannot deadlock early panic.
        for _ in 0..100_000 {
            let status = line_status();
            if status == 0xff { return; }
            if status & 0x20 != 0 {
                unsafe { out(COM1, v); }
                return;
            }
            core::hint::spin_loop();
        }
    }
}
pub fn line(s: &str) {
    let _ = writeln!(Console, "{s}");
}
pub fn log(args: fmt::Arguments<'_>) {
    let _ = Console.write_fmt(args);
}
