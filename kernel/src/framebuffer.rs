//! Optional tiny diagnostics. NEVER calls UEFI/GOP services.
use fortress_boot_kernel::bootinfo::{self, FramebufferInfo};
use core::ptr;

/// # Safety
/// Caller validated the mapped framebuffer, physical memory type, geometry,
/// and retains the Limine-provided HHDM page tables throughout this call.
pub unsafe fn paint_signature(fb: &FramebufferInfo) {
    if bootinfo::framebuffer_len(fb).is_err() { return; }
    // Write a small horizontal banner, not the whole screen.
    let width = fb.width.min(128);
    let height = fb.height.min(12);
    let rgb = (0xa0u32 << fb.red_shift) |
              (0xd0u32 << fb.green_shift) |
              (0xf0u32 << fb.blue_shift);
    for y in 0..height {
        for x in 0..width {
            let offset = y * fb.pitch + x * 4; // checked by framebuffer_len
            let addr = fb.virtual_base + offset; // checked by BootInfo validation
            unsafe { ptr::write_volatile(addr as *mut u32, rgb); }
        }
    }
}
