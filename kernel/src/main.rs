#![no_std]
#![no_main]
use core::{arch::{asm, global_asm}, fmt::Write, panic::PanicInfo, ptr};
use fortress_boot_kernel::bootinfo::{
    self, BootInfoV0, MemoryRegion, ModuleRegion, FramebufferInfo,
    FLAG_FRAMEBUFFER, FLAG_RSDP, MAX_REGIONS, MAX_MODULES,
};
mod limine;
mod serial;
mod framebuffer;
mod exceptions;
#[cfg(feature = "g1-fixture-k2-ud")]
mod k2;
#[cfg(feature = "g1-fixture-k1-real")]
mod k1_guest;
#[cfg(any(feature = "g1-fixture-k1-real", feature = "k3-fixture-runtime"))]
mod boot_memory;
#[cfg(feature = "k3-fixture-runtime")]
mod k3;
#[cfg(feature = "k3-fixture-runtime")]
mod k3_elf;
#[cfg(feature = "k3-fixture-runtime")]
mod k3_entry;
#[cfg(feature = "k3-fixture-runtime")]
mod k3_memory;
#[cfg(feature = "g1-fixture-k4")]
mod k4;

// Limine enters in long mode, CPL0, with paging on and IF=0. We supply
// our own 32-KiB 16-byte-aligned stack before calling a SysV Rust function.
global_asm!(r#"
    .section .text.boot,"ax"
    .global _start
_start:
    cli
    cld
    lea rsp, [rip + fortress_boot_stack_top]
    and rsp, -16
    call fortress_rust_entry
1:
    hlt
    jmp 1b
    .section .bss.bootstack,"aw",@nobits
    .balign 16
fortress_boot_stack_bottom:
    .zero 32768
fortress_boot_stack_top:
"#);

#[used]
#[link_section = ".limine_requests_start"]
static REQUEST_START: [u64; 4] = limine::START;
#[used]
#[link_section = ".limine_requests"]
static mut BASE_REVISION: [u64; 3] = limine::BASE;
#[used]
#[link_section = ".limine_requests"]
static mut MEMMAP: limine::Request<limine::MemMapResponse> =
    limine::Request::new(limine::MEMMAP_ID.0, limine::MEMMAP_ID.1);
#[used]
#[link_section = ".limine_requests"]
static mut HHDM: limine::Request<limine::HhdmResponse> =
    limine::Request::new(limine::HHDM_ID.0, limine::HHDM_ID.1);
#[used]
#[link_section = ".limine_requests"]
static mut EXEC: limine::Request<limine::ExecutableAddressResponse> =
    limine::Request::new(limine::EXEC_ID.0, limine::EXEC_ID.1);
#[used]
#[link_section = ".limine_requests"]
static mut RSDP: limine::Request<limine::RsdpResponse> =
    limine::Request::new(limine::RSDP_ID.0, limine::RSDP_ID.1);
#[used]
#[link_section = ".limine_requests"]
static mut MODULE: limine::Request<limine::ModuleResponse> =
    limine::Request::new(limine::MODULE_ID.0, limine::MODULE_ID.1);
#[used]
#[link_section = ".limine_requests"]
static mut FB: limine::Request<limine::FramebufferResponse> =
    limine::Request::new(limine::FB_ID.0, limine::FB_ID.1);
#[used]
#[link_section = ".limine_requests_end"]
static REQUEST_END: [u64; 2] = limine::END;

// Owned by the kernel's BSS, never by the bootloader.
static mut BOOT_INFO: BootInfoV0 = BootInfoV0::empty();

extern "C" {
    static __kernel_start: u8;
    static __kernel_end: u8;
}

fn halt() -> ! {
    loop { unsafe { asm!("cli; hlt", options(nomem, nostack)); } }
}
// A distinct failure exit is observable only in emulator test profiles.
#[cfg(feature = "g1-qemu-exit")]
#[no_mangle]
#[inline(never)]
extern "C" fn fortress_g1_debug_exit(guest_code: u8) {
    unsafe { asm!("out dx, al", in("dx") 0xf4u16, in("al") guest_code,
                  options(nomem, nostack, preserves_flags)); }
}

#[cfg(feature = "g1-qemu-exit")]
#[used]
#[no_mangle]
static FORTRESS_G1_QEMU_TEST_ONLY: u8 = 1;

// QEMU-only fixture identity, emitted before reading any Limine response.
// compile_error from kernel/build.rs prevents more than one active profile.
#[cfg(feature = "g1-qemu-exit")]
#[inline(never)]
#[allow(unreachable_code)]
fn g1_fixture_name() -> &'static str {
    #[cfg(feature = "g1-fixture-map-zero")]
    { return "map-zero"; }
    #[cfg(feature = "g1-fixture-map-overflow")]
    { return "map-overflow"; }
    #[cfg(feature = "g1-fixture-map-overlap")]
    { return "map-overlap"; }
    #[cfg(feature = "g1-fixture-fb-invalid")]
    { return "fb-invalid"; }
    #[cfg(feature = "g1-fixture-fb-alias")]
    { return "fb-alias"; }
    #[cfg(feature = "g1-fixture-kernel-overflow")]
    { return "kernel-overflow"; }
    #[cfg(feature = "g1-fixture-no-fb")]
    { return "no-fb"; }
    #[cfg(feature = "g1-fixture-late-panic")]
    { return "late-panic"; }
    #[cfg(feature = "g1-fixture-hang")]
    { return "hang"; }
    #[cfg(feature = "g1-fixture-cpu-ud")]
    { return "cpu-ud"; }
    #[cfg(feature = "g1-fixture-cpu-gp")]
    { return "cpu-gp"; }
    #[cfg(feature = "g1-fixture-console")]
    { return "console"; }
    #[cfg(feature = "g1-fixture-k2-ud")]
    { return "k2-ud"; }
    #[cfg(feature = "g1-fixture-k1-real")]
    { return "k1-real"; }
    #[cfg(feature = "g1-fixture-k3")]
    { return "k3"; }
    #[cfg(feature = "g1-fixture-k4")]
    { return "k4"; }
    "normal"
}

extern "C" fn cpu_fault(vector: u64, error: u64) -> ! {
    serial::log(format_args!("FORTRESS_CPU_FAULT vector={vector} error={error}\n"));
    #[cfg(feature = "g1-qemu-exit")]
    fortress_g1_debug_exit(0x11);
    halt();
}

fn fatal(message: &str) -> ! {
    serial::line("FORTRESS_BOOT_PANIC");
    serial::line(message);
    #[cfg(feature = "g1-qemu-exit")]
    fortress_g1_debug_exit(0x11); // independent QEMU failure exit = 35
    halt();
}
#[panic_handler]
fn panic(info: &PanicInfo<'_>) -> ! {
    let _ = writeln!(serial::Console, "FORTRESS_PANIC {info}");
    #[cfg(feature = "g1-qemu-exit")]
    fortress_g1_debug_exit(0x11);
    halt();
}

fn physical(hhdm: u64, virtual_address: u64) -> Result<u64, &'static str> {
    let phys = virtual_address.checked_sub(hhdm).ok_or("HHDM_UNDERFLOW")?;
    if phys.checked_add(hhdm) != Some(virtual_address) {
        return Err("HHDM_OVERFLOW");
    }
    Ok(phys)
}

// # Safety: all requests were fulfilled by the pinned Limine version,
// response memory is still mapped, and no bootloader-reclaimable memory is
// freed. Raw addresses from protocol data are bounds-checked as metadata.
unsafe fn make_boot_info() -> Result<&'static BootInfoV0, &'static str> {
    let revision = unsafe { ptr::read_volatile(ptr::addr_of!(BASE_REVISION).cast::<u64>().add(2)) };
    if revision != 0 { return Err("LIMINE_BASE_REVISION_UNSUPPORTED"); }
    let map = unsafe { limine::response(ptr::addr_of!(MEMMAP)) }.ok_or("NO_MEMMAP")?;
    let hhdm = unsafe { limine::response(ptr::addr_of!(HHDM)) }.ok_or("NO_HHDM")?;
    let kernel = unsafe { limine::response(ptr::addr_of!(EXEC)) }.ok_or("NO_EXEC_ADDRESS")?;
    if map.entry_count == 0 || map.entry_count > MAX_REGIONS as u64 || map.entries.is_null() {
        return Err("INVALID_MEMMAP_COUNT");
    }
    let info = unsafe { &mut *ptr::addr_of_mut!(BOOT_INFO) };
    info.hhdm_offset = hhdm.offset;
    info.kernel_physical_base = kernel.physical_base;
    info.kernel_virtual_base = kernel.virtual_base;
    let vstart = ptr::addr_of!(__kernel_start) as u64;
    let vend = ptr::addr_of!(__kernel_end) as u64;
    info.kernel_size = vend.checked_sub(vstart).ok_or("KERNEL_SIZE_OVERFLOW")?;
    if vstart != kernel.virtual_base { return Err("KERNEL_BASE_MISMATCH"); }

    for i in 0..map.entry_count as usize {
        let p = unsafe { ptr::read(map.entries.add(i)) };
        if p.is_null() { return Err("NULL_MEMMAP_ENTRY"); }
        let r = unsafe { &*p };
        info.regions[i] = MemoryRegion { base: r.base, length: r.length, kind: r.kind };
    }
    info.region_count = map.entry_count as u32;
    // QEMU-only deterministic mutations of the KERNEL-OWNED COPY. Never
    // corrupt Limine's raw pointers, page tables, firmware data or host RAM.
    #[cfg(feature = "g1-fixture-map-zero")]
    { info.region_count = 0; }
    #[cfg(feature = "g1-fixture-map-overflow")]
    { info.regions[0] = MemoryRegion { base: u64::MAX - 7, length: 16,
                                      kind: bootinfo::USABLE }; }
    #[cfg(feature = "g1-fixture-map-overlap")]
    {
        info.regions[0] = MemoryRegion { base: 0x1000, length: 0x2000,
                                          kind: bootinfo::USABLE };
        info.regions[1] = MemoryRegion { base: 0x2000, length: 0x1000, kind: 1 };
        info.region_count = 2;
    }
    bootinfo::validate_regions(info.region_slice()).map_err(|_| "MEMMAP_INVALID")?;

    if let Some(modules) = unsafe { limine::response(ptr::addr_of!(MODULE)) } {
        if modules.module_count > MAX_MODULES as u64 { return Err("TOO_MANY_MODULES"); }
        if modules.module_count > 0 && modules.modules.is_null() { return Err("NULL_MODULE_TABLE"); }
        for i in 0..modules.module_count as usize {
            let p = unsafe { ptr::read(modules.modules.add(i)) };
            if p.is_null() { return Err("NULL_MODULE"); }
            let f = unsafe { &*p };
            info.modules[i] = ModuleRegion {
                physical_base: physical(hhdm.offset, f.address)?,
                file_size: f.size,
                length: bootinfo::page_round_up(f.size).map_err(|_| "INVALID_MODULE_SIZE")?,
            };
        }
        info.module_count = modules.module_count as u32;
    }
    if let Some(rsdp) = unsafe { limine::response(ptr::addr_of!(RSDP)) } {
        if rsdp.address != 0 {
            info.rsdp_physical = physical(hhdm.offset, rsdp.address)?;
            info.flags |= FLAG_RSDP;
        }
    }
    if let Some(fbs) = unsafe { limine::response(ptr::addr_of!(FB)) } {
        if fbs.framebuffer_count > 0 {
            if fbs.framebuffers.is_null() { return Err("NULL_FRAMEBUFFER_TABLE"); }
            let p = unsafe { ptr::read(fbs.framebuffers) };
            if p.is_null() { return Err("NULL_FRAMEBUFFER"); }
            let f = unsafe { &*p };
            info.framebuffer = FramebufferInfo {
                physical_base: physical(hhdm.offset, f.address)?,
                virtual_base: f.address, width: f.width, height: f.height,
                pitch: f.pitch, bpp: f.bpp, memory_model: f.memory_model,
                red_size: f.red_size, red_shift: f.red_shift,
                green_size: f.green_size, green_shift: f.green_shift,
                blue_size: f.blue_size, blue_shift: f.blue_shift,
            };
            info.flags |= FLAG_FRAMEBUFFER;
        }
    }
    #[cfg(feature = "g1-fixture-fb-invalid")]
    { info.flags |= FLAG_FRAMEBUFFER; info.framebuffer.width = 0; }
    #[cfg(feature = "g1-fixture-fb-alias")]
    {
        let base = info.kernel_physical_base;
        let virt = hhdm.offset.checked_add(base).ok_or("FB_ALIAS_HHDM_OVERFLOW")?;
        info.flags |= FLAG_FRAMEBUFFER;
        info.framebuffer = FramebufferInfo {
            physical_base: base, virtual_base: virt,
            width: 8, height: 8, pitch: 32, bpp: 32, memory_model: 1,
            red_size: 8, green_size: 8, blue_size: 8,
            red_shift: 16, green_shift: 8, blue_shift: 0,
        };
    }
    #[cfg(feature = "g1-fixture-kernel-overflow")]
    { info.kernel_size = u64::MAX; }
    #[cfg(feature = "g1-fixture-no-fb")]
    { info.flags &= !FLAG_FRAMEBUFFER; info.framebuffer = FramebufferInfo::EMPTY; }
    bootinfo::validate(info).map_err(|_| "BOOTINFO_INVALID")?;
    Ok(info)
}

#[no_mangle]
extern "C" fn fortress_rust_entry() -> ! {
    serial::init();
    serial::line("FORTRESS_ENTRY");
    // Immutable test source selects a compile-time fixture: name must be bound
    // by BUILD to --fixture, cargo features and the per-case kernel ELF SHA.
    #[cfg(feature = "g1-qemu-exit")]
    serial::log(format_args!("FORTRESS_G1_PROFILE {}\n", g1_fixture_name()));
    // The entry stub masked IRQs and switched to our mapped bootstrap stack.
    // Limine's current code descriptor remains pinned for this boot stage.
    unsafe { exceptions::install(); }
    #[cfg(feature = "g1-fixture-k2-ud")]
    k2::exercise_ud();
    #[cfg(feature = "g1-fixture-cpu-ud")]
    unsafe { asm!("ud2"); }
    #[cfg(feature = "g1-fixture-cpu-gp")]
    unsafe {
        // Vector 32 is just outside the early IDT. CPU raises #GP with
        // error (32 << 3) | 2, testing the actual error-code slot.
        asm!("int 0x20");
    }
    #[cfg(not(feature = "g1-fixture-k2-ud"))]
    {
        let info = unsafe { make_boot_info() }.unwrap_or_else(|e| fatal(e));
        kernel_main(info)
    }
}

// Internal G1 handoff: one borrowed reference to kernel-owned static memory.
// No user-space ABI or bootloader service handles cross this boundary.
fn kernel_main(info: &'static BootInfoV0) -> ! {
    serial::log(format_args!("FORTRESS_MEMMAP_OK entries={} modules={}\n",
        info.region_count, info.module_count));
    #[cfg(feature = "g1-fixture-hang")]
    {
        serial::line("FORTRESS_G1_FIXTURE_HANG");
        halt(); // deliberately bounded by QEMU host watchdog only
    }
    if info.flags & FLAG_FRAMEBUFFER != 0 {
        unsafe { framebuffer::paint_signature(&info.framebuffer); }
        serial::line("FORTRESS_FRAMEBUFFER_OK");
    } else {
        serial::line("FORTRESS_FRAMEBUFFER_ABSENT");
    }
    if info.flags & FLAG_RSDP != 0 { serial::line("FORTRESS_RSDP_PRESENT"); }
    #[cfg(feature = "g1-fixture-k1-real")]
    k1_guest::run(info);
    #[cfg(feature = "g1-fixture-k3")]
    k3::run(info);
    #[cfg(feature = "g1-fixture-k4")]
    k4::run(info);
    serial::line("FORTRESS_BOOT_OK");
    #[cfg(feature = "g1-fixture-late-panic")]
    {
        serial::line("FORTRESS_BOOT_PANIC");
        serial::line("G1_FIXTURE_LATE_PANIC");
        #[cfg(feature = "g1-qemu-exit")]
        fortress_g1_debug_exit(0x11); // 35, never success
        halt();
    }
    #[cfg(feature = "g1-fixture-console")]
    diagnostic_console(info);
    #[cfg(not(feature = "g1-fixture-console"))]
    {
        // Test-only terminal observation; production image has no exit hook.
        #[cfg(feature = "g1-qemu-exit")]
        fortress_g1_debug_exit(0x10);
        halt();
    }
}

#[cfg(feature = "g1-fixture-console")]
fn diagnostic_console(info: &BootInfoV0) -> ! {
    use fortress_boot_kernel::console::{LineEditor, LineResult};
    use serial::Receive;

    let mut line = LineEditor::new();
    serial::clear_receive();
    serial::line("FORTRESS_CONSOLE_READY");
    serial::log(format_args!("fortress> "));
    loop {
        let byte = match serial::receive() {
            Receive::Empty => {
                // The diagnostic profile has no IRQ routing yet. Reduce
                // repeated port reads while waiting for input on one vCPU.
                for _ in 0..128 { core::hint::spin_loop(); }
                continue;
            }
            Receive::Fault => {
                line.invalidate();
                continue;
            }
            Receive::Unavailable => fatal("CONSOLE_UART_UNAVAILABLE"),
            Receive::Byte(byte) => byte,
        };
        let Some(command) = line.feed(byte) else { continue; };
        match command {
            LineResult::Empty => {},
            LineResult::Invalid => serial::line("error: invalid input"),
            LineResult::Unknown => serial::line("error: unknown command"),
            LineResult::Help => serial::line("commands: help status version calc exit"),
            LineResult::Version => serial::line("FortressOS diagnostic console v1"),
            LineResult::Status => {
                let framebuffer = if info.flags & FLAG_FRAMEBUFFER != 0 { "present" } else { "absent" };
                serial::log(format_args!(
                    "FORTRESS_CONSOLE_STATUS boot=ok regions={} modules={} framebuffer={framebuffer}\n",
                    info.region_count, info.module_count));
            }
            LineResult::Calculation(value) => serial::log(format_args!("result: {value}\n")),
            LineResult::InvalidCalculation => serial::line("error: invalid calculation"),
            LineResult::DivisionByZero => serial::line("error: division by zero"),
            LineResult::ArithmeticOverflow => serial::line("error: arithmetic overflow"),
            LineResult::Exit => {
                serial::line("FORTRESS_CONSOLE_EXIT");
                fortress_g1_debug_exit(0x10);
                halt();
            }
        }
        serial::log(format_args!("fortress> "));
    }
}
