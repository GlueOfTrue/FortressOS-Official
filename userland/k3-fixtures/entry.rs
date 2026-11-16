//! Freestanding envelope for the QEMU user-mode assembly fixtures.
#![no_std]
#![no_main]

#[cfg(all(k3_process_a, k3_process_b))]
compile_error!("select one K3 process");
#[cfg(not(any(k3_process_a, k3_process_b)))]
compile_error!("select one K3 process");

#[cfg(k3_process_a)]
core::arch::global_asm!(include_str!(env!("FORTRESS_FIXTURE_A")));
#[cfg(k3_process_b)]
core::arch::global_asm!(include_str!(env!("FORTRESS_FIXTURE_B")));

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
