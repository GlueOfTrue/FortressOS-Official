// Resolve custom linker script from the Cargo manifest, never from caller cwd.
fn main() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("linker.ld");
    println!("cargo:rustc-link-arg-bin=fortress-kernel=-T{}", path.display());
    // Controlled negative boot fixtures are never valid without the explicit
    // test-only ISA debug-exit feature. One fixture per independently logged run.
    let fixtures = [
        "G1_FIXTURE_MAP_ZERO",
        "G1_FIXTURE_MAP_OVERFLOW",
        "G1_FIXTURE_MAP_OVERLAP",
        "G1_FIXTURE_FB_INVALID",
        "G1_FIXTURE_FB_ALIAS",
        "G1_FIXTURE_KERNEL_OVERFLOW",
        "G1_FIXTURE_NO_FB",
        "G1_FIXTURE_LATE_PANIC",
        "G1_FIXTURE_HANG",
        "G1_FIXTURE_CPU_UD",
        "G1_FIXTURE_CPU_GP",
        "G1_FIXTURE_CONSOLE",
        "G1_FIXTURE_K2_UD",
        "G1_FIXTURE_K1_REAL",
        "G1_FIXTURE_K3",
        "G1_FIXTURE_K4",
    ];
    let chosen = fixtures.iter().filter(|name| {
        std::env::var_os(format!("CARGO_FEATURE_{}", name)).is_some()
    }).count();
    assert!(chosen <= 1, "only one G1 fixture may be active per guest image");
    if chosen != 0 {
        assert!(std::env::var_os("CARGO_FEATURE_G1_QEMU_EXIT").is_some(),
            "G1 injected fixture requires g1-qemu-exit; never put fixtures on hardware");
    }
    let runtime = std::env::var_os("CARGO_FEATURE_K3_FIXTURE_RUNTIME").is_some();
    let k3_or_k4 = ["G1_FIXTURE_K3", "G1_FIXTURE_K4"].iter().any(|f|
        std::env::var_os(format!("CARGO_FEATURE_{f}")).is_some());
    assert_eq!(runtime, k3_or_k4, "K3 runtime requires an explicit QEMU fixture");
    if runtime {
        for key in ["K3_A_ELF", "K3_B_ELF"] {
            println!("cargo:rerun-if-env-changed={key}");
            let path = std::env::var(key).expect("build K3 user ELF artifacts before kernel");
            println!("cargo:rerun-if-changed={path}");
        }
    }
    println!("cargo:rerun-if-changed=linker.ld");
}
