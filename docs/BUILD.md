# Build and test

## Host-only tests

Install a Rust toolchain with `rustup`. The root `rust-toolchain.toml` pins a host-facing toolchain; `kernel/rust-toolchain.toml` pins the freestanding kernel toolchain.

From a fresh public repository clone:

```sh
cargo test --workspace
cargo test --manifest-path memory-x86/Cargo.toml --all-targets
cargo +1.91.1 check --manifest-path arch/x86-entry/Cargo.toml --target x86_64-unknown-none
```

The first two commands run portable host-side tests. The third performs **cross-compilation checking**, not execution, for a privileged x86-64 module; install `x86_64-unknown-none` for Rust 1.91.1 beforehand. On Apple Silicon, native `cargo test --manifest-path arch/x86-entry/Cargo.toml` correctly fails because the module includes x86-64-only assembly.

**Do not use `cargo test --workspace --all-targets`.** The `--all-targets` flag explicitly selects the `no_std` UEFI diagnostic binary, overriding its `test = false` setting and producing a duplicate `panic_impl` with the host test harness. The ordinary `cargo test --workspace` command honors the target's default-test opt-out.

These host tests validate limited data structures and protocol models. They do **not** prove actual CPU isolation, interrupt correctness or DMA safety.

## Freestanding x86-64 kernel

The kernel requires `x86_64-unknown-none`, Rust 1.91.1 (see `kernel/rust-toolchain.toml`), a suitable linker/toolchain and a separate [Limine](https://github.com/Limine-Bootloader/Limine) x86-64 EFI loader. The Limine version expected by the standalone script is **v12.9.6**. The loader source/binary and OVMF firmware are **not** included.

For an experimental, disposable QEMU build:

```sh
rustup toolchain install 1.91.1 --profile minimal --target x86_64-unknown-none
export LIMINE_DIR=/absolute/path/to/a/verified/limine-build
G1_QEMU_TEST=1 G1_FIXTURE=k3 bash boot/build-standalone.sh
```

This stages an EFI-system-partition directory under `build/esp/`. The user ELF fixtures are synthetic. Do not copy it to real removable media or change host firmware settings.

The `boot/run-qemu.py` runner accepts paths to disposable OVMF CODE/VARS files and a staged ESP. Consult its `--help` on your machine; it never needs to access physical block devices. On Apple Silicon, `qemu-system-x86_64` uses TCG software emulation rather than hardware-accelerated x86 virtualization.

```sh
python3 boot/run-qemu.py --help
```

QEMU fixture success codes, source hashes, COM1 signatures and timeouts must all be checked together; a line of serial output by itself is not a valid positive test.

## Diagnostics

The independent `cargo xtask build|image|qemu|test` commands concern the minimal UEFI diagnostic experiment, **not** the full kernel. They use a separate UEFI target and require appropriate QEMU and OVMF host environment. Do not use `cargo xtask g1` in this curated snapshot; the internal integration/coordination harness is not distributed.

## External components and licensing

Limine, QEMU, OVMF and their dependencies are acquired separately under their own terms. No embedded firmware, signing keys or licensed GPU drivers ship in this tree.
