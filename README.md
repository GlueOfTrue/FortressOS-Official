# FortressOS

**Originally created and maintained by [GlueOfTrue](https://github.com/GlueOfTrue).** Official project source and releases are issued by the designated FortressOS maintainers; third-party forks and rebuilds are independent and are **not** endorsed, maintained or warranted by the original project.

**An experimental operating system project exploring explicit authority, isolation, and resilient system services.**

FortressOS is not a Linux distribution. The long-term idea is a small Rust-based kernel with isolated user-space services, capability-oriented access to resources, and useful desktop and server editions built on the same foundations.

This repository is an **experimental code snapshot**, not a complete OS or a secure production release. It includes early x86-64 boot and kernel experiments, portable Rust subsystem models, and small user-mode QEMU fixtures. The implementation is subject to substantial change.

## What's inside

- `kernel/` — freestanding x86-64 kernel, Limine handoff, early virtual memory, exceptions and experimental CPL3/QEMU fixtures.
- `arch/`, `memory/`, `memory-x86/` — CPU, page-table and resource-lifetime experiments.
- `cap/`, `process/`, `scheduler/` — capability and IPC models, ELF/process models and scheduling primitives.
- `gpu/`, `gui/` — early resource ownership and software-rendering experiments; **not** native graphics drivers.
- `experiments/`, `tools/xtask/`, `boot/`, `userland/` — UEFI smoke tests, build tools and synthetic QEMU test workloads.

See [Architecture](docs/ARCHITECTURE.md), [Build and test](docs/BUILD.md), [Technical status](docs/STATUS.md), and [Project vision](docs/VISION.md).

## Technical direction

The kernel should provide the smallest useful privileged mechanisms for address spaces, scheduling, interrupts and capability-mediated operations. Higher-level filesystems, devices, desktop, security policy and networking should move behind explicit service interfaces where practical.

A normal desktop should stay fast. Security-sensitive applications should gain stronger compartmentalization; hostile server tenants eventually need dedicated VM isolation and, where supported, confidential-computing hardware. These are **roadmap goals, not features provided by this snapshot**.

## Quick checks

Install Rust via `rustup`, then run from the repository root:

```sh
cargo test --workspace
cargo test --manifest-path memory-x86/Cargo.toml
cargo +1.91.1 check --manifest-path arch/x86-entry/Cargo.toml --target x86_64-unknown-none
```

The `kernel/` directory uses its own Rust 1.91.1 toolchain and `x86_64-unknown-none` target. On an ARM64 development host, `arch/x86-entry` must be **cross-checked** against x86-64, not run with native `cargo test`. Do not use `cargo test --workspace --all-targets`: `--all-targets` forces a test harness for the `no_std` UEFI diagnostic binary, which deliberately has `test = false` in its manifest. QEMU/OVMF and an independently obtained Limine loader are required for experimental boot tests. See [Build and test](docs/BUILD.md).

**Do not boot the experimental kernel on a machine containing data you care about.** The included security tests use disposable virtual machines.

## Safety and limitations

This source snapshot is not audited for production security. Its experimental integrated K3/K4 baseline has a **known writable direct-map alias of executable kernel memory (global W^X violation)**; an unverified repair exists outside this snapshot. Full process, VM, DMA, GPU and confidential-computing isolation are **not** demonstrated. Do not run untrusted workloads or store secrets using this system.

Read [SECURITY.md](SECURITY.md) and [Technical status](docs/STATUS.md) before using the code.

## Product and release licensing

Future releases distinguish the Apache-2.0 **Fortress Kernel**, its public ABI and the open baseline **Fortress Graphics** stack from the separately licensed **FortressOS** distribution. The distribution may include both open-source and proprietary components; publication of the kernel does not imply publication of all system source. Previously granted open-source rights remain unchanged. See [Licensing and release boundary](RELEASE_POLICY.md).

## License

The intended license for first-party source in this preview is **Apache License 2.0** (see [LICENSE](LICENSE)); all release rights and required third-party notices must be verified before publication. Modified redistributed files must be clearly marked, and original attribution retained as required by the license. See [NOTICE](NOTICE.md), [Brand and official builds](TRADEMARKS.md), and [Contributing](CONTRIBUTING.md). Limine, OVMF and other external build dependencies are **not** distributed here and retain their own licenses.
