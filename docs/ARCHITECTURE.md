# Architecture overview

## Boundaries

FortressOS separates an intended **kernel substrate** from a larger operating-system distribution.

The kernel is intended to own CPU transitions, address spaces, page permissions, scheduling mechanics, interrupts and unforgeable object references. A thin kernel interface should let ordinary processes communicate and acquire only explicitly granted resources. User-space services would own higher-level policy, storage, networking, devices and display where hardware permits.

This is a direction, not a claim that all these boundaries are implemented.

## Current source areas

| Source | Present scope | Not yet established |
|---|---|---|
| `kernel/` | x86-64 boot entry, COM1, early CPU and MMU, bounded ring-3 fixtures | Complete secure multi-process kernel |
| `arch/` | IRQ ownership model and entry components | Production multiprocessor dispatch |
| `memory/` | Page ownership and lifetime models | Fully verified global mappings and IOMMU |
| `cap/` | Capabilities and bounded IPC reference code | End-to-end policy enforcement |
| `process/` | Process identifiers, ELF validation and IPC states | Full POSIX userspace |
| `scheduler/` | Thread-state and dispatch model | Adaptive, preemptive, SMP scheduler |
| `gpu/`, `gui/` | Resource and software-rendering experiments | Native graphics acceleration |

## Security model

Untrusted code must never gain authority merely by learning an address or object identifier. Ownership, permissions, generation and revocation should remain connected across IPC, filesystem handles, memory mappings and devices.

Address-space protection operates at page granularity. A C program can still inspect readable bytes within its own mapped process, regardless of whether it violates C object bounds. Fine-grained memory safety requires a memory-safe language, compiler instrumentation, different compartments or hardware such as CHERI on a compatible architecture.

For hostile multitenant server use, process and container isolation alone are not the final target. Future work requires hypervisor/VM boundary design, EPT/NPT, IOMMU, honest device-isolation claims and confidential memory only on explicitly supported, attested hardware. There is no hypervisor in this snapshot.

## Trust and implementation status

See [Technical status](STATUS.md). A runnable QEMU feature test is not proof of correct whole-kernel isolation. An `unsafe` Rust block, device DMA path or privileged subsystem must have independently tested assumptions and failure behavior.
