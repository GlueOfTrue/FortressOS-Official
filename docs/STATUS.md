# Current technical status

**Snapshot class:** experimental / pre-alpha. **Production readiness:** none.

The included code is taken from an experimental integrated x86-64 K3/K4 development baseline. Independent positive tests on that baseline previously exercised narrowly defined Limine/OVMF boot, CPU faults, CPL3 execution, separate user page tables and limited IPC demonstrations. Some associated cases use fixed-phase user ELF re-entry rather than a general blocked-thread scheduler.

**Important known issue:** a runtime page-table audit of this baseline identified a writable higher-half direct-map alias for physical pages containing executable kernel code. This is a global W^X violation. The baseline must **not** be considered securely isolated. An experimental change proposed to fix it is not part of this snapshot, and its correctness has not been demonstrated by a passing integrated test.

| Area | Status in this snapshot |
|---|---|
| UEFI boot / QEMU smoke | Experimental |
| Early Rust `no_std` kernel and serial diagnostics | Source available |
| Basic CPL3/QEMU process tests | Narrow experimental fixtures |
| Full kernel memory isolation | **Not accepted; known W^X defect** |
| General blocked-thread continuation and preemption | Not established |
| SMP, NUMA, scheduling QoS | Not established |
| MAC, capabilities and IPC | Partial models/experimental integration |
| Real storage, desktop, hardware drivers | Not production-ready |
| Hypervisor, vGPU, confidential VM | Planned; not implemented |
| Formal verification of production kernel | Not established |

The release tree does not contain a public CI result proving it builds after curation. Run its test commands and keep the output separate from claims of security certification.

**Avoid:** deployment to production, exposure to the public Internet, storing sensitive data, bare-metal boot on important devices, and execution of intentionally malicious workloads outside disposable test environments.
