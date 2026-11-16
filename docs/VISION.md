# Why FortressOS?

Modern operating systems have to support two very different expectations: a responsive personal computer and a host capable of running mutually distrustful workloads.

The project explores an alternative design with **explicit ownership, narrow system services, strong failure containment, and configurable performance policies**. The objective is not to reinvent Linux or claim to be universally faster; it is to make privilege, state transitions and isolation boundaries easier to reason about.

Five guiding principles:

1. **Mechanism before convenience.** Kernel authority should be small and checkable; high-level behavior belongs in isolated services wherever feasible.
2. **Security as an understandable contract.** Desktop workloads use ordinary fast page-based isolation; sensitive domains and server tenants use stronger boundaries with explicit hardware prerequisites.
3. **Performance by workload.** Long-running servers, latency-sensitive applications and protected system services need different scheduling policies, with measurable admission and recovery guarantees.
4. **Operational independence.** Device, network, storage and GPU subsystems should avoid unnecessary dependence on a single vendor's control plane. Hardware isolation cannot be manufactured by software alone.
5. **Evidence over claims.** Host models, emulated guests, physical hardware tests and formal proofs establish different things; they must not be conflated.

Early milestones focus on a bootable protected kernel and small user-space experiments. Later possibilities include a desktop stack, capability-aware storage, service supervision and an isolated server platform.
