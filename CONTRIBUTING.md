# Contributing to FortressOS

FortressOS is an experimental operating-system research project. The preferred path for improvements is a **pull request to the official upstream source**, allowing review, tests and coherent integration.

## Proposing a change

1. Open a public issue describing the behavior, defect or API improvement. Do not paste private keys, unpublished vulnerabilities, personal information, private infrastructure or internal coordination details.
2. Create a small branch against the current published upstream code, with focused changes.
3. Explain the design, the threat model where relevant, and any compatibility impact.
4. Provide tests or reproducible QEMU fixtures that exercise both accepted and denied behavior. Distinguish host-model results from real privileged-guest results.
5. Submit a pull request. Maintainers may request revision, reject the proposal, or leave it unmerged; contributing does not create a right to upstream merge.

## License and attribution

Unless agreed otherwise in writing, intentionally submitted contributions are provided under Apache License 2.0, Section 5. Do not submit code you lack authority to license, confidential information, copied restricted content or third-party material with incompatible terms. Keep relevant authorship, copyright, change notices and attribution.

No contributor is asked to assign all copyright to one person merely by opening a pull request. Contributors remain responsible for their own representations and permissions as applicable.

## Independent forks

You are free to maintain a separate derivative within the source-code license. We encourage contributions upstream, but they are not mandatory. An independent distributor should maintain its own releases, fixes, support and security statements and **must not misrepresent** a downstream build as an official FortressOS release. See [TRADEMARKS.md](TRADEMARKS.md) and [SECURITY.md](SECURITY.md).

## Quality bar

Experimental code should not be described as production-ready. Tests must identify platform/toolchain versions and whether they were actually run. Critical changes involving memory ownership, IRQ, IPC, boot trust, IOMMU, drivers or process isolation need negative tests and a realistic failure analysis.
