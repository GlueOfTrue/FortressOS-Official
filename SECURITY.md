# Security policy

This is an experimental operating-system **research snapshot**, not a secure production platform.

**Do not rely on it to protect sensitive data.** The integrated early kernel baseline contains a known global W^X alias defect; the repair is not present in this public candidate. VM, IOMMU, GPU, network, signed boot and trusted update guarantees are not established.

Please report potentially sensitive vulnerabilities privately to the repository owner through GitHub's private vulnerability reporting feature **if enabled**. Do not include credentials, personal information, or exploit samples targeting third-party machines in public issues.

The absence of a supported production release means there is no guaranteed security patch SLA. Only tests executed against an exact, published commit establish the behavior of that commit. None of the documented prototype mechanisms should be interpreted as a certification.

## Official versus modified releases

Only releases explicitly published or endorsed by the official FortressOS maintainers are covered by their own published security-status statements. A modified binary, downstream fork or unofficial installer is a distinct distributor's product: its authors/distributors must perform their own security validation and must not claim the original maintainer approved or guaranteed the result. See [TRADEMARKS.md](TRADEMARKS.md) and the [Apache License 2.0](LICENSE).

The license's warranty and liability limitations apply subject to applicable law. These policies cannot eliminate liabilities that the law does not permit excluding, nor do they create a blanket mandatory indemnity for every downstream change.
