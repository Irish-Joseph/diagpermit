# Security

DiagX is a privacy- and security-sensitive project. We take our own supply
chain seriously because a diagnostic-security tool that is itself
insecure would be worse than useless.

## Reporting a vulnerability

**Do not open a public issue for a security problem.**

- Use GitHub's **private vulnerability reporting** for this repository.
- Alternatively email the maintainers (see GOVERNANCE.md).
- We aim to acknowledge within 2 business days and to ship a fix or a clear
  non-vulnerability rationale promptly.

Please include reproduction steps and, where possible, the affected version.

## Security practices

- **Dependabot** for dependency updates and alerts.
- **CodeQL** analysis in CI.
- **Secret scanning** where available.
- **Branch protection** with required PR reviews on `main`.
- **Signed release workflow** — releases are reproducible and checksummed.
- **Fuzz testing** for security-sensitive parsers (see
  `internal/transform/fuzz_test.go` and the safezip tests).
- **Cross-platform CI** for Linux, Windows and macOS.

## Supply chain

Each release publishes: binaries, SHA-256 checksums, an SBOM, release notes
and (as tooling matures) signatures/attestations. We work toward OpenSSF
Scorecard improvement and the OpenSSF Best Practices Badge from the start.

## Security-relevant defaults

- Network access: **disabled** by default.
- Arbitrary shell execution: **disabled** and rejected in protocol 0.1.
- Symlink following: **disabled** by default.
- Telemetry: **off**; V0.1 has none.
- Privacy transformations: **fail closed**.

## Privacy wording policy

Documentation MUST NOT say "DiagX guarantees that all secrets are removed."
Use: "DiagX records which configured detectors and transformations executed
successfully" and "Users should review diagnostic content before sharing
it." Integrity verification is never presented as a privacy guarantee.
