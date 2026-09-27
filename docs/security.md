# Security

DiagPermit is a privacy- and security-sensitive project. We take our own supply
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

## Local viewer boundary

`diagpermit ui` binds only to IPv4 loopback on a random operating-system
assigned port. A random 256-bit token establishes an HttpOnly, SameSite=Strict
session. All state-changing requests require an exact same-origin `Origin`
header and a custom mutation header. The server rejects unexpected Host values,
does not enable CORS, limits request bodies and headers, and sets read/write/idle
timeouts.

The embedded viewer uses no CDN, analytics, remote font, or external image. A
strict Content Security Policy permits scripts, styles, images, and API calls
only from the local viewer origin. Artifact previews are manifest-bound,
size-limited UTF-8 text returned inside JSON and rendered as text—not HTML.

## Privacy wording policy

Documentation MUST NOT say "DiagPermit guarantees that all secrets are removed."
Use: "DiagPermit records which configured detectors and transformations executed
successfully" and "Users should review diagnostic content before sharing
it." Integrity verification is never presented as a privacy guarantee.
