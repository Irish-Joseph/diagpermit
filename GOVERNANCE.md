# Governance

DiagPermit is a community-governed, Apache-2.0 open-source project.

## Roles

### Contributors

Anyone who submits code, docs, issues or RFCs. No special rights required.

### Maintainers

- Merge pull requests after review.
- Triage issues and assign priorities.
- Shepherd RFCs to acceptance/rejection.
- Release the CLI and publish release artifacts.
- Handle security reports first-line.

Maintainers are added by consensus of existing maintainers (a public issue
is sufficient to start the discussion). Maintainers who are inactive for
~6 months are archived; they may be reactivated on request.

## Decision process

- **Code:** PR + review; maintainers merge.
- **Protocol changes:** RFC process in `spec/rfcs/`. Accepted RFCs are
  implemented and versioned (semantic versioning; breaking protocol changes
  bump the major version).
- **Security decisions:** maintainers + the reporter, privately;
  vulnerability disclosure is never sold, suppressed or deprioritized by
  sponsors (see SECURITY.md and the sponsorship policy in SUPPORT.md).
- **Stalled decisions:** after ~3 weeks of active disagreement, maintainers
  make a reversible call and document the rationale.

## Release authority

Any maintainer may cut a patch release. Minor releases require an agreed
changelog. Release workflow is signed and publishes binaries, SHA-256
checksums and an SBOM.

## Trademarks

The name and logo are governed by TRADEMARKS.md. Governance does not grant
trademark rights.
