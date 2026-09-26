# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog, and this project adheres to
Semantic Versioning.

## [Unreleased] — V0.1 development

### Added

- DiagPermit protocol 0.1 document model: DiagnosticRequest, Capability,
  ConsentDecision, EffectiveDisclosurePlan, CollectorResult,
  TransformationReport, Manifest, DisclosureReceipt and Finding.
- Canonical JSON + SHA-256 document hashing (`pkg/protocol`).
- CLI: `diagpermit init`, `validate`, `plan`, `collect`, `inspect`, `verify`,
  `redact-test`, `collectors`, `doctor`.
- Collectors: system (os/memory/disk), runtime (python/node/java/go
  versions), application logs (bounded tail), basic Docker (version,
  container states/images/health — no environment variables).
- Privacy transformation engine `diagpermit-default-0.1`: drop, mask, replace,
  truncate, hash, pseudonymize; stable per-artifact pseudonyms; fail-closed
  behaviour; transformation reports that never contain original values.
- ZIP-backed `.diagnostic` artifacts with SHA-256 manifest and disclosure
  receipt; safe archive read/write (path traversal and decompression-bomb
  protection).
- Integrity verification distinguishing INTEGRITY VERIFIED from (never
  claimed) privacy guarantees.
- Conformance suite with 10 vectors (`conformance/`).
- Synthetic secret test corpus (`testdata/secretcorpus/`).
- Deterministic findings analyzer (e.g. DATABASE_CONNECTIVITY_FAILURE).
- Demo application `examples/broken-demo-app` (DiagShop).
- Documentation: README, quickstart, protocol overview, threat model,
  security policy.
