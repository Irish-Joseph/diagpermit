# Changelog

All notable changes to this project are documented here. The project follows
Semantic Versioning.

## [Unreleased] — V0.2 development

### Added

- Loopback-only local visual viewer (`diagpermit ui`) for request review,
  explicit consent, collection, package inspection, and integrity verification.
- Safe, manifest-bound text previews for diagnostic package contents.
- Standard DSSE envelopes with Ed25519 signing and an explicit local requester
  trust policy (`diagpermit request keygen|sign|verify`).
- Real viewer screenshots generated from the synthetic DiagShop demo.
- Frontend and local-server security tests.

### Security

- Viewer binds to `127.0.0.1` on a random port and requires a random session
  token, strict Host/Origin checks, a mutation marker, size limits, timeouts,
  CSP, and same-site cookies. CORS and remote assets are disabled.
- Signature validity and requester trust are reported separately; an unknown
  key is never mislabeled as a bad signature.

### Fixed

- Canonical request JSON now emits the documented lowercase `request.id` key
  while remaining able to read existing V0.1 artifacts.

## V0.1 development

- Protocol 0.1 types, canonical JSON hashing, consent and disclosure planning.
- System, runtime, application-log, and Docker collectors.
- Privacy transformation engine and deterministic findings.
- ZIP-backed `.diagnostic` artifacts with manifests and disclosure receipts.
- CLI planning, collection, inspection, integrity verification, and conformance
  suite across Linux, Windows, and macOS.
