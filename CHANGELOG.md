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
- Fuzz smoke runs of the privacy transformation engine in CI
  (`FuzzTransformContent`, `FuzzTransformCustomPatterns`).
- Published JSON schemas for all nine protocol 0.1 documents
  (`spec/schemas/`) with Go schema tests that validate conformance
  fixtures and real pipeline artifacts, and reject malformed documents.
- Protocol examples (`spec/examples/`) and the RFC process with the two
  accepted RFCs (`spec/rfcs/`).
- Public `ROADMAP.md` and `.github/FUNDING.yml`.

### Changed

- Renamed the transformation fuzz targets to distinct names so each can be
  selected individually (e.g. `go test -fuzz=FuzzTransformContent`).

### Security

- Viewer binds to `127.0.0.1` on a random port and requires a random session
  token, strict Host/Origin checks, a mutation marker, size limits, timeouts,
  CSP, and same-site cookies. CORS and remote assets are disabled.
- Signature validity and requester trust are reported separately; an unknown
  key is never mislabeled as a bad signature.
- Frontend dependency `source-map-js` event-loop DoS advisory resolved by
  updating the Vite toolchain (`npm audit --audit-level=high` is clean).

### Fixed

- Canonical request JSON now emits the documented lowercase `request.id` key
  while remaining able to read existing V0.1 artifacts.

### Release candidate notes (v0.2.0-rc.1)

- Release artifacts (five platform binaries, `SHA256SUMS`, CycloneDX SBOM)
  are produced by the `release.yml` workflow when a `v*` tag is pushed.
- Binaries are not cryptographically signed in this candidate; checksums and
  the source tag are the integrity controls until signing infrastructure
  lands. Do not treat the release as signed.
- Known limitations: no browser-level (Playwright) E2E job yet — the local
  viewer workflow is covered by Go API-level tests and manual smoke checks;
  Docker diagnostics require a running Docker daemon; pattern-based redaction
  never guarantees complete secret removal (by design, and stated as such in
  all user-visible output).
- Upgrade/compatibility: all V0.1 `.diagnostic` artifacts and V0.1 CLI
  commands remain supported. The protocol version is still 0.1; the CLI
  version moves to 0.2.0-rc.1 via the release tag.

## V0.1 development

- Protocol 0.1 types, canonical JSON hashing, consent and disclosure planning.
- System, runtime, application-log, and Docker collectors.
- Privacy transformation engine and deterministic findings.
- ZIP-backed `.diagnostic` artifacts with manifests and disclosure receipts.
- CLI planning, collection, inspection, integrity verification, and conformance
  suite across Linux, Windows, and macOS.
