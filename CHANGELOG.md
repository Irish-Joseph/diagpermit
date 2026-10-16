# Changelog

All notable changes to this project are documented here. The project follows
Semantic Versioning.

## [0.2.0-rc.1] — Release candidate (public testing)

> This is a release candidate intended for public testing before v0.2.0
> stable. It is not a production-stable release.

### Highlights

- Consent-driven diagnostic workflow: request → capability review →
  explicit consent → immutable disclosure plan → local collection.
- Embedded local UI (`diagpermit ui`): full request/consent/collection/
  artifact workflow on a loopback-only server with a session token, strict
  CSP, and no CORS. All assets compile into the binary; no Node.js needed.
- Privacy transformation pipeline: 15 built-in detectors plus user patterns,
  six transformation actions, per-artifact stable pseudonyms, fail-closed
  behaviour, and reports that never contain original values.
- Disclosure receipt in every artifact: request hash, plan hash, consent
  summary, collection enforcement flags, transformation summary, manifest
  hash.
- Integrity verification (`INTEGRITY VERIFIED`): archive, schemas, manifest
  coverage, hashes, request/plan/manifest binding. Integrity is never
  presented as a privacy guarantee.
- Signed diagnostic requests: DSSE envelopes, Ed25519 signatures, explicit
  local trust policy with five distinct authenticity states.
- Cross-platform: Linux (amd64/arm64), Windows (amd64), macOS (amd64/arm64).
- Published protocol JSON schemas, examples, RFCs, and a 10-vector
  conformance suite.

### Known limitations

- No browser-level (Playwright) CI E2E yet; the UI workflow is covered by
  Go API-level security tests and release smoke checks.
- Release binaries are not cryptographically signed; `SHA256SUMS` plus the
  source tag and SBOM are the current integrity controls.
- Docker diagnostics require a running Docker daemon; without one, the
  Docker capability is reported as failed (never skipped silently).
- Remaining V0.2 roadmap items are intentionally deferred: existing-tool
  adapter, policy profiles, advanced Docker diagnostics, encrypted
  artifacts. See ROADMAP.md.
- Pattern-based redaction cannot guarantee that every sensitive value is
  detected; review content before sharing (by design, and stated in all
  user-visible output).

### Compatibility

- Protocol remains 0.1. The protocol version is independent of the CLI
  version and did not change with the UI.
- V0.1 `.diagnostic` artifacts remain fully readable and verifiable.
- All V0.1 CLI commands remain available; the CLI works headless,
  independently of the UI.

### Release artifacts

Pushing the `v0.2.0-rc.1` tag triggers the release workflow, which builds
five platform binaries, `SHA256SUMS`, and a CycloneDX SBOM.

## V0.2 development history

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

## V0.1 development

- Protocol 0.1 types, canonical JSON hashing, consent and disclosure planning.
- System, runtime, application-log, and Docker collectors.
- Privacy transformation engine and deterministic findings.
- ZIP-backed `.diagnostic` artifacts with manifests and disclosure receipts.
- CLI planning, collection, inspection, integrity verification, and conformance
  suite across Linux, Windows, and macOS.
