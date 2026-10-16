# ROADMAP

The protocol version and the CLI version are independent. This roadmap
describes the public plan only.

## V0.1 — Core (implemented)

- Protocol 0.1: request, consent decision, effective disclosure plan,
  collector results, transformation report, manifest, disclosure receipt,
  and finding documents, with published JSON schemas.
- Canonical JSON hashing (SHA-256) and the `conformance/` test-vector suite.
- CLI: `init`, `validate`, `plan`, `collect`, `inspect`, `verify`,
  `redact-test`, `collectors`, `doctor`.
- Collectors: system, runtime (Python/Node.js/Java/Go), application logs,
  basic Docker (version and container state, no environment values).
- Privacy transformation engine: pattern detectors,
  drop/mask/replace/truncate/hash/pseudonymize, per-artifact stable
  pseudonyms, transformation report, fail-closed behaviour.
- Security baseline: network disabled by default, no arbitrary shell, size
  and time limits, filesystem boundary checks, symlink and special-file
  protection, hostile-archive validation.
- Packaging: ZIP-backed `.diagnostic` artifacts with SHA-256 manifest and
  disclosure receipt.
- Platforms: Linux, Windows, macOS.

## V0.2 — Trust and visualization (current)

- **Done:** loopback-only local visual viewer (`diagpermit ui`) with the
  full request → consent → collect → transform → receipt → verify workflow,
  hostile-content-safe previews, and strict local-server security.
- **Done:** signed diagnostic requests with DSSE envelopes, Ed25519
  signatures, and an explicit local requester trust policy
  (`diagpermit request keygen | sign | verify`).
- Remaining candidates (ordered roughly by user value):
  1. One existing-tool adapter (candidate: `sosreport` or Troubleshoot
     support bundles as input to the consent/disclosure layer).
  2. Policy profiles (named, reusable request templates).
  3. Advanced Docker diagnostics (bounded, explicitly consented images).
  4. Encrypted artifacts (recipient public-key, established format —
     redaction controls disclosure, encryption protects storage/transit).

## V0.3 — Ecosystem (only what users actually request)

- Plugin API (Collector / Transformer / Analyzer / Adapter / Exporter) with
  isolation research (WebAssembly/WASI); no arbitrary downloaded native
  plugins.
- First SDK.
- GitHub integration; OpenTelemetry diagnostics adapter.
- Additional database collectors; support-tool integrations.
- Optional, explicit `diagpermit explain` (local or BYO model; AI never
  decides whether sensitive information is safe to disclose).

## Explicitly NOT planned

Cloud dashboards, user accounts, billing, SaaS hosting, AI chatbots as a
core feature, automatic uploads of any kind, fleet management, enterprise
consoles, plugin marketplaces, mobile apps. DiagPermit stays local-first,
open source, and vendor-neutral.

## V1 definition

V1 will mean: a stable core protocol with documented compatibility
guarantees, a stable artifact format, a cross-platform reference
implementation, a maintained conformance suite, a production-quality
security posture, and at least one external implementation or serious
adapter. Feature count alone does not make V1.
