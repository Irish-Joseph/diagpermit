# Roadmap

## V0.1 — the core (this release)

- Protocol 0.1: DiagnosticRequest, ConsentDecision,
  EffectiveDisclosurePlan, Manifest, DisclosureReceipt,
  TransformationReport, CollectionReport, Finding schemas.
- Canonicalization rules (canonical JSON, SHA-256) and conformance vectors.
- CLI: `init`, `validate`, `plan`, `collect`, `inspect`, `verify`,
  `redact-test`, `collectors`, `doctor`.
- Collectors: system, runtime, application logs, basic Docker.
- Privacy: pattern detectors, mask/drop/truncate/hash/pseudonymize,
  transformation report, fail-closed behaviour.
- Security: network disabled by default, no arbitrary shell, size and time
  limits, filesystem boundary checking, symlink protection, archive
  validation.
- Packaging: ZIP-backed `.diagnostic` artifact, SHA-256 manifest,
  disclosure receipt.
- Platforms: Linux, Windows, macOS.
- Documentation: README, quickstart, protocol overview, threat model,
  security policy, example application.

Completion criteria: a brand-new developer can do the whole flow on all
three platforms, without any account or upload, and can run the published
conformance tests.

## V0.2

- Local viewer (`diagx view`), with hostile-content security.
- Signed diagnostic requests (in-toto / DSSE / Sigstore-compatible).
- One existing-tool adapter (candidate: sosreport or Troubleshoot).
- Policy profiles.
- Advanced Docker diagnostics.
- Encrypted artifacts (recipient public-key, established format).

## V0.3 (only what users actually request)

- Plugin API (Collector / Transformer / Analyzer / Adapter / Exporter),
  with isolation research (WebAssembly/WASI).
- First SDK.
- GitHub integration; OpenTelemetry adapter.
- Additional database collectors; support-tool integrations.

## Explicitly NOT planned

Cloud dashboards, user accounts, billing, SaaS hosting, AI chatbots as a
core feature, automatic GitHub uploads, fleet management, enterprise
consoles, plugin marketplaces, mobile apps. `diagx explain` (optional,
explicit, local/BYO model) may appear later; AI never decides whether
sensitive information is safe to disclose.
