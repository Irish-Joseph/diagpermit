# DiagX

> **Know what you're sharing before you send diagnostics.**

DiagX is an open protocol and CLI for consent-driven software diagnostics.

A requester declares what troubleshooting information it needs.

The user reviews and approves those capabilities.

Collection and privacy transformations happen locally.

The resulting diagnostic artifact contains a **disclosure receipt**
describing what was requested, approved, collected and transformed.

```bash
diagx plan
diagx collect
diagx inspect support.diagnostic
diagx verify support.diagnostic
```

**Technical:** an open protocol for consent-driven diagnostic exchange.

> **Naming note:** `DiagX` is a development codename. Do not register
> domains, publish packages or create final branding until a proper
> GitHub/package/domain/trademark search is complete (see
> [TRADEMARKS.md](TRADEMARKS.md)).

---

## What this is (and is not)

DiagX is **not** a log collector, a ZIP creator, a Kubernetes tool, a
monitoring platform, an APM product, an AI chatbot, a cloud portal, a
ticketing system, a secrets scanner or a remote-management agent.

Mature collectors already exist. Replicated Troubleshoot provides
customizable collection, redaction and analysis of Kubernetes diagnostics;
`sosreport` is an extensible support-data collection system for Linux.
DiagX does not compete with them on collection alone.

DiagX's position:

> **DiagX aims to provide a vendor-neutral consent and disclosure protocol
> around diagnostic exchange, including requester-declared capabilities,
> explicit user decisions, portable disclosure receipts, interoperability
> and conformance testing.**

Existing diagnostic collectors may eventually become DiagX adapters.

## The workflow

```
Diagnostic Request
        ↓
Capability Review
        ↓
User Consent
        ↓
Effective Disclosure Plan
        ↓
Local Collection
        ↓
Privacy Transformations
        ↓
Diagnostic Artifact + Disclosure Receipt
        ↓
Integrity Verification
        ↓
Intentional Sharing   (always a separate, deliberate action)
```

That workflow is the product.

## Quickstart

```bash
# 1. Create a project configuration
diagx init

# 2. Edit diagx.yaml to declare the capabilities your case needs
# 3. Validate it
diagx validate diagx.yaml

# 4. See exactly what would be collected (collects nothing)
diagx plan

# 5. Collect under explicit consent (local only)
diagx collect

# 6. Inspect and verify the artifact
diagx inspect support-CASE-LOCAL.diagnostic
diagx verify support-CASE-LOCAL.diagnostic
```

`diagx collect` only ever creates a local file. There is no mandatory
DiagX server, no account, no automatic cloud synchronization, no automatic
upload and no hidden telemetry. Sharing the artifact is always a separate,
deliberate action outside this tool.

See [docs/quickstart.md](docs/quickstart.md) for a walkthrough.

## Privacy: what the tools do and do not claim

DiagX applies configured pattern detectors and transformations locally and
**records which configured detectors and transformations executed
successfully.** It records counts, never the original values.

It does **not** guarantee that all secrets are removed. No general secret
detector can make that guarantee. **Users should review diagnostic content
before sharing it.** `diagx verify` proves integrity — that the package has
not changed according to the verification model — and never claims a
privacy guarantee.

If a mandatory privacy transformation fails, DiagX **fails closed**:
collection stops safely and no shareable artifact is produced.

## Commands

| Command | Purpose |
| --- | --- |
| `diagx init` | Create `diagx.yaml` project configuration |
| `diagx validate [file]` | Validate a request/project schema |
| `diagx plan` | Show exactly what would happen, without collecting |
| `diagx collect` | request → consent → plan → collection → transformation → package |
| `diagx inspect <artifact>` | Terminal-friendly summary of an artifact |
| `diagx verify <artifact>` | Check integrity and schemas |
| `diagx redact-test [file]` | See transformation behaviour safely |
| `diagx collectors` | List collectors and declared capabilities |
| `diagx doctor` | Check the health of this DiagX installation |

## Repository layout

```
cmd/            CLI
internal/       consent, collection, transform, packaging, verification, ...
pkg/protocol/   canonical protocol types
collectors/     system, runtime, application, docker
spec/           JSON schemas, examples, RFCs
conformance/    conformance test vectors
testdata/       synthetic secret test corpus
examples/       broken demo application (DiagShop)
docs/           quickstart, protocol overview, threat model, security
```

## Building

Requires Go 1.22+.

```bash
go build -o diagx ./cmd/diagx
go test ./...
go test ./conformance/   # conformance suite
```

## Security

Read [SECURITY.md](SECURITY.md) and [docs/threat-model.md](docs/threat-model.md).
Report vulnerabilities privately; do not open public issues for security
problems.

## Roadmap

See [ROADMAP.md](ROADMAP.md). V0.1 is the protocol + reference CLI +
conformance. V0.2 adds the local viewer, signed requests and the first
existing-tool adapter. AI, cloud features, plugin marketplaces and
dashboards are explicitly out of scope for V0.1.

## License

Apache License 2.0 — see [LICENSE](LICENSE).

Contributions are governed by [CONTRIBUTING.md](CONTRIBUTING.md),
[GOVERNANCE.md](GOVERNANCE.md) and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
