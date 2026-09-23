# Protocol Overview

DiagX protocol version 0.1 defines one artifact chain with six documents.

## Documents

1. **DiagnosticRequest** (`request.json`) — what the requester declares it
   needs: capabilities with requirement states, hard policy limits, purpose,
   optional expiry and retention notice.
2. **ConsentDecision** — the user's per-capability approved/denied choices,
   with mode and timestamp.
3. **EffectiveDisclosurePlan** (`disclosure.json`) — the immutable logical
   plan (approved / denied / forbidden + network/shell switches) computed
   *before* collection. Hashed into the receipt.
4. **CollectionReport** (`collection.json`) — per-capability status
   (`success`, `partial`, `failed`, `skipped`, `denied_by_user`,
   `forbidden`, `unsupported`, `timed_out`, `size_limit_exceeded`).
5. **TransformationReport** (`reports/transformations.json`) — which
   detectors executed and how many values were transformed. Never contains
   original values.
6. **DisclosureReceipt** (`attestations/disclosure-receipt.json`) — ties the
   chain together with the hashes of request, plan and manifest.

## Hashing and canonicalization

Structured documents are hashed as `sha256:<hex>` of their **canonical
JSON**: keys sorted bytewise, compact serialization, numbers preserved as
written. This makes equivalent documents hash identically regardless of
pretty-printing or property order (spec section 31).

## Versioning

Protocol version and CLI version are independent (e.g. protocol `0.1`,
CLI `0.4.2`). Both use semantic versioning. Implementations MUST reject
unknown protocol versions. See the RFCs in `spec/rfcs/` for change rules.

## Local-first

V0.1 requires: no mandatory server, no account, no automatic cloud
synchronization, no automatic upload, no hidden telemetry. `diagx collect`
only creates a local artifact.

## What integrity verification covers

`diagx verify` checks: schema validity, manifest consistency, artifact
hashes, disclosure-plan hash, request hash, archive structure and (later)
optional signatures. It distinguishes **INTEGRITY VERIFIED** from a privacy
guarantee — which it never makes.
