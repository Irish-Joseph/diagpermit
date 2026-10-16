# RFC-0001: Core DiagPermit protocol (0.1)

Status: Accepted — implemented in the reference CLI and validated by the
published conformance suite and JSON schemas.

## Scope

This RFC records the design decisions that define protocol 0.1 as shipped.
It is a description of the implemented protocol, not a proposal.

## Documents

The protocol defines nine canonical documents, each with a JSON schema in
[../schemas/](../schemas/):

- `DiagnosticRequest` — what the requester declares it needs, with
  per-capability constraints, hard policy limits, and an optional retention
  notice (a declaration only; never enforced on third parties).
- `Capability` — one declared capability with requirement
  (`required_for_case | optional | forbidden | not_requested`) and optional
  constraints (max lines/bytes, time window).
- `ConsentDecision` — the recorded user decision per capability, with the
  consent mode (`interactive | assumed | file | plan-preview`).
- `EffectiveDisclosurePlan` — the immutable approved/denied/forbidden plan
  computed before any collection. Its canonical hash is embedded in the
  disclosure receipt.
- `CollectorResult` / `CollectionReport` — what actually ran, with the nine
  defined statuses (success, partial, failed, skipped, denied_by_user,
  forbidden, unsupported, timed_out, size_limit_exceeded).
- `TransformationReport` — per-detector counts and actions only; never
  original sensitive values.
- `Manifest` — every artifact file with media type, size, SHA-256,
  collector identity/version, transformation and truncation status.
- `DisclosureReceipt` — binds request hash, plan hash, consent summary,
  collection enforcement flags, transformation summary, and manifest hash.
- `Finding` — deterministic, evidence-backed observations with severities
  `info | warning | error`. Findings are not vulnerability claims unless
  they truly are.

## Canonicalization and hashing

Structured documents are hashed over a canonical JSON form (sorted keys,
compact serialization, numbers preserved as written). Hashes are
`sha256:<hex>`. Equivalent documents must produce identical hashes.

## Consent semantics

- `required_for_case` grants the requester no bypass of the user.
- Consent is fail-closed: in file mode, anything not explicitly approved is
  denied; in interactive mode optional capabilities default to deny.
- The user may deny required capabilities; the denial is recorded and a
  warning is emitted.
- Forbidden capabilities are never collected, in any consent mode.
- Collectors execute against the approved `EffectiveDisclosurePlan`, never
  against the raw request.

## Artifact

The `.diagnostic` artifact is a ZIP package with the logical layout
`manifest.json`, `request.json`, `disclosure.json`, `collection.json`,
`data/`, `reports/`, and `attestations/` (disclosure receipt, and the
original DSSE request envelope when the request was signed).

## Privacy model

- Pattern-based transformations (drop, mask, replace, truncate, hash,
  pseudonymize) run locally before packaging.
- Mandatory transformation failure is fail-closed: no shareable artifact is
  produced.
- Pseudonyms are stable within one artifact via a random per-artifact salt.
- The project never claims that redaction guarantees removal of every
  secret. Integrity verification proves the package has not changed; it
  does not prove the package is safe to disclose.

## Security baseline

- Network access disabled by default; collectors must declare destination,
  protocol, and purpose before any network use.
- No arbitrary shell execution in protocol 0.1; runtime detection uses
  fixed executable + argument arrays with timeouts.
- Filesystem access is bounded (allowed root, size/line limits, symlink and
  special-file rejection, path-traversal protection).
- Archives are treated as hostile: traversal paths, duplicate entries, and
  decompression-bomb limits are rejected.

## Conformance

The `conformance/` suite is the portable definition of protocol behaviour.
Independent implementations should be able to run the same vectors.
