# RFC-0001: Core Diagnostic Request

**Status:** Accepted
**Protocol version:** 0.1

## Summary

Defines the `DiagnosticRequest` document: the party asking for
troubleshooting data declares, in a structured and versioned way, which
diagnostic capabilities it needs, why, under what hard limits, and for how
long the request is valid.

## Motivation

"Send me your logs" gives the requester and the user no shared, verifiable
understanding of what is being collected. A structured request makes the
scope explicit and machine-checkable before anything runs.

## Requirements

- MUST identify itself with `protocolVersion`.
- MUST contain a stable `request.id`, a `requester` and a `purpose`.
- MUST declare `capabilities` as a map of capability-id to a `Capability`
  with one of the four requirement states.
- MUST contain a `policy` with `networkAccess` and
  `arbitraryShellExecution`, both of which MUST be `false` in protocol 0.1.
- MAY set `expiresAt` (RFC 3339); a client MUST refuse to collect from an
  expired request.
- MAY carry a `retentionNotice`, which is recorded but never enforced.

## Capability requirements

- `required_for_case` — the requester believes this is necessary; it does
  NOT grant permission to bypass the user.
- `optional` — the user chooses.
- `forbidden` — the requester explicitly will not collect this.
- `not_requested` — neutral; not collected.

## Compatibility

Implementations MUST reject unknown `protocolVersion` values. Unknown
capability ids are permitted (they may simply be `unsupported`).
