# RFC-0006: Conformance Suite

**Status:** Accepted
**Protocol version:** 0.1

## Summary

A project that calls itself a protocol MUST provide a conformance suite.
`conformance/` contains numbered test vectors; each holds input files, the
expected normalized representation and the expected result.

## V0.1 vectors

```
01-basic-request
02-optional-denied
03-required-denied
04-transformations
05-corrupted-manifest
06-invalid-path
07-oversized-file
08-network-denied
09-unsupported-collector
10-hash-mismatch
```

## Rules

- Vectors must be runnable by independent implementations: inputs are data
  files, expectations are JSON.
- Where an outcome is deterministic (consent plan, statuses, redacted
  content, verification verdicts), the expected value is fixed.
- Non-deterministic values (timestamps, per-artifact pseudonym salts) are
  not asserted directly; their deterministic consequences (labels assigned
  by first occurrence, counts) are.
- The reference implementation runs the suite with `go test ./conformance/`.

## Adding vectors

New vectors are added by RFC. Each new vector must document the behavior it
pins down.
