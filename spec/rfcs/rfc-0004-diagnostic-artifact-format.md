# RFC-0004: Diagnostic Artifact Format

**Status:** Accepted
**Protocol version:** 0.1

## Summary

Defines the logical structure of a `.diagnostic` artifact. The V0.1
physical storage is ZIP; the logical structure is defined independently so a
future version may use another archive format.

## Logical structure

```
manifest.json
request.json
disclosure.json
collection.json
data/
  system/
  runtime/
  application/
  docker/
reports/
  transformations.json
  warnings.json
  findings.json
attestations/
  disclosure-receipt.json
```

## Rules

- `manifest.json` records every file except the disclosure receipt itself:
  logical path, media type, byte size, SHA-256 digest, collector identifier,
  collector version, collection timestamp, transformation status,
  truncation status.
- `request.json` is the canonical JSON of the request.
- `disclosure.json` is the canonical JSON of the effective disclosure plan.
- Archive entries MUST be relative forward-slash paths; path traversal,
  absolute paths and parent references are rejected.
- Readers MUST enforce bounds on entry count and decompressed size
  (decompression-bomb protection).
- All data files under `data/` are produced after privacy transformations.
