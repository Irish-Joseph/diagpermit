# RFC-0003: Disclosure Receipt

**Status:** Accepted
**Protocol version:** 0.1

## Summary

Every diagnostic artifact MUST contain a disclosure receipt. It answers four
questions:

1. **What was requested?** — `request.id` and `request.hash` (SHA-256 of the
   canonical JSON of the stored `request.json`).
2. **What did the user approve?** — `consent.approved` / `consent.denied`,
   plus the hash of the effective disclosure plan
   (`disclosurePlanHash`).
3. **What actually ran?** — `collection` (network/shell enforcement flags,
   start/complete times).
4. **What was ultimately packaged?** — `artifact.manifestHash` (SHA-256 of
   the canonical JSON of `manifest.json`).

## Location

`attestations/disclosure-receipt.json` inside the artifact.

## Verification

`diagx verify` recomputes `request.hash`, `disclosurePlanHash` and
`artifact.manifestHash` from the artifact contents and compares them to the
receipt. Mismatches fail integrity verification.

## Privacy disclaimer

The receipt and the integrity verification prove the package has not changed
according to the verification model. They do NOT prove that no sensitive
information remains inside. Implementations MUST NOT claim a privacy
guarantee.
