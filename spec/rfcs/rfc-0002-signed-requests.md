# RFC-0002: Signed diagnostic requests

Status: Accepted — implemented in the reference CLI (`diagpermit request
keygen | sign | verify`).

## Decision

Request authenticity uses the **DSSE envelope format** with **Ed25519**
signatures over the canonical request JSON, with the DSSE v1
pre-authentication encoding:

```
DSSEv1 <len(payloadType)> <payloadType> <len(payload)> <payload>
```

Payload type: `application/vnd.diagpermit.request.v0.1+json`.

This is an established envelope standard (used by in-toto and Sigstore),
not a proprietary signature format. Future work may add Sigstore-style
bundles and in-toto predicate layers without changing the envelope
semantics.

## Trust is separate from validity

Signature validity and requester trust are reported independently:

| Status | Meaning |
| --- | --- |
| `UNSIGNED` | No signature; collection is still allowed. |
| `SIGNATURE NOT VERIFIED` | Envelope present, but no matching local key. |
| `SIGNATURE INVALID` | A local key matched, but no signature verified. |
| `SIGNATURE VALID — IDENTITY NOT TRUSTED` | Signature valid, local policy does not trust the key for the named requester. |
| `REQUESTER VERIFIED` | Signature valid and local trust policy matches. |

A valid signature is never presented as organizational trustworthiness, and
an unknown key is never mislabeled as a bad signature.

## Artifact binding

When a signed request initiates collection, the original DSSE envelope is
stored byte-for-byte at `attestations/request.dsse.json`, and verification
checks that the envelope payload hashes to the same value as the stored
`request.json`.
