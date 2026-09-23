# RFC-0007: Signed Requests

**Status:** Draft (target: V0.2)

## Summary

V0.1 permits unsigned diagnostic requests; they are displayed as
`Authenticity: NOT VERIFIED`. This RFC sketches signed requests for V0.2.

## Constraints

- Do NOT invent a proprietary signature envelope.
- Use established standards: in-toto Attestation Framework (statement,
  predicate, envelope, bundle layers), DSSE envelopes, and Sigstore-style
  bundles where practical.
- A signed request shows `Authenticity: VERIFIED` when the signature
  verifies against the requester's published key material.
- Signing is additive: unsigned artifacts remain valid.

## Open questions

- Key distribution and rotation for requester identities.
- Whether signatures cover the whole request document or a statement about
  it.
- Tooling for requester key management in the reference CLI.
