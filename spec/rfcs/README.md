# DiagPermit Protocol RFCs

Protocol changes to the DiagPermit protocol (the documents, hashes, consent
semantics, artifact layout, and verification model described by the JSON
schemas in [../schemas/](../schemas/)) go through this lightweight RFC
process. Internal implementation changes that do not change protocol
behaviour do not require an RFC.

## Process

1. **Propose** — open a GitHub issue or draft RFC file describing the
   problem, the change, and its compatibility impact.
2. **Discuss** — maintainers and the community review. Breaking changes
   require an explicit migration note.
3. **Accept** — an accepted RFC records the decision and the protocol
   version it applies to.
4. **Implement** — the reference CLI, schemas, and conformance vectors are
   updated in the same or a linked change. Conformance vectors must pass
   before the change is released.

## Compatibility rules

- The protocol version and the CLI version are independent.
- Protocol 0.1 documents are strict: unknown fields are rejected by the
  reference implementation.
- A new protocol minor version may add optional fields; breaking changes
  require a new protocol version and new conformance vectors.
- Protocol 0.1 artifacts must remain readable (integrity-verifiable) by
  later CLI versions.

## Index

| RFC | Title | Status |
| --- | --- | --- |
| [RFC-0001](rfc-0001-core-protocol.md) | Core protocol: request, consent, plan, artifact, verification, transformations, conformance | Accepted (protocol 0.1, implemented) |
| [RFC-0002](rfc-0002-signed-requests.md) | Signed diagnostic requests (DSSE + Ed25519, local trust policy) | Accepted (implemented in the reference CLI) |
