# DiagX Protocol RFCs

This directory contains the Request-for-Comments that define and evolve the
DiagX diagnostic exchange protocol.

Protocol changes MUST go through an RFC. Implementations target a specific
protocol version; the CLI version is independent (see the product
specification, section 29).

## Status of the V0.1 core RFCs

| RFC | Title | Status |
| --- | --- | --- |
| [RFC-0001](rfc-0001-core-diagnostic-request.md) | Core Diagnostic Request | Accepted |
| [RFC-0002](rfc-0002-consent-model.md) | Consent Model | Accepted |
| [RFC-0003](rfc-0003-disclosure-receipt.md) | Disclosure Receipt | Accepted |
| [RFC-0004](rfc-0004-diagnostic-artifact-format.md) | Diagnostic Artifact Format | Accepted |
| [RFC-0005](rfc-0005-transformation-semantics.md) | Transformation Semantics | Accepted |
| [RFC-0006](rfc-0006-conformance-suite.md) | Conformance Suite | Accepted |
| [RFC-0007](rfc-0007-signed-requests.md) | Signed Requests | Draft (V0.2) |

## How to propose a change

1. Copy `rfc-template.md`.
2. Number it after the highest existing RFC.
3. Open a pull request. Discuss in review before implementation.
4. An accepted RFC that changes the wire format bumps the minor protocol
   version; a breaking change bumps the major version.
