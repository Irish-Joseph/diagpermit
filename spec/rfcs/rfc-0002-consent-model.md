# RFC-0002: Consent Model

**Status:** Accepted
**Protocol version:** 0.1

## Summary

Defines how a user's explicit consent is obtained and recorded, and how it
combines with the request to produce the immutable `EffectiveDisclosurePlan`.

## Consent states

Every capability receives one user decision: `approved` or `denied`.

- `required_for_case` — approved by default but the user MAY deny. A denial
  MUST be recorded and MUST produce a warning that the requester may lack
  enough information.
- `optional` — the user chooses; the reference CLI defaults to deny when
  prompting.
- `forbidden` — never collected, regardless of any decision.
- `not_requested` — not collected.

## Modes

- `interactive` — the user is asked directly.
- `assumed` — non-interactive approval of all non-forbidden capabilities
  (explicit `--yes`).
- `file` — decisions read from a JSON file; capabilities not listed are
  denied (consent is fail-closed).

## Effective Disclosure Plan

Before any collection, the client computes an immutable plan:

- `approved`, `denied`, `forbidden` (sorted),
- `networkAccess`, `shellExecution` (both false in 0.1).

A hash of this plan is embedded in the disclosure receipt. Collectors MUST
only run for `approved` capabilities and MUST respect the plan's global
switches.
