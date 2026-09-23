# RFC-0005: Transformation Semantics

**Status:** Accepted
**Protocol version:** 0.1

## Summary

Defines the privacy transformation engine: detector categories, the six
transformations, stable pseudonymization and the fail-closed model.

## Transformations

`drop`, `mask`, `replace`, `truncate`, `hash`, `pseudonymize`.

## Default ruleset

The built-in ruleset `diagx-default-0.1` covers, in order: private-key
material (drop), database connection credentials (mask), authorization
headers (mask), JWT-like values (mask), GitHub-style tokens (mask), cloud
credential patterns (mask), password assignments (mask), common API-token
patterns (mask), hostnames / IPv4 / IPv6 (pseudonymize), MAC addresses
(pseudonymize), email addresses (pseudonymize), home-directory usernames
(mask).

Detectors are regular expressions executed by Go's RE2 engine, which
guarantees linear-time matching (no catastrophic backtracking / ReDoS).

## Stable pseudonymization

Pseudonyms are stable within one artifact using a random per-artifact salt:
the same value maps to the same label (host-a, host-b, user-a, mac-a...)
everywhere in that artifact; different values map to different labels with
overwhelming probability.

## Fail-closed model

If a mandatory transformation fails for any reason, the run is aborted and
NO shareable artifact is produced. The failure names the collector, the
transformer and the reason.

## No false guarantee

The transformation report records which configured detectors and
transformations executed successfully and how many values were transformed.
It never contains the original values. It MUST NOT be presented as a
guarantee that all secrets are removed.
