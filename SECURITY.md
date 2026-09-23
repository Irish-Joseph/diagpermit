# Security Policy

## Supported Versions

| Version | Supported |
| --- | --- |
| V0.1.x (latest) | Yes |
| anything older | No |

## Reporting a Vulnerability

**Do not open a public issue for a security problem.**

Use GitHub's private vulnerability reporting for this repository, or email
the maintainers listed in GOVERNANCE.md.

We aim to acknowledge reports within 2 business days. Please include
reproduction steps and the affected version.

## Security-Relevant Defaults

- Network access disabled by default; arbitrary shell execution rejected
  in protocol 0.1.
- Symlink following disabled by default; file collectors bounded by
  allowed roots and size limits.
- Archive readers enforce entry-count and decompressed-size limits
  (decompression-bomb protection).
- Privacy transformations fail closed: a failed mandatory transformation
  produces no shareable artifact.
- No telemetry in V0.1.

## Privacy Wording

We do not claim that all secrets are removed. We record which configured
detectors and transformations executed successfully, and we always tell
users to review diagnostic content before sharing it. Integrity
verification never claims a privacy guarantee.
