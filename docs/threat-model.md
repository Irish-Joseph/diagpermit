# Threat Model

DiagPermit is a security-sensitive tool: it reads local files, runs typed
collectors, applies privacy transformations and packages the result. This
document states what we assume an attacker may control and how the
reference implementation protects against it.

## Assets

- **User privacy** — the primary asset. Sensitive values in collected data
  must not reach the artifact when a detector is configured for them.
- **Integrity of the disclosure chain** — the request, plan, collection
  report, transformation report, manifest and receipt must be internally
  consistent and tamper-evident.
- **The user's machine** — the tool must not become a remote-execution or
  data-exfiltration vector via a crafted request file.

## Threats and mitigations

We assume an attacker may control: request files, diagnostic logs, file
names, archive contents, plugin output, configuration, malformed
JSON/YAML and remote URLs.

| Threat | Mitigation |
| --- | --- |
| Command injection | No arbitrary shell execution in V0.1. `policy.arbitraryShellExecution=true` is rejected. Collectors execute fixed binaries with fixed argument arrays, never `/bin/sh -c`. |
| Directory traversal | File collectors use an allowed root; `fsafety` rejects `..` escapes and absolute paths outside the root. |
| Symlink attacks | `followSymlinks=false` by default; every path component is checked. |
| Special files / devices / named pipes | Only regular files are read. |
| Massive / oversized logs | Per-file and total byte limits, line limits; `size_limit_exceeded`. |
| ReDoS | Detectors use Go's RE2 (linear time). User patterns compile under the same engine; unparseable mandatory patterns fail closed. |
| ZIP bombs / decompression bombs | Archive readers enforce entry-count and decompressed-size limits. |
| Archive traversal (zip slip) | Entry names must be relative forward-slash paths; `..`, absolute and backslash names are rejected on read and write. |
| Manifest tampering | SHA-256 over every file; receipt hashes the manifest, request and plan; `diagpermit verify` recomputes all three. |
| Request substitution / malicious request | Requests are validated; unknown protocol versions rejected; network disabled by default; collectors declare capabilities; unsigned requests are shown as `Authenticity: NOT VERIFIED`. |
| Network exfiltration | `networkAccess` defaults to false; network-capable collectors are blocked unless the plan (and, later, the user) allows a declared destination/protocol/purpose. |
| Script injection (viewer) | The future viewer treats all content as hostile: HTML escaping, strict CSP, no script execution from diagnostic files, no remote images by default, restricted local binding. |
| Memory / CPU exhaustion | Size and duration limits on collection; bounded archive reads. |
| Malicious file names | Names are validated; only the logical path is stored in the manifest. |

## What we do NOT protect against

- A user who approves a capability and then shares the artifact.
- Sensitive values that no configured detector recognizes. This is why the
  project never claims a privacy guarantee and always tells users to review
  content before sharing.
- The behaviour of third parties after they receive an artifact
  (retention notices are recorded, not enforced).

## Fail-closed

If a mandatory privacy transformation fails, collection stops safely and no
shareable artifact is produced. Silent packaging of unprocessed material is
a bug, not a feature.
