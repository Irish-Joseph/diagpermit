# Local visual viewer

DiagPermit V0.2 adds a visual workflow without adding a cloud service. The Go
core remains authoritative; the embedded React/TypeScript application talks to
a temporary local Go server.

```bash
diagpermit ui
diagpermit ui diagpermit.yaml
diagpermit ui support-CASE-LOCAL.diagnostic
diagpermit ui signed-request.dsse.json --trust-store trust.json
```

The viewer supports request review, per-capability consent, immutable disclosure
planning, local collection and cancellation, transformation summaries,
deterministic findings, disclosure receipts, integrity checks, and safe package
file previews. Generated packages can be saved explicitly from the viewer.

## Local-only behavior

- Listens on `127.0.0.1` with a random port; it cannot be configured to bind a
  LAN or public address.
- Uses a random session URL and an HttpOnly, SameSite=Strict cookie.
- Loads all JavaScript and CSS from the DiagPermit binary.
- Makes no cloud, analytics, telemetry, CDN, or font request.
- Does not automatically upload or share a diagnostic package.
- Deletes its temporary working directory when the server stops.

Use `--no-open` when browser launching is undesirable. Stop the server with
Ctrl+C.

## Content inspection

Only files covered by the package manifest can be previewed. A preview must be
no larger than 256 KiB, valid UTF-8 text, free of NUL bytes, and have an
allow-listed textual media type or extension. Content is returned inside JSON
and displayed as text. HTML and scripts from a package are never executed.
