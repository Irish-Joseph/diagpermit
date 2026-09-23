# Contributing

Thanks for helping improve DiagX. This project is in early development and
contributions are welcome.

## Ground rules

- Read [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) — be excellent to each other.
- Read [GOVERNANCE.md](GOVERNANCE.md) for how decisions are made.
- Protocol changes require an RFC (see `spec/rfcs/rfc-template.md`).
- Do **not** commit real credentials, real log excerpts or anything from an
  employer/client. The synthetic corpus in `testdata/secretcorpus/` must
  stay synthetic.
- Never weaken security defaults (network off, no shell, fail-closed
  transformations, symlink protection). Security-sensitive changes need
  explicit review.

## Development

```bash
go build -o diagx ./cmd/diagx   # build
go test ./...                    # unit + integration tests
go test ./conformance/           # conformance suite
go vet ./...
gofmt -l .                       # should print nothing
```

Fuzz targets exist for the transformation engine; a longer local run:

```bash
go test ./internal/transform/ -run TestNothing -fuzz FuzzApply -fuzztime 60s
```

## Pull requests

1. Small, focused PRs are easier to review.
2. New collectors/transformation detectors need tests, including a
   redaction regression test where relevant.
3. New conformance vectors must document the behavior they pin down.
4. Sign your commits (`git commit -s`) — we use the Developer Certificate
   of Origin instead of a CLA.

## Good first issues

Tagged `good first issue` / `help wanted`: additional runtime detectors,
platform hardening, conformance vectors, documentation improvements.
Critical cryptographic/security-core changes are not good first issues.
