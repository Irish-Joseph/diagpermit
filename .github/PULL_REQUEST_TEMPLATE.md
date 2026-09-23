## What

One paragraph: what this PR changes and why.

## Type

- [ ] code
- [ ] protocol (RFC required: link it)
- [ ] docs
- [ ] tests / conformance
- [ ] security-sensitive (needs explicit security review)

## Testing

- [ ] `go test ./...` passes
- [ ] `go test ./conformance/` passes
- [ ] new behavior covered by tests
- [ ] redaction behavior: regression test added (if transformations touched)

## Checklist

- [ ] no security default weakened (network off, no shell, fail-closed, symlinks)
- [ ] no real credentials or real log content added
- [ ] commit signed off (`git commit -s`)
