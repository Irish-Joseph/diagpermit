# DiagPermit protocol examples

Copyable request and consent examples for protocol 0.1. The authoritative
shapes are the JSON schemas in [../schemas/](schemas/); these examples show
the YAML authoring form and the consent-file form used by
`diagpermit collect --consent`.

- [request-basic.yaml](request-basic.yaml) — minimal request with required,
  optional and forbidden capabilities.
- [request-diagshop.yaml](request-diagshop.yaml) — the DiagShop demo request
  (same as `examples/broken-demo-app/diagpermit.yaml`).
- [consent-basic.json](consent-basic.json) — consent file; anything not
  explicitly approved is denied (fail-closed).
