# Quickstart

## 1. Install

Build from source (Go 1.22+):

```bash
go build -o diagx ./cmd/diagx
```

Or download a release binary (with published checksums) from the releases
page.

## 2. Initialize

```bash
diagx init
```

Creates `diagx.yaml`. Edit it to declare exactly which capabilities your
support case needs:

```yaml
protocolVersion: "0.1"

request:
  id: CASE-82341

requester:
  organization: ExampleDB
  name: ExampleDB Support

purpose:
  code: database-connectivity
  description: Diagnose failed database connections

capabilities:
  system.os:
    requirement: required_for_case
  runtime.python.version:
    requirement: required_for_case
  docker.container_state:
    requirement: optional
  application.logs:
    requirement: optional
    constraints:
      maxLines: 500
  environment.values:
    requirement: forbidden
  filesystem.source_code:
    requirement: forbidden

policy:
  networkAccess: false
  arbitraryShellExecution: false
  maximumTotalBytes: 26214400
  maximumDurationSeconds: 60

local:
  applicationLogPath: ./logs/app.log
```

Validate:

```bash
diagx validate diagx.yaml
```

## 3. Plan

```bash
diagx plan
```

Shows every capability by requirement state, the network/shell switches and
the limits — without collecting anything.

## 4. Collect

```bash
diagx collect
```

You are shown the request and asked to approve each optional capability.
Denying a `required_for_case` capability is allowed; the denial is recorded
and a warning is stored in the artifact.

Non-interactive:

```bash
diagx collect --yes                              # approve all non-forbidden
diagx collect --consent consent.json             # {"approved":[...],"denied":[...]}
```

Only approved capabilities are collected, locally, under the request's
limits. Privacy transformations run before anything is packaged.

## 5. Inspect and verify

```bash
diagx inspect support-CASE-82341.diagnostic
diagx verify support-CASE-82341.diagnostic
```

`verify` recomputes every manifest hash, the request hash, the
disclosure-plan hash and the manifest hash, and checks archive structure and
schemas. It prints `INTEGRITY VERIFIED` or lists failures — and always
reminds you that integrity is **not** a privacy guarantee.

## 6. Try the demo

```bash
cd examples/broken-demo-app
docker compose up -d api          # the database stays stopped
# stop it: docker compose up -d api (db is configured not to start)
diagx plan && diagx collect --yes
diagx inspect support-*.diagnostic
```

The artifact should contain a `DATABASE_CONNECTIVITY_FAILURE` finding.
