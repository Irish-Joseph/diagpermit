# Quickstart

## 1. Install

Build from source (Go 1.27.1+):

```bash
go build -o diagpermit ./cmd/diagpermit
```

Or download a release binary (with published checksums) from the releases
page.

## 2. Initialize

```bash
diagpermit init
```

Creates `diagpermit.yaml`. Edit it to declare exactly which capabilities your
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
diagpermit validate diagpermit.yaml
```

## 3. Plan

```bash
diagpermit plan
```

Shows every capability by requirement state, the network/shell switches and
the limits — without collecting anything.

## 4. Collect

```bash
diagpermit collect
```

You are shown the request and asked to approve each optional capability.
Denying a `required_for_case` capability is allowed; the denial is recorded
and a warning is stored in the artifact.

Non-interactive:

```bash
diagpermit collect --yes                              # approve all non-forbidden
diagpermit collect --consent consent.json             # {"approved":[...],"denied":[...]}
```

Only approved capabilities are collected, locally, under the request's
limits. Privacy transformations run before anything is packaged.

## 5. Inspect and verify

```bash
diagpermit inspect support-CASE-82341.diagnostic
diagpermit verify support-CASE-82341.diagnostic
```

`verify` recomputes every manifest hash, the request hash, the
disclosure-plan hash and the manifest hash, and checks archive structure and
schemas. It prints `INTEGRITY VERIFIED` or lists failures — and always
reminds you that integrity is **not** a privacy guarantee.

## 6. Try the demo

```bash
cd examples/broken-demo-app
docker compose up -d
docker compose stop database
mkdir -p logs
docker logs diagshop-api > logs/app.log
diagpermit plan && diagpermit collect --yes
diagpermit inspect support-*.diagnostic
```

The artifact should contain a `DATABASE_CONNECTIVITY_FAILURE` finding.
