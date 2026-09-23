# DiagShop — broken demo app for DiagPermit

A deliberately broken reference application: a small API that cannot reach
its database because the database container is stopped.

## The scenario

```
database container: stopped
api container:      running, logging "database connection refused"
```

## Run the broken state

Start everything, then stop the database:

```bash
docker compose up -d
docker compose stop database
```

Then confirm the app is sick:

```bash
curl -s http://localhost:8090/
# {"app":"diagshop","database":"down","message":"cannot reach the database"}
```

The API log now contains lines like:

```
2026-09-24T00:00:00Z ERROR database connection refused (database:5432): ...
```

## Collect diagnostics

Copy the API log locally (or point `applicationLogPath` at a mounted log):

```bash
mkdir -p logs
docker logs diagshop-api > logs/app.log
```

Then run DiagPermit with the provided request:

```bash
diagpermit plan
diagpermit collect --yes
diagpermit inspect support-DIAGSHOP-1.diagnostic
diagpermit verify support-DIAGSHOP-1.diagnostic
```

The artifact should contain:

- `data/docker/containers.json` — the database container state (exited)
- `data/application/logs.txt` — the connection-refused log lines
- a finding `DATABASE_CONNECTIVITY_FAILURE` ("Application cannot connect
  and a container is not running.")

## Fix the app (and re-verify the clean state)

```bash
docker compose start database
```

Re-collect: the finding disappears and the log shows a healthy connection.
