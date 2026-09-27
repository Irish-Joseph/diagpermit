# Collecting logs from another application

DiagPermit does not connect to an application, cluster, or cloud account. It
does not run a shell command on your behalf. The application log collector
reads only the local text file named in `local.applicationLogPath`, after the
user has approved the `application.logs` capability.

This boundary is deliberate: you choose and review the source material before
DiagPermit reads it, collection stays local, and nothing is uploaded.

## Option 1: use an existing local log file

Run DiagPermit from a project or support-case directory and point the request
at a log file inside that directory:

```yaml
capabilities:
  application.logs:
    requirement: optional
    constraints:
      maxLines: 500
      maxBytes: 1048576

local:
  applicationLogPath: ./logs/application.log
```

```bash
diagpermit plan
diagpermit collect
```

Relative paths are resolved from the directory where DiagPermit is running.
The file must stay inside that directory, must be a regular file, and must not
be a symbolic link. Only the bounded tail is collected.

## Option 2: export logs, then collect the export

When the source is Docker, Kubernetes, systemd, or another log service, first
use that platform's normal tooling to create a local text file. Review it, then
point DiagPermit at that file.

### Docker

macOS/Linux:

```bash
mkdir -p logs
docker logs --since 1h my-container > logs/application.log 2>&1
```

Windows PowerShell:

```powershell
New-Item -ItemType Directory -Path .\logs -Force | Out-Null
docker logs --since 1h my-container 2>&1 | Set-Content .\logs\application.log
```

Docker container state is separate. Add `docker.container_state` to the
request if the container list and status are also relevant.

### Kubernetes

```bash
mkdir -p logs
kubectl logs deployment/my-app --since=1h --all-containers=true > logs/application.log
```

### Linux systemd

```bash
mkdir -p logs
journalctl -u my-app --since "1 hour ago" --no-pager > logs/application.log
```

### Windows Event Log

Export only the events needed for the support case:

```powershell
New-Item -ItemType Directory -Path .\logs -Force | Out-Null
Get-WinEvent -LogName Application -MaxEvents 500 |
  Format-List TimeCreated,ProviderName,Id,LevelDisplayName,Message |
  Out-File .\logs\application.log -Encoding utf8
```

These commands are examples you run yourself. They are not executed by
DiagPermit, and their platform credentials and access controls remain outside
DiagPermit.

## Review before sharing

During collection, DiagPermit applies its privacy transformations before the
package is created and records transformation counts in the disclosure
receipt. This reduces accidental disclosure; it is not a guarantee that every
sensitive value has been found.

Before sending a `.diagnostic` package:

1. Use `diagpermit plan` or the local viewer to confirm the requested scope.
2. Keep `maxLines` and `maxBytes` as small as the support case allows.
3. Open the finished package with `diagpermit inspect` or the local viewer.
4. Run `diagpermit verify` to check its structure and integrity.
5. Share it yourself through a channel you trust. DiagPermit never uploads it.

Never commit real customer logs, credentials, diagnostic packages, or
employer-confidential information to a public repository.
