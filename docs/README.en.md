# C2 Signal

C2 Signal is a defensive, multi-engine artifact triage console. It routes uploaded files to the detector that understands their format, then presents the exact rules that fired in a compact analyst interface.

Current release: **v0.1.1** · License: **MIT**

[中文](../README.md)

## Docker operations

### Requirements

- Docker Engine or Docker Desktop.
- Docker Compose v2; verify it with `docker compose version`.
- Git, only when downloading the optional community rules.
- The first image build compiles Chainsaw and Suricata. Later builds reuse the Docker cache.

### Start the bundled rule set

```bash
git clone https://github.com/din4e/c2-signal.git
cd c2-signal
cp .env.example .env
make up
```

Open <http://127.0.0.1:8080>, then verify the service if needed:

```bash
./scripts/compose.sh ps
curl http://127.0.0.1:8080/api/v1/health
```

### Enable the full community rule set

```bash
make rules
make up
```

The pinned repositories are downloaded to the ignored `rulesets/` directory and mounted read-only. `scripts/compose.sh` automatically selects the rules overlay when those checkouts exist. Without them, bundled Cobalt Strike YARA and Suricata protocol-event rules remain available, but full Sigma EVTX detection does not.

### Common operations

| Operation | Command |
|---|---|
| Start in the background or apply configuration | `make up` |
| Show container status | `./scripts/compose.sh ps` |
| Follow scanner logs | `make logs` |
| Restart the scanner | `./scripts/compose.sh restart scanner` |
| Build the image | `make build` |
| Rebuild without cache | `./scripts/compose.sh build --no-cache scanner` |
| Remove containers and network | `make down` |
| Also permanently remove history and local YARA volumes | `./scripts/compose.sh down -v` |

`make down` preserves both persistent volumes. Use `down -v` only when their contents are no longer required.

### Address and port

Edit `.env`, then run `make up`:

```dotenv
C2_SIGNAL_BIND=127.0.0.1
C2_SIGNAL_PORT=8080
```

Values can also be overridden for one command:

```bash
C2_SIGNAL_PORT=18080 make up
C2_SIGNAL_BIND=0.0.0.0 make up
```

Do not expose the second form to an untrusted network. The API has no authentication and includes rule-management endpoints. Use firewall restrictions and an authenticated TLS reverse proxy for shared deployments.

### Update and rebuild

```bash
git pull --ff-only
make build
make up
```

Community rules use revisions pinned by the project. When those pins change, remove the existing `rulesets/` directory only after confirming it contains nothing you need, then run `make rules` again.

### Persistent data and limits

- `scanner-data` stores scan history and result JSON.
- `yara-local` stores YARA managed through the browser.
- Uploaded artifacts are deleted after scanning by default.
- The container defaults to 2 CPUs, 2 GB RAM and 256 PIDs. Uploads are limited to 100 MB, with two concurrent scans and a 180-second scan timeout.
- For failures, inspect `./scripts/compose.sh ps` and `make logs`; change `C2_SIGNAL_PORT` when the host port is occupied.

## Interface

### Detection console

![C2 Signal detection console](assets/dashboard.png)

### Cobalt Strike findings

Each result includes detector status, SHA-256, grouped findings, severity and rule provenance.

![Cobalt Strike detection result](assets/detection-result.png)

### Exact YARA rule location

Open a matched YARA rule to inspect its source file at the exact declaration and line number.

![YARA source viewer](assets/rule-source-viewer.png)

### Local YARA management

Create, edit, validate, enable and disable local rules from the browser.

![Local YARA rule manager](assets/yara-manager.png)

## What it does

| Input | Engine | Detection content |
|---|---|---|
| Binaries, archives and documents | YARA | Bundled local rules plus optional community repositories |
| Windows EVTX | Chainsaw | Optional SigmaHQ rules |
| PCAP / PCAPNG | Suricata | Local rules (incl. `nocturneldr-payload.rules`) plus Suricata protocol-event rules |

Key capabilities:

- Asynchronous uploads with SHA-256, media-type and executable-format identification.
- Dedicated Cobalt Strike Beacon, BOF and decoded-configuration triage rules.
- Dedicated NocturneLdr (BYOUD stack spoofing, EAF bypass, Zilean sleep obfuscation) triage rules.
- Persistent scan history with result deletion.
- Click-through YARA source viewer with exact rule-line highlighting.
- Browser-based local YARA editing, validation, enable/disable and hot reload.
- Next.js static frontend served by a small Go API.
- Rootless, read-only Docker runtime with dropped capabilities and resource limits.

Uploaded artifacts are never executed. A clean result means only that the loaded rules did not match; it is not a safety verdict.

## Rule repositories

`scripts/fetch-rules.sh` installs reviewed, pinned revisions under the ignored `rulesets/` directory. Those repositories are not redistributed as part of C2 Signal. See [THIRD_PARTY.md](../THIRD_PARTY.md) for sources and license boundaries.

The application remains usable without community rules:

- Local Cobalt Strike and NocturneLdr YARA ship in the image.
- Local YARA created in the UI persists in the `yara-local` volume.
- Suricata retains its built-in protocol-event rules.
- EVTX hunting is unavailable until Sigma rules are installed.

## Architecture

```text
Browser
  └─ Go HTTP API / static server
       ├─ ordinary artifact ── YARA
       ├─ Windows EVTX ─────── Chainsaw + Sigma
       └─ PCAP / PCAPNG ───── Suricata

Persistent Docker volumes
  ├─ scanner-data  scan result JSON
  └─ yara-local    analyst-managed YARA
```

The Next.js application uses static export; Node.js is not present in the runtime image.

## API

```text
GET    /api/v1/health
GET    /api/v1/rules
GET    /api/v1/scans?limit=30
POST   /api/v1/scans
GET    /api/v1/scans/{id}
DELETE /api/v1/scans/{id}
GET    /api/v1/scans/{id}/rule?name={yara_rule}
GET    /api/v1/yara/rules
GET    /api/v1/yara/rules/{name}
PUT    /api/v1/yara/rules/{name}
PATCH  /api/v1/yara/rules/{name}/enabled
```

Uploads use `multipart/form-data` with field name `file` and return `202 Accepted` plus a scan ID.

## Configuration

| Variable | Default | Purpose |
|---|---:|---|
| `C2_SIGNAL_BIND` | `127.0.0.1` | Host address published by Compose |
| `C2_SIGNAL_PORT` | `8080` | Host port published by Compose |
| `MAX_UPLOAD_BYTES` | `104857600` | Maximum upload size |
| `SCAN_TIMEOUT_SECONDS` | `180` | Per-scan timeout |
| `MAX_CONCURRENT_SCANS` | `2` | Concurrent scan limit |
| `KEEP_UPLOADS` | `false` | Keep uploaded artifacts after scanning |
| `HISTORY_DIR` | `/data/history` | Persistent result directory |
| `HISTORY_LIMIT` | `200` | Maximum retained scan records |
| `MANAGED_YARA_ROOT` | `/rules/yara/local` | UI-managed YARA directory |
| `YARA_ROOTS` | `/rules/yara` | Colon-separated YARA roots |
| `SIGMA_ROOT` | `/rules/sigma` | Sigma rule root |
| `SURICATA_RULE_ROOTS` | `/rules/suricata:/opt/suricata/share/suricata/rules` | Colon-separated Suricata roots |

## Development

Frontend:

```bash
cd frontend
npm ci
npm run build
```

Backend:

```bash
cd backend
go test ./...
go run ./cmd/server
```

The local Go process requires YARA, Chainsaw and Suricata on `PATH` to execute scans. Unit tests do not require all engines.

## Security

Read [SECURITY.md](../SECURITY.md) before deploying or reporting a vulnerability. Malicious parser inputs still create risk even though artifacts are not executed. Production deployments should use an isolated host or VM, egress controls, authentication, TLS and request quotas.

## Contributing

See [CONTRIBUTING.md](../CONTRIBUTING.md). Detection contributions must include provenance, test material that is safe to redistribute, and an explicit license. Release history is recorded in [CHANGELOG.md](../CHANGELOG.md).

## License

C2 Signal is released under the [MIT License](../LICENSE). The bundled Source Han Sans subset remains under its upstream license in `frontend/public/fonts/LICENSE.txt`; optional downloaded rule repositories retain their own licenses.
