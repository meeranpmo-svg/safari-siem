# Architecture

```
 Browser (portal, signed in through the portal's /auth/verify)
   │  https://<portal>/dashboards/<page>.html      static pages + ui/vendor/*.js (no inline scripts: strict CSP)
   │
   ├── /api/itam/...  ── nginx ──► sentra-itam   node backend/itam/engine/main.js   127.0.0.1:9150
   │                                 │  store collections (JSON journal)   /var/lib/sentra-itam
   │                                 │  sealed credential vault (Asset Discovery)
   │                                 │  Python readers: pyengine/run.py, discovery/inv-helper.py (credentials on stdin)
   │                                 └─► devices / platforms, read-only: vCenter, Nutanix Prism, NetBackup, Veeam,
   │                                     Cohesity, storage arrays, Oracle (dictionary views), AD, ManageEngine, …
   │
   └── /api/soc/...   ── nginx ──► sentra-siem   node backend/siem/engine/main.js   API 127.0.0.1:9120
                                     │  state (journal + audit-YYYYMM.jsonl)   /var/lib/sentra-siem
                                     │  ClickHouse database "siem"            (events, metrics)
                                     └─◄ syslog 5514 (UDP/TCP), 6514 (TLS), HTTP ingest  ◄── collector kits (agents/)
```

## Components

| Component | Folder | Runs as | What it owns |
|---|---|---|---|
| Portal pages | `ui/` | static files in `/var/www/sentra/dashboards` | screens only, no data; every number comes from an API |
| Menu | `ui/vendor/zyb-nav.js` | loaded by every page | the one list of pages: menu, home page, search, breadcrumb |
| Asset engine | `backend/itam/engine` | systemd `sentra-itam` | assets, discovery, databases, backup, virtualization, storage, licences, GRC, AI engineers' ITAM side |
| SIEM engine | `backend/siem/engine` | systemd `sentra-siem` | log collection and search, detections, alerts, cases, UEBA, XDR, network / server change plans, audit trail, DBA mail relay |
| Collector kits | `backend/siem/agents`, `backend/itam/agent` | installed by hand on client machines | Windows / Linux / Exchange / Oracle / network log shipping, endpoint inventory |
| Installers | `backend/*/install` | run by `deploy/server/update-server.sh` | each module installs itself and rolls back on failure |

Which page uses which module and which data: **docs/CODEMAP.md** (a snapshot).

## Request path, one example

`Backup Coverage` (`ui/backup.html`) → `GET /api/itam/backup` → `backend/itam/engine/backup.js` → store collections
`backup_platforms`, `backup_objects`, `backup_settings`, `backup_exempt`, `assets` (+ `virt_capacity` and `disc_devices`
to name VMs backed up under their UUID). A sync reads NetBackup / Veeam / Cohesity through `backup-sources.js` (or its
Python twin `pyengine/backup_sources.py`), GET only.

## Rules the code keeps (do not break them)

* **Read-only towards customer systems.** Collectors and readers only read; anything that changes a system is a request
  approved by a named person (four-eyes: never the requester, never a service or AI identity) and is audited.
* **Credentials** are sealed in the vault, travel to helpers on stdin only, never in argv, logs or the browser.
* **Never fabricate data.** A value that was not read is shown as *not reported*, never as 0 or "OK".
* **Roles**: viewer < analyst < operator < admin, checked by the engine on every route, not by the page.
* **Every change of state is audited** (who, when, from where) in the engine's audit trail.
* **Pages**: no inline event handlers or inline scripts (the build moves scripts out; CSP `script-src 'self'`); every value
  that reaches the page is escaped.
* **PDPL**: customer data never leaves the server; this tree holds code only.

## Deployment

`deploy/build-package.sh` packs the update and `deploy/server/update-server.sh` installs it.
A fresh server is installed with `backend/itam/install/install.sh` and `backend/siem/install/install.sh`, then the update package.
