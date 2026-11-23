# Sentra SIEM — Operator Guide

Audience: the engineers who install, run, back up and upgrade the SIEM engine on the organisation's own servers.
Companion documents: [ONBOARDING.md](ONBOARDING.md) (adding log sources), [RULES.md](RULES.md) (detections),
[PARALLEL-RUN.md](PARALLEL-RUN.md) (running next to LogRhythm), `ARCH.md` (the technical contract).

---

## 1. Architecture

```
 log sources                         SIEM server (Ubuntu 22.04/24.04)                                   analysts
 ───────────                         ─────────────────────────────────────────────────────────────     ────────
 FortiGate / Cisco / CEF ─ syslog ──► :5514 udp/tcp, :6514 tls ┐
 Linux (rsyslog)         ─ syslog ──►                           │  sentra-siem.service (Node.js, user sentra-siem)
 Windows (SentraAgent)      ─ HTTPS ───► nginx :443 /ingest/ ─────►│  parse → enrich → detect → alerts/cases
 HTTPS JSON senders      ─ HTTPS ───►                           │           │                │
                                                                │           ▼                ▼
                                     /var/lib/sentra-siem/spool ◄──┤  batch writer ──► ClickHouse (127.0.0.1:8123)
                                     (ClickHouse down)          │                    siem.events / batches /
                                                                │                    stats_minute / alerts
                                     /var/lib/sentra-siem/state ◄──┘  alerts, cases, rules, audit (JSON journals)
                                                                   API 127.0.0.1:9120 ◄── nginx /api/soc/ ◄── portal
                                                                                           (auth_request)     (SOC pages)
```

* **One process** (`sentra-siem.service`) runs collectors, parsers, the real-time rule engine, scheduled searches, the
  SOC workflow (alerts, cases, playbooks) and the HTTP API. Node.js standard library only — no npm packages.
* **ClickHouse** stores every normalised event (`siem.events`, 12 months by default), the integrity ledger
  (`siem.batches`), per-minute source statistics and a copy of alerts for reporting. It listens on 127.0.0.1 only.
* **State** (alerts, cases, rules changes, suppressions, audit trail) lives in append-only JSON-lines journals with
  periodic snapshots under `/var/lib/sentra-siem/state` — small, easy to back up, no extra database.
* **Back-pressure**: when ClickHouse is unavailable, batches go to `/var/lib/sentra-siem/spool` (bounded, default 2 GB)
  and are replayed oldest-first; detection keeps running in memory the whole time.
* **Integrity**: every batch written gets a SHA-256 chained to the previous batch (`siem.batches`) — tamper evidence
  for auditors.
* **Access**: nothing listens publicly except what nginx exposes. `/api/soc/*` requires a portal session
  (`auth_request /auth/verify`, which supplies `X-Auth-User` / `X-Auth-Role`); `/ingest/*` requires a per-source token.
  Roles: viewer < analyst < operator < admin (writes need operator; rule changes need admin; every write is audited).

### Files and directories

| path | owner / mode | contents |
|---|---|---|
| `/opt/sentra-siem/` | root, 755/644 | code (`engine/`, `install/`, `docs/`, `agents/`), read-only for the service |
| `/opt/sentra-siem.prev/` | root | previous version after an upgrade (rollback) |
| `/etc/sentra-siem/config.json` | sentra-siem, 600 (dir 700) | configuration (listeners, sources, retention, enrichment) |
| `/etc/sentra-siem/secrets.json` | sentra-siem, 600 | ClickHouse password, ingest tokens — never printed by any tool |
| `/etc/sentra-siem/tls/` | sentra-siem, 600 | syslog-TLS certificate and key |
| `/etc/default/sentra-siem` | root, 644 | `NODE_BIN`, `NODE_OPTIONS` (heap), `SENTRA_SIEM_LOG_LEVEL` |
| `/var/lib/sentra-siem/state/` | sentra-siem, 750 | journals `*.jsonl`, snapshots `*.snap.json`, `audit-YYYYMM.jsonl`, `chain.json` |
| `/var/lib/sentra-siem/spool/` | sentra-siem | batches waiting for ClickHouse |
| `/var/lib/sentra-siem/intel/` | sentra-siem | IOC lists (`*.txt`, `*.csv`) for the `intel` rule operator (hot-reloaded) |
| `/var/lib/clickhouse/` | clickhouse | event data |
| `/etc/systemd/system/sentra-siem.service` | root | unit (hardened: `ProtectSystem=strict`, no capabilities, only `/var/lib/sentra-siem` writable) |
| `/usr/local/sbin/sentra-siem-token` | root | ingest token helper |

Logs of the engine are JSON lines on stdout → journald: `journalctl -u sentra-siem -f`.

### Ports

| port | bound to | purpose |
|---|---|---|
| 5514 udp+tcp | 127.0.0.1 (staging) / LAN IP (`--listen-lan`) | syslog (RFC 3164/5424, octet-counting or LF framing) |
| 6514 tcp | same, off by default | syslog over TLS |
| 9120 tcp | 127.0.0.1 only | engine API + `/ingest/` (reached through nginx) |
| 8123, 9000, 9009 tcp | 127.0.0.1 only | ClickHouse HTTP / native / interserver |
| 443 tcp | nginx | portal, `/api/soc/`, `/ingest/` |

Firewall rule list for collectors: [agents/network/README.md](../agents/network/README.md#firewall-rules-for-the-collector).

---

## 2. Installation

Prerequisites: Ubuntu 22.04 or 24.04, Node.js ≥ 20 (on the portal server: `/opt/sentra-ai/node/bin/node`),
root access, nginx already serving the portal with an internal `/auth/verify` location, outbound package access (or an
internal mirror) for the ClickHouse packages.

```bash
tar xzf sentra-siem-<version>.tar.gz && cd sentra-siem

# 1. ClickHouse (LTS, localhost-only, memory-capped, password in /etc/sentra-siem/secrets.json) + engine:
sudo ./install/install.sh --with-clickhouse --node-bin /opt/sentra-ai/node/bin/node

# on a dedicated collector that receives syslog from the LAN:
sudo ./install/install.sh --with-clickhouse --listen-lan            # or --listen-lan 10.10.5.20
```

What `install.sh` does (idempotent — re-running it is also the upgrade path):

1. checks Node ≥ 20, creates the system user `sentra-siem` (no shell, no home),
2. creates `/opt/sentra-siem`, `/var/lib/sentra-siem/{state,spool}`, `/etc/sentra-siem` (700) and copies the code (the
   previous version is kept in `/opt/sentra-siem.prev`),
3. creates or merges `secrets.json` (ClickHouse password, ingest tokens for `--tokens`, default `win-servers win-dc`),
4. runs `install/ch-install.sh` when `--with-clickhouse` is given and ClickHouse is missing,
5. writes a default `config.json` if none exists (listeners on 127.0.0.1; `--listen-lan`, `--syslog-port`,
   `--tls-cert/--tls-key` are applied explicitly),
6. installs the systemd unit (adds `CAP_NET_BIND_SERVICE` only if a listener port is < 1024), `/etc/default/sentra-siem`
   and `sentra-siem-token`,
7. runs `node engine/store/migrate.js` (creates/updates the ClickHouse schema and TTL),
8. starts the service, waits for the API port, prints the next steps.

Then wire nginx (once):

```bash
sudo cp /opt/sentra-siem/install/nginx-soc-http.conf /etc/nginx/conf.d/sentra-siem-http.conf   # rate-limit zones (http{})
# inside the portal's HTTPS server { } block:
#     include /opt/sentra-siem/install/nginx-soc.conf;
sudo nginx -t && sudo systemctl reload nginx
```

`nginx-soc.conf` exposes `/api/soc/` behind `auth_request /auth/verify` (identity headers are taken from the auth
response only), `/api/soc/tail` unbuffered for Server-Sent Events, and `/ingest/` without session auth (token checked
by the engine, 6 MB body limit, 20 req/s per IP with burst 200, `429` on excess).

### Syslog over TLS

```bash
# certificate issued by the the organisation internal CA, SAN = the name/IP devices use
sudo ./install/install.sh --tls-cert siem-syslog.crt --tls-key siem-syslog.key     # enables syslog.tls on 6514
```

Distribute the issuing CA to senders (rsyslog `--ca`, FortiGate CA store). The Windows agent uses nginx's HTTPS
certificate — it must chain to a CA trusted by the Windows hosts (push the CA by GPO).

### Configuration reference (`/etc/sentra-siem/config.json`)

Only keys that differ from the built-in defaults are needed; the full defaults are in `engine/config.js`.

| key | default | meaning |
|---|---|---|
| `node_name` | hostname | shown in health, written to the integrity ledger |
| `timezone` | `Asia/Riyadh` | "today" boundaries in reports |
| `api.host` / `api.port` | 127.0.0.1 / 9120 | keep on 127.0.0.1 |
| `syslog.host` | 127.0.0.1 | listener address (LAN IP on collectors) |
| `syslog.udp/tcp.port`, `.enabled` | 5514, true | plain syslog |
| `syslog.tls` | `{enabled:false, port:6514, cert, key, ca, request_cert:false}` | TLS listener (`request_cert` = require client certs) |
| `syslog.tz_offset_min` | 180 | zone assumed for RFC 3164 timestamps without zone |
| `ingest.max_mb` / `max_decompressed_mb` | 5 / 20 | HTTPS ingest body limits |
| `clickhouse.url` / `database` | http://127.0.0.1:8123 / siem | user/password come from secrets.json |
| `retention_days` | 365 | ClickHouse TTL (see §4) |
| `spool_max_mb` | 2048 | disk spool bound; oldest segments are dropped when full |
| `writer.batch_size` / `flush_ms` | 5000 / 1000 | ClickHouse insert batching |
| `sources[]` | [] | `{id, type, match:{ip|cidr}, tz_offset_min?, silent_after_s?}` — see ONBOARDING.md |
| `enrich.assets[]` | [] | `{ip, host?, tags?[]}` — fills host names, adds tags such as `dc`, `crown-jewel` |
| `enrich.admin_users[]` | [] | user names tagged `admin` (used by admin-activity rules) |
| `detect.rules_dir` | built-in pack | directory of rule JSON files |
| `tail.max_clients` | 20 | concurrent live-tail streams |
| `lr_rule_map`, `lr_match_window_s` | {}, 900 | parallel-run comparison (PARALLEL-RUN.md) |
| `m365.enabled`, `lr.enabled` | false | pull collectors — **phase 2, not implemented yet** (they only log a notice) |

Apply changes with `sudo systemctl restart sentra-siem` (a restart takes a few seconds; syslog-TCP senders and agents
reconnect/retry, UDP packets sent during the restart are lost). Validate first:

```bash
sudo -u sentra-siem SENTRA_SIEM_CONFIG=/etc/sentra-siem/config.json /opt/sentra-ai/node/bin/node \
  -e "require('/opt/sentra-siem/engine/config.js').loadConfig(); console.log('config ok')"
```

### Ingest tokens

```bash
sudo sentra-siem-token list                   # source ids with a token
sudo sentra-siem-token show win-servers       # prints only the token (pipe it into a file for deployment)
sudo sentra-siem-token add win-dmz --type windows   # new token + sources[] entry
sudo sentra-siem-token rotate win-servers     # new value; redeploy to the agents
sudo sentra-siem-token revoke win-old
sudo systemctl restart sentra-siem            # tokens are read at start
```

One token per source id (a group of hosts of the same kind), not per host. Tokens are 256-bit random hex, compared
in constant time.

---

## 3. Sizing

The engine (Node, single process) is sized for **5,000 EPS sustained** with bursts to 20,000 EPS absorbed by the
spool, on 4 vCPU / 16 GB. **Storage is the real driver.** Planning figures (replace them with measured values after a
week — query below):

| sustained EPS | events / day | ClickHouse / day (≈150 B/event) | 90 days | 365 days | suggested server |
|---:|---:|---:|---:|---:|---|
| 100 | 8.6 M | ~1.3 GB | ~0.12 TB | ~0.5 TB | 4 vCPU, 8 GB (can share the portal host) |
| 500 | 43 M | ~6.5 GB | ~0.6 TB | ~2.4 TB | 4 vCPU, 16 GB |
| 1,000 | 86 M | ~13 GB | ~1.2 TB | ~4.7 TB | 8 vCPU, 32 GB |
| 2,500 | 216 M | ~32 GB | ~2.9 TB | ~12 TB | 8–16 vCPU, 64 GB, dedicated ClickHouse disks |
| 5,000 | 432 M | ~65 GB | ~5.8 TB | ~24 TB | 16 vCPU, 64 GB; consider 90–180 days hot + archive |

* Bytes per event vary by source: Windows events (with `EventData` + message) and FortiGate traffic logs are the
  largest; `raw` is kept with ZSTD(3). Keep ~20 % free disk for merges, plus the spool (2 GB default).
* ClickHouse on the shared portal host is capped at 2.5 GB RAM (`ch-install.sh`); on a dedicated server raise
  `max_server_memory_usage` in `/etc/clickhouse-server/config.d/sentra-siem.xml`.
* Engine heap: `NODE_OPTIONS=--max-old-space-size=1536` in `/etc/default/sentra-siem`; raise to 4096 on busy collectors
  with many threshold/distinct rules.
* Measure real usage:

```sql
SELECT table, sum(rows) AS rows, formatReadableSize(sum(data_compressed_bytes)) AS on_disk,
       round(sum(data_compressed_bytes) / sum(rows)) AS bytes_per_row
FROM system.parts WHERE database = 'siem' AND active GROUP BY table;

SELECT src_id, sum(events) / 86400 AS avg_eps FROM siem.stats_minute
WHERE minute >= now() - INTERVAL 1 DAY GROUP BY src_id ORDER BY avg_eps DESC;
```

ClickHouse has two users and no `default` user:

| User | Used by | Rights |
| --- | --- | --- |
| `sentra_siem` (`secrets.json` → `clickhouse`) | the engine at runtime | SELECT and INSERT on `siem.*` only, so stored events cannot be altered or deleted through the engine |
| `sentra_siem_admin` (`secrets.json` → `clickhouse_admin`) | `engine/store/migrate.js`, backups (FREEZE), restores, uninstall | all rights on `siem.*` |

Run ClickHouse queries as root with a client config holding the password (never on the command line). Use the
engine user for queries; switch `['clickhouse']` to `['clickhouse_admin']` only for maintenance such as FREEZE or restore:

```bash
sudo install -d -m 700 /root/.clickhouse-client
sudo python3 - <<'PY'
import json
s = json.load(open('/etc/sentra-siem/secrets.json'))['clickhouse']
open('/root/.clickhouse-client/config.xml', 'w').write(
  '<config><user>%s</user><password>%s</password></config>\n' % (s['user'], s['password']))
PY
sudo chmod 600 /root/.clickhouse-client/config.xml
sudo clickhouse-client -q "SELECT count() FROM siem.events WHERE ts > now() - INTERVAL 1 HOUR"
```

---

## 4. Retention

* `retention_days` in `config.json` (default 365) is applied as a ClickHouse TTL on `siem.events` and
  `siem.stats_minute`. After changing it run the migration (it only issues `MODIFY TTL` when the value changed —
  that rewrites metadata and may trigger merges, run it off-peak):

```bash
cd /opt/sentra-siem && sudo -u sentra-siem SENTRA_SIEM_CONFIG=/etc/sentra-siem/config.json \
  "$(sed -n 's/^NODE_BIN=//p' /etc/default/sentra-siem)" engine/store/migrate.js
```

* Partitions are daily (`toYYYYMMDD(ts)`); expired data is removed by background merges, whole days at a time.
* One retention for all sources. If regulation requires longer retention for some sources, export them to the
  archive (below) before the TTL removes them.
* Workflow state (alerts, cases, audit) is **not** subject to the TTL — it stays in `/var/lib/sentra-siem/state`.
* Check what is kept: `SELECT min(ts), max(ts) FROM siem.events`.

### Archive export (cold storage)

Daily export of the previous day to compressed files on the archive volume (run from root's crontab at 02:30):

```bash
#!/bin/bash
# /usr/local/sbin/sentra-siem-archive  - export yesterday's events + ledger, verify, keep checksums
set -euo pipefail
D=$(date -d yesterday +%F); OUT=/srv/siem-archive/$D; mkdir -p "$OUT"
clickhouse-client -q "SELECT * FROM siem.events  WHERE toDate(ts) = '$D' FORMAT Native" | zstd -q -T0 -o "$OUT/events.native.zst"
clickhouse-client -q "SELECT * FROM siem.batches WHERE toDate(ts) = '$D' FORMAT JSONEachRow" | zstd -q -o "$OUT/batches.jsonl.zst"
clickhouse-client -q "SELECT count() FROM siem.events WHERE toDate(ts) = '$D'" > "$OUT/rowcount"
(cd "$OUT" && sha256sum ./* > SHA256SUMS)
```

Restore an archived day for an investigation into a separate table:
`zstd -dc events.native.zst | clickhouse-client -q "INSERT INTO siem.events_restore FORMAT Native"`
(create `siem.events_restore` with `CREATE TABLE siem.events_restore AS siem.events` and drop the TTL:
`ALTER TABLE siem.events_restore REMOVE TTL`).

---

## 5. Backup and restore

| what | how often | how | notes |
|---|---|---|---|
| `/etc/sentra-siem/` | on change + daily | `tar` → encrypted backup store | contains secrets — encrypt (e.g. `gpg --symmetric` / backup tool encryption) |
| `/var/lib/sentra-siem/state/` | hourly or daily | `tar` while running is fine | journals are append-only, snapshots are atomically renamed; a torn last line is ignored on load |
| ClickHouse `siem.*` | daily (+ archive above) | `ALTER TABLE … FREEZE` or `BACKUP` | back up `siem.batches` with `siem.events` (integrity ledger) |
| `/opt/sentra-siem`, nginx snippets | per release | the release tarball | reproducible |

State backup (small, seconds):

```bash
sudo tar czf /backup/sentra-siem-state-$(date +%F-%H%M).tgz -C /var/lib/sentra-siem state
sudo tar czf - -C / etc/sentra-siem | gpg --symmetric --cipher-algo AES256 -o /backup/sentra-siem-etc-$(date +%F).tgz.gpg
```

ClickHouse — hard-link snapshot (instant, no extra space until parts change), then copy off-host:

```bash
sudo clickhouse-client -q "ALTER TABLE siem.events FREEZE WITH NAME 'daily'"
sudo clickhouse-client -q "ALTER TABLE siem.batches FREEZE WITH NAME 'daily'"
sudo clickhouse-client -q "ALTER TABLE siem.alerts FREEZE WITH NAME 'daily'"
# snapshot is under /var/lib/clickhouse/shadow/daily/ ; copy it (rsync) to the backup server, then:
sudo clickhouse-client -q "ALTER TABLE siem.events UNFREEZE WITH NAME 'daily'"     # (also batches, alerts)
```

(ClickHouse's `BACKUP DATABASE siem TO Disk('backups', 'siem-<date>')` is an alternative once a `backups` disk is
configured in `/etc/clickhouse-server/config.d/`.)

**Restore** on a rebuilt server: install the same release with `install.sh --with-clickhouse --no-start`, restore
`/etc/sentra-siem` (keep `secrets.json` — the ClickHouse password must match what `ch-install.sh` configured; re-run
`install/ch-install.sh` after restoring secrets so the ClickHouse user gets that password), restore
`/var/lib/sentra-siem/state`, run the migration, copy the frozen parts into `/var/lib/clickhouse/data/siem/<table>/detached/`
and `ALTER TABLE siem.<table> ATTACH PARTITION …` (or `RESTORE` for `BACKUP` archives), then
`systemctl start sentra-siem`. Test a restore at least once before go-live and after major upgrades.

---

## 6. Upgrades

```bash
tar xzf sentra-siem-<new>.tar.gz && cd sentra-siem
sudo ./install/install.sh                     # keeps config/secrets/state, migrates schema, restarts
journalctl -u sentra-siem -n 50 --no-pager       # "starting" line shows the version
```

* From the engineer's Windows PC (on the VPN), `scripts\sync.ps1` does all of the above in one step and keeps the PC,
  GitHub and the server on the same commit: pull, commit + push local changes, run the tests, package the commit,
  copy it over SSH, run `install.sh`, and verify `/opt/sentra-siem/VERSION`. `-Status` only reports; `-Rollback` runs the
  rollback below.
* Schema migrations are additive (new tables/columns; TTL only when `retention_days` changed), so the previous code
  version keeps working against an upgraded schema.
* **Rollback**: `sudo systemctl stop sentra-siem && sudo mv /opt/sentra-siem /opt/sentra-siem.bad && sudo mv /opt/sentra-siem.prev
  /opt/sentra-siem && sudo systemctl start sentra-siem`.
* Built-in rule packs ship with the code (`engine/detect/rules/`). Local tuning is stored as overrides in the state
  journal and survives upgrades; an upgraded built-in rule keeps your override until you reset it (RULES.md).
* Node.js upgrade: install the new runtime, then `sudo ./install/install.sh --node-bin /new/path/node`.
* ClickHouse upgrade: stay on the LTS channel (`apt-get install --only-upgrade clickhouse-server clickhouse-client`),
  one LTS step at a time; the engine spools while ClickHouse restarts.
* Windows agent upgrade: re-run `install-agent.ps1` on the hosts (keeps config, token and bookmarks).

---

## 7. Health checks

Daily (or from monitoring):

```bash
systemctl is-active sentra-siem clickhouse-server
curl -s http://127.0.0.1:9120/api/soc/health | python3 -m json.tool | head -40   # local only; portal: SIEM Log Source Health
journalctl -u sentra-siem --since -1h -p warning --no-pager | tail -20
df -h /var/lib/clickhouse /var/lib/sentra-siem
```

`/api/soc/health` → what to look at:

| field | healthy | if not |
|---|---|---|
| `status` | `ok` | `degraded` = ClickHouse unreachable or spool not empty |
| `clickhouse.ok` | true | `systemctl status clickhouse-server`, disk space, `/var/log/clickhouse-server/clickhouse-server.err.log` |
| `spool.pending_bytes` | 0 (brief spikes ok) | growing = ClickHouse down/slow; at `spool_max_mb` the oldest data is dropped |
| `eps.avg_1m` | your normal range | sudden drop = sources silent (check Sources page) |
| `writer` | no errors, low queue | persistent queue = ClickHouse too slow (disk, merges, memory cap) |
| `pipeline` / `detector` | no stage errors | rule errors are logged with the rule id |
| `collectors.http.auth_failures` | 0 | an agent with a wrong/rotated token |

Sources page (portal: **SIEM Log Source Health**, which also shows engine health; API `GET /api/soc/sources`): every configured source with last seen, EPS (1 min /
1 h), events today, parse-error rate and status `ok | silent | errors`. `silent` = nothing for `silent_after_s`
(default 900 s; Windows agents send a heartbeat every 5 minutes); `errors` = > 20 % of the last hour's lines unparsed.

Integrity ledger linkage (each batch must reference the previous batch's hash, per node):

```sql
SELECT count() AS broken_links FROM (
  SELECT node, seq, prev_sha256, lagInFrame(sha256) OVER (PARTITION BY node ORDER BY seq
         ROWS BETWEEN 1 PRECEDING AND CURRENT ROW) AS expected, row_number() OVER (PARTITION BY node ORDER BY seq) AS rn
  FROM siem.batches) WHERE rn > 1 AND prev_sha256 != expected;
```

Detection check (after upgrades / rule changes, and monthly as SAMA evidence): `sudo sentra-siem-validate live` sends
labelled synthetic attacks for every rule and reports PASS / FAIL per rule (one-time `sudo sentra-siem-validate setup`
first). End-to-end tests from real test machines: docs/VALIDATION.md.

Suggested monitoring alerts: service not active; `status != ok` for > 10 min; free disk < 20 %; spool > 25 % of
its maximum; any configured source `silent` for > 1 h; ClickHouse `system.errors` growing.

---

## 8. Troubleshooting

| symptom | checks |
|---|---|
| service does not start | `journalctl -u sentra-siem -n 100`; config validation command (§2); `ls -l /etc/sentra-siem` (owner sentra-siem, 600); Node path in the unit (`systemctl cat sentra-siem`) |
| `EADDRINUSE` | another process on the port: `ss -lntup | grep -E '5514|6514|9120'` (rsyslog configured as a receiver on the same port?) |
| `EACCES` binding a port | port < 1024 without the capability drop-in — re-run `install.sh --syslog-port <port>` |
| device sends but nothing arrives | `tcpdump -ni any port 5514 -c 20`; host firewall (`ufw status`); `syslog.host` still 127.0.0.1?; device source IP matches `sources[].match` |
| events land under `syslog-udp`/`syslog-tcp` instead of the device's id | the packet source IP differs from `match.ip` (NAT, other interface) — check `host_ip` in search results |
| high parse-error rate | Sources page → source → sample unparsed lines (`action:unparsed AND src_id:<id>`); wrong `type`, custom log format, or non-default device format (e.g. FortiGate `csv`) |
| wrong timestamps (3 h off) | device without zone (RFC 3164/Cisco): set `tz_offset_min` on the source; device clock/NTP |
| Windows host silent | on the host: `C:\ProgramData\SentraAgent\logs\agent.log` (`TrustFailure`, `401`, unreachable); `state.json` `next_attempt`; nginx access log for `POST /ingest/` status codes |
| agents get 401 | token rotated/revoked, or engine not restarted after `sentra-siem-token add` |
| agents get 413 | nginx `client_max_body_size` smaller than 6m in another included config |
| agents get 429 | `sentra_ingest` rate — raise the zone rate or burst for WEC/NAT addresses |
| spool growing | ClickHouse down, disk full, or memory cap hit (`max_server_memory_usage`); `clickhouse-client -q "SELECT * FROM system.errors ORDER BY last_error_time DESC LIMIT 5"` |
| searches slow / time out (60 s cap) | narrow the time range, add field filters (`src_type:`, `event_code:`); check merges `SELECT * FROM system.merges` |
| live tail stops after a while | nginx must use `nginx-soc.conf`'s `/api/soc/tail` block (buffering off); `tail.max_clients` reached |
| too many alerts from one rule | RULES.md → tuning (suppression, exclusions, thresholds); noisy rules: SIEM SOC Overview / `GET /api/soc/metrics` |
| memory growth | `heap_mb` in health; many high-cardinality `group_by` rules — raise heap or tighten rules; restart is safe (state is journaled) |

Collect a support bundle (no secrets):

```bash
sudo bash -c 'mkdir -p /tmp/sentra-bundle && cd /tmp/sentra-bundle &&
  journalctl -u sentra-siem --since -24h > engine.log;
  curl -s http://127.0.0.1:9120/api/soc/health > health.json;
  curl -s http://127.0.0.1:9120/api/soc/sources > sources.json;
  cp /etc/sentra-siem/config.json .; systemctl cat sentra-siem > unit.txt; df -h > df.txt;
  tar czf /tmp/sentra-bundle.tgz -C /tmp sentra-bundle && echo /tmp/sentra-bundle.tgz'
```

---

## 8a. After-hours mode

The organisation works official hours (the business-hours calendar, default Sun–Thu 08:00–17:00 Riyadh) with no night shift.
The engine raises alerts 24/7; after-hours mode (`engine/afterhours/`) makes sure a person hears about the ones that matter.
Portal: **SOC → Threat Intel & After-hours → After-hours mode**.

| Step | What happens |
|---|---|
| Page | An alert first raised **outside working hours** at or above the page severity (default high) is e-mailed once to `page.to` plus tonight's on-call rota entry. Storm guard: at most `max_per_hour` pages; the rest are **held** and listed in the brief. Quiet rules are raised and briefed, never paged. |
| Escalate | Nobody acknowledged it within `escalate_after_min` → paged to `escalate_to`. Acknowledging = the alert's own Acknowledge / take ownership (the e-mail links to the portal, sign-in required; there are no token links). |
| Prepare | `off` / `shadow` (record only) / `prepare`: opens a case with the alert's playbook, so its containment steps are **approval requests** waiting in Playbooks & Approvals. Nothing is executed - the engine never executes actions, and only a named person can approve. At most `max_per_night` cases. |
| Brief | Each working day at `brief.at`: end of the previous working day → now (Sunday's covers the weekend). Alerts raised after hours, pages sent / failed / held / escalated, cases prepared, approvals waiting, and **Needs you today**. If the engine was down at brief time the day is recorded as *missed*, never mailed late. |

Switching the mode on stamps the time: only alerts raised **after** it are handled - the backlog is never paged. Mail uses the
SMTP relay configured for the Attack Summary schedules (Reports). Settings: admin; runs, briefs and settings: operator and
admin (they name people and hosts); viewer sees status only. Every change, page, escalation and brief is in the audit log.
API: `{prefix}/after-hours/mode/{status,config,runs,briefs,briefs/<day>,brief-now,test-page}`. Config `afterhours.portal_url`
(default: `https://<portal_host of the brand setting>/dashboards`) is the link base in the e-mails; `afterhours.scheduler: false` stops the timer.
Suggested rollout: on, containment **shadow** for a week, read the briefs, then **prepare**.

## 8b. Data Loss Prevention and Email / Phishing Analysis

**DLP** (`engine/reports/dlp.js`, page **Endpoint & Email → Data Loss Prevention**) reads the incidents the SIEM already
normalises (`action = 'dlp-incident'`, `fields.dlp_*`): Somansa Privacy-i / Mail-i / Server-i (source type `somansa`) and
Forcepoint / Symantec / Trend Micro DLP over CEF; DLP agent disabled = `agent-tamper` with `vendor_class = dlp`.
*Let through* = the product permitted or released the data. An action the product did not send is *not reported*, never assumed.
Person risk is an itemised weighted sum (data let through, sensitive classes, high severity, channels, after hours, volume,
agent disabled) - behavioural indicators, not proof (PDPL). Viewer: totals, channels, policies and classes only; names,
devices, destinations, the drill-down, CSV and report are operator / admin and audited. API `{prefix}/dlp/{summary,events,
events.csv,report.html,schedule,send-now}`; the weekly / monthly report is e-mailed through the Reports SMTP relay
(`dlp.scheduler: false` stops it). Continuous monitoring of employees needs a PDPL impact assessment (Art. 22).

**Email / Phishing Analysis** (page `email-analysis.html`) parses a pasted message or `.eml` in the browser; only the
sender / reply domains, link hosts and origin IP go to `POST {prefix}/intel/check`, which answers which indicator lists hold
them (reference lists apart, not counted as hits, audited by count). "Open a case" creates a case with `PB-PHISHING`.

## 8c. Database Dashboard (DBA alert center)

`engine/db-audit/dba-alerts.js`, page **Databases → Database Dashboard** (`db-dashboard.html`). Evaluates every 5 minutes the
Oracle readings the SIEM already holds (collector agent and the platform's read-only pass): availability (instance, listener,
no reading), space (tablespaces incl. days to full, TEMP, UNDO, FRA, ASM, server file systems), load (sessions, limits, blocking,
long queries), protection (backup age / failure, archive lag / destination, Data Guard lag) and alert-log ORA- errors (catalogue of
common codes with what to check; the platform reads `V$DIAG_ALERT_EXT` hourly - grant in `install/oracle-monitor-account.sql`).
Thresholds: defaults → per database → `*/TABLESPACE` → `DATABASE/TABLESPACE`; changes need an administrator or the DBA approver
(scope `eng:dba`) and a reason, audited. Critical → one e-mail per check to the DBA list, re-sent every `renotify_h` until
acknowledged; warnings → daily digest (or at once); spikes must last 10 min before mail; snooze (reason), maintenance windows
(mail only), recovery mail. A reading that stops arriving keeps its problem open (stale), never a silent clear.
API `{prefix}/db/dba/*`; `dba.scheduler: false` stops the timer. Mail uses the Reports SMTP relay.

## 8d. ManageEngine Applications Manager

`engine/integrations/me-apm.js`, Database Dashboard → **Applications Manager** tab. Admin sets the APM address (https) and a
REST API key (APM → Settings → REST API; use an Operator user that sees the database monitors - a key sees only its user's
monitors). The key is stored sealed in secrets.json (`integrations.me_apm.api_key`), never returned or logged, and scrubbed
from errors. Only six documented calls are ever made: ListMonitor, ListAlarms, GetMonitorData (read), PollNow, UnmanageMonitor,
ManageMonitor (control) under `/AppManager/json/`. **VERIFY** the JSON shape on the customer's APM build with *Test connection*;
a build that answers only XML is reported as "did not answer JSON". Poll now = operator, at once. Maintenance (Unmanage with
hours, alerts suppressed by default) and Resume (Manage) = a request decided by a different person - an administrator or the
approver of the monitor's area (database monitors `eng:dba`, others `infra`); service / AI identities never decide. Thresholds
and actions inside APM are not changed from here (no API relied on). Coverage compares APM's database monitors with the
dashboard by name / host text (a lead to verify). `me_apm_scheduler: false` stops the timer.

## 9. Security notes

* Keep the API on 127.0.0.1. The engine trusts `X-Auth-User` / `X-Auth-Role` on requests from loopback (that is how
  nginx passes the portal identity), so any process on the server that can reach 127.0.0.1:9120 can act as any role —
  limit shell access on the SIEM/portal server to administrators.
* `secrets.json` and `config.json` are 600 and owned by `sentra-siem`; backups of `/etc/sentra-siem` must be encrypted.
* The service runs without capabilities, with a read-only view of the system except `/var/lib/sentra-siem`
  (`systemd-analyze security sentra-siem` ≈ 1.7 "OK").
* The audit journal (`state/audit-YYYYMM.jsonl`) records every write through the API (who, role, IP, action, target);
  include it in backups and forward a copy off-host if auditors require immutability.
* No data leaves the server: there is no telemetry; outbound connections only for enabled pull collectors (M365,
  LogRhythm — phase 2) and package updates.
