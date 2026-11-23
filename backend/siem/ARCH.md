# Sentra SIEM/SOC engine — architecture contract (v1)

Custom SIEM engine for the organisation, installed on **the organisation's own servers** (Ubuntu 22.04/24.04,
data stays in the Kingdom). Runs **in parallel with LogRhythm** during validation, then replaces it.
Everything is our code except the data store (**ClickHouse**, open source, Apache-2.0) and Node.js (≥ 20).
**No npm dependencies** in the engine (Node standard library only; ClickHouse is reached over its HTTP interface with `fetch`).
Workflow state (alerts, cases, rules, sources, suppressions, audit) lives in the engine's own JSON-lines store
(`state/` directory, append-only journals + periodic snapshots) — small, transactional enough, no extra database.

```
 sources ──► collectors ──► parse/normalise ──► enrich ──► detect (real-time rules) ──► alerts ──► SOC workflow (cases, playbooks)
 (syslog UDP/TCP/TLS,        (parsers/*.js)     (geo-less,  │                                        ▲
  HTTPS ingest, Windows        common schema     asset/user  └──► batch writer ──► ClickHouse (events, 12+ months, TTL)
  agent, M365 pull,                               lookups,              │                ▲
  LogRhythm alarms)                               threat intel)         └──► spool/ (disk) when ClickHouse is down
                                                                         scheduled searches ──┘   search/tail/stats API ◄── portal (nginx auth_request)
```

## Directory layout (`sentra-siem/`)
- `engine/` — `main.js` (starts everything), `config.js`, `log.js`
- `engine/collect/` — `syslog.js` (UDP 514, TCP 514 incl. octet-counting framing, TLS 6514), `http-ingest.js` (HTTPS/HTTP POST NDJSON or JSON array, per-source token), `m365.js` (Graph sign-ins + directory audits pull), `lr.js` (LogRhythm alarm pull/receive for the parallel-run comparison)
- `engine/parse/` — `index.js` (router: picks parser by source type / content sniffing), one file per format: `rfc3164.js`, `rfc5424.js`, `linux.js` (auth, sudo, sshd, systemd, kernel), `webaccess.js` (nginx/apache combined), `fortigate.js` (key=value), `cef.js`, `leef.js`, `windows.js` (events from our Windows agent), `json.js` (generic), `m365.js`, `cisco.js` (IOS/ASA basics)
- `engine/store/` — `clickhouse.js` (HTTP client, parameterised queries, JSONEachRow inserts), `schema.sql`, `writer.js` (batching, spool, integrity chain), `spool.js`
- `engine/detect/` — `engine.js` (real-time rule engine), `rules/` (built-in rule pack JSON), `sigma.js` (Sigma YAML → native rule), `yaml.js` (minimal YAML parser for Sigma), `scheduled.js` (scheduled search rules), `intel.js` (IOC lists)
- `engine/soc/` — `state.js` (journal store), `alerts.js`, `cases.js`, `playbooks.js`, `metrics.js` (MTTD/MTTR, SLA)
- `engine/api/` — `server.js` (HTTP API on 127.0.0.1:9120, behind nginx), `query.js` (query language → ClickHouse SQL with parameters)
- `agents/windows/` — `sentra-agent.ps1` (+ install script); `agents/linux/` — rsyslog forwarding snippet
- `install/` — `install.sh`, systemd units, nginx snippet, ClickHouse users/config
- `tests/` — unit tests (node --test) + a replay tool that feeds **clearly labelled synthetic test lines** into a local engine (tests only; never shipped as data)
- `docs/` — operator guide, onboarding a log source, rule writing

## Normalised event (one row in ClickHouse `siem.events`)
| field | type | notes |
|---|---|---|
| `ts` | DateTime64(3,'UTC') | event time (from the log; falls back to receive time) |
| `rts` | DateTime64(3,'UTC') | receive time |
| `id` | UUID | engine-assigned |
| `src_type` | LowCardinality(String) | `linux`, `nginx`, `fortigate`, `windows`, `cef`, `leef`, `json`, `m365`, `cisco`, `syslog` |
| `src_id` | LowCardinality(String) | configured source id (e.g. `fw-hq-01`) |
| `collector` | LowCardinality(String) | `syslog-udp`, `syslog-tcp`, `syslog-tls`, `http`, `agent`, `m365`, `lr` |
| `host`, `host_ip` | String | reporting device |
| `category` | LowCardinality(String) | `authentication`, `network`, `web`, `process`, `iam`, `malware`, `file`, `registry`, `dns`, `system`, `policy`, `email`, `cloud`, `other` |
| `action` | LowCardinality(String) | normalised verb, e.g. `logon`, `logon-failed`, `logoff`, `user-created`, `group-member-added`, `process-start`, `connection`, `blocked`, `allowed`, `http-request`, `service-installed`, `audit-log-cleared`, `ips-detection`, `av-detection`, `sudo`, `config-change` |
| `outcome` | LowCardinality(String) | `success`, `failure`, `unknown` |
| `severity` | UInt8 | 0 info … 4 critical (source severity mapped) |
| `user`, `target_user`, `domain` | String | lower-case user names |
| `src_ip`, `dst_ip` | String | IPv4/IPv6 as text ('' when absent) |
| `src_port`, `dst_port` | UInt16 | |
| `proto` | LowCardinality(String) | |
| `process`, `parent_process`, `cmdline`, `hash` | String | |
| `url`, `http_method`, `http_status` (UInt16), `user_agent` | | |
| `dns_query` | String | |
| `event_code` | String | vendor event id (Windows EventID, FortiGate logid, CEF signature id …) |
| `message` | String | short human summary |
| `tags` | Array(LowCardinality(String)) | e.g. MITRE ids from parsers, `internet`, `admin` |
| `fields` | Map(String,String) | every other parsed key/value (vendor specific) |
| `raw` | String CODEC(ZSTD(3)) | original line / record |

ClickHouse: `MergeTree PARTITION BY toYYYYMMDD(ts) ORDER BY (src_type, host, ts) TTL toDateTime(ts) + INTERVAL {retention_days} DAY`,
skip indexes: `tokenbf_v1` on `raw` and `message`, `bloom_filter` on `user`, `src_ip`, `dst_ip`, `hash`, `event_code`.
Also `siem.batches` (integrity chain: batch id, time, rows, sha256 of the batch's NDJSON, previous batch hash) and
`siem.stats_minute` (SummingMergeTree: minute, src_id, src_type, events, bytes, parse_errors).

Internal JS event object = same field names; `ts`/`rts` as epoch milliseconds in memory; missing strings `''`, numbers `0`.

## Parser contract
`module.exports = { name, sniff(line, meta) → bool, parse(line, meta) → event-partial | null }` where `meta = { collector, src_id, src_type?, peer_ip, rts }`.
The router fills defaults (`id`, `rts`, `host_ip = peer_ip`, `ts = rts` if absent, `raw = line`, `outcome='unknown'`, `category='other'`),
counts parse errors per source, and never drops an event: an unparsed line becomes `src_type` of the source, `action='unparsed'`, `raw` kept.

## Rule format (native, JSON; Sigma is converted into this)
```json
{ "id": "SENTRA-AUTH-001", "name": "Brute force against one account", "enabled": true, "severity": 3,
  "mitre": ["T1110"], "description": "…", "author": "…", "version": 1,
  "type": "single" | "threshold" | "distinct" | "sequence",
  "match": { "all": [ { "field": "action", "op": "eq", "value": "logon-failed" } ], "any": [], "none": [] },
  "group_by": ["user"], "window_s": 300, "count": 10,          // threshold
  "distinct_field": "user", "distinct_count": 10,              // distinct (e.g. password spray: one src_ip, many users)
  "steps": [ {"match": …}, {"match": …} ], "by": ["user"],     // sequence: step 1 then step 2 within window_s, same `by` values
  "suppress_s": 3600,                                          // one alert per group per suppression window
  "fields_in_alert": ["user","src_ip","host"] }
```
Ops: `eq`, `neq`, `in`, `contains`, `startswith`, `endswith`, `re` (case-insensitive), `exists`, `gt`, `gte`, `lt`, `lte`, `cidr`, `intel` (value = IOC list name).
Field paths: top-level schema fields or `fields.<key>`.

## Alert object (engine state, also mirrored to ClickHouse `siem.alerts` for search/reporting)
`{ id, rule_id, rule_name, severity, mitre[], ts_first, ts_last, count, group: {k:v}, sample_event_ids[], summary, status: new|acknowledged|in-progress|closed-true-positive|closed-false-positive|closed-benign, assignee, case_id, notes[{at,by,text}], history[{at,by,action,detail}] }`

## Case object
`{ id: "CASE-000123", title, severity, status: open|investigating|contained|eradicated|recovered|closed, owner, alerts[], timeline[{at,by,kind,text}], evidence[{at,by,name,ref}], playbook_id, tasks[{id,title,done,by,at}], sla: {ack_due, resolve_due}, created, closed, resolution }`

## API (engine, 127.0.0.1:9120; nginx exposes it under `/api/soc/` with the portal's session check → headers `X-Auth-User`, `X-Auth-Role`)
- `GET  /api/soc/health` → engine, ClickHouse, collectors, spool, EPS
- `POST /api/soc/search` `{q, from, to, limit (≤1000), fields?, order?}` → `{rows, total_estimate, took_ms, sql_hint}`
- `POST /api/soc/histogram` `{q, from, to, buckets}` → `{buckets:[{t, n}]}`
- `POST /api/soc/top` `{q, from, to, field, limit}` → `{values:[{v, n}]}`
- `GET  /api/soc/tail?q=` → Server-Sent Events of matching events (live)
- `GET  /api/soc/sources` → per source: last seen, EPS (1 min / 1 h), events today, parse error rate, collector, status ok|silent|errors
- `GET/POST /api/soc/alerts…` (list with filters, get, ack, assign, note, close with reason, bulk), `GET/POST /api/soc/cases…` (create from alerts, update status, tasks, notes, evidence)
- `GET/POST /api/soc/rules…` (list, get, create/update native rule, import Sigma YAML, enable/disable, `POST /rules/test` = run the rule over a past time range and return would-be alerts)
- `GET  /api/soc/metrics` → alerts by severity/day, MTTD/MTTR, SLA, top rules, top sources, noisy rules
- `GET  /api/soc/lr-compare` → for the parallel run: detections in both / only ours / only LogRhythm, per rule/source
- Writes need role operator/admin; rule changes and deletions admin; every write is appended to the audit journal.

## Query language (`q`)
`field:value`, `field:"exact phrase"`, `field:val*` (prefix), `field:>=3`, `field:[a TO b]` (numbers/time), `ip:10.0.0.0/8` (cidr on src_ip/dst_ip),
bare words / quoted phrases = full-text on `raw`+`message` (tokenbf `hasToken` / `positionCaseInsensitive`), `AND`/`OR`/`NOT`/parentheses (default AND).
Always compiled to **parameterised** ClickHouse SQL (`{p1:String}` placeholders) — never string-concatenated. Unknown field names are rejected
unless they are `fields.<key>` (→ `fields['key']`).

## Build / staging host (decided)
Built and tested on the platform portal server (Ubuntu 22.04, 4 vCPU, 7.7 GB RAM, shared with the live portal):
Node runtime `/opt/sentra-ai/node/bin/node` (v22). Install dir `/opt/sentra-siem`, data `/var/lib/sentra-siem` (state/, spool/),
config `/etc/sentra-siem/config.json` + secrets `/etc/sentra-siem/secrets.json` (mode 600: ClickHouse password, ingest tokens).
**Ports (all bound to 127.0.0.1 on this host):** API 9120, syslog UDP+TCP 5514, syslog TLS 6514 (off by default), ClickHouse HTTP 8123.
ClickHouse capped at 2.5 GB RAM. Nothing listens publicly; nginx exposes `/api/soc/` behind the portal's `auth_request /auth/verify`
(headers `X-Auth-Role`, `X-Auth-User`), and `/ingest/` for token-authenticated agents later. On the organisation's own servers the
same package runs with listeners on the LAN interface.

## Internal interfaces (so components can be built independently)
- `engine/pipeline.js` (core): `createPipeline({log})` → `{ use(stageFn), emit(event), stats() }`. Collectors call `emit(event)` after parsing;
  stages run in order: `enrich` (core) → `detector.onEvent` (detect) → `writer.push` (store). A stage throwing never drops the event.
- `engine/store/clickhouse.js` (core): `createCH({url, user, password, database})` → `{ query(sql, params) → rows[], exec(sql, params), insertRows(table, rows[]), ping() }` — params are `{name: {type, value}}` passed as ClickHouse `param_<name>`.
- `engine/api/server.js` (core): `createApi({port, log})` → `{ route(method, pattern /* string with :params */, handler), start(), stop() }`;
  `handler(ctx)` gets `ctx = { method, path, params, query, body (parsed JSON), user, role, ip, ok(obj), fail(code, message), sse() }`.
  Role check helper `ctx.need('operator'|'admin')`. Every write handler must call `ctx.audit(action, target, detail)`.
- `engine/soc/state.js` (detect/soc): `createState({dir})` → `{ collection(name) → { get(id), all(filterFn?), put(obj), patch(id, fn), remove(id) }, audit(entry), snapshot() }` — append-only journals, snapshot every 5 minutes / 10k writes.
- `engine/detect/engine.js`: `createDetector({rules, now, onAlert, log})` → `{ onEvent(ev), tick(nowMs), load(rules), stats() }`.
- `engine/soc/alerts.js`: `createAlerts({state, ch, log})` → `{ raise(partial) , ...}`; `engine/detect/routes.js` and `engine/soc/routes.js` export `register(api, deps)` with `deps = { ch, state, detector, alerts, cases, config, log, search }`.
- `engine/main.js` wires everything: config → CH → pipeline → collectors → detector → alerts → api.

## Non-functional
- Target: 5,000 EPS sustained on the POC collector VM (4 vCPU, 16 GB), bursts to 20,000 with spooling; 12 months hot retention default (configurable), with nightly archive export option.
- No data leaves the server. TLS on the syslog-TLS and HTTPS ingest listeners (certificates from install). Per-source ingest tokens (HMAC-compared).
- Integrity: every batch written gets a sha256 chained to the previous one (tamper evidence for auditors).
- Back-pressure: if ClickHouse is unavailable, events go to `spool/` (bounded, oldest-first replay); detection keeps running in memory.
