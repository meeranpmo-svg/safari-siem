# AI Network Engineer — Build Document

**Customer:** the organisation · **Platform:** Zyberon SIEM (`sentra-siem`) on `the platform server`
**Code:** GitHub `meeranpmo-svg/sentra-siem`, branch `server-merge` (engine) · `meeranpmo-svg/shield`, branch `main` (portal page)
**Status:** built and tested; not yet deployed to the server · **Date:** 11 October 2026

---

## 1. Purpose

An AI-assisted network operations capability inside the SIEM that **monitors, troubleshoots, and helps manage** the
enterprise network:

| Platform | What is monitored |
| --- | --- |
| Cisco switches and routers | reachability, CPU, memory, interfaces (status, bandwidth, utilisation, errors, discards), BGP and OSPF neighbours |
| FortiGate firewalls | system, sessions, interfaces, IPsec tunnels, HA sync, SD-WAN health checks (loss / latency / jitter), BGP |
| Palo Alto firewalls | system, CPU/memory, sessions, interfaces and counters, IPsec tunnels, HA state and sync, BGP peers |
| Genian NAC | endpoints, unauthorized endpoints, quarantined endpoints (IP, MAC, host, switch port, VLAN) |
| HPE Aruba EdgeConnect (Silver Peak) | appliance state per site, active alarms |
| Branch connectivity | per-site reachability, latency, packet loss, jitter |

It answers questions such as *"Why is the Jeddah branch slow?"* with a root cause, evidence and a fix, and it can
**propose** configuration changes for human approval. **It never changes a device.**

## 2. Scope decisions

| Question | Decision used for this build |
| --- | --- |
| Network size | 1–10 branch sites |
| Where the AI runs | On-premises, inside the SIEM engine; only the AI chat calls Anthropic's API |
| Allowed actions | Monitor, investigate, recommend; changes only as approved plans applied by an engineer |
| Existing monitoring | The SIEM (syslog from all vendors) + SNMP |

The reference stack (Python/FastAPI, Prometheus/Grafana, OpenSearch, PostgreSQL, Netmiko/NAPALM) was mapped onto what
the SIEM server already runs, so nothing new needs installing or patching on an offline server:

| Reference component | This build |
| --- | --- |
| Backend (FastAPI) | SIEM engine — Node.js standard library; same login, roles, audit log |
| Metrics (Prometheus / Grafana) | Poller → ClickHouse `siem.net_metrics`; portal dashboard |
| Logs (syslog + OpenSearch) | Existing SIEM parsers + ClickHouse `siem.events` |
| Traffic analysis (NetFlow/IPFIX) | Firewall traffic logs already in the SIEM (NetFlow is a later addition) |
| Inventory (PostgreSQL) | SIEM state store `netops_devices`; credentials in `secrets.json` |
| Automation (SSH / Netmiko) | Not used: read-only APIs and SNMP; changes via approved plans |
| AI reasoning | Claude `claude-opus-5-5` through the official Anthropic SDK, with tool calling |

## 3. Architecture

```
 Portal  ─ Dashboards → AI Network Engineer (network-engineer.html)
   │        Overview · Ask the AI · Devices · Change plans · Daily report
   │  HTTPS, portal login (nginx auth_request) → /api/soc/netops/*
   ▼
 SIEM engine (sentra-siem, 127.0.0.1:9120) ─ engine/netops
   ├─ routes.js        API, roles, audit
   ├─ inventory.js     devices (state store) + write-only credentials (secrets.json)
   ├─ poller.js        every 120 s, 8 devices in parallel → snapshot + counter rates → net_metrics
   │    └─ collectors.js  ping · SNMP v2c/v3 (snmp.js) · FortiOS REST · PAN-OS XML (xml.js) · Genian REST · Orchestrator REST
   │                      (http.js: HTTPS GET only, certificate pinning)
   ├─ analyze.js       findings + site roll-up + daily report + capacity forecast
   ├─ evidence.js      read-only SQL on siem.events / siem.net_metrics
   ├─ troubleshoot.js  deterministic diagnosis workflow (works without AI)
   ├─ ai.js            Claude agent loop, 13 read-only tools ── HTTPS ──► api.anthropic.com (only when someone asks)
   └─ changes.js       change plans: propose → approve → applied → validated
   ▼
 ClickHouse: siem.events (existing logs) · siem.net_metrics (new, 400-day TTL)
   ▲
 Network devices: Cisco · FortiGate · Palo Alto · Genian NAC · EdgeConnect Orchestrator (read-only accounts)
```

## 4. Components

| File (`engine/netops/`) | Responsibility |
| --- | --- |
| `snmp.js` | SNMP client: GET/GETNEXT/GETBULK/WALK, v2c and v3 USM (HMAC-SHA-96, HMAC-SHA-256-192, AES-128-CFB), engine discovery and time sync. No SET. |
| `http.js` | Read-only HTTPS client: GET only, no redirects, size cap, certificate pinning by SHA-256 fingerprint or CA. |
| `xml.js` | Small XML reader for PAN-OS answers (no DTD/entity expansion → no XXE). |
| `collectors.js` | Ping (system `ping`, no shell); SNMP (IF-MIB, Cisco CPU/memory, FortiGate/PAN MIBs, BGP4-MIB, OSPF-MIB); FortiOS, PAN-OS (`<show>` only), Genian, EdgeConnect. |
| `inventory.js` | Device validation and CRUD; credentials validation (SNMPv3 SHA/SHA-256 only, no MD5); import of the SIEM's onboarded network sources. |
| `poller.js` | Scheduling, merging, bps/utilisation/errors-per-minute from counter deltas (64-bit safe, counter resets ignored, impossible values dropped), history rows. |
| `analyze.js` | Findings with severity, evidence, recommendation; site status; daily report; least-squares capacity forecast. |
| `evidence.js` | Device events (link/routing/HA up-down), config changes, blocked connections, top talkers, NAC lookups, metric history, daily peaks. |
| `troubleshoot.js` | Reachability → links/utilisation → VPN/SD-WAN → routing/HA → SIEM events → config changes → firewall blocks to target → NAC; ranked causes. |
| `ai.js` | Claude manual tool loop; input validation per tool schema; per-user conversations; refusal handling. |
| `changes.js` | Change-plan workflow and validation record. |
| `routes.js` | API and wiring; starts the poller. |

Other changes: `engine/config.js` (`netops` defaults), `engine/main.js` (route registration), `engine/store/schema.sql`
(`siem.net_metrics`), `install/deploy-engine.sh`, `install/netops-setup.sh`, `install/fix-config-write.sh`,
`install/sentra-siem.service`, `install/vendor/anthropic-sdk-0.133.0.tgz` (+ `.sha256`), `docs/NETOPS.md`,
`tests/netops.test.js`. Portal (shield repo): `dashboards/server/network-engineer.html`, menu and index entries,
`add-dashboards-nginx.sh` (no-cache header, whoami location).

## 5. Findings the system raises

| Kind | Trigger (defaults; configurable in `netops.thresholds`) | Severity |
| --- | --- | --- |
| unreachable | no ping reply and no other source answers | critical (core / WAN edge / firewall / criticality 3), else high |
| loss / latency / jitter | ≥ 2 % (≥ 10 % high) / ≥ 150 ms / ≥ 30 ms | medium / medium / low |
| icmp-blocked | no ping reply but SNMP/API answers | low |
| cpu / memory | ≥ 85 % (≥ 95 % high) / ≥ 90 % | medium / high |
| if-down | admin up, link down, on an uplink/WAN/trunk or described port | medium / high |
| utilization | ≥ 80 % of link speed (≥ 95 % high) | medium / high |
| errors | ≥ 10 errors per minute | medium |
| tunnel-down | IPsec tunnel not up | high |
| ha-sync | HA cluster out of sync | high |
| neighbor-down | BGP (high) or OSPF (medium) not established | high / medium |
| path-down / path-quality | SD-WAN member down / over loss, latency or jitter limit | high / medium |
| nac-quarantine / nac-unauth | quarantined / unauthorized endpoints | medium / low |
| sdwan-appliance / sdwan-alarms | EdgeConnect appliance down / critical-major alarms | high / medium |
| collector / stale / not-polled | credentials or certificate problem / data older than 15 min / never polled | medium / medium / low |

Sites roll up to **down** (nothing reachable), **degraded** (high/critical or partial reachability), **warning**,
**ok**, or **unknown**.

## 6. The AI assistant

* **Model:** `claude-opus-5-5`, adaptive thinking, effort `high`, `max_tokens` 16 000, server-side refusal fallback
  (`fallbacks: "default"`, beta `server-side-fallback-2026-07-01`), prompt caching on the stable system prompt and tools.
* **SDK:** official `@anthropic-ai/sdk` 0.133.0, bundled offline (474 KB, SHA-256 verified by the installer).
* **Tools (all read-only except recording a plan):** `network_overview`, `list_devices`, `device_status`, `findings`,
  `diagnose`, `device_events`, `config_changes`, `blocked_connections`, `top_talkers`, `nac_lookup`,
  `metric_history`, `ping` (monitored devices or private IPs only), `propose_change` (records a plan, does not execute).
* **Answer format:** summary · probable root cause with confidence · evidence · numbered fix with vendor CLI · next checks.
  Replies in the language of the question (Arabic or English).
* **Safety:** tool inputs validated against their schemas; results capped at 24 KB; at most 14 investigation steps;
  conversations private to their user and append-only.
* **Data sent to Anthropic:** only when a person asks — the question and the tool results needed (device names, IPs,
  interface names, figures, relevant log lines, usernames from change logs). **Requires the organisation's approval under
  its data classification and SAMA requirements before the API key is added.** Without a key, everything except the
  chat works.

## 7. API

Prefix `/api/soc/netops`, behind the portal login.

| Method and path | Role | Purpose |
| --- | --- | --- |
| `GET /overview` | viewer | sites, findings, poller and AI status, pending plans |
| `GET /devices`, `GET /devices/:id` | viewer | inventory, last poll, snapshot, findings, which credentials are set (never values) |
| `POST /devices`, `DELETE /devices/:id` | admin | add / update / remove a device |
| `PUT /devices/:id/credentials` | admin | SNMP / API credentials (write-only) |
| `POST /devices/seed` | admin | import onboarded network log sources |
| `POST /devices/:id/poll` | operator | poll now |
| `GET /findings` | viewer | findings by site or device |
| `POST /diagnose` | analyst | deterministic diagnosis |
| `GET /evidence/:kind` | analyst | events, changes, blocked, talkers, nac, history |
| `POST /ask`, `GET /conversations` | analyst | AI assistant |
| `GET /report` | viewer | daily report and capacity forecast |
| `GET/POST /changes`, `POST /changes/:id/decide`, `POST /changes/:id/applied` | viewer / operator / admin / operator | change plans |

## 8. Security

* **Read-only to the network:** SNMP has no SET; HTTPS client is GET-only; PAN-OS limited to `<show>` commands.
* **Credentials:** stored only in `/etc/sentra-siem/secrets.json` (`netops.devices.<id>`), mode 600, atomic write with
  `.bak`; never returned by the API; removed with the device. SNMPv3 SHA/SHA-256 + AES only.
* **TLS:** device certificates pinned by SHA-256 fingerprint; "do not verify" is possible but flagged on the device.
* **Roles:** viewer < analyst < operator < admin; every write audited (`netops.*`).
* **Change control:** an administrator other than the author approves; an engineer applies; the SIEM re-polls and
  records validation.
* **SQL:** parameterised, `readonly=2`, time-limited, row-limited.
* **Service sandbox:** the SIEM may write `/var/lib/sentra-siem` and `/etc/sentra-siem` (needed for onboarding and
  credentials); `/etc/sentra-siem/tls` stays read-only.

## 9. Device preparation (read-only accounts, allowed only from the SIEM IP)

| Vendor | Account |
| --- | --- |
| Cisco | SNMPv3 view `iso`, group `priv read`, user with `auth sha` + `priv aes 128`, access list permitting the SIEM IP |
| FortiGate | Admin profile with Read only → REST API Admin, trusted host = SIEM IP → token; pin the certificate fingerprint |
| Palo Alto | Admin role: XML API → Operational Requests only → API key (`type=keygen`) |
| Genian NAC | API key of a read-only (monitoring) administrator; node path `/mc2/rest/nodes` unless your version differs |
| EdgeConnect Orchestrator | API key of a read-only user |

Exact Cisco commands and screens: `docs/NETOPS.md`.

## 10. Deployment

Prerequisite (done on 11 Oct 2026): `install/fix-config-write.sh` — the SIEM service can write `/etc/sentra-siem`.

**Engine (PowerShell on the PC):**
```
cd C:\Users\Syed\sentra-siem
git checkout server-merge
git pull
ssh admin@platform-server "mkdir -p /tmp/sentra-siem-v1"
scp -r engine install docs admin@platform-server:/tmp/sentra-siem-v1/
ssh -t admin@platform-server "cd /tmp/sentra-siem-v1 && sed -i 's/\r$//' install/*.sh && sudo bash install/deploy-engine.sh && sudo bash install/netops-setup.sh"
```
`deploy-engine.sh` backs up `/opt/sentra-siem/engine`, syntax-checks, migrates the schema, restarts and health-checks;
if the SIEM does not come back healthy within 30 s it restores the previous engine automatically.
Rollback any time: `sudo bash install/deploy-engine.sh --rollback`.

**AI key (only after data-protection approval):**
```
ssh -t admin@platform-server "cd /tmp/sentra-siem-v1 && sudo bash install/netops-setup.sh --set-key --restart"
```
Add `--proxy http://<proxy>:<port>` if the server reaches the internet through a proxy (Node 22.21+ or 24+).

**Portal page (shield repo):**
```
cd C:\Users\Syed\shield
git pull
scp -r dashboards\server admin@platform-server:/tmp/zyb-dash-v9
ssh -t admin@platform-server "cd /tmp/zyb-dash-v9 && sed -i 's/\r$//' *.sh && sudo bash install-dashboards.sh | head -2 && sudo bash add-dashboards-nginx.sh && sudo bash add-dashboards-menu.sh"
```

**First use:** Dashboards → AI Network Engineer → Devices → *Import network log sources from the SIEM* → set site, role,
criticality → Credentials → enable SNMP / API polling → *Poll now*.

## 11. Verification checklist (after deployment)

- [ ] `deploy-engine.sh` prints "sentra-siem is healthy on the new engine" and `netops/routes.js` among registered modules
- [ ] `netops-setup.sh` prints "SDK loads for the service user", "ping works", "ClickHouse schema migrated"
- [ ] Page opens; chips show the device count and the AI status
- [ ] A device with SNMP credentials shows interfaces after *Poll now*; a second poll shows bandwidth and utilisation
- [ ] FortiGate / Palo Alto show system, tunnels and HA after the first API poll
- [ ] Genian and EdgeConnect device pages show sensible node / appliance lists (field mapping check)
- [ ] *Run diagnosis* on a site returns checks and ranked causes
- [ ] (With key) *Ask the AI* answers and lists the evidence it gathered
- [ ] A change plan can be proposed, approved by a second admin, marked applied, and shows a validation result
- [ ] Daily report tab shows the report; capacity forecast appears after 5+ days of history

## 12. Tests performed

| Test | Result |
| --- | --- |
| SIEM test suite (22 files) including `tests/netops.test.js` (10 tests) | all pass |
| SNMPv3 key derivation against RFC 3414 test vectors | match |
| SNMP client against a real net-snmp agent: v2c, v3 SHA/AES, v3 SHA-256/AES, wrong password, wrong community | correct values / clear errors |
| Poller against the real agent, two polls | interfaces, 64-bit counters, bps computed |
| FortiGate and Palo Alto collectors against mock HTTPS devices; certificate pin correct / wrong / unpinned | parsed; wrong pin and unverified certificate refused |
| Official SDK against a mock Claude API | correct endpoint, model, beta header, fallbacks, tool-result round trip |
| AI loop with scripted model | parallel tool results in one message, schema errors returned, plan recorded, refusal handled, conversations private |
| API roles and credentials | write-only, secrets.json mode 600, author cannot approve own plan, credentials removed with device |
| Portal page end to end in Chromium (real routes, simulated devices) | all tabs, panels, forms; no layout overflow on a phone |

**Not yet verified on real equipment:** Genian NAC and EdgeConnect Orchestrator API paths and field names (they vary
by version); live Claude API calls (pending key and approval).

## 13. Operations

* Poll interval 120 s, 8 devices in parallel (`netops.interval_s`, `netops.concurrency`).
* History: `siem.net_metrics`, 400 days.
* Logs: `journalctl -u sentra-siem | grep netops`.
* Disable the AI only: `"netops": {"ai": {"enabled": false}}` in `/etc/sentra-siem/config.json`, restart.
* Disable polling: `"netops": {"enabled": false}`.

| Symptom | Cause / fix |
| --- | --- |
| "SIEM: internal error" / EROFS on saving | service cannot write `/etc/sentra-siem` → `install/fix-config-write.sh` |
| "ping is not installed" / no reachability | `sudo setcap cap_net_raw+p $(command -v ping)` |
| "wrong SNMPv3 authentication password" / "unknown SNMPv3 user" | fix the credentials on the device page |
| "device certificate does not match the pinned fingerprint" | certificate renewed → update the fingerprint |
| AI "not available: no Anthropic API key" | `netops-setup.sh --set-key` |
| AI cannot reach Anthropic | set `--proxy`, or allow HTTPS to `api.anthropic.com` |

## 14. Roadmap

| Phase | Status |
| --- | --- |
| 1 Visibility — inventory, polling, history, findings, sites | built |
| 2 AI troubleshooting — deterministic workflow, Claude with evidence tools | built; next: retrieval over runbooks, diagrams and configurations |
| 3 Guided automation — change plans, approval, validation | built (execution manual by design); next: read-only config backup and diff before/after a change |
| 4 Proactive operations — daily report, capacity forecast | built; next: anomaly detection, NetFlow/IPFIX, scheduled e-mail of the daily report |
