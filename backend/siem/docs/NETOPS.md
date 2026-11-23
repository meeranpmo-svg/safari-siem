# AI Network Engineer (engine/netops)

Monitors, troubleshoots and helps manage the organisation's network — Cisco switches and routers, FortiGate and Palo Alto
firewalls, Genian NAC and HPE Aruba EdgeConnect (Silver Peak) SD-WAN — from inside the SIEM. Portal page:
**Dashboards → AI Network Engineer** (`/dashboards/network-engineer.html`).

## What it does

| Area | How |
| --- | --- |
| Visibility | Polls every device every 2 minutes (ping, SNMP v2c/v3, vendor REST/XML APIs). Interface status, bandwidth and utilisation, errors, CPU/memory/sessions, VPN tunnels, HA sync, BGP/OSPF neighbours, SD-WAN path loss/latency/jitter, NAC endpoints and quarantines, EdgeConnect appliance state and alarms. History goes to ClickHouse `siem.net_metrics` (400 days). |
| Problems | `analyze.js` turns each poll into findings with evidence and a recommended fix (site down, link saturated, uplink down, tunnel down, HA out of sync, neighbour down, path degraded, NAC quarantine, monitoring access broken…). Sites roll up to down / degraded / warning / ok. |
| Troubleshooting | `troubleshoot.js` runs the standard workflow for a site, device or unreachable application: reachability → links/utilisation → VPN/SD-WAN → routing/HA → up/down events in the SIEM → configuration changes in the SIEM → firewall blocks to the target → NAC, and ranks probable causes. Works without the AI. |
| AI assistant | Claude (`claude-opus-5-5`) with 13 read-only tools over the above plus the SIEM's logs (device events, config changes, blocked connections, top talkers from firewall traffic logs, NAC lookups, metric history, ping). Answers with summary, root cause and confidence, evidence, and a fix. |
| Guided changes | The AI or an engineer proposes a change plan (commands, prechecks, rollback). An administrator approves it (not the author), an engineer applies it, and the SIEM re-polls the device and records the validation. **The SIEM never changes a device.** |
| Proactive | Daily health report and capacity forecast (least-squares trend of daily peak utilisation → days until 90 %). |

## Design choices for this environment

The suggested reference stack (Python/FastAPI, Prometheus/Grafana, OpenSearch, PostgreSQL, Nornir/Netmiko) was mapped
onto what the SIEM server already runs, so nothing new has to be installed or kept patched on an offline server:

| Suggested | Used here |
| --- | --- |
| Python / FastAPI backend | SIEM engine (Node.js standard library), same login, roles and audit log |
| Prometheus + Grafana | poller + ClickHouse `net_metrics` + portal dashboards |
| Syslog collector + OpenSearch | the SIEM's existing syslog/parsers and ClickHouse `events` |
| NetFlow/IPFIX | firewall traffic logs already in the SIEM (top talkers); NetFlow can be added later |
| PostgreSQL inventory | SIEM state store (`netops_devices`), credentials in `secrets.json` |
| Netmiko/NAPALM SSH automation | not used — read-only APIs/SNMP only; changes go through human-approved plans |

Defaults assumed for the open questions: **1–10 branch sites**, **on-premises**, **monitor + investigate + recommend
(changes only after approval, applied by an engineer)**, **existing tools = the SIEM (syslog) + SNMP**.

## Roles

| Action | Role |
| --- | --- |
| See sites, problems, devices, report, change plans | viewer |
| Run a diagnosis, ask the AI, search evidence | analyst |
| Poll now, propose a change, mark an approved change applied | operator |
| Add/remove devices, set credentials, approve/reject change plans | admin |

Credentials are write-only: stored in `/etc/sentra-siem/secrets.json` (`netops.devices.<id>`, mode 600, previous copy kept as
`.bak`), never returned by the API, removed with the device. Every write is in the SIEM audit log.

## Read-only accounts on the devices

Create dedicated read-only accounts; allow them only from the SIEM server's IP.

* **Cisco IOS/IOS-XE (SNMPv3, recommended):**
  ```
  ip access-list standard SIEM-SNMP
   permit <SIEM-IP>
  snmp-server view SIEM-RO iso included
  snmp-server group SIEM-GRP v3 priv read SIEM-RO access SIEM-SNMP
  snmp-server user siem-mon SIEM-GRP v3 auth sha <auth-pass> priv aes 128 <priv-pass>
  ```
  (SHA-256 is also supported where the IOS release offers it.) Enter the same user/passwords under Devices → Credentials.
* **FortiGate (REST API):** System → Admin Profiles → new profile with **Read** on everything (no Write) → System →
  Administrators → Create New → REST API Admin, that profile, Trusted Hosts = SIEM IP → copy the token. Use the device
  certificate's SHA-256 fingerprint in the credentials form to pin it (FortiGate's certificate is self-signed).
  For SD-WAN health checks to show, SD-WAN performance SLAs must exist.
* **Palo Alto (XML API):** Device → Admin Roles → new role: XML API → **Operational Requests** only (everything else
  disabled), Web UI/REST off → Administrators → account with that role → generate the key:
  `https://<fw>/api/?type=keygen&user=<user>&password=<pass>` (or `request` from Panorama). Only `<show>` commands are sent.
* **Genian NAC:** Administration → API key for a read-only (monitoring) administrator. The node list path defaults to
  `/mc2/rest/nodes`; if your version uses another path, set it in the credentials (`nodes_path`). Field names differ
  between Genian versions and are matched loosely — check the first poll on the device page.
* **EdgeConnect Orchestrator:** Orchestrator → Users & Authentication → API keys → create a key for a **read-only**
  user. Appliances come from `/gms/rest/appliance`, alarms from `/gms/rest/alarm/appliance?view=active`.
  Confirm both on the device page after the first poll; the paths can be overridden if your release differs.

Ping: the `sentra-siem` user must be allowed to send ICMP (`install/netops-setup.sh` checks and prints the fix).

## Switch CLI — read-only show commands over SSH (Netmiko)

For what SNMP does not give (which port a MAC is on, CDP/LLDP neighbours, VLANs, err-disabled ports, PoE, the running
configuration, the switch's own log, model and serial on any stack) the engine logs in to Cisco IOS / IOS-XE switches and
routers and Cisco ASA over SSH and runs **show commands from a fixed list** (`engine/netops/cli.js`, `CATALOGUE`). Anything
else — `conf t`, `reload`, `copy`, `write`, `clear`, `debug`, abbreviations, `;`, `| redirect` — is refused before a
session is opened, and `cli-helper.py` checks again that every command starts with `show`.

* **Install:** `sudo bash install/netops-cli-setup.sh` (Python venv `/opt/sentra-siem/pyenv` + Netmiko; `--proxy URL` or
  offline `--wheels DIR`). `update-server.sh` runs it; without internet the rest of the platform is unaffected.
* **Account on the switch** (privilege 1 is enough for everything except `show running-config`):
  ```
  username siem-ro privilege 1 secret <password>
  ip access-list standard SIEM-SSH
   permit <SIEM-IP>
  line vty 0 15
   access-class SIEM-SSH in      ! keep your existing permits on this ACL
   transport input ssh
  ```
  With TACACS+ / ISE, give the account a command set that permits only `show *`. The enable secret field is optional and
  only used for `show running-config`.
* **Host key:** Devices → device → *Read host key* reads the SSH key **without logging in** (no username or password is
  sent). Compare the fingerprint (`show ip ssh` / your SSH client), then *Trust*. Until a key is trusted no login is
  attempted; a different key later refuses the login (*hostkey-changed*) until an administrator trusts the new one.
* **Who:** operators run commands and *Read model & serial*; administrators set the login and trust keys; the AI Network
  Engineer uses the same allowlist through its `show_commands` tool. Every session (portal or AI, user, commands, result)
  is in `GET /api/soc/netops/cli/log` and the SOC audit trail.
* **Output:** passwords, secrets, keys and SNMP communities are removed (`redact()`) before the text reaches the portal,
  the AI or a log.

## Network ticket desk — the AI as L2 / L3 support

Network tickets can be assigned to the AI Network Engineer (page → **Tickets**, `engine/netops/tickets.js`).

**Getting tickets to it**
- ServiceDesk Plus: create a technician (e.g. `AI Network Engineer`) or a support group, and assign network requests to it.
  The desk picks up open requests assigned there every *poll_s* seconds (Desk settings) — one request becomes one desk ticket, never twice.
  It uses the same connection as Integrations → ManageEngine.
- The portal: an operator opens a ticket, or imports an SDP request by number.

**What it does with a ticket**
1. Finds the scope in the text: devices by exact name or IP, sites by whole name, the user / server IP, MAC addresses.
2. Runs the standard troubleshooter on that scope.
3. If the AI is enabled (Anthropic key set — only after approval to send network data) and *Use the AI* is on, the AI investigates with its read-only
   tools and may **propose** a change plan. Without the AI, the troubleshooter's result decides.
4. Outcome: resolve suggestion · change (plan waits for approval) · escalate to **L2** (cable, optic, power, circuit, provider) or **L3**
   (routing, VPN / SD-WAN, firewall policy, HA) · needs-info (asks one precise question) · not-network.
   Low-confidence results go to L3 when *Send low-confidence results to a person* is on.
5. The triage is written to the SDP request as an internal note; an escalated request moves to the L2 / L3 group. Nothing is closed by the desk.
6. A ticket waiting for a change follows the plan: validated → resolved (note to SDP, the service desk closes the request);
   rejected or failed validation → escalated to L3.

**Controls**
- The desk runs the AI with the role set in Desk settings: *operator* (read-only show commands + propose plans) or *analyst* (investigate only).
  Since this release every AI tool has the same minimum role as its API route, also in the chat: an analyst's question cannot run CLI commands or file plans.
- Four eyes: the person who opened or assigned the ticket cannot approve the AI's plan for it; the plan's author cannot approve their own plan.
- PDPL: ticket text is readable by analysts and above, never viewers. The AI gets no requester name; e-mail addresses and phone numbers are masked.
  Ticket text is treated as a description, never as instructions to the AI.
- Every action (open, triage, assign, escalate, note, resolve, settings) is in the ticket history and the SOC audit trail.

API: `GET/POST {P}/netops/tickets`, `…/tickets/status`, `…/tickets/settings` (PUT admin), `…/tickets/import`, `…/tickets/poll`,
`…/tickets/:id`, `…/tickets/:id/{triage,assign,escalate,resolve,note}` (operator).

## Support, subscriptions and SIEM alerts

- **What the firewalls report.** With API polling on, the poller reads every 6 hours what FortiGate
  (`GET /api/v2/monitor/license/status`) and PAN-OS (`request license info` — read-only, the only non-`show` command
  allowed) report about their own support contract and security subscriptions. `GET {P}/netops/licenses` lists it; the
  Support Contracts page shows it next to the register.
- **Findings.** `support-expired` / `license-expired` (high), and `support-expiring` / `license-expiring` (high within 30 days,
  medium within 60, `thresholds.license_warn_days`). An expired subscription means that protection is no longer updated.
- **SIEM alerts** (`engine/netops/alerts-bridge.js`). Support and licence findings, critical devices unreachable, and contracts
  from the IT Asset Management register that have ended or end within 30 days are raised as SIEM alerts (rule ids
  `netops-<kind>`, `support-contract-expired` / `-expiring`). One alert per condition; repeats merge into the open alert.
  Nothing closes by itself. `config.netops.alerts`: `enabled` (default true), `kinds` (more finding kinds to raise),
  `contract_warn_days` (30).

## One-way audio troubleshooter (engine/netops/voice.js, page voice-troubleshoot.html)

Cisco IP phones where the call connects but one side hears nothing. `POST /api/soc/netops/voice {a, b, hear, minutes?, refresh?}`
(analyst; a live re-read of the firewall settings needs operator; every run audited as `netops.voice.diagnose`).

* **Evidence** - `evidence.voiceFlows`: the voice sessions between phone A and the far end (UDP, not 5060/5061/2000) on every
  FortiGate / Palo Alto / Silver Peak that logged them, **per direction**: denied, no reply (one-way), NAT, which firewall saw
  which direction; plus the SIP / SCCP signalling of phone A.
* **Settings** (`fwfacts.js`, read-only): FortiGate `default-voip-alg-mode`, the `sip` session helper, VoIP profiles per policy,
  custom service UDP ranges (does a policy cover 16384-32767, and the way back?); PAN-OS `alg-override` (SIP ALG on / off),
  rules allowing rtp / rtcp per zone pair.
* **Causes**, most likely first, each with evidence, fix and rollback per device: a policy denies one direction; asymmetric path
  (each direction on another firewall); SIP ALG rewriting the call setup (an SCCP phone is never blamed on it); NAT on the voice;
  a policy allowing voice one way only; the voice not coming back (route / gateway `bind media`); WAN / tunnel / SD-WAN flaps;
  firewall CPU / memory. "A cannot hear B" means the audio B → A is lost.
* **Phone and call manager checks** a person does during a bad call (Call Statistics, voice VLAN gateway, MTP / transcoder,
  gateway media binding) are always listed. Nothing changes a device; a fix can be proposed as a change plan.

## The AI and data protection

When someone asks the AI a question, the question and the tool results it needs (device names, IP addresses, interface
names, utilisation figures, relevant log lines, usernames in configuration-change logs) are sent to Anthropic's API
(`api.anthropic.com`) over HTTPS. Nothing is sent by the poller, the findings, the troubleshooter or the reports — only
when a person asks. Before enabling it, confirm this is acceptable under the organisation's data-classification and
regulatory (SAMA) requirements and Anthropic's commercial terms; without an API key, or with
`"netops": {"ai": {"enabled": false}}` in config.json, everything except the chat keeps working.

* Model `claude-opus-5-5`, adaptive thinking, effort `high`, server-side refusal fallback (`fallbacks: "default"`).
* Official SDK `@anthropic-ai/sdk` 0.133.0, bundled offline in `install/vendor/` (checksum-verified by the installer).
* API key: `sudo bash install/netops-setup.sh --set-key` (stored in secrets.json). Proxy: `--proxy http://host:port`
  (needs Node 22.21+ or 24+ for `NODE_USE_ENV_PROXY`).
* Conversations are stored per user (state collection `netops_chats`); a user cannot open another user's conversation.

## Deploy

On the server, from an up-to-date copy of this repository:

```
sudo bash install/deploy-engine.sh          # backs up /opt/sentra-siem/engine, installs, migrates, restarts, health-checks, auto-rollback
sudo bash install/netops-setup.sh --set-key  # SDK, API key, ping check, schema
```
then the dashboards bundle from the shield repository (`install-dashboards.sh`, `add-dashboards-nginx.sh`).
Rollback: `sudo bash install/deploy-engine.sh --rollback`.

First use: Network Engineer → Devices → **Import network log sources from the SIEM** (adds every onboarded FortiGate /
Palo Alto / Cisco / Genian / Silver Peak source with its IP), then set roles, sites and credentials, and enable SNMP/API
polling per device.

## Roadmap

1. **Visibility** — done: inventory, polling, history, findings, sites.
2. **AI troubleshooting** — done: deterministic workflow + Claude with evidence tools; runbooks/diagrams retrieval (RAG)
   is the next addition.
3. **Guided automation** — change plans, approval, validation are done; execution stays manual by design. Pre-change
   config backup/diff (read-only `show running-config` via API) is the next step.
4. **Proactive** — daily report and capacity forecast done; anomaly detection on `net_metrics`, NetFlow/IPFIX, and
   scheduled e-mail of the daily report are next.

## Files

`engine/netops/`: `snmp.js` (SNMP v2c/v3 client), `http.js` (read-only HTTPS, certificate pinning), `xml.js`,
`collectors.js` (ping, SNMP, FortiGate, PAN-OS, Genian, EdgeConnect), `inventory.js`, `poller.js`, `analyze.js`,
`evidence.js` (SIEM queries), `troubleshoot.js`, `ai.js`, `changes.js`, `routes.js`, `cli.js` + `cli-helper.py` (read-only SSH
show commands). Tests: `tests/netops.test.js`, `tests/netops-cli.test.js` (a real SSH session to `tests/helpers/fake-cisco-ssh.py`
when Netmiko is installed; `SENTRA_TEST_NETMIKO_PY=<python>`).

## Approved tasks on Cisco IOS (engine/netops/tasks.js, pam.js)

The AI Network Engineer (or an engineer) proposes a **task** from a fixed template; the platform builds the exact lines
from validated parameters, an administrator who did not ask for it approves, and an operator presses **Run**.

| Task | What the platform pushes | Refused when | Rollback |
|---|---|---|---|
| `vlan-create` {vlan, name} | `vlan N` / ` name X` | the VLAN exists | `no vlan N` |
| `port-access-vlan` {vlan, interfaces[], description} | `switchport mode access`, `switchport access vlan N` | VLAN missing, port is a trunk | the port's previous lines |
| `trunk-vlan-add` {vlans[], interfaces[]} | `switchport trunk allowed vlan add …` | port not a trunk, already allowed | `… remove …` |
| `port-description` / `port-shutdown` / `port-enable` | one line | port missing; shutdown of a trunk | previous state |
| `ios-stage` {image, url, md5} | `copy url flash:` + `verify /md5` (must equal the approved MD5) + `boot system` | INSTALL-mode switch, MD5 mismatch | previous boot variable |
| `ios-reload` {minutes} | `write memory`, `reload in N` | a reload already scheduled | `reload cancel` |

Every run: prechecks → backup of the running configuration (secrets removed, kept on the plan) → push → verify → **automatic
rollback** when verification fails → `write memory` only when verified. cli-helper.py checks every configuration line
against its own allowlist (second line of defence). The SSH host key must be pinned. `config netops.tasks.enabled=false`
switches execution off.

**Write account.** Separate from the read-only login. With PAM (`sudo zyb-pam-setup --checkout <program>`) the device stores
only the PAM account reference; the password is checked out for the run and checked in after, and a stored write password is
not used. Template for the checkout program: `install/pam/zyb-pam-example.sh` (CyberArk CCP and PAM360 examples).

## Evidence for the AI auditors (engine/netops/config-audit.js, engine/itaudit/routes.js)

The AI IT / Cyber Security Auditors in IT Asset Management test Active Directory, Cisco switches, firewalls, databases and
applications against the CIS benchmarks, SAMA CSF, NCA ECC and ISO 27001 (rules: shield `repos/sentra-itam/pyengine/infra_audit_rules.py`).
The SIEM only hands them what it already holds, read-only:

- **Running-config capture.** Once a day, every Cisco IOS / ASA device with a read-only SSH login and a trusted host key is
  read with `show running-config` through the same allow-listed CLI helper (logged as `system:it-auditor`, via `audit`).
  `redact()` removes every password, secret, key and community; it keeps the hash type digit (`enable secret 9 <removed>`) and
  `service password-encryption`, because those are what the benchmark tests. The latest copy per device is kept in
  `netops_config_audit` with its SHA-256. A device that cannot be read keeps its previous copy and records why. Switch off
  with `netops.config_audit: false`.
- **AD domain policy.** The AD sync also reads the Default Domain Policy values from the domain head (minPwdLength, history,
  ages, complexity, lockout). Fine-grained password policies are not read.
- **Route.** `GET /api/soc/audit/evidence/{ad, network, network/config/:id, database, applications}` is for analysts and above
  (named accounts and activity are personal data under PDPL). Every read is audited as `audit.evidence.read`. IT Asset Management
  calls it as `system:itam-auditor` with the role analyst.
