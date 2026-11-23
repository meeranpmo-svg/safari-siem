# sentra-itam — AI-powered IT Asset Management + CMDB — contract v1

Full IT asset management for Safari Group: every asset — on the network or not — discovered, inventoried, classified
by AI, related in a CMDB, and tracked through its lifecycle, licences, warranty, ownership and location. Networked
assets come from the **site sensors** (sentra-netops) and an optional **endpoint agent**; off-network/standalone assets
come from the sensor's local discovery, barcode/manual entry, or imports. AI classifies and normalises, spots gaps and
anomalies, optimises software licences, predicts refresh/EOL, and keeps CMDB relationships current — all explainable,
nothing auto-destructive. Node >= 20 stdlib only; service pattern like sentra-infra; reusable; Safari first (container
`safari-itam`).

## Sources of truth
- **sentra-netops site sensors** (primary for networked gear): switches, APs, routers, gateways, phones across vendors
  and sites → pushed to netops → sentra-itam subscribes (read the netops device/interface model via its API or the bridge).
- **Endpoint agent** `itam-agent` (optional, for PCs/servers/laptops): a small cross-platform agent (Windows/macOS/
  Linux) that reports hardware, OS, installed software, patch level, disk/encryption, last-user, serial/asset-tag —
  outbound only to the ITAM ingest (per-agent token), store-and-forward. For VMware estates, a **vCenter connector**
  (read-only) enumerates VMs/hosts/datastores (ties to the sentra-infra vCenter work). Agentless fallback: the sensor's
  SNMP/WMI-less discovery + import.
- **Off-network / standalone assets**: entered by the sensor's local scan where reachable, or **manually / by barcode/
  QR** in the portal (printers not on the mgmt net, UPS, projectors, spare stock, OT devices, assets at a site with no
  link). A "no network source — manually tracked" flag; a mobile-friendly add-asset form with photo + barcode.
- **Imports**: CSV, and connectors for an existing CMDB/asset DB (e.g. ManageEngine AssetExplorer, the current /api/db
  asset store) — idempotent, mapping, unmapped-field report.

## Model (`engine/model/*`)
`asset {id, asset_tag, type (server|vm|workstation|laptop|network|printer|phone|storage|ups|mobile|peripheral|
software|licence|other), name, status (in_use|in_stock|in_repair|retired|lost|disposed), source (sensor|agent|vcenter|
manual|import), site, location (building/room/rack), owner, custodian, department, vendor, model, serial, mgmt_ip?,
mac?, os, cpu/mem/disk, warranty {start,end,provider}, purchase {date,cost,po,supplier}, eol?, last_seen,
networked (bool), tags[]}`; `software {name, publisher, version, installs (count), licence_id?}`; `licence {id,
product, type, seats, used, expiry, cost, compliance (ok|over|under)}`; `ci relationship {from, to, type
(runs_on|connected_to|depends_on|member_of|installed_on)}`; `lifecycle event {asset, event, at, by}`; `stocktake`.

## AI layer (`engine/ai/*`, private model like sentra-grcai; 'not configured' until a URL is set)
- **Classify & normalise**: turn raw discovery (sysDescr, agent facts, free-text manual entries) into type/vendor/
  model/category; de-duplicate the same asset seen by sensor + agent + vCenter into one record (merge rules + AI
  tie-break, explainable).
- **CMDB relationships**: infer runs_on / connected_to / depends_on from netops topology (LLDP), vCenter (VM↔host),
  agent (software↔device) — proposed, a human confirms high-impact ones.
- **Gaps & anomalies**: assets seen on the network but not in inventory (shadow IT → ties to sentra-tiwatch ASM), assets
  in inventory not seen for N days (lost/retired?), missing owner/warranty/location, warranty/EOL expiring, licence
  over-deployment, unusual software.
- **Optimise**: software licence reclaim/true-up suggestions; refresh planning from age/EOL/warranty; stock levels.
All AI output is advisory, labelled "AI — verify"; never auto-retires or deletes an asset.

## API (`/api/itam/*`, portal auth; roles admin|operator(asset manager)|viewer; **everyone** can look up an asset by
tag for self-service "whose is this / is it ours")
`GET /summary` (counts by type/status/site, networked vs off-network, warranty/EOL expiring, licence compliance, AI
findings, discovery coverage) · `GET /assets` (+ `/:id`: full record, relationships, software, lifecycle, sources that
saw it) · `POST /assets` (manual/barcode add; operator) · `POST /assets/:id` (edit; operator) · `POST /assets/:id/
retire|dispose|move|assign` (operator; audited; no hard delete) · `GET /software` · `GET /licences` (+ compliance) ·
`GET /cmdb?asset=` (relationship graph) · `POST /cmdb` (confirm/add relationship) · `GET /discovery` (what each source
sees; unmatched) · `GET /stocktake` + `POST /stocktake/:id/scan` · `GET/POST /ai/findings` + `/:id/accept|dismiss` ·
`GET/POST /settings` (sources, agent enrolment tokens, vCenter connector creds write-only, import) · `POST /agent/*`
(agent gateway: enrol/heartbeat/report, per-agent token, like netops sensors) · `GET /import` + `POST /import/run` ·
`GET /reports` · `GET /audit` · `GET /health`.

## UI — `ui/itam-module.js` (+ `.ar.json`, `-nav.json`), ES5 like sentra-infra/ui/infra-module.js (replaces the ported
live-only 'itam'/'assetreg' placeholder pages with the full module)
Pages: `itam-overview` (assets by type/status/site, networked vs off-network donut, warranty/EOL timeline, licence
compliance, AI findings, discovery coverage per source), `itam-assets` (inventory, filter by type/site/source/owner/
status, drawer: full record, CMDB relationships graph (inline SVG), software, lifecycle, "seen by" sources; edit;
retire/move/assign; **Add asset** with barcode/QR + photo for off-network items), `itam-cmdb` (relationship map),
`itam-software` (installed software + licences + compliance), `itam-discovery` (sensor/agent/vCenter/import coverage,
unmatched devices to adopt), `itam-stocktake` (scan-based audit), `itam-ai` (findings: shadow IT, missing data,
licence reclaim, refresh plan — accept/dismiss), `itam-settings` (admin: sources, agent tokens + install command,
vCenter connector, imports). Everything live; off-network assets clearly badged; nothing sampled.

## Deliverables
`engine/**`, `agent/**` (the cross-platform endpoint agent: enrol, collect (Windows via `wmic`/PowerShell, Linux via
`/proc` + `dpkg/rpm`, macOS via `system_profiler` — shell out, degrade gracefully), outbound report, install scripts),
`engine/connectors/vcenter.js` (read-only vSphere REST — coordinate with the sentra-infra vCenter work, don't duplicate),
`ui/**`, Safari stack (`safari-itam` container ~160m, nginx `/api/itam/` + agent gateway on its own location,
apply_safari_itam.py), tests (model, AI classify/merge/relationship/gap/licence with fixtures, agent protocol, vCenter
parse vs fixture, barcode/manual add, import mapping idempotent, no-hard-delete, API roles, write-only creds, no
network in tests), docs/ITAM.md (sources, the endpoint agent + least-privilege, off-network workflow, vCenter setup,
import from ManageEngine AssetExplorer, AI findings). Keep sentra-n8n green.

## Asset Discovery extension (`engine/discovery/**`, contract v1 — see docs/DISCOVERY.md)
Extends this service (no parallel service): scopes (RFC 1918 by default, exclusions, VLAN, site, Riyadh-time schedule +
scan window, rate limits, per-scope + global method switches); **safety gate** — active methods (ICMP/TCP sweep, SNMP)
blocked per scope until a System Admin completes the audited pre-scan checklist (firewall from the platform server, SOC
notified, approver), re-closed when the addresses change; passive methods (AD/LDAPS, vCenter, Hyper-V report ingestion,
CUCM AXL/RIS, Azure Resource Graph, AWS EC2 SigV4, ARP table) always allowed; write-only AES-256-GCM credential vault
with a process-wide log scrubber; correlated results (MAC/serial/source-id strong, IP in-scope, host name weak) with
classification + OUI, reviewed by admin (approve via the ingest adopt flow, ignore with remembered reason, merge);
one-click SIEM log-source creation via the SIEM onboarding API + silent-source findings; rogue-device findings and an
optional SIEM bridge event; scheduler with cancel; every action in the hash-chained audit. API `/api/itam/discovery/*`
(admin-only writes), UI `ui/discovery-module.js` (views discovery, discovery-scopes, discovery-results, discovery-runs,
discovery-credentials).
