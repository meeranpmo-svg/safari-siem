# sentra-itam — IT Asset Management + CMDB — operations

AI-powered IT asset management and CMDB for Safari Group. Every asset — networked **or** off-network — is discovered,
de-duplicated into one record, classified, related in a CMDB and tracked through its lifecycle, licences, warranty and
ownership. **AI proposes, people approve. Nothing is ever hard-deleted.**

Service: `127.0.0.1:9150` behind nginx — `/api/itam/` (portal session auth) and `/agent/` (per-agent key).
Node >= 20, standard library only. State + hash-chained audit under `/var/lib/sentra-itam/state`.

## Sources of truth (all merged into ONE asset record)
1. **sentra-netops site sensors** — switches/APs/routers/phones. ITAM **subscribes** to the netops device + topology API
   (`config.netops.base_url`); it does **not** re-poll devices. LLDP neighbours become `connected_to` relationships.
2. **Endpoint agent `itam-agent`** — Windows/macOS/Linux; reports hardware, OS, installed software, patch level.
   Outbound-only, per-agent key, store-and-forward. See *Endpoint agent* below.
3. **vCenter connector** — read-only vSphere REST; enumerates hosts + VMs and proposes `runs_on` (VM→host). Credentials
   are entered in the portal (write-only). Coordinate with the sentra-infra vCenter work — if sentra-infra ships a vCenter
   adapter, one service should own the read and the other reuse it (today ITAM carries `engine/connectors/vcenter.js`).
4. **Manual / barcode / QR** — off-network gear (projectors, UPS, printers not on the mgmt net, spares). Flagged
   `no_network_source` automatically when added without a network identity. Looked up by tag by anyone.
5. **Imports** — CSV and CMDB connectors (ManageEngine AssetExplorer, the portal `/api/db` asset store). Idempotent.
6. **Asset Discovery** (`engine/discovery/**`, source `discovery`) — admin-defined scopes swept actively (ICMP/TCP,
   SNMP v2c/v3 with LLDP/CDP) behind a mandatory pre-scan safety gate, plus passive reads of AD, vCenter, Hyper-V
   reports, CUCM, Azure, AWS and the ARP table; write-only credential vault; results are approved / merged / ignored by a
   System Admin, then connected to the SIEM in one click. See **docs/DISCOVERY.md**.

### De-duplication + merge
Incoming records are matched by weighted identity keys (serial/UUID/asset-tag strongest, MAC medium, name weak). A
single strong-key match merges deterministically; conflicting strong keys are flagged *ambiguous* for the AI tie-break
or a human. Per-field precedence decides who wins: discovery sources win technical facts (OS, CPU, MAC, IP), humans and
imports win business facts (owner, location, warranty). **A human edit locks that field** against later discovery.

## AI layer (advisory, labelled "AI — verify")
Private model like sentra-grcai; **"not configured"** until `ai.private_url` is set. Everything is advisory and validated
JSON; the model never changes or retires an asset.
- **Deterministic findings (work with NO model):** not-seen-for-N-days, shadow IT (sensor-seen, unmanaged, no owner →
  cross-check ASM), missing owner/location/warranty, warranty/EOL expiring or passed, licence over/under-deployment,
  licence expiry.
- **Model features (`POST /ai/run/:feature`):** `classify` (type/vendor normalisation + duplicate tie-break),
  `relate` (CMDB relationship inference — high-impact links stay *proposed* for human confirm), `refresh` (lifecycle
  plan). Every call is sanitised (PII/IP/IDs stripped) and recorded in the hash-chained audit log.

## API (`/api/itam/*`) — roles: viewer / operator (asset manager) / admin
`GET /summary · /assets (+/:id) · /software · /licences · /cmdb?asset= · /discovery · /stocktake · /ai/findings ·
/reports · /audit (admin) · /status · /health`.
Writes: `POST /assets` (operator add/barcode) · `POST /assets/:id` (edit) · `POST /assets/:id/{retire,dispose,move,
assign,repair,restock,activate,lost,found}` · `POST /licences` · `POST /cmdb` (confirm/add) · `POST /discovery/run?
source=netops|vcenter` (admin) · `POST /discovery/:id/adopt` · `POST /stocktake` + `/:id/scan` + `/:id/close` ·
`POST /ai/findings/regenerate|/:id/accept|/:id/dismiss` · `POST /ai/run/:feature` · `POST /import/run` · `GET/POST
/settings` (admin) + `/settings/credential` (write-only) + `/settings/agent-tokens`.
**Everyone (viewer up) can `GET /lookup?tag=` — self-service "whose is this / is it ours".**
**No hard delete:** retire/dispose set a status and append a lifecycle event; the record and audit stay.

## Endpoint agent (`itam-agent`) — least privilege
Cross-platform, outbound-only, store-and-forward. It only **reads** local inventory and **POSTs** to `/agent`; it never
listens. Install (as a non-admin service account):

- **Windows:** `powershell -ExecutionPolicy Bypass -File agent/install/install.ps1 -Server https://<portal>/agent` (prompts for the one-time token, or `-TokenFile <path>`; the token reaches the agent on stdin, never on a command line)
  Runs as **LOCAL SERVICE** (not admin). Reads Win32_* CIM classes + the Uninstall registry keys + HotFix list.
- **Linux:** `sudo agent/install/install.sh --server https://<portal>/agent` (token prompted / piped on stdin, or `--token-file <path>`, deleted after enrolment)
  Runs as the unprivileged **itam-agent** user. Reads `/proc`, `/sys/class/dmi/id`, `dpkg`/`rpm`.
- **macOS:** same `install.sh`; uses `system_profiler` + `sw_vers`.

Enrolment: an admin issues a **one-time token** (ITAM > Settings > Agent tokens, or `POST /settings/agent-tokens`); the
agent exchanges it once for a per-agent key (sha256 stored server-side). Reports carry a monotonic `seq` + `nonce` +
timestamp — replays and stale reports (outside the clock-skew window) are rejected. Every probe degrades to null on
failure; the agent never crashes. State (incl. the key) is `0600` under `/var/lib/sentra-itam-agent` (Linux/macOS) or
`%ProgramData%\sentra-itam-agent` (Windows, ACL-restricted).

## vCenter setup (read-only)
1. Create a vSphere **read-only** role account (no power/config privileges).
2. In the portal: ITAM > Settings — set `vcenter.base_url` and the username/password (write-only; the engine never
   returns them). `insecure_tls` only for a lab self-signed cert.
3. Enable the `vcenter` source, then `POST /discovery/run?source=vcenter` (admin). Hosts/VMs are staged for adoption
   unless `auto_adopt` is on; `runs_on` links are proposed for confirmation.

## Import from ManageEngine AssetExplorer
Export assets to CSV, then ITAM > Settings > Import (or `POST /import/run` with `{"format":"csv","mapping":
"manageengine","text":"<csv>"}`). The `manageengine` mapping covers Asset Name/Tag, Product Type, Manufacturer, Serial
Number, IP/MAC, OS, Location, Department, User, Warranty Expiry, Acquisition Date, Cost, PO. Unmapped columns are
reported back. Re-running the same file **merges** by serial/tag — it never creates duplicates. Use `mapping:"db"` for
the portal `/api/db` asset store, `mapping:"generic"` for snake_case CSV/JSON.

## What the customer must supply
- **Private model URL** (`ai.private_url`) — AI stays "not configured" until set.
- **sentra-netops API base URL** (+ token if required) to subscribe to site-sensor devices/topology.
- **vCenter** base URL + a **read-only** service account (for the VMware estate).
- **CMDB/AssetExplorer export** (CSV) for the initial import, and the **off-network asset list** (barcodes/photos).
- Decision on **agent rollout** scope and the schedule for issuing enrolment tokens.
- Business data that discovery cannot know: **owners, custodians, departments, sites/locations, warranty + purchase**.

## Deploy (Safari)
`sudo python3 install/apply_safari_itam.py --private-url http://<S1>:9093 [--dry-run]` stages the `safari-itam` tenant
locally (it contacts no servers), then runs `install/install.sh`. Include `install/nginx-itam.conf` in the portal
server block and reload nginx. Container budget ~160 MB (systemd `MemoryMax=400M`).
