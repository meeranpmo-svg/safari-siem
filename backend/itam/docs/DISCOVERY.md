# Asset Discovery — the organisation (sentra-itam)

Asset Discovery extends the sentra-itam engine (no separate service). It finds what is on the network and in the
systems of record, correlates every sighting into one device, lets a **System Admin** decide what becomes an IT
asset, connects approved assets to the SIEM in one click, and raises alerts for unknown (rogue) devices and for SIEM
sources that go silent. Node >= 20, standard library only. Everything that changes state is written to the existing
hash-chained ITAM audit log with the user's name.

Customer sites: **Riyadh HQ** (main), **Jeddah DR**, **Riyadh Olaya**, **Alkhobar**. Platform server:
**the platform server** — every probe originates from this address.

## 1. Roles

| Portal role | Can do |
|---|---|
| `admin` (System Admin) | everything below: scopes, safety-gate checklist, global method switches, credentials (incl. reading their metadata), run / cancel scans, approve / ignore / merge / restore results, SIEM connect + health check, Hyper-V upload, discovery audit |
| `operator`, `viewer` | read-only: dashboard, scopes, runs, results (with duplicates), SIEM connection status |

The engine enforces this on every route (HTTP 403); the UI hides controls by the `/auth/whoami` role.

## 2. Scopes

A scope is a set of addresses plus how, when and how fast to discover them.

* **Addresses** — CIDR (`10.20.0.0/24`), range (`10.20.0.10-10.20.0.50` or `10.20.0.10-50`) or single IPs.
  RFC 1918 only by default; a public range needs `allow_public: true` (only ranges the organisation owns).
  Loopback, link-local, multicast and reserved space are always refused. Max `discovery.max_hosts_per_scope`
  (default 4096) addresses per scope. Network and broadcast addresses of /0–/30 are never probed.
* **Exclusions** — IPs / CIDRs / ranges that are never probed (printers that dislike scans, OT, …).
* **Site** (one of the four), optional **VLAN id** (1–4094), label, and **infra** flag (server / infrastructure
  subnet → an unknown device alerts immediately).
* **Schedule** (Riyadh time, UTC+3, no DST): `manual` · `once` (`YYYY-MM-DDTHH:MM`) · `daily` (`HH:MM`) ·
  `weekly` (`day` 0–6 or sun..sat + `HH:MM`). Optional **scan window** `{start, end}` (may cross midnight):
  active methods only run inside it (manual runs too); a run still going when the window closes stops
  (`stopped_window`).
* **Rate limits** — `max_hosts_per_sec` (1–500, token bucket) and `concurrency` (1–64).
* **Methods** — per-scope on/off, each also switchable globally (`POST /discovery/methods`).

### Methods

| Method | Kind | What it does | Credential |
|---|---|---|---|
| `sweep` | **active** | ICMP via the system `fping` (batch) or `ping` (per host) through `child_process.execFile` with a strict argument array (no shell; every address is re-serialised from its parsed form) + TCP connect probes (default 22, 80, 135, 443, 445, 3389, 5985; open *or* refused = host up) | — |
| `snmp` | **active** | SNMP get of sysDescr as the UDP 161 liveness probe, then sysDescr / sysObjectID / sysName / sysLocation, ifPhysAddress, ENTITY-MIB serial + model (chassis entity preferred), LLDP-MIB `lldpRemTable` (+ management address) and CISCO-CDP-MIB `cdpCacheTable` → neighbour edges. v2c or v3 USM (SHA-1/SHA-256, AES-128). Read-only by construction (no SetRequest can be encoded) | `snmp_v2c` / `snmp_v3` |
| `arp` | passive | `/proc/net/arp` of the platform server (on-link subnets only) | — |
| `ad` | passive | LDAPS (or LDAP + StartTLS, never cleartext) to `dc-hqa.corp-hq.com:636` (dial 192.168.1.52), CA `/etc/ssl/corp-hq/corp-ca.pem`; computer objects: dNSHostName, operatingSystem(+Version), lastLogonTimestamp, OU, enabled flag, DC role. Optional DNS resolution of dNSHostName joins AD computers with swept hosts inside the scope | `ldap` |
| `vcenter` | passive | vSphere REST, GET only (+ own session): hosts, VMs per host, guest OS, IPs, MACs, power state | `vcenter` |
| `hyperv` | passive | **report ingestion** from the Windows agent / relay (see §6). Direct WinRM: *future* | — |
| `cucm` | passive | AXL `listPhone` (name/MAC, model, description, device pool, protocol) + RisPort70 `selectCmDevice` (registration status, IP) | `cucm_axl` |
| `azure` | passive | client-credentials token + Azure Resource Graph (VMs joined to NICs: private IPs, MACs, size, OS type) | `azure` |
| `aws` | passive | EC2 `DescribeInstances` (SigV4) per configured region | `aws` |

## 3. SAFETY GATE — mandatory pre-scan checklist

**Active methods (sweep, SNMP) cannot run for a scope until a System Admin completes its pre-scan checklist.**
Until then the scope runs passive methods only (AD, vCenter, Hyper-V reports, CUCM, cloud, ARP table) and every run
lists the blocked methods with the reason. The checklist (`POST /discovery/scopes/:id/checklist`) requires:

1. **Firewall**: the network firewall allows from **the platform server** to the scope: SNMP **UDP 161**, SSH **TCP 22**,
   WinRM **TCP 5985/5986** and **ICMP** echo (`firewall.snmp_161 / ssh_22 / winrm_5985_5986 / icmp = true`).
2. **SOC notified** of the scan window: `soc_notified_name` + `soc_notified_date` (YYYY-MM-DD).
3. **Approved by**: `approved_by` (name).

The completion is audited (`discovery.scope.checklist`, with the admin's user name, the targets and every answer)
and bound to a fingerprint of the scope's addresses, exclusions and public flag: **changing any of them closes the
gate again** (`gate.stale = true`, audited as `checklist_invalidated`). An admin can revoke it at any time. An SNMP
credential test is also gated: the test host must sit inside an active scope whose gate is open. The dashboard and
the scopes page show pending gates prominently.

## 4. Credential vault (write-only)

Kinds: `snmp_v2c` (community), `snmp_v3` (user, auth/priv passphrases ≥ 8, SHA/SHA-256 + AES), `ssh` and `winrm`
(**stored for future use only — nothing is executed with them**), `ldap` (bind DN + password; target: servers, dial
IP, base DN, CA file), `vcenter` (target: https URL, CA file or approved SHA-256 certificate fingerprint),
`cucm_axl` (target: host, port 8443, AXL version, CA file), `azure` (tenant + client id; secret write-only), `aws`
(access key id + secret; target: regions).

* AES-256-GCM, 12-byte random IV, AAD `sentra-itam-discovery|<id>|<version>`; master key = 64 hex chars in
  `discovery.vault_key_file` (default `/etc/sentra-itam/discovery-vault.key`, mode 600, owner sentra-itam). Only
  ciphertext is stored in the state journals.
* The API returns **only**: `set: true`, a fingerprint (HMAC of the secret under a key derived from the master key —
  shows *that* it changed, reveals nothing), version, `last_tested {at, ok, latency_ms, error_class}`, who/when, and
  the non-secret target (host / URL / regions).
* **Never logged**: every secret opened from the vault is registered with a process-wide scrubber that masks it in
  every log line (even an error string from a device or library) and in discovery audit details; secret-looking
  field names are redacted too. Tests assert the secrets never appear in logs, audit, API responses or on disk.
* **Test connection** (admin) returns only `{ok, latency_ms, error_class}` — `auth | timeout | unreachable | tls |
  config | protocol | not_supported`.
* A credential used by a scope cannot be deleted (409) until it is removed from the scope.

## 5. Results review, de-duplication, classification

Every observation (any method, any run) is correlated into one device: **MAC**, **serial number** and a stable source
id (VM uuid, cloud instance id, AD DN, CUCM device name) are strong keys; an **IP** joins only inside the same scope
and only if no MAC contradicts it; the **host name** never joins (weak duplicate hint only). Each device shows type,
vendor, OS, IP(s), MAC(s), host name, location (sysLocation) / site / VLAN, first and last seen, the methods that saw
it, the number of scans that saw it, a confidence and the classification evidence.

* **Types**: server, workstation, switch, router, firewall, AP, printer, phone, VM, cloud instance, unknown — from
  systems of record (vCenter / Hyper-V / cloud / CUCM / AD), sysDescr rules, sysObjectID enterprise numbers, open
  ports, MAC OUI and host-name patterns (weak). The OUI and enterprise-number tables are small embedded lists of
  common vendors (**verify** against the IEEE MA-L registry / IANA PEN when a vendor is missing).
* **CMDB duplicates** (`engine/model/merge.js duplicateCandidates`): MAC and serial = strong, host name = weak.
* **Approve** → staged and adopted through the existing ITAM ingest flow; the merge engine de-duplicates against
  existing assets (a strong match merges instead of creating a second record — `merged_into_existing`). Human
  business data (owner, type set by a person, …) is never overwritten. LLDP/CDP neighbours between approved devices
  become proposed `connected_to` CMDB relationships.
* **Ignore** needs a reason; it is remembered by MAC / serial / source id (or IP for an address-only device), so a
  re-discovered device stays ignored. **Restore** undoes it. **Merge** attaches the device to a chosen asset.

## 6. Hyper-V (agent / relay report)

Direct WinRM from Node is not reliably implementable with the standard library (WS-Man + NTLM/Kerberos message
encryption), so it is marked **future**. Instead the Windows side reports the inventory:

```powershell
# run on each Hyper-V host (read-only cmdlets), e.g. as a scheduled task of the ITAM endpoint agent or the SIEM relay
$vms = Get-VM | ForEach-Object {
  $n = Get-VMNetworkAdapter -VM $_
  [pscustomobject]@{ name = $_.Name; vm_id = "$($_.VMId)"; state = "$($_.State)"; generation = $_.Generation
    ips = @($n.IPAddresses | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' }); macs = @($n.MacAddress) } }
$body = @{ host = @{ name = $env:COMPUTERNAME; fqdn = ([System.Net.Dns]::GetHostEntry('').HostName)
  ip = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.PrefixOrigin -ne 'WellKnown' } | Select-Object -First 1).IPAddress
  os = (Get-CimInstance Win32_OperatingSystem).Caption }; vms = @($vms); collected_at = (Get-Date).ToUniversalTime().ToString('o') }
Invoke-RestMethod -Method Post -Uri 'https://<portal host>/itam-agent/hyperv' -Headers @{ Authorization = "Bearer $AgentKey" } `
  -ContentType 'application/json' -Body ($body | ConvertTo-Json -Depth 5)
```

`POST <agent prefix>/hyperv` (`api.agent_prefix`: default `/agent`; on the portal `/itam-agent`, because `/agent/` already serves the SIEM agent kits) authenticates the enrolled ITAM agent key; the report is accepted when an active scope with the
Hyper-V method enabled covers `host.ip`. An admin can upload the same JSON at `POST /api/itam/discovery/hyperv/import`
(`{scope_id, report}`).

## 7. Connect to the SIEM

`POST /discovery/connect {asset_id, kind?}` (admin) calls the SIEM onboarding API server-side:
`POST {siem.base_url}/api/soc/onboard/sources {id, kind, site, match_ip, label}` over loopback with the SIEM
`X-Sentra-Proxy-Secret` (read from `discovery.siem.secret_file`) and the admin's identity (`X-Auth-User`, role admin).
The SIEM's one-time token and rendered steps are returned to the admin **once**; only `source_id` / kind / site are
stored on the asset — never the token. Source ids are `itam-<asset name>` (suffix `-2…` on a clash). ITAM site names
map to SIEM site ids via `discovery.siem.site_map` (Riyadh HQ → riyadh-hq, Jeddah DR → jeddah, Riyadh Olaya →
riyadh-olaya, Alkhobar → alkhobar).

| Device | SIEM connector kind |
|---|---|
| Windows domain controller (AD) | `dc` |
| Windows server / workstation | `windows` (token) |
| VMware ESXi host | `vmware-esxi-hosts` |
| FortiGate | `fortigate` · Palo Alto `palo-alto` · Cisco ASA/FTD `cisco-asa-ftd` · Check Point `check-point` · Sophos `sophos-firewall` · SonicWall `sonicwall` · F5 `f5-bigip` |
| Cisco switch / router / AP | `cisco` |
| iDRAC / iLO | `dell-idrac` / `hpe-ilo` |
| Linux / Unix | `linux` |
| other switch / router / AP / firewall | `syslog` |
| printer, IP phone, cloud instance | not connected here (print module / CUCM / cloud connectors) |

An admin can override the kind (allowed: the connectable kinds above).

**Health**: every `discovery.siem.health_interval_min` (5) the engine reads `GET /api/soc/onboard/sources` and marks
each connected asset `receiving | silent | waiting | missing`. A source that sent nothing for longer than
`discovery.siem.silent_minutes` (60) — or never, or that disappeared — raises the ITAM finding **`siem_silent`**
(labelled "Discovery"); it resolves itself when events flow again. Admins can run the check on demand.

## 8. Dashboard, rogue devices, bridge

`GET /discovery/dashboard`: total assets, connected vs not connected to the SIEM, silent sources, new devices since
the last scan, devices by type / status, running and next scheduled scans, scopes waiting for the safety gate,
vault status. **Unknown / rogue** = status *new*, not in the CMDB (no MAC/serial match), not ignored, seen only by
network methods (not by AD / vCenter / Hyper-V / CUCM / cloud), and seen ≥ `rogue_min_sightings` (default 3) scans
or on an *infra* scope. Each one is an ITAM finding **`rogue_device`** that resolves when the device is approved,
merged or ignored.

**Bridge (off by default)**: with `discovery.siem.bridge.enabled = true`, every new rogue device is posted once as
NDJSON `{source:'itam', kind:'rogue-device', at, device_id, ip, mac, vendor, type, site, scope_id, seen_count,
first_seen, reason, severity}` to the SIEM HTTP ingest (`bridge.url`, default
`http://127.0.0.1:9120/ingest/itam-bridge`) with header `X-Sentra-Token` from `bridge.token_file`. The SIEM side needs
an HTTP-ingest source `itam-bridge` with that token (**verify** with the SIEM configuration: `sources[]` entry +
`secrets.ingest_tokens["itam-bridge"]`).

## 9. Scheduler, cancel, audit

The engine scheduler ticks every `scheduler_tick_s` (30 s), starts due scopes (respecting the scan window and
`max_concurrent_runs`, default 2) and computes the next run in Riyadh time. One run per scope at a time. A run can be
cancelled (`POST /discovery/runs/:id/cancel`); the flag is honoured between hosts and methods. Runs interrupted by a
restart are marked `interrupted`.

Audited actions (`GET /audit`, `GET /discovery/audit`): `discovery.scan.start|finish|cancel`,
`discovery.approve|ignore|restore|merge`, `discovery.credential.create|update|delete|test`,
`discovery.scope.create|update|enable|disable|archive|checklist|checklist.revoke`, `discovery.connect`,
`discovery.methods.update`, `discovery.hyperv.report`, `findings.sync`.

## 10. API — `/api/itam/discovery/*`

| Method | Path | Role | Purpose |
|---|---|---|---|
| GET | `/discovery/dashboard` | any | dashboard figures |
| GET | `/discovery/methods` | any | global switches, credential kinds, sites |
| POST | `/discovery/methods` | admin | `{methods:{sweep:bool…}, rogue_min_sightings, max_concurrent_runs, icmp_mode}` |
| GET | `/discovery/scopes` | any | scopes (+ gate state, allowed / blocked methods) |
| POST | `/discovery/scopes` | admin | create `{name, site, vlan?, label?, targets[], exclusions[], allow_public?, infra?, schedule, window?, rate, methods}` |
| GET / POST | `/discovery/scopes/:id` | any / admin | read / update |
| POST | `/discovery/scopes/:id/enable` · `/disable` · `/archive` | admin | status |
| POST | `/discovery/scopes/:id/checklist` | admin | complete the safety gate |
| POST | `/discovery/scopes/:id/checklist/revoke` | admin | close the gate |
| POST | `/discovery/scopes/:id/run` | admin | start now |
| GET | `/discovery/runs` · `/discovery/runs/:id` | any | runs (`?scope_id&status&limit`) |
| POST | `/discovery/runs/:id/cancel` | admin | cancel |
| GET | `/discovery/credentials` · `/discovery/credentials/:id` | admin | metadata only |
| POST | `/discovery/credentials` | admin | create `{kind, label, target, secret}` |
| POST | `/discovery/credentials/:id` | admin | update (empty secret fields keep the stored value) |
| POST | `/discovery/credentials/:id/delete` | admin | delete (409 while used) |
| POST | `/discovery/credentials/:id/test` | admin | `{host?}` → `{ok, latency_ms, error_class}` |
| GET | `/discovery/results` | any | `?status=new|approved|ignored|merged|all&type&site&scope_id&method&q&limit` |
| GET | `/discovery/results/:id` | any | detail + duplicates + proposed asset fields |
| POST | `/discovery/results/:id/approve` · `/ignore {reason}` · `/restore` · `/merge {asset_id}` | admin | decisions |
| POST | `/discovery/hyperv/import` | admin | `{scope_id, report}` |
| GET | `/discovery/connect` | any | connections, candidates, kind mapping |
| POST | `/discovery/connect` | admin | `{asset_id, kind?}` → token + steps (once) |
| POST | `/discovery/connect/health` | admin | run the SIEM health check now |
| GET | `/discovery/audit` | admin | discovery audit tail |
| POST | `<agent prefix>/hyperv` (AS: `/itam-agent/hyperv`) | agent key | Hyper-V report |

Errors are JSON `{error}`; 400 validation, 403 role, 404 unknown id, 409 state conflict (gate, running, in use,
already decided), 502/503 SIEM or vault unavailable.

## 11. Configuration (`/etc/sentra-itam/config.json` → `discovery`)

```json
{ "discovery": {
    "sites": ["Riyadh HQ", "Jeddah DR", "Riyadh Olaya", "Alkhobar"],
    "vault_key_file": "/etc/sentra-itam/discovery-vault.key",
    "max_hosts_per_scope": 4096, "icmp_mode": "ping", "ping_bin": "/usr/bin/ping", "fping_bin": "/usr/bin/fping",
    "icmp_timeout_ms": 800, "tcp_timeout_ms": 800, "snmp_timeout_ms": 1500, "ad_resolve_dns": true,
    "siem": { "base_url": "http://127.0.0.1:9120", "prefix": "/api/soc", "secret_file": "/etc/sentra-itam/siem-proxy-secret",
              "silent_minutes": 60, "health_interval_min": 5,
              "bridge": { "enabled": false, "url": "http://127.0.0.1:9120/ingest/itam-bridge", "token_file": "/etc/sentra-itam/siem-bridge-token" } } } }
```

## 12. Least-privilege accounts the customer provides

| For | Account / permission |
|---|---|
| SNMP | v3 user (authPriv, SHA-256 + AES) with a read-only view of system, interfaces, ENTITY-MIB, LLDP-MIB, CISCO-CDP-MIB — or a read-only v2c community restricted by ACL to the platform server |
| Active Directory | a standard domain user (no admin rights) — read of computer objects is granted to Authenticated Users by default; the AD CS root CA PEM at `/etc/ssl/corp-hq/corp-ca.pem` |
| vCenter | a vSphere user with the built-in **Read-only** role at the vCenter root, propagated; the vCenter CA chain (or the approved certificate fingerprint) |
| CUCM | an application user with **Standard AXL Read Only API Access** (+ read access for RisPort70 — verify the role name for the CUCM version) |
| Azure | an app registration with the **Reader** role on the subscriptions (or management group) |
| AWS | an IAM user / role with only `ec2:DescribeInstances` |
| Hyper-V | the ITAM endpoint agent (or SIEM relay) on each Hyper-V host, enrolled with an ITAM agent token |
| SSH / WinRM | optional, stored for future use only |

## 13. "Verify" items

* CUCM: exact AXL `listPhone` returnedTags / paging limits and RisPort70 `selectCmDevice` envelope for the customer's
  CUCM version (AXL schema download in CUCM admin); RIS user role name and the 1000-devices-per-call limit.
* vCenter: `/guest/networking/interfaces` and `/guest/identity` need VMware Tools; field names checked against the
  vSphere Automation 7/8 docs, confirm on the customer's build.
* Azure Resource Graph KQL (NIC join, `powerState` projection) against the tenant.
* CISCO-CDP-MIB `cdpCacheTable` columns and the `lldpRemManAddrTable` index decoding on the customer's switch firmware.
* OUI and sysObjectID enterprise tables (small embedded lists).
* ICMP from the hardened service: `ping` uses unprivileged ICMP sockets when `net.ipv4.ping_group_range` includes the
  sentra-itam group; confirm `fping` behaviour under `NoNewPrivileges` (file capabilities are not gained), otherwise use
  `icmp_mode: "ping"`.
* SIEM bridge source definition (`itam-bridge` HTTP-ingest source + token).
