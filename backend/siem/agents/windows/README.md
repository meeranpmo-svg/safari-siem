# SentraAgent — Windows event forwarder

Ships Windows event logs to the Sentra SIEM over HTTPS. Plain PowerShell 5.1 + .NET, no modules, no binaries.

| file | purpose |
|---|---|
| `sentra-agent.ps1` | the forwarder (one pass per run, or `-Loop`) |
| `install-agent.ps1` | installs on a host: folders + ACLs, config, token, scheduled task |
| `uninstall-agent.ps1` | removes the task, program folder and (optionally) the data folder |

## How it works

```
Event log channels ──► EventLogReader (XPath: RecordID > bookmark, level / small id lists)
                  ──► allow-list filter per channel ──► JSON per event ──► NDJSON batch (≤ 2000 events, ≤ 1 MB)
                  ──► gzip ──► HTTPS POST https://<collector>/ingest/<src_id>   (X-Sentra-Token, TLS 1.2+, cert validation on)
                         └─ collector down ──► C:\ProgramData\SentraAgent\queue\*.ndjson.gz  (≤ 200 MB, replayed oldest-first)
```

* **Bookmarks** (`bookmarks.json`, last EventRecordID per channel) advance only once the events were accepted by the
  collector (HTTP 2xx) or written to the local queue. A crash or reboot mid-pass re-reads, it never skips (at-least-once;
  every POST carries `X-Sentra-Batch-Id`, stable across retries, so the engine can drop duplicates).
* **Queue full** (default policy `pause`): the agent stops reading and the events wait in the Windows event log itself.
  Nothing is lost unless the event log wraps — hence `-SetLogSizes` (Security 1 GB). Policy `drop-oldest` exists
  but is not recommended.
* **Back-off**: 3 tries per batch inside a pass (2 s, 4 s), then the collector is left alone for 1, 2, 4 … 15 minutes;
  new events meanwhile go straight to the queue.
* **Heartbeat**: every 5 minutes an event `Channel="SentraAgent", EventID=0` with agent version, queue size, last success
  and bookmarks — the SIEM Sources page shows a Windows host as *silent* when heartbeats stop.
* **First start**: a channel without a bookmark is read from the last 60 minutes only (`FirstRunLookbackMinutes`).
* **Cleared log**: if the newest RecordID is below the bookmark the channel is re-read from the start (and the
  `1102`/`104` "log cleared" event itself is forwarded so a detection rule can alert on it).
* **Self-noise**: 4104 script-block events whose `Path` is the agent script are dropped (`SkipOwnScriptBlocks`),
  otherwise the agent would log itself every minute.
* **Single instance**: global mutex `Global\SentraAgentForwarder`; the task also uses `IgnoreNew`.

### Event format (one JSON object per line)

```json
{"Channel":"Security","EventID":4625,"TimeCreated":"2026-09-29T08:15:02.123Z","Computer":"DC01.sentra.local",
 "RecordId":918273,"Level":0,"ProviderName":"Microsoft-Windows-Security-Auditing",
 "EventData":{"TargetUserName":"j.doe","IpAddress":"10.1.2.3","LogonType":"3","Status":"0xc000006d", "...":"..."},
 "Message":"An account failed to log on. ... (first 2 KB)"}
```

`EventData` holds the named `<Data>` elements (or the flattened `<UserData>` children, e.g. for 1102). Values are
strings, each capped at 32 KB (`MaxFieldChars`). `Message` is the rendered text, truncated to 2048 UTF-8 bytes; it is
off by default for Sysmon and PowerShell (all information is in `EventData` and it saves a lot of volume).

## Channels and default allow lists

| channel | default filter |
|---|---|
| `Security` | ~180 security-relevant IDs: logon 4624/4625/4647/4648/4672 (4634 logoff left out for volume), account & group management (47xx), Kerberos/NTLM (4768–4776), process creation 4688, services 4697, scheduled tasks 4698–4702, audit policy 4719, log cleared 1102, firewall rule changes 4946–4950, DS changes 5136–5141, PnP 6416, … (see `sentra-agent.ps1 -PrintDefaultConfig`) |
| `System` | service install 7045, start-type change 7040, service crashes, log cleared 104, shutdown/boot (1074, 6005/6006/6008, 12/13/41), time change (1), Netlogon/ZeroLogon (5805, 5827–5831) … |
| `Application` | **errors only** (Level 1 Critical, 2 Error), all IDs |
| `Microsoft-Windows-Sysmon/Operational` | all — filtering is done by the Sysmon configuration |
| `Microsoft-Windows-PowerShell/Operational` | 4104 (script block logging) |
| `Microsoft-Windows-Windows Defender/Operational` | detections 1006–1009/1116–1122, scan failures, RTP/tamper/config changes 5001–5013, update failures 2001/2003/2004 |
| `MSExchange Management` | Exchange servers only: admin audit of cmdlets, 1 (succeeded) and 6 (failed) → engine action `exchange-cmdlet`. Agents installed before this default existed: add `{"Name":"MSExchange Management","Enabled":true,"IncludeMessage":true,"EventIds":[1,6]}` to `Channels[]` in their `config.json`. Message tracking / IIS logs: see `agents/exchange/README.md` |

Edit `C:\ProgramData\SentraAgent\config.json` → `Channels[]`: `EventIds` (empty = all), `ExcludeEventIds`, `Levels`
(empty = all), `IncludeMessage`, `Enabled`. Channels that do not exist on the host (e.g. Sysmon not installed) are
skipped silently. Add `{"Name":"ForwardedEvents","EventIds":[],...}` on a Windows Event Collector (WEC) server to ship
events collected by WEF — `Computer` keeps the original host name.

## Install

Prerequisites: Windows Server 2012 R2+ / Windows 10+, Windows PowerShell 5.1, TCP 443 to the collector,
the collector certificate trusted by the host (internal CA pushed by GPO), an ingest token for the source id
(on the SIEM: `sudo sentra-siem-token show win-servers`).

```powershell
# elevated PowerShell, from the folder that contains the three scripts
.\install-agent.ps1 -CollectorUrl https://siem.example.local -SourceId win-servers          # prompts for the token (hidden)
.\install-agent.ps1 -CollectorUrl https://siem.example.local -SourceId win-dc `
                    -TokenFile \\deploy$\sentra\win-dc.token -SetLogSizes                             # unattended
```

Options: `-PinnedThumbprint <sha1|sha256>` (pin the collector certificate *in addition to* normal validation),
`-Loop` (one long-running process instead of a pass per minute — for busy domain controllers; `-LoopSeconds 5-300`, default 30),
`-Realtime` (= `-Loop -LoopSeconds 5`: events reach the SIEM within about 5 seconds instead of up to a minute — use it where logs
must appear instantly; to switch an installed server, re-run `.\install-agent.ps1 -CollectorUrl … -SourceId … -Realtime`), `-SetLogSizes`,
`-ResetConfig`, `-NoStart`. Re-running the installer upgrades the script and keeps config, token and bookmarks.

What it creates:

| path | ACL | contents |
|---|---|---|
| `C:\Program Files\SentraAgent\sentra-agent.ps1` | SYSTEM, Administrators full; Users read | the agent |
| `C:\ProgramData\SentraAgent\` | **SYSTEM, Administrators only** (inheritance removed) | `config.json`, `token.txt`, `bookmarks.json`, `state.json`, `queue\`, `logs\agent.log` (5 MB × 3) |
| Task Scheduler `\SentraAgent` | runs as SYSTEM | every minute (+ at boot), 30 min limit, `IgnoreNew` |

Mass deployment: copy the three scripts to a share readable by computer accounts, one token file per source id on
a share readable only by the deployment account, and run `install-agent.ps1 … -TokenFile …` from a GPO startup
script / SCCM / Intune. `install-agent.ps1 -ExportTaskXml C:\temp\SentraAgent.xml` exports the task definition for GPO
Preferences. If the machine policy enforces `AllSigned`, sign `sentra-agent.ps1` with the internal code-signing
certificate (`Set-AuthenticodeSignature`) — `-ExecutionPolicy Bypass` on the command line cannot override a GPO.

## Test without sending

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\sentra-agent.ps1 -DryRun -Channel System -Count 5
powershell -NoProfile -ExecutionPolicy Bypass -File .\sentra-agent.ps1 -DryRun -Channel Security -Count 5   # elevated
powershell -NoProfile -ExecutionPolicy Bypass -File .\sentra-agent.ps1 -PrintDefaultConfig
```

Dry-run prints the JSON lines to stdout and a size summary to stderr; it reads no config, uses no token, writes and
sends nothing.

## Pull mode - nothing installed on the servers (Windows Event Collector)

`setup-wec-pull.ps1` creates a collector-initiated subscription on ONE domain-joined Windows Server that has this agent
installed (the collector): it pulls Security / System / Application errors / PowerShell / Sysmon / Defender events from
every listed server over WinRM (its computer account, Kerberos), and the agent ships them from `ForwardedEvents`. Each
event keeps its own server name, so every server appears separately in the SIEM.

Run it elevated, as a domain admin, either on the collector or - without logging on to it - from a domain controller /
admin server with `-Collector`:

```powershell
# from a domain controller: sets up the collector remotely over WinRM
.\setup-wec-pull.ps1 -FromAD -GrantReaders -Collector lr01.corp-hq.com
.\setup-wec-pull.ps1 -Status -Collector lr01.corp-hq.com     # Active / error per server

# or on the collector itself
.\setup-wec-pull.ps1 -FromAD -GrantReaders       # every enabled Windows Server in AD - read over ADSI, no RSAT needed (or -Servers a,b / -ServerFile)
.\setup-wec-pull.ps1 -Status
.\setup-wec-pull.ps1 -ExportXml C:\temp\sub.xml -Servers a,b   # review the subscription first
.\setup-wec-pull.ps1 -Remove
```
Servers need WinRM (default on Windows Server 2012+) and TCP 5985 open from the collector; `-GrantReaders` adds the
collector to "Event Log Readers" on each (domain controllers: the domain's builtin group), from the machine the script
runs on. Nothing else changes on them. A machine outside the domain is refused: servers only send to a domain member.

## Operations

* **Status**: `Get-Content C:\ProgramData\SentraAgent\logs\agent.log -Tail 20` — one `pass done:` line per minute;
  `state.json` has `last_success`, `next_attempt`, `backoff_minutes`, `queue_full_since`.
* **Run a pass now**: `schtasks /Run /TN SentraAgent`.
* **Token rejected** (`HTTP 401/403` in the log): batches stay queued; write the new token into `token.txt`
  (re-run the installer with `-TokenFile`), the queue drains on the next pass.
* **`TrustFailure`**: the collector certificate is not trusted by this host (or the pin does not match — the log shows
  the SHA-256 it saw). Import the issuing CA into *Local Computer → Trusted Root* (GPO), never disable validation.
* **Re-send history**: stop the task, edit/delete the channel's entry in `bookmarks.json` (deleting it = last 60 min).
* **Throughput**: measured ~380 events/s per pass with message rendering on a laptop (3000 System events in ~8 s);
  a pass reads at most 20 000 events per channel. For DCs above ~300 EPS sustained: use `-Loop`, keep
  `IncludeMessage=false` for Security (the engine parses `EventData`), trim the allow list, or forward with WEF to a
  WEC server and run the agent there on `ForwardedEvents`.
* **Uninstall**: `.\uninstall-agent.ps1` (keeps the data folder if unsent batches remain; `-Force` / `-KeepData`).

## Recommended Windows audit policy

Set by **GPO** (*Computer Configuration → Policies → Windows Settings → Security Settings → Advanced Audit Policy
Configuration*) for domain machines; the `auditpol` commands below are the equivalent for a single host / testing.
Subcategory names are for English Windows — on other languages use `auditpol /list /subcategory:* /v` for the GUIDs.

```bat
:: make advanced (subcategory) policy win over legacy category policy
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v SCENoApplyLegacyAuditPolicy /t REG_DWORD /d 1 /f

:: Account logon
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable
:: Account management
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable
auditpol /set /subcategory:"Computer Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Other Account Management Events" /success:enable /failure:enable
auditpol /set /subcategory:"Distribution Group Management" /success:enable
:: Detailed tracking
auditpol /set /subcategory:"Process Creation" /success:enable
auditpol /set /subcategory:"Plug and Play Events" /success:enable
:: DS access (domain controllers)
auditpol /set /subcategory:"Directory Service Changes" /success:enable
auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable
:: Logon/Logoff
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Logoff" /success:enable
auditpol /set /subcategory:"Account Lockout" /failure:enable
auditpol /set /subcategory:"Special Logon" /success:enable
auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable /failure:enable
auditpol /set /subcategory:"Network Policy Server" /success:enable /failure:enable
:: Object access
auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable
auditpol /set /subcategory:"Certification Services" /success:enable /failure:enable
:: Policy change
auditpol /set /subcategory:"Audit Policy Change" /success:enable /failure:enable
auditpol /set /subcategory:"Authentication Policy Change" /success:enable
auditpol /set /subcategory:"Authorization Policy Change" /success:enable
auditpol /set /subcategory:"MPSSVC Rule-Level Policy Change" /success:enable /failure:enable
auditpol /set /subcategory:"Other Policy Change Events" /failure:enable
:: Privilege use
auditpol /set /subcategory:"Sensitive Privilege Use" /failure:enable
:: System
auditpol /set /subcategory:"Security State Change" /success:enable /failure:enable
auditpol /set /subcategory:"Security System Extension" /success:enable /failure:enable
auditpol /set /subcategory:"System Integrity" /success:enable /failure:enable
auditpol /set /subcategory:"Other System Events" /success:enable /failure:enable

:: command line in 4688
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
:: PowerShell script block logging (4104) - GPO: Administrative Templates > Windows Components > Windows PowerShell
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f

auditpol /get /category:*
```

Notes: *Directory Service Access* (4662) is very noisy on DCs and is not in the default allow list — add 4662 to the
Security `EventIds` only if DCSync detection by 4662 is wanted and the volume is acceptable. *Filtering Platform
Connection* (5156) and *File System* auditing are deliberately **not** enabled (volume); use Sysmon event 3 / FortiGate
logs for network visibility. Size the Security log to at least 1 GB on DCs (`-SetLogSizes` or GPO *Event Log*
settings) so it can buffer outages.

## Sysmon (recommended on servers and DCs)

* Binary: **Microsoft Sysinternals Sysmon** — official page <https://learn.microsoft.com/sysinternals/downloads/sysmon>
  (download only from Microsoft; verify the Authenticode signature: `Get-AuthenticodeSignature .\Sysmon64.exe`).
* Configuration: start from a reputable public baseline and review it before use, e.g.
  **SwiftOnSecurity sysmon-config** <https://github.com/SwiftOnSecurity/sysmon-config> (conservative, low noise) or
  **Olaf Hartong sysmon-modular** <https://github.com/olafhartong/sysmon-modular> (MITRE-mapped, more verbose).
  Keep the reviewed config in the organisation's own repository; do not pull it from the internet at install time.
* Install: `Sysmon64.exe -accepteula -i sysmonconfig.xml`; update config: `Sysmon64.exe -c sysmonconfig.xml`.
  The agent picks up `Microsoft-Windows-Sysmon/Operational` automatically (all event IDs; filter in the Sysmon config).

These are references only — nothing is downloaded by the agent or the installer.

## Baseline-hardening snapshot (agent 1.2+)

Once a day (`HardeningHours`, default 24; `0` turns it off) the agent reads the machine's security settings and sends them as
one event (`Channel SentraAgent`, `EventID 1`, `EventData.type = hardening`). It is READ-ONLY: `secedit /export` of the security
policy and user rights (to a temporary file in the data directory, deleted straight after), `auditpol /get /r`, a fixed list of
registry values (LM / NTLM, WDigest, LSA protection, UAC, SMB signing, RDP NLA, LLMNR, AutoRun, SCHANNEL TLS 1.0 / 1.1,
PowerShell logging, Security log size, WinRM), SMB server settings, Windows Firewall profiles, BitLocker volume status, Defender
status, a fixed list of services, the number of local administrators and whether Guest is enabled. Agent 1.3 adds, only where
the role is installed: IIS (sites and bindings, directory browsing, detailed errors, logging, Server / X-Powered-By headers, app
pool identities, WebDAV) and Hyper-V (live migration authentication and networks, enhanced session mode, and per VM - at most
200 - Secure Boot, vTPM, MAC spoofing, DHCP / router guard, Guest Service Interface). Agent 1.4 adds, on a domain controller,
the domain's password / lockout policy, functional levels, Recycle Bin, krbtgt password age, privileged group sizes, LDAP signing
and channel binding, LAPS coverage and COUNTS of risky accounts (password never expires / not required, no Kerberos
pre-authentication, admins with an SPN, stale for 90 days, unconstrained delegation) with at most 20 account names each; and on an
Exchange server the build, modern authentication, admin and mailbox audit, external auto-forwarding, anonymous relay on receive
connectors, OWA / ECP exposure, Extended Protection, anti-malware bypass and TLS 1.0 / 1.1 (Get-* cmdlets only). Nothing is changed.

The SIEM keeps the latest snapshot per host (`hardening/store.js`, served to analysts at `GET /api/soc/hardening/snapshots`);
IT Asset Management's **Baseline Hardening** page scores it against the CIS benchmark (SAMA CSF 3.3.8 / NCA ECC 2-3). A
machine whose agent is older than 1.2 reads "not scanned" there, with this as the fix.

## Security notes

* The token is only ever read from a file or a hidden prompt, stored in `token.txt` with a SYSTEM/Administrators-only
  ACL, and sent only in the `X-Sentra-Token` header over TLS. One token per source id; rotate with
  `sentra-siem-token rotate <src>` on the SIEM and redeploy `token.txt`.
* TLS 1.2 minimum (1.3 where the OS supports it); certificate chain + host name validation is always on; the optional
  pin is an additional check, never a replacement. No proxy unless `Proxy` is set.
* The agent needs only local read access to the event logs (it runs as SYSTEM because of the Security log) and
  outbound 443 to the collector. It opens no listening port.
