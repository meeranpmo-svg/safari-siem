# Exchange Server (on-premises, hybrid) → Sentra SIEM

Four feeds cover a hybrid Exchange deployment:

| feed | where | how it reaches the engine | parser / result |
|---|---|---|---|
| Admin audit (cmdlets run in EAC / EMS) | Windows event log `MSExchange Management`, IDs 1 (succeeded) and 6 (failed) | Windows agent (channel is in the default config; see `agents/windows/README.md` for existing installs) | `parse/windows.js` → action `exchange-cmdlet`, `fields.cmdlet`, `fields.parameters`, `fields.params.<Name>`, `fields.exchange_action` |
| Message tracking | `%ExchangeInstallPath%TransportRoles\Logs\MessageTracking\MSGTRK*.log` (also `MSGTRKMD*`, `MSGTRKMS*`) | raw CSV lines (rsyslog `imfile`, below) or JSON lines (see "JSON shapes") | `parse/exchange.js` → src_type `exchange`, category `email`, action `receive` / `send` / `deliver` / `fail` (+ `submit`, `defer`, `dsn`, `drop`, `expand`, `redirect`, `resolve`, `transfer`, `transport`) |
| IIS (OWA, ECP, EWS, Autodiscover, MAPI, PowerShell, ActiveSync) | `C:\inetpub\logs\LogFiles\W3SVC1\u_ex*.log` (front end), `W3SVC2` (Exchange Back End) | raw W3C lines (rsyslog `imfile`) or JSON lines | `parse/iis.js` → src_type `iis`, category `web`, tags `exchange`, `exchange-<vdir>` |
| Exchange Online / Entra ID / SharePoint / DLP | Microsoft 365 unified audit log | engine pull: Office 365 Management Activity API (`engine/collect/m365.js`) | `parse/m365.js` → src_type `m365` |

**Mail subjects are never stored in clear** by default: the engine keeps `fields.subject_sha256` and replaces the
subject inside `raw` with `sha256:<hex>` (message tracking and Exchange Online items). Set
`"exchange": {"store_subjects": true}` in `/etc/sentra-siem/config.json` only if the privacy review allows it. Alternatively
disable subject logging at the source: `Set-TransportService <server> -MessageTrackingLogSubjectLoggingEnabled $false`.

## Log files: paths, format, time zone

* Message tracking: CSV with header lines `#Software`, `#Version`, `#Log-Type`, `#Date`, `#Fields: date-time,client-ip,…`;
  times are UTC. Reference: <https://learn.microsoft.com/en-us/exchange/mail-flow/transport-logs/message-tracking>
* IIS: W3C extended, space-separated, `#Fields: date time s-ip cs-method …` header, UTC.
  Adding `X-Forwarded-For` (IIS Manager → Logging → Select Fields → Add Field) is recommended behind a load balancer;
  the parser then uses it as `src_ip` and keeps the balancer address in `fields.c_ip`.
* The `#Fields` header of each file is remembered per source + host + tag, so custom field selections work as long as
  the header lines are forwarded too (both options below do). Without a header the defaults are assumed.

## Option A — rsyslog `imfile` on a Linux collector (read-only SMB mount)

rsyslog does not run on Windows. Mount the log folders read-only on a Linux box with rsyslog (the SIEM host itself or
a relay). **Do not mount the `C$` admin share**: reaching it needs local administrator rights on the Exchange server,
so the collector would store an Exchange admin credential. Instead, on each Exchange server create two dedicated
read-only shares on just the log folders, granted to a dedicated non-admin AD account (share permission Read, NTFS
Read & Execute on those folders only):

```powershell
# on the Exchange server (elevated)
New-SmbShare -Name SentraMsgTrk$ -Path "$env:ExchangeInstallPath\TransportRoles\Logs\MessageTracking" -ReadAccess 'CORP\svc-sentra-exlogs'
New-SmbShare -Name SentraIis$    -Path 'C:\inetpub\logs\LogFiles\W3SVC1' -ReadAccess 'CORP\svc-sentra-exlogs'
```

```
# /etc/fstab on the collector (one pair per Exchange server; credentials file mode 600, owned by root)
//TEST-EX01/SentraMsgTrk$ /mnt/exchange/TEST-EX01/msgtrk cifs ro,credentials=/etc/sentra-siem/exch-smb.cred,vers=3.0,iocharset=utf8,nofail 0 0
//TEST-EX01/SentraIis$    /mnt/exchange/TEST-EX01/iis    cifs ro,credentials=/etc/sentra-siem/exch-smb.cred,vers=3.0,iocharset=utf8,nofail 0 0
```

Option B (the Windows shipper) needs no stored credential on the collector at all and remains the recommended choice.

Then install `agents/linux/62-sentra-siem-exchange.conf` (one pair of `input()` lines per server). The **tag carries the
Exchange server name** (`exmsgtrk-<SERVER>:` / `exiis-<SERVER>:`); the engine uses it as `host`, because the syslog
host is the collector. Map the collector's IP to a source in `config.json`, e.g.
`{"id":"exchange-onprem","type":"exchange","match":{"ip":"10.20.0.5"}}` (type `exchange` accepts both message tracking
and IIS lines). inotify does not work on CIFS mounts, so the snippet uses `mode="polling"`.

## Option B — the Exchange file shipper (Windows, recommended) or any HTTP shipper

**`agents/exchange/sentra-exchange-shipper.ps1`** runs on each Exchange server (Windows PowerShell 5.1 + .NET, no modules,
no binaries) and tails the message tracking and IIS files by byte offset, shipping the **raw lines** over the Windows
agent's HTTPS contract (gzip NDJSON → `POST /ingest/<src_id>`, `X-Sentra-Token`, stable `X-Sentra-Batch-Id`, TLS 1.2+,
disk queue ≤ 200 MB, back-off, heartbeat). Every line is prefixed with an RFC 5424 header carrying the server name
and the same tags as Option A, so the engine sets `host` and keeps the `#Fields` memory per server:

```
<174>1 2026-10-07T10:00:00Z EX01 exmsgtrk-EX01 - - - #Fields: date-time,client-ip,…
<174>1 2026-10-07T10:00:00Z EX01 exmsgtrk-EX01 - - - 2026-10-07T09:59:58.123Z,10.20.0.15,EX01,…
<174>1 2026-10-07T10:00:00Z EX01 exiis-EX01 - - - 2026-10-07 09:59:58 10.20.0.16 POST /owa/auth.owa …
```

Per-file bookmarks (offset + current header) advance only after the collector accepted the batch or it was queued;
rotation (new hourly/daily file, truncation, deletion) is handled; the `#Fields` header of a file is re-sent ahead of
its lines whenever it changes (and once per batch by default). Install with `install-exchange-shipper.ps1`
(`-CollectorUrl`, `-SourceId win-exchange`, `-TokenFile`; creates `C:\ProgramData\SentraExchangeShipper` with a
SYSTEM/Administrators ACL and the task `\SentraExchangeShipper` as SYSTEM every minute; `-Realtime` = continuous, every 5 seconds, so
mail-flow and OWA/ECP lines reach the SIEM within seconds - re-running the installer with it keeps the token and settings). Paths are discovered from
`$env:ExchangeInstallPath` / the registry and `C:\inetpub\logs\LogFiles\W3SVC{1,2}`, overridable in `config.json`
(`Sources[].Paths`, `ExchangeInstallPath`). `-DryRun -Count N` prints what would be sent. Tests:
`tests\run-tests.ps1` (fixtures + loopback `HttpListener`, no network). Admin-facing steps for both feeds (Windows
agent for the admin audit + this shipper) are in `INSTALL-EXCHANGE.txt`. Register the source as
`{"id":"win-exchange","type":"exchange"}` — the same source/token as the Windows agent on the Exchange servers
works, because the engine routes JSON event objects and raw lines by content.

Any other shipper (NXLog, Fluent Bit, a scheduled `Get-MessageTrackingLog | ConvertTo-Json -Compress`) can POST NDJSON
to `/ingest/<src_id>` with the source's token as well. Accepted shapes, one object per line:

* message tracking, keyed by the `#Fields` names: `{"server":"TEST-EX01","date-time":"…","event-id":"SEND","sender-address":"…","recipient-address":"a;b","message-subject":"…",…}`
* message tracking, `Get-MessageTrackingLog` objects: `{"Timestamp":"…","EventId":"DELIVER","Sender":"…","Recipients":["…"],"MessageSubject":"…","MessageId":"…","ClientIp":"…",…}`
  (the `/Date(ms)/` timestamps of Windows PowerShell 5.1 are understood)
* IIS, keyed by the W3C field names: `{"server":"TEST-EX01","date":"2024-05-01","time":"10:00:00","cs-method":"GET","cs-uri-stem":"/owa/","c-ip":"…","sc-status":"200",…}`
* raw lines are accepted as well: a JSON string item or an NDJSON line that is the original CSV / W3C text.

Configure the source as `{"id":"exchange-ex01","type":"exchange"}` (or `iis`) plus a token in `secrets.json`.

## Exchange Online (hybrid) — Management Activity API

Register an app in Entra ID → API permissions → **Office 365 Management APIs** → *Application* permissions
**ActivityFeed.Read** (and **ActivityFeed.ReadDlp** for `DLP.All`) → Grant admin consent. Upload a certificate
(preferred) or create a client secret. Unified audit logging must be on (Microsoft Purview). Then:

```
/etc/sentra-siem/secrets.json   "m365": {"tenant":"<tenant GUID>","client_id":"<app GUID>","cert_file":"/etc/sentra-siem/m365.crt","key_file":"/etc/sentra-siem/m365.key"}
                              (or "client_secret":"…" instead of cert_file/key_file)
/etc/sentra-siem/config.json    "m365": {"enabled": true}      optional: "content_types", "poll_s" (300), "publisher_id"
```

The engine subscribes to `Audit.AzureActiveDirectory`, `Audit.Exchange`, `Audit.SharePoint`, `Audit.General`,
`DLP.All` (first content can take up to 12 h after a new subscription), polls every 5 minutes in ≤ 24 h windows,
de-duplicates by record `Id`, checkpoints in `/var/lib/sentra-siem/state/m365-checkpoint.json` and backs off on HTTP 429.
Outbound HTTPS to `login.microsoftonline.com` and `manage.office.com` is required from the engine host.
