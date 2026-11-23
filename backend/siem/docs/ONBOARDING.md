# Onboarding a log source

Every source goes through the same five steps; the per-type sections below fill in step 3.
"Sources page" below = the portal page **SIEM Log Source Health** (data: `GET /api/soc/sources`): one row per source
with last seen, EPS (1 min / 1 h), events today, parse-error rate and status `ok | silent | errors`.

1. **Name it** — pick a `src_id` (`[A-Za-z0-9_.-]`, ≤ 64): `<kind>-<site>-<nn>`, e.g. `fw-hq-01`, `sw-core`,
   `lnx-web-01`, `win-dc`, `win-servers`. One src_id per device for network gear; one per *group* for Windows agents
   (the host name comes from each event).
2. **Register it** in `/etc/sentra-siem/config.json` → `sources` (syslog sources are matched by the sender's IP):

   ```json
   { "id": "fw-hq-01", "type": "fortigate", "match": { "ip": "10.10.1.1" }, "silent_after_s": 600 }
   ```

   | key | meaning |
   |---|---|
   | `type` | parser: `windows`, `linux`, `nginx`, `apache`, `fortigate`, `cisco`, `cef`, `leef`, `json`, `syslog` (generic) |
   | `match.ip` / `match.cidr` | string or list; exact IPs win over CIDRs; CIDRs are tried in config order |
   | `tz_offset_min` | minutes east of UTC for devices whose timestamps carry no zone (AST = 180) |
   | `silent_after_s` | Sources page shows `silent` after this many seconds without events (default 900) |

   HTTPS/agent sources are identified by the URL (`/ingest/<src_id>`) and need a token:
   `sudo sentra-siem-token add <src_id> --type windows` (also adds the `sources` entry).
   Then `sudo systemctl restart sentra-siem`.
3. **Configure the sender** (sections below).
4. **Verify** (checklist at the end): Sources page status `ok`, expected EPS, parse-error rate ≈ 0 %, fields look
   right in search, a test event arrives, the relevant built-in rules can fire.
5. **Record it** in the source inventory (owner, src_id, type, IPs, expected EPS, date, verified by) — the
   parallel-run comparison and the audit both rely on it.

Unregistered senders are still accepted (under `syslog-udp` / `syslog-tcp`) and parsed by content sniffing, but they
do not get their own row, silence monitoring or per-source statistics — always register.

---

## Windows servers and domain controllers (SentraAgent)

Details: [agents/windows/README.md](../agents/windows/README.md).

1. On the SIEM: `sudo sentra-siem-token add win-dc --type windows` (if not created by the installer) and
   `sudo sentra-siem-token show win-dc > /root/win-dc.token` for the deployment share (delete it afterwards).
2. Collector certificate: the Windows hosts must trust the CA of the nginx HTTPS certificate (GPO → Trusted Root).
3. Audit policy + PowerShell script block logging + (recommended) Sysmon — README → *Recommended Windows audit policy*.
4. Test on one host first, without sending: `.\sentra-agent.ps1 -DryRun -Channel Security -Count 5` (elevated).
5. Install: `.\install-agent.ps1 -CollectorUrl https://siem.example.local -SourceId win-dc -TokenFile \\…\win-dc.token -SetLogSizes`
6. Roll out to the group by GPO/SCCM once the first host is verified.

Verify: host appears under `win-dc` on the Sources page within ~2 minutes (heartbeat events `Channel=SentraAgent`
every 5 min); search `src_id:win-dc AND host:<host>`; generate a test event — e.g. a failed logon with a
non-existent account (`runas /user:sentra-test-nonexistent cmd`, wrong password) → `event_code:4625` with
`user`, `src_ip`, `fields.LogonType`. On DCs check Kerberos (`event_code:4768`) and group changes appear.

## Linux servers (rsyslog)

Details: [agents/linux/README.md](../agents/linux/README.md).

1. Register: `{ "id": "lnx-app-01", "type": "linux", "match": { "ip": "10.10.8.21" } }` (or one entry with a `cidr`
   for a server subnet).
2. On the host: `sudo ./install-rsyslog-forwarder.sh --collector <SIEM name> --ca ca.pem` (TLS by default; `--plain` only on a trusted segment).
3. Verify: the script sends `sentra-siem forwarding test` → search `src_id:lnx-app-01 AND "forwarding test"`; then
   `ssh wronguser@host` → `action:logon-failed` with `user`, `src_ip`, `process:sshd`; `sudo -l` → `action:sudo`.

## Web servers (nginx / apache access logs)

1. Same host registration as Linux (`type: linux` is fine — access lines are recognised by content), or a separate
   entry `type: nginx` if the host only sends web logs.
2. `sudo ./install-rsyslog-forwarder.sh --collector <SIEM IP> --web nginx` (or `apache`, `both`).
3. Verify: request a page → `category:web AND host:<host>` shows `url`, `http_status`, `src_ip`, `user_agent`.
   Parse-error rate must stay ≈ 0 %; a custom `log_format` shows up as `action:unparsed` — align it with `combined`.

## FortiGate

Details and CLI: [agents/network/README.md](../agents/network/README.md#fortigate-fortios-64--7x).

1. Register: `{ "id": "fw-hq-01", "type": "fortigate", "match": { "ip": "<FortiGate source-ip>" } }`.
2. FortiGate: `config log syslogd2 setting` (keep LogRhythm on `syslogd` during the parallel run) — `mode reliable`,
   `port 5514`, `format default`, `source-ip`; filter `severity information`; `logtraffic` on the policies.
3. Verify: `diagnose log test` on the FortiGate → search `src_id:fw-hq-01`; check `action:blocked` (deny),
   `action:ips-detection`, admin logins (`category:authentication`), config changes (`action:config-change`);
   `event_code` = FortiGate `logid`. EPS on the Sources page should match the FortiGate's log rate
   (*Log & Report → Log Settings* / FortiAnalyzer).

## Cisco IOS / IOS-XE / ASA

Details: [agents/network/README.md](../agents/network/README.md#cisco-ios--ios-xe-switches-routers).

1. Register with `"type": "cisco"` and `"tz_offset_min": 180` for IOS devices without zone in timestamps.
2. `logging host <SIEM IP> transport tcp port 5514`, `logging trap informational`, `logging source-interface …`;
   ASA: `logging host inside <SIEM IP> tcp/5514` **plus** `logging permit-hostdown`.
3. Verify: enter/leave config mode → `%SYS-5-CONFIG_I` arrives with the right time; failed SSH login →
   `action:logon-failed`; ASA deny → `action:blocked` with `src_ip`/`dst_ip`/`dst_port`.

## CEF / LEEF appliances (WAF, mail gateway, EDR, PAM, proxies …)

1. Register with `"type": "cef"` or `"type": "leef"`.
2. Product syslog settings: destination SIEM IP, TCP 5514 (or TLS 6514), format CEF / LEEF.
3. Verify: product-specific test event (most have a "send test message" button) → `src_id:<id>`; check that
   `src_ip`, `dst_ip`, `user`, `url` / `hash` are populated and `fields.*` carries the vendor extensions.

## Applications posting JSON over HTTPS

1. `sudo sentra-siem-token add app-portal --type json` → token; restart the engine.
2. The application POSTs to `https://<siem>/ingest/app-portal` with header `X-Sentra-Token: <token>`, body = JSON array
   or NDJSON (one object per line), optional `Content-Encoding: gzip`, ≤ 5 MB per request. Response:
   `{accepted, rejected, errors}`; retry on 429/5xx with back-off.
3. Put a timestamp (`ts`/`timestamp`/`@timestamp`, ISO-8601 with zone) and meaningful keys (`user`, `src_ip`,
   `action`, `outcome`, `message`) in each object — they map directly to the schema; everything else lands in
   `fields.*`.

```bash
# smoke test from the SIEM server itself (clearly labelled test record)
TOKEN="$(sudo sentra-siem-token show app-portal)"
curl -s https://siem.example.local/ingest/app-portal -H "X-Sentra-Token: $TOKEN" \
  -H 'Content-Type: application/x-ndjson' \
  --data-binary '{"ts":"2026-09-29T10:00:00+03:00","action":"logon","outcome":"success","user":"onboarding-test","message":"ONBOARDING TEST - ignore"}'
unset TOKEN
```

## Microsoft 365 / Entra ID and LogRhythm alarms

The pull collectors for Microsoft 365 (Graph sign-in / directory audit logs) and LogRhythm alarms are **phase 2**
(`m365.enabled` / `lr.enabled` currently only log a notice). Until then, LogRhythm alarms are imported for the
parallel-run comparison as described in [PARALLEL-RUN.md](PARALLEL-RUN.md).

---

## Verification checklist (per source)

| # | check | where | pass when |
|---|---|---|---|
| 1 | source row exists, `configured: true` | Sources page | status `ok` |
| 2 | events arrive continuously | Sources → last seen, EPS 1 min / 1 h | last seen < 1 min (busy sources) / < `silent_after_s` |
| 3 | volume plausible | Sources → events today vs. device's own counters / LogRhythm | within ±5 % (after filters) |
| 4 | parsing | Sources → parse-error rate; search `src_id:<id> AND action:unparsed` | < 1 % (0 % for agents) |
| 5 | time correct | compare `ts` with the device clock for a test event | < 5 s difference, correct zone |
| 6 | key fields populated | open 3–5 events in search | `host`, `user`/`src_ip`/`dst_ip`/`action`/`outcome` as applicable |
| 7 | test event end-to-end | per-type test above | found within 1 minute |
| 8 | detections can fire | `POST /api/soc/rules/test` for 1–2 relevant built-in rules over the last day, or a controlled test (e.g. 11 failed logons of a test account → SENTRA-AUTH-001) | expected alert (close it as a test) |
| 9 | silence monitoring | `silent_after_s` suits the source's normal rhythm | quiet sources (e.g. a PAM appliance) get a larger value |
| 10 | inventory updated | source inventory | entry complete, verified by + date |

## Removing a source

Stop the sender, remove the `sources` entry (and `sentra-siem-token revoke <id>` for HTTPS sources), restart the
engine. Stored events remain searchable until the retention expires.
