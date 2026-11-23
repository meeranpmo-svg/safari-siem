# Network devices — onboarding notes

Network devices send syslog straight to the SIEM collector. No agent. Each device is registered as a source in
`/etc/sentra-siem/config.json` so its lines get the right parser and its own row on the Sources page:

```json
"sources": [
  { "id": "fw-hq-01",   "type": "fortigate", "match": { "ip": "10.10.1.1" } },
  { "id": "fw-dr-01",   "type": "fortigate", "match": { "ip": ["10.20.1.1", "10.20.1.2"] } },
  { "id": "sw-core",    "type": "cisco",     "match": { "cidr": "10.10.254.0/28" }, "tz_offset_min": 180 },
  { "id": "waf-01",     "type": "cef",       "match": { "ip": "10.10.3.15" } }
]
```

`match.ip` / `match.cidr` take a string or a list and are compared with the **source IP of the syslog packet /
connection** — make every device send from a fixed interface (`source-ip` / `source-interface`). Devices that
match no source are still accepted under the generic `syslog-udp` / `syslog-tcp` source and parsed by content
sniffing, but are harder to monitor. After editing, `sudo systemctl restart sentra-siem`.

Collector ports (engine defaults, `config.json → syslog`): **TCP+UDP 5514** plain syslog, **TCP 6514** syslog over TLS
(disabled until `syslog.tls.enabled=true` and a certificate is installed). On the build/staging host everything is
bound to 127.0.0.1; on the organisation's collectors install with `--listen-lan`.
Prefer **TCP** (reliable, no silent loss above ~1–2 k EPS) and **TLS** when the path crosses untrusted segments.

---

## FortiGate (FortiOS 6.4 / 7.x)

```
config log syslogd setting
    set status enable
    set server "10.10.5.20"              # SIEM collector LAN IP
    set mode reliable                    # TCP, RFC 6587 framing   (udp = UDP 514-style)
    set port 5514
    set facility local7
    set source-ip 10.10.1.1              # fixed source = the IP registered in "sources"
    set format default                   # key=value - what the fortigate parser expects
end
config log syslogd filter
    set severity information
    set forward-traffic enable
    set local-traffic disable            # enable only if traffic to the FortiGate itself matters (noisy)
    set multicast-traffic disable
    set sniffer-traffic disable
    set anomaly enable
    set voip disable
end
```

TLS variant (FortiOS 7.x; the FortiGate must trust the CA of the SIEM syslog certificate — import it under
*System → Certificates → CA*):

```
config log syslogd setting
    set mode reliable
    set port 6514
    set enc-algorithm high               # TLS on the reliable (TCP) channel
    set ssl-min-proto-version TLSv1-2
end
```

Make sure the events you want actually get logged:

```
config log setting
    set fwpolicy-implicit-log enable     # implicit deny
    set log-user-in-upper disable
end
config firewall policy
    edit <id>
        set logtraffic all               # or "utm" for security events only, per policy
    next
end
config log eventfilter                   # system/vpn/user/admin events
    set event enable
    set system enable
    set vpn enable
    set user enable
end
```

* **Parallel run with LogRhythm**: FortiOS has up to four independent syslog destinations — keep LogRhythm on
  `config log syslogd setting` and put the SIEM on `config log syslogd2 setting` / `syslogd2 filter`
  (same commands). Both receive identical logs; see docs/PARALLEL-RUN.md.
* Time: FortiOS 7.x adds `eventtime=` (epoch) and `tz="+0300"` — the parser uses them. Keep NTP configured.
* Verify from the FortiGate CLI: `diagnose log test` (generates sample logs of each type), then search the SIEM for
  `src_id:fw-hq-01`. `diagnose sniffer packet any 'host 10.10.5.20 and port 5514' 4 5` shows the packets leave.
* Sizing: a busy perimeter FortiGate with `logtraffic all` easily produces 1–3 k EPS; `utm` only is ~10× less.
  Decide per policy (internet-facing: all; east-west: utm).

## Cisco IOS / IOS-XE (switches, routers)

```
clock timezone AST 3 0
ntp server <ntp-ip>
service timestamps log datetime msec localtime show-timezone year
logging origin-id hostname
logging source-interface Vlan100                 ! fixed source = the IP registered in "sources"
logging host 10.10.5.20 transport tcp port 5514  ! or: transport udp port 5514
logging trap informational
logging buffered 64000 informational
! authentication and config-change visibility
login on-failure log
login on-success log
archive
 log config
  logging enable
  notify syslog contenttype plaintext
  hidekeys
```

IOS timestamps carry no numeric zone: set `"tz_offset_min": 180` on the source (AST, UTC+3) as in the example
above. If TCP framing causes parse errors on an old IOS release, switch that device to UDP 5514.
Verify: `send log 6 "sentra-siem test"` (IOS-XE) or enter/leave config mode, then search `src_id:sw-core`.

## Cisco ASA / FTD

```
logging enable
logging timestamp
logging device-id hostname
logging trap informational
logging host inside 10.10.5.20 tcp/5514
logging permit-hostdown          ! IMPORTANT with TCP: without it the ASA stops passing traffic when the syslog server is down
```

Register the ASA as `"type": "cisco"`. Interesting IDs are parsed (106023 denies, 113004/113015 AAA, 302013/302014
connections, 605004/605005 admin logins, 111008/111010 config commands …).

## Generic CEF / LEEF senders (WAF, email gateway, EDR, proxies, PAM …)

Most security products can send **CEF** (ArcSight format) or **LEEF** (QRadar format) over syslog:

* Destination: SIEM collector, **TCP 5514** (or TLS 6514), format CEF (or LEEF 1.0/2.0), UTF-8.
* Register the source with `"type": "cef"` or `"type": "leef"`; CEF/LEEF lines are also recognised by content under a
  generic source.
* Mapped automatically: `src`/`dst`/`spt`/`dpt`/`proto`, `suser`/`duser`, `act`, `request` (URL), `fileHash`, severity
  (CEF 0–10 → 0–4), signature id → `event_code`, product/vendor → `fields`. Everything else lands in `fields.*`.
* If a product offers only its own syslog format, send it anyway (`"type": "syslog"`): it is stored and searchable
  as text; a dedicated parser can be added later.
* If a product can only POST JSON over HTTPS, use the HTTPS ingest endpoint instead:
  `POST https://<siem>/ingest/<src_id>` with header `X-Sentra-Token: <token>` and a JSON array or NDJSON body
  (`sudo sentra-siem-token add <src_id>` creates the token; register the source with `"type": "json"`).

## Firewall rules for the collector

Inbound **to** the SIEM collector:

| from | to port | proto | purpose |
|---|---|---|---|
| FortiGates, switches, routers, ASA, CEF/LEEF appliances, Linux servers | 5514 | TCP (+UDP only where TCP is impossible) | syslog |
| same, when TLS is used | 6514 | TCP | syslog over TLS |
| Windows servers / DCs (SentraAgent), HTTPS JSON senders | 443 | TCP | `https://<siem>/ingest/<src_id>` via nginx |
| SOC analysts' workstations / VPN range | 443 | TCP | portal + `/api/soc/` (session-authenticated) |
| admin jump host only | 22 | TCP | SSH administration |

Outbound **from** the SIEM collector (only what is enabled):

| to | port | purpose |
|---|---|---|
| NTP servers | 123/UDP | time sync (event ordering, detection windows) |
| internal DNS | 53 | name resolution |
| `login.microsoftonline.com`, `graph.microsoft.com` | 443/TCP | Microsoft 365 sign-in / audit pull (`m365.enabled`) |
| LogRhythm API (e.g. `lr-api.example.local`) | LogRhythm API port (commonly 8501, or 443 via the API gateway) | alarm pull for the parallel-run comparison (`lr.enabled`) |
| Ubuntu / ClickHouse package mirrors (or internal mirror / proxy) | 443 | install and patching only |

Never exposed (bound to 127.0.0.1, block at the host firewall anyway): engine API **9120**, ClickHouse HTTP **8123**,
ClickHouse native **9000** / interserver **9009**.

Host firewall example (ufw) on the collector:

```bash
sudo ufw default deny incoming
sudo ufw allow from 10.10.0.0/16 to any port 5514 proto tcp comment 'syslog'
sudo ufw allow from 10.10.0.0/16 to any port 5514 proto udp comment 'syslog udp (legacy devices)'
sudo ufw allow from 10.10.0.0/16 to any port 6514 proto tcp comment 'syslog tls'
sudo ufw allow from 10.10.0.0/16 to any port 443 proto tcp comment 'portal + agent ingest'
sudo ufw allow from <jump-host-ip> to any port 22 proto tcp comment 'ssh admin'
sudo ufw enable
```

Replace `10.10.0.0/16` with the actual device/server ranges; keep UDP limited to the devices that need it (UDP source
addresses can be spoofed — the IP-based source mapping is only as trustworthy as the network path).
