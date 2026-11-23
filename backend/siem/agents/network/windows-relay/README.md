# Windows syslog relay — FortiGate → SIEM

A syslog collector for a **Windows** host on the device LAN. It receives syslog locally, writes every line to a
rotating daily file, and optionally forwards batches to the SIEM over HTTPS.

Use it when the devices and the SIEM are on opposite sides of an untrusted network: the FortiGate only ever talks
to a host on its own LAN, and **nothing inbound is opened on the SIEM**. The relay dials out.

```
FortiGate ──syslog TCP 5514──▶ Windows relay ──gzip NDJSON over HTTPS──▶ /ingest/<src_id> ──▶ engine ──▶ live tail
 (LAN only)                    (daily files)         (outbound only)
```

| file | purpose |
|---|---|
| `sentra-syslog-relay.ps1` | the collector + forwarder |
| `install-relay.ps1` | folders + ACLs, config, firewall rule, scheduled task at boot; `-Uninstall` removes it |

Plain PowerShell 5.1 + .NET — no modules, no binaries, same constraint as `agents/windows/sentra-agent.ps1`.

## Why raw syslog lines are the right payload

`engine/collect/http-ingest.js` accepts "one JSON object **or raw text line** per line" and hands each line to
`parser.parse()` with the `src_type` of the registered source. So a source registered as `"type": "fortigate"`
has its lines parsed by `engine/parse/fortigate.js` whether they arrived on the syslog listener or over HTTPS.
**No engine change is needed** — the relay forwards lines verbatim.

Register the source in `/etc/sentra-siem/config.json` and mint a token on the collector:

```json
"sources": [
  { "id": "fw-hq-01", "type": "fortigate", "collector": "relay" }
]
```

```bash
sudo sentra-siem-token add fw-hq-01     # prints the token: save it to a file for -TokenFile (delete it afterwards)
sudo systemctl restart sentra-siem
```

No `match.ip` is needed for an HTTPS source — the `src_id` in the URL identifies it, and the token authenticates it.
That is a real advantage over plain syslog, where source identity rests on a spoofable packet IP.

## Install

Capture only — prove logs arrive before wiring anything to the SIEM:

```powershell
.\install-relay.ps1 -AllowFrom 192.168.1.2
```

Capture and forward:

```powershell
.\install-relay.ps1 -AllowFrom 192.168.1.2 -CollectorUrl https://siem.example.local -SrcId fw-hq-01 -TokenFile .\fw-hq-01.token
# or leave out -TokenFile and paste the token at the hidden prompt; add -PinnedThumbprint <cert SHA-256> to pin the collector certificate
```

`-AllowFrom` is an allow-list of sending device IPs and sets both the in-process check and the Windows firewall
scope. Always pass it: UDP source addresses are trivially spoofed, so an open collector will accept anything.

Watch lines arrive:

```powershell
Get-Content "$env:ProgramData\SentraSyslogRelay\logs\syslog-$(Get-Date -Format 'yyyyMMdd').log" -Tail 20 -Wait
```

Or run it in the foreground with a live echo:

```powershell
schtasks /End /TN SentraSyslogRelay
& "$env:ProgramFiles\SentraSyslogRelay\sentra-syslog-relay.ps1" -Tail
```

## FortiGate side

Use **`syslogd2`** so an existing destination (FortiAnalyzer, LogRhythm, another SIEM) keeps working untouched.
FortiOS supports four independent syslog destinations. Replace `10.10.10.10` with the relay's LAN IP and
`<fortigate-lan-ip>` with the interface the FortiGate should send from.

```
config log syslogd2 setting
    set status enable
    set server "10.10.10.10"
    set mode reliable              # TCP with RFC 6587 octet framing (udp = classic UDP)
    set port 5514
    set facility local7
    set source-ip <fortigate-lan-ip>
    set format default             # key=value - what engine/parse/fortigate.js expects
end
config log syslogd2 filter
    set severity information
    set forward-traffic enable
    set local-traffic disable      # enable only if traffic to the FortiGate itself matters (noisy)
    set multicast-traffic disable
    set sniffer-traffic disable
    set anomaly enable
    set voip disable
end
```

Then confirm the events you care about are actually logged — see the "Make sure the events you want actually get
logged" block in [`../README.md`](../README.md) (`fwpolicy-implicit-log`, per-policy `logtraffic`, `log eventfilter`).

Verify end to end:

```
diagnose log test                                              # generates sample logs of every type
diagnose sniffer packet any 'host 10.10.10.10 and port 5514' 4 5   # confirm packets leave the FortiGate
```

Then check the relay's daily file, and on the collector search `src_id:fw-hq-01`.

**Rollback** is one line — `config log syslogd2 setting` / `set status disable`. Nothing else on the FortiGate changes.

## Behaviour and limits

* **Framing** mirrors `engine/collect/syslog.js createFramer`: the mode is decided on the first frame of each TCP
  connection — octet-counting (RFC 6587, what `set mode reliable` sends) if it starts with `<digits><space><`,
  otherwise LF. Partial frames are held across TCP reads; a line longer than `max_line` (16 KB) is truncated, not
  dropped; a bogus length prefix resyncs on the next newline. Covered by the test matrix in the commit that added
  this directory (octet, byte-at-a-time reassembly, LF, CRLF, partial holds, oversized resync, truncation).
* **Batching**: flushes on 2000 lines, 1 MB, or 5 s — whichever comes first.
* **Outage**: failed batches go to `queue\*.ndjson.gz` (200 MB cap, oldest-first replay) and the collector is left
  alone for 1, 2, 4 … 15 minutes. Every POST carries a stable `X-Sentra-Batch-Id`, so a retry that the collector
  already accepted is dropped as a duplicate rather than double-counted.
* **Local copy is always written**, even when forwarding is off or failing. `keep_days` (default 14) prunes it.
* **Throughput**: this is an interpreted single-threaded poller. It is comfortable to a few hundred EPS and fine for
  `logtraffic utm`. A busy perimeter FortiGate with `logtraffic all` can produce **1–3 k EPS** (see the sizing note
  in `../README.md`) — at that rate use a compiled collector (NXLog, Fluent Bit) or run the SIEM's own syslog
  listener on a Linux host instead. Prefer `mode reliable` (TCP) either way: TCP applies backpressure, whereas UDP
  overflow is silent loss.
* **Clock**: the FortiGate's own `date=`/`time=`/`eventtime=`/`tz=` fields are what the parser uses, so the relay
  host's clock does not affect event time. Keep NTP configured on the FortiGate regardless.

## Security notes

* `config.json` holds the ingest token and is ACL'd to SYSTEM + Administrators by the installer.
* The token scopes to one `src_id` and only grants ingest — it is not an API credential.
* TLS certificate validation is always on and the collector URL must be `https://`. With a private CA, import the
  CA into the machine store. `-PinnedThumbprint` additionally pins the collector's exact certificate.
* The data folder (captured logs, queue, config) is SYSTEM + Administrators only, so local users can neither read
  firewall logs nor drop forged batches into the queue.
* The relay listens on the LAN only. Do not port-forward 5514 from the internet.
