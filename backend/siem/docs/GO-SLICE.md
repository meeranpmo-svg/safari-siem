# Go test slice: syslog collector + FortiGate parser

Question asked (Oct 2026): would the SIEM engine be faster and safer in another language? The recommendation was Go,
proven on one slice before anything is decided. This is that slice. **It is not deployed**: the running engine is
unchanged, and nothing here is wired into `install/` or the updater.

## What was ported

| Go | Node.js original | |
|---|---|---|
| `go/internal/syslog/framer.go` | `collect/syslog.js` `createFramer` | LF and RFC 6587 octet counting, decided per connection; oversized frames truncated |
| `go/internal/syslog/listener.go` | `collect/syslog.js` `createSyslog`, `collect/sources.js` | UDP, TCP, TLS (TLS 1.2+, optional client certificates); 2,000 connections / 20 per peer / 10-minute idle limits; peer → source by exact IP, then CIDR, then the collector's default; unregistered senders tagged or dropped; per-peer counters |
| `go/internal/parse/header.go` | `parse/rfc5424.js`, `parse/rfc3164.js` | both syslog header formats, incl. year-less timestamps (the year is inferred from the receive time) |
| `go/internal/parse/fortigate.go` | `parse/fortigate.js` | traffic, utm (ips, anomaly, virus, webfilter, dns, app-ctrl), event (vpn, admin login, config change, user auth) |
| `go/internal/parse/event.go`, `router.go` | `schema.js` `finalise`, `parse/index.js` | the normalised event, field for field, and the router for FortiGate sources |
| `go/internal/jsrt` | the JavaScript runtime | the rules a port keeps so both engines answer identically: JavaScript's whitespace, UTF-16 lengths, `parseInt`, `String(number)`, the UTF-8 decoder of `Buffer.toString`, key order of plain objects |

`go/cmd/sentra-ingest` runs it: `parse` (stdin → stdout, for the test), `bench`, `listen -config`. Standard library only,
one 8 MB binary, no packages to install or patch.

## Hand-back, never a guess

Go answers only what it can answer exactly like Node.js. Everything else goes back to the Node.js parser with the line
and its meta (`Handback`), and the reason is counted:

- a source whose type is not `fortigate` (other parsers are not ported);
- a line the FortiGate parser does not take (the JavaScript router would offer it to the other parsers next);
- a timestamp only JavaScript's `Date.parse` reads, e.g. `time=10:15` with no seconds.

## Proof that it gives the same answer

`node --test tests/go-fortigate-parity.test.js` (skipped where Go is not installed):

- **6,000 synthetic lines**: every header form, quoting and escapes, IPv4 / IPv6 / mapped / invalid addresses,
  nanosecond / second / millisecond event times, prototype names (`constructor`, `__proto__`), integer-like keys, Arabic,
  Turkish İ, Greek final sigma, non-breaking spaces, a 4,100-character message, 230 extra fields, non-FortiGate lines.
  **4,576 events identical to Node.js** (only the random event id differs), 1,424 handed back. Every hand-back is
  checked: Node.js must not have parsed that line as FortiGate either, unless it needed `Date.parse`.
- **400 framing cases**: random chunk splits, LF, octet counting, oversized frames, invalid UTF-8. Same frames, same
  truncation flags, same replacement characters as `createFramer` + `Buffer.toString`.

`cd go && go test -race ./...`: the JavaScript rules, and a live listener (UDP, TCP octet counting, the per-peer limit,
a hand-back).

Known difference: a message cut at 4,096 UTF-16 units through the middle of an emoji keeps half the pair in JavaScript.
UTF-8 cannot hold half a pair, so Go drops it.

## Speed

`node tools/go-slice-bench.js --lines 300000`, run on the build container: Intel Xeon 2.8 GHz, 4 cores, Node.js 22, Go 1.24.
Synthetic FortiOS 7 lines, mixed as on a perimeter firewall: 75 % traffic, 10 % IPS, 8 % web filter, 7 % VPN.

| | Node.js | Go | |
|---|---|---|---|
| parse + serialise, 1 core | 25,398 lines/s | 53,901 lines/s | **2.1×** |
| parse + serialise, all 4 cores | 25,398 (one thread) | 129,437 lines/s | **5.1×** |
| end to end over TCP (one connection) | 20,028 lines/s | 46,161 lines/s | **2.3×** |
| peak memory, collector process | 83 MB | 15 MB | **5.5× less** |

The first straight port was **slower** than Node.js: 0.7× on one core. V8 had already optimised what the port copied
line by line. Go overtook it only after profiling: a JSON writer instead of `encoding/json` plus string replacements,
values sliced in place instead of copied, a small slice instead of a hash map for a line's 30 keys, and plain scans
instead of regular expressions where a line can be rejected on its first character. The parity test ran after every
change and still matches. A rewrite in Go is therefore not faster just for being Go: each slice needs this measurement.

## Running it in shadow on the server

From the PC, with Go installed (`winget install GoLang.Go`):

```powershell
cd C:\Users\Syed\shield
powershell -ExecutionPolicy Bypass -File scripts\update-platform.ps1 -Go shadow
```

The updater runs `go vet` and the Go tests and builds one linux/amd64 binary on the PC (nothing is sent if any of these fail).
On the server, `go/install/install-go-shadow.sh` checks that the binary parses a test line, and only then installs it as
`/opt/sentra-siem-go/sentra-ingest` (the previous binary is kept). It runs as service `sentra-siem-go-shadow`:

- **its own port:** 15514 UDP and TCP (`-GoPort` to change it), so the live 5514 is untouched;
- **the SIEM's own source list:** it reads `/etc/sentra-siem/config.json` but never writes it;
- **output:** `/var/lib/sentra-siem-go-shadow/events.jsonl`, capped at 200 MB plus one rotated file, and `stats.json`;
- **sandbox:** the SIEM's `sentra-siem` account, no capabilities, read-only system, 512 MB memory cap, one core at most.

It writes nothing to ClickHouse and raises no alert. If it does not start, the previous binary is put back.

On the server:

- `sudo zyb-go-shadow` (status): lines seen per sender, parsed in Go vs handed back, and why;
- `sudo zyb-go-shadow stop|start|remove`;
- `-Go remove` in the updater takes it off.

The installer does not open the firewall or touch the FortiGates. It prints the two steps for a person to do:
open 15514 in the host firewall, and add the server as the FortiGate's **second** syslog destination (`config log syslogd2
setting`). The first destination, which feeds the SIEM, stays as it is.

An update without `-Go` leaves an installed shadow collector as it is.

## Next if the slice is accepted

1. Shadow run (above), then a comparison tool: Go's `events.jsonl` against the events Node.js stored in ClickHouse, matched
   on the raw line. No cut-over before a month with no difference.
2. Write events to ClickHouse from Go (the Node.js writer's batching and retry rules), and send hand-backs to Node.js.
3. Port the other parsers by volume: Windows, Cisco, Palo Alto, then the rest. Each one shrinks the hand-backs.
