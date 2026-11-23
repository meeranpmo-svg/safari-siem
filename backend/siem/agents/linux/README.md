# Linux hosts — rsyslog forwarding

Linux servers need no agent: the stock **rsyslog** forwards to the SIEM syslog listener.

| file | installed as | purpose |
|---|---|---|
| `60-sentra-siem-forward.conf` | `/etc/rsyslog.d/60-sentra-siem.conf` | TLS → collector:6514 (or plain TCP 5514 with --plain), RFC 5424, octet-counted framing, disk-assisted queue |
| `60-sentra-siem-forward-tls.conf` | `/etc/rsyslog.d/60-sentra-siem.conf` | same over TLS (gtls) → collector:6514, server cert verified (`x509/name`) |
| `61-sentra-siem-webaccess.conf` | `/etc/rsyslog.d/61-sentra-siem-webaccess.conf` | nginx / apache access+error logs via `imfile` |
| `install-rsyslog-forwarder.sh` | — | renders the templates, validates (`rsyslogd -N1`), rolls back on error, restarts rsyslog, sends a test line |

## What is forwarded

* `*.info` and above from every facility, plus **all** `auth`/`authpriv` messages (sshd, sudo, su, PAM, useradd …).
  On Ubuntu/RHEL journald already passes everything to rsyslog, so systemd units and the kernel are included.
* Optional web server logs (`--web nginx|apache|both`): files are read by `imfile` and sent **only** to the SIEM
  (not duplicated into `/var/log/syslog`). New files matching `*access.log` / `*error.log` are picked up automatically.
* Format: RFC 5424 (`RSYSLOG_SyslogProtocol23Format`: ISO timestamp with zone, host, app, pid) framed with
  octet-counting, so multi-line messages and embedded newlines cannot break framing.

## Reliability

`omfwd` action with a **disk-assisted LinkedList queue**: up to 100 000 messages in memory, spilling to
`/var/spool/rsyslog/sentra_siem_fwd*` (max 1 GB) while the SIEM is unreachable; `saveOnShutdown` keeps the queue across
restarts; retries forever every 10 s. rsyslog logs `action 'sentra_siem_fwd' suspended` / `resumed` to its own journal.
TCP gives delivery to the socket, not end-to-end acknowledgement — a collector crash can lose the few messages in
flight (acceptable for syslog; the SIEM's Sources page shows gaps as "silent").

## Install

```bash
# TLS 6514 (the default): CA that issued the SIEM syslog certificate; peer name = cert SAN
sudo ./install-rsyslog-forwarder.sh --collector siem.example.local --ca /tmp/sentra-ca.pem
sudo ./install-rsyslog-forwarder.sh --collector 10.10.5.20 --ca /tmp/sentra-ca.pem --peer siem.example.local

# plain TCP 5514 only on a trusted management segment: auth/sudo/sshd logs travel in clear text and the
# collector cannot authenticate the sender
sudo ./install-rsyslog-forwarder.sh --collector 10.10.5.20 --plain

# add web server logs
sudo ./install-rsyslog-forwarder.sh --collector siem.example.local --ca /tmp/sentra-ca.pem --web nginx

# show what would be written, change nothing
./install-rsyslog-forwarder.sh --collector 10.10.5.20 --web both --dry-run

sudo ./install-rsyslog-forwarder.sh --uninstall
```

TLS needs the `rsyslog-gnutls` package (the script installs it with apt when missing) and on the SIEM
`syslog.tls.enabled=true` with a certificate in `/etc/sentra-siem/tls/` (see docs/OPERATOR-GUIDE.md).

Manual install (no script): copy the template to `/etc/rsyslog.d/60-sentra-siem.conf`, replace `@@COLLECTOR@@`,
`@@PORT@@` (and `@@CAFILE@@`, `@@PEER@@` for TLS), run `sudo rsyslogd -N1`, then `sudo systemctl restart rsyslog`.

## Register the host on the SIEM

Add the host to `sources` in `/etc/sentra-siem/config.json` so its events get the right `src_id` / parser and appear
as their own line on the Sources page (otherwise they are accepted under the generic `syslog-tcp` source):

```json
{ "id": "lnx-web-01", "type": "linux", "match": { "ip": "10.10.8.21" } }
```

Hosts whose web logs are forwarded can stay `type: "linux"` — the parser router recognises combined-format access
lines by content. Use `"type": "nginx"` for a host that sends *only* web logs. Then `sudo systemctl restart sentra-siem` and follow docs/ONBOARDING.md → *Verify*.

## Web server log notes

* nginx: the default `combined` format is parsed (client IP, user, method, URL, status, bytes, referrer, UA).
  If a custom `log_format` is used, keep the combined fields first, or check the parse-error rate after onboarding.
  Behind a load balancer, log `$http_x_forwarded_for` (the engine keeps extra fields in `fields`).
* apache: `/var/log/apache2/access.log` uses `combined`; `other_vhosts_access.log` uses `vhost_combined`
  (virtual host prefix) — prefer per-vhost `CustomLog ... combined` files.
* Permissions: rsyslog runs as `syslog` (group `adm`); default log files are `root:adm 0640`. If logs live
  elsewhere, grant read access to group `adm` (and on RHEL check the SELinux context `var_log_t`).
* Volume: an access log line is ~300 bytes; 100 req/s ≈ 2.6 GB/day raw before ClickHouse compression (~8–12×).

## RHEL / Rocky / Alma

Same files work (rsyslog 8.2102+ on RHEL 9). The rsyslog user is `root` there; install `rsyslog-gnutls` for TLS,
and if SELinux blocks port 5514/6514: `semanage port -a -t syslogd_port_t -p tcp 5514`.
