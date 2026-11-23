#!/bin/bash
# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
# install-go-shadow.sh - run the Go test slice (syslog collector + FortiGate parser, docs/GO-SLICE.md) IN SHADOW beside
# the Node.js SIEM. It listens on its own port (default 15514 UDP + TCP), reads the SIEM's config.json for the source
# list (read only), and writes what it parsed to /var/lib/sentra-siem-go-shadow/events.jsonl (capped, rotated) plus
# stats.json. It does NOT replace, stop or reconfigure the SIEM, write to ClickHouse, raise alerts, or open the firewall.
#   sudo bash install-go-shadow.sh --binary ./sentra-ingest [--port 15514]   install / upgrade (the old binary is kept)
#   sudo bash install-go-shadow.sh --status                               what is running and what it has seen
#   sudo bash install-go-shadow.sh --remove                               stop it and take it all out
# Installed: /opt/sentra-siem-go/sentra-ingest (root, 755), sentra-siem-go-shadow.service (runs as the SIEM's sentra-siem account,
# no capabilities, read-only system), the command zyb-go-shadow (status | start | stop | remove).
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
DIR=/opt/sentra-siem-go; BIN=$DIR/sentra-ingest; UNIT=/etc/systemd/system/sentra-siem-go-shadow.service
STATE=/var/lib/sentra-siem-go-shadow; CFG=/etc/sentra-siem/config.json; CMD=/usr/local/sbin/zyb-go-shadow; SVC=sentra-siem
HERE="$(cd "$(dirname "$0")" && pwd)"
say() { echo "==> $*"; }
NEWBIN=""; PORT=15514; MODE=install
while [ $# -gt 0 ]; do
  case "$1" in
    --binary) NEWBIN="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    --status) MODE=status; shift ;;
    --remove) MODE=remove; shift ;;
    *) echo "unknown option $1"; exit 2 ;;
  esac
done
[[ "$PORT" =~ ^[0-9]{4,5}$ ]] && [ "$PORT" -ge 1024 ] && [ "$PORT" -le 65535 ] || { echo "!! --port must be 1024-65535"; exit 2; }

status() {
  echo "  service: $(systemctl is-active sentra-siem-go-shadow 2>/dev/null || true) ($(systemctl is-enabled sentra-siem-go-shadow 2>/dev/null || echo not installed))"
  [ -x "$BIN" ] && echo "  binary:  $BIN  sha256 $(sha256sum "$BIN" | cut -c1-16)…"
  ss -lnupt 2>/dev/null | grep -E "sentra-ingest" | awk '{print "  listening: "$1" "$5}' || true
  if [ -f "$STATE/stats.json" ]; then
    local NODE; NODE="$(systemctl show -p ExecStart --value sentra-siem 2>/dev/null | sed -n 's/.*argv\[\]=\([^ ;]*\).*/\1/p' | head -n1)"
    if [ -x "${NODE:-}" ]; then
      "$NODE" -e 'const s=JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")),p=s.parser||{};
        console.log(`  since ${s.started}: ${s.messages} lines from ${(s.peers||[]).length} sender(s) - ${p.events||0} parsed in Go, ${p.handbacks||0} handed back`+
          ` (not FortiGate ${p.handback_not_fortigate||0}, other source type ${p.handback_src_type||0}, Date.parse ${p.handback_date_parse||0})`);
        for (const x of (s.peers||[]).slice(0,10)) console.log(`    ${x.peer} ${x.collector} ${x.src_id}: ${x.messages} lines, last ${new Date(x.last_seen).toISOString()}`);' "$STATE/stats.json"
    else sed 's/^/  /' "$STATE/stats.json" | head -30; fi
  else echo "  no stats yet ($STATE/stats.json)"; fi
  ls -la "$STATE"/events.jsonl* 2>/dev/null | sed 's/^/  /' || true
}

case "$MODE" in
  status) status; exit 0 ;;
  remove)
    say "removing the Go shadow collector (the SIEM is not touched)"
    systemctl disable --now sentra-siem-go-shadow 2>/dev/null || true
    rm -f "$UNIT" "$CMD"; systemctl daemon-reload
    rm -rf "$DIR" "$STATE"
    say "removed"; exit 0 ;;
esac

[ -n "$NEWBIN" ] && [ -f "$NEWBIN" ] || { echo "!! --binary <sentra-ingest> is required"; exit 2; }
[ "$(uname -m)" = x86_64 ] || { echo "!! this server is $(uname -m); the package carries a linux/amd64 build"; exit 1; }
id "$SVC" >/dev/null 2>&1 || { echo "!! the SIEM service account '$SVC' does not exist - is sentra-siem installed?"; exit 1; }
[ -f "$CFG" ] || { echo "!! $CFG not found - is sentra-siem installed?"; exit 1; }
# a package packed on Windows carries no execute bit: work on a private copy
TMPB="$(mktemp -d)"; trap 'rm -rf "$TMPB"' EXIT
install -m 700 "$NEWBIN" "$TMPB/sentra-ingest"; NEWBIN="$TMPB/sentra-ingest"
# the binary must run here and answer like the slice (a parse of one synthetic line), before anything is replaced
TEST='{"line":"<189>date=2026-10-21 time=10:00:00 devname=\"FG-SYNTH\" logid=\"0000000013\" type=\"traffic\" subtype=\"forward\" action=\"deny\" srcip=10.1.1.5","meta":{"src_type":"fortigate","rts":1792605600000}}'
OUT="$(echo "$TEST" | "$NEWBIN" parse 2>&1 || true)"
echo "$OUT" | grep -q '"action":"blocked"' || { echo "!! the new binary did not parse the test line: $OUT"; exit 1; }
# the port must be free (and not the SIEM's own)
if ss -lnuH 2>/dev/null | awk '{print $4}' | grep -qE "[:.]$PORT\$" || ss -lntH 2>/dev/null | awk '{print $4}' | grep -qE "[:.]$PORT\$"; then
  systemctl is-active --quiet sentra-siem-go-shadow 2>/dev/null || { echo "!! port $PORT is already in use - choose another with --port"; exit 1; }
fi

say "installing $BIN"
install -d -m 755 -o root -g root "$DIR"
[ -f "$BIN" ] && cp -p "$BIN" "$BIN.prev"
install -m 755 -o root -g root "$NEWBIN" "$BIN.new" && mv -f "$BIN.new" "$BIN"

say "service sentra-siem-go-shadow (port $PORT UDP + TCP, as $SVC, read-only system)"
cat > "$UNIT" <<EOF
# Sentra - Go test slice in shadow (docs/GO-SLICE.md). Written by install-go-shadow.sh; remove with
# zyb-go-shadow remove. It never replaces the SIEM: own port, own output, nothing written to ClickHouse.
[Unit]
Description=Sentra SIEM - Go syslog/FortiGate collector (shadow, not used for alerts)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$SVC
Group=$SVC
ExecStart=$BIN listen -config $CFG -udp-port $PORT -tcp-port $PORT -no-tls -out $STATE/events.jsonl -max-out-mb 200 -stats-every 30s -stats-file $STATE/stats.json
Restart=always
RestartSec=5
StateDirectory=sentra-siem-go-shadow
StateDirectoryMode=0750
UMask=0077
LimitNOFILE=65536
MemoryMax=512M
CPUQuota=100%
NoNewPrivileges=yes
ProtectSystem=strict
ReadOnlyPaths=/etc/sentra-siem
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
ProtectProc=invisible
RestrictSUIDSGID=yes
RestrictRealtime=yes
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictAddressFamilies=AF_INET AF_INET6
SystemCallArchitectures=native
SystemCallFilter=@system-service
CapabilityBoundingSet=
AmbientCapabilities=

[Install]
WantedBy=multi-user.target
EOF
cat > "$CMD" <<EOF
#!/bin/bash
# zyb-go-shadow - the Go shadow collector (docs/GO-SLICE.md): status | start | stop | remove
case "\${1:-status}" in
  status) bash $DIR/install-go-shadow.sh --status ;;
  start|stop|restart) systemctl "\$1" sentra-siem-go-shadow ;;
  remove) bash $DIR/install-go-shadow.sh --remove ;;
  *) echo "usage: zyb-go-shadow status|start|stop|restart|remove"; exit 2 ;;
esac
EOF
chmod 755 "$CMD"
install -m 755 -o root -g root "$HERE/install-go-shadow.sh" "$DIR/install-go-shadow.sh" 2>/dev/null || true
systemctl daemon-reload
systemctl enable sentra-siem-go-shadow >/dev/null 2>&1
systemctl restart sentra-siem-go-shadow
sleep 2
if ! systemctl is-active --quiet sentra-siem-go-shadow; then
  echo "!! the shadow collector did not start:"; journalctl -u sentra-siem-go-shadow -n 20 --no-pager || true
  [ -f "$BIN.prev" ] && { mv -f "$BIN.prev" "$BIN"; systemctl restart sentra-siem-go-shadow || true; echo "   the previous binary was put back"; }
  exit 1
fi
say "running"; status
IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
cat <<EOF

  Next (nothing above changed the SIEM or the firewall):
  1. Open the shadow port in the host firewall if one is active, e.g.
       firewall-cmd --permanent --add-port=$PORT/udp --add-port=$PORT/tcp && firewall-cmd --reload     (or: ufw allow $PORT)
  2. On each FortiGate, add the server as a SECOND syslog destination (the first one, to the SIEM, stays as it is):
       config log syslogd2 setting
           set status enable
           set server "${IP:-<this server>}"
           set port $PORT
           set mode udp
       end
     The FortiGate must be registered in config.json "sources" with type "fortigate", as for the SIEM.
  3. Check: zyb-go-shadow status
EOF
