#!/bin/bash
# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
# itam-stability.sh - keep IT Asset Management (sentra-itam) up. Safe to re-run; update-server.sh runs it on every update.
#   sudo bash itam-stability.sh            install / refresh the settings below
#   sudo bash itam-stability.sh --status   show restarts, memory, out-of-memory kills, start-limit hits, watchdog events
#   sudo bash itam-stability.sh --remove   take the drop-in and the watchdog away again
# 1. systemd drop-in /etc/systemd/system/sentra-itam.service.d/20-stability.conf:
#    - no start limit: the unit allowed 10 starts in 5 minutes, after which systemd refused to start it at all until
#      someone ran "systemctl reset-failed" - one update (ten installers, each restarting it) was enough to hit it
#    - memory: the unit capped it at 400 MB; with Asset Discovery, three vCenters, Nutanix, backup coverage and core
#      licensing loaded that is too little (the kernel kills it, it restarts, loops). The cap is now 15 % of the
#      server's RAM (at least 1 GB, at most 3 GB) and Node's heap limit is set below it, so Node reports a heap error
#      in the log instead of being killed silently.
# 2. zyb-itam-watchdog.timer (every 2 min): if sentra-itam crashed and systemd stopped retrying, or it is running but its
#    API has not answered for 3 checks in a row (6 min), it is restarted and the reason is written to
#    /var/lib/zyb-itam-watchdog/events.json (also shown by --status and scripts\check-server.ps1).
#    A service an administrator stopped on purpose (clean stop, or disabled) is left alone.
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
SVC=sentra-itam; DROP=/etc/systemd/system/$SVC.service.d/20-stability.conf
WD=/usr/local/sbin/zyb-itam-watchdog; WDS=/var/lib/zyb-itam-watchdog
say() { echo "==> $*"; }
NODE_BIN="$(systemctl show -p ExecStart --value $SVC 2>/dev/null | sed -n 's/.*argv\[\]=\([^ ;]*\).*/\1/p' | head -n1)"
[ -x "${NODE_BIN:-}" ] || NODE_BIN=/opt/sentra-ai/node/bin/node; [ -x "$NODE_BIN" ] || NODE_BIN="$(command -v node || echo node)"
NODE="$NODE_BIN"

status() {
  echo "sentra-itam: $(systemctl is-active $SVC 2>/dev/null) | result $(systemctl show -p Result --value $SVC 2>/dev/null) | restarts by systemd $(systemctl show -p NRestarts --value $SVC 2>/dev/null)"
  local cur peak max; cur="$(systemctl show -p MemoryCurrent --value $SVC 2>/dev/null)"; peak="$(systemctl show -p MemoryPeak --value $SVC 2>/dev/null || true)"; max="$(systemctl show -p MemoryMax --value $SVC 2>/dev/null)"
  mb() { case "$1" in ''|'[not set]'|infinity) echo "${1:-?}";; *) echo "$(( $1 / 1048576 )) MB";; esac; }
  echo "memory: now $(mb "$cur") | peak $(mb "$peak") | limit $(mb "$max")"
  echo "last 7 days: $(journalctl -u $SVC --since '-7d' --no-pager 2>/dev/null | grep -c 'Started ') starts | $(journalctl -u $SVC --since '-7d' --no-pager 2>/dev/null | grep -ciE 'oom-kill|out of memory|oom_kill|oom killer') out-of-memory kills | $(journalctl -u $SVC --since '-7d' --no-pager 2>/dev/null | grep -ciE 'heap out of memory|allocation failed') heap errors | $(journalctl -u $SVC --since '-7d' --no-pager 2>/dev/null | grep -ciE 'start request repeated too quickly|start-limit-hit') start-limit hits"
  [ -f "$DROP" ] && echo "stability drop-in: installed" || echo "stability drop-in: NOT installed"
  echo "watchdog timer: $(systemctl is-active zyb-itam-watchdog.timer 2>/dev/null)"
  if [ -f "$WDS/events.json" ]; then echo "watchdog actions (newest first):"; "${NODE:-node}" -e 'const e=JSON.parse(require("fs").readFileSync(process.argv[1],"utf8"));for(const x of e.slice(0,10))console.log("  "+x.at+"  "+x.action+"  "+x.reason)' "$WDS/events.json" 2>/dev/null || head -c 2000 "$WDS/events.json"; fi
}

if [ "${1:-}" = "--status" ]; then status; exit 0; fi
if [ "${1:-}" = "--remove" ]; then
  systemctl disable --now zyb-itam-watchdog.timer 2>/dev/null || true
  rm -f "$DROP" /etc/systemd/system/zyb-itam-watchdog.service /etc/systemd/system/zyb-itam-watchdog.timer "$WD"
  systemctl daemon-reload; say "removed (takes effect at the next restart of $SVC)"; exit 0
fi
[ -f /etc/systemd/system/$SVC.service ] || systemctl cat $SVC >/dev/null 2>&1 || { say "IT Asset Management is not installed here - skipped"; exit 0; }

# ---- 1. drop-in
RAM_MB="$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo)"
MAX=$(( RAM_MB * 15 / 100 )); [ "$MAX" -lt 1024 ] && MAX=1024; [ "$MAX" -gt 3072 ] && MAX=3072
HEAP=$(( MAX * 70 / 100 )); HIGH=$(( MAX * 85 / 100 ))
NEW="$(cat <<EOF
# written by itam-stability.sh - see that file for why. Remove with: sudo bash itam-stability.sh --remove
[Unit]
StartLimitIntervalSec=0

[Service]
Restart=always
RestartSec=5
MemoryHigh=${HIGH}M
MemoryMax=${MAX}M
CPUQuota=200%
Environment=NODE_OPTIONS=--max-old-space-size=${HEAP}
EOF
)"
CHANGED=0
mkdir -p "$(dirname "$DROP")"
if [ ! -f "$DROP" ] || [ "$(cat "$DROP")" != "$NEW" ]; then printf '%s\n' "$NEW" > "$DROP"; chmod 644 "$DROP"; CHANGED=1; fi
if grep -q '^NODE_OPTIONS=' /etc/default/$SVC 2>/dev/null; then echo "   note: /etc/default/$SVC sets NODE_OPTIONS - that value wins over the heap limit here"; fi

# ---- 2. watchdog
cat > "$WD.new" <<'EOF'
#!/bin/bash
# zyb-itam-watchdog - started every 2 minutes by zyb-itam-watchdog.timer (installed by sentra-itam/install/itam-stability.sh)
SVC=sentra-itam; D=/var/lib/zyb-itam-watchdog; mkdir -p "$D"; chmod 755 "$D"
NODE="@NODE@"
port() { "$NODE" -e 'let c={};try{c=JSON.parse(require("fs").readFileSync("/etc/sentra-itam/config.json","utf8"))}catch(e){}console.log((c.api&&c.api.port)||9150)' 2>/dev/null || echo 9150; }
answers() { local p; p="$(port)"; timeout 8 bash -c "exec 3<>/dev/tcp/127.0.0.1/$p && printf 'GET /healthz HTTP/1.0\r\n\r\n' >&3 && head -c 12 <&3" 2>/dev/null | grep -q '^HTTP/'; }
event() {   # action reason
  local why mem; why="$(journalctl -u $SVC -n 300 --no-pager -o cat 2>/dev/null | grep -iE 'error|heap|oom|killed|cannot|EADDR|ENOENT|ENOSPC' | tail -n 3 | cut -c1-240)"
  mem="$(systemctl show -p MemoryPeak --value $SVC 2>/dev/null)"
  "$NODE" -e '
    const fs=require("fs"),f=process.argv[1];let e=[];try{e=JSON.parse(fs.readFileSync(f,"utf8"))}catch(x){}
    e.unshift({at:new Date().toISOString(),action:process.argv[2],reason:process.argv[3],memory_peak:process.argv[4]||"",log:process.argv[5].split("\n").filter(Boolean)});
    fs.writeFileSync(f+".tmp",JSON.stringify(e.slice(0,100),null,1));fs.renameSync(f+".tmp",f);' "$D/events.json" "$1" "$2" "$mem" "$why" 2>/dev/null
  logger -t zyb-itam-watchdog "$1: $2"
}
systemctl is-enabled --quiet $SVC 2>/dev/null || exit 0          # disabled on purpose
STATE="$(systemctl is-active $SVC 2>/dev/null)"; RESULT="$(systemctl show -p Result --value $SVC 2>/dev/null)"
if [ "$STATE" = failed ] || { [ "$STATE" = inactive ] && [ "$RESULT" != success ]; }; then
  systemctl reset-failed $SVC 2>/dev/null; systemctl start $SVC
  event restarted "service was down (systemd result: ${RESULT:-unknown}$([ "$RESULT" = oom-kill ] && echo ' - out of memory'))"; rm -f "$D/misses"; exit 0
fi
[ "$STATE" = active ] || exit 0                                     # stopped cleanly by an administrator, or starting
UP_S=$(( $(date +%s) - $(date -d "$(systemctl show -p ActiveEnterTimestamp --value $SVC)" +%s 2>/dev/null || date +%s) ))
[ "$UP_S" -lt 180 ] && { rm -f "$D/misses"; exit 0; }                # still loading after a start
if answers; then rm -f "$D/misses"; exit 0; fi
N=$(( $(cat "$D/misses" 2>/dev/null || echo 0) + 1 )); echo "$N" > "$D/misses"
if [ "$N" -ge 3 ]; then
  systemctl restart $SVC; rm -f "$D/misses"
  event restarted "running but its API did not answer for 3 checks in a row (about 6 minutes)"
fi
EOF
sed -i "s#@NODE@#$NODE_BIN#" "$WD.new"; chmod 755 "$WD.new"; mv "$WD.new" "$WD"
cat > /etc/systemd/system/zyb-itam-watchdog.service <<EOF
[Unit]
Description=Restart IT Asset Management (sentra-itam) when it has crashed or stopped answering
[Service]
Type=oneshot
ExecStart=$WD
EOF
cat > /etc/systemd/system/zyb-itam-watchdog.timer <<'EOF'
[Unit]
Description=Check IT Asset Management (sentra-itam) every 2 minutes
[Timer]
OnBootSec=3min
OnUnitActiveSec=2min
AccuracySec=15s
[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload
systemctl enable --now zyb-itam-watchdog.timer >/dev/null 2>&1 && say "watchdog: every 2 minutes (zyb-itam-watchdog.timer)" || echo "!! could not start the watchdog timer"
systemctl reset-failed $SVC 2>/dev/null || true
if [ "$(systemctl is-active $SVC)" != active ]; then systemctl start $SVC || true; say "sentra-itam was not running - started it ($(systemctl is-active $SVC))"
elif [ "$CHANGED" = 1 ]; then systemctl restart $SVC; say "stability settings applied: no start limit, memory ${MAX} MB (heap ${HEAP} MB) - sentra-itam restarted"
else say "stability settings already in place (memory ${MAX} MB)"; fi
status | sed 's/^/   /'
