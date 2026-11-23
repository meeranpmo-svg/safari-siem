#!/bin/bash
# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
# add-virt-capacity.sh - VMware / Nutanix capacity (engine/virt-capacity.js): host hardware, CPU / memory in use,
#   clusters, datastores and VM allocations read (read-only) from the platforms on the Virtualization page; fills the
#   empty model / serial / ESXi version / CPU / memory fields of the hosts and VMs, and feeds the capacity planning report.
#   sudo bash add-virt-capacity.sh              install / update (safe to re-run)
#   sudo bash add-virt-capacity.sh --rollback   put back the engine from before the first install
# Copies engine/virt-capacity.js and adds one registration line to engine/main.js. Nothing else in the installed engine
# is changed. Backup first, syntax check, restart, then a live check that the route answers; any failure restores the
# backup automatically. Only the vCenter / Prism addresses already saved on the Virtualization page are contacted.
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib-itam.sh"   # restart only when needed, wait until the API answers
APP=/opt/sentra-itam; SVC=sentra-itam; BK=/var/backups/sentra-itam-virt-capacity
MAIN="$APP/engine/main.js"; MOD="$APP/engine/virt-capacity.js"
LINE="  require('./virt-capacity').registerVirtCapacity(srv, app); // VMware / Nutanix capacity planning (engine/virt-capacity.js)"
say() { echo "==> $*"; }; die() { echo "!! $*"; exit 1; }

if [ "${1:-}" = "--rollback" ]; then
  [ -f "$BK/main.js" ] || die "no backup in $BK"
  cp -p "$BK/main.js" "$MAIN"; if [ -f "$BK/virt-capacity.js" ]; then cp -p "$BK/virt-capacity.js" "$MOD"; else rm -f "$MOD"; fi
  itam_restart; say "restored the engine from before virtualization capacity was added ($(systemctl is-active "$SVC"))"; exit 0
fi

[ -f "$MAIN" ] || die "IT Asset Management is not installed here ($MAIN not found)"
SRC="$HERE/../engine/virt-capacity.js"; [ -f "$SRC" ] || die "missing $SRC - copy the whole sentra-itam folder"
NODE="$(systemctl show -p ExecStart --value "$SVC" 2>/dev/null | sed -n 's/.*argv\[\]=\([^ ;]*\).*/\1/p' | head -n1)"
[ -x "${NODE:-}" ] || NODE=/opt/sentra-ai/node/bin/node; [ -x "$NODE" ] || NODE="$(command -v node || true)"
[ -x "${NODE:-}" ] || die "could not find the Node.js the service uses"

PRE_FP="$(itam_fp)"
say "backup -> $BK"
mkdir -p "$BK"; chmod 700 "$BK"
if grep -q "registerVirtCapacity" "$MAIN" && [ -f "$BK/main.js" ]; then echo "   (keeping the backup from before the first install)"
else cp -p "$MAIN" "$BK/main.js"; if [ -f "$MOD" ]; then cp -p "$MOD" "$BK/virt-capacity.js"; else rm -f "$BK/virt-capacity.js"; fi; fi
cp -p "$MAIN" "$BK/main.run.js"   # this run's main.js: a failure puts back exactly this, never the copy from before the first install (that one drops every route added since)
restore() { itam_on_restore "$1"; echo "!! $1 - restoring the previous engine"; cp -p "$BK/main.run.js" "$MAIN"; if [ -f "$BK/virt-capacity.js" ]; then cp -p "$BK/virt-capacity.js" "$MOD"; else rm -f "$MOD"; fi; itam_restart || true; echo "   $SVC: $(systemctl is-active "$SVC")"; exit 1; }

install -m 644 -o root -g root "$SRC" "$MOD"
# the virtual network readers it calls for the Virtual Network Map (virt-net-read.js, pure parsing)
[ -f "$HERE/../engine/virt-net-read.js" ] && install -m 644 -o root -g root "$HERE/../engine/virt-net-read.js" "$APP/engine/virt-net-read.js"
# the Python reader (docs/PYTHON-MIGRATION.md step 4; falls back to the Node.js one by itself when Python is missing)
[ -f "$HERE/../engine/pyengine.js" ] && install -m 644 -o root -g root "$HERE/../engine/pyengine.js" "$APP/engine/pyengine.js"
if [ -d "$HERE/../pyengine" ]; then install -d -m 755 -o root -g root "$APP/pyengine"; for f in "$HERE"/../pyengine/*.py; do install -m 644 -o root -g root "$f" "$APP/pyengine/"; done; rm -rf "$APP/pyengine/__pycache__"; fi
if grep -q "registerVirtCapacity" "$MAIN"; then say "main.js already registers virtualization capacity"
else
  if grep -q "^ *registerDiscoveryRoutes(srv, app);" "$MAIN"; then ANCHOR="registerDiscoveryRoutes(srv, app);"
  elif grep -q "^ *registerRoutes(srv, app);" "$MAIN"; then ANCHOR="registerRoutes(srv, app);"
  else restore "could not find where routes are registered in $MAIN"; fi
  LINE="$LINE" ANCHOR="$ANCHOR" awk '{print} !done && index($0, ENVIRON["ANCHOR"]) && $0 ~ /^ *register/ {print ENVIRON["LINE"]; done=1}' "$MAIN" > "$MAIN.tmp" && cat "$MAIN.tmp" > "$MAIN" && rm -f "$MAIN.tmp"
  grep -q "registerVirtCapacity" "$MAIN" || restore "could not add the registration line"
  say "registered virtualization capacity in main.js"
fi
"$NODE" --check "$MAIN" && "$NODE" --check "$MOD" || restore "syntax check failed"
[ -f "$APP/engine/pyengine.js" ] && { "$NODE" --check "$APP/engine/pyengine.js" || restore "syntax check failed (pyengine.js)"; }
PYB="$("$NODE" -e 'try{const c=JSON.parse(require("fs").readFileSync("/etc/sentra-itam/config.json","utf8"));process.stdout.write((c.discovery&&c.discovery.python_bin)||"")}catch(e){}')"; PYB="${PYB:-/opt/sentra-siem/pyenv/bin/python3}"
if [ -x "$PYB" ] && [ -f "$APP/pyengine/run.py" ]; then
  PING="$(echo '{"op":"ping"}' | runuser -u "$SVC" -- "$PYB" -I "$APP/pyengine/run.py" 2>&1 | head -c 200)"
  case "$PING" in *'"virt"'*) say "vCenter / Nutanix capacity is read by Python ($PYB): $PING";; *) say "WARNING: the Python reader did not answer ($PING) - the Node.js reader is used";; esac
else say "Python not found at $PYB - the Node.js reader is used (set discovery.python_bin in /etc/sentra-itam/config.json)"; fi

itam_restart_if_changed "$PRE_FP"
systemctl is-active --quiet "$SVC" || itam_start_failed restore

# live check: the route must exist (200 for a viewer); 404 means it was not registered. No data is changed.
CODE="$("$NODE" -e '
const fs=require("fs"),http=require("http");let c={},s={};
try{c=JSON.parse(fs.readFileSync("/etc/sentra-itam/config.json","utf8"))}catch(e){}
try{s=JSON.parse(fs.readFileSync("/etc/sentra-itam/secrets.json","utf8"))}catch(e){}
const a=c.api||{},port=a.port||9150,pre=a.prefix||"/api/itam";
const r=http.request({host:a.host||"127.0.0.1",port,method:"GET",path:pre+"/virt/capacity",headers:{"Content-Type":"application/json","X-Sentra-Proxy-Secret":s.proxy_secret||"","X-Auth-User":"zyb-install-check","X-Auth-Role":"viewer"}},res=>{res.resume();console.log(res.statusCode)});
r.on("error",()=>console.log(0));r.setTimeout(5000,()=>{r.destroy()});r.end();' 2>/dev/null || echo 0)"
case "$CODE" in
  200|403) say "virtualization capacity is live";;
  401) say "virtualization capacity installed (the live check could not authenticate - open the portal to confirm)";;
  404) restore "virtualization capacity did not register";;
  *) say "installed; the live check returned '$CODE' - open the portal to confirm";;
esac
echo "   undo: sudo bash $0 --rollback"
