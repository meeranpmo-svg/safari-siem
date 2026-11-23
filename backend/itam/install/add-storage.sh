#!/bin/bash
# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
# add-storage.sh - add storage arrays (NetApp ONTAP and HPE MSA 2060 / 2062, read-only: health, capacity, pools,
#   volumes, failed disks, events) to an installed IT Asset Management engine (/opt/sentra-itam).
#   sudo bash add-storage.sh              install / update (safe to re-run)
#   sudo bash add-storage.sh --rollback   put back the engine from before the first install
# Copies engine/storage.js, engine/storage-sources.js, the Python reader (engine/storage-sources-py.js, engine/pyengine.js,
# pyengine/*.py - the first module moved to Python, docs/PYTHON-MIGRATION.md) and adds one registration line to engine/main.js. Nothing else
# in the installed engine is changed. Backup first, syntax check, restart, then a live check that the route answers;
# any failure restores the backup automatically. Page: /dashboards/storage.html.
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib-itam.sh"   # restart only when needed, wait until the API answers
APP=/opt/sentra-itam; SVC=sentra-itam; BK=/var/backups/sentra-itam-storage
MAIN="$APP/engine/main.js"; MOD="$APP/engine/storage.js"; NTX="$APP/engine/storage-sources.js"
LINE="  require('./storage').registerStorage(srv, app); // storage arrays: NetApp ONTAP, HPE MSA (engine/storage.js)"
say() { echo "==> $*"; }; die() { echo "!! $*"; exit 1; }

if [ "${1:-}" = "--rollback" ]; then
  [ -f "$BK/main.js" ] || die "no backup in $BK"
  cp -p "$BK/main.js" "$MAIN"; if [ -f "$BK/storage.js" ]; then cp -p "$BK/storage.js" "$MOD"; else rm -f "$MOD"; fi; if [ -f "$BK/storage-sources.js" ]; then cp -p "$BK/storage-sources.js" "$NTX"; else rm -f "$NTX"; fi
  itam_restart; say "restored the engine from before the storage arrays was added ($(systemctl is-active "$SVC"))"; exit 0
fi

[ -f "$MAIN" ] || die "IT Asset Management is not installed here ($MAIN not found)"
SRC="$HERE/../engine/storage.js"; [ -f "$SRC" ] || die "missing $SRC - copy the whole sentra-itam folder"
NODE="$(systemctl show -p ExecStart --value "$SVC" 2>/dev/null | sed -n 's/.*argv\[\]=\([^ ;]*\).*/\1/p' | head -n1)"
[ -x "${NODE:-}" ] || NODE=/opt/sentra-ai/node/bin/node; [ -x "$NODE" ] || NODE="$(command -v node || true)"
[ -x "${NODE:-}" ] || die "could not find the Node.js the service uses"

PRE_FP="$(itam_fp)"
say "backup -> $BK"
mkdir -p "$BK"; chmod 700 "$BK"
if grep -q "registerStorage" "$MAIN" && [ -f "$BK/main.js" ]; then echo "   (keeping the backup from before the first install)"
else cp -p "$MAIN" "$BK/main.js"; if [ -f "$MOD" ]; then cp -p "$MOD" "$BK/storage.js"; else rm -f "$BK/storage.js"; fi; if [ -f "$NTX" ]; then cp -p "$NTX" "$BK/storage-sources.js"; else rm -f "$BK/storage-sources.js"; fi; fi
cp -p "$MAIN" "$BK/main.run.js"   # this run's main.js: a failure puts back exactly this, never the copy from before the first install (that one drops every route added since)
restore() { itam_on_restore "$1"; echo "!! $1 - restoring the previous engine"; cp -p "$BK/main.run.js" "$MAIN"; if [ -f "$BK/storage.js" ]; then cp -p "$BK/storage.js" "$MOD"; else rm -f "$MOD"; fi; if [ -f "$BK/storage-sources.js" ]; then cp -p "$BK/storage-sources.js" "$NTX"; else rm -f "$NTX"; fi; itam_restart || true; echo "   $SVC: $(systemctl is-active "$SVC")"; exit 1; }

[ -f "$HERE/../engine/storage-sources.js" ] || restore "missing engine/storage-sources.js - copy the whole sentra-itam folder"
install -m 644 -o root -g root "$SRC" "$MOD"
install -m 644 -o root -g root "$HERE/../engine/storage-sources.js" "$NTX"
# the Python reader (falls back to the Node.js one by itself when Python is missing)
for f in storage-sources-py.js py-sources.js pyengine.js; do [ -f "$HERE/../engine/$f" ] && install -m 644 -o root -g root "$HERE/../engine/$f" "$APP/engine/$f"; done
if [ -d "$HERE/../pyengine" ]; then install -d -m 755 -o root -g root "$APP/pyengine"; for f in "$HERE"/../pyengine/*.py; do install -m 644 -o root -g root "$f" "$APP/pyengine/"; done; rm -rf "$APP/pyengine/__pycache__"; say "Python modules: $(ls "$APP/pyengine" | tr '\n' ' ')"; fi
if grep -q "registerStorage" "$MAIN"; then say "main.js already registers the storage arrays"
else
  if grep -q "^ *registerDiscoveryRoutes(srv, app);" "$MAIN"; then ANCHOR="registerDiscoveryRoutes(srv, app);"
  elif grep -q "^ *registerRoutes(srv, app);" "$MAIN"; then ANCHOR="registerRoutes(srv, app);"
  else restore "could not find where routes are registered in $MAIN"; fi
  LINE="$LINE" ANCHOR="$ANCHOR" awk '{print} !done && index($0, ENVIRON["ANCHOR"]) && $0 ~ /^ *register/ {print ENVIRON["LINE"]; done=1}' "$MAIN" > "$MAIN.tmp" && cat "$MAIN.tmp" > "$MAIN" && rm -f "$MAIN.tmp"
  grep -q "registerStorage" "$MAIN" || restore "could not add the registration line"
  say "registered the storage arrays in main.js"
fi
"$NODE" --check "$MAIN" && "$NODE" --check "$MOD" && "$NODE" --check "$NTX" || restore "syntax check failed"
for f in storage-sources-py.js py-sources.js pyengine.js; do [ -f "$APP/engine/$f" ] && { "$NODE" --check "$APP/engine/$f" || restore "syntax check failed ($f)"; }; done
PYB="$("$NODE" -e 'try{const c=JSON.parse(require("fs").readFileSync("/etc/sentra-itam/config.json","utf8"));process.stdout.write((c.discovery&&c.discovery.python_bin)||"")}catch(e){}')"; PYB="${PYB:-/opt/sentra-siem/pyenv/bin/python3}"
if [ -x "$PYB" ] && [ -f "$APP/pyengine/run.py" ]; then
  PING="$(echo '{"op":"ping"}' | runuser -u "$SVC" -- "$PYB" -I "$APP/pyengine/run.py" 2>&1 | head -c 200)"
  case "$PING" in *'"ok":true'*) say "storage arrays are read by Python ($PYB): $PING";; *) say "WARNING: the Python reader did not answer ($PING) - the Node.js reader is used";; esac
else say "Python not found at $PYB - the Node.js reader is used (set discovery.python_bin in /etc/sentra-itam/config.json)"; fi

itam_restart_if_changed "$PRE_FP"
systemctl is-active --quiet "$SVC" || itam_start_failed restore

# live check: the route must exist (403 for a viewer); 404 means it was not registered. No data is changed.
CODE="$("$NODE" -e '
const fs=require("fs"),http=require("http");let c={},s={};
try{c=JSON.parse(fs.readFileSync("/etc/sentra-itam/config.json","utf8"))}catch(e){}
try{s=JSON.parse(fs.readFileSync("/etc/sentra-itam/secrets.json","utf8"))}catch(e){}
const a=c.api||{},port=a.port||9150,pre=a.prefix||"/api/itam";
const r=http.request({host:a.host||"127.0.0.1",port,method:"GET",path:pre+"/storage",headers:{"Content-Type":"application/json","X-Sentra-Proxy-Secret":s.proxy_secret||"","X-Auth-User":"zyb-install-check","X-Auth-Role":"viewer"}},res=>{res.resume();console.log(res.statusCode)});
r.on("error",()=>console.log(0));r.setTimeout(5000,()=>{r.destroy()});r.end();' 2>/dev/null || echo 0)"
case "$CODE" in
  403) say "storage arrays are live";;
  401) say "storage arrays installed (the live check could not authenticate - open the portal to confirm)";;
  404) restore "the storage arrays did not register";;
  *) say "installed; the live check returned '$CODE' - open the portal to confirm";;
esac
echo "   undo: sudo bash $0 --rollback"
