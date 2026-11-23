#!/bin/bash
# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
# add-locations.sh - add the shared locations list (add / edit / rename sites everywhere) to an installed IT Asset
#   Management engine (/opt/sentra-itam) - engine/locations.js.
#   sudo bash add-locations.sh               install / update (safe to re-run)
#   sudo bash add-locations.sh --rollback    put back the engine from before the first install
# Copies engine/locations.js and adds one registration line to engine/main.js. Nothing else in the installed engine
# is changed, so it works with whatever version is there. Backup first, syntax check, restart, then a live check that
# the route answers; any failure restores the backup automatically. The page is the IT Asset Register's Locations tile
# (portal add-on /dashboards/vendor/zyb-assetreg.js).
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib-itam.sh"   # restart only when needed, wait until the API answers
APP=/opt/sentra-itam; SVC=sentra-itam; BK=/var/backups/sentra-itam-locations
MAIN="$APP/engine/main.js"; MOD="$APP/engine/locations.js"
LINE="  require('./locations').registerLocations(srv, app); // shared locations / sites, rename everywhere (engine/locations.js)"
say() { echo "==> $*"; }; die() { echo "!! $*"; exit 1; }

if [ "${1:-}" = "--rollback" ]; then
  [ -f "$BK/main.js" ] || die "no backup in $BK"
  cp -p "$BK/main.js" "$MAIN"; if [ -f "$BK/locations.js" ]; then cp -p "$BK/locations.js" "$MOD"; else rm -f "$MOD"; fi
  itam_restart; say "restored the engine from before the locations list was added ($(systemctl is-active "$SVC"))"; exit 0
fi

[ -f "$MAIN" ] || die "IT Asset Management is not installed here ($MAIN not found)"
SRC="$HERE/../engine/locations.js"; [ -f "$SRC" ] || die "missing $SRC - copy the whole sentra-itam folder"
NODE="$(systemctl show -p ExecStart --value "$SVC" 2>/dev/null | sed -n 's/.*argv\[\]=\([^ ;]*\).*/\1/p' | head -n1)"
[ -x "${NODE:-}" ] || NODE=/opt/sentra-ai/node/bin/node; [ -x "$NODE" ] || NODE="$(command -v node || true)"
[ -x "${NODE:-}" ] || die "could not find the Node.js the service uses"

PRE_FP="$(itam_fp)"
say "backup -> $BK"
mkdir -p "$BK"; chmod 700 "$BK"
if grep -q "registerLocations" "$MAIN" && [ -f "$BK/main.js" ]; then echo "   (keeping the backup from before the first install)"
else cp -p "$MAIN" "$BK/main.js"; if [ -f "$MOD" ]; then cp -p "$MOD" "$BK/locations.js"; else rm -f "$BK/locations.js"; fi; fi
cp -p "$MAIN" "$BK/main.run.js"   # this run's main.js: a failure puts back exactly this, never the copy from before the first install (that one drops every route added since)
restore() { itam_on_restore "$1"; echo "!! $1 - restoring the previous engine"; cp -p "$BK/main.run.js" "$MAIN"; if [ -f "$BK/locations.js" ]; then cp -p "$BK/locations.js" "$MOD"; else rm -f "$MOD"; fi; itam_restart || true; echo "   $SVC: $(systemctl is-active "$SVC")"; exit 1; }

install -m 644 -o root -g root "$SRC" "$MOD"
# the writes decided in Python (step 9f, docs/PYTHON-MIGRATION.md): the bridge, the commit and the modules; without them
# the module writes in Node.js as before
for f in pyengine.js py-writer.js; do [ -f "$HERE/../engine/$f" ] && install -m 644 -o root -g root "$HERE/../engine/$f" "$APP/engine/$f"; done
if [ -d "$HERE/../pyengine" ]; then install -d -m 755 -o root -g root "$APP/pyengine"; for f in "$HERE"/../pyengine/*.py; do install -m 644 -o root -g root "$f" "$APP/pyengine/"; done; rm -rf "$APP/pyengine/__pycache__"; fi
if grep -q "registerLocations" "$MAIN"; then say "main.js already registers the locations list"
else
  if grep -q "^ *registerDiscoveryRoutes(srv, app);" "$MAIN"; then ANCHOR="registerDiscoveryRoutes(srv, app);"
  elif grep -q "^ *registerRoutes(srv, app);" "$MAIN"; then ANCHOR="registerRoutes(srv, app);"
  else restore "could not find where routes are registered in $MAIN"; fi
  LINE="$LINE" ANCHOR="$ANCHOR" awk '{print} !done && index($0, ENVIRON["ANCHOR"]) && $0 ~ /^ *register/ {print ENVIRON["LINE"]; done=1}' "$MAIN" > "$MAIN.tmp" && cat "$MAIN.tmp" > "$MAIN" && rm -f "$MAIN.tmp"
  grep -q "registerLocations" "$MAIN" || restore "could not add the registration line"
  say "registered the locations list in main.js"
fi
"$NODE" --check "$MAIN" && "$NODE" --check "$MOD" || restore "syntax check failed"

itam_restart_if_changed "$PRE_FP"
systemctl is-active --quiet "$SVC" || itam_start_failed restore

# live check: the route must exist (403 for a viewer); 404 means it was not registered. No data is changed.
CODE="$("$NODE" -e '
const fs=require("fs"),http=require("http");let c={},s={};
try{c=JSON.parse(fs.readFileSync("/etc/sentra-itam/config.json","utf8"))}catch(e){}
try{s=JSON.parse(fs.readFileSync("/etc/sentra-itam/secrets.json","utf8"))}catch(e){}
const a=c.api||{},port=a.port||9150,pre=a.prefix||"/api/itam";
const r=http.request({host:a.host||"127.0.0.1",port,method:"GET",path:pre+"/locations",headers:{"Content-Type":"application/json","X-Sentra-Proxy-Secret":s.proxy_secret||"","X-Auth-User":"zyb-install-check","X-Auth-Role":"viewer"}},res=>{res.resume();console.log(res.statusCode)});
r.on("error",()=>console.log(0));r.setTimeout(5000,()=>{r.destroy()});r.end();' 2>/dev/null || echo 0)"
case "$CODE" in
  403) say "locations list is live";;
  401) say "locations list installed (the live check could not authenticate - open the portal to confirm)";;
  404) restore "the locations list did not register";;
  *) say "installed; the live check returned '$CODE' - open the portal to confirm";;
esac
echo "   undo: sudo bash $0 --rollback"
