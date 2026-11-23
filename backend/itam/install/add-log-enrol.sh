#!/bin/bash
# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
# add-log-enrol.sh - automatic SIEM enrolment (engine/log-enrol.js): every in-use server, network device, storage and VM in the
#   inventory that sends no logs gets its SIEM log source (the AI SIEM Engineer then asks for the device configuration). Audited.
#   sudo bash add-log-enrol.sh              install / update (safe to re-run)
#   sudo bash add-log-enrol.sh --rollback   put back the engine from before the first install
# Copies the module, adds one registration line to engine/main.js. Backup first, syntax check, restart, then a live
# check that the route answers; any failure restores the backup automatically.
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib-itam.sh"
APP=/opt/sentra-itam; SVC=sentra-itam; BK=/var/backups/sentra-itam-log-enrol
MAIN="$APP/engine/main.js"; MOD="$APP/engine/log-enrol.js"
LINE="  require('./log-enrol').registerLogEnrol(srv, app); // automatic SIEM enrolment of discovered assets (engine/log-enrol.js)"
say() { echo "==> $*"; }; die() { echo "!! $*"; exit 1; }

if [ "${1:-}" = "--rollback" ]; then
  [ -f "$BK/main.js" ] || die "no backup in $BK"
  cp -p "$BK/main.js" "$MAIN"; if [ -f "$BK/log-enrol.js" ]; then cp -p "$BK/log-enrol.js" "$MOD"; else rm -f "$MOD"; fi
  itam_restart; say "restored the engine from before automatic SIEM enrolment was added ($(systemctl is-active "$SVC"))"; exit 0
fi

[ -f "$MAIN" ] || die "IT Asset Management is not installed here ($MAIN not found)"
# an engine from before inventory log collection: it is added here (the module + one line), instead of stopping
MEM="$APP/engine/monitoring-membership.js"; MEM_SRC=""
for f in "$HERE/../engine/monitoring-membership.js" "$HERE/../engine-all/monitoring-membership.js"; do [ -f "$f" ] && { MEM_SRC="$f"; break; }; done
if ! grep -q "createMembership" "$MAIN"; then
  [ -f "$MEM" ] || [ -n "$MEM_SRC" ] || die "this engine has no inventory log collection and monitoring-membership.js is not in the update folder - run the full update"
  grep -q "^ *registerDiscoveryRoutes(srv, app);" "$MAIN" || die "this engine has no Asset Discovery routes (registerDiscoveryRoutes) - run the full update first"
fi
SRC="$HERE/../engine/log-enrol.js"
[ -f "$SRC" ] || die "missing $SRC - copy the whole sentra-itam folder"
NODE="$(systemctl show -p ExecStart --value "$SVC" 2>/dev/null | sed -n 's/.*argv\[\]=\([^ ;]*\).*/\1/p' | head -n1)"
[ -x "${NODE:-}" ] || NODE=/opt/sentra-ai/node/bin/node; [ -x "$NODE" ] || NODE="$(command -v node || true)"
[ -x "${NODE:-}" ] || die "could not find the Node.js the service uses"

PRE_FP="$(itam_fp)"
say "backup -> $BK"
mkdir -p "$BK"; chmod 700 "$BK"
if grep -q "registerLogEnrol" "$MAIN" && [ -f "$BK/main.js" ]; then echo "   (keeping the backup from before the first install)"
else cp -p "$MAIN" "$BK/main.js"; if [ -f "$MOD" ]; then cp -p "$MOD" "$BK/log-enrol.js"; else rm -f "$BK/log-enrol.js"; fi; fi
cp -p "$MAIN" "$BK/main.run.js"   # this run's main.js: a failure puts back exactly this, never the copy from before the first install (that one drops every route added since)
MEM_ADDED=0
restore() { itam_on_restore "$1"; echo "!! $1 - restoring the previous engine"; cp -p "$BK/main.run.js" "$MAIN"; if [ -f "$BK/log-enrol.js" ]; then cp -p "$BK/log-enrol.js" "$MOD"; else rm -f "$MOD"; fi; [ "$MEM_ADDED" = 1 ] && rm -f "$MEM"; itam_restart || true; echo "   $SVC: $(systemctl is-active "$SVC")"; exit 1; }

if ! grep -q "createMembership" "$MAIN"; then
  if [ ! -f "$MEM" ]; then install -m 644 -o root -g root "$MEM_SRC" "$MEM"; MEM_ADDED=1; fi
  MLINE="  if (!app.membership) app.membership = require('./monitoring-membership').createMembership({ assets: app.assets, store: app.store, audit: app.audit || function () {}, discovery: app.discovery, log: app.log }); // inventory log collection (added by add-log-enrol.sh)"
  MLINE="$MLINE" awk '{print} !done && $0 ~ /^ *registerDiscoveryRoutes\(srv, app\);/ {print ENVIRON["MLINE"]; done=1}' "$MAIN" > "$MAIN.tmp" && cat "$MAIN.tmp" > "$MAIN" && rm -f "$MAIN.tmp"
  grep -q "createMembership" "$MAIN" || restore "could not add inventory log collection to main.js"
  "$NODE" --check "$MEM" || restore "monitoring-membership.js syntax check failed"
  say "added inventory log collection (monitoring-membership.js) - it was missing from this engine"
fi

install -m 644 -o root -g root "$SRC" "$MOD"
if grep -q "registerLogEnrol" "$MAIN"; then say "main.js already registers automatic SIEM enrolment"
else
  if grep -q "^ *require('\./duty')\.registerDuty(srv, app);" "$MAIN"; then ANCHOR="registerDuty(srv, app);"
  elif grep -q "^ *require('\./grc')\.registerGrc(srv, app);" "$MAIN"; then ANCHOR="registerGrc(srv, app);"
  elif grep -q "^ *require('\./pentest')\.registerPentest(srv, app);" "$MAIN"; then ANCHOR="registerPentest(srv, app);"
  elif grep -q "^ *registerDiscoveryRoutes(srv, app);" "$MAIN"; then ANCHOR="registerDiscoveryRoutes(srv, app);"
  elif grep -q "^ *registerRoutes(srv, app);" "$MAIN"; then ANCHOR="registerRoutes(srv, app);"
  else restore "could not find where routes are registered in $MAIN"; fi
  # log enrolment needs app.membership: when this script added it just after the discovery routes, go after that line
  [ "$ANCHOR" = "registerDiscoveryRoutes(srv, app);" ] && grep -q "(added by add-log-enrol.sh)" "$MAIN" && ANCHOR="(added by add-log-enrol.sh)"
  LINE="$LINE" ANCHOR="$ANCHOR" awk '{print} !done && index($0, ENVIRON["ANCHOR"]) && $0 ~ /^ *(require|register|if \(!app\.membership)/ {print ENVIRON["LINE"]; done=1}' "$MAIN" > "$MAIN.tmp" && cat "$MAIN.tmp" > "$MAIN" && rm -f "$MAIN.tmp"
  grep -q "registerLogEnrol" "$MAIN" || restore "could not add the registration line"
  say "registered automatic SIEM enrolment in main.js"
fi
"$NODE" --check "$MAIN" && "$NODE" --check "$MOD" || restore "syntax check failed"

itam_restart_if_changed "$PRE_FP"
systemctl is-active --quiet "$SVC" || itam_start_failed restore

# live check: /log-collection/auto is readable by a viewer (200). 404 means it was not registered. No data is changed.
CODE="$("$NODE" -e '
const fs=require("fs"),http=require("http");let c={},s={};
try{c=JSON.parse(fs.readFileSync("/etc/sentra-itam/config.json","utf8"))}catch(e){}
try{s=JSON.parse(fs.readFileSync("/etc/sentra-itam/secrets.json","utf8"))}catch(e){}
const a=c.api||{},port=a.port||9150,pre=a.prefix||"/api/itam";
const r=http.request({host:a.host||"127.0.0.1",port,method:"GET",path:pre+"/log-collection/auto",headers:{"Content-Type":"application/json","X-Sentra-Proxy-Secret":s.proxy_secret||"","X-Auth-User":"zyb-install-check","X-Auth-Role":"viewer"}},res=>{res.resume();console.log(res.statusCode)});
r.on("error",()=>console.log(0));r.setTimeout(5000,()=>{r.destroy()});r.end();' 2>/dev/null || echo 0)"
case "$CODE" in
  200) say "automatic SIEM enrolment is live: discovered assets are enrolled into SIEM log collection every 15 min";;
  401) say "automatic SIEM enrolment installed (the live check could not authenticate - open the portal to confirm)";;
  404) restore "automatic SIEM enrolment did not register";;
  *) say "installed; the live check returned '$CODE' - open the portal to confirm";;
esac
echo "   undo: sudo bash $0 --rollback"
