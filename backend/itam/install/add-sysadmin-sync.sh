#!/bin/bash
# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
# add-sysadmin-sync.sh - send Windows servers from IT Asset Management to the AI Windows Server Administrator and
#   Exchange servers to the AI Exchange Server Administrator (SIEM sysadmin server list) automatically, every 5 minutes
#   (engine/sysadmin-sync.js).
#   sudo bash add-sysadmin-sync.sh              install / update (safe to re-run)
#   sudo bash add-sysadmin-sync.sh --rollback   put back the engine from before the first install
# Copies engine/sysadmin-sync.js and adds one registration line to engine/main.js. Nothing else in the installed engine
# is changed. Backup first, syntax check, restart, then a live check that the route answers; any failure restores the
# backup automatically. Only server facts are sent - the WinRM logins are set once in the SIEM (write-only).
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib-itam.sh"   # restart only when needed, wait until the API answers
APP=/opt/sentra-itam; SVC=sentra-itam; BK=/var/backups/sentra-itam-sysadmin-sync
MAIN="$APP/engine/main.js"; MOD="$APP/engine/sysadmin-sync.js"
LINE="  require('./sysadmin-sync').registerSysadminSync(srv, app); // Windows / Exchange servers -> AI Server Administrators (engine/sysadmin-sync.js)"
say() { echo "==> $*"; }; die() { echo "!! $*"; exit 1; }

if [ "${1:-}" = "--rollback" ]; then
  [ -f "$BK/main.js" ] || die "no backup in $BK"
  cp -p "$BK/main.js" "$MAIN"; if [ -f "$BK/sysadmin-sync.js" ]; then cp -p "$BK/sysadmin-sync.js" "$MOD"; else rm -f "$MOD"; fi
  itam_restart; say "restored the engine from before the AI Server Administrators sync was added ($(systemctl is-active "$SVC"))"; exit 0
fi

[ -f "$MAIN" ] || die "IT Asset Management is not installed here ($MAIN not found)"
SRC="$HERE/../engine/sysadmin-sync.js"; [ -f "$SRC" ] || die "missing $SRC - copy the whole sentra-itam folder"
NODE="$(systemctl show -p ExecStart --value "$SVC" 2>/dev/null | sed -n 's/.*argv\[\]=\([^ ;]*\).*/\1/p' | head -n1)"
[ -x "${NODE:-}" ] || NODE=/opt/sentra-ai/node/bin/node; [ -x "$NODE" ] || NODE="$(command -v node || true)"
[ -x "${NODE:-}" ] || die "could not find the Node.js the service uses"

PRE_FP="$(itam_fp)"
say "backup -> $BK"
mkdir -p "$BK"; chmod 700 "$BK"
if grep -q "registerSysadminSync" "$MAIN" && [ -f "$BK/main.js" ]; then echo "   (keeping the backup from before the first install)"
else cp -p "$MAIN" "$BK/main.js"; if [ -f "$MOD" ]; then cp -p "$MOD" "$BK/sysadmin-sync.js"; else rm -f "$BK/sysadmin-sync.js"; fi; fi
cp -p "$MAIN" "$BK/main.run.js"   # this run's main.js: a failure puts back exactly this, never the copy from before the first install (that one drops every route added since)
restore() { itam_on_restore "$1"; echo "!! $1 - restoring the previous engine"; cp -p "$BK/main.run.js" "$MAIN"; if [ -f "$BK/sysadmin-sync.js" ]; then cp -p "$BK/sysadmin-sync.js" "$MOD"; else rm -f "$MOD"; fi; itam_restart || true; echo "   $SVC: $(systemctl is-active "$SVC")"; exit 1; }

install -m 644 -o root -g root "$SRC" "$MOD"
# Exchange evidence shared with the server pages (Business Services + the Email Route Map register)
[ -f "$HERE/../engine/exchange-evidence.js" ] && install -m 644 -o root -g root "$HERE/../engine/exchange-evidence.js" "$APP/engine/exchange-evidence.js"
if grep -q "registerSysadminSync" "$MAIN"; then say "main.js already registers the AI Server Administrators sync"
else
  if grep -q "^ *registerDiscoveryRoutes(srv, app);" "$MAIN"; then ANCHOR="registerDiscoveryRoutes(srv, app);"
  elif grep -q "^ *registerRoutes(srv, app);" "$MAIN"; then ANCHOR="registerRoutes(srv, app);"
  else restore "could not find where routes are registered in $MAIN"; fi
  LINE="$LINE" ANCHOR="$ANCHOR" awk '{print} !done && index($0, ENVIRON["ANCHOR"]) && $0 ~ /^ *register/ {print ENVIRON["LINE"]; done=1}' "$MAIN" > "$MAIN.tmp" && cat "$MAIN.tmp" > "$MAIN" && rm -f "$MAIN.tmp"
  grep -q "registerSysadminSync" "$MAIN" || restore "could not add the registration line"
  say "registered the AI Server Administrators sync in main.js"
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
const r=http.request({host:a.host||"127.0.0.1",port,method:"GET",path:pre+"/sysadmin-sync",headers:{"Content-Type":"application/json","X-Sentra-Proxy-Secret":s.proxy_secret||"","X-Auth-User":"zyb-install-check","X-Auth-Role":"viewer"}},res=>{res.resume();console.log(res.statusCode)});
r.on("error",()=>console.log(0));r.setTimeout(5000,()=>{r.destroy()});r.end();' 2>/dev/null || echo 0)"
case "$CODE" in
  403) say "AI Server Administrators sync is live";;
  401) say "AI Server Administrators sync installed (the live check could not authenticate - open the portal to confirm)";;
  404) restore "the AI Server Administrators sync did not register";;
  *) say "installed; the live check returned '$CODE' - open the portal to confirm";;
esac
echo "   undo: sudo bash $0 --rollback"
