#!/bin/bash
# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
# add-grc.sh - GRC policy register + control automation: the the organisation approved IT policies become live data
#   (engine/grc.js + engine/grc-policies.json). Each policy is mapped to the platform control that automates or
#   monitors it; review cycles are tracked; owners attest. Read-only governance - nothing here changes a device.
#   sudo bash add-grc.sh              install / update (safe to re-run)
#   sudo bash add-grc.sh --rollback   put back the engine from before the first install
# Copies the module and its policy register, adds one registration line to engine/main.js. Backup first, syntax check,
# restart, then a live check that the route answers; any failure restores the backup automatically.
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib-itam.sh"
APP=/opt/sentra-itam; SVC=sentra-itam; BK=/var/backups/sentra-itam-grc
MAIN="$APP/engine/main.js"; MOD="$APP/engine/grc.js"; DATA="$APP/engine/grc-policies.json"
LINE="  require('./grc').registerGrc(srv, app); // GRC policy register + control automation (engine/grc.js)"
say() { echo "==> $*"; }; die() { echo "!! $*"; exit 1; }

if [ "${1:-}" = "--rollback" ]; then
  [ -f "$BK/main.js" ] || die "no backup in $BK"
  cp -p "$BK/main.js" "$MAIN"; if [ -f "$BK/grc.js" ]; then cp -p "$BK/grc.js" "$MOD"; else rm -f "$MOD"; fi
  if [ -f "$BK/grc-policies.json" ]; then cp -p "$BK/grc-policies.json" "$DATA"; else rm -f "$DATA"; fi
  itam_restart; say "restored the engine from before the GRC module was added ($(systemctl is-active "$SVC"))"; exit 0
fi

[ -f "$MAIN" ] || die "IT Asset Management is not installed here ($MAIN not found)"
SRC="$HERE/../engine/grc.js"; SRCD="$HERE/../engine/grc-policies.json"
[ -f "$SRC" ] || die "missing $SRC - copy the whole sentra-itam folder"
[ -f "$SRCD" ] || die "missing $SRCD - copy the whole sentra-itam folder"
NODE="$(systemctl show -p ExecStart --value "$SVC" 2>/dev/null | sed -n 's/.*argv\[\]=\([^ ;]*\).*/\1/p' | head -n1)"
[ -x "${NODE:-}" ] || NODE=/opt/sentra-ai/node/bin/node; [ -x "$NODE" ] || NODE="$(command -v node || true)"
[ -x "${NODE:-}" ] || die "could not find the Node.js the service uses"

PRE_FP="$(itam_fp)"
say "backup -> $BK"
mkdir -p "$BK"; chmod 700 "$BK"
if grep -q "registerGrc" "$MAIN" && [ -f "$BK/main.js" ]; then echo "   (keeping the backup from before the first install)"
else cp -p "$MAIN" "$BK/main.js"; if [ -f "$MOD" ]; then cp -p "$MOD" "$BK/grc.js"; else rm -f "$BK/grc.js"; fi; if [ -f "$DATA" ]; then cp -p "$DATA" "$BK/grc-policies.json"; else rm -f "$BK/grc-policies.json"; fi; fi
cp -p "$MAIN" "$BK/main.run.js"   # this run's main.js: a failure puts back exactly this, never the copy from before the first install (that one drops every route added since)
restore() { itam_on_restore "$1"; echo "!! $1 - restoring the previous engine"; cp -p "$BK/main.run.js" "$MAIN"; if [ -f "$BK/grc.js" ]; then cp -p "$BK/grc.js" "$MOD"; else rm -f "$MOD"; fi; if [ -f "$BK/grc-policies.json" ]; then cp -p "$BK/grc-policies.json" "$DATA"; else rm -f "$DATA"; fi; itam_restart || true; echo "   $SVC: $(systemctl is-active "$SVC")"; exit 1; }

install -m 644 -o root -g root "$SRC" "$MOD"
# the working registers (actions, risks, exceptions, evidence) - registered by grc.js when present
[ -f "$HERE/../engine/grc-registers.js" ] && install -m 644 -o root -g root "$HERE/../engine/grc-registers.js" "$APP/engine/grc-registers.js"
# the read routes in Python (step 8d, docs/PYTHON-MIGRATION.md): the bridge and the modules; without them grc.js answers
[ -f "$HERE/../engine/pyengine.js" ] && install -m 644 -o root -g root "$HERE/../engine/pyengine.js" "$APP/engine/pyengine.js"
if [ -d "$HERE/../pyengine" ]; then install -d -m 755 -o root -g root "$APP/pyengine"; for f in "$HERE"/../pyengine/*.py; do install -m 644 -o root -g root "$f" "$APP/pyengine/"; done; rm -rf "$APP/pyengine/__pycache__"; fi
install -m 644 -o root -g root "$SRCD" "$DATA"
if grep -q "registerGrc" "$MAIN"; then say "main.js already registers the GRC module"
else
  if grep -q "^ *require('\./pentest')\.registerPentest(srv, app);" "$MAIN"; then ANCHOR="registerPentest(srv, app);"
  elif grep -q "^ *registerDiscoveryRoutes(srv, app);" "$MAIN"; then ANCHOR="registerDiscoveryRoutes(srv, app);"
  elif grep -q "^ *registerRoutes(srv, app);" "$MAIN"; then ANCHOR="registerRoutes(srv, app);"
  else restore "could not find where routes are registered in $MAIN"; fi
  LINE="$LINE" ANCHOR="$ANCHOR" awk '{print} !done && index($0, ENVIRON["ANCHOR"]) && $0 ~ /^ *(require|register)/ {print ENVIRON["LINE"]; done=1}' "$MAIN" > "$MAIN.tmp" && cat "$MAIN.tmp" > "$MAIN" && rm -f "$MAIN.tmp"
  grep -q "registerGrc" "$MAIN" || restore "could not add the registration line"
  say "registered the GRC module in main.js"
fi
"$NODE" --check "$MAIN" && "$NODE" --check "$MOD" || restore "syntax check failed"
"$NODE" -e "require('$DATA')" || restore "the policy register JSON is invalid"

itam_restart_if_changed "$PRE_FP"
systemctl is-active --quiet "$SVC" || itam_start_failed restore

# live check: /grc/summary is readable by a viewer (200). 404 means it was not registered. No data is changed.
CODE="$("$NODE" -e '
const fs=require("fs"),http=require("http");let c={},s={};
try{c=JSON.parse(fs.readFileSync("/etc/sentra-itam/config.json","utf8"))}catch(e){}
try{s=JSON.parse(fs.readFileSync("/etc/sentra-itam/secrets.json","utf8"))}catch(e){}
const a=c.api||{},port=a.port||9150,pre=a.prefix||"/api/itam";
const r=http.request({host:a.host||"127.0.0.1",port,method:"GET",path:pre+"/grc/summary",headers:{"Content-Type":"application/json","X-Sentra-Proxy-Secret":s.proxy_secret||"","X-Auth-User":"zyb-install-check","X-Auth-Role":"viewer"}},res=>{res.resume();console.log(res.statusCode)});
r.on("error",()=>console.log(0));r.setTimeout(5000,()=>{r.destroy()});r.end();' 2>/dev/null || echo 0)"
case "$CODE" in
  200) say "GRC policy register is live";;
  401) say "GRC module installed (the live check could not authenticate - open the portal to confirm)";;
  404) restore "the GRC module did not register";;
  *) say "installed; the live check returned '$CODE' - open the portal to confirm";;
esac
echo "   undo: sudo bash $0 --rollback"
