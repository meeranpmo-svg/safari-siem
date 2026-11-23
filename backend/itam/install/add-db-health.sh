#!/bin/bash
# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
# add-db-health.sh - Oracle health from the asset inventory (engine/db-health.js): the read-only Oracle login saved in Asset
#   Discovery feeds the AI Oracle DBA (no agent on the database hosts). Also installs the helper op in discovery/inv-helper.py.
#   sudo bash add-db-health.sh              install / update (safe to re-run)
#   sudo bash add-db-health.sh --rollback   put back the engine from before the first install
# Copies the module, adds one registration line to engine/main.js. Backup first, syntax check, restart, then a live
# check that the route answers; any failure restores the backup automatically.
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib-itam.sh"
APP=/opt/sentra-itam; SVC=sentra-itam; BK=/var/backups/sentra-itam-db-health
MAIN="$APP/engine/main.js"; MOD="$APP/engine/db-health.js"; MOD2="$APP/engine/db-servers.js"; MOD3="$APP/engine/db-replicate.js"; MOD4="$APP/engine/db-sessions.js"; MOD5="$APP/engine/db-morning.js"
LINE="  require('./db-health').registerDbHealth(srv, app); // Oracle health from Asset Discovery logins → AI Oracle DBA (engine/db-health.js)"
say() { echo "==> $*"; }; die() { echo "!! $*"; exit 1; }

if [ "${1:-}" = "--rollback" ]; then
  [ -f "$BK/main.js" ] || die "no backup in $BK"
  cp -p "$BK/main.js" "$MAIN"; if [ -f "$BK/db-health.js" ]; then cp -p "$BK/db-health.js" "$MOD"; else rm -f "$MOD"; fi
  itam_restart; say "restored the engine from before Oracle health from the inventory was added ($(systemctl is-active "$SVC"))"; exit 0
fi

[ -f "$MAIN" ] || die "IT Asset Management is not installed here ($MAIN not found)"
grep -q "registerDiscoveryRoutes" "$MAIN" || die "this IT Asset Management engine has no Asset Discovery (it holds the database logins) - run update-discovery.sh first"
# the read-only health op lives in the Asset Discovery login helper: install it whenever this bundle's copy differs (its
# safeguards - privilege check, call timeout, hourly dictionary scans - change with it); the old copy is kept and put back
# if the new one does not compile
PYB="$(sed -n 's/.*"python_bin" *: *"\([^"]*\)".*/\1/p' /etc/sentra-itam/config.json 2>/dev/null | head -n1)"; [ -x "${PYB:-}" ] || PYB=/opt/sentra-siem/pyenv/bin/python3; [ -x "$PYB" ] || PYB="$(command -v python3 || true)"
HELPER_SRC="$HERE/../engine/discovery/inv-helper.py"; HELPER="$APP/engine/discovery/inv-helper.py"
if [ -f "$HELPER_SRC" ] && ! cmp -s "$HELPER_SRC" "$HELPER"; then
  PYB="$(sed -n 's/.*"python_bin" *: *"\([^"]*\)".*/\1/p' /etc/sentra-itam/config.json 2>/dev/null | head -n1)"; [ -x "${PYB:-}" ] || PYB=/opt/sentra-siem/pyenv/bin/python3; [ -x "$PYB" ] || PYB="$(command -v python3 || true)"
  [ -f "$HELPER" ] && cp -p "$HELPER" "$HELPER.bak-dbhealth"
  install -m 644 -o root -g root "$HELPER_SRC" "$HELPER"
  if [ -n "$PYB" ] && ! "$PYB" -c 'import ast,sys; ast.parse(open(sys.argv[1]).read())' "$HELPER"; then
    [ -f "$HELPER.bak-dbhealth" ] && cp -p "$HELPER.bak-dbhealth" "$HELPER"; die "the new discovery/inv-helper.py does not compile - the previous copy was put back"
  fi
  say "installed the Oracle health query helper (discovery/inv-helper.py: read-only account check, 10 s call timeout)"
fi
# the helper's companion files: the tuning / Data Guard / audit readings (oracle-tuning.sql) and our own engines (db_repl.py).
# Without them the helper runs but those readings silently do not - so they are installed with it, every time they differ.
for f in oracle-tuning.sql db_repl.py; do
  FS="$HERE/../engine/discovery/$f"; FD="$APP/engine/discovery/$f"
  [ -f "$FS" ] || die "missing $FS - copy the whole sentra-itam folder"
  if ! cmp -s "$FS" "$FD"; then
    [ -f "$FD" ] && cp -p "$FD" "$FD.bak-dbhealth"
    install -m 644 -o root -g root "$FS" "$FD"
    if [ "$f" = db_repl.py ] && [ -n "${PYB:-}" ] && ! "$PYB" -c 'import ast,sys; ast.parse(open(sys.argv[1]).read())' "$FD"; then
      if [ -f "$FD.bak-dbhealth" ]; then cp -p "$FD.bak-dbhealth" "$FD"; else rm -f "$FD"; fi; die "the new discovery/$f does not compile - the previous copy was put back"
    fi
    say "installed discovery/$f"
  fi
done
SRC="$HERE/../engine/db-health.js"
[ -f "$SRC" ] || die "missing $SRC - copy the whole sentra-itam folder"
SRC2="$HERE/../engine/db-servers.js"
[ -f "$SRC2" ] || die "missing $SRC2 - copy the whole sentra-itam folder"
SRC3="$HERE/../engine/db-replicate.js"
[ -f "$SRC3" ] || die "missing $SRC3 - copy the whole sentra-itam folder"
SRC4="$HERE/../engine/db-sessions.js"
[ -f "$SRC4" ] || die "missing $SRC4 - copy the whole sentra-itam folder"
SRC5="$HERE/../engine/db-morning.js"
[ -f "$SRC5" ] || die "missing $SRC5 - copy the whole sentra-itam folder"
NODE="$(systemctl show -p ExecStart --value "$SVC" 2>/dev/null | sed -n 's/.*argv\[\]=\([^ ;]*\).*/\1/p' | head -n1)"
[ -x "${NODE:-}" ] || NODE=/opt/sentra-ai/node/bin/node; [ -x "$NODE" ] || NODE="$(command -v node || true)"
[ -x "${NODE:-}" ] || die "could not find the Node.js the service uses"

PRE_FP="$(itam_fp)"
say "backup -> $BK"
mkdir -p "$BK"; chmod 700 "$BK"
if grep -q "registerDbHealth" "$MAIN" && [ -f "$BK/main.js" ]; then echo "   (keeping the backup from before the first install)"
else cp -p "$MAIN" "$BK/main.js"; if [ -f "$MOD" ]; then cp -p "$MOD" "$BK/db-health.js"; else rm -f "$BK/db-health.js"; fi; fi
if [ -f "$MOD2" ]; then cp -p "$MOD2" "$BK/db-servers.run.js"; else rm -f "$BK/db-servers.run.js"; fi
if [ -f "$MOD3" ]; then cp -p "$MOD3" "$BK/db-replicate.run.js"; else rm -f "$BK/db-replicate.run.js"; fi
if [ -f "$MOD4" ]; then cp -p "$MOD4" "$BK/db-sessions.run.js"; else rm -f "$BK/db-sessions.run.js"; fi
if [ -f "$MOD5" ]; then cp -p "$MOD5" "$BK/db-morning.run.js"; else rm -f "$BK/db-morning.run.js"; fi
cp -p "$MAIN" "$BK/main.run.js"   # this run's main.js: a failure puts back exactly this, never the copy from before the first install (that one drops every route added since)
restore() { itam_on_restore "$1"; echo "!! $1 - restoring the previous engine"; cp -p "$BK/main.run.js" "$MAIN"; if [ -f "$BK/db-health.js" ]; then cp -p "$BK/db-health.js" "$MOD"; else rm -f "$MOD"; fi; if [ -f "$BK/db-servers.run.js" ]; then cp -p "$BK/db-servers.run.js" "$MOD2"; else rm -f "$MOD2"; fi; if [ -f "$BK/db-replicate.run.js" ]; then cp -p "$BK/db-replicate.run.js" "$MOD3"; else rm -f "$MOD3"; fi; if [ -f "$BK/db-sessions.run.js" ]; then cp -p "$BK/db-sessions.run.js" "$MOD4"; else rm -f "$MOD4"; fi; if [ -f "$BK/db-morning.run.js" ]; then cp -p "$BK/db-morning.run.js" "$MOD5"; else rm -f "$MOD5"; fi; itam_restart || true; echo "   $SVC: $(systemctl is-active "$SVC")"; exit 1; }

install -m 644 -o root -g root "$SRC" "$MOD"
install -m 644 -o root -g root "$SRC2" "$MOD2"
install -m 644 -o root -g root "$SRC3" "$MOD3"
install -m 644 -o root -g root "$SRC4" "$MOD4"
install -m 644 -o root -g root "$SRC5" "$MOD5"
if grep -q "registerDbHealth" "$MAIN"; then say "main.js already registers Oracle health from the inventory"
else
  if grep -q "^ *require('\./duty')\.registerDuty(srv, app);" "$MAIN"; then ANCHOR="registerDuty(srv, app);"
  elif grep -q "^ *require('\./grc')\.registerGrc(srv, app);" "$MAIN"; then ANCHOR="registerGrc(srv, app);"
  elif grep -q "^ *require('\./pentest')\.registerPentest(srv, app);" "$MAIN"; then ANCHOR="registerPentest(srv, app);"
  elif grep -q "^ *registerDiscoveryRoutes(srv, app);" "$MAIN"; then ANCHOR="registerDiscoveryRoutes(srv, app);"
  elif grep -q "^ *registerRoutes(srv, app);" "$MAIN"; then ANCHOR="registerRoutes(srv, app);"
  else restore "could not find where routes are registered in $MAIN"; fi
  LINE="$LINE" ANCHOR="$ANCHOR" awk '{print} !done && index($0, ENVIRON["ANCHOR"]) && $0 ~ /^ *(require|register)/ {print ENVIRON["LINE"]; done=1}' "$MAIN" > "$MAIN.tmp" && cat "$MAIN.tmp" > "$MAIN" && rm -f "$MAIN.tmp"
  grep -q "registerDbHealth" "$MAIN" || restore "could not add the registration line"
  say "registered Oracle health from the inventory in main.js"
fi
"$NODE" --check "$MAIN" && "$NODE" --check "$MOD" && "$NODE" --check "$MOD2" && "$NODE" --check "$MOD3" && "$NODE" --check "$MOD4" && "$NODE" --check "$MOD5" || restore "syntax check failed"

itam_restart_if_changed "$PRE_FP"
systemctl is-active --quiet "$SVC" || itam_start_failed restore

# live check: /db-health is readable by a viewer (200). 404 means it was not registered. No data is changed.
CODE="$("$NODE" -e '
const fs=require("fs"),http=require("http");let c={},s={};
try{c=JSON.parse(fs.readFileSync("/etc/sentra-itam/config.json","utf8"))}catch(e){}
try{s=JSON.parse(fs.readFileSync("/etc/sentra-itam/secrets.json","utf8"))}catch(e){}
const a=c.api||{},port=a.port||9150,pre=a.prefix||"/api/itam";
const r=http.request({host:a.host||"127.0.0.1",port,method:"GET",path:pre+"/db-health",headers:{"Content-Type":"application/json","X-Sentra-Proxy-Secret":s.proxy_secret||"","X-Auth-User":"zyb-install-check","X-Auth-Role":"viewer"}},res=>{res.resume();console.log(res.statusCode)});
r.on("error",()=>console.log(0));r.setTimeout(5000,()=>{r.destroy()});r.end();' 2>/dev/null || echo 0)"
case "$CODE" in
  200) say "Oracle health from the inventory is live: every Oracle login proven in Asset Discovery feeds the AI Oracle DBA every 4 min";;
  401) say "Oracle health from the inventory installed (the live check could not authenticate - open the portal to confirm)";;
  404) restore "Oracle health from the inventory did not register";;
  *) say "installed; the live check returned '$CODE' - open the portal to confirm";;
esac
echo "   undo: sudo bash $0 --rollback"
