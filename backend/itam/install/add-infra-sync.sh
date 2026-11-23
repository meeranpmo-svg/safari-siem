#!/bin/bash
# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
# add-infra-sync.sh - IT Asset Management <-> Infrastructure Automation (engine/infra-sync.js): network devices, Linux
#   servers and PostgreSQL / MySQL instances of the asset register become Infrastructure Automation targets, and targets
#   added there come back into the register. Shown on Server & asset reconciliation; part of "Sync all now".
#   sudo bash add-infra-sync.sh              install / update (safe to re-run)
#   sudo bash add-infra-sync.sh --rollback   put back the engine from before the first install
# Copies engine/infra-sync.js, adds one registration line to engine/main.js, and copies the Infrastructure Automation proxy
# secret to /etc/sentra-itam/infra-proxy-secret (640 root:sentra-itam, never printed) so IT Asset Management can call it on
# 127.0.0.1:9160. No device login is copied between the services. Backup first, syntax check, restart, live check; any
# failure restores the backup automatically.
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib-itam.sh"   # restart only when needed, wait until the API answers
APP=/opt/sentra-itam; SVC=sentra-itam; BK=/var/backups/sentra-itam-infra-sync
MAIN="$APP/engine/main.js"; MOD="$APP/engine/infra-sync.js"
LINE="  require('./infra-sync').registerInfraSync(srv, app); // IT Asset Management <-> Infrastructure Automation targets (engine/infra-sync.js)"
say() { echo "==> $*"; }; die() { echo "!! $*"; exit 1; }

if [ "${1:-}" = "--rollback" ]; then
  [ -f "$BK/main.js" ] || die "no backup in $BK"
  cp -p "$BK/main.js" "$MAIN"; if [ -f "$BK/infra-sync.js" ]; then cp -p "$BK/infra-sync.js" "$MOD"; else rm -f "$MOD"; fi
  itam_restart; say "restored the engine from before the Infrastructure Automation link was added ($(systemctl is-active "$SVC"))"; exit 0
fi

[ -f "$MAIN" ] || die "IT Asset Management is not installed here ($MAIN not found)"
SRC="$HERE/../engine/infra-sync.js"; [ -f "$SRC" ] || die "missing $SRC - copy the whole sentra-itam folder"
NODE="$(systemctl show -p ExecStart --value "$SVC" 2>/dev/null | sed -n 's/.*argv\[\]=\([^ ;]*\).*/\1/p' | head -n1)"
[ -x "${NODE:-}" ] || NODE=/opt/sentra-ai/node/bin/node; [ -x "$NODE" ] || NODE="$(command -v node || true)"
[ -x "${NODE:-}" ] || die "could not find the Node.js the service uses"

PRE_FP="$(itam_fp)"
say "backup -> $BK"
mkdir -p "$BK"; chmod 700 "$BK"
if grep -q "registerInfraSync" "$MAIN" && [ -f "$BK/main.js" ]; then echo "   (keeping the backup from before the first install)"
else cp -p "$MAIN" "$BK/main.js"; if [ -f "$MOD" ]; then cp -p "$MOD" "$BK/infra-sync.js"; else rm -f "$BK/infra-sync.js"; fi; fi
cp -p "$MAIN" "$BK/main.run.js"   # this run's main.js: a failure puts back exactly this, never the copy from before the first install (that one drops every route added since)
restore() { itam_on_restore "$1"; echo "!! $1 - restoring the previous engine"; cp -p "$BK/main.run.js" "$MAIN"; if [ -f "$BK/infra-sync.js" ]; then cp -p "$BK/infra-sync.js" "$MOD"; else rm -f "$MOD"; fi; itam_restart || true; echo "   $SVC: $(systemctl is-active "$SVC")"; exit 1; }

install -m 644 -o root -g root "$SRC" "$MOD"
if grep -q "registerInfraSync" "$MAIN"; then say "main.js already registers the Infrastructure Automation link"
else
  if grep -q "^ *registerDiscoveryRoutes(srv, app);" "$MAIN"; then ANCHOR="registerDiscoveryRoutes(srv, app);"
  elif grep -q "^ *registerRoutes(srv, app);" "$MAIN"; then ANCHOR="registerRoutes(srv, app);"
  else restore "could not find where routes are registered in $MAIN"; fi
  LINE="$LINE" ANCHOR="$ANCHOR" awk '{print} !done && index($0, ENVIRON["ANCHOR"]) && $0 ~ /^ *register/ {print ENVIRON["LINE"]; done=1}' "$MAIN" > "$MAIN.tmp" && cat "$MAIN.tmp" > "$MAIN" && rm -f "$MAIN.tmp"
  grep -q "registerInfraSync" "$MAIN" || restore "could not add the registration line"
  say "registered the Infrastructure Automation link in main.js"
fi
"$NODE" --check "$MAIN" && "$NODE" --check "$MOD" || restore "syntax check failed"

itam_restart_if_changed "$PRE_FP"
systemctl is-active --quiet "$SVC" || itam_start_failed restore

# the link: Infrastructure Automation's proxy secret, readable by the sentra-itam service only. /etc/sentra-itam belongs to the
# service account, so the file is created O_EXCL|O_NOFOLLOW under a random name, owned / moded through the descriptor,
# then renamed into place (a planted symlink is replaced, never followed).
INFRA_SEC=/etc/sentra-infra/secrets.json; OUT=/etc/sentra-itam/infra-proxy-secret
if [ -f "$INFRA_SEC" ]; then
  IGID="$(id -g "$SVC" 2>/dev/null || true)"
  if [ -z "$IGID" ]; then echo "   (service user $SVC not found - the Infrastructure Automation link is not set up)"
  elif "$NODE" -e 'const fs=require("fs"),cr=require("crypto"),path=require("path"),K=fs.constants;const [src,out,gid]=process.argv.slice(1);
const s=JSON.parse(fs.readFileSync(src,"utf8")).proxy_secret||"";if(String(s).length<16)process.exit(3);
const t=path.join(path.dirname(out),"."+path.basename(out)+"."+cr.randomBytes(8).toString("hex"));
const fd=fs.openSync(t,K.O_WRONLY|K.O_CREAT|K.O_EXCL|K.O_NOFOLLOW,0o600);
try{fs.fchownSync(fd,0,Number(gid));fs.fchmodSync(fd,0o640);fs.writeSync(fd,String(s)+"\n");fs.fsyncSync(fd)}finally{fs.closeSync(fd)}
fs.renameSync(t,out)' "$INFRA_SEC" "$OUT" "$IGID"; then say "Infrastructure Automation link -> $OUT (640 root:$SVC)"
  else echo "   (the Infrastructure Automation proxy secret is missing or too short in $INFRA_SEC - the page will say the link is not set up)"; fi
else echo "   (Infrastructure Automation is not installed on this server ($INFRA_SEC not found) - the sync waits until it is)"; fi

# live check: the route must exist (403 for a viewer); 404 means it was not registered. No data is changed.
CODE="$("$NODE" -e '
const fs=require("fs"),http=require("http");let c={},s={};
try{c=JSON.parse(fs.readFileSync("/etc/sentra-itam/config.json","utf8"))}catch(e){}
try{s=JSON.parse(fs.readFileSync("/etc/sentra-itam/secrets.json","utf8"))}catch(e){}
const a=c.api||{},port=a.port||9150,pre=a.prefix||"/api/itam";
const r=http.request({host:a.host||"127.0.0.1",port,method:"GET",path:pre+"/infra-sync",headers:{"Content-Type":"application/json","X-Sentra-Proxy-Secret":s.proxy_secret||"","X-Auth-User":"zyb-install-check","X-Auth-Role":"viewer"}},res=>{res.resume();console.log(res.statusCode)});
r.on("error",()=>console.log(0));r.setTimeout(5000,()=>{r.destroy()});r.end();' 2>/dev/null || echo 0)"
case "$CODE" in
  200|403) say "the Infrastructure Automation link is live";;
  401) say "the Infrastructure Automation link installed (the live check could not authenticate - open the portal to confirm)";;
  404) restore "the Infrastructure Automation link did not register";;
  *) say "installed; the live check returned '$CODE' - open the portal to confirm";;
esac
echo "   undo: sudo bash $0 --rollback"
