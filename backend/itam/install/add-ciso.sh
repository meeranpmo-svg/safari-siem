#!/bin/bash
# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
# add-ciso.sh - AI CISO (engine/ciso.js): one executive view over GRC, SAMA CSF, DR drills, SOC metrics, response
#   approvals and the 8 AI engineers - an itemised posture score, a risk register, the decisions waiting for a person,
#   "run every engineer now", and an AI board brief that may cite only the platform's own records (rule-based when no
#   AI is configured). It reads; it never executes a change. The SIEM side is read over the existing discovery.siem link.
#   Needs the GRC module (add-grc.sh); the duty desk (add-duty.sh) is used when present.
#   sudo bash add-ciso.sh              install / update (safe to re-run)
#   sudo bash add-ciso.sh --rollback   put back the engine from before the first install
# Copies the module, adds one registration line to engine/main.js. Backup first, syntax check, restart, then a live
# check that the route answers; any failure restores the backup automatically.
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib-itam.sh"
APP=/opt/sentra-itam; SVC=sentra-itam; BK=/var/backups/sentra-itam-ciso
MAIN="$APP/engine/main.js"; MOD="$APP/engine/ciso.js"
LINE="  require('./ciso').registerCiso(srv, app); // AI CISO: posture, risks, decisions, board brief (engine/ciso.js)"
say() { echo "==> $*"; }; die() { echo "!! $*"; exit 1; }

if [ "${1:-}" = "--rollback" ]; then
  [ -f "$BK/main.js" ] || die "no backup in $BK"
  cp -p "$BK/main.js" "$MAIN"; if [ -f "$BK/ciso.js" ]; then cp -p "$BK/ciso.js" "$MOD"; else rm -f "$MOD"; fi
  itam_restart; say "restored the engine from before the AI CISO was added ($(systemctl is-active "$SVC"))"; exit 0
fi

[ -f "$MAIN" ] || die "IT Asset Management is not installed here ($MAIN not found)"
SRC="$HERE/../engine/ciso.js"
[ -f "$APP/engine/grc.js" ] || die "install the GRC module first (add-grc.sh)"
[ -f "$APP/engine/ai/sanitise.js" ] && [ -f "$APP/engine/ai/validate.js" ] || die "this IT Asset Management engine is too old (engine/ai/sanitise.js missing) - update it first"
[ -f "$SRC" ] || die "missing $SRC - copy the whole sentra-itam folder"
NODE="$(systemctl show -p ExecStart --value "$SVC" 2>/dev/null | sed -n 's/.*argv\[\]=\([^ ;]*\).*/\1/p' | head -n1)"
[ -x "${NODE:-}" ] || NODE=/opt/sentra-ai/node/bin/node; [ -x "$NODE" ] || NODE="$(command -v node || true)"
[ -x "${NODE:-}" ] || die "could not find the Node.js the service uses"

PRE_FP="$(itam_fp)"
say "backup -> $BK"
mkdir -p "$BK"; chmod 700 "$BK"
if grep -q "registerCiso" "$MAIN" && [ -f "$BK/main.js" ]; then echo "   (keeping the backup from before the first install)"
else cp -p "$MAIN" "$BK/main.js"; if [ -f "$MOD" ]; then cp -p "$MOD" "$BK/ciso.js"; else rm -f "$BK/ciso.js"; fi; fi
cp -p "$MAIN" "$BK/main.run.js"   # this run's main.js: a failure puts back exactly this, never the copy from before the first install (that one drops every route added since)
restore() { itam_on_restore "$1"; echo "!! $1 - restoring the previous engine"; cp -p "$BK/main.run.js" "$MAIN"; if [ -f "$BK/ciso.js" ]; then cp -p "$BK/ciso.js" "$MOD"; else rm -f "$MOD"; fi; itam_restart || true; echo "   $SVC: $(systemctl is-active "$SVC")"; exit 1; }

install -m 644 -o root -g root "$SRC" "$MOD"
# the AI masking compared with Python (step 9j-a): engine/ai/guard-py.js and the bridge; without them sanitise.js answers alone
[ -f "$HERE/../engine/ai/guard-py.js" ] && install -D -m 644 -o root -g root "$HERE/../engine/ai/guard-py.js" "$APP/engine/ai/guard-py.js"
[ -f "$HERE/../engine/pyengine.js" ] && install -m 644 -o root -g root "$HERE/../engine/pyengine.js" "$APP/engine/pyengine.js"
if [ -d "$HERE/../pyengine" ]; then install -d -m 755 -o root -g root "$APP/pyengine"; for f in "$HERE"/../pyengine/*.py; do install -m 644 -o root -g root "$f" "$APP/pyengine/"; done; rm -rf "$APP/pyengine/__pycache__"; fi
if grep -q "registerCiso" "$MAIN"; then say "main.js already registers the AI CISO"
else
  if grep -q "^ *require('\./duty')\.registerDuty(srv, app);" "$MAIN"; then ANCHOR="registerDuty(srv, app);"
  elif grep -q "^ *require('\./grc')\.registerGrc(srv, app);" "$MAIN"; then ANCHOR="registerGrc(srv, app);"
  elif grep -q "^ *require('\./pentest')\.registerPentest(srv, app);" "$MAIN"; then ANCHOR="registerPentest(srv, app);"
  elif grep -q "^ *registerDiscoveryRoutes(srv, app);" "$MAIN"; then ANCHOR="registerDiscoveryRoutes(srv, app);"
  elif grep -q "^ *registerRoutes(srv, app);" "$MAIN"; then ANCHOR="registerRoutes(srv, app);"
  else restore "could not find where routes are registered in $MAIN"; fi
  LINE="$LINE" ANCHOR="$ANCHOR" awk '{print} !done && index($0, ENVIRON["ANCHOR"]) && $0 ~ /^ *(require|register)/ {print ENVIRON["LINE"]; done=1}' "$MAIN" > "$MAIN.tmp" && cat "$MAIN.tmp" > "$MAIN" && rm -f "$MAIN.tmp"
  grep -q "registerCiso" "$MAIN" || restore "could not add the registration line"
  say "registered the AI CISO in main.js"
fi
"$NODE" --check "$MAIN" && "$NODE" --check "$MOD" || restore "syntax check failed"

itam_restart_if_changed "$PRE_FP"
systemctl is-active --quiet "$SVC" || itam_start_failed restore

# live check: /ciso/briefs is readable by a viewer (200). 404 means it was not registered. No data is changed.
CODE="$("$NODE" -e '
const fs=require("fs"),http=require("http");let c={},s={};
try{c=JSON.parse(fs.readFileSync("/etc/sentra-itam/config.json","utf8"))}catch(e){}
try{s=JSON.parse(fs.readFileSync("/etc/sentra-itam/secrets.json","utf8"))}catch(e){}
const a=c.api||{},port=a.port||9150,pre=a.prefix||"/api/itam";
const r=http.request({host:a.host||"127.0.0.1",port,method:"GET",path:pre+"/ciso/briefs",headers:{"Content-Type":"application/json","X-Sentra-Proxy-Secret":s.proxy_secret||"","X-Auth-User":"zyb-install-check","X-Auth-Role":"viewer"}},res=>{res.resume();console.log(res.statusCode)});
r.on("error",()=>console.log(0));r.setTimeout(5000,()=>{r.destroy()});r.end();' 2>/dev/null || echo 0)"
case "$CODE" in
  200) say "AI CISO is live: Dashboards -> AI & Automation -> AI CISO";;
  401) say "AI CISO installed (the live check could not authenticate - open the portal to confirm)";;
  404) restore "the AI CISO did not register";;
  *) say "installed; the live check returned '$CODE' - open the portal to confirm";;
esac
# operational report: which of the 8 sources answer right now (the SIEM side goes over discovery.siem)
"$NODE" -e '
const fs=require("fs"),http=require("http");let c={},s={};
try{c=JSON.parse(fs.readFileSync("/etc/sentra-itam/config.json","utf8"))}catch(e){}
try{s=JSON.parse(fs.readFileSync("/etc/sentra-itam/secrets.json","utf8"))}catch(e){}
const a=c.api||{},port=a.port||9150,pre=a.prefix||"/api/itam";
const get=(p)=>new Promise((ok)=>{const r=http.request({host:a.host||"127.0.0.1",port,method:"GET",path:pre+p,headers:{"X-Sentra-Proxy-Secret":s.proxy_secret||"","X-Auth-User":"zyb-install-check","X-Auth-Role":"viewer"}},res=>{let b="";res.on("data",d=>b+=d);res.on("end",()=>{try{ok(JSON.parse(b))}catch(e){ok(null)}})});r.on("error",()=>ok(null));r.setTimeout(60000,()=>r.destroy());r.end();});
(async()=>{const v=await get("/ciso/overview?refresh=1"),st=await get("/ciso/status");
 if(!v||!v.sources){console.log("   operational check: no answer yet - open the page in a minute");return;}
 const live=v.sources.filter(x=>x.state==="live").length;
 console.log("==> AI CISO data sources: "+live+" of "+v.sources.length+" live");
 for(const x of v.sources)console.log("   "+(x.state==="live"?"[live]         ":x.state==="not_connected"?"[not connected]":"[error]        ")+" "+x.name+(x.error?" - "+x.error:""));
 console.log("   posture: "+(v.posture.overall==null?"withheld ("+v.posture.withheld_why+")":v.posture.overall+"/100 ("+v.posture.grade+")")+" · risks "+v.risks_total+" · decisions waiting "+v.decisions.length);
 if(st)console.log("   runs on its own: "+(st.running?"yes - board brief every working morning at "+String(st.brief_hour).padStart(2,"0")+":00 Riyadh":"no (ciso.enabled=false)"));
 if(v.sources.some(x=>["siem_duty","soc","sama","approvals"].includes(x.id)&&x.state!=="live"))console.log("   SIEM sources not live: check discovery.siem (base_url, secret_file) in /etc/sentra-itam/config.json - the same link Server Availability uses");
})();' 2>/dev/null || true
echo "   undo: sudo bash $0 --rollback"
