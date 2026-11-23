#!/bin/bash
# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
# link-itam.sh - let the SIEM read IT Asset Management (asset inventory + discovery results) on this server.
#   sudo bash link-itam.sh            set up / repair (safe to re-run)
# Used by Server Availability (servers and VMs from the inventory are monitored automatically) and "Import from
# discovery". Copies the ITAM proxy secret to /etc/sentra-siem/itam-proxy-secret (640 root:sentra-siem) and sets
# config.onboard.discovery in /etc/sentra-siem/config.json (backup first). The secret is never printed. Read-only access:
# the SIEM calls ITAM as "viewer" for the inventory. Restart sentra-siem afterwards (update-server.sh does).
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
SIEM_CFG=/etc/sentra-siem/config.json; ITAM_CFG=/etc/sentra-itam/config.json; ITAM_SEC=/etc/sentra-itam/secrets.json
OUT=/etc/sentra-siem/itam-proxy-secret
say() { echo "==> $*"; }; die() { echo "!! $*"; exit 1; }
[ -f "$ITAM_SEC" ] || { say "IT Asset Management is not installed here - nothing to link"; exit 0; }
[ -f "$SIEM_CFG" ] || die "$SIEM_CFG not found"
NODE="$(systemctl show -p ExecStart --value sentra-siem 2>/dev/null | sed -n 's/.*argv\[\]=\([^ ;]*\).*/\1/p' | head -n1)"
[ -x "${NODE:-}" ] || NODE=/opt/sentra-ai/node/bin/node; [ -x "$NODE" ] || NODE="$(command -v node || true)"
[ -x "${NODE:-}" ] || die "could not find Node.js"

umask 077
# /etc/sentra-siem belongs to the service account, so nothing in it is trusted by root: new files are created with
# O_EXCL|O_NOFOLLOW under a random name, owned/moded through the open descriptor, then renamed into place (a rename
# replaces a planted symlink instead of following it).
SGID="$(id -g sentra-siem)" || die "user sentra-siem not found"
"$NODE" -e 'const fs=require("fs"),cr=require("crypto"),path=require("path"),K=fs.constants;const [src,out,gid]=process.argv.slice(1);
const s=JSON.parse(fs.readFileSync(src,"utf8")).proxy_secret||"";if(String(s).length<16){process.exit(3)}
const t=path.join(path.dirname(out),"."+path.basename(out)+"."+cr.randomBytes(8).toString("hex"));
const fd=fs.openSync(t,K.O_WRONLY|K.O_CREAT|K.O_EXCL|K.O_NOFOLLOW,0o600);
try{fs.fchownSync(fd,0,Number(gid));fs.fchmodSync(fd,0o640);fs.writeSync(fd,String(s)+"\n");fs.fsyncSync(fd)}finally{fs.closeSync(fd)}
fs.renameSync(t,out)' "$ITAM_SEC" "$OUT" "$SGID" || die "the ITAM proxy secret is missing or too short in $ITAM_SEC"
say "ITAM proxy secret -> $OUT (640 root:sentra-siem)"

# backup: refuse a symlinked config; the copy is a new root-only file (O_EXCL|O_NOFOLLOW), never a write through a link
"$NODE" -e 'const fs=require("fs"),cr=require("crypto"),K=fs.constants;const f=process.argv[1];
if(!fs.lstatSync(f).isFile()){console.error("!! "+f+" is not a regular file (symlink?) - refusing");process.exit(4)}
const b=f+".bak-link-itam-"+new Date().toISOString().replace(/\D/g,"").slice(0,14)+"-"+cr.randomBytes(3).toString("hex");
const fd=fs.openSync(b,K.O_WRONLY|K.O_CREAT|K.O_EXCL|K.O_NOFOLLOW,0o600);try{fs.writeSync(fd,fs.readFileSync(f))}finally{fs.closeSync(fd)}' "$SIEM_CFG" || die "could not back up $SIEM_CFG"
RES="$("$NODE" -e '
const fs=require("fs");const [sc,ic,sf]=process.argv.slice(1);
let itam={};try{itam=JSON.parse(fs.readFileSync(ic,"utf8"))}catch(e){}
const a=itam.api||{},port=a.port||9150,pre=(a.prefix||"/api/itam").replace(/\/+$/,"");
const c=JSON.parse(fs.readFileSync(sc,"utf8"));c.onboard=c.onboard||{};
const d={base_url:"http://"+(a.host&&a.host!=="0.0.0.0"?a.host:"127.0.0.1")+":"+port,prefix:pre+"/discovery",secret_file:sf,timeout_ms:20000};
const before=JSON.stringify(c.onboard.discovery||null);c.onboard.discovery=Object.assign({},c.onboard.discovery||{},d);
const K=fs.constants,fd=fs.openSync(sc,K.O_WRONLY|K.O_TRUNC|K.O_NOFOLLOW);try{fs.writeSync(fd,JSON.stringify(c,null,2)+"\n")}finally{fs.closeSync(fd)}  /* in place (keeps the owner and mode the SIEM needs); O_NOFOLLOW: never through a symlink */
console.log((before===JSON.stringify(c.onboard.discovery)?"unchanged ":"set ")+d.base_url+pre);' "$SIEM_CFG" "$ITAM_CFG" "$OUT")"
say "SIEM config onboard.discovery: $RES"

# live check: the inventory answers with the copied secret (viewer, read only)
CODE="$("$NODE" -e '
const fs=require("fs"),http=require("http");const c=JSON.parse(fs.readFileSync(process.argv[1],"utf8")).onboard.discovery;
const u=new URL(c.base_url);const s=fs.readFileSync(c.secret_file,"utf8").trim();
const r=http.request({host:u.hostname,port:u.port,path:c.prefix.replace(/\/discovery$/,"")+"/assets?limit=1",headers:{"X-Sentra-Proxy-Secret":s,"X-Auth-User":"system:sentra-siem","X-Auth-Role":"viewer"}},res=>{let b="";res.on("data",d=>b+=d);res.on("end",()=>{let t="";try{t=JSON.parse(b).total}catch(e){}console.log(res.statusCode+" "+t)})});
r.on("error",e=>console.log("0 "+e.code));r.setTimeout(8000,()=>r.destroy());r.end();' "$SIEM_CFG" 2>/dev/null || echo "0 error")"
case "$CODE" in
  200*) say "IT Asset Management answers: ${CODE#200 } assets in the inventory";;
  401*|403*) die "IT Asset Management refused the secret (HTTP ${CODE%% *}) - check $ITAM_SEC";;
  *) die "IT Asset Management is not reachable ($CODE) - is sentra-itam running? (systemctl status sentra-itam)";;
esac
echo "   restart the SIEM to use it: sudo systemctl restart sentra-siem"
