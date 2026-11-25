#!/bin/bash
# Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
# link-siem.sh - let IT Asset Management call the SIEM on this server (the other direction of sentra-siem/install/link-itam.sh).
#   sudo bash link-siem.sh            set up / repair (safe to re-run)
# Without it every IT Asset Management feature that reads the SIEM (SharePoint, Connect to SIEM, the CISO / duty sources, the
# bridge) answers "SIEM connection not configured (discovery.siem.secret_file)". What it does:
#   1. reads the SIEM proxy secret (sealed secrets.json, through sentra-siem-secrets; an older plaintext file is read as JSON)
#      and writes it to /etc/sentra-itam/siem-proxy-secret (640 root:sentra-itam) - the secret is never printed
#   2. sets discovery.siem.{base_url, prefix, secret_file} in /etc/sentra-itam/config.json (backup first, other keys kept)
#   3. checks the SIEM accepts it (a 401 means it was refused), then restarts sentra-itam so the setting is used
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
ITAM_CFG=/etc/sentra-itam/config.json; SIEM_CFG=/etc/sentra-siem/config.json; SIEM_SEC=/etc/sentra-siem/secrets.json
OUT=/etc/sentra-itam/siem-proxy-secret
say() { echo "==> $*"; }; die() { echo "!! $*"; exit 1; }
[ -d /etc/sentra-itam ] || { say "IT Asset Management is not installed here - nothing to link"; exit 0; }
[ -f "$SIEM_SEC" ] || { say "the SIEM is not installed here - nothing to link"; exit 0; }
[ -f "$ITAM_CFG" ] || die "$ITAM_CFG not found"
[ -L "$ITAM_CFG" ] && die "$ITAM_CFG is a symbolic link - refusing"
getent group sentra-itam >/dev/null || die "group sentra-itam not found"
NODE="$(systemctl show -p ExecStart --value sentra-itam 2>/dev/null | sed -n 's/.*argv\[\]=\([^ ;]*\).*/\1/p' | head -n1)"
[ -x "${NODE:-}" ] || NODE=/opt/sentra-ai/node/bin/node; [ -x "$NODE" ] || NODE="$(command -v node || true)"
[ -x "${NODE:-}" ] || die "could not find Node.js"
umask 077

# 1. the secret: sealed (the normal case) through the SIEM's own reader, else a plaintext secrets.json from an older version
SECRET=""
if [ -x /usr/local/sbin/sentra-siem-secrets ]; then SECRET="$(/usr/local/sbin/sentra-siem-secrets get proxy_secret 2>/dev/null || true)"; fi
if [ -z "$SECRET" ] && ! grep -q '"_sealed"' "$SIEM_SEC"; then
  SECRET="$("$NODE" -e 'try{process.stdout.write(String(JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")).proxy_secret||""))}catch(e){/* unreadable: empty, reported below */}' "$SIEM_SEC")"
fi
[ "${#SECRET}" -ge 16 ] || die "could not read the SIEM proxy secret (sealed secrets.json: run sudo bash /opt/sentra-siem/install/secure-secrets.sh first)"
# written under a random name with O_EXCL|O_NOFOLLOW, owned / moded through the descriptor, then renamed into place
printf '%s' "$SECRET" | "$NODE" -e 'const fs=require("fs"),cr=require("crypto"),path=require("path"),K=fs.constants;const [out,gid]=process.argv.slice(1);
const s=fs.readFileSync(0,"utf8");const t=path.join(path.dirname(out),"."+path.basename(out)+"."+cr.randomBytes(8).toString("hex"));
const fd=fs.openSync(t,K.O_WRONLY|K.O_CREAT|K.O_EXCL|K.O_NOFOLLOW,0o600);
try{fs.fchownSync(fd,0,Number(gid));fs.fchmodSync(fd,0o640);fs.writeSync(fd,s+"\n");fs.fsyncSync(fd)}finally{fs.closeSync(fd)}
fs.renameSync(t,out)' "$OUT" "$(getent group sentra-itam | cut -d: -f3)"
unset SECRET
say "SIEM proxy secret -> $OUT (640 root:sentra-itam)"

# 2. the setting (backup first; written in place so the owner and mode stay what the ITAM service needs)
cp -p "$ITAM_CFG" "$ITAM_CFG.bak-link-siem-$(date +%Y%m%d%H%M%S)"
RES="$("$NODE" -e '
const fs=require("fs"),K=fs.constants;const [ic,sc,sf]=process.argv.slice(1);
let s={};try{s=JSON.parse(fs.readFileSync(sc,"utf8"))}catch(e){/* SIEM config unreadable: the defaults (127.0.0.1:9120) */}
const a=s.api||{},port=a.port||9120,host=a.host&&a.host!=="0.0.0.0"?a.host:"127.0.0.1";
const c=JSON.parse(fs.readFileSync(ic,"utf8"));c.discovery=c.discovery||{};const before=JSON.stringify(c.discovery.siem||null);
c.discovery.siem=Object.assign({},c.discovery.siem||{},{base_url:"http://"+host+":"+port,prefix:(c.discovery.siem&&c.discovery.siem.prefix)||"/api/soc",secret_file:sf});
const fd=fs.openSync(ic,K.O_WRONLY|K.O_TRUNC|K.O_NOFOLLOW);try{fs.writeSync(fd,JSON.stringify(c,null,2)+"\n")}finally{fs.closeSync(fd)}
console.log((before===JSON.stringify(c.discovery.siem)?"unchanged ":"set ")+c.discovery.siem.base_url+c.discovery.siem.prefix);' "$ITAM_CFG" "$SIEM_CFG" "$OUT")"
say "IT Asset Management config discovery.siem: $RES"

# 3. the SIEM accepts the secret (viewer, read only); 401 = refused
CODE="$("$NODE" -e '
const fs=require("fs"),http=require("http");const c=JSON.parse(fs.readFileSync(process.argv[1],"utf8")).discovery.siem;const u=new URL(c.base_url);
const r=http.request({host:u.hostname,port:u.port,path:c.prefix+"/onboard/sources",headers:{"X-Sentra-Proxy-Secret":fs.readFileSync(c.secret_file,"utf8").trim(),"X-Auth-User":"system:sentra-itam","X-Auth-Role":"viewer"}},res=>{res.resume();console.log(res.statusCode)});
r.on("error",e=>console.log("0 "+e.code));r.setTimeout(8000,()=>r.destroy());r.end();' "$ITAM_CFG" 2>/dev/null || echo "0 error")"
case "$CODE" in
  401*) die "the SIEM refused the secret (HTTP 401) - the SIEM's secrets changed? re-run after: sudo bash /opt/sentra-siem/install/secure-secrets.sh";;
  0*) echo "!! the SIEM is not answering now ($CODE) - the link is set; check: systemctl status sentra-siem";;
  *) say "the SIEM accepts IT Asset Management (HTTP ${CODE})";;
esac
if systemctl is-active --quiet sentra-itam; then systemctl restart sentra-itam && say "sentra-itam restarted (uses the SIEM link)"; fi
