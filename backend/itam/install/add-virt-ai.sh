#!/bin/bash
# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
# add-virt-ai.sh (sudo zyb-virt-ai) - turn on Claude for the IT Asset Management AI engineers: the AI Virtualization
#   Administrator (engine/virt-ai.js) and, through the model provider (engine/ai/anthropic.js), the AI GRC Consultant, the
#   AI CISO brief and the asset classification jobs. All installed by add-duty.sh. Nothing here touches vCenter or Prism: Claude only reads what the capacity collection already holds and
#   can only RECORD change plans for four-eyes approval.
#   sudo bash add-virt-ai.sh                   check: SDK, key, permission, proxy - and say what is missing
#   sudo bash add-virt-ai.sh --set-key         type the Anthropic API key (hidden) -> /etc/sentra-itam/secrets.json
#   sudo bash add-virt-ai.sh --from-siem       reuse the key already stored for the SIEM (netops.anthropic_api_key)
#   sudo bash add-virt-ai.sh --allow-external  record that sending virtualization inventory (VM / host / datastore names
#                                              and figures) to Anthropic is approved - asks for a typed confirmation
# The key is never printed, never passed on a command line, and never needs to be sent in chat or e-mail.
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
SVC=sentra-itam; ETC=/etc/sentra-itam; SEC="$ETC/secrets.json"; HERE="$(cd "$(dirname "$0")" && pwd)"
SETKEY=0; FROMSIEM=0; ALLOW=0
while [ $# -gt 0 ]; do case "$1" in --set-key) SETKEY=1;; --from-siem) FROMSIEM=1;; --allow-external) ALLOW=1;; *) echo "unknown option $1"; exit 1;; esac; shift; done
NODE="$(systemctl show -p ExecStart --value "$SVC" 2>/dev/null | sed -n 's/.*argv\[\]=\([^ ;]*\).*/\1/p' | head -n1)"
[ -x "${NODE:-}" ] || NODE=/opt/sentra-ai/node/bin/node; [ -x "$NODE" ] || NODE="$(command -v node || true)"
[ -x "${NODE:-}" ] || { echo "could not find the Node.js the service uses"; exit 1; }
say() { echo "==> $*"; }
[ -f "$SEC" ] || { echo "$SEC not found - IT Asset Management is not installed here"; exit 1; }

# store the key SEALED in secrets.json (AES-256-GCM under the vault master key - engine/secret-values.js): the value goes
# on stdin (never argv / environment), symlinks refused, owner and mode kept, no plaintext backup copy
store_key() {
  local T="$HERE/itam-secrets.js"; [ -f "$T" ] || T=/opt/sentra-itam/install/itam-secrets.js
  printf '%s' "$1" | "$NODE" "$T" set anthropic_api_key || { echo "!! could not store the key sealed - nothing was written in clear"; exit 1; }
}
# the service must still be able to read the file afterwards (root:sentra-itam 640, as install.sh creates it)
check_read() {
  if ! runuser -u "$SVC" -- test -r "$SEC"; then
    chown root:"$SVC" "$SEC"; chmod 640 "$SEC"
    runuser -u "$SVC" -- test -r "$SEC" && echo "==> repaired $SEC permissions (root:$SVC 640) so $SVC can read it" || { echo "!! $SVC cannot read $SEC - check: ls -l $SEC"; exit 1; }
  fi
}
check_read   # also repairs a file an earlier version of this script left at 600
if [ "$SETKEY" = 1 ]; then
  read -r -s -p "Anthropic API key (input hidden): " KEY; echo
  case "$KEY" in sk-ant-*) ;; *) echo "that does not look like an Anthropic API key (sk-ant-...)"; exit 1;; esac
  store_key "$KEY"; unset KEY; check_read; say "API key stored in $SEC (anthropic_api_key) - the engine picks it up without a restart"
fi
if [ "$FROMSIEM" = 1 ]; then
  KEY="$("$NODE" -e 'try{const s=require("/opt/sentra-siem/engine/secretfile").read("/etc/sentra-siem/secrets.json")||{};process.stdout.write(String((s.netops||{}).anthropic_api_key||""))}catch(e){}')"   # the SIEM file is sealed at rest
  [ -n "$KEY" ] || { echo "no key in /etc/sentra-siem/secrets.json - use --set-key"; exit 1; }
  store_key "$KEY"; unset KEY; check_read; say "copied the SIEM's Anthropic key into $SEC"
fi

# local trusted call to the ITAM API (proxy secret, as an administrator named after the sudo user)
itam() {   # itam METHOD PATH [JSON]
  M="$1" P="$2" B="${3:-}" U="${SUDO_USER:-root}" "$NODE" -e '
const fs=require("fs"),http=require("http");let c={},s={};
try{c=JSON.parse(fs.readFileSync("/etc/sentra-itam/config.json","utf8"))}catch(e){}
try{s=JSON.parse(fs.readFileSync("/etc/sentra-itam/secrets.json","utf8"))}catch(e){}
const a=c.api||{},E=process.env,h={"X-Sentra-Proxy-Secret":s.proxy_secret||"","X-Auth-User":E.U,"X-Auth-Role":"admin"};if(E.B)h["Content-Type"]="application/json";
const r=http.request({host:a.host||"127.0.0.1",port:a.port||9150,method:E.M,path:(a.prefix||"/api/itam")+E.P,headers:h},res=>{let d="";res.on("data",x=>d+=x).on("end",()=>console.log(res.statusCode+" "+d))});
r.on("error",()=>console.log("0 "));r.setTimeout(20000,()=>r.destroy());if(E.B)r.write(E.B);r.end();'
}
if [ "$ALLOW" = 1 ]; then
  echo "Claude will receive: virtualization inventory (VM, host, cluster, datastore names, capacity, snapshot ages), the GRC"
  echo "records (policy register, control results, framework coverage, DR drills, open gaps; sanitised with the redaction"
  echo "terms in ITAM settings) and the duty desk's findings. No passwords or keys are sent. This is data processing by Anthropic outside the platform"
  echo "(PDPL / SAMA outsourcing). Only continue if the organisation has approved it."
  read -r -p "Type YES to allow: " OKAY
  [ "$OKAY" = YES ] || { echo "not changed"; exit 1; }
  R="$(itam POST /settings '{"external_ai_allowed":true}')"
  case "${R%% *}" in 200) say "external AI allowed in IT Asset Management settings (recorded in the audit trail as ${SUDO_USER:-root})";; *) echo "could not change the setting: $R"; exit 1;; esac
fi

# SDK: the SIEM's pinned bundle (netops-setup.sh installs it root-owned and world-readable on every update)
if runuser -u "$SVC" -- "$NODE" -e "require('/opt/sentra-siem/vendor/node_modules/@anthropic-ai/sdk')" 2>/dev/null; then say "Anthropic SDK loads for the $SVC user"
else echo "!! the Anthropic SDK does not load for $SVC - run: sudo bash $(ls -td ~/sentra-update-*/ | head -n1)sentra-siem/install/netops-setup.sh"; fi
# outbound proxy: reuse the SIEM's if this engine has none
if grep -q '^HTTPS_PROXY=' /etc/default/sentra-siem 2>/dev/null && ! grep -q '^HTTPS_PROXY=' /etc/default/sentra-itam 2>/dev/null; then
  touch /etc/default/sentra-itam; chmod 640 /etc/default/sentra-itam
  grep -E '^(HTTPS_PROXY|NODE_USE_ENV_PROXY|NO_PROXY)=' /etc/default/sentra-siem >> /etc/default/sentra-itam
  systemctl reset-failed "$SVC" 2>/dev/null || true; systemctl restart "$SVC"; sleep 5
  say "copied the SIEM's outbound proxy to /etc/default/sentra-itam and restarted $SVC"
fi

R="$(itam GET /virt/ai/status)"; CODE="${R%% *}"; BODY="${R#* }"
case "$CODE" in
  200) "$NODE" -e 'const j=JSON.parse(process.argv[1]);console.log(j.enabled?"==> AI Virtualization Administrator: Claude analysis ON ("+j.model+"). Open the page → a work item → Investigate with AI, or Ask.":"!! Claude analysis is OFF: "+j.reason)' "$BODY";;
  404) echo "!! /virt/ai is not served - run the update (add-duty.sh installs engine/virt-ai.js) and try again";;
  *)   echo "!! status check returned $CODE";;
esac
R="$(itam GET /duty/readiness)"; [ "${R%% *}" = 200 ] && "$NODE" -e 'const j=JSON.parse(process.argv[1]);for(const id of ["grc","ciso"]){const e=(j.engineers||[]).find(x=>x.id===id);if(!e)continue;const c=e.checks.find(x=>/^AI (answers|brief)$/.test(x.name));if(c)console.log((c.ok===false?"!! ":"==> ")+e.name+": "+(c.detail||""))}' "${R#* }"
