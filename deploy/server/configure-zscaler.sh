#!/bin/bash
# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
# configure-zscaler.sh — add / configure a Zscaler (ZIA + optional ZPA) connection for the AI Security Engineer — Zscaler,
# through the SIEM's trusted local API (127.0.0.1 + proxy secret). Works even when the portal admin role is not yet wired.
# READ-ONLY: ZIA API key + admin login / ZPA client; nothing on Zscaler is changed. Run on the SIEM host (the platform server):
#   sudo bash configure-zscaler.sh
set -uo pipefail
[ "$(id -u)" = 0 ] || { echo "run with sudo (it needs to read the SIEM proxy secret)"; exit 1; }
CFG=/etc/sentra-siem/config.json
[ -f "$CFG" ] || { echo "SIEM config not found ($CFG) — is sentra-siem installed on this host?"; exit 1; }
NODE="$(command -v node || true)"; [ -x "${NODE:-}" ] || NODE="$(systemctl show -p ExecStart --value sentra-siem 2>/dev/null | sed -n 's/.*argv\[\]=\([^ ;]*\).*/\1/p' | head -n1)"
[ -x "${NODE:-}" ] || { echo "node not found"; exit 1; }
SECF="$("$NODE" -e 'process.stdout.write((require("/etc/sentra-siem/config.json").secrets_path)||"/etc/sentra-siem/secrets.json")')"
SEC="$("$NODE" -e 'try{process.stdout.write((require("/opt/sentra-siem/engine/secretfile").read(process.argv[1])||{}).proxy_secret||"")}catch(e){}' "$SECF")"
[ -n "$SEC" ] || { echo "could not read the proxy secret from $SECF"; exit 1; }
read -r PORT PFX < <("$NODE" -e 'const c=require("/etc/sentra-siem/config.json");console.log(((c.api||{}).port||9120)+" "+((c.api_prefix||"/api/soc").replace(/\/+$/,"")))')
BASE="http://127.0.0.1:$PORT$PFX"; ADMIN="${SUDO_USER:-admin}"
# the proxy secret goes to curl in a 0600 header file, never on the command line (ps shows every argument)
HDR="$(mktemp)"; chmod 600 "$HDR"; trap 'rm -f "$HDR"' EXIT; printf 'X-Sentra-Proxy-Secret: %s\n' "$SEC" > "$HDR"
api() { curl -s -H @"$HDR" -H "X-Auth-User: $ADMIN" -H "X-Auth-Role: admin" -H "Content-Type: application/json" "$@"; }
jbuild() { "$NODE" -e "$1"; }

echo "=============================================================="
echo " Configure a Zscaler connection (read-only: ZIA + optional ZPA)"
echo "=============================================================="
read -r -p "Connection id (lowercase, e.g. sentra): " ID
read -r -p "Label [Zscaler]: " LABEL; LABEL="${LABEL:-Zscaler}"
read -r -p "ZIA cloud host (e.g. zsapi.zscalertwo.net): " ZC
read -r -p "ZIA admin username (e.g. admin@domain): " ZU
read -r -s -p "ZIA API key: " ZKEY; echo
read -r -s -p "ZIA admin password: " ZPW; echo
read -r -p "Also configure ZPA? [y/N]: " WANTZPA

[ -n "$ID" ] && [ -n "$ZC" ] && [ -n "$ZU" ] || { echo "id, ZIA cloud and username are required"; exit 1; }

ZPA_JSON='{}'; ZPASEC='{}'; HAVE_ZPA=false
if [[ "$WANTZPA" =~ ^[Yy]$ ]]; then
  read -r -p "ZPA base URL [https://config.private.zscaler.com]: " ZB; ZB="${ZB:-https://config.private.zscaler.com}"
  read -r -p "ZPA customer id: " ZCUST
  read -r -p "ZPA client id: " ZCID
  read -r -s -p "ZPA client secret: " ZCS; echo
  HAVE_ZPA=true
  ZPA_JSON="$(ZB="$ZB" ZCUST="$ZCUST" ZCID="$ZCID" jbuild 'const e=process.env;process.stdout.write(JSON.stringify({enabled:true,base_url:e.ZB,customerId:e.ZCUST,clientId:e.ZCID}))')"
fi

echo "==> adding the tenant…"
TEN="$(ID="$ID" LABEL="$LABEL" ZC="$ZC" ZU="$ZU" ZPA_JSON="$ZPA_JSON" HAVE_ZPA="$HAVE_ZPA" \
  jbuild 'const e=process.env;const t={id:e.ID,label:e.LABEL,zia:{enabled:true,cloud:e.ZC,username:e.ZU}};if(e.HAVE_ZPA==="true")t.zpa=JSON.parse(e.ZPA_JSON);process.stdout.write(JSON.stringify(t))')"
RESP="$(api -X POST "$BASE/zscaler/tenants" -d "$TEN")"
echo "    $RESP"
echo "$RESP" | grep -q '"error"' && { echo "!! could not add the tenant (see the message above)"; exit 1; }

echo "==> saving the credentials (write-only)…"
CREDS="$(ZKEY="$ZKEY" ZPW="$ZPW" ZCS="${ZCS:-}" HAVE_ZPA="$HAVE_ZPA" \
  jbuild 'const e=process.env;const c={zia:{apiKey:e.ZKEY,password:e.ZPW}};if(e.HAVE_ZPA==="true"&&e.ZCS)c.zpa={clientSecret:e.ZCS};process.stdout.write(JSON.stringify(c))')"
echo "$CREDS" | api -X PUT "$BASE/zscaler/tenants/$ID/credentials" --data-binary @- >/dev/null && echo "    saved"

echo "==> testing (live read-only login)…"
TEST="$(api -X POST "$BASE/zscaler/tenants/$ID/test")"
echo "    $TEST"
if echo "$TEST" | grep -q '"ok":true'; then
  echo; echo "✓ Connected. The AI Security Engineer — Zscaler will now patrol the tenant."
  echo "  Open the portal → AI & Automation → AI Zscaler Engineer to see posture and work items."
else
  echo; echo "✗ Not connected yet — the message above says why (credentials, API access not enabled, or reachability to the Zscaler cloud)."
fi
