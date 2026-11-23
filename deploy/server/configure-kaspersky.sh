#!/bin/bash
# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
# configure-kaspersky.sh — add / configure a Kaspersky Security Center (KSC) connection for the AI Endpoint Protection
# Engineer, through the SIEM's trusted local API (127.0.0.1 + proxy secret). Works even when the portal admin role is not
# yet wired, because it does not go through the browser session. READ-ONLY: a KSC read-only account; nothing on KSC is
# changed. Run on the SIEM host (the platform server):   sudo bash configure-kaspersky.sh
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
jbuild() { "$NODE" -e "$1"; }   # builds JSON from env vars so secrets never land in argv / shell history

echo "=============================================================="
echo " Configure a Kaspersky Security Center connection (read-only)"
echo "=============================================================="
read -r -p "Connection id (lowercase, e.g. ksc-ruh): " ID
read -r -p "Label [KSC]: " LABEL; LABEL="${LABEL:-KSC}"
read -r -p "KSC host (e.g. ksc.corp.local): " KHOST
read -r -p "OpenAPI port [13299]: " KPORT; KPORT="${KPORT:-13299}"
read -r -p "Read-only KSC user: " KUSER
read -r -p "Internal KSC user (not a domain account)? [Y/n]: " INT; case "$INT" in n|N) INTERNAL=false;; *) INTERNAL=true;; esac
read -r -p "Databases counted out of date after how many days [3]: " DBD; DBD="${DBD:-3}"
read -r -s -p "KSC account password: " KPW; echo
read -r -p "KSC certificate SHA-256 fingerprint to pin (optional, Enter to skip): " KFP

[ -n "$ID" ] && [ -n "$KHOST" ] && [ -n "$KUSER" ] || { echo "id, host and user are required"; exit 1; }

echo "==> adding the server…"
SRV="$(ID="$ID" LABEL="$LABEL" KHOST="$KHOST" KPORT="$KPORT" KUSER="$KUSER" INTERNAL="$INTERNAL" DBD="$DBD" \
  jbuild 'const e=process.env;process.stdout.write(JSON.stringify({id:e.ID,label:e.LABEL,host:e.KHOST,port:+e.KPORT,user:e.KUSER,internal:e.INTERNAL==="true",dbStaleDays:+e.DBD}))')"
RESP="$(api -X POST "$BASE/ksc/servers" -d "$SRV")"
echo "    $RESP"
echo "$RESP" | grep -q '"error"' && { echo "!! could not add the server (see the message above)"; exit 1; }

echo "==> saving the password (write-only)…"
KPW="$KPW" KFP="$KFP" jbuild 'const e=process.env;process.stdout.write(JSON.stringify(e.KFP?{password:e.KPW,fingerprint256:e.KFP}:{password:e.KPW}))' \
  | api -X PUT "$BASE/ksc/servers/$ID/credentials" --data-binary @- >/dev/null && echo "    saved"

echo "==> testing (live read-only probe of KSC)…"
TEST="$(api -X POST "$BASE/ksc/servers/$ID/test")"
echo "    $TEST"
if echo "$TEST" | grep -q '"ok":true'; then
  echo
  echo "✓ Connected. The AI Endpoint Protection Engineer will now patrol KSC."
  echo "  Open the portal → AI & Automation → AI Endpoint (Kaspersky) to see posture and work items."
else
  echo
  echo "✗ Not connected yet — the message above says why (account rights, OpenAPI not enabled on $KPORT, or reachability)."
  echo "  Fix it and re-run, or re-test with:  (see configure-kaspersky.sh header)"
fi
