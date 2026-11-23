#!/bin/bash
# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
# configure-virtualization.sh — add / configure a VMware vCenter or Nutanix Prism connection for the AI Virtualization
# Administrator, through IT Asset Management's trusted local API (127.0.0.1 + proxy secret). Works even when the portal
# admin role is not yet wired. READ-ONLY account; nothing on vCenter/Prism is changed. Handles the self-signed
# certificate (shows its SHA-256 and lets you trust/pin it). Run on the host (the platform server):
#   sudo bash configure-virtualization.sh
set -uo pipefail
[ "$(id -u)" = 0 ] || { echo "run with sudo (it needs to read the IT Asset Management proxy secret)"; exit 1; }
CFG=/etc/sentra-itam/config.json
[ -f "$CFG" ] || { echo "IT Asset Management config not found ($CFG) — is sentra-itam installed on this host?"; exit 1; }
NODE="$(command -v node || true)"; [ -x "${NODE:-}" ] || NODE="$(systemctl show -p ExecStart --value sentra-itam 2>/dev/null | sed -n 's/.*argv\[\]=\([^ ;]*\).*/\1/p' | head -n1)"
[ -x "${NODE:-}" ] || { echo "node not found"; exit 1; }
SECF=/etc/sentra-itam/secrets.json
SEC="$("$NODE" -e 'try{process.stdout.write((require("/opt/sentra-siem/engine/secretfile").read(process.argv[1])||{}).proxy_secret||"")}catch(e){}' "$SECF")"
[ -n "$SEC" ] || { echo "could not read the proxy secret from $SECF"; exit 1; }
read -r PORT PFX < <("$NODE" -e 'const c=require("/etc/sentra-itam/config.json");console.log(((c.api||{}).port||9150)+" "+(((c.api||{}).prefix)||"/api/itam").replace(/\/+$/,""))')
BASE="http://127.0.0.1:$PORT$PFX"; ADMIN="${SUDO_USER:-admin}"
# the proxy secret goes to curl in a 0600 header file, never on the command line (ps shows every argument)
HDR="$(mktemp)"; chmod 600 "$HDR"; trap 'rm -f "$HDR"' EXIT; printf 'X-Sentra-Proxy-Secret: %s\n' "$SEC" > "$HDR"
api() { curl -s -H @"$HDR" -H "X-Auth-User: $ADMIN" -H "X-Auth-Role: admin" -H "Content-Type: application/json" "$@"; }
jget() { "$NODE" -e 'let d="";process.stdin.on("data",c=>d+=c).on("end",()=>{let j={};try{j=JSON.parse(d)}catch(e){};let v=j;for(const k of process.argv[1].split("."))v=v&&v[k];process.stdout.write(v==null?"":String(v))})' "$1"; }

echo "================================================================"
echo " Configure a virtualization platform (VMware vCenter / Nutanix)"
echo "================================================================"
read -r -p "Kind [vcenter/nutanix] (default vcenter): " KIND; KIND="${KIND:-vcenter}"
case "$KIND" in vcenter|nutanix) ;; *) echo "kind must be vcenter or nutanix"; exit 1;; esac
read -r -p "Label (e.g. VC-RUH): " LABEL
read -r -p "Address https://<host or IP>[:port] (e.g. https://vcenter.corp.local): " URL
read -r -p "Site (optional): " SITE
read -r -p "Read-only username (e.g. svc-ro@vsphere.local): " VUSER
read -r -s -p "Password: " VPW; echo
read -r -p "Collect every N minutes [60]: " INT; INT="${INT:-60}"

[ -n "$URL" ] && [ -n "$VUSER" ] || { echo "address and username are required"; exit 1; }
case "$URL" in https://*) ;; *) echo "the address must start with https://"; exit 1;; esac

echo "==> adding the platform…"
BODY="$(KIND="$KIND" LABEL="$LABEL" URL="$URL" SITE="$SITE" VUSER="$VUSER" VPW="$VPW" INT="$INT" \
  "$NODE" -e 'const e=process.env;process.stdout.write(JSON.stringify({kind:e.KIND,label:e.LABEL,base_url:e.URL,site:e.SITE,username:e.VUSER,password:e.VPW,interval_min:+e.INT}))')"
RESP="$(printf '%s' "$BODY" | api -X POST "$BASE/virt" --data-binary @-)"
ID="$(printf '%s' "$RESP" | jget platform.id)"
[ -n "$ID" ] || { echo "!! could not add the platform: $RESP"; exit 1; }
echo "    added as $ID"

run_test() { api -X POST "$BASE/virt/$ID/test"; }
echo "==> testing the connection…"
T="$(run_test)"; OK="$(printf '%s' "$T" | jget result.ok)"
if [ "$OK" != "true" ]; then
  FP="$(printf '%s' "$T" | jget platform.presented.fingerprint256)"
  MSG="$(printf '%s' "$T" | jget result.message)"
  if [ -n "$FP" ]; then
    echo "    the server presented a certificate that is not yet trusted:"
    echo "      SHA-256: $FP"
    [ -n "$MSG" ] && echo "      ($MSG)"
    read -r -p "    Trust and pin THIS certificate? [y/N]: " YN
    if [[ "$YN" =~ ^[Yy]$ ]]; then
      printf '{"fingerprint":"%s"}' "$FP" | api -X POST "$BASE/virt/$ID/pin" --data-binary @- >/dev/null
      echo "    pinned — re-testing…"; T="$(run_test)"; OK="$(printf '%s' "$T" | jget result.ok)"
    fi
  fi
fi

if [ "$OK" = "true" ]; then
  echo "==> connection OK — running the first collection…"
  S="$(api -X POST "$BASE/virt/$ID/sync")"
  H="$(printf '%s' "$S" | jget sync.hosts)"; V="$(printf '%s' "$S" | jget sync.vms)"; C="$(printf '%s' "$S" | jget sync.clusters)"
  echo "    hosts: ${H:-?}   VMs: ${V:-?}   clusters: ${C:-?}"
  echo
  echo "✓ The AI Virtualization Administrator is now operational."
  echo "  Portal → AI & Automation → AI Virtualization Admin  (and Servers & Data → Virtualization)."
else
  echo
  echo "✗ Not connected: $(printf '%s' "$T" | jget result.message)"
  echo "  Check the address, that the account can read the inventory (Read-only / Observer role), and reachability from this host."
fi
