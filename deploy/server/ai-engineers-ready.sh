#!/bin/bash
# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
# ai-engineers-ready.sh (installed as zyb-ai-ready) — bring every AI engineer as far as the platform can on its own, then
# print exactly what is left for a person. Runs on the platform server (the platform server):   sudo zyb-ai-ready
#   1. engines: restarts sentra-itam / sentra-siem only if their code on disk is newer than the running process
#   2. syncs and collections that READ from the sources and feed the engineers (nothing is changed on any device, server,
#      database or cloud tenant; nothing is applied back to the inventory):
#        assets → AI Network / Security Engineer devices · assets → AI Windows / Exchange Administrators · assets →
#        Server Availability (AI Application Manager) · licence facts (fills empty fields only) · vCenter / Nutanix capacity
#        (AI Virtualization Administrator) · Oracle health (AI Oracle DBA) · SIEM log-source enrolment · Zscaler and Kaspersky
#        reads · then every duty desk patrols and the AI CISO re-scores
#   3. the readiness check of every engineer, and a short "only a person can do this" list
# Uses the engines' trusted local API (127.0.0.1 + proxy secret), so it works while the portal admin role is not wired.
set -uo pipefail
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
NODE="$(command -v node || true)"
[ -x "${NODE:-}" ] || NODE="$(systemctl show -p ExecStart --value sentra-itam 2>/dev/null | sed -n 's/.*argv\[\]=\([^ ;]*\).*/\1/p' | head -n1)"
[ -x "${NODE:-}" ] || { echo "node not found"; exit 1; }
OK=0; WARN=0; FAIL=0
ok()   { echo "   ✓ $*"; OK=$((OK+1)); }
warn() { echo "   • $*"; WARN=$((WARN+1)); }
bad()  { echo "   ✗ $*"; FAIL=$((FAIL+1)); }
step() { echo; echo "== $* =="; }

# ---- endpoints + secrets (never printed)
read -r SPORT SPFX SSEC < <("$NODE" -e '
const fs=require("fs");const rd=(p)=>{try{if(/secrets[^\/]*\.json$/.test(p))return require("/opt/sentra-siem/engine/secretfile").read(p)||{};return JSON.parse(fs.readFileSync(p,"utf8"))}catch(e){return {}}};
const c=rd("/etc/sentra-siem/config.json"),s=rd(c.secrets_path||"/etc/sentra-siem/secrets.json");
console.log(((c.api||{}).port||9120)+" "+((c.api_prefix||"/api/soc").replace(/\/+$/,""))+" "+(s.proxy_secret||"-"))')
read -r IPORT IPFX ISEC < <("$NODE" -e '
const fs=require("fs");const rd=(p)=>{try{if(/secrets[^\/]*\.json$/.test(p))return require("/opt/sentra-siem/engine/secretfile").read(p)||{};return JSON.parse(fs.readFileSync(p,"utf8"))}catch(e){return {}}};
const c=rd("/etc/sentra-itam/config.json"),s=rd("/etc/sentra-itam/secrets.json");
console.log(((c.api||{}).port||9150)+" "+(((c.api||{}).prefix)||"/api/itam").replace(/\/+$/,"")+" "+(s.proxy_secret||"-"))')
ADMIN="${SUDO_USER:-admin}"
# call siem|itam METHOD PATH [JSON] [timeout-s] → prints "<http code> <body>"
call() {
  local base sec
  if [ "$1" = siem ]; then base="http://127.0.0.1:$SPORT$SPFX"; sec="$SSEC"; else base="http://127.0.0.1:$IPORT$IPFX"; sec="$ISEC"; fi
  local body="${4:-}" t="${5:-120}" out code hdr
  hdr="$(mktemp)"; chmod 600 "$hdr"; printf 'X-Sentra-Proxy-Secret: %s\n' "$sec" > "$hdr"   # never on the curl command line
  [ "$2" != GET ] && [ -z "$body" ] && body='{}'
  out="$(mktemp)"
  if [ -n "$body" ]; then code="$(curl -s -m "$t" -o "$out" -w '%{http_code}' -X "$2" -H @"$hdr" -H "X-Auth-User: $ADMIN" -H "X-Auth-Role: admin" -H 'Content-Type: application/json' --data "$body" "$base$3")"
  else code="$(curl -s -m "$t" -o "$out" -w '%{http_code}' -X "$2" -H @"$hdr" -H "X-Auth-User: $ADMIN" -H "X-Auth-Role: admin" "$base$3")"; fi
  echo "$code $(head -c 20000 "$out")"; rm -f "$out" "$hdr"
}
# summarise a JSON answer with a small JS expression over `j`
sum() { "$NODE" -e 'let d="";process.stdin.on("data",c=>d+=c).on("end",()=>{let j={};try{j=JSON.parse(d)}catch(e){};try{process.stdout.write(String(eval(process.argv[1])))}catch(e){process.stdout.write("")}})' "$1"; }
run() {   # run LABEL siem|itam METHOD PATH JSON SUMMARY-EXPR [timeout]
  local label="$1" r code body
  r="$(call "$2" "$3" "$4" "$5" "${7:-120}")"; code="${r%% *}"; body="${r#* }"
  case "$code" in
    2??) ok "$label — $(printf '%s' "$body" | sum "$6")";;
    404) warn "$label — not installed on this server (run the update)";;
    403|401) bad "$label — refused ($code): check the proxy secret files";;
    000) bad "$label — no answer (engine down or timed out)";;
    *)   bad "$label — HTTP $code: $(printf '%s' "$body" | sum 'j.error||(j.errors||[]).join("; ")||""')";;
  esac
}

step "1/3 Engines"
for SVC in sentra-itam sentra-siem; do
  APPDIR=/opt/$SVC/engine; [ -d "$APPDIR" ] || { warn "$SVC is not installed here"; continue; }
  PID="$(systemctl show -p MainPID --value "$SVC" 2>/dev/null)"; UP="$(ps -o etimes= -p "$PID" 2>/dev/null | tr -d ' ')"
  if [ -z "$PID" ] || [ "$PID" = 0 ] || [ -z "$UP" ]; then systemctl restart "$SVC"; sleep 5; ok "$SVC was not running — started ($(systemctl is-active "$SVC"))"; continue; fi
  NEWER="$(find "$APPDIR" -name '*.js' -newermt "@$(( $(date +%s) - UP ))" -print 2>/dev/null | head -n 1)"
  if [ -n "$NEWER" ]; then systemctl restart "$SVC"; for i in $(seq 1 30); do systemctl is-active --quiet "$SVC" && break; sleep 2; done; ok "$SVC restarted to run the installed code ($(systemctl is-active "$SVC"))"
  else ok "$SVC is running the installed code"; fi
done
sleep 3

step "2/3 Feed the engineers (read-only syncs and collections)"
run "Assets → AI Network / Security Engineer devices"   itam POST /netops-sync/run       '' '(j.sent||j.added||[]).length!=null?((j.sent||j.added||[]).length+" sent, "+((j.pending||[]).length)+" pending"):"done"'
run "Assets → AI Windows / Exchange Administrators"     itam POST /sysadmin-sync/run     '' '(j.sent||j.added||[]).length!=null?((j.sent||j.added||[]).length+" sent, "+((j.pending||[]).length)+" pending"):"done"'
run "Assets → Server Availability (AI Application Mgr)" siem POST /netops/avail/import   '{"source":"inventory"}' '(j.eligible!=null?j.eligible+" servers/VMs ("+(j.added||0)+" added)":"done")' 180
run "Endpoint Central → AI Desktop Support Engineer"   itam POST /me/ec/sync             '' '(j.computers!=null? j.computers+" computers read"+(j.added?", "+j.added+" added to the inventory":""):(j.error||"done"))' 300
run "Desk support: ticket triage + automated patching"  itam POST /me/desk/scan           '' '"triage "+(j.mode||"off")+(j.triaged?" ("+j.triaged+" applied)":"")+(j.proposed?" ("+j.proposed+" proposed)":"")+" · patching "+((j.patch||{}).mode||"off")+((j.patch||{}).requested?", "+j.patch.requested+" requested":"")+((j.patch||{}).approved?", "+j.patch.approved+" auto-approved":"")+((j.patch||{}).skipped?" - "+j.patch.skipped:"")' 300
run "Licence facts from assets (empty fields only)"     itam POST /licence-sync/run      '' '"done"'
run "vCenter / Nutanix → AI Virtualization Admin"       itam POST /virt/capacity/run     '' '((j.results||[]).length? (j.results.map(r=>r.label+(r.ok?" ok ("+r.hosts+" hosts, "+r.vms+" VMs)":" FAILED: "+r.error)).join("; ")) : "no vCenter / Nutanix connected yet")' 600
run "Oracle health → AI Oracle DBA"                     itam POST /db-health/run         '' '(j.note? j.note : j.read+" database(s) read, "+j.sent+" records sent"+(j.failed?", "+j.failed+" failed":"")+(j.push_error?" — SIEM: "+j.push_error:""))' 600
run "SIEM log-source enrolment of assets"               itam POST /log-collection/auto/run '' '(j.enrolled? j.enrolled.length+" enrolled":"done")' 300
for kind in zscaler ksc; do
  if [ "$kind" = zscaler ]; then LIST=/zscaler/tenants; ONE=/zscaler/tenants; LBL="Zscaler"; else LIST=/ksc/servers; ONE=/ksc/servers; LBL="Kaspersky KSC"; fi
  r="$(call siem GET "$LIST")"; code="${r%% *}"; body="${r#* }"
  if [ "$code" = 404 ]; then warn "$LBL — not installed on this server (run the update)"; continue; fi
  IDS="$(printf '%s' "$body" | sum '(j.items||[]).map(x=>x.id).join(" ")')"
  [ -n "$IDS" ] || { warn "$LBL — no connection added yet"; continue; }
  for id in $IDS; do run "$LBL read: $id" siem POST "$ONE/$id/sync" '' '((j.errors||[]).length? "read with problems: "+j.errors.join("; ") : "read OK")' 180; done
done
run "Duty desks patrol — SIEM engineers"                siem POST /duty/patrol           '{}' '(j.results||[]).map(r=>r.engineer+(r.not_connected?" (not connected)":" "+(r.opened||0)+" new")).join(", ")' 600
run "Duty desks patrol — IT Asset engineers"            itam POST /duty/patrol           '{}' '(j.results||[]).map(r=>r.engineer+(r.not_connected?" (not connected)":" "+(r.opened||0)+" new")).join(", ")' 600
run "AI CISO re-scores the posture"                     itam POST /ciso/patrol           '{}' '"done"' 300

step "3/3 Readiness of every AI engineer"
HERE="$(cd "$(dirname "$0")" && pwd)"
if command -v zyb-ai-readiness >/dev/null 2>&1; then READY_OUT="$(zyb-ai-readiness 2>&1)"; elif [ -f "$HERE/ai-readiness.sh" ]; then READY_OUT="$(bash "$HERE/ai-readiness.sh" 2>&1)"; else READY_OUT="readiness check not installed"; fi
echo "$READY_OUT"

step "Only a person can do these"
PY=/opt/sentra-siem/pyenv/bin/python3
# the newest update folder (there can be several ~/sentra-update-* folders: a bare * would match them all)
UPD="$(ls -td /home/*/sentra-update-*/ /root/sentra-update-*/ 2>/dev/null | head -n1)"; UPD="${UPD%/}"; [ -n "$UPD" ] || UPD="<newest sentra-update folder>"
if [ -x "$PY" ]; then MISS="$("$PY" -c 'import importlib.util as u;print(" ".join(m for m in ["oracledb","pypsrp","netmiko","pymysql","pg8000","pytds","paramiko"] if not u.find_spec(m)))' 2>/dev/null)"
  [ -n "$MISS" ] && echo "  • Python drivers missing ($MISS): sudo bash $UPD/sentra-siem/install/netops-cli-setup.sh"
else echo "  • Python environment for read-only logins missing: sudo bash $UPD/sentra-siem/install/netops-cli-setup.sh"; fi
/usr/local/sbin/sentra-siem-secrets get netops.anthropic_api_key >/dev/null 2>&1 || echo "  • AI analysis is off (no Anthropic key). Once the organisation approves sending device/server data: sudo bash $UPD/sentra-siem/install/netops-setup.sh --set-key --restart"
grep -q '"anthropic_api_key"' /etc/sentra-itam/secrets.json 2>/dev/null || echo "  • Claude for the AI Virtualization Administrator is off (no key). Once approved: sudo zyb-virt-ai --allow-external, then sudo zyb-virt-ai --set-key (or --from-siem to reuse the SIEM's key)"
echo "$READY_OUT" | awk '/fix: /{sub(/^[ \t]*fix: /,"");print "  • "$0}' | sort -u
WHO_NGX="$(nginx -T 2>/dev/null | grep -c 'ZYB-WHOAMI2' || true)"
[ "${WHO_NGX:-0}" -gt 0 ] || echo "  • Admin buttons hidden on the dashboards (whoami.json gives an empty role): re-run the update - add-dashboards-nginx.sh fixes it. Meanwhile: sudo zyb-configure-zscaler · sudo zyb-configure-kaspersky · sudo zyb-configure-virtualization"
echo
echo "== done: $OK ok, $WARN to note, $FAIL failed =="
[ "$FAIL" -eq 0 ]
