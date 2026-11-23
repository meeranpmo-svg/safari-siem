#!/bin/bash
# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
# add-duty.sh - AI engineers' duty desk for the AI Penetration Testing Engineer, the AI Desktop Support Engineer and the
#   AI GRC Consultant (engine/grc-consultant.js: compliance gaps as work items, the roadmap and "ask the consultant") and the
#   AI Virtualization Administrator (engine/virt-admin.js: vCenter / Prism health, change plans for approval)
#   (engine/duty.js + engine/duty-core.js, shared with the SIEM). They patrol, open work items, investigate and follow
#   fixes to a verified result. Nothing is executed by the duty desk: a pentest is never started (engagements keep
#   their two-administrator authorisation) and a patch install is only REQUESTED - a different person approves it.
#   Needs the pentest and desk support modules (add-pentest.sh, add-desksupport.sh) installed first.
#   sudo bash add-duty.sh              install / update (safe to re-run)
#   sudo bash add-duty.sh --rollback   put back the engine from before the first install
# Also installs the AI auditors, the audit checklist, the AI PDPL Consultant and the AI PKI Engineer (engine/auditors.js,
#   audit-checklist.js, audit-engage.js, pdpl.js, pdpl-consent.js, pdpl-workflows.js, mail-reputation.js, libraesva.js, servers.js, certs.js; their rules are pyengine/pdpl_rules.py and cert_rules.py, copied with the other
#   Python modules).
# Copies the modules, adds one registration line to engine/main.js. Backup first, syntax check, restart, then a live
# check that the route answers; any failure restores the backup automatically.
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib-itam.sh"
APP=/opt/sentra-itam; SVC=sentra-itam; BK=/var/backups/sentra-itam-duty
MAIN="$APP/engine/main.js"; MOD="$APP/engine/duty.js"; DATA="$APP/engine/duty-core.js"; GCM="$APP/engine/grc-consultant.js"; VAM="$APP/engine/virt-admin.js"; VAI="$APP/engine/virt-ai.js"; AIP="$APP/engine/ai/provider.js"; AIA="$APP/engine/ai/anthropic.js"
LINE="  require('./duty').registerDuty(srv, app); // AI engineers' duty desk: pentest + desktop support (engine/duty.js)"
say() { echo "==> $*"; }; die() { echo "!! $*"; if type itam_report >/dev/null 2>&1; then itam_report duty failed "$("${NODE:-node}" -e 'process.stdout.write(JSON.stringify({note:String(process.argv[1]).slice(0,300)}))' "$*" 2>/dev/null || echo '{}')"; fi; exit 1; }   # a stop is recorded too (Update Health, the summary)
# set -e stops the installer at the first failing command - silently, so the update summary said only "itam-duty" (bug): name it
set -E; trap 'die "add-duty stopped at line $LINENO (exit $?): $BASH_COMMAND"' ERR

if [ "${1:-}" = "--rollback" ]; then
  [ -f "$BK/main.js" ] || die "no backup in $BK"
  cp -p "$BK/main.js" "$MAIN"; if [ -f "$BK/duty.js" ]; then cp -p "$BK/duty.js" "$MOD"; else rm -f "$MOD"; fi
  if [ -f "$BK/duty-core.js" ]; then cp -p "$BK/duty-core.js" "$DATA"; else rm -f "$DATA"; fi
  if [ -f "$BK/grc-consultant.js" ]; then cp -p "$BK/grc-consultant.js" "$GCM"; fi
  if [ -f "$BK/virt-admin.js" ]; then cp -p "$BK/virt-admin.js" "$VAM"; fi
  if [ -f "$BK/virt-ai.js" ]; then cp -p "$BK/virt-ai.js" "$VAI"; fi
  if [ -f "$BK/ai-provider.js" ]; then cp -p "$BK/ai-provider.js" "$AIP"; rm -f "$AIA"; fi
  itam_restart; say "restored the engine from before the duty desk was added ($(systemctl is-active "$SVC"))"; exit 0
fi

[ -f "$MAIN" ] || die "IT Asset Management is not installed here ($MAIN not found)"
SRC="$HERE/../engine/duty.js"; SRCD="$HERE/../engine/duty-core.js"; SRCG="$HERE/../engine/grc-consultant.js"; SRCV="$HERE/../engine/virt-admin.js"
[ -f "$APP/engine/pentest.js" ] || die "install the penetration testing module first (add-pentest.sh)"
[ -f "$APP/engine/desksupport.js" ] || die "install the desk support module first (add-desksupport.sh)"
[ -f "$SRC" ] || die "missing $SRC - copy the whole sentra-itam folder"
[ -f "$SRCD" ] || die "missing $SRCD - copy the whole sentra-itam folder"
[ -f "$SRCG" ] || die "missing $SRCG - copy the whole sentra-itam folder"
[ -f "$SRCV" ] || die "missing $SRCV - copy the whole sentra-itam folder"
NODE="$(systemctl show -p ExecStart --value "$SVC" 2>/dev/null | sed -n 's/.*argv\[\]=\([^ ;]*\).*/\1/p' | head -n1)"
[ -x "${NODE:-}" ] || NODE=/opt/sentra-ai/node/bin/node; [ -x "$NODE" ] || NODE="$(command -v node || true)"
[ -x "${NODE:-}" ] || die "could not find the Node.js the service uses"

PRE_FP="$(itam_fp)"
say "backup -> $BK"
mkdir -p "$BK"; chmod 700 "$BK"
if grep -q "registerDuty" "$MAIN" && [ -f "$BK/main.js" ]; then echo "   (keeping the backup from before the first install)"
else cp -p "$MAIN" "$BK/main.js"; if [ -f "$MOD" ]; then cp -p "$MOD" "$BK/duty.js"; else rm -f "$BK/duty.js"; fi; if [ -f "$DATA" ]; then cp -p "$DATA" "$BK/duty-core.js"; else rm -f "$BK/duty-core.js"; fi; fi
cp -p "$MAIN" "$BK/main.run.js"   # this run's main.js: a failure puts back exactly this, never the copy from before the first install (that one drops every route added since)
restore() { itam_on_restore "$1"; echo "!! $1 - restoring the previous engine"; for d in ${DEPS_UPDATED:-}; do [ -f "$BK/run-$d.js" ] && cp -p "$BK/run-$d.js" "$APP/engine/$d.js"; done; if [ -f "$BK/ai-provider.js" ]; then cp -p "$BK/ai-provider.js" "$AIP"; [ -f "$BK/ai-anthropic.js" ] && cp -p "$BK/ai-anthropic.js" "$AIA" || rm -f "$AIA"; fi; if [ -f "$BK/virt-ai.js" ]; then cp -p "$BK/virt-ai.js" "$VAI"; fi; if [ -f "$BK/grc-consultant.js" ]; then cp -p "$BK/grc-consultant.js" "$GCM"; fi; if [ -f "$BK/virt-admin.js" ]; then cp -p "$BK/virt-admin.js" "$VAM"; fi; cp -p "$BK/main.run.js" "$MAIN"; if [ -f "$BK/duty.js" ]; then cp -p "$BK/duty.js" "$MOD"; else rm -f "$MOD"; fi; if [ -f "$BK/duty-core.js" ]; then cp -p "$BK/duty-core.js" "$DATA"; else rm -f "$DATA"; fi; itam_restart || true; echo "   $SVC: $(systemctl is-active "$SVC")"; exit 1; }

install -m 644 -o root -g root "$SRC" "$MOD"
# the AI masking compared with Python (step 9j-a): engine/ai/guard-py.js and the bridge; without them sanitise.js answers alone
[ -f "$HERE/../engine/ai/guard-py.js" ] && install -D -m 644 -o root -g root "$HERE/../engine/ai/guard-py.js" "$APP/engine/ai/guard-py.js"
[ -f "$HERE/../engine/pyengine.js" ] && install -m 644 -o root -g root "$HERE/../engine/pyengine.js" "$APP/engine/pyengine.js"
if [ -d "$HERE/../pyengine" ]; then install -d -m 755 -o root -g root "$APP/pyengine"; for f in "$HERE"/../pyengine/*.py; do install -m 644 -o root -g root "$f" "$APP/pyengine/"; done; rm -rf "$APP/pyengine/__pycache__"; fi
install -m 644 -o root -g root "$SRCD" "$DATA"
# the duty rules in Python (step 7, docs/PYTHON-MIGRATION.md) - identical to the SIEM's; without it duty-core.js answers in Node.js
[ -f "$HERE/../engine/duty_rules.py" ] && install -m 644 -o root -g root "$HERE/../engine/duty_rules.py" "$APP/engine/duty_rules.py"
# the virtualization change-plan reads in Python (step 8e): the bridge and the modules; without them virt-admin.js answers
[ -f "$HERE/../engine/pyengine.js" ] && install -m 644 -o root -g root "$HERE/../engine/pyengine.js" "$APP/engine/pyengine.js"
if [ -d "$HERE/../pyengine" ]; then install -d -m 755 -o root -g root "$APP/pyengine"; for f in "$HERE"/../pyengine/*.py; do install -m 644 -o root -g root "$f" "$APP/pyengine/"; done; rm -rf "$APP/pyengine/__pycache__"; fi
install -m 644 -o root -g root "$SRCG" "$GCM"
# the AI auditors, the audit checklist and the AI PDPL Consultant (duty.js loads them; without them it leaves them out)
# the Exchange Online runner script (engine/exo.js runs it under PowerShell 7; add-exo-runtime.sh installs the module)
if [ -f "$HERE/../engine/exo/exo-run.ps1" ]; then install -d -m 755 -o root -g root "$APP/engine/exo"; install -m 644 -o root -g root "$HERE/../engine/exo/exo-run.ps1" "$APP/engine/exo/exo-run.ps1"; fi
if [ -f "$HERE/../engine/exo/spo-run.ps1" ]; then install -d -m 755 -o root -g root "$APP/engine/exo"; install -m 644 -o root -g root "$HERE/../engine/exo/spo-run.ps1" "$APP/engine/exo/spo-run.ps1"; fi
# every module duty.js loads with optional('./x') is installed too - read from duty.js itself, so a new module cannot be left
# off this list (that happened: CMDB Studio, Scope Studio, Compliance Assistant, SQL DBA and the database inventory were
# never copied, optional() skipped them and their pages said "not installed" after every update)
OPT="$( { grep -o "optional('\./[a-z0-9-]*')" "$SRC" || true; } | sed "s/optional('\.\/\(.*\)')/\1/" | sort -u | tr '\n' ' ')"
OPT="$OPT $( { grep -o "^ *\['\./[a-z0-9-]*'," "$SRC" || true; } | sed "s/^ *\['\.\/\([a-z0-9-]*\)',/\1/" | sort -u | tr '\n' ' ')"   # INTEL_MODULES entries
for m in $OPT; do
  F="$HERE/../engine/$m.js"; [ -f "$F" ] || F="$HERE/../engine-all/$m.js"
  [ -f "$F" ] && { [ -f "$APP/engine/$m.js" ] && [ ! -f "$BK/$m.js" ] && cp -p "$APP/engine/$m.js" "$BK/$m.js"; install -m 644 -o root -g root "$F" "$APP/engine/$m.js"; }
done
echo "==> duty modules installed: $OPT"
for m in virt-net-read auditors audit-checklist pdpl pdpl-consent pdpl-workflows pdpl-access pdpl-intake pdpl-vendor pdpl-catalog pdpl-ropa pdpl-office pdpl-notify smtp db-targets pdpl-assessment ndmo nca-ecc iso27001 audit-engage audit-ccm audit-analytics audit-analytics-lib audit-auto vuln-dashboard mobile-test iso-lifecycle nca-ecc-intel roadmap risk-assess intel-kit controls-intel maturity-intel netcfg-intel raci-intel nca-itaudit-intel ndmo-intel pdpl-studio-intel risk-command cert-autopilot fwlib-intel aigov-intel bcm-intel overview-intel contcomp-intel validation-intel custody-intel docs-intel sama-ia sama-audit appsec apppt crosswalk grc-dashboard grc-register ia-resilience pdpl-intel dept-checklist gmp vulnscan audit-dashboard onboarding onboarding-ad m365-licensing ad-writer ad-directory sso-groups identity-advisor ipam offboarding exo mdm movers access-reviews pam cert-autodiscover nhi mail-reputation mail-doctor libraesva servers app-route hardening exchange-evidence db-health certs cert-issue cert-install cert-estate csr acme adcs infra-overview audit-verify approve-scopes check errors; do
  # the package's engine/ holds only hand-picked files; every engine file is in engine-all/ (the intel-kit pages - Maturity,
  # Framework Library, Network Config Audit, ... - were only there, so they were never installed and answered 404)
  F="$HERE/../engine/$m.js"; [ -f "$F" ] || F="$HERE/../engine-all/$m.js"
  [ -f "$F" ] && { [ -f "$APP/engine/$m.js" ] && [ ! -f "$BK/$m.js" ] && cp -p "$APP/engine/$m.js" "$BK/$m.js"; install -m 644 -o root -g root "$F" "$APP/engine/$m.js"; }
done
# every engine file an installed module require()s ('./x') is installed too, followed until nothing new is needed. Bug fixed:
# xlsx-read.js was required by audit-analytics.js and audit-repo.js but on no list, so on the server both failed to load and
# the update reported itam-duty. A dependency the package does not have is named, never skipped silently.
# Bug fixed: a dependency already on the server was never updated - Business Risk ran on the old xlsx-read.js (no sheet / header
# choice), so importing the risk register said 'the sheet has no "Risk Code" column', and the intel kit kept its old tool loop.
# A dependency that differs from the package's copy is replaced; this run's copy is kept as $BK/run-<name>.js and put back on failure.
DEPS_UPDATED=""
# Core files are never replaced here: main.js (every add-on adds its line to it), and every file a patch in patches/ changes or
# core-known.txt lists - the core upgrade (update-discovery.sh core_upgrade) owns them and leaves a file changed on the server alone.
# Bug fixed: the dependency update above replaced those too (http.js, routes.js, findings.js, monitoring-membership.js, as main.js
# requires them), so the update reported itam-pages. A core file an earlier run replaced, still the package's copy, is put back.
# Bug fixed: under set -euo pipefail a grep that matched nothing (no patch file, no engine line, no core-known.txt) failed this
# whole line and stopped the installer - the update's "itam-duty" with no reason (until the ERR trap named line 102).
PROTECT=" main $( { grep -h '^+++ ' "$HERE"/patches/*.patch 2>/dev/null || true; } | { grep -o 'engine/[a-z0-9-]*\.js' || true; } | sed 's#engine/##;s#\.js$##' | sort -u | tr '\n' ' ')$( if [ -f "$HERE/core-known.txt" ]; then { grep -v '^#' "$HERE/core-known.txt" || true; } | awk '{print $2}' | { grep -o '^engine/[a-z0-9-]*\.js$' || true; } | sed 's#engine/##;s#\.js$##' | sort -u | tr '\n' ' '; fi)"
for d in $PROTECT; do
  [ -f "$BK/run-$d.js" ] && [ -f "$APP/engine/$d.js" ] || continue
  S="$HERE/../engine/$d.js"; [ -f "$S" ] || S="$HERE/../engine-all/$d.js"
  if [ -f "$S" ] && cmp -s "$S" "$APP/engine/$d.js"; then cp -p "$BK/run-$d.js" "$APP/engine/$d.js"; echo "   ~ $d.js: the server's own copy is put back (an earlier update replaced this core file)"
    [ -z "${NODE:-}" ] || "$NODE" --check "$APP/engine/$d.js" || restore "syntax check failed ($d.js)"; fi
  mv -f "$BK/run-$d.js" "$BK/run-$d.js.restored"
done
for pass in 1 2 3 4 5 6; do
  NEW=0
  for f in "$APP"/engine/*.js; do
    for d in $(grep -o "require('\./[a-z0-9-]*')" "$f" | sed "s/require('\.\/\(.*\)')/\1/" | sort -u); do
      if [ -d "$APP/engine/$d" ] && [ ! -f "$APP/engine/$d.js" ]; then continue; fi   # a directory module (discovery/index.js) has its own installer
      S="$HERE/../engine/$d.js"; [ -f "$S" ] || S="$HERE/../engine-all/$d.js"
      if [ -f "$APP/engine/$d.js" ]; then
        case "$PROTECT " in *" $d "*) continue;; esac   # a core file: core_upgrade's, never replaced here
        if [ -f "$S" ] && ! cmp -s "$S" "$APP/engine/$d.js"; then
          case " $DEPS_UPDATED " in *" $d "*) ;; *) cp -p "$APP/engine/$d.js" "$BK/run-$d.js"; DEPS_UPDATED="$DEPS_UPDATED $d";; esac
          install -m 644 -o root -g root "$S" "$APP/engine/$d.js"; echo "   ~ $d.js updated (needed by $(basename "$f"))"; NEW=1
          [ -z "${NODE:-}" ] || "$NODE" --check "$APP/engine/$d.js" || restore "syntax check failed ($d.js)"
        fi
        continue
      fi
      if [ -f "$S" ]; then install -m 644 -o root -g root "$S" "$APP/engine/$d.js"; echo "   + $d.js (needed by $(basename "$f"))"; NEW=1
        [ -z "${NODE:-}" ] || "$NODE" --check "$APP/engine/$d.js" || restore "syntax check failed ($d.js)"
      else echo "   !! $(basename "$f") needs $d.js, which this package does not have"; fi
    done
  done
  [ "$NEW" = 1 ] || break
done
install -m 644 -o root -g root "$SRCV" "$VAM"
# Claude analysis for the virtualization administrator (optional; stays off until add-virt-ai.sh) - keep the copy it replaces
SRCA="$HERE/../engine/virt-ai.js"
if [ -f "$SRCA" ]; then if [ -f "$VAI" ] && [ ! -f "$BK/virt-ai.js" ]; then cp -p "$VAI" "$BK/virt-ai.js"; fi; install -m 644 -o root -g root "$SRCA" "$VAI"; fi
# direct Claude for the IT Asset Management model provider (GRC consultant, AI CISO brief, classification): engine/ai/
SRCP="$HERE/../engine/ai/provider.js"; SRCN="$HERE/../engine/ai/anthropic.js"
if [ -f "$SRCP" ] && [ -f "$SRCN" ] && [ -d "$APP/engine/ai" ]; then
  if [ -f "$AIP" ] && [ ! -f "$BK/ai-provider.js" ]; then cp -p "$AIP" "$BK/ai-provider.js"; [ -f "$AIA" ] && cp -p "$AIA" "$BK/ai-anthropic.js"; fi
  install -m 644 -o root -g root "$SRCN" "$AIA"; install -m 644 -o root -g root "$SRCP" "$AIP"
fi
if grep -q "registerDuty" "$MAIN"; then say "main.js already registers the duty desk"
else
  if grep -q "^ *require('\./grc')\.registerGrc(srv, app);" "$MAIN"; then ANCHOR="registerGrc(srv, app);"
  elif grep -q "^ *require('\./pentest')\.registerPentest(srv, app);" "$MAIN"; then ANCHOR="registerPentest(srv, app);"
  elif grep -q "^ *registerDiscoveryRoutes(srv, app);" "$MAIN"; then ANCHOR="registerDiscoveryRoutes(srv, app);"
  elif grep -q "^ *registerRoutes(srv, app);" "$MAIN"; then ANCHOR="registerRoutes(srv, app);"
  else restore "could not find where routes are registered in $MAIN"; fi
  LINE="$LINE" ANCHOR="$ANCHOR" awk '{print} !done && index($0, ENVIRON["ANCHOR"]) && $0 ~ /^ *(require|register)/ {print ENVIRON["LINE"]; done=1}' "$MAIN" > "$MAIN.tmp" && cat "$MAIN.tmp" > "$MAIN" && rm -f "$MAIN.tmp"
  grep -q "registerDuty" "$MAIN" || restore "could not add the registration line"
  say "registered the duty desk in main.js"
fi
for m in auditors audit-checklist pdpl pdpl-consent pdpl-workflows pdpl-access pdpl-intake pdpl-vendor pdpl-catalog pdpl-ropa pdpl-office pdpl-notify smtp db-targets pdpl-assessment ndmo nca-ecc iso27001 audit-engage audit-ccm audit-analytics audit-analytics-lib audit-auto vuln-dashboard mobile-test iso-lifecycle nca-ecc-intel roadmap risk-assess intel-kit controls-intel maturity-intel netcfg-intel raci-intel nca-itaudit-intel ndmo-intel pdpl-studio-intel risk-command cert-autopilot fwlib-intel aigov-intel bcm-intel overview-intel contcomp-intel validation-intel custody-intel docs-intel sama-ia sama-audit appsec apppt crosswalk grc-dashboard grc-register ia-resilience pdpl-intel dept-checklist gmp vulnscan audit-dashboard onboarding onboarding-ad m365-licensing ad-writer offboarding ad-directory sso-groups identity-advisor ipam exo mdm movers access-reviews pam cert-autodiscover nhi mail-reputation mail-doctor libraesva servers app-route hardening db-health certs cert-issue cert-install cert-estate csr acme adcs; do [ ! -f "$APP/engine/$m.js" ] || "$NODE" --check "$APP/engine/$m.js" || restore "syntax check failed ($m.js)"; done
"$NODE" --check "$MAIN" && "$NODE" --check "$MOD" && "$NODE" --check "$DATA" && "$NODE" --check "$GCM" && "$NODE" --check "$VAM" && { [ ! -f "$VAI" ] || "$NODE" --check "$VAI"; } && { [ ! -f "$AIA" ] || { "$NODE" --check "$AIA" && "$NODE" --check "$AIP"; }; } || restore "syntax check failed"

# the SIEM link must pass the analyst role (PDPL Data Catalog, Baseline Hardening, AI auditors read SIEM routes that refuse viewers)
[ -f "$HERE/fix-siem-role.sh" ] && APP="$APP" NODE="$NODE" bash "$HERE/fix-siem-role.sh"
itam_restart_if_changed "$PRE_FP"
systemctl is-active --quiet "$SVC" || itam_start_failed restore

# live check: the routes only the NEW code has must answer - /duty/engineers alone is also answered by an older process
# still running with the previous files. A 404 there gets one restart (itam_serves), then the engine is restored.
CODE="$(itam_code /duty/engineers)"
case "$CODE" in
  200) ;;
  401) say "duty desk installed (the live check could not authenticate - open the portal to confirm)"; echo "   undo: sudo bash $0 --rollback"; exit 0;;
  404) restore "the duty desk did not register";;
  *) say "installed; the live check returned '$CODE' - open the portal to confirm"; echo "   undo: sudo bash $0 --rollback"; exit 0;;
esac
CHECK="/duty/readiness /update-guard /tickets-intel /virt/admin /audit-programme /audit-checklist /ia/profile /dept-checklist /iso27001 /vulnscan /mail-route/troubleshoot /audit-dashboard /audit-auto /audit-analytics /audit-repo /vuln-dashboard /mobile-test /iso-lifecycle /nca-ecc-intel /roadmap /risk-assess /controls-intel /maturity-intel /netcfg-intel /raci-intel /nca-itaudit-intel /ndmo-intel /pdpl-studio /risk-command /certs/autopilot /licence /fwlib-intel /aigov-intel /bcm-intel /overview-intel /contcomp-intel /validation-intel /custody-intel /docs-intel /sama-itaudit /audit-ccm /sama-ia /sama-audit /appsec /apppt /crosswalk /gap-analysis /grc-dashboard /grc-register /ia-resilience /pdpl/intel /certs /pdpl/breaches /pdpl/holds /pdpl/access /pdpl/catalog /pdpl/ropa/templates /pdpl/office/mine /ndmo /nca-ecc /onboarding /onboarding/ad /onboarding/m365 /offboarding /ad-directory /sso-groups /identity-advisor/status /ipam /movers /access-reviews /pam /certs/autodiscovery /nhi/summary /certs/report /mail-route /servers /audit-programme /audit-ccm /audit-dashboard /report-center /notify /workspace/org /virt-network /sla /risk-studio /updates /infra-inventory /servers-dashboard /ops-wall /exec-dashboard /phishsim /brand /cmdb/deps /impl-plan /dr-studio /vsphere-studio /vapt-studio /vapt-center /discovery-studio /platform/update-health"; grep -q "registerGrc" "$MAIN" && CHECK="$CHECK /grc/roadmap"
# Every page is checked, but ONE page that does not answer no longer rolls back all the others (that removed the Email Route Map,
# VAPT Studio and the rest when a single module failed): the duty desk itself answers, so the new engine stays, the pages that
# do not answer are named with the cause the log shows, and the update is marked failed so it is seen. update-report.json keeps it.
MISS=""; for p in $CHECK; do itam_serves "$p" || MISS="$MISS $p"; done
if [ -n "$MISS" ]; then
  echo "!! the engine is running, but these pages do not answer yet:$MISS"
  itam_doctor
  itam_report duty partial "{\"missing\":\"${MISS# }\",\"checked\":\"$CHECK\",\"findings\":$ITAM_FINDINGS}"
  echo "   Every other page stays installed (nothing rolled back). Fix the cause above and run the update again; the Update Health page (Platform Admin) shows the same."
  echo "   undo the whole duty desk: sudo bash $0 --rollback"
  exit 3
fi
itam_report duty ok "{\"checked\":\"$CHECK\"}"
say "duty desk is live: the pentest, desktop support, GRC consultant and virtualization engineers patrol every 10 minutes (checked: ${CHECK// /, })"
echo "   undo: sudo bash $0 --rollback"
