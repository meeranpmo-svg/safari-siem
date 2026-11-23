#!/bin/bash
# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
# update-server.sh - install the whole platform update on the platform server, in order. Run by update-platform.ps1
# from the unpacked bundle:  sudo bash update-server.sh
#   1 SIEM engine (link to IT Asset Management, backup, migrate, restart, health check, automatic rollback)
#   2 AI Network Engineer setup (offline SDK, ping check, schema) - the API key is set separately (--set-key)
#   3 dashboards (pages + add-ons), nginx /dashboards/ (whoami, no-cache), server stats timer, portal menu add-on
#   4 IT Asset Management: admin Delete API (engine/asset-delete.js; the buttons come from the zyb-itamdel.js add-on),
#     PC / server IP and MAC from the SIEM's logs (engine/siem-ip.js), end-of-life + isolation (engine/lifecycle.js)
#   5 summary
set -uo pipefail
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
HERE="$(cd "$(dirname "$0")" && pwd)"
find "$HERE" -name '*.sh' -exec sed -i 's/\r$//' {} +
step() { echo; echo "================ $* ================"; }
FAILED=""

# a platform backup before anything changes (zyb-backup from install-platform.sh): the engines' own rollback covers
# their programs, this covers settings and data. A failed backup stops the update; ZYB_SKIP_BACKUP=1 overrides.
if [ -x /usr/local/sbin/zyb-backup ]; then
  step "0/5 platform backup before the update"
  if ZYB_BACKUP_BY=update /usr/local/sbin/zyb-backup; then echo "==> backup taken (list: sudo zyb-restore list)"
  elif [ "${ZYB_SKIP_BACKUP:-}" = 1 ]; then echo "!! backup failed - continuing because ZYB_SKIP_BACKUP=1"
  else echo "!! the platform backup failed - nothing was changed. Fix it (sudo zyb-backup shows why) or re-run with ZYB_SKIP_BACKUP=1"; exit 1; fi
fi

step "1/5 SIEM engine"
bash "$HERE/sentra-siem/install/link-itam.sh" || FAILED="$FAILED link-itam"   # SIEM reads the asset inventory (Server Availability sync); the engine restart below picks it up
if bash "$HERE/sentra-siem/install/deploy-engine.sh"; then :; else echo "!! engine update failed and was rolled back - stopping here (dashboards not changed)"; exit 1; fi
bash "$HERE/sentra-siem/install/secure-secrets.sh" || FAILED="$FAILED secure-secrets"   # passwords sealed at rest, key apart from the data

step "2/5 AI Network Engineer setup"
bash "$HERE/sentra-siem/install/netops-setup.sh" || FAILED="$FAILED netops-setup"
# Netmiko for the read-only switch CLI (show commands over SSH): from the bundled wheels (offline), else PyPI / a proxy - not counted as a failure
# ... and re-run when the package carries a different wheel bundle (security fixes), not only when something is missing
WSUM="$(cut -d' ' -f1 "$HERE/sentra-siem/install/vendor/python-wheels-linux-x86_64.tgz.sha256" 2>/dev/null)"
if [ -x /opt/sentra-siem/pyenv/bin/python3 ] && /opt/sentra-siem/pyenv/bin/python3 -c 'import netmiko, pypsrp, pymysql, pg8000, pytds' 2>/dev/null \
   && { [ -z "$WSUM" ] || [ "$(cat /opt/sentra-siem/pyenv/.bundle-sha256 2>/dev/null)" = "$WSUM" ]; }; then echo "==> Netmiko, pypsrp and the database drivers already installed (current wheel bundle)"
else bash "$HERE/sentra-siem/install/netops-cli-setup.sh" || CLI_NOTE=1; fi

step "3/5 Dashboards, nginx, server stats, health + backup, menu"
cd "$HERE/dashboards"
bash install-dashboards.sh | grep -E '==> dashboards installed|==> static build|Content-Security-Policy|missing|nothing changed' || FAILED="$FAILED dashboards"
bash add-dashboards-nginx.sh || FAILED="$FAILED nginx"
bash web-cache.sh | grep -E "^==>|^!!" || FAILED="$FAILED web-cache"   # browsers re-check portal pages: an update shows without Ctrl+F5
bash install-sysinfo.sh >/dev/null && echo "==> server stats timer installed" || FAILED="$FAILED sysinfo"
bash install-platform.sh || FAILED="$FAILED platform-health-backup"
# the portal pages from git (repos/live/portal) - before the menu add-on, which adds its two lines to index.html again
if [ -f "$HERE/portal/app.js" ]; then bash install-portal.sh "$HERE/portal" || FAILED="$FAILED portal-pages"; else echo "!! portal pages not in this bundle"; FAILED="$FAILED portal-pages"; fi
bash add-dashboards-menu.sh || FAILED="$FAILED menu"
# sign-in page design: once switched on (install-login-skin.sh), keep its script current - same service desk contact
if nginx -T 2>/dev/null | grep -q '# ZYB-LOGINSKIN'; then
  ZDESK="$(sed -n "s/.*var DESK = '\([^']*\)'.*/\1/p" /var/www/sentra/zyb-login/zyb-login.js 2>/dev/null | head -n1)"
  LSKIN="$(bash install-login-skin.sh ${ZDESK:+--desk "$ZDESK"} 2>&1)"; LSKIN_RC=$?
  printf '%s\n' "$LSKIN" | grep -E '^==> done|^!!' || true
  if [ $LSKIN_RC != 0 ]; then   # the reason goes into the summary at the end, so nobody has to scroll for it
    LWHY="$(printf '%s\n' "$LSKIN" | grep -E '^!!' | tail -n1 | sed 's/^!! *//')"; [ -n "$LWHY" ] || LWHY="$(printf '%s\n' "$LSKIN" | grep -v '^[[:space:]]*$' | tail -n1)"
    FAILED="$FAILED login-skin"; NOTES="${NOTES:-}$(printf '\n   login-skin: %s' "${LWHY:-the installer stopped without a message}")"
  fi
fi

install -m 755 -o root -g root "$HERE/sentra-siem/install/harden-server.sh" /usr/local/sbin/zyb-harden 2>/dev/null && echo "==> security hardening tool installed: sudo zyb-harden (report) / sudo zyb-harden --apply"
install -m 755 -o root -g root "$HERE/dashboards/harden-web.sh" /usr/local/sbin/zyb-harden-web 2>/dev/null && echo "==> web hardening tool installed: sudo zyb-harden-web (report) / sudo zyb-harden-web --apply"
install -m 755 -o root -g root "$HERE/ai-readiness.sh" /usr/local/sbin/zyb-ai-readiness 2>/dev/null && echo "==> AI readiness check installed: sudo zyb-ai-readiness"
# server-side helpers as commands (no need to find the update folder): make every AI engineer ready, and add Zscaler /
# Kaspersky / vCenter-Nutanix connections from the shell while the portal admin role is not wired
for pair in "ai-engineers-ready.sh:zyb-ai-ready" "configure-zscaler.sh:zyb-configure-zscaler" "configure-kaspersky.sh:zyb-configure-kaspersky" "configure-virtualization.sh:zyb-configure-virtualization" "check-oracle.sh:zyb-check-oracle"; do
  [ -f "$HERE/scripts/${pair%%:*}" ] && install -m 755 -o root -g root "$HERE/scripts/${pair%%:*}" "/usr/local/sbin/${pair##*:}"
done
[ -f "$HERE/sentra-siem/install/netops-pam-setup.sh" ] && install -m 755 -o root -g root "$HERE/sentra-siem/install/netops-pam-setup.sh" /usr/local/sbin/zyb-pam-setup && echo "==> installed: sudo zyb-pam-setup (network write accounts from your PAM)"
[ -f "$HERE/sentra-itam/install/add-virt-ai.sh" ] && install -m 755 -o root -g root "$HERE/sentra-itam/install/add-virt-ai.sh" /usr/local/sbin/zyb-virt-ai && echo "==> installed: sudo zyb-virt-ai --set-key (Claude for the AI Virtualization Administrator)"
[ -x /usr/local/sbin/zyb-ai-ready ] && echo "==> installed: sudo zyb-ai-ready · sudo zyb-configure-zscaler · sudo zyb-configure-kaspersky · sudo zyb-configure-virtualization"
# web hardening already applied: refresh it for the new build (the dashboards' policy follows .zyb-static.json); services untouched
if nginx -T 2>/dev/null | grep -q '# ZYB-WEB$'; then bash "$HERE/dashboards/harden-web.sh" --apply --no-systemd | grep -E '^==> nginx|^!!' || FAILED="$FAILED web-hardening"
elif [ "${ZYB_HARDEN_WEB:-}" = apply ]; then step "web hardening (first time, -HardenWeb apply)"; bash "$HERE/dashboards/harden-web.sh" --apply || FAILED="$FAILED web-hardening"
elif [ "${ZYB_HARDEN_WEB:-}" = report ]; then step "web hardening report (nothing changed)"; bash "$HERE/dashboards/harden-web.sh"; fi

# the Go test slice in shadow (sentra-siem docs/GO-SLICE.md) - only when the update was run with -Go shadow / -Go remove;
# it never replaces the SIEM: own port, own output file
if [ "${ZYB_GO:-}" = shadow ]; then
  if [ -f "$HERE/sentra-siem/go/sentra-ingest" ]; then step "Go shadow collector (-Go shadow)"; bash "$HERE/sentra-siem/go/install-go-shadow.sh" --binary "$HERE/sentra-siem/go/sentra-ingest" ${ZYB_GO_PORT:+--port "$ZYB_GO_PORT"} || FAILED="$FAILED go-shadow"
  else echo "!! -Go shadow was asked but the package has no Go build"; FAILED="$FAILED go-shadow"; fi
elif [ "${ZYB_GO:-}" = remove ]; then step "Go shadow collector: remove (-Go remove)"; bash "$HERE/sentra-siem/go/install-go-shadow.sh" --remove || FAILED="$FAILED go-shadow"
elif [ -x /usr/local/sbin/zyb-go-shadow ]; then echo "==> Go shadow collector: left as it is (run the update with -Go shadow to upgrade it; status: sudo zyb-go-shadow)"; fi

step "4/5 IT Asset Management - Delete, discovery IP / MAC"
# Every IT Asset Management step runs through itam_step: its output is shown as before and kept, so the summary at the end
# repeats the "!!" lines of a step that failed. Bug fixed: a step that stopped early (die) or rolled back wrote no "pages not
# answering" entry, and the summary said only "these steps reported a problem: itam-duty" with no reason on screen.
STEPLOG="$(mktemp -d 2>/dev/null || echo /tmp/zyb-steps-$$)"; mkdir -p "$STEPLOG"; chmod 700 "$STEPLOG"
itam_step() { local tag="$1" rc; shift; bash "$@" 2>&1 | tee "$STEPLOG/$tag.log"; rc=${PIPESTATUS[0]}; [ "$rc" = 0 ] && return 0; FAILED="$FAILED $tag"; return 0; }
# stability first: no systemd start limit, enough memory, watchdog (the add-ons below used to hit the start limit)
if [ -f /opt/sentra-itam/engine/main.js ]; then itam_step itam-stability "$HERE/sentra-itam/install/itam-stability.sh"; fi
# the shared error register first: every add-on below guards its background jobs with it (engine/errors.js)
# (and the shared input validation / AI guard rails the add-ons require: engine/check.js, engine/ai-guard.js)
if [ -f /opt/sentra-itam/engine/main.js ]; then for f in errors.js check.js ai-guard.js saferegex.js brand.js brand.default.json grc-policy-file.js; do [ -f "$HERE/sentra-itam/engine-all/$f" ] && install -m 644 -o root -g root "$HERE/sentra-itam/engine-all/$f" "/opt/sentra-itam/engine/$f" && echo "==> shared engine file installed: engine/$f"; done; fi
# the discovery engine first: add-ons such as Virtualization use parts of it (the shared sealer, the SIEM link)
if [ -f /opt/sentra-itam/engine/discovery/runner.js ]; then itam_step itam-discovery "$HERE/sentra-itam/install/update-discovery.sh"; fi
if [ -f /opt/sentra-itam/engine/main.js ]; then itam_step itam-delete "$HERE/sentra-itam/install/add-asset-delete.sh"; itam_step itam-siem-ip "$HERE/sentra-itam/install/add-siem-ip.sh"; itam_step itam-lifecycle "$HERE/sentra-itam/install/add-lifecycle.sh"; itam_step itam-locations "$HERE/sentra-itam/install/add-locations.sh"; itam_step itam-roles "$HERE/sentra-itam/install/add-roles.sh"; itam_step itam-core-licensing "$HERE/sentra-itam/install/add-core-licensing.sh"; itam_step itam-netops-sync "$HERE/sentra-itam/install/add-netops-sync.sh"; itam_step itam-virt "$HERE/sentra-itam/install/add-virt.sh"; itam_step itam-backup "$HERE/sentra-itam/install/add-backup.sh"; itam_step itam-sysadmin-sync "$HERE/sentra-itam/install/add-sysadmin-sync.sh"; itam_step itam-storage "$HERE/sentra-itam/install/add-storage.sh"; itam_step itam-reconcile "$HERE/sentra-itam/install/add-reconcile.sh"; itam_step itam-budget "$HERE/sentra-itam/install/add-budget.sh"; itam_step itam-licence-sync "$HERE/sentra-itam/install/add-licence-sync.sh"; itam_step itam-asset-links "$HERE/sentra-itam/install/add-asset-links.sh"; itam_step itam-inventory-facts "$HERE/sentra-itam/install/add-inventory-facts.sh"; itam_step itam-manageengine "$HERE/sentra-itam/install/add-manageengine.sh";  itam_step itam-desksupport "$HERE/sentra-itam/install/add-desksupport.sh"; itam_step itam-virt-capacity "$HERE/sentra-itam/install/add-virt-capacity.sh"; itam_step itam-virt-power "$HERE/sentra-itam/install/add-virt-power.sh"; itam_step itam-handover "$HERE/sentra-itam/install/add-handover.sh"; itam_step itam-infra-sync "$HERE/sentra-itam/install/add-infra-sync.sh"; itam_step itam-infra-overview "$HERE/sentra-itam/install/add-infra-overview.sh"; itam_step itam-cisco-support "$HERE/sentra-itam/install/add-cisco-support.sh"; itam_step itam-support-contracts "$HERE/sentra-itam/install/add-support-contracts.sh"; itam_step itam-domains "$HERE/sentra-itam/install/add-domains.sh"; itam_step itam-service-map "$HERE/sentra-itam/install/add-service-map.sh"; itam_step itam-pentest "$HERE/sentra-itam/install/add-pentest.sh"; itam_step itam-grc "$HERE/sentra-itam/install/add-grc.sh"; itam_step itam-duty "$HERE/sentra-itam/install/add-duty.sh"; itam_step itam-ownership "$HERE/sentra-itam/install/add-ownership.sh"; itam_step itam-ciso "$HERE/sentra-itam/install/add-ciso.sh"; itam_step itam-log-enrol "$HERE/sentra-itam/install/add-log-enrol.sh"; itam_step itam-db-health "$HERE/sentra-itam/install/add-db-health.sh"; itam_step itam-cred-security "$HERE/sentra-itam/install/add-cred-security.sh"; [ -f "$HERE/sentra-itam/install/add-remote-console.sh" ] && { itam_step itam-remote-console "$HERE/sentra-itam/install/add-remote-console.sh"; }; else echo "IT Asset Management is not installed here - skipped"; fi

# wait until sentra-itam accepts connections on its API port. "systemctl is-active" is true the moment the process starts, long
# before it listens: the final page check then got "connection refused" on its first page and reported "/mail-route (HTTP 0,
# no answer in 30 s)" after every update that restarted sentra-itam here - whatever that page did. itam_up is lib-itam.sh's.
itam_listen() { ( SVC=sentra-itam; NODE="${NODE:-$(command -v node || echo /opt/sentra-ai/node/bin/node)}"; . "$HERE/sentra-itam/install/lib-itam.sh"; itam_up "${1:-90}" ); }
# safety net: a file an installed module require()s but that no installer copied stops sentra-itam (every page: HTTP 502).
# Find such requires in the installed engine and supply the file from the package (engine-all); report any still missing.
if [ -f /opt/sentra-itam/engine/main.js ] && [ -d "$HERE/sentra-itam/engine-all" ]; then
  NODE_I="$(systemctl show -p ExecStart --value sentra-itam 2>/dev/null | sed -n 's/.*argv\[\]=\([^ ;]*\).*/\1/p' | head -n1)"; [ -x "${NODE_I:-}" ] || NODE_I="$(command -v node || echo /opt/sentra-ai/node/bin/node)"
  MISSING="$("$NODE_I" -e '
    const fs=require("fs"),path=require("path"),D="/opt/sentra-itam/engine",out=new Set();
    const walk=(d)=>{for(const f of fs.readdirSync(d,{withFileTypes:true})){const p=path.join(d,f.name);if(f.isDirectory()&&!/node_modules|\.prev/.test(f.name))walk(p);else if(f.name.endsWith(".js")){const s=fs.readFileSync(p,"utf8");for(const m of s.matchAll(/require\(\s*["\x27](\.{1,2}\/[^"\x27]+)["\x27]\s*\)/g)){let t=path.resolve(path.dirname(p),m[1]);if(!/\.(js|json)$/.test(t))t+=".js";if(!fs.existsSync(t)&&!fs.existsSync(t.replace(/\.js$/,"/index.js")))out.add(path.relative(D,t));}}}};
    walk(D);process.stdout.write([...out].join(" "));' 2>/dev/null)"
  FIXED=""; for m in $MISSING; do case "$m" in ..*|/*) continue;; esac; [ -f "$HERE/sentra-itam/engine-all/$m" ] && install -D -m 644 -o root -g root "$HERE/sentra-itam/engine-all/$m" "/opt/sentra-itam/engine/$m" && FIXED="$FIXED $m"; done   # sub-folders too (discovery/py-methods.js)
  [ -n "$FIXED" ] && echo "==> supplied engine files an installed module needed:$FIXED" && systemctl restart sentra-itam && itam_listen 90
  STILL="$(for m in $MISSING; do [ -f "/opt/sentra-itam/engine/$m" ] || echo -n "$m "; done)"
  [ -n "$STILL" ] && { echo "!! sentra-itam needs files that are not in the package: $STILL"; FAILED="$FAILED itam-missing-files"; }
fi
# safety net: every installer restarts sentra-itam only when ITS files changed, so engine files can be newer than the
# running process (one installer copied, another skipped the restart). Then the new code is on disk but not running:
# pages show "not installed". One restart fixes that for every module at once.
if [ -f /opt/sentra-itam/engine/main.js ]; then
  IPID="$(systemctl show -p MainPID --value sentra-itam 2>/dev/null)"
  IUP="$(ps -o etimes= -p "$IPID" 2>/dev/null | tr -d ' ')"   # seconds since the process started (procfs times are not reliable)
  if [ -n "$IPID" ] && [ "$IPID" != 0 ] && [ -n "$IUP" ]; then
    NEWER="$(find /opt/sentra-itam/engine -name '*.js' -newermt "@$(( $(date +%s) - IUP ))" -print 2>/dev/null | head -n 3 | sed 's#/opt/sentra-itam/engine/##' | tr '\n' ' ')"
    if [ -n "$NEWER" ]; then
      echo "==> sentra-itam was started before these files changed: $NEWER- restarting it so the new code runs"
      systemctl restart sentra-itam || FAILED="$FAILED itam-restart"
      itam_listen 90 || echo "   sentra-itam is not listening on its port 90 s after the restart"
    else echo "==> sentra-itam is running the installed code"; fi
  fi
fi
# every add-on's registration line must be in main.js: a line missing = that page answers 404 ("not installed")
if [ -f /opt/sentra-itam/engine/main.js ]; then
  NOREG=""; for f in "$HERE"/sentra-itam/install/add-*.sh; do fn="$(sed -n "s/^LINE=.*require('[^']*')\.\(register[A-Za-z]*\)(.*/\1/p" "$f" | head -n1)"; [ -n "$fn" ] && ! grep -q "\.$fn(" /opt/sentra-itam/engine/main.js && NOREG="$NOREG $(basename "$f" .sh)"; done
  [ -n "$NOREG" ] && { echo "!! IT Asset Management add-ons NOT registered (their pages show 'not installed'):$NOREG - see the !! lines of those installers above"; FAILED="$FAILED itam-unregistered:${NOREG// /,}"; } || echo "==> every IT Asset Management add-on is registered"
fi
# sentra-itam down = every IT Asset Management page shows HTTP 502 / "not installed": show WHY right here
if [ -f /opt/sentra-itam/engine/main.js ] && ! systemctl is-active --quiet sentra-itam; then
  echo "!! sentra-itam is NOT running - every IT Asset Management page will show HTTP 502. Its last log lines:"
  journalctl -u sentra-itam -n 25 --no-pager 2>/dev/null | sed 's/^/   /'
  FAILED="$FAILED itam-not-running"
fi
# final page check, AFTER the last restart: an installer that ran before another one finished may have seen a 404 that is gone now.
# Each page's API is asked once; what still does not answer is named with the cause the update doctor recorded (nothing is rolled
# back here). The full picture: Platform Admin -> Update Health (/opt/sentra-itam/update-report.json).
if [ -f /opt/sentra-itam/engine/main.js ] && systemctl is-active --quiet sentra-itam && [ -f "$HERE/sentra-itam/install/lib-itam.sh" ]; then
  ( HERE="$HERE/sentra-itam/install"; APP=/opt/sentra-itam; SVC=sentra-itam; NODE="${NODE:-$(command -v node || echo /opt/sentra-ai/node/bin/node)}"; . "$HERE/lib-itam.sh"
    itam_up 90 || echo "   sentra-itam is not listening on its port after 90 s"
    BAD=""; for p in /mail-route /servers /audit-programme /audit-ccm /audit-dashboard /sama-itaudit /report-center /notify /dr-studio /vsphere-studio /vapt-studio /vapt-center /discovery-studio /ciso/briefs /duty/readiness /console /platform/update-health; do
      c="$(itam_code "$p")"
      why=""
      if [ "$c" = 0 ]; then t0=$SECONDS; c="$(itam_code "$p" 30000)"
        # an instant 0 is a refused connection (the engine restarting, not listening yet), not a slow page: wait for the port, ask again
        if [ "$c" = 0 ] && [ $((SECONDS - t0)) -lt 5 ]; then itam_up 90; c="$(itam_code "$p" 30000)"; [ "$c" = 0 ] && why=", connection refused - sentra-itam is not listening"; fi
        [ "$c" = 0 ] && [ -z "$why" ] && why=", no answer in 30 s"
        [ "$c" != 0 ] && [ "$c" != 404 ] && case "$c" in 5*) ;; *) echo "   note: $p answered only on a second try (HTTP $c) - installed; the engine was restarting or the page is slow";; esac; fi
      case "$c" in 404|0|5*) BAD="$BAD $p(HTTP $c$why)";; esac; done
    if [ -n "$BAD" ]; then
      echo "!! after the update these pages' APIs still do not answer:$BAD"
      itam_doctor; itam_report final-check partial "{\"missing\":\"${BAD# }\",\"findings\":$ITAM_FINDINGS}"
      echo "   see Platform Admin -> Update Health for each page and the fix; the rest of the update is kept"; exit 1
    else echo "==> every checked page answers after the update"; itam_report final-check ok '{}'; fi ) || FAILED="$FAILED itam-pages"
fi
step "5/5 Summary"
echo "sentra-siem: $(systemctl is-active sentra-siem)   sentra-itam: $(systemctl is-active sentra-itam 2>/dev/null)   nginx: $(systemctl is-active nginx)   stats timer: $(systemctl is-active zyb-sysinfo.timer)"
SINCE="$(systemctl show -p ActiveEnterTimestamp --value sentra-siem 2>/dev/null)"   # this start of the service only, however many lines it logged since
# route modules: the engine writes what happened to each one at this start (<data_dir>/state/routes-status.json); the journal
# search stays only as the fallback for an older engine - journald drops lines when a start logs a burst, so it could say
# "NOT registered" about a working module and never said why one was missing
SIEM_DATA="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get("data_dir") or "")' /etc/sentra-siem/config.json 2>/dev/null)"; SIEM_DATA="${SIEM_DATA:-/var/lib/sentra-siem}"
RSTAT="$SIEM_DATA/state/routes-status.json"
api_state() { # api_state <label> <module>
  local r=""
  if [ -f "$RSTAT" ]; then r="$(python3 - "$RSTAT" "$2" <<'PY' 2>/dev/null
import json, sys
d = json.load(open(sys.argv[1])); m = next((x for x in d.get("modules", []) if x.get("module") == sys.argv[2]), None)
words = {"registered": "registered", "not_present": "NOT registered - the file is not in the installed engine (re-run the update)",
         "load_failed": "NOT registered - it failed to load: ", "register_failed": "NOT registered - its setup failed: "}
print("NOT registered - not started (the SIEM state store was not available at this start: journalctl -u sentra-siem | grep state)" if not m else words.get(m["state"], m["state"]) + m.get("error", ""))
PY
)"; fi
  if [ -z "$r" ]; then journalctl -u sentra-siem ${SINCE:+--since "$SINCE"} --no-pager 2>/dev/null | grep -q "\"module\":\"$2\"" && r="registered" || r="NOT registered (journalctl -u sentra-siem -n 100)"; fi
  echo "$1: $r"
}
api_state "AI Network Engineer API" netops/routes.js
api_state "DFIR API" dfir/routes.js
api_state "AI Zscaler Engineer API" zscaler/routes.js
api_state "AI Kaspersky Engineer API" ksc/routes.js
# Server Availability <- IT Asset Management: run one sync now (IT Asset Management was restarted several times above,
# so a failure logged during the update itself means nothing) and print the real result
for i in $(seq 1 20); do systemctl is-active --quiet sentra-itam 2>/dev/null && break; sleep 3; done; sleep 3
NODE_S="$(systemctl show -p ExecStart --value sentra-siem 2>/dev/null | sed -n 's/.*argv\[\]=\([^ ;]*\).*/\1/p' | head -n1)"; [ -x "${NODE_S:-}" ] || NODE_S="$(command -v node || echo /opt/sentra-ai/node/bin/node)"
"$NODE_S" -e '
const fs=require("fs"),http=require("http");let c={},s={};
try{c=JSON.parse(fs.readFileSync("/etc/sentra-siem/config.json","utf8"))}catch(e){}
try{s=require("/opt/sentra-siem/engine/secretfile").read(c.secrets_path||"/etc/sentra-siem/secrets.json")||{}}catch(e){try{s=JSON.parse(fs.readFileSync(c.secrets_path||"/etc/sentra-siem/secrets.json","utf8"))}catch(e2){}}
const a=c.api||{},pre=(c.api_prefix||"/api/soc").replace(/\/+$/,""),body="{\"source\":\"inventory\"}";
const r=http.request({host:a.host&&a.host!=="0.0.0.0"?a.host:"127.0.0.1",port:a.port||9120,method:"POST",path:pre+"/netops/avail/import",timeout:90000,headers:{"Content-Type":"application/json","Content-Length":body.length,"X-Sentra-Proxy-Secret":s.proxy_secret||"","X-Auth-User":"zyb-update","X-Auth-Role":"admin"}},res=>{let d="";res.on("data",x=>d+=x);res.on("end",()=>{let j={};try{j=JSON.parse(d)}catch(e){}
 if(res.statusCode===200)console.log("Server Availability inventory sync: OK - "+j.eligible+" servers / VMs from IT Asset Management ("+j.added+" added, "+(j.removed||0)+" removed"+(j.skipped_no_ip&&j.skipped_no_ip.length?", "+j.skipped_no_ip.length+" without a management IP":"")+")");
 else console.log("Server Availability inventory sync: FAILED - "+(j.error||("HTTP "+res.statusCode))+(res.statusCode===503?"  (fix: sudo bash sentra-siem/install/link-itam.sh)":""));});});
r.on("timeout",()=>r.destroy(new Error("timeout")));r.on("error",e=>console.log("Server Availability inventory sync: could not reach the SIEM API ("+e.message+")"));r.end(body);' 2>/dev/null || echo "Server Availability inventory sync: not checked"

[ -f /var/www/sentra/dashboards/network-engineer.html ] && echo "AI Network Engineer page: installed" || echo "AI Network Engineer page: missing"
/usr/local/sbin/sentra-siem-secrets get netops.anthropic_api_key >/dev/null 2>&1 && echo "AI key: set" || echo "AI key: not set (chat off until approved: sudo bash $HERE/sentra-siem/install/netops-setup.sh --set-key --restart)"
[ -n "${CLI_NOTE:-}" ] && echo "Switch CLI + Windows/Exchange checks (Netmiko, pypsrp): NOT installed - $(sed -n 's/.*"reason":"\([^"]*\)".*/\1/p' /opt/sentra-siem/pyenv-status.json 2>/dev/null || echo 'see the message in step 2'); everything else works without it"
echo "Web hardening: $(nginx -T 2>/dev/null | grep -q '# ZYB-WEB$' && echo "applied (dashboards CSP $(grep -qs '^add_header Content-Security-Policy "default' /etc/nginx/snippets/zyb-dash-headers.conf && echo enforced || echo report-only))" || echo 'not applied (re-run the update with -HardenWeb report, then -HardenWeb apply)')"
if [ -x /usr/local/sbin/zyb-ai-ready ]; then echo; echo "==> bringing every AI engineer up to date (read-only syncs, collections, patrol, readiness)"; /usr/local/sbin/zyb-ai-ready || true
else bash "$HERE/ai-readiness.sh" 2>/dev/null || echo "AI engineers readiness: not checked"; fi
echo "SIEM writable folders: $(systemctl show sentra-siem -p ReadWritePaths --value)"
if [ -n "$FAILED" ]; then
  echo; echo "!! these steps reported a problem:$FAILED"
  [ -n "${NOTES:-}" ] && echo "   why:${NOTES}"
  # what each IT Asset Management step recorded (pages not answering and the cause found), so nobody has to scroll for it
  if [ -f /opt/sentra-itam/update-report.json ] && [ -f "$HERE/sentra-itam/install/update-doctor.js" ]; then
    "${NODE:-$(command -v node || echo /opt/sentra-ai/node/bin/node)}" "$HERE/sentra-itam/install/update-doctor.js" summary /opt/sentra-itam/update-report.json 2>/dev/null || true
  fi
  # each failed step's own "!!" lines (and the indented lines under them), so the reason is on screen without scrolling
  for t in $FAILED; do [ -s "$STEPLOG/$t.log" ] || continue; echo "   $t said:"
    said="$(awk '/^!!/{p=1;n=0} p&&/^(!!|   )/{print "     " $0; if(++n>=14)p=0; next} {p=0}' "$STEPLOG/$t.log" | head -n 30)"
    # no "!!" line (it stopped without saying why): its last lines, so the reason is still on screen
    if [ -n "$said" ]; then echo "$said"; else grep -v '^[[:space:]]*$' "$STEPLOG/$t.log" | tail -n 12 | sed 's/^/     /'; fi; done
  echo "   the full messages are above; Platform Admin -> Update Health shows the same per page"; exit 1
fi
echo; echo "==> update complete - open the portal (Ctrl + F5 once) → Dashboards → AI Network Engineer"
