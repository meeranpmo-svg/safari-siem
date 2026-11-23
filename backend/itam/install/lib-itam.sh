# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
# lib-itam.sh - shared by the add-*.sh installers and update-discovery.sh (sourced, not run).
# Why: every installer used to restart sentra-itam unconditionally and check it 3 s later. One update ran ten of them in a
# few minutes; systemd allows 10 starts per 5 minutes, so the service hit its start limit and stayed down ("Asset
# Discovery Service - Not connected"), and installers whose live check then failed rolled themselves back ("does not
# have this yet"). Now: no restart when nothing changed, the start-limit counter is cleared before a restart, and the
# installer waits until the API actually answers (a big inventory takes longer than 3 s to load).
#   itam_fp              fingerprint of the installed engine (all .js files)
#   itam_up [seconds]    wait until the ITAM API port accepts connections (default 90 s); 0 = up
#   itam_restart         reset-failed + restart + itam_up
#   itam_restart_if_changed "$PRE_FP"   supply missing required files (itam_supply_deps), then restart only when the
#                        engine changed or the service is not answering
#   itam_code PATH [ms] HTTP status of GET {prefix}PATH as a viewer (0 = no answer); reads nothing, changes nothing
#   itam_serves PATH     the RUNNING engine answers PATH (not 404). A 404 while the files on disk are new means the old
#                        process is still running (files replaced without a restart): restart once and check again.

itam_port() { "${NODE:-node}" -e 'let c={};try{c=JSON.parse(require("fs").readFileSync("/etc/sentra-itam/config.json","utf8"))}catch(e){}console.log((c.api&&c.api.port)||9150)' 2>/dev/null || echo 9150; }
itam_fp() { find "${APP:-/opt/sentra-itam}/engine" -name '*.js' -type f -exec sha256sum {} + 2>/dev/null | sort | sha256sum | cut -c1-16 || true; }
itam_up() {
  local max="${1:-90}" port i; port="$(itam_port)"
  for ((i = 0; i < max; i += 2)); do
    systemctl is-active --quiet "${SVC:-sentra-itam}" && (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null && return 0
    sleep 2
  done
  return 1
}
itam_restart() {
  systemctl reset-failed "${SVC:-sentra-itam}" 2>/dev/null || true
  systemctl restart "${SVC:-sentra-itam}"
  itam_up 90 || echo "   ${SVC:-sentra-itam} is not answering on its port after 90 s"
}
itam_code() {
  "${NODE:-node}" -e '
const fs=require("fs"),http=require("http");let c={},s={};
try{c=JSON.parse(fs.readFileSync("/etc/sentra-itam/config.json","utf8"))}catch(e){}
try{s=JSON.parse(fs.readFileSync("/etc/sentra-itam/secrets.json","utf8"))}catch(e){}
const a=c.api||{};
const r=http.request({host:a.host||"127.0.0.1",port:a.port||9150,method:"GET",path:(a.prefix||"/api/itam")+process.argv[1],headers:{"X-Sentra-Proxy-Secret":s.proxy_secret||"","X-Auth-User":"zyb-install-check","X-Auth-Role":"viewer"}},res=>{res.resume();console.log(res.statusCode)});
r.on("error",()=>console.log(0));r.setTimeout(Number(process.argv[2])||8000,()=>{r.destroy()});r.end();' "$1" "${2:-8000}" 2>/dev/null || echo 0
}
itam_serves() {
  local code; code="$(itam_code "$1")"
  if [ "$code" = 404 ]; then
    echo "==> the running ${SVC:-sentra-itam} does not serve $1 yet (an older process) - restarting it once"
    itam_restart; code="$(itam_code "$1")"
  fi
  # no answer in 8 s: a page's first request after a restart can be slow (cold caches, a heavy read) - ask once more with 30 s
  # before calling it missing, the same rule the update's final page check uses (it was failing itam-duty on a page that worked)
  if [ "$code" = 0 ]; then local t0=$SECONDS; code="$(itam_code "$1" 30000)"
    # an instant 0 is a refused connection (the service restarting, not listening yet), not a slow page: wait for the port, ask again
    if [ "$code" = 0 ] && [ $((SECONDS - t0)) -lt 5 ]; then itam_up 90 >/dev/null; code="$(itam_code "$1" 30000)"; [ "$code" = 0 ] && echo "   $1: connection refused - ${SVC:-sentra-itam} is not listening"; fi
    [ "$code" != 0 ] && [ "$code" != 404 ] && echo "   note: $1 answered only on a second try (HTTP $code) - installed; the service was restarting or the page is slow"; fi
  [ "$code" != 404 ] && [ "$code" != 0 ]
}
# A file an installed module require()s but that no installer copied stops sentra-itam at start (every page: HTTP 502),
# and the installer then rolls back - so the page keeps saying "not installed" (nutanix.js needs discovery/diag.js, which
# an older Asset Discovery does not have). Supply such files from this package BEFORE the restart: only missing files,
# never one that exists (that is each module's own installer's job), and say which.
itam_supply_deps() {
  local pkg="${HERE:-.}/../engine" app="${APP:-/opt/sentra-itam}/engine" miss f got=""
  [ -d "$pkg" ] && [ -d "$app" ] || return 0
  miss="$("${NODE:-node}" -e '
    const fs=require("fs"),path=require("path"),D=process.argv[1],out=new Set();
    const walk=(d)=>{for(const f of fs.readdirSync(d,{withFileTypes:true})){const p=path.join(d,f.name);if(f.isDirectory()){if(!/node_modules|\.prev/.test(f.name))walk(p);}else if(f.name.endsWith(".js")){const s=fs.readFileSync(p,"utf8");for(const m of s.matchAll(/require\(\s*["\x27](\.{1,2}\/[^"\x27]+)["\x27]\s*\)/g)){let t=path.resolve(path.dirname(p),m[1]);if(!/\.(js|json)$/.test(t))t+=".js";if(!fs.existsSync(t)&&!fs.existsSync(t.replace(/\.js$/,"/index.js")))out.add(path.relative(D,t));}}}};
    walk(D);process.stdout.write([...out].join(" "));' "$app" 2>/dev/null || true)"
  for f in $miss; do case "$f" in ..*|/*) continue;; esac; [ -f "$pkg/$f" ] && install -D -m 644 -o root -g root "$pkg/$f" "$app/$f" && got="$got $f"; done
  [ -n "$got" ] && echo "==> supplied engine files an installed module needs:$got"
  return 0
}
# Update doctor (install/update-doctor.js): load every installed module BEFORE the restart and supply what one of them needs, check
# the Python rules import, read the log and name the cause of a failure, and record each installer's result for the Update Health
# page (/opt/sentra-itam/update-report.json). An update that cannot start a page must say which page and why - never roll back the rest.
ITAM_DOCTOR="${HERE:-.}/update-doctor.js"; ITAM_REPORT="${ITAM_REPORT:-${APP:-/opt/sentra-itam}/update-report.json}"
itam_preflight() {
  [ -f "$ITAM_DOCTOR" ] || return 0
  local out; out="$(cd /tmp && "${NODE:-node}" "$ITAM_DOCTOR" preflight "${APP:-/opt/sentra-itam}/engine" "${HERE:-.}/../engine" 2>/dev/null || true)"
  [ -n "$out" ] && "${NODE:-node}" -e 'const r=JSON.parse(process.argv[1]);if(r.supplied.length)console.log("==> preflight supplied files a module needs: "+r.supplied.join(", "));for(const e of r.errors)console.log("!! preflight: "+e.module+" does not load ("+e.code+": "+e.message+")");if(!r.errors.length)console.log("==> preflight: "+r.checked+" engine modules load")' "$out" 2>/dev/null || true
  local PY="${PYTHON_BIN:-/opt/sentra-siem/pyenv/bin/python3}"; [ -x "$PY" ] || PY="$(command -v python3 || true)"
  if [ -n "$PY" ] && [ -f "${APP:-/opt/sentra-itam}/pyengine/run.py" ]; then
    if ! (cd "${APP:-/opt/sentra-itam}/pyengine" && "$PY" -c "import run" >/tmp/zyb-pyimport.log 2>&1); then echo "!! preflight: the Python rules do not import:"; tail -n 3 /tmp/zyb-pyimport.log; else echo "==> preflight: the Python rules import"; fi
  fi
  return 0
}
itam_doctor() {   # print the causes the service log shows, with the fix; echo the findings JSON in ITAM_FINDINGS
  ITAM_FINDINGS='{"findings":[]}'; [ -f "$ITAM_DOCTOR" ] || return 0
  journalctl -u "${SVC:-sentra-itam}" -n 400 --no-pager > /tmp/zyb-itam-log.txt 2>/dev/null || true
  ITAM_FINDINGS="$("${NODE:-node}" "$ITAM_DOCTOR" diagnose /tmp/zyb-itam-log.txt 2>/dev/null || echo '{"findings":[]}')"
  "${NODE:-node}" -e 'const r=JSON.parse(process.argv[1]);for(const f of r.findings)console.log("   cause: "+f.cause+"\n   fix:   "+f.fix)' "$ITAM_FINDINGS" 2>/dev/null || true
}
itam_report() {   # itam_report <installer> <status> [json detail]
  [ -f "$ITAM_DOCTOR" ] || return 0
  "${NODE:-node}" "$ITAM_DOCTOR" report "$ITAM_REPORT" "$1" "$2" "${3:-}" 2>/dev/null && chmod 640 "$ITAM_REPORT" 2>/dev/null && chgrp "${SVC:-sentra-itam}" "$ITAM_REPORT" 2>/dev/null || true
}
itam_restart_if_changed() {
  itam_supply_deps
  itam_preflight
  if [ "$1" = "$(itam_fp)" ] && itam_up 4; then echo "==> already installed - ${SVC:-sentra-itam} not restarted"
  else echo "==> restarting ${SVC:-sentra-itam}"; itam_restart; fi
}

# Was the engine healthy BEFORE this installer changed anything? (measured when the installer sources this file)
# A start failure is only this installer's fault when the engine was up before it ran. When it was already down (a
# broken secrets file, another module, …), rolling back would only remove a good module and break the next installer
# in the chain - which is exactly how one EACCES on secrets.json once rolled back half of an update.
if systemctl is-active --quiet "${SVC:-sentra-itam}" 2>/dev/null && (exec 3<>"/dev/tcp/127.0.0.1/$(itam_port)") 2>/dev/null; then ITAM_PRE_UP=1; else ITAM_PRE_UP=0; fi
itam_start_failed() {   # itam_start_failed <restore function>
  journalctl -u "${SVC:-sentra-itam}" -n 20 --no-pager | tail -n 20
  if [ "${ITAM_PRE_UP:-1}" = 0 ]; then
    echo "!! ${SVC:-sentra-itam} was already not running before this installer changed anything - the cause is in the log above, not in this module."
    echo "   This installer's files are kept (nothing rolled back). Fix the cause, then: sudo systemctl restart ${SVC:-sentra-itam}"
    exit 1
  fi
  "$1" "${SVC:-sentra-itam} did not start"
}
# Every installer's restore() calls this first: a rollback is never silent. It names the cause from the service log and records
# "<installer> rolled-back: <reason>" in the update report, so Platform Admin -> Update Health shows which page went back and why.
itam_on_restore() {
  local name; name="$(basename "${0:-installer}" .sh)"; name="${name#add-}"
  itam_doctor
  itam_report "$name" rolled-back "$("${NODE:-node}" -e 'process.stdout.write(JSON.stringify({reason:process.argv[1],findings:JSON.parse(process.argv[2])}))' "${1:-rolled back}" "$ITAM_FINDINGS" 2>/dev/null || echo '{}')"
  return 0
}
