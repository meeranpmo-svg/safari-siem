#!/bin/bash
# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
# add-remote-console.sh - Remote console (engine/remote-console.js, engine/ws.js; WebSocket support in engine/http.js):
#   log in to Windows (RDP), Linux / Solaris / ESXi / Nutanix / network devices (SSH) from the portal through an Apache
#   Guacamole gateway (guacd) on THIS server, only after another person approves a time-limited request; every session
#   recorded. Page: dashboards/remote-console.html (Servers & Virtualization -> Remote Console).
#   sudo bash add-remote-console.sh                    install / update the engine part and the nginx tunnel (safe to re-run)
#   sudo bash add-remote-console.sh --install-gateway  also install guacd (127.0.0.1:4822) and the recordings folder
#   sudo bash add-remote-console.sh --rollback         put back the engine files and nginx config from before the first install
# The console stays OFF until an administrator switches it on in the page's settings. Nothing here stores a credential:
# people type their own account into the remote login.
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib-itam.sh"
APP=/opt/sentra-itam; SVC=sentra-itam; BK=/var/backups/sentra-itam-remote-console; REC=/var/lib/sentra-itam/console-recordings
FILES="http.js ws.js remote-console.js"
say() { echo "==> $*"; }; die() { echo "!! $*"; exit 1; }
NGX_INC="$APP/install/nginx-itam.conf"

if [ "${1:-}" = "--rollback" ]; then
  [ -d "$BK" ] || die "no backup in $BK"
  for f in $FILES; do if [ -f "$BK/$f" ]; then cp -p "$BK/$f" "$APP/engine/$f"; elif [ "$f" != http.js ]; then rm -f "$APP/engine/$f"; fi; done
  if [ -f "$BK/nginx-itam.conf" ]; then cp -p "$BK/nginx-itam.conf" "$NGX_INC"; nginx -t 2>/dev/null && systemctl reload nginx; fi
  itam_restart; say "restored the engine and nginx from before the remote console ($(systemctl is-active "$SVC"))"; exit 0
fi
[ -f "$APP/engine/main.js" ] || die "IT Asset Management is not installed here"
NODE="$(systemctl show -p ExecStart --value "$SVC" 2>/dev/null | sed -n 's/.*argv\[\]=\([^ ;]*\).*/\1/p' | head -n1)"
[ -x "${NODE:-}" ] || NODE=/opt/sentra-ai/node/bin/node; [ -x "$NODE" ] || NODE="$(command -v node || true)"
src() { for d in "$HERE/../engine" "$HERE/../engine-all"; do [ -f "$d/$1" ] && { echo "$d/$1"; return 0; }; done; return 1; }

# 1. engine files: backup once, syntax check, install, restart only if changed, live check
mkdir -p "$BK"; PRE="$(itam_fp)"
for f in $FILES; do
  S="$(src "$f")" || die "missing engine/$f in the package - copy the whole sentra-itam folder"
  "$NODE" --check "$S" || die "engine/$f does not pass a syntax check - nothing installed"
done
for f in $FILES; do [ -f "$APP/engine/$f" ] && [ ! -f "$BK/$f" ] && cp -p "$APP/engine/$f" "$BK/$f"; install -m 644 -o root -g root "$(src "$f")" "$APP/engine/$f"; done
restore() { itam_on_restore "$1"; echo "!! $1 - restoring the previous engine files"; for f in $FILES; do if [ -f "$BK/$f" ]; then cp -p "$BK/$f" "$APP/engine/$f"; elif [ "$f" != http.js ]; then rm -f "$APP/engine/$f"; fi; done; itam_restart || true; exit 1; }
itam_restart_if_changed "$PRE" || restore "sentra-itam did not come back"
code="$(itam_code /console)"
# the files passed the syntax check and the preflight and the engine is running: a 404 here means duty.js (which registers
# /console) is older than this package - restoring http.js / ws.js would not fix that, it only takes the page away. So: diagnose,
# record it for Platform Admin -> Update Health, keep the new files, and say exactly what to do.
RC_PARTIAL=""
case "$code" in
  200|401|403) say "remote console API answers (HTTP $code for a viewer: operators only)"; itam_report remote-console ok '{}';;
  *) if itam_serves /console; then itam_report remote-console ok '{}'
     else
       RC_PARTIAL=1; itam_doctor
       echo "!! the remote console API does not answer (HTTP $code). The engine is running and the new files are KEPT (nothing rolled back)."
       grep -q "optional('./remote-console')" "$APP/engine/duty.js" 2>/dev/null || echo "   cause: the installed engine/duty.js does not load remote-console.js yet - run add-duty.sh (the update runs it before this step), then this script again"
       itam_report remote-console partial "{\"missing\":\"/console\",\"http\":\"$code\",\"findings\":$ITAM_FINDINGS}"
     fi;;
esac

# 2. nginx: the WebSocket tunnel location next to /api/itam/
if [ -f "$NGX_INC" ] && ! grep -q 'console/tunnel' "$NGX_INC"; then
  [ -f "$BK/nginx-itam.conf" ] || cp -p "$NGX_INC" "$BK/nginx-itam.conf"
  install -m 644 -o root -g root "$HERE/nginx-itam.conf" "$NGX_INC"
  if nginx -t 2>/dev/null; then systemctl reload nginx; say "nginx: console tunnel location added"; else cp -p "$BK/nginx-itam.conf" "$NGX_INC"; echo "!! nginx -t failed with the tunnel location - restored the previous file (the console page will show 'tunnel not reachable')"; fi
elif [ -f "$NGX_INC" ]; then say "nginx: console tunnel location already present"
else
  echo "!! $NGX_INC not found: add the 'location = /api/itam/console/tunnel' block from $HERE/nginx-itam.conf to the portal's server { } yourself"
fi

# 3. the gateway (only when asked): guacd on 127.0.0.1:4822 and the recordings folder (group sentra-itam may read)
if [ "${1:-}" = "--install-gateway" ]; then
  if ! command -v guacd >/dev/null 2>&1 && ! systemctl list-unit-files 2>/dev/null | grep -q '^guacd'; then
    if command -v apt-get >/dev/null; then DEBIAN_FRONTEND=noninteractive apt-get install -y guacd libguac-client-rdp0 libguac-client-ssh0
    elif command -v dnf >/dev/null; then dnf install -y epel-release >/dev/null 2>&1 || true; dnf install -y guacd libguac-client-rdp libguac-client-ssh
    else die "no apt-get or dnf: install guacd 1.5 (with the RDP and SSH plugins) yourself, bound to 127.0.0.1:4822"; fi
  fi
  mkdir -p /etc/guacamole
  if [ ! -f /etc/guacamole/guacd.conf ] || ! grep -q '^bind_host *= *127.0.0.1' /etc/guacamole/guacd.conf; then
    printf '# written by add-remote-console.sh: the gateway listens on this server only\n[server]\nbind_host = 127.0.0.1\nbind_port = 4822\n' > /etc/guacamole/guacd.conf
  fi
  GU="$(systemctl show -p User --value guacd 2>/dev/null)"; GU="${GU:-root}"
  install -d -m 2750 -o "$GU" -g sentra-itam "$REC"
  systemctl enable --now guacd >/dev/null 2>&1 || systemctl restart guacd
  sleep 1
  (exec 3<>/dev/tcp/127.0.0.1/4822) 2>/dev/null && say "guacd answers on 127.0.0.1:4822; recordings in $REC" || echo "!! guacd is not answering on 127.0.0.1:4822 - see: journalctl -u guacd -n 30"
  if ss -ltn 2>/dev/null | grep -q '0.0.0.0:4822\|\*:4822\|\[::\]:4822'; then echo "!! guacd listens on all interfaces - set bind_host = 127.0.0.1 in /etc/guacamole/guacd.conf"; fi
else
  command -v guacd >/dev/null 2>&1 || say "guacd is not installed yet: run  sudo bash $0 --install-gateway  when you decide to use the remote console"
fi
say "remote console installed. It is OFF until an administrator switches it on: Remote Console -> Settings (gateway 127.0.0.1:4822, approvers, maximum minutes)."
[ -z "$RC_PARTIAL" ] || { echo "!! remote console: installed but its API is not registered yet - see Platform Admin -> Update Health"; exit 3; }
