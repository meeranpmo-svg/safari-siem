#!/bin/bash
# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
# itam-agent installer for Linux / macOS. Installs the agent, enrols it with a one-time token, and sets up a
# scheduled run (systemd timer on Linux, launchd on macOS).
#
#   printf '%s\n' '<one-time-token>' | sudo ./install.sh --server https://<portal>/agent [--node-bin PATH] [--interval 3600]
#   sudo ./install.sh --server https://<portal>/agent --token-file /root/itam-token   (file is deleted after enrolment)
#   (with neither, the token is read from stdin / prompted for without echo)
#
# The one-time token is NEVER put on a command line (visible in `ps` / shell history): the installer hands it to the
# agent on stdin. `--token <value>` is still accepted for compatibility but warns. The server must be https://.
#
# LEAST PRIVILEGE:
#   - The agent only READS local inventory (/proc, /sys/class/dmi, dpkg/rpm, system_profiler) and makes OUTBOUND
#     HTTPS to the ITAM gateway. It never listens on a port and needs no inbound firewall rule.
#   - It runs as a dedicated unprivileged user `itam-agent` (NOT root). DMI serials under /sys are world-readable on
#     most hardware; if a serial is not readable unprivileged it is simply reported null (degrade, never fail).
#   - State (including the per-agent key) lives in /var/lib/sentra-itam-agent, mode 600, owned by itam-agent.
set -euo pipefail
SERVER="" TOKEN="" TOKEN_FILE="" NODE_BIN="$(command -v node || echo /usr/bin/node)" INTERVAL=3600
while [ $# -gt 0 ]; do case "$1" in
  --server) SERVER="$2"; shift 2;;
  --token) TOKEN="$2"; echo "warning: --token exposes the token in the process list; pipe it on stdin or use --token-file" >&2; shift 2;;
  --token-file) TOKEN_FILE="$2"; shift 2;;
  --node-bin) NODE_BIN="$2"; shift 2;; --interval) INTERVAL="$2"; shift 2;;
  *) echo "unknown option $1" >&2; exit 2;; esac; done
[ "$(id -u)" = 0 ] || { echo "run as root (sudo)"; exit 1; }
[ -n "$SERVER" ] || { echo "need --server"; exit 2; }
case "$SERVER" in https://*) ;; *) echo "--server must be an https:// URL"; exit 2;; esac
if [ -z "$TOKEN" ] && [ -n "$TOKEN_FILE" ]; then
  [ -f "$TOKEN_FILE" ] || { echo "token file $TOKEN_FILE not found"; exit 2; }
  IFS= read -r TOKEN < "$TOKEN_FILE" || true
fi
if [ -z "$TOKEN" ]; then
  if [ -t 0 ]; then printf 'one-time enrolment token: ' >&2; IFS= read -r -s TOKEN; echo >&2; else IFS= read -r TOKEN || true; fi
fi
[ -n "$TOKEN" ] || { echo "no enrolment token (pipe it on stdin or use --token-file)"; exit 2; }
[ -x "$NODE_BIN" ] || { echo "node not found (use --node-bin)"; exit 1; }

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"   # agent/ dir
APP=/opt/itam-agent DATA=/var/lib/sentra-itam-agent USER=itam-agent
id "$USER" >/dev/null 2>&1 || useradd --system --home-dir "$DATA" --shell /usr/sbin/nologin "$USER" 2>/dev/null || true
mkdir -p "$APP" "$DATA"
cp -r "$HERE"/*.js "$HERE/collect" "$APP/"
chown -R root:root "$APP"; chmod 755 "$APP"
chown -R "$USER":"$USER" "$DATA" 2>/dev/null || chown -R "$USER" "$DATA"; chmod 700 "$DATA"

echo "enrolling ..."
# token goes to the agent on stdin (printf is a shell builtin: it never appears in the process list)
printf '%s\n' "$TOKEN" | sudo -u "$USER" ITAM_AGENT_DIR="$DATA" "$NODE_BIN" "$APP/agent.js" enrol --server "$SERVER" --token-stdin --dir "$DATA"
TOKEN=""
# a supplied token file is single-use: remove it once enrolment succeeded
if [ -n "$TOKEN_FILE" ]; then (command -v shred >/dev/null 2>&1 && shred -u "$TOKEN_FILE") || rm -f "$TOKEN_FILE"; fi

if command -v systemctl >/dev/null 2>&1; then
  cat > /etc/systemd/system/itam-agent.service <<EOF
[Unit]
Description=Sentra ITAM endpoint agent (outbound-only inventory)
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
User=$USER
Environment=ITAM_AGENT_DIR=$DATA
ExecStart=$NODE_BIN $APP/agent.js once --dir $DATA
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=$DATA
PrivateTmp=yes
EOF
  cat > /etc/systemd/system/itam-agent.timer <<EOF
[Unit]
Description=Run the ITAM endpoint agent periodically
[Timer]
OnBootSec=120
OnUnitActiveSec=${INTERVAL}
Persistent=true
[Install]
WantedBy=timers.target
EOF
  systemctl daemon-reload; systemctl enable --now itam-agent.timer
  echo "installed: systemd timer itam-agent.timer (every ${INTERVAL}s)"
else
  echo "no systemd; add a cron/launchd entry to run: $NODE_BIN $APP/agent.js once --dir $DATA"
fi
