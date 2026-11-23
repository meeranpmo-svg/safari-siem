#!/usr/bin/env bash
# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
# install-collector.sh - install the Sentra SIEM Oracle collector on the DATABASE HOST (Linux; Solaris: see README).
#   sudo bash install-collector.sh [--user oracle] [--start]     install / update (safe to re-run; keeps the config)
#   sudo bash install-collector.sh --uninstall                   stop and remove the service and program (keeps /etc/sentra-oracle)
# Files: program /opt/sentra-oracle, config /etc/sentra-oracle (owner = the Oracle user, 700), state /var/lib/sentra-oracle.
# Asks for the SIEM ingest token (hidden) when /etc/sentra-oracle/token does not exist yet. Nothing in the database changes.
set -euo pipefail
OUSER=oracle; START=0; UNINSTALL=0
while [ $# -gt 0 ]; do case "$1" in --user) OUSER="$2"; shift 2 ;; --start) START=1; shift ;; --uninstall) UNINSTALL=1; shift ;; *) echo "unknown option $1"; exit 2 ;; esac; done
[ "$(id -u)" = 0 ] || { echo "run with sudo / as root"; exit 1; }
HERE="$(cd "$(dirname "$0")" && pwd)"; APP=/opt/sentra-oracle; ETC=/etc/sentra-oracle; VAR=/var/lib/sentra-oracle; UNIT=/etc/systemd/system/sentra-oracle-collector.service
say() { echo "==> $*"; }
if [ "$UNINSTALL" = 1 ]; then
  if command -v systemctl >/dev/null 2>&1 && [ -f "$UNIT" ]; then systemctl disable --now sentra-oracle-collector 2>/dev/null || true; rm -f "$UNIT"; systemctl daemon-reload; fi
  rm -rf "$APP"; say "removed the collector ($ETC and $VAR kept - delete them by hand if no longer needed)"; exit 0
fi
id "$OUSER" >/dev/null 2>&1 || { echo "user $OUSER does not exist (give the Oracle software owner with --user)"; exit 1; }
OGROUP="$(id -gn "$OUSER")"
for t in curl gzip awk sed; do command -v "$t" >/dev/null 2>&1 || { echo "missing $t"; exit 1; }; done

say "program -> $APP"
mkdir -p "$APP"
for f in sentra-oracle-collector.sh collect.sql collect-perf.sql collect-pack.sql create-monitor-user.sql collector.conf.example README.md; do
  [ -f "$HERE/$f" ] || { echo "missing $HERE/$f - copy the whole agents/oracle folder"; exit 1; }
  sed 's/\r$//' "$HERE/$f" > "$APP/$f"   # a Windows copy may have added CR
done
chown -R root:root "$APP"; chmod 755 "$APP" "$APP/sentra-oracle-collector.sh"; chmod 644 "$APP"/*.sql "$APP/collector.conf.example" "$APP/README.md"
bash -n "$APP/sentra-oracle-collector.sh"

say "config -> $ETC (owner $OUSER)"
mkdir -p "$ETC" "$VAR"; chown "$OUSER:$OGROUP" "$ETC" "$VAR"; chmod 700 "$ETC" "$VAR"
if [ ! -f "$ETC/collector.conf" ]; then install -m 600 -o "$OUSER" -g "$OGROUP" "$APP/collector.conf.example" "$ETC/collector.conf"; say "wrote $ETC/collector.conf from the example - EDIT IT (ORACLE_HOME, ORACLE_SID, DB_CONNECT, SOURCE_ID, CA_FILE)"; fi
if [ ! -s "$ETC/token" ]; then
  if [ -t 0 ]; then
    read -r -s -p "SIEM ingest token for this source (Log Sources > the Oracle source; hidden): " TOK; echo
    if [ "${#TOK}" -ge 16 ]; then (umask 077; printf '%s\n' "$TOK" > "$ETC/token"); chown "$OUSER:$OGROUP" "$ETC/token"; chmod 600 "$ETC/token"; say "token saved to $ETC/token (600)"; else echo "   no token saved - put it in $ETC/token (mode 600, owner $OUSER) later"; fi
    TOK=''
  else echo "   put the ingest token in $ETC/token (mode 600, owner $OUSER)"; fi
fi

if command -v systemctl >/dev/null 2>&1; then
  say "service sentra-oracle-collector (runs as $OUSER)"
  cat > "$UNIT" <<EOF
[Unit]
Description=Sentra SIEM Oracle collector (health, performance, audit)
After=network-online.target
[Service]
Type=simple
User=$OUSER
Environment=SENTRA_ORA_CONF=$ETC/collector.conf
ExecStart=$APP/sentra-oracle-collector.sh --loop
Restart=always
RestartSec=30
NoNewPrivileges=true
ProtectSystem=full
ReadWritePaths=$VAR
[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload; systemctl enable sentra-oracle-collector >/dev/null 2>&1 || true
  if [ "$START" = 1 ]; then systemctl restart sentra-oracle-collector; say "started ($(systemctl is-active sentra-oracle-collector))"; else echo "   enabled, not started: test first, then  sudo systemctl start sentra-oracle-collector"; fi
else
  echo "   no systemd: add to $OUSER's crontab:   * * * * * $APP/sentra-oracle-collector.sh --once"
fi
echo
echo "Next:"
echo "  1. DBA, as SYSDBA (in a CDB: inside the PDB):  @$APP/create-monitor-user.sql   then put the password in $ETC/db-password (600, owner $OUSER)"
echo "  2. edit $ETC/collector.conf"
echo "  3. test as $OUSER:   sudo -u $OUSER $APP/sentra-oracle-collector.sh --test"
echo "  4. start:            sudo systemctl start sentra-oracle-collector"
