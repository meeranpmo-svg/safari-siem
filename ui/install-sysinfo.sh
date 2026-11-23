#!/bin/bash
# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
# install-sysinfo.sh - install the server-stats job for the portal home page (CPU, memory, storage, city temperature).
# Copies zyb-sysinfo.sh to /usr/local/sbin/zyb-sysinfo, creates /etc/zyb-sysinfo.conf (only if missing) and a systemd
# timer that refreshes /var/www/sentra/dashboards/sysinfo.json every 30 seconds.
#   sudo bash install-sysinfo.sh            install / update
#   sudo bash install-sysinfo.sh --remove   stop and remove (keeps the .conf)
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
HERE="$(cd "$(dirname "$0")" && pwd)"
if [ "${1:-}" = "--remove" ]; then
  systemctl disable --now zyb-sysinfo.timer 2>/dev/null || true
  rm -f /etc/systemd/system/zyb-sysinfo.timer /etc/systemd/system/zyb-sysinfo.service /usr/local/sbin/zyb-sysinfo /usr/local/lib/zyb/zyb-siemstats.js /var/www/sentra/dashboards/sysinfo.json
  systemctl daemon-reload; echo "removed (settings kept in /etc/zyb-sysinfo.conf)"; exit 0
fi
[ -f "$HERE/zyb-sysinfo.sh" ] || { echo "zyb-sysinfo.sh not found next to this script"; exit 1; }
install -m 755 -o root -g root "$HERE/zyb-sysinfo.sh" /usr/local/sbin/zyb-sysinfo
sed -i 's/\r$//' /usr/local/sbin/zyb-sysinfo
install -d -m 755 /usr/local/lib/zyb
[ -f "$HERE/zyb-siemstats.js" ] && install -m 755 -o root -g root "$HERE/zyb-siemstats.js" /usr/local/lib/zyb/zyb-siemstats.js && sed -i 's/\r$//' /usr/local/lib/zyb/zyb-siemstats.js
rm -f /var/cache/zyb-sysinfo/siem.json
if [ ! -f /etc/zyb-sysinfo.conf ]; then
  cat > /etc/zyb-sysinfo.conf <<'CONF'
# Settings for the portal home page server stats (zyb-sysinfo). Change, then wait 30 seconds.
CITY="Riyadh"
LAT="24.7136"
LON="46.6753"
# folders where the SIEM keeps logs (each one's disk is shown as log storage)
LOG_PATHS="/var/lib/clickhouse /opt/sentra-siem /var/log"
# outbound proxy for the temperature lookup, if the server reaches the internet through one, e.g. http://proxy:8080
PROXY=""
CONF
  chmod 644 /etc/zyb-sysinfo.conf
fi
cat > /etc/systemd/system/zyb-sysinfo.service <<'UNIT'
[Unit]
Description=Portal home page server stats (sysinfo.json)
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/zyb-sysinfo
Nice=10
UNIT
cat > /etc/systemd/system/zyb-sysinfo.timer <<'UNIT'
[Unit]
Description=Refresh portal server stats every 30 seconds
[Timer]
OnBootSec=20s
OnUnitActiveSec=30s
AccuracySec=5s
[Install]
WantedBy=timers.target
UNIT
systemctl daemon-reload
systemctl enable --now zyb-sysinfo.timer >/dev/null
/usr/local/sbin/zyb-sysinfo
echo "==> server stats installed; refreshed every 30 s. Current values:"
cat /var/www/sentra/dashboards/sysinfo.json
grep -q '"temp":null' /var/www/sentra/dashboards/sysinfo.json && echo "    (no temperature: the server cannot reach api.open-meteo.com - set PROXY in /etc/zyb-sysinfo.conf, or the page will try from the browser)"
grep -q '"siem":{"error"' /var/www/sentra/dashboards/sysinfo.json && echo "    (SIEM log size: ClickHouse could not be read - see the error above)"
true
