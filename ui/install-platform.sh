#!/bin/bash
# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
# install-platform.sh - server health monitoring + encrypted backup / restore of the whole platform, for the
# "Platform Health & Backup" dashboard (/dashboards/platform.html).
#   sudo bash install-platform.sh            install / update (safe to re-run; keeps settings and the backup key)
#   sudo bash install-platform.sh --remove   stop and remove the timers and programs (keeps settings, key and backups)
# Installs:
#   zyb-health   (/usr/local/lib/zyb/zyb-health.js, timer every minute)  → /var/www/sentra/dashboards/health.json
#   zyb-backup   (/usr/local/sbin/zyb-backup, nightly 01:30 + "Run backup now")   settings /etc/zyb-backup.conf
#   zyb-restore  (/usr/local/sbin/zyb-restore)   list / verify / extract / apply / events
#   the backup key /etc/zyb-backup/backup.key (created once, root only) - COPY IT OFF THIS SERVER
#   zyb-svcctl   (/usr/local/lib/zyb/zyb-svcctl.js, zyb-svcctl.path) start / stop / restart of listed services from the
#                portal (administrators); list in /etc/zyb-svcctl.conf, history in /var/lib/zyb-svcctl/history.json
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
HERE="$(cd "$(dirname "$0")" && pwd)"
say() { echo "==> $*"; }
if [ "${1:-}" = "--remove" ]; then
  systemctl disable --now zyb-health.timer zyb-backup.timer zyb-backup.path zyb-backup-settings.path zyb-svcctl.path 2>/dev/null || true
  rm -f /etc/systemd/system/zyb-svcctl.{service,path} /usr/local/lib/zyb/zyb-svcctl.js
  rm -f /etc/systemd/system/zyb-health.{service,timer} /etc/systemd/system/zyb-backup.{service,timer,path} /etc/systemd/system/zyb-backup-settings.{service,path} /usr/local/sbin/zyb-health /usr/local/sbin/zyb-backup /usr/local/sbin/zyb-restore /usr/local/lib/zyb/zyb-health.js
  systemctl daemon-reload; echo "removed (kept /etc/zyb-backup.conf, /etc/zyb-backup/backup.key and the backups in /var/backups/zyb)"; exit 0
fi
for f in zyb-health.js zyb-health-io.js zyb-backup.sh zyb-restore.sh zyb-svcctl.js; do [ -f "$HERE/$f" ] || { echo "$f not found next to this script"; exit 1; }; done

NODE="$(systemctl show -p ExecStart --value sentra-siem 2>/dev/null | sed -n 's/.*argv\[\]=\([^ ;]*\).*/\1/p' | head -n1)"
[ -x "${NODE:-}" ] || NODE=/opt/sentra-ai/node/bin/node; [ -x "$NODE" ] || NODE="$(command -v node || true)"
[ -x "${NODE:-}" ] || { echo "Node.js not found"; exit 1; }
install -d -m 755 /usr/local/lib/zyb; echo "$NODE" > /usr/local/lib/zyb/node-path

say "health monitor"
install -m 755 "$HERE/zyb-health.js" /usr/local/lib/zyb/zyb-health.js; sed -i 's/\r$//' /usr/local/lib/zyb/zyb-health.js
install -m 644 "$HERE/zyb-health-io.js" /usr/local/lib/zyb/zyb-health-io.js; sed -i 's/\r$//' /usr/local/lib/zyb/zyb-health-io.js
printf '#!/bin/sh\nexec "%s" /usr/local/lib/zyb/zyb-health.js "$@"\n' "$NODE" > /usr/local/sbin/zyb-health; chmod 755 /usr/local/sbin/zyb-health
[ -f /etc/zyb-health.conf ] || cat > /etc/zyb-health.conf <<'CONF'
{
  "disk_warn": 85, "disk_crit": 95, "inode_warn": 85, "temp_warn": 80, "temp_crit": 90, "cert_warn_days": 30, "backup_max_h": 26,
  "services": ["sentra-siem", "sentra-itam", "sentra-auth", "clickhouse-server", "nginx", "docker"],
  "containers": ["noc-m365"],
  "cert": ""
}
CONF
cat > /etc/systemd/system/zyb-health.service <<'UNIT'
[Unit]
Description=Platform server health (health.json for the Platform Health & Backup dashboard)
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/zyb-health
Nice=10
TimeoutStartSec=90
UNIT
cat > /etc/systemd/system/zyb-health.timer <<'UNIT'
[Unit]
Description=Platform server health every minute
[Timer]
OnBootSec=1min
OnUnitActiveSec=60s
AccuracySec=10s
[Install]
WantedBy=timers.target
UNIT

say "backup"
for f in zyb-backup zyb-restore; do install -m 750 "$HERE/$f.sh" /usr/local/sbin/$f; sed -i 's/\r$//' /usr/local/sbin/$f; done
install -d -m 700 /etc/zyb-backup /var/backups/zyb; install -d -m 755 /var/lib/zyb-backup
if [ ! -s /etc/zyb-backup/backup.key ]; then
  umask 077; openssl rand -base64 48 > /etc/zyb-backup/backup.key; chmod 600 /etc/zyb-backup/backup.key; NEWKEY=1
fi
[ -f /etc/zyb-backup.conf ] || cat > /etc/zyb-backup.conf <<'CONF'
# Platform backup settings (zyb-backup). Run a backup now: sudo zyb-backup   ·   restore: sudo zyb-restore
DEST=/var/backups/zyb          # where the encrypted backups are kept on this server
KEEP_DAYS=14                   # delete backups older than this ...
KEEP_MIN=3                     # ... but always keep at least this many
# Copy every backup OFF this server (strongly recommended - a backup on the same disk is lost with the server):
REMOTE_DIR=""                  # a mounted network share or disk under /mnt, /media, /srv or /backup, e.g. /mnt/backup (fstab)
SFTP_TARGET=""                 # or user@backup-server:/backups/sentra  (key login, no password)
SFTP_KEY=""                    # private key for SFTP, e.g. /root/.ssh/zyb_backup
CH_EVENT_DAYS=0                # also save the SIEM log events of the last N days (0 = only table definitions; events are large)
VERIFY=1                       # read every new backup back to prove it can be restored
EXTRA_PATHS=""                 # more folders to include, space separated
CONF
chmod 600 /etc/zyb-backup.conf
cat > /etc/systemd/system/zyb-backup.service <<'UNIT'
[Unit]
Description=Platform backup (zyb-backup)
After=network-online.target
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/zyb-backup
Nice=10
IOSchedulingClass=idle
TimeoutStartSec=6h
UNIT
cat > /etc/systemd/system/zyb-backup.timer <<'UNIT'
[Unit]
Description=Nightly platform backup
[Timer]
OnCalendar=*-*-* 01:30
RandomizedDelaySec=10min
Persistent=true
[Install]
WantedBy=timers.target
UNIT
cat > /etc/systemd/system/zyb-backup.path <<'UNIT'
[Unit]
Description=Run the platform backup when requested from the portal ("Run backup now")
[Path]
PathExists=/var/lib/sentra-siem/platform/backup-request
Unit=zyb-backup.service
[Install]
WantedBy=paths.target
UNIT
cat > /etc/systemd/system/zyb-backup-settings.service <<'UNIT'
[Unit]
Description=Apply backup settings changed in the portal (Platform Health & Backup > Backup settings)
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/zyb-backup --apply-settings
TimeoutStartSec=2min
UNIT
cat > /etc/systemd/system/zyb-backup-settings.path <<'UNIT'
[Unit]
Description=Watch for backup settings changed in the portal
[Path]
PathExists=/var/lib/sentra-siem/platform/backup-settings.json
Unit=zyb-backup-settings.service
[Install]
WantedBy=paths.target
UNIT
say "service control (start / stop / restart from the portal)"
install -m 755 "$HERE/zyb-svcctl.js" /usr/local/lib/zyb/zyb-svcctl.js; sed -i 's/\r$//' /usr/local/lib/zyb/zyb-svcctl.js
install -d -m 755 /var/lib/zyb-svcctl
[ -f /etc/zyb-svcctl.conf ] || cat > /etc/zyb-svcctl.conf <<'CONF'
{
  "allow": ["sentra-itam", "sentra-siem", "sentra-infra", "clickhouse-server", "nginx", "docker", "zyb-sysinfo.timer", "zyb-health.timer", "zyb-backup.timer"],
  "no_stop": ["sentra-siem", "nginx"]
}
CONF
chmod 644 /etc/zyb-svcctl.conf
cat > /etc/systemd/system/zyb-svcctl.service <<UNIT
[Unit]
Description=Start / stop / restart a platform service requested from the portal (Platform Health > Services)
[Service]
Type=oneshot
ExecStart=$NODE /usr/local/lib/zyb/zyb-svcctl.js
TimeoutStartSec=5min
UNIT
cat > /etc/systemd/system/zyb-svcctl.path <<'UNIT'
[Unit]
Description=Watch for service start / stop / restart requests from the portal
[Path]
PathExists=/var/lib/sentra-siem/platform/svc-request
Unit=zyb-svcctl.service
[Install]
WantedBy=paths.target
UNIT
systemctl daemon-reload
systemctl enable --now zyb-health.timer zyb-backup.timer zyb-backup.path zyb-backup-settings.path zyb-svcctl.path >/dev/null 2>&1
/usr/local/sbin/zyb-backup --write-settings >/dev/null 2>&1 || true   # current settings for the portal page
systemctl start zyb-health.service || true

if ! command -v smartctl >/dev/null && [ "$(systemd-detect-virt 2>/dev/null || echo none)" = none ]; then
  echo "   tip: install smartmontools for disk health (SMART): sudo dnf install -y smartmontools  or  sudo apt-get install -y smartmontools"
fi
command -v zstd >/dev/null || echo "   tip: install zstd for smaller, faster backups (gzip is used until then)"
say "installed: health every minute, backup nightly at 01:30 (next: $(systemctl show zyb-backup.timer -p NextElapseUSecRealtime --value 2>/dev/null))"
if [ "${NEWKEY:-}" = 1 ]; then
  echo ""
  echo "   !! A new backup key was created: /etc/zyb-backup/backup.key"
  echo "   !! Copy that file to a safe place OFF this server (password vault / sealed USB). Without it NO backup can be restored."
  echo "   !! Key fingerprint (to recognise the right copy later): $(sha256sum /etc/zyb-backup/backup.key | cut -c1-16)"
fi
grep -q '^REMOTE_DIR=""' /etc/zyb-backup.conf && grep -q '^SFTP_TARGET=""' /etc/zyb-backup.conf && echo "   note: backups stay on this server until a copy target is set (Platform Health & Backup > Backup settings)"
exit 0
