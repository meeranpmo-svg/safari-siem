#!/bin/bash
# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
# Sentra SIEM - remove the engine.
#
#   sudo ./uninstall.sh                     stop + remove service, code, helper; KEEP config, secrets, data, ClickHouse data
#   sudo ./uninstall.sh --purge             also delete /etc/sentra-siem, /var/lib/sentra-siem (state: alerts, cases, audit!)
#                                           and the sentra-siem user
#   sudo ./uninstall.sh --purge --drop-database --yes
#                                           also DROP the ClickHouse database `siem` (all stored events!)
#
# ClickHouse itself (package, config in /etc/clickhouse-server/*.d/sentra-siem.xml) is left installed; remove it with
# `apt-get purge clickhouse-server clickhouse-client` if it is not used by anything else.
# Before purging on a production system: export what auditors may need (cases, audit journal, events) - see
# docs/OPERATOR-GUIDE.md "Backup".
set -euo pipefail

PURGE=0 DROP_DB=0 YES=0
while [ $# -gt 0 ]; do
  case "$1" in
    --purge)         PURGE=1; shift ;;
    --drop-database) DROP_DB=1; shift ;;
    --yes)           YES=1; shift ;;
    -h|--help)       sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *)               echo "unknown option: $1" >&2; exit 2 ;;
  esac
done
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }
if [ "$DROP_DB" = 1 ] && [ "$PURGE" = 0 ]; then echo "--drop-database requires --purge" >&2; exit 2; fi

confirm() {
  [ "$YES" = 1 ] && return 0
  local ans
  read -r -p "$1 Type YES to continue: " ans
  [ "$ans" = "YES" ]
}

if [ "$PURGE" = 1 ]; then
  confirm "This permanently deletes SIEM configuration, secrets and workflow state (alerts, cases, audit journal)." \
    || { echo "aborted"; exit 1; }
fi

echo "==> stopping sentra-siem"
if systemctl list-unit-files sentra-siem.service >/dev/null 2>&1; then
  systemctl disable --now sentra-siem.service >/dev/null 2>&1 || true
fi
rm -f /etc/systemd/system/sentra-siem.service
rm -rf /etc/systemd/system/sentra-siem.service.d
systemctl daemon-reload
systemctl reset-failed sentra-siem.service >/dev/null 2>&1 || true

if [ "$DROP_DB" = 1 ]; then
  SFJ=/opt/sentra-siem/engine/secretfile.js; NODE_SF="$(command -v node || echo /opt/sentra-ai/node/bin/node)"
  sget() { "$NODE_SF" "$SFJ" get "$1" 2>/dev/null; }
  if [ -r /etc/sentra-siem/secrets.json ] && [ -f "$SFJ" ] && command -v curl >/dev/null 2>&1; then
    echo "==> dropping ClickHouse database siem"
    # the migration user owns DDL (older installs: the engine user)
    CU="$(sget clickhouse_admin.user || sget clickhouse.user)"
    PW="$(sget clickhouse_admin.password || sget clickhouse.password)"
    # credentials via stdin config, not argv (argv is visible in ps)
    printf 'user = "%s:%s"\n' "$CU" "$PW" | curl -fsS -K - --data-binary 'DROP DATABASE IF EXISTS siem' 'http://127.0.0.1:8123/' \
      || echo "warning: could not drop database siem (is clickhouse-server running?)" >&2
    unset PW
  else
    echo "warning: cannot drop the database (secrets.json, python3 or curl missing)" >&2
  fi
fi

echo "==> removing code and helpers"
rm -rf /opt/sentra-siem /opt/sentra-siem.prev /opt/sentra-siem.new
rm -f /usr/local/sbin/sentra-siem-token /usr/local/sbin/sentra-siem-validate /etc/default/sentra-siem

if [ "$PURGE" = 1 ]; then
  echo "==> purging configuration, secrets and data"
  rm -rf /etc/sentra-siem /var/lib/sentra-siem
  # the nginx include holds the nginx->engine proxy secret
  rm -f /etc/nginx/sentra-siem-proxy-secret.conf
  if id sentra-siem >/dev/null 2>&1; then userdel sentra-siem 2>/dev/null || true; fi
  getent group sentra-siem >/dev/null 2>&1 && groupdel sentra-siem 2>/dev/null || true
  echo "note: remove the nginx include (install/nginx-soc.conf) and /etc/nginx/conf.d/sentra-siem-http.conf, then reload nginx"
  echo "note: all ingest tokens were deleted with secrets.json; uninstall the Windows/Exchange agents and relays too"
else
  echo "kept: /etc/sentra-siem (config, secrets), /var/lib/sentra-siem (state, spool), ClickHouse database siem"
fi
echo "sentra-siem removed."
