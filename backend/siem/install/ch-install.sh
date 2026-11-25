#!/bin/bash
# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
# Sentra SIEM — ClickHouse (LTS) install for the build/staging host: localhost only, memory-capped, password-protected.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
# no package step may stop to ask a person something: answers are the defaults, the 'restart services?' helper stays out
# of the way, and nothing reads the terminal (a hidden question once left the installer waiting for ever)
export NEEDRESTART_MODE=a NEEDRESTART_SUSPEND=1 UCF_FORCE_CONFOLD=1 APT_LISTCHANGES_FRONTEND=none
APT='apt-get -y -q -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold -o DPkg::Lock::Timeout=300'
mkdir -p /etc/sentra-siem /var/lib/sentra-siem && chmod 700 /etc/sentra-siem
if ! command -v clickhouse-server >/dev/null 2>&1; then
  $APT install apt-transport-https ca-certificates curl gnupg </dev/null >/dev/null
  curl -fsSL --connect-timeout 20 --max-time 120 'https://packages.clickhouse.com/rpm/lts/repodata/repomd.xml.key' | gpg --dearmor --yes -o /usr/share/keyrings/clickhouse-keyring.gpg
  [ -s /usr/share/keyrings/clickhouse-keyring.gpg ] || { echo "could not fetch the ClickHouse signing key (does the server reach packages.clickhouse.com on 443?)" >&2; exit 1; }
  echo "deb [signed-by=/usr/share/keyrings/clickhouse-keyring.gpg] https://packages.clickhouse.com/deb lts main" > /etc/apt/sources.list.d/clickhouse.list
  $APT update </dev/null >/dev/null
  echo "    downloading and installing ClickHouse (several hundred MB - this is the slow step; progress: tail -f /var/log/dpkg.log)"
  $APT install clickhouse-server clickhouse-client </dev/null 2>&1 | grep -E '^(Get:|Fetched|Setting up|Unpacking|E:|W:)' || true
  command -v clickhouse-server >/dev/null 2>&1 || { echo "ClickHouse did not install (see the lines above)" >&2; exit 1; }
fi
# secrets (generated once, never printed). Two ClickHouse users:
#   sentra_siem        the engine at runtime: SELECT + INSERT on siem.* only (cannot ALTER, DELETE or DROP stored events)
#   sentra_siem_admin  schema migrations only (engine/store/migrate.js): full rights on siem.*
# The stock `default` user (no password after a non-interactive install) is removed.
if [ ! -f /etc/sentra-siem/secrets.json ]; then
  printf '{"clickhouse":{"user":"sentra_siem","password":"%s"},"ingest_tokens":{}}\n' "$(openssl rand -hex 24)" > /etc/sentra-siem/secrets.json
  chmod 600 /etc/sentra-siem/secrets.json
fi
# secrets.json may be sealed (engine/secretfile.js): read / write it through that module, values never on a command line
SFJ="$(cd "$(dirname "$0")/.." && pwd)/engine/secretfile.js"; [ -f "$SFJ" ] || SFJ=/opt/sentra-siem/engine/secretfile.js
NODE_SF="$(command -v node || echo /opt/sentra-ai/node/bin/node)"
sget() { "$NODE_SF" "$SFJ" get "$1"; }
if ! sget clickhouse_admin.password >/dev/null 2>&1; then printf '{"clickhouse_admin":{"user":"sentra_siem_admin","password":"%s"}}' "$(openssl rand -hex 24)" | "$NODE_SF" "$SFJ" merge >/dev/null; fi
chmod 600 /etc/sentra-siem/secrets.json
PW=$(sget clickhouse.password)
APW=$(sget clickhouse_admin.password)
HASH=$(printf '%s' "$PW" | sha256sum | cut -d' ' -f1)
AHASH=$(printf '%s' "$APW" | sha256sum | cut -d' ' -f1)
# credentials go to curl on stdin, never on the command line (visible in ps)
chq() { printf 'user = "sentra_siem_admin:%s"\n' "$APW" | curl -s --max-time 30 -K - "http://127.0.0.1:8123/?query=$1"; }
cat > /etc/clickhouse-server/config.d/sentra-siem.xml <<'XML'
<clickhouse>
  <listen_host>127.0.0.1</listen_host>
  <max_server_memory_usage>2684354560</max_server_memory_usage>
  <mark_cache_size>268435456</mark_cache_size>
  <uncompressed_cache_size>0</uncompressed_cache_size>
  <max_concurrent_queries>50</max_concurrent_queries>
  <logger><level>warning</level><size>100M</size><count>3</count></logger>
</clickhouse>
XML
cat > /etc/clickhouse-server/users.d/sentra-siem.xml <<XML
<clickhouse>
  <users>
    <default remove="remove"/>
    <sentra_siem>
      <password_sha256_hex>${HASH}</password_sha256_hex>
      <networks><ip>127.0.0.1</ip><ip>::1</ip></networks>
      <profile>default</profile><quota>default</quota>
      <access_management>0</access_management>
      <grants><query>GRANT SELECT, INSERT ON siem.*</query></grants>
    </sentra_siem>
    <sentra_siem_admin>
      <password_sha256_hex>${AHASH}</password_sha256_hex>
      <networks><ip>127.0.0.1</ip><ip>::1</ip></networks>
      <profile>default</profile><quota>default</quota>
      <access_management>0</access_management>
      <grants><query>GRANT ALL ON siem.*</query><query>GRANT CREATE DATABASE ON *.*</query></grants>
    </sentra_siem_admin>
  </users>
  <profiles><default><max_memory_usage>1500000000</max_memory_usage><max_execution_time>60</max_execution_time></default></profiles>
</clickhouse>
XML
chmod 640 /etc/clickhouse-server/users.d/sentra-siem.xml; chown root:clickhouse /etc/clickhouse-server/users.d/sentra-siem.xml
systemctl enable clickhouse-server >/dev/null 2>&1
systemctl restart clickhouse-server
for i in $(seq 1 30); do curl -s http://127.0.0.1:8123/ping >/dev/null 2>&1 && break; sleep 1; done
chq 'CREATE%20DATABASE%20IF%20NOT%20EXISTS%20siem' && echo "db ok"
echo "version: $(chq 'SELECT%20version()')"
ss -lntp | grep -E ':(8123|9000|9009) ' | awk '{print "listen", $4}'
systemctl is-active clickhouse-server
