#!/bin/bash
# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
# netops-setup.sh - prepare the server for the AI Network Engineer (docs/NETOPS.md). Run from the repository folder.
#   sudo bash install/netops-setup.sh                 install the bundled Anthropic SDK (offline), check ping, migrate schema
#   sudo bash install/netops-setup.sh --set-key       also store the Anthropic API key (typed, not echoed) in secrets.json
#   sudo bash install/netops-setup.sh --proxy http://proxy.local:8080   let the engine reach api.anthropic.com via a proxy
#   sudo bash install/netops-setup.sh --restart       restart sentra-siem at the end
# Nothing here touches network devices. The SDK goes to /opt/sentra-siem/vendor (root-owned, read-only for the service).
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
HERE="$(cd "$(dirname "$0")" && pwd)"; APP=/opt/sentra-siem; ETC=/etc/sentra-siem; SVC=sentra-siem
SETKEY=0; PROXY=""; RESTART=0
while [ $# -gt 0 ]; do case "$1" in --set-key) SETKEY=1;; --proxy) PROXY="${2:-}"; shift;; --restart) RESTART=1;; *) echo "unknown option $1"; exit 1;; esac; shift; done
NODE_BIN="$(command -v node || true)"; [ -n "$NODE_BIN" ] || { echo "node not found"; exit 1; }
say() { echo "==> $*"; }

# 1. bundled SDK (pinned, checksum verified)
TGZ="$HERE/vendor/anthropic-sdk-0.133.0.tgz"
[ -f "$TGZ" ] || { echo "missing $TGZ - copy the whole repository"; exit 1; }
(cd "$HERE/vendor" && sha256sum -c anthropic-sdk-0.133.0.tgz.sha256 >/dev/null) || { echo "SDK bundle checksum mismatch - not installing"; exit 1; }
rm -rf "$APP/vendor.new"; mkdir -p "$APP/vendor.new"; tar -xzf "$TGZ" -C "$APP/vendor.new" --no-same-owner
chown -R root:root "$APP/vendor.new"; find "$APP/vendor.new" -type d -exec chmod 755 {} +; find "$APP/vendor.new" -type f -exec chmod 644 {} +
rm -rf "$APP/vendor.old"; [ -d "$APP/vendor" ] && mv "$APP/vendor" "$APP/vendor.old"; mv "$APP/vendor.new" "$APP/vendor"; rm -rf "$APP/vendor.old"
runuser -u "$SVC" -- "$NODE_BIN" -e "require('$APP/vendor/node_modules/@anthropic-ai/sdk'); console.log('    SDK loads for the service user')"
say "Anthropic SDK 0.133.0 installed in $APP/vendor"

# 2. API key → secrets.json netops.anthropic_api_key (sealed at rest, atomic, no plaintext copy; key via stdin, not argv)
if [ "$SETKEY" = 1 ]; then
  read -r -s -p "Anthropic API key (input hidden): " KEY; echo
  case "$KEY" in sk-ant-*) ;; *) echo "that does not look like an Anthropic API key (sk-ant-...)"; exit 1;; esac
  SFJ="$APP/engine/secretfile.js"; [ -f "$SFJ" ] || SFJ="$(cd "$(dirname "$0")/.." && pwd)/engine/secretfile.js"
  # secretfile.js refuses a symlinked secrets.json and writes through O_EXCL temp files
  printf '%s' "$KEY" | SENTRA_SIEM_SECRETS="$ETC/secrets.json" "$NODE_BIN" "$SFJ" set netops.anthropic_api_key >/dev/null || { unset KEY; echo "could not store the key"; exit 1; }
  unset KEY; say "API key stored in $ETC/secrets.json (netops.anthropic_api_key)"
fi

# 3. outbound proxy for the engine (only api.anthropic.com is contacted by the AI assistant)
if [ -n "$PROXY" ]; then
  case "$PROXY" in http://*|https://*) ;; *) echo "proxy must start with http:// or https://"; exit 1;; esac
  touch /etc/default/sentra-siem; chmod 640 /etc/default/sentra-siem
  sed -i '/^HTTPS_PROXY=/d;/^NODE_USE_ENV_PROXY=/d;/^NO_PROXY=/d' /etc/default/sentra-siem
  printf 'HTTPS_PROXY=%s\nNODE_USE_ENV_PROXY=1\nNO_PROXY=127.0.0.1,localhost,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16\n' "$PROXY" >> /etc/default/sentra-siem
  NV="$("$NODE_BIN" -p 'process.versions.node')"
  "$NODE_BIN" -e 'const [a,b]=process.versions.node.split(".").map(Number); process.exit(a>=24||(a===22&&b>=21)?0:1)' \
    || echo "    WARNING: Node $NV does not honour NODE_USE_ENV_PROXY (needs 22.21+ or 24+); upgrade Node or allow direct HTTPS to api.anthropic.com"
  say "proxy set in /etc/default/sentra-siem"
fi

# 4. can the service ping? (reachability checks)
if runuser -u "$SVC" -- ping -n -c 1 -W 1 127.0.0.1 >/dev/null 2>&1; then say "ping works for the $SVC user"
else echo "    WARNING: the $SVC user cannot ping. Fix with:  sudo setcap cap_net_raw+p \$(command -v ping)   (or sysctl net.ipv4.ping_group_range)"; fi

# 5. schema (adds siem.net_metrics; idempotent)
if [ -f "$APP/engine/store/migrate.js" ]; then
  (cd "$APP" && runuser -u "$SVC" -- env SENTRA_SIEM_CONFIG="$ETC/config.json" "$NODE_BIN" engine/store/migrate.js) && say "ClickHouse schema migrated" || echo "    WARNING: migration failed - see the message above"
fi
[ -f "$APP/engine/netops/routes.js" ] || echo "    NOTE: $APP/engine/netops is not deployed yet - deploy the engine first (docs/NETOPS.md, Deploy)"
if [ "$RESTART" = 1 ]; then systemctl restart "$SVC"; sleep 3; systemctl is-active --quiet "$SVC" && say "sentra-siem restarted" || { echo "sentra-siem failed to start: journalctl -u sentra-siem -n 50"; exit 1; }; fi
say "done. Open the portal → Dashboards → AI Network Engineer"
