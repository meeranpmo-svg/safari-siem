#!/bin/bash
# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
# Sentra SIEM - install / upgrade the engine on Ubuntu 22.04 / 24.04.
#
#   sudo ./install/install.sh [options]          (run from the unpacked sentra-siem/ package; re-run = upgrade)
#
# Options:
#   --node-bin PATH        Node.js >= 20 binary (default: $NODE_BIN, else /opt/sentra-ai/node/bin/node, else `node`)
#   --listen-lan [IP]      bind the syslog listeners to the LAN IP (auto-detected from the default route if IP omitted)
#                          instead of 127.0.0.1. The API always stays on 127.0.0.1 (nginx fronts it).
#   --syslog-port N        plain syslog UDP+TCP port (default 5514). A port < 1024 adds CAP_NET_BIND_SERVICE.
#   --tls-cert F --tls-key F   install a certificate for syslog-over-TLS (6514) and enable that listener
#   --tokens "a b c"       ingest token source ids to create if missing (default: "win-servers win-dc")
#   --retention-days N     ClickHouse TTL written into a NEW config (default 365)
#   --with-clickhouse      run install/ch-install.sh first when ClickHouse is not installed yet
#   --no-migrate           skip `node engine/store/migrate.js`
#   --no-start             install everything but do not (re)start the service
#   -h | --help
#
# Layout: /opt/sentra-siem (code, root-owned, read-only for the service), /var/lib/sentra-siem/{state,spool} (data),
# /etc/sentra-siem (700: config.json, secrets.json 600, tls/), /etc/default/sentra-siem (env), systemd unit sentra-siem.service,
# /usr/local/sbin/sentra-siem-token. Existing config.json / secrets.json are never overwritten (only merged).
set -euo pipefail
umask 022

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_ROOT="$(cd "$HERE/.." && pwd)"
APP=/opt/sentra-siem
DATA=/var/lib/sentra-siem
ETC=/etc/sentra-siem
ENVF=/etc/default/sentra-siem
UNIT=/etc/systemd/system/sentra-siem.service
DROPIN_DIR=/etc/systemd/system/sentra-siem.service.d
SVC_USER=sentra-siem

NODE_BIN_OPT="${NODE_BIN:-}"
LISTEN_LAN=0 LAN_IP="" SYSLOG_PORT="" TLS_CERT="" TLS_KEY="" TOKENS="win-servers win-dc" RETENTION=365
WITH_CH=0 MIGRATE=1 START=1

say()  { printf '\033[1m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[33mwarning:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }
usage() { sed -n '2,22p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }
is_ipv4() { [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; }

while [ $# -gt 0 ]; do
  case "$1" in
    --node-bin)        NODE_BIN_OPT="${2:-}"; shift 2 ;;
    --listen-lan)      LISTEN_LAN=1; if [ $# -ge 2 ] && is_ipv4 "${2:-}"; then LAN_IP="$2"; shift; fi; shift ;;
    --syslog-port)     SYSLOG_PORT="${2:-}"; shift 2 ;;
    --tls-cert)        TLS_CERT="${2:-}"; shift 2 ;;
    --tls-key)         TLS_KEY="${2:-}"; shift 2 ;;
    --tokens)          TOKENS="${2:-}"; shift 2 ;;
    --retention-days)  RETENTION="${2:-}"; shift 2 ;;
    --with-clickhouse) WITH_CH=1; shift ;;
    --no-migrate)      MIGRATE=0; shift ;;
    --no-start)        START=0; shift ;;
    -h|--help)         usage 0 ;;
    *)                 echo "unknown option: $1" >&2; usage 2 ;;
  esac
done

# ---------------------------------------------------------------------------------------------------------------
# 0. preflight
# ---------------------------------------------------------------------------------------------------------------
[ "$(id -u)" = 0 ] || die "run as root (sudo $0 ...)"
[ -f "$SRC_ROOT/engine/main.js" ] || die "engine/main.js not found under $SRC_ROOT - run this script from the unpacked package"
[ -f "$HERE/setup-json.js" ] && [ -f "$HERE/sentra-siem.service" ] && [ -f "$HERE/sentra-siem-token" ] || die "install/ is incomplete"
if [ -r /etc/os-release ]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  case "${ID:-}:${VERSION_ID:-}" in
    ubuntu:22.04|ubuntu:24.04) ;;
    *) warn "tested on Ubuntu 22.04/24.04 only (this is ${PRETTY_NAME:-unknown}) - continuing" ;;
  esac
fi
command -v systemctl >/dev/null 2>&1 || die "systemd is required"
if ! [[ "$RETENTION" =~ ^[0-9]+$ ]] || [ "$RETENTION" -lt 1 ]; then die "invalid --retention-days '$RETENTION'"; fi
if [ -n "$SYSLOG_PORT" ]; then
  if ! [[ "$SYSLOG_PORT" =~ ^[0-9]+$ ]] || [ "$SYSLOG_PORT" -lt 1 ] || [ "$SYSLOG_PORT" -gt 65535 ]; then die "invalid --syslog-port"; fi
fi
if [ -n "$TLS_CERT$TLS_KEY" ]; then
  if [ ! -r "$TLS_CERT" ] || [ ! -r "$TLS_KEY" ]; then die "--tls-cert and --tls-key must both be readable files"; fi
fi
for t in $TOKENS; do [[ "$t" =~ ^[A-Za-z0-9_.-]{1,64}$ ]] || die "invalid token source id '$t'"; done

# Node.js
if [ -z "$NODE_BIN_OPT" ]; then
  if [ -x /opt/sentra-ai/node/bin/node ]; then NODE_BIN_OPT=/opt/sentra-ai/node/bin/node
  else NODE_BIN_OPT="$(command -v node || true)"; fi
fi
if [ -z "$NODE_BIN_OPT" ] || [ ! -x "$NODE_BIN_OPT" ]; then die "Node.js not found - pass --node-bin /path/to/node (>= 20)"; fi
# Running as root, only execute a Node.js binary that no other account can replace: the binary and every
# directory above it must be owned by root and not group/world-writable (the default runtime lives in another
# product's tree, /opt/sentra-ai, whose service account must not be able to gain root through us).
trusted_bin() {
  local p
  p="$(readlink -f "$1" 2>/dev/null)" || return 1
  [ -x "$p" ] || return 1
  while [ -n "$p" ] && [ "$p" != "/" ]; do
    [ "$(stat -c %u "$p")" = 0 ] || return 1
    case "$(stat -c %A "$p")" in ?????w????|????????w?) return 1 ;; esac
    p="$(dirname "$p")"
  done
  return 0
}
NODE_BIN="$(readlink -f "$NODE_BIN_OPT")"
trusted_bin "$NODE_BIN" || die "$NODE_BIN (or a parent directory) is not root-owned or is group/world-writable - fix the permissions or pass --node-bin with a root-owned Node.js"
NODE_MAJOR="$("$NODE_BIN" -p 'process.versions.node.split(".")[0]' 2>/dev/null || echo 0)"
if ! [[ "$NODE_MAJOR" =~ ^[0-9]+$ ]] || [ "$NODE_MAJOR" -lt 20 ]; then
  die "Node.js >= 20 required, $NODE_BIN is $("$NODE_BIN" -v 2>/dev/null || echo unknown)"
fi
say "Node.js $("$NODE_BIN" -v) at $NODE_BIN"

if [ "$LISTEN_LAN" = 1 ] && [ -z "$LAN_IP" ]; then
  LAN_IP="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i == "src") { print $(i + 1); exit }}')"
  [ -n "$LAN_IP" ] || die "could not detect the LAN IP - pass it: --listen-lan 10.x.x.x"
fi

# ---------------------------------------------------------------------------------------------------------------
# 1. service user and directories
# ---------------------------------------------------------------------------------------------------------------
if ! id "$SVC_USER" >/dev/null 2>&1; then
  say "creating system user $SVC_USER"
  useradd --system --user-group --home-dir "$DATA" --no-create-home --shell /usr/sbin/nologin \
          --comment "Sentra SIEM engine" "$SVC_USER"
fi
if ! runuser -u "$SVC_USER" -- "$NODE_BIN" -v >/dev/null 2>&1; then
  die "user $SVC_USER cannot execute $NODE_BIN (check the permissions of its parent directories)"
fi

fix_perms() {
  install -d -m 750 -o "$SVC_USER" -g "$SVC_USER" "$DATA" "$DATA/state" "$DATA/spool"
  install -d -m 700 -o "$SVC_USER" -g "$SVC_USER" "$ETC" "$ETC/tls"
  local f
  for f in "$ETC"/*.json "$ETC"/tls/*; do
    [ -e "$f" ] || continue
    chown "$SVC_USER:$SVC_USER" "$f"
    chmod 600 "$f"
  done
}
say "directories: $APP (code), $DATA (data), $ETC (config, 700)"
fix_perms

# ---------------------------------------------------------------------------------------------------------------
# 2. code: stage, then swap (previous version kept in $APP.prev for rollback)
# ---------------------------------------------------------------------------------------------------------------
say "installing engine code to $APP"
STAGE="$APP.new"
rm -rf "$STAGE"
mkdir -p "$STAGE"
for d in engine install docs agents ui; do
  if [ -d "$SRC_ROOT/$d" ]; then cp -a "$SRC_ROOT/$d" "$STAGE/"; fi
done
for f in ARCH.md package.json VERSION; do
  if [ -f "$SRC_ROOT/$f" ]; then cp -a "$SRC_ROOT/$f" "$STAGE/"; fi
done
chown -R root:root "$STAGE"
find "$STAGE" -type d -exec chmod 755 {} +
find "$STAGE" -type f -exec chmod 644 {} +
find "$STAGE/install" -type f \( -name '*.sh' -o -name 'sentra-siem-token' -o -name 'sentra-siem-validate' \) -exec chmod 755 {} +
if [ -d "$STAGE/agents/validation" ]; then find "$STAGE/agents/validation" -name '*.sh' -exec chmod 755 {} +; fi
if [ -d "$STAGE/agents/linux" ]; then find "$STAGE/agents/linux" -name '*.sh' -exec chmod 755 {} +; fi
if [ -d "$APP" ]; then rm -rf "$APP.prev"; mv "$APP" "$APP.prev"; fi
mv "$STAGE" "$APP"
install -m 755 -o root -g root "$APP/install/sentra-siem-token" /usr/local/sbin/sentra-siem-token
if [ -f "$APP/install/sentra-siem-validate" ]; then install -m 755 -o root -g root "$APP/install/sentra-siem-validate" /usr/local/sbin/sentra-siem-validate; fi

# ---------------------------------------------------------------------------------------------------------------
# 3. secrets.json (same shape as ch-install.sh: clickhouse user/password + ingest_tokens) - never printed
# ---------------------------------------------------------------------------------------------------------------
say "secrets: $ETC/secrets.json (mode 600, never printed)"
CREATED_TOKENS="$(umask 077; "$NODE_BIN" "$APP/install/setup-json.js" secrets "$ETC/secrets.json" "$TOKENS")"
"$NODE_BIN" "$APP/install/setup-json.js" nginx-secret "$ETC/secrets.json" /etc/nginx/sentra-siem-proxy-secret.conf && say "nginx proxy-secret include: /etc/nginx/sentra-siem-proxy-secret.conf (600)"
fix_perms
bash "$APP/install/secure-secrets.sh" --no-restart || die "secrets.json could not be sealed (AES-256-GCM) - not continuing with passwords in clear. Fix the cause, then: sudo bash $APP/install/secure-secrets.sh"

# ---------------------------------------------------------------------------------------------------------------
# 4. ClickHouse (optional) - reuses install/ch-install.sh, which reads its password from secrets.json
# ---------------------------------------------------------------------------------------------------------------
if ! command -v clickhouse-server >/dev/null 2>&1; then
  if [ "$WITH_CH" = 1 ]; then
    say "installing ClickHouse (install/ch-install.sh)"
    bash "$APP/install/ch-install.sh"
    fix_perms
  else
    warn "ClickHouse is not installed - re-run with --with-clickhouse (or run install/ch-install.sh), then migrate"
    MIGRATE=0
  fi
elif [ ! -f /etc/clickhouse-server/users.d/sentra-siem.xml ]; then
  # ClickHouse installed by hand (or an earlier run stopped before this step): the engine's users do not exist yet -
  # "Authentication failed ... there is no user with such name". Create them from secrets.json (restarts ClickHouse).
  say "ClickHouse is installed but has no SIEM users yet: creating them (install/ch-install.sh)"
  bash "$APP/install/ch-install.sh"
  fix_perms
elif ! grep -q 'sentra_siem_admin' /etc/clickhouse-server/users.d/sentra-siem.xml; then
  # upgrade from a version where the engine user had full rights and `default` had no password
  say "ClickHouse users: engine user to SELECT/INSERT only, separate migration user, default user removed (restarts ClickHouse; the engine spools meanwhile)"
  bash "$APP/install/ch-install.sh"
  fix_perms
fi

# ---------------------------------------------------------------------------------------------------------------
# 5. config.json - written only when missing; listener flags are applied to an existing file when given
# ---------------------------------------------------------------------------------------------------------------
if [ -f "$ETC/config.json" ]; then say "config: keeping $ETC/config.json"; else say "config: writing default $ETC/config.json"; fi
TLS_ON=0
if [ -n "$TLS_CERT" ]; then TLS_ON=1; fi
CFG_SUMMARY="$(umask 077; NODE_NAME="$(hostname -s 2>/dev/null || hostname)" RETENTION="$RETENTION" LISTEN_LAN="$LISTEN_LAN" \
  LAN_IP="$LAN_IP" SYSLOG_PORT="$SYSLOG_PORT" TLS_ON="$TLS_ON" TOKENS="$TOKENS" \
  "$NODE_BIN" "$APP/install/setup-json.js" config "$ETC/config.json")"
read -r SYSLOG_HOST SYSLOG_TCP_PORT TLS_STATE MIN_PORT API_PORT <<<"$CFG_SUMMARY"
if [ -n "$TLS_CERT" ]; then
  install -m 600 -o "$SVC_USER" -g "$SVC_USER" "$TLS_CERT" "$ETC/tls/syslog.crt"
  install -m 600 -o "$SVC_USER" -g "$SVC_USER" "$TLS_KEY" "$ETC/tls/syslog.key"
fi
fix_perms

# ---------------------------------------------------------------------------------------------------------------
# 6. environment file, systemd unit, optional low-port capability
# ---------------------------------------------------------------------------------------------------------------
if [ -f "$ENVF" ]; then
  if grep -q '^NODE_BIN=' "$ENVF"; then sed -i "s|^NODE_BIN=.*|NODE_BIN=$NODE_BIN|" "$ENVF"; else echo "NODE_BIN=$NODE_BIN" >> "$ENVF"; fi
else
  cat > "$ENVF" <<EOF
# Sentra SIEM - environment for sentra-siem.service and sentra-siem-token (written by install.sh, kept on upgrade)
NODE_BIN=$NODE_BIN
# V8 heap for the engine (detection windows, batches). ~1.5 GB is enough for 5k EPS; raise on dedicated collectors.
NODE_OPTIONS=--max-old-space-size=1536
SENTRA_SIEM_LOG_LEVEL=info
EOF
fi
chmod 640 "$ENVF"   # may hold HTTPS_PROXY=user:pass@ (netops-setup.sh); systemd reads it as root

say "systemd unit $UNIT"
sed "s|@NODE_BIN@|$NODE_BIN|g" "$APP/install/sentra-siem.service" > "$UNIT"
chmod 644 "$UNIT"
if [ "$MIN_PORT" -lt 1024 ]; then
  say "a listener uses port $MIN_PORT (< 1024): granting CAP_NET_BIND_SERVICE only"
  install -d -m 755 "$DROPIN_DIR"
  cat > "$DROPIN_DIR/10-low-ports.conf" <<'EOF'
# written by install.sh because a configured listener port is below 1024
[Service]
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
EOF
else
  rm -f "$DROPIN_DIR/10-low-ports.conf"
fi
systemctl daemon-reload
systemctl enable sentra-siem.service >/dev/null 2>&1

# ---------------------------------------------------------------------------------------------------------------
# 7. database schema
# ---------------------------------------------------------------------------------------------------------------
if [ "$MIGRATE" = 1 ]; then
  if [ -f "$APP/engine/store/migrate.js" ]; then
    say "migrating ClickHouse schema (engine/store/migrate.js)"
    if ! (cd "$APP" && runuser -u "$SVC_USER" -- env SENTRA_SIEM_CONFIG="$ETC/config.json" "$NODE_BIN" engine/store/migrate.js); then
      warn "migration failed - check ClickHouse (systemctl status clickhouse-server), then re-run:"
      warn "  cd $APP && sudo -u $SVC_USER SENTRA_SIEM_CONFIG=$ETC/config.json $NODE_BIN engine/store/migrate.js"
    fi
  else
    warn "engine/store/migrate.js not present in this package - schema not migrated"
  fi
fi

# ---------------------------------------------------------------------------------------------------------------
# 8. start
# ---------------------------------------------------------------------------------------------------------------
if [ "$START" = 1 ]; then
  say "starting sentra-siem"
  systemctl restart sentra-siem.service
  ok=0
  for _ in $(seq 1 20); do
    if ss -lnt 2>/dev/null | awk '{print $4}' | grep -qE "(^|:)${API_PORT}\$"; then ok=1; break; fi
    sleep 1
  done
  if [ "$ok" = 1 ]; then say "sentra-siem is running (API on 127.0.0.1:$API_PORT)"
  else warn "sentra-siem did not open port $API_PORT within 20 s - journalctl -u sentra-siem -n 50"; fi
fi

# ---------------------------------------------------------------------------------------------------------------
# 9. next steps
# ---------------------------------------------------------------------------------------------------------------
cat <<EOF

Sentra SIEM installed.
  code      $APP   (previous version, if any: $APP.prev)
  data      $DATA/{state,spool}
  config    $ETC/config.json   secrets: $ETC/secrets.json (600)
  service   systemctl status sentra-siem   -   logs: journalctl -u sentra-siem -f
  syslog    $SYSLOG_HOST:$SYSLOG_TCP_PORT (udp+tcp), TLS listener $TLS_STATE
  tokens    created now: ${CREATED_TOKENS:-none}  ->  sudo sentra-siem-token list | show <src> | add <src>

Next steps
  1. nginx (portal server block), see $APP/install/nginx-soc.conf:
       sudo cp $APP/install/nginx-soc-http.conf /etc/nginx/conf.d/sentra-siem-http.conf
       add   include $APP/install/nginx-soc.conf;   inside the portal's server { } block
       sudo nginx -t && sudo systemctl reload nginx
  2. register log sources in $ETC/config.json "sources" (id, type, match.ip / match.cidr), then
       sudo systemctl restart sentra-siem          (details: $APP/docs/ONBOARDING.md)
EOF
if [ "$SYSLOG_HOST" = "127.0.0.1" ]; then
  echo "  3. listeners are on 127.0.0.1 only; on a collector re-run with --listen-lan to accept syslog from the LAN"
else
  echo "  3. open the host firewall for the device ranges only: $APP/agents/network/README.md"
fi
cat <<EOF
  4. Windows: $APP/agents/windows/README.md   (token: sudo sentra-siem-token show win-servers)
     Linux:   $APP/agents/linux/install-rsyslog-forwarder.sh --collector <this host's LAN IP>
  5. detection test: sudo sentra-siem-validate setup (once), then sudo sentra-siem-validate live   ($APP/docs/VALIDATION.md)
  6. health: portal page "SIEM Log Source Health", or: curl -s http://127.0.0.1:9120/api/soc/health
EOF
