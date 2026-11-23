#!/bin/bash
# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
# Sentra ITAM (sentra-itam) - install / upgrade on Ubuntu 22.04 / 24.04. Idempotent: re-run = upgrade.
#
#   sudo ./install/install.sh [options]          (run from the unpacked sentra-itam/ package)
#
# Options:
#   --node-bin PATH          Node.js >= 20 (default: /opt/sentra-ai/node/bin/node)
#   --provider P             private (production, S1 private model) | claude (staging) | none
#   --private-url URL        private model base URL, e.g. http://10.0.0.10:9093  (/draft is appended)
#   --private-token-file F   file with the optional Bearer token for the private model (stored in secrets.json)
#   --model NAME             model name written into config.json (ai.model)
#   --no-start               install everything but do not (re)start the service
#   -h | --help
#
# Layout: /opt/sentra-itam (code, read-only to the service), /var/lib/sentra-itam/state (700, service-owned),
# /etc/sentra-itam (750: config.json, secrets.json 600), /etc/default/sentra-itam, systemd unit sentra-itam.service,
# /etc/nginx/sentra-itam-proxy-secret.conf (600). The nginx site file is NOT edited: include
# /opt/sentra-itam/install/nginx-itam.conf in the portal's server block yourself (see the summary at the end).
# Runs as a dedicated unprivileged user sentra-itam. Existing config/secrets are merged, never clobbered.
set -euo pipefail
umask 022

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_ROOT="$(cd "$HERE/.." && pwd)"
APP=/opt/sentra-itam
DATA=/var/lib/sentra-itam
ETC=/etc/sentra-itam
ENVF=/etc/default/sentra-itam
UNIT=/etc/systemd/system/sentra-itam.service
NGINX_SECRET=/etc/nginx/sentra-itam-proxy-secret.conf
SVC_USER=sentra-itam

NODE_BIN_OPT="${NODE_BIN:-/opt/sentra-ai/node/bin/node}"
PROVIDER="" PRIVATE_URL="" TOKEN_FILE="" MODEL="" START=1

say()  { printf '\033[1m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[33mwarning:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }
usage() { sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --node-bin)           NODE_BIN_OPT="${2:-}"; shift 2 ;;
    --provider)           PROVIDER="${2:-}"; shift 2 ;;
    --private-url)        PRIVATE_URL="${2:-}"; shift 2 ;;
    --private-token-file) TOKEN_FILE="${2:-}"; shift 2 ;;
    --model)              MODEL="${2:-}"; shift 2 ;;
    --no-start)           START=0; shift ;;
    -h|--help)            usage 0 ;;
    *)                    echo "unknown option: $1" >&2; usage 2 ;;
  esac
done

[ "$(id -u)" = 0 ] || die "run as root (sudo $0 ...)"
[ -f "$SRC_ROOT/engine/main.js" ] || die "engine/main.js not found under $SRC_ROOT - run this from the unpacked package"
for f in setup-json.js sentra-itam.service nginx-itam.conf; do [ -f "$HERE/$f" ] || die "install/$f is missing"; done
command -v systemctl >/dev/null 2>&1 || die "systemd is required"
[ -x "$NODE_BIN_OPT" ] || die "node not executable at $NODE_BIN_OPT (use --node-bin)"
NODE_MAJOR="$("$NODE_BIN_OPT" -e 'process.stdout.write(String(process.versions.node.split(".")[0]))')"
[ "$NODE_MAJOR" -ge 20 ] || die "Node.js >= 20 required (found $("$NODE_BIN_OPT" -v))"

say "service account $SVC_USER"
id "$SVC_USER" >/dev/null 2>&1 || useradd --system --home-dir "$DATA" --shell /usr/sbin/nologin "$SVC_USER"

say "code -> $APP"
mkdir -p "$APP"
cp -r "$SRC_ROOT/engine" "$SRC_ROOT/agent" "$APP/"
[ -d "$SRC_ROOT/docs" ] && cp -r "$SRC_ROOT/docs" "$APP/" || true
cp -r "$SRC_ROOT/install" "$APP/"
chown -R root:root "$APP"; chmod -R go-w "$APP"

say "state -> $DATA (700, $SVC_USER)"
mkdir -p "$DATA/state"; chown -R "$SVC_USER:$SVC_USER" "$DATA"; chmod 700 "$DATA"

say "config -> $ETC"
mkdir -p "$ETC"; chmod 750 "$ETC"; chown root:"$SVC_USER" "$ETC"
CFG_ARGS=(); [ -n "$PROVIDER" ] && CFG_ARGS+=(--provider "$PROVIDER"); [ -n "$PRIVATE_URL" ] && CFG_ARGS+=(--private-url "$PRIVATE_URL"); [ -n "$MODEL" ] && CFG_ARGS+=(--model "$MODEL")
"$NODE_BIN_OPT" "$HERE/setup-json.js" config "$ETC/config.json" "${CFG_ARGS[@]}"
SEC_ARGS=(); [ -n "$TOKEN_FILE" ] && SEC_ARGS+=(--private-token-file "$TOKEN_FILE")
"$NODE_BIN_OPT" "$HERE/setup-json.js" secrets "$ETC/secrets.json" "${SEC_ARGS[@]}"
chown root:"$SVC_USER" "$ETC/config.json"; chmod 640 "$ETC/config.json"
chown root:"$SVC_USER" "$ETC/secrets.json"; chmod 640 "$ETC/secrets.json"

# Asset Discovery credential vault master key (AES-256-GCM). Created once, never overwritten: losing or replacing it
# makes every stored discovery credential unreadable (they would have to be re-entered).
VAULT_KEY="$ETC/discovery-vault.key"
if [ ! -s "$VAULT_KEY" ]; then
  say "discovery vault key -> $VAULT_KEY (600, $SVC_USER)"
  ( umask 077; "$NODE_BIN_OPT" -e 'process.stdout.write(require("crypto").randomBytes(32).toString("hex") + "\n")' > "$VAULT_KEY" )
fi
chown "$SVC_USER":"$SVC_USER" "$VAULT_KEY"; chmod 600 "$VAULT_KEY"
# every value in secrets.json except proxy_secret (nginx needs it in clear) sealed with AES-256-GCM under the vault key
mkdir -p "$APP/install"; install -m 0750 "$HERE/itam-secrets.js" "$APP/install/itam-secrets.js"
"$NODE_BIN_OPT" "$APP/install/itam-secrets.js" seal || { echo "!! could not seal $ETC/secrets.json - stopping (nothing is left half-written)"; exit 1; }

say "nginx proxy-secret include -> $NGINX_SECRET (600)"
PROXY_SECRET="$("$NODE_BIN_OPT" -e 'process.stdout.write(JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")).proxy_secret)' "$ETC/secrets.json")"
( umask 077; printf 'proxy_set_header X-Sentra-Proxy-Secret "%s";\n' "$PROXY_SECRET" > "$NGINX_SECRET" )   # never readable by others, not even briefly
chmod 600 "$NGINX_SECRET"

say "systemd unit"
sed "s#@NODE_BIN@#$NODE_BIN_OPT#g" "$HERE/sentra-itam.service" > "$UNIT"
[ -f "$ENVF" ] || printf '# SENTRA_ITAM_LOG_LEVEL=info\n' > "$ENVF"
systemctl daemon-reload
systemctl enable sentra-itam >/dev/null 2>&1 || true
if [ "$START" = 1 ]; then say "starting"; systemctl restart sentra-itam; sleep 1; systemctl --no-pager --full status sentra-itam | sed -n '1,6p' || true; else warn "--no-start: not starting"; fi

cat <<EOF

$(say "done")
Next:
  1. Include the nginx locations in the portal HTTPS server block:
         include /opt/sentra-itam/install/nginx-itam.conf;
     then: nginx -t && systemctl reload nginx
  2. Set the private model URL if not already:  --private-url http://<S1>:9093   (AI stays 'not configured' until then)
  3. In the portal (ITAM > Settings): enable sources, set the vCenter + netops credentials (write-only), issue agent
     enrolment tokens, and import your current CMDB / ManageEngine AssetExplorer CSV.
  4. Health check:  curl -s -H "X-Sentra-Proxy-Secret: <secret>" http://127.0.0.1:9150/api/itam/health
EOF
