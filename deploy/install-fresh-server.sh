#!/bin/bash
# Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
# install-fresh-server.sh - put the whole platform on a NEW server (Ubuntu 22.04 / 24.04), in order, from this tree:
#   1 checks and system packages (nginx, openssl, python3; Node.js 20+)
#   2 SIEM engine + ClickHouse            backend/siem/install/install.sh --with-clickhouse
#   3 IT Asset Management engine          backend/itam/install/install.sh
#   4 sign-in service                     the organisation's own, installed UNCHANGED from --auth-src
#   5 nginx: HTTPS site for the portal host (deploy/nginx-site.conf.tmpl), the engines behind the sign-in
#   6 pages: dashboards, /dashboards/ behind the sign-in, server stats
#   7 summary: what is running, what a person still has to do
# Run on the server, from the tree (git clone or the unpacked archive):
#   sudo bash deploy/install-fresh-server.sh --auth-src /path/to/auth [--host soc.example.com] [--ip 10.0.0.5]
#        [--tls-cert F --tls-key F] [--node-bin PATH] [--auth-port 9098] [--skip-clickhouse]
# --host / --ip default to the brand setting (brand/brand.json: portal_host, platform_ip).
# --auth-src: a folder holding the sign-in service (one *-auth.js file, Node standard library only, and optionally its
#   bootstrap-admin.js). It is copied as it is: this script never creates an account, never sets or reads a password
#   and never changes two-factor settings. The first administrator is created by a person, with the service's own tool.
# Without --tls-cert / --tls-key a self-signed certificate is made so the site can start; replace it with the
#   organisation's certificate (the summary says where).
# Re-running is safe: every step upgrades in place and existing settings, secrets and data are kept.
set -uo pipefail
umask 022
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
TREE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
say()  { printf '\n\033[1m================ %s ================\033[0m\n' "$*"; }
ok()   { printf '==> %s\n' "$*"; }
warn() { printf '\033[33m!! %s\033[0m\n' "$*" >&2; }
die()  { printf '\033[31mx %s\033[0m\n' "$*" >&2; exit 1; }
FAILED=""; NOTES=""
note() { NOTES="$NOTES"$'\n'"   - $*"; }

AUTH_SRC="" HOST="" IP="" CERT="" KEY="" NODE_OPT="" AUTH_PORT=9098 WITH_CH=1
while [ $# -gt 0 ]; do
  case "$1" in
    --auth-src) AUTH_SRC="${2:-}"; shift 2 ;;
    --host) HOST="${2:-}"; shift 2 ;;
    --ip) IP="${2:-}"; shift 2 ;;
    --tls-cert) CERT="${2:-}"; shift 2 ;;
    --tls-key) KEY="${2:-}"; shift 2 ;;
    --node-bin) NODE_OPT="${2:-}"; shift 2 ;;
    --auth-port) AUTH_PORT="${2:-}"; shift 2 ;;
    --skip-clickhouse) WITH_CH=0; shift ;;
    -h|--help) sed -n '2,22p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown option: $1 (see --help)" ;;
  esac
done

# ------------------------------------------------------------------------------------------------ 1 checks, packages
say "1/7 checks and system packages"
for d in backend/siem/install backend/itam/install ui brand; do [ -e "$TREE/$d" ] || die "$TREE is not the platform tree ($d is missing)"; done
. /etc/os-release 2>/dev/null || true
case "${ID:-}:${VERSION_ID:-}" in ubuntu:22.04|ubuntu:24.04) ok "Ubuntu $VERSION_ID" ;; *) warn "tested layout is Ubuntu 22.04 / 24.04; this is ${PRETTY_NAME:-unknown} - continuing" ;; esac
command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ] || die "systemd is required (the engines run as services)"
# brand setting -> host and address (values are checked: they go into nginx and file names)
bval() { sed -n "s/^[[:space:]]*\"$1\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p" "$TREE/brand/brand.json" | head -n1; }
[ -n "$HOST" ] || HOST="$(bval portal_host)"; [ -n "$IP" ] || IP="$(bval platform_ip)"
case "$HOST" in ''|*[!a-z0-9.-]*) die "portal host name is not set or not a plain DNS name: '$HOST' (--host, or portal_host in brand/brand.json)" ;; esac
[[ "$IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || die "the server's LAN address is not set: '$IP' (--ip, or platform_ip in brand/brand.json)"
ip -4 -o addr show 2>/dev/null | grep -q "inet $IP/" || die "this server has no network interface with the address $IP. The SIEM listens for syslog on that address and cannot start without it: give the server's own LAN address with --ip (its addresses: $(ip -4 -o addr show scope global 2>/dev/null | awk '{print $4}' | tr '\n' ' '))"
[[ "$AUTH_PORT" =~ ^[0-9]{2,5}$ ]] || die "--auth-port must be a port number"
ok "portal host $HOST, server address $IP"
# the sign-in service source: checked now, before anything is installed
AUTH_JS=""
if [ -n "$AUTH_SRC" ]; then
  [ -d "$AUTH_SRC" ] || die "--auth-src $AUTH_SRC is not a folder"
  AUTH_JS="$(find "$AUTH_SRC" -maxdepth 1 -type f -name '*-auth.js' | head -n1)"
  [ -n "$AUTH_JS" ] || die "no *-auth.js file in $AUTH_SRC (the sign-in service)"
elif [ ! -f /opt/sentra-auth/.installed ]; then
  die "--auth-src is required on the first run: the folder that holds the organisation's sign-in service"
fi
# no package step may stop to ask a person something, and none reads the terminal (a hidden question would wait for ever);
# another package run in progress (automatic updates) is waited for, up to 20 minutes, instead of failing at once
export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a NEEDRESTART_SUSPEND=1 UCF_FORCE_CONFOLD=1 APT_LISTCHANGES_FRONTEND=none
APT='apt-get -y -q -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold -o DPkg::Lock::Timeout=1200'
# dpkg itself has no lock timeout: while automatic updates hold the lock it is retried every 10 s for up to 20 minutes (the
# lock is never removed - that can damage the package database); any other dpkg error stops here as before
dpkg_configure() {
  local i out
  for i in $(seq 1 120); do
    if out="$(dpkg --configure -a </dev/null 2>&1)"; then [ -n "$out" ] && printf '%s\n' "$out"; return 0; fi
    if ! printf '%s' "$out" | grep -q 'lock'; then printf '%s\n' "$out" >&2; return 1; fi
    [ "$i" = 1 ] && { warn "another package installer is running (usually Ubuntu's automatic updates) - waiting for it to finish, up to 20 minutes:"; printf '%s\n' "$out" | grep -m1 'locked by' >&2; }
    [ $((i % 6)) = 0 ] && echo "   still waiting ($((i / 6)) min) - nothing to do; it continues by itself"
    sleep 10
  done
  printf '%s\n' "$out" >&2; return 1
}
# another package operation (automatic updates, an apt-get left in another window, its dpkg) is WAITED for - every 10 s, up to
# 20 minutes - instead of failing at once; a holder stuck on the disk (state D, nothing written) is said plainly, because waiting
# will not help then: the VM's storage is stalling. The lock files are never removed.
pkg_busy() { ps -eo pid=,stat=,etime=,args= | grep -E '[a]pt-get|[d]pkg |[/]dpkg |[u]nattended-upgr|[a]pt\.systemd|[p]ackagekit' | awk -v me="$$" '$1 != me'; }
wait_pkg_idle() {
  local i b
  for i in $(seq 1 120); do
    b="$(pkg_busy)"; [ -z "$b" ] && return 0
    if [ "$i" = 1 ]; then warn "another package operation is running - waiting for it to finish (up to 20 minutes):"; printf '   %s\n' "$b" | cut -c1-160 >&2; fi
    [ $((i % 6)) = 0 ] && echo "   still waiting ($((i / 6)) min) - nothing to do; it continues by itself"
    sleep 10
  done
  b="$(pkg_busy)"; [ -z "$b" ] && return 0
  printf '%s\n' "$b" | awk '$2 ~ /^D/' | grep -q . && warn "the package process is stuck waiting on the disk (state D) - the virtual machine's storage is stalling, not Ubuntu. Restart the VM from the Hyper-V host (Turn Off, Start), then: sudo dpkg --configure -a; and run this script again"
  return 1
}
wait_pkg_idle || die "another package operation is still running after 20 minutes (shown above) - let it finish (or restart the VM from the Hyper-V host if it is stuck), then run this script again. The lock files are never removed: that can damage the package database"
dpkg --audit 2>/dev/null | grep -q . && { warn "a package was left half-installed - finishing it first"; dpkg_configure || die "dpkg --configure -a failed (shown above): the package system must be healthy before the platform is installed. If another installer is still running, wait for it (ps -p <pid>) and run this script again"; }
$APT update </dev/null >/dev/null 2>/tmp/sentra-apt.$$ || { warn "apt-get update failed - packages are installed from what is already known:"; tail -n 5 /tmp/sentra-apt.$$ >&2; }
$APT install nginx openssl python3 python3-venv curl ca-certificates </dev/null >/dev/null 2>/tmp/sentra-apt.$$ || { cat /tmp/sentra-apt.$$ >&2; rm -f /tmp/sentra-apt.$$; die "could not install nginx / openssl / python3 - the package system's own message is above"; }
rm -f /tmp/sentra-apt.$$
ok "nginx, openssl, python3 installed"
# Node.js 20+: the one given, one already here, else the distribution's when it is new enough
NODE_BIN=""
for c in "$NODE_OPT" /opt/sentra-ai/node/bin/node "$(command -v node 2>/dev/null || true)"; do
  [ -n "$c" ] && [ -x "$c" ] && [ "$("$c" -p 'process.versions.node.split(".")[0]' 2>/dev/null || echo 0)" -ge 20 ] && { NODE_BIN="$c"; break; }
done
if [ -z "$NODE_BIN" ]; then
  $APT install nodejs </dev/null >/dev/null 2>&1 || true
  c="$(command -v node 2>/dev/null || true)"; [ -n "$c" ] && [ "$("$c" -p 'process.versions.node.split(".")[0]' 2>/dev/null || echo 0)" -ge 20 ] && NODE_BIN="$c"
fi
[ -n "$NODE_BIN" ] || die "Node.js 20 or later is needed and this Ubuntu release does not package it. Unpack the official Linux x64 build from nodejs.org into /opt/sentra-ai/node (so that /opt/sentra-ai/node/bin/node exists), check its SHA-256 against the published list, and run this script again."
ok "Node.js $("$NODE_BIN" -v) at $NODE_BIN"
"$NODE_BIN" "$TREE/tools/brand/apply-brand.js" --check >/dev/null 2>&1 || die "the generated brand copies are stale - run: node tools/brand/apply-brand.js (on the PC), then copy the tree again"
install -d -m 755 /etc/sentra; printf '%s\n' "$HOST" > /etc/sentra/portal-host

# ------------------------------------------------------------------------------------------------ 2 SIEM engine
say "2/7 SIEM engine and ClickHouse"
CH=""; [ "$WITH_CH" = 1 ] && CH="--with-clickhouse"
if bash "$TREE/backend/siem/install/install.sh" --node-bin "$NODE_BIN" --listen-lan "$IP" $CH; then ok "SIEM engine installed"
else die "the SIEM engine did not install - fix what it reports above and run this script again (nothing after it was touched)"; fi
command -v clickhouse-server >/dev/null 2>&1 || { FAILED="$FAILED clickhouse"; note "ClickHouse is not installed: events cannot be stored. The server must reach packages.clickhouse.com, or install the clickhouse-server package from your own mirror, then: sudo bash $TREE/backend/siem/install/install.sh --with-clickhouse"; }

# ------------------------------------------------------------------------------------------------ 3 asset engine
say "3/7 IT Asset Management engine"
if bash "$TREE/backend/itam/install/install.sh" --node-bin "$NODE_BIN" --provider none; then ok "asset engine installed (AI features off until a model is configured in Platform Admin)"
else die "the asset engine did not install - fix what it reports above and run this script again"; fi
[ -x "$TREE/backend/siem/install/link-itam.sh" ] || chmod +x "$TREE/backend/siem/install/link-itam.sh" 2>/dev/null
bash "$TREE/backend/siem/install/link-itam.sh" || { FAILED="$FAILED link-itam"; note "the SIEM could not be linked to the asset inventory: sudo bash /opt/sentra-siem/install/link-itam.sh"; }
bash "$TREE/backend/itam/install/link-siem.sh" || { FAILED="$FAILED link-siem"; note "IT Asset Management could not be linked to the SIEM: sudo bash /opt/sentra-itam/install/link-siem.sh"; }

# ------------------------------------------------------------------------------------------------ 4 sign-in service
say "4/7 sign-in service"
if [ -n "$AUTH_JS" ]; then
  id sentra-auth >/dev/null 2>&1 || useradd --system --user-group --home-dir /var/lib/sentra-auth --no-create-home --shell /usr/sbin/nologin sentra-auth
  install -d -m 755 -o root -g root /opt/sentra-auth
  install -d -m 700 -o sentra-auth -g sentra-auth /var/lib/sentra-auth /var/lib/sentra-auth/store
  # the service's files exactly as given (code is root-owned and read-only to the service)
  install -m 644 -o root -g root "$AUTH_JS" /opt/sentra-auth/auth.js
  [ -f "$AUTH_SRC/bootstrap-admin.js" ] && install -m 644 -o root -g root "$AUTH_SRC/bootstrap-admin.js" /opt/sentra-auth/bootstrap-admin.js
  sha256sum "$AUTH_JS" | cut -d' ' -f1 > /opt/sentra-auth/.installed
  # where it keeps its data and listens: both spellings of the variables the service may read (loopback only)
  { for p in SAFARI_AUTH SENTRA_AUTH AS_AUTH; do
      printf '%s_CFG=/var/lib/sentra-auth/auth.json\n%s_LOG=/var/lib/sentra-auth/auth.log\n%s_STORE=/var/lib/sentra-auth/store\n%s_HOST=127.0.0.1\n%s_PORT=%s\n' "$p" "$p" "$p" "$p" "$p" "$AUTH_PORT"; done
    echo NODE_ENV=production; } > /etc/default/sentra-auth
  chmod 644 /etc/default/sentra-auth
  cat > /etc/systemd/system/sentra-auth.service <<UNIT
[Unit]
Description=Sentra platform sign-in service (the organisation's own; installed unchanged by install-fresh-server.sh)
After=network.target

[Service]
User=sentra-auth
Group=sentra-auth
EnvironmentFile=/etc/default/sentra-auth
WorkingDirectory=/opt/sentra-auth
ExecStart=$NODE_BIN /opt/sentra-auth/auth.js
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/lib/sentra-auth
CapabilityBoundingSet=
MemoryMax=192M

[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload; systemctl enable --quiet sentra-auth; systemctl restart sentra-auth
fi
AUTH_OK=0; for i in 1 2 3 4 5 6 7 8 9 10; do
  c="$(curl -s --noproxy '*' -o /dev/null -w '%{http_code}' --max-time 3 "http://127.0.0.1:$AUTH_PORT/auth/verify" 2>/dev/null || true)"
  case "$c" in 401|403|200|204) AUTH_OK=1; break ;; esac; sleep 1; done
if [ "$AUTH_OK" = 1 ]; then ok "sign-in service answers on 127.0.0.1:$AUTH_PORT (no session: $c)"
else FAILED="$FAILED sign-in"; note "the sign-in service does not answer /auth/verify on 127.0.0.1:$AUTH_PORT: sudo journalctl -u sentra-auth -n 40 (nobody can sign in until it does)"; fi

# ------------------------------------------------------------------------------------------------ 5 nginx
say "5/7 nginx: HTTPS site for $HOST"
install -d -m 755 /var/www/sentra
LOGO_TYPE=image/png
LOGO_SRC="$(bval logo)"; [ -n "$LOGO_SRC" ] && [ -f "$TREE/brand/$LOGO_SRC" ] && { install -m 644 "$TREE/brand/$LOGO_SRC" /var/www/sentra/logo
  case "$LOGO_SRC" in *.svg) LOGO_TYPE=image/svg+xml ;; *.webp) LOGO_TYPE=image/webp ;; *.jpg|*.jpeg) LOGO_TYPE=image/jpeg ;; esac; }
if [ -n "$CERT" ] || [ -n "$KEY" ]; then
  [ -f "$CERT" ] && [ -f "$KEY" ] || die "--tls-cert and --tls-key must both be files"
  install -d -m 700 /etc/sentra/tls; install -m 644 "$CERT" /etc/sentra/tls/portal.crt; install -m 600 "$KEY" /etc/sentra/tls/portal.key
  ok "certificate installed from $CERT"
elif [ ! -f /etc/sentra/tls/portal.crt ]; then
  install -d -m 700 /etc/sentra/tls
  openssl req -x509 -newkey rsa:2048 -nodes -days 365 -subj "/CN=$HOST" -addext "subjectAltName=DNS:$HOST,IP:$IP" \
    -keyout /etc/sentra/tls/portal.key -out /etc/sentra/tls/portal.crt >/dev/null 2>&1 || die "could not create a certificate"
  chmod 600 /etc/sentra/tls/portal.key
  note "the site uses a SELF-SIGNED certificate (browsers and agents will warn). Install the organisation's certificate: sudo bash $TREE/deploy/install-fresh-server.sh --tls-cert <file> --tls-key <file>"
fi
chmod 711 /etc/sentra/tls   # nginx reads the certificate as root before it drops privileges; the key stays 600
cp "$TREE/backend/siem/install/nginx-soc-http.conf" /etc/nginx/conf.d/sentra-siem-http.conf
printf '%s\n' '# Sentra platform - sign-in attempts per client address (deploy/install-fresh-server.sh)' 'limit_req_zone $binary_remote_addr zone=sentra_login:10m rate=30r/m;' > /etc/nginx/conf.d/sentra-portal-http.conf
SITE=/etc/nginx/sites-available/sentra
BAK=""; [ -f "$SITE" ] && { install -d -m 700 /var/backups/nginx-zyb; BAK="/var/backups/nginx-zyb/sentra.$(date +%Y%m%d-%H%M%S)"; cp -a "$SITE" "$BAK"; }
if [ -n "$BAK" ] && grep -q 'ZYB-DASHBOARDS\|/dashboards/' "$SITE"; then ok "the site file already exists with the dashboards in it - left as it is ($SITE)"
else
  sed -e "s|@HOST@|$HOST|g" -e "s|@IP@|$IP|g" -e "s|@CERT@|/etc/sentra/tls/portal.crt|g" -e "s|@KEY@|/etc/sentra/tls/portal.key|g" \
      -e "s|@AUTH_PORT@|$AUTH_PORT|g" -e "s|@LOGO_TYPE@|$LOGO_TYPE|g" "$TREE/deploy/nginx-site.conf.tmpl" > "$SITE"
  ln -sf "$SITE" /etc/nginx/sites-enabled/sentra
  [ -L /etc/nginx/sites-enabled/default ] && rm -f /etc/nginx/sites-enabled/default   # the stock "Welcome to nginx" site
fi
if nginx -t 2>/tmp/sentra-nginx-t.$$; then systemctl enable --quiet nginx; systemctl reload nginx 2>/dev/null || systemctl restart nginx; ok "nginx configuration is valid and loaded"
else cat /tmp/sentra-nginx-t.$$ >&2; [ -n "$BAK" ] && cp -a "$BAK" "$SITE"; rm -f /tmp/sentra-nginx-t.$$; die "nginx refused the configuration (shown above) - the previous site file was put back"; fi
rm -f /tmp/sentra-nginx-t.$$

# ------------------------------------------------------------------------------------------------ 6 pages
say "6/7 pages"
export NODE="$NODE_BIN"   # the page installers look for Node.js here first
( cd "$TREE/ui" && bash install-dashboards.sh | grep -E '==> dashboards installed|==> static build|Content-Security-Policy|missing|nothing changed' ) || { FAILED="$FAILED dashboards"; note "the pages were not installed: cd $TREE/ui && sudo bash install-dashboards.sh"; }
( cd "$TREE/ui" && bash add-dashboards-nginx.sh ) || { FAILED="$FAILED dashboards-nginx"; note "/dashboards/ was not added to nginx: cd $TREE/ui && sudo bash add-dashboards-nginx.sh"; }
( cd "$TREE/ui" && bash install-sysinfo.sh >/dev/null ) && ok "server stats timer installed" || { FAILED="$FAILED sysinfo"; }
( cd "$TREE/ui" && bash install-platform.sh ) || { FAILED="$FAILED platform-health-backup"; note "health checks and the nightly backup were not set up: cd $TREE/ui && sudo bash install-platform.sh"; }

# ------------------------------------------------------------------------------------------------ 7 summary
say "7/7 summary"
for s in clickhouse-server sentra-siem sentra-itam sentra-auth nginx; do st="$(systemctl is-active "$s" 2>/dev/null | head -n1)"; printf '   %-18s %s\n' "$s" "${st:-not installed}"; done
code() { curl -sk --noproxy '*' -o /dev/null -w '%{http_code}' --max-time 6 --resolve "$HOST:443:127.0.0.1" "https://$HOST$1" 2>/dev/null || true; }
printf '   %-34s %s  (expect 302: to the home page)\n' "https://$HOST/" "$(code /)"
printf '   %-34s %s  (expect 302: to the sign-in page - nobody is signed in)\n' "https://$HOST/dashboards/" "$(code /dashboards/)"
printf '   %-34s %s  (expect 200: the sign-in page)\n' "https://$HOST/login" "$(code /login)"
printf '   %-34s %s  (expect 401: the API refuses without a session)\n' "https://$HOST/api/itam/health" "$(code /api/itam/health)"
echo
echo "What a person does next:"
echo "   1. DNS: point $HOST at $IP (or add it to the hosts file of the PCs that will open the portal)."
if [ -f /opt/sentra-auth/bootstrap-admin.js ]; then
echo "   2. Create the first administrator - interactive, the password is typed without echo and never shown:"
echo "        sudo -u sentra-auth env \$(grep -v '^#' /etc/default/sentra-auth | xargs) $NODE_BIN /opt/sentra-auth/bootstrap-admin.js"
echo "      then open https://$HOST/ , sign in, scan the QR code with an authenticator app and keep the recovery codes."
else
echo "   2. Create the first administrator with the sign-in service's own tool, then open https://$HOST/ and enrol two-factor."
fi
echo "   3. Further accounts: Platform Administration -> Identity & Sign-in -> Users."
echo "   4. Firewall: allow 443/tcp from staff PCs and remote-site agents to $IP; syslog 5514 (udp+tcp) from devices."
echo "   5. Connect the sources: Start here -> Connections & Setup (Fortinet, Hyper-V scopes in Asset Discovery, Exchange, switches)."
[ -n "$NOTES" ] && { echo; echo "Needs attention:$NOTES"; }
if [ -n "$FAILED" ]; then echo; warn "finished with problems in:$FAILED"; exit 1; fi
echo; ok "the platform is installed on $HOST ($IP)"
