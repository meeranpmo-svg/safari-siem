#!/bin/bash
# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
# harden-server.sh - security hardening for the Sentra SIEM / portal server (the platform server).
# Default is a REPORT ONLY (no change). Apply parts explicitly; every change is backed up and --remove undoes it.
#   sudo bash harden-server.sh                         report: what is in place, what would change
#   sudo bash harden-server.sh --apply                 nginx headers + TLS + login rate limit, SSH hardening (passwords still
#                                                      allowed), kernel network settings, automatic security updates
#   sudo bash harden-server.sh --apply --keys-only     also turn SSH passwords off - ONLY if your user already has an SSH key
#   sudo bash harden-server.sh --firewall [--allow-port 8443/tcp ...]   default-deny inbound firewall (see the report first)
#   sudo bash harden-server.sh --remove                undo everything this script added
# Closes review item ZS-21 (key-only SSH, no root login) on this server.
set -uo pipefail
# the portal's host name is a setting, never text in this script: ZYB_PORTAL_HOST, else /etc/sentra/portal-host, else the
# brand setting (/etc/sentra/brand.json, or the copy this engine was installed with)
ZYB_HOST="${ZYB_PORTAL_HOST:-$(cat /etc/sentra/portal-host 2>/dev/null || true)}"
for _b in /etc/sentra/brand.json "$(cd "$(dirname "$0")" && pwd)/../engine/util/brand.default.json" /opt/sentra-siem/engine/util/brand.default.json; do
  [ -n "$ZYB_HOST" ] || ZYB_HOST="$(sed -n 's/.*"portal_host": *"\([^"]*\)".*/\1/p' "$_b" 2>/dev/null | head -n1)"
done
case "$ZYB_HOST" in ''|*[!a-z0-9.-]*) echo "the portal host name is not set - run: echo soc.example.com | sudo tee /etc/sentra/portal-host"; exit 1;; esac
ZYB_HOST_RE="$(printf '%s' "$ZYB_HOST" | sed 's/\./\\./g')"
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
APPLY=0; KEYS=0; FW=0; REMOVE=0; EXTRA=()
while [ $# -gt 0 ]; do case "$1" in --apply) APPLY=1;; --keys-only) KEYS=1;; --firewall) FW=1;; --remove) REMOVE=1;; --allow-port) EXTRA+=("${2:-}"); shift;; *) echo "unknown option $1"; exit 1;; esac; shift; done
BK=/var/backups/zyb-hardening; mkdir -p "$BK"; chmod 700 "$BK"; STAMP=$(date +%Y%m%d-%H%M%S)
say() { echo "==> $*"; }; note() { echo "    $*"; }
ME="${SUDO_USER:-root}"; HOMEDIR="$(getent passwd "$ME" | cut -d: -f6)"
nginx_site() { # the file that holds the portal server block, as nginx itself reports it (follows links and includes)
  nginx -T 2>/dev/null | awk '/^# configuration file /{f=$4; sub(/:$/,"",f)} /server_name[^;]*'"$ZYB_HOST_RE"'/{print f; exit}'
}
NGINX_SITE="$(nginx_site)"; [ -n "$NGINX_SITE" ] || NGINX_SITE="$(grep -RlE --exclude='*.bak*' --exclude='*~' 'server_name[^;]*'"$ZYB_HOST_RE"'' /etc/nginx/sites-enabled /etc/nginx/conf.d /etc/nginx/nginx.conf 2>/dev/null | head -n1 || true)"; [ -n "$NGINX_SITE" ] && NGINX_SITE="$(readlink -f "$NGINX_SITE")"
SNIP=/etc/nginx/snippets/zyb-security-headers.conf; HTTPCONF=/etc/nginx/conf.d/zyb-security.conf
SSHD=/etc/ssh/sshd_config.d/01-zyb-hardening.conf; SYSCTL=/etc/sysctl.d/90-zyb-hardening.conf

if [ "$REMOVE" = 1 ]; then
  if [ -n "$NGINX_SITE" ]; then cp -a "$NGINX_SITE" "$BK/$(basename "$NGINX_SITE").$STAMP"; sed -i 's/limit_req zone=zyb_login burst=10 nodelay; //; /ZYB-SECHEADERS\|ZYB-LOGINLIMIT\|ZYB-TLS/d' "$NGINX_SITE"; fi
  rm -f "$SNIP" "$HTTPCONF"; nginx -t && systemctl reload nginx
  rm -f "$SSHD"; sshd -t && (systemctl reload ssh 2>/dev/null || systemctl reload sshd)
  rm -f "$SYSCTL"; sysctl --system >/dev/null
  say "removed nginx headers / rate limit, SSH hardening and kernel settings (firewall and automatic updates were left as they are)"; exit 0
fi

echo "################ REPORT ($(hostname), $(. /etc/os-release 2>/dev/null; echo "$PRETTY_NAME")) ################"
say "network listeners reachable from other machines"
ss -Hltnup 2>/dev/null | awk '{print $1, $5, $7}' | grep -vE ' (127\.|\[::1\]|::1:)' | sed 's/users:((//; s/,pid=.*//' | sort -u | sed 's/^/    /'
say "SSH"; sshd -T 2>/dev/null | grep -E '^(permitrootlogin|passwordauthentication|maxauthtries|x11forwarding|port) ' | sed 's/^/    /'
KEYOK=0; [ -s "$HOMEDIR/.ssh/authorized_keys" ] && KEYOK=1; note "SSH key for $ME: $([ $KEYOK = 1 ] && echo present || echo 'NONE - keep passwords on until a key is added')"
say "nginx portal block: ${NGINX_SITE:-not found}"
[ -n "$NGINX_SITE" ] && { grep -q ZYB-SECHEADERS "$NGINX_SITE" && note "security headers: in place" || note "security headers: missing"; grep -nE 'ssl_protocols' "$NGINX_SITE" /etc/nginx/nginx.conf 2>/dev/null | sed 's/^/    /'; grep -nE 'location[^{]*(login|signin)' "$NGINX_SITE" | sed 's/^/    login location: /'; }
say "firewall"; if command -v ufw >/dev/null; then ufw status | head -3 | sed 's/^/    /'; elif command -v firewall-cmd >/dev/null; then note "firewalld: $(firewall-cmd --state 2>&1)"; else note "no ufw / firewalld installed"; fi
say "automatic security updates"; if [ -f /etc/apt/apt.conf.d/20auto-upgrades ]; then grep -h Unattended /etc/apt/apt.conf.d/20auto-upgrades | sed 's/^/    /'; elif systemctl is-enabled dnf-automatic.timer >/dev/null 2>&1; then note "dnf-automatic enabled"; else note "not configured"; fi
[ "$APPLY" = 0 ] && [ "$FW" = 0 ] && { echo; say "report only - nothing changed. Re-run with --apply (and later --firewall) to harden."; exit 0; }

if [ "$APPLY" = 1 ]; then
  echo; echo "################ APPLY ################"
  # ---- nginx: headers, TLS, login rate limit
  if [ -n "$NGINX_SITE" ]; then
    cp -a "$NGINX_SITE" "$BK/$(basename "$NGINX_SITE").$STAMP"; [ -f "$HTTPCONF" ] && cp -a "$HTTPCONF" "$BK/"
    mkdir -p /etc/nginx/snippets
    cat > "$SNIP" <<'NGX'
# security headers for the portal (harden-server.sh). Included wherever a location sets its own add_header,
# because nginx stops inheriting add_header in that case.
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "SAMEORIGIN" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()" always;
add_header Content-Security-Policy "frame-ancestors 'self'; object-src 'none'; base-uri 'self'" always;
add_header Cross-Origin-Opener-Policy "same-origin" always;
NGX
    grep -qE 'listen[^;]*443[^;]*ssl|ssl_certificate ' "$NGINX_SITE" && echo 'add_header Strict-Transport-Security "max-age=31536000" always;' >> "$SNIP"
    cat > "$HTTPCONF" <<'NGX'
# harden-server.sh: hide the nginx version; login attempts limited to 10 per minute per address (burst 10)
server_tokens off;
limit_req_zone $binary_remote_addr zone=zyb_login:10m rate=10r/m;
limit_req_status 429;
NGX
    if ! grep -q ZYB-SECHEADERS "$NGINX_SITE"; then
      awk '/server_name[^;]*'"$ZYB_HOST_RE"'/ && !d { print; print "    include snippets/zyb-security-headers.conf;  # ZYB-SECHEADERS"; d=1; next }
           /ZYB-NOCACHE/ || /add_header Cache-Control "no-store"/ { print; match($0,/^ */); printf "%sinclude snippets/zyb-security-headers.conf;  # ZYB-SECHEADERS\n", substr($0,1,RLENGTH); next } { print }' "$NGINX_SITE" > "$NGINX_SITE.zyb" && cat "$NGINX_SITE.zyb" > "$NGINX_SITE"; rm -f "$NGINX_SITE.zyb"
    fi
    if ! grep -qE '^\s*ssl_protocols' "$NGINX_SITE" && grep -q 'ssl_certificate ' "$NGINX_SITE"; then
      awk '/ssl_certificate_key/ && !d { print; match($0,/^ */); s=substr($0,1,RLENGTH); print s "ssl_protocols TLSv1.2 TLSv1.3;  # ZYB-TLS"; print s "ssl_session_tickets off;  # ZYB-TLS"; d=1; next } { print }' "$NGINX_SITE" > "$NGINX_SITE.zyb" && cat "$NGINX_SITE.zyb" > "$NGINX_SITE"; rm -f "$NGINX_SITE.zyb"
    fi
    if ! grep -qE 'ZYB-LOGINLIMIT|zone=zyb_login' "$NGINX_SITE"; then
      # multi-line block: add a marked line inside it; one-line block "location = /login { ... }": insert inside the braces
      awk '/location[^{]*(login|signin)[^{]*\{/ && !/verify/ {
             if (index(substr($0, index($0,"{")), "}")) { sub(/\{/, "{ limit_req zone=zyb_login burst=10 nodelay; "); print; next }
             print; match($0,/^ */); print substr($0,1,RLENGTH) "    limit_req zone=zyb_login burst=10 nodelay;  # ZYB-LOGINLIMIT"; next } { print }' "$NGINX_SITE" > "$NGINX_SITE.zyb" && cat "$NGINX_SITE.zyb" > "$NGINX_SITE"; rm -f "$NGINX_SITE.zyb"
    fi
    if nginx -t 2>/dev/null; then systemctl reload nginx; say "nginx: security headers, TLS 1.2+, hidden version, login rate limit"; grep -c 'ZYB-SECHEADERS' "$NGINX_SITE" | sed 's/^/    header includes: /'; grep -qE 'ZYB-LOGINLIMIT|zone=zyb_login' "$NGINX_SITE" || note "no login location matched - rate limit zone created but not attached (send me the portal's login path)"
    else nginx -t; cp -a "$BK/$(basename "$NGINX_SITE").$STAMP" "$NGINX_SITE"; rm -f "$SNIP" "$HTTPCONF"; nginx -t && systemctl reload nginx; echo "!! nginx test failed - restored the original configuration"; fi
  else note "nginx portal block not found - skipped"; fi

  # ---- SSH
  if [ -d /etc/ssh/sshd_config.d ] && grep -qiE '^\s*Include\s+/etc/ssh/sshd_config\.d' /etc/ssh/sshd_config; then
    PW=yes; if [ "$KEYS" = 1 ]; then if [ "$KEYOK" = 1 ]; then PW=no; else note "--keys-only refused: $ME has no ~/.ssh/authorized_keys - passwords stay on (add a key first, see docs)"; fi; fi
    cat > "$SSHD" <<SSH
# harden-server.sh (ZS-21). Named 01- so it wins over later files (first value wins in sshd).
PermitRootLogin no
PasswordAuthentication $PW
KbdInteractiveAuthentication $PW
PermitEmptyPasswords no
MaxAuthTries 4
LoginGraceTime 30
X11Forwarding no
ClientAliveInterval 300
ClientAliveCountMax 2
SSH
    if sshd -t; then systemctl reload ssh 2>/dev/null || systemctl reload sshd; say "SSH: root login off, 4 tries, idle sessions closed after 10 min, passwords $([ $PW = no ] && echo OFF \(keys only\) || echo still allowed)"; note "keep this session open and test a new login before closing it"
    else rm -f "$SSHD"; echo "!! sshd rejected the settings - removed"; fi
  else note "sshd_config has no Include for sshd_config.d - SSH skipped (tell me and I will adapt)"; fi

  # ---- kernel network settings
  cat > "$SYSCTL" <<'SYS'
# harden-server.sh: safe network hardening (loose reverse-path filter so syslog on several interfaces keeps working)
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.rp_filter = 2
net.ipv4.tcp_syncookies = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
SYS
  sysctl --system >/dev/null 2>&1 && say "kernel network settings applied"

  # ---- automatic security updates
  if command -v apt-get >/dev/null; then
    if dpkg -s unattended-upgrades >/dev/null 2>&1 || apt-get install -y -q unattended-upgrades >/dev/null 2>&1; then
      printf 'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n' > /etc/apt/apt.conf.d/20auto-upgrades; say "automatic security updates on (unattended-upgrades, security pocket)"
    else note "unattended-upgrades could not be installed (no package repository reachable?) - skipped"; fi
  elif command -v dnf >/dev/null; then
    if rpm -q dnf-automatic >/dev/null 2>&1 || dnf -y -q install dnf-automatic >/dev/null 2>&1; then
      sed -i 's/^upgrade_type.*/upgrade_type = security/; s/^apply_updates.*/apply_updates = yes/' /etc/dnf/automatic.conf; systemctl enable --now dnf-automatic.timer >/dev/null; say "automatic security updates on (dnf-automatic)"
    else note "dnf-automatic could not be installed - skipped"; fi
  fi
fi

if [ "$FW" = 1 ]; then
  echo; echo "################ FIREWALL ################"
  SSHP="$(sshd -T 2>/dev/null | awk '/^port /{print $2; exit}')"; SSHP="${SSHP:-22}"
  ALLOW=("$SSHP/tcp" 80/tcp 443/tcp 5514/tcp 5514/udp 6514/tcp "${EXTRA[@]}")
  PUB="$(ss -Hltnu 2>/dev/null | awk '{print $1, $5}' | grep -vE ' (127\.|\[::1\]|::1:)' | awk '{n=split($2,a,":"); print a[n] "/" $1}' | sort -u)"
  MISSING=""; for p in $PUB; do case " ${ALLOW[*]} " in *" $p "*) ;; *) MISSING="$MISSING $p";; esac; done
  if [ -n "$MISSING" ]; then echo "!! these services listen on the network but are NOT in the allow list:$MISSING"; echo "   re-run with --allow-port <port>/<proto> for each one that must stay reachable (nothing changed)"; exit 1; fi
  if command -v ufw >/dev/null; then
    for p in "${ALLOW[@]}"; do ufw allow "$p" >/dev/null; done; ufw default deny incoming >/dev/null; ufw default allow outgoing >/dev/null; ufw --force enable >/dev/null; ufw status numbered | sed 's/^/    /'
  elif command -v firewall-cmd >/dev/null; then
    systemctl enable --now firewalld >/dev/null; for p in "${ALLOW[@]}"; do firewall-cmd -q --permanent --add-port="$p"; done; firewall-cmd -q --reload; firewall-cmd --list-ports | sed 's/^/    open: /'
  else echo "!! neither ufw nor firewalld is installed - nothing changed"; exit 1; fi
  say "firewall on: inbound allowed only to ${ALLOW[*]}"
fi
say "done. Backups: $BK  ·  undo: sudo bash harden-server.sh --remove"
