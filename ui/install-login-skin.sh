#!/bin/bash
# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
# install-login-skin.sh - the approved sign-in page design, switched on in nginx. The sign-in service is NOT changed:
# nginx adds one <script> line to the sign-in pages it passes through (sub_filter), and that script (login-skin/zyb-login.js)
# redraws the page around the service's own form - same fields, same action, same two-step verification and lockout.
# The script is served from /zyb-login/ without a login (the sign-in page is shown before anyone is signed in); it holds
# only layout and the two logos.
#   sudo bash install-login-skin.sh [--desk "itdesk@example.com"]   switch on (or update)
#   sudo bash install-login-skin.sh --remove                              switch off, back to the original page
# Backs up the nginx file first (outside /etc/nginx), runs nginx -t, reloads only if it passes, checks the result with
# curl, and puts the backup back if anything fails.
set -euo pipefail
# the portal's host name is a setting, never text in this script: ZYB_PORTAL_HOST, else /etc/sentra/portal-host, else the
# brand setting this package was built with (vendor/zyb-org.js, written by tools/brand/apply-brand.js)
ZYB_HOST="${ZYB_PORTAL_HOST:-$(cat /etc/sentra/portal-host 2>/dev/null || true)}"
for _b in "$(cd "$(dirname "$0")" && pwd)/vendor/zyb-org.js" /var/www/sentra/dashboards/vendor/zyb-org.js; do
  [ -n "$ZYB_HOST" ] || ZYB_HOST="$(sed -n 's/.*"portal_host": *"\([^"]*\)".*/\1/p' "$_b" 2>/dev/null | head -n1)"
done
case "$ZYB_HOST" in ''|*[!a-z0-9.-]*) echo "the portal host name is not set - run: echo soc.example.com | sudo tee /etc/sentra/portal-host"; exit 1;; esac
ZYB_HOST_RE="$(printf '%s' "$ZYB_HOST" | sed 's/\./\\./g')"
# ZYB_NGINX_ETC / ZYB_NGINX / ZYB_NGINX_RELOAD / ZYB_BAKDIR / ZYB_WEB / ZYB_CURL / ZYB_WAIT: only for the test
# (tools/frontend-audit/login-skin-install.test.js)
ETC="${ZYB_NGINX_ETC:-/etc/nginx}"; NGX="${ZYB_NGINX:-nginx}"; RELOAD="${ZYB_NGINX_RELOAD:-systemctl reload nginx}"; CURL="${ZYB_CURL:-curl}"
[ -n "${ZYB_NGINX_ETC:-}" ] || [ "$(id -u)" = 0 ] || { echo "!! login-skin: run with sudo"; exit 1; }
HERE="$(cd "$(dirname "$0")" && pwd)"
MARK="ZYB-LOGINSKIN"; WEB="${ZYB_WEB:-/var/www/sentra/zyb-login}"; HOST="$ZYB_HOST"
WAIT="${ZYB_WAIT:-30}"   # seconds the checks keep trying: the update has just reloaded nginx and restarted services
MODE=on; DESK=""
while [ $# -gt 0 ]; do case "$1" in --remove) MODE=off;; --desk) DESK="${2:-}"; shift;; *) echo "!! login-skin: unknown option: $1"; exit 1;; esac; shift; done
if [ -n "$DESK" ]; then printf '%s' "$DESK" | grep -qE '^[A-Za-z0-9@._+ ()-]{3,80}$' || { echo "!! login-skin --desk: an email address or phone number, letters, digits and @ . _ + - ( ) only"; exit 1; }; fi

# (|| true: nginx -T fails on a broken config, and under pipefail that must not end the script silently - the grep below finds the file)
nginx_site() { { $NGX -T 2>/dev/null || true; } | awk '/^# configuration file /{f=$4; sub(/:$/,"",f)} /server_name[^;]*'"$ZYB_HOST_RE"'/{print f; exit}'; }
FILE="$(nginx_site)"; [ -n "$FILE" ] || FILE="$(grep -RlE --exclude='*.bak*' --exclude='*~' 'server_name[^;]*'"$ZYB_HOST_RE"'' "$ETC/sites-enabled" "$ETC/conf.d" "$ETC/nginx.conf" 2>/dev/null | head -n1 || true)"
[ -n "$FILE" ] || { echo "!! login-skin: could not find the nginx file with server_name $ZYB_HOST - nothing changed"; exit 1; }
FILE="$(readlink -f "$FILE")"; echo "==> portal server block: $FILE"
BAKDIR="${ZYB_BAKDIR:-/var/backups/nginx-zyb}"; mkdir -p "$BAKDIR"; chmod 700 "$BAKDIR"
BAK="$BAKDIR/$(basename "$FILE").$(date +%Y%m%d-%H%M%S)-login"; cp -a "$FILE" "$BAK"; echo "    backup: $BAK"
restore() { cp -a "$BAK" "$FILE"; { $NGX -t >/dev/null 2>&1 && $RELOAD; } || true; echo "!! login-skin: $1 - the original nginx file was put back, the sign-in page is as it was"; exit 1; }
TAG='<script src="/zyb-login/zyb-login.js"></script></head>'
INS=" sub_filter_types text/html; sub_filter '</head>' '$TAG'; sub_filter_once on; set \$zyb_loginskin 1;"
export INS
strip() { awk -v m="$MARK" 'index($0,"# " m " BEGIN"){skip=1;next} skip{if(index($0,"# " m " END"))skip=0;next} index($0,"# " m){next}
  { ins=ENVIRON["INS"]; while ((i=index($0,ins))>0) $0=substr($0,1,i-1) substr($0,i+length(ins)); print }' "$1"; }

if [ "$MODE" = off ]; then
  strip "$BAK" > "$FILE"; $NGX -t || restore "nginx -t failed"; $RELOAD
  rm -rf "$WEB"; echo "==> sign-in skin switched off - the sign-in service's own page is back"; exit 0
fi

{ $NGX -V 2>&1 || true; } | grep -q -- '--with-http_sub_module' || { rm -f "$BAK"; echo "!! login-skin: this nginx was built without the sub_filter module - nothing changed"; exit 1; }
[ -f "$HERE/login-skin/zyb-login.js" ] || { rm -f "$BAK"; echo "!! login-skin: login-skin/zyb-login.js is missing next to this script"; exit 1; }
mkdir -p "$WEB"; chmod 755 "$WEB"
# the brand setting (vendor/zyb-org.js: company name, logo, colours) is built into the script, so the sign-in page needs one file
[ -f "$HERE/vendor/zyb-org.js" ] || { rm -f "$BAK"; echo "!! login-skin: vendor/zyb-org.js (the brand setting) is missing next to this script"; exit 1; }
{ cat "$HERE/vendor/zyb-org.js"; echo; cat "$HERE/login-skin/zyb-login.js"; } > "$WEB/zyb-login.js.new"
# the service desk contact: written as a JavaScript string; the value was checked above to hold no quote or backslash
[ -n "$DESK" ] && sed -i "s|var DESK = '';|var DESK = '$DESK';|" "$WEB/zyb-login.js.new"
chmod 644 "$WEB/zyb-login.js.new"; mv "$WEB/zyb-login.js.new" "$WEB/zyb-login.js"
echo "    script: $WEB/zyb-login.js${DESK:+ (service desk: $DESK)}"

# start from the file without an earlier install, then add: the public /zyb-login/ location (before the logo location,
# like the dashboards install) and the sub_filter line inside every location that serves the sign-in pages
strip "$BAK" > "$FILE.zyb"
awk -v m="$MARK" -v web="$WEB" '
  /server_name[^;]*'"$ZYB_HOST_RE"'/ { inblock=1 }
  inblock && !pub && /location = \/logo\.webp/ {
    print "    # " m " BEGIN (sign-in page design; remove with install-login-skin.sh --remove)"
    print "    location ^~ /zyb-login/ { alias " web "/; default_type application/javascript; charset utf-8; add_header Cache-Control \"no-cache\" always; }"
    print "    # " m " END"
    pub=1
  }
  inblock && /^[[:space:]]*location[[:space:]]+((=|\^~)[[:space:]]*)?(\/login([\/[:space:]{]|$)|@login)/ && index($0,"{") {
    i=index($0,"{"); $0=substr($0,1,i) ENVIRON["INS"] substr($0,i+1); n++
  }
  { print }
  END { if (!pub) exit 3; if (!n) exit 4 }' "$FILE.zyb" > "$FILE.new" || {
    rc=$?; rm -f "$FILE.zyb" "$FILE.new"; cp -a "$BAK" "$FILE"
    [ $rc = 3 ] && echo "!! login-skin: could not find the place to add /zyb-login/ (location = /logo.webp) - nothing changed"
    [ $rc = 4 ] && { echo "!! login-skin: no nginx location for the sign-in page (location /login or @login) - nothing changed. Send me these lines:"; { $NGX -T 2>/dev/null || true; } | grep -nE 'location|proxy_pass|error_page' | grep -iE 'login|auth|@' | head -20; }
    exit 1; }
cat "$FILE.new" > "$FILE"; rm -f "$FILE.zyb" "$FILE.new"
echo "    sign-in locations changed: $(grep -c 'zyb_loginskin' "$FILE")"
$NGX -t || restore "nginx -t failed"
$RELOAD

# check, for up to $WAIT seconds: the update has just reloaded nginx several times and restarted services, so the first
# answers can be a 502 or an old worker. Each failure names its cause; only a failure caused by this change puts the
# original file back - a sign-in service that is down is not the skin's fault, and removing the skin would not help.
code() { local c; c="$($CURL -sk -o /dev/null -w '%{http_code}' -H "Host: $HOST" "https://127.0.0.1$1" 2>/dev/null || true)"; echo "${c:-000}"; }
T0=$(date +%s); JS=""; LG=""; HDR=""; BODY=""
while :; do
  JS="$(code /zyb-login/zyb-login.js)"
  LG="$(code /login)"
  if [ "$JS" = 200 ] && [ "$LG" = 200 ]; then
    BODY="$($CURL -sk -H "Host: $HOST" https://127.0.0.1/login 2>/dev/null || true)"
    printf '%s' "$BODY" | grep -q 'zyb-login/zyb-login.js' && break
  fi
  [ $(( $(date +%s) - T0 )) -ge "$WAIT" ] && break
  sleep 2
done
if [ "$JS" = 200 ] && [ "$LG" = 200 ] && printf '%s' "$BODY" | grep -q 'zyb-login/zyb-login.js'; then
  echo "==> done: the sign-in page shows the new design. Open https://$HOST/login in a private window."
  echo "    switch off: sudo bash install-login-skin.sh --remove"; exit 0
fi
[ "$JS" = 200 ] || restore "the design script is not reachable at /zyb-login/ (HTTP $JS after ${WAIT}s)"
if [ "$LG" != 200 ]; then
  echo "!! login-skin: the sign-in page itself did not answer (HTTP $LG after ${WAIT}s) - the sign-in service is down or still starting; the design stays switched on and appears once it answers. Check: systemctl status sentra-auth"
  exit 1
fi
HDR="$($CURL -sk -D - -o /dev/null -H "Host: $HOST" -H 'Accept-Encoding: gzip' https://127.0.0.1/login 2>/dev/null | tr -d '\r' || true)"
if printf '%s' "$HDR" | grep -qi '^content-encoding:'; then
  restore "the sign-in service sends its page compressed, so nginx cannot add the design line. Add  proxy_set_header Accept-Encoding \"\";  to the /login location in $FILE, then run the update again"
fi
restore "the sign-in page did not get the design line (it may be served from another location than /login)"
