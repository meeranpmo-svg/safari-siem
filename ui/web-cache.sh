#!/bin/bash
# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
# web-cache.sh - stop browsers keeping old portal pages after an update on the portal (run by update-server.sh).
# The portal's own pages (index.html, its app.js / menu scripts when unversioned, JSON it loads) were sent with no
# Cache-Control at all, so a browser cached them by guesswork (a share of the file's age) and kept showing the old build
# until Ctrl+F5. Here every such file is sent "re-check first" (expires epoch = Cache-Control: no-cache): the browser
# keeps its copy but asks nginx, which answers 304 when nothing changed - so it costs a round trip, not a download.
# Left alone: /api/ and /auth/ (the services set their own headers), /dashboards/ and /zyb-login/ (their own rules,
# add-dashboards-nginx.sh / install-login-skin.sh), and any file requested with ?v=<build> (its URL changes each build).
# `expires` is used rather than add_header on purpose: a server-level add_header would stop the locations inheriting
# the security headers set above them. Backed up, nginx -t, reload only if the test passes, else restored.
#   sudo bash web-cache.sh   |   --remove
set -euo pipefail
# the portal's host name is a setting, never text in this script: ZYB_PORTAL_HOST, else /etc/sentra/portal-host, else the
# brand setting this package was built with (vendor/zyb-org.js, written by tools/brand/apply-brand.js)
ZYB_HOST="${ZYB_PORTAL_HOST:-$(cat /etc/sentra/portal-host 2>/dev/null || true)}"
for _b in "$(cd "$(dirname "$0")" && pwd)/vendor/zyb-org.js" /var/www/sentra/dashboards/vendor/zyb-org.js; do
  [ -n "$ZYB_HOST" ] || ZYB_HOST="$(sed -n 's/.*"portal_host": *"\([^"]*\)".*/\1/p' "$_b" 2>/dev/null | head -n1)"
done
case "$ZYB_HOST" in ''|*[!a-z0-9.-]*) echo "the portal host name is not set - run: echo soc.example.com | sudo tee /etc/sentra/portal-host"; exit 1;; esac
ZYB_HOST_RE="$(printf '%s' "$ZYB_HOST" | sed 's/\./\\./g')"
# ZYB_NGINX_ETC / ZYB_NGINX / ZYB_NGINX_RELOAD / ZYB_BAKDIR: only for the test (tools/frontend-audit/web-cache.test.js)
ETC="${ZYB_NGINX_ETC:-/etc/nginx}"; NGX="${ZYB_NGINX:-nginx}"; RELOAD="${ZYB_NGINX_RELOAD:-systemctl reload nginx}"
[ -n "${ZYB_NGINX_ETC:-}" ] || [ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
MARK="ZYB-PORTALCACHE"
MAP="$ETC/conf.d/zyb-portal-cache.conf"
# (|| true: nginx -T fails on a broken config, and under pipefail that must not end the script silently - the grep below finds the file)
nginx_site() { { $NGX -T 2>/dev/null || true; } | awk '/^# configuration file /{f=$4; sub(/:$/,"",f)} /server_name[^;]*'"$ZYB_HOST_RE"'/{print f; exit}'; }
FILE="$(nginx_site)"; [ -n "$FILE" ] || FILE="$(grep -RlE --exclude='*.bak*' --exclude='*~' 'server_name[^;]*'"$ZYB_HOST_RE"'' "$ETC/sites-enabled" "$ETC/conf.d" "$ETC/nginx.conf" 2>/dev/null | head -n1 || true)"
[ -n "$FILE" ] || { echo "!! web-cache: could not find the nginx file with server_name $ZYB_HOST - nothing changed"; exit 1; }
FILE="$(readlink -f "$FILE")"
BAKDIR="${ZYB_BAKDIR:-/var/backups/nginx-zyb}"; mkdir -p "$BAKDIR"; chmod 700 "$BAKDIR"
BAK="$BAKDIR/$(basename "$FILE").cache.$(date +%Y%m%d-%H%M%S)"
cp -a "$FILE" "$BAK"
MAPBAK=""; [ -f "$MAP" ] && { MAPBAK="$BAKDIR/zyb-portal-cache.conf.$(date +%Y%m%d-%H%M%S)"; cp -a "$MAP" "$MAPBAK"; }
put_back() { cp -a "$BAK" "$FILE"; if [ -n "$MAPBAK" ]; then cp -a "$MAPBAK" "$MAP"; else rm -f "$MAP"; fi; }
# nginx -t failed after our change: put everything back. A site that already sets its own `expires` keeps it (its own cache
# policy wins - not an update failure); any other error is shown in full so it can be fixed, and the step fails.
restore() {
  local err; err="$({ $NGX -t 2>&1 || true; } | grep -E 'emerg|error' | head -n3 || true)"; put_back
  if printf '%s' "$err" | grep -qiE '"expires" directive is duplicate'; then
    echo "==> web-cache: the site already sets its own expires (cache policy) - left as it is; browsers follow that policy"; exit 0
  fi
  echo "!! web-cache: nginx -t failed with the cache rule - the original files were restored, nothing changed. nginx said: ${err:-no message}"; exit 1
}

if [ "${1:-}" = "--remove" ]; then
  grep -v "# $MARK" "$BAK" > "$FILE"; rm -f "$MAP"
  $NGX -t 2>/dev/null || restore
  $RELOAD; echo "==> web-cache: removed"; exit 0
fi

# nginx must be valid BEFORE this step - otherwise the error is not ours and we must not reload anything
if ! PRE="$($NGX -t 2>&1)"; then rm -f "$BAK" "${MAPBAK:-/nonexistent}" 2>/dev/null; echo "!! web-cache: nginx -t already fails before this step (not caused by it) - nothing changed. nginx said: $(printf '%s' "$PRE" | grep -E 'emerg|error' | head -n3 || true)"; exit 1; fi
# the map lives at http level: only possible where nginx includes conf.d/*.conf (the Ubuntu / Debian default)
CONFD_RX="^\\s*include\\s+$(printf '%s' "$ETC" | sed 's/[.]/\\./g')/conf\\.d/\\*\\.conf"
if ! $NGX -T 2>/dev/null | grep -qE "$CONFD_RX"; then
  rm -f "$BAK"; echo "!! web-cache: nginx does not include $ETC/conf.d/*.conf - not changed (browsers may need Ctrl+F5 after an update)"; exit 0
fi
cat > "$MAP" <<'NGX'
# web-cache.sh (ZYB-PORTALCACHE): which portal responses the browser must re-check (epoch = Cache-Control: no-cache).
# Key: "<path>|<?v= value>". First matching regex wins.
map "$uri|$arg_v" $zyb_portal_expires {
    default off;
    "~^/(api|auth|dashboards|zyb-login)(/|\|)" off;
    "~\|.+$" off;
    "~*^[^|]*(/|\.html?|\.js|\.css|\.json|\.webmanifest)\|$" epoch;
}
NGX
chmod 644 "$MAP"

if grep -q "# $MARK" "$BAK"; then
  echo "==> web-cache: portal pages already re-checked by browsers"
else
  # one line after server_name in every portal server block (HTTP and HTTPS)
  awk -v m="$MARK" '
    /^[ \t]*server_name[ \t][^;]*'"$ZYB_HOST_RE"'/ { print; match($0, /^[ \t]*/); printf "%sexpires $zyb_portal_expires;  # %s: browsers re-check portal pages, so an update shows without Ctrl+F5\n", substr($0, 1, RLENGTH), m; n++; next }
    { print }
    END { if (!n) exit 3 }' "$BAK" > "$FILE" || { cp -a "$BAK" "$FILE"; echo "!! web-cache: no server_name $ZYB_HOST line found - nothing changed"; exit 1; }
fi
$NGX -t 2>/dev/null || restore
$RELOAD
echo "==> web-cache: done - portal pages are re-checked on every visit (304 when unchanged); undo: sudo bash web-cache.sh --remove"
