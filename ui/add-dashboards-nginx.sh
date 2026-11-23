#!/bin/bash
# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
# add-dashboards-nginx.sh - publish /var/www/sentra/dashboards at https://<portal>/dashboards/ behind the
# portal's own login (auth_request /auth/verify, 401 -> @login), in the portal server block.
# Backs up the nginx file, inserts the location once (marker ZYB-DASHBOARDS), runs nginx -t and reloads only if the
# test passes - otherwise the backup is restored.   sudo bash add-dashboards-nginx.sh   |   --remove to take it out
set -euo pipefail
# the portal's host name is a setting, never text in this script: ZYB_PORTAL_HOST, else /etc/sentra/portal-host, else the
# brand setting this package was built with (vendor/zyb-org.js, written by tools/brand/apply-brand.js)
ZYB_HOST="${ZYB_PORTAL_HOST:-$(cat /etc/sentra/portal-host 2>/dev/null || true)}"
for _b in "$(cd "$(dirname "$0")" && pwd)/vendor/zyb-org.js" /var/www/sentra/dashboards/vendor/zyb-org.js; do
  [ -n "$ZYB_HOST" ] || ZYB_HOST="$(sed -n 's/.*"portal_host": *"\([^"]*\)".*/\1/p' "$_b" 2>/dev/null | head -n1)"
done
case "$ZYB_HOST" in ''|*[!a-z0-9.-]*) echo "the portal host name is not set - run: echo soc.example.com | sudo tee /etc/sentra/portal-host"; exit 1;; esac
ZYB_HOST_RE="$(printf '%s' "$ZYB_HOST" | sed 's/\./\\./g')"
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
MARK="ZYB-DASHBOARDS"
nginx_site() { # the file that holds the portal server block, as nginx itself reports it (follows links and includes)
  nginx -T 2>/dev/null | awk '/^# configuration file /{f=$4; sub(/:$/,"",f)} /server_name[^;]*'"$ZYB_HOST_RE"'/{print f; exit}'
}
FILE="$(nginx_site)"; [ -n "$FILE" ] || FILE="$(grep -RlE --exclude='*.bak*' --exclude='*~' 'server_name[^;]*'"$ZYB_HOST_RE"'' /etc/nginx/sites-enabled /etc/nginx/conf.d /etc/nginx/nginx.conf 2>/dev/null | head -n1 || true)"
[ -n "$FILE" ] || { echo "could not find the nginx file with server_name $ZYB_HOST"; exit 1; }
FILE="$(readlink -f "$FILE")"
echo "==> portal server block: $FILE"
# backups go OUTSIDE /etc/nginx: nginx would load a copy left in sites-enabled as a second server block
BAKDIR=/var/backups/nginx-zyb; mkdir -p "$BAKDIR"; chmod 700 "$BAKDIR"
BAK="$BAKDIR/$(basename "$FILE").$(date +%Y%m%d-%H%M%S)"
cp -a "$FILE" "$BAK"
echo "    backup: $BAK"

restore() { cp -a "$BAK" "$FILE"; echo "nginx -t failed - the original file was restored, nothing changed"; exit 1; }

if [ "${1:-}" = "--remove" ]; then
  awk -v m="$MARK" 'index($0,"# " m " BEGIN"){skip=1} !skip{print} index($0,"# " m " END"){skip=0}' "$BAK" > "$FILE"
  nginx -t || restore
  systemctl reload nginx; echo "==> /dashboards/ removed"; exit 0
fi

# /dashboards/whoami.json: the signed-in user's login name and role. The dashboards show Approve / Add / Configure from it.
# Values come from the portal's own login check, never from the browser. It must NOT be answered with "return": return
# runs in nginx's rewrite phase, BEFORE auth_request (access phase), so the user and role were always empty - every
# administrator saw the dashboards as a viewer - and the URL answered without a login. SSI fills the values in after
# the login check instead (template written below, outside the dashboards folder so a page update cannot remove it).
WHODIR=/var/www/sentra/zyb-whoami
WHO="$(cat <<NGX
    location = /dashboards/whoami.json {
        auth_request /auth/verify;
        auth_request_set \$sentra_role \$upstream_http_x_auth_role;
        auth_request_set \$sentra_user \$upstream_http_x_auth_user;
        default_type application/json;
        add_header Cache-Control "no-store" always;
        ssi on; ssi_types application/json;
        alias $WHODIR/whoami.json;
    }  # ZYB-WHOAMI2
NGX
)"; export WHO
mkdir -p "$WHODIR"; chmod 755 "$WHODIR"
printf '%s\n' '{"user":"<!--# echo var="sentra_user" default="" -->","role":"<!--# echo var="sentra_role" default="" -->"}' > "$WHODIR/whoami.json"
chmod 644 "$WHODIR/whoami.json"

# /dashboards/clear-cache: answers 204 with Clear-Site-Data "cache", so the browser drops every file it cached for this site
# (saved settings, storage and the sign-in cookie are not touched). The pages call it once when they see a new build
# (vendor/zyb-update.js), then reload - no Ctrl+F5 in any browser. Harmless without a login: it only empties the
# caller's own browser cache, so it is answered before the login check on purpose.
CLEAR="$(cat <<'NGX'
    location = /dashboards/clear-cache {
        add_header Clear-Site-Data '"cache"' always;
        add_header Cache-Control "no-store" always;
        return 204;
    }  # ZYB-CLEARCACHE
NGX
)"; export CLEAR
NOCACHE='        add_header Cache-Control "no-cache" always;  # ZYB-NOCACHE: browsers re-check (ETag) so updates show without Ctrl+F5'; export NOCACHE
# pages and scripts compressed on the way out (about 1 MB of add-on scripts becomes about a quarter of that)
GZIP='        gzip on; gzip_comp_level 5; gzip_min_length 1024; gzip_vary on; gzip_types text/css application/javascript text/javascript application/json image/svg+xml;  # ZYB-GZIP'; export GZIP

if grep -q "# $MARK BEGIN" "$FILE"; then
  if grep -q "ZYB-WHOAMI2" "$FILE" && grep -q "ZYB-NOCACHE" "$FILE" && grep -q "ZYB-GZIP" "$FILE" && grep -q "ZYB-CLEARCACHE" "$FILE"; then echo "==> /dashboards/ is already configured - nothing to do"; rm -f "$BAK"; exit 0; fi
  # older install: add what is missing inside the existing block (whoami location, no-cache header)
  HW=0; grep -q ZYB-WHOAMI2 "$BAK" && HW=1; HN=0; grep -q ZYB-NOCACHE "$BAK" && HN=1; HG=0; grep -q ZYB-GZIP "$BAK" && HG=1; HC=0; grep -q ZYB-CLEARCACHE "$BAK" && HC=1
  awk -v m="$MARK" -v hw="$HW" -v hn="$HN" -v hg="$HG" -v hc="$HC" '
    index($0,"# " m " BEGIN") { inb=1 }
    hw == 0 && /location = \/dashboards\/whoami\.json \{/ { skipw=1 }
    skipw { if (index($0, "ZYB-WHOAMI")) skipw=0; next }
    inb && !nc && (hn == 0 || hg == 0) && /location \/dashboards\/ \{/ { print; if (hn == 0) print ENVIRON["NOCACHE"]; if (hg == 0) print ENVIRON["GZIP"]; nc=1; next }
    index($0,"# " m " END") && !done && (hw == 0 || hc == 0) { if (hw == 0) print ENVIRON["WHO"]; if (hc == 0) print ENVIRON["CLEAR"]; done=1 }
    { print }' "$BAK" > "$FILE"
  nginx -t || restore
  systemctl reload nginx; echo "==> /dashboards/ updated: signed-in user and role lookup (admins see Approve / Add / Configure again), automatic cache refresh, cache clearing after an update, compression"; exit 0
fi
[ -d /var/www/sentra/dashboards ] || { echo "run install-dashboards.sh first"; rm -f "$BAK"; exit 1; }

# insert just before the logo location of the portal server block
awk -v m="$MARK" '
  /server_name[^;]*'"$ZYB_HOST_RE"'/ { inblock=1 }
  inblock && !done && /location = \/logo\.webp/ {
    print "    # " m " BEGIN (dashboards behind the portal login; remove with add-dashboards-nginx.sh --remove)"
    print "    location = /dashboards { return 301 /dashboards/; }"
    print "    location /dashboards/ {"
    print "        auth_request /auth/verify;"
    print "        auth_request_set $sentra_role $upstream_http_x_auth_role;"
    print "        auth_request_set $sentra_user $upstream_http_x_auth_user;"
    print "        error_page 401 = @login;"
    print ENVIRON["NOCACHE"]
    print ENVIRON["GZIP"]
    print "        alias /var/www/sentra/dashboards/;"
    print "        index index.html;"
    print "    }"
    print ENVIRON["WHO"]
    print ENVIRON["CLEAR"]
    print "    # " m " END"
    done=1
  }
  { print }
  END { if (!done) exit 3 }' "$BAK" > "$FILE" || { cp -a "$BAK" "$FILE"; echo "could not find the place to insert (location = /logo.webp) - nothing changed"; exit 1; }

nginx -t || restore
systemctl reload nginx
echo "==> done: open https://$ZYB_HOST/dashboards/ - sign in as usual"
echo "    undo: sudo bash add-dashboards-nginx.sh --remove"
