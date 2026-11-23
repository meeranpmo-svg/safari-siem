#!/bin/bash
# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
# add-dashboards-menu.sh - add a "Dashboards" group to the portal's left menu.
# Finds the portal page(s) that hold the menu (<ul class="nav">), backs each up to /var/backups/zyb-portal, and adds
# ONE line before </body>:  <script src="/dashboards/vendor/zyb-menu.js" defer></script><!--ZYB-MENU-->
# The script (installed with the dashboards) draws the group in the same style as the other menu items.
#   sudo bash add-dashboards-menu.sh            add (a second run changes nothing)
#   sudo bash add-dashboards-menu.sh --remove   take the line out again
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
MARK='<!--ZYB-MENU-->'
LINE='<script src="/dashboards/vendor/zyb-menu.js" defer></script><!--ZYB-MENU-->'
# and ONE line right after <head>: zyb-early.js runs before the portal's code, so a refresh never shows the old pages
EMARK='<!--ZYB-EARLY-->'
# zyb-org.js (the brand setting) goes first: the scripts added to the portal read the company name from it
ELINE='<script src="/dashboards/vendor/zyb-org.js"></script><script src="/dashboards/vendor/zyb-early.js"></script><!--ZYB-EARLY-->'
[ -f /var/www/sentra/dashboards/vendor/zyb-menu.js ] || { echo "run install-dashboards.sh first (zyb-menu.js is not installed)"; exit 1; }
BAKDIR=/var/backups/zyb-portal; mkdir -p "$BAKDIR"; chmod 700 "$BAKDIR"
STAMP=$(date +%Y%m%d-%H%M%S)

mapfile -t FILES < <(grep -rlE --include='*.html' '<ul class="nav"' /var/www/sentra /opt/sentra-ai /opt/sentra-auth 2>/dev/null \
  | grep -vE '/dashboards/|/agent/|\.bak|\.prev|/node_modules/|backup' | head -n 6 || true)
if [ "${#FILES[@]}" -eq 0 ]; then
  echo "no portal page with the menu (<ul class=\"nav\">) was found - nothing changed."
  echo "send the output of: sudo bash /tmp/portal-find-sidebar.sh"
  exit 1
fi
if [ "${#FILES[@]}" -gt 5 ]; then echo "more than 5 candidate pages found - nothing changed:"; printf '  %s\n' "${FILES[@]}"; exit 1; fi

for f in "${FILES[@]}"; do
  if [ "${1:-}" = "--remove" ]; then
    grep -q "$MARK" "$f" || { echo "  $f: not present"; continue; }
    cp -a "$f" "$BAKDIR/$(echo "$f" | tr / _).$STAMP"
    sed -i "\#$MARK#d" "$f"; sed -i "s#$ELINE##" "$f"
    echo "  $f: removed"
    continue
  fi
  # the early line (also on pages that already have the menu line): right after the first <head ...>
  if ! grep -q "$EMARK" "$f" && grep -qiE '<head[ >]' "$f" && [ -f /var/www/sentra/dashboards/vendor/zyb-early.js ]; then
    cp -a "$f" "$BAKDIR/$(echo "$f" | tr / _).$STAMP.early"
    awk -v line="$ELINE" '!done && tolower($0) ~ /<head[ >]/ { n=index(tolower($0),"<head"); rest=substr($0,n); m=index(rest,">"); print substr($0,1,n+m-1) line substr($0,n+m); done=1; next } {print}' "$f" > "$f.zybtmp" && cat "$f.zybtmp" > "$f"; rm -f "$f.zybtmp"
    grep -q "$EMARK" "$f" && echo "  $f: early menu script added (no old pages on refresh)"
  fi
  if grep -q "$MARK" "$f"; then echo "  $f: already added"; continue; fi
  grep -qi '</body>' "$f" || { echo "  $f: no </body> - skipped"; continue; }
  cp -a "$f" "$BAKDIR/$(echo "$f" | tr / _).$STAMP"
  # insert before the LAST </body> (case-insensitive), keeping owner and mode
  awk -v line="$LINE" '{a[NR]=$0} tolower($0) ~ /<\/body>/ {last=NR} END{for(i=1;i<=NR;i++){ if(i==last){ n=index(tolower(a[i]),"</body>"); print substr(a[i],1,n-1) line; print substr(a[i],n) } else print a[i] }}' "$f" > "$f.zybtmp"
  cat "$f.zybtmp" > "$f"; rm -f "$f.zybtmp"
  echo "  $f: Dashboards menu added (backup in $BAKDIR)"
done
echo "done - reload the portal (Ctrl + F5). The Dashboards group is at the top of the left menu."
