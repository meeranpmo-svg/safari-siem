#!/bin/bash
# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
# install-portal.sh - put the portal pages from this repository (repos/live/portal: app.js + index.html) on the server,
# where nginx serves them (/var/www/sentra). Run by update-server.sh BEFORE add-dashboards-menu.sh, which then adds
# its two menu lines to the new index.html again.
#
# Until this script existed nothing copied the repository's portal to the server, so every change made to the portal in
# git (ISP & Bandwidth, the live Switches card, the Admin Panel backup tab, the error reporting …) never reached it.
#
# Safety: the server's files are replaced only when they are a version this repository knows - the copy taken from the
# server (commit 9e38268e) or a version this script deployed (recorded in /var/lib/zyb/portal-deployed.txt). If someone
# changed the portal on the server some other way, nothing is replaced: the server's copy is kept for comparison and the
# script says so. /var/lib/zyb/portal-force (or ZYB_PORTAL_FORCE=1) replaces it anyway, backed up first.
#   sudo bash install-portal.sh SRC_DIR            install from SRC_DIR (holds app.js and index.html)
#   sudo touch /var/lib/zyb/portal-force   replace a server copy changed some other way at the next run (once)
#   sudo bash install-portal.sh --rollback         put back the copy from before the last install
set -uo pipefail
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
WEB="${ZYB_PORTAL_WEB:-/var/www/sentra}"
STATE="${ZYB_PORTAL_STATE:-/var/lib/zyb}"; KNOWN="$STATE/portal-deployed.txt"
BAK="${ZYB_PORTAL_BAK:-/var/backups/zyb-portal/pages}"
# the versions taken from the server into git (commit 9e38268e): app.js, and index.html with the menu lines left out
BASE_APP=f50c0197a000e8d04e484dd0ce78bd923aa7be91ed3bae37cc9e59fdbafb74e1
BASE_IDX=aa397ab94511b68289a9bc1614da46162b51c11a775fb4a973c3102edaabc26f
mkdir -p "$STATE" "$BAK"; chmod 700 "$BAK"

# index.html as it is without the two lines add-dashboards-menu.sh adds, so the menu add-on does not read as "changed"
norm_idx() { sed -e 's#<script src="/dashboards/vendor/zyb-early.js"></script><!--ZYB-EARLY-->##' -e '\#<!--ZYB-MENU-->#d' "$1" | sha256sum | cut -d' ' -f1; }
app_sum() { sha256sum "$1" | cut -d' ' -f1; }
known() { [ "$1" = "$2" ] || grep -qx "$3 $1" "$KNOWN" 2>/dev/null; }

if [ "${1:-}" = "--rollback" ]; then
  L="$(ls -1d "$BAK"/20* 2>/dev/null | tail -n1)"
  [ -n "$L" ] || { echo "!! portal: no backup to roll back to"; exit 1; }
  for f in app.js index.html; do [ -f "$L/$f" ] && cat "$L/$f" > "$WEB/$f"; done
  echo "==> portal: put back the pages from $(basename "$L")"; exit 0
fi

SRC="${1:-}"
[ -f "$SRC/app.js" ] && [ -f "$SRC/index.html" ] || { echo "!! portal: app.js / index.html not found in '${SRC}' - nothing changed"; exit 1; }
[ -f "$WEB/app.js" ] && [ -f "$WEB/index.html" ] || { echo "!! portal: $WEB/app.js or index.html is missing on this server - nothing changed (is the portal served from somewhere else?)"; exit 1; }

NEW_APP="$(app_sum "$SRC/app.js")"; NEW_IDX="$(norm_idx "$SRC/index.html")"
CUR_APP="$(app_sum "$WEB/app.js")"; CUR_IDX="$(norm_idx "$WEB/index.html")"
if [ "$CUR_APP" = "$NEW_APP" ] && [ "$CUR_IDX" = "$NEW_IDX" ]; then echo "==> portal: pages already current"; exit 0; fi

# the new app.js must at least parse before it replaces a working one
if command -v node >/dev/null 2>&1; then
  node --check "$SRC/app.js" 2>/tmp/zyb-portal-check.txt || { echo "!! portal: the new app.js does not parse - nothing changed: $(head -c 300 /tmp/zyb-portal-check.txt)"; exit 1; }
fi
grep -q 'src="app.js?v=' "$SRC/index.html" || { echo "!! portal: the new index.html does not load app.js - nothing changed"; exit 1; }

UNKNOWN=""
known "$CUR_APP" "$BASE_APP" app || UNKNOWN="$UNKNOWN app.js"
known "$CUR_IDX" "$BASE_IDX" idx || UNKNOWN="$UNKNOWN index.html"
STAMP="$(date +%Y%m%d-%H%M%S)-$$"
FORCE="${ZYB_PORTAL_FORCE:-}"; [ -f "$STATE/portal-force" ] && FORCE=1   # one-shot: sudo touch /var/lib/zyb/portal-force, then run the update again
if [ -n "$UNKNOWN" ] && [ "$FORCE" != 1 ]; then
  KEEP="$BAK/server-changed-$STAMP"; mkdir -p "$KEEP"; cp -p "$WEB/app.js" "$WEB/index.html" "$KEEP/"
  echo "!! portal: NOT updated - the server's$UNKNOWN was changed by something other than this update (copy kept in $KEEP)."
  echo "!!   Send this message to Claude. To replace it anyway (the server's copy is backed up first): sudo touch $STATE/portal-force, then run the update again."
  exit 1
fi

D="$BAK/$STAMP"; mkdir -p "$D"; cp -p "$WEB/app.js" "$WEB/index.html" "$D/" || { echo "!! portal: backup failed - nothing changed"; exit 1; }
# write over the existing files (keeps their owner and mode); app.js first, then the page that asks for the new ?v=
cat "$SRC/app.js" > "$WEB/app.js.zybnew" && cat "$WEB/app.js.zybnew" > "$WEB/app.js"; rm -f "$WEB/app.js.zybnew"
cat "$SRC/index.html" > "$WEB/index.html"
if [ "$(app_sum "$WEB/app.js")" != "$NEW_APP" ] || [ "$(norm_idx "$WEB/index.html")" != "$NEW_IDX" ]; then
  cat "$D/app.js" > "$WEB/app.js"; cat "$D/index.html" > "$WEB/index.html"
  echo "!! portal: the copy did not verify - the previous pages were put back"; exit 1
fi
{ echo "app $NEW_APP"; echo "idx $NEW_IDX"; } >> "$KNOWN"; rm -f "$STATE/portal-force"
ls -1d "$BAK"/20* 2>/dev/null | head -n -10 | xargs -r rm -rf   # keep the last 10 backups
echo "==> portal: pages updated (app.js $(sed -n 's/.*app\.js?v=\([0-9]*\).*/\1/p' "$WEB/index.html" | head -n1)) - previous copy in $D, undo: sudo bash install-portal.sh --rollback${UNKNOWN:+ (forced over a server change:$UNKNOWN)}"
