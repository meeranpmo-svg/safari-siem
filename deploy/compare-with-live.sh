#!/usr/bin/env bash
# Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
# compare-with-live.sh - READ-ONLY: what the clean tree holds against what the server actually runs.
#   the asset engine    backend/itam/{engine,pyengine}  vs /opt/sentra-itam/{engine,pyengine}
#   the SIEM engine     backend/siem/engine              vs /opt/sentra-siem/engine
#   the portal pages    ui/ after the same build the installer applies (build-static.js, with the stamp the server serves
#                       now)                             vs /var/www/sentra/dashboards
# Each file is SAME, DIFFERENT, NOT ON THE SERVER (in the clean tree, never installed) or ONLY ON THE SERVER (installed
# but not live code - an old module, or a file another installer added). Nothing is written outside a temporary folder.
#
#   bash compare-with-live.sh [--list]        (--list prints every file, not only the differences)
# Override the live locations for a test: ITAM=/x SIEM=/y WEB=/z bash compare-with-live.sh
set -uo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
ITAM="${ITAM:-/opt/sentra-itam}"; SIEM="${SIEM:-/opt/sentra-siem}"; WEB="${WEB:-/var/www/sentra/dashboards}"
LIST=0; [ "${1:-}" = "--list" ] && LIST=1
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
tot_same=0; tot_diff=0; tot_miss=0; tot_only=0

cmp_tree() {   # <label> <clean dir> <live dir> [find filter]
  local label="$1" a="$2" b="$3" same=0 diff=0 miss=0 only=0 f
  echo "== $label"
  if [ ! -d "$b" ]; then echo "   live folder $b not found - skipped"; return; fi
  while IFS= read -r f; do
    if [ ! -f "$b/$f" ]; then miss=$((miss+1)); echo "   NOT ON THE SERVER  $f"
    elif cmp -s "$a/$f" "$b/$f"; then same=$((same+1)); [ "$LIST" = 1 ] && echo "   same               $f"
    else diff=$((diff+1)); echo "   DIFFERENT          $f"; fi
  done < <(cd "$a" && find . -type f ! -path '*/__pycache__/*' ! -name '*.pyc' ! -name '.zyb-static.json' | sed 's#^\./##' | sort)
  while IFS= read -r f; do
    [ -f "$a/$f" ] || { only=$((only+1)); echo "   ONLY ON THE SERVER $f"; }
  done < <(cd "$b" && find . -type f ! -path '*/__pycache__/*' ! -name '*.pyc' ! -name '*.bak' ! -name '*.gz' ! -name '.zyb-static.json' | sed 's#^\./##' | sort)
  echo "   -> same $same · different $diff · not on the server $miss · only on the server $only"
  tot_same=$((tot_same+same)); tot_diff=$((tot_diff+diff)); tot_miss=$((tot_miss+miss)); tot_only=$((tot_only+only))
}

cmp_tree "asset engine (sentra-itam) - engine" "$HERE/backend/itam/engine" "$ITAM/engine"
cmp_tree "asset engine (sentra-itam) - pyengine" "$HERE/backend/itam/pyengine" "$ITAM/pyengine"
cmp_tree "SIEM engine (sentra-siem) - engine" "$HERE/backend/siem/engine" "$SIEM/engine"

# the pages: apply the installer's build to a copy, with the stamp the live index.html carries
if [ -f "$WEB/index.html" ]; then
  STAMP="$(grep -o '?v=[0-9A-Za-z._-]*' "$WEB/index.html" | head -n1 | cut -c4-)"
  cp -a "$HERE/ui" "$TMP/ui"
  if [ -n "$STAMP" ] && command -v node >/dev/null && node "$TMP/ui/build-static.js" "$TMP/ui" "$STAMP" >/dev/null 2>&1; then
    echo "   (pages built with the live stamp $STAMP before comparing)"
  else echo "   (pages compared as they are - no stamp found or node missing; built pages will read DIFFERENT)"; fi
  cmp_tree "portal pages (dashboards)" "$TMP/ui" "$WEB"
else echo "== portal pages: $WEB/index.html not found - skipped"; fi

echo
echo "TOTAL same $tot_same · different $tot_diff · not on the server $tot_miss · only on the server $tot_only"
echo "DIFFERENT = the server runs another version (not updated yet, or changed on the server). ONLY ON THE SERVER = installed"
echo "but not live code in the clean tree (docs/CODEMAP.md lists what was left out and why). Nothing was changed."
