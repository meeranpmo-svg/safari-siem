#!/usr/bin/env bash
# Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
# run-tests.sh [itam|siem|ui] - every test of the clean tree (default: all three parts). Exit code 1 if anything failed.
set -uo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"; PART="${1:-all}"; bad=0
suite() {   # <label> <folder>: node --test once, summary lines shown, exit code kept
  echo "== $1"; local out; out="$(cd "$2" && node --test tests/*.test.js 2>&1)"; local rc=$?
  printf '%s\n' "$out" | grep -E '^# (pass|fail|skipped)|^not ok' | sed 's/^/   /'; [ "$rc" = 0 ] || bad=1
}
node "$HERE/tools/brand/apply-brand.js" --check >/dev/null || { echo "   the generated brand copies are stale: run node tools/brand/apply-brand.js"; bad=1; }
if [ "$PART" = all ] || [ "$PART" = itam ]; then suite "asset engine (backend/itam)" "$HERE/backend/itam"; fi
if [ "$PART" = all ] || [ "$PART" = siem ]; then suite "SIEM engine (backend/siem)" "$HERE/backend/siem"; fi
if [ "$PART" = all ] || [ "$PART" = ui ]; then
  echo "== pages (tests/ui, Chromium)"
  if [ -z "${PLAYWRIGHT:-}" ] && ! node -e "require('playwright')" 2>/dev/null; then echo "   skipped: set PLAYWRIGHT=<path to the playwright package>"; else
    # the page tests cover every module, so they run with nothing switched off; sector-profile.test.js builds its own
    # copy of the real brand setting and checks what is off for this organisation. The real page copy is put back whatever happens.
    node "$HERE/tools/brand/apply-brand.js" --all-modules >/dev/null; trap 'node "$HERE/tools/brand/apply-brand.js" >/dev/null' EXIT
    n=0; f=0; for t in "$HERE"/tests/ui/*.test.js; do n=$((n+1)); r="$(cd "$HERE/tests/ui" && timeout 300 node "$t" 2>&1)"; rc=$?
      [ "$rc" = 0 ] || { f=$((f+1)); bad=1; echo "   FAIL $(basename "$t"): $(printf '%s\n' "$r" | grep -m3 -E 'FAIL|Error' | tr '\n' ' ')"; }; done
    node "$HERE/tools/brand/apply-brand.js" >/dev/null; trap - EXIT
    echo "   $((n-f)) of $n page tests passed"; fi
fi
[ "$bad" = 0 ] && echo "ALL GREEN" || echo "FAILURES - see above"
exit "$bad"
