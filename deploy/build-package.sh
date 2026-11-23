#!/usr/bin/env bash
# Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
# build-package.sh - the update package (what update-server.sh installs) built from this tree, in the layout of
# deploy/stage-map.txt. It only builds: nothing is copied to a server and nothing is installed.
#
#   deploy/build-package.sh <out-dir>
#
# Result: <out-dir>/stage/ (the package contents), <out-dir>/sentra-update.tgz and its SHA-256 in <out-dir>/sentra-update.tgz.sha256
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:?usage: build-package.sh <out-dir>}"
MAP="$HERE/deploy/stage-map.txt"
[ -f "$MAP" ] || { echo "x $MAP missing"; exit 1; }
node "$HERE/tools/brand/apply-brand.js" --check >/dev/null || { echo "x the generated brand copies are stale - run: node tools/brand/apply-brand.js"; exit 1; }
src_of() { echo "$HERE/$1"; }   # a path in this tree
rm -rf "$OUT/stage"; mkdir -p "$OUT/stage"
n=0
while read -r rec from to; do
  case "$rec" in ''|'#'*) continue ;; esac
  src="$(src_of "$from")"; dst="$OUT/stage/$to"
  if [ "$rec" = 1 ]; then                       # a whole folder, copied to that name (Copy-Item -Recurse dir dest)
    [ -d "$src" ] || { echo "x missing folder $src"; exit 1; }
    mkdir -p "$(dirname "$dst")"; rm -rf "$dst"; cp -a "$src" "$dst"
    find "$dst" \( -name __pycache__ -o -name .git \) -prune -exec rm -rf {} + 2>/dev/null || true
  else
    case "$to" in */) mkdir -p "$dst" ;; *) mkdir -p "$(dirname "$dst")" ;; esac
    shopt -s nullglob; set -- $src; shopt -u nullglob    # engine/*.js style sources
    [ "$#" -gt 0 ] || { echo "x missing $src"; exit 1; }
    cp -p "$@" "$dst"
  fi
  n=$((n+1))
done < "$MAP"
[ -f "$OUT/stage/sentra-siem/install/vendor/anthropic-sdk-0.133.0.tgz" ] || { echo "x the offline SDK bundle is missing from the package"; exit 1; }
tar -czf "$OUT/sentra-update.tgz" -C "$OUT/stage" .
( cd "$OUT" && sha256sum sentra-update.tgz > sentra-update.tgz.sha256 )
echo "package: $n entries, $(find "$OUT/stage" -type f | wc -l) files, $(du -sh "$OUT/sentra-update.tgz" | cut -f1) -> $OUT/sentra-update.tgz"
echo "SHA-256: $(cut -d' ' -f1 "$OUT/sentra-update.tgz.sha256")"
