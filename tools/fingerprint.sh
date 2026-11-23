#!/usr/bin/env bash
# Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
# fingerprint.sh - write deploy/SHA256SUMS: the SHA-256 of every production file (pages, engines, server scripts; tests
# left out). deploy/compare-with-live.sh on the server and reviews use it. Run it before building a package.
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"; cd "$HERE"
find ui backend deploy/server -type f -not -path '*/tests/*' -not -path '*/__pycache__/*' -print0 | LC_ALL=C sort -z | xargs -0 sha256sum > deploy/SHA256SUMS
echo "deploy/SHA256SUMS: $(wc -l < deploy/SHA256SUMS) files"
