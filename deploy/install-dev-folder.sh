#!/usr/bin/env bash
# Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
# install-dev-folder.sh - put the clean the organisation tree on the server at /opt/sentra-platform, for development and code
# analysis. It does NOT touch the running platform: no service is stopped, started or reconfigured, nothing under
# /opt/sentra-itam, /opt/sentra-siem, /var/www or /etc is written. The previous copy is kept as /opt/sentra-platform.prev-<time>.
#
#   sudo bash install-dev-folder.sh <sentra-platform.tgz> <sha256 of it>        (Place-OnServer.ps1 runs this for you)
# DEST can be overridden for a test: DEST=/tmp/x bash install-dev-folder.sh …
set -euo pipefail
TGZ="${1:?usage: install-dev-folder.sh <sentra-platform.tgz> <sha256>}"; SUM="${2:?the SHA-256 of the archive is required}"
DEST="${DEST:-/opt/sentra-platform}"
case "$DEST" in /opt/sentra-itam*|/opt/sentra-siem*|/var/www*|/etc*|/|/opt) echo "x refusing to write $DEST (a live platform folder)"; exit 1 ;; esac
[[ "$SUM" =~ ^[0-9a-f]{64}$ ]] || { echo "x the SHA-256 must be 64 hex characters - nothing was changed"; exit 1; }
echo "$SUM  $TGZ" | sha256sum -c --quiet - || { echo "x the archive does not match its SHA-256 - nothing was changed"; exit 1; }
# the archive must be a plain tree of relative paths (no absolute paths, no ..)
if tar -tzf "$TGZ" | grep -qE '(^/|(^|/)\.\.(/|$))'; then echo "x the archive holds absolute or .. paths - refused"; exit 1; fi
NEW="$(mktemp -d "${DEST}.new.XXXXXX")"
trap 'rm -rf "$NEW"' EXIT
tar -xzf "$TGZ" -C "$NEW" --no-same-owner
[ -f "$NEW/README.md" ] && [ -d "$NEW/backend" ] && [ -d "$NEW/ui" ] || { echo "x the archive is not an Sentra clean tree"; exit 1; }
if [ "$(id -u)" = 0 ]; then chown -R root:root "$NEW"; fi
chmod -R u=rwX,go=rX "$NEW"; find "$NEW" -name '*.sh' -exec chmod 755 {} +
if [ -e "$DEST" ]; then PREV="${DEST}.prev-$(date +%Y%m%d-%H%M%S)"; mv "$DEST" "$PREV"; echo "  previous copy kept: $PREV"; fi
mv "$NEW" "$DEST"; trap - EXIT
# keep the three newest previous copies
{ ls -1d "${DEST}".prev-* 2>/dev/null || true; } | sort | head -n -3 | while read -r old; do rm -rf "$old"; done
echo "OK  $DEST ($(find "$DEST" -type f | wc -l) files) - the running platform was not touched"
echo "    compare it with what runs:  bash $DEST/deploy/compare-with-live.sh"
