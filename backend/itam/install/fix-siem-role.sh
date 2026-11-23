#!/usr/bin/env bash
# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
# The ITAM -> SIEM link (engine/discovery/siem.js) must pass the analyst role through: the SIEM's evidence routes
# (Baseline Hardening snapshots, AI auditors' network evidence, the PDPL Data Catalog's file discovery) refuse viewers.
# The fix was made in the repository but siem.js is only changed on a server through the discovery patch chain, which
# never carried it - so a server kept sending every non-admin request as viewer and those pages got HTTP 403.
# This replaces exactly that one line when it is still the old one; anything else is left alone. Safe to run again.
# Called by update-discovery.sh and add-duty.sh (the caller restarts sentra-itam when the engine changed).
set -euo pipefail
APP="${APP:-/opt/sentra-itam}"; F="$APP/engine/discovery/siem.js"
[ -f "$F" ] || { echo "==> SIEM link: $F not installed - skipped"; exit 0; }
OLD="'X-Auth-Role': who.role === 'admin' ? 'admin' : 'viewer'"
NEW="'X-Auth-Role': (who.role === 'admin' || who.role === 'analyst') ? who.role : 'viewer'"
if grep -qF "ROLE_PASS.has(who.role) ? who.role : 'viewer'" "$F" || grep -qF "$NEW" "$F"; then echo "==> SIEM link: analyst role already passed through"; exit 0; fi
if ! grep -qF "$OLD" "$F"; then echo "!! SIEM link: $F differs from every shipped version - the analyst role fix was not applied; send this line to Claude"; exit 0; fi
cp -p "$F" "$F.pre-role-fix"
# fixed-string replacement of the one line (no regex: the line holds quotes and ?:)
OLD="$OLD" NEW="$NEW" awk '{ i = index($0, ENVIRON["OLD"]); if (i) $0 = substr($0, 1, i - 1) ENVIRON["NEW"] substr($0, i + length(ENVIRON["OLD"])); print }' "$F.pre-role-fix" > "$F.new.js"
if [ -n "${NODE:-}" ] && ! "$NODE" --check "$F.new.js"; then rm -f "$F.new.js"; echo "!! SIEM link: the fixed file did not pass the syntax check - kept the previous one"; exit 0; fi
cat "$F.new.js" > "$F"; rm -f "$F.new.js"
echo "==> SIEM link: analyst role now passed through (Baseline Hardening, AI auditors, PDPL Data Catalog no longer get HTTP 403); previous file: $F.pre-role-fix"
