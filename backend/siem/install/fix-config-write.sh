#!/bin/bash
# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
# fix-config-write.sh - let the SIEM service write /etc/sentra-siem (config.json / secrets.json).
# Needed by Connect & Onboard, Add Devices, asset-discovery "Connect" (sentra-itam → SIEM) and the AI Network Engineer.
# Symptom without it: "SIEM: internal error" on Connect; the service sandbox (ProtectSystem=strict) makes /etc read-only.
# Adds a systemd drop-in (the unit file itself is not edited); /etc/sentra-siem/tls stays read-only.
#   sudo bash fix-config-write.sh            add the drop-in, restart, verify
#   sudo bash fix-config-write.sh --remove   take it out again
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
SVC=sentra-siem; DIR=/etc/systemd/system/$SVC.service.d; F=$DIR/10-config-write.conf
echo "==> current sandbox: $(systemctl show "$SVC" -p ProtectSystem --value) / writable: $(systemctl show "$SVC" -p ReadWritePaths --value)"
if [ "${1:-}" = "--remove" ]; then rm -f "$F"; systemctl daemon-reload; systemctl restart "$SVC"; echo "==> removed"; exit 0; fi
OWN="$(stat -c %U /etc/sentra-siem)"; [ "$OWN" = "$SVC" ] || echo "    NOTE: /etc/sentra-siem is owned by $OWN (expected $SVC) - the write may still fail on permissions: sudo chown $SVC:$SVC /etc/sentra-siem /etc/sentra-siem/*.json"
mkdir -p "$DIR"
cat > "$F" <<'UNIT'
# written by fix-config-write.sh: the SIEM writes config.json / secrets.json here (onboarding, device credentials)
[Service]
ReadWritePaths=/etc/sentra-siem
ReadOnlyPaths=/etc/sentra-siem/tls
UNIT
systemctl daemon-reload
systemctl restart "$SVC"
sleep 3
systemctl is-active --quiet "$SVC" || { echo "!! $SVC did not start - removing the drop-in"; rm -f "$F"; systemctl daemon-reload; systemctl restart "$SVC"; exit 1; }
echo "==> now writable: $(systemctl show "$SVC" -p ReadWritePaths --value)"
echo "==> done - try Connect in IT Asset Management again"
