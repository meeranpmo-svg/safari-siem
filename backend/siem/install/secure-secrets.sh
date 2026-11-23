#!/bin/bash
# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
# secure-secrets.sh - keep the platform's passwords in a safe place (idempotent; install.sh and the server update run it).
#   1. a key for the SIEM secrets: /etc/sentra-siem-keys/secrets.key, root:sentra-siem 0440, in a folder the SIEM service
#      cannot write (only /etc/sentra-siem is writable for it) - the engine can open its secrets, never replace the key
#   2. /etc/sentra-siem/secrets.json sealed with it (AES-256-GCM, engine/secretfile.js); the engine reads it as before
#   3. plaintext copies left by older versions (secrets.json.bak, .bak-<random>) removed
#   4. the token files of IT Asset Management tightened (root:sentra-itam 0640)
#   5. /usr/local/sbin/sentra-siem-secrets: status | get <key> | set <key> (value on stdin) | seal | unseal
# The key is kept out of the nightly backup archive (zyb-backup puts it in the separate, local-only keys archive): keep a
# copy of the newest keys archive and of /etc/zyb-backup/backup.key in an offline safe.
#   sudo bash install/secure-secrets.sh [--no-restart]
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
APP=/opt/sentra-siem; ETC=/etc/sentra-siem; KD=/etc/sentra-siem-keys; KEY=$KD/secrets.key; SEC=$ETC/secrets.json
NODE_BIN="$( { systemctl show -p ExecStart --value sentra-siem 2>/dev/null || true; } | sed -n 's/.*argv\[\]=\([^ ;]*\).*/\1/p' | head -n1)"; [ -x "${NODE_BIN:-}" ] || NODE_BIN="$(command -v node || echo /opt/sentra-ai/node/bin/node)"
SFJ=$APP/engine/secretfile.js
say() { echo "==> $*"; }
[ -f "$SFJ" ] || { echo "!! $SFJ missing - update the SIEM engine first (deploy-engine.sh); nothing changed"; exit 1; }
id sentra-siem >/dev/null 2>&1 || { echo "!! user sentra-siem not found - is the SIEM installed?"; exit 1; }

# 1. key
install -d -m 750 -o root -g sentra-siem "$KD"
if [ ! -s "$KEY" ]; then ( umask 0227; openssl rand -hex 32 > "$KEY" ); say "secrets key created: $KEY"; fi
chown root:sentra-siem "$KEY"; chmod 440 "$KEY"
[ -L "$KEY" ] && { echo "!! $KEY is a symbolic link - refusing"; exit 1; }

# 5. CLI
printf '#!/bin/sh\n# sentra-siem-secrets - read / change the sealed SIEM secrets (root). Values are taken on stdin, never on the command line.\nexec "%s" /opt/sentra-siem/engine/secretfile.js "$@"\n' "$NODE_BIN" > /usr/local/sbin/sentra-siem-secrets
chmod 755 /usr/local/sbin/sentra-siem-secrets; chown root:root /usr/local/sbin/sentra-siem-secrets

# 2. seal
CHANGED=0
if [ -f "$SEC" ]; then
  [ -L "$SEC" ] && { echo "!! $SEC is a symbolic link - refusing"; exit 1; }
  if grep -q '"_sealed"' "$SEC"; then say "secrets.json already sealed"
  else SENTRA_SIEM_SECRETS="$SEC" SENTRA_SIEM_SECRETS_KEY="$KEY" "$NODE_BIN" "$SFJ" seal >/dev/null && CHANGED=1 && say "secrets.json sealed (AES-256-GCM)"; fi
  chown sentra-siem:sentra-siem "$SEC"; chmod 600 "$SEC"
  SENTRA_SIEM_SECRETS="$SEC" SENTRA_SIEM_SECRETS_KEY="$KEY" "$NODE_BIN" "$SFJ" get proxy_secret >/dev/null 2>&1 || { echo "!! the sealed secrets.json cannot be read back - check $KEY"; exit 1; }
fi

# 3. plaintext copies
N=0; for f in "$ETC"/secrets.json.bak "$ETC"/secrets.json.bak-* "$ETC"/.secrets.json.tmp-* /etc/sentra-itam/secrets.json.bak-*; do
  [ -f "$f" ] && [ ! -L "$f" ] || continue; sz=$(stat -c %s "$f"); head -c "$sz" /dev/zero > "$f" 2>/dev/null || true; rm -f "$f"; N=$((N+1)); done
[ "$N" -gt 0 ] && say "removed $N plaintext copies of secrets files"

# 4. IT Asset Management token files
for f in /etc/sentra-itam/siem-proxy-secret /etc/sentra-itam/siem-bridge-token /etc/sentra-itam/fortigate-isolation.token /etc/sentra-itam/secrets.json; do
  [ -f "$f" ] && [ ! -L "$f" ] && { chown root:sentra-itam "$f" 2>/dev/null || true; chmod 640 "$f"; }; done
[ -f /etc/sentra-itam/discovery-vault.key ] && { chown sentra-itam:sentra-itam /etc/sentra-itam/discovery-vault.key; chmod 600 /etc/sentra-itam/discovery-vault.key; }
[ -f /var/lib/sentra-siem/state/dataopt.key ] && chmod 600 /var/lib/sentra-siem/state/dataopt.key

if [ "$CHANGED" = 1 ] && [ "${1:-}" != --no-restart ] && systemctl is-active --quiet sentra-siem; then systemctl restart sentra-siem && say "sentra-siem restarted (reads the sealed secrets)"; fi
say "credentials: SIEM secrets sealed, key $KEY (root:sentra-siem 0440) - keep the newest backup keys archive and the backup key offline"
