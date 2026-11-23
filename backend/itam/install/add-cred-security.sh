#!/bin/bash
# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
# add-cred-security.sh - credential encryption evidence and fixes (SAMA CSF 3.3.9 / 3.3.5, NCA ECC 2-8, ISO 27001 A.8.24):
#   - every value in /etc/sentra-itam/secrets.json (Claude API key, private-model token, netops token, legacy vCenter login)
#     sealed with AES-256-GCM under the vault master key; proxy_secret stays readable (nginx holds it in clear anyway)
#   - database logins can use TLS (Encryption in transit: require / verify; Oracle over TCPS) and never fall back to clear
#   - GET {prefix}/security/credentials: the live evidence report (stores sealed vs clear, key custody, self-test, how each
#     login reaches its device, findings with their control); POST .../scan (admin): no secret in clear on disk
#   sudo bash add-cred-security.sh              install / update (safe to re-run)
#   sudo bash add-cred-security.sh --rollback   put back the engine files and secrets.json from before the first install
# Backup first, syntax check, restart, live check; any failure restores the backup automatically.
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib-itam.sh"
APP=/opt/sentra-itam; SVC=sentra-itam; BK=/var/backups/sentra-itam-credsec; ETC=/etc/sentra-itam; SEC="$ETC/secrets.json"
MAIN="$APP/engine/main.js"
LINE="  require('./cred-posture').registerCredPosture(srv, app); // credential encryption evidence (engine/cred-posture.js)"
# engine files this installs (each only replaced when the module is installed, except the two new ones)
NEW="engine/cred-posture.js engine/secret-values.js"
UPD="engine/config.js engine/ai/anthropic.js engine/virt-ai.js engine/db-health.js engine/discovery/vault.js engine/discovery/methods/login.js engine/discovery/inv-helper.py"
say() { echo "==> $*"; }; die() { echo "!! $*"; exit 1; }

if [ "${1:-}" = "--rollback" ]; then
  [ -f "$BK/main.js" ] || die "no backup in $BK"
  cp -p "$BK/main.js" "$MAIN"
  for f in $NEW $UPD; do b="$BK/files/$f"; if [ -f "$b" ]; then cp -p "$b" "$APP/$f"; elif [ -f "$BK/files/$f.absent" ]; then rm -f "$APP/$f"; fi; done
  [ -f "$BK/secrets.json" ] && cp -p "$BK/secrets.json" "$SEC"
  itam_restart; say "restored the engine and secrets.json from before this module ($(systemctl is-active "$SVC"))"; exit 0
fi

[ -f "$MAIN" ] || die "IT Asset Management is not installed here ($MAIN not found)"
for f in $NEW $UPD; do [ -f "$HERE/../$f" ] || die "missing $HERE/../$f - copy the whole sentra-itam folder"; done
NODE="$(systemctl show -p ExecStart --value "$SVC" 2>/dev/null | sed -n 's/.*argv\[\]=\([^ ;]*\).*/\1/p' | head -n1)"
[ -x "${NODE:-}" ] || NODE=/opt/sentra-ai/node/bin/node; [ -x "$NODE" ] || NODE="$(command -v node || true)"
[ -x "${NODE:-}" ] || die "could not find the Node.js the service uses"

PRE_FP="$(itam_fp)"
say "backup -> $BK"
mkdir -p "$BK/files"; chmod 700 "$BK"
if grep -q "registerCredPosture" "$MAIN" && [ -f "$BK/main.js" ]; then echo "   (keeping the backup from before the first install)"
else
  cp -p "$MAIN" "$BK/main.js"
  for f in $NEW $UPD; do mkdir -p "$(dirname "$BK/files/$f")"; if [ -f "$APP/$f" ]; then cp -p "$APP/$f" "$BK/files/$f"; rm -f "$BK/files/$f.absent"; else rm -f "$BK/files/$f"; touch "$BK/files/$f.absent"; fi; done
  # the plaintext secrets.json is kept ONLY in this root-only backup (700) for --rollback; it is removed once the
  # sealed file has been confirmed working (end of this script)
  [ -f "$SEC" ] && install -m 600 -o root -g root "$SEC" "$BK/secrets.json"
fi
mkdir -p "$BK/run"; cp -p "$MAIN" "$BK/run/main.js"; [ -f "$SEC" ] && install -m 600 -o root -g root "$SEC" "$BK/run/secrets.json"
for f in $NEW $UPD; do mkdir -p "$(dirname "$BK/run/$f")"; if [ -f "$APP/$f" ]; then cp -p "$APP/$f" "$BK/run/$f"; else rm -f "$BK/run/$f"; fi; done
restore() { itam_on_restore "$1";
  echo "!! $1 - restoring the previous engine"
  cp -p "$BK/run/main.js" "$MAIN"
  for f in $NEW $UPD; do if [ -f "$BK/run/$f" ]; then cp -p "$BK/run/$f" "$APP/$f"; else case " $NEW " in *" $f "*) rm -f "$APP/$f";; esac; fi; done
  if [ -f "$BK/run/secrets.json" ]; then cat "$BK/run/secrets.json" > "$SEC"; fi
  itam_restart || true; echo "   $SVC: $(systemctl is-active "$SVC")"; exit 1
}

for f in $NEW; do install -D -m 644 -o root -g root "$HERE/../$f" "$APP/$f"; done
for f in $UPD; do [ -f "$APP/$f" ] && install -m 644 -o root -g root "$HERE/../$f" "$APP/$f"; done
install -D -m 750 -o root -g root "$HERE/itam-secrets.js" "$APP/install/itam-secrets.js"

if grep -q "registerCredPosture" "$MAIN"; then say "main.js already registers the credential evidence"
else
  if grep -q "^ *registerDiscoveryRoutes(srv, app);" "$MAIN"; then ANCHOR="registerDiscoveryRoutes(srv, app);"
  elif grep -q "^ *registerRoutes(srv, app);" "$MAIN"; then ANCHOR="registerRoutes(srv, app);"
  else restore "could not find where routes are registered in $MAIN"; fi
  LINE="$LINE" ANCHOR="$ANCHOR" awk '{print} !done && index($0, ENVIRON["ANCHOR"]) && $0 ~ /^ *(require|register)/ {print ENVIRON["LINE"]; done=1}' "$MAIN" > "$MAIN.tmp" && cat "$MAIN.tmp" > "$MAIN" && rm -f "$MAIN.tmp"
  grep -q "registerCredPosture" "$MAIN" || restore "could not add the registration line"
  say "registered the credential evidence in main.js"
fi
for f in "$MAIN" $NEW $UPD; do case "$f" in *.js) p="$f"; [ -f "$p" ] || p="$APP/$f"; [ -f "$p" ] && { "$NODE" --check "$p" || restore "syntax check failed: $f"; };; esac; done
command -v python3 >/dev/null && python3 -c "import ast,sys;ast.parse(open(sys.argv[1]).read())" "$APP/engine/discovery/inv-helper.py" 2>/dev/null || [ ! -f "$APP/engine/discovery/inv-helper.py" ] || restore "inv-helper.py does not parse"

# seal secrets.json (proxy_secret stays readable); the service must still read the file afterwards
if [ -f "$SEC" ]; then
  "$NODE" "$APP/install/itam-secrets.js" seal || restore "could not seal $SEC"
  runuser -u "$SVC" -- test -r "$SEC" || { chown root:"$SVC" "$SEC"; chmod 640 "$SEC"; }
  "$NODE" "$APP/install/itam-secrets.js" status || restore "secrets.json still has a value in clear or one that cannot be opened"
fi

itam_restart_if_changed "$PRE_FP"
systemctl is-active --quiet "$SVC" || itam_start_failed restore

# live check as a viewer: 403 = the route is there and refuses a viewer (it needs operator); 404 = not registered
CODE="$(itam_code /security/credentials)"
case "$CODE" in
  403) say "credential evidence is live (Credential Security page; operator / admin)";;
  404) restore "the credential evidence did not register";;
  0) restore "sentra-itam is not answering after the change";;
  *) say "installed; the live check returned '$CODE' - open the Credential Security page to confirm";;
esac
# the sealed file works: drop the plaintext copies this run kept (the first-install copy stays for --rollback, 600 root)
rm -f "$BK/run/secrets.json"
echo "   the plaintext secrets.json from before sealing is kept only in $BK/secrets.json (root, 600) for --rollback;"
echo "   remove it once you are satisfied:  sudo shred -u $BK/secrets.json"
echo "   undo: sudo bash $0 --rollback"
