#!/bin/bash
# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
# deploy-engine.sh - update /opt/sentra-siem/engine from this repository with an automatic rollback.
#   sudo bash install/deploy-engine.sh             back up engine → install new → syntax check → migrate → restart → health
#   sudo bash install/deploy-engine.sh --rollback  put the previous engine back
# If the service does not come back healthy within 30 s the previous engine is restored and restarted automatically.
# Configuration (/etc/sentra-siem), data (/var/lib/sentra-siem) and ClickHouse data are not touched.
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
HERE="$(cd "$(dirname "$0")/.." && pwd)"; APP=/opt/sentra-siem; ETC=/etc/sentra-siem; SVC=sentra-siem
NODE_BIN="$(command -v node || true)"; [ -n "$NODE_BIN" ] || { echo "node not found"; exit 1; }
# /etc/sentra-siem belongs to the service account: read config.json as data only (never require(), which would run a
# symlinked .js as root), refuse a symlink, and accept only a numeric port.
PORT="$("$NODE_BIN" -e 'const fs=require("fs");let p=9120;try{const f=process.argv[1];if(fs.lstatSync(f).isFile()){const c=JSON.parse(fs.readFileSync(f,"utf8"));const n=Number(c.api&&c.api.port);if(Number.isInteger(n)&&n>0&&n<65536)p=n}}catch(e){}console.log(p)' "$ETC/config.json")"
[[ "$PORT" =~ ^[0-9]{1,5}$ ]] || PORT=9120
healthy() { for _ in $(seq 1 15); do sleep 2; systemctl is-active --quiet "$SVC" && curl -fsS -m 3 "http://127.0.0.1:$PORT/api/soc/health" 2>/dev/null | grep -q '"status"' && return 0; done; return 1; }

if [ "${1:-}" = "--rollback" ]; then
  PREV="$(ls -1dt "$APP"/engine.prev-* 2>/dev/null | head -1)"; [ -n "$PREV" ] || { echo "no previous engine found"; exit 1; }
  rm -rf "$APP/engine.bad"; mv "$APP/engine" "$APP/engine.bad"; cp -a "$PREV" "$APP/engine"; systemctl restart "$SVC"
  healthy && echo "==> rolled back to $PREV" || { echo "service still unhealthy: journalctl -u $SVC -n 80"; exit 1; }; exit 0
fi

[ -f "$HERE/engine/main.js" ] || { echo "run from the sentra-siem repository (engine/main.js not found)"; exit 1; }
"$NODE_BIN" --check "$HERE/engine/main.js"
for f in $(find "$HERE/engine" -name '*.js'); do "$NODE_BIN" --check "$f" || { echo "syntax error in $f - nothing changed"; exit 1; }; done
STAMP=$(date +%Y%m%d-%H%M%S)
cp -a "$APP/engine" "$APP/engine.prev-$STAMP"
ls -1dt "$APP"/engine.prev-* | tail -n +4 | xargs -r rm -rf   # keep the last 3 backups
rm -rf "$APP/engine.new"; cp -a "$HERE/engine" "$APP/engine.new"; find "$APP/engine.new" -name '*.sh' -exec sed -i 's/\r$//' {} +
chown -R root:root "$APP/engine.new"; find "$APP/engine.new" -type d -exec chmod 755 {} +; find "$APP/engine.new" -type f -exec chmod 644 {} +
rm -rf "$APP/engine"; mv "$APP/engine.new" "$APP/engine"
echo "==> engine installed (backup: $APP/engine.prev-$STAMP)"
(cd "$APP" && runuser -u "$SVC" -- env SENTRA_SIEM_CONFIG="$ETC/config.json" "$NODE_BIN" engine/store/migrate.js) || echo "    WARNING: schema migration failed - the engine still starts; re-run later"
systemctl restart "$SVC"
if healthy; then echo "==> sentra-siem is healthy on the new engine"
  # every route module's outcome at this start (engine/util/route-status.js): the count, and each one NOT registered with why
  sleep 2; RS="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get("data_dir") or "/var/lib/sentra-siem")' /etc/sentra-siem/config.json 2>/dev/null || echo /var/lib/sentra-siem)/state/routes-status.json"
  python3 - "$RS" <<'PY' 2>/dev/null || journalctl -u "$SVC" -n 400 --no-pager 2>/dev/null | grep -E 'route registration failed|optional module failed' | tail -10
import json, sys
m = json.load(open(sys.argv[1])).get("modules", [])
ok = [x for x in m if x.get("state") == "registered"]; bad = [x for x in m if x.get("state") != "registered"]
print("    route modules: %d registered%s" % (len(ok), ", %d NOT registered:" % len(bad) if bad else ""))
for x in bad: print("    !! %s: %s %s" % (x.get("module"), x.get("state"), x.get("error", "")))
PY
else
  echo "!! sentra-siem did not come back healthy - restoring the previous engine"
  journalctl -u "$SVC" -n 30 --no-pager || true
  rm -rf "$APP/engine.bad"; mv "$APP/engine" "$APP/engine.bad"; cp -a "$APP/engine.prev-$STAMP" "$APP/engine"; systemctl restart "$SVC"
  healthy && echo "==> previous engine restored and healthy (failed copy kept in $APP/engine.bad)" || echo "!! still unhealthy: journalctl -u $SVC -n 100"
  exit 1
fi
