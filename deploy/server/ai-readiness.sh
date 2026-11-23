#!/bin/bash
# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
# ai-readiness.sh (installed as zyb-ai-readiness) - is every AI engineer FULLY working, and if not, what exactly to fix.
# Reads the SIEM and IT Asset Management readiness checks on this server (read-only; nothing is changed).
#   sudo zyb-ai-readiness
set -uo pipefail
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
NODE="$(command -v node || true)"; [ -n "$NODE" ] || NODE="$(systemctl show -p ExecStart --value sentra-itam 2>/dev/null | sed -n 's/.*path=\([^ ;]*\).*/\1/p' | head -n1)"
[ -x "${NODE:-}" ] || { echo "node not found"; exit 1; }
"$NODE" -e '
const fs = require("fs"), http = require("http");
const rd = (p)=>{try{if(/secrets[^\/]*\.json$/.test(p))return require("/opt/sentra-siem/engine/secretfile").read(p)||{};return JSON.parse(fs.readFileSync(p,"utf8"))}catch(e){return {}}};
const sc = rd("/etc/sentra-siem/config.json"), ss = rd(sc.secrets_path || "/etc/sentra-siem/secrets.json"), ic = rd("/etc/sentra-itam/config.json"), is = rd("/etc/sentra-itam/secrets.json");
const get = (port, path, secret) => new Promise((ok) => {
  const r = http.request({ host: "127.0.0.1", port, method: "GET", path, headers: { "X-Sentra-Proxy-Secret": secret || "", "X-Auth-User": "zyb-readiness", "X-Auth-Role": "viewer" } }, (res) => {
    let b = ""; res.on("data", (d) => b += d); res.on("end", () => { try { ok(res.statusCode === 200 ? JSON.parse(b) : { error: "HTTP " + res.statusCode + (res.statusCode === 404 ? " (not installed - run the update)" : "") }); } catch (e) { ok({ error: "not JSON" }); } });
  }); r.on("error", (e) => ok({ error: e.message })); r.setTimeout(90000, () => r.destroy(new Error("timeout"))); r.end();
});
(async () => {
  const siem = await get((sc.api || {}).port || 9120, (sc.api_prefix || "/api/soc").replace(/\/+$/, "") + "/duty/readiness", ss.proxy_secret);
  const itam = await get((ic.api || {}).port || 9150, ((ic.api || {}).prefix || "/api/itam") + "/duty/readiness", is.proxy_secret);
  const all = [].concat(siem.engineers || [], itam.engineers || []);
  const mark = { ready: "[READY]   ", partial: "[PARTIAL] ", blocked: "[BLOCKED] " };
  console.log("==> AI engineers fully working: " + all.filter((e) => e.status === "ready").length + " of " + all.length);
  if (siem.error) console.log("    SIEM readiness: " + siem.error);
  if (itam.error) console.log("    IT Asset Management readiness: " + itam.error);
  const order = { blocked: 0, partial: 1, ready: 2 };
  for (const e of all.sort((a, b) => order[a.status] - order[b.status])) {
    console.log("    " + (mark[e.status] || "[?]       ") + e.name);
    for (const c of e.checks.filter((x) => x.ok === false)) { console.log("              - " + c.name + ": " + c.detail); console.log("                fix: " + c.fix); }
  }
})();'
