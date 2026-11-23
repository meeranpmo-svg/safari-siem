// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * The databases the platform may read with a proven read-only login: the login Asset Discovery proved on each host
 * (disc_devices extra.db_login.<engine> + the vault credential of kind db_login) and the Oracle databases registered on
 * the Databases page (db_health_targets). One list for the baseline hardening scan (engine/hardening.js) and the PDPL
 * personal-data discovery and identity search (engine/pdpl.js), so both read exactly the same systems.
 *   dbTargets(app, { engines }) → [{ key, engine, ip, port, service?, asset_id, host, instance, cred_id }]   (max 300)
 */
const ENGINES = ['oracle', 'mssql', 'postgres'], PORT = { oracle: 1521, mssql: 1433, postgres: 5432, mysql: 3306 };   // mysql only when asked (engine/db-inventory.js)
const s = (v, n) => String(v == null ? '' : v).replace(/[\u0000-\u001f]/g, ' ').trim().slice(0, n);

function dbTargets(app, opts = {}) {
  const want = opts.engines || ENGINES, store = app.store;
  const V = app.discovery && app.discovery.vault; if (!V) return [];
  let creds = []; try { creds = (V.list() || []).filter((c) => c.kind === 'db_login' && c.target && want.includes(c.target.engine)); } catch (e) { creds = []; }
  const out = [], seen = new Set();
  for (const d of store.collection('disc_devices').all((x) => x.ip && x.status !== 'ignored' && x.extra && x.extra.db_login)) {
    for (const eng of want) {
      const o = d.extra.db_login[eng]; if (!o) continue;
      const c = creds.find((k) => k.target.engine === eng && k.label === o.credential); if (!c) continue;
      const port = (c.target && c.target.port) || PORT[eng], key = eng + '|' + d.ip + '|' + port;
      if (seen.has(key)) continue; seen.add(key);
      out.push({ key, engine: eng, ip: d.ip, port, asset_id: d.asset_id || null, host: o.host_name || d.hostname || d.ip, instance: s(o.instance || o.version || '', 80), cred_id: c.id });
    }
  }
  if (want.includes('oracle')) {
    for (const r of store.collection('db_health_targets').all((x) => !x.paused)) {
      const key = 'oracle|' + r.host + '|' + (r.port || 1521); if (seen.has(key)) continue; seen.add(key);
      out.push({ key, engine: 'oracle', ip: r.host, port: r.port || 1521, service: r.service, asset_id: r.asset_id || null, host: r.label || r.host, instance: s(r.label || r.service || '', 80), cred_id: r.cred_id });
    }
  }
  return out.slice(0, 300);
}

module.exports = { dbTargets, ENGINES, PORT };
