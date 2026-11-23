// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// The asset read routes answered by Python (pyengine/assets_read.py, migration step 8c): /assets, /assets/:id, /lookup,
// /software, /licences, /cmdb. Python reads the store files itself, read-only - this process stays the only writer.
// Step 9a: answered by the RESIDENT Python service (pyengine/serve.py), which keeps the store in memory - measured on
// 5,000 assets: list 26-43 ms, detail 1 ms (one process per request took 200 ms). On by default for /assets,
// /assets/:id, /lookup and /cmdb. The software roll-up is a hot path where JavaScript is 6x faster (85 ms against
// 511 ms), so /software and /licences stay in Node.js unless assets.engine = "python"; assets.engine = "node" turns
// all of it off. Each call answers null when off, when Python is missing or fails, and the route answers from Node.js.
// Used by engine/routes.js (install/patches/assets-python.patch).
//   createAssetsPy(app) → { list(query), detail(id), lookup(tag), software(), licences(), cmdb(query) } → Promise<answer | null>
function createAssetsPy(app) {
  const cfg = (app.config && app.config.assets) || {};
  if (cfg.engine === 'node' || !app.store || !app.store.dir) return null;
  const all = cfg.engine === 'python';   // also the roll-up routes (slower in Python - see above)
  let py = null;
  try { py = require('./pyengine').createPyEngine({ python: ((app.config && app.config.discovery) || {}).python_bin || undefined, timeoutMs: 60000 }); } catch (e) { return null; }
  const plain = (q) => { const o = {}; for (const k of Object.keys(q || {})) if (typeof q[k] === 'string') o[k] = q[k]; return o; };
  async function ask(op, body, ok) {
    try { const r = await py.call(op, Object.assign({ dir: app.store.dir }, body)); return r && r.ok !== false && ok(r) ? r : null; } catch (e) { return null; }
  }
  return {
    list: (query) => ask('assets.list', { query: plain(query) }, (r) => Array.isArray(r.assets)),
    detail: (id) => ask('assets.detail', { id: String(id) }, (r) => typeof r.found === 'boolean'),
    lookup: (tag) => ask('assets.lookup', { tag }, (r) => Array.isArray(r.assets)),
    software: () => (all ? ask('assets.software', {}, (r) => Array.isArray(r.software)) : Promise.resolve(null)),
    // the licence sync add-on counts Microsoft 365 subscriptions from what Microsoft assigned (its wrapper marks itself)
    licences: () => !all ? Promise.resolve(null) : ask('assets.licences', { m365: !!(app.licences && app.licences.complianceView && app.licences.complianceView.m365) }, (r) => Array.isArray(r.licences)),
    cmdb: (query) => ask('assets.cmdb', { query: plain(query) }, (r) => Array.isArray(r.relationships) || !!r.graph),
  };
}

module.exports = { createAssetsPy };
