// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// The human asset WRITES decided in Python (pyengine/assets_write.py, migration step 9d) - add, edit, the lifecycle
// transitions, move, assign - and committed here: the store keeps ONE writer. A decision is written only if
//   - Python decided on the record this process holds now (based_on = SHA-256 of its JSON) and it did not change while
//     Python decided (the same check before and after the call),
//   - it writes exactly one record of the assets collection: the asset itself (a new one: the id given to Python, unused).
// Otherwise - and whenever Python is missing, fails, or answers {node: true} for a value it does not read exactly like
// JavaScript - the Node.js function in engine/assets.js decides, as before. On by default; assets.engine = "node" turns
// it off with the asset reads (engine/assets-py.js). Source upserts (discovery / agent merges) stay in Node.js.
// Used by engine/routes.js (install/patches/assets-write.patch).
//   createAssetsWrite(app) → { create(body, who), edit(id, body, who), transition(id, action, who, reason), move(id, body, who),
//                              assign(id, body, who), stats() } → Promise<the answer of engine/assets.js>
const crypto = require('node:crypto');

const newId = () => `as_${crypto.randomBytes(6).toString('hex')}`;
const bad = (msg, status = 400) => Object.assign(new Error(msg), { status });
const sha = (t) => crypto.createHash('sha256').update(t, 'utf8').digest('hex');

function createAssetsWrite(app) {
  const { assets, store } = app;
  const stats = { python: 0, node: 0, changed_meanwhile: 0 };
  const cfg = (app.config && app.config.assets) || {};
  let py = null;
  if (cfg.engine !== 'node' && store && store.dir) {
    try { py = require('./pyengine').createPyEngine({ python: ((app.config && app.config.discovery) || {}).python_bin || undefined, timeoutMs: 30000 }); } catch (e) { py = null; }
  }
  const col = store.collection('assets');
  const who0 = (who) => ({ user: who && who.user, role: who && who.role });

  async function write(op, id, extra, who, node0) {
    const node = () => { stats.node++; return node0(); };
    if (!py) return node();
    const isNew = id === null;
    const target = isNew ? newId() : String(id);
    const before = isNew ? null : JSON.stringify(col.get(target));
    let r = null;
    try { r = await py.call(op, Object.assign({ dir: store.dir, at: new Date().toISOString(), who: who0(who) }, isNew ? { new_id: target } : { id: target }, extra)); } catch (e) { r = null; }
    const now = isNew ? null : JSON.stringify(col.get(target));
    if (r && now !== before) stats.changed_meanwhile++;
    if (!r || r.ok === false || r.node || (!r.refuse && !('result' in r)) || now !== before) return node();
    if (!isNew && r.based_on !== sha(String(before))) { stats.changed_meanwhile++; return node(); }   // decided on another copy
    if (r.refuse) { stats.python++; throw bad(r.refuse.error, r.refuse.status); }
    const puts = r.puts || [];
    const ok = puts.length === 1 && puts[0] && puts[0].c === 'assets' && puts[0].o && puts[0].o.id === target && (!isNew || !col.get(target)) && !(r.removes && r.removes.length);
    if (!ok) return node();   // never anything but the one asset
    stats.python++;
    col.put(puts[0].o);
    if (r.audit && app.audit) app.audit(r.audit);
    return r.result;
  }

  return {
    create: (body, who) => write('assets.create', null, { body, source: 'manual' }, who, () => assets.create(body, who, { source: 'manual' })),
    edit: (id, body, who) => write('assets.edit', id, { body }, who, () => assets.edit(id, body, who)),
    transition: (id, action, who, reason) => write('assets.transition', id, { action, reason }, who, () => assets.transition(id, action, who, reason)),
    move: (id, body, who) => write('assets.move', id, { body }, who, () => assets.move(id, body, who)),
    assign: (id, body, who) => write('assets.assign', id, { body }, who, () => assets.assign(id, body, who)),
    engine: () => (py ? 'python' : 'node'),
    stats: () => Object.assign({}, stats),
  };
}

module.exports = { createAssetsWrite };
