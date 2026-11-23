// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// One commit for the writes decided in Python (migration step 9e onwards, docs/PYTHON-MIGRATION.md): the store keeps ONE
// writer, this process. A Python decision is written only if
//   - every record it decided on is, byte for byte, the record this process holds now (based_on: "collection/id" ->
//     SHA-256 of its JSON, null when absent),
//   - no collection it read whole changed while it decided (the files' size / time / inode, which every put, delete and
//     compaction changes - checked before and after the call, nothing to hash),
//   - it writes only into the collections the route names (own) and only records it decided on or the new id it was given.
// Otherwise - and when Python is missing, fails, or answers {node: true} for a value it does not read exactly like
// JavaScript - the Node.js function decides, as before.
// A refusal may carry records Node.js writes before it refuses (a counter used up, a record created first): they pass
// the same checks and are written, then the refusal is answered - exactly as the Node.js function does.
//   createPyWriter(app, { off }) → { write(op, spec, who, node) → Promise<answer>, stats(), engine() }
//     spec: { reads: [collections read whole], own: [collections it may write], newId?: () => id, extra: {...},
//             after?: (result) => answer   (an answer that is a READ after the write - computed here, by Node.js),
//             newIdRe?: /^x_[0-9a-f]{10}$/  (several new records, ids made by Python: each matching, unused, distinct) }
//   Python answers {puts, removes?, audit? | audits?, result} or {refuse: {status, error}, puts?}, always with based_on
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const bad = (msg, status = 400) => Object.assign(new Error(msg), { status });
const sha = (t) => crypto.createHash('sha256').update(t, 'utf8').digest('hex');

function createPyWriter(app, opts = {}) {
  const store = app.store;
  const stats = { python: 0, node: 0, changed_meanwhile: 0, node_by_op: {} };
  let py = null;
  if (!opts.off && store && store.dir) {
    try { py = require('./pyengine').createPyEngine({ python: ((app.config && app.config.discovery) || {}).python_bin || undefined, timeoutMs: 30000 }); } catch (e) { py = null; }
  }
  const stamp = (col) => ['jsonl', 'snap.json'].map((ext) => { try { const s = fs.statSync(path.join(store.dir, `${col}.${ext}`)); return `${s.size}:${s.mtimeMs}:${s.ino}`; } catch (e) { return '-'; } }).join('/');
  const stamps = (cols) => cols.map(stamp).join('|');

  async function write(op, spec, who, node0) {
    const node = () => { stats.node++; stats.node_by_op[op] = (stats.node_by_op[op] || 0) + 1; return node0(); };
    if (!py) return node();
    const reads = spec.reads || [], own = new Set(spec.own || []);
    const newId = spec.newId ? spec.newId() : undefined;
    const before = stamps(reads);
    let r = null;
    try { r = await py.call(op, Object.assign({ dir: store.dir, at: new Date().toISOString(), now: Date.now(), who: { user: who && who.user, role: who && who.role, ip: who && who.ip } }, newId === undefined ? {} : { new_id: newId }, spec.extra || {})); } catch (e) { r = null; }
    if (!r || r.ok === false || r.node || (!r.refuse && !('result' in r)) || typeof r.based_on !== 'object' || !r.based_on) return node();
    if (stamps(reads) !== before) { stats.changed_meanwhile++; return node(); }
    for (const [k, h] of Object.entries(r.based_on)) {
      const i = k.indexOf('/'); if (i < 1) return node();
      if (sha(String(JSON.stringify(store.collection(k.slice(0, i)).get(k.slice(i + 1))))) !== h) { stats.changed_meanwhile++; return node(); }
    }
    const puts = r.puts || [], removes = r.removes || [], decided = (c, id) => Object.prototype.hasOwnProperty.call(r.based_on, `${c}/${id}`);
    if (!Array.isArray(puts) || !Array.isArray(removes)) return node();
    const fresh = new Set(), isNew = (c, id) => !store.collection(c).get(id) && !fresh.has(`${c}/${id}`) && fresh.add(`${c}/${id}`);
    if (!puts.every((x) => x && own.has(x.c) && x.o && (decided(x.c, x.o.id) || (newId !== undefined && x.o.id === newId && isNew(x.c, newId)) || (spec.newIdRe && typeof x.o.id === 'string' && spec.newIdRe.test(x.o.id) && isNew(x.c, x.o.id))))) return node();
    if (!removes.every((x) => x && own.has(x.c) && decided(x.c, x.id))) return node();
    stats.python++;
    for (const x of removes) store.collection(x.c).remove(x.id);
    for (const x of puts) store.collection(x.c).put(x.o);
    if (r.refuse) throw bad(r.refuse.error, r.refuse.status);
    if (app.audit) for (const e of r.audits || (r.audit ? [r.audit] : [])) app.audit(e);
    return spec.after ? spec.after(r.result) : r.result;
  }

  return { write, stats: () => Object.assign({}, stats, { node_by_op: Object.assign({}, stats.node_by_op) }), engine: () => (py ? 'python' : 'node') };
}

module.exports = { createPyWriter };
