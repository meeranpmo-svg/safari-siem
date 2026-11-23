// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Asset ownership ({P} = /api/itam): every asset has an IT OWNER (the team / person who runs and fixes it) and a
 * BUSINESS OWNER (the business head accountable for the service and the data on it), plus the BUSINESS SERVICE it
 * supports. ISO 27001 A.5.9 / SAMA CSF asset management / NCA ECC 2-1 expect both to be named.
 *   - per asset:   it_owner, business_owner, business_service (collection asset_ownership, keyed by asset id)
 *   - per service: business_owner, it_owner set once for a business service (ownership_services) and INHERITED by every
 *                  asset of that service that has no owner of its own. Effective owner = asset's own > service's > none.
 *   - never guessed: an asset's department or name is shown as a hint, never written as an owner
 * Active assets only (retired / disposed / lost are out of scope). Every change is audited with who / when / reason.
 * Routes:
 *   GET  /ownership                      viewer    coverage, every active asset with its effective owners, owners directory
 *   GET  /ownership/services             viewer    service owner map (with asset counts)
 *   POST /ownership/assign               operator  {ids[], it_owner?, business_owner?, business_service?, reason}
 *   POST /ownership/services             operator  {service, business_owner?, it_owner?}   (empty value clears it)
 *   POST /ownership/import               operator  {rows:[{asset (tag | serial | name | ip), it_owner, business_owner, business_service}], reason}
 */
const CLOSED = { retired: 1, disposed: 1, lost: 1 };
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const s = (v, n) => { const t = String(v == null ? '' : v).replace(/[\u0000-\u001f]/g, ' ').trim(); return t ? t.slice(0, n || 200) : ''; };
const keyOf = (svc) => s(svc, 120).toLowerCase();

function createOwnership(app, opts = {}) {
  const store = app.store, now = opts.now || Date.now;
  const own = store.collection('asset_ownership'), svcCol = store.collection('ownership_services');
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: (who && who.user) || '', role: (who && who.role) || '', ip: (who && who.ip) || '', action, target, detail }); };
  const active = () => app.assets.all().filter((a) => !CLOSED[a.status]);

  function services() {
    const map = {}; for (const x of svcCol.all()) map[x.id] = x;
    return map;
  }
  function effective(a, svcMap) {
    const o = own.get(a.id) || {}, svc = o.business_service || '', sv = svc ? svcMap[keyOf(svc)] : null;
    const pick = (k) => (o[k] ? { v: o[k], from: 'asset' } : sv && sv[k] ? { v: sv[k], from: 'service' } : { v: '', from: '' });
    const it = pick('it_owner'), bo = pick('business_owner');
    return { id: a.id, asset_tag: a.asset_tag || '', name: a.name || '', type: a.type || '', status: a.status || '', site: a.site || '', mgmt_ip: a.mgmt_ip || '',
      department: a.department || '', user: a.owner || '', business_service: svc, it_owner: it.v, it_owner_from: it.from, business_owner: bo.v, business_owner_from: bo.from,
      updated_by: o.by || '', updated_at: o.at || null };
  }

  function view(q = {}) {
    const svcMap = services(), rows = active().map((a) => effective(a, svcMap));
    const n = rows.length, withIt = rows.filter((r) => r.it_owner).length, withBo = rows.filter((r) => r.business_owner).length, both = rows.filter((r) => r.it_owner && r.business_owner).length;
    const byType = {}; for (const r of rows) { const t = byType[r.type || 'other'] = byType[r.type || 'other'] || { type: r.type || 'other', total: 0, missing_it: 0, missing_business: 0 }; t.total++; if (!r.it_owner) t.missing_it++; if (!r.business_owner) t.missing_business++; }
    const dir = (k) => { const m = {}; for (const r of rows) if (r[k]) { const d = m[r[k]] = m[r[k]] || { owner: r[k], assets: 0, services: {} }; d.assets++; if (r.business_service) d.services[r.business_service] = 1; } return Object.values(m).map((d) => ({ owner: d.owner, assets: d.assets, services: Object.keys(d.services).sort() })).sort((a, b) => b.assets - a.assets); };
    let items = rows;
    if (q.missing === 'it') items = items.filter((r) => !r.it_owner); else if (q.missing === 'business') items = items.filter((r) => !r.business_owner); else if (q.missing === 'any') items = items.filter((r) => !r.it_owner || !r.business_owner);
    const pct = (x) => (n ? Math.round(x / n * 1000) / 10 : null);
    return { generated: now(), summary: { assets: n, with_it_owner: withIt, with_business_owner: withBo, with_both: both, it_pct: pct(withIt), business_pct: pct(withBo), both_pct: pct(both), missing_it: n - withIt, missing_business: n - withBo },
      by_type: Object.values(byType).sort((a, b) => b.total - a.total), it_owners: dir('it_owner'), business_owners: dir('business_owner'), services: serviceList(rows), items };
  }
  function serviceList(rows) {
    rows = rows || active().map((a) => effective(a, services()));
    const svcMap = services(), m = {};
    for (const r of rows) if (r.business_service) { const k = keyOf(r.business_service); m[k] = m[k] || { id: k, service: r.business_service, assets: 0 }; m[k].assets++; }
    for (const x of Object.values(svcMap)) m[x.id] = m[x.id] || { id: x.id, service: x.service, assets: 0 };
    return Object.values(m).map((x) => Object.assign(x, { business_owner: (svcMap[x.id] || {}).business_owner || '', it_owner: (svcMap[x.id] || {}).it_owner || '', by: (svcMap[x.id] || {}).by || '', at: (svcMap[x.id] || {}).at || null })).sort((a, b) => b.assets - a.assets || a.service.localeCompare(b.service));
  }

  function assign(body = {}, who) {
    const ids = [].concat(body.ids || []).map(String).filter(Boolean);
    if (!ids.length) throw httpErr(400, 'choose at least one asset');
    if (ids.length > 2000) throw httpErr(400, 'at most 2000 assets at once');
    const fields = ['it_owner', 'business_owner', 'business_service'].filter((k) => k in body);
    if (!fields.length) throw httpErr(400, 'set an IT owner, a business owner or a business service');
    const reason = s(body.reason, 500);
    const done = [], missing = [];
    for (const id of ids) {
      const a = app.assets.raw(id); if (!a) { missing.push(id); continue; }
      const o = Object.assign({ id }, own.get(id) || {}), before = { it_owner: o.it_owner || '', business_owner: o.business_owner || '', business_service: o.business_service || '' };
      for (const k of fields) o[k] = s(body[k], k === 'business_service' ? 120 : 200);
      o.by = (who && who.user) || ''; o.at = now(); o.source = body.source === 'import' ? 'import' : 'manual';
      own.put(o); done.push(id);
      audit(who, 'asset.ownership', id, { before, after: { it_owner: o.it_owner || '', business_owner: o.business_owner || '', business_service: o.business_service || '' }, reason });
    }
    return { updated: done.length, not_found: missing };
  }
  function setService(body = {}, who) {
    const name = s(body.service, 120); if (!name) throw httpErr(400, 'a business service name is required');
    const id = keyOf(name), cur = svcCol.get(id) || { id, service: name };
    const before = { business_owner: cur.business_owner || '', it_owner: cur.it_owner || '' };
    const rec = Object.assign({}, cur, { service: name, by: (who && who.user) || '', at: now() });
    for (const k of ['business_owner', 'it_owner']) if (k in body) rec[k] = s(body[k], 200);
    svcCol.put(rec);
    audit(who, 'ownership.service', id, { service: name, before, after: { business_owner: rec.business_owner || '', it_owner: rec.it_owner || '' } });
    return rec;
  }
  function importRows(body = {}, who) {
    const rows = [].concat(body.rows || []); if (!rows.length) throw httpErr(400, 'no rows');
    if (rows.length > 5000) throw httpErr(400, 'at most 5000 rows at once');
    const list = active(), idx = {};
    const add = (k, a) => { if (!k) return; const key = String(k).trim().toLowerCase(); if (!key) return; (idx[key] = idx[key] || []).push(a); };
    for (const a of list) { add(a.asset_tag, a); add(a.serial, a); add(a.name, a); add(a.mgmt_ip, a); }
    let updated = 0; const unmatched = [], ambiguous = [];
    for (const r of rows) {
      const ref = s(r.asset || r.asset_tag || r.serial || r.name || r.ip, 200), hits = idx[ref.toLowerCase()] || [];
      const uniq = [...new Set(hits.map((a) => a.id))];
      if (!uniq.length) { unmatched.push(ref); continue; }
      if (uniq.length > 1) { ambiguous.push(ref); continue; }                // never guess between two assets
      const b = { ids: uniq, reason: s(body.reason, 400) || 'CSV import', source: 'import' };
      for (const k of ['it_owner', 'business_owner', 'business_service']) if (r[k] != null && String(r[k]).trim() !== '') b[k] = r[k];
      if (Object.keys(b).length <= 3) continue;
      assign(b, who); updated++;
    }
    return { rows: rows.length, updated, unmatched, ambiguous };
  }
  function summary() { return view({}).summary; }

  // owners of one asset, inherited from its business service when not set on the asset (used by the GRC consultant)
  function ownerOf(id) { const a = app.assets.all().find((x) => x.id === id); return a ? effective(a, services()) : null; }
  return { view, serviceList, assign, setService, importRows, summary, effective, ownerOf };
}

function registerOwnership(srv, app, opts = {}) {
  const O = createOwnership(app, opts);
  // the writes decided in Python (pyengine/addons_write.py, migration step 9f), committed by engine/py-writer.js; off with
  // ownership.engine = "node", a missing Python bridge, or a clock of its own (opts.now: Python is given Date.now())
  const W = opts.now ? null : (() => { try { return require('./py-writer').createPyWriter(app, { off: ((app.config && app.config.ownership) || {}).engine === 'node' }); } catch (e) { return null; } })();
  const w = (op, b, who, node) => (W ? W.write(op, { own: ['asset_ownership', 'ownership_services'], reads: ['assets'], extra: { body: b } }, who, node) : node());
  app.ownershipWriteStats = () => (W ? W.stats() : null);
  srv.route('GET', '/ownership', (ctx) => void ctx.need('viewer') || O.view(ctx.query || {}));
  srv.route('GET', '/ownership/services', (ctx) => void ctx.need('viewer') || ({ services: O.serviceList() }));
  srv.route('POST', '/ownership/assign', (ctx) => { ctx.need('operator'); const b = ctx.body || {}; return w('ownership.assign', b, ctx.who, () => O.assign(b, ctx.who)); });
  srv.route('POST', '/ownership/services', (ctx) => { ctx.need('operator'); const b = ctx.body || {}; return w('ownership.service', b, ctx.who, () => O.setService(b, ctx.who)); });
  srv.route('POST', '/ownership/import', (ctx) => { ctx.need('operator'); const b = ctx.body || {}; return w('ownership.import', b, ctx.who, () => O.importRows(b, ctx.who)); });
  (app.addons = app.addons || {}).ownership = O;
  return O;
}

module.exports = { createOwnership, registerOwnership };
