// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Admin delete for inventory assets. Self-contained: it works on the stored collections directly, so it can be added
// to an existing install with one registration line (install/add-asset-delete.sh) whatever version the rest is.
//   POST /assets/:id/delete     {reason, discovery: 'review'|'ignore', force}          (admin)
//   POST /bulk/assets/delete    {ids[], reason, discovery, force}                      (admin, max 500)
//   POST /assets/:id/merge      {from, reason, force}   the duplicate 'from' merged into :id, then removed (admin)
// The record and its relationships are removed; the audit entry keeps who deleted what, when and why (a snapshot of the
// identifying fields). A SIEM log source is stopped first; if the SIEM cannot be reached the delete is refused (409,
// code siem_stop_failed) unless force:true. Discovery results linked to the asset go back to review, or are ignored by
// MAC / serial / source id so the next discovery run keeps the device out. An agent bound to the asset is unbound.

const bad = (msg, status = 400, code) => Object.assign(new Error(msg), { status }, code ? { code2: code } : {});
const s = (v, max) => String(v == null ? '' : v).replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, max);
const BULK_MAX = 500;

function createAssetDelete(app) {
  const { store } = app;
  const audit = (e) => { if (app.audit) app.audit(e); };
  const assets = store.collection('assets');
  const rels = store.collection('relationships');
  const devices = store.collection('disc_devices');
  const ignores = store.collection('disc_ignores');
  const agents = store.collection('agents');
  const hex12 = (m) => { const h = String(m || '').toLowerCase().replace(/[^0-9a-f]/g, ''); return h.length === 12 ? h : null; };

  // the same ignore keys discovery uses (engine/discovery/devices.js keysOf + IP-only fallback)
  function ignoreKeys(d) {
    const k = [];
    for (const m of d.macs || []) { const h = hex12(m); if (h) k.push(`mac:${h}`); }
    if (d.serial) k.push(`ser:${String(d.serial).toLowerCase()}`);
    for (const u of d.uids || []) k.push(`uid:${u}`);
    if (!k.length && d.ip) k.push(`ipo:${d.scope_id || ''}:${d.ip}`);
    return k;
  }

  function unlinkDiscovery(assetId, mode, reason, who) {
    const at = new Date().toISOString();
    const hit = devices.all((x) => x.asset_id === assetId);
    for (const d of hit) {
      if (mode === 'ignore') {
        const why = s(reason, 500) || 'asset deleted from the inventory';
        for (const k of ignoreKeys(d)) ignores.put({ id: k, device_id: d.id, reason: why, by: who.user, at });
        devices.patch(d.id, (x) => { x.status = 'ignored'; x.asset_id = null; x.ignore_reason = why; x.decided_by = who.user; x.decided_at = at; });
      } else {
        devices.patch(d.id, (x) => { x.status = 'new'; x.asset_id = null; x.decided_by = who.user; x.decided_at = at; });
      }
      audit({ by: who.user, role: who.role, ip: who.ip, action: 'discovery.unlink', target: d.id, detail: { asset_id: assetId, now: mode === 'ignore' ? 'ignored' : 'new', ip: d.ip || null, mac: d.mac || null } });
    }
    return hit.length;
  }

  async function remove(id, body, who) {
    if (typeof assets.remove !== 'function') throw bad('this store does not support delete', 501);
    const a = assets.get(String(id || ''));
    if (!a) throw bad('asset not found', 404);
    const reason = s(body.reason, 500);
    if (reason.length < 3) throw bad('a reason is required to delete an asset (min 3 characters)');
    const mode = body.discovery === 'ignore' ? 'ignore' : 'review';
    let siem = null;
    const sid = (a.siem && a.siem.source_id) || (a.log_collection && a.log_collection.state !== 'stopped' && a.log_collection.source_id) || null;
    if (sid && app.membership && typeof app.membership.stop === 'function') {
      try { const r = await app.membership.stop(a.id, who, { confirm: true, reason: `asset deleted: ${reason}` }); siem = { stopped: true, source_id: r.source_id || sid }; } catch (e) {
        if (body.force !== true) throw bad(`the SIEM log source for this asset could not be stopped (${e.message}) — try again, or delete anyway`, 409, 'siem_stop_failed');
        siem = { stopped: false, source_id: sid, error: e.message };
      }
    } else if (sid) siem = { stopped: false, source_id: sid, error: 'log collection control is not available in this version — remove the source in the SIEM' };
    const discovery = unlinkDiscovery(a.id, mode, reason, who);
    for (const ag of agents.all((x) => x.asset_id === a.id)) agents.patch(ag.id, (o) => { o.asset_id = null; });
    const gone = rels.all((r) => r.from === a.id || r.to === a.id);
    for (const r of gone) rels.remove(r.id);
    const cur = assets.get(a.id) || a;
    const snapshot = { name: cur.name || null, asset_tag: cur.asset_tag || null, serial: cur.serial || null, type: cur.type || null, status: cur.status || null, mgmt_ip: cur.mgmt_ip || null, mac: cur.mac || null, site: cur.site || null, owner: cur.owner || null, sources: (cur.sources || []).map((x) => x.source), created_at: cur.created_at || null };
    assets.remove(a.id);
    if (app.membership && typeof app.membership.invalidate === 'function') app.membership.invalidate();
    audit({ by: who.user, role: who.role, ip: who.ip, action: 'asset.delete', target: a.id, detail: { reason, deleted: snapshot, relationships_removed: gone.length, discovery_results: discovery, discovery_mode: mode, siem } });
    return { deleted: a.id, asset: snapshot, relationships_removed: gone.length, discovery_results: discovery, discovery_mode: mode, siem };
  }

  async function bulk(body, who) {
    const ids = Array.isArray(body.ids) ? [...new Set(body.ids.map(String))] : [];
    if (!ids.length) throw bad('ids[] required');
    if (ids.length > BULK_MAX) throw bad(`at most ${BULK_MAX} assets per bulk delete`);
    if (s(body.reason, 500).length < 3) throw bad('a reason is required to delete assets (min 3 characters)');
    const results = [];
    for (const id of ids) {
      try { const r = await remove(id, body, who); results.push({ asset_id: id, ok: true, name: r.asset.name }); } catch (e) { results.push(Object.assign({ asset_id: id, ok: false, error: e.message, status: e.status || 500 }, e.code2 ? { code: e.code2 } : {})); }
    }
    const ok = results.filter((r) => r.ok).length;
    audit({ by: who.user, role: who.role, ip: who.ip, action: 'asset.bulk-delete', target: 'bulk', detail: { total: ids.length, ok } });
    return { total: ids.length, ok, failed: ids.length - ok, results };
  }

  // MERGE a duplicate into the record that stays: the empty fields of the one kept are filled from the duplicate (nothing the kept
  // record already says is overwritten), tags and sources are joined, discovery results, agents and relationships move to it, then
  // the duplicate is removed like a delete (its SIEM log source stopped). Audited with both records' identifying fields.
  const FILL = ['mgmt_ip', 'mac', 'serial', 'asset_tag', 'model', 'vendor', 'manufacturer', 'os', 'os_version', 'site', 'location', 'department', 'owner', 'custodian', 'warranty_end', 'eol', 'purchase_date', 'cpu', 'ram_gb', 'disk_gb', 'fqdn', 'domain', 'description'];
  async function merge(keepId, body, who) {
    const keep = assets.get(String(keepId || '')), fromId = s(body.from, 120), src = assets.get(fromId);
    if (!keep) throw bad('asset not found', 404);
    if (!fromId) throw bad('from is required: the duplicate to merge into this asset');
    if (!src) throw bad('from: no asset ' + fromId, 404);
    if (src.id === keep.id) throw bad('from: an asset cannot be merged into itself');
    const reason = s(body.reason, 500); if (reason.length < 3) throw bad('a reason is required to merge assets (min 3 characters)');
    const filled = [];
    assets.patch(keep.id, (o) => {
      for (const f of FILL) if ((o[f] == null || o[f] === '') && src[f] != null && src[f] !== '') { o[f] = src[f]; filled.push(f); }
      o.tags = [...new Set([].concat(o.tags || [], src.tags || []))];
      const k = (x) => (x && (x.source || x)) + ''; const have = new Set((o.sources || []).map(k)); o.sources = (o.sources || []).concat((src.sources || []).filter((x) => !have.has(k(x))));
      if (!o.siem && src.siem) { o.siem = src.siem; filled.push('siem'); }
      o.merged_from = [].concat(o.merged_from || [], [{ id: src.id, name: src.name || null, at: new Date().toISOString(), by: who.user }]).slice(-20);
      o.updated_at = new Date().toISOString(); return o;
    });
    // what pointed at the duplicate now points at the record that stays
    let moved = 0;
    for (const d of devices.all((x) => x.asset_id === src.id)) { devices.patch(d.id, (x) => { x.asset_id = keep.id; }); moved++; }
    for (const ag of agents.all((x) => x.asset_id === src.id)) { agents.patch(ag.id, (o) => { o.asset_id = keep.id; }); moved++; }
    const seen = new Set(rels.all((r) => r.from === keep.id || r.to === keep.id).map((r) => [r.from, r.to, r.type].join('|')));
    for (const r of rels.all((x) => x.from === src.id || x.to === src.id)) {
      const n = { from: r.from === src.id ? keep.id : r.from, to: r.to === src.id ? keep.id : r.to }; const key = [n.from, n.to, r.type].join('|');
      if (n.from === n.to || seen.has(key)) continue; seen.add(key); rels.put(Object.assign({}, r, { id: r.id + '-m', from: n.from, to: n.to })); moved++;
    }
    // the SIEM source moved to the record that stays is not stopped with the duplicate
    const srcCopy = assets.get(src.id); if (filled.includes('siem')) assets.patch(src.id, (o) => { delete o.siem; if (o.log_collection) o.log_collection = Object.assign({}, o.log_collection, { state: 'stopped' }); return o; });
    const r = await remove(src.id, { reason: 'merged into ' + (keep.name || keep.id) + ': ' + reason, discovery: 'review', force: body.force === true }, who);
    audit({ by: who.user, role: who.role, ip: who.ip, action: 'asset.merge', target: keep.id, detail: { reason, merged: { id: srcCopy.id, name: srcCopy.name || null, mgmt_ip: srcCopy.mgmt_ip || null, serial: srcCopy.serial || null }, filled, links_moved: moved } });
    return { kept: keep.id, merged: src.id, filled, links_moved: moved, deleted: r.asset };
  }

  return { remove, bulk, merge, BULK_MAX };
}

function registerAssetDelete(srv, app) {
  const del = createAssetDelete(app);
  srv.route('POST', '/assets/:id/delete', async (ctx) => { ctx.need('admin'); return del.remove(ctx.params.id, ctx.body || {}, ctx.who); });
  srv.route('POST', '/bulk/assets/delete', async (ctx) => { ctx.need('admin'); return del.bulk(ctx.body || {}, ctx.who); });
  srv.route('POST', '/assets/:id/merge', async (ctx) => {
    ctx.need('admin');
    const { body } = require('./check');
    const v = body(ctx.body || {}).str('from', { required: true, max: 120 }).str('reason', { required: true, min: 3, max: 500 }).bool('force', { def: false }).done();
    return del.merge(ctx.params.id, v, ctx.who);
  });
  return del;
}

module.exports = { createAssetDelete, registerAssetDelete };
