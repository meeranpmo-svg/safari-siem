// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Admin delete for inventory assets. Self-contained: it works on the stored collections directly, so it can be added
// to an existing install with one registration line (install/add-asset-delete.sh) whatever version the rest is.
//   POST /assets/:id/delete     {reason, discovery: 'review'|'ignore', force}          (admin)
//   POST /bulk/assets/delete    {ids[], reason, discovery, force}                      (admin, max 500)
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

  return { remove, bulk, BULK_MAX };
}

function registerAssetDelete(srv, app) {
  const del = createAssetDelete(app);
  srv.route('POST', '/assets/:id/delete', async (ctx) => { ctx.need('admin'); return del.remove(ctx.params.id, ctx.body || {}, ctx.who); });
  srv.route('POST', '/bulk/assets/delete', async (ctx) => { ctx.need('admin'); return del.bulk(ctx.body || {}, ctx.who); });
  return del;
}

module.exports = { createAssetDelete, registerAssetDelete };
