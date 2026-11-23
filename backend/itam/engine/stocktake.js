// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Scan-based stocktake / physical audit. An admin opens a stocktake (optionally scoped to a site); operators scan
// asset tags/serials; the engine marks each as found, flags unexpected (not in inventory) and missing (expected but
// not scanned). Nothing is deleted; results feed findings. No hard delete.
const crypto = require('node:crypto');

const bad = (msg, status = 400) => Object.assign(new Error(msg), { status });

function createStocktake({ store, audit, assets }) {
  const col = store.collection('stocktakes');

  function open(body, who) {
    const id = `stk_${crypto.randomBytes(5).toString('hex')}`;
    const site = String((body && body.site) || '').trim() || null;
    const expected = assets.all().filter((a) => a.status !== 'disposed' && a.status !== 'retired' && (!site || a.site === site)).map((a) => a.id);
    const rec = { id, name: String((body && body.name) || `Stocktake ${new Date().toISOString().slice(0, 10)}`).slice(0, 200), site, status: 'open', opened_by: who && who.user, opened_at: new Date().toISOString(), expected, scanned: [], unexpected: [], closed_at: null };
    col.put(rec);
    if (audit) audit({ by: who && who.user, role: who && who.role, action: 'stocktake.open', target: id, detail: { site, expected: expected.length } });
    return view(rec);
  }

  function scan(id, body, who) {
    const rec = col.get(id); if (!rec) throw bad('stocktake not found', 404);
    if (rec.status !== 'open') throw bad('stocktake is closed');
    const code = String((body && (body.code || body.tag || body.serial)) || '').trim();
    if (!code) throw bad('scan needs a code (asset tag or serial)');
    const matches = assets.byTag(code);
    const now = new Date().toISOString();
    if (!matches.length) {
      if (!rec.unexpected.some((u) => u.code === code)) rec.unexpected.push({ code, at: now, by: who && who.user });
      col.put(rec);
      return { result: 'unexpected', code, asset: null, stocktake: view(rec) };
    }
    const a = matches[0];
    if (!rec.scanned.some((s) => s.asset_id === a.id)) rec.scanned.push({ asset_id: a.id, code, at: now, by: who && who.user });
    col.put(rec);
    return { result: rec.expected.includes(a.id) ? 'found' : 'found_out_of_scope', code, asset: a, stocktake: view(rec) };
  }

  function close(id, who) {
    const rec = col.get(id); if (!rec) throw bad('stocktake not found', 404);
    if (rec.status === 'closed') return view(rec);
    const scannedIds = new Set(rec.scanned.map((s) => s.asset_id));
    rec.missing = rec.expected.filter((aid) => !scannedIds.has(aid));
    rec.status = 'closed'; rec.closed_at = new Date().toISOString(); rec.closed_by = who && who.user;
    col.put(rec);
    if (audit) audit({ by: who && who.user, role: who && who.role, action: 'stocktake.close', target: id, detail: { expected: rec.expected.length, found: rec.scanned.length, missing: rec.missing.length, unexpected: rec.unexpected.length } });
    return view(rec);
  }

  function view(rec) {
    const scannedIds = new Set(rec.scanned.map((s) => s.asset_id));
    const missing = rec.status === 'closed' ? (rec.missing || []) : rec.expected.filter((aid) => !scannedIds.has(aid));
    return { id: rec.id, name: rec.name, site: rec.site, status: rec.status, opened_by: rec.opened_by, opened_at: rec.opened_at, closed_at: rec.closed_at, expected: rec.expected.length, found: rec.scanned.length, missing: missing.length, unexpected: rec.unexpected.length, scanned: rec.scanned, unexpected_scans: rec.unexpected, missing_ids: missing };
  }
  function list() { return col.all().map(view); }
  function get(id) { const r = col.get(id); return r ? view(r) : null; }

  return { open, scan, close, list, get };
}

module.exports = { createStocktake };
