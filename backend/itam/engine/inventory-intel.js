// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * ITAM Inventory intelligence (IT Assets -> Inventory, {P} = /api/itam). One read of the register for the Inventory page: a compact
 * row per asset, facet counts, and what the register says about itself - computed, never written:
 *   quality      0-100 per asset: the share of the fields that matter for its type that are filled (serial, MAC for networked
 *                devices, owner, site, department, vendor / model, warranty, end of life, classification, CIA), with the missing ones
 *   duplicates   pairs the merge rules would match (same serial / MAC strong, same name weak) - for a person to merge or explain
 *   outliers     ML: memory / disk / CPU far from the median of the same model (>= 3 assets of that model): x2 or /2 - a wrong
 *                record or a changed machine
 *   stale        in use, not seen for longer than the ITAM not-seen threshold; ghosts - retired / disposed yet seen in the last 7 days
 *   coverage     per field and per site, so the worst place to fix data is visible
 *   GET /inventory?all=1     viewer    (all=1 includes retired / disposed)
 * Writes stay on the existing asset routes (POST /assets, /assets/:id, /assets/:id/<action>), validated and audited there.
 */
const DAY = 86400000;
const CLOSED = { retired: 1, disposed: 1, lost: 1 };
const HW = { server: 1, workstation: 1, laptop: 1, network: 1, storage: 1, printer: 1, phone: 1, ups: 1, mobile: 1 };
const FIELDS = [['serial', (a) => HW[a.type]], ['mac', (a) => a.networked && HW[a.type]], ['owner', () => true], ['site', () => true], ['department', () => true],
  ['vendor', (a) => a.type !== 'vm'], ['model', (a) => a.type !== 'vm'], ['warranty', (a) => HW[a.type]], ['eol', (a) => HW[a.type] || a.type === 'vm'], ['classification', () => true], ['cia', () => true]];
const median = (a) => { const x = a.slice().sort((p, q) => p - q), m = x.length >> 1; return x.length ? (x.length % 2 ? x[m] : (x[m - 1] + x[m]) / 2) : null; };
const has = (a, f) => { const v = a[f]; if (v == null || v === '') return false; if (f === 'cia') return !!(v.c || v.i || v.a); if (f === 'warranty') return !!(v.end || v.start); return true; };

function createInventoryIntel(app, opts = {}) {
  const now = opts.now || Date.now;
  function view(q = {}) {
    const T = now(), all = app.store.collection('assets').all(), st = (app.settings && app.settings.get && app.settings.get()) || {}, nsd = st.not_seen_days || 30;
    const list = q.all === '1' ? all : all.filter((a) => !CLOSED[a.status]);
    const age = (a) => (a.last_seen ? Math.round((T - Date.parse(a.last_seen)) / DAY) : null);
    // outliers per model
    const byModel = {}; for (const a of all) if (!CLOSED[a.status] && a.model) (byModel[String(a.model).toLowerCase()] = byModel[String(a.model).toLowerCase()] || []).push(a);
    const out = {};
    for (const [m, L] of Object.entries(byModel)) { if (L.length < 3) continue;
      for (const k of ['mem_gb', 'disk_gb']) { const vals = L.map((a) => a[k]).filter((v) => typeof v === 'number' && v > 0); if (vals.length < 3) continue; const md = median(vals);
        for (const a of L) if (typeof a[k] === 'number' && a[k] > 0 && (a[k] >= md * 2 || a[k] <= md / 2)) (out[a.id] = out[a.id] || []).push((k === 'mem_gb' ? 'memory ' : 'disk ') + a[k] + ' GB vs ' + md + ' GB typical for ' + L[0].model + ' (' + vals.length + ' assets)'); } }
    // duplicates (strong keys first)
    // duplicates, by index (same rules as the merge: serial / MAC strong, short host name weak)
    const dups = [], seenPair = new Set(), act = all.filter((a) => !CLOSED[a.status]), idx = { serial: {}, mac: {}, hostname: {} };
    const hex = (v) => String(v || '').toLowerCase().replace(/[^0-9a-f]/g, ''), sn = (v) => String(v || '').toLowerCase().split('.')[0];
    for (const a of act) { if (a.serial && String(a.serial).length >= 3) (idx.serial[String(a.serial).toLowerCase()] = idx.serial[String(a.serial).toLowerCase()] || []).push(a); if (hex(a.mac).length === 12) (idx.mac[hex(a.mac)] = idx.mac[hex(a.mac)] || []).push(a); if (sn(a.name).length >= 3) (idx.hostname[sn(a.name)] = idx.hostname[sn(a.name)] || []).push(a); }
    const pairs = {};
    for (const [by, m] of Object.entries(idx)) for (const L of Object.values(m)) if (L.length > 1) for (let x = 0; x < L.length; x++) for (let y = x + 1; y < L.length; y++) { const k = [L[x].id, L[y].id].sort().join('|'); (pairs[k] = pairs[k] || { a: L[x], b: L[y], by: [] }).by.push(by); }
    for (const [k, p] of Object.entries(pairs)) { seenPair.add(k); dups.push({ a: p.a.id, a_name: p.a.name || p.a.id, b: p.b.id, b_name: p.b.name || p.b.id, by: p.by, strength: p.by.includes('serial') || p.by.includes('mac') ? 'strong' : 'weak' }); }
    dups.sort((x, y) => (x.strength === y.strength ? 0 : x.strength === 'strong' ? -1 : 1));
    const dupOf = {}; for (const d of dups) { (dupOf[d.a] = dupOf[d.a] || []).push(d.b); (dupOf[d.b] = dupOf[d.b] || []).push(d.a); }
    const fieldCov = Object.fromEntries(FIELDS.map(([f]) => [f, { need: 0, have: 0 }])), siteQ = {};
    const rows = list.map((a) => {
      const need = FIELDS.filter(([, w]) => w(a)), missing = need.filter(([f]) => !has(a, f)).map(([f]) => f);
      for (const [f] of need) { fieldCov[f].need++; if (has(a, f)) fieldCov[f].have++; }
      const quality = need.length ? Math.round(100 * (need.length - missing.length) / need.length) : 100, ag = age(a);
      const issues = [];
      if (a.status === 'in_use' && a.networked && ag != null && ag > nsd) issues.push('stale');
      if (CLOSED[a.status] && ag != null && ag <= 7) issues.push('ghost');
      if (dupOf[a.id]) issues.push('duplicate');
      if (out[a.id]) issues.push('outlier');
      if (quality < 60) issues.push('incomplete');
      const s = a.site || '(no site)'; const sq = siteQ[s] = siteQ[s] || { site: s, assets: 0, q: 0 }; sq.assets++; sq.q += quality;
      return { id: a.id, name: a.name, asset_tag: a.asset_tag, type: a.type, status: a.status, site: a.site, department: a.department, owner: a.owner, custodian: a.custodian,
        vendor: a.vendor, model: a.model, serial: a.serial, mac: a.mac, ip: a.mgmt_ip, os: a.os, warranty_end: a.warranty && a.warranty.end ? String(a.warranty.end).slice(0, 10) : null,
        support_end: a.support && a.support.end ? String(a.support.end).slice(0, 10) : null, eol: a.eol ? String(a.eol).slice(0, 10) : null, classification: a.classification || null, cia: a.cia || null,
        cpu: a.cpu || null, mem_gb: a.mem_gb == null ? null : a.mem_gb, disk_gb: a.disk_gb == null ? null : a.disk_gb,
        purchase_date: a.purchase && a.purchase.date ? String(a.purchase.date).slice(0, 10) : null, purchase_cost: a.purchase && a.purchase.cost != null ? a.purchase.cost : null, supplier: (a.purchase && a.purchase.supplier) || null, po: (a.purchase && a.purchase.po) || null,
        last_seen: a.last_seen || null, seen_days: ag, sources: (a.sources || []).map((x) => x.source || x), quality, missing, issues, outlier: out[a.id] || [], duplicate_of: dupOf[a.id] || [], updated_at: a.updated_at };
    });
    const facet = (k) => { const m = {}; for (const r of rows) { const v = r[k] || '(none)'; m[v] = (m[v] || 0) + 1; } return Object.entries(m).sort((x, y) => y[1] - x[1]).map(([v, n]) => ({ value: v, count: n })); };
    const iss = {}; for (const r of rows) for (const i of r.issues) iss[i] = (iss[i] || 0) + 1;
    return { at: new Date(T).toISOString(), total: rows.length, not_seen_days: nsd, rows,
      facets: { type: facet('type'), status: facet('status'), site: facet('site'), department: facet('department'), vendor: facet('vendor'), issue: Object.entries(iss).map(([v, n]) => ({ value: v, count: n })) },
      quality: { avg: rows.length ? Math.round(rows.reduce((n, r) => n + r.quality, 0) / rows.length) : null, by_field: Object.entries(fieldCov).map(([f, c]) => ({ field: f, have: c.have, need: c.need, pct: c.need ? Math.round(100 * c.have / c.need) : null })),
        by_site: Object.values(siteQ).map((s) => ({ site: s.site, assets: s.assets, avg: Math.round(s.q / s.assets) })).sort((x, y) => x.avg - y.avg) },
      duplicates: dups.slice(0, 200),
      note: 'Quality is the share of the fields that matter for each asset type that are filled. Duplicates use the same rules as the merge; outliers compare each asset with the median of its own model.' };
  }
  return { view };
}

function registerInventoryIntel(srv, app, I) {
  srv.route('GET', '/inventory', (ctx) => { ctx.need('viewer'); return I.view(ctx.query || {}); });
}

module.exports = { createInventoryIntel, registerInventoryIntel, FIELDS };
