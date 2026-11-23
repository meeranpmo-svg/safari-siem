// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * ITAM Stocktake intelligence (IT Assets -> Stocktake, {P} = /api/itam). Over the scan-based stocktakes (engine/stocktake.js: open /
 * scan / close, decided in parity with Python and audited there - unchanged here) and the asset register - computed, never written:
 *   progress     per stocktake: found / expected, by type and by department, the scan rate per hour, the last scans
 *   missing      every expected asset not scanned, with a likelihood it is really gone and why: seen on the network in the last 7 days
 *                (probably present, not scanned), portable (may be with its user), missing in an earlier stocktake too, not seen for
 *                90+ days (likely lost) - and how a person resolved it
 *   unexpected   codes scanned that match no asset, with the closest tag / serial (edit distance <= 2 after O/0, I/1, S/5 folding:
 *                a typo or a worn label) - or "not in the register: add it"
 *   misplaced    assets found in a stocktake scoped to another site (propose moving the record)
 *   plan         which site to count next: days since its last closed count, assets, share of critical assets, last accuracy
 *   GET  /stocktake-intel[?id=]                 viewer
 *   POST /stocktake/:id/resolve                 operator, a person: {asset_id, outcome found|lost|moved|explained, note}. Records the
 *        resolution (audited). Marking an asset lost or moving it stays on POST /assets/:id/lost | /move (validated, audited there).
 */
const { body } = require('./check');
const { isHuman } = require('./approve-scopes');
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const DAY = 86400000;
const PORTABLE = { laptop: 1, mobile: 1, phone: 1, tablet: 1 };
const CRIT = (a) => a && (a.classification === 'secret' || a.classification === 'top_secret' || (a.cia && (a.cia.c === 'high' || a.cia.i === 'high' || a.cia.a === 'high')));
const fold = (s) => String(s || '').toLowerCase().replace(/[^0-9a-z]/g, '').replace(/o/g, '0').replace(/[il]/g, '1').replace(/s/g, '5');
function lev(a, b, cap) {
  if (Math.abs(a.length - b.length) > cap) return cap + 1;
  let p = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) { const c = [i]; let lo = i;
    for (let j = 1; j <= b.length; j++) { c[j] = Math.min(p[j] + 1, c[j - 1] + 1, p[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1)); lo = Math.min(lo, c[j]); }
    if (lo > cap) return cap + 1; p = c; }
  return p[b.length];
}

function createStocktakeIntel(app, opts = {}) {
  const now = opts.now || Date.now;
  const RES = app.store.collection('stocktake_resolutions');
  function view(q = {}) {
    const T = now(), assets = app.store.collection('assets').all(), A = Object.fromEntries(assets.map((a) => [a.id, a]));
    const takes = app.store.collection('stocktakes').all().sort((x, y) => String(y.opened_at).localeCompare(String(x.opened_at)));
    const closed = takes.filter((s) => s.status === 'closed');
    const missedBefore = {}; for (const s of closed) for (const id of s.missing || []) (missedBefore[id] = missedBefore[id] || []).push(s.id);
    const res = {}; for (const r of RES.all()) res[r.stocktake_id + '|' + r.asset_id] = r;
    const codes = []; for (const a of assets) for (const k of ['asset_tag', 'serial']) if (a[k] && String(a[k]).length >= 3) codes.push({ f: fold(a[k]), raw: a[k], field: k, a });
    const summary = takes.map((s) => { const n = s.expected.length, f = s.scanned.filter((x) => s.expected.includes(x.asset_id)).length;
      return { id: s.id, name: s.name, site: s.site, status: s.status, opened_at: s.opened_at, closed_at: s.closed_at, opened_by: s.opened_by, expected: n, found: f, unexpected: s.unexpected.length, pct: n ? Math.round(100 * f / n) : null }; });
    let detail = null;
    const s = q.id ? takes.find((x) => x.id === q.id) : (takes.find((x) => x.status === 'open') || takes[0]);
    if (q.id && !s) throw httpErr(404, 'stocktake not found');
    if (s) {
      const scanned = new Set(s.scanned.map((x) => x.asset_id)), missingIds = s.status === 'closed' ? (s.missing || []) : s.expected.filter((id) => !scanned.has(id));
      const group = (key) => { const m = {}; for (const id of s.expected) { const a = A[id] || {}, v = a[key] || '(none)', r = m[v] = m[v] || { value: v, expected: 0, found: 0 }; r.expected++; if (scanned.has(id)) r.found++; } return Object.values(m).sort((x, y) => (x.found / x.expected) - (y.found / y.expected)); };
      const missing = missingIds.map((id) => { const a = A[id] || { id }, why = [], seen = a.last_seen ? Math.floor((T - Date.parse(a.last_seen)) / DAY) : null; let p = 50;
        if (seen != null && seen <= 7) { p -= 35; why.push('seen on the network ' + seen + ' day(s) ago - probably present, not scanned'); }
        else if (seen != null && seen >= 90) { p += 30; why.push('not seen for ' + seen + ' days'); }
        else if (seen == null) why.push('never seen on the network (no live source)');
        if (PORTABLE[a.type]) { p -= 10; why.push('portable - may be with ' + (a.owner || a.custodian || 'its user')); }
        const prev = (missedBefore[id] || []).filter((x) => x !== s.id); if (prev.length) { p += 20; why.push('also missing in ' + prev.length + ' earlier stocktake(s)'); }
        if (a.status === 'in_repair' || a.status === 'repair') { p -= 20; why.push('recorded as in repair'); }
        const r = res[s.id + '|' + id];
        return { asset_id: id, name: a.name || id, asset_tag: a.asset_tag || null, serial: a.serial || null, type: a.type || null, department: a.department || null, owner: a.owner || null, custodian: a.custodian || null,
          location: a.location || null, last_seen: a.last_seen || null, seen_days: seen, critical: !!CRIT(a), likely_gone: Math.max(0, Math.min(100, p)), why, resolution: r ? { outcome: r.outcome, note: r.note, by: r.by, at: r.at } : null }; })
        .sort((x, y) => (x.resolution ? 1 : 0) - (y.resolution ? 1 : 0) || y.likely_gone - x.likely_gone || (y.critical ? 1 : 0) - (x.critical ? 1 : 0));
      const unexpected = s.unexpected.map((u) => { const f = fold(u.code); let best = null;
        if (f.length >= 3) for (const c of codes) { const d = c.f === f ? 0 : lev(f, c.f, 2); if (d <= 2 && (!best || d < best.d)) best = { d, c }; }
        return { code: u.code, at: u.at, by: u.by, suggestion: best ? { asset_id: best.c.a.id, name: best.c.a.name, field: best.c.field, value: best.c.raw, distance: best.d, why: best.d === 0 ? 'the same code once O/0, I/1, S/5 and punctuation are ignored' : best.d + ' character(s) away from this ' + (best.c.field === 'asset_tag' ? 'tag' : 'serial') + ' - a typo or a worn label?' } : null }; });
      const misplaced = s.site ? s.scanned.filter((x) => !s.expected.includes(x.asset_id) && A[x.asset_id]).map((x) => ({ asset_id: x.asset_id, name: A[x.asset_id].name, recorded_site: A[x.asset_id].site || null, found_at: s.site, at: x.at, by: x.by })) : [];
      const hrs = s.scanned.length > 1 ? (Date.parse(s.scanned[s.scanned.length - 1].at) - Date.parse(s.scanned[0].at)) / 3600000 : 0;
      detail = Object.assign({}, summary.find((x) => x.id === s.id), { by_type: group('type'), by_department: group('department'), missing, unexpected, misplaced,
        rate_per_hour: hrs > 0.05 ? Math.round(s.scanned.length / hrs) : null, eta_minutes: hrs > 0.05 && s.status === 'open' ? Math.round(missingIds.length / (s.scanned.length / hrs) * 60) : null,
        recent: s.scanned.slice(-15).reverse().map((x) => ({ asset_id: x.asset_id, name: (A[x.asset_id] || {}).name || x.asset_id, code: x.code, at: x.at, by: x.by })),
        resolved: missing.filter((m) => m.resolution).length });
    }
    // plan: which site to count next
    const sites = {}; for (const a of assets) { if (a.status === 'retired' || a.status === 'disposed') continue; const k = a.site || '(no site)', r = sites[k] = sites[k] || { site: k, assets: 0, critical: 0 }; r.assets++; if (CRIT(a)) r.critical++; }
    const plan = Object.values(sites).map((r) => { const last = closed.find((c) => (c.site || null) === (r.site === '(no site)' ? null : r.site)) || closed.find((c) => !c.site);
      const days = last ? Math.floor((T - Date.parse(last.closed_at)) / DAY) : null, acc = last && last.expected.length ? Math.round(100 * (last.expected.length - (last.missing || []).length) / last.expected.length) : null, why = [];
      let p = days == null ? 60 : Math.min(60, Math.round(days / 6)); why.push(days == null ? 'never counted' : 'last counted ' + days + ' days ago' + (last.site ? '' : ' (in a register-wide count)'));
      if (r.critical) { p += Math.min(20, r.critical * 2); why.push(r.critical + ' critical asset(s)'); }
      if (acc != null && acc < 95) { p += Math.round((95 - acc) / 2); why.push('last accuracy ' + acc + ' %'); }
      return Object.assign(r, { last_counted_days: days, last_accuracy: acc, priority: Math.min(100, p), why }); }).sort((x, y) => y.priority - x.priority);
    const lastClosed = closed[0];
    return { at: new Date(T).toISOString(), stocktakes: summary, current: detail, plan,
      kpis: { open: takes.filter((x) => x.status === 'open').length, closed: closed.length, last_accuracy: lastClosed && lastClosed.expected.length ? Math.round(100 * (lastClosed.expected.length - (lastClosed.missing || []).length) / lastClosed.expected.length) : null,
        repeat_missing: Object.values(missedBefore).filter((l) => l.length >= 2).length, sites_never_counted: plan.filter((p) => p.last_counted_days == null).length },
      note: 'Likelihoods are indicators from what the register and the network sources know - a person confirms before an asset is marked lost.' };
  }
  function resolve(id, input, who) {
    if (!isHuman(who && who.user)) throw httpErr(403, 'a service or AI identity cannot resolve a stocktake: a person does');
    const b = body(input || {}).str('asset_id', { required: true, max: 120 }).oneOf('outcome', ['found', 'lost', 'moved', 'explained'], { required: true }).str('note', { max: 500 }).done();
    const s = app.store.collection('stocktakes').get(id); if (!s) throw httpErr(404, 'stocktake not found');
    if (!s.expected.includes(b.asset_id)) throw httpErr(400, 'asset_id: this asset was not expected in this stocktake');
    if (s.scanned.some((x) => x.asset_id === b.asset_id)) throw httpErr(409, 'asset_id: this asset was scanned - nothing to resolve');
    if ((b.outcome === 'explained' || b.outcome === 'lost') && !(b.note && b.note.trim())) throw httpErr(400, 'note: say what happened to it');
    const rec = { id: s.id + '|' + b.asset_id, stocktake_id: s.id, asset_id: b.asset_id, outcome: b.outcome, note: b.note || null, by: who.user, role: who.role, at: new Date(now()).toISOString() };
    RES.put(rec);
    app.audit({ by: who.user, role: who.role, ip: who.ip, action: 'stocktake.resolve', target: s.id, detail: { asset_id: b.asset_id, outcome: b.outcome, note: b.note || null } });
    return { ok: true, resolution: rec };
  }
  return { view, resolve };
}

function registerStocktakeIntel(srv, app, I) {
  srv.route('GET', '/stocktake-intel', (ctx) => { ctx.need('viewer'); return I.view(ctx.query || {}); });
  srv.route('POST', '/stocktake/:id/resolve', (ctx) => { ctx.need('operator'); return I.resolve(ctx.params.id, ctx.body, ctx.who); });
}

module.exports = { createStocktakeIntel, registerStocktakeIntel, fold, lev };
