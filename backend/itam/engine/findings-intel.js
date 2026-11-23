// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * ITAM AI Findings intelligence (IT Assets -> AI Findings, {P} = /api/itam). Over the findings the deterministic rules raise
 * (engine/findings.js: not seen, shadow IT, missing data, warranty / end of life, licence over- and under-use) and the people's
 * decisions on them - computed, never written; decisions stay on POST /ai/findings/:id/accept|dismiss (audited there):
 *   priority   0-100 per open finding, itemised: severity, how critical the asset is (classification, CIA, type), how long it has
 *              been open, and what people did with this kind before (LEARNED: a kind dismissed >= 70 % of the time over >= 5
 *              decisions is lowered, with the count; a kind always accepted is raised)
 *   learning   per kind: open / accepted / dismissed / resolved, dismissal rate, median days to a decision, the most common
 *              dismissal reasons, and a tuning suggestion when a kind is mostly dismissed (the rule is noisy here)
 *              A finding that came back after it was resolved is raised (recurring).
 *   hotspots   the assets, sites and owners with the most open findings; ageing (open > 30 days); a 12-week opened vs closed trend
 *   fix        where each kind is fixed (Inventory, Asset Data Autopilot, Software & Licences, Renewals & Expiry, Lifecycle)
 *   GET /ai/findings/intel     viewer
 *   POST /ai/findings/bulk     operator, a person: {ids[], status accepted|dismissed|open, reason} - dismissing needs a reason (it is what
 *                              the learning reads); each finding is audited by findings.setStatus, plus one bulk record
 */
const { body } = require('./check');
const { isHuman } = require('./approve-scopes');
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const DAY = 86400000;
const SEV = { high: 60, medium: 35, low: 15 };
const FIX = { not_seen: ['inventory.html', 'Inventory'], shadow_it: ['software-studio.html', 'Software & Licences'], missing_owner: ['inventory.html', 'Inventory'], missing_location: ['inventory.html', 'Inventory'],
  missing_warranty: ['asset-autofill.html', 'Asset Data Autopilot'], warranty_expired: ['renewals-expiry.html', 'Renewals & Expiry'], warranty_expiring: ['renewals-expiry.html', 'Renewals & Expiry'],
  eol_passed: ['lifecycle-studio.html', 'Lifecycle Studio'], eol_expiring: ['lifecycle-studio.html', 'Lifecycle Studio'], licence_over: ['software-studio.html', 'Software & Licences'], licence_under: ['software-studio.html', 'Software & Licences'], licence_expiring: ['renewals-expiry.html', 'Renewals & Expiry'] };
const median = (a) => { const x = a.slice().sort((p, q) => p - q), m = x.length >> 1; return x.length ? (x.length % 2 ? x[m] : (x[m - 1] + x[m]) / 2) : null; };
const decidedAt = (f) => f.accepted_at || f.dismissed_at || f.resolved_at || null;

function createFindingsIntel(app, opts = {}) {
  const now = opts.now || Date.now;
  function view() {
    const T = now(), all = app.store.collection('findings').all(), assets = Object.fromEntries(app.store.collection('assets').all().map((a) => [a.id, a]));
    // learning per kind
    const K = {};
    for (const f of all) {
      const k = K[f.kind] = K[f.kind] || { kind: f.kind, open: 0, accepted: 0, dismissed: 0, resolved: 0, days: [], reasons: {} };
      K[f.kind][f.status] = (K[f.kind][f.status] || 0) + 1;
      if ((f.status === 'accepted' || f.status === 'dismissed') && f.created_at && decidedAt(f)) k.days.push((Date.parse(decidedAt(f)) - Date.parse(f.created_at)) / DAY);
      if (f.status === 'dismissed' && f.reason) { const r = String(f.reason).trim().toLowerCase().slice(0, 80); k.reasons[r] = (k.reasons[r] || 0) + 1; }
    }
    const kinds = Object.values(K).map((k) => { const dec = k.accepted + k.dismissed, rate = dec ? Math.round(100 * k.dismissed / dec) : null;
      const out = { kind: k.kind, open: k.open, accepted: k.accepted, dismissed: k.dismissed, resolved: k.resolved, decided: dec, dismissal_rate: rate, median_days_to_decide: k.days.length ? Math.round(median(k.days) * 10) / 10 : null,
        top_reasons: Object.entries(k.reasons).sort((a, b) => b[1] - a[1]).slice(0, 3).map(([reason, n]) => ({ reason, n })), fix: FIX[k.kind] ? { href: FIX[k.kind][0], label: FIX[k.kind][1] } : null, learned: dec >= 5 };
      if (dec >= 5 && rate >= 70) out.tuning = 'People dismissed ' + k.dismissed + ' of ' + dec + ' "' + k.kind + '" findings' + (out.top_reasons[0] ? ' (most often: "' + out.top_reasons[0].reason + '")' : '') + ' - the rule is noisy here; adjust its threshold in ITAM Settings or the data it reads.';
      return out; }).sort((a, b) => b.open - a.open);
    const KM = Object.fromEntries(kinds.map((k) => [k.kind, k]));
    // priority per open finding
    const open = all.filter((f) => f.status === 'open').map((f) => {
      const a = f.asset_id ? assets[f.asset_id] : null, why = [], add = (p, w) => { why.push({ points: p, why: w }); return p; };
      let p = add(SEV[f.severity] || 20, f.severity + ' severity');
      if (a) { if (a.classification === 'top_secret' || a.classification === 'secret') p += add(20, 'asset classified ' + a.classification.replace('_', ' '));
        else if (a.classification === 'restricted') p += add(8, 'asset classified restricted');
        if (a.cia && (a.cia.c === 'high' || a.cia.i === 'high' || a.cia.a === 'high')) p += add(12, 'high CIA value');
        if (['server', 'network', 'storage'].includes(a.type)) p += add(8, a.type + ' (others depend on it)'); }
      const age = f.created_at ? Math.floor((T - Date.parse(f.created_at)) / DAY) : 0;
      if (age >= 7) p += add(Math.min(15, Math.floor(age / 7)), 'open ' + age + ' days');
      if (f.reopened_at) p += add(10, 'came back after it was resolved');
      const k = KM[f.kind];
      if (k && k.learned && k.dismissal_rate >= 70) p += add(-15, 'people dismiss ' + k.dismissal_rate + ' % of this kind (' + k.decided + ' decisions)');
      else if (k && k.learned && k.dismissal_rate <= 10) p += add(8, 'people accept almost all of this kind (' + k.decided + ' decisions)');
      return Object.assign({}, f, { priority: Math.max(0, Math.min(100, p)), why, age_days: age, asset_name: a ? a.name || a.id : null, site: a ? a.site || null : null, owner: a ? a.owner || null : null, fix: FIX[f.kind] ? { href: FIX[f.kind][0], label: FIX[f.kind][1] } : null });
    }).sort((x, y) => y.priority - x.priority);
    // hotspots
    const top = (key) => { const m = {}; for (const f of open) { const v = f[key]; if (v) m[v] = (m[v] || 0) + 1; } return Object.entries(m).sort((a, b) => b[1] - a[1]).slice(0, 8).map(([value, n]) => ({ value, n })); };
    const byAsset = {}; for (const f of open) if (f.asset_id) { const r = byAsset[f.asset_id] = byAsset[f.asset_id] || { asset_id: f.asset_id, name: f.asset_name, n: 0, worst: 0 }; r.n++; r.worst = Math.max(r.worst, f.priority); }
    // trend: 12 weeks of opened vs closed
    const weeks = []; for (let i = 11; i >= 0; i--) { const end = T - i * 7 * DAY, start = end - 7 * DAY; weeks.push({ week_ending: new Date(end).toISOString().slice(0, 10),
      opened: all.filter((f) => f.created_at && Date.parse(f.created_at) > start && Date.parse(f.created_at) <= end).length,
      closed: all.filter((f) => decidedAt(f) && Date.parse(decidedAt(f)) > start && Date.parse(decidedAt(f)) <= end).length }); }
    return { at: new Date(T).toISOString(),
      kpis: { open: open.length, high: open.filter((f) => f.severity === 'high').length, recurring: open.filter((f) => f.reopened_at).length, aged: open.filter((f) => f.age_days > 30).length, top_priority: open.filter((f) => f.priority >= 70).length,
        accepted: all.filter((f) => f.status === 'accepted').length, dismissed: all.filter((f) => f.status === 'dismissed').length, resolved: all.filter((f) => f.status === 'resolved').length, noisy_kinds: kinds.filter((k) => k.tuning).length },
      open, kinds, hotspots: { assets: Object.values(byAsset).sort((a, b) => b.n - a.n || b.worst - a.worst).slice(0, 10), sites: top('site'), owners: top('owner') }, trend: weeks,
      note: 'Priority and learning come from the findings and the decisions people made on them here. Findings are advisory: nothing changes an asset; accept or dismiss is a person\'s decision.' };
  }
  return { view };
}

function registerFindingsIntel(srv, app, I) {
  srv.route('GET', '/ai/findings/intel', (ctx) => { ctx.need('viewer'); return I.view(); });
  srv.route('POST', '/ai/findings/bulk', (ctx) => {
    ctx.need('operator');
    if (!isHuman(ctx.who && ctx.who.user)) throw httpErr(403, 'a service or AI identity cannot decide findings: a person does');
    const b = body(ctx.body || {}).list('ids', { required: true, min: 1, max: 200, unique: true, item: 'str' }).oneOf('status', ['accepted', 'dismissed', 'open'], { required: true }).str('reason', { max: 300 }).done();
    if (b.status === 'dismissed' && !(b.reason && b.reason.trim())) throw httpErr(400, 'reason: say why these findings are dismissed - the learning reads it');
    const col = app.store.collection('findings'), missing = b.ids.filter((id) => !col.get(id));
    if (missing.length) throw httpErr(404, 'ids: no finding ' + missing.slice(0, 5).join(', '));
    const done = b.ids.map((id) => app.findings.setStatus(id, b.status, ctx.who, b.reason || null).id);
    app.audit({ by: ctx.who.user, role: ctx.who.role, ip: ctx.who.ip, action: 'ai.findings.bulk', target: 'findings', detail: { status: b.status, count: done.length, reason: b.reason || null } });
    return { ok: true, status: b.status, updated: done.length, ids: done };
  });
}

module.exports = { createFindingsIntel, registerFindingsIntel, FIX };
