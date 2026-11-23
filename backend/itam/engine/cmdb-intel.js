// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const { body } = require('./check');
const { guardOf } = require('./errors');
const { isHuman } = require('./approve-scopes');
/*
 * CMDB Studio insights ({P} = /api/itam, IT Assets -> CMDB Studio). Machine learning over the register and its relationships, next to
 * the Python rules in engine/cmdb-studio.js (quality, duplicates, proposals, blast radius) - every number explained:
 *   importance     PageRank over the dependency graph (A runs_on / depends_on / installed_on B passes importance to B; member_of to the
 *                  cluster; connected_to both ways at half weight). The "crown jewels" are what most of the estate stands on.
 *                  A CI with importance 50+ that others stand on, rated low / medium / unrated, is a MISMATCH to review.
 *   service groups label propagation on the confirmed relationships (deterministic order) - CIs that work together. A group of 3+
 *                  CIs that no registered business application (Application Route Map) touches is "unmapped service".
 *   coverage       per CI type and per site: share with at least one relationship, an owner, a criticality, a serial number.
 *   calibration    how often people confirmed each kind of proposal (learned from peers, LLDP / CDP neighbours, likely gateway,
 *                  AI analyst) - Laplace-smoothed - and the proposal's confidence blended with it (calibrated confidence).
 *   health         a snapshot per day (quality, relationship coverage, orphans, duplicates, single points of failure, proposals
 *                  waiting); trend per week by least squares, 30-day projection and the days until quality reaches the target -
 *                  withheld below 3 snapshots, never guessed.
 *   GET  /cmdb/studio/insights          viewer
 *   POST /cmdb/studio/snapshot          operator   take today's health snapshot now                         audited
 *   POST /cmdb/studio/accept-bulk       operator   {keys[1..50], note}  confirm several ML proposals, a person, each audited
 */
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const DAY = 86400000;
const NEEDS = new Set(['runs_on', 'depends_on', 'installed_on']);
const CLOSED = { retired: 1, disposed: 1 };
const CRIT = { critical: 4, high: 3, medium: 2, low: 1 };
const KEY = /^(runs_on|connected_to|depends_on|member_of|installed_on)\|[A-Za-z0-9_.:-]{1,80}\|[A-Za-z0-9_.:-]{1,80}$/;
const KINDS = { learned: 'Learned from peers', neighbours: 'LLDP / CDP neighbours', gateway: 'Likely gateway', ai: 'AI analyst' };
const low = (s) => String(s == null ? '' : s).toLowerCase();
// business criticality: the field when set, else the CIA availability rating (Asset Studio / Asset Data Autopilot)
const critOf = (a) => a.criticality || (a.cia && a.cia.a ? low(a.cia.a) : null);
const r2 = (x) => Math.round(x * 100) / 100;

function createCmdbIntel(app, opts = {}) {
  const now = opts.now || Date.now, store = app.store, L = app.log || { every() {} };
  const hist = () => store.collection('cmdb_health'), target = () => (((app.config || {}).cmdb_ai || {}).quality_target || 80);
  const audit = (who, action, target0, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role || '', ip: who.ip || '', action: 'cmdb.studio.' + action, target: target0, detail }); };
  const studio = () => { const S = (app.addons || {}).cmdbStudio; if (!S) throw httpErr(424, 'CMDB Studio is not loaded - the insights are built on it'); return S; };

  function load() {
    const assets = store.collection('assets').all((a) => !CLOSED[a.status]).slice(0, 30000), byId = new Map(assets.map((a) => [a.id, a]));
    const rels = store.collection('relationships').all((r) => r.status !== 'rejected' && byId.has(r.from) && byId.has(r.to)).slice(0, 100000);
    let apps = []; try { apps = ((store.collection('app_route').get('profile') || {}).apps) || []; } catch (e) { apps = []; /* no Application Route Map yet */ }
    return { assets, byId, rels, apps };
  }
  // ---------- importance (PageRank on the dependency direction)
  function importance(D) {
    const ids = D.assets.map((a) => a.id), N = ids.length; if (!N) return [];
    const out = new Map(ids.map((i) => [i, []]));   // edges along which importance flows: dependent -> what it needs
    const dependents = new Map(ids.map((i) => [i, 0]));
    for (const r of D.rels) {
      if (NEEDS.has(r.type)) { out.get(r.from).push([r.to, 1]); dependents.set(r.to, dependents.get(r.to) + 1); }
      else if (r.type === 'member_of') { out.get(r.from).push([r.to, 1]); }
      else if (r.type === 'connected_to') { out.get(r.from).push([r.to, 0.5]); out.get(r.to).push([r.from, 0.5]); }
    }
    const d = 0.85; let pr = new Map(ids.map((i) => [i, 1 / N]));
    for (let it = 0; it < 40; it++) {
      const nx = new Map(ids.map((i) => [i, (1 - d) / N])); let dangling = 0;
      for (const i of ids) { const e = out.get(i), w = e.reduce((s, x) => s + x[1], 0); if (!w) { dangling += pr.get(i); continue; } for (const [j, wt] of e) nx.set(j, nx.get(j) + d * pr.get(i) * wt / w); }
      for (const i of ids) nx.set(i, nx.get(i) + d * dangling / N);
      pr = nx;
    }
    const max = Math.max(...pr.values()), min = Math.min(...pr.values()), span = max - min || 1;
    const rows = ids.map((i) => { const a = D.byId.get(i); return { id: i, name: a.name, type: a.type || '', site: a.site || '', criticality: critOf(a) || null, dependents: dependents.get(i), score: Math.round(100 * (pr.get(i) - min) / span) }; })
      .sort((a, b) => b.score - a.score || b.dependents - a.dependents);
    // a mismatch: half or more of the top importance, at least one CI stands on it, rated below high (or not rated)
    for (const r of rows) r.mismatch = r.score >= 50 && r.dependents > 0 && (CRIT[low(r.criticality)] || 0) < 3
      ? (r.criticality ? 'rated ' + r.criticality : 'no criticality') + ' but ' + r.dependents + ' CI(s) stand on it (importance ' + r.score + ')' : null;
    return rows;
  }
  // ---------- service groups (label propagation on confirmed relationships)
  function groups(D) {
    const adj = new Map(D.assets.map((a) => [a.id, []]));
    for (const r of D.rels) if (r.status === 'confirmed') { adj.get(r.from).push(r.to); adj.get(r.to).push(r.from); }
    const ids = [...adj.keys()].filter((i) => adj.get(i).length).sort(), lab = new Map(ids.map((i) => [i, i]));
    for (let it = 0; it < 20; it++) {
      let changed = 0;
      for (const i of ids) {
        const c = new Map(); for (const j of adj.get(i)) c.set(lab.get(j), (c.get(lab.get(j)) || 0) + 1);
        let best = lab.get(i), bn = -1; for (const [l, n] of [...c].sort((a, b) => (a[0] < b[0] ? -1 : 1))) if (n > bn) { best = l; bn = n; }
        if (best !== lab.get(i)) { lab.set(i, best); changed++; }
      }
      if (!changed) break;
    }
    const by = new Map(); for (const i of ids) { const l = lab.get(i); if (!by.has(l)) by.set(l, []); by.get(l).push(i); }
    const appIx = new Map(); for (const ap of D.apps) for (const m of ap.machines || []) { const k = low(String(m).split('.')[0]); if (!appIx.has(k)) appIx.set(k, []); appIx.get(k).push(ap.name); }
    const mode = (arr) => { const c = new Map(); for (const x of arr.filter(Boolean)) c.set(x, (c.get(x) || 0) + 1); return [...c].sort((a, b) => b[1] - a[1])[0] || null; };
    return [...by.values()].filter((m) => m.length >= 2).map((m, n) => {
      const as = m.map((i) => D.byId.get(i)), apps = [...new Set(as.flatMap((a) => appIx.get(low(String(a.name || '').split('.')[0])) || []))];
      const tok = mode(as.map((a) => (String(a.name || '').match(/^[A-Za-z]{2,}/) || [''])[0].toUpperCase())), site = mode(as.map((a) => a.site)), types = {};
      for (const a of as) types[a.type || 'other'] = (types[a.type || 'other'] || 0) + 1;
      return { id: 'g' + (n + 1), size: m.length, name: (tok && tok[1] >= 2 ? tok[0] + ' group' : 'Group ' + (n + 1)) + (site ? ' · ' + site[0] : ''), site: site ? site[0] : null, types,
        members: as.slice(0, 40).map((a) => ({ id: a.id, name: a.name, type: a.type || '' })), apps, unmapped: !apps.length && m.length >= 3 };
    }).sort((a, b) => b.size - a.size).slice(0, 60);
  }
  // ---------- coverage by type and site
  function coverage(D) {
    const linked = new Set(); for (const r of D.rels) { linked.add(r.from); linked.add(r.to); }
    const F = { linked: (a) => linked.has(a.id), owner: (a) => !!a.owner, criticality: (a) => !!a.criticality, serial: (a) => !!a.serial };
    const roll = (key) => { const m = new Map(); for (const a of D.assets) { const k = key(a) || '(none)'; if (!m.has(k)) m.set(k, []); m.get(k).push(a); }
      return [...m].map(([k, as]) => Object.assign({ key: k, cis: as.length }, Object.fromEntries(Object.keys(F).map((f) => [f, Math.round(100 * as.filter(F[f]).length / as.length)])))).sort((a, b) => b.cis - a.cis); };
    const all = D.assets.length ? Object.fromEntries(Object.keys(F).map((f) => [f, Math.round(100 * D.assets.filter(F[f]).length / D.assets.length)])) : null;
    return { fields: Object.keys(F), overall: all, by_type: roll((a) => a.type), by_site: roll((a) => a.site) };
  }
  // ---------- calibration from people's decisions
  function calibration() {
    const acc = {}, rej = {}, add = (o, k) => { o[k] = (o[k] || 0) + 1; };
    for (const r of store.collection('relationships').all(() => true)) {
      const m = /^CMDB Studio \((learned|neighbours|gateway)\)/.exec(r.rationale || ''); if (m && r.status === 'confirmed') add(acc, m[1]);
      if (r.source === 'ai' && r.status === 'confirmed') add(acc, 'ai');
    }
    for (const d of store.collection('cmdb_decisions').all(() => true)) { if (d.kind && KINDS[d.kind]) add(rej, d.kind); else if (d.was && d.was.source === 'ai') add(rej, 'ai'); }
    return Object.keys(KINDS).map((k) => { const a = acc[k] || 0, x = rej[k] || 0; return { kind: k, label: KINDS[k], confirmed: a, rejected: x, rate: r2((a + 1) / (a + x + 2)), decisions: a + x }; });
  }
  const calibrate = (conf, cal) => { if (!cal || !cal.decisions) return conf; const w = Math.min(0.7, cal.decisions / (cal.decisions + 5)); return r2((1 - w) * conf + w * cal.rate); };
  // ---------- health history
  function measure(v) {
    const s = v.summary || {}, D = load(), linked = new Set(); for (const r of D.rels) { linked.add(r.from); linked.add(r.to); }
    return { quality_pct: s.quality_pct == null ? null : s.quality_pct, coverage_pct: D.assets.length ? Math.round(100 * D.assets.filter((a) => linked.has(a.id)).length / D.assets.length) : null,
      cis: s.cis || 0, orphans: s.orphans || 0, duplicates: s.duplicates || 0, spof: s.spof || 0, proposals: s.proposals || 0 };
  }
  async function snapshot(who) {
    const S = studio(), v = await S.view(who || { role: 'admin' }), m = measure(v), day = new Date(now()).toISOString().slice(0, 10);
    hist().put(Object.assign({ id: day, day, at: new Date(now()).toISOString() }, m));
    for (const x of hist().all().sort((a, b) => b.day.localeCompare(a.day)).slice(400)) hist().remove(x.id);
    return Object.assign({ day }, m);
  }
  function trend(rows, key) {
    const pts = rows.filter((r) => r[key] != null).map((r) => [Date.parse(r.day + 'T00:00:00Z') / DAY, r[key]]);
    if (pts.length < 3) return { enough: false, points: pts.length, note: 'needs 3 daily snapshots (' + pts.length + ' so far) - the trend is withheld, not guessed' };
    const n = pts.length, mx = pts.reduce((s, p) => s + p[0], 0) / n, my = pts.reduce((s, p) => s + p[1], 0) / n;
    const sxx = pts.reduce((s, p) => s + (p[0] - mx) ** 2, 0) || 1, slope = pts.reduce((s, p) => s + (p[0] - mx) * (p[1] - my), 0) / sxx;
    const last = pts[pts.length - 1], proj = Math.round(Math.max(0, Math.min(100, last[1] + slope * 30)) * 10) / 10;
    return { enough: true, points: n, per_week: r2(slope * 7), projected_30d: proj, latest: last[1] };
  }
  async function insights(who) {
    const S = studio(), v = await S.view(who), D = load(), imp = importance(D), cal = calibration(), calBy = Object.fromEntries(cal.map((c) => [c.kind, c]));
    const rows = hist().all().sort((a, b) => a.day.localeCompare(b.day)).slice(-120), q = trend(rows, 'quality_pct'), cv = trend(rows, 'coverage_pct'), tg = target();
    if (q.enough) q.days_to_target = q.latest >= tg ? 0 : q.per_week > 0 ? Math.ceil((tg - q.latest) / (q.per_week / 7)) : null;
    const proposals = (v.proposals || []).map((p) => ({ key: p.key, kind: p.kind, from_name: p.from_name, to_name: p.to_name, type: p.type, confidence: p.confidence, calibrated: calibrate(p.confidence, calBy[p.kind]) }))
      .sort((a, b) => b.calibrated - a.calibrated);
    return { at: new Date(now()).toISOString(), importance: imp.slice(0, 60), mismatches: imp.filter((r) => r.mismatch).slice(0, 40), groups: groups(D), coverage: coverage(D),
      calibration: cal, proposals, health: { target: tg, history: rows, quality: q, coverage: cv, today: measure(v) } };
  }
  async function acceptBulk(input, who) {
    const b = body(input).list('keys', { required: true, max: 50, unique: true }).str('note', { required: true, min: 5, max: 300 })
      .rule((o) => { const bad = (o.keys || []).findIndex((k) => typeof k !== 'string' || !KEY.test(k)); return bad >= 0 ? 'keys[' + bad + '] is not a relationship proposal key' : null; }).done();
    if (!isHuman(who.user)) throw httpErr(403, 'a service or AI identity cannot confirm relationships: a person does');
    const S = studio(), done = [], skipped = [];
    for (const k of b.keys) {
      try { const r = await S.accept({ key: k }, who); done.push({ key: k, relationship: r.relationship && r.relationship.id }); }
      catch (e) { if (e.status && e.status < 500) skipped.push({ key: k, why: e.message }); else throw e; }
    }
    audit(who, 'accept-bulk', done.length + ' relationship(s)', { note: b.note, confirmed: done.map((x) => x.key), skipped: skipped.map((x) => x.key) });
    return { confirmed: done, skipped };
  }
  if (!(app.noTimers || opts.noTimer)) {
    const tick = guardOf(app, 'cmdb.health.snapshot', async () => { const day = new Date(now()).toISOString().slice(0, 10); if (!hist().get(day)) await snapshot({ user: 'system:cmdb-health', role: 'admin' }); });
    const t1 = setTimeout(tick, 90000), t2 = setInterval(tick, 3 * 3600000); if (t1.unref) t1.unref(); if (t2.unref) t2.unref();
  }
  return { insights, snapshot, acceptBulk, _importance: importance, _groups: groups, _load: load };
}

function registerCmdbIntel(srv, app, I0) {
  const I = I0 || createCmdbIntel(app);
  app.addons = app.addons || {}; app.addons.cmdbIntel = I;
  srv.route('GET', '/cmdb/studio/insights', (ctx) => { ctx.need('viewer'); return I.insights(ctx.who); });
  srv.route('POST', '/cmdb/studio/snapshot', async (ctx) => { ctx.need('operator'); const r = await I.snapshot(ctx.who);
    if (app.audit) app.audit({ by: ctx.who.user, role: ctx.who.role, ip: ctx.who.ip || '', action: 'cmdb.studio.snapshot', target: r.day, detail: r }); return r; });
  srv.route('POST', '/cmdb/studio/accept-bulk', (ctx) => { ctx.need('operator'); return I.acceptBulk(ctx.body, ctx.who); }, { maxBody: 16384 });
  return I;
}
module.exports = { createCmdbIntel, registerCmdbIntel };
