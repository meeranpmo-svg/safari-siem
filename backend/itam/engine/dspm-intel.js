// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('./brand');
const { body, param } = require('./check');
const { isHuman } = require('./approve-scopes');
const { createIntelKit, robustZ, trend } = require('./intel-kit');
/*
 * DSPM intelligence ({P} = /api/itam, page data-posture.html) - statistics over what Data Security Posture (engine/data-posture.js)
 * already reads, plus a read-only AI advisor. Nothing here changes a store, a file, a permission or a record. Every figure is an
 * INDICATOR for a person to confirm (PDPL), never proof, and every point of every score is itemised with its reason.
 *
 *   stores     each data store (SharePoint / Teams site, OneDrive, file-share root, database, cloud bucket / container) scored 0-100:
 *              sensitivity (the most sensitive class it holds, weight 0-10 x 3, at most 30) + volume (5 x log10(1 + items holding
 *              personal data), at most 15) + exposure (anonymous link 10, outside sharing 6, everyone / organisation 4 each, public store
 *              25; at most 25) + credentials (4 + 2 per item, at most 10) + location (outside the Kingdom 10, unknown 3) + governance
 *              (no processing activity names it 10, a category not declared 4). Tier: critical >= 70, high >= 50, medium >= 30, else
 *              low. A store whose last scan is older than 30 days is flagged "scan stale" - the score is only as fresh as the scan.
 *   toxic      combinations that are worse than their parts, each from named facts of one store: credentials + reachable outside;
 *              strong personal data (ID / Iqama / passport / IBAN / card / health / salary) + outside the Kingdom; health or financial
 *              data + public / anonymous / everyone; personal data no activity names + reachable outside.
 *   anomalies  each risk's count today against its daily history (data_posture_hist): robust z (median / MAD, 7+ days); |z| >= 3.5
 *              and a change of 2+ is flagged; with less history it says so instead of guessing.
 *   forecast   the score's straight-line trend over the daily snapshots (3+), projected to Good (8) - a projection, not a promise.
 *   fixes      what fixing each measure gives back: points regained if every item of it were fixed (the risk's cap applied), and
 *              per item; ranked by points regained. Shows where an hour of remediation moves the score most.
 *   ask        the AI advisor (operator+, a person): one read-only tool, dspm_insights, store labels and counts only - never a file
 *              name, a path, a person (a OneDrive is named after its owner: withheld) or a value. Through engine/ai-guard.js (budget before / record after, redactSecrets, untrusted()
 *              tool output, UNTRUSTED_RULE). It proposes; a person decides and changes the system.
 *   changes    each store's score is kept once a day (dspm_store_hist, 120 days): stores that are NEW and high / critical since the
 *              previous day, and stores whose score ROSE by 15+ or moved up a tier, each with the factor that changed.
 *   peers      a store against the others of its type (5+ of them): robust z of log(items holding personal data); a store with
 *              |z| >= 3.5 and 3x the typical count is "unusual for its type" - often a forgotten export or a copied database.
 *   trends     every risk's count over the daily snapshots: slope per week and direction (3+ snapshots).
 *   plans      a remediation plan DRAFTED from the ranking (no model): for each critical / high / toxic store, the actions its own
 *              facts call for, from a fixed list (ACTIONS). A different person approves it (four-eyes, never a service / AI
 *              identity); nothing is executed by the platform - the owners do the work. An item is VERIFIED only when a later read
 *              shows the fact gone (the anonymous links are no longer there, the store is no longer public, ...); "claimed" records
 *              what a person says, "accepted risk" needs a reason. Overdue = past the plan's due date and not verified.
 *   graph      the data access graph: data class -> store -> who can reach it (anyone with the link, people outside, everyone /
 *              the whole organisation, a public cloud store, outside the Kingdom). A RISKY PATH is a sensitive class (identity,
 *              financial, health, credentials) reaching outside people, a public store or another country.
 *   labels     a suggested sensitivity label for every store and file from the classes found - Restricted (health, biometric,
 *              credentials, national ID / Iqama / passport), Confidential (IBAN, card, salary, credit), Internal (contact, CV, date
 *              of birth, name, address) - and a MISMATCH when a Restricted or Confidential store is reachable outside. Suggestions
 *              for the people who label in Microsoft Purview: this platform applies no label (read-only).
 *   rot        redundant / obsolete data: the same file name holding personal data in two or more places (copies), files with
 *              personal data unchanged for 3 years, stores whose newest file is over 2 years old. Indicators to review with the owner
 *              against the retention schedule, never deleted from here.
 * Roles: GET /data-posture/insights viewer (counts and tiers only, no store names); operator / admin also the named stores (audited
 *   'data.posture.insights.read'). POST /data-posture/ask operator, a person (audited 'data-posture.ai.ask').
 */
const STRONG = ['national_id', 'iqama', 'passport', 'iban', 'card', 'health', 'salary'];
const SENSITIVE_CATS = ['health', 'financial'];
const WEIGHT = { health: 10, biometric: 10, private_key: 9, api_key: 9, password: 9, secret_file: 8, national_id: 8, iqama: 8, passport: 8, card: 8, iban: 7, salary: 7, credit: 7, cv: 5, birth_date: 5, mobile: 4, address: 4, email: 3, name: 2 };
const CRED = ['private_key', 'api_key', 'password', 'secret_file'];
const RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 };
const DAY = 86400000, STALE_DAYS = 30, TOP = 30;
const ACTIONS = {
  remove_public_access: ['Remove public access', (f) => f.public !== true],
  remove_anonymous_links: ['Remove the anonymous links', (f) => !f.anon],
  restrict_external_sharing: ['Stop sharing with outside people', (f) => !f.external],
  restrict_open_access: ['Restrict access opened to everyone / the whole organisation', (f) => !f.wide],
  rotate_and_remove_secrets: ['Rotate the secrets and remove them from the store', (f) => !f.cred_items],
  move_or_record_transfer: ['Move the data into the Kingdom or record the transfer basis and impact assessment', (f) => f.in_kingdom !== false],
  record_processing_activity: ['Record the processing activity that uses this store (ROPA)', (f) => !f.undeclared && !(f.undeclared_cats || []).length],
};
const PLAN_ID = /^DSPM-PLAN-\d{4}$/, ITEM_STATUS = ['claimed', 'accepted_risk', 'open'];
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const r1 = (x) => Math.round(x * 10) / 10, r2 = (x) => Math.round(x * 100) / 100;
const tierOf = (v) => (v >= 70 ? 'critical' : v >= 50 ? 'high' : v >= 30 ? 'medium' : 'low');
const OUTSIDE = (sh) => sh === 'anonymous' || sh === 'external';

function createDspmIntel(app, P, opts = {}) {
  if (!P || typeof P.build !== 'function') throw new Error('DSPM intelligence needs Data Security Posture (engine/data-posture.js)');
  const now = opts.now || Date.now;
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role, ip: who.ip || '', action, target, detail }); };
  const named = (who) => (RANK[String(who && who.role || '').toLowerCase()] || 0) >= RANK.operator;

  /* ---- one row per store, with the facts every factor reads */
  function storeFacts(C, R) {
    const out = new Map(), t = now();
    const get = (id, o) => out.get(id) || out.set(id, Object.assign({ id, kinds: {}, personal_items: 0, cred_items: 0, anon: 0, external: 0, wide: 0, public: null, in_kingdom: undefined, undeclared: false, undeclared_cats: [], last_scan: null }, o)).get(id);
    for (const st of C.stores) {
      const x = get(st.id, { label: st.label, type: st.type, last_scan: st.last_scan || null });
      for (const k of Object.keys(st.kinds || {})) x.kinds[k] = (x.kinds[k] || 0) + st.kinds[k];
    }
    for (const r of C.rows) {
      const x = out.get(r.store.id); if (!x) continue;
      if (r.personal) x.personal_items++; if (r.cred) x.cred_items++;
      if (r.personal || r.cred) { if (r.shared === 'anonymous') x.anon++; else if (r.shared === 'external') x.external++; else if (r.shared === 'organization' || r.shared === 'everyone') x.wide++; }
    }
    for (const d of C.dbs.filter((z) => z.discovered)) {
      const x = get(d.id, { label: d.label, type: d.type, last_scan: d.last_scan || null }); Object.assign(x.kinds, d.kinds); x.personal_items = d.personal ? d.columns : 0;
      x.cred_items = CRED.reduce((a, k) => a + (Number(d.kinds[k]) || 0), 0);
    }
    for (const c of C.cloudStores) {
      const x = get(c.id, { label: c.label, type: c.type, last_scan: c.last_scan || null, region: c.region || '' });
      for (const k of Object.keys(c.kinds || {})) if (Number(c.kinds[k])) x.kinds[k] = Number(c.kinds[k]);
      x.personal_items = c.personal ? c.with_findings : 0; x.cred_items = c.credentials || 0; x.public = c.public; x.in_kingdom = c.in_kingdom;
    }
    // governance: the shadow-data risk already matched each store against the records of processing
    const byLabel = new Map(); for (const x of out.values()) { const k = String(x.label).toLowerCase(); if (!byLabel.has(k)) byLabel.set(k, x); }
    for (const it of (R.shadow && R.shadow.items) || []) {
      const x = byLabel.get(String(it.store || '').toLowerCase()); if (!x) continue;
      if (it.measure === 'undeclared_store') x.undeclared = true; else if (it.measure === 'undeclared_category') x.undeclared_cats = (it.classes || []).slice(0, 6);
    }
    for (const x of out.values()) x.stale = x.last_scan ? (t - Date.parse(x.last_scan)) / DAY > STALE_DAYS : null;
    return [...out.values()].filter((x) => x.personal_items > 0 || x.cred_items > 0);
  }
  function scoreStore(x, L) {
    const why = [], add = (factor, pts, reason) => { if (pts) why.push({ factor, points: r1(pts), reason }); };
    const ks = Object.keys(x.kinds).filter((k) => Number(x.kinds[k])), top = ks.sort((a, b) => (WEIGHT[b] || 1) - (WEIGHT[a] || 1))[0];
    if (top) add('sensitivity', Math.min(30, (WEIGHT[top] || 1) * 3), 'holds ' + (L[top] || top) + (ks.length > 1 ? ' and ' + (ks.length - 1) + ' other class(es)' : ''));
    if (x.personal_items) add('volume', Math.min(15, 5 * Math.log10(1 + x.personal_items)), x.personal_items + ' item(s) holding personal data');
    const ex = Math.min(25, (x.public === true ? 25 : 0) + x.anon * 10 + x.external * 6 + x.wide * 4);
    if (ex) add('exposure', ex, [x.public === true ? 'public store' : '', x.anon ? x.anon + ' anonymous link(s)' : '', x.external ? x.external + ' shared outside' : '', x.wide ? x.wide + ' open to everyone / the organisation' : ''].filter(Boolean).join(', '));
    if (x.cred_items) add('credentials', Math.min(10, 4 + 2 * x.cred_items), x.cred_items + ' item(s) holding a secret');
    if (x.in_kingdom === false) add('location', 10, 'outside the Kingdom' + (x.region ? ' (' + x.region + ')' : ''));
    else if (x.in_kingdom === null) add('location', 3, 'location could not be read - unknown, not safe');
    if (x.undeclared) add('governance', 10, 'no processing activity names this store');
    else if (x.undeclared_cats.length) add('governance', 4, 'categories not declared: ' + x.undeclared_cats.join(', '));
    const score = Math.min(100, Math.round(why.reduce((a, w) => a + w.points, 0)));
    return { score, tier: tierOf(score), why };
  }
  function toxicOf(x, L) {
    const out = [], ks = Object.keys(x.kinds).filter((k) => Number(x.kinds[k])), reach = x.public === true || x.anon > 0 || x.external > 0;
    if (x.cred_items && reach) out.push({ kind: 'credentials_exposed', title: 'Secrets reachable from outside', why: x.cred_items + ' item(s) with a secret in a store reachable outside the organisation - treat the secret as leaked: rotate it' });
    const strong = ks.filter((k) => STRONG.includes(k));
    if (strong.length && x.in_kingdom === false) out.push({ kind: 'strong_abroad', title: 'Identity / financial / health data abroad', why: strong.map((k) => L[k] || k).join(', ') + ' in a store outside the Kingdom - PDPL transfer basis and impact assessment needed' });
    const sens = ks.filter((k) => SENSITIVE_CATS.includes(P.CATEGORY[k]));
    if (sens.length && (reach || x.wide)) out.push({ kind: 'sensitive_open', title: 'Health or financial data open', why: sens.map((k) => L[k] || k).join(', ') + ' in a store that is ' + (x.public === true ? 'public' : x.anon ? 'behind anonymous links' : x.external ? 'shared outside' : 'open to everyone') });
    if (x.undeclared && reach) out.push({ kind: 'shadow_exposed', title: 'Shadow data shared outside', why: 'personal data no processing activity names, reachable outside the organisation' });
    return out;
  }

  /* ---- history: anomalies and the score forecast */
  function history() { return app.store.collection('data_posture_hist').all().sort((a, b) => String(a.id).localeCompare(String(b.id))); }
  function anomalies(R) {
    const H = history(), today = new Date(now() + 3 * 3600000).toISOString().slice(0, 10), past = H.filter((h) => h.id < today);
    const out = [];
    for (const k of Object.keys(R)) {
      const X = R[k]; if (!X.measured || X.count == null) continue;
      const vals = past.map((h) => h.counts && h.counts[k]).filter((v) => Number.isFinite(v)).slice(-60);
      const z = robustZ(vals, X.count);
      if (!z) { out.push({ risk: k, title: X.title, count: X.count, judged: false, why: 'needs 7 daily snapshots (' + vals.length + ' so far)' }); continue; }
      const delta = X.count - z.usual, flag = !!((Math.abs(z.z) >= 3.5 || z.never_moved) && Math.abs(delta) >= 2);
      out.push({ risk: k, title: X.title, count: X.count, usual: z.usual, z: Number.isFinite(z.z) ? z.z : null, judged: true, flagged: flag, direction: delta > 0 ? 'up' : delta < 0 ? 'down' : 'flat',
        why: flag ? X.title + ': ' + X.count + ' against a usual ' + z.usual + (z.never_moved ? ' (it never moved before)' : ' (robust z ' + z.z + ')') : 'within its usual range' });
    }
    return out;
  }
  function forecast(S) {
    const pts = history().filter((h) => h.score != null).map((h) => ({ t: Date.parse(h.id + 'T00:00:00Z') / DAY, y: h.score }));
    const tr = trend(pts, { target: 8, current: S.value, now: now(), higherIsBetter: true });
    return Object.assign({ current: S.value, label: S.label, points: pts.slice(-60).map((p) => ({ day: new Date(p.t * DAY).toISOString().slice(0, 10), score: p.y })) }, tr);
  }
  function fixes(R) {
    const out = [];
    for (const k of Object.keys(R)) {
      const X = R[k]; if (!X.measured) continue;
      for (const b of X.breakdown || []) {
        if (!b.count) continue;
        const without = r2(Math.min(X.cap, Math.max(0, (X.raw != null ? X.raw : X.deduction) - b.points))), gain = r2(X.deduction - without);
        out.push({ risk: k, title: X.title, measure: b.measure, text: b.text, count: b.count, gain, per_item: r2(gain / b.count),
          why: gain > 0 ? 'fixing all ' + b.count + ' gives back ' + gain + ' point(s)' : 'the risk is over its cap of ' + X.cap + ': fixing these alone does not move the score yet' });
      }
    }
    return out.sort((a, b) => b.gain - a.gain || b.per_item - a.per_item);
  }

  /* ---- per-store daily history: new and risen stores */
  const shist = () => app.store.collection('dspm_store_hist'), dayOf = (t) => new Date(t + 3 * 3600000).toISOString().slice(0, 10);
  const TIER_N = { low: 0, medium: 1, high: 2, critical: 3 };
  function storeChanges(scored) {
    const day = dayOf(now());
    if (!shist().get(day)) {
      const stores = {}; for (const x of scored.slice(0, 300)) stores[x.id] = { score: x.score, tier: x.tier, label: x.label, type: x.type, factors: Object.fromEntries(x.why.map((w) => [w.factor, w.points])) };
      shist().put({ id: day, at: new Date(now()).toISOString(), stores });
      const all = shist().all().sort((a, b) => String(a.id).localeCompare(String(b.id))); for (const x of all.slice(0, Math.max(0, all.length - 120))) shist().remove(x.id);
    }
    const prev = shist().all((h) => h.id < day).sort((a, b) => String(b.id).localeCompare(String(a.id)))[0];
    if (!prev) return { since: null, new: [], risen: [], fell: 0, why: 'the first daily snapshot of the stores is today: changes show from tomorrow' };
    const added = [], risen = []; let fell = 0;
    for (const x of scored) {
      const p0 = prev.stores[x.id];
      if (!p0) { if (TIER_N[x.tier] >= 2) added.push({ id: x.id, label: x.label, type: x.type, score: x.score, tier: x.tier, why: 'not in the ' + prev.id + ' snapshot' }); continue; }
      const d = x.score - p0.score;
      if (d >= 15 || TIER_N[x.tier] > TIER_N[p0.tier]) {
        const ch = x.why.filter((w) => (p0.factors || {})[w.factor] !== w.points).map((w) => w.factor + ' ' + ((p0.factors || {})[w.factor] || 0) + ' → ' + w.points);
        risen.push({ id: x.id, label: x.label, type: x.type, score: x.score, previous: p0.score, tier: x.tier, previous_tier: p0.tier, why: ch.join(', ') || 'score ' + p0.score + ' → ' + x.score });
      } else if (d <= -15) fell++;
    }
    return { since: prev.id, new: added.slice(0, 20), risen: risen.sort((a, b) => (b.score - b.previous) - (a.score - a.previous)).slice(0, 20), fell };
  }
  /* ---- peers: a store against the others of its type */
  function peers(scored) {
    const by = new Map(); for (const x of scored) (by.get(x.type) || by.set(x.type, []).get(x.type)).push(x);
    const out = [], judged = [];
    for (const [type, L0] of by) {
      if (L0.length < 7) continue; judged.push(type);
      const vals = L0.map((x) => Math.log10(1 + x.personal_items)), sorted = L0.map((x) => x.personal_items).sort((a, b) => a - b), typical = sorted[Math.floor(sorted.length / 2)];
      for (const x of L0) { const z = robustZ(vals.filter((_, i) => L0[i] !== x), Math.log10(1 + x.personal_items));
        if (z && (z.z >= 3.5 || (z.never_moved && x.personal_items > typical)) && x.personal_items >= 3 * Math.max(1, typical)) out.push({ id: x.id, label: x.label, type, personal_items: x.personal_items, typical, z: Number.isFinite(z.z) ? z.z : null, why: x.personal_items + ' items holding personal data where a typical ' + type + ' store has ' + typical + ' - often a forgotten export or a copied database' }); }
    }
    return { judged_types: judged, items: out.sort((a, b) => b.personal_items / Math.max(1, b.typical) - a.personal_items / Math.max(1, a.typical)).slice(0, 15), why: judged.length ? null : 'peers are compared once a store type has 7 or more stores' };
  }
  /* ---- every risk's trend over the daily snapshots */
  function riskTrends(R) {
    const H = history();
    return Object.keys(R).map((k) => { const pts = H.filter((h) => h.counts && Number.isFinite(h.counts[k])).map((h) => ({ t: Date.parse(h.id + 'T00:00:00Z') / DAY, y: h.counts[k] }));
      const tr = trend(pts); return { risk: k, title: R[k].title, count: R[k].count, measured: R[k].measured, points: pts.slice(-30).map((p) => p.y), slope_per_week: tr.slope_per_week == null ? null : tr.slope_per_week, direction: tr.direction || null, why: tr.why }; });
  }
  /* ---- remediation plans: drafted from the ranking, approved by a second person, verified by the data */
  const plans = () => app.store.collection('dspm_plans');
  const person = (who, what) => { if (!isHuman(who && who.user)) throw httpErr(403, 'a service or AI identity cannot ' + what + ': a person does'); };
  function actionsFor(f, x) {
    const a = [];
    if (f.public === true) a.push('remove_public_access');
    if (f.anon) a.push('remove_anonymous_links');
    if (f.external) a.push('restrict_external_sharing');
    if (f.wide && x.toxic.some((t) => t.kind === 'sensitive_open')) a.push('restrict_open_access');
    if (f.cred_items) a.push('rotate_and_remove_secrets');
    if (f.in_kingdom === false) a.push('move_or_record_transfer');
    if (f.undeclared || (f.undeclared_cats || []).length) a.push('record_processing_activity');
    return a;
  }
  function verifyPlans(facts) {
    const t = new Date(now()).toISOString();
    for (const pl of plans().all((x) => x.status === 'approved')) {
      let changed = false;
      for (const it of pl.items) {
        if (it.status === 'verified' || it.status === 'accepted_risk') continue;
        const f = facts.get(it.store_id), fixed = !f ? 'the store no longer holds personal data or secrets' : ACTIONS[it.action][1](f) ? 'the latest read no longer shows it' : null;
        if (fixed) { it.status = 'verified'; it.verified_at = t; it.history = (it.history || []).concat([{ at: t, by: 'system:dspm-verify', status: 'verified', note: fixed }]); changed = true;
          if (app.audit) app.audit({ by: 'system:dspm-verify', role: 'system', ip: '', action: 'data.posture.plan.verified', target: pl.id + '#' + it.n, detail: { action: it.action, why: fixed } }); }
      }
      if (changed) { if (pl.items.every((i) => i.status === 'verified' || i.status === 'accepted_risk')) { pl.status = 'completed'; pl.completed_at = t; } plans().put(pl); }
    }
  }
  function planView(pl) {
    const t = now(), open = pl.items.filter((i) => i.status !== 'verified' && i.status !== 'accepted_risk');
    return Object.assign({}, pl, { progress: { total: pl.items.length, verified: pl.items.filter((i) => i.status === 'verified').length, accepted_risk: pl.items.filter((i) => i.status === 'accepted_risk').length, open: open.length,
      overdue: pl.status === 'approved' && pl.due_at && Date.parse(pl.due_at) < t ? open.length : 0 } });
  }
  async function listPlans(who) {
    await insights(who);   // verification runs on the latest read
    return { items: plans().all().sort((a, b) => String(b.id).localeCompare(String(a.id))).slice(0, 20).map(planView), actions: Object.fromEntries(Object.entries(ACTIONS).map(([k, v]) => [k, v[0]])) };
  }
  async function draftPlan(input, who) {
    const b = body(input || {}).int('due_days', { min: 7, max: 180 }).str('note', { max: 1000 }).done();
    person(who, 'draft a remediation plan');
    if (plans().all((x) => x.status === 'proposed').length) throw httpErr(409, 'a plan is already waiting for approval - approve or reject it first');
    const { scored, facts } = await compute(who), items = [];
    for (const x of scored) {
      if (!(TIER_N[x.tier] >= 2 || x.toxic.length)) continue;
      for (const a of actionsFor(facts.get(x.id), x)) items.push({ n: items.length + 1, store_id: x.id, store: x.label, type: x.type, score: x.score, action: a, label: ACTIONS[a][0], status: 'open', history: [] });
      if (items.length >= 40) break;
    }
    if (!items.length) throw httpErr(409, 'no critical, high or toxic store needs an action - nothing to plan');
    const n = plans().all().length + 1, id = 'DSPM-PLAN-' + String(n).padStart(4, '0'), at = new Date(now()).toISOString();
    const pl = { id, status: 'proposed', by: who.user, at, due_days: b.due_days || 30, note: b.note || '', items: items.slice(0, 40), basis: 'drafted from the store risk ranking (critical / high / toxic stores; actions from each store\'s own facts)' };
    plans().put(pl); audit(who, 'data.posture.plan.draft', id, { items: pl.items.length, due_days: pl.due_days });
    return planView(pl);
  }
  function getPlan(id) { const pl = plans().get(param(id, 'id')); if (!pl || !PLAN_ID.test(pl.id)) throw httpErr(404, 'no such plan'); return pl; }
  function decidePlan(id, input, who) {
    const b = body(input || {}).oneOf('decision', ['approve', 'reject'], { required: true }).str('note', { max: 1000 }).rule((o) => (o.decision === 'reject' && !o.note ? 'note is required: say why the plan is rejected' : null)).done();
    person(who, 'decide a remediation plan');
    const pl = getPlan(id);
    if (pl.status !== 'proposed') throw httpErr(409, 'the plan is ' + pl.status + ', not waiting for a decision');
    if (pl.by === who.user) throw httpErr(403, 'four-eyes: the person who drafted the plan cannot approve or reject it');
    const at = new Date(now()).toISOString();
    Object.assign(pl, { status: b.decision === 'approve' ? 'approved' : 'rejected', decided_by: who.user, decided_at: at, decision_note: b.note || '' });
    if (pl.status === 'approved') pl.due_at = new Date(now() + pl.due_days * DAY).toISOString();
    plans().put(pl); audit(who, 'data.posture.plan.' + (pl.status === 'approved' ? 'approve' : 'reject'), pl.id, { drafted_by: pl.by, note: b.note || '' });
    return planView(pl);
  }
  function setItem(id, n, input, who) {
    const b = body(input || {}).oneOf('status', ITEM_STATUS, { required: true }).str('note', { max: 1000 }).rule((o) => (o.status === 'accepted_risk' && !o.note ? 'note is required: say why the risk is accepted' : null)).done();
    person(who, 'update a plan item');
    const pl = getPlan(id), k = Number(n);
    if (pl.status !== 'approved') throw httpErr(409, 'items are worked once the plan is approved (it is ' + pl.status + ')');
    const it = pl.items.find((x) => x.n === k); if (!it) throw httpErr(404, 'no item ' + n + ' in ' + pl.id);
    if (it.status === 'verified') throw httpErr(409, 'item ' + k + ' is already verified by the data');
    const at = new Date(now()).toISOString(); it.status = b.status; it.history = (it.history || []).concat([{ at, by: who.user, status: b.status, note: b.note || '' }]);
    if (pl.items.every((i) => i.status === 'verified' || i.status === 'accepted_risk')) { pl.status = 'completed'; pl.completed_at = at; }
    plans().put(pl); audit(who, 'data.posture.plan.item', pl.id + '#' + k, { status: b.status, note: b.note || '' });
    return planView(pl);
  }


  /* ---- access graph, label suggestions, redundant / obsolete data */
  const SENS_CAT = ['identity', 'financial', 'health', 'credentials'];
  const LEVEL = (k) => (['health', 'biometric', 'private_key', 'api_key', 'password', 'secret_file', 'national_id', 'iqama', 'passport'].includes(k) ? 3 : ['iban', 'card', 'salary', 'credit'].includes(k) ? 2 : ['mobile', 'email', 'cv', 'birth_date', 'name', 'address'].includes(k) ? 1 : 0);
  const LEVEL_NAME = ['General', 'Internal', 'Confidential', 'Restricted'];
  const ACCESS = { anonymous: 'Anyone with the link', external: 'People outside', wide: 'Everyone / the whole organisation', public: 'Public cloud store', abroad: 'Outside the Kingdom' };
  function graph(C, scored, facts) {
    const top = scored.slice(0, 12), edgesCS = [], edgesSA = [], risky = [];
    for (const x of top) {
      const f = facts.get(x.id), cats = {};
      for (const k of Object.keys(f.kinds)) { const c = P.CATEGORY[k] || 'other'; if (c !== 'other') cats[c] = (cats[c] || 0) + Number(f.kinds[k]); }
      for (const c of Object.keys(cats)) edgesCS.push({ from: c, to: x.id, n: cats[c] });
      const acc = {}; if (f.anon) acc.anonymous = f.anon; if (f.external) acc.external = f.external; if (f.wide) acc.wide = f.wide; if (f.public === true) acc.public = f.personal_items || 1; if (f.in_kingdom === false) acc.abroad = f.personal_items || 1;
      for (const a of Object.keys(acc)) edgesSA.push({ from: x.id, to: a, n: acc[a] });
      for (const c of Object.keys(cats).filter((z) => SENS_CAT.includes(z))) for (const a of Object.keys(acc).filter((z) => z !== 'wide')) risky.push({ class: c, store: x.label, store_id: x.id, access: a, items: Math.min(cats[c], acc[a]), why: c + ' data in ' + x.label + ' reachable by: ' + ACCESS[a] });
    }
    const classes = [...new Set(edgesCS.map((e) => e.from))].sort((a, b) => SENS_CAT.indexOf(b) - SENS_CAT.indexOf(a));
    return { classes, stores: top.map((x) => ({ id: x.id, label: x.type === 'onedrive' ? x.label : x.label, type: x.type, score: x.score, tier: x.tier })), access: Object.keys(ACCESS).filter((a) => edgesSA.some((e) => e.to === a)).map((a) => ({ id: a, label: ACCESS[a] })),
      edges: edgesCS.concat(edgesSA), risky: risky.slice(0, 30), risky_total: risky.length };
  }
  function labels(C, scored, facts) {
    const byStore = new Map(); for (const r of C.rows) { const a = byStore.get(r.store.id) || byStore.set(r.store.id, [0, 0, 0, 0]).get(r.store.id); a[Math.max(0, ...r.kinds.map(LEVEL))]++; }
    const items = scored.map((x) => { const f = facts.get(x.id), lv = Math.max(0, ...Object.keys(f.kinds).filter((k) => Number(f.kinds[k])).map(LEVEL)), files = byStore.get(x.id) || null;
      const outside = f.anon || f.external || f.public === true, mismatch = lv >= 2 && outside;
      return { id: x.id, store: x.label, type: x.type, suggested: LEVEL_NAME[lv], level: lv, files: files ? { restricted: files[3], confidential: files[2], internal: files[1], general: files[0] } : null, mismatch,
        why: 'holds ' + Object.keys(f.kinds).filter((k) => LEVEL(k) === lv && Number(f.kinds[k])).map((k) => P.KIND_LABEL[k] || k).join(', ') + (mismatch ? ' - and it is reachable outside the organisation' : '') }; })
      .sort((a, b) => b.level - a.level || Number(b.mismatch) - Number(a.mismatch));
    const totals = { restricted: 0, confidential: 0, internal: 0, general: 0 }; for (const it of items) totals[it.suggested.toLowerCase()]++;
    return { totals, mismatches: items.filter((x) => x.mismatch).length, items: items.slice(0, 60), scheme: 'Restricted: health, biometric, credentials, national ID / Iqama / passport · Confidential: IBAN, card, salary, credit · Internal: contact, CV, date of birth, name, address' };
  }
  function rot(C) {
    const t = now(), personal = C.rows.filter((r) => r.personal || r.cred);
    const byName = new Map(); for (const r of personal) { const k = String(r.name || '').trim().toLowerCase(); if (k.length < 4) continue; (byName.get(k) || byName.set(k, []).get(k)).push(r); }
    const copies = [...byName.entries()].map(([, L0]) => { const places = new Set(L0.map((r) => r.store.id + '|' + String(r.path || '').toLowerCase())); return { name: L0[0].name, copies: places.size, stores: [...new Set(L0.map((r) => r.store.label))].slice(0, 6), kinds: [...new Set(L0.flatMap((r) => r.kinds))].map((k) => P.KIND_LABEL[k] || k).slice(0, 5) }; })
      .filter((x) => x.copies >= 2).sort((a, b) => b.copies - a.copies);
    const old = personal.filter((r) => r.modified && t - Date.parse(r.modified) > 3 * 365 * DAY);
    const oldBy = new Map(); for (const r of old) oldBy.set(r.store.label, (oldBy.get(r.store.label) || 0) + 1);
    const newest = new Map(); for (const r of C.rows) { if (!r.modified) continue; const m = Date.parse(r.modified); if (!newest.has(r.store.label) || m > newest.get(r.store.label)) newest.set(r.store.label, m); }
    const stale = [...newest.entries()].filter(([, m]) => t - m > 2 * 365 * DAY).map(([store, m]) => ({ store, newest: new Date(m).toISOString().slice(0, 10) }));
    return { redundant: { groups: copies.length, files: copies.reduce((a, x) => a + x.copies, 0), items: copies.slice(0, 20) }, obsolete: { files: old.length, by_store: [...oldBy.entries()].sort((a, b) => b[1] - a[1]).slice(0, 10).map(([store, n]) => ({ store, files: n })) },
      stale_stores: stale.slice(0, 20), note: 'Copies are matched on the file name only (the discovery reads no content hash): confirm before removing one. Review against the retention schedule with the data owner; nothing is deleted from this platform.' };
  }

  async function compute(who) {
    const { C, R, S } = await P.build(who), L = P.KIND_LABEL, F = storeFacts(C, R), facts = new Map(F.map((x) => [x.id, x]));
    const scored = F.map((x) => Object.assign({ id: x.id, label: x.label, type: x.type, personal_items: x.personal_items, cred_items: x.cred_items, last_scan: x.last_scan, stale: x.stale }, scoreStore(x, L), { toxic: toxicOf(x, L) }))
      .sort((a, b) => b.score - a.score || String(a.label).localeCompare(String(b.label)));
    return { C, R, S, scored, facts };
  }

  async function insights(who) {
    const { C, R, S, scored, facts } = await compute(who);
    verifyPlans(facts); const changes = storeChanges(scored);
    const tiers = { critical: 0, high: 0, medium: 0, low: 0 }; for (const x of scored) tiers[x.tier]++;
    const toxicCount = {}; for (const x of scored) for (const tx of x.toxic) toxicCount[tx.kind] = (toxicCount[tx.kind] || 0) + 1;
    const isN = named(who);
    const out = { generated_at: new Date(now()).toISOString(), named: isN, score: { value: S.value, label: S.label, provisional: S.provisional, based_on: S.based_on },
      stores: { total: scored.length, tiers, stale: scored.filter((x) => x.stale).length, histogram: Array.from({ length: 10 }, (_, i) => ({ from: i * 10, n: scored.filter((x) => Math.min(9, Math.floor(x.score / 10)) === i).length })) },
      toxic: Object.keys(toxicCount).map((k) => ({ kind: k, stores: toxicCount[k] })), anomalies: anomalies(R), forecast: forecast(S), fixes: fixes(R), trends: riskTrends(R),
      changes: { since: changes.since, why: changes.why || null, new: changes.new.length, risen: changes.risen.length, fell: changes.fell }, peers: { judged_types: 0, outliers: 0 },
      method: 'Store risk 0-100 = sensitivity (30) + volume (15) + exposure (25) + credentials (10) + location (10) + governance (10), every point itemised. Toxic combinations, unusual jumps (robust z over the daily snapshots) and the score trend are statistics over what this platform read: indicators for a person to confirm, not proof.' };
    if (isN) {
      out.stores.items = scored.slice(0, TOP);
      const pe = peers(scored); out.peers = { judged_types: pe.judged_types.length, outliers: pe.items.length, items: pe.items, why: pe.why };
      out.graph = graph(C, scored, facts); out.labels = labels(C, scored, facts); out.rot = rot(C);
      out.changes.new_items = changes.new; out.changes.risen_items = changes.risen;
      const pl = plans().all((x) => x.status === 'proposed' || x.status === 'approved').sort((a, b) => String(b.id).localeCompare(String(a.id)))[0]; out.plan = pl ? planView(pl) : null;
      out.toxic_items = scored.filter((x) => x.toxic.length).slice(0, TOP).map((x) => ({ store: x.label, type: x.type, score: x.score, toxic: x.toxic }));
      audit(who, 'data.posture.insights.read', 'stores', { stores: out.stores.items.length });
    }
    if (!isN) { const pe = peers(scored); out.peers = { judged_types: pe.judged_types.length, outliers: pe.items.length, why: pe.why };
      const g = graph(C, scored, facts), lb = labels(C, scored, facts), ro = rot(C);
      out.graph = { risky_total: g.risky_total }; out.labels = { totals: lb.totals, mismatches: lb.mismatches, scheme: lb.scheme }; out.rot = { redundant: { groups: ro.redundant.groups, files: ro.redundant.files }, obsolete: { files: ro.obsolete.files }, stale_stores: ro.stale_stores.length, note: ro.note }; }
    if (S.value == null) out.empty = 'Nothing is connected yet - connect a source on the posture page; the store ranking, anomalies and forecast start when a source reports.';
    return out;
  }

  /* ---- the AI advisor: store labels and counts only, never a file name, a path, a person or a value */
  async function advisorView(who) {
    const v = await insights(Object.assign({}, who, { role: 'operator' }));
    return { score: v.score, tiers: v.stores.tiers, stale_scans: v.stores.stale,
      top_stores: (v.stores.items || []).slice(0, 15).map((x) => ({ store: x.type === 'onedrive' ? 'a person\'s OneDrive (name withheld)' : x.label, type: x.type, score: x.score, tier: x.tier, factors: x.why.map((w) => w.factor + ' ' + w.points + ': ' + w.reason), toxic: x.toxic.map((t) => t.title) })),
      toxic: v.toxic, anomalies: v.anomalies.filter((a) => a.flagged), forecast: { current: v.forecast.current, why: v.forecast.why, date: v.forecast.date || null },
      best_fixes: v.fixes.slice(0, 8).map((f) => ({ risk: f.title, measure: f.text, count: f.count, gain: f.gain })),
      since_yesterday: { since: v.changes.since, new_high_risk_stores: v.changes.new, risen: v.changes.risen, fell: v.changes.fell },
      unusual_for_type: (v.peers.items || []).filter((x) => x.type !== 'onedrive').map((x) => ({ store: x.label, type: x.type, items: x.personal_items, typical: x.typical })),
      risk_trends: v.trends.filter((x) => x.direction).map((x) => ({ risk: x.title, per_week: x.slope_per_week, direction: x.direction })),
      plan: v.plan ? { id: v.plan.id, status: v.plan.status, progress: v.plan.progress } : null };
  }
  const K = createIntelKit(app, { key: 'data-posture', feature: 'itam.dspm-advisor', now: opts.now, sdk: opts.sdk, getKey: opts.getKey, noTimer: true,
    system: ('You are the data security posture (DSPM) advisor for ' + ZYB_ORG.name + ', a Saudi insurer under PDPL, SAMA and NCA. Read the posture through the dspm_insights tool and answer the data-protection officer or the security team: which stores to fix first and why, what each toxic combination means, whether a jump is worth investigating, and the concrete next step for each (rotate a secret, remove an anonymous link, record a processing activity, add a transfer basis, move data into the Kingdom). Use only what the tool returns and say what is not measured. The figures are indicators, not proof of a breach. You cannot change anything: a person does.'),
    tools: [{ name: 'dspm_insights', description: 'Data security posture: score, store risk tiers, the 15 riskiest stores with itemised factors, toxic combinations, unusual jumps, the score forecast and the fixes that regain the most points. Store labels and counts only.', run: (input, who) => advisorView(who) }] });

  return { insights, ask: K.ask, TOOLS: K.TOOLS, listPlans, draftPlan, decidePlan, setItem, ACTIONS, _peers: peers, _scoreStore: scoreStore, _toxicOf: toxicOf };
}

function registerDspmIntel(srv, app, P, opts) {
  const I = createDspmIntel(app, P, opts || {});
  (app.addons = app.addons || {}).dspmIntel = I;
  srv.route('GET', '/data-posture/insights', (ctx) => { ctx.need('viewer'); body(ctx.query || {}).done(); return I.insights(ctx.who); });
  srv.route('GET', '/data-posture/plans', (ctx) => { ctx.need('operator'); body(ctx.query || {}).done(); return I.listPlans(ctx.who); });
  srv.route('POST', '/data-posture/plans', (ctx) => { ctx.need('operator'); return I.draftPlan(ctx.body, ctx.who); }, { maxBody: 4096 });
  srv.route('POST', '/data-posture/plans/:id/decide', (ctx) => { ctx.need('operator'); return I.decidePlan(ctx.params.id, ctx.body, ctx.who); }, { maxBody: 4096 });
  srv.route('POST', '/data-posture/plans/:id/items/:n', (ctx) => {
    ctx.need('operator'); if (!/^\d{1,3}$/.test(String(ctx.params.n || ''))) throw Object.assign(new Error('n must be an item number'), { status: 400 });
    return I.setItem(ctx.params.id, ctx.params.n, ctx.body, ctx.who); }, { maxBody: 4096 });
  srv.route('POST', '/data-posture/ask', (ctx) => { ctx.need('operator'); return I.ask(ctx.body, ctx.who); }, { maxBody: 8192 });
  return I;
}

module.exports = { createDspmIntel, registerDspmIntel };
