// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const { body, param } = require('./check');
const { guardOf } = require('./errors');
/*
 * Cisco Update Manager ({P} = /api/itam; Network -> Cisco Updates). Which Cisco switches, routers and ASAs need a software
 * update, why, by when, and the plan that does it. It joins what the platform already holds - nothing new is read from a device:
 *   devices      the Cisco devices of the AI Network Engineer and their running software (cisco-support.js psirtView().devices)
 *   advisories   the Cisco PSIRT advisories for each running version (psirtView().versions - only version strings go to Cisco)
 *   support      Smart Net coverage per device (cisco-support.js report(), matched by device name): an image can only be
 *                downloaded under a contract, so a device without one is flagged before anyone plans its upgrade
 *   policy       an administrator's target version per platform (OS type, optional model / name prefix): the "golden" release,
 *                and a minimum below which a device must be upgraded; deadlines per advisory severity (days from first seen)
 * Per device: status (on target / behind / below minimum / no policy / version unknown), the advisories on its version, whether the
 * target fixes each one (only when Cisco's "first fixed" names a release of the same train - otherwise "check"), the deadline
 * (first time the platform saw the advisory on this device + the severity's days) and a priority with every point named.
 * Plans: draft -> submitted -> approved (four-eyes: a different named person with the network approval scope; service and AI
 * identities never decide) -> completed. A plan changes nothing on a device: the upgrade itself is run as the AI Network
 * Engineer's staged tasks (ios-stage: copy, verify MD5, set boot - no reload; ios-reload: scheduled), which have their own
 * approval. "Complete" is verified: a device counts as done only when the version it reports equals the plan's target.
 *   GET  /cisco-update                          viewer    overview, devices, advisories, plans, policy
 *   POST /cisco-update/policy                   admin     {rules[{ostype, match?, target, minimum?, note?}], sla{Critical, High, Medium, Low}}
 *   POST /cisco-update/plans                    operator  {name, device_ids[], target, image?, md5?, window?, reason}
 *   POST /cisco-update/plans/:id/submit         operator  the requester sends it for approval
 *   POST /cisco-update/plans/:id/approve        approver  four-eyes (eng:network scope, or an administrator)
 *   POST /cisco-update/plans/:id/reject         approver  {reason}
 *   POST /cisco-update/plans/:id/cancel         operator  the requester or an administrator, {reason}
 *   POST /cisco-update/plans/:id/complete       operator  verifies every device against the running version reported now
 * Every state change is audited (cisco.update.*) with who, role, IP and what changed.
 */
const OSTYPES = ['ios', 'iosxe', 'nxos', 'asa'];
const SIRS = ['Critical', 'High', 'Medium', 'Low'];
const DEF_SLA = { Critical: 14, High: 30, Medium: 90, Low: 180 };
const SEVN = { Critical: 4, High: 3, Medium: 2, Low: 1, Informational: 0 };
const VER_RE = /^[0-9][0-9A-Za-z.()_-]{0,39}$/, MD5_RE = /^[a-fA-F0-9]{32}$/, IMG_RE = /^[A-Za-z0-9._-]{3,120}$/;
const DAY = 86400000;
const s = (v, max) => String(v == null ? '' : v).replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, max || 200);
const bad = (msg, status = 400) => Object.assign(new Error(msg), { status });
const iso = (t) => new Date(t).toISOString();
const isService = (u) => /^(duty|system|ai|svc|service|core)[:_-]/i.test(String(u || ''));

/* Cisco version strings: 15.2(7)E8, 17.9.4a, 16.12.10, 9.18(3)56 (ASA), 10.3(4a) (NX-OS). Compared chunk by chunk: digits as
 * numbers, letters as text; a release with fewer parts is lower (17.9 < 17.9.4). Good enough to order releases of one train. */
function verParts(v) { return String(v || '').toLowerCase().match(/\d+|[a-z]+/g) || []; }
function cmpVer(a, b) {
  const A = verParts(a), B = verParts(b);
  for (let i = 0; i < Math.max(A.length, B.length); i++) {
    const x = A[i], y = B[i];
    if (x === undefined) return -1; if (y === undefined) return 1;
    const nx = /^\d+$/.test(x), ny = /^\d+$/.test(y);
    if (nx && ny) { const d = Number(x) - Number(y); if (d) return d < 0 ? -1 : 1; continue; }
    if (nx !== ny) return nx ? 1 : -1;            // 17.9.4 > 17.9.a? a digit part outranks a letter suffix
    if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}
const train = (v) => verParts(v).filter((x) => /^\d+$/.test(x)).slice(0, 2).join('.');

function ruleFor(rules, d) {
  const name = String(d.name || '').toLowerCase(), model = String(d.model || '').toLowerCase();
  const hits = (rules || []).filter((r) => r.ostype === d.ostype && (!r.match || name.startsWith(r.match.toLowerCase()) || model.startsWith(r.match.toLowerCase())));
  return hits.sort((a, b) => (b.match || '').length - (a.match || '').length)[0] || null;   // the most specific rule wins
}

/* the analysis: pure, so the tests and the page agree */
function analyse({ devices = [], versions = [], coverage = [], policy = {}, seen = {}, plans = [], now = Date.now() }) {
  const sla = Object.assign({}, DEF_SLA, policy.sla || {}), rules = policy.rules || [];
  const vmap = new Map(versions.map((v) => [v.key, v])), cov = new Map(coverage.map((c) => [String(c.name || '').toLowerCase(), c]));
  const inPlan = new Map();
  for (const p of plans) if (['draft', 'submitted', 'approved'].includes(p.status)) for (const id of p.device_ids || []) inPlan.set(id, p);
  const out = devices.map((d) => {
    const v = d.key ? vmap.get(d.key) : null, r = ruleFor(rules, d), c = cov.get(String(d.name || '').toLowerCase()) || null;
    let status, why;
    if (!d.version) { status = 'unknown'; why = 'the running version is not known yet - the AI Network Engineer reads it with show version (SSH login + trusted host key)'; }
    else if (!r) { status = 'no-policy'; why = 'no target version set for ' + d.ostype + (d.model ? ' / ' + d.model : '') + ' - an administrator sets it under Policy'; }
    else if (r.minimum && cmpVer(d.version, r.minimum) < 0) { status = 'below-minimum'; why = d.version + ' is below the minimum ' + r.minimum + ' - must be upgraded'; }
    else if (cmpVer(d.version, r.target) < 0) { status = 'behind'; why = d.version + ' -> target ' + r.target; }
    else { status = 'on-target'; why = d.version + (cmpVer(d.version, r.target) > 0 ? ' (newer than the target ' + r.target + ')' : ' = target'); }
    const advs = ((v && v.advisories) || []).map((a) => {
      const first = seen[d.id + '|' + a.id] || now, days = sla[a.sir] != null ? sla[a.sir] : null, due = days != null ? first + days * DAY : null;
      const same = r ? (a.first_fixed || []).filter((f) => train(f) === train(r.target)) : [];
      const fixed = !r ? null : same.length ? same.some((f) => cmpVer(f, r.target) <= 0) : null;
      return { id: a.id, title: a.title, sir: a.sir, cvss: a.cvss, cves: a.cves || [], first_fixed: a.first_fixed || [], url: a.url || '', first_seen: iso(first),
        due: due ? iso(due) : null, overdue: !!(due && now > due), days_left: due ? Math.ceil((due - now) / DAY) : null, fixed_by_target: fixed };
    }).sort((x, y) => (SEVN[y.sir] || 0) - (SEVN[x.sir] || 0) || (y.cvss || 0) - (x.cvss || 0));
    const worst = advs[0] ? advs[0].sir : null, overdue = advs.filter((a) => a.overdue).length;
    // priority: every point named (worst advisory, overdue, below minimum, no support contract)
    const pts = [];
    if (worst) pts.push([{ Critical: 40, High: 25, Medium: 10, Low: 3 }[worst] || 0, worst + ' advisory on ' + d.version]);
    if (advs.length > 1) pts.push([Math.min(15, (advs.length - 1) * 2), advs.length + ' advisories on this version']);
    if (overdue) pts.push([20, overdue + ' past its deadline']);
    if (status === 'below-minimum') pts.push([20, 'below the minimum release']);
    else if (status === 'behind') pts.push([8, 'behind the target release']);
    const support = !c ? 'unknown' : c.status;
    if (c && (c.status === 'expired' || c.status === 'not-covered' || c.status === 'not-assigned')) pts.push([5, 'no valid support contract - the image cannot be downloaded under Smart Net']);
    const score = Math.min(100, pts.reduce((n, p) => n + p[0], 0));
    const p = inPlan.get(d.id);
    return { id: d.id, name: d.name, vendor: d.vendor, ostype: d.ostype, model: d.model || '', version: d.version, status, why, target: r ? r.target : null, minimum: r ? r.minimum || null : null,
      rule: r ? (r.match ? r.ostype + ' / ' + r.match : r.ostype) : null, advisories: advs, worst, overdue, support, support_end: c ? c.end || null : null,
      score, level: score >= 50 ? 'high' : score >= 20 ? 'medium' : score > 0 ? 'low' : 'none', points: pts.map((x) => ({ points: x[0], text: x[1] })), plan: p ? { id: p.id, name: p.name, status: p.status } : null };
  }).sort((a, b) => b.score - a.score || String(a.name).localeCompare(String(b.name)));
  const cnt = (f) => out.filter(f).length;
  const kpis = { devices: out.length, on_target: cnt((d) => d.status === 'on-target'), behind: cnt((d) => d.status === 'behind'), below_minimum: cnt((d) => d.status === 'below-minimum'),
    no_policy: cnt((d) => d.status === 'no-policy'), unknown: cnt((d) => d.status === 'unknown'), with_advisories: cnt((d) => d.advisories.length), critical: cnt((d) => d.worst === 'Critical'),
    overdue: cnt((d) => d.overdue > 0), no_support: cnt((d) => ['expired', 'not-covered', 'not-assigned'].includes(d.support)), unplanned: cnt((d) => (d.status === 'behind' || d.status === 'below-minimum' || d.advisories.length) && !d.plan) };
  const actions = [];
  const names = (L) => L.slice(0, 4).map((d) => d.name).join(', ') + (L.length > 4 ? ' +' + (L.length - 4) : '');
  const od = out.filter((d) => d.overdue); if (od.length) actions.push({ priority: 100, title: od.length + ' device(s) past an advisory deadline', detail: names(od) + ' - plan the upgrade and get it approved.', filter: 'overdue' });
  const cr = out.filter((d) => d.worst === 'Critical' && !d.plan); if (cr.length) actions.push({ priority: 90, title: cr.length + ' device(s) with a Critical advisory and no plan', detail: names(cr), filter: 'critical' });
  const bm = out.filter((d) => d.status === 'below-minimum' && !d.plan); if (bm.length) actions.push({ priority: 80, title: bm.length + ' device(s) below the minimum release', detail: names(bm), filter: 'below-minimum' });
  const ns = out.filter((d) => ['expired', 'not-covered', 'not-assigned'].includes(d.support) && (d.status !== 'on-target' || d.advisories.length)); if (ns.length) actions.push({ priority: 60, title: ns.length + ' device(s) need an update but have no valid support contract', detail: names(ns) + ' - renew Smart Net before planning (Support Contracts).', filter: 'no-support' });
  const np = out.filter((d) => d.status === 'no-policy'); if (np.length) actions.push({ priority: 40, title: np.length + ' device(s) have no target version', detail: 'Set a target per platform under Policy: ' + [...new Set(np.map((d) => d.ostype))].join(', '), filter: 'no-policy' });
  const uk = out.filter((d) => d.status === 'unknown'); if (uk.length) actions.push({ priority: 30, title: uk.length + ' device(s) with an unknown version', detail: names(uk) + ' - give the AI Network Engineer an SSH login and trust the host key.', filter: 'unknown' });
  return { kpis, devices: out, actions: actions.sort((a, b) => b.priority - a.priority), sla };
}

function createCiscoUpdate(app, opts = {}) {
  const now = opts.now || Date.now, store = app.store, L = app.log || { info() {}, warn() {} };
  const plans = () => store.collection('cisco_update_plans'), cfgC = () => store.collection('cisco_update_cfg'), seenC = () => store.collection('cisco_update_seen');
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role || '', ip: who.ip || '', action, target, detail }); };
  const person = (who, what) => { if (!who || !who.user || isService(who.user)) throw bad('a named person ' + what + ' - not a service or AI identity', 403); };
  const cs = () => opts.ciscoSupport || (app.addons && app.addons.ciscoSupport) || null;
  const policy = () => Object.assign({ rules: [], sla: Object.assign({}, DEF_SLA) }, cfgC().get('policy') || {});
  function inputs() {
    const C = cs();
    if (!C) return { connected: false, reason: 'Cisco support (engine/cisco-support.js) is not installed - run the update.', devices: [], versions: [], coverage: [], meta: {} };
    const ps = C.psirtView(), rep = (() => { try { return C.report(); } catch (e) { L.warn('cisco-update: coverage report failed', { err: String(e.message).slice(0, 160) }); return { rows: [] }; } })();
    return { connected: true, devices: ps.devices || [], versions: ps.versions || [], coverage: rep.rows || [], meta: { api: ps.api, last_check: ps.last_check, last_error: ps.last_error } };
  }
  // the first time each advisory is seen on each device (deadlines run from it)
  function record(inp) {
    const t = now(), S = seenC(), vmap = new Map(inp.versions.map((v) => [v.key, v])); let added = 0;
    for (const d of inp.devices) for (const a of ((d.key && vmap.get(d.key)) || {}).advisories || []) { const id = d.id + '|' + a.id; if (!S.get(id)) { S.put({ id, at: t }); added++; } }
    return added;
  }
  function seenMap() { const m = {}; for (const r of seenC().all()) m[r.id] = r.at; return m; }
  function view() {
    const inp = inputs(); record(inp);
    const P = plans().all().sort((a, b) => (a.created_at < b.created_at ? 1 : -1));
    const a = analyse({ devices: inp.devices, versions: inp.versions, coverage: inp.coverage, policy: policy(), seen: seenMap(), plans: P, now: now() });
    const byVer = {}; for (const v of inp.versions) byVer[v.key] = { key: v.key, ostype: v.ostype, version: v.version, count: v.count, worst: v.worst, by_sir: v.by_sir, at: v.at, error: v.error, devices: inp.devices.filter((d) => d.key === v.key).map((d) => d.name) };
    return Object.assign({ connected: inp.connected, reason: inp.reason || null, api: inp.meta.api || null, last_check: inp.meta.last_check || null, last_error: inp.meta.last_error || null,
      policy: policy(), plans: P, versions: Object.values(byVer).sort((x, y) => (SEVN[y.worst] || -1) - (SEVN[x.worst] || -1)), ostypes: OSTYPES, sirs: SIRS,
      note: 'A device is exposed only if the affected feature is in use - read each advisory. A plan changes nothing on a device: the AI Network Engineer runs the staged upgrade tasks, with their own approval.' }, a);
  }
  function setPolicy(b0, who) {
    person(who, 'sets the update policy');
    const b = body(b0 || {}).list('rules', { required: true, max: 100 }).done();
    const rules = b.rules.map((x, i) => {
      if (!x || typeof x !== 'object' || Array.isArray(x)) throw bad(`rules[${i}] must be an object`);
      const r = body(x).oneOf('ostype', OSTYPES, { required: true }).str('match', { max: 60 }).str('target', { required: true, max: 40, re: VER_RE, msg: `rules[${i}].target is not a version` })
        .str('minimum', { max: 40, re: VER_RE, msg: `rules[${i}].minimum is not a version` }).str('note', { max: 300 }).done();
      if (r.minimum && cmpVer(r.minimum, r.target) > 0) throw bad(`rules[${i}]: the minimum ${r.minimum} is above the target ${r.target}`);
      return r;
    });
    const key = (r) => r.ostype + '|' + String(r.match || '').toLowerCase(); const seen = new Set();
    for (const r of rules) { if (seen.has(key(r))) throw bad('two rules for ' + r.ostype + (r.match ? ' / ' + r.match : '') + ' - keep one'); seen.add(key(r)); }
    const sla = Object.assign({}, DEF_SLA);
    if (b0.sla !== undefined) {
      if (!b0.sla || typeof b0.sla !== 'object' || Array.isArray(b0.sla)) throw bad('sla must be an object');
      const s2 = body(b0.sla); for (const k of SIRS) s2.int(k, { min: 1, max: 730, def: DEF_SLA[k] }); Object.assign(sla, s2.done());
    }
    const before = policy(), next = { id: 'policy', rules, sla, updated_by: who.user, updated_at: iso(now()) };
    cfgC().put(next);
    audit(who, 'cisco.update.policy', 'policy', { rules: rules.length, before_rules: (before.rules || []).length, sla });
    return { policy: next };
  }
  function mustPlan(id) { const p = plans().get(param(id, 'id')); if (!p) throw bad('there is no update plan "' + s(id, 40) + '"', 404); return p; }
  const hist = (p, who, what) => { p.history = (p.history || []).concat([{ at: iso(now()), by: who.user, what: s(what, 300) }]).slice(-100); };
  function createPlan(b0, who) {
    person(who, 'raises an update plan');
    const b = body(b0 || {}).str('name', { required: true, min: 4, max: 120 }).list('device_ids', { required: true, max: 200, item: 'id', unique: true })
      .str('target', { required: true, max: 40, re: VER_RE, msg: 'target is not a version' }).str('image', { max: 120, re: IMG_RE, msg: 'image must be a file name (letters, digits, . _ -)' })
      .str('md5', { max: 32, re: MD5_RE, msg: 'md5 must be 32 hexadecimal characters' }).date('window').str('reason', { required: true, min: 5, max: 1000 }).done();
    const inp = inputs(), known = new Map(inp.devices.map((d) => [d.id, d]));
    const unknown = b.device_ids.filter((id) => !known.has(id)); if (unknown.length) throw bad('device_ids: not a Cisco device of the AI Network Engineer: ' + unknown.slice(0, 5).join(', '));
    const kinds = [...new Set(b.device_ids.map((id) => known.get(id).ostype).filter(Boolean))]; if (kinds.length > 1) throw bad('device_ids: one plan covers one platform - these mix ' + kinds.join(' and '));
    const busy = plans().all((p) => ['draft', 'submitted', 'approved'].includes(p.status) && (p.device_ids || []).some((id) => b.device_ids.includes(id)));
    if (busy.length) throw bad('device_ids: already in plan "' + busy[0].name + '" (' + busy[0].status + ')', 409);
    if (b.image && !b.md5) throw bad('md5 is required with an image - the staged task verifies the copied image against it');
    const id = 'cu_' + require('node:crypto').randomBytes(5).toString('hex');
    const p = Object.assign({ id, status: 'draft', ostype: kinds[0] || null, created_by: who.user, created_at: iso(now()) }, b, { devices: b.device_ids.map((x) => ({ id: x, name: known.get(x).name, from: known.get(x).version || null })) });
    hist(p, who, 'created'); plans().put(p);
    audit(who, 'cisco.update.plan.create', id, { name: p.name, devices: p.device_ids.length, target: p.target, ostype: p.ostype });
    return { plan: p };
  }
  function transition(id, who, from, to, action, extra) {
    const p = mustPlan(id);
    if (!from.includes(p.status)) throw bad('this plan is ' + p.status + ', not ' + from.join(' / '), 409);
    Object.assign(p, extra || {}, { status: to, updated_at: iso(now()), updated_by: who.user }); hist(p, who, action + (extra && extra.reason ? ': ' + extra.reason : ''));
    plans().put(p); audit(who, 'cisco.update.plan.' + action, p.id, Object.assign({ name: p.name, to }, extra && extra.reason ? { reason: extra.reason } : {}));
    return { plan: p };
  }
  const isAdmin = (who) => String(who.role || '').toLowerCase() === 'admin';
  function submit(id, who) { person(who, 'submits a plan'); const p = mustPlan(id); if (p.created_by !== who.user && !isAdmin(who)) throw bad('only the person who raised the plan (or an administrator) submits it', 403); return transition(id, who, ['draft'], 'submitted', 'submit'); }
  function approve(id, who) {
    person(who, 'approves an update plan'); const p = mustPlan(id);
    if (String(p.created_by || '').trim().toLowerCase() === String(who.user || '').trim().toLowerCase()) throw bad('a second person has to approve a plan you raised', 403);
    return transition(id, who, ['submitted'], 'approved', 'approve', { approved_by: who.user, approved_at: iso(now()) });
  }
  function reject(id, b0, who) {
    person(who, 'rejects an update plan'); const b = body(b0 || {}).str('reason', { required: true, min: 5, max: 500 }).done(); const p = mustPlan(id);
    if (p.created_by === who.user) throw bad('the person who raised the plan cancels it instead of rejecting it', 403);
    return transition(id, who, ['submitted'], 'rejected', 'reject', { reason: b.reason, rejected_by: who.user });
  }
  function cancel(id, b0, who) {
    person(who, 'cancels a plan'); const b = body(b0 || {}).str('reason', { required: true, min: 5, max: 500 }).done(); const p = mustPlan(id);
    if (p.created_by !== who.user && !isAdmin(who)) throw bad('only the person who raised the plan (or an administrator) cancels it', 403);
    return transition(id, who, ['draft', 'submitted', 'approved'], 'cancelled', 'cancel', { reason: b.reason });
  }
  // complete = verified: the version each device reports now must equal the target
  function complete(id, who) {
    person(who, 'completes a plan'); const p = mustPlan(id);
    if (p.status !== 'approved') throw bad('only an approved plan is completed (this one is ' + p.status + ')', 409);
    const cur = new Map(inputs().devices.map((d) => [d.id, d]));
    const res = p.device_ids.map((x) => { const d = cur.get(x), v = d ? d.version : null; return { id: x, name: d ? d.name : x, version: v, done: !!(v && cmpVer(v, p.target) === 0) }; });
    const pending = res.filter((r) => !r.done);
    p.verification = { at: iso(now()), by: who.user, devices: res };
    if (pending.length) {
      hist(p, who, 'verification: ' + pending.length + ' of ' + res.length + ' not yet on ' + p.target); plans().put(p);
      audit(who, 'cisco.update.plan.verify', p.id, { done: res.length - pending.length, pending: pending.length });
      return { plan: p, completed: false, pending };
    }
    return Object.assign(transition(id, who, ['approved'], 'completed', 'complete', { completed_at: iso(now()) }), { completed: true, pending: [] });
  }
  return { view, setPolicy, createPlan, submit, approve, reject, cancel, complete, record: () => record(inputs()), policy };
}

function registerCiscoUpdate(srv, app, U) {
  const gate = (ctx) => { if (typeof app.approveGate === 'function') return app.approveGate(ctx, 'eng:network'); ctx.need('admin'); };
  srv.route('GET', '/cisco-update', (ctx) => { ctx.need('viewer'); return U.view(); });
  srv.route('POST', '/cisco-update/policy', (ctx) => { ctx.need('admin'); return U.setPolicy(ctx.body || {}, ctx.who); });
  srv.route('POST', '/cisco-update/plans', (ctx) => { ctx.need('operator'); return U.createPlan(ctx.body || {}, ctx.who); });
  srv.route('POST', '/cisco-update/plans/:id/submit', (ctx) => { ctx.need('operator'); return U.submit(ctx.params.id, ctx.who); });
  srv.route('POST', '/cisco-update/plans/:id/approve', (ctx) => { ctx.need('operator'); gate(ctx); return U.approve(ctx.params.id, ctx.who); });
  srv.route('POST', '/cisco-update/plans/:id/reject', (ctx) => { ctx.need('operator'); gate(ctx); return U.reject(ctx.params.id, ctx.body || {}, ctx.who); });
  srv.route('POST', '/cisco-update/plans/:id/cancel', (ctx) => { ctx.need('operator'); return U.cancel(ctx.params.id, ctx.body || {}, ctx.who); });
  srv.route('POST', '/cisco-update/plans/:id/complete', (ctx) => { ctx.need('operator'); return U.complete(ctx.params.id, ctx.who); });
  return U;
}
// first-seen dates are recorded on every view, and once a day in the background so deadlines start even if nobody looks
function startCiscoUpdate(app, U, opts = {}) {
  if (opts.noTimer) return null;
  const t = setInterval(guardOf(app, 'cisco-update.record', () => U.record()), 6 * 3600000); if (t.unref) t.unref(); return t;
}

module.exports = { createCiscoUpdate, registerCiscoUpdate, startCiscoUpdate, analyse, cmpVer, train, ruleFor, DEF_SLA };
