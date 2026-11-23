// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Continuous control monitoring ({P} = /api/itam, Audit -> Continuous Control Monitoring): the platform's own hash-chained
 * audit trail (engine/store.js audit-YYYYMM.jsonl) tested every day against eight controls, so an auditor sees the whole
 * population - not a sample - and every exception with the record behind it:
 *   CT-01 segregation of duties     a person approved what they requested themselves (same target, or the record names them)
 *   CT-02 decisions by a person     an approval recorded by a service, system or AI identity (policy auto-approvals counted apart)
 *   CT-03 after-hours admin changes outside Sun-Thu 07:00-18:00 Riyadh, scored by how rare that hour is for this person
 *                                   (their own 30-day hour-of-day distribution; < 5 % = rare, under 20 changes = no baseline yet)
 *   CT-04 change volume             a person's changes on one day against their own previous 14 days (robust z = 0.6745 (x - median)
 *                                   / MAD >= 3.5, and at least 20 changes)
 *   CT-05 personal-data reads       exports, previews and evidence views per person against their peers (robust z >= 3.5, >= 10,
 *                                   >= 3 x the peer median; needs 3 people to compare)
 *   CT-06 trail integrity           the whole hash chain re-verified
 *   CT-07 self-granted roles        a person changed their own platform role
 *   CT-08 credential settings       credential / key / token changes by anyone but an administrator
 * A test with nothing to test reads "not testable" with the reason - never "effective". The statistics are indicators for an
 * auditor to follow up, not proof of wrongdoing (a busy shift is not misconduct), and the page says so.
 * People decide: an auditor explains an exception or marks it for a finding (never one about themselves - independence); the
 * finding is drafted from the facts (rules, or the AI when an administrator allows external AI) and becomes an audit finding only
 * when an auditor on that engagement accepts it into the IT / Cyber / Internal Audit Team (engine/audit-engage.js addFinding).
 *
 *   GET  /audit-ccm                              operator  latest run, 30-day trend, dispositions, drafts (names people: PDPL)
 *   POST /audit-ccm/run                          operator  run every test now                                         audited
 *   GET  /audit-ccm/export                       operator  exceptions as CSV                                          audited
 *   POST /audit-ccm/exceptions/:id/disposition   operator  {decision: explained|finding, note}                        audited
 *   POST /audit-ccm/tests/:id/draft              operator  {use_ai?} draft a finding from a test's open exceptions    audited
 *   POST /audit-ccm/drafts/:id/accept            operator  {team, engagement, owner, title?, condition?, ...}         audited
 *   POST /audit-ccm/drafts/:id/discard           operator  {note}                                                     audited
 *   GET  /audit-ccm/ai/status                    operator  whether the AI may draft, and why not
 */
const fs = require('node:fs');
const path = require('node:path');
const { body, param } = require('./check');
const { guardOf } = require('./errors');
const G = require('./ai-guard');

const DAY = 86400000, WINDOW_DAYS = 30, RIYADH = 3 * 3600000, MODEL = 'claude-opus-5-5', MAX_EXC = 200;
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const norm = (u) => String(u == null ? '' : u).trim().toLowerCase();
const s = (v, n = 200) => String(v == null ? '' : v).replace(/\s+/g, ' ').trim().slice(0, n);
const isService = (u) => !norm(u) || /^(duty|system|core|ai|svc|service|agent|bot)([:._-]|$)/i.test(String(u).trim());
const READ = /(^|[._-])(view|export|read|ask|brief|preview|download|trace|list|get|status|call)$/;
const APPROVE = /(^|[._-])(approve|approved|decide|endorse|authorise|authorize)$/;
const REQUEST = /(^|[._-])(request|requested|raise|propose|submit|create)$/;
const PD_READ = /(export|evidence\.view|statement\.view|preview|download|trace)$/;
const CRED = /(credential|secret|api[_-]?key|vault|sealer|token\.issue|set[_-]?key)/i;
const riyadh = (at) => { const d = new Date(Date.parse(at) + RIYADH); return { day: d.toISOString().slice(0, 10), hour: d.getUTCHours(), dow: d.getUTCDay() }; };
const working = (r) => r.dow <= 4 && r.hour >= 7 && r.hour < 18;   // Sun-Thu 07:00-18:00
const median = (a) => { if (!a.length) return 0; const b = a.slice().sort((x, y) => x - y), m = b.length >> 1; return b.length % 2 ? b[m] : (b[m - 1] + b[m]) / 2; };
const mad = (a) => { const m = median(a); return median(a.map((x) => Math.abs(x - m))); };
const robustZ = (x, a) => 0.6745 * (x - median(a)) / Math.max(mad(a), 1);   // MAD floored at 1: a person who always does 2 is not alarming at 4
const named = (d, k) => d && typeof d === 'object' && typeof d[k] === 'string' ? d[k] : '';

const TESTS = [
  { id: 'CT-01', name: 'Segregation of duties', objective: 'Nobody approves what they requested themselves.', maps: ['ISO 27001 A.5.3', 'NCA ECC 2-2-1', 'SAMA CSF 3.3.5'] },
  { id: 'CT-02', name: 'Decisions are made by a person', objective: 'Approvals are recorded by a named person - never by a service, system or AI identity.', maps: ['ISO 27001 A.5.3', 'NCA ECC 1-6'] },
  { id: 'CT-03', name: 'After-hours administrator changes', objective: 'Administrator changes outside working hours (Sun-Thu 07:00-18:00 Riyadh) that are unusual for that person are reviewed.', maps: ['ISO 27001 A.8.2', 'ISO 27001 A.8.16', 'NCA ECC 2-2-3'] },
  { id: 'CT-04', name: 'Change volume', objective: 'A day far above a person\'s own usual number of changes is reviewed.', maps: ['ISO 27001 A.8.16', 'NCA ECC 2-12-1'] },
  { id: 'CT-05', name: 'Personal-data reads and exports', objective: 'Reads and exports of records that name people stay proportionate to the role.', maps: ['PDPL Art. 19', 'ISO 27001 A.5.34', 'NCA ECC 2-7'] },
  { id: 'CT-06', name: 'Audit trail integrity', objective: 'The audit trail is complete and unaltered (hash chain).', maps: ['ISO 27001 A.8.15', 'NCA ECC 2-12-3', 'SAMA CSF 3.3.14'] },
  { id: 'CT-07', name: 'No self-granted roles', objective: 'Nobody changes their own platform role.', maps: ['ISO 27001 A.5.18', 'NCA ECC 2-2-1'] },
  { id: 'CT-08', name: 'Credential settings by administrators', objective: 'Only administrators change credentials, keys and security-integration settings.', maps: ['ISO 27001 A.8.2', 'ISO 27001 A.5.17', 'NCA ECC 2-2-2'] },
];
const TEST = Object.fromEntries(TESTS.map((t) => [t.id, t]));
const TEAMS = { it: 'auditEngage', cyber: 'cyberAuditEngage', internal: 'internalAuditEngage' };

function createAuditCcm(app, opts = {}) {
  const now = opts.now || Date.now, store = app.store, L = app.log || { info() {}, warn() {}, error() {} };
  const iso = () => new Date(now()).toISOString();
  const c = (n) => store.collection(n), runs = () => c('ccm_runs'), disp = () => c('ccm_dispositions'), drafts = () => c('ccm_drafts');
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role || '', ip: who.ip || '', action: 'audit-ccm.' + action, target, detail }); };
  const person = (who) => { if (!who || isService(who.user)) throw httpErr(403, 'a named person makes this decision - not a service or AI identity'); };

  /* ---- the population: every audit record of the last 30 days, read from the journal files themselves */
  const safeId = (id) => String(id).replace(/[^A-Za-z0-9._:-]/g, '_').slice(0, 80);   // also the route id (check.js ID)
  function trail() {
    const since = now() - WINDOW_DAYS * DAY, dir = store.dir, out = [];
    let unreadable = 0, files = [];
    try { files = fs.readdirSync(dir).filter((f) => /^audit-\d{6}\.jsonl$/.test(f)).sort(); } catch (e) { files = []; /* no trail yet: every test reads not testable */ }
    const first = new Date(since).toISOString().slice(0, 7).replace('-', '');
    for (const f of files.filter((x) => x.slice(6, 12) >= first)) {
      for (const line of fs.readFileSync(path.join(dir, f), 'utf8').split('\n')) {
        if (!line) continue;
        let r; try { r = JSON.parse(line); } catch (e) { unreadable++; continue; /* counted, and CT-06 reports where the chain breaks */ }
        const t = Date.parse(r.at); if (!(t >= since) || t > now()) continue;
        if (String(r.action || '').startsWith('audit-ccm.')) continue;   // the monitor never tests its own records
        out.push(r);
      }
    }
    return { recs: out, unreadable, since: new Date(since).toISOString() };
  }
  const exc = (t, key, r, why, score, extra) => Object.assign({ id: safeId(t + '.' + key), test: t, at: r ? r.at : null, by: r ? s(r.by, 80) : null, role: r ? s(r.role, 20) : null,
    action: r ? s(r.action, 80) : null, target: r ? s(r.target, 120) : null, seq: r ? r.seq : null, why, score: Math.round(score * 100) / 100 }, extra || {});

  function ct01(R) {
    const pop = R.filter((r) => (APPROVE.test(r.action || '') || named(r.detail, 'decision') === 'approve') && !/auto-approve/.test(r.action || '') && !isService(r.by)), out = [];   // the rest is CT-02's
    const reqBy = new Map();
    for (const r of R) if (REQUEST.test(r.action || '') && r.target) { const k = String(r.target); if (!reqBy.has(k)) reqBy.set(k, new Set()); reqBy.get(k).add(norm(r.by)); }
    for (const r of pop) {
      const d = r.detail || {}, me = norm(r.by);
      const recorded = ['requested_by', 'requester', 'prepared_by', 'raised_by', 'submitted_by'].find((k) => norm(named(d, k)) === me);
      if (recorded) out.push(exc('CT-01', r.seq, r, r.by + ' approved ' + r.target + ' and the record names them as ' + recorded.replace('_', ' '), 1));
      else if (r.target && reqBy.has(String(r.target)) && reqBy.get(String(r.target)).has(me)) out.push(exc('CT-01', r.seq, r, r.by + ' requested ' + r.target + ' and approved it', 0.9));
    }
    return { population: pop.length, exceptions: out };
  }
  function ct02(R) {
    const pop = R.filter((r) => APPROVE.test(r.action || '') || /auto-approve/.test(r.action || '')), out = [];
    let auto = 0;
    for (const r of pop) {
      if (/auto-approve/.test(r.action)) { auto++; continue; }   // a policy an administrator set: counted, not an exception
      if (isService(r.by)) out.push(exc('CT-02', r.seq, r, 'approval recorded by ' + (r.by || 'no identity') + ', not a named person', 1));
    }
    return { population: pop.length, exceptions: out, note: auto ? auto + ' approval(s) by an administrator\'s auto-approve policy - counted, reviewed with the policy itself' : '' };
  }
  function ct03(R) {
    const pop = R.filter((r) => r.role === 'admin' && !isService(r.by) && !READ.test(r.action || '')), byUser = new Map(), out = [];
    for (const r of pop) { const u = norm(r.by); if (!byUser.has(u)) byUser.set(u, []); byUser.get(u).push(r); }
    let usual = 0;
    for (const list of byUser.values()) {
      const hours = new Array(24).fill(0); for (const r of list) hours[riyadh(r.at).hour]++;
      for (const r of list) {
        const t = riyadh(r.at); if (working(t)) continue;
        const p = hours[t.hour] / list.length, when = (['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'][t.dow]) + ' ' + String(t.hour).padStart(2, '0') + ':00 Riyadh';
        if (list.length < 20) out.push(exc('CT-03', r.seq, r, when + ' - outside working hours; ' + list.length + ' admin changes in 30 days is too few to know what is usual for ' + r.by, 0.5, { rarity: null }));
        else if (p < 0.05) out.push(exc('CT-03', r.seq, r, when + ' - outside working hours and rare for ' + r.by + ' (' + Math.round(p * 1000) / 10 + ' % of their changes are at this hour)', 1 - p, { rarity: Math.round(p * 1000) / 1000 }));
        else usual++;
      }
    }
    return { population: pop.length, exceptions: out, note: usual ? usual + ' after-hours change(s) at an hour that is usual for that person - not raised' : '' };
  }
  function ct04(R) {
    const pop = R.filter((r) => !isService(r.by) && !READ.test(r.action || '')), per = new Map(), out = [];
    for (const r of pop) { const u = norm(r.by), d = riyadh(r.at).day; if (!per.has(u)) per.set(u, { name: r.by, days: new Map(), last: new Map() }); const x = per.get(u); x.days.set(d, (x.days.get(d) || 0) + 1); x.last.set(d, r); }
    for (const x of per.values()) {
      const days = [...x.days.keys()].sort(), first = Date.parse(days[0] + 'T00:00:00Z');
      for (const d of days) {
        const n = x.days.get(d); if (n < 20) continue;
        const base = []; for (let i = 14; i >= 1; i--) { const t = Date.parse(d + 'T00:00:00Z') - i * DAY; if (t >= first) base.push(x.days.get(new Date(t).toISOString().slice(0, 10)) || 0); }
        if (base.length < 7) continue;   // no baseline yet for this person
        const z = robustZ(n, base);
        if (z >= 3.5) out.push(exc('CT-04', norm(x.name) + '.' + d, x.last.get(d), x.name + ' made ' + n + ' changes on ' + d + ' against a usual ' + median(base) + ' a day (robust z ' + z.toFixed(1) + ', ' + base.length + ' days of baseline)', Math.min(1, z / 10), { day: d, count: n, usual: median(base), z: Math.round(z * 10) / 10 }));
      }
    }
    return { population: pop.length, exceptions: out };
  }
  function ct05(R) {
    const pop = R.filter((r) => !isService(r.by) && PD_READ.test(r.action || '')), per = new Map(), out = [];
    for (const r of pop) { const u = norm(r.by); if (!per.has(u)) per.set(u, { name: r.by, n: 0, last: r }); const x = per.get(u); x.n++; x.last = r; }
    if (pop.length && per.size < 3) return { population: pop.length, exceptions: [], untestable: 'only ' + per.size + ' person(s) read or exported personal data in 30 days - a peer comparison needs 3' };
    for (const x of per.values()) {
      const peers = [...per.values()].filter((y) => y !== x).map((y) => y.n), z = robustZ(x.n, peers), pm = median(peers);
      if (x.n >= 10 && x.n >= 3 * Math.max(pm, 1) && z >= 3.5) out.push(exc('CT-05', norm(x.name), x.last, x.name + ' read or exported records that name people ' + x.n + ' times in 30 days; the median of the other ' + peers.length + ' people is ' + pm + ' (robust z ' + z.toFixed(1) + ')', Math.min(1, z / 10), { count: x.n, peer_median: pm, z: Math.round(z * 10) / 10 }));
    }
    return { population: pop.length, exceptions: out };
  }
  function ct06(T) {
    let v; try { v = store.verifyAudit(); } catch (e) { return { population: 0, exceptions: [], untestable: 'the trail could not be read: ' + s(e.message, 160) }; }
    const out = [];
    if (!v.ok) out.push(exc('CT-06', 'chain', null, 'the hash chain breaks at ' + v.bad_at + ' (' + (v.reason || 'hash chain broken') + ') after ' + v.checked + ' good records - the trail was edited, cut or damaged', 1, { bad_at: v.bad_at }));
    return { population: v.checked + (v.ok ? 0 : 1), exceptions: out, note: v.ok ? v.checked + ' records verified from the first one' : '' };
  }
  function ct07(R) {
    const pop = R.filter((r) => r.action === 'roles.assign'), out = [];
    for (const r of pop) if (!isService(r.by) && norm(r.target) === norm(r.by)) out.push(exc('CT-07', r.seq, r, r.by + ' changed their own role (' + s(named(r.detail, 'from') || 'none', 40) + ' -> ' + s((r.detail && r.detail.to) || 'none', 40) + ')', 1));
    return { population: pop.length, exceptions: out };
  }
  function ct08(R) {
    const pop = R.filter((r) => !READ.test(r.action || '') && CRED.test(r.action || '')), out = [];
    for (const r of pop) if (!isService(r.by) && r.role !== 'admin') out.push(exc('CT-08', r.seq, r, r.by + ' (' + (r.role || 'no role') + ') changed ' + r.action + ' - credential settings are for administrators', 1));
    return { population: pop.length, exceptions: out };
  }
  const RUN = { 'CT-01': ct01, 'CT-02': ct02, 'CT-03': ct03, 'CT-04': ct04, 'CT-05': ct05, 'CT-06': (R, T) => ct06(T), 'CT-07': ct07, 'CT-08': ct08 };

  function run(who) {
    const T = trail(), at = iso(), tests = [];
    for (const t of TESTS) {
      let r; try { r = RUN[t.id](T.recs, T); } catch (e) { L.error('audit-ccm test failed', { test: t.id, err: s(e.message, 200) }); r = { population: 0, exceptions: [], untestable: 'the test failed: ' + s(e.message, 160) }; }
      const ex = r.exceptions.sort((a, b) => b.score - a.score || String(b.at).localeCompare(String(a.at)));
      const status = r.untestable ? 'not_testable' : !r.population ? 'not_testable' : ex.length ? 'exceptions' : 'effective';
      tests.push(Object.assign({}, t, { status, population: r.population, exceptions_total: ex.length, exceptions: ex.slice(0, MAX_EXC), truncated: ex.length > MAX_EXC,
        reason: r.untestable || (!r.population ? 'no records of this kind in the last ' + WINDOW_DAYS + ' days - nothing to test, which is not the same as effective' : ''), note: r.note || '' }));
    }
    const day = riyadh(at).day, rec = { id: 'CCM-' + day, day, at, by: who ? who.user : 'schedule', window_from: T.since, records: T.recs.length, unreadable: T.unreadable,
      summary: { effective: tests.filter((x) => x.status === 'effective').length, exceptions: tests.filter((x) => x.status === 'exceptions').length, not_testable: tests.filter((x) => x.status === 'not_testable').length, open: tests.reduce((n, x) => n + x.exceptions.filter((e) => !disp().get(safeId(e.id))).length, 0) }, tests };
    runs().put(rec);
    if (who) audit(who, 'run', rec.id, { records: rec.records, exceptions: tests.reduce((n, x) => n + x.exceptions_total, 0) });
    else if (app.audit) app.audit({ by: 'duty', role: '', ip: '', action: 'audit-ccm.run', target: rec.id, detail: { records: rec.records, exceptions: tests.reduce((n, x) => n + x.exceptions_total, 0) } });
    return rec;
  }
  const latest = () => runs().all(() => true).sort((a, b) => String(b.at).localeCompare(String(a.at)))[0] || null;

  function view() {
    const r = latest() || run(null);
    const tests = r.tests.map((t) => Object.assign({}, t, { exceptions: t.exceptions.map((e) => Object.assign({}, e, { disposition: disp().get(safeId(e.id)) || null })) }));
    const trend = runs().all(() => true).sort((a, b) => a.day.localeCompare(b.day)).slice(-30).map((x) => ({ day: x.day, effective: x.summary.effective, exceptions: x.tests.reduce((n, t) => n + t.exceptions_total, 0), open: x.summary.open, records: x.records }));
    const open = tests.reduce((n, t) => n + t.exceptions.filter((e) => !e.disposition).length, 0);
    return { at: r.at, run: r.id, by: r.by, window_from: r.window_from, records: r.records, unreadable: r.unreadable, summary: Object.assign({}, r.summary, { open }), tests, trend, insight: insight(r, tests),
      drafts: drafts().all(() => true).sort((a, b) => String(b.at).localeCompare(String(a.at))).slice(0, 50), ai: aiStatus(), teams: Object.keys(TEAMS).filter((k) => app.addons && app.addons[TEAMS[k]]),
      note: 'Every record in the platform audit trail for the last ' + WINDOW_DAYS + ' days is tested - the whole population, not a sample. The statistics flag what is unusual for a person or their peers: they are indicators for an auditor to follow up, not proof of wrongdoing.' };
  }

  // ---- insight over the daily runs (all explainable): per-control 30-day strip and today against the control's own history
  // (robust z on median / MAD, 7+ runs), how concentrated the exceptions are on a few people, when they happen (Riyadh weekday x
  // hour), and how long the open ones have been open (the first daily run that held the exception)
  function insight(r, tests) {
    const all = runs().all(() => true).sort((a, b) => a.day.localeCompare(b.day)), last = all.slice(-30), days = last.map((x) => x.day);
    const controls = TESTS.map((t) => {
      const hist = last.map((x) => { const y = x.tests.find((q) => q.id === t.id); return y ? (y.status === 'not_testable' ? null : y.exceptions_total) : null; });
      const prior = hist.slice(0, -1).filter((v) => v != null), cur = hist[hist.length - 1];
      let unusual = null;
      if (cur != null && prior.length >= 7 && cur > 0 && prior.every((v) => v === 0)) unusual = { z: null, flag: true, why: 'the first exception after ' + prior.length + ' clean run(s) - a control that never failed before has failed' };
      else if (cur != null && prior.length >= 7) { const z = Math.round(robustZ(cur, prior) * 10) / 10; unusual = { z, flag: z >= 3.5, why: 'today ' + cur + ' against a median of ' + median(prior) + ' over ' + prior.length + ' run(s) (robust z ' + z + ')' }; }
      else unusual = { z: null, flag: false, why: 'needs 7 earlier runs to learn this control (' + prior.length + ' so far)' };
      return { id: t.id, name: t.name, strip: hist, unusual };
    });
    const firstSeen = new Map(); for (const x of all) for (const t of x.tests) for (const e of t.exceptions) if (!firstSeen.has(e.id)) firstSeen.set(e.id, x.day);
    const people = new Map(), clock = Array.from({ length: 7 }, () => new Array(24).fill(0)), ageing = { '0-1': 0, '2-7': 0, '8-30': 0, '30+': 0 };
    let total = 0;
    const today = Date.parse(r.day + 'T00:00:00Z');
    for (const t of tests) for (const e of t.exceptions) {
      total++;
      if (e.by) { const k = norm(e.by), p = people.get(k) || { name: e.by, count: 0, tests: new Set(), max: 0 }; p.count++; p.tests.add(t.id); p.max = Math.max(p.max, e.score || 0); people.set(k, p); }
      if (e.at) { const h = riyadh(e.at); clock[h.dow][h.hour]++; }
      if (!e.disposition) { const f = firstSeen.get(e.id) || r.day, d = Math.round((today - Date.parse(f + 'T00:00:00Z')) / DAY); ageing[d <= 1 ? '0-1' : d <= 7 ? '2-7' : d <= 30 ? '8-30' : '30+']++; }
    }
    const P = [...people.values()].sort((a, b) => b.count - a.count).map((p) => ({ name: p.name, count: p.count, tests: [...p.tests], max_score: Math.round(p.max * 100) / 100 }));
    const topN = Math.max(1, Math.ceil(P.length * 0.2)), topShare = total && P.length ? Math.round(P.slice(0, topN).reduce((n, p) => n + p.count, 0) / P.reduce((n, p) => n + p.count, 0) * 100) : null;
    return { days, controls, people: P.slice(0, 15), people_total: P.length, concentration: topShare == null ? { why: 'no exception names a person' } : { top_share: topShare, top_people: topN, why: 'the top ' + topN + ' person(s) (20 %) hold ' + topShare + ' % of the exceptions that name a person - concentration is a lead, not a conclusion' },
      clock, ageing, exceptions_total: total };
  }

  function findExc(id) {
    const r = latest(); if (!r) throw httpErr(404, 'no control test has run yet');
    for (const t of r.tests) for (const e of t.exceptions) if (safeId(e.id) === id) return e;
    throw httpErr(404, 'no exception ' + id + ' in the latest run');
  }
  function dispose(id0, b0, who) {
    person(who);
    const id = param(id0, 'id'), b = body(b0).oneOf('decision', ['explained', 'finding'], { required: true }).str('note', { required: true, min: 10, max: 2000 }).done();
    const e = findExc(id);
    if (e.by && norm(e.by) === norm(who.user)) throw httpErr(403, 'this exception is about you - another auditor decides it (independence)');
    const d = { id, test: e.test, decision: b.decision, note: b.note, by: who.user, at: iso() };
    disp().put(d); audit(who, 'disposition', id, { test: e.test, decision: b.decision, about: e.by });
    return d;
  }

  /* ---- a finding drafted from a test's open exceptions: rules always, the AI when allowed; a person accepts or discards */
  const cfg = () => (app.config && app.config.ia_ai) || {};
  const getKey = opts.getKey || (() => { const get = require('./secret-values').fileValue(process.env.SENTRA_ITAM_SECRETS || '/etc/sentra-itam/secrets.json', 'anthropic_api_key', app.config && app.config.discovery && app.config.discovery.vault_key_file); return () => get() || process.env.ANTHROPIC_API_KEY || ''; })();
  let Ctor = null, loadError = '';
  function loadSdk() {
    if (opts.sdk) return opts.sdk; if (Ctor) return Ctor;
    for (const p of [cfg().sdk_path, '@anthropic-ai/sdk', '/opt/sentra-itam/vendor/node_modules/@anthropic-ai/sdk', '/opt/sentra-siem/vendor/node_modules/@anthropic-ai/sdk', require('path').join(__dirname, 'ai-sdk-shim.js')].filter(Boolean)) {
      try { if (p.startsWith('/') && !fs.existsSync(p)) continue; const m = require(p); Ctor = require('./ai-backend').wrap(m.Anthropic || m.default || m); return Ctor; } catch (e) { loadError = e.code === 'MODULE_NOT_FOUND' ? 'Anthropic SDK not installed (the update installs it)' : s(e.message, 200); }
    }
    return null;
  }
  function aiStatus() {
    const model = cfg().model || MODEL;
    let allowed = false; try { allowed = !!(app.settings && require('./ai-backend').allowed(app.settings.get())); } catch (e) { allowed = false; /* settings unreadable = not allowed */ }
    if (!allowed) return { enabled: false, reason: 'external AI is not allowed in IT Asset Management settings (external_ai_allowed), or the AI engine is switched off (Platform Administration -> AI Engine) - findings are drafted by the rules only', model };
    if (!getKey()) return { enabled: false, reason: 'no Anthropic API key (sudo zyb-virt-ai --set-key) - findings are drafted by the rules only', model };
    if (!loadSdk()) return { enabled: false, reason: loadError || 'Anthropic SDK not installed', model };
    return { enabled: true, model };
  }
  function ruleDraft(t, ex) {
    const people = [...new Set(ex.map((e) => e.by).filter(Boolean))], n = ex.length;
    return { title: t.name + ': ' + n + ' exception' + (n === 1 ? '' : 's') + ' in ' + WINDOW_DAYS + ' days',
      condition: 'Continuous control test ' + t.id + ' found ' + n + ' exception(s) in ' + t.population + ' record(s) of the platform audit trail between ' + latest().window_from.slice(0, 10) + ' and ' + latest().at.slice(0, 10) + (people.length ? ', involving ' + people.slice(0, 8).join(', ') + (people.length > 8 ? ' and ' + (people.length - 8) + ' more' : '') : '') + '. Examples: ' + ex.slice(0, 3).map((e) => e.why).join('; ') + '.',
      criteria: t.objective + ' (' + t.maps.join(', ') + ')',
      cause: 'To be confirmed with the control owner - the trail shows what happened, not why.',
      effect: { 'CT-01': 'One person can request and approve the same change, so an error or a misuse has no second check.', 'CT-02': 'A change can be authorised without a person accountable for it.', 'CT-03': 'Privileged changes outside working hours get less oversight and may indicate a misused account.', 'CT-04': 'An unusual burst of changes may hide an error, an unapproved bulk change or a misused account.', 'CT-05': 'Personal data may be read or exported beyond what the role needs (PDPL Art. 19).', 'CT-06': 'The audit trail cannot be relied on as evidence.', 'CT-07': 'A person can raise their own access without approval.', 'CT-08': 'Credentials can be changed by people outside the administrators who own them.' }[t.id],
      recommendation: { 'CT-01': 'Enforce four-eyes approval in code for these actions and review the listed approvals with the requesters\' managers.', 'CT-02': 'Remove approval rights from service and AI identities; re-approve the listed changes by a named person.', 'CT-03': 'Confirm each listed change with the administrator and their change record; require a change ticket for after-hours admin work.', 'CT-04': 'Confirm the listed days with the person and their change records.', 'CT-05': 'Review the reads and exports with the person\'s manager and the DPO; narrow the role if they are not needed.', 'CT-06': 'Investigate the break with the platform administrator, restore the trail from backup and ship the trail off the server.', 'CT-07': 'Revert the self-granted roles and restrict role assignment to a second administrator.', 'CT-08': 'Revert or re-confirm the listed changes and restrict them to administrators.' }[t.id],
      rating: ['CT-01', 'CT-02', 'CT-06', 'CT-07'].includes(t.id) ? 'high' : n >= 5 ? 'medium' : 'low' };
  }
  const FIELDS = ['title', 'condition', 'criteria', 'cause', 'effect', 'recommendation'];
  async function aiDraft(t, ex, base, who) {
    const st = aiStatus(); if (!st.enabled) throw httpErr(503, st.reason);
    const facts = JSON.stringify({ test: { id: t.id, name: t.name, objective: t.objective, maps: t.maps, population: t.population }, exceptions: ex.slice(0, 40).map((e) => ({ at: e.at, by: e.by, role: e.role, action: e.action, target: e.target, why: e.why })), rule_draft: base });
    const q = G.redactSecrets('Improve the wording of this internal audit finding for the Board Audit Committee using ONLY the facts below. Do not add facts, names, numbers or causes the facts do not show; keep "cause" as to be confirmed unless the facts state it. Answer with one JSON object with exactly the keys title, condition, criteria, cause, effect, recommendation, rating (high|medium|low).\n\n' + G.untrusted('ccm:' + t.id, facts));
    const budget = G.sharedBudget({ log: L, limits: () => ((app.config && app.config.ai) || {}).limits || {} });
    budget.admit(who.user, 'itam.ccm-draft', q.length);
    const flags = G.injectionSignals(facts), usage = { input_tokens: 0, output_tokens: 0 };
    let text = '';
    try {
      const Anthropic = loadSdk(), client = new Anthropic({ apiKey: getKey(), timeout: (cfg().timeout_s || 180) * 1000, maxRetries: 2 });
      const resp = await client.messages.create({ model: st.model, max_tokens: 4000, system: 'You are an internal auditor at a Saudi insurer drafting a finding from continuous control monitoring results. You write; an auditor decides.\n\n' + G.UNTRUSTED_RULE, messages: [{ role: 'user', content: q }] });
      for (const k of Object.keys(usage)) usage[k] += (resp.usage && resp.usage[k]) || 0;
      text = (resp.content || []).filter((b) => b.type === 'text').map((b) => b.text).join('\n');
    } finally { budget.record(who.user, 'itam.ccm-draft', usage, flags); }
    const m = text.match(/\{[\s\S]*\}/); let o = null; try { o = m ? JSON.parse(m[0]) : null; } catch (e) { o = null; /* not JSON: the rule draft stands, the answer is reported as unusable */ }
    if (!o || typeof o !== 'object') throw httpErr(502, 'the AI did not return a usable draft - the rule-based draft is still available');
    const out = {};
    for (const k of FIELDS) out[k] = typeof o[k] === 'string' && o[k].trim() ? s(o[k], k === 'title' ? 200 : 2000) : base[k];   // schema-checked: anything else keeps the rule text
    const RK = { low: 0, medium: 1, high: 2 };   // the AI may raise the rating, never lower it - injected text asking for "low" changes nothing; the accepting auditor decides
    out.rating = RK[o.rating] > RK[base.rating] ? o.rating : base.rating;
    return { draft: out, flags };
  }
  async function draft(tid0, b0, who) {
    person(who);
    const tid = String(tid0 || ''); if (!TEST[tid]) throw httpErr(404, 'no control test ' + s(tid, 20));
    const b = body(b0).bool('use_ai', { def: false }).done();
    const r = latest(); if (!r) throw httpErr(409, 'run the control tests first');
    const t = r.tests.find((x) => x.id === tid), ex = t.exceptions.filter((e) => { const d = disp().get(safeId(e.id)); return !d || d.decision === 'finding'; });
    if (!ex.length) throw httpErr(409, t.id + ' has no open exception to draft a finding from');
    let content = ruleDraft(t, ex), source = 'rules', flags = [];
    if (b.use_ai) { const a = await aiDraft(t, ex, content, who); content = a.draft; source = 'ai'; flags = a.flags; }
    const n = drafts().all(() => true).length + 1, d = Object.assign({ id: 'CCMD-' + String(n).padStart(4, '0'), test: t.id, run: r.id, exceptions: ex.map((e) => e.id).slice(0, 60), source, flags, state: 'draft', drafted_for: who.user, at: iso() }, content);
    drafts().put(d); audit(who, 'draft', d.id, { test: t.id, source, exceptions: ex.length, flags: flags.length });
    return d;
  }
  function accept(id0, b0, who) {
    person(who);
    const d = drafts().get(param(id0, 'id')); if (!d) throw httpErr(404, 'no draft ' + s(id0, 30));
    if (d.state !== 'draft') throw httpErr(409, 'the draft is ' + d.state);
    const b = body(b0).oneOf('team', Object.keys(TEAMS), { required: true }).str('engagement', { required: true, id: true }).str('owner', { required: true, max: 80, re: /^[A-Za-z0-9][A-Za-z0-9 ._@\\-]{1,79}$/, msg: 'owner: a user name' })
      .str('title', { max: 200 }).str('condition', { max: 4000 }).str('criteria', { max: 2000 }).str('cause', { max: 2000 }).str('effect', { max: 2000 }).str('recommendation', { max: 2000 }).oneOf('rating', ['high', 'medium', 'low']).done();
    const team = app.addons && app.addons[TEAMS[b.team]]; if (!team) throw httpErr(409, 'the ' + b.team + ' audit team is not installed');
    const f = team.addFinding(b.engagement, Object.assign({}, ...FIELDS.concat('rating').map((k) => ({ [k]: b[k] || d[k] })), { owner: b.owner }), who);   // its own checks: auditor on that engagement, state, owner
    d.state = 'accepted'; d.accepted_by = who.user; d.accepted_at = iso(); d.finding = f.id; d.team = b.team; d.edited = FIELDS.concat('rating').filter((k) => b[k] && b[k] !== d[k]);
    drafts().put(d); audit(who, 'accept', d.id, { finding: f.id, team: b.team, engagement: b.engagement, source: d.source, edited: d.edited });
    return { draft: d, finding: f };
  }
  function discard(id0, b0, who) {
    person(who);
    const d = drafts().get(param(id0, 'id')); if (!d) throw httpErr(404, 'no draft ' + s(id0, 30));
    if (d.state !== 'draft') throw httpErr(409, 'the draft is ' + d.state);
    const b = body(b0).str('note', { required: true, min: 5, max: 1000 }).done();
    d.state = 'discarded'; d.discarded_by = who.user; d.discarded_at = iso(); d.note = b.note;
    drafts().put(d); audit(who, 'discard', d.id, { test: d.test, source: d.source });
    return d;
  }
  function exportCsv(who) {
    const r = latest() || run(null), q = (v) => { let x = String(v == null ? '' : v); if (/^[=+\-@\t\r]/.test(x)) x = "'" + x; return '"' + x.replace(/"/g, '""') + '"'; };
    const L2 = [['test', 'control', 'exception', 'at', 'by', 'role', 'action', 'target', 'why', 'score', 'decision', 'decided_by', 'note'].join(',')];
    for (const t of r.tests) for (const e of t.exceptions) { const d = disp().get(safeId(e.id)) || {}; L2.push([t.id, t.name, e.id, e.at, e.by, e.role, e.action, e.target, e.why, e.score, d.decision || 'open', d.by || '', d.note || ''].map(q).join(',')); }
    audit(who, 'export', r.id, { rows: L2.length - 1 });
    return { filename: 'control-monitoring-' + r.day + '.csv', csv: '# Continuous control monitoring ' + r.id + ', records ' + r.records + ' from ' + r.window_from + '. Indicators for follow-up, not proof of wrongdoing.\n' + L2.join('\n') + '\n' };
  }

  let timer = null;
  const daily = guardOf(app, 'audit-ccm.daily', () => { const day = riyadh(iso()).day; if (!runs().get('CCM-' + day)) run(null); });
  function start() { if (timer || app.noTimers || opts.noTimer) return; setTimeout(daily, 60000).unref(); timer = setInterval(daily, 3600000); if (timer.unref) timer.unref(); }

  // read-only, for the auditor's dashboard: the latest stored run with its open exceptions - never starts a run
  function summary() {
    const r = latest(); if (!r) return null;
    const open = []; for (const t of r.tests) for (const e of t.exceptions) if (!disp().get(safeId(e.id))) open.push(Object.assign({ name: t.name }, e));
    return { run: r.id, at: r.at, records: r.records, effective: r.summary.effective, exceptions: r.summary.exceptions, not_testable: r.summary.not_testable,
      tests: r.tests.map((t) => ({ id: t.id, name: t.name, status: t.status, exceptions: t.exceptions_total })), open: open.sort((a, b) => b.score - a.score) };
  }
  return { TESTS, trail, summary, run: (who) => { person(who); return run(who); }, runScheduled: () => run(null), view, dispose, draft, accept, discard, exportCsv, aiStatus, start };
}

function registerAuditCcm(srv, app, C) {
  const op = (fn) => (ctx) => { ctx.need('operator'); return fn(ctx); };   // names people and their activity (PDPL): no viewers
  srv.route('GET', '/audit-ccm', op(() => C.view()));
  srv.route('POST', '/audit-ccm/run', op((ctx) => C.run(ctx.who)));
  srv.route('GET', '/audit-ccm/export', op((ctx) => C.exportCsv(ctx.who)));
  srv.route('GET', '/audit-ccm/ai/status', op(() => C.aiStatus()));
  srv.route('POST', '/audit-ccm/exceptions/:id/disposition', op((ctx) => C.dispose(ctx.params.id, ctx.body, ctx.who)));
  srv.route('POST', '/audit-ccm/tests/:id/draft', op((ctx) => C.draft(ctx.params.id, ctx.body, ctx.who)));
  srv.route('POST', '/audit-ccm/drafts/:id/accept', op((ctx) => C.accept(ctx.params.id, ctx.body, ctx.who)));
  srv.route('POST', '/audit-ccm/drafts/:id/discard', op((ctx) => C.discard(ctx.params.id, ctx.body, ctx.who)));
}

module.exports = { createAuditCcm, registerAuditCcm, TESTS, robustZ, median };
