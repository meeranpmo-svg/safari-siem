// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const crypto = require('node:crypto');
const { body, param } = require('./check');
const { guardOf } = require('./errors');
const { isHuman } = require('./approve-scopes');
/*
 * PDPL Control Monitor ({P} = /api/itam, PDPL -> Control Monitor). Continuous tests of the technical and organisational controls
 * the PDPL asks for (Law Art. 19, Implementing Regulation Art. 23: security measures; Art. 18 / IR Art. 19: retention; IR Art. 33:
 * records), run against what this platform already reads - never a questionnaire answer.
 *
 * SYSTEMS that hold personal data = the systems named on processing activities (RoPA records) + the databases where the read-only
 * discovery found personal data. Each is joined to ONE asset in the register by exact name, host name, short host name or IP
 * (case-insensitive). No similarity matching: a system that matches nothing, or more than one asset, says so, and an operator links
 * it by hand (audited). Sensitive = health, credit, biometric, genetic, criminal, religious, beliefs, ethnic or parentage data.
 *
 * TESTS per system (pass | fail | not_measured | na), each with its evidence:
 *   M01 in the asset register          M02 classified confidential or above      M03 confidentiality rated (high when sensitive)
 *   M04 operating system supported     M05 a named owner                          M06-M10 endpoint protection, patching, backup,
 *   vulnerability scan, logs in the SIEM - read from Asset Coverage (engine/asset-coverage.js): weak / missing = fail, an
 *   exemption recorded there = pass (exempt), a tool not connected = not measured (never a pass)
 *   M11 a retention schedule names the system
 * PROGRAMME test P01: staff acknowledged the approved PDPL policies (an acknowledgement campaign at >= 95 %).
 * Score = passes / (passes + fails); not measured is counted apart and says what to connect.
 *
 * RUNS every 6 hours (and on demand) keep a snapshot. A test that passed last run and fails now is DRIFT: listed on the run,
 * written to the audit trail. A failing test can be sent to the GRC register as a remediation action (never twice while open).
 * The trend is a least-squares line over the scores of the last 30 runs.
 * ACKNOWLEDGEMENTS: an administrator or the DPO starts a campaign for one APPROVED policy - the signed GRC register or a GRC draft approved
 * four-eyes, which is how a new PDPL policy gets there (its version is fixed) and
 * the people who must read it; each person acknowledges for themselves (any role, a person, on the campaign, once). Overdue =
 * past the due date without acknowledging.
 * EVIDENCE PACK: the latest run, every test with its evidence, the campaigns, each section and the whole hashed (SHA-256).
 *
 *   GET  /pdpl/monitor                          viewer    score, counts, trend (operators also see systems, tests and drift)
 *   POST /pdpl/monitor/run                      operator  run now                                                   audited
 *   POST /pdpl/monitor/map {system, asset_id | remove}  operator  link a system to its asset                         audited
 *   POST /pdpl/monitor/grc {key}                operator  a failing test -> GRC remediation action                   audited
 *   GET  /pdpl/monitor/pack                     operator  evidence pack                                             audited
 *   GET  /pdpl/monitor/campaigns                operator  campaigns, completion, who is pending
 *   GET  /pdpl/monitor/policies                 operator  policies a campaign may ask for: signed register + approved GRC drafts
 *   POST /pdpl/monitor/campaigns {policy, audience[], due, note?}  admin or the DPO                                  audited
 *   POST /pdpl/monitor/campaigns/:id/close      admin or the DPO                                                    audited
 *   GET  /pdpl/monitor/my                       viewer    the policies I am asked to acknowledge
 *   POST /pdpl/monitor/campaigns/:id/ack {version}  any role, as yourself                                            audited
 */
const DAY = 86400000, EVERY = 6 * 3600000, KEEP = 90;
const SENSITIVE = ['health', 'credit', 'biometric', 'genetic', 'criminal', 'religious', 'beliefs', 'ethnic', 'parentage'];
const CLASS_OK = ['confidential', 'restricted', 'secret', 'top_secret'];
const COVER = [['M06', 'edr', 'Endpoint protection on the host'], ['M07', 'patch', 'Patching current (Endpoint Central)'], ['M08', 'backup', 'Backed up recently'],
  ['M09', 'vuln_scan', 'Scanned for vulnerabilities in 90 days'], ['M10', 'siem_logs', 'Logs reach the SIEM']];
const TESTS = [['M01', 'In the asset register', 'IR Art. 23'], ['M02', 'Classified confidential or above', 'IR Art. 23'], ['M03', 'Confidentiality rated (high when sensitive data)', 'Art. 19'],
  ['M04', 'Operating system supported', 'IR Art. 23'], ['M05', 'A named owner', 'Art. 19']].concat(COVER.map((c) => [c[0], c[2], c[0] === 'M08' ? 'IR Art. 23' : 'Art. 19'])).concat([['M11', 'A retention schedule names the system', 'Art. 18 / IR Art. 19']]);
const TITLE = Object.fromEntries(TESTS.map((t) => [t[0], t[1]])), REF = Object.fromEntries(TESTS.map((t) => [t[0], t[2]]));
// a policy ABOUT personal data - not one that merely lists the PDPL among its frameworks (Regulatory Compliance, Staff Training)
const PDPL_TITLE = /\b(personal data|data protection|privacy|PDPL)\b/i;
const KEY_RE = /^(S-[a-z0-9-]{1,60}:M\d{2}|P01)$/;
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const low = (v) => String(v == null ? '' : v).trim().toLowerCase();
const slug = (v) => low(v).replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 60) || 'x';
const sha = (o) => crypto.createHash('sha256').update(JSON.stringify(o)).digest('hex');

function createPdplMonitor(app, opts = {}) {
  const now = opts.now || Date.now, store = app.store, L = app.log || {};
  const C = (n) => store.collection(n);
  const runs = () => C('pdpl_mon_runs'), maps = () => C('pdpl_mon_map'), camps = () => C('pdpl_mon_campaigns');
  const iso = () => new Date(now()).toISOString();
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role, ip: who.ip || '', action, target, detail }); };
  const recs = (kind) => C('pdpl_records').all((r) => r.kind === kind && !r.retired && r.status !== 'retired');
  const dpo = () => (C('pdpl_records').get('profile') || {}).dpo_user || null;
  let G0 = null; const grc = () => opts.grc || (app.addons && app.addons.grc) || G0 || (G0 = (() => { try { return require('./grc').createGrc(app); } catch (e) { if (L.every) L.every('pdpl-monitor:grc', 3600000, 'warn', 'PDPL monitor: the GRC policy register could not be opened', { err: String(e.message).slice(0, 160) }); return null; } })());
  const coverage = () => opts.coverage || (app.addons && app.addons.assetCoverage) || null;

  // ---- systems holding personal data
  function systems() {
    const by = new Map();
    const add = (name, extra) => {
      const n = String(name || '').trim(); if (!n) return;
      const k = low(n); const s = by.get(k) || { id: 'S-' + slug(n), name: n, ropa: [], categories: [], hosts: [], from: [] };
      if (extra.ropa) s.ropa.push(extra.ropa); if (extra.host && !s.hosts.includes(extra.host)) s.hosts.push(extra.host);
      for (const c of extra.categories || []) if (!s.categories.includes(c)) s.categories.push(c);
      if (!s.from.includes(extra.from)) s.from.push(extra.from); by.set(k, s);
    };
    for (const r of recs('ropa')) for (const n of r.systems || []) add(n, { ropa: r.id, categories: r.data_categories || [], from: 'RoPA' });
    for (const d of C('pdpl_discovery').all((x) => x.id !== '_last' && x.ok)) {
      const cats = [...new Set((d.columns || []).filter((c) => c.confirmed !== false && c.category).map((c) => c.category))];
      if (cats.length) add(d.label || d.host, { host: d.host, categories: cats, from: 'discovery' });
    }
    return [...by.values()].map((s) => Object.assign(s, { sensitive: s.categories.some((c) => SENSITIVE.includes(c)) })).sort((a, b) => a.name.localeCompare(b.name));
  }
  function assetFor(s, assets) {
    const m = maps().get(s.id);
    if (m) { const a = assets.find((x) => x.id === m.asset_id); return a ? { asset: a, how: 'linked by ' + m.by } : { asset: null, why: 'linked to ' + m.asset_id + ', which is no longer in the register' }; }
    const keys = new Set([low(s.name)].concat(s.hosts.map(low)));
    const hit = assets.filter((a) => {
      const names = [a.name, a.hostname, String(a.hostname || '').split('.')[0]].map(low).filter(Boolean);
      const ips = [a.ip].concat(a.ips || []).map(low).filter(Boolean);
      return names.some((n) => keys.has(n)) || ips.some((i) => keys.has(i));
    });
    if (hit.length === 1) return { asset: hit[0], how: 'same name / host / IP' };
    return { asset: null, why: hit.length ? 'matches ' + hit.length + ' assets (' + hit.slice(0, 3).map((a) => a.name || a.id).join(', ') + ') - link the right one' : 'no asset has this name, host name or IP - add it to the register or link it' };
  }

  // ---- tests
  async function evaluate() {
    const assets = C('assets').all((a) => a.status !== 'disposed' && a.status !== 'retired');
    let cov = null, covErr = null;
    const CV = coverage();
    if (CV && typeof CV.view === 'function') { try { cov = await CV.view(); } catch (e) { covErr = String(e.message).slice(0, 160); if (L.every) L.every('pdpl-monitor:coverage', 3600000, 'warn', 'PDPL monitor: asset coverage could not be read', { err: covErr }); } }
    else covErr = 'Asset Coverage is not installed';
    const covBy = new Map(((cov && cov.rows) || []).map((r) => [r.id, r]));
    const retention = recs('retention'), t = now();
    const out = [];
    for (const s of systems()) {
      const m = assetFor(s, assets), a = m.asset, T = {};
      const put = (id, state, evidence) => { T[id] = { state, evidence }; };
      put('M01', a ? 'pass' : 'fail', a ? (a.name || a.id) + ' (' + m.how + ')' : m.why);
      if (!a) { for (const [id] of TESTS.slice(1)) if (id !== 'M11') put(id, 'not_measured', 'no asset to read - link the system first'); }
      else {
        const cl = low(a.classification);
        put('M02', CLASS_OK.includes(cl) ? 'pass' : 'fail', cl ? 'classified ' + cl : 'not classified in the asset register');
        const c = low(a.cia && a.cia.c);
        put('M03', !c ? 'fail' : s.sensitive ? (c === 'high' ? 'pass' : 'fail') : (c === 'high' || c === 'medium' ? 'pass' : 'fail'),
          !c ? 'confidentiality not rated' : 'confidentiality ' + c + (s.sensitive ? ' - sensitive data (' + s.categories.filter((x) => SENSITIVE.includes(x)).join(', ') + ') needs high' : ''));
        const eol = a.eol ? Date.parse(a.eol) : NaN;
        put('M04', isNaN(eol) ? 'not_measured' : eol < t ? 'fail' : 'pass', isNaN(eol) ? 'no end-of-life date in the register (Asset Data Autopilot fills it)' : (eol < t ? 'end of life since ' : 'supported until ') + String(a.eol).slice(0, 10) + (a.os ? ' (' + a.os + ')' : ''));
        put('M05', String(a.owner || '').trim() ? 'pass' : 'fail', String(a.owner || '').trim() ? 'owner ' + a.owner : 'no owner in the register');
        const row = covBy.get(a.id);
        for (const [id, k] of COVER) {
          const ctl = row && row.controls && row.controls[k];
          if (!row) { put(id, 'not_measured', covErr || 'Asset Coverage has no row for this asset'); continue; }
          if (!ctl || ctl.state === 'na') { put(id, 'na', 'does not apply to a ' + (row.type || 'asset')); continue; }
          const st = ctl.state, why = ctl.why || '';
          put(id, st === 'present' || st === 'exempt' ? 'pass' : st === 'not_checked' ? 'not_measured' : 'fail', st + (why ? ': ' + String(why).slice(0, 160) : ''));
        }
      }
      const r = retention.find((x) => (x.systems || []).some((n) => low(n) === low(s.name)));
      put('M11', r ? 'pass' : 'fail', r ? 'retention schedule ' + r.id + ' (' + (r.name || '') + ')' : 'no retention schedule names this system');
      out.push({ id: s.id, name: s.name, sensitive: s.sensitive, categories: s.categories, from: s.from, ropa: s.ropa, asset: a ? { id: a.id, name: a.name || a.id, how: m.how } : null, tests: T });
    }
    // programme: acknowledgements
    const cs = camps().all(), open = cs.filter((c) => c.status === 'open'), last = cs.slice().sort((x, y) => String(y.created_at).localeCompare(String(x.created_at)))[0];
    let p01;
    if (!cs.length) p01 = { state: 'fail', evidence: 'no policy acknowledgement campaign has been run - staff have not confirmed they read the PDPL policies' };
    else {
      const worst = (open.length ? open : [last]).map(campView).sort((x, y) => x.pct - y.pct)[0];
      p01 = worst.pct >= 95 ? { state: 'pass', evidence: worst.policy + ' v' + worst.version + ': ' + worst.pct + '% acknowledged' }
        : worst.overdue_count ? { state: 'fail', evidence: worst.policy + ' v' + worst.version + ': ' + worst.pct + '% acknowledged, ' + worst.overdue_count + ' past ' + worst.due }
        : { state: 'not_measured', evidence: worst.policy + ' v' + worst.version + ': ' + worst.pct + '% so far, due ' + worst.due };
    }
    return { systems: out, programme: { P01: p01 }, coverage_error: covErr };
  }
  function flat(ev) {
    const o = {};
    for (const s of ev.systems) for (const [id, r] of Object.entries(s.tests)) o[s.id + ':' + id] = r.state;
    o.P01 = ev.programme.P01.state; return o;
  }
  function score(states) { const v = Object.values(states), p = v.filter((x) => x === 'pass').length, f = v.filter((x) => x === 'fail').length; return { pass: p, fail: f, not_measured: v.filter((x) => x === 'not_measured').length, score: p + f ? Math.round((100 * p) / (p + f)) : null }; }

  let running = null;
  async function run(who) {
    if (running) return running;
    running = (async () => {
      const ev = await evaluate(), st = flat(ev), sc = score(st);
      const prev = runs().all().sort((a, b) => String(b.at).localeCompare(String(a.at)))[0];
      const drift = [], fixed = [];
      if (prev) for (const [k, v] of Object.entries(st)) { const p = prev.states[k]; if (p === 'pass' && v === 'fail') drift.push(k); if (p === 'fail' && v === 'pass') fixed.push(k); }
      const rec = Object.assign({ id: 'RUN-' + now(), at: iso(), by: who.user, states: st, drift, fixed, systems: ev.systems.length }, sc);
      runs().put(rec);
      const all = runs().all().sort((a, b) => String(b.at).localeCompare(String(a.at)));
      for (const old of all.slice(KEEP)) runs().remove(old.id);
      audit(who, 'pdpl.monitor.run', rec.id, { score: sc.score, pass: sc.pass, fail: sc.fail, not_measured: sc.not_measured, drift: drift.length, fixed: fixed.length });
      if (drift.length) audit(who, 'pdpl.monitor.drift', rec.id, { failing_now: drift.slice(0, 50) });
      return { run: rec, ev };
    })();
    try { return await running; } finally { running = null; }
  }
  function trend() {
    const rs = runs().all().filter((r) => r.score != null).sort((a, b) => String(a.at).localeCompare(String(b.at))).slice(-30);
    const pts = rs.map((r) => ({ at: r.at, score: r.score }));
    if (rs.length < 3) return { points: pts, slope_per_week: null, note: 'a trend needs three runs - ' + rs.length + ' so far' };
    const x = rs.map((r) => Date.parse(r.at) / DAY), y = rs.map((r) => r.score), n = x.length, mx = x.reduce((a, b) => a + b) / n, my = y.reduce((a, b) => a + b) / n;
    const sxx = x.reduce((a, v) => a + (v - mx) ** 2, 0), slope = sxx ? x.reduce((a, v, i) => a + (v - mx) * (y[i] - my), 0) / sxx : 0;
    const lastY = y[n - 1], days = slope > 0 && lastY < 100 ? Math.ceil((100 - lastY) / slope) : null;
    return { points: pts, slope_per_week: Math.round(slope * 7 * 10) / 10, days_to_full: days, note: slope > 0 ? 'improving' : slope < 0 ? 'getting worse' : 'flat' };
  }
  async function view(who) {
    const latest = runs().all().sort((a, b) => String(b.at).localeCompare(String(a.at)))[0] || null;
    const base = { last_run: latest ? { id: latest.id, at: latest.at, by: latest.by, score: latest.score, pass: latest.pass, fail: latest.fail, not_measured: latest.not_measured, drift: latest.drift.length, fixed: latest.fixed.length } : null, trend: trend(),
      tests: TESTS.map((t) => ({ id: t[0], title: t[1], ref: t[2] })).concat([{ id: 'P01', title: 'Staff acknowledged the PDPL policies', ref: 'Art. 19 / IR Art. 23' }]) };
    if (who.role === 'viewer') return base;
    const ev = await evaluate(), st = flat(ev);
    const per = ev.systems.map((s) => Object.assign({}, s, score(Object.fromEntries(Object.entries(s.tests).map(([k, r]) => [k, r.state])))));
    const byTest = base.tests.map((t) => { const v = t.id === 'P01' ? [st.P01] : per.map((s) => s.tests[t.id] && s.tests[t.id].state).filter(Boolean); return Object.assign({}, t, score(Object.fromEntries(v.map((x, i) => [i, x])))); });
    const open = new Set(C('grc_actions').all((a) => a.source === 'pdpl' && String(a.ref || '').startsWith('monitor:') && !['closed', 'done', 'verified', 'cancelled'].includes(a.status)).map((a) => a.ref.slice(8)));
    return Object.assign(base, { now: score(st), systems: per, programme: ev.programme, by_test: byTest, coverage_error: ev.coverage_error, drift: latest ? latest.drift : [], fixed: latest ? latest.fixed : [], in_grc: [...open],
      note: 'Each test reads the platform: the asset register, Asset Coverage (EDR, patching, backup, vulnerability scans, SIEM logs) and the PDPL registers. Not measured means the source is not connected - it is never counted as a pass. Indicators of control operation, not a certificate.' });
  }

  // ---- links, GRC, pack
  function mapSystem(input, who) {
    const b = body(input || {}).str('system', { required: true, max: 70, re: /^S-[a-z0-9-]{1,60}$/, msg: 'system must be a system id (S-...)' }).str('asset_id', { max: 80 }).bool('remove').done();
    if (!systems().some((s) => s.id === b.system)) throw httpErr(404, 'no system ' + b.system + ' holds personal data in the registers');
    if (b.remove) { maps().remove(b.system); audit(who, 'pdpl.monitor.unlink', b.system, {}); return { ok: true, system: b.system, asset_id: null }; }
    if (!b.asset_id) throw httpErr(400, 'asset_id is required (or remove: true)');
    const a = C('assets').get(b.asset_id); if (!a) throw httpErr(400, 'asset_id: no asset ' + b.asset_id + ' in the register');
    maps().put({ id: b.system, asset_id: a.id, by: who.user, at: iso() });
    audit(who, 'pdpl.monitor.link', b.system, { asset_id: a.id, asset: a.name || a.id });
    return { ok: true, system: b.system, asset_id: a.id };
  }
  async function toGrc(input, who) {
    const b = body(input || {}).str('key', { required: true, max: 80, re: KEY_RE, msg: 'key must be <system>:<test> (S-...:Mnn) or P01' }).done();
    const ev = await evaluate(); let r, label;
    if (b.key === 'P01') { r = ev.programme.P01; label = 'Staff acknowledgement of the PDPL policies'; }
    else { const [sid, tid] = b.key.split(':'); const s = ev.systems.find((x) => x.id === sid); r = s && s.tests[tid]; label = s ? s.name + ' - ' + TITLE[tid] : ''; }
    if (!r) throw httpErr(404, 'no test ' + b.key);
    if (r.state !== 'fail') throw httpErr(409, b.key + ' is ' + r.state.replace('_', ' ') + ' - only a failing test becomes an action');
    const G = opts.grcRegisters || (app.addons && app.addons.grcRegisters) || (() => { try { return require('./grc-registers').createGrcRegisters(app); } catch (e) { return null; } })(); if (!G) throw httpErr(424, 'the GRC register is not installed - the action cannot be raised');
    const tid = b.key === 'P01' ? 'P01' : b.key.split(':')[1];
    const act = G.actionCreate({ title: ('PDPL control monitor: ' + label).slice(0, 200), source: 'pdpl', ref: 'monitor:' + b.key, framework: 'PDPL', priority: tid === 'M01' || tid === 'M03' || tid === 'M08' ? 'high' : 'medium',
      due: new Date(now() + 30 * DAY).toISOString().slice(0, 10), description: 'PDPL Control Monitor test ' + b.key + ' (' + (REF[tid] || 'Art. 19') + ') fails: ' + r.evidence + '. It closes on its own evidence: the monitor shows the test passing.' }, who);
    audit(who, 'pdpl.monitor.grc', b.key, { action: act.id });
    return { ok: true, action: act.id };
  }
  async function pack(who) {
    const v = await view(Object.assign({}, who, { role: 'operator' }));
    const sections = { summary: { now: v.now, last_run: v.last_run, trend: v.trend }, systems: v.systems.map((s) => ({ id: s.id, name: s.name, sensitive: s.sensitive, asset: s.asset, tests: s.tests })), programme: v.programme, campaigns: campaigns().items.map((c) => ({ id: c.id, policy: c.policy, version: c.version, due: c.due, audience: c.audience_count, acknowledged: c.acked_count, pct: c.pct })) };
    const hashes = Object.fromEntries(Object.entries(sections).map(([k, x]) => [k, sha(x)]));
    const out = { title: 'PDPL Control Monitor - evidence pack', generated_at: iso(), generated_by: who.user, note: v.note, sections, sha256: hashes, pack_sha256: sha(hashes) };
    audit(who, 'pdpl.monitor.pack', 'evidence-pack', { pack_sha256: out.pack_sha256, systems: sections.systems.length });
    return out;
  }

  // ---- acknowledgement campaigns
  // a campaign asks for an APPROVED policy: one of the signed GRC register, or a GRC draft approved four-eyes (how a new PDPL
  // policy - PDPL -> Policies, PP-01 ... - becomes approved). An unapproved draft is refused: staff acknowledge what was approved.
  function policyOf(id) {
    const G = grc();
    const p = G && typeof G.policy === 'function' ? G.policy(id) : null;
    if (p) return { doc_id: p.doc_id, title: p.title, version: String(p.version || '1'), purpose: p.purpose || '', source: 'register' };
    const d = G && typeof G.draftGet === 'function' ? G.draftGet(id) : null;
    if (d && d.status === 'approved') return { doc_id: d.id, title: d.title, version: String(d.version || '1.0'), purpose: d.purpose || '', source: 'approved draft' + (d.approved_by ? ' (approved by ' + d.approved_by + ')' : '') };
    if (d) throw httpErr(409, 'policy: ' + id + ' is a GRC draft in status "' + d.status + '" - it needs four-eyes approval (GRC Policies) before staff are asked to acknowledge it');
    return null;
  }
  function policyChoices() {
    const G = grc(); const out = [];
    try { for (const d of (G && typeof G.draftList === 'function' ? G.draftList({ status: 'approved' }).items : [])) out.push({ id: d.id, title: d.title, version: String(d.version || '1.0'), source: 'approved draft', pdpl: PDPL_TITLE.test(d.title) || /^PDPL\b/.test(String(d.frameworks || '')) }); }
    catch (e) { if (L.every) L.every('pdpl-monitor:drafts', 3600000, 'warn', 'PDPL monitor: approved GRC drafts could not be listed', { err: String(e.message).slice(0, 160) }); }
    try { for (const p of (G && typeof G.register === 'function' ? G.register({}).items : [])) out.push({ id: p.doc_id, title: p.title, version: String(p.version || '1'), source: 'register', pdpl: PDPL_TITLE.test(p.title) }); }
    catch (e) { if (L.every) L.every('pdpl-monitor:register', 3600000, 'warn', 'PDPL monitor: the GRC register could not be read', { err: String(e.message).slice(0, 160) }); }
    out.sort((a, b) => (b.pdpl - a.pdpl) || (a.source === b.source ? 0 : a.source === 'approved draft' ? -1 : 1));
    return { items: out, has_pdpl_policy: out.some((x) => x.pdpl),
      note: out.some((x) => x.pdpl) ? '' : 'No approved PDPL policy yet. PDPL -> Policies: start the Personal Data Protection Policy (PP-01) from its outline or upload your own, submit it, and a second administrator approves it on GRC Policies - then it can be sent to staff here.' };
  }
  const mayRun = (who) => who.role === 'admin' || (dpo() && low(dpo()) === low(who.user));
  function campView(c) {
    const acked = Object.keys(c.acks || {}), aud = c.audience || [], t = now(), past = Date.parse(c.due + 'T23:59:59Z') < t;
    const pending = aud.filter((u) => !(c.acks || {})[low(u)]);
    return { id: c.id, policy: c.policy, title: c.title, version: c.version, due: c.due, note: c.note || '', status: c.status, created_by: c.created_by, created_at: c.created_at,
      audience_count: aud.length, acked_count: acked.length, pct: aud.length ? Math.round((100 * acked.length) / aud.length) : 0, pending: pending.slice(0, 500), overdue_count: past && c.status === 'open' ? pending.length : 0 };
  }
  function campaigns() { return { items: camps().all().sort((a, b) => String(b.created_at).localeCompare(String(a.created_at))).map(campView) }; }
  function campStart(input, who) {
    const b = body(input || {}).str('policy', { required: true, max: 40, re: /^[A-Za-z0-9._-]{2,40}$/, msg: 'policy must be a GRC register document id' })
      .list('audience', { item: 'str', itemMax: 120, max: 5000, unique: true, required: true }).date('due', { required: true }).str('note', { max: 500 }).done();
    if (!isHuman(who.user)) throw httpErr(403, 'only a person starts an acknowledgement campaign - ' + who.user + ' is a service / AI identity');
    if (!mayRun(who)) throw httpErr(403, 'starting an acknowledgement campaign needs an administrator or the DPO named in the PDPL profile');
    const p = policyOf(b.policy);
    if (!p) throw httpErr(400, 'policy: no policy ' + b.policy + ' in the GRC register or among the approved GRC drafts');
    const aud = [...new Set(b.audience.map((u) => String(u).trim()).filter(Boolean))];
    if (!aud.length) throw httpErr(400, 'audience: name at least one person');
    const bad = aud.find((u) => !isHuman(u) || !/^[A-Za-z0-9._@\\-]{2,120}$/.test(u)); if (bad) throw httpErr(400, 'audience: ' + bad + ' is not a person\'s user name');
    const d = Date.parse(b.due + 'T00:00:00Z'), t = now();
    if (d < t - DAY || d > t + 180 * DAY) throw httpErr(400, 'due must be from today to 180 days ahead');
    const version = p.version;
    if (camps().all((c) => c.status === 'open' && c.policy === p.doc_id && c.version === version).length) throw httpErr(409, 'an open campaign already asks for ' + p.doc_id + ' v' + version);
    const c = { id: 'ACK-' + now(), policy: p.doc_id, title: String(p.title || '').slice(0, 200), version, policy_source: p.source, audience: aud, due: b.due, note: b.note || '', status: 'open', acks: {}, created_by: who.user, created_at: iso() };
    camps().put(c); audit(who, 'pdpl.monitor.campaign.start', c.id, { policy: c.policy, version, audience: aud.length, due: c.due });
    return campView(c);
  }
  function mustCamp(id) { const c = camps().get(id); if (!c) throw httpErr(404, 'no campaign ' + id); return c; }
  function campClose(id, who) {
    if (!isHuman(who.user)) throw httpErr(403, 'only a person closes a campaign');
    if (!mayRun(who)) throw httpErr(403, 'closing a campaign needs an administrator or the DPO');
    const c = mustCamp(id); if (c.status !== 'open') throw httpErr(409, 'campaign ' + id + ' is ' + c.status);
    Object.assign(c, { status: 'closed', closed_by: who.user, closed_at: iso() }); camps().put(c);
    const v = campView(c); audit(who, 'pdpl.monitor.campaign.close', id, { acknowledged: v.acked_count, audience: v.audience_count });
    return v;
  }
  function mine(who) {
    const me = low(who.user);
    return { items: camps().all((c) => c.status === 'open' && (c.audience || []).some((u) => low(u) === me)).map((c) => {
      let p = null; try { p = policyOf(c.policy); } catch (e) { p = null; /* the draft was reopened after the campaign: no text to show, the campaign still names it */ }
      return { id: c.id, policy: c.policy, title: c.title, version: c.version, due: c.due, note: c.note, purpose: p ? String(p.purpose || '').slice(0, 1200) : '', acknowledged_at: (c.acks || {})[me] ? c.acks[me].at : null };
    }) };
  }
  function ack(id, input, who) {
    const b = body(input || {}).str('version', { required: true, max: 20 }).done();
    if (!isHuman(who.user)) throw httpErr(403, 'an acknowledgement is a person\'s own - ' + who.user + ' is a service / AI identity');
    const c = mustCamp(id); if (c.status !== 'open') throw httpErr(409, 'campaign ' + id + ' is ' + c.status);
    const me = low(who.user);
    if (!(c.audience || []).some((u) => low(u) === me)) throw httpErr(403, who.user + ' is not asked to acknowledge ' + c.policy + ' in this campaign');
    if (b.version !== c.version) throw httpErr(409, 'version: the campaign asks for v' + c.version + ' - reload the page');
    if ((c.acks || {})[me]) throw httpErr(409, 'already acknowledged on ' + c.acks[me].at.slice(0, 10));
    c.acks = Object.assign({}, c.acks, { [me]: { at: iso(), ip: who.ip || '' } }); camps().put(c);
    audit(who, 'pdpl.monitor.ack', id, { policy: c.policy, version: c.version });
    return { ok: true, id, policy: c.policy, version: c.version, acknowledged_at: c.acks[me].at };
  }

  let timer = null;
  function start() {
    if (opts.noTimer || timer) return;
    const tick = guardOf(app, 'pdpl.monitor.run', async () => {
      try { await run({ user: 'system:pdpl-monitor', role: 'system', ip: '' }); } finally { timer = setTimeout(tick, EVERY); if (timer.unref) timer.unref(); }
    });
    timer = setTimeout(tick, 120000); if (timer.unref) timer.unref();
  }
  return { view, run, mapSystem, toGrc, pack, campaigns, policyChoices, campStart, campClose, mine, ack, start, _evaluate: evaluate };
}

function registerPdplMonitor(srv, app, M) {
  const W = (ctx) => ({ user: ctx.who.user, role: ctx.who.role, ip: ctx.who.ip });
  srv.route('GET', '/pdpl/monitor', (ctx) => { ctx.need('viewer'); return M.view(W(ctx)); });
  srv.route('POST', '/pdpl/monitor/run', async (ctx) => { ctx.need('operator'); const r = await M.run(W(ctx)); return { ok: true, run: r.run }; });
  srv.route('POST', '/pdpl/monitor/map', (ctx) => { ctx.need('operator'); return M.mapSystem(ctx.body, W(ctx)); }, { maxBody: 2048 });
  srv.route('POST', '/pdpl/monitor/grc', (ctx) => { ctx.need('operator'); return M.toGrc(ctx.body, W(ctx)); }, { maxBody: 1024 });
  srv.route('GET', '/pdpl/monitor/pack', (ctx) => { ctx.need('operator'); return M.pack(W(ctx)); });
  srv.route('GET', '/pdpl/monitor/campaigns', (ctx) => { ctx.need('operator'); return M.campaigns(); });
  srv.route('GET', '/pdpl/monitor/policies', (ctx) => { ctx.need('operator'); return M.policyChoices(); });
  srv.route('POST', '/pdpl/monitor/campaigns', (ctx) => { ctx.need('operator'); return M.campStart(ctx.body, W(ctx)); }, { maxBody: 262144 });
  srv.route('POST', '/pdpl/monitor/campaigns/:id/close', (ctx) => { ctx.need('operator'); return M.campClose(param(ctx.params.id, 'id'), W(ctx)); });
  srv.route('GET', '/pdpl/monitor/my', (ctx) => { ctx.need('viewer'); return M.mine(W(ctx)); });
  srv.route('POST', '/pdpl/monitor/campaigns/:id/ack', (ctx) => { ctx.need('viewer'); return M.ack(param(ctx.params.id, 'id'), ctx.body, W(ctx)); },
    { maxBody: 1024, anyRole: 'every employee acknowledges for themselves; ack checks the person is on the campaign' });
}

module.exports = { createPdplMonitor, registerPdplMonitor, SENSITIVE };
