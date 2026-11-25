// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('./brand');
const { guardOf } = require('./errors');
/*
 * AI CISO ({P} = /api/itam): the executive layer over the platform. It does not collect anything new - it pulls what
 * the modules already hold, in one pass, and turns it into what a CISO / BISO reads:
 *   posture    six domains, each 0-100 with every point itemised (governance, SAMA CSF, detection & response,
 *              exposure, resilience, operations). An input the platform does not hold is "not measured" and is left
 *              out - never assumed to be fine. The overall score is withheld until 3 domains are measured.
 *   risks      a register built from real records only (open critical/high work items of the 8 AI engineers, SAMA
 *              gaps, failing GRC controls, overdue or failed DR drills, cases breaching their SLA), each with its source
 *   decisions  what is waiting for a person: change plans awaiting approval, items that need a human, SOC response
 *              approvals, drills to sign off, policies past review
 *   team       the 8 AI engineers (6 in the SIEM, 2 here): open work, critical, last patrol, late
 *   brief      a board brief written by the AI from the above ONLY; every claim cites a record id from the context and
 *              unknown ids are stripped. With no AI configured (or on any AI error) a rule-based brief is produced and
 *              labelled as such. Never executes anything - it recommends, people decide.
 * Sources: this engine (GRC + drills, duty desk, pentest) and the SIEM over the existing discovery.siem link
 * (/duty/*, /metrics, /compliance/sama, /approvals). A source that cannot be read is shown as such.
 * Routes:
 * Runs on its own (operational, not only when someone opens the page): every working morning (Sun-Thu, Riyadh) at
 * ciso.brief_hour (default 7) it writes the board brief, and once an hour it records the posture (ciso_history, one row
 * per day, 400 days) so the page shows the trend. ciso.enabled=false stops the timer; the page still works on demand.
 *   GET  /ciso/overview[?refresh=1] · /ciso/briefs · /ciso/briefs/:id · /ciso/status · /ciso/history · /ciso/insights   viewer
 *   POST /ciso/patrol   run every AI engineer now (both engines)              operator
 *   POST /ciso/brief    write a board brief                                   operator
 */
const fs = require('fs');
const http = require('http');
const https = require('https');
const crypto = require('crypto');
const { sanitisePair } = require('./ai/sanitise');
// the masking by Python too when it answers identically (engine/ai/guard-py.js, migration step 9j-a); otherwise sanitise.js
const guardSanitise = async (app, system, prompt, terms) => { try { return await require('./ai/guard-py').guardFor(app.config).sanitisePair(system, prompt, terms); } catch (e) { return sanitisePair(system, prompt, terms); } };
const { extractJson } = require('./ai/validate');

const SEV = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
const TERMINAL = new Set(['resolved', 'closed']);
const ENGINEER_PAGE = { network: 'network-engineer.html', security: 'ai-security-engineer.html', windows: 'windows-admin.html',
  exchange: 'exchange-admin.html', pentest: 'pentest.html', desktop: 'desk-support.html', dba: 'ai-dba.html', sqldba: 'ai-sql-dba.html', apps: 'ai-app-manager.html', grc: 'ai-grc-consultant.html', siem: 'log-assurance.html', virt: 'ai-virt-admin.html' };
const DOMAINS = [
  { id: 'governance', name: 'Governance & policy', weight: 15, page: 'grc-policies.html' },
  { id: 'compliance', name: 'SAMA CSF compliance', weight: 20, page: 'sama-compliance.html' },
  { id: 'detection', name: 'Detection & response', weight: 20, page: 'soc-tickets.html' },
  { id: 'exposure', name: 'Exposure & vulnerabilities', weight: 20, page: 'pentest.html' },
  { id: 'resilience', name: 'Resilience (DR / BCM)', weight: 15, page: 'dr-drills.html' },
  { id: 'operations', name: 'Security operations hygiene', weight: 10, page: 'ai-team.html' },
];
const MIN_DOMAINS = 3;
const clip = (s, n) => String(s == null ? '' : s).replace(/\s+/g, ' ').trim().slice(0, n);
const riyadhDay = (t) => new Date(t + 3 * 3600000).toISOString().slice(0, 10);
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });

function createCiso(app, opts = {}) {
  const store = app.store, now = opts.now || Date.now, log = app.log || { info() {}, warn() {}, error() {} };
  const briefCol = store.collection('ciso_briefs'), histCol = store.collection('ciso_history');
  const RUN = { timer: null, last_tick: null, last_error: null, last_snapshot: 0, auto_briefs: 0 };
  const cfg = (app.config && app.config.ciso) || {};
  const sc = ((app.config && app.config.discovery) || {}).siem || {};
  // the compliance domain follows the organisation's frameworks (brand modules_off): SAMA CSF where it applies, otherwise
  // NCA ECC (the platform's register) and Aramco CCC - an organisation is never scored on a framework it is not under
  const SAMA = !!cfg.all_frameworks || !new Set(ZYB_ORG.modules_off || []).has('fw-sama');
  const DOM = DOMAINS.map((d) => (d.id === 'compliance' && !SAMA ? Object.assign({}, d, { name: 'Regulatory compliance (NCA ECC · Aramco CCC)', page: 'nca-ecc.html' }) : d));
  const base = String(sc.base_url || 'http://127.0.0.1:9120').replace(/\/+$/, ''), prefix = sc.prefix || '/api/soc';
  let G = null; const grc = () => G || (G = (app.addons && app.addons.grc) || require('./grc').createGrc(app));
  let cache = null;

  function secret() {
    if (!sc.secret_file) throw Object.assign(new Error('SIEM link not configured (discovery.siem.secret_file)'), { notConnected: true });
    const txt = String((opts.readFile || ((p) => fs.readFileSync(p, 'utf8')))(sc.secret_file)).trim();
    let v = txt; if (txt.startsWith('{')) { try { v = String(JSON.parse(txt).proxy_secret || ''); } catch { v = ''; } }
    if (v.length < 16) throw Object.assign(new Error('SIEM proxy secret missing'), { notConnected: true });
    return v;
  }
  // who = the signed-in person for actions (the SIEM checks the role itself); reads go as a system viewer
  function siem(method, path, body, who) {
    if (opts.siem) return opts.siem(method, path, body, who);
    return new Promise((ok, bad) => {
      let s; try { s = secret(); } catch (e) { bad(e); return; }
      const u = new URL(base + prefix + path), data = body ? JSON.stringify(body) : null, lib = u.protocol === 'https:' ? https : http;
      const headers = { 'X-Sentra-Proxy-Secret': s, 'X-Auth-User': (who && who.user) || 'system:itam-ciso', 'X-Auth-Role': (who && who.role) || 'viewer' };
      if (data) { headers['Content-Type'] = 'application/json'; headers['Content-Length'] = Buffer.byteLength(data); }
      const r = lib.request(u, { method, headers, timeout: 20000 }, (res) => {
        let buf = ''; res.on('data', (c) => { buf += c; if (buf.length > 8e6) r.destroy(new Error('SIEM answer too large')); });
        res.on('end', () => { let j = null; try { j = JSON.parse(buf); } catch { j = null; }
          if (res.statusCode !== 200) return bad(new Error('SIEM ' + path + ': HTTP ' + res.statusCode + (j && j.error ? ' ' + clip(j.error, 120) : '')));
          if (!j) return bad(new Error('SIEM ' + path + ': not JSON')); ok(j); });
      });
      r.on('timeout', () => r.destroy(new Error('SIEM ' + path + ': timeout'))); r.on('error', bad);
      if (data) r.write(data); r.end();
    });
  }
  async function source(id, name, fn) {
    try { const d = await fn(); return d == null ? { id, name, state: 'not_connected' } : { id, name, state: 'live', data: d }; }
    catch (e) { return { id, name, state: e.notConnected ? 'not_connected' : 'error', error: clip(e.message, 200) }; }
  }

  async function collect() {
    const list = await Promise.all([
      source('grc', 'GRC policy register', () => grc().summary()),
      source('drills', 'DR & BCM drills', () => ({ summary: grc().drillSummary(), systems: grc().drillSystems() })),
      source('itam_duty', 'AI engineers (IT Asset Management)', () => app.duty ? { engineers: app.duty.engineers(), items: app.duty.list({ status: 'open', limit: 500 }).items } : null),
      source('ownership', 'Asset ownership', () => app.addons && app.addons.ownership ? app.addons.ownership.summary() : null),
      source('pentest', 'Attack surface (pentest)', () => app.addons && app.addons.pentest ? app.addons.pentest.assessment().summary : null),
      source('siem_duty', 'AI engineers (SIEM)', async () => { const [e, i] = await Promise.all([siem('GET', '/duty/engineers'), siem('GET', '/duty/items?status=open&limit=500')]); return { engineers: e.engineers || [], items: i.items || [] }; }),
      source('soc', 'SOC metrics (30 days)', () => siem('GET', '/metrics')),
      SAMA ? source('sama', 'SAMA CSF coverage', () => siem('GET', '/compliance/sama')) : null,
      SAMA ? null : source('nca', 'NCA ECC register', async () => { const N = app.addons && app.addons.ncaEcc; if (!N) return null; const v = await N.view(); return v && v.score != null ? { score: v.score, counts: v.counts, nca: v.nca } : null; }),
      SAMA ? null : source('aramco', 'Aramco CCC readiness', () => { const X = app.addons && app.addons.aramcoCcc; if (!X) return null; const v = X.view({ user: 'system:ciso', role: 'viewer' }); return v.controls_total && v.score != null ? { score: v.score, assessed: v.assessed, applicable: v.applicable, stages_done: (v.stages || []).filter((x) => x.done).length, stages: (v.stages || []).length, days_left: v.days_left == null ? null : v.days_left } : null; }),
      source('approvals', 'SOC response approvals', async () => (await siem('GET', '/approvals?status=pending')).items || []),
      source('logflow', 'Log-flow assurance (SIEM)', async () => { const a = await siem('GET', '/collection/assurance'); return { summary: a.summary, inventory: a.inventory, collector: a.collector, unknown_senders: (a.unknown_senders || []).length }; }),
    ]);
    const S = {}; for (const s of list.filter(Boolean)) S[s.id] = s;
    return S;
  }
  const live = (S, id) => (S[id] && S[id].state === 'live' ? S[id].data : null);

  /* ---- posture: every point itemised; an input not held is not measured (never a free pass) */
  function domain(id, items, measured, why) {
    const d = DOM.find((x) => x.id === id);
    const pts = items.reduce((a, x) => a + x.points, 0);
    return { id, name: d.name, weight: d.weight, page: d.page, measured, score: measured ? Math.max(0, Math.min(100, 100 + pts)) : null,
      items, not_measured_why: measured ? null : why };
  }
  const cap = (v, max) => -Math.min(max, v);
  function posture(S) {
    const out = [];
    const g = live(S, 'grc');
    if (g) {
      const it = [];
      if (g.reviews.overdue) it.push({ label: g.reviews.overdue + ' policies past their review date', points: cap(5 * g.reviews.overdue, 30) });
      const cs = Object.entries(g.control_status || {});
      const fail = cs.filter(([, v]) => v && (v.state || v.status) === 'fail'), part = cs.filter(([, v]) => v && (v.state || v.status) === 'partial'), unk = cs.filter(([, v]) => v && (v.state || v.status) === 'unknown');
      if (fail.length) it.push({ label: fail.length + ' automated controls failing (' + fail.map(([k]) => k).slice(0, 6).join(', ') + ')', points: cap(10 * fail.length, 40) });
      if (part.length) it.push({ label: part.length + ' automated controls partial (' + part.map(([k]) => k).slice(0, 6).join(', ') + ')', points: cap(4 * part.length, 20) });
      if (unk.length) it.push({ label: unk.length + ' controls without a data source - not scored', points: 0 });
      const ow = live(S, 'ownership');
      if (ow && ow.assets) {
        if (ow.missing_business) it.push({ label: ow.missing_business + ' of ' + ow.assets + ' assets without a business owner', points: cap(Math.ceil(ow.missing_business / ow.assets * 20), 20) });
        if (ow.missing_it) it.push({ label: ow.missing_it + ' of ' + ow.assets + ' assets without an IT owner', points: cap(Math.ceil(ow.missing_it / ow.assets * 10), 10) });
      }
      if (!it.length) it.push({ label: 'all policies in review cycle, no failing controls', points: 0 });
      out.push(domain('governance', it, true));
    } else out.push(domain('governance', [], false, 'GRC register not readable'));

    const sm = live(S, 'sama');
    if (sm && sm.summary && sm.summary.coverage_pct != null) {
      const c = sm.summary.counts || {};
      out.push(domain('compliance', [{ label: 'SAMA CSF coverage ' + sm.summary.coverage_pct + '% (' + (c.covered || 0) + ' covered, ' + (c.partial || 0) + ' partial, ' + (c.gap || 0) + ' gap)', points: Math.round(sm.summary.coverage_pct) - 100 }], true));
    } else if (SAMA) out.push(domain('compliance', [], false, S.sama && S.sama.error ? S.sama.error : 'SAMA coverage not available from the SIEM'));
    else {
      // NCA ECC and Aramco CCC: each framework held is one item, the domain score is their mean (never a free pass for one not held)
      const nc = live(S, 'nca'), ac = live(S, 'aramco'), it = [];
      if (nc) it.push({ label: 'NCA ECC register ' + nc.score + '% (indicative, from the register)', points: Math.round(nc.score) - 100 });
      if (ac) it.push({ label: 'Aramco CCC readiness ' + ac.score + '% (' + ac.assessed + ' of ' + ac.applicable + ' controls assessed)', points: Math.round(ac.score) - 100 });
      if (it.length) out.push(domain('compliance', it.length === 2 ? it.map((x) => Object.assign({}, x, { points: Math.round(x.points / 2) })) : it, true));
      else out.push(domain('compliance', [], false, 'neither the NCA ECC register nor Aramco CCC is assessed yet'));
    }

    const m = live(S, 'soc');
    if (m) {
      const o = m.open_by_severity || {}, it = [];
      const crit = Number(o[4] || 0), high = Number(o[3] || 0);
      if (crit) it.push({ label: crit + ' open critical alerts', points: cap(6 * crit, 30) });
      if (high) it.push({ label: high + ' open high alerts', points: cap(2 * high, 20) });
      const br = ((m.sla || {}).breaching_now || []).length;
      if (br) it.push({ label: br + ' cases breaching their SLA now', points: cap(5 * br, 30) });
      const rc = (m.sla || {}).resolve_compliance_pct;
      if (rc != null && rc < 90) it.push({ label: 'resolve SLA compliance ' + rc + '% (target 90%)', points: cap(Math.round(90 - rc), 20) });
      logflowItems(S, it);
      if (!it.length) it.push({ label: 'no open critical/high alerts, SLAs met', points: 0 });
      out.push(domain('detection', it, true));
    } else {
      // without SOC metrics the domain is still measured when log-flow assurance answers (what the SOC can see at all)
      const it = []; logflowItems(S, it);
      out.push(it.length ? domain('detection', it, true) : domain('detection', [], false, S.soc && S.soc.error ? S.soc.error : 'SOC metrics not available'));
    }

    const p = live(S, 'pentest');
    if (p && p.assets) {
      const b = p.by_severity || {}, it = [];
      if (b.critical) it.push({ label: b.critical + ' critical exposures', points: cap(15 * b.critical, 45) });
      if (b.high) it.push({ label: b.high + ' high exposures', points: cap(5 * b.high, 30) });
      if (b.medium) it.push({ label: b.medium + ' medium exposures', points: cap(b.medium, 10) });
      if (p.exposed_assets) it.push({ label: p.exposed_assets + ' internet-facing assets with findings', points: cap(3 * p.exposed_assets, 15) });
      if (!it.length) it.push({ label: p.assets + ' assets assessed, no medium-or-worse exposure', points: 0 });
      out.push(domain('exposure', it, true));
    } else out.push(domain('exposure', [], false, 'no assets assessed by the AI Penetration Testing Engineer yet'));

    const dr = live(S, 'drills');
    if (dr && (dr.summary.total || dr.systems.length)) {
      const s = dr.summary, it = [];
      const od = dr.systems.filter((x) => x.overdue);
      if (od.length) it.push({ label: od.length + ' systems overdue for a recovery test (' + od.map((x) => x.system).slice(0, 5).join(', ') + ')', points: cap(10 * od.length, 40) });
      const fails = (s.by_result || {}).fail || 0; if (fails) it.push({ label: fails + ' drills failed', points: cap(15 * fails, 30) });
      if (s.rto && s.rto.pct != null && s.rto.pct < 100) it.push({ label: 'RTO met in ' + s.rto.pct + '% of measured drills', points: cap(Math.round((100 - s.rto.pct) / 4), 25) });
      const aw = s.awaiting_signoff || 0; if (aw) it.push({ label: aw + ' completed drills not signed off', points: cap(3 * aw, 15) });
      if (!it.length) it.push({ label: 'all systems tested within their cycle', points: 0 });
      out.push(domain('resilience', it, true));
    } else out.push(domain('resilience', [], false, 'no DR drills recorded - SAMA expects documented recovery tests'));

    const items = allItems(S);
    if (live(S, 'itam_duty') || live(S, 'siem_duty')) {
      const it = [], c = items.filter((x) => x.severity === 'critical').length, h = items.filter((x) => x.severity === 'high').length;
      const stale = items.filter((x) => (x.status === 'needs-human' || x.status === 'diagnosed') && now() - (x.detected_at || now()) > 3 * 86400000).length;
      if (c) it.push({ label: c + ' critical work items open across the AI engineers', points: cap(10 * c, 40) });
      if (h) it.push({ label: h + ' high work items open', points: cap(3 * h, 30) });
      if (stale) it.push({ label: stale + ' items waiting for a person more than 3 days', points: cap(2 * stale, 20) });
      if (!it.length) it.push({ label: 'no critical/high work open', points: 0 });
      out.push(domain('operations', it, true));
    } else out.push(domain('operations', [], false, 'no AI engineer reachable'));

    const measured = out.filter((d) => d.measured);
    const w = measured.reduce((a, d) => a + d.weight, 0);
    const overall = measured.length >= MIN_DOMAINS ? Math.round(measured.reduce((a, d) => a + d.score * d.weight, 0) / w) : null;
    return { overall, grade: overall == null ? null : overall >= 85 ? 'strong' : overall >= 70 ? 'adequate' : overall >= 50 ? 'weak' : 'critical',
      measured: measured.length, of: out.length, withheld_why: overall == null ? `only ${measured.length} of ${out.length} domains measured (need ${MIN_DOMAINS})` : null, domains: out };
  }

  function allItems(S) {
    const a = (live(S, 'itam_duty') || {}).items || [], b = (live(S, 'siem_duty') || {}).items || [];
    // the GRC consultant's items restate gaps this engine already scores from the GRC records itself (governance,
    // compliance, resilience): counting them again as operations work would score one gap twice
    return a.map((x) => Object.assign({ engine: 'itam' }, x)).concat(b.map((x) => Object.assign({ engine: 'siem' }, x))).filter((x) => !TERMINAL.has(x.status) && x.engineer !== 'grc');
  }

  // detection is only as good as the logs that reach it: assets that should log and do not are blind spots
  function logflowItems(S, it) {
    const lf = live(S, 'logflow'); if (!lf || !lf.summary) return;
    const s = lf.summary;
    if (lf.collector && lf.collector.quiet) it.push({ label: 'SIEM receiving no logs at all', points: 40 });
    if (s.coverage_pct != null && s.coverage_pct < 95) it.push({ label: 'log coverage ' + s.coverage_pct + '% of ' + s.required + ' assets that must log (target 95%)', points: cap(Math.round(95 - s.coverage_pct), 25) });
    if (s.silent) it.push({ label: s.silent + ' assets stopped sending logs', points: cap(3 * s.silent, 15) });
  }

  /* ---- risk register: records only, each with its source and a link */
  function risks(S) {
    const r = [];
    for (const x of allItems(S)) if (SEV[x.severity] >= 3) r.push({ ref: 'duty:' + x.id, severity: x.severity, domain: x.engineer === 'pentest' ? 'exposure' : x.engineer === 'apps' || x.engineer === 'virt' ? 'resilience' : x.engineer === 'siem' ? 'detection' : 'operations',
      title: clip(x.title, 160), source: 'AI ' + x.engineer + ' engineer', status: x.status, owner: x.owner || '', site: x.site || (x.target && x.target.site) || '',
      age_h: x.detected_at ? Math.round((now() - x.detected_at) / 3600000) : null, link: (ENGINEER_PAGE[x.engineer] || 'ai-team.html') });
    const sm = live(S, 'sama');
    if (sm && sm.controls) for (const c of sm.controls.filter((x) => x.status === 'gap').slice(0, 15)) r.push({ ref: 'sama:' + c.id, severity: 'high', domain: 'compliance',
      title: 'SAMA CSF ' + c.id + ' ' + clip(c.title, 100) + ' - gap', source: 'SAMA CSF coverage', status: 'gap', owner: c.owner || '', link: 'sama-compliance.html' });
    const g = live(S, 'grc');
    if (g) for (const [k, v] of Object.entries(g.control_status || {})) if (v && (v.state || v.status) === 'fail') r.push({ ref: 'grc:' + k, severity: 'high', domain: 'governance',
      title: 'Control "' + k + '" failing' + (v.detail ? ': ' + clip(v.detail, 120) : ''), source: 'GRC control automation', status: 'fail', link: 'grc-policies.html' });
    const ow = live(S, 'ownership');
    if (ow && ow.assets && (ow.missing_business || ow.missing_it)) r.push({ ref: 'ownership:coverage', severity: ow.business_pct != null && ow.business_pct < 50 ? 'high' : 'medium', domain: 'governance',
      title: (ow.missing_business ? ow.missing_business + ' assets without a business owner' : '') + (ow.missing_business && ow.missing_it ? ', ' : '') + (ow.missing_it ? ow.missing_it + ' without an IT owner' : ''), source: 'Asset ownership', status: 'unassigned', link: 'asset-ownership.html' });
    const dr = live(S, 'drills');
    if (dr) {
      for (const s of dr.systems.filter((x) => x.overdue)) r.push({ ref: 'drill-system:' + s.system, severity: s.last_result === 'fail' ? 'critical' : 'high', domain: 'resilience',
        title: s.system + ': recovery test ' + (s.last ? 'overdue (last ' + clip(s.last.executed, 10) + ')' : 'never performed'), source: 'DR & BCM drills', status: 'overdue', link: 'dr-drills.html' });
    }
    const m = live(S, 'soc');
    if (m) for (const c of ((m.sla || {}).breaching_now || []).slice(0, 15)) r.push({ ref: 'case:' + c.id, severity: Number(c.severity) >= 4 ? 'critical' : 'high', domain: 'detection',
      title: 'Case ' + c.id + ' breaching SLA: ' + clip(c.title, 120), source: 'SOC cases', status: c.resolve_breached ? 'resolve SLA breached' : 'ack SLA breached', link: 'soc-tickets.html' });
    r.sort((a, b) => SEV[b.severity] - SEV[a.severity] || (b.age_h || 0) - (a.age_h || 0));
    return r;
  }

  function decisions(S) {
    const d = [];
    for (const x of allItems(S)) {
      if (x.status === 'awaiting-approval') d.push({ ref: 'duty:' + x.id, kind: 'approve-change', who: 'operator / admin (not the requester)', severity: x.severity, title: clip(x.title, 140), from: 'AI ' + x.engineer + ' engineer', link: ENGINEER_PAGE[x.engineer] || 'ai-team.html' });
      else if (x.status === 'needs-human' && SEV[x.severity] >= 2) d.push({ ref: 'duty:' + x.id, kind: 'needs-a-person', who: 'operator', severity: x.severity, title: clip(x.title, 140), from: 'AI ' + x.engineer + ' engineer', link: ENGINEER_PAGE[x.engineer] || 'ai-team.html' });
    }
    for (const a of (live(S, 'approvals') || [])) d.push({ ref: 'approval:' + a.id, kind: 'approve-response', who: 'admin', severity: 'high', title: clip(a.title || a.action_id || 'response action', 140) + (a.case_id ? ' (case ' + a.case_id + ')' : ''), from: 'SOC response', link: 'soc-response.html' });
    const dr = live(S, 'drills');
    if (dr && dr.summary.awaiting_signoff) d.push({ ref: 'drills:signoff', kind: 'sign-off', who: 'admin (independent of who ran it)', severity: 'medium', title: dr.summary.awaiting_signoff + ' completed DR drills awaiting sign-off', from: 'DR & BCM drills', link: 'dr-drills.html' });
    const g = live(S, 'grc');
    if (g && g.reviews.overdue) d.push({ ref: 'grc:reviews', kind: 'policy-review', who: 'admin', severity: 'medium', title: g.reviews.overdue + ' policies past their review date', from: 'GRC policy register', link: 'grc-policies.html' });
    d.sort((a, b) => SEV[b.severity] - SEV[a.severity]);
    return d;
  }

  function team(S) {
    const t = [];
    for (const [eng, sid] of [['itam', 'itam_duty'], ['siem', 'siem_duty']]) {
      const s = S[sid];
      if (!s || s.state !== 'live') { t.push({ engine: eng, state: s ? s.state : 'not_connected', error: s && s.error }); continue; }
      for (const e of s.data.engineers) t.push({ engine: eng, state: 'live', id: e.id, name: e.name, open: e.open, critical: e.critical, high: e.high,
        last_patrol: e.last_patrol, late: e.late, last_error: e.last_error, not_connected: e.not_connected, by_status: e.by_status || {}, resolved_24h: e.resolved_24h, link: ENGINEER_PAGE[e.id] || 'ai-team.html' });
    }
    return t;
  }

  // BISO view: the same risks grouped by where they sit - a site only when the record names one (never guessed)
  function byArea(rs) {
    const dom = {}, site = {};
    for (const x of rs) {
      const d = dom[x.domain] = dom[x.domain] || { domain: x.domain, name: (DOM.find((z) => z.id === x.domain) || {}).name || x.domain, critical: 0, high: 0, total: 0 };
      d.total++; if (x.severity === 'critical') d.critical++; else if (x.severity === 'high') d.high++;
      const k = x.site || '(no site recorded)'; const s = site[k] = site[k] || { site: k, critical: 0, high: 0, total: 0 };
      s.total++; if (x.severity === 'critical') s.critical++; else if (x.severity === 'high') s.high++;
    }
    const order = (a, b) => b.critical - a.critical || b.high - a.high || b.total - a.total;
    return { by_domain: Object.values(dom).sort(order), by_site: Object.values(site).sort(order) };
  }

  /* overview: fresh for 30 s; up to 15 min old it is answered at once (stale:true, with its age) while ONE background refresh
     reads the sources again - the page no longer waits on every SIEM call. Concurrent callers share one collection. */
  let inflight = null;
  function refreshNow() {
    if (!inflight) inflight = compute().catch((e) => { log.warn('ciso: overview refresh failed', { err: clip(e && e.message, 200) }); throw e; }).finally(() => { inflight = null; });
    return inflight;
  }
  async function overview(force) {
    const age = cache ? now() - cache.at : Infinity;
    if (!force && age < 30000) return Object.assign(cache.v, { stale: false, age_s: Math.round(age / 1000) });
    if (!force && age < 15 * 60000) { refreshNow().catch(() => { /* logged in refreshNow; the cached answer stands */ }); return Object.assign(cache.v, { stale: true, age_s: Math.round(age / 1000) }); }
    return refreshNow();
  }
  async function compute() {
    const S = await collect();
    const rs = risks(S);
    const v = { generated: now(), sources: Object.values(S).map((s) => ({ id: s.id, name: s.name, state: s.state, error: s.error || null })),
      posture: posture(S), risks: rs.slice(0, 150), risks_total: rs.length, decisions: decisions(S), team: team(S), areas: byArea(rs),
      soc: (() => { const m = live(S, 'soc'); return m ? { mttd_s: m.mttd_s, mttr_s: m.mttr_s, open_by_severity: m.open_by_severity, alerts_by_day: Array.isArray(m.alerts_by_day) ? m.alerts_by_day.slice(-60) : [], sla: m.sla ? { ack_compliance_pct: m.sla.ack_compliance_pct, resolve_compliance_pct: m.sla.resolve_compliance_pct, breaching_now: (m.sla.breaching_now || []).length, at_risk: m.sla.at_risk } : null } : null; })(),
      compliance: (() => { const sm = live(S, 'sama'), g = live(S, 'grc'), dr = live(S, 'drills');
        const nc = live(S, 'nca'), ac = live(S, 'aramco');
        return { sama: sm && sm.summary ? { coverage_pct: sm.summary.coverage_pct, counts: sm.summary.counts, by_domain: sm.summary.by_domain } : null,
          frameworks: SAMA ? ['sama'] : ['nca', 'aramco'], nca: nc ? { score: nc.score, counts: nc.counts } : null, aramco: ac || null,
          grc: g ? { policies: g.total, overdue: g.reviews.overdue, attested: g.attested, by_cls: g.by_cls } : null,
          drills: dr ? { total: dr.summary.total, systems: dr.systems.length, overdue: dr.systems.filter((x) => x.overdue).length, rto: dr.summary.rto, rpo: dr.summary.rpo, by_result: dr.summary.by_result, awaiting_signoff: dr.summary.awaiting_signoff } : null }; })(),
      last_brief: (() => { const b = latestBrief(); return b ? { id: b.id, at: b.at, kind: b.kind, headline: b.headline } : null; })() };
    cache = { at: now(), v };
    try { snapshot(v); } catch (e) { log.warn('ciso: history snapshot failed', { err: e.message }); }
    v.trend = history(90); v.stale = false; v.age_s = 0;
    return v;
  }

  /* ---- insights for the CISO dashboard (pyengine/ciso_insights_rules.py): posture forecast, domain movers, alert anomaly */
  let pyE = null;
  const py = () => opts.py || pyE || (pyE = require('./pyengine').createPyEngine({ python: opts.python || ((app.config && app.config.discovery) || {}).python_bin || undefined, timeoutMs: 30000, resident: false }));
  async function insights() {
    const v = await overview(false);
    const r = await py().call('ciso.insights', { history: history(90), domains: (v.posture.domains || []).map((d) => ({ id: d.id, name: d.name, score: d.score })),
      alerts_by_day: (v.soc && v.soc.alerts_by_day) || [], open_by_severity: (v.soc && v.soc.open_by_severity) || {}, now: now() });
    if (!r || r.ok === false) { log.warn('ciso: insights (Python) did not answer', { err: clip(r && r.error, 200) }); throw Object.assign(new Error('the CISO insights run in Python and Python did not answer - run the update so pyengine is installed'), { status: 409 }); }
    delete r.ok; return r;
  }
  /* ---- posture history (one row per Riyadh day, the latest of the day wins) */
  function snapshot(v) {
    const t = now(), day = riyadhDay(t), dom = {};
    for (const d of v.posture.domains) dom[d.id] = d.score;
    histCol.put({ id: day, day, at: t, overall: v.posture.overall, grade: v.posture.grade, measured: v.posture.measured, domains: dom,
      risks: v.risks_total, critical: v.risks.filter((r) => r.severity === 'critical').length, decisions: v.decisions.length });
    RUN.last_snapshot = t;
    const old = histCol.all().sort((a, b) => b.at - a.at).slice(400); for (const o of old) { try { histCol.remove(o.id); } catch (e) { /* keep */ } }
  }
  function history(days) { return histCol.all().sort((a, b) => a.at - b.at).slice(-Math.min(Number(days) || 30, 400)); }

  /* ---- the AI CISO's own day: posture every hour, the board brief every working morning */
  const briefHour = () => { const h = Number(cfg.brief_hour); return Number.isFinite(h) && h >= 0 && h <= 23 ? h : 7; };
  const workingDay = (t) => { const d = new Date(t + 3 * 3600000).getUTCDay(); return d !== 5 && d !== 6; };   // Riyadh: Friday / Saturday off
  const riyadhHour = (t) => new Date(t + 3 * 3600000).getUTCHours();
  function autoBriefDone(t) { const d = riyadhDay(t); return briefCol.all((b) => b.auto && riyadhDay(b.at) === d).length > 0; }
  function nextBrief(t) {
    for (let i = 0; i < 9; i++) {
      const dayStart = Date.parse(riyadhDay(t + i * 86400000) + 'T00:00:00Z') - 3 * 3600000, at = dayStart + briefHour() * 3600000;
      if (workingDay(at) && at > t && !(i === 0 && autoBriefDone(t))) return at;
      if (i === 0 && workingDay(t) && riyadhHour(t) >= briefHour() && !autoBriefDone(t)) return t;   // due now (next tick)
    }
    return null;
  }
  async function tick() {
    const t = now(); RUN.last_tick = t;
    try {
      if (t - RUN.last_snapshot >= 3600000) await overview(true);
      if (workingDay(t) && riyadhHour(t) >= briefHour() && !autoBriefDone(t)) {
        const b = await brief({ user: 'ai-ciso', role: 'system', ip: '' }, { auto: true });
        RUN.auto_briefs++; log.info('ciso: morning brief written', { id: b.id, kind: b.kind });
      }
      RUN.last_error = null;
    } catch (e) { RUN.last_error = clip(e.message, 200); log.warn('ciso: tick failed', { err: e.message }); }
  }
  function start() { if (RUN.timer) return; const job = guardOf(app, 'ciso.tick', () => tick()); RUN.timer = setInterval(job, 10 * 60000); if (RUN.timer.unref) RUN.timer.unref(); setTimeout(job, 90000).unref(); }
  function stop() { if (RUN.timer) clearInterval(RUN.timer); RUN.timer = null; }
  function status() {
    const t = now(), lb = latestBrief();
    return { running: !!RUN.timer, brief_hour: briefHour(), working_days: 'Sun-Thu (Riyadh)', next_brief: nextBrief(t), last_tick: RUN.last_tick, last_error: RUN.last_error,
      last_snapshot: RUN.last_snapshot || null, auto_briefs: RUN.auto_briefs, last_brief: lb ? { id: lb.id, at: lb.at, kind: lb.kind, auto: !!lb.auto } : null,
      sources: cache ? cache.v.sources : null, history_days: histCol.all().length, ai_daily_cap: Number(cfg.ai_daily_cap) || 6 };
  }

  /* ---- run every AI engineer now */
  async function patrolAll(who) {
    const out = [];
    if (app.duty) for (const e of app.duty.engineers()) { try { const r = await app.duty.patrol(e.id); out.push({ engine: 'itam', engineer: e.id, ok: !(r.errors && r.errors.length), opened: r.opened || 0, cleared: r.cleared || 0, not_connected: !!r.not_connected, skipped: !!r.skipped, error: (r.errors && r.errors[0]) || r.reason || null }); } catch (x) { out.push({ engine: 'itam', engineer: e.id, ok: false, error: clip(x.message, 160) }); } }
    else out.push({ engine: 'itam', ok: false, error: 'duty desk not installed here (add-duty.sh)' });
    try { const r = await siem('POST', '/duty/patrol', {}, who); for (const x of (r.results || [r])) out.push({ engine: 'siem', engineer: x.engineer || '', ok: !(x.errors && x.errors.length) && !x.error, opened: x.opened || 0, cleared: x.cleared || 0, not_connected: !!x.not_connected, skipped: !!x.skipped, error: (x.errors && x.errors[0]) || x.error || x.reason || null }); }
    catch (x) { out.push({ engine: 'siem', ok: false, error: clip(x.message, 160) }); }
    cache = null;
    if (app.audit) app.audit({ by: (who && who.user) || '', role: (who && who.role) || '', ip: (who && who.ip) || '', action: 'ciso.patrol_all', target: 'ciso', detail: { results: out.length, failed: out.filter((x) => !x.ok).length } });
    return { at: now(), results: out };
  }

  /* ---- board brief */
  function latestBrief() { return briefCol.all().sort((a, b) => b.at - a.at)[0] || null; }
  function briefsToday() { const d = riyadhDay(now()); return briefCol.all((b) => b.kind === 'ai' && riyadhDay(b.at) === d).length; }
  const SYSTEM = [
    ('You are the AI CISO assistant of ' + ZYB_ORG.name + ' (Saudi Arabia; regulated by SAMA CSF, NCA ECC, PDPL, the Insurance Authority).'),
    'Write a board-level security brief for the CISO / BISO from the CONTEXT only. Never invent a number, system, person, date or event that is not in the context.',
    'Every risk, figure or recommendation must cite the record ids it rests on, exactly as written in the context (field "ref"), in a "refs" array. No citation, no claim.',
    'If a domain is "not measured", say it is not measured and why - never describe it as good. Do not soften critical items.',
    'You recommend; people decide. Never state that something was done, fixed or executed. Recommendations are for named roles (CISO, SOC lead, IT operations, risk, business owner), not named people.',
    'Answer with ONE JSON object and nothing else: {"headline": string (<= 140 chars), "summary": string (3-5 sentences, plain business language),',
    '"priorities": [{"action": string, "why": string, "owner_role": string, "horizon": "today"|"this week"|"this quarter", "refs": [string]}] (3-7, most important first),',
    '"board_points": [{"text": string, "refs": [string]}] (3-5 points a board member should hear), "not_measured": [string]}',
  ].join('\n');
  function context(v) {
    return {
      as_of: new Date(v.generated).toISOString(),
      posture: { overall: v.posture.overall, grade: v.posture.grade, withheld_why: v.posture.withheld_why,
        domains: v.posture.domains.map((d) => ({ ref: 'domain:' + d.id, name: d.name, score: d.score, measured: d.measured, not_measured_why: d.not_measured_why, items: d.items.map((i) => i.label + ' (' + i.points + ')') })) },
      risks: v.risks.slice(0, 30).map((r) => ({ ref: r.ref, severity: r.severity, domain: r.domain, title: r.title, source: r.source, status: r.status, age_h: r.age_h })),
      decisions: v.decisions.slice(0, 20).map((d) => ({ ref: d.ref, kind: d.kind, severity: d.severity, title: d.title, who: d.who })),
      soc: v.soc, compliance: v.compliance && { sama: v.compliance.sama && { ref: 'domain:compliance', coverage_pct: v.compliance.sama.coverage_pct, counts: v.compliance.sama.counts }, grc: v.compliance.grc, drills: v.compliance.drills },
      ai_team: v.team.filter((t) => t.state === 'live').map((t) => ({ engineer: t.name, open: t.open, critical: t.critical, late: t.late })),
      sources_unavailable: v.sources.filter((s) => s.state !== 'live').map((s) => s.name + ': ' + (s.error || s.state)),
    };
  }
  function refsOf(v) {
    const s = new Set(); v.posture.domains.forEach((d) => s.add('domain:' + d.id)); v.risks.forEach((r) => s.add(r.ref)); v.decisions.forEach((d) => s.add(d.ref)); return s;
  }
  function ruleBrief(v, why) {
    const p = v.posture, crit = v.risks.filter((r) => r.severity === 'critical'), weak = p.domains.filter((d) => d.measured).sort((a, b) => a.score - b.score);
    const priorities = [];
    for (const r of crit.slice(0, 3)) priorities.push({ action: 'Resolve: ' + r.title, why: 'critical, from ' + r.source, owner_role: r.domain === 'compliance' || r.domain === 'governance' ? 'Risk & compliance' : r.domain === 'resilience' ? 'IT operations' : 'SOC lead', horizon: 'today', refs: [r.ref] });
    const ap = v.decisions.filter((d) => d.kind.startsWith('approve'));
    if (ap.length) priorities.push({ action: 'Decide the ' + ap.length + ' pending approval(s)', why: 'fixes and responses wait on a person', owner_role: 'CISO', horizon: 'today', refs: ap.slice(0, 5).map((d) => d.ref) });
    if (weak[0] && weak[0].score < 70) priorities.push({ action: 'Raise ' + weak[0].name + ' (score ' + weak[0].score + ')', why: weak[0].items.map((i) => i.label).slice(0, 2).join('; '), owner_role: 'CISO', horizon: 'this week', refs: ['domain:' + weak[0].id] });
    const nm = p.domains.filter((d) => !d.measured);
    return { kind: 'rules', why_rules: why, headline: p.overall == null ? 'Security posture not yet measurable: ' + p.withheld_why : 'Security posture ' + p.overall + '/100 (' + p.grade + '), ' + crit.length + ' critical risk(s), ' + v.decisions.length + ' decision(s) waiting',
      summary: [p.overall == null ? 'The overall score is withheld: ' + p.withheld_why + '.' : 'Overall posture is ' + p.overall + '/100 (' + p.grade + ') across ' + p.measured + ' measured domains.',
        weak.length ? 'Weakest: ' + weak.slice(0, 2).map((d) => d.name + ' ' + d.score).join(', ') + '.' : '',
        v.risks_total + ' open risks in the register (' + crit.length + ' critical).', v.decisions.length ? v.decisions.length + ' items need a decision.' : 'No decisions pending.'].filter(Boolean).join(' '),
      priorities, board_points: weak.slice(0, 3).map((d) => ({ text: d.name + ': ' + d.score + '/100 - ' + d.items.map((i) => i.label).slice(0, 2).join('; '), refs: ['domain:' + d.id] })),
      not_measured: nm.map((d) => d.name + ': ' + d.not_measured_why) };
  }
  function cleanAi(o, known) {
    let dropped = 0;
    const refs = (a) => [].concat(a || []).map((x) => clip(x, 120)).filter((x) => { const ok = known.has(x); if (!ok) dropped++; return ok; }).slice(0, 10);
    const pr = [].concat(o.priorities || []).slice(0, 7).map((x) => ({ action: clip(x.action, 300), why: clip(x.why, 400), owner_role: clip(x.owner_role, 60), horizon: ['today', 'this week', 'this quarter'].includes(x.horizon) ? x.horizon : 'this week', refs: refs(x.refs) })).filter((x) => x.action && x.refs.length);
    const bp = [].concat(o.board_points || []).slice(0, 6).map((x) => ({ text: clip(x.text, 400), refs: refs(x.refs) })).filter((x) => x.text && x.refs.length);
    return { headline: clip(o.headline, 160), summary: clip(o.summary, 1500), priorities: pr, board_points: bp, not_measured: [].concat(o.not_measured || []).slice(0, 8).map((x) => clip(x, 200)), refs_dropped: dropped };
  }
  async function brief(who, o = {}) {
    const v = await overview(true), t = now();
    const rec = { id: 'CB-' + riyadhDay(t) + '-' + t, at: t, by: (who && who.user) || '', auto: !!o.auto, posture_overall: v.posture.overall, grade: v.posture.grade,
      risks_total: v.risks_total, decisions_total: v.decisions.length };
    let out = null; const capN = Number(cfg.ai_daily_cap) || 6;
    if (!app.provider) out = ruleBrief(v, 'no AI provider in this engine');
    else if (briefsToday() >= capN) out = ruleBrief(v, 'daily AI brief cap reached (' + capN + ')');
    else {
      const st = await app.provider.status().catch(() => ({ state: 'error' }));
      if (st.state !== 'ready') out = ruleBrief(v, 'AI not available: ' + (st.message || st.state));
      else {
        const settings = (app.settings && app.settings.get && app.settings.get()) || {};
        const pair = await guardSanitise(app, SYSTEM, 'CONTEXT:\n' + JSON.stringify(context(v)), settings.redact_terms);
        let res; try { res = await app.provider.call({ system: pair.system, prompt: pair.prompt, who: { user: rec.by }, feature: 'itam.ciso_brief' }); } catch (e) { res = { ok: false, code: 'internal', message: e.message }; }
        if (app.audit) app.audit({ by: rec.by, role: (who && who.role) || '', ip: (who && who.ip) || '', action: 'ai.call', target: rec.id, detail: { feature: 'ciso_brief', status: res.ok ? 'ok' : 'error', code: res.ok ? null : res.code, model: res.model || null, system_sha256: pair.system_sha256, prompt_sha256: pair.prompt_sha256 } });
        const j = res.ok ? extractJson(res.text || '').obj : null;
        if (j && typeof j === 'object') {
          const c = cleanAi(j, refsOf(v));
          if (c.headline && c.priorities.length) out = Object.assign({ kind: 'ai', model: res.model || null }, c);
          else out = ruleBrief(v, 'the AI answer cited no record ids it was given - replaced by the rule-based brief');
        } else out = ruleBrief(v, res.ok ? 'the AI answer was not valid JSON' : 'AI call failed: ' + clip(res.message || res.code, 160));
      }
    }
    Object.assign(rec, out, { context_sha256: crypto.createHash('sha256').update(JSON.stringify(context(v))).digest('hex') });
    briefCol.put(rec);
    if (app.audit) app.audit({ by: rec.by, role: (who && who.role) || '', ip: (who && who.ip) || '', action: 'ciso.brief', target: rec.id, detail: { kind: rec.kind, overall: rec.posture_overall } });
    if (cache) cache.v.last_brief = { id: rec.id, at: rec.at, kind: rec.kind, headline: rec.headline };
    return rec;
  }
  function briefs(limit) { return briefCol.all().sort((a, b) => b.at - a.at).slice(0, Math.min(Number(limit) || 20, 100)).map((b) => ({ id: b.id, at: b.at, by: b.by, auto: !!b.auto, kind: b.kind, headline: b.headline, posture_overall: b.posture_overall })); }
  function briefGet(id) { const b = briefCol.get(id); if (!b) throw httpErr(404, 'brief not found'); return b; }

  return { collect, overview, insights, posture, risks, decisions, team, patrolAll, brief, briefs, briefGet, history, status, tick, start, stop, nextBrief, DOMAINS: DOM };
}

function registerCiso(srv, app, opts = {}) {
  const C = createCiso(app, opts);
  srv.route('GET', '/ciso/overview', (ctx) => void ctx.need('viewer') || C.overview((ctx.query || {}).refresh === '1'));
  srv.route('GET', '/ciso/briefs', (ctx) => void ctx.need('viewer') || ({ briefs: C.briefs((ctx.query || {}).limit) }));
  srv.route('GET', '/ciso/briefs/:id', (ctx) => void ctx.need('viewer') || C.briefGet(ctx.params.id));
  srv.route('POST', '/ciso/patrol', (ctx) => { ctx.need('operator'); return C.patrolAll(ctx.who); });
  srv.route('POST', '/ciso/brief', (ctx) => { ctx.need('operator'); return C.brief(ctx.who); });
  srv.route('GET', '/ciso/status', (ctx) => void ctx.need('viewer') || C.status());
  srv.route('GET', '/ciso/history', (ctx) => void ctx.need('viewer') || ({ history: C.history((ctx.query || {}).days) }));
  srv.route('GET', '/ciso/insights', (ctx) => { ctx.need('viewer'); return C.insights(); });
  (app.addons = app.addons || {}).ciso = C;
  if (((app.config && app.config.ciso) || {}).enabled !== false && !opts.noTimer) C.start();
  return C;
}

module.exports = { createCiso, registerCiso, DOMAINS };
