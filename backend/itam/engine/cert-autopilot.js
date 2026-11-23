// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('./brand');
const { body } = require('./check');
const { createIntelKit, registerIntel, beta, DAY } = require('./intel-kit');
/*
 * Certificate Renewal Autopilot ({P} = /api/itam; Certificates -> Autopilot). Built over what the lifecycle already does - the
 * inventory and Python lifecycle rules (certs.js), issuance with automatic renewal for endpoints flagged auto_renew
 * (cert-issue.js: ACME http-01 / AD CS, same names, by system:pki), four-eyes installation on Palo Alto / FortiGate with
 * automatic roll-back (cert-install.js) and verification by a scan. The autopilot decides nothing on its own that those do not
 * already allow: it shows, per certificate, how far the renewal can run without a person and what stops it, learns how long each
 * step really takes, and gives people bulk actions.
 *   readiness     per endpoint, the five steps (scanned · issued · names · installed · verified) as auto / approval / person /
 *                 blocked, each blocker with the fix; level full (auto_renew on, nothing but the four-eyes install approval) /
 *                 ready (would be full once auto_renew is switched on) / assisted (a person does a step) / blocked
 *   lead model    how long issuance (per method), the install approval and the installation (per device kind) took in this
 *                 platform's own history - median and P90, shrunk toward stated defaults below 3 observations (k = 3) - and the
 *                 failure rate per method (Beta-smoothed). Predicted lead = issue + approval + install + 3 days per person step
 *   risk          0-100, itemised: slack (days left less the predicted P90 lead), expired, critical, failure rate, person
 *                 steps, blocked. "start now" = the recommended start date (expiry - P90 lead - safety margin) has passed
 *   bottlenecks   the blockers ranked by how many endpoints each one holds back from full automation - fix one, automate N
 *   calendar      recommended renewal starts per week for 13 weeks (the workload ahead)
 *   history       one snapshot a day (automation coverage, at risk) through the intel kit
 *   GET  /certs/autopilot                     viewer
 *   POST /certs/autopilot/enable              operator  {ids[]}  switch auto_renew on (refused for a blocked endpoint)  audited
 *   POST /certs/autopilot/start               operator  {ids[]}  a PERSON starts the renewals now: renewal + certificate
 *                                                       request each (names outside the current ones still need approval)  audited
 *   POST /certs/autopilot/propose-installs    operator  {ids[]?} propose the installation of every issued certificate whose
 *                                                       endpoint has a bound device; a DIFFERENT person approves             audited
 *   POST /certs/autopilot/settings            admin     {margin_days, version}
 *   POST /certs/autopilot/ask                 operator  read-only AI PKI advisor (kit)
 */
const DEF = { margin_days: 7 };
// stated defaults (days) used until the platform has its own history
const PRIOR = { issue: { acme: 1, adcs: 2, manual: 7 }, approval: 2, install: 1, person: 3 };
const SHRINK = 3, DONE = ['verified', 'cancelled'];
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const q = (a, p) => { if (!a.length) return null; const s = a.slice().sort((x, y) => x - y); return s[Math.min(s.length - 1, Math.floor(p * s.length))]; };
const r1 = (x) => (x == null ? null : Math.round(x * 10) / 10);
const at = (h, to) => { const x = (h || []).find((e) => e.to === to); return x ? Date.parse(x.at) : null; };

function learn(samples, prior) {
  const n = samples.length, med = q(samples, 0.5), p90 = q(samples, 0.9);
  const blend = (v, pr) => (n ? (n * v + SHRINK * pr) / (n + SHRINK) : pr);
  return { n, median: r1(blend(med, prior)), p90: r1(blend(p90, prior * 2)), observed_median: r1(med), source: n >= SHRINK ? 'learned from ' + n + ' run(s)' : n ? 'default blended with ' + n + ' run(s)' : 'default (no history yet)' };
}

function createCertAutopilot(app, opts = {}) {
  let K;
  const C = () => (K.A().certs) || null, st = () => app.store;
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role || '', ip: who.ip || '', action: 'certs.autopilot.' + action, target, detail }); };
  function model() {
    const R = st().collection('cert_requests').all(), J = st().collection('cert_install_jobs').all(), Tg = st().collection('cert_install_targets').all();
    const issueS = { acme: [], adcs: [], manual: [] }, fails = { acme: [0, 0], adcs: [0, 0], manual: [0, 0] };
    for (const r of R) {
      const m = issueS[r.method] ? r.method : null; if (!m) continue;
      const t0 = r.created_ms || Date.parse(r.created_at), t1 = at(r.history, 'issued');
      if (t1 && t0) issueS[m].push((t1 - t0) / DAY);
      if (['issued', 'failed'].includes(r.status)) { fails[m][1]++; if (r.status === 'failed') fails[m][0]++; }
    }
    const appr = [], inst = {}, kindOf = (id) => (Tg.find((t) => t.id === id) || {}).kind || 'other';
    for (const j of J) {
      const p = at(j.history, 'proposed'), a = at(j.history, 'approved'), v = at(j.history, 'verified') || at(j.history, 'installed');
      if (p && a) appr.push((a - p) / DAY);
      if (a && v) (inst[kindOf(j.target_id)] = inst[kindOf(j.target_id)] || []).push((v - a) / DAY);
    }
    const issue = {}; for (const m of Object.keys(issueS)) issue[m] = Object.assign(learn(issueS[m], PRIOR.issue[m]), { failure_rate: Math.round(beta(fails[m][0], fails[m][1]) * 100), finished: fails[m][1] });
    const install = {}; for (const k of ['paloalto', 'fortigate']) install[k] = learn(inst[k] || [], PRIOR.install);
    return { issue, approval: learn(appr, PRIOR.approval), install, person_days: PRIOR.person,
      why: 'Durations are this platform\'s own history (request created -> issued; install proposed -> approved -> verified), shrunk toward the stated defaults while fewer than ' + SHRINK + ' runs exist; failure rate is Beta-smoothed (50 % with no history). A person step adds ' + PRIOR.person + ' days.' };
  }
  function readiness(row, ep, iss, targets) {
    const steps = [], add = (step, mode, detail, fix) => steps.push({ step, mode, detail, fix: fix || '' });
    const m = row.issuer_kind, names = ((row.scan || {}).names || []);
    if (['not-scanned', 'unreachable'].includes(row.state)) add('scanned', 'blocked', row.state === 'unreachable' ? 'the certificate could not be read' : 'not scanned yet', 'Scan the endpoint (Endpoints -> Scan); check the host and port are reachable from the platform.');
    else add('scanned', 'auto', 'read every 6 hours');
    if (m === 'acme') {
      if (!iss.acme) add('issued', 'blocked', 'ACME is not configured', 'Issuers -> ACME: set the directory URL (and EAB for a commercial CA).');
      else if (names.some((n) => /^\*\./.test(n))) add('issued', 'person', 'a wildcard needs dns-01: a person publishes the TXT record', 'Use an AD CS / ordered certificate for wildcards, or publish the TXT record when asked.');
      else if (!iss.acme.http01_webroot) add('issued', 'person', 'no http-01 web root: dns-01 TXT records are published by a person', 'Issuers -> ACME: set the http-01 web root so validation runs unattended.');
      else add('issued', 'auto', 'ACME http-01, unattended');
    } else if (m === 'adcs') {
      if (!iss.adcs) add('issued', 'blocked', 'AD CS is not configured', 'Issuers -> AD CS: set the web enrolment URL, template and service account.');
      else add('issued', 'auto', 'AD CS template ' + (iss.adcs.template || '') + ' (a CA manager may hold it)');
    } else if (m === 'manual') add('issued', 'person', 'ordered from a commercial CA: the CSR is downloaded and the certificate pasted back', 'Move it to ACME (EAB) if the CA offers it.');
    else add('issued', 'blocked', m === 'self' ? 'self-signed: no issuer to renew from' : 'issuer not known', 'Set the issuer kind on the endpoint (ACME, AD CS or ordered).');
    add('names', 'auto', 'renewed with the same names (a change of names goes to a second person)');
    const tg = targets.find((t) => t.endpoint_id === ep.id && t.key_set), dt = row.deploy_target;
    if (tg) add('installed', 'approval', (tg.kind === 'paloalto' ? 'Palo Alto' : 'FortiGate') + ' ' + tg.label + ': a second person approves, then it runs (roll-back on failure)');
    else if (['paloalto', 'fortigate'].includes(dt)) add('installed', 'blocked', 'installed on ' + row.deploy_target_name + ' but no device is set up for it', 'Publishing -> Add a device (an administrator) and bind it to this endpoint.');
    else if (dt && dt !== 'none') add('installed', 'person', 'installed by hand on ' + row.deploy_target_name + ' from the exported certificate', 'Only Palo Alto and FortiGate are installed by the platform today.');
    else add('installed', 'person', 'where it is installed is not set', 'Set "installed on" for the endpoint.');
    add('verified', 'auto', 'a scan confirms the new certificate (different fingerprint, later expiry)');
    const blocked = steps.some((s) => s.mode === 'blocked'), person = steps.filter((s) => s.mode === 'person').length;
    const unattended = !blocked && !person;
    const level = blocked ? 'blocked' : unattended && row.auto_renew ? 'full' : unattended ? 'ready' : 'assisted';
    return { steps, level, person_steps: person, approval: steps.some((s) => s.mode === 'approval') };
  }
  async function view() {
    const Cx = C(); if (!Cx) return { installed: false, notes: ['the certificate lifecycle module is not installed'] };
    const a = await Cx.assess(), M = model(), S = K.settings(DEF), t = K.now();
    const iss = Cx.issue ? Cx.issue.issuers() : { acme: null, adcs: null }, targets = Cx.install ? Cx.install.targets() : [];
    const E = st().collection('cert_endpoints'), R = st().collection('cert_requests').all(), J = st().collection('cert_install_jobs').all(), RN = st().collection('cert_renewals').all();
    const openReq = (id) => R.find((x) => x.endpoint_id === id && !['issued', 'failed', 'cancelled'].includes(x.status));
    const rows = [];
    for (const row of a.endpoints) {
      const ep = E.get(row.id); if (!ep || ep.retired) continue;
      const rd = readiness(row, ep, iss, targets), m = M.issue[row.issuer_kind];
      const kind = (targets.find((x) => x.endpoint_id === ep.id) || {}).kind;
      const lead = (m ? m.p90 : PRIOR.issue.manual * 2) + (rd.approval ? M.approval.p90 : 0) + (kind ? M.install[kind].p90 : PRIOR.install) + rd.person_steps * PRIOR.person;
      const exp = (row.scan || {}).not_after || null, days = row.days_left;
      const slack = days == null ? null : r1(days - lead), start = exp ? exp - (lead + S.margin_days) * DAY : null;
      const pts = [], P = (label, n) => { if (n) pts.push({ label, points: n }); };
      if (row.state === 'expired') P('expired ' + (-days) + ' day(s) ago', 40);
      else if (slack != null) { if (slack < 0) P('predicted lead ' + r1(lead) + ' d is longer than the ' + days + ' days left', 40); else if (slack < 7) P('under a week of slack', 25); else if (slack < 30) P('under 30 days of slack', 10); }
      if (row.critical) P('critical service', 15);
      if (m && m.failure_rate > 50) P(row.issuer_kind + ' renewals failed ' + m.failure_rate + ' % of the time', Math.round((m.failure_rate - 50) / 2.5));
      P(rd.person_steps + ' step(s) need a person', rd.person_steps * 5);
      if (rd.level === 'blocked') P('automation blocked', 15);
      const risk = Math.min(100, pts.reduce((s, x) => s + x.points, 0));
      const inflight = openReq(row.id), job = J.find((j) => j.endpoint_id === row.id && ['proposed', 'approved', 'running'].includes(j.status));
      const issued = R.filter((x) => x.endpoint_id === row.id && x.status === 'issued' && !J.some((j) => j.request_id === x.id && !['rejected', 'cancelled', 'failed'].includes(j.status))).sort((x, y) => y.created_ms - x.created_ms)[0];
      rows.push({ id: row.id, label: row.label, host: row.host, port: row.port, owner: row.owner, critical: row.critical, state: row.state, days_left: days, expires: (row.scan || {}).not_after_iso || '',
        issuer_kind: row.issuer_kind, issuer_name: row.issuer_kind_name, auto_renew: row.auto_renew, deploy: row.deploy_target_name, level: rd.level, steps: rd.steps,
        lead_days: r1(lead), slack_days: slack, start_by: start ? new Date(start).toISOString().slice(0, 10) : null, start_now: !!(start && start <= t && !inflight && !(row.renewal)),
        risk, risk_why: pts, in_flight: inflight ? { id: inflight.id, status: inflight.status } : job ? { id: job.id, status: 'install ' + job.status } : row.renewal ? { id: row.renewal.id, status: 'renewal ' + row.renewal.status } : null,
        install_ready: issued && targets.some((x) => x.endpoint_id === row.id && x.key_set) && !job ? issued.id : null });
    }
    rows.sort((x, y) => y.risk - x.risk || (x.slack_days == null ? 1e9 : x.slack_days) - (y.slack_days == null ? 1e9 : y.slack_days));
    const cnt = (f) => rows.filter(f).length, n = rows.length;
    const bott = {}; for (const r of rows) for (const s of r.steps) if (s.mode === 'blocked' || s.mode === 'person') { const k = s.step + '|' + s.detail.replace(/ [A-Z][\w-]+ [\w.-]+:.*/, ''); (bott[k] = bott[k] || { step: s.step, mode: s.mode, detail: s.detail, fix: s.fix, endpoints: [] }).endpoints.push(r.id); }
    const bottlenecks = Object.values(bott).map((b) => Object.assign(b, { count: b.endpoints.length, endpoints: b.endpoints.slice(0, 20) })).sort((x, y) => (y.mode === 'blocked') - (x.mode === 'blocked') || y.count - x.count);
    const weeks = []; const w0 = t - ((new Date(t).getUTCDay()) * DAY);
    for (let i = 0; i < 13; i++) { const a0 = w0 + i * 7 * DAY, a1 = a0 + 7 * DAY; weeks.push({ week: new Date(a0).toISOString().slice(0, 10), starts: rows.filter((r) => r.start_by && Date.parse(r.start_by) >= (i ? a0 : 0) && Date.parse(r.start_by) < a1).length }); }
    const closed = RN.filter((r) => DONE.includes(r.status) && Date.parse((r.history || []).slice(-1)[0] ? r.history.slice(-1)[0].at : r.opened_at) >= t - 90 * DAY);
    const verified = closed.filter((r) => r.status === 'verified'), onTime = verified.filter((r) => r.old_not_after && Date.parse(r.verified_at) < r.old_not_after);
    const coverage = n ? Math.round(cnt((r) => r.level === 'full') / n * 100) : null;
    const brief = [];
    if (!n) brief.push('No certificate endpoints yet - add them or switch on automatic discovery (Discover).');
    else {
      brief.push(cnt((r) => r.level === 'full') + ' of ' + n + ' certificates renew on their own (' + coverage + ' %); ' + cnt((r) => r.level === 'ready') + ' more would, once automatic renewal is switched on.');
      if (cnt((r) => r.start_now)) brief.push(cnt((r) => r.start_now) + ' should be started now: the predicted lead time plus the ' + S.margin_days + '-day margin has run out.');
      if (cnt((r) => r.slack_days != null && r.slack_days < 0)) brief.push(cnt((r) => r.slack_days != null && r.slack_days < 0) + ' will probably not finish before expiry at the usual pace - start them and chase the person steps.');
      if (bottlenecks[0]) brief.push('Biggest blocker: "' + bottlenecks[0].detail + '" on ' + bottlenecks[0].count + ' endpoint(s) - ' + bottlenecks[0].fix);
      if (cnt((r) => r.install_ready)) brief.push(cnt((r) => r.install_ready) + ' issued certificate(s) are ready to install on a firewall: propose them, a second person approves.');
    }
    return { generated_at: K.iso(), installed: true, ai: K.aiStatus(), settings: S, brief,
      kpis: { endpoints: n, full: cnt((r) => r.level === 'full'), ready: cnt((r) => r.level === 'ready'), assisted: cnt((r) => r.level === 'assisted'), blocked: cnt((r) => r.level === 'blocked'), coverage,
        start_now: cnt((r) => r.start_now), at_risk: cnt((r) => r.risk >= 40), in_flight: cnt((r) => r.in_flight), install_ready: cnt((r) => r.install_ready),
        renewed_90d: verified.length, on_time_pct: verified.length ? Math.round(onTime.length / verified.length * 100) : null },
      queue: rows, bottlenecks: bottlenecks.slice(0, 12), calendar: weeks, model: M,
      history: K.history(90).map((h) => ({ date: h.id, coverage: h.coverage, at_risk: h.at_risk })),
      note: 'The autopilot shows and starts; it does not approve. Installations on firewalls always need a second person, and a renewal is closed only by a scan that sees the new certificate.' };
  }
  const pick = async (ids) => { const v = await view(); if (!v.installed) throw httpErr(409, 'the certificate lifecycle module is not installed'); const want = new Set(ids || []); return { v, rows: ids ? v.queue.filter((r) => want.has(r.id)) : v.queue }; };
  async function enable(b0, who) {
    const b = body(b0 || {}).list('ids', { required: true, max: 200, item: 'id', unique: true }).done();
    K.person(who, 'switch on automatic renewal');
    const { rows } = await pick(b.ids), out = [];
    for (const id of b.ids) {
      const r = rows.find((x) => x.id === id);
      if (!r) { out.push({ id, ok: false, error: 'no such endpoint' }); continue; }
      if (r.level === 'blocked') { out.push({ id, ok: false, error: 'blocked: ' + r.steps.filter((s) => s.mode === 'blocked').map((s) => s.detail).join('; ') }); continue; }
      if (r.auto_renew) { out.push({ id, ok: true, note: 'already on' }); continue; }
      C().putEndpoint({ id, auto_renew: true }, who); out.push({ id, ok: true });
    }
    audit(who, 'enable', 'endpoints', { asked: b.ids.length, switched_on: out.filter((x) => x.ok && !x.note).length });
    return { results: out };
  }
  async function startRenewals(b0, who) {
    const b = body(b0 || {}).list('ids', { required: true, max: 50, item: 'id', unique: true }).done();
    K.person(who, 'start renewals');
    const Cx = C(); if (!Cx.issue) throw httpErr(409, 'certificate issuance is not installed');
    const { rows } = await pick(b.ids), out = [];
    for (const id of b.ids) {
      const r = rows.find((x) => x.id === id);
      if (!r) { out.push({ id, ok: false, error: 'no such endpoint' }); continue; }
      if (r.in_flight && !/^renewal /.test(r.in_flight.status)) { out.push({ id, ok: false, error: 'already in progress: ' + r.in_flight.id + ' (' + r.in_flight.status + ')' }); continue; }
      if (r.level === 'blocked') { out.push({ id, ok: false, error: 'blocked: ' + r.steps.filter((s) => s.mode === 'blocked').map((s) => s.fix).join(' ') }); continue; }
      try {
        let rn = r.in_flight ? { id: r.in_flight.id } : null;
        if (!rn) rn = Cx.openRenewal({ endpoint_id: id, note: 'started from the renewal autopilot' }, who);
        const qq = await Cx.issue.create({ endpoint_id: id, renewal_id: rn.id }, who);
        out.push({ id, ok: qq.status !== 'failed', renewal: rn.id, request: qq.id, status: qq.status, error: qq.error || undefined });
      } catch (e) { if (!e.status || e.status >= 500) throw e; out.push({ id, ok: false, error: e.message }); }
    }
    audit(who, 'start', 'endpoints', { asked: b.ids.length, started: out.filter((x) => x.ok).length, results: out.map((x) => x.id + ':' + (x.ok ? x.status : 'refused')) });
    return { results: out };
  }
  async function proposeInstalls(b0, who) {
    const b = body(b0 || {}).list('ids', { max: 50, item: 'id', unique: true }).done();
    K.person(who, 'propose installations');
    const Cx = C(); if (!Cx.install) throw httpErr(409, 'certificate installation is not installed');
    const { rows } = await pick(b.ids), targets = Cx.install.targets(), out = [];
    for (const r of rows.filter((x) => x.install_ready)) {
      const tg = targets.find((x) => x.endpoint_id === r.id && x.key_set);
      try { const j = await Cx.install.propose({ request_id: r.install_ready, target_id: tg.id, reason: 'renewal autopilot: issued certificate ready for ' + r.label }, who); out.push({ id: r.id, ok: true, job: j.id }); }
      catch (e) { if (!e.status || e.status >= 500) throw e; out.push({ id: r.id, ok: false, error: e.message }); }
    }
    audit(who, 'propose-installs', 'endpoints', { proposed: out.filter((x) => x.ok).length, refused: out.filter((x) => !x.ok).length });
    return { results: out, note: out.length ? 'A different person approves each installation (Publishing).' : 'No issued certificate is waiting for a bound device.' };
  }
  function saveSettings(b0, who) { const b = body(b0 || {}).int('margin_days', { required: true, min: 0, max: 60 }).int('version', { required: true, min: 0 }).done(); return K.saveSettings(DEF, { margin_days: b.margin_days }, b.version, who); }
  async function snapshot() { return K.snapshot(async () => { const v = await view(); if (!v.installed || !v.kpis.endpoints) return null; return { coverage: v.kpis.coverage, at_risk: v.kpis.at_risk, endpoints: v.kpis.endpoints }; }); }
  K = createIntelKit(app, { key: 'cert-autopilot', feature: 'itam.pki-advisor', now: opts.now, sdk: opts.sdk, getKey: opts.getKey, noTimer: opts.noTimer,
    system: ('You are the PKI advisor to the certificate owners of ' + ZYB_ORG.name + '. You read the renewal autopilot: per certificate the automation level, the five renewal steps and what blocks them, the predicted lead time learned from this platform\'s own history, slack, risk points and the bottlenecks. Recommend what to renew first and which one fix automates the most certificates. Base every statement on the tool output, cite endpoint ids, never invent a certificate, date or person. You cannot change anything: renewals are started, and installations approved, by people.'),
    tools: [{ name: 'autopilot_overview', description: 'KPIs, brief, the renewal queue (level, steps, lead, slack, risk with reasons), bottlenecks, calendar and the learned lead-time model.', run: async () => { const v = await view();
      return { kpis: v.kpis, brief: v.brief, queue: (v.queue || []).slice(0, 60).map((r) => ({ id: r.id, label: r.label, state: r.state, days_left: r.days_left, level: r.level, lead_days: r.lead_days, slack_days: r.slack_days, start_by: r.start_by, risk: r.risk, risk_why: r.risk_why, blockers: r.steps.filter((s) => s.mode !== 'auto').map((s) => s.step + ': ' + s.detail) })), bottlenecks: v.bottlenecks, model: v.model }; } }] });
  return { view, enable, startRenewals, proposeInstalls, saveSettings, snapshot, ask: K.ask, start: () => K.start(snapshot), stop: K.stop, TOOLS: K.TOOLS, readiness, model };
}
function registerCertAutopilot(srv, app, X) {
  registerIntel(srv, X, '/certs/autopilot');
  srv.route('POST', '/certs/autopilot/enable', (ctx) => { ctx.need('operator'); return X.enable(ctx.body, ctx.who); }, { maxBody: 8192 });
  srv.route('POST', '/certs/autopilot/start', (ctx) => { ctx.need('operator'); return X.startRenewals(ctx.body, ctx.who); }, { maxBody: 4096 });
  srv.route('POST', '/certs/autopilot/propose-installs', (ctx) => { ctx.need('operator'); return X.proposeInstalls(ctx.body, ctx.who); }, { maxBody: 4096 });
}
module.exports = { createCertAutopilot, registerCertAutopilot, PRIOR, learn };
