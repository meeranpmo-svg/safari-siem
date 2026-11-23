// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('./brand');
const fs = require('node:fs');
const { body, param } = require('./check');
const { guardOf } = require('./errors');
const { isHuman } = require('./approve-scopes');
const G = require('./ai-guard');
/*
 * SAMA Cyber Security Framework + Insurance Authority - the automated assessment ({P} = /api/itam). Python decides
 * (pyengine/sama_ia_rules.py); this file validates at the boundary, gathers the facts, commits and audits.
 *
 * Every requirement is verified against one of four evidence pillars - GRC (policies, risk, attestations, control
 * monitoring, audit findings), Hardening (baseline coverage, critical failures, patching), Pentest / VAPT (scans, pentest
 * cadence, exposed services) and SIEM logs (the SIEM's own SAMA evidence, log flow, retention) - plus Operations (assets,
 * backups, certificates, mail). The facts are the NCA ECC register's (read once, cached), so SAMA, NCA ECC and ISO 27001
 * never disagree about the same evidence, and an approved NCA ECC confirmation counts here too.
 *
 * Automated: a snapshot every day (history for the trend, the forecast and the chance-of-gap model); the AI Assessor drafts
 * the assessment report with read-only tools over the register (rules draft it when external AI is off). People decide:
 * a confirmation is approved by the CISO named in the NCA ECC profile or an administrator, never the person who recorded
 * it; a report is approved by the CISO / an administrator who did not request it; service and AI identities never do.
 *
 *   GET  /sama-ia                       viewer    the register (people's names only for operator / admin)
 *   GET  /sama-ia/export                operator  CSV                                                       audited
 *   POST /sama-ia/profile               admin     {applicability{3.3.12, 3.3.13}, applicability_note{}}      audited
 *   POST /sama-ia/confirm               operator  {id, status, evidence?, note?}                              audited
 *   POST /sama-ia/confirm/:id/decide    operator  CISO / admin, four eyes: {decision, note?}                   audited
 *   POST /sama-ia/run                   operator  assess now and keep today's snapshot                         audited
 *   POST /sama-ia/gaps-to-grc           operator  CISO / admin: every gap becomes a GRC action (once)         audited
 *   GET  /sama-ia/ai/status             operator  whether the AI Assessor may run, and why not
 *   POST /sama-ia/report                operator  {use_ai?} draft the assessment report                        audited
 *   GET  /sama-ia/reports               operator  drafts and approved reports
 *   POST /sama-ia/reports/:id/decide    operator  CISO / admin, not the requester: {decision, note?}          audited
 */
const STATUSES = ['compliant', 'partial', 'non_compliant', 'not_applicable'];
const RID = /^(?:SA-3\.[1-4]\.\d{1,2}-\d{2}|IA-277-\d{2})$/;
const DECIDE = ['3.3.12', '3.3.13'];
const PILLARS = ['grc', 'hardening', 'pentest', 'siem', 'ops'];
const HORIZONS = ['30 days', '90 days', '180 days'];
const DAY = 86400000, MODEL = 'claude-opus-5-5', MAX_TURNS = 6;
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const same = (a, b) => !!a && String(a).trim().toLowerCase() === String(b || '').trim().toLowerCase();
const s = (x, n) => String(x == null ? '' : x).slice(0, n);

function pythonBin(app, opts) {
  const c = opts.python || ((app.config && app.config.discovery) || {}).python_bin;
  return [c, '/opt/sentra-siem/pyenv/bin/python3'].filter(Boolean).find((p) => fs.existsSync(p)) || 'python3';
}

function createSamaIa(app, opts = {}) {
  const now = opts.now || Date.now, store = app.store;
  const iso = () => new Date(now()).toISOString();
  const day = (ms) => new Date(ms + 3 * 3600000).toISOString().slice(0, 10);   // Riyadh day
  const col = (n) => store.collection(n);
  const prof = () => col('sama_profile'), conf = () => col('sama_confirm'), runs = () => col('sama_runs'), reps = () => col('sama_reports');
  let pyE = null;
  const py = () => opts.py || pyE || (pyE = require('./pyengine').createPyEngine({ python: pythonBin(app, opts), timeoutMs: 60000, resident: false }));
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role, ip: who.ip || '', action: 'sama.' + action, target, detail }); };
  const L = app.log || { every() {}, warn() {}, info() {} };
  const warn = (key, msg, err) => { if (L.every) L.every('sama:' + key, 3600000, 'warn', msg, { err: s((err && err.message) || err, 200) }); };
  const addon = (k) => app.addons && app.addons[k];
  const byId = (c) => { const o = {}; for (const x of c.all(() => true)) o[x.id] = x; return o; };
  const profile = () => prof().get('profile') || {};
  const eccProfile = () => { try { return col('ecc_profile').get('profile') || {}; } catch (e) { warn('eccp', 'SAMA: the NCA ECC profile was not read', e); return {}; } };
  const eccConfirms = () => { try { return byId(col('ecc_confirm')); } catch (e) { warn('eccc', 'SAMA: the NCA ECC confirmations were not read', e); return {}; } };
  const person = (who, what) => { if (!isHuman(who.user)) throw httpErr(403, 'a service or AI identity cannot ' + what + ': a person does'); };
  const ciso = (who) => who.role === 'admin' || same(eccProfile().ciso_user, who.user);
  const needCiso = (who, what) => { person(who, what); if (!ciso(who)) throw httpErr(403, what + ' needs the CISO named in the NCA ECC profile or an administrator'); };

  async function rules(op, input) {
    const r = await py().call(op, input || {});
    if (!r || r.ok === false) { warn('py', 'SAMA: the rules (Python) did not answer', r && r.error); throw httpErr(409, 'The SAMA rules run in Python and Python did not answer - run the update so pyengine is installed'); }
    return r;
  }

  // ---- one evidence collection: NCA ECC's facts plus control monitoring and the audit teams, cached briefly
  function auditFacts() {
    const T = ['internalAuditEngage', 'auditEngage', 'cyberAuditEngage'].map(addon).filter(Boolean);
    if (!T.length) return null;
    let engagements = 0, overdue = 0, open = 0;
    for (const t of T) {
      try {
        engagements += t.listEngagements().filter((x) => x.state !== 'planning').length;
        const f = t.listFindings().filter((x) => ['issued', 'responded', 'implemented'].includes(x.state));
        open += f.length; overdue += f.filter((x) => x.overdue).length;
      } catch (e) { warn('team', 'SAMA: an audit team was not read', e); }
    }
    return { teams: T.length, engagements, open, overdue };
  }
  function ccmFacts() {
    const C = addon('auditCcm'); if (!C) return null;
    try { const r = C.summary(); return r ? { run: r.run, at: r.at, tests: r.tests.map((t) => ({ id: t.id, name: t.name, status: t.status, exceptions: t.exceptions })) } : { run: null }; }
    catch (e) { warn('ccm', 'SAMA: control monitoring was not read', e); return null; }
  }
  // the infrastructure modules that already run the controls: each read on its own, a module not installed or not answering is
  // left out (its checks read "not measured"), never counted as a pass
  async function infraFacts() {
    const SYS = { user: 'system:sama-ia', role: 'admin' }, out = {}, today = new Date(now()).toISOString().slice(0, 10);
    const read = async (k, fn) => { try { const v = await fn(); if (v) out[k] = v; } catch (e) { warn('infra:' + k, 'SAMA: ' + k + ' was not read', e); } };
    await read('offboarding', () => { const O = addon('offboarding'); if (!O || !O.list) return null;
      const it = O.list().items || [], open = it.filter((x) => !['completed', 'cancelled'].includes(x.status));
      return { total: it.length, open: open.length, overdue: open.filter((x) => x.last_day && String(x.last_day) < today && !(x.disabled && x.disabled.at)).length,
        failed: open.filter((x) => x.disabled && x.disabled.error && !x.disabled.at).length }; });
    await read('access_reviews', () => { const A = addon('accessReviews'); if (!A) return null;
      const c = A.list(SYS).campaigns || [], done = c.filter((x) => x.status === 'closed' || x.status === 'signed').map((x) => Date.parse(x.started_at)).filter(Boolean);
      return { campaigns: c.length, overdue: c.filter((x) => x.overdue).length, last_done_days: done.length ? Math.floor((now() - Math.max(...done)) / DAY) : null,
        removal_failed: c.reduce((n, x) => n + ((x.counts || {}).removal_failed || 0), 0) }; });
    await read('pam', () => { const M = addon('pam'); if (!M) return null; const l = M.list(SYS);
      return { groups: (l.groups || []).length, connected: !!(l.directory && l.directory.connected), expire_failed: (l.counts || {}).expire_failed || 0, active: (l.counts || {}).active || 0 }; });
    await read('nhi', async () => { const N = addon('nhi'); if (!N) return null; const v = await N.summary();
      return Object.assign({ connected: (v.sources || []).some((x) => x.id !== 'platform' && x.connected) }, v.counts || {}); });
    await read('mdm', () => {   // the MDM settings are read as stored (engine/mdm.js), so nothing is created just to look
      const c = col('mdm_cfg').get('cfg'); if (!c || !c.provider || c.provider === 'none') return null;
      const L = addon('onboarding') && addon('onboarding').lic;
      return { provider: c.provider, ready: c.provider === 'manageengine' ? !!(c.base_url && c.token_enc) : !!(L && L.devicesEnabled && L.devicesEnabled()) }; });
    await read('vulnscan', () => { const V = addon('vulnscan'); if (!V) return null; const v = V.view();
      return { connected: !!(v.connection && (v.connection.configured || v.connection.ready)), last_scan: v.last_scan ? v.last_scan.finished_at : null, critical: v.open.critical, high: v.open.high, open: v.open_total }; });
    await read('lifecycle', () => { const L = addon('lifecycle'); return L && L.view ? L.view({}).summary : null; });
    return out;
  }
  let factsAt = 0, factsP = null;
  function facts() {
    if (opts.facts) return Promise.all([opts.facts(), infraFacts()]).then(([f, inf]) => Object.assign({ ccm: ccmFacts(), audit: auditFacts(), infra: inf }, f));
    if (factsP && now() - factsAt < 60000) return factsP;
    const N = addon('ncaEcc');
    factsAt = now();
    factsP = (N ? N.facts().catch((e) => { warn('facts', 'SAMA: the platform facts could not be read', e); return {}; }) : Promise.resolve({}))
      .then(async (f) => Object.assign({}, f, { ccm: ccmFacts(), audit: auditFacts(), infra: await infraFacts() }));
    return factsP;
  }
  const history = () => runs().all(() => true).sort((a, b) => a.at - b.at);
  async function assess() {
    return rules('sama.view', { facts: await facts(), profile: profile(), ecc_profile: eccProfile(), confirms: byId(conf()), ecc_confirms: eccConfirms(),
      history: history().slice(-120), settings: profile().settings || {}, now: now() });
  }
  function forViewer(v) {   // confirmations name people (PDPL): a viewer sees the result, not who
    const strip = (r) => Object.assign({}, r, { confirmation: r.confirmation ? { status: r.confirmation.status } : null,
      why: (r.confirmation || r.via_ecc) && /confirmed by|recorded by/.test(r.why || '') ? (r.result === 'pending' ? 'recorded - waiting for a second person to approve' : 'confirmed by a person and approved by a second person') : r.why });
    return Object.assign({}, v, { requirements: v.requirements.map(strip), ia: Object.assign({}, v.ia, { requirements: v.ia.requirements.map(strip) }), profile: { applicability: v.profile.applicability } });
  }
  async function view(who) {
    const v = await assess();
    const p = profile();
    const out = Object.assign({}, v, { profile: { applicability: p.applicability || {}, applicability_note: p.applicability_note || {}, updated_by: p.updated_by || null, ciso: eccProfile().ciso_user || null },
      history: history().slice(-90).map((h) => ({ day: h.id, score: h.score, at_target: h.at_target })), ai: aiStatus(), generated_at: iso() });
    return who && who.role === 'viewer' ? forViewer(out) : out;
  }

  function putProfile(input, who) {
    person(who, 'change the SAMA profile');
    const src = input || {}, p = profile(), appl = Object.assign({}, p.applicability || {}), note = Object.assign({}, p.applicability_note || {});
    const a = src.applicability, nt = src.applicability_note;
    if (a !== undefined) {
      if (!a || typeof a !== 'object' || Array.isArray(a)) throw httpErr(400, 'applicability must be an object {"3.3.12": "applies" | "not_applicable", "3.3.13": ...}');
      for (const k of Object.keys(a)) { if (!DECIDE.includes(k)) throw httpErr(400, 'applicability: ' + s(k, 20) + ' is not a subdomain that needs a decision (3.3.12, 3.3.13)'); Object.assign(appl, body(a).oneOf(k, ['applies', 'not_applicable'], { required: true }).done()); }
    }
    if (nt !== undefined) {
      if (!nt || typeof nt !== 'object' || Array.isArray(nt)) throw httpErr(400, 'applicability_note must be an object {"3.3.12": "why"}');
      for (const k of Object.keys(nt)) { if (!DECIDE.includes(k)) throw httpErr(400, 'applicability_note: ' + s(k, 20) + ' is not 3.3.12 or 3.3.13'); Object.assign(note, body(nt).str(k, { max: 500 }).done()); }
    }
    for (const k of DECIDE) if (appl[k] === 'not_applicable' && !(note[k] && note[k].length >= 10)) throw httpErr(400, 'applicability_note.' + k + ' is required: say why ' + k + ' does not apply (at least 10 characters)');
    const b = body(src.settings === undefined ? {} : src.settings).int('hardening_coverage_pct', { min: 50, max: 100 }).done();
    const rec = Object.assign({}, p, { id: 'profile', applicability: appl, applicability_note: note, settings: Object.assign({}, p.settings || {}, b), updated_by: who.user, updated_at: iso() });
    prof().put(rec); factsP = null;
    audit(who, 'profile', 'profile', { applicability: appl, settings: rec.settings });
    return { applicability: appl, applicability_note: note, settings: rec.settings };
  }

  const find = (v, id) => v.requirements.concat(v.ia.requirements).find((r) => r.id === id);
  async function confirm(input, who) {
    person(who, 'record a SAMA requirement');
    const b = body(input || {}).str('id', { required: true, re: RID, msg: 'id must be a SAMA requirement (e.g. SA-3.3.8-01) or IA-277-01' }).oneOf('status', STATUSES, { required: true })
      .str('evidence', { max: 500 }).str('note', { max: 1000 })
      .rule((o) => ((o.status === 'compliant' || o.status === 'partial') && !o.evidence ? 'evidence is required for compliant / partial: name the document, report or record relied on' : null))
      .rule((o) => ((o.status === 'non_compliant' || o.status === 'not_applicable') && !o.note ? 'note is required: say what is missing, or why it does not apply' : null)).done();
    if (!find(await assess(), b.id)) throw httpErr(404, 'no SAMA requirement ' + b.id);
    const prev = conf().get(b.id);
    conf().put({ id: b.id, status: b.status, evidence: b.evidence || '', note: b.note || '', by: who.user, role: who.role, at: iso(), approved_by: null, approved_at: null });
    audit(who, 'confirm', b.id, { status: b.status, previous: prev ? prev.status : null, evidence: b.evidence ? 'given' : 'none' });
    return find(await assess(), b.id);
  }
  async function decide(id0, input, who) {
    const id = param(id0, 'id');
    if (!RID.test(id)) throw httpErr(400, 'id must be a SAMA requirement (e.g. SA-3.3.8-01) or IA-277-01');
    const b = body(input || {}).oneOf('decision', ['approve', 'reject'], { required: true }).str('note', { max: 1000 })
      .rule((o) => (o.decision === 'reject' && !o.note ? 'note is required: say why it is rejected' : null)).done();
    const c = conf().get(id); if (!c) throw httpErr(404, 'nothing recorded for ' + id + ' yet');
    if (c.approved_by) throw httpErr(409, id + ' was already approved by ' + c.approved_by);
    needCiso(who, 'approving a SAMA requirement');
    if (same(c.by, who.user)) throw httpErr(403, 'four eyes: ' + who.user + ' recorded ' + id + ' and cannot also approve it');
    if (b.decision === 'reject') { conf().remove(id); audit(who, 'confirm.reject', id, { recorded_by: c.by, status: c.status, note: b.note }); }
    else { conf().put(Object.assign({}, c, { approved_by: who.user, approved_at: iso(), approve_note: b.note || '' })); audit(who, 'confirm.approve', id, { recorded_by: c.by, status: c.status }); }
    return find(await assess(), id);
  }

  // ---- the daily snapshot: history for the trend, the forecast and the chance-of-gap model
  function keep(v, who) {
    const d = day(now());
    const rec = { id: d, at: now(), score: v.overall.score, at_target: v.readiness.at_target, results: v.snapshot.results, by: who ? who.user : 'system:sama-ia' };
    runs().put(rec);
    const H = history(); for (const h of H.slice(0, Math.max(0, H.length - 400))) runs().remove(h.id);
    return rec;
  }
  async function run(who) {
    person(who, 'run the SAMA assessment');
    factsP = null;
    const v = await assess(), r = keep(v, who);
    audit(who, 'run', r.id, { score: r.score, at_target: r.at_target, gaps: v.overall.counts.not, regressions: v.regressions.length });
    return { day: r.id, score: r.score, at_target: r.at_target, regressions: v.regressions };
  }
  const tick = guardOf(app, 'sama-ia.daily', async () => { if (runs().get(day(now()))) return; factsP = null; keep(await assess(), null); });
  let timer = null;
  function start() { if (opts.noTimer || app.noTimers || timer) return; setTimeout(tick, 120000).unref(); timer = setInterval(tick, 3 * 3600000); if (timer.unref) timer.unref(); }

  async function gapsToGrc(who) {
    needCiso(who, 'sending SAMA gaps to GRC');
    const GR = addon('grcRegisters') || (() => { try { return require('./grc-registers').createGrcRegisters(app); } catch (e) { warn('grc-reg', 'SAMA: the GRC registers are not installed', e); return null; } })();
    if (!GR) throw httpErr(409, 'the GRC registers are not installed - run the update');
    const v = await assess(), out = { created: [], skipped: [] }, due = { high: 30, medium: 60, low: 90 };
    for (const r of v.requirements.concat(v.ia.requirements).filter((x) => x.result === 'gap')) {
      try {
        out.created.push(GR.actionCreate({ title: 'SAMA ' + r.id + ': ' + r.title.slice(0, 150), source: 'sama', ref: 'sama:' + r.id, framework: 'SAMA CSF', priority: r.severity,
          due: new Date(now() + due[r.severity] * DAY).toISOString().slice(0, 10), description: 'SAMA CSF ' + r.subdomain + ' ' + r.subdomain_name + ' (' + r.pillar_name + '): ' + s(r.why, 500) + ' Close it with: ' + r.evidence_hint + '.' }, { user: who.user, role: who.role, ip: who.ip }).id);
      } catch (e) { out.skipped.push(r.id + ': ' + s(e.message, 120)); }
    }
    audit(who, 'gaps_to_grc', 'register', { created: out.created.length, skipped: out.skipped.length });
    return out;
  }

  async function exportCsv(who) {
    const v = await assess();
    const q = (x) => { const t = String(x == null ? '' : x); return /^[=+\-@\t\r]/.test(t) ? "'" + t : t; };   // no formula injection in Excel
    const cell = (x) => '"' + q(x).replace(/"/g, '""') + '"';
    const lines = [['SAMA Cyber Security Framework - automated assessment', iso().slice(0, 10), 'score ' + v.overall.score + ' %', v.readiness.at_target + ' of ' + v.readiness.subdomains + ' subdomains at level ' + v.target_level, 'indicative, from the platform register'].map(cell).join(',')];
    lines.push(['Requirement', 'Subdomain', 'Subdomain name', 'Pillar', 'Requirement text', 'Severity', 'Result', 'Why', 'Automated', 'From NCA ECC', 'Recorded by', 'Approved by'].map(cell).join(','));
    for (const r of v.requirements.concat(v.ia.requirements)) lines.push([r.id, r.subdomain, r.subdomain_name, r.pillar_name, r.title, r.severity, r.result, r.why, r.automated ? 'yes' : 'no', r.via_ecc || '', r.confirmation ? r.confirmation.by : '', r.confirmation ? r.confirmation.approved_by : ''].map(cell).join(','));
    lines.push(''); lines.push(['Subdomain', 'Name', 'Indicative level', 'Rule', 'Score'].map(cell).join(','));
    for (const x of v.subdomains) lines.push([x.id, x.name, x.maturity.level == null ? x.maturity.name : x.maturity.level + ' ' + x.maturity.name, x.maturity.why, x.score == null ? '' : x.score + ' %'].map(cell).join(','));
    audit(who, 'export', 'register', { rows: lines.length - 2 });
    return { filename: 'sama-ia-assessment-' + iso().slice(0, 10) + '.csv', csv: lines.join('\r\n') };
  }

  /* ---- the AI Assessor: drafts the assessment report with read-only tools over the register; the CISO approves */
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
    if (!allowed) return { enabled: false, reason: 'external AI is not allowed in IT Asset Management settings (external_ai_allowed), or the AI engine is switched off (Platform Administration -> AI Engine) - the report is drafted by the rules only', model };
    if (!getKey()) return { enabled: false, reason: 'no Anthropic API key (sudo zyb-virt-ai --set-key) - the report is drafted by the rules only', model };
    if (!loadSdk()) return { enabled: false, reason: loadError || 'Anthropic SDK not installed', model };
    return { enabled: true, model };
  }
  // what the report always carries: the figures come from the rules, never from the model
  function figures(v) {
    return { score: v.overall.score, pct: v.overall.pct, readiness: v.readiness, target_level: v.target_level,
      domains: v.domains.map((d) => ({ id: d.id, name: d.name, status: d.status, score: d.score, at_target: d.at_target, subdomains: d.subdomains })),
      pillars: v.pillars, trend: v.trend, regressions: v.regressions, ia: { score: v.ia.levels.score, status: v.ia.levels.status } };
  }
  function ruleReport(v) {
    const gaps = v.priorities.filter((p) => p.result === 'gap');
    const met = v.subdomains.filter((x) => (x.maturity.level || 0) >= v.target_level);
    const H = (sev) => (sev === 'high' ? '30 days' : sev === 'medium' ? '90 days' : '180 days');
    const sevOf = (id) => (find(v, id) || {}).severity || 'medium';
    return {
      executive_summary: ('Automated SAMA CSF assessment of ' + ZYB_ORG.short + ' on ') + iso().slice(0, 10) + ': ' + v.overall.score + ' % of applicable requirements met (fully ' + v.overall.pct.compliant + ' %, partially ' + v.overall.pct.partially + ' %, not ' + v.overall.pct.not + ' %, not assessed ' + v.overall.pct.not_assessed + ' %). '
        + v.readiness.at_target + ' of ' + v.readiness.subdomains + ' subdomains reach the indicative level ' + v.target_level + ' SAMA expects; ' + v.readiness.not_assessed + ' have no evidence yet. '
        + (v.regressions.length ? v.regressions.length + ' requirement(s) regressed since the last run. ' : '') + 'Indicative, from the platform register - not SAMA\'s or an auditor\'s rating.',
      strengths: met.slice(0, 8).map((x) => x.id + ' ' + x.name + ': level ' + x.maturity.level + ' (' + x.maturity.why + ')'),
      key_gaps: gaps.slice(0, 12).map((p) => ({ id: p.id, gap: p.title + ' - ' + s(p.action, 300), recommendation: 'Close with the evidence: ' + ((find(v, p.id) || {}).evidence_hint || 'the record') + '.' })),
      roadmap: gaps.slice(0, 12).map((p) => ({ horizon: H(sevOf(p.id)), action: 'Close ' + p.id + ' (' + p.pillar + '): ' + p.title, requirement: p.id })),
      regulator_note: (ZYB_ORG.short + ' is regulated by the Insurance Authority, which keeps insurers on the SAMA Cyber Security Framework (circular UTC/277/202401). IA view: ') + v.ia.levels.score + ' % met.',
    };
  }
  // the assessor's tools: read-only, over the register already computed; which tools exist is decided here, by role
  const TOOLS = [
    { name: 'list_requirements', roles: ['operator', 'admin'], description: 'List requirements, optionally filtered by pillar and/or result.',
      input_schema: { type: 'object', properties: { pillar: { type: 'string', enum: PILLARS }, result: { type: 'string', enum: ['verified', 'met', 'partial', 'gap', 'pending', 'not_measured', 'no_evidence', 'not_applicable'] } }, additionalProperties: false } },
    { name: 'get_requirement', roles: ['operator', 'admin'], description: 'One requirement with its evidence, result and run history.',
      input_schema: { type: 'object', properties: { id: { type: 'string' } }, required: ['id'], additionalProperties: false } },
    { name: 'get_subdomain', roles: ['operator', 'admin'], description: 'One SAMA subdomain (e.g. 3.3.14) with its indicative maturity and requirements.',
      input_schema: { type: 'object', properties: { id: { type: 'string' } }, required: ['id'], additionalProperties: false } },
  ];
  const brief = (r) => ({ id: r.id, subdomain: r.subdomain, pillar: r.pillar, title: r.title, severity: r.severity, result: r.result, why: s(r.why, 300), history: r.history });
  function runTool(v, who, name, input) {
    const t = TOOLS.find((x) => x.name === name);
    if (!t || !t.roles.includes(who.role)) return { error: 'tool not available: ' + s(name, 40) };   // re-checked on every call
    const i = input && typeof input === 'object' && !Array.isArray(input) ? input : {};
    if (name === 'list_requirements') {
      if (i.pillar !== undefined && !PILLARS.includes(i.pillar)) return { error: 'pillar must be one of ' + PILLARS.join(', ') };
      return v.requirements.concat(v.ia.requirements).filter((r) => (!i.pillar || r.pillar === i.pillar) && (!i.result || r.result === i.result)).slice(0, 60).map((r) => ({ id: r.id, title: r.title, result: r.result, severity: r.severity }));
    }
    if (name === 'get_requirement') { if (!RID.test(String(i.id || ''))) return { error: 'id must look like SA-3.3.8-01' }; const r = find(v, i.id); return r ? brief(r) : { error: 'no requirement ' + i.id }; }
    if (!/^3\.[1-4]\.\d{1,2}$/.test(String(i.id || ''))) return { error: 'id must look like 3.3.14' };
    const x = v.subdomains.find((y) => y.id === i.id); if (!x) return { error: 'no subdomain ' + i.id };
    return { id: x.id, name: x.name, maturity: x.maturity, score: x.score, requirements: v.requirements.filter((r) => r.subdomain === x.id).map(brief) };
  }
  const str = (x, n) => (typeof x === 'string' ? x.slice(0, n) : '');
  function checkReport(o, v, flags) {   // the model's answer is data: keep only the declared fields, ids that exist, horizons we know
    const ids = new Set(v.requirements.concat(v.ia.requirements).map((r) => r.id));
    const gaps = (Array.isArray(o.key_gaps) ? o.key_gaps : []).slice(0, 15).filter((g) => g && ids.has(g.id) ? true : (flags.push('dropped a gap naming an unknown requirement'), false)).map((g) => ({ id: g.id, gap: str(g.gap, 600), recommendation: str(g.recommendation, 600) }));
    const road = (Array.isArray(o.roadmap) ? o.roadmap : []).slice(0, 20).filter((x) => x && HORIZONS.includes(x.horizon) && (!x.requirement || ids.has(x.requirement)) ? true : (flags.push('dropped a roadmap item (unknown horizon or requirement)'), false)).map((x) => ({ horizon: x.horizon, action: str(x.action, 400), requirement: x.requirement || null }));
    const out = { executive_summary: str(o.executive_summary, 3000), strengths: (Array.isArray(o.strengths) ? o.strengths : []).slice(0, 10).map((x) => str(x, 300)).filter(Boolean), key_gaps: gaps, roadmap: road, regulator_note: str(o.regulator_note, 1000) };
    if (!out.executive_summary) throw httpErr(502, 'the AI did not return a usable report - the rule-based report is still available');
    return out;
  }
  async function aiReport(v, who) {
    const st = aiStatus(); if (!st.enabled) throw httpErr(503, st.reason);
    const flags = [];
    const tools = TOOLS.filter((t) => t.roles.includes(who.role)).map(({ name, description, input_schema }) => ({ name, description, input_schema }));
    const ctx = JSON.stringify({ figures: figures(v), subdomains: v.subdomains.map((x) => ({ id: x.id, name: x.name, level: x.maturity.level, rule: x.maturity.why, score: x.score })), priorities: v.priorities.slice(0, 15) });
    const sys = ('You are the AI Assessor of ' + ZYB_ORG.name + ', a Saudi insurer regulated by the Insurance Authority under the SAMA Cyber Security Framework. ')
      + 'You draft the assessment report from the platform\'s register; a person (the CISO) approves it. Use only the register and your read-only tools. Never change or invent a score, a level, a requirement or a fact; '
      + 'the figures are fixed by the platform. Recommendations are proposals for people to decide. When you are done, answer with ONE JSON object with exactly the keys executive_summary, strengths (array of strings), '
      + 'key_gaps (array of {id, gap, recommendation}, id a requirement id), roadmap (array of {horizon: "30 days"|"90 days"|"180 days", action, requirement}), regulator_note.\n\n' + G.UNTRUSTED_RULE;
    const messages = [{ role: 'user', content: G.redactSecrets('Draft the SAMA CSF / IA assessment report. The register summary:\n\n' + G.untrusted('sama:register', ctx)) }];
    flags.push(...G.injectionSignals(ctx).map((n) => 'injection-like text in the register (signal ' + n + ')'));
    const budget = G.sharedBudget({ log: L, limits: () => ((app.config && app.config.ai) || {}).limits || {} });
    const Anthropic = loadSdk(), client = new Anthropic({ apiKey: getKey(), timeout: (cfg().timeout_s || 180) * 1000, maxRetries: 2 });
    let text = '', calls = 0;
    for (let turn = 0; turn < MAX_TURNS; turn++) {
      const q = JSON.stringify(messages).length;
      budget.admit(who.user, 'itam.sama-assessor', q);
      let resp = null, usage = null;
      try { resp = await client.messages.create({ model: st.model, max_tokens: 6000, system: sys, tools, messages }); usage = resp.usage; }
      finally { budget.record(who.user, 'itam.sama-assessor', usage, flags); }
      const uses = (resp.content || []).filter((c) => c.type === 'tool_use');
      text = (resp.content || []).filter((c) => c.type === 'text').map((c) => c.text).join('\n');
      if (!uses.length || resp.stop_reason !== 'tool_use') break;
      messages.push({ role: 'assistant', content: resp.content });
      messages.push({ role: 'user', content: uses.map((u) => { calls++; const out = JSON.stringify(runTool(v, who, u.name, u.input)); flags.push(...G.injectionSignals(out).map((n) => 'injection-like text in ' + u.name + ' output (signal ' + n + ')')); return { type: 'tool_result', tool_use_id: u.id, content: G.untrusted('sama:tool:' + u.name, G.redactSecrets(out)) }; }) });
      if (turn === MAX_TURNS - 1) flags.push('stopped after ' + MAX_TURNS + ' turns');
    }
    const m = text.match(/\{[\s\S]*\}/); let o = null; try { o = m ? JSON.parse(m[0]) : null; } catch (e) { o = null; /* not JSON: reported as unusable below */ }
    if (!o || typeof o !== 'object') throw httpErr(502, 'the AI did not return a usable report - the rule-based report is still available');
    return { content: checkReport(o, v, flags), flags, tool_calls: calls };
  }
  async function report(input, who) {
    person(who, 'draft the SAMA assessment report');
    const b = body(input || {}).bool('use_ai', { def: false }).done();
    const v = await assess();
    let content = ruleReport(v), source = 'rules', flags = [], calls = 0;
    if (b.use_ai) { const a = await aiReport(v, who); content = a.content; source = 'ai'; flags = a.flags; calls = a.tool_calls; }
    const n = reps().all(() => true).length + 1;
    const d = Object.assign({ id: 'SAMA-R-' + String(n).padStart(4, '0'), state: 'draft', source, flags, tool_calls: calls, figures: figures(v), requested_by: who.user, at: iso() }, content);
    reps().put(d);
    audit(who, 'report.draft', d.id, { source, flags: flags.length, tool_calls: calls, score: d.figures.score });
    return d;
  }
  async function decideReport(id0, input, who) {
    const id = param(id0, 'id'); const d = reps().get(id); if (!d) throw httpErr(404, 'no report ' + s(id, 30));
    const b = body(input || {}).oneOf('decision', ['approve', 'reject'], { required: true }).str('note', { max: 1000 })
      .rule((o) => (o.decision === 'reject' && !o.note ? 'note is required: say why it is rejected' : null)).done();
    if (d.state !== 'draft') throw httpErr(409, d.id + ' is ' + d.state);
    needCiso(who, 'approving the SAMA assessment report');
    if (same(d.requested_by, who.user)) throw httpErr(403, 'four eyes: ' + who.user + ' requested ' + d.id + ' and cannot also approve it');
    Object.assign(d, { state: b.decision === 'approve' ? 'approved' : 'rejected', decided_by: who.user, decided_at: iso(), decide_note: b.note || '' });
    reps().put(d);
    audit(who, 'report.' + d.state, d.id, { requested_by: d.requested_by, source: d.source });
    return d;
  }
  const reports = () => reps().all(() => true).sort((a, b) => String(b.at).localeCompare(String(a.at))).slice(0, 30);
  return { view, assess, facts, putProfile, confirm, decide, run, tick, start, gapsToGrc, exportCsv, aiStatus, report, decideReport, reports, TOOLS };
}

function registerSamaIa(srv, app, S) {
  const op = (fn) => (ctx) => { ctx.need('operator'); return fn(ctx); };
  srv.route('GET', '/sama-ia', (ctx) => { ctx.need('viewer'); return S.view(ctx.who); });
  srv.route('GET', '/sama-ia/export', op((ctx) => S.exportCsv(ctx.who)));
  srv.route('POST', '/sama-ia/profile', (ctx) => { ctx.need('admin'); return S.putProfile(ctx.body, ctx.who); });
  srv.route('POST', '/sama-ia/confirm', op((ctx) => S.confirm(ctx.body, ctx.who)));
  srv.route('POST', '/sama-ia/confirm/:id/decide', op((ctx) => S.decide(ctx.params.id, ctx.body, ctx.who)));
  srv.route('POST', '/sama-ia/run', op((ctx) => S.run(ctx.who)));
  srv.route('POST', '/sama-ia/gaps-to-grc', op((ctx) => S.gapsToGrc(ctx.who)));
  srv.route('GET', '/sama-ia/ai/status', op(() => S.aiStatus()));
  srv.route('POST', '/sama-ia/report', op((ctx) => S.report(ctx.body, ctx.who)));
  srv.route('GET', '/sama-ia/reports', op(() => S.reports()));
  srv.route('POST', '/sama-ia/reports/:id/decide', op((ctx) => S.decideReport(ctx.params.id, ctx.body, ctx.who)));
}

module.exports = { createSamaIa, registerSamaIa };
