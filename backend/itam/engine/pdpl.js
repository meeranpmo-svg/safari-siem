// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('./brand');
/*
 * The AI PDPL Consultant: oversees the organisation's compliance with the Saudi Personal Data Protection Law (SDAIA) and
 * prepares the compliance statement the DPO signs. The RULES are in Python (pyengine/pdpl_rules.py): the 24 requirements,
 * what the registers prove, the findings, readiness, and who may sign. This file validates at the boundary, checks the
 * role, calls Python, commits what Python decided, and writes the audit record ("Python decides, Node.js commits").
 *
 * Registers (operator; PDPL - nothing here is published to viewers): profile (DPO, SDAIA registration, privacy policy;
 * admin), records of processing, data subject requests (a reference only - never the person's details), breaches,
 * impact assessments, processors, transfers outside the Kingdom. Records are evidence: archived, never deleted.
 * The consultant is a duty engineer: every gap is a work item for Governance, re-checked each patrol and closed when the
 * register no longer shows it. It proposes nothing for execution and signs nothing: the DPO signs the statement and a
 * different person in management countersigns. The statement is an internal self-assessment, NOT an SDAIA certificate.
 *
 *   GET  /pdpl                          viewer    requirements, counts, readiness, statement status
 *   GET  /pdpl/records?kind=            operator  the registers
 *   POST /pdpl/records                  operator  {kind, id?, ...} (profile: admin)   audited
 *   POST /pdpl/confirm                  operator  {id, status, evidence?, note?}       audited
 *   GET  /pdpl/statement                operator  the statement to read before signing (audited)
 *   POST /pdpl/statement/sign           operator  {as: dpo|management, digest}         audited
 *
 * Automation (the consultant does the legwork, a person decides):
 *   Personal-data discovery - every database with a proven read-only login is scanned READ-ONLY: the Oracle databases on
 *   the Databases page and every Oracle / SQL Server / PostgreSQL login Asset Discovery proved (engine/db-targets.js;
 *   inv-helper ops oracle_pii_scan / db_pii_scan - a login that can write, own or administer is refused). Oracle (the
 *   column dictionary and comments; where the login can already read a table, 50 values are tested INSIDE the helper and
 *   only the number of matches comes back - no value is stored, logged or shown). Python compares what was found with the
 *   records of processing: personal data in a system no activity names, categories an activity does not declare,
 *   sensitive data without an impact assessment. "Adopt" pre-fills a processing activity for the DPO to complete.
 *   GET  /pdpl/discovery                operator  last scan per database + findings
 *   POST /pdpl/discovery/run            admin     scan now (weekly on its own)                      audited
 *   POST /pdpl/discovery/adopt          operator  {db} → a processing activity pre-filled from the scan audited
 *   Breach workflow - a SIEM incident becomes a breach record with the 72-hour clock running; the SDAIA notification
 *   draft (Implementing Regulation Art. 24 contents) and the data subject notice (Arabic / English) are prepared from it.
 *   The platform does NOT send them: SDAIA is notified through its portal, by the DPO.
 *   POST /pdpl/breach/from-incident     operator  {case_id, aware_at?}                              audited
 *   GET  /pdpl/breach/:id/draft         operator  the drafts, the clock, what is still missing          audited
 *   DPIA wizard - a fixed questionnaire scored in Python (likelihood + severity, measures reduce it, every point named);
 *   the result is a draft until the named DPO signs it (not the person who prepared it).
 *   GET  /pdpl/dpia/questions           operator
 *   POST /pdpl/dpia/assess              operator  {ropa_id, answers, measures[], id?}                 audited
 *   POST /pdpl/dpia/:id/sign            operator  the DPO named in the profile; four-eyes              audited
 *   Consent ledger - engine/pdpl-consent.js (purposes are records of kind consent_purpose, admin): systems send grants and
 *   withdrawals with a consent key, check consent before processing; the person's identifier is kept only as a one-way
 *   reference; the ledger is append-only and hash-chained. Its counts feed P-05 (consent records) and P-20 (withdrawal).
 *   Retention schedule - records of kind retention (systems, trigger, period, legal reference, destroy / anonymise,
 *   review interval) and destruction runs. The platform never deletes data: a run is planned by the system owner,
 *   approved by the DPO (or an administrator) who did not plan it, carried out in the system and recorded with evidence.
 *   GET  /pdpl/retention                operator  rules, next destruction due, runs
 *   POST /pdpl/destruction              operator  {retention_id, system, cutoff, note?}               audited
 *   POST /pdpl/destruction/:id/approve  operator  the DPO / an administrator, not the planner, a person audited
 *   POST /pdpl/destruction/:id/reject   operator  {note}                                               audited
 *   POST /pdpl/destruction/:id/done     operator  {count, method, evidence, executed_at}  only after approval  audited
 *   Legal holds - records of kind legal_hold (a claim, court case, complaint, regulator inquiry, investigation or audit
 *   needs records past their retention). An active hold that covers the system a destruction touches stops the plan, the
 *   approval and the recording of the run (re-checked at each step, so a hold placed later still stops it) unless the run
 *   names the hold and states how the held records are excluded. A hold is released by the DPO or an administrator who
 *   did not place it; reviewed every review_months. The case reference only - never the person's details.
 *   GET  /pdpl/holds                    operator  holds, what each covers, review due
 *   POST /pdpl/holds                    operator  {ref, reason, systems[] | all_systems, data_categories[], scope, review_months}  audited
 *   POST /pdpl/holds/:id/review         operator  {note}   still needed                                 audited
 *   POST /pdpl/holds/:id/release        operator  {note}   the DPO / an administrator, not the placer      audited
 *   Sensitive-access log - engine/pdpl-access.js: the claims / medical / fraud systems send who opened which record and
 *   why; exceptions and volume indicators for a reviewer (not the user concerned). Insurer DPIA triggers (fraud scoring,
 *   profiling, automated underwriting, telematics) and reinsurance flows are rules in pdpl_rules.py.
 * The operating pages (one menu page per PDPL area) are engine/pdpl-workflows.js; rules in pyengine/pdpl_workflows.py.
 */
const fs = require('node:fs');
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const KINDS = ['profile', 'ropa', 'dsr', 'breach', 'dpia', 'processor', 'transfer', 'consent_purpose', 'retention', 'destruction', 'sensitive_control', 'steward', 'playbook', 'training', 'maturity', 'accountability', 'committee_meeting', 'pbd_review', 'programme_review', 'legal_hold'];
const WF_ONLY = ['sensitive_control', 'steward', 'playbook', 'training', 'maturity', 'accountability', 'committee_meeting', 'pbd_review', 'programme_review'];   // written only through engine/pdpl-workflows.js
const HOLD_REASONS = ['claim', 'litigation', 'complaint', 'regulator', 'fraud_investigation', 'audit', 'other'];
const TRIGGERS = ['collection', 'end_of_contract', 'policy_expiry', 'claim_closed', 'employment_end', 'last_contact', 'other'];
const isService = (u) => /^(duty|system|ai|svc|service)[:_-]/i.test(String(u || ''));
const DISC_EVERY = 7 * 86400000, DAY = 86400000;
const BASES = ['consent', 'explicit_consent', 'contract', 'legal_obligation', 'vital_interest', 'public_interest', 'legitimate_interest'];
const CATS = ['identity', 'contact', 'financial', 'health', 'credit', 'biometric', 'genetic', 'criminal', 'religious', 'beliefs', 'ethnic', 'parentage', 'location', 'employment', 'other'];
// what flows abroad at an insurer: reinsurance treaties, retrocession, overseas TPAs, treatment abroad, travel assistance, group services, hosting
const FLOWS = ['reinsurance', 'retrocession', 'international_tpa', 'medical_abroad', 'assistance', 'group_service', 'cloud_hosting', 'other'];
const TBASES = ['adequacy', 'bcr', 'scc', 'certification', 'code_of_conduct', 'exemption_contract', 'exemption_public', 'exemption_vital'];
const STATUSES = ['compliant', 'partial', 'non_compliant', 'not_applicable'];
const DT = /^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}(:\d{2}(\.\d{1,3})?)?(Z|[+-]\d{2}:\d{2})?)?$/;

function pythonBin(app, opts) {
  const c = opts.python || ((app.config && app.config.discovery) || {}).python_bin;
  return [c, '/opt/sentra-siem/pyenv/bin/python3'].filter(Boolean).find((p) => fs.existsSync(p)) || 'python3';
}

// PDPL results in the shared compliance language: only what the DPO confirmed counts as compliant
const PDPL_LEVEL = { compliant: 'fully', partial: 'partially', non_compliant: 'not', not_applicable: 'na', auto_pass: 'not_assessed', not_assessed: 'not_assessed' };

function createPdpl(app, opts = {}) {
  const now = opts.now || Date.now, store = app.store;
  const py = opts.py || require('./pyengine').createPyEngine({ python: pythonBin(app, opts), timeoutMs: 30000, resident: false });
  const recs = () => store.collection('pdpl_records'), conf = () => store.collection('pdpl_confirm'), att = () => store.collection('pdpl_statement');
  function tests() {
    const AU = app.addons && app.addons.auditors, out = {};
    if (AU) for (const id of ['itaudit', 'cyberaudit']) for (const t of AU.programme(id, false).tests) out[t.id] = { state: t.state, title: t.title, detail: t.detail };
    try { const Dm = app.addons && app.addons.domains; if (Dm && typeof Dm.view === 'function') out['CY-14'] = Object.assign(out['CY-14'] || {}, { outside_ksa: Number((Dm.view('admin').summary || {}).outside_ksa) || 0 }); }
    catch (e) { if (app.log && app.log.every) app.log.every('pdpl:domains', 600000, 'warn', 'PDPL consultant could not read Domains & Hosting', { err: String(e.message).slice(0, 200) }); }
    return out;
  }
  let C0 = null;
  const consentM = () => C0 || (C0 = opts.consent || require('./pdpl-consent').createConsent(app, { now, sealer: opts.consentSealer, purposes: () => recs().all((r) => r.kind === 'consent_purpose') }));
  // consent purposes carry their ledger counts into the rules (P-05 consent records, P-20 withdrawal)
  async function records() {
    const all = recs().all();
    if (!all.some((r) => r.kind === 'consent_purpose')) return all;
    let st = {}; try { st = await consentM().stats(); } catch (e) { st = {}; if (app.log && app.log.every) app.log.every('pdpl:consent-stats', 600000, 'warn', 'consent ledger counts not readable', { err: String(e.message).slice(0, 200) }); }
    return all.map((r) => (r.kind === 'consent_purpose' ? Object.assign({}, r, st[r.id] || {}) : r));
  }
  async function inputs(extra) {
    const confirms = {}; for (const c of conf().all()) confirms[c.id] = c;
    return Object.assign({ records: await records(), confirms, tests: tests(), now: now(), attestation: att().get('statement') }, extra || {});
  }
  async function call(op, extra) {
    const r = await py.call(op, await inputs(extra));
    if (r && r.ok === false) {
      if (app.log && app.log.every) app.log.every('pdpl:py', 300000, 'error', 'PDPL rules (Python) did not answer', { op, cls: r.error_class, err: String(r.error || '').slice(0, 200) });
      throw httpErr(409, 'The PDPL rules run in Python and Python did not answer (' + (r.error_class || 'error') + ') - run the update so pyengine is installed');
    }
    return r;
  }
  const assess = () => call('pdpl.assess');
  async function view(op) {
    const a = await assess(), st = await call('pdpl.statement');
    // the same four levels as NCA ECC and NDMO (engine/compliance-levels.js); an automated pass still waits for the DPO's confirmation
    const CL = require('./compliance-levels');
    const reqs = a.requirements.map((r) => Object.assign({}, r, { level: CL.levelOf(r.result, PDPL_LEVEL) }));
    return { requirements: reqs, counts: a.counts, compliance_pct: a.compliance_pct, levels: CL.levels(a.requirements, PDPL_LEVEL), by_area: CL.group(a.requirements, 'area', PDPL_LEVEL), readiness: op ? a.readiness : { ready: a.readiness.ready, open: a.readiness.blockers.length, digest: a.readiness.digest },
      findings: op ? a.findings : a.findings.length, statement: st, connected: a.connected, engine: 'python',
      note: 'An internal PDPL self-assessment. The statement is signed by the appointed DPO and countersigned by a different person in management; it is not an SDAIA certificate, and SDAIA (or a body it accredits) remains the only authority for certification. Article references are for the DPO to verify.' };
  }
  function putRecord(b, who) {
    let rec;
    if (b.kind === 'profile') rec = Object.assign({}, recs().get('profile') || {}, b, { id: 'profile' });
    else if (b.id) {
      const cur = recs().get(b.id); if (!cur) throw httpErr(404, 'no PDPL record ' + b.id);
      if (cur.kind !== b.kind) throw httpErr(400, 'kind does not match the record (' + cur.kind + ')');
      rec = Object.assign({}, cur, b);
    } else {
      const n = recs().all((r) => r.kind === b.kind).length + 1;
      let id = 'PD-' + b.kind.toUpperCase() + '-' + String(n).padStart(3, '0'), k = n; while (recs().get(id)) id = 'PD-' + b.kind.toUpperCase() + '-' + String(++k).padStart(3, '0');
      rec = Object.assign({ status: 'active', created_by: who.user, created_at: new Date(now()).toISOString() }, b, { id });
    }
    rec.updated_by = who.user; rec.updated_at = new Date(now()).toISOString();
    recs().put(rec);
    if (app.audit) app.audit({ by: who.user, role: who.role, ip: who.ip || '', action: 'pdpl.record.put', target: rec.id, detail: { kind: rec.kind, fields: Object.keys(b).filter((k) => k !== 'kind' && k !== 'id').sort() } });
    return rec;
  }
  async function confirm(b, who) {
    if (/^(duty|system|ai|svc|service)[:_-]/i.test(String(who.user || ''))) throw httpErr(403, 'a service or AI identity cannot confirm a PDPL requirement');
    const prev = conf().get(b.id);
    const a0 = await assess(); if (!a0.requirements.some((r) => r.id === b.id)) throw httpErr(404, 'no PDPL requirement ' + b.id);
    conf().put({ id: b.id, status: b.status, evidence: b.evidence || '', note: b.note || '', by: who.user, role: who.role, at: new Date(now()).toISOString() });
    if (app.audit) app.audit({ by: who.user, role: who.role, ip: who.ip || '', action: 'pdpl.confirm', target: b.id, detail: { status: b.status, previous: prev ? prev.status : null } });
    return (await assess()).requirements.find((r) => r.id === b.id);
  }
  async function statement(who) {
    const a = await assess(), st = await call('pdpl.statement'), P = recs().get('profile') || {};
    const doc = { title: 'Personal Data Protection Law (PDPL) - Compliance Statement', organisation: ZYB_ORG.name, generated_at: new Date(now()).toISOString(),
      basis: 'Internal self-assessment against the Personal Data Protection Law (Royal Decree M/19, amended by M/148), its Implementing Regulation and the Cross-Border Transfer Regulation, prepared by the AI PDPL Consultant from the records of processing, data subject requests, breaches, impact assessments, processors, transfers and the AI auditors\' security tests, and confirmed requirement by requirement by named people.',
      not_certificate: 'This statement is not a certificate issued by SDAIA or by a body SDAIA has accredited. It records that management and the DPO have assessed the organisation as compliant on the date below.',
      dpo: P.dpo_user || null, sdaia_ref: P.sdaia_ref || null, compliance_pct: a.compliance_pct, counts: a.counts, ready: a.readiness.ready, blockers: a.readiness.blockers, blockers_ar: a.readiness.blockers_ar || a.readiness.blockers, digest: a.readiness.digest,
      requirements: a.requirements.map((r) => ({ id: r.id, area: r.area, title: r.title, ref: r.ref, result: r.result, why: r.why, evidence: r.confirmation ? r.confirmation.evidence : '' })), statement: st };
    if (app.audit) app.audit({ by: who.user, role: who.role, ip: who.ip || '', action: 'pdpl.statement.view', target: a.readiness.digest, detail: { ready: a.readiness.ready, compliance_pct: a.compliance_pct } });
    return doc;
  }
  async function signStatement(b, who) {
    const r = await call('pdpl.sign', { signer: { user: who.user, role: who.role }, as: b.as, digest: b.digest });
    if (r.refuse) throw httpErr(r.refuse.status, r.refuse.error);
    att().put(r.put);
    if (app.audit) app.audit({ by: who.user, role: who.role, ip: who.ip || '', action: r.audit.action, target: r.audit.target, detail: r.audit.detail });
    return await call('pdpl.statement');
  }

  // ---- personal-data discovery
  const disc = () => store.collection('pdpl_discovery');
  const H = () => (app.addons && app.addons.dbHealth) || opts.dbHealth || null;
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role, ip: who.ip || '', action, target, detail }); };
  let scanning = null;
  // Oracle databases registered on the Databases page (dbHealth.piiScan), then every database Asset Discovery proved a
  // read-only login on - Oracle, SQL Server, PostgreSQL (db-targets.js, inv-helper op db_pii_scan). Same rules for all.
  let runHelper = null;
  const helper = () => opts.invRun || runHelper || (runHelper = require('./discovery/methods/login').realRunner(((app.config && app.config.discovery) || {}).python_bin || '/opt/sentra-siem/pyenv/bin/python3'));
  async function helperWith(t, body) {
    const V = app.discovery && app.discovery.vault; if (!V) throw httpErr(409, 'Asset Discovery credential vault not available');
    let c = null;
    try {
      c = V.open(t.cred_id); const tg = c.target || {};
      return await helper()(Object.assign({ engine: t.engine, host: t.ip, port: t.port, username: c.secret.username, password: c.secret.password, service: t.service || tg.service, database: tg.database, tls: tg.tls || 'off', ca_file: tg.ca_file }, body));
    } finally { if (c) try { c.release(); } catch (e) { /* the vault entry is released on its own at the end of the read */ } }
  }
  function scanRec(t, r, at) {
    return { id: t.key, db: t.key, engine: t.engine || 'oracle', label: t.host || t.ip, host: t.ip, port: t.port || null, service: t.service || '', instance: t.instance || '', cred_id: t.cred_id || null, at, ok: !!(r && r.ok),
      error: r && !r.ok ? String(r.error_class || '') + (r.error ? ': ' + String(r.error).slice(0, 200) : '') : '',
      columns: r && r.ok ? (r.columns || []).map((c) => ({ owner: c.owner, table: c.table, column: c.column, type: c.type, rows: c.rows, kind: c.kind, category: c.category, by: c.by, confirmed: c.confirmed === undefined ? null : c.confirmed, sampled: c.sampled, matched: c.matched })) : ((disc().get(t.key) || {}).columns || []),
      scanned_columns: r && r.ok ? r.scanned_columns : null, truncated: !!(r && r.truncated), probed: (r && r.probed) || 0, probe_denied: (r && r.probe_denied) || 0 };
  }
  const discoveryTargets = () => {
    const h = H(), reg = h && typeof h.piiScan === 'function' ? h.targets().list.map((t) => Object.assign({ engine: 'oracle', via: 'dbHealth' }, t)) : [];
    const covered = new Set(reg.map((t) => t.ip + ':' + (t.port || 1521)));
    let more = []; try { more = require('./db-targets').dbTargets(app); } catch (e) { if (e.code !== 'MODULE_NOT_FOUND') throw e; }
    more = more.filter((t) => !(t.engine === 'oracle' && covered.has(t.ip + ':' + t.port)));
    return reg.concat(more);
  };
  async function runDiscovery(who) {
    if (scanning) return scanning;
    scanning = (async () => {
      const T = discoveryTargets();
      // SharePoint / OneDrive runs in the SIEM (its own budget, in the background); an administrator's Scan now starts it too
      let sp = null;
      if (api.catalog && who.role === 'admin') { try { sp = await api.catalog.startSharepoint(who); } catch (e) { sp = { started: false, reason: String(e.message).slice(0, 160) }; } }
      if (!T.length && sp && sp.started !== undefined && (sp.started || sp.running)) { audit(who, 'pdpl.discovery.run', 'sharepoint', { databases: 0, sharepoint: sp }); return { at: new Date(now()).toISOString(), databases: [], sharepoint: sp }; }
      if (!T.length) throw httpErr(409, 'No database with a read-only login yet: register Oracle databases on the Databases page, or let Asset Discovery prove a read-only login on SQL Server / PostgreSQL hosts - nothing to scan');
      const at = new Date(now()).toISOString(), out = [];
      for (const t of T) {
        let r;
        try { r = t.via === 'dbHealth' ? await H().piiScan(t) : await helperWith(t, { op: 'db_pii_scan' }); } catch (e) { r = { ok: false, error: String(e.message || e) }; }
        const rec = scanRec(t, r, at);
        disc().put(rec); out.push({ db: rec.db, engine: rec.engine, label: rec.label, ok: rec.ok, columns: rec.columns.length, error: rec.error });
        if (!rec.ok && app.log && app.log.every) app.log.every('pdpl:scan:' + rec.db, 3600000, 'warn', 'personal-data discovery could not read a database', { engine: rec.engine, host: rec.host, cls: r && r.error_class });
      }
      disc().put({ id: '_last', at, by: who.user, databases: out.length });
      audit(who, 'pdpl.discovery.run', 'databases', { databases: out.length, ok: out.filter((x) => x.ok).length, columns: out.reduce((a, x) => a + x.columns, 0), engines: [...new Set(out.map((x) => x.engine))], sharepoint: sp });
      return { at, databases: out, sharepoint: sp };
    })();
    try { return await scanning; } finally { scanning = null; }
  }
  async function discovery() {
    const scans = disc().all((x) => x.id !== '_last');
    const r = await call('pdpl.discovery', { scans });
    return Object.assign({ last: disc().get('_last') || null, note: 'Column names, comments and row estimates from the data dictionary; where the login may read a table, a sample is tested inside the helper and only the number of matches is kept. No personal data value is stored or shown.' }, r);
  }
  async function adopt(b, who) {
    const s0 = disc().get(b.db); if (!s0 || !s0.ok) throw httpErr(404, 'no successful scan for ' + b.db);
    const cats = [...new Set(s0.columns.filter((c) => c.confirmed !== false).map((c) => c.category))].filter((c) => CATS.includes(c));
    if (!cats.length) throw httpErr(409, 'the scan found no personal data in ' + s0.label);
    const rec = putRecord({ kind: 'ropa', name: 'Personal data in ' + s0.label + ' (from discovery)', systems: [s0.label], data_categories: cats, from_discovery: s0.db,
      sources: 1, purpose: '', owner: '' }, who);
    audit(who, 'pdpl.discovery.adopt', rec.id, { db: s0.db, categories: cats });
    return rec;
  }
  function discoveryDue() { const l = disc().get('_last'); return !l || now() - Date.parse(l.at) > DISC_EVERY; }
  const hasTargets = () => { try { return discoveryTargets().length > 0; } catch (e) { return false; } };

  // ---- breach workflow
  async function breachFromIncident(b, who) {
    if (isService(who.user)) throw httpErr(403, 'a person opens a breach record, not a service identity');
    if (recs().all((r) => r.kind === 'breach' && r.source_case === b.case_id).length) throw httpErr(409, 'a breach record already exists for ' + b.case_id);
    let c = null;
    const L = app.discovery && app.discovery.siem;
    if (opts.siemCase) c = await opts.siemCase(b.case_id);
    else if (L && typeof L.call === 'function') {
      const r = await L.call('GET', '/cases/' + encodeURIComponent(b.case_id), { user: 'system:itam-pdpl', role: 'viewer' });
      if (r && r.status === 404) throw httpErr(404, 'no SIEM incident ' + b.case_id);
      if (!r || r.status !== 200) throw httpErr(502, 'the SIEM did not answer for ' + b.case_id);
      c = r.json;
    } else throw httpErr(503, 'SIEM link not configured');
    const rec = putRecord({ kind: 'breach', ref: b.case_id, source_case: b.case_id, aware_at: b.aware_at || new Date(now()).toISOString().slice(0, 16) + 'Z',
      description: String((c && (c.title + (c.description ? ' - ' + c.description : ''))) || '').slice(0, 1000), incident_severity: c && c.severity, occurred_at: c && c.created ? new Date(c.created).toISOString().slice(0, 16) + 'Z' : undefined }, who);
    audit(who, 'pdpl.breach.from_incident', rec.id, { case_id: b.case_id });
    return rec;
  }
  async function breachDraft(id, who) {
    const b = recs().get(id); if (!b || b.kind !== 'breach') throw httpErr(404, 'no breach record ' + id);
    const r = await call('pdpl.breach_draft', { breach: b, profile: recs().get('profile') || {} });
    audit(who, 'pdpl.breach.draft', id, { hours_left: r.hours_left, missing: r.missing.length });
    return r;
  }

  // ---- DPIA wizard
  const dpiaQuestions = () => call('pdpl.dpia_questions');
  async function dpiaAssess(b, who) {
    if (isService(who.user)) throw httpErr(403, 'a person prepares an impact assessment, not a service identity');
    const ro = recs().get(b.ropa_id); if (!ro || ro.kind !== 'ropa') throw httpErr(404, 'no processing activity ' + b.ropa_id);
    const sc = await call('pdpl.dpia_score', { answers: b.answers, measures: b.measures || [] });
    if (sc.refuse) throw httpErr(sc.refuse.status, sc.refuse.error);
    if (b.id) { const cur = recs().get(b.id); if (!cur || cur.kind !== 'dpia') throw httpErr(404, 'no impact assessment ' + b.id); if (cur.completed) throw httpErr(409, b.id + ' is signed - start a new assessment for a change'); }
    const rec = putRecord(Object.assign({ kind: 'dpia', ropa_id: b.ropa_id, answers: b.answers, measures: b.measures || [], score: sc, outcome: sc.outcome, prepared_by: who.user, wizard: true }, b.id ? { id: b.id } : {}), who);
    audit(who, 'pdpl.dpia.assess', rec.id, { ropa_id: b.ropa_id, residual: sc.residual, level: sc.level });
    return rec;
  }
  function dpiaSign(id, who) {
    const d = recs().get(id); if (!d || d.kind !== 'dpia' || !d.wizard) throw httpErr(404, 'no impact assessment ' + id + ' from the wizard');
    if (d.completed) throw httpErr(409, id + ' is already signed');
    const P = recs().get('profile') || {};
    if (!P.dpo_user) throw httpErr(409, 'no DPO is named in the PDPL profile');
    if (String(P.dpo_user).toLowerCase() !== String(who.user).toLowerCase()) throw httpErr(403, 'only the DPO named in the profile (' + P.dpo_user + ') signs an impact assessment');
    if (String(d.prepared_by).toLowerCase() === String(who.user).toLowerCase()) throw httpErr(403, 'four-eyes: the DPO cannot sign an assessment they prepared - another person prepares it');
    const rec = putRecord({ kind: 'dpia', id, completed: new Date(now()).toISOString().slice(0, 10), approved_by: who.user }, who);
    audit(who, 'pdpl.dpia.sign', id, { outcome: d.outcome, residual: d.score && d.score.residual });
    return rec;
  }

  // ---- consent ledger view
  async function consentView() {
    const C = consentM();
    const r = await call('pdpl.consent_view', { keys: C.keys(), chain: C.verify() });
    return Object.assign({ keys: C.keys(), channels: C.CHANNELS, api: { events: 'POST /agent/consent/events', check: 'GET /agent/consent/check', auth: 'Authorization: Bearer <consent key>' } }, r);
  }

  // ---- retention schedule and destruction runs
  const retentionView = () => call('pdpl.retention_view');
  const human = (who, what) => { if (isService(who.user)) throw httpErr(403, 'a person ' + what + ', not a service identity'); };
  // legal holds: an active hold covering the system stops the run unless the run names it and says how its records are excluded
  async function holdGate(retentionId, system, excluded, step) {
    const r = await call('pdpl.hold_check', { retention_id: retentionId, system, excluded: excluded || [] });
    if (r.blocking.length) throw httpErr(409, 'legal hold ' + r.blocking.map((h) => h.id + ' (' + h.ref + ')').join(', ') + ' covers ' + system + ' - ' + step + ' refused. Release the hold, or plan the run again naming the hold and how its records are excluded');
    return r.covering;
  }
  async function planDestruction(b, who) {
    human(who, 'plans a destruction');
    const q = recs().get(b.retention_id); if (!q || q.kind !== 'retention') throw httpErr(404, 'no retention rule ' + b.retention_id);
    if (b.cutoff > new Date(now() - (Number(q.period_months) || 0) * 30 * DAY).toISOString().slice(0, 10)) throw httpErr(400, 'cutoff is inside the retention period of ' + q.period_months + ' months - only records older than that may be destroyed');
    const ex = b.exclude_holds || [];
    for (const id of ex) { const h = recs().get(id); if (!h || h.kind !== 'legal_hold' || h.status !== 'active') throw httpErr(400, 'exclude_holds: ' + id + ' is not an active legal hold'); }
    const cov = await holdGate(b.retention_id, b.system, ex, 'planning');
    const named = cov.filter((h) => ex.includes(h.id));
    if (ex.length && named.length !== ex.length) throw httpErr(400, 'exclude_holds: ' + ex.filter((id) => !named.some((h) => h.id === id)).join(', ') + ' does not cover ' + b.system);
    const rec = putRecord(Object.assign({ kind: 'destruction', retention_id: b.retention_id, system: b.system, cutoff: b.cutoff, note: b.note || '', action: q.action || 'destroy', status: 'planned' },
      named.length ? { holds_excluded: named.map((h) => ({ id: h.id, ref: h.ref })), exclusion: b.exclusion } : {}), who);
    audit(who, 'pdpl.destruction.plan', rec.id, { retention_id: b.retention_id, system: b.system, cutoff: b.cutoff, holds_excluded: named.map((h) => h.id) });
    return rec;
  }
  async function decideDestruction(id, b, who) {
    human(who, 'approves a destruction');
    const x = recs().get(id); if (!x || x.kind !== 'destruction') throw httpErr(404, 'no destruction run ' + id);
    if (x.status !== 'planned') throw httpErr(409, id + ' is ' + x.status + ' - only a planned run is approved or rejected');
    const P = recs().get('profile') || {};
    const isDpo = P.dpo_user && String(P.dpo_user).toLowerCase() === String(who.user).toLowerCase();
    if (!isDpo && who.role !== 'admin') throw httpErr(403, 'the DPO (' + (P.dpo_user || 'not named') + ') or an administrator approves a destruction');
    if (String(x.created_by).toLowerCase() === String(who.user).toLowerCase()) throw httpErr(403, 'four-eyes: the person who planned the destruction cannot approve it');
    if (b.decision === 'reject' && !b.note) throw httpErr(400, 'note is required: say why the destruction is rejected');
    if (b.decision === 'approve') await holdGate(x.retention_id, x.system, (x.holds_excluded || []).map((h) => h.id), 'approval');
    const t = new Date(now()).toISOString();
    const rec = putRecord(b.decision === 'approve' ? { kind: 'destruction', id, status: 'approved', approved_by: who.user, approved_at: t } : { kind: 'destruction', id, status: 'rejected', rejected_by: who.user, rejected_at: t, reject_note: b.note }, who);
    audit(who, 'pdpl.destruction.' + b.decision, id, { note: String(b.note || '').slice(0, 200) });
    return rec;
  }
  async function doneDestruction(id, b, who) {
    human(who, 'records a destruction');
    const x = recs().get(id); if (!x || x.kind !== 'destruction') throw httpErr(404, 'no destruction run ' + id);
    if (x.status !== 'approved') throw httpErr(409, id + ' is ' + x.status + ' - a destruction is recorded only after it was approved');
    if (Date.parse(b.executed_at) > now() + 300000) throw httpErr(400, 'executed_at cannot be in the future');
    if (Date.parse(b.executed_at) < Date.parse(x.approved_at) - 60000) throw httpErr(400, 'executed_at is before the approval');
    await holdGate(x.retention_id, x.system, (x.holds_excluded || []).map((h) => h.id), 'recording');
    const rec = putRecord({ kind: 'destruction', id, status: 'executed', executed_at: b.executed_at, count: b.count, method: b.method, evidence: b.evidence, executed_recorded_by: who.user }, who);
    audit(who, 'pdpl.destruction.done', id, { count: b.count, method: b.method, evidence: String(b.evidence).slice(0, 200) });
    return rec;
  }

  const holdsView = () => call('pdpl.holds_view');
  function getHold(id) { const h = recs().get(id); if (!h || h.kind !== 'legal_hold') throw httpErr(404, 'no legal hold ' + id); return h; }
  function placeHold(b, who) {
    human(who, 'places a legal hold');
    if (!b.all_systems && !(b.systems || []).length) throw httpErr(400, 'systems is required (or all_systems): say which systems hold the records');
    const t = new Date(now()).toISOString();
    const rec = putRecord({ kind: 'legal_hold', ref: b.ref, reason: b.reason, systems: b.all_systems ? [] : b.systems, all_systems: !!b.all_systems, data_categories: b.data_categories || [], scope: b.scope,
      review_months: b.review_months || 6, status: 'active', placed_by: who.user, placed_at: t, history: [{ at: t, by: who.user, action: 'placed', note: b.scope }] }, who);
    audit(who, 'pdpl.hold.place', rec.id, { ref: b.ref, reason: b.reason, systems: rec.all_systems ? 'all' : rec.systems });
    return rec;
  }
  function reviewHold(id, b, who) {
    human(who, 'reviews a legal hold');
    const h = getHold(id); if (h.status !== 'active') throw httpErr(409, id + ' was released - nothing to review');
    const t = new Date(now()).toISOString();
    const rec = putRecord({ kind: 'legal_hold', id, reviewed_at: t, reviewed_by: who.user, history: (h.history || []).concat([{ at: t, by: who.user, action: 'reviewed', note: b.note }]) }, who);
    audit(who, 'pdpl.hold.review', id, { note: String(b.note).slice(0, 200) });
    return rec;
  }
  function releaseHold(id, b, who) {
    human(who, 'releases a legal hold');
    const h = getHold(id); if (h.status !== 'active') throw httpErr(409, id + ' is already released');
    const P = recs().get('profile') || {};
    const isDpo = P.dpo_user && String(P.dpo_user).toLowerCase() === String(who.user).toLowerCase();
    if (!isDpo && who.role !== 'admin') throw httpErr(403, 'the DPO (' + (P.dpo_user || 'not named') + ') or an administrator releases a legal hold');
    if (String(h.placed_by).toLowerCase() === String(who.user).toLowerCase()) throw httpErr(403, 'four-eyes: the person who placed the hold cannot release it');
    const t = new Date(now()).toISOString();
    const rec = putRecord({ kind: 'legal_hold', id, status: 'released', released_by: who.user, released_at: t, release_note: b.note, history: (h.history || []).concat([{ at: t, by: who.user, action: 'released', note: b.note }]) }, who);
    audit(who, 'pdpl.hold.release', id, { ref: h.ref, note: String(b.note).slice(0, 200) });
    return rec;
  }

  // Arabic title and recommendation for findings built here in Node.js (journal integrity and the like); the Python
  // answers already carry theirs (pyengine/pdpl_ar.py). Without Python the English stays - the work items still open.
  async function arabic(list) {
    const miss = list.filter((f) => f && !f.title_ar);
    if (!miss.length) return list;
    try {
      const r = await py.call('pdpl.translate', { findings: miss });
      if (r && Array.isArray(r.findings)) r.findings.forEach((t, i) => { if (t && t.title_ar && miss[i]) Object.assign(miss[i], { title_ar: t.title_ar, recommendation_ar: t.recommendation_ar }); });
    } catch (e) { if (app.log && app.log.every) app.log.every('pdpl:arabic', 3600000, 'warn', 'Arabic for PDPL findings not computed', { err: String(e.message).slice(0, 200) }); }
    return list;
  }

  // the duty engineer: each gap the registers show is a work item; re-checked every patrol
  let last = null;
  const adapter = {
    id: 'pdpl', name: 'AI PDPL Consultant',
    async findings() {
      const a = await assess(); last = a;
      if (discoveryDue() && hasTargets()) { try { await runDiscovery({ user: 'system:pdpl-consultant', role: 'system' }); } catch (e) { if (app.log && app.log.every) app.log.every('pdpl:discovery', 3600000, 'warn', 'personal-data discovery could not run', { err: String(e.message).slice(0, 200) }); } }
      if (recs().all((r) => r.kind === 'consent_purpose').length) { try { a.findings = a.findings.concat((await consentView()).findings); } catch (e) { if (app.log && app.log.every) app.log.every('pdpl:consent-view', 3600000, 'warn', 'consent ledger findings not computed', { err: String(e.message).slice(0, 200) }); } }
      if (api.workflows) { try { a.findings = a.findings.concat(await api.workflows.findings()); } catch (e) { if (app.log && app.log.every) app.log.every('pdpl:workflows', 3600000, 'warn', 'sensitive-data / processor findings not computed', { err: String(e.message).slice(0, 200) }); } }
      if (api.ropaCampaigns) try { a.findings = a.findings.concat(await api.ropaCampaigns.findings()); } catch (e) { if (app.log && app.log.every) app.log.every('pdpl:ropa-campaign', 3600000, 'warn', 'RoPA campaign findings not computed', { err: String(e.message).slice(0, 200) }); }
      if (api.catalog) try { a.findings = a.findings.concat(await api.catalog.findings()); } catch (e) { if (app.log && app.log.every) app.log.every('pdpl:file-findings', 3600000, 'warn', 'file exposure findings not computed', { err: String(e.message).slice(0, 200) }); }
      if (api.vendor) try { a.findings = a.findings.concat(await api.vendor.findings()); } catch (e) { if (app.log && app.log.every) app.log.every('pdpl:vendor', 3600000, 'warn', 'vendor risk findings not computed', { err: String(e.message).slice(0, 200) }); }
      if (api.intake) try { a.findings = a.findings.concat(await api.intake.findings()); } catch (e) { if (app.log && app.log.every) app.log.every('pdpl:intake', 3600000, 'warn', 'request intake findings not computed', { err: String(e.message).slice(0, 200) }); }
      if (api.access) try { a.findings = a.findings.concat(await api.access.findings()); } catch (e) { if (app.log && app.log.every) app.log.every('pdpl:access', 3600000, 'warn', 'sensitive-access findings not computed', { err: String(e.message).slice(0, 200) }); }
      let d = []; try { d = (await discovery()).findings; } catch (e) { d = []; if (app.log && app.log.every) app.log.every('pdpl:discovery-rules', 3600000, 'warn', 'discovery findings not computed', { err: String(e.message).slice(0, 200) }); }
      const all = a.findings.concat(d);
      return a.connected || all.length ? arabic(all) : null;
    },
    investigate(it) {
      const rq = last && last.requirements.find((x) => String(it.key).indexOf(x.id + ':') === 0);
      if (!rq) return { summary: 'The PDPL requirement is no longer in the catalogue.', checks: [], causes: [] };
      return { summary: rq.id + ' ' + rq.title + ' (' + rq.ref + ') - owned by Governance, Risk & Compliance with the DPO.',
        checks: [{ name: 'Requirement', status: rq.result === 'non_compliant' ? 'fail' : 'warn', detail: rq.result + ': ' + rq.why }, { name: 'Audit procedure', status: 'ok', detail: rq.procedure }],
        causes: [{ cause: it.title, confidence: 'high', fix: it.recommendation }] };
    },
    async verify(it) {
      let a; try { a = await assess(); } catch (e) { return { present: null, note: 'could not re-check: ' + String(e.message).slice(0, 120) }; }
      const present = a.findings.some((f) => f.key === it.key);
      return { present, note: present ? 'the registers still show it' : 'the registers no longer show it' };
    },
  };
  const api = { view, putRecord, confirm, statement, signStatement, assess, adapter, consent: consentM, consentView, retentionView, planDestruction, decideDestruction, doneDestruction, holdsView, placeHold, reviewHold, releaseHold, runDiscovery, discovery, adopt, breachFromIncident, breachDraft, dpiaQuestions, dpiaAssess, dpiaSign, rules: call, records: (kind) => recs().all((r) => !kind || r.kind === kind) };
  // the PDPL operating pages (RoPA, sensitive data, requests, transfers, breach playbook, processors, programme) when installed
  api._now = now;   // the same clock for the Privacy Cockpit (engine/pdpl-cockpit.js)
  try { api.workflows = require('./pdpl-workflows').createWorkflows(app, api, { now }); } catch (e) { if (e.code !== 'MODULE_NOT_FOUND') throw e; api.workflows = null; }
  // optional parts: a file the update did not install leaves its page out (and says so) instead of every PDPL page
  const part = (f, make) => { try { return make(require(f)); } catch (e) { if (e.code !== 'MODULE_NOT_FOUND' || !String(e.message).includes(f.slice(2))) throw e; if (app.log && app.log.every) app.log.every('pdpl:part:' + f, 3600000, 'warn', 'PDPL part not installed - run the update', { file: f }); return null; } };
  api.catalog = part('./pdpl-catalog', (m) => m.createCatalog(app, api, { now, py, disc, helperWith, discoveryTargets }));
  api.ropaCampaigns = part('./pdpl-ropa', (m) => m.createRopa(app, api, { now, py }));   // RoPA by department: campaign, stewards, review
  api.access = part('./pdpl-access', (m) => m.createAccess(app, { now, py }));   // the sensitive-access log the claims / medical / fraud systems send
  api.vendor = part('./pdpl-vendor', (m) => m.createVendor(app, api, { now }));   // vendor risk: tier, questionnaire, residual, schedule
  api.intake = part('./pdpl-intake', (m) => m.createIntake(app, api, { now, sealer: opts.intakeSealer }));   // requests sent in by the customer portal / app / call centre
  return api;
}

function registerPdplRoutes(srv, app, PD) {
  const { body } = require('./check');
  const isOp = (ctx) => ctx.who && (ctx.who.role === 'operator' || ctx.who.role === 'admin');
  srv.route('GET', '/pdpl', async (ctx) => { ctx.need('viewer'); return PD.view(isOp(ctx)); });
  srv.route('GET', '/pdpl/records', (ctx) => {
    ctx.need('operator');   // processing activities, requests and breaches are PDPL records themselves
    const q = body(ctx.query || {}).oneOf('kind', KINDS, {}).done();
    return { records: PD.records(q.kind) };
  });
  srv.route('POST', '/pdpl/records', (ctx) => {
    ctx.need('operator');
    const k = body(ctx.body).oneOf('kind', KINDS, { required: true }).done().kind;
    if (k === 'profile') ctx.need('admin');   // naming the DPO decides who may sign the statement
    const upd = !!(ctx.body && ctx.body.id), need = upd ? {} : { required: true };   // an update sends only what changes
    const v = body(ctx.body).oneOf('kind', KINDS, { required: true }).str('id', { max: 40, re: /^PD-[A-Z_]+-\d{3,}$/, msg: 'id must be a PDPL record id (PD-KIND-nnn)' }).oneOf('status', ['active', 'archived']);
    const dt = (f, o) => v.str(f, Object.assign({ max: 30, re: DT, msg: f + ' must be a date or date-time (YYYY-MM-DD[THH:MM])' }, o || {}));
    if (k === 'profile') { v.str('dpo_user', { max: 80, re: /^[A-Za-z0-9._@-]+$/, msg: 'dpo_user must be the DPO\'s platform user name' }); dt('dpo_appointed'); v.str('privacy_policy_url', { max: 300, re: /^https:\/\/\S+$/, msg: 'privacy_policy_url must be an https:// address' }).bool('privacy_policy_published').bool('sdaia_registered').str('sdaia_ref', { max: 80 }).str('dpo_contact', { max: 160 }).str('dpo_reports_to', { max: 160 }).bool('dpo_can_stop');
      for (const r of ['ia', 'sama', 'nca', 'chi']) v.int('notify_hours_' + r, { min: 1, max: 720 }); }   // other regulators' deadlines, from the circulars followed
    if (k === 'ropa') { v.str('name', Object.assign({}, need, { max: 160  })).str('purpose', { max: 500 }).oneOf('legal_basis', BASES).list('data_categories', { item: CATS, unique: true, max: 15 }).str('subjects', { max: 160 }).int('sources', { min: 1, max: 50 }).bool('automated_decision').bool('large_scale_monitoring').bool('fraud_scoring').bool('profiling').bool('automated_underwriting').bool('telematics').bool('reinsurance_outside').list('reinsurers', { item: 'str', itemMax: 120, max: 30, unique: true }).list('systems', { item: 'str', itemMax: 120, max: 50 }).int('retention_months', { min: 1, max: 1200 }).str('owner', { max: 120 }).bool('lia_done').bool('consent_records').bool('transfer_outside').int('volume', { min: 0, max: 100000000 }).list('recipients', { item: 'str', itemMax: 160, max: 50, unique: true })
      .str('security_measures', { max: 1000 }).str('retention_basis', { max: 300 }).str('controller_notes', { max: 1000 }).list('processor_ids', { item: 'id', max: 50, unique: true }).rule((o) => ((o.processor_ids || []).some((x) => !/^PD-PROCESSOR-\d{3,}$/.test(x)) ? 'processor_ids must be processor ids (PD-PROCESSOR-nnn)' : null)); dt('reviewed'); }
    if (k === 'dsr') { v.str('ref', Object.assign({}, need, { max: 60  })).oneOf('type', ['access', 'copy', 'correction', 'destruction', 'withdraw_consent', 'other'], need); dt('received', need); dt('responded'); v.bool('extended'); dt('extension_notified'); v.oneOf('outcome', ['fulfilled', 'partially', 'refused']).str('refusal_reason', { max: 500 }); }
    if (k === 'breach') { v.str('ref', Object.assign({}, need, { max: 60  })); dt('aware_at', need); dt('sdaia_notified_at'); dt('subjects_notified_at'); v.bool('harm_likely').int('subjects_count', { min: 0, max: 100000000 }).list('categories', { item: CATS, unique: true, max: 13 }).str('description', { max: 1000 }); dt('occurred_at'); v.str('risks', { max: 1000 }).str('measures', { max: 1000 }).str('prevention', { max: 1000 }).str('delay_reason', { max: 500 }); }
    if (k === 'dpia') { v.str('ropa_id', Object.assign({}, need, { re: /^PD-ROPA-\d{3,}$/, msg: 'ropa_id must be a processing activity id (PD-ROPA-nnn)' })); dt('completed'); v.oneOf('outcome', ['acceptable', 'mitigations', 'not_acceptable']).str('approved_by', { max: 120 }); }
    if (k === 'processor') { v.str('name', Object.assign({}, need, { max: 160  })).str('service', { max: 300 }); dt('agreement'); v.list('clauses', { item: ['purpose', 'duration', 'breach_notice', 'subprocessors', 'foreign_law', 'audit_right'], unique: true }); dt('assessed'); v.bool('outside_ksa').oneOf('role', ['processor', 'joint_controller']); }
    if (k === 'consent_purpose') ctx.need('admin');   // what systems may record consent for, and under which notice version
    if (WF_ONLY.includes(k) && !(upd && Object.keys(ctx.body).every((f) => ['kind', 'id', 'status'].includes(f)))) throw Object.assign(new Error(k + ' records are written on their PDPL page (only archiving goes through here)'), { status: 400 });
    if (k === 'destruction') throw Object.assign(new Error('destruction runs go through the destruction workflow (plan, approve, done)'), { status: 400 });
    if (k === 'legal_hold') throw Object.assign(new Error('legal holds go through the legal-hold workflow (place, review, release) - a hold is never archived or edited here'), { status: 400 });
    if (k === 'consent_purpose') { v.str('title', Object.assign({}, need, { max: 160 })).str('description', { max: 1000 }).str('ropa_id', { max: 40, re: /^PD-ROPA-\d{3,}$/, msg: 'ropa_id must be a processing activity id (PD-ROPA-nnn)' }).bool('explicit').bool('marketing').int('version', { min: 1, max: 1000 }).str('notice_url', { max: 300, re: /^https:\/\/\S+$/, msg: 'notice_url must be an https:// address' }); }
    if (k === 'retention') { v.str('name', Object.assign({}, need, { max: 160 })).str('ropa_id', { max: 40, re: /^PD-ROPA-\d{3,}$/, msg: 'ropa_id must be a processing activity id (PD-ROPA-nnn)' }).list('systems', { item: 'str', itemMax: 120, max: 50 }).list('data_categories', { item: CATS, unique: true, max: 15 })
      .int('period_months', Object.assign({}, need, { min: 1, max: 1200 })).oneOf('trigger', TRIGGERS, need).str('legal_ref', { max: 300 }).oneOf('action', ['destroy', 'anonymise'], need).str('owner', { max: 120 }).int('review_months', { min: 1, max: 60 }); }
    if (k === 'transfer') { v.str('name', Object.assign({}, need, { max: 160  })).str('country', Object.assign({}, need, { max: 80  })).str('ropa_id', { max: 40, re: /^PD-ROPA-\d{3,}$/, msg: 'ropa_id must be a processing activity id (PD-ROPA-nnn)' }).oneOf('basis', TBASES); dt('risk_assessed'); v.bool('sensitive').bool('large_scale')
      .oneOf('flow_type', FLOWS).str('counterparty', { max: 160 }).oneOf('data_form', ['aggregated', 'pseudonymised', 'identified']).str('identified_why', { max: 500 }); }
    return PD.putRecord(v.done(), ctx.who);
  });
  srv.route('POST', '/pdpl/confirm', (ctx) => {
    ctx.need('operator');
    const b = body(ctx.body).str('id', { required: true, re: /^P-\d{2}$/, msg: 'id must be a PDPL requirement id (P-nn)' }).oneOf('status', STATUSES, { required: true }).str('evidence', { max: 500 }).str('note', { max: 1000 })
      .rule((o) => ((o.status === 'compliant' || o.status === 'partial') && !o.evidence ? 'evidence is required for a compliant or partially compliant result' : null))
      .rule((o) => ((o.status === 'non_compliant' || o.status === 'not_applicable') && !o.note ? 'note is required: say what is missing, or why the requirement does not apply' : null)).done();
    return PD.confirm(b, ctx.who);
  });
  srv.route('GET', '/pdpl/discovery', async (ctx) => { ctx.need('operator'); return PD.discovery(); });
  srv.route('POST', '/pdpl/discovery/run', async (ctx) => { ctx.need('admin'); return PD.runDiscovery(ctx.who); });
  srv.route('POST', '/pdpl/discovery/adopt', async (ctx) => {
    ctx.need('operator');
    const b = body(ctx.body).str('db', { required: true, max: 200, re: /^[A-Za-z0-9_.:|-]+$/, msg: 'db must be a scanned database key' }).done();
    return PD.adopt(b, ctx.who);
  });
  srv.route('POST', '/pdpl/breach/from-incident', async (ctx) => {
    ctx.need('operator');
    const b = body(ctx.body).str('case_id', { required: true, re: /^CASE-\d{1,9}$/, msg: 'case_id must be a SIEM incident id (CASE-nnnnnn)' }).str('aware_at', { max: 30, re: DT, msg: 'aware_at must be a date-time (YYYY-MM-DDTHH:MM)' }).done();
    return PD.breachFromIncident(b, ctx.who);
  });
  srv.route('GET', '/pdpl/breach/:id/draft', async (ctx) => {
    ctx.need('operator');
    const { param } = require('./check');
    return PD.breachDraft(param(ctx.params.id, 'id'), ctx.who);
  });
  srv.route('GET', '/pdpl/dpia/questions', async (ctx) => { ctx.need('operator'); return PD.dpiaQuestions(); });
  srv.route('POST', '/pdpl/dpia/assess', async (ctx) => {
    ctx.need('operator');
    const b = body(ctx.body).str('ropa_id', { required: true, re: /^PD-ROPA-\d{3,}$/, msg: 'ropa_id must be a processing activity id (PD-ROPA-nnn)' }).str('id', { re: /^PD-DPIA-\d{3,}$/, msg: 'id must be an impact assessment id (PD-DPIA-nnn)' })
      .list('measures', { max: 20, item: 'id' }).done();
    const a = ctx.body && ctx.body.answers;
    if (!a || typeof a !== 'object' || Array.isArray(a)) throw Object.assign(new Error('answers must be an object {question: option}'), { status: 400 });
    const answers = {}; for (const [k, v] of Object.entries(a).slice(0, 30)) { if (!/^[a-z_]{1,30}$/.test(k) || typeof v !== 'string' || v.length > 60) throw Object.assign(new Error('answers: ' + k.slice(0, 30) + ' is not a valid answer'), { status: 400 }); answers[k] = v; }
    b.answers = answers;
    return PD.dpiaAssess(b, ctx.who);
  });
  srv.route('POST', '/pdpl/dpia/:id/sign', async (ctx) => {
    ctx.need('operator');
    const { param } = require('./check');
    const id = param(ctx.params.id, 'id'); if (!/^PD-DPIA-\d{3,}$/.test(id)) throw Object.assign(new Error('id must be an impact assessment id (PD-DPIA-nnn)'), { status: 400 });
    return PD.dpiaSign(id, ctx.who);
  });
  require('./pdpl-consent').registerConsentRoutes(srv, app, PD.consent(), PD);
  if (PD.workflows) require('./pdpl-workflows').registerWorkflowRoutes(srv, app, PD.workflows);
  if (PD.access) require('./pdpl-access').registerAccessRoutes(srv, app, PD.access);
  if (PD.ropaCampaigns) require('./pdpl-ropa').registerRopaRoutes(srv, app, PD.ropaCampaigns);
  if (PD.catalog) require('./pdpl-catalog').registerCatalogRoutes(srv, app, PD.catalog);
  if (PD.vendor) require('./pdpl-vendor').registerVendorRoutes(srv, app, PD.vendor);
  // the Privacy Cockpit: every clock, the request models, the activity risk (engine/pdpl-cockpit.js)
  { const CM = require('./pdpl-cockpit'); const C = CM.createPdplCockpit(app, { now: PD._now }); CM.registerPdplCockpit(srv, app, C); (app.addons = app.addons || {}).pdplCockpit = C; }
  if (PD.intake) require('./pdpl-intake').registerIntakeRoutes(srv, app, PD.intake);
  srv.route('GET', '/pdpl/retention', async (ctx) => { ctx.need('operator'); return PD.retentionView(); });
  const DID = (ctx) => { const id = require('./check').param(ctx.params.id, 'id'); if (!/^PD-DESTRUCTION-\d{3,}$/.test(id)) throw Object.assign(new Error('id must be a destruction run id (PD-DESTRUCTION-nnn)'), { status: 400 }); return id; };
  const DATE = { required: true, max: 10, re: /^\d{4}-\d{2}-\d{2}$/, msg: 'cutoff must be a date (YYYY-MM-DD)' };
  srv.route('POST', '/pdpl/destruction', (ctx) => {
    ctx.need('operator');
    const b = body(ctx.body).str('retention_id', { required: true, re: /^PD-RETENTION-\d{3,}$/, msg: 'retention_id must be a retention rule id (PD-RETENTION-nnn)' }).str('system', { required: true, max: 120 }).str('cutoff', DATE).str('note', { max: 500 })
      .list('exclude_holds', { item: 'id', max: 20, unique: true }).str('exclusion', { max: 500 })
      .rule((o) => ((o.exclude_holds || []).some((x) => !/^PD-LEGAL_HOLD-\d{3,}$/.test(x)) ? 'exclude_holds must be legal hold ids (PD-LEGAL_HOLD-nnn)' : null))
      .rule((o) => ((o.exclude_holds || []).length && String(o.exclusion || '').trim().length < 10 ? 'exclusion is required: say how the records under the hold are left out of this run (at least 10 characters)' : null)).done();
    return PD.planDestruction(b, ctx.who);
  });
  srv.route('POST', '/pdpl/destruction/:id/approve', (ctx) => { ctx.need('operator'); return PD.decideDestruction(DID(ctx), { decision: 'approve' }, ctx.who); });
  srv.route('POST', '/pdpl/destruction/:id/reject', (ctx) => {
    ctx.need('operator');
    const b = body(ctx.body).str('note', { required: true, max: 500 }).done();
    return PD.decideDestruction(DID(ctx), { decision: 'reject', note: b.note }, ctx.who);
  });
  srv.route('POST', '/pdpl/destruction/:id/done', (ctx) => {
    ctx.need('operator');
    const b = body(ctx.body).int('count', { required: true, min: 0, max: 1000000000 }).oneOf('method', ['deleted', 'anonymised', 'purged_with_backups', 'media_destroyed'], { required: true })
      .str('evidence', { required: true, max: 300 }).str('executed_at', { required: true, max: 30, re: DT, msg: 'executed_at must be a date or date-time' }).done();
    return PD.doneDestruction(DID(ctx), b, ctx.who);
  });
  const HID = (ctx) => { const id = require('./check').param(ctx.params.id, 'id'); if (!/^PD-LEGAL_HOLD-\d{3,}$/.test(id)) throw Object.assign(new Error('id must be a legal hold id (PD-LEGAL_HOLD-nnn)'), { status: 400 }); return id; };
  srv.route('GET', '/pdpl/holds', async (ctx) => { ctx.need('operator'); return PD.holdsView(); });
  srv.route('POST', '/pdpl/holds', (ctx) => {
    ctx.need('operator');
    const b = body(ctx.body).str('ref', { required: true, max: 80, re: /^[A-Za-z0-9][A-Za-z0-9 ._\/#-]*$/, msg: 'ref must be the case reference (claim no., court case no., complaint no.) - letters, digits, . _ / # -' })
      .oneOf('reason', HOLD_REASONS, { required: true }).list('systems', { item: 'str', itemMax: 120, max: 50, unique: true }).bool('all_systems').list('data_categories', { item: CATS, unique: true, max: 15 })
      .str('scope', { required: true, min: 10, max: 500 }).int('review_months', { min: 1, max: 24 }).done();
    return PD.placeHold(b, ctx.who);
  });
  srv.route('POST', '/pdpl/holds/:id/review', (ctx) => { ctx.need('operator'); return PD.reviewHold(HID(ctx), body(ctx.body).str('note', { required: true, min: 5, max: 500 }).done(), ctx.who); });
  srv.route('POST', '/pdpl/holds/:id/release', (ctx) => { ctx.need('operator'); return PD.releaseHold(HID(ctx), body(ctx.body).str('note', { required: true, min: 10, max: 500 }).done(), ctx.who); });
  srv.route('GET', '/pdpl/statement', (ctx) => { ctx.need('operator'); return PD.statement(ctx.who); });
  srv.route('POST', '/pdpl/statement/sign', (ctx) => {
    ctx.need('operator');
    const b = body(ctx.body).oneOf('as', ['dpo', 'management'], { required: true }).str('digest', { required: true, re: /^sha256:[0-9a-f]{64}$/, msg: 'digest must be the statement digest (sha256:…)' }).done();
    return PD.signStatement(b, ctx.who);
  });
}

module.exports = { PDPL_LEVEL, createPdpl, registerPdplRoutes, KINDS };
