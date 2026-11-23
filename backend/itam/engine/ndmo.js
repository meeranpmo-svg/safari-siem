// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const fs = require('node:fs');
const { body, param } = require('./check');
/*
 * NDMO data management register (NDMO, {P} = /api/itam): the 15 domains of the NDMO Data Management and Personal Data
 * Protection Standards, tailored to the organisation as an insurer. Python decides (pyengine/ndmo_rules.py); this file
 * validates at the boundary, gathers the facts the platform already holds, commits and audits.
 *
 * Facts are read, never written: the AI PDPL Consultant's requirements and findings (the Personal Data Protection domain IS
 * the PDPL register), the PDPL records (processing activities, stewards, training, committee, privacy-by-design reviews,
 * retention, destruction, processors, transfers), the Data Catalog scans, the GRC policy register (the signed set and the
 * drafts approved on Policies & Controls), database monitoring, backup platforms, application route maps and assets.
 *
 * A person records a control (evidence for compliant / partial, a note for non-compliant / not applicable) and a second
 * person approves it - the Chief Data Officer named in the NDMO profile or an administrator, never the one who recorded it,
 * never a service or AI identity. The registers win over a person: automated evidence of a gap is never hidden. The official
 * NDMO control list is imported from the NDMO document (rows of code, domain, title, specification) and each official
 * control is mapped to a register control; Python suggests a mapping, an administrator accepts it.
 *
 *   GET  /ndmo                              viewer    domains, controls, maturity, coverage, PDPL link
 *   GET  /ndmo/suggest                      operator  a register control suggested for each unmapped official control
 *   GET  /ndmo/export                       operator  the register as CSV (with the official codes mapped)          audited
 *   POST /ndmo/profile                      admin     {cdo_user, dmo_established, strategy_approved, committee_last_met,
 *                                                      applicability{OD,FOI}, applicability_note{OD,FOI}}            audited
 *   POST /ndmo/confirm                      operator  {id, status, evidence?, note?}  a person, not a service        audited
 *   POST /ndmo/confirm/:id/decide           operator  {decision: approve|reject, note?}  CDO / administrator, four eyes  audited
 *   POST /ndmo/official                     admin     {rows[{code, domain, title, spec?}], replace?}               audited
 *   POST /ndmo/mapping                      admin     {code, control} | {code, remove: true} | {accept: [codes]}   audited
 *   POST /ndmo/gaps-to-grc                  operator  CDO / administrator: every gap becomes a GRC action (once)   audited
 *
 * The duty engineer (id ndmo, "AI Data Governance Officer") turns each gap into a work item and closes it when the
 * register no longer shows it. It proposes; it never approves and never changes a system.
 */
const STATUSES = ['compliant', 'partial', 'non_compliant', 'not_applicable'];
const CID = /^ZS-[A-Z]{2,3}-\d{2}$/;
const CODE = /^[A-Za-z]{1,6}[ ._-]?\d{1,3}(?:[._-]\d{1,3}){0,3}[A-Za-z]?$/;
const USER = { max: 80, re: /^[A-Za-z0-9._@\\-]{2,80}$/, msg: 'a user name (letters, digits, . _ - @ \\)' };
const DAY = 86400000;
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const isService = (u) => /^(duty|system|core|ai|svc|service|agent|bot)[:._-]/i.test(String(u || ''));
const same = (a, b) => !!a && String(a).trim().toLowerCase() === String(b || '').trim().toLowerCase();

function pythonBin(app, opts) {
  const c = opts.python || ((app.config && app.config.discovery) || {}).python_bin;
  return [c, '/opt/sentra-siem/pyenv/bin/python3'].filter(Boolean).find((p) => fs.existsSync(p)) || 'python3';
}

// NDMO results in the shared compliance language (an automated pass counts as met, as it does in the NDMO score)
const NDMO_LEVEL = { met: 'fully', auto_pass: 'fully', partial: 'partially', gap: 'not', not_applicable: 'na', pending: 'not_assessed', no_evidence: 'not_assessed' };

function createNdmo(app, opts = {}) {
  const now = opts.now || Date.now, store = app.store;
  const iso = () => new Date(now()).toISOString();
  const prof = () => store.collection('ndmo_profile'), conf = () => store.collection('ndmo_confirm'), off = () => store.collection('ndmo_official'), map = () => store.collection('ndmo_mapping');
  let pyE = null;
  const py = () => opts.py || pyE || (pyE = require('./pyengine').createPyEngine({ python: pythonBin(app, opts), timeoutMs: 60000, resident: false }));
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role, ip: who.ip || '', action, target, detail }); };
  const warn = (key, msg, err) => { if (app.log && app.log.every) app.log.every('ndmo:' + key, 3600000, 'warn', msg, { err: String((err && err.message) || err || '').slice(0, 200) }); };
  async function rules(op, input) {
    const r = await py().call(op, input || {});
    if (!r || r.ok === false) {
      warn('py', 'NDMO: the rules (Python) did not answer', r && r.error);
      throw httpErr(409, 'The NDMO rules run in Python and Python did not answer - run the update so pyengine is installed');
    }
    return r;
  }
  const profile = () => prof().get('profile') || {};
  const confirms = () => { const o = {}; for (const c of conf().all(() => true)) o[c.id] = c; return o; };
  const official = () => off().all(() => true).sort((a, b) => String(a.code).localeCompare(String(b.code), 'en', { numeric: true }));
  const mapping = () => { const o = {}; for (const m of map().all(() => true)) o[m.id] = m.control; return o; };
  const within = (v, days) => { const t = Date.parse(v || ''); return Number.isFinite(t) && now() - t <= days * DAY; };
  const count = (name, fn) => { try { return store.collection(name).all(fn || (() => true)).length; } catch (e) { warn('count:' + name, 'NDMO: could not read ' + name, e); return 0; } };

  // ---- the facts the platform already holds (read-only); each source on its own, so one missing source leaves the others
  async function facts() {
    const F = { pdpl: { available: false }, records: {}, catalog: {}, grc_policies: [], ops: {} };
    const PD = app.addons && app.addons.pdpl;
    if (PD) {
      try {
        const a = await PD.assess(), req = {};
        for (const r of a.requirements || []) req[r.id] = r.result;
        let fd = a.findings || [];
        try { if (PD.workflows) fd = fd.concat(await PD.workflows.findings()); } catch (e) { warn('pdpl-wf', 'NDMO: PDPL sensitive-data findings not read', e); }
        const keys = count('pdpl_access_keys', (k) => !k.revoked && k.status !== 'revoked');
        F.pdpl = { available: true, compliance_pct: a.compliance_pct, requirements: req, findings: fd.map((f) => ({ key: f.key, severity: f.severity })), access_connected: keys > 0 };
        const R = (k) => { try { return PD.records(k) || []; } catch (e) { return []; } };
        const ropa = R('ropa').filter((r) => r.status !== 'archived');
        const full = (r) => r.owner && r.purpose && r.legal_basis && (r.data_categories || []).length && (r.systems || []).length && r.retention_months;
        const date = (r) => r.date || r.created_at;
        const procs = R('processor').filter((r) => r.status !== 'archived'), tr = R('transfer').filter((r) => r.status !== 'archived');
        const meetings = R('committee_meeting').map((m) => m.date).filter(Boolean).sort();
        const reviews = R('programme_review').map((m) => m.date).filter(Boolean).sort();
        F.records = {
          ropa_total: ropa.length, ropa_complete: ropa.filter(full).length, ropa_with_retention: ropa.filter((r) => r.retention_months).length,
          ropa_with_categories: ropa.filter((r) => (r.data_categories || []).length).length,
          ropa_departments: [...new Set(ropa.map((r) => r.owner).filter(Boolean))], stewards_departments: [...new Set(R('steward').filter((s) => s.status !== 'archived').map((s) => s.department).filter(Boolean))],
          training_12m: R('training').filter((t) => within(date(t), 365)).length, committee_last: meetings[meetings.length - 1] || null,
          pbd_12m: R('pbd_review').filter((p) => within(p.created_at, 365)).length, programme_review_last: reviews[reviews.length - 1] || null,
          retention_rules: R('retention').filter((r) => r.status !== 'archived').length,
          destruction_done_12m: R('destruction').filter((d) => d.status === 'executed' && within(d.executed_at, 365)).length,
          destruction_due: (a.findings || []).filter((f) => /^P-12:retention:[^:]+:overdue$/.test(f.key || '')).length,
          holds_overdue: (a.findings || []).filter((f) => /^P-12:retention:hold:.*:review$/.test(f.key || '')).length,
          processors: procs.length, processors_with_agreement: procs.filter((p) => p.agreement).length,
          transfers: tr.length, transfers_with_basis: tr.filter((t) => t.basis).length,
        };
      } catch (e) { warn('pdpl', 'NDMO: the PDPL registers could not be read', e); F.pdpl = { available: false }; }
    }
    try {
      const scans = store.collection('pdpl_discovery').all((x) => x.id !== '_last'), last = store.collection('pdpl_discovery').get('_last');
      F.catalog = { db_scans: scans.filter((x) => x.ok !== false).length, db_last_scan: last ? last.at : null, files_scanned: 0 };
      if (PD && PD.catalog && opts.catalogFiles !== false) {
        try { const v = await PD.catalog.view({ user: 'system:ndmo', role: 'admin' }); F.catalog.files_scanned = Array.isArray(v.files) ? v.files.length : (v.files && v.files.total) || 0; } catch (e) { warn('catalog', 'NDMO: the Data Catalog file discovery was not read', e); }
      }
    } catch (e) { warn('catalog-db', 'NDMO: the Data Catalog scans were not read', e); }
    try {
      const signed = require('./grc-policy-file')();
      F.grc_policies = (Array.isArray(signed) ? signed : signed.policies || []).map((p) => ({ title: p.title, status: p.status, next_review: p.next_review }))
        .concat(store.collection('grc_drafts').all((d) => d.status === 'approved').map((d) => ({ title: d.title, status: 'approved', next_review: d.next_review || null })));
    } catch (e) { warn('grc', 'NDMO: the GRC policy register was not read', e); }
    const rep = (r) => r.at || r.date || r.created_at;
    F.ops = { db_targets: count('db_health_targets'), morning_reports_7d: count('db_morning_reports', (r) => within(rep(r), 7)), backup_platforms: count('backup_platforms'),
      backup_objects: count('backup_objects'), app_routes: count('app_route'), assets: count('assets', (a) => a.status !== 'disposed') };
    return F;
  }

  async function view() {
    const v = await rules('ndmo.view', { facts: await facts(), profile: profile(), confirms: confirms(), official: official(), mapping: mapping(), now: now() });
    const p = profile();
    return Object.assign({}, v, { profile: { cdo_user: p.cdo_user || null, dmo_established: p.dmo_established || null, strategy_approved: p.strategy_approved || null,
      committee_last_met: p.committee_last_met || null, applicability: p.applicability || {}, applicability_note: p.applicability_note || {}, updated_by: p.updated_by || null, updated_at: p.updated_at || null },
    official_total: official().length, generated_at: iso() }, levelsOf(v));
  }
  // the same four levels as NCA ECC and PDPL (engine/compliance-levels.js), overall and per domain; every control gets its level
  function levelsOf(v) {
    const CL = require('./compliance-levels');
    for (const c of v.controls) c.level = CL.levelOf(c.result, NDMO_LEVEL);
    return { levels: CL.levels(v.controls, NDMO_LEVEL), domain_levels: CL.group(v.controls, 'domain', NDMO_LEVEL, (v.domains || []).map((d) => [d.code, d.name])) };
  }

  function putProfile(input, who) {
    const b = body(input || {}).str('cdo_user', USER).date('dmo_established', { notFuture: true, now: now() }).date('strategy_approved', { notFuture: true, now: now() })
      .date('committee_last_met', { notFuture: true, now: now() }).done();
    const appl = {}, notes = {};
    const a = (input || {}).applicability, n = (input || {}).applicability_note;
    if (a !== undefined) {
      if (!a || typeof a !== 'object' || Array.isArray(a)) throw httpErr(400, 'applicability must be an object {OD, FOI}');
      for (const k of Object.keys(a)) { if (!['OD', 'FOI'].includes(k)) throw httpErr(400, 'applicability: ' + k + ' is not a domain that needs a decision (OD, FOI)'); Object.assign(appl, body(a).oneOf(k, ['applies', 'partial', 'not_applicable']).done()); }
    }
    if (n !== undefined) {
      if (!n || typeof n !== 'object' || Array.isArray(n)) throw httpErr(400, 'applicability_note must be an object {OD, FOI}');
      for (const k of Object.keys(n)) { if (!['OD', 'FOI'].includes(k)) throw httpErr(400, 'applicability_note: ' + k + ' is not OD or FOI'); Object.assign(notes, body(n).str(k, { max: 500 }).done()); }
    }
    for (const k of Object.keys(appl)) if (appl[k] === 'not_applicable' && !(notes[k] || (profile().applicability_note || {})[k])) throw httpErr(400, 'applicability_note.' + k + ' is required: say why the domain does not apply');
    const cur = profile();
    const rec = Object.assign({}, cur, b, { id: 'profile', applicability: Object.assign({}, cur.applicability, appl), applicability_note: Object.assign({}, cur.applicability_note, notes), updated_by: who.user, updated_at: iso() });
    prof().put(rec);
    audit(who, 'ndmo.profile', 'profile', { fields: Object.keys(b).concat(Object.keys(appl).map((k) => 'applicability.' + k)), cdo_user: rec.cdo_user || null });
    return rec;
  }

  async function confirm(input, who) {
    if (isService(who.user)) throw httpErr(403, 'a service or AI identity cannot record an NDMO control: a person does');
    const b = body(input || {}).str('id', { required: true, re: CID, msg: 'id must be a register control (ZS-XX-nn)' }).oneOf('status', STATUSES, { required: true })
      .str('evidence', { max: 500 }).str('note', { max: 1000 })
      .rule((o) => ((o.status === 'compliant' || o.status === 'partial') && !o.evidence ? 'evidence is required for compliant / partial: name the document, register or record relied on' : null))
      .rule((o) => ((o.status === 'non_compliant' || o.status === 'not_applicable') && !o.note ? 'note is required: say what is missing, or why it does not apply' : null)).done();
    const v = await view();
    if (!v.controls.some((c) => c.id === b.id)) throw httpErr(404, 'no NDMO register control ' + b.id);
    const prev = conf().get(b.id);
    conf().put({ id: b.id, status: b.status, evidence: b.evidence || '', note: b.note || '', by: who.user, role: who.role, at: iso(), approved_by: null, approved_at: null });
    audit(who, 'ndmo.confirm', b.id, { status: b.status, previous: prev ? prev.status : null, evidence: b.evidence ? 'given' : 'none' });
    return (await view()).controls.find((c) => c.id === b.id);
  }

  async function decide(id, input, who) {
    const cid = param(id);
    if (!CID.test(cid)) throw httpErr(400, 'id must be a register control (ZS-XX-nn)');
    const b = body(input || {}).oneOf('decision', ['approve', 'reject'], { required: true }).str('note', { max: 1000 })
      .rule((o) => (o.decision === 'reject' && !o.note ? 'note is required: say why it is rejected' : null)).done();
    const c = conf().get(cid); if (!c) throw httpErr(404, 'nothing recorded for ' + cid + ' yet');
    if (c.approved_by) throw httpErr(409, cid + ' was already approved by ' + c.approved_by);
    if (isService(who.user)) throw httpErr(403, 'only a person approves: ' + who.user + ' is a service / AI identity');
    if (!(who.role === 'admin' || same(profile().cdo_user, who.user))) throw httpErr(403, 'approving an NDMO control needs the Chief Data Officer named in the NDMO profile or an administrator');
    if (same(c.by, who.user)) throw httpErr(403, 'four eyes: ' + who.user + ' recorded ' + cid + ' and cannot also approve it');
    if (b.decision === 'reject') {
      conf().remove(cid);
      audit(who, 'ndmo.confirm.reject', cid, { recorded_by: c.by, status: c.status, note: b.note });
    } else {
      conf().put(Object.assign({}, c, { approved_by: who.user, approved_at: iso(), approve_note: b.note || '' }));
      audit(who, 'ndmo.confirm.approve', cid, { recorded_by: c.by, status: c.status });
    }
    return (await view()).controls.find((x) => x.id === cid);
  }

  async function importOfficial(input, who) {
    const b = body(input || {}).list('rows', { required: true, max: 3000 }).bool('replace', { def: true }).done();
    const rows = b.rows.map((r, i) => {
      if (!r || typeof r !== 'object' || Array.isArray(r)) throw httpErr(400, 'rows[' + i + '] must be an object {code, domain, title, spec}');
      try { return body(r).str('code', { required: true, max: 30 }).str('domain', { required: true, max: 120 }).str('title', { required: true, max: 1000 }).str('spec', { max: 4000 }).done(); }
      catch (e) { throw httpErr(400, 'rows[' + i + '].' + e.message); }
    });
    const r = await rules('ndmo.import', { rows });
    if (!r.rows.length) throw httpErr(400, 'no row could be imported: ' + (r.errors || []).slice(0, 5).join('; '));
    if (b.replace) for (const o of off().all(() => true)) off().remove(o.id);
    for (const o of r.rows) off().put(Object.assign({ id: o.code }, o, { imported_by: who.user, imported_at: iso() }));
    // a mapping whose official code is no longer in the list is dropped
    const codes = new Set(official().map((o) => o.code));
    for (const m of map().all(() => true)) if (!codes.has(m.id)) map().remove(m.id);
    audit(who, 'ndmo.official.import', 'official', { imported: r.rows.length, errors: r.error_count || 0, replace: b.replace });
    return { imported: r.rows.length, errors: r.errors, error_count: r.error_count || 0, total: official().length };
  }

  async function suggest() {
    return rules('ndmo.suggest', { official: official(), mapping: mapping() });
  }

  async function setMapping(input, who) {
    const src = input || {};
    if (src.accept !== undefined) {
      const b = body(src).list('accept', { required: true, max: 3000, item: 'str', itemMax: 30 }).done();
      const s = await suggest(), by = {}; for (const x of s.suggestions || []) by[x.code] = x.control;
      const done = [], skipped = [];
      for (const code of b.accept) { if (by[code]) { map().put({ id: code, control: by[code], by: who.user, at: iso(), suggested: true }); done.push(code); } else skipped.push(code); }
      audit(who, 'ndmo.mapping.accept', 'official', { accepted: done.length, skipped: skipped.length });
      return { accepted: done.length, skipped };
    }
    const b = body(src).str('code', { required: true, max: 30, re: CODE, msg: 'code must be an official control code (e.g. DG.1.1)' }).str('control', { re: CID, msg: 'control must be a register control (ZS-XX-nn)' }).bool('remove').done();
    if (!off().get(b.code)) throw httpErr(404, 'official control ' + b.code + ' is not in the imported list');
    if (b.remove) { map().remove(b.code); audit(who, 'ndmo.mapping.remove', b.code, {}); return { code: b.code, control: null }; }
    if (!b.control) throw httpErr(400, 'control is required (or remove: true)');
    const v = await view();
    if (!v.controls.some((c) => c.id === b.control)) throw httpErr(400, 'control: no register control ' + b.control);
    const prev = map().get(b.code);
    map().put({ id: b.code, control: b.control, by: who.user, at: iso() });
    audit(who, 'ndmo.mapping', b.code, { control: b.control, previous: prev ? prev.control : null });
    return { code: b.code, control: b.control };
  }

  async function gapsToGrc(who) {
    if (isService(who.user)) throw httpErr(403, 'a service or AI identity cannot raise GRC actions from the NDMO register');
    if (!(who.role === 'admin' || same(profile().cdo_user, who.user))) throw httpErr(403, 'sending NDMO gaps to GRC needs the Chief Data Officer named in the NDMO profile or an administrator');
    const G = (app.addons && app.addons.grcRegisters) || (() => { try { return require('./grc-registers').createGrcRegisters(app); } catch (e) { warn('grc-reg', 'NDMO: the GRC registers are not installed', e); return null; } })();
    if (!G) throw httpErr(409, 'the GRC registers are not installed - run the update');
    const v = await view(), out = { created: [], skipped: [] };
    const due = { high: 30, medium: 60, low: 90 };
    for (const c of v.controls.filter((x) => x.result === 'gap')) {
      const pri = c.severity === 'high' ? 'high' : c.severity === 'medium' ? 'medium' : 'low';
      try {
        const act = G.actionCreate({ title: 'NDMO ' + c.id + ' (' + c.domain_name + '): ' + c.title.slice(0, 150), source: 'ndmo', ref: 'ndmo:' + c.id, framework: 'NDMO', priority: pri,
          due: new Date(now() + due[pri] * DAY).toISOString().slice(0, 10), description: 'NDMO register gap: ' + String(c.why || '').slice(0, 500) + (c.official.length ? ' Official controls: ' + c.official.join(', ') + '.' : '') + ' Close it with the evidence: ' + c.evidence_hint + '.' }, who);
        out.created.push(act.id);
      } catch (e) { out.skipped.push(c.id + ': ' + String(e.message).slice(0, 120)); }
    }
    audit(who, 'ndmo.gaps_to_grc', 'register', { created: out.created.length, skipped: out.skipped.length });
    return out;
  }

  async function exportCsv(who) {
    const v = await view();
    const q = (s) => { const t = String(s == null ? '' : s); return /^[=+\-@\t\r]/.test(t) ? "'" + t : t; };   // no formula injection in Excel
    const cell = (s) => '"' + q(s).replace(/"/g, '""') + '"';
    const ST = { fully_compliant: 'Fully compliant', partially_compliant: 'Partially compliant', not_compliant: 'Not compliant', not_assessed: 'Not assessed', not_applicable: 'Not applicable' };
    const LV = { fully: 'Fully compliant', partially: 'Partially compliant', not: 'Not compliant', not_assessed: 'Not assessed', not_applicable: 'Not applicable' };
    const lines = [['Level', 'Code', 'Name', 'Status', 'Fully compliant %', 'Partially compliant %', 'Not compliant %', 'Not assessed %', 'Applicable controls'].map(cell).join(',')];
    const sum = (lvl, code, name, n) => lines.push([lvl, code, name, ST[n.status] || n.status, n.pct.fully, n.pct.partially, n.pct.not, n.pct.not_assessed, n.applicable].map(cell).join(','));
    sum('Overall', 'NDMO', 'National Data Management Office standards', v.levels);
    for (const d of v.domain_levels) sum('Domain', d.key, d.name, d);
    lines.push('');
    lines.push(['Control', 'Domain', 'Title', 'Level', 'Result', 'Why', 'Official controls', 'Recorded by', 'Approved by'].map(cell).join(','));
    for (const c of v.controls) lines.push([c.id, c.domain_name, c.title, LV[c.level] || c.level || '', c.result, c.why, (c.official || []).join(' '), c.confirmation ? c.confirmation.by : '', c.confirmation ? c.confirmation.approved_by : ''].map(cell).join(','));
    audit(who, 'ndmo.export', 'register', { controls: v.controls.length });
    return { filename: 'ndmo-register-' + iso().slice(0, 10) + '.csv', csv: lines.join('\r\n') };
  }

  // the duty engineer: every gap is a work item; re-checked every patrol and closed when the register no longer shows it
  let last = null;
  const adapter = {
    id: 'ndmo', name: 'AI Data Governance Officer',
    async findings() {
      const v = await view(); last = v;
      return v.findings;
    },
    investigate(it) {
      const c = last && last.controls.find((x) => 'ndmo:' + x.id === it.key);
      if (!c) return { summary: 'NDMO register item - see the NDMO page for the evidence.', checks: [], causes: [{ cause: it.title, confidence: 'high', fix: it.recommendation }] };
      return { summary: c.id + ' ' + c.title + ' (' + c.domain_name + ')' + (c.official.length ? ' - official ' + c.official.join(', ') : ''),
        checks: [{ name: 'Register', status: c.result === 'gap' ? 'fail' : 'warn', detail: c.result + ': ' + (c.why || '') }, { name: 'Evidence expected', status: 'ok', detail: c.evidence_hint }],
        causes: [{ cause: it.title, confidence: 'high', fix: it.recommendation }] };
    },
    async verify(it) {
      let v; try { v = await view(); } catch (e) { return { present: null, note: 'could not re-check: ' + String(e.message).slice(0, 120) }; }
      const present = v.findings.some((f) => f.key === it.key);
      return { present, note: present ? 'the register still shows it' : 'the register no longer shows it' };
    },
  };
  return { view, facts, putProfile, confirm, decide, importOfficial, suggest, setMapping, gapsToGrc, exportCsv, adapter };
}

function registerNdmoRoutes(srv, app, N) {
  srv.route('GET', '/ndmo', (ctx) => { ctx.need('viewer'); return N.view(); });
  srv.route('GET', '/ndmo/suggest', (ctx) => { ctx.need('operator'); return N.suggest(); });
  srv.route('GET', '/ndmo/export', (ctx) => { ctx.need('operator'); return N.exportCsv(ctx.who); });
  srv.route('POST', '/ndmo/profile', (ctx) => { ctx.need('admin'); return N.putProfile(ctx.body, ctx.who); });
  srv.route('POST', '/ndmo/confirm', (ctx) => { ctx.need('operator'); return N.confirm(ctx.body, ctx.who); });
  srv.route('POST', '/ndmo/confirm/:id/decide', (ctx) => { ctx.need('operator'); return N.decide(ctx.params.id, ctx.body, ctx.who); });
  srv.route('POST', '/ndmo/official', (ctx) => { ctx.need('admin'); return N.importOfficial(ctx.body, ctx.who); });
  srv.route('POST', '/ndmo/mapping', (ctx) => { ctx.need('admin'); return N.setMapping(ctx.body, ctx.who); });
  srv.route('POST', '/ndmo/gaps-to-grc', (ctx) => { ctx.need('operator'); return N.gapsToGrc(ctx.who); });
}

module.exports = { createNdmo, registerNdmoRoutes };
