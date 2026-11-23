// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const fs = require('node:fs');
const { body, param } = require('./check');
/*
 * NCA Essential Cybersecurity Controls verification (ECC-1:2018, {P} = /api/itam): the 5 domains and 29 subdomains, with a
 * plain-language register for the organisation. Python decides (pyengine/nca_ecc_rules.py); this file validates at the
 * boundary, gathers the facts the platform and the SIEM already hold, commits and audits.
 *
 * Facts are read, never written, each source on its own (one missing source leaves the others): the GRC policy register
 * and its live checks (assets, patching, backups, roles), the risk and action registers, DR & BCM drills, asset ownership,
 * hardening, the attack surface and the security testing cadence, certificates, mail reputation and the domains' DMARC,
 * vendor risk, the AI PDPL Consultant, and through the AI CISO's SIEM link the SAMA CSF evidence (event, incident, threat,
 * IAM and infrastructure controls overlap ECC), log-flow assurance and log retention. A source that is not connected makes
 * its controls "not measured" with what to connect - never a pass.
 *
 * A person records a control (evidence for compliant / partial, a note for non-compliant / not applicable) and a second
 * person approves it - the CISO named in the ECC profile or an administrator, never the one who recorded it, never a service
 * or AI identity. Automated evidence wins over a person: a verified gap is never hidden by a confirmation.
 *
 *   GET  /nca-ecc                           viewer    domains, subdomains, controls, sources, coverage
 *   GET  /nca-ecc/suggest                   operator  a register control for each unmapped official control
 *   GET  /nca-ecc/export                    operator  the register as CSV (with the official codes mapped)        audited
 *   POST /nca-ecc/profile                   admin     {ciso_user, function_established, reports_to, strategy_approved,
 *                                                      committee_last_met, applicability{4-2,5-1}, applicability_note}  audited
 *   POST /nca-ecc/confirm                   operator  {id, status, evidence?, note?}  a person, not a service       audited
 *   POST /nca-ecc/confirm/:id/decide        operator  {decision: approve|reject, note?}  CISO / administrator, four eyes audited
 *   POST /nca-ecc/official                  admin     {rows[{code, title, spec?}], replace?}                     audited
 *   POST /nca-ecc/mapping                   admin     {code, control} | {code, remove: true} | {accept: [codes]} audited
 *   POST /nca-ecc/gaps-to-grc               operator  CISO / administrator: every verified gap becomes a GRC action (once) audited
 *
 * The duty engineer (id nca-ecc, "AI Cybersecurity Compliance Officer") turns each gap into a work item and closes it when
 * the register no longer shows it. It proposes; it never approves and never changes a system.
 */
const STATUSES = ['compliant', 'partial', 'non_compliant', 'not_applicable'];
const CID = /^ZS-[1-5]-\d{1,2}-\d{2}$/;
const CODE = /^(?:ECC[ -]?)?[1-5]-\d{1,2}(?:-\d{1,2}){0,3}(?:-[PT]\d{1,2})?$/i;
const DECIDE = ['4-2', '5-1'];
const USER = { max: 80, re: /^[A-Za-z0-9._@\\-]{2,80}$/, msg: 'a user name (letters, digits, . _ - @ \\)' };
const DAY = 86400000;
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const isService = (u) => /^(duty|system|core|ai|svc|service|agent|bot)[:._-]/i.test(String(u || ''));
const same = (a, b) => !!a && String(a).trim().toLowerCase() === String(b || '').trim().toLowerCase();

function pythonBin(app, opts) {
  const c = opts.python || ((app.config && app.config.discovery) || {}).python_bin;
  return [c, '/opt/sentra-siem/pyenv/bin/python3'].filter(Boolean).find((p) => fs.existsSync(p)) || 'python3';
}

function createNcaEcc(app, opts = {}) {
  const now = opts.now || Date.now, store = app.store;
  const iso = () => new Date(now()).toISOString();
  const prof = () => store.collection('ecc_profile'), conf = () => store.collection('ecc_confirm'), off = () => store.collection('ecc_official'), map = () => store.collection('ecc_mapping');
  let pyE = null;
  const py = () => opts.py || pyE || (pyE = require('./pyengine').createPyEngine({ python: pythonBin(app, opts), timeoutMs: 60000, resident: false }));
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role, ip: who.ip || '', action, target, detail }); };
  const warn = (key, msg, err) => { if (app.log && app.log.every) app.log.every('ecc:' + key, 3600000, 'warn', msg, { err: String((err && err.message) || err || '').slice(0, 200) }); };
  async function rules(op, input) {
    const r = await py().call(op, input || {});
    if (!r || r.ok === false) {
      warn('py', 'NCA ECC: the rules (Python) did not answer', r && r.error);
      throw httpErr(409, 'The NCA ECC rules run in Python and Python did not answer - run the update so pyengine is installed');
    }
    return r;
  }
  const profile = () => prof().get('profile') || {};
  const confirms = () => { const o = {}; for (const c of conf().all(() => true)) o[c.id] = c; return o; };
  const official = () => off().all(() => true).sort((a, b) => String(a.code).localeCompare(String(b.code), 'en', { numeric: true }));
  const mapping = () => { const o = {}; for (const m of map().all(() => true)) o[m.id] = m.control; return o; };
  const within = (v, days) => { const t = typeof v === 'number' ? v : Date.parse(v || ''); return Number.isFinite(t) && now() - t <= days * DAY; };
  const n = (v) => Number(v) || 0;
  const addon = (k) => app.addons && app.addons[k];
  // one source: its facts, or {available:false} with the reason logged once an hour
  async function source(key, fn) {
    try { const d = await fn(); return d ? Object.assign({ available: true }, d) : { available: false }; }
    catch (e) { warn('src:' + key, 'NCA ECC: ' + key + ' could not be read', e); return { available: false, error: String(e.message || e).slice(0, 160) }; }
  }

  // ---- the facts the platform and the SIEM already hold (read-only)
  async function facts() {
    if (opts.facts) return opts.facts();
    const grc = () => addon('grc') || require('./grc').createGrc(app);
    const reg = () => addon('grcRegisters') || require('./grc-registers').createGrcRegisters(app);
    const PD = addon('pdpl');
    const F = {};
    F.grc = await source('grc', () => {
      const s = grc().summary();
      let pol = [];
      try {
        const signed = require('./grc-policy-file')();
        pol = (Array.isArray(signed) ? signed : signed.policies || []).map((p) => ({ title: p.title, status: p.status, next_review: p.next_review }));
      } catch (e) { warn('grc-json', 'NCA ECC: the signed policy register was not read', e); }
      pol = pol.concat(store.collection('grc_drafts').all((d) => d.status === 'approved').map((d) => ({ title: d.title, status: 'approved', next_review: d.next_review || null })));
      return { total: s.total, reviews_overdue: s.reviews.overdue, attested: s.attested, control_status: s.control_status, policies: pol };
    });
    F.risk = await source('risk', () => {
      const R = reg(), risks = R.riskList().items.filter((r) => r.status === 'open'), acts = R.actionList({ status: 'open' }).items;
      return { total: risks.length, review_overdue: risks.filter((r) => r.review_overdue).length, actions_open: acts.length, actions_overdue: acts.filter((a) => a.overdue).length };
    });
    F.drills = await source('drills', () => {
      const s = grc().drillSummary();
      const done = store.collection('grc_drills').all((d) => d.status === 'completed' && within(d.completed_at || d.completed || d.scheduled, 365)).length;
      return { systems_total: s.systems.total, systems_tested: s.systems.tested, systems_overdue: s.systems.overdue, awaiting_signoff: s.awaiting_signoff, completed_12m: done };
    });
    F.ownership = await source('ownership', () => (addon('ownership') ? addon('ownership').summary().summary : null));
    F.hardening = await source('hardening', async () => (addon('hardening') ? (await addon('hardening').view()).summary : null));
    F.pentest = await source('pentest', () => (addon('pentest') ? addon('pentest').assessment().summary : null));
    F.cadence = await source('cadence', () => (addon('pentest') && addon('pentest').cadence ? addon('pentest').cadence.schedule().summary : null));
    F.certs = await source('certs', async () => {
      if (!addon('certs')) return null;
      const a = await addon('certs').assess();
      return { endpoints: (a.endpoints || []).length, expired: n((a.counts || {}).expired), weak: (a.findings || []).filter((x) => /weak/.test(String(x.kind || x.key || ''))).length };
    });
    F.mail = await source('mail', () => {
      const MR = addon('mailReputation'), last = MR ? MR.view().last : null;
      const checks = store.collection('dom_checks').all((c) => String(c.id).startsWith('d:') && c.records && Array.isArray(c.records.DMARC));
      if (!last && !checks.length) return null;
      const enforced = (c) => c.records.DMARC.length && /;\s*p=(quarantine|reject)/i.test(';' + String(c.records.DMARC[0]).replace(/^v=DMARC1/i, ''));
      return { ips: last ? n((last.counts || {}).listed) + n((last.counts || {}).clean) : 0, listed: last ? n((last.counts || {}).listed) : 0, dmarc: checks.length ? checks.every(enforced) : null };
    });
    F.vendor = await source('vendor', async () => (PD && PD.vendor ? (await PD.vendor.view()).summary : null));
    F.pdpl = await source('pdpl', async () => {
      if (!PD) return null;
      const a = await PD.assess(), req = {};
      for (const r of a.requirements || []) req[r.id] = r.result;
      return { compliance_pct: a.compliance_pct, requirements: req };
    });
    try { F.training_12m = PD ? (PD.records('training') || []).filter((t) => within(t.date || t.created_at, 365)).length : null; } catch (e) { warn('training', 'NCA ECC: the training records were not read', e); F.training_12m = null; }
    F.siem = await source('siem', async () => {
      const C = addon('ciso'); if (!C || typeof C.collect !== 'function') return null;
      const S = await C.collect(), live = (id) => (S[id] && S[id].state === 'live' ? S[id].data : null);
      const sama = live('sama'), lf = live('logflow');
      if (!sama && !lf) return null;
      const st = {}; let ret = null;
      for (const c of (sama && sama.controls) || []) {
        st[c.id] = c.status;
        for (const k of c.checks || []) if (k.kind === 'retention' && Number.isFinite(Number(k.value)) && k.value !== null) ret = Math.max(ret || 0, Number(k.value));
      }
      const s = (lf && lf.summary) || {};
      return { sama: sama ? st : null, retention_days: ret, logflow: lf ? { required: s.required, silent: s.silent, not_onboarded: s['not-onboarded'], no_connector: s['no-connector'], coverage_pct: s.coverage_pct } : null };
    });
    return F;
  }

  async function view() {
    const v = await rules('ecc.view', { facts: await facts(), profile: profile(), confirms: confirms(), official: official(), mapping: mapping(), now: now() });
    const p = profile();
    return Object.assign({}, v, { profile: { ciso_user: p.ciso_user || null, function_established: p.function_established || null, reports_to: p.reports_to || null,
      strategy_approved: p.strategy_approved || null, committee_last_met: p.committee_last_met || null, applicability: p.applicability || {}, applicability_note: p.applicability_note || {},
      updated_by: p.updated_by || null, updated_at: p.updated_at || null }, official_total: official().length, generated_at: iso() });
  }

  function putProfile(input, who) {
    const d = { notFuture: true, now: now() };
    const b = body(input || {}).str('ciso_user', USER).date('function_established', d).str('reports_to', { max: 80 }).date('strategy_approved', d).date('committee_last_met', d).done();
    const appl = {}, notes = {};
    const a = (input || {}).applicability, nt = (input || {}).applicability_note;
    if (a !== undefined) {
      if (!a || typeof a !== 'object' || Array.isArray(a)) throw httpErr(400, 'applicability must be an object {"4-2", "5-1"}');
      for (const k of Object.keys(a)) { if (!DECIDE.includes(k)) throw httpErr(400, 'applicability: ' + k + ' is not a subdomain that needs a decision (4-2, 5-1)'); Object.assign(appl, body(a).oneOf(k, ['applies', 'not_applicable']).done()); }
    }
    if (nt !== undefined) {
      if (!nt || typeof nt !== 'object' || Array.isArray(nt)) throw httpErr(400, 'applicability_note must be an object {"4-2", "5-1"}');
      for (const k of Object.keys(nt)) { if (!DECIDE.includes(k)) throw httpErr(400, 'applicability_note: ' + k + ' is not 4-2 or 5-1'); Object.assign(notes, body(nt).str(k, { max: 500 }).done()); }
    }
    for (const k of Object.keys(appl)) if (appl[k] === 'not_applicable' && !(notes[k] || (profile().applicability_note || {})[k])) throw httpErr(400, 'applicability_note.' + k + ' is required: say why the subdomain does not apply');
    const cur = profile();
    const rec = Object.assign({}, cur, b, { id: 'profile', applicability: Object.assign({}, cur.applicability, appl), applicability_note: Object.assign({}, cur.applicability_note, notes), updated_by: who.user, updated_at: iso() });
    prof().put(rec);
    audit(who, 'ecc.profile', 'profile', { fields: Object.keys(b).concat(Object.keys(appl).map((k) => 'applicability.' + k)), ciso_user: rec.ciso_user || null });
    return rec;
  }

  async function confirm(input, who) {
    if (isService(who.user)) throw httpErr(403, 'a service or AI identity cannot record an ECC control: a person does');
    const b = body(input || {}).str('id', { required: true, re: CID, msg: 'id must be a register control (ZS-n-n-nn)' }).oneOf('status', STATUSES, { required: true })
      .str('evidence', { max: 500 }).str('note', { max: 1000 })
      .rule((o) => ((o.status === 'compliant' || o.status === 'partial') && !o.evidence ? 'evidence is required for compliant / partial: name the document, report or record relied on' : null))
      .rule((o) => ((o.status === 'non_compliant' || o.status === 'not_applicable') && !o.note ? 'note is required: say what is missing, or why it does not apply' : null)).done();
    const v = await view();
    if (!v.controls.some((c) => c.id === b.id)) throw httpErr(404, 'no ECC register control ' + b.id);
    const prev = conf().get(b.id);
    conf().put({ id: b.id, status: b.status, evidence: b.evidence || '', note: b.note || '', by: who.user, role: who.role, at: iso(), approved_by: null, approved_at: null });
    audit(who, 'ecc.confirm', b.id, { status: b.status, previous: prev ? prev.status : null, evidence: b.evidence ? 'given' : 'none' });
    return (await view()).controls.find((c) => c.id === b.id);
  }

  async function decide(id, input, who) {
    const cid = param(id);
    if (!CID.test(cid)) throw httpErr(400, 'id must be a register control (ZS-n-n-nn)');
    const b = body(input || {}).oneOf('decision', ['approve', 'reject'], { required: true }).str('note', { max: 1000 })
      .rule((o) => (o.decision === 'reject' && !o.note ? 'note is required: say why it is rejected' : null)).done();
    const c = conf().get(cid); if (!c) throw httpErr(404, 'nothing recorded for ' + cid + ' yet');
    if (c.approved_by) throw httpErr(409, cid + ' was already approved by ' + c.approved_by);
    if (isService(who.user)) throw httpErr(403, 'only a person approves: ' + who.user + ' is a service / AI identity');
    if (!(who.role === 'admin' || same(profile().ciso_user, who.user))) throw httpErr(403, 'approving an ECC control needs the CISO named in the ECC profile or an administrator');
    if (same(c.by, who.user)) throw httpErr(403, 'four eyes: ' + who.user + ' recorded ' + cid + ' and cannot also approve it');
    if (b.decision === 'reject') {
      conf().remove(cid);
      audit(who, 'ecc.confirm.reject', cid, { recorded_by: c.by, status: c.status, note: b.note });
    } else {
      conf().put(Object.assign({}, c, { approved_by: who.user, approved_at: iso(), approve_note: b.note || '' }));
      audit(who, 'ecc.confirm.approve', cid, { recorded_by: c.by, status: c.status });
    }
    return (await view()).controls.find((x) => x.id === cid);
  }

  async function importOfficial(input, who) {
    const b = body(input || {}).list('rows', { required: true, max: 3000 }).bool('replace', { def: true }).done();
    const rows = b.rows.map((r, i) => {
      if (!r || typeof r !== 'object' || Array.isArray(r)) throw httpErr(400, 'rows[' + i + '] must be an object {code, title, spec}');
      try { return body(r).str('code', { required: true, max: 30 }).str('title', { required: true, max: 1000 }).str('spec', { max: 4000 }).done(); }
      catch (e) { throw httpErr(400, 'rows[' + i + '].' + e.message); }
    });
    const r = await rules('ecc.import', { rows });
    if (!r.rows.length) throw httpErr(400, 'no row could be imported: ' + (r.errors || []).slice(0, 5).join('; '));
    if (b.replace) for (const o of off().all(() => true)) off().remove(o.id);
    for (const o of r.rows) off().put(Object.assign({ id: o.code }, o, { imported_by: who.user, imported_at: iso() }));
    const codes = new Set(official().map((o) => o.code));
    for (const m of map().all(() => true)) if (!codes.has(m.id)) map().remove(m.id);
    audit(who, 'ecc.official.import', 'official', { imported: r.rows.length, errors: r.error_count || 0, replace: b.replace });
    return { imported: r.rows.length, errors: r.errors, error_count: r.error_count || 0, total: official().length };
  }

  const suggest = () => rules('ecc.suggest', { official: official(), mapping: mapping() });

  async function setMapping(input, who) {
    const src = input || {};
    if (src.accept !== undefined) {
      const b = body(src).list('accept', { required: true, max: 3000, item: 'str', itemMax: 30 }).done();
      const s = await suggest(), by = {}; for (const x of s.suggestions || []) by[x.code] = x.control;
      const done = [], skipped = [];
      for (const code of b.accept) { if (by[code]) { map().put({ id: code, control: by[code], by: who.user, at: iso(), suggested: true }); done.push(code); } else skipped.push(code); }
      audit(who, 'ecc.mapping.accept', 'official', { accepted: done.length, skipped: skipped.length });
      return { accepted: done.length, skipped };
    }
    const b = body(src).str('code', { required: true, max: 30, re: CODE, msg: 'code must be an ECC control code (e.g. 2-10-3-1)' }).str('control', { re: CID, msg: 'control must be a register control (ZS-n-n-nn)' }).bool('remove').done();
    if (!off().get(b.code)) throw httpErr(404, 'official control ' + b.code + ' is not in the imported list');
    if (b.remove) { map().remove(b.code); audit(who, 'ecc.mapping.remove', b.code, {}); return { code: b.code, control: null }; }
    if (!b.control) throw httpErr(400, 'control is required (or remove: true)');
    const v = await view();
    if (!v.controls.some((c) => c.id === b.control)) throw httpErr(400, 'control: no register control ' + b.control);
    const prev = map().get(b.code);
    map().put({ id: b.code, control: b.control, by: who.user, at: iso() });
    audit(who, 'ecc.mapping', b.code, { control: b.control, previous: prev ? prev.control : null });
    return { code: b.code, control: b.control };
  }

  async function gapsToGrc(who) {
    if (isService(who.user)) throw httpErr(403, 'a service or AI identity cannot raise GRC actions from the ECC register');
    if (!(who.role === 'admin' || same(profile().ciso_user, who.user))) throw httpErr(403, 'sending ECC gaps to GRC needs the CISO named in the ECC profile or an administrator');
    const G = addon('grcRegisters') || (() => { try { return require('./grc-registers').createGrcRegisters(app); } catch (e) { warn('grc-reg', 'NCA ECC: the GRC registers are not installed', e); return null; } })();
    if (!G) throw httpErr(409, 'the GRC registers are not installed - run the update');
    const v = await view(), out = { created: [], skipped: [] };
    const due = { high: 30, medium: 60, low: 90 };
    for (const c of v.controls.filter((x) => x.result === 'gap')) {
      const pri = c.severity === 'high' ? 'high' : c.severity === 'medium' ? 'medium' : 'low';
      try {
        const act = G.actionCreate({ title: 'NCA ECC ' + c.subdomain + ' ' + c.id + ': ' + c.title.slice(0, 150), source: 'nca', ref: 'ecc:' + c.id, framework: 'NCA ECC', priority: pri,
          due: new Date(now() + due[pri] * DAY).toISOString().slice(0, 10), description: 'NCA ECC ' + c.subdomain + ' ' + c.subdomain_name + ' gap: ' + String(c.why || '').slice(0, 500) + (c.official.length ? ' Official controls: ' + c.official.join(', ') + '.' : '') + ' Close it with the evidence: ' + c.evidence_hint + '.' }, who);
        out.created.push(act.id);
      } catch (e) { out.skipped.push(c.id + ': ' + String(e.message).slice(0, 120)); }
    }
    audit(who, 'ecc.gaps_to_grc', 'register', { created: out.created.length, skipped: out.skipped.length });
    return out;
  }

  async function exportCsv(who) {
    const v = await view();
    const q = (s) => { const t = String(s == null ? '' : s); return /^[=+\-@\t\r]/.test(t) ? "'" + t : t; };   // no formula injection in Excel
    const cell = (s) => '"' + q(s).replace(/"/g, '""') + '"';
    const LV = { fully: 'Fully compliant', partially: 'Partially compliant', not: 'Not compliant', not_assessed: 'Not assessed', not_applicable: 'Not applicable' };
    const ST = { fully_compliant: 'Fully compliant', partially_compliant: 'Partially compliant', not_compliant: 'Not compliant', not_assessed: 'Not assessed', not_applicable: 'Not applicable' };
    // NCA's assessment language first: the overall, each domain and each subdomain with the share of its controls at each level
    const lines = [['Level', 'Code', 'Name', 'NCA status', 'Fully compliant %', 'Partially compliant %', 'Not compliant %', 'Not assessed %', 'Applicable controls'].map(cell).join(',')];
    const sum = (lvl, code, name, n) => { if (!n) return; lines.push([lvl, code, name, ST[n.status] || n.status, n.pct.fully, n.pct.partially, n.pct.not, n.pct.not_assessed, n.applicable].map(cell).join(',')); };
    sum('Overall', 'ECC-1:2018', 'NCA Essential Cybersecurity Controls', v.nca);
    for (const d of v.domains) { sum('Domain', d.code, d.name, d.nca); for (const x of v.subdomains.filter((y) => y.domain === d.code)) sum('Subdomain', x.code, x.name, x.nca); }
    lines.push('');
    lines.push(['Control', 'Subdomain', 'Subdomain name', 'Title', 'NCA level', 'Result', 'Why', 'Automated', 'Official controls', 'Recorded by', 'Approved by'].map(cell).join(','));
    for (const c of v.controls) lines.push([c.id, c.subdomain, c.subdomain_name, c.title, LV[c.nca_level] || c.nca_level || '', c.result, c.why, c.automated ? 'yes' : 'no', (c.official || []).join(' '), c.confirmation ? c.confirmation.by : '', c.confirmation ? c.confirmation.approved_by : ''].map(cell).join(','));
    audit(who, 'ecc.export', 'register', { controls: v.controls.length });
    return { filename: 'nca-ecc-register-' + iso().slice(0, 10) + '.csv', csv: lines.join('\r\n') };
  }

  let last = null;
  const adapter = {
    id: 'nca-ecc', name: 'AI Cybersecurity Compliance Officer',
    async findings() { const v = await view(); last = v; return v.findings; },
    investigate(it) {
      const c = last && last.controls.find((x) => 'ecc:' + x.id === it.key);
      if (!c) return { summary: 'NCA ECC register item - see the NCA ECC page for the evidence.', checks: [], causes: [{ cause: it.title, confidence: 'high', fix: it.recommendation }] };
      return { summary: c.id + ' ' + c.title + ' (' + c.subdomain + ' ' + c.subdomain_name + ')' + (c.official.length ? ' - official ' + c.official.join(', ') : ''),
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

function registerNcaEccRoutes(srv, app, N) {
  srv.route('GET', '/nca-ecc', (ctx) => { ctx.need('viewer'); return N.view(); });
  srv.route('GET', '/nca-ecc/suggest', (ctx) => { ctx.need('operator'); return N.suggest(); });
  srv.route('GET', '/nca-ecc/export', (ctx) => { ctx.need('operator'); return N.exportCsv(ctx.who); });
  srv.route('POST', '/nca-ecc/profile', (ctx) => { ctx.need('admin'); return N.putProfile(ctx.body, ctx.who); });
  srv.route('POST', '/nca-ecc/confirm', (ctx) => { ctx.need('operator'); return N.confirm(ctx.body, ctx.who); });
  srv.route('POST', '/nca-ecc/confirm/:id/decide', (ctx) => { ctx.need('operator'); return N.decide(ctx.params.id, ctx.body, ctx.who); });
  srv.route('POST', '/nca-ecc/official', (ctx) => { ctx.need('admin'); return N.importOfficial(ctx.body, ctx.who); });
  srv.route('POST', '/nca-ecc/mapping', (ctx) => { ctx.need('admin'); return N.setMapping(ctx.body, ctx.who); });
  srv.route('POST', '/nca-ecc/gaps-to-grc', (ctx) => { ctx.need('operator'); return N.gapsToGrc(ctx.who); });
}

module.exports = { createNcaEcc, registerNcaEccRoutes };
