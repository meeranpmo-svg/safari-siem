// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const crypto = require('node:crypto');
const { body, param } = require('./check');
const { guardOf } = require('./errors');
const { isHuman } = require('./approve-scopes');
/*
 * Regulator Evidence Packs ({P} = /api/itam). Every month - and on "Build now" by an operator - one FROZEN pack per framework
 * (SAMA CSF, Insurance Authority, NCA ECC, PDPL, NDMO), fingerprinted with SHA-256 over its canonical JSON, so an auditor's
 * request is answered from a pack that already exists instead of a screen that changes while they read it.
 *
 * Per control / requirement, read (never written) from the register that owns it:
 *   SAMA CSF            engine/sama-ia.js view().requirements; owners from the gap tracker (engine/sama-audit.js)
 *   Insurance Authority engine/sama-ia.js view().ia.requirements + the SAMA CSF baseline (the IA register is SAMA CSF + IA items),
 *                       with the operational resilience areas of engine/ia-resilience.js beside it
 *   NCA ECC             engine/nca-ecc.js view().controls
 *   PDPL                engine/pdpl.js view(true).requirements, the registers' record COUNTS by kind (never a record itself)
 *   NDMO                engine/ndmo.js view().controls
 * and for each: its result as the register holds it (implemented / partial / not implemented / not applicable / not tested),
 * the register's own reason, the automated check or the two-person confirmation it rests on, the evidence files of the GRC
 * evidence register (engine/grc-registers.js: name, SHA-256 re-hashed from the stored bytes, collected, next due, state), the
 * SAMA policies that support it (engine/grc.js csfCoverage), open GRC remediation actions, the owner, and what is missing.
 * Evidence files are named and hashed - their content never enters a pack (PDPL), and nothing leaves this server.
 * A framework whose module is not installed gets a pack that SAYS so (no controls, nothing counted as passing). A register
 * that cannot be read (Python not answering) gets no pack that month: the build fails visibly and the job retries hourly.
 *
 * Frozen: no route changes a pack. A compliance reviewer - an administrator, a person (never a service or AI identity), who did
 * not build it - signs it off once; the sign-off records the fingerprint it signed and the pack is immutable from then on. The
 * last 24 packs per framework are kept; an older UNSIGNED pack is removed (audited); a signed pack is never removed here.
 *
 *   GET  /evidence-packs                       operator  frameworks, packs, job state (packs name control owners)
 *   GET  /evidence-packs/:id                   operator  the pack, its integrity re-checked, the previous pack
 *   GET  /evidence-packs/:id/compare?with=:id  operator  what changed since the previous month (or the pack named)
 *   GET  /evidence-packs/:id/export            operator  the workbook rows for Excel (built on the page)   audited
 *   POST /evidence-packs/build                 operator  {framework: all | sama | ia | ecc | pdpl | ndmo}   a person   audited
 *   POST /evidence-packs/:id/sign              admin     {confirm: true, note?}  a person who did not build it   audited
 * Signals for Notification & Escalation (X.signals()): a month's pack not built; controls that got worse since last month.
 */
const DAY = 86400000, HOUR = 3600000, KEEP = 24;
const SYS = { user: 'system:evidence-packs', role: 'admin', ip: '' };
const STATUSES = ['implemented', 'partial', 'not_implemented', 'not_applicable', 'not_tested'];
const LABEL = { implemented: 'implemented', partial: 'partial', not_implemented: 'not implemented', not_applicable: 'not applicable', not_tested: 'not tested' };
const RANK = { implemented: 3, partial: 2, not_tested: 1, not_implemented: 0 };
// the registers' own vocabularies -> the pack's five results (a level when the register gives one, else its result)
const BY_LEVEL = { fully: 'implemented', partially: 'partial', not: 'not_implemented', not_assessed: 'not_tested', not_applicable: 'not_applicable', na: 'not_applicable' };
const BY_RESULT = { verified: 'implemented', met: 'implemented', compliant: 'implemented', partial: 'partial', gap: 'not_implemented', non_compliant: 'not_implemented',
  not_applicable: 'not_applicable', not_measured: 'not_tested', no_evidence: 'not_tested', pending: 'not_tested', not_assessed: 'not_tested', auto_pass: 'not_tested' };
const FW = {
  sama: { code: 'SAMA', short: 'SAMA CSF', name: 'SAMA Cyber Security Framework', module: 'samaIa', source: 'engine/sama-ia.js (SAMA CSF assessment) with the gap tracker of engine/sama-audit.js', ev: ['SAMA CSF'], page: 'sama-audit.html' },
  ia: { code: 'IA', short: 'Insurance Authority', name: 'Insurance Authority - SAMA CSF baseline for insurers', module: 'samaIa', source: 'engine/sama-ia.js (IA register = SAMA CSF + IA items) with engine/ia-resilience.js', ev: ['SAMA CSF', 'Other'], page: 'ia-framework.html' },
  ecc: { code: 'ECC', short: 'NCA ECC', name: 'NCA Essential Cybersecurity Controls (ECC-1:2018)', module: 'ncaEcc', source: 'engine/nca-ecc.js (NCA ECC register)', ev: ['NCA ECC'], page: 'nca-ecc.html' },
  pdpl: { code: 'PDPL', short: 'PDPL', name: 'Personal Data Protection Law (SDAIA)', module: 'pdpl', source: 'engine/pdpl.js (AI PDPL Consultant register)', ev: ['PDPL'], page: 'pdpl-assessment.html' },
  ndmo: { code: 'NDMO', short: 'NDMO', name: 'NDMO Data Management and Personal Data Protection Standards', module: 'ndmo', source: 'engine/ndmo.js (NDMO data management register)', ev: ['NDMO'], page: 'ndmo.html' },
};
const KEYS = Object.keys(FW);
const ID_RE = /^EP-(SAMA|IA|ECC|PDPL|NDMO)-\d{4}-\d{2}-\d{2,3}$/;

const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const s = (v, n) => String(v == null ? '' : v).replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, '').trim().slice(0, n || 300);
const same = (a, b) => !!String(a || '').trim() && String(a || '').trim().toLowerCase() === String(b || '').trim().toLowerCase();
const sha = (x) => crypto.createHash('sha256').update(x).digest('hex');
// canonical JSON: keys sorted at every level, so the same content always hashes to the same fingerprint
function canon(v) {
  if (Array.isArray(v)) return '[' + v.map(canon).join(',') + ']';
  if (v && typeof v === 'object') return '{' + Object.keys(v).filter((k) => v[k] !== undefined).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',') + '}';
  return JSON.stringify(v === undefined ? null : v);
}
const CONTENT = ['id', 'framework', 'code', 'name', 'period', 'kind', 'built_at', 'built_by', 'installed', 'reason', 'source', 'register', 'summary', 'controls', 'live', 'prev'];
const fingerprint = (p) => sha(canon(Object.fromEntries(CONTENT.map((k) => [k, p[k] === undefined ? null : p[k]]))));

function createEvidencePacks(app, opts = {}) {
  const now = opts.now || (() => Date.now());
  const st = app.store, packs = () => st.collection('evidence_packs'), meta = () => st.collection('evidence_pack_job');
  const A = () => app.addons || {};
  const L = app.log || { every() {}, warn() {}, info() {}, error() {} };
  const warn = (key, msg, f) => { if (L.every) L.every('evidence-packs:' + key, HOUR, 'warn', msg, f || {}); else if (L.warn) L.warn(msg, f || {}); };
  const iso = () => new Date(now()).toISOString();
  const riyadh = (ms) => new Date(ms + 3 * HOUR).toISOString();          // Riyadh wall time (UTC+3, no DST)
  const periodOf = (ms) => riyadh(ms).slice(0, 7);
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role || '', ip: who.ip || '', action: 'evidence-packs.' + action, target, detail }); };
  const busy = {};

  // ---------- reading the registers (each on its own; a failure is said, never a pass)
  function evidenceRegister() {
    const G = A().grcRegisters;
    let items = [];
    try { items = G ? G.evList().items : st.collection('grc_evidence').all(() => true); } catch (e) { warn('evid', 'evidence packs: the GRC evidence register was not read', { err: s(e.message, 200) }); return { ok: false, items: [] }; }
    const files = st.collection('grc_files'), today = riyadh(now()).slice(0, 10), soon = riyadh(now() + 30 * DAY).slice(0, 10);
    return { ok: true, items: items.map((e) => {
      const f = e.file || {};
      let integrity = 'link';
      if (f.kind !== 'link' && !f.url) {
        const b = f.file_id ? files.get(f.file_id) : null;
        integrity = !b || !b.content_b64 ? 'missing' : (sha(Buffer.from(b.content_b64, 'base64')) === f.sha256 ? 'verified' : 'mismatch');
      }
      const state = (e.status === 'retired' || e.state === 'retired' ? 'retired' : !e.next_due ? 'current' : e.next_due < today ? 'stale' : e.next_due <= soon ? 'due_soon' : 'current');
      return { id: s(e.id, 40), framework: s(e.framework, 40), control: s(e.control, 60), title: s(e.title, 200), kind: s(e.kind, 20), owner: s(e.owner, 120),
        file: s(f.filename || f.url, 200), sha256: f.sha256 ? s(f.sha256, 64) : null, collected: e.collected || null, next_due: e.next_due || null, state, integrity };
    }) };
  }
  function actionsRegister() {
    const G = A().grcRegisters;
    try { return G ? G.actionList({}).items : []; } catch (e) { warn('act', 'evidence packs: the GRC remediation actions were not read', { err: s(e.message, 200) }); return []; }
  }
  function policyCoverage() {
    const G = A().grc; if (!G || !G.csfCoverage) return null;
    try {
      const c = G.csfCoverage(), out = {};
      for (const x of Array.isArray(c.controls) ? c.controls : Object.values(c.controls || {})) if (x && x.code) out[x.code] = (x.policies || []).map((p) => ({ doc_id: s(p.doc_id, 40), title: s(p.title, 200), owner: s(p.owner, 120), status: s(p.status, 60), score: p.score == null ? null : p.score }));
      return out;
    } catch (e) { warn('pol', 'evidence packs: the policy register was not read', { err: s(e.message, 200) }); return null; }
  }
  function lastRuns() {
    const out = {};
    try { const r = st.collection('sama_runs').all(() => true).sort((a, b) => a.at - b.at); out.sama_assessment = r.length ? { runs: r.length, last: r[r.length - 1].id, score: r[r.length - 1].score } : { runs: 0, last: null }; } catch (e) { warn('runs', 'evidence packs: the SAMA run history was not read', { err: s(e.message, 200) }); }
    try {
      const C = A().auditCcm, m = C && C.summary ? C.summary() : null;
      out.control_monitoring = !C ? { installed: false } : m ? { run: m.run || null, at: m.at || null, tests: (m.tests || []).slice(0, 60).map((t) => ({ id: s(t.id, 40), name: s(t.name, 160), status: s(t.status, 30), exceptions: Number(t.exceptions) || 0 })) } : { run: null, note: 'no control-monitoring run yet' };
    } catch (e) { warn('ccm', 'evidence packs: control monitoring was not read', { err: s(e.message, 200) }); }
    try { const v = st.verifyAudit(); out.audit_log = { ok: !!v.ok, checked: v.checked || 0 }; } catch (e) { warn('alog', 'evidence packs: the audit-log chain was not verified', { err: s(e.message, 200) }); }
    return out;
  }

  // (the state is judged at the pack's own time, so a pack built by the monthly job reads the same whenever it is opened)
  // one control in the pack's shape; ev = evidence items for this framework, keys = the control codes evidence may be filed under
  function control(fw, r, ctx) {
    const level = r.nca_level || r.level;
    const status = (level && BY_LEVEL[level]) || BY_RESULT[r.result] || 'not_tested';
    const keys = [r.id, r.subdomain, ...(Array.isArray(r.official) ? r.official : [])].filter(Boolean).map((k) => String(k).toLowerCase());
    const ev = ctx.ev.filter((e) => FW[fw].ev.includes(e.framework) && keys.includes(e.control.toLowerCase()) && e.state !== 'retired');
    const acts = ctx.actions.filter((a) => a.ref && (String(a.ref).toLowerCase().endsWith(':' + String(r.id).toLowerCase()) || same(a.ref, r.id)) && ['open', 'in_progress', 'done'].includes(a.status))
      .map((a) => ({ id: s(a.id, 20), status: s(a.status, 20), owner: s(a.owner, 120), due: a.due || null }));
    const c = r.confirmation || null;
    const conf = c ? { status: s(c.status, 30), evidence: s(c.evidence, 300), recorded_by: s(c.by, 120), recorded_at: c.at || null, approved_by: s(c.approved_by, 120) || null, approved_at: c.approved_at || null } : null;
    const tracked = ctx.owners[r.id];
    let owner = '', owner_source = '';
    if (tracked) { owner = tracked; owner_source = 'gap tracker'; }
    else if (acts.find((a) => a.owner)) { owner = acts.find((a) => a.owner).owner; owner_source = 'remediation action'; }
    else if (ev.find((e) => e.owner)) { owner = ev.find((e) => e.owner).owner; owner_source = 'evidence register'; }
    else if (ctx.accountable) { owner = ctx.accountable.user; owner_source = ctx.accountable.role; }
    const why = s(r.why || r.why_result || (r.auto && r.auto.detail) || '', 400);
    const expected = s(r.evidence_hint || r.evidence_expected || '', 300);
    const automated = !!r.automated && !['not_measured'].includes(r.result) && !(r.auto && r.auto.state === 'not_tested');
    const tested = conf && conf.approved_at ? { at: conf.approved_at, how: 'confirmed by a person, approved by a second person' }
      : automated && status !== 'not_tested' ? { at: ctx.at, how: 'automated check when the pack was built' } : null;
    const current = ev.filter((e) => e.state === 'current' || e.state === 'due_soon');
    const missing = [];
    if (status === 'not_implemented') missing.push('not implemented: ' + (why || 'the register shows a gap'));
    else if (status === 'partial') missing.push('partly implemented: ' + (why || 'the register shows it partly met'));
    else if (status === 'not_tested') missing.push('not tested: ' + (why || 'no result in the register yet'));
    if (conf && !conf.approved_by) missing.push('recorded by ' + (conf.recorded_by || 'a person') + ' - waiting for a second person to approve');
    if (status !== 'not_applicable') {
      if (!ev.length && !(status === 'implemented' && automated)) missing.push('no evidence file in the GRC evidence register' + (expected ? ' (expected: ' + expected + ')' : ''));
      else if (ev.length && !current.length) missing.push('evidence expired: ' + ev.map((e) => e.id + (e.next_due ? ' (due ' + e.next_due + ')' : '')).join(', '));
      for (const e of ev.filter((x) => x.integrity === 'mismatch' || x.integrity === 'missing')) missing.push(e.id + ': ' + (e.integrity === 'mismatch' ? 'the stored file no longer matches its recorded SHA-256' : 'the stored file is missing'));
      if (!owner) missing.push('no owner recorded');
    }
    const pol = ctx.policies && (ctx.policies[r.subdomain] || (ctx.eccToSama[r.id] && ctx.policies[ctx.eccToSama[r.id]])) || [];
    return { ref: s(r.id, 40), title: s(r.title, 300), group: s([r.domain, r.subdomain && r.subdomain !== r.domain ? r.subdomain : null].filter(Boolean).join(' / ') + (r.subdomain_name || r.domain_name || r.area ? ' ' + (r.subdomain_name || r.domain_name || r.area) : ''), 200),
      ref_doc: r.ref ? s(r.ref, 120) : undefined, status, register_result: s(r.result, 30), why, expected, severity: r.severity ? s(r.severity, 10) : undefined, automated: !!r.automated,
      owner, owner_source, confirmation: conf, tested, evidence: ev.map((e) => ({ id: e.id, title: e.title, file: e.file, sha256: e.sha256, collected: e.collected, next_due: e.next_due, state: e.state, integrity: e.integrity })),
      policies: pol.slice(0, 8), actions: acts.slice(0, 8), missing };
  }

  async function gather(fw) {
    const F = FW[fw], M = A()[F.module];
    if (!M) return { installed: false, reason: 'The ' + F.short + ' module (' + F.source.split(' ')[0] + ') is not installed on this server - nothing was assessed and nothing is shown as passing. Run the update to install it.' };
    const at = iso(), evr = evidenceRegister(), ctx = { at, ev: evr.items, actions: actionsRegister(), owners: {}, accountable: null, policies: null, eccToSama: {} };
    let rows = [], register = {}, live = {};
    if (fw === 'sama' || fw === 'ia') {
      const v = await M.view(SYS);
      try { const G = A().samaAudit; if (G) for (const g of ((await G.view(SYS)).gaps || [])) if (g.owner) ctx.owners[g.id] = s(g.owner, 120); } catch (e) { warn('gaps', 'evidence packs: the SAMA gap tracker was not read', { err: s(e.message, 200) }); }
      ctx.policies = policyCoverage();
      if (v.profile && v.profile.ciso) ctx.accountable = { user: s(v.profile.ciso, 120), role: 'CISO (NCA ECC profile)' };
      if (fw === 'sama') {
        rows = v.requirements || [];
        register = { status: v.overall && v.overall.status, score: v.overall ? v.overall.score : null, counts: v.overall ? v.overall.counts : null, generated_at: v.generated_at || at };
        live.pillars = (v.pillars || []).map((p) => ({ name: s(p.name, 60), requirements: p.requirements, automated: p.automated, connected: p.connected, ok: p.ok, gaps: p.gaps, not_assessed: p.not_assessed }));
      } else {
        rows = ((v.ia && v.ia.requirements) || []).concat(v.requirements || []);
        register = { status: v.ia && v.ia.levels && v.ia.levels.status, score: v.ia && v.ia.levels ? v.ia.levels.score : null, counts: v.ia && v.ia.levels ? v.ia.levels.counts : null, circular: v.ia && v.ia.circular, generated_at: v.generated_at || at };
        const R = A().iaResilience;
        if (R) {
          try { const r = await R.view(SYS); live.resilience = { index: r.index == null ? null : r.index, why: s(r.index_why, 300), areas: Object.values(r.pillars || {}).map((p) => ({ name: s(p.name, 80), measured: !!p.available, score: p.available ? p.score : null, why: s(p.available ? p.why : p.reason, 300) })) }; }
          catch (e) { live.resilience = { error: 'the operational resilience view could not be read: ' + s(e.message, 160) }; }
        } else live.resilience = { installed: false, note: 'engine/ia-resilience.js is not installed - DR, backup and third-party resilience are not in this pack' };
      }
    } else if (fw === 'ecc') {
      const v = await M.view();
      rows = v.controls || [];
      register = { status: v.nca && v.nca.status, score: v.score == null ? null : v.score, counts: v.nca ? v.nca.counts : null, generated_at: v.generated_at || at };
      if (v.profile && v.profile.ciso_user) ctx.accountable = { user: s(v.profile.ciso_user, 120), role: 'CISO (NCA ECC profile)' };
      live.sources = (v.sources || []).map((x) => ({ id: s(x.id, 40), connected: !!x.connected }));
      ctx.policies = policyCoverage();
      const S = A().samaIa;   // a SAMA requirement mapped to an ECC control brings its supporting policies
      if (S && ctx.policies) { try { for (const q of (await S.view(SYS)).requirements || []) if (q.ecc && !ctx.eccToSama[q.ecc]) ctx.eccToSama[q.ecc] = q.subdomain; } catch (e) { warn('ecc-map', 'evidence packs: the SAMA to ECC mapping was not read', { err: s(e.message, 200) }); } }
    } else if (fw === 'pdpl') {
      const v = await M.view(true);
      rows = v.requirements || [];
      register = { status: v.levels && v.levels.status, score: v.compliance_pct == null ? null : v.compliance_pct, counts: v.levels ? v.levels.counts : null, statement: v.statement ? s(v.statement.status, 30) : null, generated_at: at };
      if (v.readiness && v.readiness.dpo_user) ctx.accountable = { user: s(v.readiness.dpo_user, 120), role: 'DPO (PDPL profile)' };
      try { const by = {}; for (const r of M.records()) if (r.kind !== 'profile') by[r.kind] = (by[r.kind] || 0) + 1; live.record_counts = by; } catch (e) { warn('pdpl-rec', 'evidence packs: the PDPL record counts were not read', { err: s(e.message, 200) }); }
    } else if (fw === 'ndmo') {
      const v = await M.view();
      rows = v.controls || [];
      register = { status: v.levels && v.levels.status, score: v.score == null ? null : v.score, counts: v.levels ? v.levels.counts : null, generated_at: v.generated_at || at };
      if (v.profile && v.profile.cdo_user) ctx.accountable = { user: s(v.profile.cdo_user, 120), role: 'Chief Data Officer (NDMO profile)' };
    }
    const controls = rows.map((r) => control(fw, r, ctx));
    Object.assign(live, lastRuns(), { evidence_register: evr.ok ? 'read' : 'not read', policies: ctx.policies ? 'read' : (fw === 'sama' || fw === 'ia' || fw === 'ecc' ? 'not read' : 'not mapped for this framework') });
    return { installed: true, reason: null, register, controls, live };
  }

  function summarize(controls) {
    const counts = Object.fromEntries(STATUSES.map((k) => [k, 0]));
    for (const c of controls) counts[c.status]++;
    const applicable = controls.length - counts.not_applicable, ev = controls.flatMap((c) => c.evidence);
    const uniq = [...new Map(ev.map((e) => [e.id, e])).values()];
    return { controls: controls.length, applicable, counts, implemented_pct: applicable ? Math.round(100 * counts.implemented / applicable) : null,
      with_evidence: controls.filter((c) => c.evidence.some((e) => e.state === 'current' || e.state === 'due_soon')).length,
      without_owner: controls.filter((c) => c.status !== 'not_applicable' && !c.owner).length, with_missing: controls.filter((c) => c.missing.length).length,
      evidence: { items: uniq.length, current: uniq.filter((e) => e.state === 'current').length, due_soon: uniq.filter((e) => e.state === 'due_soon').length, stale: uniq.filter((e) => e.state === 'stale').length,
        mismatch: uniq.filter((e) => e.integrity === 'mismatch').length, missing_file: uniq.filter((e) => e.integrity === 'missing').length } };
  }

  // ---------- building
  const ofFw = (fw) => packs().all((p) => p.framework === fw).sort((a, b) => String(b.built_at).localeCompare(String(a.built_at)) || String(b.id).localeCompare(String(a.id)));
  async function buildOne(fw, who, kind) {
    if (busy[fw]) throw httpErr(409, 'a ' + FW[fw].short + ' pack is being built right now - try again in a minute');
    busy[fw] = true;
    try {
      const F = FW[fw], t = now(), period = periodOf(t);
      let g;
      try { g = await gather(fw); } catch (e) {
        warn('read:' + fw, 'evidence packs: the ' + F.short + ' register could not be read - no pack built', { framework: fw, err: s(e.message, 200) });
        throw httpErr(409, 'The ' + F.short + ' register could not be read (' + s(e.message, 200) + ') - no pack was built, so nothing is shown as passing. Fix the register and build again.');
      }
      const seq = packs().all((p) => p.framework === fw && p.period === period).length + 1;
      const id = 'EP-' + F.code + '-' + period + '-' + String(seq).padStart(2, '0');
      const prevP = ofFw(fw)[0] || null;
      const controls = g.controls || [];
      const p = { id, framework: fw, code: F.code, name: F.name, period, kind, built_at: new Date(t).toISOString(), built_by: who.user, installed: g.installed, reason: g.reason,
        source: F.source, register: g.register || null, summary: g.installed ? summarize(controls) : null, controls, live: g.live || null, prev: prevP ? { id: prevP.id, sha256: prevP.sha256 } : null };
      p.sha256 = fingerprint(p); p.signoff = null;
      packs().put(p);
      audit(who, 'build', id, { framework: fw, period, kind, sha256: p.sha256, installed: p.installed, controls: controls.length, implemented_pct: p.summary ? p.summary.implemented_pct : null });
      prune(fw);
      return row(p);
    } finally { busy[fw] = false; }
  }
  // keep the last KEEP packs per framework; an older unsigned pack goes (audited), a signed pack is never removed here
  function prune(fw) {
    for (const p of ofFw(fw).slice(KEEP)) {
      if (p.signoff) continue;
      packs().remove(p.id);
      audit(SYS, 'prune', p.id, { framework: fw, period: p.period, sha256: p.sha256, keep: KEEP });
    }
  }
  async function build(input, who) {
    const b = body(input || {}).oneOf('framework', ['all'].concat(KEYS), { def: 'all' }).done();
    if (!isHuman(who.user)) throw httpErr(403, 'a service or AI identity cannot build a pack from here: a person presses Build now (the monthly job builds them itself)');
    const list = b.framework === 'all' ? KEYS : [b.framework], built = [], failed = [];
    for (const fw of list) {
      try { built.push(await buildOne(fw, who, 'manual')); } catch (e) { if (list.length === 1) throw e; failed.push({ framework: fw, error: s(e.message, 300) }); }
    }
    return { built, failed };
  }

  // ---------- reading packs
  function row(p) {
    return { id: p.id, framework: p.framework, code: p.code, name: p.name, period: p.period, kind: p.kind, built_at: p.built_at, built_by: p.built_by, installed: p.installed, reason: p.reason,
      sha256: p.sha256, summary: p.summary, signoff: p.signoff ? { by: p.signoff.by, at: p.signoff.at } : null };
  }
  function must(id0, name = 'id') {
    const id = param(id0, name); if (!ID_RE.test(id)) throw httpErr(400, name + ' must be an evidence pack id (e.g. EP-SAMA-2026-11-01)');
    const p = packs().get(id); if (!p) throw httpErr(404, 'no evidence pack ' + id + ' (packs older than the last ' + KEEP + ' per framework are removed unless signed)');
    return p;
  }
  function integrity(p) {
    const re = fingerprint(p), ok = re === p.sha256 && (!p.signoff || p.signoff.sha256 === p.sha256);
    return { ok, sha256: p.sha256, recomputed: re, why: ok ? 'the content hashes to the fingerprint recorded when it was built' + (p.signoff ? ' and signed' : '') : 'the content no longer matches its fingerprint - this pack must not be relied on' };
  }
  function signBlock(p, who) {
    if (!who || who.role !== 'admin') return 'sign-off needs an administrator (the compliance reviewer)';
    if (!isHuman(who.user)) return 'a service or AI identity never signs off: a person does';
    if (p.signoff) return 'already signed off by ' + p.signoff.by + ' on ' + String(p.signoff.at).slice(0, 10) + ' - a signed pack cannot change';
    if (same(p.built_by, who.user)) return 'four eyes: ' + who.user + ' built this pack and cannot also sign it off';
    if (!p.installed) return 'nothing to sign: the ' + FW[p.framework].short + ' module is not installed, so the pack holds no assessment';
    if (!integrity(p).ok) return 'the pack no longer matches its fingerprint - it cannot be signed';
    return null;
  }
  function previousOf(p) {
    const older = ofFw(p.framework).filter((x) => x.id !== p.id && String(x.built_at) < String(p.built_at));
    return older.find((x) => x.period < p.period) || older[0] || null;
  }
  function get(id, who) {
    const p = must(id), prev = previousOf(p), why = signBlock(p, who);
    return Object.assign({}, p, { integrity: integrity(p), previous: prev ? { id: prev.id, period: prev.period } : null, can_sign: !why, sign_block: why });
  }
  function list(who) {
    const all = packs().all(() => true).sort((a, b) => String(b.built_at).localeCompare(String(a.built_at)) || String(b.id).localeCompare(String(a.id)));
    const period = periodOf(now()), j = meta().get('job') || {};
    return { me: { user: who.user, role: who.role }, period, keep: KEEP,
      frameworks: KEYS.map((k) => { const F = FW[k], mine = all.filter((p) => p.framework === k), last = mine[0] || null, M = A()[F.module];
        return { key: k, code: F.code, name: F.name, short: F.short, page: F.page, source: F.source, installed: !!M, packs: mine.length, this_month: mine.some((p) => p.period === period), latest: last ? row(last) : null }; }),
      packs: all.map(row), job: { started: !!timer, last_run: j.last_run || null, last_error: j.last_error || null, failed: j.failed || [] },
      can: { build: who.role === 'operator' || who.role === 'admin', sign: who.role === 'admin' && isHuman(who.user) } };
  }

  // ---------- comparing with the previous month
  function compare(id, q, who) {
    const p = must(id);
    const w = q && q.with !== undefined && q.with !== '' ? must(q.with, 'with') : previousOf(p);
    if (w && w.framework !== p.framework) throw httpErr(400, 'with must be a pack of the same framework (' + FW[p.framework].short + ')');
    if (w && w.id === p.id) throw httpErr(400, 'with must be a different pack');
    const out = { pack: row(p), previous: w ? row(w) : null, worse: [], better: [], changed: [], added: [], removed: [], evidence_expired: [], evidence_changed: [], evidence_new: [] };
    if (!w) { out.note = 'no earlier ' + FW[p.framework].short + ' pack to compare with yet'; return out; }
    const before = new Map((w.controls || []).map((c) => [c.ref, c])), after = new Map((p.controls || []).map((c) => [c.ref, c]));
    for (const [ref, c] of after) {
      const o = before.get(ref);
      if (!o) { out.added.push({ ref, title: c.title, status: c.status }); continue; }
      if (o.status === c.status) continue;
      const x = { ref, title: c.title, from: o.status, to: c.status, why: c.why };
      const ra = RANK[o.status], rb = RANK[c.status];
      if (ra == null || rb == null || (o.status === 'not_tested' && c.status === 'not_implemented') || (o.status === 'not_implemented' && c.status === 'not_tested')) out.changed.push(x);
      else (rb < ra ? out.worse : out.better).push(x);
    }
    for (const [ref, o] of before) if (!after.has(ref)) out.removed.push({ ref, title: o.title, status: o.status });
    const evOf = (P) => { const m = new Map(); for (const c of P.controls || []) for (const e of c.evidence || []) m.set(e.id, Object.assign({ control: c.ref }, e)); return m; };
    const eb = evOf(w), ea = evOf(p), live = (e) => e && (e.state === 'current' || e.state === 'due_soon');
    for (const [eid, o] of eb) {
      const n = ea.get(eid);
      if (live(o) && !live(n)) out.evidence_expired.push({ id: eid, control: o.control, title: o.title, was: o.state, now: n ? n.state : 'no longer in the register', next_due: (n || o).next_due || null });
      else if (n && o.sha256 && n.sha256 && o.sha256 !== n.sha256) out.evidence_changed.push({ id: eid, control: o.control, title: o.title, from: o.sha256, to: n.sha256 });
      if (n && n.integrity !== o.integrity && (n.integrity === 'mismatch' || n.integrity === 'missing')) out.evidence_changed.push({ id: eid, control: o.control, title: o.title, integrity: n.integrity });
    }
    for (const [eid, n] of ea) if (!eb.has(eid)) out.evidence_new.push({ id: eid, control: n.control, title: n.title, state: n.state });
    const a = p.summary || {}, b = w.summary || {};
    out.delta = { implemented_pct: a.implemented_pct != null && b.implemented_pct != null ? a.implemented_pct - b.implemented_pct : null, implemented: ((a.counts || {}).implemented || 0) - ((b.counts || {}).implemented || 0), without_owner: (a.without_owner || 0) - (b.without_owner || 0) };
    return out;
  }

  // ---------- sign-off (four eyes, a person, once)
  function sign(id, input, who) {
    const b = body(input || {}).bool('confirm', { required: true }).str('note', { max: 1000 }).rule((o) => (o.confirm !== true ? 'confirm must be true: tick the statement that you reviewed the pack' : null)).done();
    const p = must(id), why = signBlock(p, who);
    if (why) throw httpErr(/already signed|nothing to sign|no longer matches/.test(why) ? 409 : 403, why);
    const rec = Object.assign({}, p, { signoff: { by: who.user, role: who.role, at: iso(), note: b.note || '', sha256: p.sha256, statement: STATEMENT } });
    packs().put(rec);
    audit(who, 'sign', p.id, { framework: p.framework, period: p.period, sha256: p.sha256, built_by: p.built_by, note: b.note ? 'given' : 'none' });
    return get(p.id, who);
  }

  // ---------- the workbook (rows only; the page writes the .xlsx with vendor/zyb-xlsx.js - nothing leaves the server but this)
  function exportRows(id, who) {
    const p = must(id), I = integrity(p), sm = p.summary || {};
    const list = (a) => (a || []).join('; ');
    const summary = [['Pack', p.id], ['Framework', p.name], ['Period', p.period], ['Built', p.built_at.replace('T', ' ').slice(0, 16) + ' UTC by ' + p.built_by + ' (' + p.kind + ')'],
      ['SHA-256 fingerprint', p.sha256], ['Integrity', I.ok ? 'intact' : 'DOES NOT MATCH - do not rely on it'], ['Signed off', p.signoff ? p.signoff.by + ' on ' + p.signoff.at.slice(0, 10) : 'not signed off'],
      ['Source', p.source], ['Module', p.installed ? 'installed' : 'NOT INSTALLED - ' + p.reason]]
      .concat(p.installed ? [['Controls', sm.controls], ['Implemented', (sm.counts || {}).implemented], ['Partial', (sm.counts || {}).partial], ['Not implemented', (sm.counts || {}).not_implemented],
        ['Not applicable', (sm.counts || {}).not_applicable], ['Not tested', (sm.counts || {}).not_tested], ['Implemented % of applicable', sm.implemented_pct == null ? '' : sm.implemented_pct], ['Controls without an owner', sm.without_owner]] : [])
      .concat(p.prev ? [['Previous pack', p.prev.id + ' (' + p.prev.sha256 + ')']] : []);
    const controls = (p.controls || []).map((c) => [c.ref, c.group, c.title, LABEL[c.status], c.register_result, c.why, c.owner, c.owner_source, c.tested ? String(c.tested.at).slice(0, 10) + ' - ' + c.tested.how : '',
      list(c.evidence.map((e) => e.id + ' ' + (e.file || e.title) + (e.sha256 ? ' sha256:' + e.sha256 : ''))), list((c.policies || []).map((x) => x.doc_id + ' ' + x.title)), list(c.missing)]);
    const evidence = [];
    for (const c of p.controls || []) for (const e of c.evidence) evidence.push([c.ref, e.id, e.title, e.file, e.sha256 || '', e.collected || '', e.next_due || '', e.state, e.integrity]);
    const missing = [];
    for (const c of p.controls || []) for (const m of c.missing) missing.push([c.ref, c.title, c.owner, m]);
    audit(who, 'export', p.id, { framework: p.framework, period: p.period, sha256: p.sha256, controls: controls.length });
    return { filename: 'evidence-pack-' + p.id + '.xlsx', title: 'Regulator evidence pack ' + p.id + ' - ' + p.name, sheets: [
      { name: 'Summary', columns: [{ h: 'Field', w: 28 }, { h: 'Value', w: 90 }], rows: summary },
      { name: 'Controls', columns: [{ h: 'Reference', w: 16 }, { h: 'Domain', w: 30 }, { h: 'Title', w: 60 }, { h: 'Result', w: 16 }, { h: 'Register result', w: 14 }, { h: 'Register reason', w: 50 }, { h: 'Owner', w: 22 }, { h: 'Owner from', w: 20 }, { h: 'Last tested', w: 30 }, { h: 'Evidence (file and SHA-256)', w: 60 }, { h: 'Policies', w: 40 }, { h: 'What is missing', w: 70 }], rows: controls },
      { name: 'Evidence', columns: [{ h: 'Control', w: 16 }, { h: 'Evidence', w: 12 }, { h: 'Title', w: 40 }, { h: 'File', w: 30 }, { h: 'SHA-256', w: 66 }, { h: 'Collected', w: 12, t: 'd' }, { h: 'Next due', w: 12, t: 'd' }, { h: 'State', w: 10 }, { h: 'Integrity', w: 10 }], rows: evidence },
      { name: 'Missing', columns: [{ h: 'Control', w: 16 }, { h: 'Title', w: 60 }, { h: 'Owner', w: 22 }, { h: 'What is missing', w: 80 }], rows: missing }] };
  }

  // ---------- the monthly job: each framework without a pack for this month gets one (retried hourly until it is built)
  async function tick() {
    const period = periodOf(now()), failed = [];
    for (const fw of KEYS) {
      if (packs().all((p) => p.framework === fw && p.period === period).length) continue;
      try { await buildOne(fw, SYS, 'monthly'); } catch (e) { failed.push({ framework: fw, error: s(e.message, 300) }); }
    }
    meta().put({ id: 'job', last_run: iso(), period, failed, last_error: failed.length ? failed.map((f) => FW[f.framework].short + ': ' + f.error).join(' | ').slice(0, 1000) : null });
    if (failed.length) throw new Error('evidence packs not built for ' + period + ': ' + failed.map((f) => f.framework).join(', '));
    return { period, failed };
  }
  const job = guardOf(app, 'evidence-packs.monthly', tick);
  let timer = null, stopped = false;
  function schedule(ms) {
    if (stopped) return;
    timer = setTimeout(async () => { try { await job(); } finally { schedule(HOUR); } }, ms);   // rescheduled whatever happened
    if (timer.unref) timer.unref();
  }
  function start() { if (app.noTimers || opts.noTimer || timer) return false; stopped = false; schedule(opts.firstDelayMs || 2 * 60000); return true; }
  function stop() { stopped = true; if (timer) clearTimeout(timer); timer = null; }

  // ---------- signals for Notification & Escalation
  function signals() {
    const out = [], period = periodOf(now()), day = Number(riyadh(now()).slice(8, 10));
    for (const fw of KEYS) {
      const F = FW[fw], mine = ofFw(fw);
      // a missing pack is signalled once the framework has pack history or the job recorded a failed attempt - a new install
      // (no pack yet, the job about to build the first ones) pages nobody
      const j = (meta().get('job') || {}).failed || [], f = j.find((x) => x.framework === fw);
      if (day >= 2 && !mine.some((p) => p.period === period) && (mine.length || f)) {
        out.push({ fp: 'evidence-packs:missing:' + fw + ':' + period, source: 'platform', ref: fw + ':' + period, title: 'Regulator evidence pack not built: ' + F.short + ' ' + period,
          text: 'No ' + F.short + ' evidence pack exists for ' + period + (f ? ' - the last attempt failed: ' + s(f.error, 300) : ' - the monthly job has not built it') + '. Open Regulator Evidence Packs and press Build now.', severity: 2, condition: true });
      }
      const last = mine[0];
      if (last && last.period === period && last.installed) {
        const c = compare(last.id, {}, SYS);
        if (c.previous && c.previous.period < last.period && c.worse.length) {
          out.push({ fp: 'evidence-packs:worse:' + last.id, source: 'platform', ref: last.id, title: c.worse.length + ' ' + F.short + ' control(s) got worse since last month (' + last.period + ')',
            text: c.worse.slice(0, 10).map((x) => x.ref + ' ' + LABEL[x.from] + ' -> ' + LABEL[x.to]).join('; ') + (c.worse.length > 10 ? ' …' : '') + '. Compare ' + last.id + ' with ' + c.previous.id + ' in Regulator Evidence Packs.', severity: c.worse.length >= 5 ? 3 : 2, condition: true });
        }
      }
    }
    return out;
  }

  return { list, get, compare, build, sign, exportRows, tick, start, stop, signals, fingerprint, periodOf, FW, KEEP };
}
const STATEMENT = 'I reviewed this evidence pack as the compliance reviewer. It reflects the registers as they stood when it was built; I did not build it.';

function registerEvidencePacks(srv, app, X) {
  const E = X && typeof X.list === 'function' ? X : createEvidencePacks(app, X || {});
  (app.addons = app.addons || {}).evidencePacks = app.addons.evidencePacks || E;
  srv.route('GET', '/evidence-packs', (ctx) => { ctx.need('operator'); return E.list(ctx.who); });
  srv.route('POST', '/evidence-packs/build', (ctx) => { ctx.need('operator'); return E.build(ctx.body, ctx.who); }, { maxBody: 1024 });
  srv.route('GET', '/evidence-packs/:id', (ctx) => { ctx.need('operator'); return E.get(ctx.params.id, ctx.who); });
  srv.route('GET', '/evidence-packs/:id/compare', (ctx) => { ctx.need('operator'); return E.compare(ctx.params.id, ctx.query, ctx.who); });
  srv.route('GET', '/evidence-packs/:id/export', (ctx) => { ctx.need('operator'); return E.exportRows(ctx.params.id, ctx.who); });
  srv.route('POST', '/evidence-packs/:id/sign', (ctx) => { ctx.need('admin'); return E.sign(ctx.params.id, ctx.body, ctx.who); }, { maxBody: 4096 });
  return E;
}

module.exports = { createEvidencePacks, registerEvidencePacks, fingerprint, canon, STATEMENT };
