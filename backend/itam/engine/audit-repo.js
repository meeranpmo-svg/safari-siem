// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('./brand');
/*
 * Audit Repository ({P} = /api/itam, Audit -> Audit Repository): every past audit and inspection of the organisation in one place -
 * SAMA inspections, Insurance Authority, NCA, SDAIA, CMA, the external auditor, internal audit, certification bodies - year by year,
 * with their reports and findings, so the next audit starts from what the last ones said.
 *   reports    year, body, kind, title, auditor, issued date, the report files themselves (PDF / Word / Excel; type checked by its bytes,
 *              SHA-256 kept, stored on this server only - audit reports and their evidence never go to GitHub or any outside service)
 *   findings   ref, title, condition, area, framework controls, rating, owner, due date, status (open -> in progress -> closed, risk
 *              accepted, not agreed) with the closure evidence and every change in its history. A management letter's findings list
 *              imports from Excel or CSV (column names matched by meaning: observation / finding / issue -> title, risk / severity ->
 *              rating, target date -> due ...), each line checked, nothing half-imported
 *   repeats    a finding that says again what an earlier year said is what a regulator weighs most. Each finding is compared with the
 *              findings of earlier years (word overlap of title and condition, same area, shared controls) and likely repeats are
 *              PROPOSED with the score itemised; a person confirms or rejects each one (an AI or service identity never does)
 *   analytics  per year and per body: findings by rating, closure rate (Beta-smoothed, so one closure is not "100 %"), median days to
 *              close, overdue, repeat rate; areas found in 3+ years (systemic); findings carried forward from earlier years still open;
 *              late-closure risk of each open finding from how findings of the same area and rating closed before; next-audit pack
 *   actions    an open finding becomes a GRC remediation action (source 'audit') when a person raises it, linked both ways
 *   advisor    the read-only AI audit advisor (intel kit: budget, redactSecrets, untrusted tool output); it reads the register - never
 *              the files - and proposes; people decide
 * Viewers are refused: findings name weaknesses and people. Every view of a report, upload, download, import and change is audited.
 *   GET  /audit-repo                               the register, analytics, proposals                         operator
 *   POST /audit-repo/reports                       {year, body, kind, title, auditor, issued, scope?, notes?}  operator, person
 *   POST /audit-repo/reports/:id                   edit the same fields + status (draft / final)                operator, person
 *   POST /audit-repo/reports/:id/archive           {note}                                                       admin, person
 *   POST /audit-repo/reports/:id/files             {filename, content_b64, sha256?}                             operator, person
 *   GET  /audit-repo/files/:id                     the file (base64) - audited                                  operator
 *   POST /audit-repo/reports/:id/findings          one finding                                                  operator, person
 *   POST /audit-repo/reports/:id/findings/import   {csv | xlsx_b64 + filename, dry_run?}                        operator, person
 *   POST /audit-repo/findings/:id                  {status?, owner?, due?, rating?, note, evidence?}            operator, person
 *   POST /audit-repo/findings/:id/repeat           {of, decision: confirm | reject, note}                       operator, person
 *   POST /audit-repo/findings/:id/to-action        raise a GRC remediation action                               operator, person
 *   GET  /audit-repo/export                        the register as Excel sheets (zyb-xlsx.js)                   operator, audited
 *   POST /audit-repo/ask                           {question}  the AI advisor                                   operator
 */
const crypto = require('node:crypto');
const { body, param, fileCheck } = require('./check');
const { createIntelKit, beta, DAY } = require('./intel-kit');
const { readXlsx } = require('./xlsx-read');
const L = require('./audit-analytics-lib');

const BODIES = { sama: 'SAMA', ia: 'Insurance Authority', nca: 'NCA', sdaia: 'SDAIA', cma: 'CMA', zatca: 'ZATCA', external: 'External auditor', internal: 'Internal audit', iso: 'Certification body', other: 'Other' };
const KINDS = ['inspection', 'external_audit', 'internal_audit', 'it_audit', 'cyber_audit', 'certification', 'assessment', 'pentest', 'other'];
const RATINGS = ['critical', 'high', 'medium', 'low'], RW = { critical: 4, high: 3, medium: 2, low: 1 };
const STATUS = ['open', 'in_progress', 'closed', 'risk_accepted', 'not_agreed'], OPEN = ['open', 'in_progress'];
const FILE_TYPES = ['pdf', 'docx', 'doc', 'xlsx', 'xls', 'pptx', 'msg', 'eml', 'csv', 'txt', 'png', 'jpg', 'jpeg'];
const MAX_FILE = 16 * 1024 * 1024, REPEAT_MIN = 0.45;
const isService = (u) => /^(duty|system|ai|svc|service)[:_-]/i.test(String(u || ''));
const same = (a, b) => String(a || '').toLowerCase() === String(b || '').toLowerCase();
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
// a management letter's columns, matched by meaning (English and Arabic headings)
const SYN = {
  ref: /^(ref|reference|finding (no|number|#|id)|no\.?|#|id|observation (no|#)|رقم)/i,
  title: /^(title|finding|observation|issue|subject|ملاحظة|الملاحظة|العنوان)/i,
  condition: /^(condition|description|details|detail|observation details|finding details|الوصف|التفاصيل)/i,
  area: /^(area|domain|category|process|function|section|المجال)/i,
  controls: /^(control|controls|criteria|requirement|reference to|framework|الضابط)/i,
  rating: /^(rating|risk|risk rating|severity|priority|significance|التصنيف|الخطورة)/i,
  owner: /^(owner|responsible|action owner|management owner|department|المسؤول)/i,
  due: /^(due|due date|target|target date|deadline|implementation date|التاريخ المستهدف)/i,
  status: /^(status|state|الحالة)/i,
  response: /^(management response|response|management comment|agreed action|رد الإدارة)/i,
};
const RATE_WORDS = { critical: 'critical', 'very high': 'critical', high: 'high', significant: 'high', major: 'high', medium: 'medium', moderate: 'medium', med: 'medium', low: 'low', minor: 'low', 'مرتفع': 'high', 'عالي': 'high', 'متوسط': 'medium', 'منخفض': 'low', 'حرج': 'critical' };
const STATUS_WORDS = { open: 'open', new: 'open', 'not started': 'open', 'in progress': 'in_progress', ongoing: 'in_progress', 'partially implemented': 'in_progress', closed: 'closed', implemented: 'closed', resolved: 'closed', 'risk accepted': 'risk_accepted', accepted: 'risk_accepted', 'not agreed': 'not_agreed', disagreed: 'not_agreed', 'مفتوح': 'open', 'مغلق': 'closed' };
const STOP = new Set('the and for with that this from are was were has have not all any but its into per our their there these those which while been being than then them they very within without should would could must may can will shall also such other more most some only over under upon of to in on at by as is be or an a no'.split(' '));
const words = (s) => [...new Set(String(s || '').toLowerCase().normalize('NFKC').split(/[^\p{L}\p{N}]+/u).filter((w) => w.length >= 3 && !STOP.has(w)).map((w) => (w.length > 5 ? w.replace(/(ings|ing|ions|ion|ed|es|(?<!s)s)$/u, '') : w)))];
const jacc = (a, b) => { if (!a.length || !b.length) return 0; const B = new Set(b); let i = 0; for (const x of a) if (B.has(x)) i++; return i / (a.length + b.length - i); };
const norm = (s) => String(s || '').trim().toLowerCase().replace(/\s+/g, ' ');
const days = (a, b) => (a && b ? Math.round((Date.parse(b) - Date.parse(a)) / DAY) : null);
const median = (a) => { if (!a.length) return null; const b = a.slice().sort((x, y) => x - y), m = b.length >> 1; return b.length % 2 ? b[m] : (b[m - 1] + b[m]) / 2; };

function createAuditRepo(app, opts = {}) {
  let K;
  const st = app.store, R = () => st.collection('ar_reports'), F = () => st.collection('ar_findings'), B = () => st.collection('ar_files');
  const now = () => (opts.now ? opts.now() : Date.now()), iso = () => new Date(now()).toISOString(), today = () => iso().slice(0, 10);
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role || '', ip: who.ip || '', action: 'audit-repo.' + action, target, detail }); };
  const person = (who, what) => { if (!who || !who.user || isService(who.user)) throw httpErr(403, 'a named person ' + what + ' - not a service or AI identity'); };
  const nextId = (pre, col, pad) => { let n = col().all(() => true).length + 1, id; do { id = pre + String(n++).padStart(pad, '0'); } while (col().get(id)); return id; };
  const hist = (rec, who, what) => { rec.history = (rec.history || []).concat([{ at: iso(), by: who.user, what: String(what).slice(0, 600) }]).slice(-200); };
  const mustReport = (id) => { const r = R().get(param(id, 'id')); if (!r) throw httpErr(404, 'no audit report ' + String(id).slice(0, 40)); return r; };
  const mustFinding = (id) => { const f = F().get(param(id, 'id')); if (!f) throw httpErr(404, 'no finding ' + String(id).slice(0, 40)); return f; };
  const live = (r) => r && !r.archived;

  /* ---------- reports ---------- */
  const reportFields = (b0, cur) => {
    const yr = new Date(now()).getUTCFullYear() + 1;
    const b = body(b0 || {}).int('year', { required: !cur, min: 2000, max: yr }).oneOf('body', Object.keys(BODIES), { required: !cur }).oneOf('kind', KINDS, { required: !cur })
      .str('title', { required: !cur, min: 3, max: 200 }).str('auditor', { required: !cur, max: 120 }).date('issued', { notFuture: true, now: now() }).str('scope', { max: 2000 }).str('notes', { max: 2000 })
      .oneOf('status', ['draft', 'final']).done();
    if (b.issued && b.year && Math.abs(Number(b.issued.slice(0, 4)) - b.year) > 1) throw httpErr(400, 'issued: ' + b.issued + ' is far from the audit year ' + b.year + ' - check the year');
    return b;
  };
  function createReport(b0, who) {
    person(who, 'records an audit report'); const b = reportFields(b0, null);
    const dup = R().all((r) => live(r) && r.year === b.year && r.body === b.body && norm(r.title) === norm(b.title))[0];
    if (dup) throw httpErr(409, 'title: ' + dup.id + ' already records "' + dup.title + '" (' + BODIES[dup.body] + ' ' + dup.year + ')');
    const r = Object.assign({ id: nextId('AR-', R, 4), status: 'draft', files: [], created_by: who.user, created_at: iso(), scope: '', notes: '', issued: null }, b);
    hist(r, who, 'recorded'); R().put(r); audit(who, 'report.create', r.id, { year: r.year, body: r.body, kind: r.kind }); return rview(r);
  }
  function editReport(id, b0, who) {
    person(who, 'edits an audit report'); const r = mustReport(id); if (r.archived) throw httpErr(409, r.id + ' is archived');
    const b = reportFields(b0, r), changed = Object.keys(b).filter((k) => JSON.stringify(r[k]) !== JSON.stringify(b[k]));
    if (!changed.length) return rview(r);
    Object.assign(r, b); hist(r, who, 'changed ' + changed.join(', ')); R().put(r); audit(who, 'report.edit', r.id, { changed }); return rview(r);
  }
  function archiveReport(id, b0, who) {
    person(who, 'archives an audit report'); const b = body(b0 || {}).str('note', { required: true, min: 5, max: 500 }).done(), r = mustReport(id);
    if (r.archived) throw httpErr(409, r.id + ' is already archived');
    r.archived = { by: who.user, at: iso(), note: b.note }; hist(r, who, 'archived: ' + b.note); R().put(r); audit(who, 'report.archive', r.id, { note: b.note.slice(0, 200) }); return rview(r);
  }
  function addFile(id, b0, who) {
    person(who, 'adds a report file'); const r = mustReport(id); if (r.archived) throw httpErr(409, r.id + ' is archived');
    const b = body(b0 || {}).str('filename', { required: true, max: 200 }).str('content_b64', { required: true, max: Math.ceil(MAX_FILE * 4 / 3) + 16 }).str('sha256', { max: 64 }).done();
    if (!/^[A-Za-z0-9+/=\r\n]+$/.test(b.content_b64)) throw httpErr(400, 'content_b64: the file content is not base64');
    const buf = Buffer.from(b.content_b64, 'base64'), fc = fileCheck(b.filename, buf, { allow: FILE_TYPES, max: MAX_FILE }), sha = crypto.createHash('sha256').update(buf).digest('hex');
    if (b.sha256 && b.sha256.toLowerCase() !== sha) throw httpErr(400, 'sha256: the file arrived damaged (it differs from what the browser computed) - upload it again');
    if ((r.files || []).some((x) => x.sha256 === sha)) throw httpErr(409, 'content_b64: this exact file is already on ' + r.id);
    const fid = 'ARD-' + sha.slice(0, 16);
    if (!B().get(fid)) B().put({ id: fid, filename: fc.name, type: fc.ext, mime: fc.mime, size: buf.length, sha256: sha, content_b64: buf.toString('base64'), at: iso(), by: who.user });
    r.files = (r.files || []).concat([{ id: fid, filename: fc.name, type: fc.ext, size: buf.length, sha256: sha, at: iso(), by: who.user }]);
    hist(r, who, 'file added: ' + fc.name); R().put(r); audit(who, 'file.add', r.id, { file: fid, name: fc.name, size: buf.length, sha256: sha }); return rview(r);
  }
  function getFile(fid, who) {
    const f = B().get(param(fid, 'id')); if (!f) throw httpErr(404, 'no file ' + String(fid).slice(0, 40));
    const rep = R().all((r) => (r.files || []).some((x) => x.id === f.id))[0];
    audit(who, 'file.download', f.id, { name: f.filename, report: rep ? rep.id : null });
    return { id: f.id, filename: f.filename, mime: f.mime, size: f.size, sha256: f.sha256, content_b64: f.content_b64 };
  }

  /* ---------- findings ---------- */
  const findingFields = (b0, cur) => {
    const b = body(b0 || {}).str('ref', { max: 60 }).str('title', { required: !cur, min: 3, max: 300 }).str('condition', { max: 6000 }).str('area', { max: 120 })
      .list('controls', { max: 20, item: 'str', itemMax: 60, unique: true }).oneOf('rating', RATINGS, { required: !cur }).str('owner', { max: 120 }).date('due').str('response', { max: 4000 }).done();
    return b;
  };
  function addFinding(rid, b0, who, via) {
    person(who, 'records a finding'); const r = mustReport(rid); if (r.archived) throw httpErr(409, r.id + ' is archived');
    const b = findingFields(b0, null);
    if (b.ref && F().all((f) => f.report === r.id && norm(f.ref) === norm(b.ref))[0]) throw httpErr(409, 'ref: ' + b.ref + ' is already a finding of ' + r.id);
    const f = Object.assign({ id: nextId('ARF-', F, 5), report: r.id, year: r.year, body: r.body, status: 'open', ref: '', condition: '', area: '', controls: [], owner: '', due: null, response: '', created_by: who.user, created_at: iso(), repeat: [] }, b);
    if (b0 && b0.status && STATUS.includes(b0.status) && b0.status !== 'open') { f.status = b0.status; if (f.status === 'closed') { f.closed_at = r.issued || today(); f.evidence = String(b0.evidence || 'closed before it was recorded here (' + (via || 'entry') + ')').slice(0, 1000); } }
    hist(f, who, 'recorded' + (via ? ' (' + via + ')' : '')); F().put(f); audit(who, 'finding.create', f.id, { report: r.id, rating: f.rating, status: f.status, via: via || 'form' }); return fview(f);
  }
  function importFindings(rid, b0, who) {
    person(who, 'imports findings'); const r = mustReport(rid); if (r.archived) throw httpErr(409, r.id + ' is archived');
    const b = body(b0 || {}).str('csv', { max: 4000000 }).str('xlsx_b64', { max: 11500000 }).str('filename', { max: 200 }).bool('dry_run').rule((x) => (!x.csv && !x.xlsx_b64 ? 'csv or xlsx_b64: the findings list is required' : null)).done();
    let P;
    if (b.csv) P = L.parseCsv(b.csv, { maxRows: 2000, maxCols: 40 });
    else { if (!/^[A-Za-z0-9+/=\r\n]+$/.test(b.xlsx_b64)) throw httpErr(400, 'xlsx_b64: the file content is not base64'); const buf = Buffer.from(b.xlsx_b64, 'base64'); fileCheck(b.filename || 'findings.xlsx', buf, { allow: ['xlsx'], max: 8 * 1024 * 1024 }); P = readXlsx(buf, { maxRows: 2000, maxCols: 40 }); }
    const map = {}; for (const [k, re] of Object.entries(SYN)) { const f = P.fields.find((x) => re.test(String(x).trim()) && !Object.values(map).includes(x)); if (f) map[k] = f; }
    if (!map.title) throw httpErr(400, 'the file has no finding / observation / title column - columns found: ' + P.fields.slice(0, 12).join(', '));
    const rows = [], errors = [];
    P.rows.forEach((x, i) => {
      const line = i + 2, title = String(x[map.title] || '').trim(); if (!title) return;
      const rt = map.rating ? RATE_WORDS[norm(x[map.rating])] : null, stt = map.status ? (STATUS_WORDS[norm(x[map.status])] || (norm(x[map.status]) ? null : 'open')) : 'open';
      if (!rt) { errors.push({ line, error: map.rating ? 'rating "' + String(x[map.rating]).slice(0, 30) + '" is not critical / high / medium / low' : 'no rating column' }); return; }
      if (!stt) { errors.push({ line, error: 'status "' + String(x[map.status]).slice(0, 30) + '" is not open / in progress / closed / risk accepted / not agreed' }); return; }
      let due = map.due ? String(x[map.due] || '').trim().slice(0, 10) : '';
      if (due && L.date(due) === null) { errors.push({ line, error: 'due "' + due + '" is not a date' }); return; }
      if (due && !/^\d{4}-\d{2}-\d{2}$/.test(due)) due = new Date(L.date(due)).toISOString().slice(0, 10);
      rows.push({ line, f: { ref: map.ref ? String(x[map.ref] || '').trim().slice(0, 60) : '', title: title.slice(0, 300), condition: map.condition ? String(x[map.condition] || '').slice(0, 6000) : '', area: map.area ? String(x[map.area] || '').trim().slice(0, 120) : '',
        controls: map.controls ? String(x[map.controls] || '').split(/[;,\n]/).map((s) => s.trim()).filter(Boolean).slice(0, 20) : [], rating: rt, owner: map.owner ? String(x[map.owner] || '').trim().slice(0, 120) : '', response: map.response ? String(x[map.response] || '').slice(0, 4000) : '', status: stt },
        due: due || undefined });
    });
    const refs = new Set(F().all((f) => f.report === r.id && f.ref).map((f) => norm(f.ref)));
    for (const x of rows) { if (x.f.ref && refs.has(norm(x.f.ref))) errors.push({ line: x.line, error: 'ref ' + x.f.ref + ' is already a finding of ' + r.id }); else if (x.f.ref) refs.add(norm(x.f.ref)); }
    // all or nothing: one bad line and the file is returned with every problem named, so it is fixed once and imported once
    if (errors.length || b.dry_run) return { report: r.id, columns: map, rows: rows.length, errors: errors.slice(0, 200), imported: 0, dry_run: !!b.dry_run };
    const ids = rows.map((x) => addFinding(r.id, Object.assign({}, x.f, x.due ? { due: x.due } : {}), who, 'import line ' + x.line).id);
    audit(who, 'finding.import', r.id, { rows: ids.length, columns: Object.keys(map), format: b.csv ? 'csv' : 'xlsx' });
    return { report: r.id, columns: map, rows: rows.length, errors: [], imported: ids.length, ids };
  }
  function updateFinding(id, b0, who) {
    person(who, 'updates a finding'); const f = mustFinding(id);
    const b = body(b0 || {}).oneOf('status', STATUS).str('owner', { max: 120 }).date('due').oneOf('rating', RATINGS).str('note', { required: true, min: 3, max: 2000 }).str('evidence', { max: 2000 }).str('response', { max: 4000 }).done();
    const ch = [];
    if (b.status && b.status !== f.status) {
      if (b.status === 'closed' && !(b.evidence || '').trim()) throw httpErr(400, 'evidence: closing a finding needs the evidence it was closed on');
      if (b.status === 'risk_accepted' && !/accept/i.test(b.note) && b.note.length < 15) throw httpErr(400, 'note: say who accepted the risk and until when');
      ch.push('status ' + f.status + ' -> ' + b.status); f.status = b.status;
      if (b.status === 'closed') { f.closed_at = today(); f.closed_by = who.user; f.evidence = b.evidence; } else if (OPEN.includes(b.status)) { f.closed_at = null; f.closed_by = null; }
    }
    for (const k of ['owner', 'due', 'rating', 'response']) if (b[k] !== undefined && b[k] !== f[k]) { ch.push(k + (k === 'response' ? '' : ' ' + (f[k] || '-') + ' -> ' + b[k])); f[k] = b[k]; }
    if (!ch.length) throw httpErr(400, 'nothing to change - give a new status, owner, due date, rating or response');
    hist(f, who, ch.join('; ') + ' - ' + b.note); F().put(f); audit(who, 'finding.update', f.id, { changes: ch, note: b.note.slice(0, 200) }); return fview(f);
  }

  /* ---------- repeats: proposed by the model, decided by a person ---------- */
  function repeatCandidates(f, all) {
    const wf = words(f.title + ' ' + f.condition), cf = new Set((f.controls || []).map(norm)), out = [];
    for (const g of all) {
      if (g.id === f.id || !(g.year < f.year)) continue;
      const jw = jacc(wf, words(g.title + ' ' + g.condition)), ar = f.area && g.area && norm(f.area) === norm(g.area) ? 1 : 0, cc = (g.controls || []).filter((c) => cf.has(norm(c))).length;
      const score = Math.round((0.6 * jw + 0.25 * ar + 0.15 * (cc ? 1 : 0)) * 100) / 100;
      if (score >= REPEAT_MIN) out.push({ of: g.id, year: g.year, body: g.body, title: g.title, status: g.status, score, why: [Math.round(jw * 100) + '% of the words in common', ar ? 'same area (' + g.area + ')' : null, cc ? cc + ' shared control(s)' : null].filter(Boolean) });
    }
    return out.sort((a, b) => b.score - a.score).slice(0, 3);
  }
  function decideRepeat(id, b0, who) {
    person(who, 'confirms or rejects a repeat'); const f = mustFinding(id);
    const b = body(b0 || {}).str('of', { required: true, id: true }).oneOf('decision', ['confirm', 'reject'], { required: true }).str('note', { required: true, min: 3, max: 1000 }).done();
    const g = mustFinding(b.of); if (!(g.year < f.year)) throw httpErr(400, 'of: a repeat is of a finding from an earlier year (' + g.id + ' is ' + g.year + ', this is ' + f.year + ')');
    f.repeat = (f.repeat || []).filter((x) => x.of !== g.id).concat([{ of: g.id, decision: b.decision, note: b.note, by: who.user, at: iso() }]);
    hist(f, who, (b.decision === 'confirm' ? 'confirmed as a repeat of ' : 'not a repeat of ') + g.id + ' - ' + b.note); F().put(f);
    audit(who, 'finding.repeat', f.id, { of: g.id, decision: b.decision }); return fview(f);
  }
  function toAction(id, who) {
    person(who, 'raises a remediation action'); const f = mustFinding(id);
    if (!OPEN.includes(f.status)) throw httpErr(409, f.id + ' is ' + f.status + ' - only an open finding needs an action');
    if (f.action) throw httpErr(409, f.id + ' already has action ' + f.action);
    const GR = app.addons && app.addons.grcRegisters; if (!GR) throw httpErr(424, 'the GRC register is not installed - the action cannot be raised');
    const a = GR.actionCreate({ title: f.title.slice(0, 200), source: 'audit', ref: f.id, description: BODIES[f.body] + ' ' + f.year + (f.ref ? ' ' + f.ref : '') + ': ' + (f.condition || f.title).slice(0, 3000), owner: f.owner, priority: f.rating === 'critical' ? 'high' : f.rating === 'low' ? 'low' : f.rating === 'high' ? 'high' : 'medium', due: f.due || undefined, framework: f.body === 'sama' ? 'sama' : f.body === 'nca' ? 'nca' : '' }, who);
    f.action = a.id; hist(f, who, 'remediation action ' + a.id + ' raised'); F().put(f); audit(who, 'finding.action', f.id, { action: a.id }); return { finding: fview(f), action: a };
  }

  /* ---------- views and analytics ---------- */
  const rview = (r) => ({ id: r.id, year: r.year, body: r.body, body_name: BODIES[r.body], kind: r.kind, title: r.title, auditor: r.auditor, issued: r.issued, scope: r.scope, notes: r.notes, status: r.status, files: r.files || [], archived: r.archived || null, created_by: r.created_by, created_at: r.created_at, history: (r.history || []).slice(-20) });
  function fview(f, all) {
    const t = today(), overdue = !!(OPEN.includes(f.status) && f.due && f.due < t), conf = (f.repeat || []).filter((x) => x.decision === 'confirm').map((x) => x.of);
    return Object.assign({}, f, { history: (f.history || []).slice(-30), overdue, days_overdue: overdue ? days(f.due, t) : 0, repeat_of: conf, days_to_close: f.closed_at ? days((R().get(f.report) || {}).issued || String(f.created_at || '').slice(0, 10) || null, f.closed_at) : null,   // from the report's issue date
      candidates: all ? repeatCandidates(f, all).filter((c) => !(f.repeat || []).some((x) => x.of === c.of)) : undefined });
  }
  // late-closure risk of an open finding: the share of earlier findings of the same area (else rating) that closed after their due
  // date or are still open past it - Beta-smoothed, so a new area with no history reads 50 %, not 0
  function lateRisk(f, all) {
    const past = all.filter((g) => g.id !== f.id && g.due && (g.closed_at || (OPEN.includes(g.status) && g.due < today())));
    const area = f.area ? past.filter((g) => norm(g.area) === norm(f.area)) : [], pool = area.length >= 3 ? area : past.filter((g) => g.rating === f.rating);
    const late = pool.filter((g) => (g.closed_at ? g.closed_at > g.due : true)).length;
    return { p: Math.round(beta(late, pool.length) * 100), basis: pool.length ? pool.length + ' earlier finding(s) of ' + (pool === area ? 'the ' + f.area + ' area' : 'rating ' + f.rating) + ', ' + late + ' closed late or still overdue' : 'no history yet - 50 % by default' };
  }
  function view(who) {
    const reps = R().all(live), rid = new Set(reps.map((r) => r.id)), all = F().all((f) => rid.has(f.report)), t = today();
    const fv = all.map((f) => fview(f, all));
    const years = [...new Set(reps.map((r) => r.year))].sort((a, b) => b - a);
    const cell = (L2) => { const closed = L2.filter((f) => f.status === 'closed'), done = L2.filter((f) => !OPEN.includes(f.status)); const dc = closed.map((f) => f.days_to_close).filter((d) => d != null && d >= 0);
      return { findings: L2.length, by_rating: Object.fromEntries(RATINGS.map((r) => [r, L2.filter((f) => f.rating === r).length])), open: L2.filter((f) => OPEN.includes(f.status)).length, overdue: L2.filter((f) => f.overdue).length,
        closed: closed.length, closure_rate: L2.length ? Math.round(beta(done.length, L2.length) * 100) : null, median_days_to_close: median(dc), repeats: L2.filter((f) => f.repeat_of.length).length }; };
    const byYear = years.map((y) => Object.assign({ year: y, reports: reps.filter((r) => r.year === y).length }, cell(fv.filter((f) => f.year === y))));
    const bodies = Object.keys(BODIES).filter((k) => reps.some((r) => r.body === k)).map((k) => Object.assign({ body: k, name: BODIES[k], years: [...new Set(reps.filter((r) => r.body === k).map((r) => r.year))].sort() }, cell(fv.filter((f) => f.body === k))));
    const matrix = bodies.map((b) => ({ body: b.body, name: b.name, cells: years.map((y) => { const L2 = fv.filter((f) => f.body === b.body && f.year === y); return L2.length || reps.some((r) => r.body === b.body && r.year === y) ? { year: y, findings: L2.length, open: L2.filter((f) => OPEN.includes(f.status)).length, repeats: L2.filter((f) => f.repeat_of.length).length } : null; }) }));
    const areaYears = {}; for (const f of fv) if (f.area) (areaYears[norm(f.area)] = areaYears[norm(f.area)] || { area: f.area, years: new Set(), findings: 0, open: 0 }), areaYears[norm(f.area)].years.add(f.year), areaYears[norm(f.area)].findings++, OPEN.includes(f.status) && areaYears[norm(f.area)].open++;
    const systemic = Object.values(areaYears).filter((a) => a.years.size >= 3).map((a) => ({ area: a.area, years: [...a.years].sort(), findings: a.findings, open: a.open })).sort((a, b) => b.years.length - a.years.length || b.findings - a.findings);
    const curYear = years[0] || null, carried = fv.filter((f) => OPEN.includes(f.status) && curYear && f.year < curYear).sort((a, b) => a.year - b.year || RW[b.rating] - RW[a.rating]);
    const open = fv.filter((f) => OPEN.includes(f.status)).map((f) => Object.assign(f, { late_risk: lateRisk(f, all) }));
    const proposals = fv.filter((f) => f.candidates && f.candidates.length).map((f) => ({ finding: f.id, year: f.year, body: f.body, title: f.title, candidates: f.candidates })).sort((a, b) => b.candidates[0].score - a.candidates[0].score);
    // one trend line over the years with findings: are there fewer each year?
    const pts = byYear.filter((y) => y.findings).map((y) => ({ x: y.year, y: y.findings })).sort((a, b) => a.x - b.x);
    let trend = null; if (pts.length >= 3) { const n = pts.length, mx = pts.reduce((a, p) => a + p.x, 0) / n, my = pts.reduce((a, p) => a + p.y, 0) / n, sxx = pts.reduce((a, p) => a + (p.x - mx) ** 2, 0); const sl = sxx ? pts.reduce((a, p) => a + (p.x - mx) * (p.y - my), 0) / sxx : 0; trend = { per_year: Math.round(sl * 10) / 10, direction: sl > 0.5 ? 'rising' : sl < -0.5 ? 'falling' : 'flat', years: n }; }
    const actions = [];
    const A = (p, title, detail, n, filter) => { if (n) actions.push({ priority: p, title, detail, count: n, filter }); };
    A(100, carried.filter((f) => f.body === 'sama' || f.body === 'ia').length + ' SAMA / Insurance Authority finding(s) from earlier years still open', 'Regulators read an old finding still open as a governance failure: close or re-plan each one with a dated owner before the next inspection.', carried.filter((f) => f.body === 'sama' || f.body === 'ia').length, 'carried');
    A(90, fv.filter((f) => f.repeat_of.length && OPEN.includes(f.status)).length + ' confirmed repeat finding(s) still open', 'A repeat says the first fix did not hold: look for the root cause, not the symptom.', fv.filter((f) => f.repeat_of.length && OPEN.includes(f.status)).length, 'repeat');
    A(80, fv.filter((f) => f.overdue && (f.rating === 'critical' || f.rating === 'high')).length + ' critical / high finding(s) past their due date', 'Escalate to the owner\'s head of department; re-plan with a new date and a reason.', fv.filter((f) => f.overdue && (f.rating === 'critical' || f.rating === 'high')).length, 'overdue');
    A(70, proposals.length + ' finding(s) look like a repeat of an earlier year', 'Confirm or reject each proposal - the repeat rate per year counts confirmed repeats only.', proposals.length, 'proposals');
    A(60, open.filter((f) => f.late_risk.p >= 70 && f.due && f.due >= t).length + ' open finding(s) likely to close late', 'Findings of this area / rating have usually closed after their due date: check progress now.', open.filter((f) => f.late_risk.p >= 70 && f.due && f.due >= t).length, 'late');
    A(50, systemic.length + ' area(s) found in 3 or more years', 'A systemic weakness: a programme, not a ticket.', systemic.length, 'systemic');
    A(40, open.filter((f) => !f.owner || !f.due).length + ' open finding(s) without an owner or a due date', 'Every finding needs a named owner and a date.', open.filter((f) => !f.owner || !f.due).length, 'unowned');
    A(30, reps.filter((r) => !(r.files || []).length).length + ' report(s) with no report file', 'Attach the signed report so the evidence sits with the record.', reps.filter((r) => !(r.files || []).length).length, 'nofile');
    actions.sort((a, b) => b.priority - a.priority);
    if (who) audit(who, 'view', 'register', { reports: reps.length, findings: all.length });
    const kpis = { reports: reps.length, years: years.length, findings: fv.length, open: open.length, overdue: fv.filter((f) => f.overdue).length, carried: carried.length, repeats: fv.filter((f) => f.repeat_of.length).length, proposals: proposals.length, systemic: systemic.length,
      closure_rate: fv.length ? Math.round(beta(fv.filter((f) => !OPEN.includes(f.status)).length, fv.length) * 100) : null };
    return { generated_at: iso(), installed: true, bodies_catalogue: BODIES, kinds: KINDS, ratings: RATINGS, statuses: STATUS, kpis, actions, by_year: byYear, by_body: bodies, matrix: { years, rows: matrix }, systemic, trend,
      reports: reps.sort((a, b) => b.year - a.year || String(b.issued || '').localeCompare(String(a.issued || ''))).map(rview), archived: R().all((r) => !!r.archived).map((r) => ({ id: r.id, year: r.year, body: r.body, title: r.title, archived: r.archived })),
      findings: fv.sort((a, b) => b.year - a.year || RW[b.rating] - RW[a.rating]), carried: carried.map((f) => f.id), proposals, ai: K.aiStatus(),
      note: 'Repeats are proposed by word overlap, area and shared controls and decided by a person. Closure rates are Beta-smoothed. Report files stay on this server.' };
  }
  function exportX(who) {
    const v = view(null); audit(who, 'export', 'register', { findings: v.findings.length });
    const rep = Object.fromEntries(v.reports.map((r) => [r.id, r]));
    return { filename: 'audit-repository-' + today() + '.xlsx', sheets: [
      { name: 'Findings', columns: ['Finding', 'Year', 'Body', 'Report', 'Ref', 'Title', 'Area', 'Rating', 'Status', 'Owner', 'Due', 'Overdue days', 'Closed', 'Repeat of', 'Late risk %', 'Action'].map((h) => ({ h, t: /Year|days|%/.test(h) ? 'n' : /Due|Closed/.test(h) ? 'd' : 's' })),
        rows: v.findings.map((f) => [f.id, f.year, BODIES[f.body], (rep[f.report] || {}).title || f.report, f.ref, f.title, f.area, f.rating, f.status, f.owner, f.due || '', f.days_overdue || '', f.closed_at || '', f.repeat_of.join(' '), f.late_risk ? f.late_risk.p : '', f.action || '']) },
      { name: 'By year', columns: ['Year', 'Reports', 'Findings', 'Critical', 'High', 'Medium', 'Low', 'Open', 'Overdue', 'Closure rate %', 'Median days to close', 'Repeats'].map((h) => ({ h, t: 'n' })), rows: v.by_year.map((y) => [y.year, y.reports, y.findings, y.by_rating.critical, y.by_rating.high, y.by_rating.medium, y.by_rating.low, y.open, y.overdue, y.closure_rate, y.median_days_to_close, y.repeats]) },
      { name: 'Reports', columns: ['Report', 'Year', 'Body', 'Kind', 'Title', 'Auditor', 'Issued', 'Files'].map((h) => ({ h, t: h === 'Year' || h === 'Files' ? 'n' : h === 'Issued' ? 'd' : 's' })), rows: v.reports.map((r) => [r.id, r.year, r.body_name, r.kind, r.title, r.auditor, r.issued || '', r.files.length]) }] };
  }

  K = createIntelKit(app, { key: 'audit-repo', feature: 'itam.audit-repo-advisor', now: opts.now, sdk: opts.sdk, getKey: opts.getKey, noTimer: true,
    system: ('You are the audit history advisor to the internal audit, IT audit, cyber security audit and compliance teams of ' + ZYB_ORG.name + '. You see the register of past audits and inspections (SAMA, Insurance Authority, NCA, SDAIA, the external auditor, internal audit, certification bodies): reports, findings, ratings, owners, due dates, status, repeat proposals and the analytics. Help prepare for the next audit: what an inspector will ask about, which findings are carried forward, which areas keep coming back and what a root-cause fix would look like. Repeat findings are proposed by the page and decided by a person - you never confirm one, close a finding or change anything. Cite finding ids.'),
    tools: [{ name: 'register', description: 'The audit register: KPIs, findings per year and body, systemic areas, carried-forward findings, repeat proposals and the actions list.', run: async () => { const v = view(null); return { kpis: v.kpis, by_year: v.by_year, by_body: v.by_body.map((b) => ({ body: b.name, years: b.years, findings: b.findings, open: b.open, closure_rate: b.closure_rate })), systemic: v.systemic, actions: v.actions, trend: v.trend }; } },
      { name: 'findings', description: 'Findings filtered by body, year, status or area (id, year, body, ref, title, area, rating, status, owner, due, repeat_of, late risk). No report files.', input_schema: { type: 'object', properties: { body: { type: 'string', enum: Object.keys(BODIES) }, year: { type: 'integer' }, status: { type: 'string', enum: STATUS }, area: { type: 'string', maxLength: 120 } }, additionalProperties: false },
        run: async (q) => { const v = view(null); return v.findings.filter((f) => (!q.body || f.body === q.body) && (!q.year || f.year === q.year) && (!q.status || f.status === q.status) && (!q.area || norm(f.area).includes(norm(q.area)))).slice(0, 80).map((f) => ({ id: f.id, year: f.year, body: f.body, ref: f.ref, title: f.title, area: f.area, rating: f.rating, status: f.status, owner: f.owner, due: f.due, repeat_of: f.repeat_of, late_risk: f.late_risk ? f.late_risk.p : null, condition: String(f.condition || '').slice(0, 600) })); } }] });

  return { view, createReport, editReport, archiveReport, addFile, getFile, addFinding: (rid, b, who) => addFinding(rid, b, who, null), importFindings, updateFinding, decideRepeat, toAction, exportX, repeatCandidates, words, ask: K.ask, aiStatus: K.aiStatus, TOOLS: K.TOOLS, start: () => {}, BODIES };
}

function registerAuditRepo(srv, app, X) {
  const op = (fn) => (ctx) => { ctx.need('operator'); return fn(ctx); };   // findings name weaknesses and people: no viewers
  srv.route('GET', '/audit-repo', op((ctx) => X.view(ctx.who)));
  srv.route('POST', '/audit-repo/reports', op((ctx) => X.createReport(ctx.body, ctx.who)), { maxBody: 16384 });
  srv.route('POST', '/audit-repo/reports/:id', op((ctx) => X.editReport(ctx.params.id, ctx.body, ctx.who)), { maxBody: 16384 });
  srv.route('POST', '/audit-repo/reports/:id/archive', (ctx) => { ctx.need('admin'); return X.archiveReport(ctx.params.id, ctx.body, ctx.who); }, { maxBody: 4096 });
  srv.route('POST', '/audit-repo/reports/:id/files', op((ctx) => X.addFile(ctx.params.id, ctx.body, ctx.who)), { maxBody: 23000000 });
  srv.route('GET', '/audit-repo/files/:id', op((ctx) => X.getFile(ctx.params.id, ctx.who)));
  srv.route('POST', '/audit-repo/reports/:id/findings', op((ctx) => X.addFinding(ctx.params.id, ctx.body, ctx.who)), { maxBody: 32768 });
  srv.route('POST', '/audit-repo/reports/:id/findings/import', op((ctx) => X.importFindings(ctx.params.id, ctx.body, ctx.who)), { maxBody: 12000000 });
  srv.route('POST', '/audit-repo/findings/:id', op((ctx) => X.updateFinding(ctx.params.id, ctx.body, ctx.who)), { maxBody: 16384 });
  srv.route('POST', '/audit-repo/findings/:id/repeat', op((ctx) => X.decideRepeat(ctx.params.id, ctx.body, ctx.who)), { maxBody: 4096 });
  srv.route('POST', '/audit-repo/findings/:id/to-action', op((ctx) => X.toAction(ctx.params.id, ctx.who)), { maxBody: 1024 });
  srv.route('GET', '/audit-repo/export', op((ctx) => X.exportX(ctx.who)));
  srv.route('GET', '/audit-repo/ai/status', op(() => X.aiStatus()));
  srv.route('POST', '/audit-repo/ask', op((ctx) => X.ask(ctx.body, ctx.who)), { maxBody: 8192 });
}

module.exports = { createAuditRepo, registerAuditRepo, BODIES, words };
