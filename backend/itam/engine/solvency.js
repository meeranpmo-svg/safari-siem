// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Solvency & Capital (Business Risk): the Insurance Authority's "Solvency and Capital Template" (SCA.nn), run by the platform.
 * The template's ~16,000 formulas stay the calculation - the platform never re-implements or overwrites them. It reads each
 * workbook the actuarial / finance teams prepare, runs the review around it, and gives back the file in exactly the format the
 * Authority issued.
 *
 *   import       the filled template (.xlsx, operator). Read: insurer, as-at date and template version; the results Excel computed
 *                (Regulatory Solvency schedules 1-4 and the solvency ratio; RBC, own funds and the RBC solvency ratio, actual and
 *                projected; the composition of the capital charge; every stress / scenario test with its rank); the template's own
 *                Validations (Pass / Fail with the "comment if fail"); the Sign-off Record. A newer upload for the same as-at date
 *                replaces a draft; after approval it is a resubmission (revision 2, 3, ...).
 *   changes      against the previous approved return: every input value that changed (sheet, cell, old, new), largest first, and
 *                the change in each headline figure.
 *   integrity    against the previous return on the same template version: every formula that differs - the Authority's
 *                instruction is "do not make changes to the formula in the green cells".
 *   sign-off     each area of the Sign-off Record is signed in the platform by the named person (their own account): name,
 *                title, department, expert judgement, comments.
 *   failures     a validation that fails needs an explanation (in the workbook or recorded here).
 *   workflow     draft -> reviewed (a different person from the one who uploaded) -> approved by the Risk Head (approval scope
 *                'risk': an administrator or a job role carrying it; never the uploader, never a service / AI identity; every
 *                area signed off and every failure explained) -> submitted (date and the Authority's reference). Returned to
 *                draft with a reason. Every step audited.
 *   report       the same workbook, with the platform's sign-offs written into the Sign-off Record and the explanations into
 *                the empty "comment if fail" cells, flagged to recalculate when opened - nothing else changes.
 * Files are kept on the server (data_dir/state/solvency, mode 600), never in the repository: they hold the company's figures.
 */
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { body, param, fileCheck } = require('./check');
const { readBook, patchBook, splitRef } = require('./xlsx-book');
const { isHuman } = require('./approve-scopes');

const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const NOT_INPUT = new Set(['Instructions', 'Version', 'Dropdown', 'Correlations', 'Validations', 'Comparison with SII', 'Sign-off Record', 'Comments', 'Summary of results', 'RBC']);
const STATUS = ['draft', 'reviewed', 'approved', 'submitted', 'superseded'];
const sha = (b) => crypto.createHash('sha256').update(b).digest('hex');
const short = (s) => crypto.createHash('sha1').update(String(s)).digest('hex').slice(0, 10);
const num = (v) => (typeof v === 'number' && Number.isFinite(v) ? v : null);
const str = (v) => (v === null || v === undefined ? '' : String(v)).trim();
const COLS = (a, b) => { const out = []; for (let c = a; c <= b; c++) { let s = '', n = c; while (n) { s = String.fromCharCode(65 + ((n - 1) % 26)) + s; n = Math.floor((n - 1) / 26); } out.push(s); } return out; };

// ---------------------------------------------------------------- reading the template
function rowsOf(sh) { const R = new Map(); if (!sh) return R; for (const [ref, c] of sh.cells) { const { row, col } = splitRef(ref); if (!R.has(row)) R.set(row, {}); R.get(row)[col] = c; } return R; }
function findRow(R, cols, re) { for (const [row, cells] of [...R.entries()].sort((a, b) => a[0] - b[0])) for (const c of cols) { const x = cells[c]; if (x && typeof x.v === 'string' && re.test(x.v.trim())) return row; } return null; }
function read(buf) {
  const B = readBook(buf), need = ['Instructions', 'Regulatory Solvency', 'Projected RBC', 'Summary of results', 'Sign-off Record', 'Validations'];
  const missing = need.filter((n) => !B.sheet(n));
  if (missing.length) throw httpErr(400, 'this is not the Insurance Authority Solvency and Capital template: no sheet ' + missing.map((n) => '"' + n + '"').join(', '));
  const cell = (s, ref) => { const sh = B.sheet(s); const c = sh && sh.cells.get(ref); return c ? c.v : null; };
  const ins = rowsOf(B.sheet('Instructions'));
  const rowIns = findRow(ins, ['B'], /^Name of the Insurer/i), rowAt = findRow(ins, ['B'], /^(Data as at|Valuation Date)\b/i);   // the 2026 Q1 template says "Valuation Date"
  const insurer = rowIns ? str((ins.get(rowIns).C || {}).v) : '';
  let asAt = rowAt ? (ins.get(rowAt).C || {}).v : null;
  if (typeof asAt === 'number') asAt = new Date(Math.round((asAt - 25569) * 864e5)).toISOString().slice(0, 10);
  asAt = /^\d{4}-\d{2}-\d{2}/.test(str(asAt)) ? str(asAt).slice(0, 10) : null;
  if (!asAt) throw httpErr(400, 'Instructions: "Data as at" / "Valuation Date" is not a date - fill it in the template and upload again');
  let version = '';
  const ver = B.sheet('Version'); if (ver) for (const c of ver.cells.values()) if (typeof c.v === 'string' && /^SCA\.\d{2,3}$/.test(c.v.trim()) && c.v.trim() > version) version = c.v.trim();
  const year = +asAt.slice(0, 4);

  // Regulatory Solvency: the year columns and schedules 1-4
  const RS = rowsOf(B.sheet('Regulatory Solvency')), ycols = [];
  for (const [row, cells] of RS) for (const c of COLS(3, 12)) if (cells[c] && num(cells[c].v) >= 2000 && num(cells[c].v) <= 2100 && !ycols.some((y) => y.col === c)) ycols.push({ col: c, year: cells[c].v, row });
  ycols.sort((a, b) => a.year - b.year);
  const RSI = { claims_gh: /^Claims Method/i, premium_gh: /^Premium Method/i, req_ps: /^Required margin \(Protection/i, admissible: /^Total Admissible Assets/i, liabilities: /^Total Liabilities/i, naa: /^Total Net Admissible Assets/i, required: /^Total Required Minimum Margin/i, mcr: /^Minimum Capital Requirement/i, excess: /^Excess/i, ratio: /^Solvency Ratio/i, basis: /^Basis for Required/i };
  const regulatory = { columns: ycols.map((y) => ({ year: y.year, kind: y.year > year ? 'projection' : 'actual' })), rows: {} };
  for (const k of Object.keys(RSI)) { const r = findRow(RS, ['B', 'C'], RSI[k]); regulatory.rows[k] = ycols.map((y) => (r && RS.get(r)[y.col] ? RS.get(r)[y.col].v : null)); }

  // Projected RBC: RBC, own funds, RBC solvency ratio by year-end (business plan, and the alternative if filled)
  const PR = rowsOf(B.sheet('Projected RBC')), hdr = findRow(PR, COLS(3, 16), /^\d{4}YE$/), pcols = [];
  if (hdr) for (const c of COLS(3, 16)) { const x = PR.get(hdr)[c]; if (x && /^\d{4}YE$/.test(str(x.v))) pcols.push({ col: c, label: str(x.v), year: +str(x.v).slice(0, 4) }); }
  const alt = [], plan = []; pcols.forEach((p) => ((pcols.filter((q) => q.label === p.label)[0] === p) ? plan : alt).push(p));
  const PRI = { rbc: /^RBC$/i, own_funds: /^Own Funds$/i, net_ra: /^Net RA$/i, net_csm: /^Net CSM$/i, ratio: /^RBC Solvency Ratio/i };
  const projected = { columns: plan.map((p) => ({ label: p.label, kind: p.year > year ? 'projection' : 'actual' })), rows: {}, alternative: null };
  for (const k of Object.keys(PRI)) { const r = findRow(PR, ['A', 'B'], PRI[k]); projected.rows[k] = plan.map((p) => (r && PR.get(r)[p.col] ? num(PR.get(r)[p.col].v) : null)); }
  if (alt.length) { const r = findRow(PR, ['A', 'B'], PRI.ratio), a = alt.map((p) => (r && PR.get(r)[p.col] ? num(PR.get(r)[p.col].v) : null)); if (a.some((v) => v)) projected.alternative = { columns: alt.map((p) => p.label), ratio: a }; }

  // RBC: composition of the capital charge (share of the overall RBC)
  const RB = rowsOf(B.sheet('RBC')), composition = [];
  const top = findRow(RB, ['AA'], /^Overall RBC/i);
  if (top) for (let r = top + 1; r < top + 12; r++) { const c = RB.get(r) || {}; if (!c.AA || typeof c.AA.v !== 'string') continue; const label = c.AA.v.trim(); if (/^RBC$/i.test(label)) break; composition.push({ label, share: num(c.AB && c.AB.v) }); }

  // Summary of results: every stress / scenario test, before and after risk mitigation, with its rank
  const SR = rowsOf(B.sheet('Summary of results')), hs = findRow(SR, ['B'], /^Stress\/?\s*Scenario Test/i), tests = [];
  let total = null;
  if (hs) for (let r = hs + 1; r < hs + 80; r++) { const c = SR.get(r); if (!c || !c.B) continue; const t = { test: str(c.B.v), undiv_before: num(c.C && c.C.v), div_before: num(c.D && c.D.v), undiv_after: num(c.F && c.F.v), div_after: num(c.G && c.G.v), rank_after: num(c.H && c.H.v) };
    if (/^Undiversified Change in NAV/i.test(t.test)) { total = t; break; } tests.push(t); }

  // Validations: every Pass / Fail check, its label and the "comment if fail" next to it
  const V = B.sheet('Validations'), VR = rowsOf(V), checks = [];
  for (const [row, cells] of VR) for (const col of Object.keys(cells)) {
    const v = cells[col].v, isPF = typeof v === 'string' && /^(pass|fail)$/i.test(v.trim()), isFalse = v === false;
    if (!isPF && !isFalse) continue;
    const ci = splitRef(col + row).c; let label = '';
    for (let k = ci - 1; k >= 1 && !label; k--) { const x = cells[COLS(k, k)[0]]; if (x && typeof x.v === 'string' && !/^(pass|fail|checks|true|false)$/i.test(x.v.trim()) && x.v.trim()) label = x.v.trim(); }
    let head = ''; for (let r = row; r >= 1 && !head; r--) { const x = (VR.get(r) || {})[col]; if (r < row && x && typeof x.v === 'string' && !/^(pass|fail)$/i.test(x.v.trim())) head = x.v.trim(); }
    const right = COLS(ci + 1, ci + 1)[0], rc = cells[right];
    const comment = rc && typeof rc.v === 'string' && !/^(pass|fail)$/i.test(rc.v.trim()) ? rc.v.trim() : '';
    const commentCell = rc && rc.f !== null ? null : right + row;
    checks.push({ ref: col + row, label: label.slice(0, 160), column: head.slice(0, 80), status: isFalse ? 'fail' : v.trim().toLowerCase(), comment: comment.slice(0, 600), comment_cell: isPF ? commentCell : null });
  }

  // Sign-off Record: one slot per row naming a function and a person
  const SO = rowsOf(B.sheet('Sign-off Record')), slots = []; let area = '', section = '';
  const hrow = findRow(SO, ['A'], /^Area$/i) || 2;
  for (const row of [...SO.keys()].sort((a, b) => a - b)) {
    if (row <= hrow) continue; const c = SO.get(row), t = (k) => str(c[k] && c[k].v);
    const any = ['B', 'C', 'D', 'E', 'F'].some((k) => t(k));
    if (t('A') && !any && /Results\s*$/i.test(t('A'))) { section = t('A'); continue; }
    if (t('A')) area = t('A');
    if (!any && !t('A')) continue;
    slots.push({ row, section, area, department: t('B'), name: t('C'), title: t('D'), judgement: t('E'), comment: t('F') });
  }

  // inputs (values typed into the template) and formulas, for the comparisons
  const inputs = {}, formulas = {};
  for (const s of B.sheets) for (const [ref, c] of s.cells) {
    if (c.f !== null) { formulas[s.name + '!' + ref] = short(c.f); continue; }
    if (!NOT_INPUT.has(s.name) && num(c.v) !== null) inputs[s.name + '!' + ref] = c.v;
  }
  const curR = regulatory.columns.findIndex((x) => x.year === year), curP = projected.columns.findIndex((x) => x.label === year + 'YE');
  const headline = {
    regulatory_ratio: curR >= 0 ? num(regulatory.rows.ratio[curR]) : null, net_admissible: curR >= 0 ? num(regulatory.rows.naa[curR]) : null,
    required_margin: curR >= 0 ? num(regulatory.rows.required[curR]) : null, excess: curR >= 0 ? num(regulatory.rows.excess[curR]) : null,
    rbc: curP >= 0 ? projected.rows.rbc[curP] : null, own_funds: curP >= 0 ? projected.rows.own_funds[curP] : null, rbc_ratio: curP >= 0 ? projected.rows.ratio[curP] : null,
  };
  return { parts: partsOf(regulatory, projected, year), insurer, as_at: asAt, year, version, regulatory, projected, composition, tests, total, checks, slots, inputs, formulas, headline, sheets: B.sheets.length };
}

// ---------------------------------------------------------------- what-if (the template's own top-level formulas)
// Regulatory Solvency: net admissible assets = admissible assets - liabilities; required = MAX(MAX(claims, premium method) [general and
// health] + protection & savings, minimum capital requirement); ratio = net admissible / required. Projected RBC: ratio = (own funds +
// net RA + net CSM) / RBC. Checked against the ratios Excel computed: a template whose parts do not give its own ratio is not what-if'd.
const PARTS = ['admissible', 'liabilities', 'claims_gh', 'premium_gh', 'req_ps', 'mcr', 'own_funds', 'net_ra', 'net_csm', 'rbc'];
function partsOf(regulatory, projected, year) {
  const ri = regulatory.columns.findIndex((c) => c.year === year), pi = projected.columns.findIndex((c) => c.label === year + 'YE');
  const g = (o, k, i) => (i >= 0 && o.rows[k] ? num(o.rows[k][i]) : null);
  return { admissible: g(regulatory, 'admissible', ri), liabilities: g(regulatory, 'liabilities', ri), claims_gh: g(regulatory, 'claims_gh', ri), premium_gh: g(regulatory, 'premium_gh', ri), req_ps: g(regulatory, 'req_ps', ri), mcr: g(regulatory, 'mcr', ri),
    own_funds: g(projected, 'own_funds', pi), net_ra: g(projected, 'net_ra', pi), net_csm: g(projected, 'net_csm', pi), rbc: g(projected, 'rbc', pi),
    excel: { regulatory_ratio: g(regulatory, 'ratio', ri), rbc_ratio: g(projected, 'ratio', pi) } };
}
function ratios(p) {
  const z = (v) => (v == null ? 0 : v);
  const naa = z(p.admissible) - z(p.liabilities), req = Math.max(Math.max(z(p.claims_gh), z(p.premium_gh)) + z(p.req_ps), z(p.mcr));
  const avail = z(p.own_funds) + z(p.net_ra) + z(p.net_csm);
  return { net_admissible: naa, required: req, excess: naa - req, regulatory_ratio: req ? naa / req : null, available_capital: avail, rbc: z(p.rbc), rbc_ratio: p.rbc ? avail / p.rbc : null,
    binding: z(p.mcr) > Math.max(z(p.claims_gh), z(p.premium_gh)) + z(p.req_ps) ? 'minimum capital requirement' : (z(p.premium_gh) >= z(p.claims_gh) ? 'premium method' : 'claims method') };
}
const close = (a, b) => a != null && b != null && Math.abs(a - b) <= Math.max(1e-6, Math.abs(b) * 1e-6);

// ---------------------------------------------------------------- the module
function createSolvency(app, opts = {}) {
  const now = opts.now || Date.now, iso = () => new Date(now()).toISOString();
  const RET = () => app.store.collection('sca_returns');
  // inside the store's own folder (data_dir/state): the one place the service is certain to write (ProtectSystem=strict)
  const dir = opts.dir || path.join((app.config && app.config.data_dir) || '.', 'state', 'solvency');
  const file = (id, ext) => path.join(dir, id + ext);
  const audit = (who, action, target, detail) => app.audit({ by: who.user, role: who.role, ip: who.ip || '', action: 'brisk.solvency.' + action, target, detail });
  const person = (who, what) => { if (!isHuman(who && who.user)) throw httpErr(403, 'only a person can ' + what + ' (not a service or AI identity)'); };
  const get = (id) => { const r = RET().get(param(id, 'id')); if (!r) throw httpErr(404, 'no return ' + id); return r; };
  const side = (r) => { try { return JSON.parse(fs.readFileSync(file(r.id, '.json'), 'utf8')); } catch (e) { if (e.code === 'ENOENT') return { inputs: {}, formulas: {} }; throw e; } };
  const all = () => RET().all().sort((a, b) => (a.as_at === b.as_at ? b.revision - a.revision : a.as_at < b.as_at ? 1 : -1));
  const summary = (r) => ({ id: r.id, as_at: r.as_at, revision: r.revision, insurer: r.insurer, version: r.version, filename: r.filename, status: r.status, headline: r.headline,
    uploaded_by: r.uploaded_by, uploaded_at: r.uploaded_at, fails: r.checks.filter((c) => c.status === 'fail').length, unexplained: unexplained(r).length,
    unsigned: r.slots.filter((s) => !r.signoff[s.row]).length, slots: r.slots.length, approved_by: r.approval ? r.approval.by : null, submitted: r.submission || null });
  const unexplained = (r) => r.checks.filter((c) => c.status === 'fail' && !c.comment && !(r.explain || {})[c.ref]);
  function previousApproved(r) { return all().find((x) => x.id !== r.id && ['approved', 'submitted'].includes(x.status) && (x.as_at < r.as_at || (x.as_at === r.as_at && x.revision < r.revision))) || null; }
  function sameVersion(r) { const E = RET().all().filter((x) => x.id !== r.id && x.version === r.version && (x.seq || 0) < (r.seq || 0)).sort((a, b) => b.seq - a.seq); return E.find((x) => x.status !== 'superseded') || E[0] || null; }

  function importReturn(input, who) {
    person(who, 'upload a return');
    const b = body(input || {}).str('filename', { required: true, max: 200 }).str('xlsx_b64', { required: true, max: 34 * 1024 * 1024 }).done();
    if (!/^[A-Za-z0-9+/=\r\n]+$/.test(b.xlsx_b64)) throw httpErr(400, 'xlsx_b64: not base64');
    const buf = Buffer.from(b.xlsx_b64, 'base64'), f = fileCheck(b.filename, buf, { allow: ['xlsx'], max: 25 * 1024 * 1024 });
    let R;
    try { R = read(buf); } catch (e) {
      if (e.status) throw e;
      if (app.log && app.log.error) app.log.error('solvency: the workbook could not be read', { file: f.name, message: e.message, at: String(e.stack || '').split('\n')[1] || '' });
      throw httpErr(422, 'the workbook could not be read (' + String(e.message).slice(0, 160) + ') - send the file name and this message to the platform team');
    }
    const at = iso(), id = 'sca-' + R.as_at.replace(/-/g, '') + '-' + crypto.randomBytes(3).toString('hex');
    const same = all().filter((x) => x.as_at === R.as_at && x.status !== 'superseded');
    const locked = same.find((x) => ['approved', 'submitted'].includes(x.status));
    const revision = Math.max(0, ...all().filter((x) => x.as_at === R.as_at).map((x) => x.revision)) + 1;
    try {
      fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
      fs.writeFileSync(file(id, '.xlsx'), buf, { mode: 0o600 });
      fs.writeFileSync(file(id, '.json'), JSON.stringify({ inputs: R.inputs, formulas: R.formulas }), { mode: 0o600 });
    } catch (e) {
      if (app.log && app.log.error) app.log.error('solvency: the workbook could not be stored', { dir, code: e.code, message: e.message });
      // the administrator can act on this: say where and why (no figures in the message)
      throw httpErr(424, 'the server could not store the workbook (' + (e.code || 'error') + ' in ' + dir + ') - an administrator runs the update again or gives the sentra-itam service write access there');
    }
    for (const x of same) if (!['approved', 'submitted'].includes(x.status)) { x.status = 'superseded'; x.superseded_by = id; x.history.push({ at, by: who.user, action: 'superseded', note: 'replaced by revision ' + revision }); RET().put(x); }
    const seq = Math.max(0, ...RET().all().map((x) => x.seq || 0)) + 1;
    const rec = { id, seq, as_at: R.as_at, revision, resubmission: !!locked, insurer: R.insurer, version: R.version, filename: f.name, size: buf.length, sha256: sha(buf),
      uploaded_by: who.user, uploaded_at: at, status: 'draft', headline: R.headline, regulatory: R.regulatory, projected: R.projected, composition: R.composition,
      parts: R.parts, tests: R.tests, total: R.total, checks: R.checks, slots: R.slots, inputs: Object.keys(R.inputs).length, formulas: Object.keys(R.formulas).length,
      signoff: {}, explain: {}, review: null, approval: null, submission: null, history: [{ at, by: who.user, action: 'uploaded', note: f.name }] };
    RET().put(rec);
    const CC = (app.addons || {}).solvencyCollect; if (CC) rec.cycle = CC.onReturn(rec, who); if (rec.cycle) RET().put(rec);
    audit(who, 'import', id, { as_at: R.as_at, revision, version: R.version, sha256: rec.sha256, fails: R.checks.filter((c) => c.status === 'fail').length, resubmission: rec.resubmission });
    return detail(id);
  }
  function changes(r) {
    const p = previousApproved(r); if (!p) return null;
    const A = side(p).inputs, B = side(r).inputs, list = [];
    for (const k of new Set(Object.keys(A).concat(Object.keys(B)))) { const a = A[k] === undefined ? null : A[k], c = B[k] === undefined ? null : B[k]; if (a !== c) list.push({ cell: k, old: a, new: c, delta: (c || 0) - (a || 0) }); }
    list.sort((x, y) => Math.abs(y.delta) - Math.abs(x.delta));
    const by = {}; list.forEach((x) => { const s = x.cell.split('!')[0]; by[s] = (by[s] || 0) + 1; });
    const H = {}; for (const k of Object.keys(r.headline)) H[k] = { old: p.headline[k], new: r.headline[k], delta: num(r.headline[k]) !== null && num(p.headline[k]) !== null ? r.headline[k] - p.headline[k] : null };
    return { against: { id: p.id, as_at: p.as_at, revision: p.revision }, changed: list.length, by_sheet: by, largest: list.slice(0, 40), headline: H };
  }
  function integrity(r) {
    const p = sameVersion(r); if (!p) return { against: null, changed: [], note: 'first return on template ' + (r.version || '(version not stated)') + ' - nothing to compare the formulas with' };
    const A = side(p).formulas, B = side(r).formulas, changed = [];
    for (const k of new Set(Object.keys(A).concat(Object.keys(B)))) if (A[k] !== B[k]) changed.push({ cell: k, was: A[k] ? 'formula' : 'value', now: B[k] ? (A[k] ? 'different formula' : 'formula') : 'value (formula removed)' });
    return { against: { id: p.id, as_at: p.as_at, revision: p.revision }, changed: changed.slice(0, 200), count: changed.length };
  }
  function detail(id) {
    const r = get(id);
    return Object.assign({}, r, { unexplained: unexplained(r).map((c) => c.ref), unsigned: r.slots.filter((s) => !r.signoff[s.row]).map((s) => s.row), changes: changes(r), integrity: integrity(r) });
  }
  function list() { const R = all(); const cur = R.find((x) => x.status !== 'superseded'); return { returns: R.map(summary), latest: cur ? summary(cur) : null }; }
  const editable = (r) => { if (!['draft'].includes(r.status)) throw httpErr(409, 'return ' + r.id + ' is ' + r.status + ' - only a draft can change (return it to draft first)'); };

  function signoff(id, input, who) {
    person(who, 'sign off');
    const b = body(input || {}).int('row', { required: true, min: 1, max: 1000 }).str('name', { required: true, max: 120 }).str('title', { required: true, max: 120 }).str('department', { max: 120 })
      .str('judgement', { max: 1000 }).str('comment', { max: 2000 }).done();
    const r = get(id); editable(r);
    const s = r.slots.find((x) => x.row === b.row); if (!s) throw httpErr(400, 'row: the Sign-off Record has no area on row ' + b.row);
    r.signoff[b.row] = { name: b.name, title: b.title, department: b.department || s.department, judgement: b.judgement || '-', comment: b.comment || '-', by: who.user, at: iso() };
    r.history.push({ at: iso(), by: who.user, action: 'signed off', note: s.area + ' · ' + (b.department || s.department) });
    RET().put(r); audit(who, 'signoff', id, { row: b.row, area: s.area, department: b.department || s.department });
    return detail(id);
  }
  function explain(id, input, who) {
    person(who, 'explain a failed check');
    const b = body(input || {}).str('ref', { required: true, max: 10, re: /^[A-Z]{1,3}\d{1,5}$/, msg: 'ref: a cell such as C25' }).str('note', { required: true, max: 1000 }).done();
    const r = get(id); editable(r);
    const c = r.checks.find((x) => x.ref === b.ref && x.status === 'fail'); if (!c) throw httpErr(400, 'ref: ' + b.ref + ' is not a failed check of this return');
    r.explain[b.ref] = { note: b.note, by: who.user, at: iso() }; RET().put(r); audit(who, 'explain', id, { ref: b.ref, check: c.label });
    return detail(id);
  }
  function review(id, input, who) {
    person(who, 'review');
    const b = body(input || {}).str('note', { max: 1000 }).done(), r = get(id); editable(r);
    if (r.uploaded_by === who.user) throw httpErr(403, 'four eyes: the person who uploaded the return cannot review it');
    r.status = 'reviewed'; r.review = { by: who.user, at: iso(), note: b.note || '' }; r.history.push({ at: iso(), by: who.user, action: 'reviewed', note: b.note || '' });
    RET().put(r); audit(who, 'review', id, { note: b.note || '' }); return detail(id);
  }
  function approve(id, input, who) {
    person(who, 'approve');
    const b = body(input || {}).str('note', { max: 1000 }).done(), r = get(id);
    if (r.status !== 'reviewed') throw httpErr(409, 'only a reviewed return can be approved (this one is ' + r.status + ')');
    if (r.uploaded_by === who.user) throw httpErr(403, 'four eyes: the person who uploaded the return cannot approve it');
    const un = r.slots.filter((s) => !r.signoff[s.row]); if (un.length) throw httpErr(409, 'not signed off yet: ' + un.map((s) => s.area + (s.department ? ' (' + s.department + ')' : '')).join('; '));
    const ux = unexplained(r); if (ux.length) throw httpErr(409, 'failed checks without an explanation: ' + ux.map((c) => c.ref + ' ' + c.label).join('; '));
    r.status = 'approved'; r.approval = { by: who.user, role: who.role, at: iso(), note: b.note || '' }; r.history.push({ at: iso(), by: who.user, action: 'approved', note: b.note || '' });
    RET().put(r); audit(who, 'approve', id, { as_at: r.as_at, revision: r.revision, regulatory_ratio: r.headline.regulatory_ratio, rbc_ratio: r.headline.rbc_ratio }); return detail(id);
  }
  function sendBack(id, input, who) {
    person(who, 'return a return to draft');
    const b = body(input || {}).str('reason', { required: true, max: 1000 }).done(), r = get(id);
    if (!['reviewed', 'approved'].includes(r.status)) throw httpErr(409, 'a ' + r.status + ' return cannot go back to draft');
    r.status = 'draft'; r.review = null; r.approval = null; r.history.push({ at: iso(), by: who.user, action: 'returned to draft', note: b.reason });
    RET().put(r); audit(who, 'return', id, { reason: b.reason }); return detail(id);
  }
  function submitted(id, input, who) {
    person(who, 'record the submission');
    const b = body(input || {}).str('date', { required: true, max: 10, re: /^\d{4}-\d{2}-\d{2}$/, msg: 'date: YYYY-MM-DD' }).str('reference', { required: true, max: 120 }).str('note', { max: 1000 }).done(), r = get(id);
    if (r.status !== 'approved') throw httpErr(409, 'only an approved return is submitted (this one is ' + r.status + ')');
    if (b.date > iso().slice(0, 10)) throw httpErr(400, 'date: the submission date is in the future');
    r.status = 'submitted'; r.submission = { date: b.date, reference: b.reference, note: b.note || '', by: who.user, at: iso() };
    r.history.push({ at: iso(), by: who.user, action: 'submitted to the Insurance Authority', note: b.reference }); RET().put(r);
    audit(who, 'submitted', id, { date: b.date, reference: b.reference }); return detail(id);
  }
  function download(id, who) {
    const r = get(id); let buf;
    try { buf = fs.readFileSync(file(r.id, '.xlsx')); } catch (e) { if (e.code === 'ENOENT') throw httpErr(410, 'the workbook of ' + r.id + ' is no longer on the server'); throw e; }
    if (sha(buf) !== r.sha256) throw httpErr(500, 'the stored workbook of ' + r.id + ' does not match its fingerprint');
    const so = {}, val = {};
    for (const row of Object.keys(r.signoff)) { const s = r.signoff[row]; Object.assign(so, { ['B' + row]: s.department, ['C' + row]: s.name, ['D' + row]: s.title, ['E' + row]: s.judgement, ['F' + row]: s.comment }); }
    for (const c of r.checks) { const x = (r.explain || {})[c.ref]; if (x && !c.comment && c.comment_cell) val[c.comment_cell] = x.note; }
    const edits = {}; if (Object.keys(so).length) edits['Sign-off Record'] = so; if (Object.keys(val).length) edits.Validations = val;
    const out = patchBook(buf, edits);
    audit(who, 'download', id, { status: r.status, signoffs: Object.keys(r.signoff).length, explanations: Object.keys(val).length });
    return { filename: r.filename, status: r.status, final: ['approved', 'submitted'].includes(r.status), xlsx_b64: out.toString('base64') };
  }
  // what-if: the Risk Head changes the figures behind the two ratios and sees them move (nothing in the return changes)
  function partsFor(r) {
    if (r.parts) return r.parts;
    let buf; try { buf = fs.readFileSync(file(r.id, '.xlsx')); } catch (e) { if (e.code === 'ENOENT') throw httpErr(410, 'the workbook of ' + r.id + ' is no longer on the server'); throw e; }
    r.parts = read(buf).parts; RET().put(r); return r.parts;     // returns uploaded before the what-if existed: read once from the stored file
  }
  function whatIf(id, input, who) {
    const b0 = input || {}, bb = body(b0); for (const k of PARTS) bb.num(k, { min: -1e12, max: 1e12 }); const b = bb.done();
    const r = get(id), base = partsFor(r), cur = ratios(base);
    const reproducible = { regulatory: close(cur.regulatory_ratio, base.excel.regulatory_ratio), rbc: close(cur.rbc_ratio, base.excel.rbc_ratio) };
    const scen = Object.assign({}, base); for (const k of PARTS) if (b[k] !== undefined) scen[k] = b[k];
    const after = ratios(scen), changed = PARTS.filter((k) => b[k] !== undefined && b[k] !== base[k]);
    // how far each figure can move before a ratio reaches 100 %
    const room = { net_admissible: cur.net_admissible - cur.required, own_funds: cur.available_capital - cur.rbc, rbc: cur.available_capital - cur.rbc };
    const sens = ['admissible', 'liabilities', 'premium_gh', 'own_funds', 'rbc'].map((k) => { const up = Object.assign({}, base, { [k]: (base[k] || 0) * 1.1 }), dn = Object.assign({}, base, { [k]: (base[k] || 0) * 0.9 }); const U = ratios(up), Dn = ratios(dn);
      return { part: k, plus10: { regulatory_ratio: U.regulatory_ratio, rbc_ratio: U.rbc_ratio }, minus10: { regulatory_ratio: Dn.regulatory_ratio, rbc_ratio: Dn.rbc_ratio } }; });
    return { id: r.id, as_at: r.as_at, base: Object.assign({}, base, cur), scenario: Object.assign({}, scen, after), changed, reproducible, room, sensitivity: sens, scenarios: r.scenarios || [] };
  }
  function scenarioSave(id, input, who) {
    person(who, 'save a scenario');
    const raw = input || {}, bb = body(raw).str('name', { required: true, max: 80 }).str('note', { max: 1000 }); for (const k of PARTS) bb.num(k, { min: -1e12, max: 1e12 }); const b = bb.done();
    const r = get(id), w = whatIf(id, b, who); if (!w.changed.length) throw httpErr(400, 'the scenario changes no figure');
    r.scenarios = (r.scenarios || []).filter((x) => x.name.toLowerCase() !== b.name.toLowerCase());
    if (r.scenarios.length >= 30) throw httpErr(409, 'this return already holds 30 scenarios - delete one first');
    const rec = { name: b.name, note: b.note || '', changes: Object.fromEntries(w.changed.map((k) => [k, b[k]])), regulatory_ratio: w.scenario.regulatory_ratio, rbc_ratio: w.scenario.rbc_ratio, by: who.user, at: iso() };
    r.scenarios.push(rec); RET().put(r);
    audit(who, 'scenario.save', id, { name: b.name, changes: rec.changes, regulatory_ratio: rec.regulatory_ratio, rbc_ratio: rec.rbc_ratio });
    return whatIf(id, {}, who);
  }
  function scenarioDelete(id, input, who) {
    person(who, 'delete a scenario');
    const b = body(input || {}).str('name', { required: true, max: 80 }).done(), r = get(id), before = (r.scenarios || []).length;
    r.scenarios = (r.scenarios || []).filter((x) => x.name.toLowerCase() !== b.name.toLowerCase());
    if (r.scenarios.length === before) throw httpErr(404, 'no scenario named ' + b.name);
    RET().put(r); audit(who, 'scenario.delete', id, { name: b.name }); return whatIf(id, {}, who);
  }
  // insights: the pictures and the numbers behind them, all from figures Excel computed (nothing invented, nothing assumed)
  //   history    every approved / submitted return and this one: both ratios over time; trend (least squares) and next year's
  //              estimate only with 3+ dated returns - the page says how little history there is otherwise
  //   projection the business plan's ratios (Projected RBC / Regulatory Solvency columns)
  //   bridge     what moved each ratio since the last approved return, one figure at a time (sequential attribution)
  //   stress     each stress / scenario test's loss after mitigation applied to today's capital: the ratio after it, and the
  //              tests that would take a ratio below 100 %; the diversified total too
  //   reverse    the loss that takes each ratio to 100 %
  function insights(id) {
    const r = get(id), p = partsFor(r), cur = ratios(p);
    const pts = RET().all().filter((x) => x.id === r.id || ['approved', 'submitted'].includes(x.status)).sort((a, b) => (a.as_at < b.as_at ? -1 : a.as_at > b.as_at ? 1 : a.revision - b.revision));
    const byDate = {}; for (const x of pts) byDate[x.as_at] = x;          // the latest revision of each date
    const history = Object.keys(byDate).sort().map((d) => { const x = byDate[d]; return { as_at: d, id: x.id, status: x.status, regulatory_ratio: x.headline.regulatory_ratio, rbc_ratio: x.headline.rbc_ratio }; });
    const fit = (key) => { const P = history.filter((h) => num(h[key]) !== null).map((h) => [Date.parse(h.as_at) / (365.25 * 864e5), h[key]]); if (P.length < 3) return null;
      const n = P.length, mx = P.reduce((a, q) => a + q[0], 0) / n, my = P.reduce((a, q) => a + q[1], 0) / n, sxx = P.reduce((a, q) => a + (q[0] - mx) ** 2, 0); if (!sxx) return null;
      const slope = P.reduce((a, q) => a + (q[0] - mx) * (q[1] - my), 0) / sxx, last = P[P.length - 1][0], res = P.map((q) => q[1] - (my + slope * (q[0] - mx))), se = Math.sqrt(res.reduce((a, e) => a + e * e, 0) / Math.max(1, n - 2));
      const next = my + slope * (last + 1 - mx); return { per_year: slope, next_year: next, low: next - 1.28 * se, high: next + 1.28 * se, points: n }; };
    const trend = { regulatory: fit('regulatory_ratio'), rbc: fit('rbc_ratio'), note: history.length < 3 ? 'trend needs 3 or more approved returns (' + history.length + ' so far)' : null };
    const projection = { rbc: (r.projected.columns || []).map((c, i) => ({ label: c.label, kind: c.kind, ratio: num(r.projected.rows.ratio[i]) })), regulatory: (r.regulatory.columns || []).map((c, i) => ({ label: String(c.year), kind: c.kind, ratio: num(r.regulatory.rows.ratio[i]) })) };
    let bridge = null; const prev = previousApproved(r);
    if (prev) {
      const q = partsFor(prev), a = Object.assign({}, q), step = (label, keys, which) => { const before = ratios(a)[which]; for (const k of keys) a[k] = p[k]; return { label, delta: ratios(a)[which] - before }; };
      const reg = [step('Admissible assets', ['admissible'], 'regulatory_ratio'), step('Liabilities', ['liabilities'], 'regulatory_ratio'), step('Required margin', ['claims_gh', 'premium_gh', 'req_ps', 'mcr'], 'regulatory_ratio')];
      Object.assign(a, q);
      const rbc = [step('Own funds', ['own_funds'], 'rbc_ratio'), step('Net RA and CSM', ['net_ra', 'net_csm'], 'rbc_ratio'), step('Risk-based capital', ['rbc'], 'rbc_ratio')];
      bridge = { against: { id: prev.id, as_at: prev.as_at, revision: prev.revision }, regulatory: { from: ratios(q).regulatory_ratio, to: cur.regulatory_ratio, steps: reg }, rbc: { from: ratios(q).rbc_ratio, to: cur.rbc_ratio, steps: rbc } };
    }
    const after = (loss) => ({ regulatory_ratio: cur.required ? (cur.net_admissible - loss) / cur.required : null, rbc_ratio: cur.rbc ? (cur.available_capital - loss) / cur.rbc : null });
    const stress = (r.tests || []).filter((t) => num(t.div_after) !== null).map((t) => { const loss = Math.max(0, -t.div_after), A = after(loss);
      return { test: t.test, loss, rank: t.rank_after, regulatory_ratio: A.regulatory_ratio, rbc_ratio: A.rbc_ratio, breach: (A.regulatory_ratio !== null && A.regulatory_ratio < 1) || (A.rbc_ratio !== null && A.rbc_ratio < 1) }; }).sort((x, y) => y.loss - x.loss);
    // the template's total adds the tests up with no correlation between them: far harsher than the RBC, which combines them with
    // correlations - shown as a sum with that note, never as a breach
    const total = r.total && num(r.total.div_after) !== null ? Object.assign({ test: 'Sum of every test', loss: Math.max(0, -r.total.div_after), note: 'every test at once, added with no diversification between them - the RBC (' + Math.round(cur.rbc) + ') is the correlated combination' }, after(Math.max(0, -r.total.div_after))) : null;
    const reverse = { regulatory: cur.net_admissible - cur.required, rbc: cur.available_capital - cur.rbc, own_funds: p.own_funds };
    return { id: r.id, as_at: r.as_at, current: cur, history, trend, projection, bridge, stress, total, reverse, composition: r.composition || [], breaches: stress.filter((x) => x.breach).map((x) => x.test) };
  }
  // for the collection workflow (engine/solvency-collect.js): the inputs of every approved return, oldest first, and a stored workbook
  const history = () => RET().all().filter((x) => ['approved', 'submitted'].includes(x.status)).sort((a, b) => (a.as_at < b.as_at ? -1 : a.as_at > b.as_at ? 1 : a.revision - b.revision)).map((x) => ({ id: x.id, as_at: x.as_at, revision: x.revision, version: x.version, inputs: side(x).inputs }));
  const workbook = (id) => { const r = get(id), buf = fs.readFileSync(file(r.id, '.xlsx')); if (sha(buf) !== r.sha256) throw httpErr(500, 'the stored workbook of ' + r.id + ' does not match its fingerprint'); return { rec: r, buf }; };
  // ---- two returns side by side (any two dates; the older is "from", the newer "to"): the headline figures, the parts behind the two
  // ratios, the capital-charge mix, every stress test, the checks and sign-off - each with its change. The regulatory ratio's change is
  // split exactly into what net admissible assets did and what the required margin did (holding the other at its "from" value first).
  function compare(q) {
    const a0 = get(param(q && q.a, 'a')), b0 = get(param(q && q.b, 'b'));
    if (a0.id === b0.id) throw httpErr(400, 'b: choose two different returns');
    const [A, B] = a0.as_at < b0.as_at || (a0.as_at === b0.as_at && a0.revision <= b0.revision) ? [a0, b0] : [b0, a0];
    const d = (x, y) => (num(x) !== null && num(y) !== null ? y - x : null), rel = (x, y) => (num(x) !== null && num(y) !== null && x !== 0 ? (y - x) / Math.abs(x) : null);
    const line = (key, label, x, y, kind) => ({ key, label, kind: kind || 'amount', from: num(x), to: num(y), change: d(x, y), change_pct: kind === 'ratio' || kind === 'share' ? null : rel(x, y) });
    const hA = A.headline || {}, hB = B.headline || {};
    const headline = [line('regulatory_ratio', 'Regulatory solvency ratio', hA.regulatory_ratio, hB.regulatory_ratio, 'ratio'), line('net_admissible', 'Net admissible assets', hA.net_admissible, hB.net_admissible),
      line('required_margin', 'Required minimum margin', hA.required_margin, hB.required_margin), line('excess', 'Excess over the margin', hA.excess, hB.excess),
      line('rbc_ratio', 'RBC solvency ratio', hA.rbc_ratio, hB.rbc_ratio, 'ratio'), line('own_funds', 'Own funds', hA.own_funds, hB.own_funds), line('rbc', 'Risk-based capital', hA.rbc, hB.rbc)];
    const PL = { admissible: 'Total admissible assets', liabilities: 'Total liabilities', claims_gh: 'Claims method margin (general & health)', premium_gh: 'Premium method margin (general & health)', req_ps: 'Required margin (protection & savings)', mcr: 'Minimum capital requirement', own_funds: 'Own funds', net_ra: 'Net risk adjustment', net_csm: 'Net CSM', rbc: 'Risk-based capital' };
    const pA = A.parts || {}, pB = B.parts || {}, parts = PARTS.map((k) => line(k, PL[k], pA[k], pB[k]));
    const rA = ratios(pA), rB = ratios(pB);
    // the bridge: ratio = NAA / required. (NAA_b - NAA_a) / req_a, then NAA_b / req_b - NAA_b / req_a - the two add up to the change
    let bridge = null; const na = num(hA.net_admissible), nb = num(hB.net_admissible), qa = num(hA.required_margin), qb = num(hB.required_margin);
    if (na !== null && nb !== null && qa && qb) bridge = { from: na / qa, assets: (nb - na) / qa, margin: nb / qb - nb / qa, to: nb / qb,
      note: 'Net admissible assets moved the ratio by the first figure (at last year\'s margin); the required margin moved it by the second. They add up to the change.' };
    const labels = [...new Set((A.composition || []).map((c) => c.label).concat((B.composition || []).map((c) => c.label)))];
    const cOf = (r, l) => { const c = (r.composition || []).find((x) => x.label === l); return c ? c.share : null; };
    const composition = labels.map((l) => line(l, l, cOf(A, l), cOf(B, l), 'share'));
    const tn = [...new Set((A.tests || []).map((t) => t.test).concat((B.tests || []).map((t) => t.test)))];
    const tOf = (r, n) => (r.tests || []).find((t) => t.test === n) || {};
    const stress = tn.map((n) => Object.assign(line(n, n, tOf(A, n).div_after, tOf(B, n).div_after), { rank_from: tOf(A, n).rank_after == null ? null : tOf(A, n).rank_after, rank_to: tOf(B, n).rank_after == null ? null : tOf(B, n).rank_after }));
    const st = (r) => ({ id: r.id, as_at: r.as_at, revision: r.revision, status: r.status, version: r.version, filename: r.filename, approved_by: r.approval ? r.approval.by : null,
      fails: r.checks.filter((c) => c.status === 'fail').length, unexplained: unexplained(r).length, signed: r.slots.filter((x) => r.signoff[x.row]).length, slots: r.slots.length, binding: ratios(r.parts || {}).binding });
    const notes = [];
    if (A.version !== B.version) notes.push('The two returns use different template versions (' + (A.version || '—') + ' and ' + (B.version || '—') + '): a line the template moved or renamed can read as blank in one year.');
    for (const r of [A, B]) if (!['approved', 'submitted'].includes(r.status)) notes.push(r.as_at + ' revision ' + r.revision + ' is ' + r.status + ', not approved: its figures can still change.');
    if (rA.binding !== rB.binding) notes.push('The binding requirement changed: ' + rA.binding + ' (' + A.as_at + ') to ' + rB.binding + ' (' + B.as_at + ').');
    return { from: st(A), to: st(B), headline, parts, bridge, composition, stress, notes, amounts: "SR '000 as in the template" };
  }
  return { compare, _now: now, insights, whatIf, scenarioSave, scenarioDelete, list, detail, importReturn, signoff, explain, review, approve, sendBack, submitted, download, history, workbook, dir, _read: read };
}

function registerSolvency(srv, app, S) {
  const W = (ctx) => ({ user: ctx.who.user, role: ctx.who.role, ip: ctx.who.ip });
  const ID = (ctx) => param(ctx.params.id, 'id');
  const riskGate = (ctx) => { if (typeof app.approveGate === 'function') app.approveGate(ctx, 'risk'); else ctx.need('admin'); };
  srv.route('GET', '/brisk/solvency', (ctx) => { ctx.need('viewer'); return S.list(); });
  srv.route('GET', '/brisk/solvency/compare', (ctx) => { ctx.need('viewer'); return S.compare(ctx.query || {}); });
  srv.route('GET', '/brisk/solvency/:id', (ctx) => { ctx.need('viewer'); return S.detail(ID(ctx)); });
  srv.route('POST', '/brisk/solvency/import', (ctx) => { ctx.need('operator'); return S.importReturn(ctx.body, W(ctx)); }, { maxBody: 35 * 1024 * 1024 });
  srv.route('POST', '/brisk/solvency/:id/signoff', (ctx) => { ctx.need('operator'); return S.signoff(ID(ctx), ctx.body, W(ctx)); }, { maxBody: 8192 });
  srv.route('POST', '/brisk/solvency/:id/explain', (ctx) => { ctx.need('operator'); return S.explain(ID(ctx), ctx.body, W(ctx)); }, { maxBody: 4096 });
  srv.route('POST', '/brisk/solvency/:id/review', (ctx) => { ctx.need('operator'); return S.review(ID(ctx), ctx.body, W(ctx)); }, { maxBody: 4096 });
  srv.route('POST', '/brisk/solvency/:id/approve', (ctx) => { ctx.need('operator'); riskGate(ctx); return S.approve(ID(ctx), ctx.body, W(ctx)); }, { maxBody: 4096 });
  srv.route('POST', '/brisk/solvency/:id/return', (ctx) => { ctx.need('operator'); riskGate(ctx); return S.sendBack(ID(ctx), ctx.body, W(ctx)); }, { maxBody: 4096 });
  srv.route('POST', '/brisk/solvency/:id/submitted', (ctx) => { ctx.need('operator'); riskGate(ctx); return S.submitted(ID(ctx), ctx.body, W(ctx)); }, { maxBody: 4096 });
  srv.route('GET', '/brisk/solvency/:id/download', (ctx) => { ctx.need('operator'); return S.download(ID(ctx), W(ctx)); });
  // what-if: a calculation only (nothing stored) - any operator; saving a scenario for the committee is the Risk function's
  srv.route('GET', '/brisk/solvency/:id/insights', (ctx) => { ctx.need('viewer'); return S.insights(ID(ctx)); });
  srv.route('POST', '/brisk/solvency/:id/whatif', (ctx) => { ctx.need('operator'); return S.whatIf(ID(ctx), ctx.body, W(ctx)); }, { maxBody: 4096 });
  srv.route('POST', '/brisk/solvency/:id/scenarios', (ctx) => { ctx.need('operator'); riskGate(ctx); return S.scenarioSave(ID(ctx), ctx.body, W(ctx)); }, { maxBody: 4096 });
  srv.route('POST', '/brisk/solvency/:id/scenarios/delete', (ctx) => { ctx.need('operator'); riskGate(ctx); return S.scenarioDelete(ID(ctx), ctx.body, W(ctx)); }, { maxBody: 1024 });
  (app.addons = app.addons || {}).solvency = S;
  // collecting the inputs from the departments (engine/solvency-collect.js)
  const CM = require('./solvency-collect'); const CC = CM.createCollect(app, S, { now: S._now }); CM.registerCollect(srv, app, CC); app.addons.solvencyCollect = CC;
}

module.exports = { createSolvency, registerSolvency, STATUS, NOT_INPUT, _read: read };
