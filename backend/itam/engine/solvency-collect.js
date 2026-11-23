// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Solvency & Capital - collecting the inputs from the departments (engine/solvency.js holds the returns).
 * The Insurance Authority's template is filled by several functions: Finance (balance sheet, investments, counterparties),
 * Actuarial (underwriting risk, projections), Reinsurance (scenarios), Risk (operational risk). The platform runs that round:
 *
 *   cycle        opened by the Risk function (approval scope 'risk') for an as-at date with a due date, from a base workbook: the
 *                last approved return (its values are carried forward as the starting point) or a new template uploaded.
 *   packs        one per department: the template sheets it owns (an editable default), a named owner, a GRC action with the
 *                due date so the request sits in that department's action list. The department downloads the whole template
 *                (formulas and instructions for context), fills ITS sheets and uploads it; only its own sheets are read, so it
 *                cannot change another department's figures. A changed formula in its sheets is refused.
 *   checks (ML)  every value against last year's and the history of approved returns, deterministic and explained:
 *                  units      about 1,000 x (or 1/1,000) the previous value - SAR entered instead of SAR '000
 *                  sign       the sign flipped on a material amount
 *                  empty      a cell that had a value is now blank (the template says 0, never blank)
 *                  jump       robust z-score >= 4 over 3+ approved returns, else a change of more than 50 %, on a material amount
 *                  stale      90 %+ of the pack's values unchanged from the base - carried forward, not updated?
 *                each flag (not 'stale', which is a note) needs the department's explanation before the pack can be accepted.
 *   four eyes    submit marks the GRC action done; a different person in the Risk function accepts (action verified closed) or
 *                returns it with a reason (action reopened). Never a service / AI identity.
 *   assemble     when every pack is accepted: the base workbook with every accepted value and the new as-at date written in, to
 *                recalculate in Excel and upload as the return (the review and approval run on that upload).
 *   AI           the AI Business Risk Officer reads the cycle (progress, overdue, flags with explanations) through a read-only tool and
 *                can draft explanations - a person writes them in. Nothing is changed by the AI.
 * Files stay on the server (data_dir/state/solvency/cycles/<id>/, mode 600). Every step validated, role-checked and audited.
 */
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { body, param, fileCheck } = require('./check');
const { readBook, patchBook, splitRef } = require('./xlsx-book');
const { isHuman } = require('./approve-scopes');
const { NOT_INPUT } = require('./solvency');

const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const DEPTS = {
  'Finance Function': ['SOFP', 'Regulatory Solvency', 'Market', 'Counterparty Default', 'SOI', 'Comparison with Last Year', 'Input Collation'],
  'Actuarial Function': ['Non-Life & Short Term P&S UW', 'Life UW', 'Projected RBC', 'LOB-wise Allocation', 'AF contribution'],
  'Reinsurance': ['Scenarios'],
  'Risk Function': ['Op risk'],
};
const MATERIAL = 1000;            // SR '000 - one million riyals
const KINDS = { units: 'about 1,000 x the previous value - SAR entered instead of SAR \'000?', sign: 'the sign flipped', empty: 'left blank (the template needs 0, never blank)', jump: 'unusual change' };
const num = (v) => (typeof v === 'number' && Number.isFinite(v) ? v : null);
const slug = (s) => String(s).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 40);
const median = (a) => { const b = a.slice().sort((x, y) => x - y), m = b.length >> 1; return b.length % 2 ? b[m] : (b[m - 1] + b[m]) / 2; };
const shortHash = (s) => crypto.createHash('sha1').update(String(s)).digest('hex').slice(0, 10);

// ---------------------------------------------------------------- machine learning checks (pure, tested on their own)
function checkValues(cells, base, hist, o = {}) {
  const mat = o.material || MATERIAL, flags = []; let unchanged = 0, compared = 0;
  for (const cell of cells) {
    const nv = base[cell] === undefined && o.values[cell] === undefined ? undefined : (o.values[cell] === undefined ? null : o.values[cell]);
    if (nv === undefined) continue;
    const pv = base[cell] === undefined ? null : base[cell];
    if (pv !== null && nv !== null) { compared++; if (pv === nv) unchanged++; }
    if (pv !== null && nv === null) { flags.push({ cell, kind: 'empty', old: pv, new: null, why: 'had ' + pv + ' last time; now blank - the template needs 0, never blank' }); continue; }
    if (pv === null || nv === null || pv === nv) continue;
    const ratio = Math.abs(nv / (pv || 1e-12)), big = Math.max(Math.abs(pv), Math.abs(nv)) >= mat;
    if (pv !== 0 && nv !== 0 && big && ((ratio >= 700 && ratio <= 1400) || (ratio >= 1 / 1400 && ratio <= 1 / 700))) { flags.push({ cell, kind: 'units', old: pv, new: nv, why: Math.round(ratio >= 1 ? ratio : 1 / ratio) + ' x ' + (ratio >= 1 ? 'larger' : 'smaller') + ' than ' + pv + ' - amounts are in SR \'000' }); continue; }
    if (pv * nv < 0 && big) { flags.push({ cell, kind: 'sign', old: pv, new: nv, why: 'was ' + pv + ', now ' + nv }); continue; }
    const H = (hist[cell] || []).filter((x) => num(x) !== null);
    if (H.length >= 3) {
      const m = median(H), mad = median(H.map((x) => Math.abs(x - m))) * 1.4826 || Math.abs(m) * 0.05 || 1, z = Math.abs(nv - m) / mad;
      if (z >= 4 && Math.abs(nv - m) >= mat) flags.push({ cell, kind: 'jump', old: pv, new: nv, why: 'robust z ' + z.toFixed(1) + ' against ' + H.length + ' approved returns (median ' + Math.round(m) + ')' });
    } else {
      const ch = (nv - pv) / Math.max(Math.abs(pv), 1);
      if (Math.abs(ch) > 0.5 && Math.abs(nv - pv) >= mat) flags.push({ cell, kind: 'jump', old: pv, new: nv, why: (ch > 0 ? '+' : '') + Math.round(ch * 100) + ' % against the previous value' });
    }
  }
  const order = { units: 0, sign: 1, empty: 2, jump: 3 };
  flags.sort((a, b) => order[a.kind] - order[b.kind] || Math.abs((b.new || 0) - (b.old || 0)) - Math.abs((a.new || 0) - (a.old || 0)));
  const stale = compared >= 20 && unchanged / compared >= 0.9 ? { unchanged, compared, note: Math.round(unchanged / compared * 100) + ' % of the values are the same as the base - carried forward, not updated?' } : null;
  return { flags: flags.slice(0, 500), more: Math.max(0, flags.length - 500), stale, compared, unchanged };
}

function createCollect(app, S, opts = {}) {
  const now = opts.now || Date.now, iso = () => new Date(now()).toISOString(), today = () => iso().slice(0, 10);
  const CYC = () => app.store.collection('sca_cycles');
  const root = path.join(S.dir, 'cycles'), cdir = (id) => path.join(root, id), cfile = (id, name) => path.join(cdir(id), name);
  const audit = (who, action, target, detail) => app.audit({ by: who.user, role: who.role, ip: who.ip || '', action: 'brisk.solvency.cycle.' + action, target, detail });
  const person = (who, what) => { if (!isHuman(who && who.user)) throw httpErr(403, 'only a person can ' + what + ' (not a service or AI identity)'); };
  const GR = () => (app.addons && app.addons.grcRegisters) || null;
  const get = (id) => { const c = CYC().get(param(id, 'id')); if (!c) throw httpErr(404, 'no collection cycle ' + id); return c; };
  const pack = (c, key) => { const p = c.packs.find((x) => x.key === key); if (!p) throw httpErr(404, 'no department pack ' + key + ' in ' + c.id); return p; };
  const write = (id, name, data) => {
    try { fs.mkdirSync(cdir(id), { recursive: true, mode: 0o700 }); fs.writeFileSync(cfile(id, name), data, { mode: 0o600 }); } catch (e) {
      if (app.log && app.log.error) app.log.error('solvency: a collection file could not be stored', { dir: cdir(id), code: e.code });
      throw httpErr(424, 'the server could not store the file (' + (e.code || 'error') + ' in ' + cdir(id) + ') - an administrator runs the update again');
    }
  };
  const readJson = (id, name, def) => { try { return JSON.parse(fs.readFileSync(cfile(id, name), 'utf8')); } catch (e) { if (e.code === 'ENOENT') return def; throw e; } };
  const baseBuf = (c) => fs.readFileSync(cfile(c.id, 'base.xlsx'));
  const grc = (fn, what) => { const R = GR(); if (!R) return null; try { return fn(R); } catch (e) {
    // the GRC register is a convenience here: a refusal there (an action already closed by hand) never blocks the solvency round
    if (app.log && app.log.warn) app.log.warn('solvency: GRC action not updated', { what, message: e.message }); return null; } };

  // the base: input cells (numeric constants outside the result sheets) and the formulas, per sheet
  function mapBook(buf) {
    const B = readBook(buf), inputs = {}, formulas = {}, sheets = {};
    for (const s of B.sheets) for (const [ref, c] of s.cells) {
      const k = s.name + '!' + ref;
      if (c.f !== null) { formulas[k] = shortHash(c.f); continue; }
      if (!NOT_INPUT.has(s.name) && num(c.v) !== null) { inputs[k] = c.v; sheets[s.name] = (sheets[s.name] || 0) + 1; }
    }
    let version = ''; const ver = B.sheet('Version'); if (ver) for (const c of ver.cells.values()) if (typeof c.v === 'string' && /^SCA\.\d{2,3}$/.test(c.v.trim()) && c.v.trim() > version) version = c.v.trim();
    return { B, inputs, formulas, sheets, version };
  }
  function historyByCell() { const H = {}; for (const r of S.history()) for (const k of Object.keys(r.inputs)) (H[k] = H[k] || []).push(r.inputs[k]); return H; }

  function open(input, who) {
    person(who, 'open a collection round');
    const b = body(input || {}).str('as_at', { required: true, max: 10, re: /^\d{4}-\d{2}-\d{2}$/, msg: 'as_at: YYYY-MM-DD' }).str('due', { required: true, max: 10, re: /^\d{4}-\d{2}-\d{2}$/, msg: 'due: YYYY-MM-DD' })
      .str('base_return', { max: 80, id: true }).str('filename', { max: 200 }).str('xlsx_b64', { max: 34 * 1024 * 1024 }).done();
    if (b.due < today()) throw httpErr(400, 'due: the due date is in the past');
    if (CYC().all().some((x) => x.as_at === b.as_at && x.status !== 'cancelled')) throw httpErr(409, 'a collection round for ' + b.as_at + ' already exists');
    const raw = input || {}, assign = raw.assign == null ? null : raw.assign, owners = raw.owners == null ? {} : raw.owners;
    if (assign !== null && (typeof assign !== 'object' || Array.isArray(assign))) throw httpErr(400, 'assign: an object of sheet -> department');
    if (typeof owners !== 'object' || Array.isArray(owners)) throw httpErr(400, 'owners: an object of department -> account name');
    let buf, base;
    if (b.xlsx_b64) {
      if (!/^[A-Za-z0-9+/=\r\n]+$/.test(b.xlsx_b64)) throw httpErr(400, 'xlsx_b64: not base64');
      buf = Buffer.from(b.xlsx_b64, 'base64'); fileCheck(b.filename || 'template.xlsx', buf, { allow: ['xlsx'], max: 25 * 1024 * 1024 }); base = { kind: 'upload', filename: b.filename || 'template.xlsx' };
    } else {
      const H = S.history(), last = b.base_return ? null : H[H.length - 1];
      const id = b.base_return || (last && last.id); if (!id) throw httpErr(400, 'base_return: no approved return to carry forward - upload the template (xlsx_b64)');
      const w = S.workbook(id); if (!['approved', 'submitted'].includes(w.rec.status)) throw httpErr(409, 'base_return: ' + id + ' is ' + w.rec.status + ' - carry forward an approved return');
      buf = w.buf; base = { kind: 'return', id, as_at: w.rec.as_at, filename: w.rec.filename };
    }
    let M; try { M = mapBook(buf); } catch (e) { if (e.status) throw e; throw httpErr(422, 'the template could not be read (' + String(e.message).slice(0, 160) + ')'); }
    if (!M.B.sheet('Instructions') || !M.B.sheet('Regulatory Solvency')) throw httpErr(400, 'this is not the Insurance Authority Solvency and Capital template');
    // sheet -> department: the default, then the Risk function's changes; a sheet with inputs nobody owns goes to the Risk function
    const own = {}; for (const d of Object.keys(DEPTS)) for (const sh of DEPTS[d]) own[sh] = d;
    if (assign) for (const sh of Object.keys(assign)) {
      if (!(sh in M.sheets)) throw httpErr(400, 'assign: the template has no input sheet "' + String(sh).slice(0, 60) + '"');
      const d = String(assign[sh] || '').trim(); if (!/^[A-Za-z][A-Za-z &()/-]{1,59}$/.test(d)) throw httpErr(400, 'assign: "' + String(sh).slice(0, 60) + '" needs a department name'); own[sh] = d;
    }
    const by = {}; for (const sh of Object.keys(M.sheets)) { const d = own[sh] || 'Risk Function'; (by[d] = by[d] || []).push(sh); }
    for (const d of Object.keys(owners)) if (!by[d]) throw httpErr(400, 'owners: no department "' + String(d).slice(0, 60) + '" in this round');
    const id = 'scc-' + b.as_at.replace(/-/g, '') + '-' + crypto.randomBytes(3).toString('hex'), at = iso();
    write(id, 'base.xlsx', buf); write(id, 'map.json', JSON.stringify({ inputs: M.inputs, formulas: M.formulas }));
    const packs = Object.keys(by).sort().map((d) => {
      const owner = owners[d] ? String(owners[d]).trim().toLowerCase() : '';
      if (owner && !/^[a-z0-9._@\\-]{2,120}$/.test(owner)) throw httpErr(400, 'owners: "' + d + '" needs an account name');
      return { key: slug(d), department: d, sheets: by[d].sort(), cells: by[d].reduce((n, sh) => n + M.sheets[sh], 0), owner, due: b.due, status: 'open', flags: [], stale: null, explain: {}, submitted: null, accepted: null, returned: null, action: null, history: [{ at, by: who.user, action: 'requested' }] };
    });
    const c = { id, as_at: b.as_at, due: b.due, version: M.version, base, status: 'collecting', opened_by: who.user, opened_at: at, packs, assembled: null, return_id: null };
    for (const p of packs) {
      const a = grc((R) => R.actionCreate({ title: ('Solvency & Capital ' + b.as_at + ': ' + p.department + ' - fill ' + p.sheets.join(', ')).slice(0, 200), source: 'risk', ref: 'SCA:' + id + ':' + p.key, owner: p.owner || p.department, due: b.due, priority: 'high',
        description: 'Download your pack on the Solvency & Capital page (Business Risk), fill the sheets ' + p.sheets.join(', ') + ' in SR \'000, and upload it. Every flagged value needs an explanation.' }, who), 'create');
      p.action = a ? a.id : null;
    }
    CYC().put(c); audit(who, 'open', id, { as_at: b.as_at, due: b.due, base: base.kind === 'return' ? base.id : 'upload', packs: packs.map((p) => p.department) });
    return view(id);
  }

  function packView(c, p) {
    const flags = p.flags.map((f) => Object.assign({}, f, { explanation: p.explain[f.cell] || null }));
    return Object.assign({}, p, { flags, open_flags: flags.filter((f) => !f.explanation).length, overdue: ['open', 'returned'].includes(p.status) && p.due < today() });
  }
  function view(id) {
    const c = get(id), packs = c.packs.map((p) => packView(c, p)), done = packs.filter((p) => p.status === 'accepted').length;
    return Object.assign({}, c, { packs, progress: { accepted: done, total: packs.length, submitted: packs.filter((p) => p.status === 'submitted').length, overdue: packs.filter((p) => p.overdue).length }, ready: done === packs.length && c.status === 'collecting' });
  }
  function list() { return { cycles: CYC().all().sort((a, b) => (a.as_at < b.as_at ? 1 : -1)).map((c) => { const v = view(c.id); return { id: v.id, as_at: v.as_at, due: v.due, status: v.status, progress: v.progress, version: v.version, return_id: v.return_id }; }), departments: DEPTS }; }

  function download(id, key, who) {
    const c = get(id), p = pack(c, param(key, 'key')), vals = readJson(c.id, 'pack-' + p.key + '.json', null);
    const edits = {}; if (vals) for (const k of Object.keys(vals)) { const i = k.indexOf('!'), sh = k.slice(0, i); (edits[sh] = edits[sh] || {})[k.slice(i + 1)] = vals[k]; }
    const out = patchBook(baseBuf(c), edits);
    audit(who, 'pack.download', c.id, { pack: p.key });
    return { filename: 'SCA ' + c.as_at + ' - ' + p.department + '.xlsx', sheets: p.sheets, xlsx_b64: out.toString('base64') };
  }
  function submit(id, key, input, who) {
    person(who, 'submit a department pack');
    const b = body(input || {}).str('filename', { required: true, max: 200 }).str('xlsx_b64', { required: true, max: 34 * 1024 * 1024 }).str('note', { max: 1000 }).done();
    const c = get(id), p = pack(c, param(key, 'key'));
    if (c.status !== 'collecting') throw httpErr(409, 'the round for ' + c.as_at + ' is ' + c.status);
    if (!['open', 'returned', 'submitted'].includes(p.status)) throw httpErr(409, p.department + ' is already accepted');
    if (p.owner && p.owner !== String(who.user).toLowerCase() && who.role !== 'admin') throw httpErr(403, p.department + ' is owned by ' + p.owner + ' - only they (or an administrator) submit it');
    if (!/^[A-Za-z0-9+/=\r\n]+$/.test(b.xlsx_b64)) throw httpErr(400, 'xlsx_b64: not base64');
    const buf = Buffer.from(b.xlsx_b64, 'base64'); fileCheck(b.filename, buf, { allow: ['xlsx'], max: 25 * 1024 * 1024 });
    let M; try { M = mapBook(buf); } catch (e) { if (e.status) throw e; throw httpErr(422, 'the workbook could not be read (' + String(e.message).slice(0, 160) + ')'); }
    if (M.version !== c.version) throw httpErr(400, 'this workbook is template ' + (M.version || '?') + '; the round uses ' + (c.version || '?') + ' - download the pack again');
    const map = readJson(c.id, 'map.json', { inputs: {}, formulas: {} }), mine = new Set(p.sheets), inSheets = (k) => mine.has(k.slice(0, k.indexOf('!')));
    const changed = Object.keys(map.formulas).filter((k) => inSheets(k) && map.formulas[k] !== M.formulas[k]);
    if (changed.length) throw httpErr(409, changed.length + ' formula cell(s) changed in your sheets (' + changed.slice(0, 6).join(', ') + ') - the template\'s formulas cannot change; download the pack again and type values only');
    const values = {}; for (const k of Object.keys(M.inputs)) if (inSheets(k)) values[k] = M.inputs[k];
    const cells = [...new Set(Object.keys(map.inputs).filter(inSheets).concat(Object.keys(values)))];
    const R = checkValues(cells, map.inputs, historyByCell(), { values });
    write(c.id, 'pack-' + p.key + '.json', JSON.stringify(values));
    const at = iso(), keep = p.explain || {}; p.explain = {}; for (const f of R.flags) if (keep[f.cell]) p.explain[f.cell] = keep[f.cell];
    p.flags = R.flags; p.more = R.more; p.stale = R.stale; p.status = 'submitted'; p.submitted = { by: who.user, at, filename: fileCheck(b.filename, buf, { allow: ['xlsx'], max: 25 * 1024 * 1024 }).name, values: Object.keys(values).length, note: b.note || '' };
    p.history.push({ at, by: who.user, action: 'submitted', note: Object.keys(values).length + ' values, ' + R.flags.length + ' flagged' });
    if (p.action) grc((G) => G.actionStatus(p.action, { status: 'done', note: 'pack uploaded: ' + Object.keys(values).length + ' values' }, who), 'done');
    CYC().put(c); audit(who, 'pack.submit', c.id, { pack: p.key, values: Object.keys(values).length, flags: R.flags.length, kinds: R.flags.reduce((o, f) => (o[f.kind] = (o[f.kind] || 0) + 1, o), {}) });
    return view(c.id);
  }
  function explain(id, key, input, who) {
    person(who, 'explain a flagged value');
    const b = body(input || {}).str('cell', { required: true, max: 120 }).str('note', { required: true, max: 1000 }).done();
    const c = get(id), p = pack(c, param(key, 'key'));
    if (p.status !== 'submitted') throw httpErr(409, p.department + ' is ' + p.status + ' - explanations are given on a submitted pack');
    if (!p.flags.some((f) => f.cell === b.cell)) throw httpErr(400, 'cell: ' + b.cell + ' is not flagged in ' + p.department);
    p.explain[b.cell] = { note: b.note, by: who.user, at: iso() }; CYC().put(c);
    audit(who, 'pack.explain', c.id, { pack: p.key, cell: b.cell }); return view(c.id);
  }
  function accept(id, key, input, who) {
    person(who, 'accept a department pack');
    const b = body(input || {}).str('note', { max: 1000 }).done(), c = get(id), p = pack(c, param(key, 'key'));
    if (p.status !== 'submitted') throw httpErr(409, p.department + ' is ' + p.status + ' - only a submitted pack is accepted');
    if (p.submitted && p.submitted.by === who.user) throw httpErr(403, 'four eyes: ' + who.user + ' submitted this pack - someone else in the Risk function accepts it');
    const open = p.flags.filter((f) => !p.explain[f.cell]); if (open.length) throw httpErr(409, open.length + ' flagged value(s) without an explanation: ' + open.slice(0, 5).map((f) => f.cell + ' (' + f.kind + ')').join(', '));
    p.status = 'accepted'; p.accepted = { by: who.user, at: iso(), note: b.note || '' }; p.history.push({ at: iso(), by: who.user, action: 'accepted', note: b.note || '' });
    if (p.action) grc((G) => G.actionStatus(p.action, { status: 'closed', note: 'accepted by the Risk function' }, who), 'closed');
    CYC().put(c); audit(who, 'pack.accept', c.id, { pack: p.key, flags: p.flags.length }); return view(c.id);
  }
  function sendBack(id, key, input, who) {
    person(who, 'return a department pack');
    const b = body(input || {}).str('reason', { required: true, max: 1000 }).done(), c = get(id), p = pack(c, param(key, 'key'));
    if (!['submitted', 'accepted'].includes(p.status) || c.status !== 'collecting') throw httpErr(409, p.department + ' is ' + p.status + ' - nothing to return');
    const wasAccepted = p.status === 'accepted'; p.status = 'returned'; p.accepted = null; p.returned = { by: who.user, at: iso(), reason: b.reason };
    p.history.push({ at: iso(), by: who.user, action: 'returned', note: b.reason });
    if (p.action && !wasAccepted) grc((G) => G.actionStatus(p.action, { status: 'open', note: 'returned: ' + b.reason }, who), 'reopen');
    CYC().put(c); audit(who, 'pack.return', c.id, { pack: p.key, reason: b.reason }); return view(c.id);
  }
  function assemble(id, who) {
    person(who, 'assemble the workbook');
    const c = get(id), v = view(id);
    if (!v.ready && c.status !== 'assembled') throw httpErr(409, 'not every department is accepted yet: ' + v.packs.filter((p) => p.status !== 'accepted').map((p) => p.department + ' (' + p.status + ')').join(', '));
    const edits = {};
    for (const p of c.packs) { const vals = readJson(c.id, 'pack-' + p.key + '.json', {}); for (const k of Object.keys(vals)) { const i = k.indexOf('!'), sh = k.slice(0, i); (edits[sh] = edits[sh] || {})[k.slice(i + 1)] = vals[k]; } }
    // the new as-at date, as an Excel date number in the cell the template keeps it in
    const ins = readBook(baseBuf(c), { sheets: ['Instructions'] }).sheet('Instructions');
    for (const [ref, cl] of ins.cells) if (typeof cl.v === 'string' && /^Data as at/i.test(cl.v.trim())) { const r = splitRef(ref), target = 'C' + r.row; (edits.Instructions = edits.Instructions || {})[target] = Date.parse(c.as_at + 'T00:00:00Z') / 864e5 + 25569; }
    const out = patchBook(baseBuf(c), edits); write(c.id, 'assembled.xlsx', out);
    if (c.status !== 'assembled') { c.status = 'assembled'; c.assembled = { by: who.user, at: iso(), values: Object.values(edits).reduce((n, e) => n + Object.keys(e).length, 0) }; CYC().put(c); }
    audit(who, 'assemble', c.id, { values: c.assembled.values });
    return { filename: 'Solvency_and_Capital_Template_' + c.as_at.slice(0, 4) + '_v' + (c.version || 'SCA') + ' (assembled ' + c.as_at + ').xlsx', xlsx_b64: out.toString('base64'), next: 'open it in Excel so every formula recalculates, check it, save, and upload it as the return' };
  }
  function cancel(id, input, who) {
    person(who, 'cancel a collection round');
    const b = body(input || {}).str('reason', { required: true, max: 1000 }).done(), c = get(id);
    if (!['collecting', 'assembled'].includes(c.status)) throw httpErr(409, 'the round is ' + c.status);
    c.status = 'cancelled'; c.cancelled = { by: who.user, at: iso(), reason: b.reason };
    for (const p of c.packs) if (p.action && p.status !== 'accepted') grc((G) => G.actionStatus(p.action, { status: 'cancelled', note: 'round cancelled: ' + b.reason }, who), 'cancel');
    CYC().put(c); audit(who, 'cancel', c.id, { reason: b.reason }); return view(c.id);
  }
  // a return uploaded for the same date closes the round
  function onReturn(rec, who) {
    const c = CYC().all().find((x) => x.as_at === rec.as_at && x.status === 'assembled'); if (!c) return null;
    c.status = 'returned'; c.return_id = rec.id; CYC().put(c); audit(who, 'linked', c.id, { return: rec.id }); return c.id;
  }
  // read-only summary for the AI Business Risk Officer (its output is framed as untrusted data by the intel kit)
  function aiSummary() {
    const c = CYC().all().filter((x) => x.status !== 'cancelled').sort((a, b) => (a.as_at < b.as_at ? 1 : -1))[0]; if (!c) return { round: null, note: 'no collection round is open' };
    const v = view(c.id);
    return { round: { as_at: v.as_at, due: v.due, status: v.status, progress: v.progress }, departments: v.packs.map((p) => ({ department: p.department, sheets: p.sheets, status: p.status, overdue: p.overdue, values: p.submitted ? p.submitted.values : 0,
      flags: p.flags.slice(0, 15).map((f) => ({ cell: f.cell, kind: f.kind, old: f.old, new: f.new, why: f.why, explanation: f.explanation ? f.explanation.note : null })), unexplained: p.open_flags, stale: p.stale ? p.stale.note : null })) };
  }
  return { open, list, view, download, submit, explain, accept, sendBack, assemble, cancel, onReturn, aiSummary, DEPTS };
}

function registerCollect(srv, app, C) {
  const W = (ctx) => ({ user: ctx.who.user, role: ctx.who.role, ip: ctx.who.ip });
  const ID = (ctx) => param(ctx.params.id, 'id'), KEY = (ctx) => param(ctx.params.key, 'key');
  const riskGate = (ctx) => { if (typeof app.approveGate === 'function') app.approveGate(ctx, 'risk'); else ctx.need('admin'); };
  srv.route('GET', '/brisk/solvency-cycles', (ctx) => { ctx.need('viewer'); return C.list(); });
  srv.route('GET', '/brisk/solvency-cycles/:id', (ctx) => { ctx.need('viewer'); return C.view(ID(ctx)); });
  srv.route('POST', '/brisk/solvency-cycles', (ctx) => { ctx.need('operator'); riskGate(ctx); return C.open(ctx.body, W(ctx)); }, { maxBody: 35 * 1024 * 1024 });
  srv.route('POST', '/brisk/solvency-cycles/:id/cancel', (ctx) => { ctx.need('operator'); riskGate(ctx); return C.cancel(ID(ctx), ctx.body, W(ctx)); }, { maxBody: 4096 });
  srv.route('GET', '/brisk/solvency-cycles/:id/packs/:key/download', (ctx) => { ctx.need('operator'); return C.download(ID(ctx), KEY(ctx), W(ctx)); });
  srv.route('POST', '/brisk/solvency-cycles/:id/packs/:key/submit', (ctx) => { ctx.need('operator'); return C.submit(ID(ctx), KEY(ctx), ctx.body, W(ctx)); }, { maxBody: 35 * 1024 * 1024 });
  srv.route('POST', '/brisk/solvency-cycles/:id/packs/:key/explain', (ctx) => { ctx.need('operator'); return C.explain(ID(ctx), KEY(ctx), ctx.body, W(ctx)); }, { maxBody: 4096 });
  srv.route('POST', '/brisk/solvency-cycles/:id/packs/:key/accept', (ctx) => { ctx.need('operator'); riskGate(ctx); return C.accept(ID(ctx), KEY(ctx), ctx.body, W(ctx)); }, { maxBody: 4096 });
  srv.route('POST', '/brisk/solvency-cycles/:id/packs/:key/return', (ctx) => { ctx.need('operator'); riskGate(ctx); return C.sendBack(ID(ctx), KEY(ctx), ctx.body, W(ctx)); }, { maxBody: 4096 });
  srv.route('POST', '/brisk/solvency-cycles/:id/assemble', (ctx) => { ctx.need('operator'); riskGate(ctx); return C.assemble(ID(ctx), W(ctx)); }, { maxBody: 1024 });
}

module.exports = { createCollect, registerCollect, checkValues, DEPTS };
