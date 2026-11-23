// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('./brand');
const { body, param, fileCheck } = require('./check');
const { isHuman } = require('./approve-scopes');
/*
 * Implementation gap assessment - one engagement from the team to the approved report, the same seven steps for every framework.
 * A framework plugs in through an adapter (engine/pdpl-gap.js for PDPL, engine/nca-gap.js for NCA ECC); the adapter says where the
 * framework's own review lives, what the baseline reads and which GRC reference a gap carries. The steps:
 *   1 team & scope      lead assessor, assessors, sponsor, departments and systems in scope, dates; the approver (DPO / CISO) comes
 *                       from the framework's own profile
 *   2 kick-off          the framework's standard evidence list (each item with its article / control) to every department in scope,
 *                       with a due date; the assessor records each item received (with its reference), accepts it or returns it
 *   3 baseline          a snapshot of what the platform already shows before anyone answers - an empty register reads as empty
 *   4 review            the framework's own review (the PDPL self-assessment; the NCA ECC control register), approved there by the
 *                       DPO / CISO under four eyes - this engagement never answers or approves on its behalf
 *   5 gap rating        every gap rated: likelihood x impact (1-5), root cause, recommendation, owner, target date
 *   6 remediation plan  publishing writes each gap's owner, due date, priority and recommendation onto its GRC action (created when
 *                       missing) and freezes the gap list into the engagement
 *   7 report            executive summary and signature by the lead; approval by the DPO / CISO or an administrator - a person,
 *                       never the one who signed. HTML (white, company logo) or CSV; every download audited
 * AI / ML (gapIntel, every figure explained; nothing is decided by it):
 *   suggested rating   per gap, likelihood from the framework's own chance-of-gap model when it has one (SAMA: the register's p_gap from
 *                      its run history, +1 for a regression, +1 when the result flaps) else 3; impact from the severity / weight; a partial
 *                      result -1 on both. Shown beside each gap with the reasons; a person rates (one click takes the suggestion)
 *   fix-once clusters  gaps sharing one cause (the same missing record or evidence source) ranked by the risk one fix removes
 *   forecast           the score the plan reaches by each target date, assuming each gap closes by its target (a gap's share of what is
 *                      left is its weight) - a plan without dates is said, not projected
 *   evidence analytics requests per department: accepted, returned, overdue, response rate - the slowest department named
 *   AI draft           the executive summary drafted by the AI from the engagement's own facts (ai-guard: budget admitted before and
 *                      recorded after, secrets redacted, the facts wrapped as untrusted, UNTRUSTED_RULE); stored as a draft the lead edits
 *                      and saves - the AI never signs, approves or rates
 * previous years    a previous year's gap report (this platform's CSV / Excel export, or a consultant's spreadsheet) is imported per
 *                    framework: the columns are found by their headings (gap / control / clause id, requirement, result, risk, owner,
 *                    target, root cause, recommendation, area); only the rows and the file's SHA-256 are kept, never the file. Each
 *                    engagement is compared with the latest earlier report: recurring gaps (in both), new gaps, gaps closed since -
 *                    matched on the id, else on the requirement text. In the view, the report and the exports.
 * Only the named team (lead, assessors) and administrators change an engagement; a viewer reads nothing; a service or AI identity
 * does nothing. Every step is audited. An internal gap assessment - the report says it is not the regulator's certificate.
 */
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const esc = (v) => String(v == null ? '' : v).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const csvCell = (v) => { let t = String(v == null ? '' : v); if (/^[=+\-@\t\r]/.test(t)) t = "'" + t; return /[",\r\n]/.test(t) ? '"' + t.replace(/"/g, '""') + '"' : t; };
const same = (a, b) => !!a && String(a).trim().toLowerCase() === String(b || '').trim().toLowerCase();
const DATE = /^\d{4}-\d{2}-\d{2}$/;
const USER = /^[A-Za-z0-9._@\\-]{2,80}$/;
const EV_STATUS = ['requested', 'received', 'accepted', 'returned', 'na'];
const rating = (l, i) => { const s = l * i; return { score: s, level: s >= 15 ? 'critical' : s >= 10 ? 'high' : s >= 5 ? 'medium' : 'low' }; };

function createGapEngagement(app, A, opts = {}) {
  const now = opts.now || Date.now, col = () => app.store.collection(A.collection);
  const iso = () => new Date(now()).toISOString(), today = () => iso().slice(0, 10);
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role, ip: who.ip || '', action: A.audit + action, target, detail }); };
  const GR = () => (app.addons && app.addons.grcRegisters) || (() => { try { return require('./grc-registers').createGrcRegisters(app); } catch (e) { return null; /* GRC registers not installed: the plan stays on the engagement */ } })();
  const warn = (k, msg, er) => { if (app.log && app.log.every) app.log.every(A.fw + '-gap:' + k, 600000, 'warn', msg, { err: String((er && er.message) || er || '').slice(0, 200) }); };
  const approver = async (cx) => { try { return (await A.approver(app, cx)) || null; } catch (er) { warn('approver', A.name + ' gap: the approver could not be read', er); return null; } };
  const must = (id0) => { const id = param(id0, 'id'), e = col().get(id); if (!e) throw httpErr(404, 'no ' + A.name + ' gap assessment ' + id); return e; };
  const hist = (e, who, what) => { e.history = (e.history || []).concat([{ at: iso(), by: who.user, what: String(what).slice(0, 300) }]).slice(-500); };
  const person = (who, what) => { if (!isHuman(who.user)) throw httpErr(403, 'a person ' + what + ', not a service or AI identity'); };
  const team = (e, who) => { person(who, 'works the gap assessment'); if (who.role === 'admin' || same(e.lead, who.user) || (e.assessors || []).some((a) => same(a, who.user))) return; throw httpErr(403, 'only the lead assessor, the assessors of ' + e.id + ' or an administrator can do this'); };
  const lead = (e, who) => { person(who, 'acts as lead assessor'); if (!(same(e.lead, who.user) || who.role === 'admin')) throw httpErr(403, 'only the lead assessor (' + e.lead + ') or an administrator can do this'); };
  const open = (e) => { if (e.status === 'closed') throw httpErr(409, e.id + ' is closed - its report is approved'); };

  function scopeFields(src, required) {
    const b = body(src || {}).str('name', { required, min: 3, max: 120 }).str('lead', { required, re: USER, msg: 'lead must be a user name' })
      .list('assessors', { max: 12, item: 'str', itemMax: 80, unique: true }).str('sponsor', { max: 80, re: USER, msg: 'sponsor must be a user name' }).list('departments', { required, max: 40, item: 'str', itemMax: 80, unique: true }).list('systems', { max: 60, item: 'str', itemMax: 80, unique: true })
      .str('scope_note', { max: 2000 }).str('start', { re: DATE, msg: 'start must be YYYY-MM-DD' }).str('target', { required, re: DATE, msg: 'target must be YYYY-MM-DD' }).done();
    for (const a of b.assessors || []) if (!USER.test(String(a))) throw httpErr(400, 'assessors: "' + String(a).slice(0, 40) + '" is not a user name');
    if (b.departments) { b.departments = b.departments.map((d) => String(d).trim().slice(0, 80)).filter(Boolean); if (required && !b.departments.length) throw httpErr(400, 'departments: name at least one department in scope'); }
    if (b.systems) b.systems = b.systems.map((d) => String(d).trim().slice(0, 80)).filter(Boolean);
    if (b.start && b.target && b.target < b.start) throw httpErr(400, 'target must be on or after start');
    return b;
  }
  function create(src, who) {
    person(who, 'opens a gap assessment'); const b = scopeFields(src, true);
    const live = col().all((e) => e.status !== 'closed')[0]; if (live) throw httpErr(409, 'gap assessment ' + live.id + ' (' + live.name + ') is still open - finish it first');
    const n = col().all().length + 1, id = A.prefix + '-' + new Date(now()).getUTCFullYear() + '-' + String(n).padStart(3, '0');
    const e = Object.assign({ id, framework: A.fw, status: 'setup', assessors: [], systems: [], sponsor: '', scope_note: '', start: today(), evidence: [], ratings: {}, created_by: who.user, created_at: iso() }, b);
    hist(e, who, 'opened'); col().put(e); audit(who, 'create', id, { name: e.name, lead: e.lead, departments: e.departments.length }); return view1(e);
  }
  function scope(id, src, who) {
    const e = must(id); team(e, who); if (e.status !== 'setup') throw httpErr(409, 'scope is fixed once the kick-off has gone out');
    const b = scopeFields(src, false); Object.assign(e, b); hist(e, who, 'scope updated: ' + Object.keys(b).join(', ')); col().put(e); audit(who, 'scope', e.id, { fields: Object.keys(b) }); return view1(e);
  }
  function kickoff(id, src, who) {
    const e = must(id); team(e, who); if (e.status !== 'setup') throw httpErr(409, 'the kick-off was already sent');
    const b = body(src || {}).str('due', { required: true, re: DATE, msg: 'due must be YYYY-MM-DD' }).done(); if (b.due < today()) throw httpErr(400, 'due must be today or later');
    let k = 0; e.evidence = [];
    for (const d of e.departments) for (const [key, what, ref] of A.evidence) e.evidence.push({ id: 'EV' + String(++k).padStart(3, '0'), key, department: d, what, ref, due: b.due, status: 'requested', reference: '', note: '', by: null, at: null });
    e.status = 'kickoff'; e.kickoff_at = iso(); e.kickoff_by = who.user; hist(e, who, 'kick-off: ' + e.evidence.length + ' evidence requests to ' + e.departments.length + ' department(s), due ' + b.due); col().put(e);
    audit(who, 'kickoff', e.id, { requests: e.evidence.length, departments: e.departments.length, due: b.due });
    return view1(e);
  }
  function evidence(id, rid0, src, who) {
    const e = must(id); team(e, who); open(e); if (e.status === 'setup') throw httpErr(409, 'send the kick-off first');
    const rid = param(rid0, 'rid'), r = (e.evidence || []).find((x) => x.id === rid); if (!r) throw httpErr(404, 'no evidence request ' + rid);
    const b = body(src || {}).oneOf('status', EV_STATUS.filter((s) => s !== 'requested'), { required: true }).str('reference', { max: 300 }).str('note', { max: 1000 })
      .rule((o) => ((o.status === 'received' || o.status === 'accepted') && !o.reference && !r.reference ? 'reference is required: name the document, register or link received' : null))
      .rule((o) => ((o.status === 'returned' || o.status === 'na') && !o.note ? 'note is required: say what is missing, or why it does not apply' : null)).done();
    const prev = r.status; Object.assign(r, b, { reference: b.reference || r.reference, by: who.user, at: iso() });
    hist(e, who, rid + ' ' + r.department + ' ' + r.key + ': ' + prev + ' -> ' + b.status); col().put(e); audit(who, 'evidence', e.id, { request: rid, from: prev, to: b.status }); return view1(e);
  }
  async function baseline(id, who) {
    const e = must(id); team(e, who); open(e); if (e.status === 'setup') throw httpErr(409, 'send the kick-off first');
    const b = await A.baseline(app);
    e.baseline = Object.assign({ at: iso(), by: who.user, approver: await approver() }, b);
    hist(e, who, 'baseline taken: ' + (b.empty || []).length + ' empty / not connected'); col().put(e); audit(who, 'baseline', e.id, { empty: b.empty || [] }); return view1(e);
  }
  async function linkReview(id, who) {
    const e = must(id); team(e, who); open(e); if (!e.baseline) throw httpErr(409, 'take the baseline first');
    if (e.review_id) return view1(e);
    e.review_id = await A.startReview(app, e, who); if (e.status === 'kickoff') e.status = 'fieldwork';
    hist(e, who, A.reviewName + ' ' + e.review_id + ' linked'); col().put(e); audit(who, 'review', e.id, { review: e.review_id }); return view1(e);
  }
  async function reviewOf(e, cx) {
    if (!e.review_id) return null;
    try { return await A.review(app, e, cx); } catch (er) { warn('review', A.name + ' gap: the ' + A.reviewName + ' could not be read', er); return null; }
  }
  async function gapsOf(e, rv, cx) {
    const raw = e.plan && e.plan.snapshot ? e.plan.snapshot : rv && rv.done ? await A.gaps(app, e, cx) : [];
    return raw.map((g) => { const r = (e.ratings || {})[g.id] || null; return Object.assign({}, g, { rating: r, risk: r ? rating(r.likelihood, r.impact) : null }); })
      .sort((x, y) => ((y.risk ? y.risk.score : -1) - (x.risk ? x.risk.score : -1)) || ((y.weight || 0) - (x.weight || 0)) || String(x.id).localeCompare(y.id));
  }
  async function rate(id, gid0, src, who) {
    const e = must(id); team(e, who); open(e); if (e.plan) throw httpErr(409, 'the remediation plan is published - gaps are fixed');
    const gid = String(gid0 || ''); if (!A.gid.test(gid)) throw httpErr(400, 'gid is not a ' + A.gidName);
    const cx = {}, rv = await reviewOf(e, cx); if (!rv || !rv.done) throw httpErr(409, 'the ' + A.reviewName + ' must be complete and approved by the ' + A.approverName + ' before gaps are rated');
    if (!(await A.gaps(app, e, cx)).some((g) => g.id === gid)) throw httpErr(404, gid + ' is not a gap');
    const b = body(src || {}).int('likelihood', { required: true, min: 1, max: 5 }).int('impact', { required: true, min: 1, max: 5 }).str('root_cause', { required: true, min: 5, max: 1000 })
      .str('recommendation', { required: true, min: 10, max: 1500 }).str('owner', { required: true, re: USER, msg: 'owner must be a user name' }).str('target', { required: true, re: DATE, msg: 'target must be YYYY-MM-DD' }).done();
    e.ratings = Object.assign({}, e.ratings, { [gid]: Object.assign(b, { by: who.user, at: iso() }) });
    if (e.status === 'fieldwork' || e.status === 'kickoff') e.status = 'analysis';
    hist(e, who, gid + ' rated ' + rating(b.likelihood, b.impact).level); col().put(e); audit(who, 'rate', e.id, { gap: gid, likelihood: b.likelihood, impact: b.impact, owner: b.owner, target: b.target }); return view1(e);
  }
  async function publish(id, who) {
    const e = must(id); team(e, who); open(e); if (e.plan) throw httpErr(409, 'the plan is already published');
    const cx = {}, rv = await reviewOf(e, cx); if (!rv || !rv.done) throw httpErr(409, 'the ' + A.reviewName + ' must be complete and approved first');
    const gaps = await gapsOf(e, rv, cx), unrated = gaps.filter((g) => !g.rating); if (unrated.length) throw httpErr(400, unrated.length + ' gap(s) not rated yet: ' + unrated.slice(0, 8).map((g) => g.id).join(', '));
    const G = GR(), out = { updated: [], created: [], failed: [] };
    const pri = (lv) => (lv === 'critical' || lv === 'high' ? 'high' : lv === 'medium' ? 'medium' : 'low');
    for (const g of gaps) {
      if (!G) break;
      const act = A.action(e, g), desc = A.name + ' gap assessment ' + e.id + ' - root cause: ' + g.rating.root_cause + ' Recommendation: ' + g.rating.recommendation;
      try {
        const ex = G.actionList({ source: act.source, ref: act.ref, status: 'open' }).items[0];
        if (ex) { G.actionUpdate(ex.id, { owner: g.rating.owner, due: g.rating.target, priority: pri(g.risk.level), description: desc }, who); out.updated.push(ex.id); }
        else { const c = G.actionCreate({ title: act.title, source: act.source, ref: act.ref, framework: act.framework, priority: pri(g.risk.level), owner: g.rating.owner, due: g.rating.target, description: desc }, who); out.created.push(c.id); }
      } catch (er) { out.failed.push(g.id + ': ' + String(er.message).slice(0, 120)); }
    }
    const snapshot = gaps.map((g) => { const x = Object.assign({}, g); delete x.rating; delete x.risk; return x; });
    e.plan = { at: iso(), by: who.user, gaps: gaps.length, actions: out.updated.concat(out.created), failed: out.failed, grc: !!G, snapshot, review: { score: rv.score, chapters: rv.chapters || [] } };
    e.status = 'plan'; hist(e, who, 'remediation plan published: ' + e.plan.actions.length + ' GRC action(s)'); col().put(e);
    audit(who, 'plan', e.id, { gaps: gaps.length, updated: out.updated.length, created: out.created.length, failed: out.failed.length }); return Object.assign(await view1(e), { result: out });
  }
  async function summary(id, src, who) {
    const e = must(id); lead(e, who); open(e); if (e.signed_by) throw httpErr(409, 'the report is signed - the summary is fixed');
    const b = body(src || {}).str('summary', { required: true, min: 20, max: 8000 }).done(); e.summary = b.summary; e.summary_by = who.user;
    hist(e, who, 'executive summary saved'); col().put(e); audit(who, 'summary', e.id, { length: b.summary.length }); return view1(e);
  }
  async function sign(id, who) {
    const e = must(id); lead(e, who); open(e); if (!e.plan) throw httpErr(409, 'publish the remediation plan before signing'); if (!e.summary) throw httpErr(409, 'write the executive summary first');
    if (e.signed_by) throw httpErr(409, 'already signed by ' + e.signed_by);
    e.signed_by = who.user; e.signed_at = iso(); e.status = 'report'; hist(e, who, 'report signed'); col().put(e); audit(who, 'sign', e.id, {}); return view1(e);
  }
  async function approve(id, who) {
    const e = must(id); open(e); person(who, 'approves the gap assessment report');
    if (!e.signed_by) throw httpErr(409, 'the lead assessor signs the report first');
    if (!(who.role === 'admin' || same(await approver(), who.user))) throw httpErr(403, 'approving the report needs the ' + A.approverName + ' named in the ' + A.name + ' profile or an administrator');
    if (same(e.signed_by, who.user)) throw httpErr(403, 'four eyes: ' + who.user + ' signed the report and cannot also approve it');
    e.approved_by = who.user; e.approved_at = iso(); e.status = 'closed'; hist(e, who, 'report approved - engagement closed'); col().put(e); audit(who, 'approve', e.id, {}); return view1(e);
  }
  // ---- previous years' reports: imported, compared
  const HIST = () => app.store.collection(A.collection + '_history');
  const HEAD = { id: /^(gap|id|ref(erence)?|control( id)?|clause|requirement id|question id|code|no\.?|#)$/i, text: /^(text|question|control|requirement|title|description|control title|requirement text|finding)$/i,
    result: /^(result|answer|status|compliance|assessment|rating result|compliance status)$/i, risk: /^(risk|risk rating|rating|severity|priority|risk level)$/i, owner: /^(owner|responsible|action owner)$/i,
    target: /^(target|target date|due|due date)$/i, root_cause: /^(root cause|cause)$/i, recommendation: /^(recommendation|remediation|action|corrective action)$/i, area: /^(area|domain|chapter|section|subdomain|category)$/i };
  const cellText = (c) => (c && c.v != null ? String(c.v).trim() : '');
  function rowsFromBook(buf, ext) {
    let grid = [];
    if (ext === 'csv') {
      const t = buf.toString('utf8').replace(/^\ufeff/, ''); const lines = []; let row = [], cur = '', q = false;
      for (let i = 0; i < t.length; i++) { const ch = t[i];
        if (q) { if (ch === '"' && t[i + 1] === '"') { cur += '"'; i++; } else if (ch === '"') q = false; else cur += ch; }
        else if (ch === '"') q = true; else if (ch === ',') { row.push(cur); cur = ''; } else if (ch === '\n' || ch === '\r') { if (ch === '\r' && t[i + 1] === '\n') i++; row.push(cur); lines.push(row); row = []; cur = ''; } else cur += ch; }
      if (cur || row.length) { row.push(cur); lines.push(row); } grid = lines.filter((r) => !/^#/.test(r[0] || '') && r.some((x) => String(x).trim()));
    } else {
      const B = require('./xlsx-book').readBook(buf); let best = null;
      for (const sh of B.sheets) { const R = new Map(); for (const [ref, c] of sh.cells) { const m = /^([A-Z]+)(\d+)$/.exec(ref); if (!m) continue; const r = +m[2]; if (!R.has(r)) R.set(r, {}); R.get(r)[m[1]] = cellText(c); }
        const rows = [...R.keys()].sort((x, y) => x - y).map((r) => { const o = R.get(r), cols = Object.keys(o).sort((x, y) => x.length - y.length || x.localeCompare(y)); const arr = []; for (const k of cols) arr[require('./xlsx-book').colNum(k) - 1] = o[k]; return Array.from(arr, (x) => x || ''); });
        const score = rows.slice(0, 15).reduce((m, r) => Math.max(m, r.filter((x) => Object.values(HEAD).some((re) => re.test(String(x).trim()))).length), 0);
        if (!best || score > best.score) best = { score, rows }; }
      grid = best ? best.rows : [];
    }
    // the heading row: the first row (of the first 15) that names an id or a requirement column
    let h = -1; for (let i = 0; i < Math.min(15, grid.length); i++) { const r = grid[i].map((x) => String(x).trim()); if (r.some((x) => HEAD.id.test(x)) || r.some((x) => HEAD.text.test(x))) { h = i; break; } }
    if (h < 0) throw httpErr(400, 'no heading row found - the file needs a column named like Gap / Control / Clause / Requirement (and ideally Result, Risk, Owner, Target)');
    const hdr = grid[h].map((x) => String(x).trim()), col = {}; for (const k of Object.keys(HEAD)) { const i = hdr.findIndex((x) => HEAD[k].test(x)); if (i >= 0) col[k] = i; }
    if (col.id == null && col.text == null) throw httpErr(400, 'the heading row has neither a gap / control id nor a requirement column');
    const out = []; for (const r of grid.slice(h + 1)) { const g = {}; for (const k of Object.keys(col)) g[k] = String(r[col[k]] == null ? '' : r[col[k]]).replace(/^'(?=[=+\-@])/, '').trim().slice(0, k === 'text' || k === 'recommendation' || k === 'root_cause' ? 600 : 120); if (g.id || g.text) out.push(g); if (out.length >= 5000) break; }
    return { rows: out, columns: Object.keys(col) };
  }
  function importHistory(src, who) {
    person(who, 'imports a previous gap report'); if (!(who.role === 'admin' || col().all((e) => e.lead === who.user || (e.assessors || []).some((x) => same(x, who.user))).length)) throw httpErr(403, 'an administrator or a gap-assessment lead / assessor imports previous reports');
    const b = body(src || {}).str('filename', { required: true, max: 200 }).str('data_b64', { required: true, max: 34 * 1024 * 1024 }).int('year', { required: true, min: 2010, max: 2100 }).str('label', { max: 120 }).done();
    if (!/^[A-Za-z0-9+/=\r\n]+$/.test(b.data_b64)) throw httpErr(400, 'data_b64: not base64');
    const buf = Buffer.from(b.data_b64, 'base64'), f = fileCheck(b.filename, buf, { allow: ['xlsx', 'csv'], max: 25 * 1024 * 1024 });
    const parsed = rowsFromBook(buf, f.ext); if (!parsed.rows.length) throw httpErr(400, 'no gap rows under the heading row');
    const id = 'H-' + b.year + '-' + String(HIST().all().length + 1).padStart(3, '0');
    const rec = { id, year: b.year, label: b.label || (A.name + ' gap assessment ' + b.year), filename: f.name, sha256: require('crypto').createHash('sha256').update(buf).digest('hex'), rows: parsed.rows, columns: parsed.columns, by: who.user, at: iso() };
    HIST().put(rec); audit(who, 'history.import', id, { year: b.year, rows: parsed.rows.length, columns: parsed.columns, sha256: rec.sha256.slice(0, 16) });
    return histList();
  }
  function removeHistory(hid0, who) { person(who, 'removes a previous report'); if (who.role !== 'admin') throw httpErr(403, 'an administrator removes an imported report');
    const hid = param(hid0, 'hid'), h = HIST().get(hid); if (!h) throw httpErr(404, 'no imported report ' + hid); HIST().remove(hid); audit(who, 'history.remove', hid, { year: h.year, rows: h.rows.length }); return histList(); }
  function histList() { return { reports: HIST().all().sort((a, b) => b.year - a.year || String(b.at).localeCompare(String(a.at))).map((h) => ({ id: h.id, year: h.year, label: h.label, filename: h.filename, rows: h.rows.length, columns: h.columns, by: h.by, at: h.at, sha256: h.sha256.slice(0, 16) })) }; }
  const keyOf = (x) => String(x || '').toLowerCase().replace(/[^a-z0-9.]+/g, ' ').trim();
  const textKey = (x) => String(x || '').toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim().slice(0, 80);
  const isGap = (r) => !r.result || /gap|no\b|non.?compliant|not met|partial|missing|fail|open|not in place/i.test(r.result);
  function compare(e, gaps) {
    const year = Number(String(e.start || e.created_at || iso()).slice(0, 4)), prior = HIST().all().filter((h) => h.year < year || (h.year === year && h.at < e.created_at)).sort((a, b) => b.year - a.year || String(b.at).localeCompare(String(a.at)))[0];
    if (!prior) return null;
    const prev = prior.rows.filter(isGap), byId = new Map(), byText = new Map(); prev.forEach((r, i) => { if (r.id) byId.set(keyOf(r.id), i); if (r.text) byText.set(textKey(r.text), i); });
    const hit = new Set(), recurring = [], fresh = [];
    for (const g of gaps) { let i = byId.has(keyOf(g.id)) ? byId.get(keyOf(g.id)) : byText.has(textKey(g.text)) ? byText.get(textKey(g.text)) : -1;
      if (i >= 0 && !hit.has(i)) { hit.add(i); recurring.push({ id: g.id, text: g.text, before: { result: prev[i].result || 'gap', risk: prev[i].risk || '', owner: prev[i].owner || '' } }); } else fresh.push({ id: g.id, text: g.text }); }
    const closed = prev.filter((r, i) => !hit.has(i)).map((r) => ({ id: r.id || '', text: r.text || '', result: r.result || '' }));
    return { with: { id: prior.id, year: prior.year, label: prior.label, rows: prior.rows.length }, recurring, new: fresh, closed,
      note: recurring.length + ' gap(s) were already gaps in ' + prior.year + ', ' + fresh.length + ' are new, ' + closed.length + ' of ' + prior.year + '\'s gap(s) are no longer gaps. Matched on the id, else the requirement text - check a closed gap is truly closed and not renamed.' };
  }
  // ---- AI / ML
  const SEVW = (g) => (g.weight >= 3 ? 'high' : g.weight >= 2 ? 'medium' : 'low');
  async function featuresOf(e, cx) { if (!A.features) return {}; try { return (await A.features(app, e, cx)) || {}; } catch (er) { warn('features', A.name + ' gap: the model features could not be read', er); return {}; } }
  function suggest(g, f) {
    const why = [], sev = f && f.severity ? f.severity : SEVW(g);
    let imp = sev === 'high' ? 4 : sev === 'medium' ? 3 : 2; why.push('impact ' + imp + ': ' + sev + ' severity');
    let lik = 3, pg = f && typeof f.p_gap === 'number' ? f.p_gap : null;
    if (pg != null) { lik = Math.round(1 + 4 * pg); why.push('likelihood ' + lik + ': ' + Math.round(pg * 100) + '% chance of a gap next run (' + (f.runs || 0) + ' run(s) seen)'); } else why.push('likelihood 3: no run history - the middle of the scale');
    if (f && f.regression) { lik += 1; why.push('+1 likelihood: it was met before and regressed'); }
    if (f && f.flapping) { lik += 1; why.push('+1 likelihood: the result keeps changing'); }
    if (/partial/.test(String(g.answer))) { lik -= 1; imp -= 1; why.push('-1 on both: partly in place'); }
    lik = Math.max(1, Math.min(5, lik)); imp = Math.max(1, Math.min(5, imp));
    return { likelihood: lik, impact: imp, risk: rating(lik, imp), why };
  }
  function gapIntel(e, rv, gaps, feats) {
    const t = today(), sug = {}; for (const g of gaps) sug[g.id] = suggest(g, feats[g.id]);
    const risk = (g) => (g.rating ? rating(g.rating.likelihood, g.rating.impact).score : sug[g.id].risk.score);
    // fix once, close many: one cause (the framework's own reason / evidence source) behind several gaps
    const norm = (x) => String(x || '').toLowerCase().replace(/\d[\d,.%]*/g, '#').replace(/\s+/g, ' ').trim().slice(0, 90);
    const cl = {}; for (const g of gaps) { const f = feats[g.id] || {}, k = f.cause ? norm(f.cause) : norm(g.note) || norm(g.req); if (!k) continue; (cl[k] = cl[k] || { cause: f.cause || g.note || g.req, gaps: [], risk: 0 }); cl[k].gaps.push(g.id); cl[k].risk += risk(g); }
    const clusters = Object.values(cl).filter((c) => c.gaps.length > 1).sort((a, b) => b.risk - a.risk || b.gaps.length - a.gaps.length).slice(0, 10);
    // forecast: the score the plan reaches by each target date
    let forecast = null; const base = rv && rv.score != null ? rv.score : null, dated = gaps.filter((g) => g.rating && g.rating.target);
    if (base != null && gaps.length && dated.length) {
      const W = gaps.reduce((s, g) => s + (g.weight || 1), 0), by = {}; for (const g of dated) by[g.rating.target] = (by[g.rating.target] || 0) + (g.weight || 1);
      let acc = 0; const points = Object.keys(by).sort().map((d) => { acc += by[d]; return { date: d, gaps_closed: dated.filter((g) => g.rating.target <= d).length, score: Math.round(base + (100 - base) * acc / W) }; });
      forecast = { from: base, points, undated: gaps.length - dated.length, note: dated.length < gaps.length ? (gaps.length - dated.length) + ' gap(s) have no target date yet - they are not in the forecast' : 'every gap closes by its target date' };
    }
    // evidence requests per department
    const dep = {}; for (const r of e.evidence || []) { const d = (dep[r.department] = dep[r.department] || { department: r.department, total: 0, requested: 0, accepted: 0, returned: 0, na: 0, received: 0, overdue: 0 }); d.total++; if (d[r.status] != null) d[r.status]++; if ((r.status === 'requested' || r.status === 'returned') && r.due && r.due < t) d.overdue++; }
    const depts = Object.values(dep).map((d) => Object.assign(d, { response_pct: d.total ? Math.round((d.total - d.requested) * 100 / d.total) : 0 })).sort((a, b) => b.overdue - a.overdue || a.response_pct - b.response_pct);
    const slow = depts.find((d) => d.overdue) || null;
    return { suggestions: sug, clusters, forecast, evidence: { departments: depts, slowest: slow ? slow.department + ': ' + slow.overdue + ' overdue, ' + slow.response_pct + '% answered' : null }, ai: aiStatus() };
  }
  const aicfg = () => (app.config && app.config.gap_ai) || {};
  const getKey = opts.getKey || (() => { try { return require('./secret-values').fileValue(process.env.SENTRA_ITAM_SECRETS || '/etc/sentra-itam/secrets.json', 'anthropic_api_key', app.config && app.config.discovery && app.config.discovery.vault_key_file)() || process.env.ANTHROPIC_API_KEY || ''; } catch (er) { return process.env.ANTHROPIC_API_KEY || ''; } });
  let Ctor = null, loadError = '';
  function loadSdk() { if (opts.sdk) return opts.sdk; if (Ctor) return Ctor;
    for (const p of [aicfg().sdk_path, '@anthropic-ai/sdk', '/opt/sentra-itam/vendor/node_modules/@anthropic-ai/sdk', '/opt/sentra-siem/vendor/node_modules/@anthropic-ai/sdk'].filter(Boolean)) {
      try { if (p.startsWith('/') && !require('fs').existsSync(p)) continue; const m = require(p); Ctor = require('./ai-backend').wrap(m.Anthropic || m.default || m); return Ctor; } catch (er) { loadError = er.code === 'MODULE_NOT_FOUND' ? 'Anthropic SDK not installed' : String(er.message).slice(0, 160); }
    } return null; }
  function aiStatus() {
    const model = aicfg().model || 'claude-opus-5-5';
    let allowed = false; try { allowed = !!(app.settings && require('./ai-backend').allowed(app.settings.get())); } catch (er) { allowed = false; /* settings unreadable = not allowed */ }
    if (opts.sdk) allowed = true;
    if (!allowed) return { enabled: false, reason: 'external AI is not allowed (IT Asset Management settings), or the AI engine is off (Platform Administration -> AI Engine)', model };
    if (!getKey()) return { enabled: false, reason: 'no AI key is set on this server', model };
    if (!loadSdk()) return { enabled: false, reason: loadError || 'the AI SDK is not installed', model };
    return { enabled: true, model };
  }
  async function aiDraft(id, who) {
    const e = must(id); lead(e, who); open(e); if (!e.plan) throw httpErr(409, 'publish the remediation plan first - the draft is written from it');
    const st = aiStatus(); if (!st.enabled) throw httpErr(503, st.reason);
    const G = require('./ai-guard'), v = await view1(e);
    const facts = { framework: A.name, engagement: v.name, scope: { departments: v.departments, systems: v.systems }, score: v.review && v.review.score, by_area: (v.plan.review && v.plan.review.chapters) || [],
      gaps: v.gaps.map((g) => ({ id: g.id, area: g.area, requirement: String(g.text).slice(0, 200), result: g.answer, risk: g.risk ? g.risk.level : null, root_cause: g.rating && g.rating.root_cause, recommendation: g.rating && g.rating.recommendation, owner: g.rating && g.rating.owner, target: g.rating && g.rating.target })),
      evidence: v.evidence_status, forecast: v.intel && v.intel.forecast };
    const q = G.redactSecrets('Draft the executive summary (at most 220 words) of this internal ' + A.name + ' gap assessment for senior management: where the organisation stands, the critical and high gaps and what closes them, owners and dates, and the readiness the plan reaches. Use only the facts below; do not add facts, figures or names. Plain sentences, no headings.\n\n' + G.untrusted('engagement facts', JSON.stringify(facts)));
    const budget = G.sharedBudget({ log: app.log, limits: () => ((app.config && app.config.ai) || {}).limits || {} });
    budget.admit(who.user, A.fw + '.gap-summary', q.length);
    const client = new (loadSdk())({ apiKey: getKey(), timeout: 120000, maxRetries: 2 }), usage = { input_tokens: 0, output_tokens: 0 };
    let text = '', model = st.model;
    try {
      const resp = await client.messages.create({ model, max_tokens: 2000, system: 'You draft internal compliance summaries for a Saudi insurer. You state only what the facts say.\n\n' + G.UNTRUSTED_RULE, messages: [{ role: 'user', content: q }] });
      for (const k of Object.keys(usage)) usage[k] += (resp.usage && resp.usage[k]) || 0; model = resp.model || model;
      text = resp.stop_reason === 'refusal' ? '' : (resp.content || []).filter((b) => b.type === 'text').map((b) => b.text).join('\n').trim();
    } finally { budget.record(who.user, A.fw + '.gap-summary', usage, G.injectionSignals(q)); }
    if (!text) throw httpErr(502, 'the AI returned no draft - write the summary by hand');
    e.ai_draft = { text: text.slice(0, 8000), model, requested_by: who.user, at: iso() };
    hist(e, who, 'AI drafted the executive summary (not adopted)'); col().put(e); audit(who, 'ai-draft', e.id, { chars: text.length, model });
    return view1(e);
  }
  function stepsOf(e, rv, gaps, apr) {
    const ev = e.evidence || [], evDone = ev.filter((x) => ['accepted', 'na'].includes(x.status)).length, rated = gaps.filter((g) => g.rating).length, done4 = !!(rv && rv.done) || !!e.plan;
    const s = [
      { done: true, what: e.lead + ' leads; ' + e.departments.length + ' department(s) in scope', block: null },
      { done: e.status !== 'setup', what: ev.length ? evDone + ' of ' + ev.length + ' evidence requests accepted or not applicable' : 'no requests sent', block: e.status === 'setup' ? 'send the kick-off with a due date' : null },
      { done: !!e.baseline, what: e.baseline ? (e.baseline.empty || []).length + ' empty / not connected' : 'not taken', block: e.status === 'setup' ? 'send the kick-off first' : !e.baseline ? 'take the baseline' : null },
      { done: done4, what: rv ? rv.what : 'not started', block: !e.baseline ? 'take the baseline first' : !e.review_id ? 'start the ' + A.reviewName : done4 ? null : rv ? rv.block || null : null },
      { done: done4 && rated === gaps.length, what: gaps.length ? rated + ' of ' + gaps.length + ' gaps rated' : done4 ? 'no gaps' : '—', block: !done4 ? 'the ' + A.reviewName + ' must be complete and approved' : rated < gaps.length ? 'rate every gap: likelihood, impact, root cause, recommendation, owner, target' : null },
      { done: !!e.plan, what: e.plan ? e.plan.actions.length + ' GRC action(s)' : 'not published', block: !e.plan ? (rated < gaps.length || !done4 ? 'rate every gap first' : 'publish the plan') : null },
      { done: e.status === 'closed', what: e.approved_by ? 'approved by ' + e.approved_by : e.signed_by ? 'signed by ' + e.signed_by + ', awaiting approval' : e.summary ? 'summary written' : 'not started', block: !e.plan ? 'publish the plan first' : !e.summary ? 'the lead writes the executive summary' : !e.signed_by ? 'the lead signs' : !e.approved_by ? 'the ' + (apr ? A.approverName + ' (' + apr + ')' : A.approverName) + ' or an administrator approves - not the signer' : null },
    ];
    return s.map((x, i) => Object.assign({ n: i + 1, title: A.steps[i] }, x));
  }
  async function view1(e) {
    const cx = {}, rv = await reviewOf(e, cx), gaps = await gapsOf(e, rv, cx), apr = await approver(cx), steps = stepsOf(e, rv, gaps, apr), cur = steps.find((s) => !s.done);
    const intel = gapIntel(e, rv, gaps, gaps.length ? await featuresOf(e, cx) : {});
    let yoy = null; try { yoy = compare(e, gaps); } catch (er) { warn('yoy', A.name + ' gap: the comparison with the previous report failed', er); }
    const ev = e.evidence || [], byStatus = {}; for (const s of EV_STATUS) byStatus[s] = ev.filter((x) => x.status === s).length;
    const lv = { critical: 0, high: 0, medium: 0, low: 0 }; for (const g of gaps) if (g.risk) lv[g.risk.level]++;
    const pub = Object.assign({}, e); if (pub.plan) { pub.plan = Object.assign({}, pub.plan); delete pub.plan.snapshot; }
    return Object.assign(pub, { steps, current_step: cur ? cur.n : null, approver: apr, approver_name: A.approverName, evidence_status: byStatus, review: rv, gaps, gap_levels: lv, intel, compare: yoy });
  }
  async function list() {
    const all = col().all().sort((x, y) => String(y.created_at).localeCompare(String(x.created_at)));
    const cur = all.find((e) => e.status !== 'closed') || all[0] || null;
    return { framework: A.fw, name: A.name, engagements: all.map((e) => ({ id: e.id, name: e.name, status: e.status, lead: e.lead, target: e.target, approved_by: e.approved_by || null })), current: cur ? await view1(cur) : null,
      approver: await approver(), approver_name: A.approverName, history: histList().reports, steps: A.steps, evidence_catalogue: A.evidence.map(([key, what, ref]) => ({ key, what, ref })), note: A.note };
  }
  async function report(id, q, who) {
    const fmt = (q && q.format) || 'html'; if (!['html', 'csv', 'json'].includes(fmt)) throw httpErr(400, 'format must be html, csv or json');
    const v = await view1(must(id)); audit(who, 'report', v.id, { format: fmt, status: v.status });
    const gcols = ['Gap', A.reqLabel, 'Area', 'Reference', A.textLabel, 'Result', 'Likelihood', 'Impact', 'Risk', 'Root cause', 'Recommendation', 'Owner', 'Target'];
    const grow = (g) => [g.id, g.req, g.area, g.ref, g.text, g.answer, g.rating && g.rating.likelihood, g.rating && g.rating.impact, g.risk ? g.risk.level + ' (' + g.risk.score + ')' : 'not rated', g.rating && g.rating.root_cause, g.rating && g.rating.recommendation, g.rating && g.rating.owner, g.rating && g.rating.target];
    if (fmt === 'json') return { filename: A.fw + '-gap-' + v.id + '.xlsx', title: A.reportTitle + ' - ' + v.name, engagement: { id: v.id, name: v.name, lead: v.lead, assessors: v.assessors, departments: v.departments, systems: v.systems, start: v.start, target: v.target, status: v.status, signed_by: v.signed_by || null, approved_by: v.approved_by || null, summary: v.summary || '' },
      score: v.review && v.review.score, chapters: (v.plan && v.plan.review ? v.plan.review.chapters : v.review && v.review.chapters) || [], gaps: v.gaps.map((g) => ({ id: g.id, requirement: g.req, area: g.area, reference: g.ref, text: g.text, result: g.answer, likelihood: g.rating && g.rating.likelihood, impact: g.rating && g.rating.impact, risk: g.risk ? g.risk.level : null, risk_score: g.risk ? g.risk.score : null, root_cause: g.rating && g.rating.root_cause, recommendation: g.rating && g.rating.recommendation, owner: g.rating && g.rating.owner, target: g.rating && g.rating.target })),
      evidence: (v.evidence || []).map((x) => ({ id: x.id, department: x.department, what: x.what, ref: x.ref, due: x.due, status: x.status, reference: x.reference, note: x.note })), compare: v.compare, disclaimer: A.disclaimer };
    if (fmt === 'csv') return { filename: A.fw + '-gap-' + v.id + '.csv', csv: ['# ' + A.name + ' gap assessment ' + v.id + ' ' + v.name + ' (' + v.status + ')', gcols.join(',')].concat(v.gaps.map((g) => grow(g).map(csvCell).join(','))).join('\r\n') };
    const bv = (app.store.collection('pentest_settings').get('report_brand') || {}).values || {}, org = bv.org_name || ZYB_ORG.name, logo = /^data:image\/(png|jpe?g|webp|svg\+xml);base64,/.test(bv.letterhead || '') ? bv.letterhead : '';
    const tbl = (h, rows, empty) => rows.length ? '<table><thead><tr>' + h.map((x) => '<th>' + esc(x) + '</th>').join('') + '</tr></thead><tbody>' + rows.map((r) => '<tr>' + r.map((x) => '<td>' + esc(x == null ? '' : x) + '</td>').join('') + '</tr>').join('') + '</tbody></table>' : '<p class="muted">' + esc(empty) + '</p>';
    let h = '<!doctype html><html><head><meta charset="utf-8"><title>' + esc(A.name) + ' gap assessment ' + esc(v.id) + '</title><style>@media print{*{-webkit-print-color-adjust:exact;print-color-adjust:exact}}body{font:13px/1.5 Arial,sans-serif;color:#111;background:#fff;margin:32px}h1{font-size:21px;margin:8px 0 0}h2{font-size:16px;border-bottom:2px solid #1f3a5f;padding-bottom:3px;margin-top:22px}table{border-collapse:collapse;width:100%;background:#fff}th,td{border:1px solid #bbb;padding:4px 6px;text-align:left;vertical-align:top}th{background:#eef2f7}.muted{color:#555}img.logo{max-height:46px}.sum{white-space:pre-wrap}</style></head><body>';
    h += '<div style="display:flex;justify-content:space-between;align-items:center">' + (logo ? '<img class="logo" src="' + esc(logo) + '" alt="' + esc(org) + '">' : '<b>' + esc(org) + '</b>') + '<span class="muted">Generated ' + esc(iso().slice(0, 16).replace('T', ' ')) + ' UTC by ' + esc(who.user) + '</span></div>';
    h += '<h1>' + esc(A.reportTitle) + ' - ' + esc(v.name) + '</h1><p class="muted">' + esc(v.id) + ' · lead ' + esc(v.lead) + (v.assessors.length ? ' · assessors ' + esc(v.assessors.join(', ')) : '') + ' · ' + esc(A.approverName) + ' ' + esc(v.approver || 'not named') + ' · ' + (v.approved_by ? 'approved by ' + esc(v.approved_by) + ' ' + esc(String(v.approved_at).slice(0, 10)) : v.signed_by ? 'signed by ' + esc(v.signed_by) + ', not yet approved' : 'DRAFT - not signed') + '</p>';
    h += '<h2>Executive summary</h2>' + (v.summary ? '<div class="sum">' + esc(v.summary) + '</div>' : '<p class="muted">Not written yet.</p>');
    h += '<h2>Scope</h2><p>Departments: ' + esc(v.departments.join(', ')) + (v.systems.length ? '<br>Systems: ' + esc(v.systems.join(', ')) : '') + (v.scope_note ? '<br>' + esc(v.scope_note) : '') + '<br>Period: ' + esc(v.start) + ' to ' + esc(v.target) + '</p>';
    const sc = v.plan && v.plan.review ? v.plan.review : v.review;
    if (sc && sc.score != null) h += '<h2>Compliance score</h2><p>' + esc(A.reviewName) + (v.review ? ' ' + esc(v.review.id) : '') + ': <b>' + esc(sc.score) + '%</b>' + (v.plan ? ' (at plan publication)' : '') + '</p>' + tbl(['Area', 'Score %', 'Gaps'], (sc.chapters || []).map((c) => [c.area, c.score, c.gaps]), '');
    if (v.baseline) h += '<h2>Baseline (' + esc(v.baseline.at.slice(0, 10)) + ')</h2>' + tbl(['Item', 'Value'], (v.baseline.table || []).map((r) => [r.label, r.text != null ? r.text : r.value]), '');
    h += '<h2>Evidence requests</h2><p>' + EV_STATUS.map((s) => esc(s) + ' ' + v.evidence_status[s]).join(' · ') + '</p>';
    if (v.compare) h += '<h2>Compared with ' + esc(v.compare.with.label) + ' (' + esc(v.compare.with.year) + ')</h2><p>Recurring ' + v.compare.recurring.length + ' · new ' + v.compare.new.length + ' · closed since ' + v.compare.closed.length + '</p>' + tbl(['Recurring gap', 'Requirement', 'Last time'], v.compare.recurring.map((r) => [r.id, r.text, [r.before.result, r.before.risk, r.before.owner].filter(Boolean).join(' · ')]), 'None.') + '<p class="muted">' + esc(v.compare.note) + '</p>';
    h += '<h2>Gap register</h2><p>Critical ' + v.gap_levels.critical + ' · high ' + v.gap_levels.high + ' · medium ' + v.gap_levels.medium + ' · low ' + v.gap_levels.low + '</p>' + tbl(gcols, v.gaps.map(grow), 'No gaps, or the ' + A.reviewName + ' is not complete yet.');
    h += '<p class="muted">' + esc(A.disclaimer) + ' Remediation is tracked as GRC actions' + (v.plan ? ' (' + v.plan.actions.length + ')' : '') + '.</p>';
    return { filename: A.fw + '-gap-' + v.id + '.html', html: h + '</body></html>' };
  }
  return { list, history: histList, importHistory, removeHistory, view: (id) => view1(must(id)), create, scope, kickoff, evidence, baseline, linkReview, rate, publish, summary, sign, approve, report, aiDraft, aiStatus };
}

// the same routes under each framework's base (/pdpl/gap, /nca-ecc/gap); every route declares its role, writes check the team in the engine
function registerGapRoutes(srv, app, G, base) {
  const who = (ctx) => Object.assign({ ip: ctx.ip }, ctx.who);
  srv.route('GET', base, (ctx) => { ctx.need('operator'); return G.list(); });
  srv.route('POST', base, (ctx) => { ctx.need('operator'); return G.create(ctx.body, who(ctx)); }, { maxBody: 16384 });
  srv.route('GET', base + '/history', (ctx) => { ctx.need('operator'); return G.history(); });
  srv.route('POST', base + '/history/import', (ctx) => { ctx.need('operator'); return G.importHistory(ctx.body, who(ctx)); }, { maxBody: 35 * 1024 * 1024 });
  srv.route('POST', base + '/history/:hid/remove', (ctx) => { ctx.need('admin'); return G.removeHistory(ctx.params.hid, who(ctx)); }, { maxBody: 512 });
  srv.route('GET', base + '/:id', (ctx) => { ctx.need('operator'); return G.view(ctx.params.id); });
  srv.route('GET', base + '/:id/report', (ctx) => { ctx.need('operator'); return G.report(ctx.params.id, ctx.query || {}, who(ctx)); });
  srv.route('POST', base + '/:id/scope', (ctx) => { ctx.need('operator'); return G.scope(ctx.params.id, ctx.body, who(ctx)); }, { maxBody: 16384 });
  srv.route('POST', base + '/:id/kickoff', (ctx) => { ctx.need('operator'); return G.kickoff(ctx.params.id, ctx.body, who(ctx)); }, { maxBody: 512 });
  srv.route('POST', base + '/:id/evidence/:rid', (ctx) => { ctx.need('operator'); return G.evidence(ctx.params.id, ctx.params.rid, ctx.body, who(ctx)); }, { maxBody: 4096 });
  srv.route('POST', base + '/:id/baseline', (ctx) => { ctx.need('operator'); return G.baseline(ctx.params.id, who(ctx)); }, { maxBody: 512 });
  srv.route('POST', base + '/:id/review', (ctx) => { ctx.need('operator'); return G.linkReview(ctx.params.id, who(ctx)); }, { maxBody: 512 });
  srv.route('POST', base + '/:id/gaps/:gid', (ctx) => { ctx.need('operator'); return G.rate(ctx.params.id, ctx.params.gid, ctx.body, who(ctx)); }, { maxBody: 8192 });
  srv.route('POST', base + '/:id/plan', (ctx) => { ctx.need('operator'); return G.publish(ctx.params.id, who(ctx)); }, { maxBody: 512 });
  srv.route('POST', base + '/:id/report/summary', (ctx) => { ctx.need('operator'); return G.summary(ctx.params.id, ctx.body, who(ctx)); }, { maxBody: 16384 });
  srv.route('POST', base + '/:id/report/ai-draft', (ctx) => { ctx.need('operator'); return G.aiDraft(ctx.params.id, who(ctx)); }, { maxBody: 512 });
  srv.route('POST', base + '/:id/report/sign', (ctx) => { ctx.need('operator'); return G.sign(ctx.params.id, who(ctx)); }, { maxBody: 512 });
  srv.route('POST', base + '/:id/report/approve', (ctx) => { ctx.need('operator'); return G.approve(ctx.params.id, who(ctx)); }, { maxBody: 512 });
  return G;
}
module.exports = { createGapEngagement, registerGapRoutes, rating };
