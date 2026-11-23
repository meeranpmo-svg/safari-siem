// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('./brand');
const crypto = require('crypto');
const { body, param, fileCheck } = require('./check');
const { readBook } = require('./xlsx-book');
const { isHuman } = require('./approve-scopes');
/*
 * RBC Own Funds & Solvency Assessment (Business Risk -> RBC Assessment). Finance uploads the Insurance Authority's quarterly "RBC Own Funds
 * and Solvency Assessment" workbook (1-Instructions, 2-Own Funds & Solvency, 3-Financial Projection) for a period - 2025 year end, 2026 Q1,
 * Q2 ... The platform reads EVERY schedule out of it and explains it; nothing is typed in again and nothing is invented.
 *   read         sheets are found by name; rows by their label in column A, inside the schedule they sit in, so a row added by the company
 *                does not shift the reading. Current column B, prior column C (their headers name the periods). Formula cells use the value
 *                Excel saved. Schedule 1 (MCR, RBC), 2 (solvency position and ratio), 3 (basic own funds by tier with components), 4
 *                (ancillary), 5 (total by tier), 6 (tier limits with every PASS / FAIL check, and the eligible own-funds adjustments), the
 *                financial projection (quarters, H1, year) and the board / management questions with their answers.
 *   insights     solvency ratio against 100% and the target; MCR cover; headroom (how far own funds can fall before the ratio reaches 100% and
 *                the target); the change since the prior column split exactly into the own-funds effect and the RBC effect; capital quality
 *                (goodwill + intangibles as a share of Tier 1); tier mix; every FAIL check; projection quarters with a net combined ratio above
 *                100%, the claims-ratio slope (least squares), loss-making quarters; board questions answered "No". Each insight names its
 *                figures. Across approved periods: the ratio series and its slope - withheld below 3 periods.
 *   workflow     draft (uploaded) -> approved (a different person, Risk approval scope; never the uploader, never a service / AI identity)
 *                -> reopened with a reason. Uploading the same period again replaces its draft. Only the parsed figures are kept (and the
 *                file's SHA-256), never the file. Every step audited.
 *   GET  /brisk/rbc                     operator  periods, the latest assessment with insights, the series, settings
 *   GET  /brisk/rbc/:id                 operator  one assessment: every schedule, the projection, the answers, the insights
 *   POST /brisk/rbc/import              operator  {filename, xlsx_b64, period?}                                  audited
 *   POST /brisk/rbc/:id/approve         risk      four eyes, not the uploader                                    audited
 *   POST /brisk/rbc/:id/reopen          risk      {reason}                                                       audited
 *   GET  /brisk/rbc/:id/report          operator  ?format=html|csv                                               audited
 *   POST /brisk/rbc/settings            admin     {target_ratio, quality_pct}                                    audited
 */
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const esc = (v) => String(v == null ? '' : v).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const csvCell = (v) => { let t = String(v == null ? '' : v); if (/^[=+\-@\t\r]/.test(t)) t = "'" + t; return /[",\r\n]/.test(t) ? '"' + t.replace(/"/g, '""') + '"' : t; };
const r1 = (x) => (x == null || !isFinite(x) ? null : Math.round(x * 10) / 10);
const pct = (x) => (x == null || !isFinite(x) ? null : Math.round(x * 1000) / 10);    // 2.6 -> 260
const num = (c) => (c && typeof c.v === 'number' && isFinite(c.v) ? c.v : null);
const txt = (c) => (c && c.v != null ? String(c.v).trim() : '');
const fmtN = (x) => (x == null ? '-' : Math.round(x).toLocaleString('en-US'));
function lsq(pts) { const n = pts.length; if (n < 2) return null; const mx = pts.reduce((a, p) => a + p[0], 0) / n, my = pts.reduce((a, p) => a + p[1], 0) / n;
  let sxx = 0, sxy = 0; for (const [x, y] of pts) { sxx += (x - mx) * (x - mx); sxy += (x - mx) * (y - my); } if (!sxx) return null; return { slope: sxy / sxx, intercept: my - (sxy / sxx) * mx }; }
// 'Q1 2026' -> 2026-Q1, 'YE 2025' / 'FY2025' / '2025' -> 2025, 'H1 2026' -> 2026-H1
function normPeriod(s) {
  const t = String(s == null ? '' : s).toUpperCase().replace(/\s+/g, ' ').trim(); let m;
  if ((m = /^(\d{4})-(Q[1-4]|H[12])$/.exec(t))) return m[1] + '-' + m[2];
  if ((m = /\b(Q[1-4]|H[12])\b.*?\b(20\d{2})\b/.exec(t)) || (m = /\b(20\d{2})\b.*?\b(Q[1-4]|H[12])\b/.exec(t))) { const y = /^\d/.test(m[1]) ? m[1] : m[2], q = /^\d/.test(m[1]) ? m[2] : m[1]; return y + '-' + q; }
  if ((m = /^(?:YE|FY|YEAR END)?\s*(20\d{2})$/.exec(t))) return m[1];
  return null;
}
const PERIOD = /^20\d{2}(-Q[1-4]|-H[12])?$/;
const periodNum = (p) => { const m = /^(\d{4})(?:-Q([1-4])|-H([12]))?$/.exec(p || ''); if (!m) return null; return +m[1] + (m[2] ? +m[2] / 4 : m[3] ? +m[3] / 2 : 1); };

// ---- the workbook reader ---------------------------------------------------------------------------------------------------------------
function rowsOf(sh) {   // row number -> { A: label, cells: { col: cell } }
  const R = new Map();
  for (const [ref, c] of sh.cells) { const m = /^([A-Z]+)(\d+)$/.exec(ref); if (!m) continue; const n = +m[2]; if (!R.has(n)) R.set(n, { n, cells: {} }); R.get(n).cells[m[1]] = c; }
  return [...R.values()].sort((a, b) => a.n - b.n).map((r) => Object.assign(r, { label: txt(r.cells.A) }));
}
function parseOwnFunds(sh) {
  const rows = rowsOf(sh), out = { sections: {}, checks: [], period_label: null, prior_label: null, company_type: '' };
  const hdr = rows.find((r) => /^required capital$/i.test(r.label));
  if (!hdr) throw httpErr(400, 'sheet "' + sh.name + '": the "Required capital" header row (Schedule 1) was not found - is this the IA RBC Own Funds template?');
  out.period_label = txt(hdr.cells.B) || null; out.prior_label = txt(hdr.cells.C) || null;
  const typeRow = rows.find((r) => /select from here/i.test(r.label)); if (typeRow) out.company_type = txt(typeRow.cells.B);
  let sec = null, secTitle = '', seen6 = 0, lastTier = null;
  for (const r of rows) {
    const m = /^schedule\s*(\d)\b\s*[-:]?\s*(.*)$/i.exec(r.label);
    if (m) { let k = 's' + m[1]; if (m[1] === '6') { seen6++; if (seen6 > 1 || /eligible own funds$/i.test(m[2].trim())) k = 's6e'; } sec = k; secTitle = m[2].trim(); out.sections[k] = out.sections[k] || { title: secTitle, rows: [] }; lastTier = null; continue; }
    // every PASS / FAIL cell in the sheet, with the row's label (or the section's) for context
    for (const [col, c] of Object.entries(r.cells)) { const v = txt(c).toUpperCase(); if (v === 'PASS' || v === 'FAIL') out.checks.push({ ref: col + r.n, result: v, label: (r.label || '').trim() || (out.sections[sec] || {}).title || '', section: sec, column: col === 'B' ? 'current' : col === 'C' ? 'prior' : col }); }
    if (!sec) continue;
    const cur = num(r.cells.B), prior = num(r.cells.C);
    if (!r.label && cur == null && prior == null) continue;
    const label = r.label || '(unlabelled component)', tier = /^tier\s*([123])\b/i.exec(label);
    const row = { label: label.trim(), current: cur, prior, row: r.n };
    if (tier) { row.tier = +tier[1]; lastTier = row; } else if (lastTier && /^s[34]$/.test(sec)) { row.component_of = 'Tier ' + lastTier.tier; }
    out.sections[sec].rows.push(row);
  }
  return out;
}
function pick(sec, re, o = {}) { const rs = (sec && sec.rows) || []; const r = rs.find((x) => re.test(x.label) && (!o.headline || x.tier)); return r || null; }
function parseProjection(sh) {
  const rows = rowsOf(sh), hdr = rows.find((r) => /^item$/i.test(r.label)); if (!hdr) return null;
  const cols = Object.entries(hdr.cells).filter(([k, c]) => k !== 'A' && k !== 'B' && txt(c)).map(([k, c]) => ({ col: k, label: txt(c) })).sort((a, b) => (a.col.length - b.col.length) || a.col.localeCompare(b.col));
  const lines = [];
  for (const r of rows) { if (r.n <= hdr.n || !r.label) continue; const vals = {}; let any = false; for (const c of cols) { const v = num(r.cells[c.col]); vals[c.label] = v; if (v != null) any = true; } if (any) lines.push({ label: r.label, values: vals, row: r.n }); }
  const line = (re) => lines.find((l) => re.test(l.label)) || null;
  return { columns: cols.map((c) => c.label), lines, revenue: line(/^insurance revenue/i), net_income: line(/^net income.*after/i), claims: line(/^claims\s*%/i), combined: line(/combined ratio/i), gwp: line(/^gwp\b/i) };
}
function parseInstructions(sh) {
  const rows = rowsOf(sh), co = rows.find((r) => /^company\b/i.test(r.label) && txt(r.cells.B));
  const qa = rows.filter((r) => txt(r.cells.F) && r.n > 10).map((r) => ({ question: r.label || ['B', 'C', 'D', 'E'].map((k) => txt(r.cells[k])).find(Boolean) || '', answer: txt(r.cells.F), note: txt(r.cells.G), attachment: txt(r.cells.H), row: r.n })).filter((q) => q.question);
  return { company: co ? txt(co.cells.B) : '', questions: qa };
}
function parseWorkbook(buf) {
  let B; try { B = readBook(buf); } catch (e) { throw httpErr(400, 'the workbook could not be read: ' + String(e.message || e).slice(0, 120)); }
  const find = (re) => B.sheets.find((s) => re.test(s.name)) || null;
  const of = find(/own\s*funds/i); if (!of) throw httpErr(400, 'no "Own Funds & Solvency" sheet - upload the IA RBC Own Funds and Solvency Assessment workbook (sheets: ' + B.sheets.map((s) => s.name).slice(0, 8).join(', ') + ')');
  const pr = find(/projection/i), ins = find(/instruction/i);
  return { own_funds: parseOwnFunds(of), projection: pr ? parseProjection(pr) : null, instructions: ins ? parseInstructions(ins) : { company: '', questions: [] }, sheets: B.sheets.map((s) => s.name) };
}

// ---- the figures and the insights ------------------------------------------------------------------------------------------------------
function figures(P) {
  const S = P.own_funds.sections, g = (k, re, o) => pick(S[k], re, o);
  const both = (r) => ({ current: r ? r.current : null, prior: r ? r.prior : null });
  const f = {
    mcr: both(g('s1', /^mcr\b/i)), rbc: both(g('s1', /^rbc\b/i) || g('s2', /^rbc\b/i)),
    total_assets: both(g('s2', /^total assets/i)), total_liabilities: both(g('s2', /^total liabilities/i)), regulatory_adjustments: both(g('s2', /^regulatory adjustments/i)),
    own_funds: both(g('s2', /^own funds\b/i)), eligible_own_funds: both(g('s2', /^eligible own funds/i)), solvency_ratio: both(g('s2', /^solvency ratio/i)),
    tiers: [1, 2, 3].map((t) => ({ tier: t, basic: both(g('s3', new RegExp('^tier\\s*' + t + '\\b', 'i'), { headline: true })), ancillary: both(g('s4', new RegExp('^tier\\s*' + t + '\\b', 'i'), { headline: true })), total: both(g('s5', new RegExp('^tier\\s*' + t + '\\b', 'i'), { headline: true })) })),
    total_own_funds: both(g('s5', /^total own funds/i)),
    adjustments: ['Net Contractual Service Margin', 'Net Risk Adjustment', "Company's Own Shares", 'Goodwill', 'Foreseeable dividends', 'Intangible Assets', 'Deferred Tax'].map((n) => { const r = g('s6e', new RegExp('^' + n.replace(/[.*+?^${}()|[\]\\']/g, '.') , 'i')); return Object.assign({ item: n }, both(r)); }),
    total_adjustments: both(g('s6e', /^total adjustments/i)), eligible_before: both(g('s6e', /before adjustments/i)), eligible_after: both(g('s6e', /after adjustments/i)),
    components: ((S.s3 && S.s3.rows) || []).filter((r) => r.component_of).map((r) => ({ tier: r.component_of, label: r.label, current: r.current, prior: r.prior })),
  };
  // the ratio as the template computes it (eligible / RBC) when its own cell is missing
  for (const k of ['current', 'prior']) if (f.solvency_ratio[k] == null && f.eligible_own_funds[k] != null && f.rbc[k]) f.solvency_ratio[k] = f.eligible_own_funds[k] / f.rbc[k];
  return f;
}
function insightsOf(P, f, cfg) {
  const I = [], add = (key, level, text, o) => I.push(Object.assign({ key, level, text }, o || {}));
  const OF = f.eligible_own_funds.current, R = f.rbc.current, M = f.mcr.current, SR = f.solvency_ratio.current, tgt = cfg.target_ratio;
  if (SR == null) add('ratio', 'bad', 'The solvency ratio could not be read (Schedule 2) - check the eligible own funds and RBC rows are filled.');
  else add('ratio', SR < 1 ? 'bad' : SR < tgt ? 'watch' : 'ok', 'Solvency ratio ' + pct(SR) + '% - ' + (SR < 1 ? 'BELOW the 100% regulatory minimum' : SR < tgt ? 'above 100% but below the ' + pct(tgt) + '% target' : 'above the ' + pct(tgt) + '% target') + ' (eligible own funds ' + fmtN(OF) + ' / RBC ' + fmtN(R) + ').', { value: pct(SR) });
  if (OF != null && M) add('mcr', OF / M < 1 ? 'bad' : 'ok', 'MCR cover ' + pct(OF / M) + '% (eligible own funds ' + fmtN(OF) + ' / MCR ' + fmtN(M) + ').', { value: pct(OF / M) });
  if (OF != null && R) {
    const h100 = OF - R, hT = OF - tgt * R;
    add('headroom', h100 < 0 ? 'bad' : hT < 0 ? 'watch' : 'ok', 'Headroom ' + fmtN(h100) + ' above 100% RBC: own funds can fall ' + (h100 > 0 ? r1(h100 / OF * 100) + '%' : '0%') + ' before the ratio reaches 100%' + (hT > 0 ? ', and ' + r1(hT / OF * 100) + '% (' + fmtN(hT) + ') before it reaches the ' + pct(tgt) + '% target.' : '; it is already below the ' + pct(tgt) + '% target by ' + fmtN(-hT) + '.'), { headroom_100: h100, headroom_target: hT });
  }
  const OF0 = f.eligible_own_funds.prior, R0 = f.rbc.prior;
  if (OF != null && R && OF0 != null && R0) {
    const d = OF / R - OF0 / R0, ofE = (OF - OF0) / R0, rbcE = OF / R - OF / R0;
    add('change', d < -0.1 ? 'watch' : 'info', 'Since ' + (P.own_funds.prior_label || 'the prior period') + ' the ratio moved ' + (d >= 0 ? '+' : '') + r1(d * 100) + ' pts (' + pct(OF0 / R0) + '% -> ' + pct(OF / R) + '%): own funds ' + (OF >= OF0 ? '+' : '') + fmtN(OF - OF0) + ' contributed ' + (ofE >= 0 ? '+' : '') + r1(ofE * 100) + ' pts, RBC ' + (R >= R0 ? '+' : '') + fmtN(R - R0) + ' contributed ' + (rbcE >= 0 ? '+' : '') + r1(rbcE * 100) + ' pts.', { delta_pts: r1(d * 100), own_funds_effect_pts: r1(ofE * 100), rbc_effect_pts: r1(rbcE * 100) });
  }
  const t1 = (f.tiers[0].basic.current != null ? f.tiers[0].basic.current : f.tiers[0].total.current), gw = (f.adjustments.find((a) => a.item === 'Goodwill') || {}).current, ia = (f.adjustments.find((a) => a.item === 'Intangible Assets') || {}).current;
  if (t1 && (gw != null || ia != null)) { const q = ((gw || 0) + (ia || 0)) / t1 * 100;
    add('quality', q > cfg.quality_pct ? 'watch' : 'ok', 'Capital quality: goodwill ' + fmtN(gw) + ' + intangibles ' + fmtN(ia) + ' are ' + r1(q) + '% of Tier 1 (' + fmtN(t1) + ')' + (q > cfg.quality_pct ? ' - above ' + cfg.quality_pct + '%: a large part of Tier 1 is not loss-absorbing and is deducted from eligible own funds.' : '.'), { value: r1(q) }); }
  const tot = f.tiers.reduce((a, t) => a + (t.total.current || 0), 0);
  if (tot > 0) add('tiers', 'info', 'Tier mix: ' + f.tiers.map((t) => 'Tier ' + t.tier + ' ' + r1((t.total.current || 0) / tot * 100) + '%').join(', ') + '.');
  const fails = P.own_funds.checks.filter((c) => c.result === 'FAIL');
  if (P.own_funds.checks.length) add('checks', fails.length ? 'bad' : 'ok', fails.length ? fails.length + ' template check(s) FAIL: ' + fails.map((c) => (c.label || c.ref) + ' (' + c.ref + ', ' + c.column + ')').join('; ') + '.' : 'All ' + P.own_funds.checks.length + ' template checks PASS (tier limits and MCR / RBC cover).', { fails: fails.length });
  const pj = P.projection;
  if (pj && pj.combined) {
    const qs = pj.columns.filter((c) => /^Q[1-4]$/i.test(c)), over = qs.filter((q) => pj.combined.values[q] != null && pj.combined.values[q] > 1);
    add('combined', over.length ? 'watch' : 'ok', over.length ? 'Projection: net combined ratio above 100% in ' + over.map((q) => q + ' (' + pct(pj.combined.values[q]) + '%)').join(', ') + ' - underwriting loss expected in ' + (over.length > 1 ? 'those quarters' : 'that quarter') + '.' : 'Projection: net combined ratio at or below 100% in every quarter.', { quarters_over: over });
    if (pj.claims) { const pts = qs.map((q, i) => [i, pj.claims.values[q]]).filter((p) => p[1] != null), fit = lsq(pts);
      if (fit && pts.length >= 3) add('claims', fit.slope > 0.01 ? 'watch' : 'info', 'Projected claims ratio ' + (fit.slope > 0 ? 'rises' : 'falls') + ' ' + r1(Math.abs(fit.slope) * 100) + ' pts a quarter (least squares over ' + pts.length + ' quarters: ' + pts.map((p) => pct(p[1]) + '%').join(', ') + ').', { slope_pts: r1(fit.slope * 100) }); }
    if (pj.net_income) { const loss = qs.filter((q) => pj.net_income.values[q] != null && pj.net_income.values[q] < 0); if (loss.length) add('loss', 'watch', 'Projected net loss after zakat & tax in ' + loss.join(', ') + '.'); }
  } else add('projection', 'info', 'No financial projection sheet was found in the workbook - the projection insights are not available.');
  const no = (P.instructions.questions || []).filter((q) => /^(no|لا)$/i.test(q.answer));
  if (no.length) add('board', 'watch', no.length + ' board / management question(s) answered "No": ' + no.map((q) => q.question.slice(0, 80)).join('; ') + '.');
  return I;
}

function createRbcAssessment(app, opts = {}) {
  const store = app.store, now = opts.now || Date.now;
  const C = () => store.collection('rbc_assessments'), S = () => store.collection('rbc_settings');
  const iso = () => new Date(now()).toISOString();
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role, ip: who.ip || '', action: 'rbc.' + action, target, detail }); };
  const cfg = () => Object.assign({ target_ratio: 1.5, quality_pct: 20 }, S().get('settings') || {});
  const human = (who, what) => { if (!isHuman(who.user)) throw httpErr(403, 'a person ' + what + ', not a service or AI identity'); };

  function build(rec) { const f = figures(rec.parsed); return { f, insights: insightsOf(rec.parsed, f, cfg()) }; }
  function summary(r) { const { f, insights } = build(r);
    return { id: r.id, period: r.period, prior_label: r.parsed.own_funds.prior_label, company: r.parsed.instructions.company, status: r.status, uploaded_by: r.by, uploaded_at: r.created_at, approved_by: r.approved_by || null, filename: r.filename,
      solvency_ratio: pct(f.solvency_ratio.current), mcr_cover: f.mcr.current && f.eligible_own_funds.current != null ? pct(f.eligible_own_funds.current / f.mcr.current) : null, own_funds: f.eligible_own_funds.current, rbc: f.rbc.current,
      alerts: insights.filter((i) => i.level === 'bad').length, watch: insights.filter((i) => i.level === 'watch').length }; }
  function series() {
    const pts = C().all((r) => r.status === 'approved').map((r) => ({ period: r.period, p: periodNum(r.period), ratio: pct(figures(r.parsed).solvency_ratio.current) })).filter((x) => x.p != null && x.ratio != null).sort((a, b) => a.p - b.p);
    if (pts.length < 3) return { measured: false, points: pts, why: 'needs 3 approved periods (' + pts.length + ' so far)' };
    const fit = lsq(pts.map((x) => [x.p, x.ratio])); return { measured: true, points: pts, slope_pts_per_quarter: fit ? r1(fit.slope / 4) : null, warning: fit && fit.slope < 0 && pts[pts.length - 1].ratio + fit.slope / 4 * 2 < pct(cfg().target_ratio) ? 'ratio trending below the ' + pct(cfg().target_ratio) + '% target within two quarters' : null };
  }
  function view() {
    const all = C().all().map(summary).sort((a, b) => (periodNum(b.period) || 0) - (periodNum(a.period) || 0));
    const latest = all.find((x) => x.status === 'approved') || all[0] || null;
    return { generated_at: iso(), periods: all, latest: latest ? detail(latest.id) : null, series: series(), settings: cfg(),
      note: all.length ? 'Read from the uploaded IA RBC Own Funds and Solvency Assessment workbooks. Figures are as the company entered them in the template (amounts as in the template, usually SAR thousands); a different person in the Risk function approves each period.' : 'No RBC assessment uploaded yet. Upload the IA "RBC Own Funds and Solvency Assessment" workbook for a period (e.g. 2025 year end, 2026 Q1) to see every schedule and its insights.' };
  }
  function detail(id0) { const id = param(id0, 'id'), r = C().get(id); if (!r) throw httpErr(404, 'assessment not found'); const { f, insights } = build(r);
    return Object.assign(summary(r), { figures: f, insights, checks: r.parsed.own_funds.checks, sections: r.parsed.own_funds.sections, projection: r.parsed.projection, questions: r.parsed.instructions.questions, company_type: r.parsed.own_funds.company_type,
      period_label: r.parsed.own_funds.period_label, sheets: r.parsed.sheets, sha256: r.sha256, reopen_reason: r.reopen_reason || null, approved_at: r.approved_at || null }); }

  function importBook(src, who) {
    human(who, 'uploads an RBC assessment');
    const b = body(src || {}).str('filename', { required: true, max: 200 }).str('xlsx_b64', { required: true, max: 34 * 1024 * 1024 }).str('period', { max: 10, re: PERIOD, msg: 'period must look like 2026-Q1 or 2025' }).done();
    if (!/^[A-Za-z0-9+/=\r\n]+$/.test(b.xlsx_b64)) throw httpErr(400, 'xlsx_b64: not base64');
    const buf = Buffer.from(b.xlsx_b64, 'base64'), fc = fileCheck(b.filename, buf, { allow: ['xlsx'], max: 25 * 1024 * 1024 });
    const parsed = parseWorkbook(buf), period = b.period || normPeriod(parsed.own_funds.period_label);
    if (!period) throw httpErr(400, 'period: the workbook header "' + (parsed.own_funds.period_label || '') + '" does not name a period - give period (e.g. 2026-Q1)');
    const f = figures(parsed); if (f.rbc.current == null && f.eligible_own_funds.current == null) throw httpErr(400, 'the RBC and own-funds rows are empty for ' + period + ' - is the template filled?');
    const old = C().all((r) => r.period === period)[0];
    if (old && old.status === 'approved') throw httpErr(409, 'the ' + period + ' assessment is approved - reopen it before uploading a new version');
    const rec = { id: old ? old.id : 'RBC-' + crypto.randomBytes(4).toString('hex'), period, filename: fc.name, sha256: crypto.createHash('sha256').update(buf).digest('hex'), parsed, status: 'draft', approved_by: null, by: who.user, created_at: iso(), replaced: old ? (old.replaced || 0) + 1 : 0 };
    C().put(rec); audit(who, old ? 'replace' : 'import', rec.id, { period, filename: fc.name, sha256: rec.sha256.slice(0, 16) });
    return detail(rec.id);
  }
  function approve(id0, who) {
    human(who, 'approves an RBC assessment'); const id = param(id0, 'id'), r = C().get(id); if (!r) throw httpErr(404, 'assessment not found');
    if (r.status === 'approved') throw httpErr(409, 'already approved'); if (r.by === who.user) throw httpErr(403, 'four eyes: the person who uploaded it cannot approve it');
    C().put(Object.assign({}, r, { status: 'approved', approved_by: who.user, approved_at: iso() })); audit(who, 'approve', id, { period: r.period }); return detail(id);
  }
  function reopen(id0, src, who) {
    human(who, 'reopens an RBC assessment'); const id = param(id0, 'id'), r = C().get(id); if (!r) throw httpErr(404, 'assessment not found'); if (r.status !== 'approved') throw httpErr(409, 'not approved');
    const b = body(src || {}).str('reason', { required: true, min: 5, max: 500 }).done();
    C().put(Object.assign({}, r, { status: 'draft', approved_by: null, reopened_by: who.user, reopened_at: iso(), reopen_reason: b.reason })); audit(who, 'reopen', id, { reason: b.reason }); return detail(id);
  }
  function setSettings(src, who) {
    const b = body(src || {}).num('target_ratio', { min: 1, max: 5, def: 1.5 }).num('quality_pct', { min: 0, max: 100, def: 20 }).done();
    S().put(Object.assign({ id: 'settings' }, b, { by: who.user, at: iso() })); audit(who, 'settings', 'settings', b); return cfg();
  }
  function report(id0, q, who) {
    const fmt = (q && q.format) || 'html'; if (!['html', 'csv'].includes(fmt)) throw httpErr(400, 'format must be html or csv');
    const d = detail(id0), f = d.figures; audit(who, 'report', d.id, { format: fmt, period: d.period });
    const lines = [['Schedule 1', 'MCR', f.mcr], ['Schedule 1', 'RBC', f.rbc], ['Schedule 2', 'Total Assets', f.total_assets], ['Schedule 2', 'Total Liabilities', f.total_liabilities], ['Schedule 2', 'Regulatory Adjustments', f.regulatory_adjustments],
      ['Schedule 2', 'Own Funds', f.own_funds], ['Schedule 2', 'Eligible Own Funds', f.eligible_own_funds]].concat(f.tiers.map((t) => ['Schedule 5', 'Tier ' + t.tier, t.total]), f.adjustments.map((a) => ['Schedule 6', a.item, a]), [['Schedule 6', 'Total Adjustments', f.total_adjustments]]);
    if (fmt === 'csv') return { filename: 'rbc-assessment-' + d.period + '.csv', csv: ['# RBC Own Funds & Solvency Assessment ' + d.period + ' (' + d.status + ')', 'Schedule,Item,' + csvCell(d.period_label || 'Current') + ',' + csvCell(d.prior_label || 'Prior')]
      .concat(lines.map(([s, n, v]) => [s, n, v.current, v.prior].map(csvCell).join(',')), ['Schedule 2,Solvency Ratio %,' + pct(f.solvency_ratio.current) + ',' + pct(f.solvency_ratio.prior), '', 'Insight,Level'], d.insights.map((i) => [i.text, i.level].map(csvCell).join(','))).join('\r\n') };
    const bv = (store.collection('pentest_settings').get('report_brand') || {}).values || {}, brandName = bv.org_name || ZYB_ORG.name, logo = /^data:image\/(png|jpe?g|webp|svg\+xml);base64,/.test(bv.letterhead || '') ? bv.letterhead : '';
    const col = { ok: '#1e7d3a', watch: '#a15c07', bad: '#b42318', info: '#1f5fa8' };
    const tbl = (head, rows) => '<table><thead><tr>' + head.map((x) => '<th>' + esc(x) + '</th>').join('') + '</tr></thead><tbody>' + rows.map((r) => '<tr>' + r.map((x) => '<td>' + esc(x) + '</td>').join('') + '</tr>').join('') + '</tbody></table>';
    let h = '<!doctype html><html><head><meta charset="utf-8"><title>RBC assessment ' + esc(d.period) + '</title><style>@media print{*{-webkit-print-color-adjust:exact;print-color-adjust:exact}}body{font:13px/1.5 Arial,sans-serif;color:#111;background:#fff;margin:32px}h1{font-size:21px;margin:8px 0 0}h2{font-size:16px;border-bottom:2px solid #1f3a5f;padding-bottom:3px;margin-top:22px}table{border-collapse:collapse;width:100%;background:#fff}th,td{border:1px solid #bbb;padding:4px 6px;text-align:left}th{background:#eef2f7}td:nth-child(n+3){text-align:right}.muted{color:#555}img.logo{max-height:46px}li{margin:3px 0}</style></head><body>';
    h += '<div style="display:flex;justify-content:space-between;align-items:center">' + (logo ? '<img class="logo" src="' + esc(logo) + '" alt="' + esc(brandName) + '">' : '<b>' + esc(brandName) + '</b>') + '<span class="muted">Generated ' + esc(iso().slice(0, 16).replace('T', ' ')) + ' UTC by ' + esc(who.user) + '</span></div>';
    h += '<h1>RBC Own Funds &amp; Solvency Assessment - ' + esc(d.period) + '</h1><p class="muted">' + esc(d.company || '') + ' · ' + esc(d.status) + (d.approved_by ? ' by ' + esc(d.approved_by) : ' (not yet approved)') + ' · from ' + esc(d.filename) + ' (SHA-256 ' + esc(d.sha256.slice(0, 16)) + '…)</p>';
    h += '<h2>Key figures</h2><p>Solvency ratio <b>' + esc(d.solvency_ratio) + '%</b> · MCR cover <b>' + esc(d.mcr_cover) + '%</b> · eligible own funds ' + esc(fmtN(d.own_funds)) + ' · RBC ' + esc(fmtN(d.rbc)) + '</p>';
    h += '<h2>Insights</h2><ul>' + d.insights.map((i) => '<li><b style="color:' + col[i.level] + '">' + esc(i.level.toUpperCase()) + '</b> ' + esc(i.text) + '</li>').join('') + '</ul>';
    h += '<h2>Schedules</h2>' + tbl(['Schedule', 'Item', d.period_label || 'Current', d.prior_label || 'Prior'], lines.map(([s, n, v]) => [s, n, fmtN(v.current), fmtN(v.prior)]).concat([['Schedule 2', 'Solvency Ratio', pct(f.solvency_ratio.current) + '%', f.solvency_ratio.prior != null ? pct(f.solvency_ratio.prior) + '%' : '-']]));
    if (d.checks.length) h += '<h2>Template checks</h2>' + tbl(['Check', 'Cell', 'Column', 'Result'], d.checks.map((c) => [c.label, c.ref, c.column, c.result]));
    if (d.projection) h += '<h2>Financial projection</h2>' + tbl(['Item'].concat(d.projection.columns), [d.projection.revenue, d.projection.net_income, d.projection.claims, d.projection.combined, d.projection.gwp].filter(Boolean).map((l) => [l.label].concat(d.projection.columns.map((c) => { const v = l.values[c]; return v == null ? '-' : Math.abs(v) < 5 ? pct(v) + '%' : fmtN(v); }))));
    if (d.questions.length) h += '<h2>Board and management questions</h2>' + tbl(['Question', 'Answer', 'Note'], d.questions.map((q) => [q.question, q.answer, q.note]));
    return { filename: 'rbc-assessment-' + d.period + '.html', html: h + '</body></html>' };
  }
  return { view, detail, importBook, approve, reopen, setSettings, report, parseWorkbook, normPeriod };
}

function registerRbcAssessment(srv, app, R0) {
  const R = R0 && R0.view ? R0 : createRbcAssessment(app, R0 || {});
  app.addons = app.addons || {}; app.addons.rbcAssessment = R;
  const who = (ctx) => Object.assign({ ip: ctx.ip }, ctx.who);
  srv.route('GET', '/brisk/rbc', (ctx) => { ctx.need('operator'); return R.view(); });
  srv.route('POST', '/brisk/rbc/import', (ctx) => { ctx.need('operator'); return R.importBook(ctx.body, who(ctx)); }, { maxBody: 35 * 1024 * 1024 });
  srv.route('POST', '/brisk/rbc/settings', (ctx) => { ctx.need('admin'); return R.setSettings(ctx.body, who(ctx)); }, { maxBody: 1024 });
  srv.route('GET', '/brisk/rbc/:id', (ctx) => { ctx.need('operator'); return R.detail(ctx.params.id); });
  srv.route('GET', '/brisk/rbc/:id/report', (ctx) => { ctx.need('operator'); return R.report(ctx.params.id, ctx.query || {}, who(ctx)); });
  srv.route('POST', '/brisk/rbc/:id/approve', (ctx) => { (app.approveGate ? app.approveGate(ctx, 'risk') : ctx.need('admin')); return R.approve(ctx.params.id, who(ctx)); }, { maxBody: 512 });
  srv.route('POST', '/brisk/rbc/:id/reopen', (ctx) => { (app.approveGate ? app.approveGate(ctx, 'risk') : ctx.need('admin')); return R.reopen(ctx.params.id, ctx.body, who(ctx)); }, { maxBody: 1024 });
  return R;
}
module.exports = { createRbcAssessment, registerRbcAssessment, normPeriod };
