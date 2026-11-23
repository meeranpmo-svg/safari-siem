// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('./brand');
const { body, param, fileCheck } = require('./check');
const { pdfText } = require('./pdf-text');
const { pricingFromPdf } = require('./pricing-pdf');
const { guardOf } = require('./errors');
const { isHuman } = require('./approve-scopes');
/*
 * Pricing Adequacy (Business Risk -> Pricing Adequacy). Is the premium enough for the risk, per line of business - Motor and Medical.
 * Actuarial RECORDS the pricing review for a period and line (from the actuarial report and the pricing model); the platform does the
 * adequacy maths, trends it, cross-checks it against the solvency return's own loss ratios, and extracts the report. Nothing is
 * invented: an empty line says what to enter. A review is approved by a different person in the Risk function (four eyes).
 *   record       per period (YYYY or YYYY-Qn) and line / sub-line: earned premium (net, SAR '000), the ULTIMATE loss ratio %, the
 *                expense and commission ratios %, the target loss ratio %, the rate change implemented %, and exposure growth %.
 *   adequacy     combined ratio = ULR + expense + commission. A line is ADEQUATE when the combined ratio is at or below 100% and the
 *                ULR is at or below target; WATCH between 100 and 105 or a small target miss; INADEQUATE above 105% or a material
 *                target miss. The required rate change to reach the target loss ratio is ULR / target - 1 (less any rate already taken).
 *                Every verdict is itemised (the three ratio parts, the target gap, the rate already taken).
 *   benchmark    when engine/solvency.js holds an approved return, the line's net loss ratio there is read as a cross-check: a recorded
 *                ULR well below the regulatory loss ratio is flagged as optimistic (the page says it is a prompt to check, not proof).
 *   trend (ML)   one snapshot a day; least-squares slope of the combined ratio and ULR per line over the approved reviews, and a Holt
 *                early-warning when the combined ratio is forecast above 100% within 3 periods. Withheld below 3 periods.
 *   workflow     draft -> approved (a different person, Risk approval scope; never the recorder, never a service / AI identity) ->
 *                reopened with a reason. Every step audited. Edits only before approval.
 *   report       per line: the combined-ratio build-up, rate adequacy, the benchmark and the trend - HTML (print / PDF) or CSV, audited.
 *   GET  /pricing-adequacy                 operator  lines, reviews, KPIs, trend, benchmark, settings
 *   GET  /pricing-adequacy/:id             operator  one review with its breakdown
 *   POST /pricing-adequacy                 operator  record / update a review (draft)                               audited
 *   POST /pricing-adequacy/:id/approve     risk      four eyes, not the recorder                                   audited
 *   POST /pricing-adequacy/:id/reopen      risk      {reason}                                                      audited
 *   GET  /pricing-adequacy/report          operator  ?line=&format=html|csv                                        audited
 *   POST /pricing-adequacy/settings        admin     {watch, inadequate, target_combined}                          audited
 *   POST /pricing-adequacy/extract         operator  {filename, data_b64}: an actuarial report PDF read for its figures (engine/pdf-text.js +
 *                                                    engine/pricing-pdf.js) - PROPOSALS per period / line / field with the page and table
 *                                                    they came from; nothing is recorded. The actuary confirms or corrects every value in the
 *                                                    review form, which records the draft with its source (file, fingerprint, pages); a
 *                                                    different person approves it as before. The file itself is not kept.            audited
 */
const DAY = 86400000;
const LINES = { motor: { name: 'Motor', subs: ['Compulsory (TPL)', 'Comprehensive', 'Compulsory + Others'] }, medical: { name: 'Medical', subs: ['Individual', 'SME / Group', 'Corporate'] } };
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const esc = (v) => String(v == null ? '' : v).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const csvCell = (v) => { let t = String(v == null ? '' : v); if (/^[=+\-@\t\r]/.test(t)) t = "'" + t; return /[",\r\n]/.test(t) ? '"' + t.replace(/"/g, '""') + '"' : t; };
const r1 = (x) => Math.round(x * 10) / 10;
const PERIOD = /^\d{4}(-Q[1-4]|-H[1-2]|-\d{2})?$/;
function lsq(pts) { const n = pts.length; if (n < 2) return null; const mx = pts.reduce((a, p) => a + p[0], 0) / n, my = pts.reduce((a, p) => a + p[1], 0) / n;
  let sxx = 0, sxy = 0; for (const [x, y] of pts) { sxx += (x - mx) * (x - mx); sxy += (x - mx) * (y - my); } if (!sxx) return null; const b = sxy / sxx; return { slope: b, intercept: my - b * mx }; }

function createPricingAdequacy(app, opts = {}) {
  const store = app.store, now = opts.now || Date.now;
  const XT = () => store.collection('pricing_extracts'), C = () => store.collection('pricing_reviews'), H = () => store.collection('pricing_hist'), S = () => store.collection('pricing_settings');
  const A = () => app.addons || {};
  const iso = (t) => new Date(t == null ? now() : t).toISOString();
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role, ip: who.ip || '', action: 'pricing.' + action, target, detail }); };
  const cfg = () => Object.assign({ watch: 100, inadequate: 105, target_combined: 100 }, S().get('settings') || {});
  const human = (who, what) => { if (!isHuman(who.user)) throw httpErr(403, 'a person ' + what + ', not a service or AI identity'); };
  const riskGate = (ctx) => { if (typeof app.approveGate === 'function') app.approveGate(ctx, 'risk'); else ctx.need('admin'); };
  const periodNum = (p) => { const m = /^(\d{4})(?:-Q([1-4])|-H([1-2])|-(\d{2}))?$/.exec(p); if (!m) return null; const y = +m[1]; return y + (m[2] ? (+m[2] - 1) / 4 : m[3] ? (+m[3] - 1) / 2 : m[4] ? (+m[4] - 1) / 12 : 0); };

  function derive(r) {
    const comb = r1(r.ulr + r.expense_ratio + r.commission_ratio), c = cfg();
    const targetMiss = r1(r.ulr - r.target_loss_ratio), reqRate = r.target_loss_ratio > 0 ? r1((r.ulr / r.target_loss_ratio - 1) * 100 - (r.rate_change || 0)) : null;
    const why = [{ part: 'Ultimate loss ratio', value: r.ulr }, { part: 'Expense ratio', value: r.expense_ratio }, { part: 'Commission ratio', value: r.commission_ratio }, { part: 'Combined ratio', value: comb }];
    let status, msg;
    if (comb > c.inadequate || targetMiss > 3) { status = 'inadequate'; msg = comb > c.inadequate ? 'combined ratio ' + comb + '% above ' + c.inadequate + '%' : 'ULR ' + r.ulr + '% is ' + targetMiss + 'pts above target ' + r.target_loss_ratio + '%'; }
    else if (comb > c.watch || targetMiss > 0) { status = 'watch'; msg = comb > c.watch ? 'combined ratio ' + comb + '% above 100%' : 'ULR just above target'; }
    else { status = 'adequate'; msg = 'combined ' + comb + '% at or below 100% and ULR at or below target'; }
    return { combined_ratio: comb, target_combined: r1(r.target_loss_ratio + r.expense_ratio + r.commission_ratio), target_miss: targetMiss, required_rate_change: reqRate, status, status_why: msg, build_up: why };
  }
  // the solvency return's net loss ratio for the line, as a cross-check (optional)
  function benchmark(line) {
    try { const SV = A().solvency; if (!SV || !SV.inputsForLob && !SV.lobLossRatios) return null;
      const f = SV.lobLossRatios ? SV.lobLossRatios() : null; if (!f) return null; const key = line === 'motor' ? /motor/i : /medical|health/i;
      const hit = (f || []).filter((x) => key.test(x.lob || x.name || '')); if (!hit.length) return null;
      const lr = hit.reduce((a, x) => a + (x.net_loss_ratio || x.loss_ratio || 0), 0) / hit.length;
      return { net_loss_ratio: r1(lr), lob: hit.map((x) => x.lob || x.name).join(', '), source: 'latest approved Solvency & Capital return' };
    } catch (e) { return null; /* solvency optional or its shape differs: no benchmark */ }
  }
  function viewRow(r) { const d = derive(r); return Object.assign({ id: r.id, period: r.period, line: r.line, line_name: (LINES[r.line] || {}).name || r.line, sub_line: r.sub_line || '', nep: r.nep, ulr: r.ulr, expense_ratio: r.expense_ratio, commission_ratio: r.commission_ratio, target_loss_ratio: r.target_loss_ratio, rate_change: r.rate_change, exposure_growth: r.exposure_growth, status_rec: r.status, recorded_by: r.by, approved_by: r.approved_by || null, updated_at: r.updated_at }, d); }

  function record(src, who) {
    human(who, 'records a pricing review');
    const b = body(src || {}).str('id', { max: 60, re: /^PR-[a-z0-9]+$/i }).str('period', { required: true, re: PERIOD, msg: 'period must be a year or quarter (e.g. 2026 or 2026-Q1)' }).oneOf('line', Object.keys(LINES), { required: true })
      .str('sub_line', { max: 60 }).num('nep', { required: true, min: 0, max: 1e12 }).num('ulr', { required: true, min: 0, max: 400 }).num('expense_ratio', { required: true, min: 0, max: 200 }).num('commission_ratio', { min: 0, max: 100, def: 0 })
      .num('target_loss_ratio', { required: true, min: 1, max: 200 }).num('rate_change', { min: -100, max: 200, def: 0 }).num('exposure_growth', { min: -100, max: 1000, def: 0 }).str('note', { max: 2000 })
      .str('source_extract', { max: 40, re: /^PX-[a-z0-9]+$/i, msg: 'source_extract: the id of a report read on this page (PX-...)' }).str('source_note', { max: 500 }).done();
    let source = null;
    if (b.source_extract) { const x = XT().get(b.source_extract); if (!x) throw httpErr(400, 'source_extract: no report read with id ' + b.source_extract);
      source = { extract: x.id, filename: x.filename, sha256: x.sha256.slice(0, 16), read_by: x.by, read_at: x.at, note: b.source_note || '' }; }
    delete b.source_extract; delete b.source_note;
    if (b.sub_line && LINES[b.line] && !LINES[b.line].subs.includes(b.sub_line)) throw httpErr(400, 'sub_line must be one of: ' + LINES[b.line].subs.join(', '));
    let rec;
    if (b.id) { rec = C().get(b.id); if (!rec) throw httpErr(404, 'review ' + b.id + ' not found'); if (rec.approved_by) throw httpErr(409, 'an approved review is not edited - reopen it first'); rec = Object.assign({}, rec, b, { status: 'draft', updated_by: who.user, updated_at: iso() }); }
    else { const dup = C().all((x) => x.period === b.period && x.line === b.line && (x.sub_line || '') === (b.sub_line || ''))[0]; if (dup) throw httpErr(409, 'a review already exists for ' + b.line + ' ' + (b.sub_line || '(whole line)') + ' ' + b.period + ': ' + dup.id);
      rec = Object.assign({ id: 'PR-' + Math.random().toString(36).slice(2, 9), status: 'draft', approved_by: null, by: who.user, created_at: iso(), updated_at: iso() }, b); }
    if (source) rec.source = source;
    C().put(rec); audit(who, 'record', rec.id, { line: rec.line, period: rec.period, sub_line: rec.sub_line || '', source: source ? source.extract : null }); return detail(rec.id);
  }
  function approve(id0, who) {
    human(who, 'approves a pricing review'); const id = param(id0, 'id'), r = C().get(id); if (!r) throw httpErr(404, 'review not found');
    if (r.approved_by) throw httpErr(409, 'already approved'); if (r.by === who.user) throw httpErr(403, 'four eyes: the person who recorded it cannot approve it');
    C().put(Object.assign({}, r, { status: 'approved', approved_by: who.user, approved_at: iso() })); audit(who, 'approve', id, { line: r.line, period: r.period }); return detail(id);
  }
  function reopen(id0, src, who) {
    human(who, 'reopens a pricing review'); const id = param(id0, 'id'), r = C().get(id); if (!r) throw httpErr(404, 'review not found'); if (!r.approved_by) throw httpErr(409, 'not approved');
    const b = body(src || {}).str('reason', { required: true, min: 5, max: 500 }).done();
    C().put(Object.assign({}, r, { status: 'draft', approved_by: null, reopened_by: who.user, reopened_at: iso(), reopen_reason: b.reason })); audit(who, 'reopen', id, { reason: b.reason }); return detail(id);
  }
  function trendFor(line, rows) {
    const appr = rows.filter((r) => r.line === line && r.status_rec === 'approved' && !r.sub_line).map((r) => ({ p: periodNum(r.period), comb: r.combined_ratio, ulr: r.ulr, period: r.period })).filter((x) => x.p != null).sort((a, b) => a.p - b.p);
    if (appr.length < 3) return { measured: false, why: 'needs 3 approved whole-line reviews (' + appr.length + ' so far)' };
    const fc = lsq(appr.map((x, i) => [i, x.comb])), ulrfit = lsq(appr.map((x, i) => [i, x.ulr]));
    const next = fc ? r1(fc.intercept + fc.slope * (appr.length + 1)) : null;
    return { measured: true, points: appr.map((x) => ({ period: x.period, combined: x.comb, ulr: x.ulr })), combined_slope_per_period: fc ? r1(fc.slope) : null, ulr_slope_per_period: ulrfit ? r1(ulrfit.slope) : null,
      forecast_next: next, warning: next != null && next > 100 && fc.slope > 0 ? 'combined ratio trending to ' + next + '% - above 100% within the next period' : null };
  }
  function view() {
    const rows = C().all().map(viewRow).sort((a, b) => String(b.period).localeCompare(String(a.period)) || a.line.localeCompare(b.line) || String(a.sub_line).localeCompare(String(b.sub_line)));
    const whole = rows.filter((r) => !r.sub_line), lines = Object.keys(LINES).map((k) => {
      const latest = whole.filter((r) => r.line === k).sort((a, b) => (periodNum(b.period) || 0) - (periodNum(a.period) || 0))[0] || null;
      return { key: k, name: LINES[k].name, subs: LINES[k].subs, latest: latest || null, benchmark: benchmark(k), trend: trendFor(k, rows) };
    });
    const appr = rows.filter((r) => r.status_rec === 'approved');
    const kpis = { reviews: rows.length, approved: appr.length, draft: rows.length - appr.length, inadequate: appr.filter((r) => r.status === 'inadequate').length, watch: appr.filter((r) => r.status === 'watch').length,
      worst_combined: appr.length ? Math.max.apply(null, appr.map((r) => r.combined_ratio)) : null };
    return { generated_at: iso(), lines, reviews: rows, kpis, settings: cfg(), note: 'Premium adequacy per line: combined ratio = ULR + expense + commission. Figures are recorded by Actuarial from the pricing model and the actuarial report; a different person in the Risk function approves each. The solvency cross-check is a prompt to review, not proof.' };
  }
  function detail(id0) { const id = param(id0, 'id'), r = C().get(id); if (!r) throw httpErr(404, 'review not found'); const v = viewRow(r);
    return Object.assign(v, { source: r.source || null, note_text: r.note || '', benchmark: benchmark(r.line), reopen_reason: r.reopen_reason || null, history: { recorded_by: r.by, recorded_at: r.created_at, approved_by: r.approved_by, approved_at: r.approved_at || null } }); }

  function report(q, who) {
    const fmt = (q && q.format) || 'html', line = q && q.line; if (!['html', 'csv'].includes(fmt)) throw httpErr(400, 'format must be html or csv');
    const v = view(), rows = v.reviews.filter((r) => (!line || r.line === line) && r.status_rec === 'approved');
    audit(who, 'report', line || 'all', { format: fmt, rows: rows.length });
    const cols = ['Period', 'Line', 'Sub-line', 'Net earned premium', 'ULR %', 'Expense %', 'Commission %', 'Combined %', 'Target LR %', 'Target miss pts', 'Rate taken %', 'Required rate %', 'Status'];
    const row = (r) => [r.period, r.line_name, r.sub_line, r.nep, r.ulr, r.expense_ratio, r.commission_ratio, r.combined_ratio, r.target_loss_ratio, r.target_miss, r.rate_change, r.required_rate_change, r.status];
    if (fmt === 'csv') return { filename: 'pricing-adequacy-' + (line || 'all') + '-' + v.generated_at.slice(0, 10) + '.csv', csv: ['# Pricing adequacy ' + v.generated_at, cols.join(',')].concat(rows.map((r) => row(r).map(csvCell).join(','))).join('\r\n') };
    // the shared report brand (set in the pentest report settings): the company logo (letterhead) and name on every report
    const bv = (store.collection('pentest_settings').get('report_brand') || {}).values || {};
    const brand = { name: bv.org_name || ZYB_ORG.name, logo_url: bv.letterhead || '' };
    const tbl = (c, rs) => '<table><thead><tr>' + c.map((x) => '<th>' + esc(x) + '</th>').join('') + '</tr></thead><tbody>' + (rs.length ? rs.map((r) => '<tr>' + r.map((x) => '<td>' + esc(x) + '</td>').join('') + '</tr>').join('') : '<tr><td colspan="' + c.length + '">None approved</td></tr>') + '</tbody></table>';
    // white background, black-on-white, print-safe (the old reports printed gray)
    let h = '<!doctype html><html><head><meta charset="utf-8"><title>Pricing adequacy</title><style>@media print{*{-webkit-print-color-adjust:exact;print-color-adjust:exact}}body{font:13px/1.5 Arial,sans-serif;color:#111;background:#fff;margin:32px}h1{font-size:21px;margin:0}h2{font-size:16px;border-bottom:2px solid #1f3a5f;padding-bottom:3px;margin-top:22px}table{border-collapse:collapse;width:100%;background:#fff}th,td{border:1px solid #bbb;padding:4px 6px;text-align:left}th{background:#eef2f7;color:#111}.muted{color:#555}img.logo{max-height:46px}</style></head><body>';
    h += '<div style="display:flex;justify-content:space-between;align-items:center">' + (brand.logo_url ? '<img class="logo" src="' + esc(brand.logo_url) + '" alt="' + esc(brand.name || '') + '">' : '<b>' + esc(brand.name || ZYB_ORG.name) + '</b>') + '<span class="muted">Generated ' + esc(v.generated_at.slice(0, 16).replace('T', ' ')) + ' UTC by ' + esc(who.user) + '</span></div>';
    h += '<h1>Pricing adequacy' + (line ? ' - ' + esc((LINES[line] || {}).name || line) : '') + '</h1>';
    for (const L of v.lines) { if (line && L.key !== line) continue; const lr = v.reviews.filter((r) => r.line === L.key && r.status_rec === 'approved');
      h += '<h2>' + esc(L.name) + '</h2>' + (L.latest ? '<p>Latest (' + esc(L.latest.period) + '): combined ratio <b>' + esc(L.latest.combined_ratio) + '%</b> - ' + esc(L.latest.status) + '. ' + esc(L.latest.status_why) + (L.benchmark ? ' Solvency cross-check: net loss ratio ' + esc(L.benchmark.net_loss_ratio) + '% (' + esc(L.benchmark.lob) + ').' : '') + (L.trend.warning ? ' <b>' + esc(L.trend.warning) + '</b>' : '') + '</p>' : '<p class="muted">No approved review yet.</p>');
      h += tbl(cols, lr.map(row)); }
    return { filename: 'pricing-adequacy-' + (line || 'all') + '-' + v.generated_at.slice(0, 10) + '.html', html: h + '</body></html>' };
  }
  function setSettings(src, who) { const b = body(src || {}).num('watch', { min: 90, max: 110, def: 100 }).num('inadequate', { min: 100, max: 130, def: 105 }).num('target_combined', { min: 80, max: 120, def: 100 }).done();
    if (b.inadequate <= b.watch) throw httpErr(400, 'inadequate threshold must be above the watch threshold'); S().put(Object.assign({ id: 'settings' }, b, { by: who.user, at: iso() })); audit(who, 'settings', 'settings', b); return cfg(); }
  function snapshot() { const v = view(), h = H(), id = iso().slice(0, 10); if (h.get(id)) return null;
    h.put({ id, at: iso(), lines: v.lines.map((L) => ({ line: L.key, combined: L.latest ? L.latest.combined_ratio : null, status: L.latest ? L.latest.status : null })) });
    for (const x of h.all((y) => Date.parse(y.at) < now() - 800 * DAY)) if (h.remove) h.remove(x.id); return id; }
  let timer = null; const runSnap = guardOf(app, 'pricing.snapshot', async () => { snapshot(); });
  function start() { if (opts.noTimer || timer) return; const loop = () => { Promise.resolve(runSnap()).finally(() => { timer = setTimeout(loop, 12 * 3600000); if (timer.unref) timer.unref(); }); }; timer = setTimeout(loop, 120000); if (timer.unref) timer.unref(); }
  // an actuarial report PDF read for its figures: proposals only, kept with the file's fingerprint so a review can name its source
  function extract(src, who) {
    human(who, 'reads a report for pricing figures');
    const b = body(src || {}).str('filename', { required: true, max: 200 }).str('data_b64', { required: true, max: 34 * 1024 * 1024 }).done();
    if (!/^[A-Za-z0-9+/=\r\n]+$/.test(b.data_b64)) throw httpErr(400, 'data_b64: not base64');
    const buf = Buffer.from(b.data_b64, 'base64'), f = fileCheck(b.filename, buf, { allow: ['pdf'], max: 25 * 1024 * 1024 });
    let doc; try { doc = pdfText(buf); } catch (e) { if (e.status) throw e; if (app.log && app.log.every) app.log.every('pricing:pdf', 600000, 'warn', 'pricing: a PDF could not be read', { file: f.name, err: String(e.message).slice(0, 200) }); throw httpErr(400, 'the PDF could not be read (' + String(e.message).slice(0, 120) + ') - export it again from Word / Excel, or enter the figures by hand'); }
    const r = pricingFromPdf(doc), id = 'PX-' + Math.random().toString(36).slice(2, 10), sha = require('crypto').createHash('sha256').update(buf).digest('hex');
    const rec = { id, filename: f.name, size: f.size, sha256: sha, pages: doc.pages.length, proposals: r.proposals, groups: r.groups, lob_map: r.lob_map, by: who.user, at: iso() };
    XT().put(rec); audit(who, 'extract', id, { filename: f.name, sha256: sha.slice(0, 16), pages: doc.pages.length, proposals: r.proposals });
    return Object.assign({ id, filename: f.name, sha256: sha.slice(0, 16), pages: doc.pages.length, warnings: doc.warnings }, r);
  }
  return { extract, view, detail, record, approve, reopen, report, setSettings, snapshot, start, derive, LINES };
}

function registerPricingAdequacy(srv, app, P0) {
  const P = P0 && P0.view ? P0 : createPricingAdequacy(app, P0 || {});
  app.addons = app.addons || {}; app.addons.pricingAdequacy = P; P.start();
  const who = (ctx) => Object.assign({ ip: ctx.ip }, ctx.who);
  srv.route('GET', '/pricing-adequacy', (ctx) => { ctx.need('operator'); return P.view(); });
  srv.route('GET', '/pricing-adequacy/report', (ctx) => { ctx.need('operator'); return P.report(ctx.query || {}, who(ctx)); });
  srv.route('GET', '/pricing-adequacy/:id', (ctx) => { ctx.need('operator'); return P.detail(ctx.params.id); });
  srv.route('POST', '/pricing-adequacy', (ctx) => { ctx.need('operator'); return P.record(ctx.body, who(ctx)); }, { maxBody: 8192 });
  srv.route('POST', '/pricing-adequacy/:id/approve', (ctx) => { (app.approveGate ? app.approveGate(ctx, 'risk') : ctx.need('admin')); return P.approve(ctx.params.id, who(ctx)); }, { maxBody: 512 });
  srv.route('POST', '/pricing-adequacy/:id/reopen', (ctx) => { (app.approveGate ? app.approveGate(ctx, 'risk') : ctx.need('admin')); return P.reopen(ctx.params.id, ctx.body, who(ctx)); }, { maxBody: 1024 });
  srv.route('POST', '/pricing-adequacy/extract', (ctx) => { ctx.need('operator'); return P.extract(ctx.body, who(ctx)); }, { maxBody: 35 * 1024 * 1024 });
  srv.route('POST', '/pricing-adequacy/settings', (ctx) => { ctx.need('admin'); return P.setSettings(ctx.body, who(ctx)); }, { maxBody: 1024 });
  return P;
}
module.exports = { createPricingAdequacy, registerPricingAdequacy, LINES };
