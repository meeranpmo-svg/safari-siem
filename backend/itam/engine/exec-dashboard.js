// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const { body } = require('./check');
const { guardOf } = require('./errors');
/*
 * Executive Dashboard ({P} = /api/itam; the portal's "Executive Dashboard"). It replaced a portal view whose "Top priorities" were a
 * hard-coded list. Everything here is read from modules of this platform at the moment it is asked for - nothing new is collected:
 *   - Reporting Center, executive report: compliance, resilience, security, SOC, assets and platform KPIs, with their ML insights
 *     (trend, 30-day forecast, unusual today, what changed) - report-center.js
 *   - AI CISO: the itemised security posture score by domain and the decisions waiting for a person - ciso.js
 *   - Risk Studio: the open risk register, high-band and over-appetite risks - risk-studio.js
 * Executive health index (explainable): five pillars, each 0-100 or NOT MEASURED (never assumed), weighted
 *   cyber posture 30 · compliance 25 · resilience 20 · IT operations 15 · risk 10; withheld below 3 measured pillars.
 * ML on its own daily history (exec_hist, one row per Riyadh day): least-squares trend (points per week, >= 7 days), 30-day forecast
 *   clamped 0-100, "unusual today" (robust z on median / MAD of the last 14 days), each pillar's change against 7 days ago; and a ranked
 *   "needs the executive" list across decisions, risks, worsening KPIs and measurement gaps, each with its reason and where to go.
 * AI: the executive brief is the Reporting Center's read-only analyst (ai-guard: budget, redaction, untrusted tool output, role
 *   re-checked per call) asked about the executive report - this module adds no second model path. Operator and above.
 *   GET  /exec-dashboard           viewer    the dashboard (records today's index once a day)
 *   POST /exec-dashboard/snapshot  admin     record today's index now                         audited
 *   POST /exec-dashboard/brief     operator  {question?} AI executive brief                    audited
 */
const RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 };
const RIYADH = 3 * 3600000, DAY = 86400000, MIN_PILLARS = 3, KEEP = 400;
const PILLARS = [
  { id: 'cyber', name: 'Cyber security posture', weight: 30, page: 'ciso-dashboard.html' },
  { id: 'compliance', name: 'Regulatory compliance', weight: 25, page: 'report-center.html' },
  { id: 'resilience', name: 'Resilience (DR & backup)', weight: 20, page: 'dr-studio.html' },
  { id: 'operations', name: 'IT operations', weight: 15, page: 'servers-dashboard.html' },
  { id: 'risk', name: 'Enterprise IT risk', weight: 10, page: 'risk-studio.html' },
];
const SEVW = { critical: 4, high: 3, medium: 2, low: 1 };
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const clip = (v, n) => String(v == null ? '' : v).replace(/[\u0000-\u001f]/g, ' ').trim().slice(0, n);
const num = (v) => (typeof v === 'number' && Number.isFinite(v) ? v : null);
const mean = (a) => (a.length ? a.reduce((s, x) => s + x, 0) / a.length : null);
const median = (a) => { const s = a.slice().sort((x, y) => x - y), n = s.length; return n ? (n % 2 ? s[(n - 1) / 2] : (s[n / 2 - 1] + s[n / 2]) / 2) : null; };
const riyadhDay = (t) => new Date(t + RIYADH).toISOString().slice(0, 10);

/* ---- pure: pillars + index from the three sources (tested directly) */
function pillars({ report, ciso, riskSum }) {
  const sec = (id) => ((report && report.sections) || []).find((s) => s.id === id) || null;
  const kv = (s, key) => { const k = s && s.state === 'ok' ? s.kpis.find((x) => x.key === key) : null; return k ? num(k.value) : null; };
  const out = [];
  const P = (id, score, items, why) => { const d = PILLARS.find((x) => x.id === id); out.push(Object.assign({}, d, { score: score == null ? null : Math.max(0, Math.min(100, Math.round(score))), measured: score != null, items, why: why || null })); };
  // cyber: the CISO's own weighted posture (itemised by domain there)
  const po = ciso && ciso.posture;
  if (po && po.overall != null) P('cyber', po.overall, (po.domains || []).filter((d) => d.measured).map((d) => ({ label: d.name, value: d.score, unit: '/100' })));
  else P('cyber', null, [], po ? po.withheld_why || 'posture withheld' : 'AI CISO not installed');
  // compliance: mean of the framework scores that are measured
  const cs = sec('compliance');
  const fw = cs && cs.state === 'ok' ? cs.kpis.filter((k) => /^compliance\./.test(k.key) && k.unit === '%' && num(k.value) != null) : [];
  P('compliance', fw.length ? mean(fw.map((k) => k.value)) : null, fw.map((k) => ({ label: k.label, value: k.value, unit: '%' })), fw.length ? null : cs ? cs.note || 'no framework measured' : 'Reporting Center not installed');
  // resilience: DR readiness and backup coverage
  const rs = sec('resilience'), dr = kv(rs, 'dr.readiness'), bk = kv(rs, 'backup.coverage'), ri = [];
  if (dr != null) ri.push({ label: 'DR readiness', value: dr, unit: '%' }); if (bk != null) ri.push({ label: 'Backup coverage', value: bk, unit: '%' });
  P('resilience', ri.length ? mean(ri.map((x) => x.value)) : null, ri, ri.length ? null : rs ? rs.note || 'not measured' : 'not measured');
  // IT operations: pages working, register health, CMDB quality
  const pl = sec('platform'), as = sec('assets'), oi = [];
  const pw = kv(pl, 'platform.pages_working'), pd = kv(pl, 'platform.pages_down');
  if (pw != null && pd != null && pw + pd > 0) oi.push({ label: 'Platform pages working', value: Math.round(100 * pw / (pw + pd)), unit: '%' });
  const ah = kv(as, 'assets.health'); if (ah != null) oi.push({ label: 'Asset register health', value: ah, unit: '%' });
  const cq = kv(as, 'cmdb.quality'); if (cq != null) oi.push({ label: 'CMDB quality', value: cq, unit: '%' });
  P('operations', oi.length ? mean(oi.map((x) => x.value)) : null, oi, oi.length ? null : 'Update Health / Asset Studio not reporting');
  // risk: 100 minus capped points for high-band and over-appetite open risks
  if (riskSum && num(riskSum.open) != null) {
    const hi = riskSum.high || 0, oa = riskSum.over_appetite || 0, pts = Math.min(60, 12 * hi) + Math.min(40, 8 * oa);
    P('risk', 100 - pts, [{ label: 'Open risks', value: riskSum.open, unit: '' }, { label: 'High band', value: hi, unit: '' }, { label: 'Over appetite', value: oa, unit: '' }]);
  } else P('risk', null, [], 'Risk Studio not installed');
  const m = out.filter((p) => p.measured), w = m.reduce((s, p) => s + p.weight, 0);
  const index = m.length >= MIN_PILLARS ? Math.round(m.reduce((s, p) => s + p.score * p.weight, 0) / w) : null;
  return { pillars: out, index, grade: index == null ? null : index >= 85 ? 'strong' : index >= 70 ? 'adequate' : index >= 50 ? 'weak' : 'critical', measured: m.length,
    withheld_why: index == null ? 'only ' + m.length + ' of ' + out.length + ' pillars measured (need ' + MIN_PILLARS + ')' : null };
}

/* ---- pure: ML on the index history */
function learn(hist, today) {
  const H = hist.filter((h) => num(h.index) != null).sort((a, b) => a.day.localeCompare(b.day)).slice(-90);
  const out = { days: H.length, trend: null, forecast_30d: null, unusual: null, pillar_change: {} };
  if (H.length >= 7) {
    const pts = H.slice(-30), x0 = Date.parse(pts[0].day), xs = pts.map((h) => (Date.parse(h.day) - x0) / DAY), ys = pts.map((h) => h.index);
    const mx = mean(xs), my = mean(ys), sxx = xs.reduce((s, x) => s + (x - mx) ** 2, 0), slope = sxx ? xs.reduce((s, x, i) => s + (x - mx) * (ys[i] - my), 0) / sxx : 0;
    out.trend = { per_week: Math.round(slope * 7 * 10) / 10, verdict: Math.abs(slope * 7) < 0.5 ? 'steady' : slope > 0 ? 'improving' : 'worsening', days: pts.length };
    const last = xs[xs.length - 1]; out.forecast_30d = Math.max(0, Math.min(100, Math.round(my + slope * (last + 30 - mx))));
    if (today != null) {
      const base = H.slice(-15, -1).map((h) => h.index), m = median(base), mad = median(base.map((v) => Math.abs(v - m))) || 1, z = (today - m) / (1.4826 * mad);
      if (base.length >= 7 && Math.abs(z) >= 3) out.unusual = { today, usual: m, z: Math.round(z * 10) / 10, direction: z < 0 ? 'down' : 'up' };
    }
  }
  const wk = H.filter((h) => h.day <= riyadhDay(Date.parse(H.length ? H[H.length - 1].day : '1970-01-01') - 7 * DAY)).pop();
  if (wk && H.length) for (const [k, v] of Object.entries(H[H.length - 1].pillars || {})) if (num(v) != null && num((wk.pillars || {})[k]) != null) out.pillar_change[k] = v - wk.pillars[k];
  return out;
}

/* ---- pure: the ranked list of what needs the executive */
function attention({ ciso, risks, insights, pillarsOut }) {
  const L = [];
  for (const d of ((ciso && ciso.decisions) || []).slice(0, 30)) L.push({ kind: 'decision', severity: d.severity || 'medium', score: 10 * (SEVW[d.severity] || 2) + 5, title: clip(d.title, 160), why: 'waiting for ' + clip(d.who, 60) + ' · from ' + clip(d.from, 60), link: d.link || 'ciso-dashboard.html' });
  for (const r of (risks || []).filter((x) => x.band === 'high' || x.over_appetite).slice(0, 15)) L.push({ kind: 'risk', severity: r.band === 'high' ? 'high' : 'medium', score: 10 * (r.band === 'high' ? 3 : 2) + (r.over_appetite ? 4 : 0), title: clip(r.title, 160), why: (r.band === 'high' ? 'high residual risk' : 'medium risk') + (r.over_appetite ? ' · above the risk appetite' : '') + (r.owner ? ' · owner ' + clip(r.owner, 40) : ' · no owner'), link: 'risk-studio.html' });
  if (insights && insights.ok) for (const n of (insights.notable || []).slice(0, 12)) {
    const bad = /worse|unusual|declin|rising|breach/i.test(String(n.why || '') + ' ' + String(n.kind || '')) && !/better|improv/i.test(String(n.why || ''));
    if (!bad) continue;
    L.push({ kind: 'trend', severity: 'medium', score: 18, title: clip(n.label, 120), why: clip(n.why, 160) + (n.text ? ' (' + clip(n.text, 80) + ')' : ''), link: 'report-center.html' });
  }
  for (const p of pillarsOut.filter((x) => !x.measured)) L.push({ kind: 'gap', severity: 'low', score: 8, title: p.name + ' is not measured', why: clip(p.why, 160), link: p.page });
  return L.sort((a, b) => b.score - a.score).slice(0, 25);
}

function createExecDashboard(app, opts = {}) {
  const now = opts.now || Date.now, store = app.store, L = app.log || { info() {}, every() {} };
  const hist = () => store.collection('exec_hist');
  const A = () => app.addons || {};
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role, ip: who.ip || '', action: 'exec.' + action, target, detail }); };
  async function sources(who) {
    const R = A().reportCenter, C = A().ciso, RS = A().riskStudio, src = [];
    const take = async (name, fn) => { try { const v = await fn(); src.push({ name, state: v ? 'ok' : 'not installed' }); return v; } catch (e) { src.push({ name, state: 'error', error: clip(e.message, 160) }); if (L.every) L.every('exec:' + name, 3600000, 'warn', 'executive source failed', { source: name, err: clip(e.message, 160) }); return null; } };
    // the executive report is read as admin (it is the same figures every role sees on the Reporting Center, without host names)
    const report = await take('Reporting Center', () => (R ? R.build('executive', { user: who.user, role: 'admin' }) : null));
    const insights = await take('Reporting Center insights', () => (R ? R.insights('executive') : null));
    const ciso = await take('AI CISO', () => (C ? C.overview(false) : null));
    const risk = await take('Risk Studio', () => (RS ? RS.view({ user: who.user, role: 'viewer' }) : null));
    return { report, insights, ciso, risk, src };
  }
  function record(p, force) {
    const day = riyadhDay(now()), cur = hist().get(day);
    if (cur && !force) return cur;
    const row = { id: day, day, at: now(), index: p.index, pillars: Object.fromEntries(p.pillars.map((x) => [x.id, x.score])) };
    hist().put(row);
    const cut = riyadhDay(now() - KEEP * DAY); for (const h of hist().all((x) => x.day < cut)) hist().remove(h.id);
    return row;
  }
  async function view(who) {
    const S = await sources(who);
    const p = pillars({ report: S.report, ciso: S.ciso, riskSum: S.risk && S.risk.summary });
    if (p.index != null) record(p, false);
    const ml = learn(hist().all(() => true), p.index);
    const can = (r) => (RANK[who.role] || 0) >= RANK[r];
    const att = attention({ ciso: S.ciso, risks: S.risk && S.risk.risks, insights: S.insights, pillarsOut: p.pillars });
    const kpis = []; for (const s of ((S.report && S.report.sections) || [])) for (const k of s.kpis || []) kpis.push(Object.assign({ section: s.id }, k));
    const ins = S.insights && S.insights.ok ? S.insights.kpis.filter((k) => k.verdict && k.verdict !== 'not measured').map((k) => ({ key: k.key, label: k.label, verdict: k.verdict, change: k.change || null, forecast: k.forecast == null ? null : k.forecast, unusual: !!k.unusual })) : [];
    const sections = ((S.report && S.report.sections) || []).map((s) => ({ id: s.id, title: s.title, state: s.state, note: s.note }));
    const hs = hist().all(() => true).sort((a, b) => a.day.localeCompare(b.day)).slice(-90).map((h) => ({ day: h.day, index: h.index, pillars: h.pillars }));
    return {
      at: new Date(now()).toISOString(), index: p.index, grade: p.grade, withheld_why: p.withheld_why, measured: p.measured, pillars: p.pillars, ml, history: hs,
      attention: att, decisions_waiting: ((S.ciso && S.ciso.decisions) || []).length, risks: S.risk && S.risk.summary ? { open: S.risk.summary.open, high: S.risk.summary.high, over_appetite: S.risk.summary.over_appetite } : null,
      kpis, insights: ins, sections, sources: S.src, last_ciso_brief: (S.ciso && S.ciso.last_brief) || null,
      ai: A().reportCenter ? Object.assign({ for_role: can('operator') }, A().reportCenter.aiStatus()) : { enabled: false, reason: 'Reporting Center not installed' },
      can_snapshot: can('admin'),
    };
  }
  async function snapshot(who) {
    const S = await sources(who), p = pillars({ report: S.report, ciso: S.ciso, riskSum: S.risk && S.risk.summary });
    if (p.index == null) throw httpErr(409, 'the index is withheld: ' + p.withheld_why + ' - nothing recorded');
    const row = record(p, true); audit(who, 'snapshot', row.day, { index: row.index }); return { day: row.day, index: row.index };
  }
  const DEFAULT_Q = 'Write the executive brief for the CIO and CISO from the executive report: 1. Headline in one sentence 2. What improved 3. What got worse or is at risk, with the figure 4. What is not measured 5. Three decisions for this week, each tied to a figure.';
  async function brief(input, who) {
    if ((RANK[who.role] || 0) < RANK.operator) throw httpErr(403, 'the AI executive brief is for operators and administrators');
    const b = body(input || {}).str('question', { max: 600, min: 5 }).done();
    const R = A().reportCenter; if (!R) throw httpErr(424, 'the Reporting Center is not installed - it writes the brief');
    const r = await R.ask({ question: b.question || DEFAULT_Q, report: 'executive' }, who);
    audit(who, 'brief', 'executive', { custom_question: !!b.question, steps: (r.steps || []).length });
    return r;
  }
  if (!(app.noTimers || opts.noTimer)) {
    const t = setInterval(guardOf(app, 'exec.snapshot', async () => { const h = new Date(now() + RIYADH).getUTCHours(); if (h >= 7 && !hist().get(riyadhDay(now()))) { const S = await sources({ user: 'system:exec', role: 'admin' }); const p = pillars({ report: S.report, ciso: S.ciso, riskSum: S.risk && S.risk.summary }); if (p.index != null) record(p, false); } }), 30 * 60000);
    if (t.unref) t.unref();
  }
  return { view, snapshot, brief, PILLARS };
}

function registerExecDashboard(srv, app, E) {
  srv.route('GET', '/exec-dashboard', (ctx) => { ctx.need('viewer'); return E.view(ctx.who); });
  srv.route('POST', '/exec-dashboard/snapshot', (ctx) => { ctx.need('admin'); return E.snapshot(ctx.who); });
  srv.route('POST', '/exec-dashboard/brief', (ctx) => { ctx.need('operator'); return E.brief(ctx.body, ctx.who); }, { maxBody: 4096 });
  (app.addons = app.addons || {}).execDashboard = E;
}

module.exports = { createExecDashboard, registerExecDashboard, pillars, learn, attention, PILLARS };
