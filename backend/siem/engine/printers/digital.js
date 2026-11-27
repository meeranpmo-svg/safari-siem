// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Print to Digital - the assistant that helps the organisation print less and move the work to digital workflows, built on the
 * printer fleet the platform already watches (printers.js: SNMP page counters per printer, its department and site) and, where they
 * are imported, usage reports (pages, colour / mono, cost per department and month). Read-only: it changes no printer and no setting.
 *   where      pages a month per department, site and printer; colour share; cost from the organisation's own cost per page (an
 *              administrator sets it - the defaults are placeholders and say so); paper in sheets, reams and kg (A4 80 g/m2 = 5 g);
 *   trend      monthly pages with a least-squares line, and progress against the reduction target from a baseline
 *   ideas      per department, what replaces the printing in its work: approvals and invoices in the ERP (Oracle Fusion), e-signature,
 *              HR forms and onboarding packs in SharePoint, timesheets / permits / inspections on tablets at project sites, scan to
 *              SharePoint instead of copies - each with the pages it would save at a stated adoption rate (an estimate, said so)
 *   fleet      printers to consolidate (little use), colour printers used mostly for mono, sites with many small printers
 *   roadmap    three phases (quick wins, workflows, culture) with their estimated effect
 *   GET {P}/printers/digital            viewer  (departments and printers only - never a person's printing)
 *   PUT {P}/printers/digital/settings   admin   {cost_mono, cost_colour, target_pct, baseline_month_pages}
 */
const { body } = require('../util/check');
const { HttpError, wrap, audit, prefixOf } = require('../soc/routeutil');

const SHEET_G = 5, REAM = 500;   // A4 80 g/m2: 0.06237 m2 x 80 g = 4.99 g a sheet
const DEF = { cost_mono: 0.05, cost_colour: 0.35, target_pct: 30, baseline_month_pages: null, currency: 'SAR' };
// what replaces printing, by the kind of work a department does: [match, idea, share of its pages it can remove when adopted]
const IDEAS = [
  [/financ|account|treasur/i, 'Approve invoices and payments in Oracle Fusion and keep ZATCA e-invoices digital - no printed invoice packs or payment vouchers', 0.55],
  [/procure|purchas|supply|store/i, 'Purchase requisitions, POs and goods receipts approved in Oracle Fusion; suppliers send quotes and invoices electronically', 0.5],
  [/human|hr\b|people|personnel/i, 'HR forms, leave and onboarding packs in SharePoint / the ERP with e-signature; contracts signed electronically', 0.6],
  [/project|site|operation|maintenance|field/i, 'Timesheets, work permits, job cards and site reports on tablets (Microsoft Forms / Power Apps), synced to SharePoint', 0.45],
  [/hse|safety|health|environment/i, 'Inspections, toolbox talks and incident reports on tablets with photos, instead of printed checklists', 0.5],
  [/legal|compliance|contract/i, 'Contracts and approvals by e-signature; a SharePoint contract register instead of printed copies', 0.5],
  [/fleet|transport|vehicle/i, 'Trip sheets, fuel logs and vehicle checks on a mobile form', 0.5],
  [/admin|facilit|reception|general/i, 'Digital memos, circulars and visitor registration; scan incoming mail to SharePoint', 0.4],
  [/it\b|information|technology|security/i, 'Change and access approvals in the service desk; manuals and evidence in SharePoint', 0.6],
  [/management|executive|board/i, 'Board and committee packs on tablets (SharePoint / Teams), signed electronically', 0.6],
];
const QUICK = ['Default every printer and every PC to double-sided, black and white', 'Secure "follow-me" release: a job prints only when its owner taps the card - abandoned jobs (often 10-20%) are never printed', 'Scan to SharePoint / OneDrive instead of copying', 'Remove personal desk printers where a shared one is near'];
const low = (v) => String(v == null ? '' : v).toLowerCase();
function lsq(pts) { const n = pts.length; if (n < 3) return null; let sx = 0, sy = 0, sxy = 0, sxx = 0; pts.forEach((y, x) => { sx += x; sy += y; sxy += x * y; sxx += x * x; }); const d = n * sxx - sx * sx; return d ? (n * sxy - sx * sy) / d : null; }

function createPrintDigital({ printers, state, now = Date.now }) {
  const col = state.collection('print_digital');
  const settings = () => Object.assign({}, DEF, (col.get('settings') || {}).v || {});
  async function view() {
    const S = settings(), V = await printers.view(), U = printers.usage({ users: false });
    const items = V.items || [], periods = (U.periods || []).slice().sort((a, b) => String(a.period).localeCompare(String(b.period)));
    // pages a month per department: the latest imported month, else the printers' own counters over 30 days
    const fromUsage = periods.length > 0, last = periods[periods.length - 1];
    const dept = {};
    if (fromUsage) for (const d of last.by_department || []) dept[d.name] = { name: d.name, pages: d.pages, colour: d.color, mono: d.mono, cost: d.cost || null, printers: 0 };
    for (const p of items) { const k = p.department || p.site || '(no department)'; const o = dept[k] = dept[k] || { name: k, pages: 0, colour: null, mono: null, cost: null, printers: 0 }; o.printers++; if (!fromUsage) o.pages += p.pages_30d || 0; }
    const D = Object.values(dept).filter((d) => d.pages > 0 || d.printers > 0).map((d) => {
      const cost = d.cost != null && d.cost > 0 ? d.cost : (d.colour != null ? d.colour * S.cost_colour + (d.mono || 0) * S.cost_mono : d.pages * S.cost_mono);
      const idea = IDEAS.find(([re]) => re.test(d.name)), share = idea ? idea[2] : 0.3;
      return Object.assign(d, { cost: Math.round(cost), colour_pct: d.colour != null && d.pages ? Math.round(100 * d.colour / d.pages) : null, idea: idea ? idea[1] : 'Move the printed forms of this department into SharePoint / the ERP and sign electronically', can_save_pct: Math.round(share * 100), can_save_pages: Math.round(d.pages * share), can_save_cost: Math.round(cost * share) });
    }).sort((a, b) => b.pages - a.pages);
    const total = D.reduce((n, d) => n + d.pages, 0), cost = D.reduce((n, d) => n + d.cost, 0), colour = fromUsage ? D.reduce((n, d) => n + (d.colour || 0), 0) : null;
    // the trend: imported months, else the counters by day folded to weeks
    let trend = periods.map((p) => ({ period: p.period, pages: p.totals.pages, colour: p.totals.color }));
    if (!trend.length) { const byDay = {}; for (const p of items) for (const x of p.pages_by_day || []) byDay[x.day] = (byDay[x.day] || 0) + x.pages; trend = Object.keys(byDay).sort().map((k) => ({ period: k, pages: byDay[k] })); }
    const slope = lsq(trend.map((x) => x.pages)), baseline = S.baseline_month_pages || (fromUsage && periods.length >= 3 ? Math.round(periods.slice(0, 3).reduce((n, p) => n + p.totals.pages, 0) / 3) : null);
    const progress = baseline ? Math.round(100 * (baseline - total) / baseline) : null;
    // the fleet
    const bySite = {}; for (const p of items) (bySite[p.site || '(no site)'] = bySite[p.site || '(no site)'] || []).push(p);
    const fleet = [];
    for (const p of items) { if ((p.pages_30d || 0) < 300 && p.snapshot && p.snapshot.ok) fleet.push({ printer: p.name, site: p.site || '', kind: 'consolidate', why: (p.pages_30d || 0) + ' pages in 30 days - share a nearby printer and remove this one' }); }
    for (const [site, L] of Object.entries(bySite)) if (L.length >= 6 && L.reduce((n, p) => n + (p.pages_30d || 0), 0) / L.length < 1500) fleet.push({ printer: L.length + ' printers', site, kind: 'right-size', why: 'many printers with light use - fewer shared multifunction printers with follow-me release' });
    const savings = D.reduce((n, d) => n + d.can_save_pages, 0), savingsCost = D.reduce((n, d) => n + d.can_save_cost, 0);
    const kp = { pages_month: total, cost_month: Math.round(cost), sheets_year: total * 12, reams_year: Math.round(total * 12 / REAM), paper_kg_year: Math.round(total * 12 * SHEET_G / 1000), colour_pct: colour != null && total ? Math.round(100 * colour / total) : null,
      printers: items.length, target_pct: S.target_pct, progress_pct: progress, baseline, can_save_pages_month: savings, can_save_cost_year: Math.round(savingsCost * 12), trend_per_period: slope !== null ? Math.round(slope) : null };
    const insights = [], p = (lvl, t, d) => insights.push({ level: lvl, title: t, detail: d });
    if (D[0]) p('warn', D[0].name + ' prints the most: ' + D[0].pages.toLocaleString() + ' pages a month', 'Start there: ' + D[0].idea + '.');
    if (kp.colour_pct !== null && kp.colour_pct > 25) p('warn', kp.colour_pct + '% of pages are colour', 'Colour costs several times mono: make black and white the default everywhere and keep colour for the few who need it.');
    if (slope !== null && slope > 0) p('crit', 'Printing is rising', 'About ' + Math.round(slope) + ' more pages each period - the trend goes the wrong way.');
    else if (slope !== null && slope < 0) p('info', 'Printing is falling', 'About ' + Math.round(-slope) + ' fewer pages each period.');
    if (progress !== null) p(progress >= S.target_pct ? 'info' : 'warn', progress + '% below the baseline (target ' + S.target_pct + '%)', progress >= S.target_pct ? 'Target reached - set the next one.' : 'Gap to target: ' + (S.target_pct - progress) + ' points.');
    const cons = fleet.filter((f) => f.kind === 'consolidate'); if (cons.length) p('info', cons.length + ' printer(s) barely used', 'Consolidate them: ' + cons.slice(0, 5).map((f) => f.printer).join(', ') + '.');
    if (S.cost_mono === DEF.cost_mono && S.cost_colour === DEF.cost_colour) p('info', 'Costs use placeholder prices', 'An administrator sets the real cost per mono and colour page (contract / toner) for accurate figures.');
    const roadmap = [
      { phase: 'Month 1 - quick wins', actions: QUICK, effect: 'typically 15-25% fewer pages (estimate)' },
      { phase: 'Months 2-4 - workflows', actions: D.slice(0, 5).map((d) => d.name + ': ' + d.idea), effect: 'up to ' + (total ? Math.round(100 * savings / total) : 0) + '% fewer pages when adopted (estimate)' },
      { phase: 'Months 5-6 - culture', actions: ['A monthly print report per department to its head', 'Print quotas or approval for large colour jobs', 'Celebrate the departments that cut the most'], effect: 'keeps the gains' }];
    return { generated_at: new Date(now()).toISOString(), source: fromUsage ? 'usage report ' + last.period : 'printer page counters, last 30 days', settings: S, kpis: kp, departments: D, trend, fleet: fleet.slice(0, 100), insights, roadmap,
      note: 'Estimates from the pages the printers and usage reports record; savings depend on adoption. Paper: A4 80 g/m2 = 5 g a sheet. Nothing here changes a printer or a setting.' };
  }
  function setSettings(b0, who) {
    const b = body(b0 || {}).num('cost_mono', { min: 0, max: 10 }).num('cost_colour', { min: 0, max: 20 }).int('target_pct', { min: 5, max: 90 }).int('baseline_month_pages', { min: 0, max: 100000000 }).str('currency', { max: 3, re: /^[A-Z]{3}$/, msg: 'currency: a 3-letter code' }).done();
    const v = Object.assign({}, settings(), b); delete v.v; col.put({ id: 'settings', v, by: who, at: new Date(now()).toISOString() }); return v;
  }
  return { view, setSettings, IDEAS };
}

function register(api, deps, PR) {
  const P = prefixOf(deps), X = createPrintDigital({ printers: PR, state: deps.state, now: deps.now });
  api.route('GET', `${P}/printers/digital`, wrap(deps, null, async () => X.view()));
  api.route('PUT', `${P}/printers/digital/settings`, wrap(deps, 'admin', (ctx) => { const v = X.setSettings(ctx.body, ctx.user); audit(ctx, 'printers.digital.settings', 'settings', v); return v; }));
  return X;
}
module.exports = { createPrintDigital, register, IDEAS, SHEET_G };
