// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * ITAM Overview (IT Assets -> IT Asset Management & CMDB, {P} = /api/itam). One read over the ITAM modules' own views - nothing is
 * recomputed differently here, so this page cannot disagree with them:
 *   Inventory (data quality, duplicates, not seen), Asset Data Autopilot (proposals), Purchasing (orders, budget use, late), Software &
 *   Licences (compliance, unlicensed), Renewals & Expiry (expired, due), Stocktake (last accuracy), AI Findings (priority queue).
 *   health     0-100 from the parts that are MEASURED, each itemised with its weight and value; a part with no data is "not measured"
 *              and left out (never counted as good); withheld until >= 3 parts are measured, so an empty register is not "100"
 *   actions    the next things to do across modules, ranked, each with the page that fixes it
 *   trend      one snapshot of the health per day (background job, guardOf), 90 days kept
 *   GET /itam/overview      viewer (cost figures only where the module itself shows them to the caller's role)
 * A module that fails to answer is reported in `errors` with its name, not hidden.
 */
const { guardOf } = require('./errors');
const DAY = 86400000;
const r1 = (x) => Math.round(x * 10) / 10;

function createItamOverview(app, opts = {}) {
  const now = opts.now || Date.now;
  const SNAP = app.store.collection('itam_overview_snapshots');
  const AD = () => app.addons || {};
  async function parts(role, errors) {
    const P = {};
    const get = async (name, fn) => { try { P[name] = await fn(); } catch (e) { errors.push({ module: name, error: e.message || String(e) }); if (app.log && app.log.every) app.log.every('itam.overview.' + name, 3600000, 'warn', 'itam overview: ' + name + ' failed', { error: e.message }); } };
    if (AD().inventoryIntel) await get('inventory', () => AD().inventoryIntel.view({}));
    if (AD().assetAutofill) await get('autofill', () => AD().assetAutofill.analyse());
    if (AD().purchasing && role !== 'viewer') await get('purchasing', () => AD().purchasing.view(role)); // the Purchasing route is operator+
    if (AD().softwareStudio) await get('software', () => AD().softwareStudio.analyse(role));
    if (AD().expiryHub) await get('expiry', () => AD().expiryHub.view(role));
    if (AD().stocktakeIntel) await get('stocktake', () => AD().stocktakeIntel.view({}));
    if (AD().findingsIntel) await get('findings', () => AD().findingsIntel.view());
    return P;
  }
  function health(P) {
    const comp = [], add = (key, label, weight, value, detail, href) => comp.push({ key, label, weight, value: value == null ? null : Math.max(0, Math.min(100, Math.round(value))), measured: value != null, detail, href });
    const inv = P.inventory;
    add('quality', 'Asset data quality', 25, inv && inv.total ? inv.quality.avg : null, inv && inv.total ? 'average record completeness over ' + inv.total + ' assets' : 'no assets in the register', 'inventory.html');
    const sw = P.software && P.software.kpis;
    add('licences', 'Licence compliance', 15, sw && sw.licences ? 100 * (sw.licences - sw.over) / sw.licences : null, sw && sw.licences ? sw.over + ' of ' + sw.licences + ' licences over-deployed' : 'no licences recorded', 'software-studio.html');
    const ex = P.expiry && P.expiry.kpis;
    add('renewals', 'Renewals on time', 15, ex && ex.items ? 100 * (1 - (ex.expired + ex.due) / ex.items) : null, ex && ex.items ? ex.expired + ' expired, ' + ex.due + ' due of ' + ex.items + ' tracked' : 'nothing tracked for renewal', 'renewals-expiry.html');
    const st = P.stocktake && P.stocktake.kpis;
    add('stocktake', 'Last stocktake accuracy', 15, st && st.last_accuracy != null ? st.last_accuracy : null, st && st.last_accuracy != null ? st.last_accuracy + ' % found in the last closed count' : 'no closed stocktake', 'stocktake.html');
    const fi = P.findings && P.findings.kpis, assets = inv ? inv.total : 0;
    add('findings', 'Open high-priority findings', 15, fi && assets ? 100 * (1 - Math.min(1, fi.top_priority / Math.max(5, assets / 20))) : null, fi && assets ? fi.top_priority + ' findings with priority 70+ (' + fi.open + ' open)' : 'no assets to raise findings on', 'ai-findings.html');
    const pu = P.purchasing && P.purchasing.kpis;
    add('purchasing', 'Orders on schedule', 15, pu && pu.open ? 100 * (1 - pu.late / pu.open) : null, pu && pu.open ? pu.late + ' of ' + pu.open + ' open orders late' : 'no open purchase orders', 'asset-purchasing.html');
    const m = comp.filter((c) => c.measured), w = m.reduce((n, c) => n + c.weight, 0);
    for (const c of comp) c.points = c.measured ? r1(c.weight * c.value / 100 * (100 / w)) : 0;
    return { score: m.length >= 3 ? Math.round(m.reduce((n, c) => n + c.weight * c.value, 0) / w) : null, measured: m.length, components: comp,
      why: m.length >= 3 ? 'weighted over the ' + m.length + ' measured parts; parts with no data are left out' : 'withheld: only ' + m.length + ' of ' + comp.length + ' parts have data - connect them before a score means anything' };
  }
  function actions(P) {
    const A = [], add = (pr, title, detail, href, module) => A.push({ priority: Math.round(pr), title, detail, href, module });
    const fi = P.findings; if (fi) for (const f of fi.open.slice(0, 3)) add(f.priority, f.title, 'AI Findings - priority ' + f.priority + (f.why[0] ? ': ' + f.why.map((w) => w.why).slice(0, 2).join(', ') : ''), 'ai-findings.html', 'findings');
    const ex = P.expiry; if (ex) for (const x of (ex.items || []).filter((i) => i.state === 'expired' || i.state === 'due').sort((a, b) => (a.days_left || 0) - (b.days_left || 0)).slice(0, 3)) add(x.state === 'expired' ? 90 : 75, (x.state === 'expired' ? 'Expired: ' : 'Renew now: ') + (x.name || x.title || x.kind), (x.days_left < 0 ? -x.days_left + ' days ago' : x.days_left + ' days left') + (x.owner ? ' · owner ' + x.owner : ' · no owner'), 'renewals-expiry.html', 'expiry');
    const pu = P.purchasing && P.purchasing.kpis; if (pu) { if (pu.awaiting_approval) add(65, pu.awaiting_approval + ' purchase order(s) waiting for approval', 'a different person approves', 'asset-purchasing.html', 'purchasing'); if (pu.late) add(70, pu.late + ' order(s) late', 'past the expected delivery learned for the vendor', 'asset-purchasing.html', 'purchasing'); if (pu.delivered_not_live) add(45, pu.delivered_not_live + ' delivered asset(s) not live yet', 'go-live pending', 'asset-purchasing.html', 'purchasing'); }
    const sw = P.software && P.software.kpis; if (sw) { if (sw.over) add(72, sw.over + ' licence(s) over-deployed', 'true-up exposure', 'software-studio.html', 'software'); if (sw.unlicensed) add(60, sw.unlicensed + ' product(s) installed with no licence', 'record a licence or remove it', 'software-studio.html', 'software'); }
    const af = P.autofill; if (af && af.verified) add(55, af.verified + ' verified data proposal(s) ready to accept', 'warranty / support / end of life / CIA from vendor and contract sources', 'asset-autofill.html', 'autofill');
    const inv = P.inventory; if (inv) { const strong = (inv.duplicates || []).filter((d) => d.strength === 'strong').length; if (strong) add(62, strong + ' likely duplicate asset record(s)', 'same serial or MAC', 'inventory.html', 'inventory'); const stale = (inv.facets.issue.find((i) => i.value === 'stale') || {}).count; if (stale) add(50, stale + ' networked asset(s) not seen for ' + inv.not_seen_days + '+ days', 'confirm, move to stock or retire', 'inventory.html', 'inventory'); /* same rule as Inventory's ghost */ const T = now(), ghost = app.store.collection('assets').all((a) => ['retired', 'disposed', 'lost'].includes(a.status) && a.last_seen && T - Date.parse(a.last_seen) <= 7 * DAY).length; if (ghost) add(68, ghost + ' retired asset(s) still seen on the network', 'retired on paper, still running', 'inventory.html', 'inventory'); }
    const st = P.stocktake; if (st) { if (st.kpis.open && st.current && st.current.status === 'open') add(40, 'Stocktake in progress: ' + st.current.found + ' of ' + st.current.expected + ' found', st.current.name, 'stocktake.html', 'stocktake'); else if (st.plan && st.plan[0] && st.plan[0].priority >= 60) add(st.plan[0].priority * 0.6, 'Count ' + st.plan[0].site + ' next', st.plan[0].why.join(', '), 'stocktake.html', 'stocktake'); }
    return A.sort((a, b) => b.priority - a.priority).slice(0, 15);
  }
  async function view(role) {
    role = role || 'viewer'; const errors = [], P = await parts(role, errors), H = health(P), T = now();
    const inv = P.inventory, fi = P.findings && P.findings.kpis, sw = P.software && P.software.kpis, ex = P.expiry && P.expiry.kpis, pu = P.purchasing, st = P.stocktake && P.stocktake.kpis, af = P.autofill;
    const typeF = inv ? inv.facets.type.slice(0, 10) : [], siteF = inv ? inv.facets.site.slice(0, 10) : [];
    return { at: new Date(T).toISOString(), health: H, actions: actions(P), errors,
      tiles: { assets: inv ? inv.total : null, quality: inv ? inv.quality.avg : null, findings_open: fi ? fi.open : null, findings_top: fi ? fi.top_priority : null, renewals_due: ex ? ex.expired + ex.due : null, renew_90: ex ? ex.d90 : null,
        licences_over: sw ? sw.over : null, unlicensed: sw ? sw.unlicensed : null, orders_open: pu ? pu.kpis.open : null, orders_late: pu ? pu.kpis.late : null, stocktake_accuracy: st ? st.last_accuracy : null, proposals: af ? af.proposals.length : null },
      breakdown: { type: typeF, site: siteF, sites_all: inv ? inv.facets.site.slice(0, 60) : [], status: inv ? inv.facets.status : [], weakest_fields: inv ? inv.quality.by_field.filter((f) => f.pct != null).sort((a, b) => a.pct - b.pct).slice(0, 5) : [], weakest_sites: inv ? inv.quality.by_site.slice(0, 5) : [], sites_quality: inv ? inv.quality.by_site.slice(0, 60) : [] },
      budget: pu && pu.budget && pu.budget.connected ? { fy: pu.budget.fy, currency: pu.currency, envelopes: pu.budget.envelopes.map((e) => ({ name: e.name, utilisation_pct: e.utilisation_pct, remaining: role === 'viewer' ? undefined : e.remaining })) } : null,
      trend: SNAP.all().sort((a, b) => String(a.day).localeCompare(String(b.day))).slice(-90).map((s) => ({ day: s.day, score: s.score, measured: s.measured })),
      modules: [['inventory', 'Inventory', 'inventory.html'], ['autofill', 'Asset Data Autopilot', 'asset-autofill.html'], ['purchasing', 'Asset Purchasing', 'asset-purchasing.html'], ['software', 'Software & Licences', 'software-studio.html'], ['expiry', 'Renewals & Expiry', 'renewals-expiry.html'], ['stocktake', 'Stocktake', 'stocktake.html'], ['findings', 'AI Findings', 'ai-findings.html']]
        .map(([k, label, href]) => ({ key: k, label, href, state: P[k] ? 'ok' : errors.some((e) => e.module === k) ? 'error' : k === 'purchasing' && role === 'viewer' && AD().purchasing ? 'operators' : 'not installed' })).concat([{ key: 'cmdb', label: 'CMDB & Dependencies', href: 'cmdb-deps.html', state: 'link' }, { key: 'discovery', label: 'Discovery', href: 'discovery-studio.html', state: 'link' }, { key: 'settings', label: 'ITAM Settings', href: 'itam-settings.html', state: 'link' }]),
      note: 'Every figure comes from the module that owns it; open the module for the detail. A part with no data is shown as not measured, never as good.' };
  }
  async function snapshot() {
    const v = await view('viewer'), day = new Date(now()).toISOString().slice(0, 10);
    SNAP.put({ id: day, day, score: v.health.score, measured: v.health.measured, at: new Date(now()).toISOString() });
    const old = SNAP.all().sort((a, b) => String(a.day).localeCompare(String(b.day))); for (const s of old.slice(0, Math.max(0, old.length - 90))) SNAP.remove(s.id);
    return { day, score: v.health.score };
  }
  let timer = null;
  function start() {
    if (opts.noTimer || timer) return;
    const run = guardOf(app, 'itam.overview.snapshot', snapshot);
    const loop = async () => { try { await run(); } finally { timer = setTimeout(loop, DAY); if (timer.unref) timer.unref(); } };
    timer = setTimeout(loop, 10 * 60000); if (timer.unref) timer.unref();
  }
  function stop() { if (timer) clearTimeout(timer); timer = null; }
  return { view, snapshot, start, stop };
}

function registerItamOverview(srv, app, O) {
  srv.route('GET', '/itam/overview', (ctx) => { ctx.need('viewer'); return O.view(ctx.role || (ctx.who && ctx.who.role)); });
}

module.exports = { createItamOverview, registerItamOverview };
