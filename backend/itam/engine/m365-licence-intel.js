// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Microsoft 365 Licences & Security - licence management and the security that the licences buy, with AI / ML, READ-ONLY.
 * Reads the tenant through the Microsoft 365 connection of HR Onboarding (engine/m365-licensing.js userApps(): GET /subscribedSkus,
 * /users with their licences, and the 30-day usage reports) - no new credential, nothing is ever changed in the tenant.
 *   licences     per subscription: bought, assigned, free, expiring (warning) and suspended seats, utilisation
 *   waste        paid licences on disabled accounts; on accounts with no activity in any service for inactive_days; never used;
 *                a licence another of the user's licences already contains (its service plans are a subset); a suite with
 *                desktop Office used only on the web / mobile (a lighter plan may do) - each an indicator a person confirms
 *   money        the monthly / yearly cost of that waste from the prices an administrator enters (none entered: counts only)
 *   ML           a daily history per licence: least-squares forecast of the days until the assigned seats reach the bought ones,
 *                and an unusual jump in assignments (z-score over the last 30 days)
 *   security     what the licences give each enabled licensed user: Entra ID P1 (Conditional Access), P2, Defender for Office 365
 *                P1 / P2, Defender for Endpoint, Intune, Purview information protection - coverage and the users without it
 * Reclaiming a licence is not done here: HR Offboarding reclaims a leaver's licences after a second administrator approves, or a
 * person removes it in the Microsoft 365 admin centre. PDPL: only names / user principal names are kept, no content.
 *   GET  /m365-licences             viewer    licences, waste, forecast, security coverage; users' names for operator and above
 *   POST /m365-licences/refresh     operator  read the tenant now (a person)                                    audited
 *   PUT  /m365-licences/settings    admin     {inactive_days, currency, prices: {SKU part: monthly price}}      audited
 * Refreshed every 6 hours in the background (guardOf) while the connection is set.
 */
const { body } = require('./check');
const { isHuman } = require('./approve-scopes');
const { guardOf } = require('./errors');

const DAY = 86400000;
const bad = (msg, status = 400) => Object.assign(new Error(msg), { status });
// friendly names of common subscriptions (the part number is shown when it is not here)
const NAMES = { SPE_E3: 'Microsoft 365 E3', SPE_E5: 'Microsoft 365 E5', SPE_F1: 'Microsoft 365 F3', ENTERPRISEPACK: 'Office 365 E3', ENTERPRISEPREMIUM: 'Office 365 E5',
  STANDARDPACK: 'Office 365 E1', DESKLESSPACK: 'Office 365 F3', SPB: 'Microsoft 365 Business Premium', O365_BUSINESS_PREMIUM: 'Microsoft 365 Business Standard',
  O365_BUSINESS_ESSENTIALS: 'Microsoft 365 Business Basic', O365_BUSINESS: 'Microsoft 365 Apps for business', OFFICESUBSCRIPTION: 'Microsoft 365 Apps for enterprise',
  EXCHANGESTANDARD: 'Exchange Online (Plan 1)', EXCHANGEENTERPRISE: 'Exchange Online (Plan 2)', EXCHANGEDESKLESS: 'Exchange Online Kiosk', EMS: 'Enterprise Mobility + Security E3',
  EMSPREMIUM: 'Enterprise Mobility + Security E5', AAD_PREMIUM: 'Entra ID P1', AAD_PREMIUM_P2: 'Entra ID P2', ATP_ENTERPRISE: 'Defender for Office 365 (Plan 1)',
  THREAT_INTELLIGENCE: 'Defender for Office 365 (Plan 2)', WIN_DEF_ATP: 'Defender for Endpoint P2', DEFENDER_ENDPOINT_P1: 'Defender for Endpoint P1', INTUNE_A: 'Intune Plan 1',
  POWER_BI_PRO: 'Power BI Pro', POWER_BI_STANDARD: 'Power BI (free)', FLOW_FREE: 'Power Automate (free)', TEAMS_EXPLORATORY: 'Teams Exploratory', VISIOCLIENT: 'Visio Plan 2',
  PROJECTPROFESSIONAL: 'Project Plan 3', MCOMEETADV: 'Audio Conferencing', MCOEV: 'Teams Phone', PHONESYSTEM_VIRTUALUSER: 'Teams Phone Resource Account',
  Microsoft_Teams_Rooms_Pro: 'Teams Rooms Pro', DYN365_ENTERPRISE_PLAN1: 'Dynamics 365 Plan', DYN365_FINANCE: 'Dynamics 365 Finance', DYN365_SCM: 'Dynamics 365 Supply Chain Management',
  DYN365_ENTERPRISE_SALES: 'Dynamics 365 Sales', DYN365_TEAM_MEMBERS: 'Dynamics 365 Team Members', CCIBOTS_PRIVPREV_VIRAL: 'Copilot Studio (trial)', Microsoft_365_Copilot: 'Microsoft 365 Copilot' };
const FREE = /FREE|TRIAL|VIRAL|EXPLORATORY|STANDARD_STUDENT|DEVELOPER|_IW$|POWER_BI_STANDARD|WINDOWS_STORE|STREAM$/i;
// the security a licence buys, read from its service plans
const CAPS = [['p1', 'Entra ID P1 (Conditional Access)', /^AAD_PREMIUM$/], ['p2', 'Entra ID P2 (risk-based sign-in, PIM)', /^AAD_PREMIUM_P2$/],
  ['mdo1', 'Defender for Office 365 P1 (Safe Links / Attachments)', /^ATP_ENTERPRISE$/], ['mdo2', 'Defender for Office 365 P2 (investigation)', /^THREAT_INTELLIGENCE$/],
  ['mde', 'Defender for Endpoint', /^(WINDEFATP|MDE_LITE|MDE_SMB)$/], ['intune', 'Intune (device management)', /^INTUNE_A$/],
  ['mip', 'Purview information protection', /^(RMS_S_PREMIUM|RMS_S_PREMIUM2|MIP_S_CLP1|MIP_S_CLP2)$/]];
const DESKTOP_PLAN = /^OFFICESUBSCRIPTION$/;

function lsq(pts) { const n = pts.length; if (n < 2) return null; let sx = 0, sy = 0, sxy = 0, sxx = 0; for (const [x, y] of pts) { sx += x; sy += y; sxy += x * y; sxx += x * x; }
  const d = n * sxx - sx * sx; if (!d) return null; const b = (n * sxy - sx * sy) / d; return { slope: b, icept: (sy - b * sx) / n }; }

function createM365LicenceIntel(app, opts = {}) {
  const now = opts.now || Date.now, iso = () => new Date(now()).toISOString(), C = (x) => app.store.collection(x);
  const latest = () => C('m365lic_latest'), daily = () => C('m365lic_daily'), conf = () => C('m365lic_settings');
  const source = opts.source || (() => (app.addons && app.addons.onboarding && app.addons.onboarding.lic) || null);
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role || '', ip: who.ip || '', action: 'm365lic.' + action, target, detail }); };
  const log = (k, msg, d) => { if (app.log && app.log.every) app.log.every('m365lic:' + k, 3600000, 'warn', msg, d); };
  const settings = () => Object.assign({ inactive_days: 90, currency: 'SAR', prices: {} }, (conf().get('s') || {}).v || {});
  const connected = () => { const L = source(); return !!(L && typeof L.connected === 'function' && L.connected()); };
  let running = null;

  // ---- read the tenant (read-only) and keep what the analysis needs: names, licences, last activity - no content
  async function refresh(who) {
    if (running) return running;
    running = (async () => {
      const L = source(); if (!L || !connected()) throw bad('Microsoft 365 is not connected - an administrator sets the tenant, app and secret in HR Onboarding -> Microsoft 365', 409);
      const r = await L.userApps();
      const act = new Map((r.act || []).map((x) => [String(x.userPrincipalName || '').toLowerCase(), x]));
      const appu = new Map((r.apps || []).map((x) => [String(x.userPrincipalName || '').toLowerCase(), x]));
      const day = (v) => (v && /^\d{4}-\d{2}-\d{2}/.test(String(v)) ? String(v).slice(0, 10) : null);
      const desktopUse = (x) => { if (!x) return null; const flat = JSON.stringify(x.details || x); return /"(windows|mac)"\s*:\s*(true|"Yes")/i.test(flat) || /(Windows|Mac)"\s*:\s*(true|"Yes")/.test(flat); };
      const webOnly = (x) => { if (!x) return null; const flat = JSON.stringify(x.details || x); return /"(web|mobile)"\s*:\s*(true|"Yes")/i.test(flat) || /(Web|Mobile)"\s*:\s*(true|"Yes")/.test(flat); };
      const users = (r.users || []).filter((u) => (u.assignedLicenses || []).length).map((u) => {
        const k = String(u.userPrincipalName || '').toLowerCase(), a = act.get(k), ap = appu.get(k);
        const last = a ? [a.exchangeLastActivityDate, a.oneDriveLastActivityDate, a.sharePointLastActivityDate, a.teamsLastActivityDate, a.yammerLastActivityDate, a.skypeForBusinessLastActivityDate].map(day).filter(Boolean).sort().pop() || null : undefined;
        return { upn: u.userPrincipalName || '', name: u.displayName || '', enabled: u.accountEnabled !== false, licences: (u.assignedLicenses || []).map((l) => ({ sku_id: l.skuId, disabled: l.disabledPlans || [] })),
          last_activity: last, in_report: !!a, desktop: desktopUse(ap), web_mobile: webOnly(ap) };
      });
      const concealed = (r.act || []).length > 0 && (r.act || []).every((x) => /^[0-9A-F]{32}$/i.test(String(x.userPrincipalName || '')));
      const rec = { id: 'cur', at: iso(), skus: r.skus || [], users, errors: (r.errors || []).slice(0, 10), reports: { activity: (r.act || []).length, apps: (r.apps || []).length, concealed } };
      latest().put(rec);
      const d = iso().slice(0, 10); daily().put({ id: d, skus: Object.fromEntries((r.skus || []).map((s) => [s.part, { enabled: s.enabled, consumed: s.consumed }])) });
      for (const o of daily().all((x) => now() - Date.parse(x.id + 'T00:00:00Z') > 400 * DAY)) daily().remove(o.id);
      if (who && who.user && !/^system:/.test(who.user)) audit(who, 'refresh', 'm365', { skus: rec.skus.length, users: users.length, errors: rec.errors.length });
      return rec;
    })();
    try { return await running; } finally { running = null; }
  }

  // ---- the analysis (pure, from the last read and the history)
  function analyse(rec, st) {
    const skus = rec.skus || [], byId = new Map(skus.map((s) => [s.sku_id, s])), price = (part) => { const p = Number((st.prices || {})[part]); return Number.isFinite(p) && p > 0 ? p : null; };
    const planIds = (s) => new Set((s.plans || []).map((p) => p.id)), planNames = (s, dis) => (s.plans || []).filter((p) => !(dis || []).includes(p.id)).map((p) => p.name);
    const paid = (s) => s && !FREE.test(s.part) && s.enabled > 0;
    const hist = daily().all().sort((a, b) => a.id.localeCompare(b.id));
    const lic = skus.map((s) => {
      const pts = hist.filter((h) => h.skus && h.skus[s.part]).map((h) => [Date.parse(h.id + 'T00:00:00Z') / DAY, h.skus[s.part].consumed]);
      let days = null; const f = pts.length >= 5 ? lsq(pts) : null;
      if (f && f.slope > 0.01 && s.enabled > s.consumed) { const x = (s.enabled - f.icept) / f.slope - now() / DAY; days = x > 0 ? Math.round(x) : 0; }
      const last30 = pts.slice(-31, -1).map((p) => p[1]); let jump = null;
      if (last30.length >= 7) { const m = last30.reduce((a, b) => a + b, 0) / last30.length, sd = Math.sqrt(last30.reduce((a, b) => a + (b - m) * (b - m), 0) / last30.length) || 1, z = (s.consumed - m) / sd;
        if (Math.abs(z) >= 3 && Math.abs(s.consumed - m) >= 5) jump = { z: Math.round(z * 10) / 10, from: Math.round(m), to: s.consumed }; }
      return { sku_id: s.sku_id, part: s.part, name: NAMES[s.part] || s.part, free_sku: FREE.test(s.part), bought: s.enabled, assigned: s.consumed, free: s.enabled - s.consumed,
        expiring: s.warning || 0, suspended: s.suspended || 0, util: s.enabled ? Math.round(1000 * s.consumed / s.enabled) / 10 : null, price: price(s.part), days_to_full: days, jump, history: pts.length };
    }).sort((a, b) => (b.bought - a.bought));
    // waste per user licence (paid subscriptions only); each with its reason and evidence
    const cutoff = new Date(now() - (st.inactive_days || 90) * DAY).toISOString().slice(0, 10), W = [];
    for (const u of rec.users || []) {
      const held = u.licences.map((l) => ({ l, s: byId.get(l.sku_id) })).filter((x) => x.s);
      for (const { s } of held) {
        if (!paid(s)) continue;
        const add = (reason, why) => W.push({ upn: u.upn, name: u.name, part: s.part, licence: NAMES[s.part] || s.part, reason, why, monthly: price(s.part) });
        if (!u.enabled) { add('disabled', 'the account is disabled but still holds the licence'); continue; }
        if (u.in_report && !u.last_activity) { add('never-used', 'no activity in any Microsoft 365 service in the 30-day report'); continue; }
        if (u.last_activity && u.last_activity < cutoff) { add('inactive', 'last activity ' + u.last_activity + ' (over ' + (st.inactive_days || 90) + ' days)'); continue; }
        const mine = planIds(s); const sup = held.find((o) => o.s !== s && paid(o.s) && mine.size > 0 && [...mine].every((id) => planIds(o.s).has(id)) && planIds(o.s).size > mine.size);
        if (sup) { add('overlap', 'everything in it is already in ' + (NAMES[sup.s.part] || sup.s.part)); continue; }
        if (planNames(s).some((n) => DESKTOP_PLAN.test(n)) && u.desktop === false && u.web_mobile === true) add('right-size', 'desktop Office not used in 30 days - only web / mobile');
      }
    }
    const R = (k) => W.filter((w) => w.reason === k), money = W.reduce((a, w) => a + (w.monthly || 0), 0), priced = W.filter((w) => w.monthly).length;
    // security that the licences buy: coverage among enabled users holding a paid licence
    const active = (rec.users || []).filter((u) => u.enabled && u.licences.some((l) => paid(byId.get(l.sku_id))));
    const capOf = (u) => { const names = new Set(); for (const l of u.licences) { const s = byId.get(l.sku_id); if (s) planNames(s, l.disabled).forEach((n) => names.add(n)); } return names; };
    const userCaps = active.map((u) => ({ u, c: capOf(u) }));
    const security = CAPS.map(([key, label, re]) => { const has = userCaps.filter((x) => [...x.c].some((n) => re.test(n))).length;
      return { key, label, covered: has, users: active.length, pct: active.length ? Math.round(1000 * has / active.length) / 10 : null, licensed_in_tenant: skus.some((s) => (s.plans || []).some((p) => re.test(p.name))) }; });
    const noP1 = userCaps.filter((x) => ![...x.c].some((n) => /^AAD_PREMIUM(_P2)?$/.test(n))).map((x) => ({ upn: x.u.upn, name: x.u.name }));
    const totals = { bought: lic.filter((l) => !l.free_sku).reduce((a, l) => a + l.bought, 0), assigned: lic.filter((l) => !l.free_sku).reduce((a, l) => a + l.assigned, 0) };
    totals.free = totals.bought - totals.assigned; totals.util = totals.bought ? Math.round(1000 * totals.assigned / totals.bought) / 10 : null;
    // what the AI noticed - each with its figure
    const N = [];
    if (R('disabled').length) N.push({ tone: 'bad', text: R('disabled').length + ' paid licences sit on disabled accounts - reclaim them through HR Offboarding or the admin centre.' });
    if (R('inactive').length) N.push({ tone: 'warn', text: R('inactive').length + ' paid licences belong to people with no activity for over ' + st.inactive_days + ' days.' });
    if (R('never-used').length) N.push({ tone: 'warn', text: R('never-used').length + ' paid licences show no use at all in the last 30 days.' });
    if (R('overlap').length) N.push({ tone: 'warn', text: R('overlap').length + ' licences duplicate what another licence of the same person already includes.' });
    if (R('right-size').length) N.push({ tone: 'info', text: R('right-size').length + ' people with desktop Office use only web / mobile - a lighter plan may do.' });
    if (money) N.push({ tone: 'bad', text: 'The flagged licences cost about ' + Math.round(money).toLocaleString('en-US') + ' ' + st.currency + ' a month (' + Math.round(money * 12).toLocaleString('en-US') + ' a year) at the prices entered.' });
    for (const l of lic) { if (l.days_to_full != null && l.days_to_full <= 60) N.push({ tone: l.days_to_full <= 14 ? 'bad' : 'warn', text: l.name + ' runs out of seats in about ' + l.days_to_full + ' days at the current rate (forecast from ' + l.history + ' days).' });
      if (l.jump) N.push({ tone: 'warn', text: l.name + ': assigned seats jumped from about ' + l.jump.from + ' to ' + l.jump.to + ' (unusual, z = ' + l.jump.z + ').' });
      if (l.expiring) N.push({ tone: 'warn', text: l.name + ': ' + l.expiring + ' seats are in the expiry warning period - renew or they stop working.' });
      if (l.suspended) N.push({ tone: 'bad', text: l.name + ': ' + l.suspended + ' seats are suspended.' });
      if (!l.free_sku && l.free < 0) N.push({ tone: 'bad', text: l.name + ': more assigned than bought (' + l.assigned + ' of ' + l.bought + ').' }); }
    const p1 = security.find((x) => x.key === 'p1'); if (p1 && p1.users && p1.covered < p1.users) N.push({ tone: 'bad', text: (p1.users - p1.covered) + ' licensed people have no Entra ID P1 - Conditional Access cannot protect their sign-in.' });
    const mdo = security.find((x) => x.key === 'mdo1'); if (mdo && mdo.users && mdo.covered < mdo.users) N.push({ tone: 'warn', text: (mdo.users - mdo.covered) + ' mailboxes have no Defender for Office 365 - no Safe Links / Safe Attachments.' });
    return { licences: lic, totals, waste: { items: W, by_reason: { disabled: R('disabled').length, inactive: R('inactive').length, 'never-used': R('never-used').length, overlap: R('overlap').length, 'right-size': R('right-size').length },
      monthly: money ? Math.round(money) : null, priced, currency: st.currency }, security, no_p1: noP1, noticed: N, people: active.length };
  }

  function view(role) {
    const RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 }, st = settings(), rec = latest().get('cur');
    const base = { connected: connected(), settings: (RANK[role] || 0) >= 3 ? st : { inactive_days: st.inactive_days, currency: st.currency } };
    if (!rec) return Object.assign(base, { read: null, note: connected() ? 'Not read yet - Refresh reads the tenant now (it also runs every 6 hours).' : 'Microsoft 365 is not connected: an administrator sets the tenant, app and secret in HR Onboarding -> Microsoft 365, with the Organization.Read.All, User.Read.All and Reports.Read.All application permissions.' });
    const a = analyse(rec, st), names = (RANK[role] || 0) >= 2;
    if (!names) { a.waste.items = []; a.no_p1 = []; }   // a viewer sees the figures, not the people (PDPL)
    else { a.waste.items = a.waste.items.slice(0, 1000); a.no_p1 = a.no_p1.slice(0, 500); }
    // the daily history for the chart: the five biggest paid subscriptions, the last 90 days
    const parts = a.licences.filter((l) => !l.free_sku).slice(0, 5).map((l) => ({ part: l.part, name: l.name }));
    const history = daily().all().sort((x, y) => x.id.localeCompare(y.id)).slice(-90).map((h) => ({ date: h.id, v: Object.fromEntries(parts.map((p) => [p.part, h.skus && h.skus[p.part] ? h.skus[p.part].consumed : null])) }));
    return Object.assign(base, { read: { at: rec.at, errors: rec.errors, reports: rec.reports }, names, history, trend_parts: parts }, a);
  }

  function putSettings(b0, who) {
    if (!isHuman(who.user)) throw bad('a person changes these settings', 403);
    const src = b0 && typeof b0 === 'object' ? b0 : {};
    const b = body(Object.assign({}, src, { prices: undefined })).int('inactive_days', { min: 14, max: 365 }).str('currency', { max: 3, re: /^[A-Z]{3}$/, msg: 'currency must be a 3-letter code such as SAR' }).done();
    const cur = settings(), v = Object.assign({}, cur, b);
    if (src.prices !== undefined) {
      if (!src.prices || typeof src.prices !== 'object' || Array.isArray(src.prices)) throw bad('prices must be an object {licence part number: monthly price}');
      const P = {}; for (const [k, x] of Object.entries(src.prices)) { if (!/^[A-Za-z0-9_.-]{1,64}$/.test(k)) throw bad('prices.' + String(k).slice(0, 40) + ': not a licence part number');
        if (x === null || x === '') continue; const n = Number(x); if (!Number.isFinite(n) || n < 0 || n > 100000) throw bad('prices.' + k + ' must be a monthly price between 0 and 100000'); P[k] = n; }
      if (Object.keys(P).length > 300) throw bad('prices: at most 300 licences');
      v.prices = P;
    }
    conf().put({ id: 's', v, by: who.user, at: iso() });
    audit(who, 'settings', 'm365', { inactive_days: v.inactive_days, currency: v.currency, prices: Object.keys(v.prices || {}).length });
    return view(who.role);
  }

  async function tick() { if (!connected()) return; try { await refresh({ user: 'system:m365lic', role: 'system' }); } catch (e) { log('tick', 'Microsoft 365 licence read failed', { err: String(e.message || e).slice(0, 200) }); throw e; } }
  return { refresh, view, putSettings, analyse, tick: guardOf(app, 'm365lic.refresh', tick), NAMES, CAPS };
}

function registerM365LicenceIntel(srv, app, X, opts = {}) {
  srv.route('GET', '/m365-licences', (ctx) => { ctx.need('viewer'); return X.view(ctx.who.role); });
  srv.route('POST', '/m365-licences/refresh', async (ctx) => { ctx.need('operator'); if (!isHuman(ctx.who.user)) throw bad('a person refreshes', 403); body(ctx.body).done(); await X.refresh(ctx.who); return X.view(ctx.who.role); }, { maxBody: 256 });
  srv.route('PUT', '/m365-licences/settings', (ctx) => { ctx.need('admin'); return X.putSettings(ctx.body, ctx.who); }, { maxBody: 32768 });
  if (!(app.noTimers || opts.noTimer)) { const job = guardOf(app, 'm365lic.tick', () => X.tick()), t1 = setTimeout(job, 120000), t2 = setInterval(job, 6 * 3600000); if (t1.unref) t1.unref(); if (t2.unref) t2.unref(); }
  (app.addons = app.addons || {}).m365LicenceIntel = X;
  return X;
}

module.exports = { createM365LicenceIntel, registerM365LicenceIntel, NAMES, CAPS };
