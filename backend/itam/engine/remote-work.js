// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Work From Home (remote work): employees ask for days at home, a named approver of their department (or an administrator)
 * decides - never the person who asked, never an AI or service identity - and IT sees who works remotely today with what it
 * needs: a company laptop on record and a VPN connection.
 *
 *   policy     days per month, notice, which departments may, who approves each department, a company laptop required
 *   requests   from / to (working days only: the organisation's weekend is not counted), reason, department; over-policy is
 *              allowed but marked for the approver; overlapping requests are refused
 *   board      today: who is at home by department, the next 14 working days, waiting decisions, use this month by department;
 *              readiness of today's remote workers (laptop on record, VPN logon seen today through the FortiGate logs)
 *   indicators administrators only: VPN logons today by people with no approved day - INDICATORS, NOT PROOF (a shared account,
 *              an on-call engineer, a site office on VPN); the page says so and nothing is done automatically (PDPL)
 *
 * Personal data: user name, department, dates and the reason the person typed - nothing else (PDPL data minimisation). The
 * VPN check reads only user names that logged on today, through the SIEM link, as the read-only auditing role.
 *
 *   GET  /remote-work/me                     any role   my requests, my days this month, the policy, what waits for me to decide
 *   POST /remote-work/requests               any role   {from, to, reason, department}            (my own request)
 *   POST /remote-work/requests/:id/cancel    any role   the person who asked, before the day has passed
 *   POST /remote-work/requests/:id/decide    any role   {decision, comment} - an approver of that department or an admin
 *   GET  /remote-work/board                  operator   today, next 14 days, waiting, month by department, readiness
 *   GET  /remote-work/policy                 viewer     the policy
 *   PUT  /remote-work/policy                 admin      {max_days_month, notice_days, require_laptop, departments}
 */
const ZYB_ORG = require('./brand');
const { body, param } = require('./check');
const { isHuman } = require('./approve-scopes');
const { guardOf } = require('./errors');

const DAY = 86400000, RIYADH = 3 * 3600000, MAX_SPAN = 31;
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const DEPTS = () => (Array.isArray(ZYB_ORG.departments) ? ZYB_ORG.departments : []).map((d) => (typeof d === 'string' ? { id: d, name: d } : { id: String(d.id), name: String(d.name || d.id) }));
// the organisation's weekend (getUTCDay numbers); Saudi Arabia: Friday and Saturday
const WEEKEND = () => (Array.isArray(ZYB_ORG.weekend) && ZYB_ORG.weekend.length ? ZYB_ORG.weekend.map(Number) : [5, 6]);
const low = (u) => String(u || '').trim().toLowerCase().replace(/^.*\\/, '').replace(/@.*$/, '');

function createRemoteWork(app, opts = {}) {
  const now = opts.now || Date.now, C = (x) => app.store.collection(x);
  const reqs = () => C('rw_requests'), pol = () => C('rw_policy');
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role || '', ip: who.ip || '', action: 'remote-work.' + action, target, detail }); };
  const today = () => new Date(now() + RIYADH).toISOString().slice(0, 10);
  const dayOf = (d) => new Date(Date.parse(d + 'T00:00:00Z')).getUTCDay();
  function workDays(from, to) { const out = []; for (let t = Date.parse(from + 'T00:00:00Z'); t <= Date.parse(to + 'T00:00:00Z'); t += DAY) { const d = new Date(t).toISOString().slice(0, 10); if (!WEEKEND().includes(dayOf(d))) out.push(d); } return out; }
  const addDays = (d, n) => new Date(Date.parse(d + 'T00:00:00Z') + n * DAY).toISOString().slice(0, 10);

  function policy() {
    const p = pol().get('policy') || {}, deps = {};
    for (const d of DEPTS()) { const x = (p.departments || {})[d.id] || {}; deps[d.id] = { name: d.name, allowed: x.allowed !== false, approvers: Array.isArray(x.approvers) ? x.approvers : [] }; }
    return { max_days_month: p.max_days_month == null ? 8 : p.max_days_month, notice_days: p.notice_days == null ? 1 : p.notice_days, require_laptop: p.require_laptop !== false,
      departments: deps, weekend: WEEKEND(), updated_by: p.updated_by || null, updated_at: p.updated_at || null };
  }
  function putPolicy(b0, who) {
    if (!isHuman(who.user)) throw httpErr(403, 'a person sets the work-from-home policy');
    const ids = DEPTS().map((d) => d.id);
    const v = body(b0).int('max_days_month', { min: 0, max: 23, required: true }).int('notice_days', { min: 0, max: 30, required: true }).bool('require_laptop', { def: true }).done();
    const raw = b0 && b0.departments, deps = {};   // departments: checked field by field below (no undeclared key reaches the store)
    if (raw !== undefined) {
      if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw httpErr(400, 'departments must be an object of department id → {allowed, approvers}');
      for (const [k, x] of Object.entries(raw)) {
        if (!ids.includes(k)) throw httpErr(400, 'departments.' + String(k).slice(0, 40) + ': not a department of the organisation');
        const y = body(x).bool('allowed', { def: true }).list('approvers', { max: 20, item: 'id', unique: true }).done();
        deps[k] = { allowed: y.allowed, approvers: (y.approvers || []).map(low) };
      }
    }
    const cur = pol().get('policy') || {};
    const next = Object.assign({ id: 'policy' }, cur, v, raw !== undefined ? { departments: deps } : {}, { updated_by: who.user, updated_at: new Date(now()).toISOString() });
    pol().put(next);
    audit(who, 'policy', 'policy', { max_days_month: next.max_days_month, notice_days: next.notice_days, require_laptop: next.require_laptop, departments: Object.keys(next.departments || {}).length });
    return policy();
  }

  const isApprover = (who, r) => { const p = policy(), d = p.departments[r.department]; return who.role === 'admin' || !!(d && d.approvers.includes(low(who.user))); };
  const usedInMonth = (user, month, exceptId) => reqs().all((x) => x.user === user && ['approved', 'pending'].includes(x.status) && x.id !== exceptId)
    .reduce((n, x) => n + x.days.filter((d) => d.slice(0, 7) === month).length, 0);
  function nextId() { let m = 0; for (const x of reqs().all()) { const k = Number(String(x.id).slice(4)); if (k > m) m = k; } return 'WFH-' + String(m + 1).padStart(5, '0'); }

  function request(b0, who) {
    if (!isHuman(who.user)) throw httpErr(403, 'a person asks for their own work-from-home days');
    const b = body(b0).date('from', { required: true }).date('to', { required: true }).str('reason', { required: true, min: 5, max: 400 })
      .oneOf('department', DEPTS().map((d) => d.id), { required: true }).done();
    if (b.to < b.from) throw httpErr(400, 'to: must be on or after from');
    if (b.from < today()) throw httpErr(400, 'from: a day that has passed cannot be asked for');
    if ((Date.parse(b.to) - Date.parse(b.from)) / DAY + 1 > MAX_SPAN) throw httpErr(400, 'to: at most ' + MAX_SPAN + ' days in one request');
    const p = policy(), dep = p.departments[b.department];
    if (!dep.allowed) throw httpErr(403, 'department: ' + dep.name + ' does not work from home under the current policy');
    const days = workDays(b.from, b.to); if (!days.length) throw httpErr(400, 'from: the dates are all weekend days');
    const user = low(who.user);
    const clash = reqs().all((x) => x.user === user && ['pending', 'approved'].includes(x.status) && x.days.some((d) => days.includes(d)));
    if (clash.length) throw httpErr(409, 'you already asked for some of these days (' + clash[0].id + ')');
    const notes = [];
    const shortNotice = (Date.parse(b.from) - Date.parse(today())) / DAY < p.notice_days; if (shortNotice) notes.push('less than ' + p.notice_days + ' day(s) notice');
    const months = [...new Set(days.map((d) => d.slice(0, 7)))];
    for (const m of months) { const n = usedInMonth(user, m) + days.filter((d) => d.slice(0, 7) === m).length; if (n > p.max_days_month) notes.push(m + ': ' + n + ' day(s), over the ' + p.max_days_month + ' allowed'); }
    const laptop = laptopOf(user); if (p.require_laptop && !laptop.length) notes.push('no company laptop on record for this person');
    const r = reqs().put({ id: nextId(), user, department: b.department, from: b.from, to: b.to, days, reason: b.reason, status: 'pending', notes, created_at: new Date(now()).toISOString() });
    audit(who, 'request', r.id, { from: r.from, to: r.to, days: days.length, department: r.department, over_policy: notes.length > 0 });
    return r;
  }
  function decide(id, b0, who) {
    param(id, 'id');
    if (!isHuman(who.user)) throw httpErr(403, 'only a person decides');
    const r = reqs().get(id); if (!r) throw httpErr(404, 'request not found');
    if (r.status !== 'pending') throw httpErr(409, 'this request is ' + r.status);
    if (low(who.user) === r.user) throw httpErr(403, 'you cannot decide your own request');
    if (!isApprover(who, r)) throw httpErr(403, 'only an approver of ' + (policy().departments[r.department] || {}).name + ' or an administrator decides');
    const b = body(b0).oneOf('decision', ['approved', 'rejected'], { required: true }).str('comment', { max: 400 }).done();
    if (b.decision === 'rejected' && !b.comment) throw httpErr(400, 'comment: say why it is rejected');
    const x = reqs().patch(id, (o) => { o.status = b.decision; o.decided_by = low(who.user); o.decided_at = new Date(now()).toISOString(); o.comment = b.comment || ''; return o; });
    audit(who, 'decide', id, { decision: b.decision, user: r.user });
    return x;
  }
  function cancel(id, who) {
    param(id, 'id');
    const r = reqs().get(id); if (!r) throw httpErr(404, 'request not found');
    if (r.user !== low(who.user)) throw httpErr(403, 'only the person who asked cancels it');
    if (!['pending', 'approved'].includes(r.status)) throw httpErr(409, 'this request is ' + r.status);
    if (r.to < today()) throw httpErr(409, 'these days have passed');
    const x = reqs().patch(id, (o) => { o.status = 'cancelled'; o.cancelled_at = new Date(now()).toISOString(); return o; });
    audit(who, 'cancel', id, {});
    return x;
  }

  // the company laptop(s) on record for a person: the asset register's owner or custodian (no other personal data read)
  function laptopOf(user) {
    const A = app.assets; if (!A || typeof A.all !== 'function') return [];
    return A.all().filter((a) => (low(a.owner) === user || low(a.custodian) === user) && /laptop|notebook|desktop|workstation|pc/i.test(String(a.type || a.category || '')) && !['disposed', 'retired'].includes(a.status))
      .slice(0, 5).map((a) => ({ id: a.id, name: a.name || a.hostname || a.id, type: a.type || '' }));
  }
  // VPN logons today (FortiGate logs in the SIEM), user names only; null when the SIEM link or the logs are not there
  async function vpnToday() {
    const d = app.discovery; if (!d || !d.siem || typeof d.siem.call !== 'function') return { connected: false, why: 'no link to the SIEM' };
    try {
      const from = new Date(Date.parse(today() + 'T00:00:00Z') - RIYADH).toISOString();
      const x = await d.siem.call('POST', '/top', { user: 'system:remote-work', role: 'analyst' }, { q: 'tags:vpn AND action:logon', field: 'user', from, to: 'now', limit: 100 });
      if (!x || x.status !== 200 || !x.json) return { connected: false, why: 'the SIEM answered HTTP ' + (x && x.status) };
      return { connected: true, users: new Set((x.json.values || []).map((v) => low(v.v)).filter(Boolean)) };
    } catch (e) { return { connected: false, why: String(e.message || e).slice(0, 160) }; }
  }

  const pub = (r) => ({ id: r.id, user: r.user, department: r.department, from: r.from, to: r.to, days: r.days.length, reason: r.reason, status: r.status, notes: r.notes || [],
    decided_by: r.decided_by || null, comment: r.comment || '', created_at: r.created_at });
  function me(who) {
    const user = low(who.user), m = today().slice(0, 7), p = policy();
    const mine = reqs().all((x) => x.user === user).sort((a, b) => String(b.from).localeCompare(String(a.from))).slice(0, 50).map(pub);
    const waiting = reqs().all((x) => x.status === 'pending' && x.user !== user && isApprover(who, x)).sort((a, b) => a.from.localeCompare(b.from)).map(pub);
    return { user, today: today(), policy: { max_days_month: p.max_days_month, notice_days: p.notice_days, require_laptop: p.require_laptop, weekend: p.weekend },
      departments: DEPTS().map((d) => ({ id: d.id, name: d.name, allowed: p.departments[d.id].allowed })),
      used_this_month: reqs().all((x) => x.user === user && x.status === 'approved').reduce((n, x) => n + x.days.filter((d) => d.slice(0, 7) === m).length, 0),
      requests: mine, waiting_for_me: waiting, laptop: laptopOf(user) };
  }
  async function board(who) {
    const t = today(), m = t.slice(0, 7), p = policy(), approved = reqs().all((x) => x.status === 'approved');
    const home = approved.filter((x) => x.days.includes(t));
    const vpn = await vpnToday();
    const byDept = {}; for (const d of DEPTS()) byDept[d.id] = { id: d.id, name: d.name, today: 0, month_days: 0, people_month: 0 };
    for (const x of home) if (byDept[x.department]) byDept[x.department].today++;
    const pm = {}; for (const x of approved) { const n = x.days.filter((d) => d.slice(0, 7) === m).length; if (n && byDept[x.department]) { byDept[x.department].month_days += n; pm[x.department + '|' + x.user] = 1; } }
    for (const k of Object.keys(pm)) byDept[k.split('|')[0]].people_month++;
    const next = []; for (let i = 0, d = t; next.length < 14 && i < 30; i++, d = addDays(d, 1)) if (!WEEKEND().includes(dayOf(d))) next.push({ day: d, approved: approved.filter((x) => x.days.includes(d)).length, pending: reqs().all((x) => x.status === 'pending' && x.days.includes(d)).length });
    const ready = home.map((x) => { const lap = laptopOf(x.user); return { id: x.id, user: x.user, department: x.department, laptop: lap.length ? lap[0].name : null, vpn: vpn.connected ? vpn.users.has(x.user) : null }; });
    const out = { today: t, policy: { max_days_month: p.max_days_month, require_laptop: p.require_laptop },
      kpis: { home_today: home.length, pending: reqs().all((x) => x.status === 'pending').length, no_laptop: ready.filter((r) => !r.laptop).length, no_vpn: vpn.connected ? ready.filter((r) => r.vpn === false).length : null,
        over_policy: reqs().all((x) => x.status === 'pending' && (x.notes || []).length).length },
      today_list: ready, departments: Object.values(byDept).filter((d) => d.today || d.month_days || p.departments[d.id].allowed), next_days: next,
      pending: reqs().all((x) => x.status === 'pending').sort((a, b) => a.from.localeCompare(b.from)).slice(0, 100).map(pub),
      vpn: { connected: vpn.connected, why: vpn.connected ? null : vpn.why } };
    // indicators for administrators only: a VPN logon today with no approved day (not proof of anything)
    if (who.role === 'admin' && vpn.connected) {
      const ok = new Set(home.map((x) => x.user));
      out.indicators = { note: 'Indicators, not proof: a VPN logon today without an approved work-from-home day. It can be an on-call engineer, a site office on VPN, travel or a shared account - ask before concluding anything.',
        vpn_without_approval: [...vpn.users].filter((u) => !ok.has(u)).sort().slice(0, 200) };
    }
    return out;
  }
  // approved days that have passed are kept for 13 months (the month-by-month view and the audit), then removed (PDPL: no longer needed)
  function prune() { const cut = addDays(today(), -400); for (const x of reqs().all((r) => r.to < cut)) reqs().remove(x.id); }
  if (!(app.noTimers || opts.noTimer)) { const tm = setInterval(guardOf(app, 'remote-work.prune', prune), DAY); if (tm.unref) tm.unref(); }
  return { me, board, request, decide, cancel, policy, putPolicy, prune, workDays };
}

function registerRemoteWork(srv, app, R0) {
  const R = R0 || createRemoteWork(app);
  app.addons = app.addons || {}; app.addons.remoteWork = R;
  const self = { anyRole: 'every employee works with their own work-from-home requests; decisions are checked against the department approvers in code' };
  srv.route('GET', '/remote-work/me', (ctx) => { ctx.need('viewer'); return R.me(ctx.who); });
  srv.route('POST', '/remote-work/requests', (ctx) => { ctx.need('viewer'); return R.request(ctx.body, ctx.who); }, Object.assign({ maxBody: 4096 }, self));
  srv.route('POST', '/remote-work/requests/:id/cancel', (ctx) => { ctx.need('viewer'); return R.cancel(ctx.params.id, ctx.who); }, Object.assign({ maxBody: 1024 }, self));
  srv.route('POST', '/remote-work/requests/:id/decide', (ctx) => { ctx.need('viewer'); return R.decide(ctx.params.id, ctx.body, ctx.who); }, Object.assign({ maxBody: 2048 }, self));
  srv.route('GET', '/remote-work/board', async (ctx) => { ctx.need('operator'); return R.board(ctx.who); });
  srv.route('GET', '/remote-work/policy', (ctx) => { ctx.need('viewer'); return R.policy(); });
  srv.route('PUT', '/remote-work/policy', (ctx) => { ctx.need('admin'); return R.putPolicy(ctx.body, ctx.who); }, { maxBody: 16384 });
  return R;
}

module.exports = { createRemoteWork, registerRemoteWork };
