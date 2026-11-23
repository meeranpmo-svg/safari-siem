// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('./brand');
const { body, param } = require('./check');
const { guardOf } = require('./errors');
/*
 * Privileged access requests - just-in-time, time-limited AD group membership ({P} = /api/itam, Identity & Microsoft 365 ->
 * Privileged Access). Nobody needs to sit in an admin group all the time: they ask for the group for a few hours, a second
 * person approves, the platform adds them at the start time and REMOVES them when the time is up, and reads the directory back
 * both times.
 *   1. eligible     an administrator lists the groups that can be requested (server admins, firewall admins, SQL admins ...),
 *                   the most hours each may be held (1-72), who approves (named people, or any administrator) and whether a
 *                   ticket is required. Tier-0 built-in groups (Domain / Enterprise / Schema Admins, Administrators, the
 *                   Operators groups, Key Admins, Group Policy Creator Owners, DnsAdmins) are refused: they stay with the
 *                   break-glass procedure. The directory account needs "write members" on the eligible groups only
 *   2. request      a person (operator) asks for a group, for how many hours, why (and the ticket), now or at a start time
 *                   within 7 days; their own AD account (same user name as the platform) must exist and be enabled
 *   3. approve      one of the group's approvers, or an administrator - never the requester, never a service / AI identity
 *   4. grant        at the start time the platform adds the membership and reads it back; the request is "active" until it
 *                   expires. The requester or an administrator can end it early
 *   5. expire       when the time is up the membership is removed and read back. A removal that fails is retried every minute
 *                   and shown as an alert until it succeeds - an expired grant that is still a member is the worst outcome
 *   Standing access: members of an eligible group who hold it without an active grant are listed, so permanent admin
 *   membership can be removed (zero standing privilege).
 * Access to privileged groups is personal data and security-sensitive: operators and administrators only.
 *   GET  /pam                          operator  eligible groups, my requests, waiting for me, active grants, counts
 *   POST /pam/config                   admin     {groups: [{name, max_hours, approvers?[], ticket_required?}]}        audited
 *   POST /pam/requests                 operator  {group, hours, reason, ticket?, start_at?}
 *   POST /pam/requests/:id/decide      operator  {decision: approve|reject, note?}   an approver, not the requester
 *   POST /pam/requests/:id/end         operator  {reason}   the requester or an administrator (ends an active grant now)
 *   POST /pam/requests/:id/cancel      operator  {reason}   before it is granted
 *   GET  /pam/standing                 admin     standing members of the eligible groups (read from the directory)
 *   POST /pam/run                      admin     grant / expire what is due now (the 1-minute job does it too)
 */
const TIER0 = /^(domain admins|enterprise admins|schema admins|administrators|account operators|backup operators|server operators|print operators|key admins|enterprise key admins|group policy creator owners|dnsadmins|domain controllers|read-only domain controllers|enterprise read-only domain controllers|cert publishers|protected users)$/i;
const GROUP = /^[A-Za-z0-9 ._&()-]{1,128}$/;
const USERNAME = /^[A-Za-z0-9._@\\-]{2,80}$/;
const SAM = /^[A-Za-z0-9][A-Za-z0-9._-]{0,19}$/;
const SECRETISH = /\b(pass(word|wd|phrase|code)?|pwd|secret|pin)\b\s*(is|was|=|:|-)?\s*\S{4,}/i;
const HOUR = 3600000, DAY = 86400000;
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const norm = (u) => String(u == null ? '' : u).trim().toLowerCase();
const same = (a, b) => !!norm(a) && norm(a) === norm(b);
const isService = (u) => /^(duty|system|core|ai|svc|service|agent|bot)[:._-]/i.test(String(u || ''));
const OPEN = ['pending', 'approved', 'active', 'expire_failed'];

function createPam(app, opts = {}) {
  const now = opts.now || Date.now, store = app.store;
  const reqC = () => store.collection('pam_requests'), cfgC = () => store.collection('pam_cfg');
  const iso = (ms) => new Date(ms === undefined ? now() : ms).toISOString();
  const AD = () => opts.ad || (app.addons && app.addons.onboarding && app.addons.onboarding.ad) || null;
  const connected = () => { const a = AD(); if (!a) return false; const c = a.cfg(); return !!(c.bind_enc && (c.servers || []).length && c.base_dn); };
  const SYSTEM = { user: 'system:pam', role: 'system', ip: '' };
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role, ip: who.ip || '', action, target, detail }); };
  const log = (level, key, msg, detail) => { if (app.log && app.log.every) app.log.every('pam:' + key, level === 'error' ? 300000 : 3600000, level, msg, detail); };
  const person = (who, what) => { if (isService(who.user)) throw httpErr(403, 'a service or AI identity cannot ' + what + ': a person does'); };
  const cfg = () => Object.assign({ groups: [] }, cfgC().get('cfg') || {});
  const groupOf = (name) => cfg().groups.find((g) => same(g.name, name));
  const get = (id) => { const k = param(id); if (!/^PAR-\d{4,6}$/.test(k)) throw httpErr(400, 'id must be a privileged access request (PAR-nnnn)'); const r = reqC().get(k); if (!r) throw httpErr(404, 'no request ' + k); return r; };
  const hist = (r, who, step, detail) => { r.history = (r.history || []).concat([{ at: iso(), by: who.user, step, detail: detail || null }]).slice(-100); };
  const notify = async (users, key, subject, text) => {
    const N = app.addons && app.addons.privacyOffice && app.addons.privacyOffice.notifier;
    if (!N || typeof N.sendPlatform !== 'function' || !users.length) return;
    try { await N.sendPlatform({ key, event: 'privileged-access', users: users.slice(0, 20), from_name: (ZYB_ORG.short + ' privileged access'), subject, text }); }
    catch (e) { log('warn', 'notify', 'privileged access: notification not sent', { err: String(e.message).slice(0, 160) }); }
  };
  const canApprove = (r, who) => { const g = groupOf(r.group); return g && (g.approvers || []).length ? (g.approvers || []).some((a) => same(a, who.user)) : who.role === 'admin'; };

  function configure(input, who) {
    person(who, 'change the eligible groups');
    const b = body(input || {}).list('groups', { required: true, max: 100 }).done();
    const seen = new Set();
    const groups = b.groups.map((g, i) => {
      if (!g || typeof g !== 'object' || Array.isArray(g)) throw httpErr(400, 'groups[' + i + '] must be {name, max_hours, approvers?, ticket_required?}');
      const x = body(g).str('name', { required: true, max: 128, re: GROUP, msg: 'groups[' + i + '].name must be a group name' }).num('max_hours', { required: true, min: 1, max: 72 })
        .list('approvers', { max: 20, item: 'str', itemMax: 80, unique: true, def: [] }).bool('ticket_required', { def: false }).done();
      if (!Number.isInteger(x.max_hours)) throw httpErr(400, 'groups[' + i + '].max_hours must be a whole number of hours (1-72)');
      if (TIER0.test(x.name)) throw httpErr(400, 'groups[' + i + ']: ' + x.name + ' is a tier-0 built-in group - it stays with the break-glass procedure, not just-in-time requests');
      const badA = x.approvers.find((a) => !USERNAME.test(a) || isService(a)); if (badA) throw httpErr(400, 'groups[' + i + '].approvers: ' + badA + ' must be a person\'s platform user name');
      if (seen.has(norm(x.name))) throw httpErr(400, 'groups: ' + x.name + ' is listed twice'); seen.add(norm(x.name));
      return x;
    });
    cfgC().put({ id: 'cfg', groups, updated_by: who.user, updated_at: iso() });
    audit(who, 'pam.config', 'groups', { groups: groups.map((g) => g.name + ':' + g.max_hours + 'h' + (g.approvers.length ? ':' + g.approvers.join('|') : '')) });
    return cfg();
  }

  function view(r) {
    const left = r.status === 'active' ? Math.max(0, Date.parse(r.expires_at) - now()) : null;
    return Object.assign({}, r, { minutes_left: left === null ? null : Math.round(left / 60000) });
  }
  function list(who) {
    const all = reqC().all(() => true).sort((a, b) => String(b.id).localeCompare(String(a.id)));
    const c = cfg();
    return { groups: c.groups, directory: { connected: connected() },
      mine: all.filter((r) => same(r.requester, who.user)).slice(0, 100).map(view),
      to_approve: all.filter((r) => r.status === 'pending' && !same(r.requester, who.user) && canApprove(r, who)).map(view),
      active: all.filter((r) => ['active', 'expire_failed'].includes(r.status)).map(view),
      recent: who.role === 'admin' ? all.slice(0, 200).map(view) : [],
      counts: { pending: all.filter((r) => r.status === 'pending').length, approved: all.filter((r) => r.status === 'approved').length, active: all.filter((r) => r.status === 'active').length,
        expire_failed: all.filter((r) => r.status === 'expire_failed').length, grant_failed: all.filter((r) => r.status === 'grant_failed').length } };
  }

  async function request(input, who) {
    person(who, 'request privileged access');
    const b = body(input || {}).str('group', { required: true, max: 128, re: GROUP, msg: 'group must be a group name' }).num('hours', { required: true, min: 1, max: 72 })
      .str('reason', { required: true, min: 10, max: 500 }).str('ticket', { max: 60, re: /^[A-Za-z0-9#._\/-]{2,60}$/, msg: 'ticket must be a ticket or change number (CHG-1234)' })
      .str('start_at', { max: 30 }).done();
    if (!Number.isInteger(b.hours)) throw httpErr(400, 'hours must be a whole number');
    if (SECRETISH.test(b.reason)) throw httpErr(400, 'reason looks like it contains a password');
    const g = groupOf(b.group); if (!g) throw httpErr(400, 'group: ' + b.group + ' is not a group that can be requested - an administrator lists the eligible groups');
    if (b.hours > g.max_hours) throw httpErr(400, 'hours: ' + g.name + ' can be held for at most ' + g.max_hours + ' hour(s)');
    if (g.ticket_required && !b.ticket) throw httpErr(400, 'ticket is required for ' + g.name);
    let start = now();
    if (b.start_at) { start = Date.parse(b.start_at); if (!isFinite(start)) throw httpErr(400, 'start_at must be a date and time (ISO 8601)'); if (start < now() - 5 * 60000) throw httpErr(400, 'start_at is in the past'); if (start > now() + 7 * DAY) throw httpErr(400, 'start_at must be within 7 days'); }
    if (!SAM.test(who.user)) throw httpErr(400, 'your platform user name (' + who.user + ') is not an Active Directory user name - privileged access is granted to the AD account with the same name');
    if (reqC().all((r) => OPEN.includes(r.status) && same(r.requester, who.user) && same(r.group, g.name)).length) throw httpErr(409, 'you already have an open request or grant for ' + g.name);
    if (connected()) {
      let u; try { u = await AD().writer().findUser(who.user); } catch (e) { throw httpErr(409, 'the directory did not answer: ' + String(e.message).slice(0, 160)); }
      if (!u) throw httpErr(409, 'no Active Directory account ' + who.user + ' - privileged access is granted to your own AD account');
      if (!u.enabled) throw httpErr(409, 'your Active Directory account is disabled');
      if (u.member_of.some((d) => same(/^CN=([^,]+)/i.exec(d) && /^CN=([^,]+)/i.exec(d)[1], g.name))) throw httpErr(409, 'you are already a permanent member of ' + g.name + ' - nothing to request (it is listed as standing access)');
    }
    const n = reqC().all(() => true).length + 1, id = 'PAR-' + String(n).padStart(4, '0');
    const r = { id, group: g.name, requester: who.user.toLowerCase(), hours: b.hours, reason: b.reason, ticket: b.ticket || '', start_at: iso(start), status: 'pending', requested_at: iso(), history: [] };
    hist(r, who, 'requested', { hours: b.hours, start_at: r.start_at });
    reqC().put(r);
    audit(who, 'pam.request', id, { group: g.name, hours: b.hours, ticket: r.ticket || null, start_at: r.start_at });
    await notify(g.approvers && g.approvers.length ? g.approvers : [], 'pam|' + id + '|request', 'Privileged access request ' + id + ': ' + r.requester + ' asks for ' + g.name + ' for ' + b.hours + ' h',
      r.requester + ' asks to be added to ' + g.name + ' for ' + b.hours + ' hour(s) from ' + r.start_at.replace('T', ' ').slice(0, 16) + ' UTC.\nReason: ' + b.reason + (r.ticket ? '\nTicket: ' + r.ticket : '') + '\n\nIdentity & Microsoft 365 -> Privileged Access.');
    return view(r);
  }

  async function decide(id, input, who) {
    const r = get(id); person(who, 'approve privileged access');
    const b = body(input || {}).oneOf('decision', ['approve', 'reject'], { required: true }).str('note', { max: 300 })
      .rule((o) => (o.decision === 'reject' && !o.note ? 'note is required: say why' : null)).done();
    if (r.status !== 'pending') throw httpErr(409, r.id + ' is ' + r.status);
    if (same(r.requester, who.user)) throw httpErr(403, 'four eyes: you cannot approve your own privileged access');
    if (!canApprove(r, who)) { const g = groupOf(r.group); throw httpErr(403, 'approving ' + r.group + ' needs ' + (g && (g.approvers || []).length ? 'one of: ' + g.approvers.join(', ') : 'an administrator')); }
    r.decision = { decision: b.decision, by: who.user, at: iso(), note: b.note || '' };
    r.status = b.decision === 'approve' ? 'approved' : 'rejected';
    hist(r, who, b.decision); reqC().put(r);
    audit(who, 'pam.' + b.decision, r.id, { group: r.group, requester: r.requester, hours: r.hours, note: b.note || null });
    if (b.decision === 'approve' && Date.parse(r.start_at) <= now()) await grant(r);
    await notify([r.requester], 'pam|' + r.id + '|' + b.decision, 'Privileged access ' + r.id + ' ' + (b.decision === 'approve' ? 'approved' : 'rejected') + ': ' + r.group,
      b.decision === 'approve' ? 'Approved by ' + who.user + '. ' + r.group + ' for ' + r.hours + ' h from ' + r.start_at.replace('T', ' ').slice(0, 16) + ' UTC; it is removed automatically when the time is up.' : 'Rejected by ' + who.user + ': ' + b.note);
    return view(get(r.id));
  }

  const dnOfGroup = async (W, name) => { const g = await W.groupMembers(name); return g; };
  async function grant(r) {
    if (!connected()) { r.status = 'grant_failed'; r.error = 'the directory is not connected (Directory settings)'; reqC().put(r); return r; }
    try {
      const W = AD().writer();
      const u = await W.findUser(r.requester); if (!u) throw new Error('no AD account ' + r.requester);
      if (!u.enabled) throw new Error('the AD account is disabled');
      const g = await dnOfGroup(W, r.group); if (!g) throw new Error('group ' + r.group + ' not found in the directory');
      await W.addToGroup(g.dn, u.dn);
      const after = await W.groupMembers(g.dn);
      if (!after.members.some((m) => same(m.sam, r.requester))) throw new Error('read back: not a member');
      Object.assign(r, { status: 'active', granted_at: iso(), expires_at: iso(now() + r.hours * HOUR), group_dn: g.dn, user_dn: u.dn, error: null });
      hist(r, SYSTEM, 'granted', { expires_at: r.expires_at });
      audit(SYSTEM, 'pam.granted', r.id, { group: r.group, requester: r.requester, expires_at: r.expires_at, approved_by: r.decision.by });
    } catch (e) {
      Object.assign(r, { status: 'grant_failed', error: String(e.message).slice(0, 200) });
      hist(r, SYSTEM, 'grant_failed', { error: r.error });
      audit(SYSTEM, 'pam.grant_failed', r.id, { group: r.group, requester: r.requester, error: r.error });
      log('warn', 'grant', 'privileged access: grant failed', { id: r.id, err: r.error });
    }
    reqC().put(r);
    return r;
  }
  async function removeNow(r, why, who) {
    try {
      const W = AD().writer();
      await W.removeFromGroup(r.group_dn, r.user_dn);
      const after = await W.groupMembers(r.group_dn);
      if (after && after.members.some((m) => same(m.sam, r.requester))) throw new Error('read back: still a member');
      Object.assign(r, { status: why === 'expired' ? 'expired' : 'ended', removed_at: iso(), error: null });
      hist(r, who, why === 'expired' ? 'expired' : 'ended');
      audit(who, why === 'expired' ? 'pam.expired' : 'pam.ended', r.id, { group: r.group, requester: r.requester, held_minutes: Math.round((now() - Date.parse(r.granted_at)) / 60000) });
    } catch (e) {
      Object.assign(r, { status: 'expire_failed', error: String(e.message).slice(0, 200), failed_at: iso(), attempts: (r.attempts || 0) + 1 });
      hist(r, SYSTEM, 'remove_failed', { error: r.error });
      if (r.attempts === 1 || r.attempts % 30 === 0) audit(SYSTEM, 'pam.remove_failed', r.id, { group: r.group, requester: r.requester, error: r.error, attempts: r.attempts });
      log('error', 'remove:' + r.id, 'privileged access: an expired membership could not be removed - still a member of a privileged group', { id: r.id, group: r.group, err: r.error });
    }
    reqC().put(r);
    return r;
  }
  async function end(id, input, who) {
    const r = get(id); person(who, 'end privileged access');
    const b = body(input || {}).str('reason', { required: true, min: 3, max: 300 }).done();
    if (!['active', 'expire_failed'].includes(r.status)) throw httpErr(409, r.id + ' is ' + r.status + ' - only an active grant is ended');
    if (!(same(r.requester, who.user) || who.role === 'admin')) throw httpErr(403, 'ending a grant needs the requester or an administrator');
    if (!connected()) throw httpErr(409, 'the directory is not connected');
    r.end_reason = b.reason; r.ended_by = who.user;
    await removeNow(r, 'ended', who);
    if (r.status === 'expire_failed') throw httpErr(409, 'the directory refused the removal: ' + r.error + ' - it is retried every minute');
    return view(r);
  }
  function cancel(id, input, who) {
    const r = get(id); person(who, 'cancel a request');
    const b = body(input || {}).str('reason', { required: true, min: 3, max: 300 }).done();
    if (!['pending', 'approved', 'grant_failed'].includes(r.status)) throw httpErr(409, r.id + ' is ' + r.status);
    if (!(same(r.requester, who.user) || who.role === 'admin')) throw httpErr(403, 'cancelling needs the requester or an administrator');
    Object.assign(r, { status: 'cancelled', cancel: { by: who.user, at: iso(), reason: b.reason } });
    hist(r, who, 'cancelled', { reason: b.reason }); reqC().put(r);
    audit(who, 'pam.cancel', r.id, { group: r.group, reason: b.reason });
    return view(r);
  }

  // every minute: grant what is approved and due, remove what has expired, retry failed removals
  async function tick(who) {
    let granted = 0, expired = 0, failed = 0;
    if (!connected()) return { granted, expired, failed, note: 'directory not connected' };
    for (const r of reqC().all((x) => x.status === 'approved' && Date.parse(x.start_at) <= now())) { await grant(r); if (r.status === 'active') granted++; else failed++; }
    for (const r of reqC().all((x) => (x.status === 'active' && Date.parse(x.expires_at) <= now()) || x.status === 'expire_failed')) {
      await removeNow(r, 'expired', SYSTEM); if (r.status === 'expired') { expired++; notify([r.requester], 'pam|' + r.id + '|expired', 'Privileged access ' + r.id + ' ended: ' + r.group, 'Your membership of ' + r.group + ' was removed at the end of the approved time.'); } else failed++;
    }
    if (who && (granted || expired || failed)) audit(who, 'pam.run', 'due', { granted, expired, failed });
    return { granted, expired, failed };
  }

  async function standing() {
    if (!connected()) throw httpErr(409, 'the directory is not connected');
    const W = AD().writer(), active = reqC().all((r) => ['active', 'expire_failed'].includes(r.status)), out = [];
    for (const g of cfg().groups) {
      let r; try { r = await W.groupMembers(g.name); } catch (e) { out.push({ group: g.name, error: String(e.message).slice(0, 160) }); continue; }
      if (!r) { out.push({ group: g.name, error: 'not found in the directory' }); continue; }
      out.push({ group: g.name, members: r.members.length, standing: r.members.filter((m) => !active.some((a) => same(a.group, g.name) && same(a.requester, m.sam))).map((m) => ({ user: m.sam, name: m.display_name, enabled: m.enabled, last_logon: m.last_logon })),
        just_in_time: active.filter((a) => same(a.group, g.name)).map((a) => ({ user: a.requester, request: a.id, expires_at: a.expires_at })) });
    }
    return { groups: out, read_at: iso(), note: 'Standing members hold the group permanently. To reach zero standing privilege, remove them in Active Directory (or with an access review) and let them request it when needed.' };
  }

  if (!(app.noTimers || opts.noTimer)) { const t = setInterval(guardOf(app, 'pam.tick', () => tick(null)), 60000); if (t.unref) t.unref(); }
  return { configure, list, request, decide, end, cancel, tick, standing, TIER0 };
}

function registerPam(srv, app, M) {
  srv.route('GET', '/pam', (ctx) => { ctx.need('operator'); return M.list(ctx.who); });
  srv.route('POST', '/pam/config', (ctx) => { ctx.need('admin'); return M.configure(ctx.body, ctx.who); });
  srv.route('GET', '/pam/standing', (ctx) => { ctx.need('admin'); return M.standing(); });
  srv.route('POST', '/pam/run', async (ctx) => { ctx.need('admin'); body(ctx.body).done(); if (isService(ctx.who.user)) throw httpErr(403, 'a person runs it'); return M.tick(ctx.who); });
  srv.route('POST', '/pam/requests', (ctx) => { ctx.need('operator'); return M.request(ctx.body, ctx.who); });
  srv.route('POST', '/pam/requests/:id/decide', (ctx) => { ctx.need('operator'); return M.decide(ctx.params.id, ctx.body, ctx.who); });
  srv.route('POST', '/pam/requests/:id/end', (ctx) => { ctx.need('operator'); return M.end(ctx.params.id, ctx.body, ctx.who); });
  srv.route('POST', '/pam/requests/:id/cancel', (ctx) => { ctx.need('operator'); return M.cancel(ctx.params.id, ctx.body, ctx.who); });
}

module.exports = { createPam, registerPam, TIER0 };
