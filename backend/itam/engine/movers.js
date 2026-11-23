// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const { body, param } = require('./check');
const { guardOf } = require('./errors');
const { PRIVILEGED } = require('./onboarding');
/*
 * HR movers ({P} = /api/itam, User Desktops -> HR Movers): an employee who changes department or job keeps only the access
 * the new job needs - group memberships changed in Active Directory on the effective date, after two decisions by two people.
 *   1. request     HR or the desk (operator) records the move: who, from / to department, new job title, effective date, the
 *                  receiving manager, the groups to LEAVE (from the account's current groups, read from the directory) and the
 *                  groups to JOIN (only from the administrator's allowed list; never an admin group)
 *   2. manager     the receiving manager (or an administrator) approves the access the new job needs - never the requester
 *   3. approve     an administrator who is neither the requester nor the manager who approved approves the change to the
 *                  directory (four eyes). Refused when the account looks like someone else (its employee number differs), is
 *                  privileged (admin groups / adminCount), or is on the never-change list
 *   4. apply       AUTOMATIC on the effective date at 06:00 Riyadh (at once if that has passed): re-read and re-checked, groups
 *                  LEFT first (least privilege), then groups JOINED, department / title updated, read back and verified, each
 *                  group's result recorded. A partial result is retried. Without directory settings, the person who changed it
 *                  by hand records it
 * Reverting (a mistake) is asked by an administrator and approved by another: the groups left are joined again, the groups
 * joined are left, department / title restored. Privileged groups are never joined or left here (a domain administrator does).
 * Names and employee numbers are personal data (PDPL): operators and administrators only; viewers are refused.
 *   GET  /movers                         operator  list + counts + the groups movers may join
 *   GET  /movers/lookup?username=        operator  the account and its current groups, before raising a request (read-only)
 *   GET  /movers/:id                     operator
 *   POST /movers                         operator  {name, employee_id, username, from_department, to_department, to_title?, effective_date,
 *                                                   manager, remove_groups[], add_groups[], update_attributes?, note?}
 *   POST /movers/:id/manager             operator  {decision: approve|reject, note?}   the receiving manager or an admin, not the requester
 *   POST /movers/:id/approve             admin     {decision: approve|reject, note?}   not the requester, not the manager who approved
 *   POST /movers/:id/applied             operator  {directory_ref, note?}   manual record when automatic changes are off / failed
 *   POST /movers/:id/retry               admin     apply again after a failure or a partial result
 *   POST /movers/:id/cancel              operator  {reason}   before the change was applied
 *   POST /movers/:id/revert              admin     {reason}
 *   POST /movers/:id/revert/decide       admin     {decision, note?}   not the person who asked
 *   POST /movers/run                     admin     apply the changes that are due now (the 5-minute job does it too)
 */
const SAM = /^[A-Za-z0-9][A-Za-z0-9._-]{0,19}$/;
const USER = { max: 80, re: /^[A-Za-z0-9._@\\-]{2,80}$/, msg: 'manager must be a platform user name (letters, digits, . _ - @ \\)' };
const GROUP = /^[A-Za-z0-9 ._&()-]{1,128}$/;
const PRIV_ACCOUNT = /\b(domain admins|enterprise admins|schema admins|administrators|account operators|backup operators|server operators|print operators|dnsadmins|key admins|organization management|admins?)\b/i;
const SECRETISH = /\b(pass(word|wd|phrase|code)?|pwd|secret|pin)\b\s*(is|was|=|:|-)?\s*\S{4,}/i;
const TZ = 3, APPLY_HOUR = 6, DAY = 86400000;
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const norm = (u) => String(u == null ? '' : u).trim().toLowerCase();
const same = (a, b) => !!norm(a) && norm(a) === norm(b);
const isService = (u) => /^(duty|system|core|ai|svc|service|agent|bot)[:._-]/i.test(String(u || ''));
const cnOf = (dn) => { const m = /^CN=((?:[^,\\]|\\.)+)/i.exec(dn || ''); return m ? m[1].replace(/\\(.)/g, '$1') : dn; };

function createMovers(app, opts = {}) {
  const now = opts.now || Date.now, store = app.store;
  const col = () => store.collection('movers');
  const iso = () => new Date(now()).toISOString();
  const AD = () => opts.ad || (app.addons && app.addons.onboarding && app.addons.onboarding.ad) || null;
  const auto = () => { const a = AD(); return !!(a && a.moversEnabled()); };
  const allowed = () => { const a = AD(); return a ? (a.cfg().allowed_groups || []) : []; };
  const SYSTEM = { user: 'system:movers-ad', role: 'system', ip: '' };
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role, ip: who.ip || '', action, target, detail }); };
  const warn = (key, msg, detail) => { if (app.log && app.log.every) app.log.every('movers:' + key, 3600000, 'warn', msg, detail); };
  const person = (who, what) => { if (isService(who.user)) throw httpErr(403, 'a service or AI identity cannot ' + what + ': a person does'); };
  const notMover = (r, who, what) => { if (same(r.username, who.user)) throw httpErr(403, 'the person moving cannot ' + what + ' on their own request'); };
  const hist = (r, who, step, detail) => { r.history = (r.history || []).concat([{ at: iso(), by: who.user, role: who.role, step, detail: detail || null }]).slice(-200); };
  const get = (id) => { const k = param(id); if (!/^MOV-\d{3,6}$/.test(k)) throw httpErr(400, 'id must be a mover request (MOV-nnn)'); const r = col().get(k); if (!r) throw httpErr(404, 'no mover request ' + k); return r; };
  const open = (r) => !['completed', 'cancelled'].includes(r.status);
  const dueAt = (r) => new Date(Date.parse(r.effective_date + 'T00:00:00Z') + (APPLY_HOUR - TZ) * 3600000).toISOString();
  const has = (list, g) => list.some((x) => same(x, g));

  function steps(r) {
    return [
      { key: 'manager', name: 'Receiving manager approved the access', done: !!(r.manager_ok && r.manager_ok.decision === 'approve'), by: r.manager_ok && r.manager_ok.by },
      { key: 'approve', name: 'Directory change approved (four eyes)', done: !!(r.change && r.change.approved_by), by: r.change && r.change.approved_by },
      { key: 'applied', name: 'Groups changed in the directory', done: !!(r.applied && r.applied.at), by: r.applied && r.applied.by },
    ];
  }
  function view(r) {
    const st = steps(r), left = st.filter((s) => !s.done);
    return Object.assign({}, r, { steps: st, next: open(r) && left.length ? left[0].key : null,
      due_at: r.change && r.change.approved_by && !(r.applied && r.applied.at) ? dueAt(r) : null });
  }
  function list() {
    const items = col().all(() => true).map(view).sort((a, b) => (open(a) === open(b) ? String(a.effective_date).localeCompare(String(b.effective_date)) : open(a) ? -1 : 1));
    const o = items.filter(open);
    return { items, counts: { open: o.length, waiting_manager: o.filter((x) => x.next === 'manager').length, waiting_approval: o.filter((x) => x.next === 'approve').length,
      scheduled: o.filter((x) => x.next === 'applied' && !(x.applied && x.applied.error)).length, failed: o.filter((x) => x.applied && x.applied.error && !x.applied.at).length,
      completed: items.filter((x) => x.status === 'completed').length },
    directory: { automatic: auto(), apply_hour: APPLY_HOUR }, allowed_groups: allowed() };
  }

  // the account, its groups and why the platform would refuse to change it (read-only)
  async function lookupUser(username, employeeId) {
    if (!auto()) return { read: false, reason: 'automatic group changes are off - Directory settings' };
    const A = AD(), c = A.cfg();
    let u;
    try { u = await A.writer().findUser(username); }
    catch (e) { warn('lookup', 'movers: the directory could not be read', { err: String(e.message).slice(0, 160) }); return { read: false, reason: 'the directory did not answer: ' + String(e.message).slice(0, 160), at: iso() }; }
    if (!u) return { read: true, found: false, at: iso(), blockers: ['no account ' + username + ' in the directory'] };
    const blockers = [];
    if (employeeId && u.employee_id && !same(u.employee_id, employeeId)) blockers.push('the directory account ' + username + ' belongs to employee ' + u.employee_id + ', not ' + employeeId + ' - check the user name');
    const groups = u.member_of.map(cnOf);
    const priv = groups.filter((g) => PRIV_ACCOUNT.test(g));
    if (priv.length || u.admin_count) blockers.push('privileged account (' + (priv.join(', ') || 'adminCount') + ') - a domain administrator changes it by hand');
    if ((c.never_disable || []).some((x) => same(x, u.sam))) blockers.push(u.sam + ' is on the never-change list');
    if (same(u.dn, c.bind_dn)) blockers.push('this is the platform\'s own directory service account');
    if (!u.enabled) blockers.push('the account is disabled');
    return { read: true, found: true, at: iso(), dn: u.dn, display_name: u.display_name, employee_id: u.employee_id || null, enabled: u.enabled, department: u.department || '', title: u.title || '',
      groups, member_dns: u.member_of, blockers };
  }
  async function lookup(q) {
    const username = String((q && q.username) || '').trim();
    if (!SAM.test(username)) throw httpErr(400, 'username must be the Active Directory user name (sAMAccountName)');
    const d = await lookupUser(username.toLowerCase(), null);
    delete d.member_dns;
    return Object.assign(d, { allowed_groups: allowed() });
  }
  const pub = (d) => { const x = Object.assign({}, d); delete x.member_dns; return x; };

  async function create(input, who) {
    person(who, 'raise a mover request');
    const b = body(input || {}).str('name', { required: true, max: 120, min: 3 }).str('employee_id', { required: true, max: 20, re: /^[A-Za-z0-9-]{1,20}$/, msg: 'employee_id must be the HR employee number (letters, digits, -)' })
      .str('username', { required: true, max: 20, re: SAM, msg: 'username must be the Active Directory user name (sAMAccountName), e.g. sara.ghamdi' })
      .str('from_department', { required: true, max: 120 }).str('to_department', { required: true, max: 120 }).str('to_title', { max: 120 }).date('effective_date', { required: true })
      .str('manager', Object.assign({ required: true }, USER)).list('remove_groups', { max: 50, item: 'str', itemMax: 128, unique: true, def: [] }).list('add_groups', { max: 30, item: 'str', itemMax: 128, unique: true, def: [] })
      .bool('update_attributes', { def: true }).str('note', { max: 1000 })
      .rule((o) => (o.effective_date < new Date(now() - 30 * DAY).toISOString().slice(0, 10) ? 'effective_date is more than 30 days ago - change it by hand and record why' : null)).done();
    if (SECRETISH.test(b.note || '')) throw httpErr(400, 'note looks like it contains a password - the platform never holds one');
    const badName = b.add_groups.concat(b.remove_groups).find((g) => !GROUP.test(g)); if (badName) throw httpErr(400, 'groups: ' + badName + ' is not a group name');
    const both = b.add_groups.filter((g) => has(b.remove_groups, g)); if (both.length) throw httpErr(400, 'add_groups: ' + both.join(', ') + ' is also in remove_groups');
    const priv = b.add_groups.concat(b.remove_groups).filter((g) => PRIVILEGED.test(g));
    if (priv.length) throw httpErr(400, 'groups: ' + priv.join(', ') + ' is privileged - a privileged-access request, not a move');
    if (!b.add_groups.length && !b.remove_groups.length && !(b.update_attributes && (b.to_title || b.to_department !== b.from_department))) throw httpErr(400, 'nothing to change: name the groups to leave or join');
    if (same(b.username, who.user)) throw httpErr(403, 'you cannot raise a mover request for your own account');
    if (same(b.manager, b.username)) throw httpErr(400, 'manager cannot be the person moving');
    if (col().all((r) => open(r) && same(r.username, b.username)).length) throw httpErr(409, 'an open mover request already exists for ' + b.username);
    if (auto()) {
      const al = allowed(); const off = b.add_groups.filter((g) => !has(al, g));
      if (off.length) throw httpErr(400, 'add_groups: ' + off.join(', ') + ' is not on the list of groups movers may join (Directory settings)');
    }
    const n = col().all(() => true).length + 1, id = 'MOV-' + String(n).padStart(3, '0');
    const r = Object.assign({ id }, b, { username: b.username.toLowerCase(), status: 'requested', requested_by: who.user, requested_at: iso(), history: [] });
    const d = await lookupUser(r.username, r.employee_id);
    if (d.read && d.found) {
      const gone = b.remove_groups.filter((g) => !has(d.groups, g)); if (gone.length) throw httpErr(400, 'remove_groups: ' + r.username + ' is not a member of ' + gone.join(', '));
      r.add_groups = b.add_groups.filter((g) => !has(d.groups, g));
      r.already_member = b.add_groups.filter((g) => has(d.groups, g));
    }
    r.directory = pub(d);
    hist(r, who, 'requested', { leave: r.remove_groups.length, join: r.add_groups.length });
    col().put(r);
    audit(who, 'movers.request', id, { username: r.username, from: b.from_department, to: b.to_department, effective_date: b.effective_date, manager: b.manager, remove_groups: r.remove_groups, add_groups: r.add_groups });
    return view(r);
  }

  function manager(id, input, who) {
    const r = get(id); person(who, 'approve a move'); notMover(r, who, 'approve');
    const b = body(input || {}).oneOf('decision', ['approve', 'reject'], { required: true }).str('note', { max: 1000 })
      .rule((o) => (o.decision === 'reject' && !o.note ? 'note is required: say what to change' : null)).done();
    if (r.status !== 'requested') throw httpErr(409, r.id + ' is ' + r.status + ' - only a new request is approved by the manager');
    if (same(r.requested_by, who.user)) throw httpErr(403, 'four eyes: ' + who.user + ' raised ' + r.id + ' and cannot also approve it');
    if (!(same(r.manager, who.user) || who.role === 'admin')) throw httpErr(403, 'approving needs the receiving manager (' + r.manager + ') or an administrator');
    r.manager_ok = { decision: b.decision, by: who.user, at: iso(), note: b.note || '' };
    if (b.decision === 'reject') { r.status = 'cancelled'; r.cancel = { by: who.user, at: iso(), reason: 'rejected by the manager: ' + b.note }; }
    else r.status = 'in_progress';
    hist(r, who, 'manager', { decision: b.decision }); col().put(r);
    audit(who, 'movers.manager', r.id, { decision: b.decision, username: r.username });
    return view(r);
  }

  async function approve(id, input, who) {
    const r = get(id); person(who, 'approve a directory change'); notMover(r, who, 'approve');
    const b = body(input || {}).oneOf('decision', ['approve', 'reject'], { required: true }).str('note', { max: 1000 })
      .rule((o) => (o.decision === 'reject' && !o.note ? 'note is required: say why' : null)).done();
    if (r.status !== 'in_progress') throw httpErr(409, r.id + ' is ' + r.status + ' - the receiving manager approves first');
    if (r.change && r.change.approved_by) throw httpErr(409, 'already approved by ' + r.change.approved_by);
    if (same(r.requested_by, who.user)) throw httpErr(403, 'four eyes: ' + who.user + ' raised ' + r.id + ' and cannot also approve the change');
    if (r.manager_ok && same(r.manager_ok.by, who.user)) throw httpErr(403, 'four eyes: ' + who.user + ' approved as the manager; a different administrator approves the directory change');
    if (b.decision === 'reject') {
      r.change = { rejected_by: who.user, rejected_at: iso(), note: b.note };
      hist(r, who, 'change_reject', { note: b.note }); col().put(r);
      audit(who, 'movers.change.reject', r.id, { username: r.username, note: b.note });
      return view(r);
    }
    if (auto()) {
      const d = await lookupUser(r.username, r.employee_id); r.directory = pub(d);
      if (!d.read) throw httpErr(409, 'cannot approve without reading the account: ' + d.reason);
      if (d.blockers.length) throw httpErr(409, 'the platform will not change this account automatically: ' + d.blockers.join('; ') + ' - change it by hand and record it');
    }
    r.change = { approved_by: who.user, approved_at: iso(), note: b.note || '', mode: auto() ? 'automatic' : 'manual' };
    hist(r, who, 'change_approve', { due_at: dueAt(r), mode: r.change.mode }); col().put(r);
    audit(who, 'movers.change.approve', r.id, { username: r.username, remove_groups: r.remove_groups, add_groups: r.add_groups, due_at: dueAt(r), mode: r.change.mode, requested_by: r.requested_by, manager: r.manager_ok.by });
    if (auto() && Date.parse(dueAt(r)) <= now()) await applyNow(r);
    return view(get(r.id));
  }

  // leave first, then join, then the attributes; every group's result kept; read back
  async function change(r, leave, join, attrs, W, d) {
    const results = [];
    for (const g of leave) {
      const gdn = d.member_dns.find((x) => same(cnOf(x), g));
      if (!gdn) { results.push({ group: g, op: 'leave', ok: true, note: 'not a member' }); continue; }
      try { await W.removeFromGroup(gdn, d.dn); results.push({ group: g, op: 'leave', ok: true }); } catch (e) { results.push({ group: g, op: 'leave', ok: false, error: String(e.message).slice(0, 160) }); }
    }
    for (const g of join) {
      try {
        const gdn = await W.findGroup(g);
        if (!gdn) { results.push({ group: g, op: 'join', ok: false, error: 'group not found in the directory' }); continue; }
        await W.addToGroup(gdn, d.dn); results.push({ group: g, op: 'join', ok: true });
      } catch (e) { results.push({ group: g, op: 'join', ok: false, error: String(e.message).slice(0, 160) }); }
    }
    if (attrs) { try { await W.setAttrs(d.dn, attrs); results.push({ group: null, op: 'attributes', ok: true }); } catch (e) { results.push({ group: null, op: 'attributes', ok: false, error: String(e.message).slice(0, 160) }); } }
    return results;
  }
  async function applyNow(r) {
    const A = AD();
    try {
      const d = await lookupUser(r.username, r.employee_id);
      if (!d.read) throw new Error(d.reason);
      if (d.blockers.length) throw new Error(d.blockers.join('; '));
      if (!r.before) r.before = { groups: d.groups, department: d.department, title: d.title, at: iso() };
      const attrs = r.update_attributes ? Object.assign({ department: r.to_department }, r.to_title ? { title: r.to_title } : {}) : null;
      const results = await change(r, r.remove_groups, r.add_groups, attrs, A.writer(), d);
      const after = await lookupUser(r.username, null);
      const stillIn = r.remove_groups.filter((g) => has(after.groups || [], g)), missing = r.add_groups.filter((g) => !has(after.groups || [], g));
      const failed = results.filter((x) => !x.ok);
      const verified = !failed.length && !stillIn.length && !missing.length;
      if (!verified) {
        const why = failed.map((x) => (x.group || x.op) + ': ' + x.error).concat(stillIn.map((g) => g + ': still a member'), missing.map((g) => g + ': not a member yet'));
        throw Object.assign(new Error('partly applied - ' + why.join('; ')), { results });
      }
      r.applied = { at: iso(), by: SYSTEM.user, dn: d.dn, results, verified: true, groups_after: after.groups, error: null };
      r.status = 'completed'; r.completed_at = iso();
      hist(r, SYSTEM, 'applied', { left: r.remove_groups.length, joined: r.add_groups.length });
      audit(SYSTEM, 'movers.applied', r.id, { username: r.username, dn: d.dn, left: r.remove_groups, joined: r.add_groups, attributes: !!attrs, approved_by: r.change.approved_by });
    } catch (e) {
      const msg = String(e.message).slice(0, 400);
      r.applied = Object.assign({}, r.applied || {}, { error: msg, results: e.results || (r.applied && r.applied.results) || [], failed_at: iso(), attempts: ((r.applied && r.applied.attempts) || 0) + 1 });
      hist(r, SYSTEM, 'apply_failed', { error: msg });
      audit(SYSTEM, 'movers.apply.failed', r.id, { username: r.username, error: msg });
      warn('apply', 'movers: the group change did not complete', { id: r.id, err: msg });
    }
    col().put(r);
    return r;
  }
  async function runDue(who) {
    if (!auto()) return { ran: 0, note: 'automatic group changes are off' };
    let ran = 0, ok = 0;
    for (const r of col().all((x) => x.status === 'in_progress' && x.change && x.change.approved_by && !(x.applied && x.applied.at))) {
      if (Date.parse(dueAt(r)) > now()) continue;
      const f = r.applied || {};
      if (!who && f.failed_at && (f.attempts >= 3 || now() - Date.parse(f.failed_at) < 3600000)) continue;
      ran++; await applyNow(r); if (r.applied.at) ok++;
    }
    if (who && ran) audit(who, 'movers.run', 'due', { ran, applied: ok });
    return { ran, applied: ok, failed: ran - ok };
  }
  async function retry(id, who) {
    const r = get(id); person(who, 'change a directory account'); notMover(r, who, 'act');
    if (!(r.change && r.change.approved_by)) throw httpErr(409, 'the change has not been approved');
    if (r.applied && r.applied.at) throw httpErr(409, 'already applied');
    if (!auto()) throw httpErr(409, 'automatic group changes are off - change it by hand and record it');
    if (Date.parse(dueAt(r)) > now()) throw httpErr(409, 'not due before ' + dueAt(r) + ' - the approval was for the effective date');
    audit(who, 'movers.retry', r.id, { username: r.username });
    await applyNow(r);
    return view(get(r.id));
  }
  function manualApplied(id, input, who) {
    const r = get(id); person(who, 'record the change'); notMover(r, who, 'record');
    const b = body(input || {}).str('directory_ref', { required: true, min: 3, max: 300 }).str('note', { max: 500 }).done();
    if (SECRETISH.test(b.directory_ref + ' ' + (b.note || ''))) throw httpErr(400, 'directory_ref looks like it contains a password - the platform never holds one');
    if (!(r.change && r.change.approved_by)) throw httpErr(409, 'the change must be approved (four eyes) before it is recorded');
    if (r.applied && r.applied.at) throw httpErr(409, 'already recorded by ' + r.applied.by);
    r.applied = Object.assign({}, r.applied || {}, { at: iso(), by: who.user, manual: true, directory_ref: b.directory_ref, note: b.note || '', error: null });
    r.status = 'completed'; r.completed_at = iso();
    hist(r, who, 'applied', { manual: true }); col().put(r);
    audit(who, 'movers.applied.manual', r.id, { username: r.username, directory_ref: b.directory_ref });
    return view(r);
  }
  function cancel(id, input, who) {
    const r = get(id); person(who, 'cancel a mover request'); notMover(r, who, 'cancel');
    const b = body(input || {}).str('reason', { required: true, min: 5, max: 500 }).done();
    if (!open(r)) throw httpErr(409, r.id + ' is already ' + r.status);
    if (r.applied && r.applied.at) throw httpErr(409, 'the change was already applied - ask for a revert instead');
    if (!(same(r.requested_by, who.user) || same(r.manager, who.user) || who.role === 'admin')) throw httpErr(403, 'cancelling needs the requester, the manager or an administrator');
    r.status = 'cancelled'; r.cancel = { by: who.user, at: iso(), reason: b.reason };
    hist(r, who, 'cancel', { reason: b.reason }); col().put(r);
    audit(who, 'movers.cancel', r.id, { reason: b.reason, username: r.username, partly_applied: !!(r.applied && r.applied.results && r.applied.results.some((x) => x.ok)) });
    return view(r);
  }
  function revertRequest(id, input, who) {
    const r = get(id); person(who, 'ask for a revert'); notMover(r, who, 'act');
    const b = body(input || {}).str('reason', { required: true, min: 5, max: 500 }).done();
    if (!(r.applied && r.applied.at && !r.applied.manual && r.before)) throw httpErr(409, 'only a change the platform applied can be reverted here - otherwise in Active Directory');
    if (r.revert && ['pending', 'done'].includes(r.revert.status)) throw httpErr(409, 'a revert is already ' + r.revert.status);
    r.revert = { status: 'pending', requested_by: who.user, at: iso(), reason: b.reason };
    hist(r, who, 'revert_request', { reason: b.reason }); col().put(r);
    audit(who, 'movers.revert.request', r.id, { username: r.username, reason: b.reason });
    return view(r);
  }
  async function revertDecide(id, input, who) {
    const r = get(id); person(who, 'approve a revert'); notMover(r, who, 'approve');
    const b = body(input || {}).oneOf('decision', ['approve', 'reject'], { required: true }).str('note', { max: 500 })
      .rule((o) => (o.decision === 'reject' && !o.note ? 'note is required: say why' : null)).done();
    const q = r.revert; if (!q || q.status !== 'pending') throw httpErr(409, 'no revert is waiting for ' + r.id);
    if (same(q.requested_by, who.user)) throw httpErr(403, 'four eyes: ' + who.user + ' asked for the revert and cannot also approve it');
    if (b.decision === 'approve') {
      if (!auto()) throw httpErr(409, 'automatic group changes are off - revert it in Active Directory');
      const d = await lookupUser(r.username, r.employee_id);
      if (!d.read || !d.found) throw httpErr(409, 'the account cannot be read: ' + (d.reason || 'not found'));
      const attrs = r.update_attributes ? { department: r.before.department, title: r.before.title } : null;
      const results = await change(r, r.add_groups, r.remove_groups, attrs, AD().writer(), d);
      const failed = results.filter((x) => !x.ok);
      q.results = results;
      if (failed.length) {
        hist(r, who, 'revert_failed'); col().put(r);
        audit(who, 'movers.revert.failed', r.id, { username: r.username, failed: failed.map((x) => x.group || x.op) });
        throw httpErr(409, 'the revert did not complete: ' + failed.map((x) => (x.group || x.op) + ': ' + x.error).join('; '));
      }
    }
    Object.assign(q, { status: b.decision === 'approve' ? 'done' : 'rejected', decided_by: who.user, decided_at: iso(), note: b.note || '' });
    hist(r, who, 'revert_' + b.decision); col().put(r);
    audit(who, 'movers.revert.' + b.decision, r.id, { username: r.username, requested_by: q.requested_by, rejoined: b.decision === 'approve' ? r.remove_groups : [], left: b.decision === 'approve' ? r.add_groups : [] });
    return view(r);
  }

  function start() {
    if (app.noTimers || opts.noTimer) return;
    const t = setInterval(guardOf(app, 'movers.apply', () => runDue(null)), 5 * 60000);
    if (t.unref) t.unref();
  }
  start();
  return { list, lookup, one: (id) => view(get(id)), create, manager, approve, retry, manualApplied, cancel, revertRequest, revertDecide, runDue };
}

function registerMovers(srv, app, M) {
  srv.route('GET', '/movers', (ctx) => { ctx.need('operator'); return M.list(); });
  srv.route('GET', '/movers/lookup', (ctx) => { ctx.need('operator'); const q = body(ctx.query || {}).str('username', { required: true, max: 20, re: SAM, msg: 'username must be the Active Directory user name (sAMAccountName)' }).done(); return M.lookup(q); });
  srv.route('POST', '/movers/run', async (ctx) => { ctx.need('admin'); body(ctx.body).done(); if (isService(ctx.who.user)) throw httpErr(403, 'a person runs it'); return M.runDue(ctx.who); });
  srv.route('GET', '/movers/:id', (ctx) => { ctx.need('operator'); return M.one(ctx.params.id); });
  srv.route('POST', '/movers', (ctx) => { ctx.need('operator'); return M.create(ctx.body, ctx.who); });
  srv.route('POST', '/movers/:id/manager', (ctx) => { ctx.need('operator'); return M.manager(ctx.params.id, ctx.body, ctx.who); });
  srv.route('POST', '/movers/:id/approve', (ctx) => { ctx.need('admin'); return M.approve(ctx.params.id, ctx.body, ctx.who); });
  srv.route('POST', '/movers/:id/retry', (ctx) => { ctx.need('admin'); body(ctx.body).done(); return M.retry(ctx.params.id, ctx.who); });
  srv.route('POST', '/movers/:id/applied', (ctx) => { ctx.need('operator'); return M.manualApplied(ctx.params.id, ctx.body, ctx.who); });
  srv.route('POST', '/movers/:id/cancel', (ctx) => { ctx.need('operator'); return M.cancel(ctx.params.id, ctx.body, ctx.who); });
  srv.route('POST', '/movers/:id/revert', (ctx) => { ctx.need('admin'); return M.revertRequest(ctx.params.id, ctx.body, ctx.who); });
  srv.route('POST', '/movers/:id/revert/decide', (ctx) => { ctx.need('admin'); return M.revertDecide(ctx.params.id, ctx.body, ctx.who); });
}

module.exports = { createMovers, registerMovers };
