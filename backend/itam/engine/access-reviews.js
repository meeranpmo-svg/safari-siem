// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('./brand');
const { body, param } = require('./check');
const { guardOf } = require('./errors');
/*
 * Quarterly access reviews of Active Directory groups ({P} = /api/itam, Identity & Microsoft 365 -> Access Reviews): every
 * member of every group in scope is attested by their line manager each quarter, and access that is no longer needed is
 * removed after a second person approves.
 *   1. scope       an administrator lists the groups to review (privileged groups belong here most of all), a fallback
 *                  reviewer per group, the days managers have (default 21), and whether removals are applied automatically
 *   2. campaign    one per quarter (2026-Q4), started by an administrator or automatically on the first day of the quarter: the
 *                  members of each group are READ from the directory (read-only) with their manager (AD "manager"), state,
 *                  last sign-in and whether they are new since last quarter. Reviewer = the manager's user name (it must be
 *                  the person's platform user name); no manager -> the group's fallback reviewer; never the member themselves
 *   3. attest      each reviewer marks every line "keep" or "remove" (a reason is required to remove, and to keep a disabled or
 *                  dormant account), then signs the attestation ("I have reviewed ... and it is appropriate") - signed lines
 *                  are locked. Reminders go to reviewers through the platform mail relay; past the due date it is overdue
 *   4. remove      lines marked "remove" are approved by an administrator who is not the reviewer (four eyes); with directory
 *                  settings and automatic removal on, the platform removes the membership and reads it back; privileged
 *                  groups, privileged accounts and the never-change list are removed by hand by a domain administrator and
 *                  recorded
 *   5. close       an administrator closes the campaign; anything not attested or not removed is listed as an exception in
 *                  the report. The CSV export is the evidence (SAMA CSF 3.3.5, NCA ECC 2-2-1-5, ISO 27001 A.5.18)
 * Who is in which group, with names and managers, is personal data (PDPL): operators and administrators only.
 *   GET  /access-reviews                          operator  campaigns, scope, counts, my open lines
 *   POST /access-reviews/config                   admin     {groups: [{name, fallback_reviewer?}], due_days, auto_start, auto_remove}
 *   POST /access-reviews                          admin     {quarter?}   start a campaign (reads the directory)
 *   GET  /access-reviews/:id                      operator  summary per group and per reviewer
 *   GET  /access-reviews/:id/items                operator  ?mine=1&group=&state=   the lines
 *   POST /access-reviews/:id/decide               operator  {decisions: [{item, decision: keep|remove, reason?}]}   the assigned reviewer
 *   POST /access-reviews/:id/sign                 operator  {statement: true}   the reviewer, once all their lines are decided
 *   POST /access-reviews/:id/reassign             admin     {items[], reviewer, reason}
 *   POST /access-reviews/:id/removals/decide      admin     {items[], decision: approve|reject, note?}   not the reviewer
 *   POST /access-reviews/:id/removals/done        operator  {items[], directory_ref}   removed by hand (not the member)
 *   POST /access-reviews/:id/remind               admin     e-mail the reviewers with open lines
 *   POST /access-reviews/:id/close                admin     {note?}
 *   GET  /access-reviews/:id/export               operator  CSV evidence                                         audited
 */
const PRIVILEGED = /\b(domain admins|enterprise admins|schema admins|administrators|account operators|backup operators|server operators|print operators|dnsadmins|key admins|organization management|admins?)\b/i;
const GROUP = /^[A-Za-z0-9 ._&()-]{1,128}$/;
const USERNAME = /^[A-Za-z0-9._@\\-]{2,80}$/;
const SECRETISH = /\b(pass(word|wd|phrase|code)?|pwd|secret|pin)\b\s*(is|was|=|:|-)?\s*\S{4,}/i;
const DORMANT_DAYS = 90, DAY = 86400000, TZ = 3;
const STATEMENT = 'I have reviewed every membership listed for me in this campaign; the access I marked "keep" is needed for the person\'s current job and the access I marked "remove" is not.';
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const norm = (u) => String(u == null ? '' : u).trim().toLowerCase();
const same = (a, b) => !!norm(a) && norm(a) === norm(b);
const isService = (u) => /^(duty|system|core|ai|svc|service|agent|bot)[:._-]/i.test(String(u || ''));
const quarterOf = (ms) => { const d = new Date(ms + TZ * 3600000); return d.getUTCFullYear() + '-Q' + (Math.floor(d.getUTCMonth() / 3) + 1); };

function createAccessReviews(app, opts = {}) {
  const now = opts.now || Date.now, store = app.store;
  const camps = () => store.collection('access_reviews'), itemsC = () => store.collection('access_review_items'), cfgC = () => store.collection('access_review_cfg');
  const iso = () => new Date(now()).toISOString();
  const AD = () => opts.ad || (app.addons && app.addons.onboarding && app.addons.onboarding.ad) || null;
  const connected = () => { const a = AD(); if (!a) return false; const c = a.cfg(); return !!(c.bind_enc && (c.servers || []).length && c.base_dn); };
  const SYSTEM = { user: 'system:access-reviews', role: 'system', ip: '' };
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role, ip: who.ip || '', action, target, detail }); };
  const warn = (key, msg, detail) => { if (app.log && app.log.every) app.log.every('access-reviews:' + key, 3600000, 'warn', msg, detail); };
  const person = (who, what) => { if (isService(who.user)) throw httpErr(403, 'a service or AI identity cannot ' + what + ': a person does'); };
  const cfg = () => Object.assign({ groups: [], due_days: 21, auto_start: false, auto_remove: false }, cfgC().get('cfg') || {});
  const getC = (id) => { const k = param(id); if (!/^AR-\d{4}-Q[1-4]$/.test(k)) throw httpErr(400, 'id must be a campaign (AR-2026-Q4)'); const c = camps().get(k); if (!c) throw httpErr(404, 'no campaign ' + k); return c; };
  const lines = (cid, f) => itemsC().all((x) => x.campaign === cid && (!f || f(x)));
  const neverChange = () => { const a = AD(); return a ? (a.cfg().never_disable || []) : []; };

  // ---- scope
  function configure(input, who) {
    person(who, 'change the review scope');
    const b = body(input || {}).list('groups', { max: 200 }).num('due_days', { min: 7, max: 60 }).bool('auto_start').bool('auto_remove').done();
    if (b.due_days !== undefined && !Number.isInteger(b.due_days)) throw httpErr(400, 'due_days must be a whole number of days (7-60)');
    if (b.groups) {
      const seen = new Set();
      b.groups = b.groups.map((g, i) => {
        if (!g || typeof g !== 'object' || Array.isArray(g)) throw httpErr(400, 'groups[' + i + '] must be {name, fallback_reviewer?}');
        const x = body(g).str('name', { required: true, max: 128, re: GROUP, msg: 'groups[' + i + '].name must be a group name' }).str('fallback_reviewer', { max: 80, re: USERNAME, msg: 'groups[' + i + '].fallback_reviewer must be a platform user name' }).done();
        if (seen.has(norm(x.name))) throw httpErr(400, 'groups: ' + x.name + ' is listed twice'); seen.add(norm(x.name));
        return { name: x.name, fallback_reviewer: x.fallback_reviewer || '', privileged: PRIVILEGED.test(x.name) };
      });
    }
    const c = Object.assign(cfg(), b, { id: 'cfg', updated_by: who.user, updated_at: iso() });
    cfgC().put(c);
    audit(who, 'access-reviews.config', 'scope', { groups: c.groups.map((g) => g.name), due_days: c.due_days, auto_start: c.auto_start, auto_remove: c.auto_remove });
    return cfg();
  }

  // ---- campaign
  async function start(input, who) {
    if (who !== SYSTEM) person(who, 'start a campaign');
    const b = body(input || {}).str('quarter', { max: 7, re: /^\d{4}-Q[1-4]$/, msg: 'quarter must look like 2026-Q4' }).done();
    const q = b.quarter || quarterOf(now()), id = 'AR-' + q, c = cfg();
    if (camps().get(id)) throw httpErr(409, 'the ' + q + ' campaign already exists');
    if (!c.groups.length) throw httpErr(409, 'no group is in scope - an administrator lists the groups to review first');
    if (!connected()) throw httpErr(409, 'the directory is not connected - an administrator sets Directory settings (HR Onboarding) first');
    const W = AD().writer();
    const prev = camps().all((x) => x.id !== id).sort((a, b2) => String(b2.id).localeCompare(String(a.id)))[0];
    const prevKeys = prev ? new Set(lines(prev.id).map((x) => norm(x.group) + '|' + norm(x.user))) : null;
    const groups = [], rows = [];
    for (const g of c.groups) {
      let r;
      try { r = await W.groupMembers(g.name); } catch (e) { groups.push({ name: g.name, error: 'not read: ' + String(e.message).slice(0, 160) }); warn('read', 'access reviews: a group could not be read', { group: g.name, err: String(e.message).slice(0, 160) }); continue; }
      if (!r) { groups.push({ name: g.name, error: 'not found in the directory' }); continue; }
      groups.push({ name: g.name, dn: r.dn, members: r.members.length, privileged: g.privileged, fallback_reviewer: g.fallback_reviewer });
      for (const m of r.members) rows.push({ g, gdn: r.dn, m });
    }
    if (!groups.some((g) => !g.error)) throw httpErr(409, 'no group in scope could be read: ' + groups.map((g) => g.name + ' (' + g.error + ')').join('; '));
    let sams = {};
    try { sams = await W.samsOf(rows.map((x) => x.m.manager_dn)); } catch (e) { warn('managers', 'access reviews: managers could not be read', { err: String(e.message).slice(0, 160) }); }
    const camp = { id, quarter: q, status: 'open', started_by: who.user, started_at: iso(), due_at: new Date(now() + c.due_days * DAY).toISOString(), groups, auto_remove: c.auto_remove, previous: prev ? prev.id : null, history: [] };
    let n = 0;
    for (const { g, gdn, m } of rows) {
      const mgr = m.manager_dn ? sams[m.manager_dn.toLowerCase()] || '' : '';
      let reviewer = mgr, source = 'manager';
      if (!reviewer || same(reviewer, m.sam)) { reviewer = g.fallback_reviewer && !same(g.fallback_reviewer, m.sam) ? g.fallback_reviewer : ''; source = reviewer ? 'group fallback' : 'unassigned'; }
      const dormant = !m.last_logon || now() - Date.parse(m.last_logon) > DORMANT_DAYS * DAY;
      itemsC().put({ id: id + ':' + String(++n).padStart(5, '0'), campaign: id, group: g.name, group_dn: gdn, privileged_group: g.privileged, user: m.sam.toLowerCase(), user_dn: m.dn, display_name: m.display_name,
        employee_id: m.employee_id || null, enabled: m.enabled, last_logon: m.last_logon, dormant, privileged_account: m.admin_count, manager: mgr || null, reviewer: reviewer || null, reviewer_source: source,
        new_since_last: prevKeys ? !prevKeys.has(norm(g.name) + '|' + norm(m.sam)) : null, decision: null, state: 'open' });
    }
    camp.lines = n;
    camps().put(camp);
    audit(who, 'access-reviews.start', id, { groups: groups.map((g) => g.name + ':' + (g.error ? 'error' : g.members)), lines: n, due_at: camp.due_at });
    if (opts.noAutoRemind !== true) await remind(id, who === SYSTEM ? SYSTEM : who, true).catch((e) => warn('remind', 'access reviews: first reminders not sent', { err: String(e.message).slice(0, 160) }));
    return summary(id);
  }

  function summary(id) {
    const c = getC(id), all = lines(c.id);
    const by = (k) => { const m = {}; for (const x of all) { const key = x[k] || '(unassigned)'; const s = m[key] || (m[key] = { name: key, lines: 0, decided: 0, keep: 0, remove: 0, signed: false }); s.lines++; if (x.decision) s.decided++; if (x.decision === 'keep') s.keep++; if (x.decision === 'remove') s.remove++; } return Object.values(m); };
    const reviewers = by('reviewer').map((r) => Object.assign(r, { signed: !!(c.attestations || []).find((a) => same(a.by, r.name)) }));
    const counts = { lines: all.length, decided: all.filter((x) => x.decision).length, keep: all.filter((x) => x.decision === 'keep').length, remove: all.filter((x) => x.decision === 'remove').length,
      unassigned: all.filter((x) => !x.reviewer).length, removal_pending: all.filter((x) => x.state === 'removal_pending').length, removal_approved: all.filter((x) => x.state === 'removal_approved').length,
      removed: all.filter((x) => x.state === 'removed').length, removal_failed: all.filter((x) => x.state === 'removal_failed').length, reviewers: reviewers.length, signed: reviewers.filter((r) => r.signed).length,
      new_since_last: all.filter((x) => x.new_since_last).length, dormant: all.filter((x) => x.dormant).length, disabled: all.filter((x) => !x.enabled).length };
    return Object.assign({}, c, { counts, by_group: by('group'), by_reviewer: reviewers, overdue: c.status === 'open' && now() > Date.parse(c.due_at), statement: STATEMENT });
  }

  function list(who) {
    const c = cfg();
    const campaigns = camps().all(() => true).sort((a, b) => String(b.id).localeCompare(String(a.id))).map((x) => { const s = summary(x.id); return { id: s.id, quarter: s.quarter, status: s.status, started_at: s.started_at, due_at: s.due_at, overdue: s.overdue, counts: s.counts }; });
    const mine = itemsC().all((x) => same(x.reviewer, who.user) && !x.decision && (camps().get(x.campaign) || {}).status === 'open').length;
    return { campaigns, scope: c, current_quarter: quarterOf(now()), directory: { connected: connected(), auto_remove_possible: connected() }, mine_open: mine, statement: STATEMENT };
  }
  function items(id, q, who) {
    const c = getC(id);
    const f = body(q || {}).str('mine', { max: 1 }).str('group', { max: 128 }).oneOf('state', ['open', 'decided', 'remove', 'keep', 'kept', 'removal_pending', 'removal_approved', 'removed', 'removal_failed', 'unassigned'], {}).done();
    let all = lines(c.id);
    if (f.mine === '1') all = all.filter((x) => same(x.reviewer, who.user));
    if (f.group) all = all.filter((x) => same(x.group, f.group));
    if (f.state) all = all.filter((x) => (f.state === 'decided' ? !!x.decision : f.state === 'unassigned' ? !x.reviewer : ['keep', 'remove'].includes(f.state) ? x.decision === f.state : x.state === f.state));
    return { campaign: c.id, status: c.status, items: all.slice(0, 5000), total: all.length, signed: !!(c.attestations || []).find((a) => same(a.by, who.user)) };
  }

  const openCamp = (c) => { if (c.status !== 'open') throw httpErr(409, c.id + ' is ' + c.status); };
  function decide(id, input, who) {
    const c = getC(id); person(who, 'attest access'); openCamp(c);
    const b = body(input || {}).list('decisions', { required: true, max: 2000 }).done();
    if ((c.attestations || []).find((a) => same(a.by, who.user))) throw httpErr(409, 'you already signed this campaign - your lines are locked');
    const out = [];
    b.decisions.forEach((d, i) => {
      if (!d || typeof d !== 'object') throw httpErr(400, 'decisions[' + i + '] must be {item, decision, reason?}');
      const x = body(d).str('item', { required: true, max: 40, re: /^AR-\d{4}-Q[1-4]:\d{5}$/, msg: 'decisions[' + i + '].item is not a review line' }).oneOf('decision', ['keep', 'remove'], { required: true }).str('reason', { max: 300 }).done();
      const it = itemsC().get(x.item);
      if (!it || it.campaign !== c.id) throw httpErr(404, 'decisions[' + i + ']: no line ' + x.item + ' in ' + c.id);
      if (!same(it.reviewer, who.user)) throw httpErr(403, 'decisions[' + i + ']: ' + x.item + ' is reviewed by ' + (it.reviewer || 'nobody yet') + ', not you');
      if (same(it.user, who.user)) throw httpErr(403, 'decisions[' + i + ']: you cannot attest your own access');
      if (x.decision === 'remove' && !(x.reason && x.reason.length >= 3)) throw httpErr(400, 'decisions[' + i + '].reason is required to remove access: say why it is no longer needed');
      if (x.decision === 'keep' && (!it.enabled || it.dormant) && !(x.reason && x.reason.length >= 3)) throw httpErr(400, 'decisions[' + i + '].reason is required to keep a ' + (!it.enabled ? 'disabled' : 'dormant (no sign-in for ' + DORMANT_DAYS + ' days)') + ' account in ' + it.group);
      if (x.reason && SECRETISH.test(x.reason)) throw httpErr(400, 'decisions[' + i + '].reason looks like it contains a password');
      out.push([it, x]);
    });
    for (const [it, x] of out) { Object.assign(it, { decision: x.decision, reason: x.reason || '', decided_by: who.user, decided_at: iso(), state: 'decided' }); itemsC().put(it); }
    audit(who, 'access-reviews.decide', c.id, { lines: out.length, keep: out.filter(([, x]) => x.decision === 'keep').length, remove: out.filter(([, x]) => x.decision === 'remove').map(([it]) => it.group + ':' + it.user) });
    return items(c.id, { mine: '1' }, who);
  }
  function sign(id, input, who) {
    const c = getC(id); person(who, 'sign an attestation'); openCamp(c);
    const b = body(input || {}).bool('statement', { required: true }).rule((o) => (o.statement !== true ? 'statement must be true: you confirm the attestation text' : null)).done();
    if ((c.attestations || []).find((a) => same(a.by, who.user))) throw httpErr(409, 'already signed');
    const mine = lines(c.id, (x) => same(x.reviewer, who.user));
    if (!mine.length) throw httpErr(409, 'no line in ' + c.id + ' is assigned to you');
    const open = mine.filter((x) => !x.decision); if (open.length) throw httpErr(409, open.length + ' of your lines are not decided yet');
    const rec = { by: who.user, role: who.role, at: iso(), statement: STATEMENT, accepted: b.statement, lines: mine.length, keep: mine.filter((x) => x.decision === 'keep').length, remove: mine.filter((x) => x.decision === 'remove').length };
    c.attestations = (c.attestations || []).concat([rec]);
    for (const it of mine) { if (it.decision === 'remove') it.state = 'removal_pending'; else it.state = 'kept'; it.signed_at = rec.at; itemsC().put(it); }
    camps().put(c);
    audit(who, 'access-reviews.attest', c.id, { lines: rec.lines, keep: rec.keep, remove: rec.remove });
    return summary(c.id);
  }
  function reassign(id, input, who) {
    const c = getC(id); person(who, 'reassign review lines'); openCamp(c);
    const b = body(input || {}).list('items', { required: true, max: 2000, item: 'str', itemMax: 40, unique: true }).str('reviewer', { required: true, max: 80, re: USERNAME, msg: 'reviewer must be a platform user name' })
      .str('reason', { required: true, min: 5, max: 300 }).done();
    if (isService(b.reviewer)) throw httpErr(400, 'reviewer must be a person');
    const its = b.items.map((k, i) => { const it = itemsC().get(k); if (!it || it.campaign !== c.id) throw httpErr(404, 'items[' + i + ']: no line ' + k); if (it.state !== 'open' && it.state !== 'decided') throw httpErr(409, 'items[' + i + ']: ' + k + ' is already signed'); if (same(it.user, b.reviewer)) throw httpErr(400, 'items[' + i + ']: ' + b.reviewer + ' cannot review their own access'); return it; });
    for (const it of its) { Object.assign(it, { reviewer: b.reviewer.toLowerCase(), reviewer_source: 'reassigned by ' + who.user, decision: null, reason: '', decided_by: null, state: 'open' }); itemsC().put(it); }
    audit(who, 'access-reviews.reassign', c.id, { lines: its.length, reviewer: b.reviewer, reason: b.reason });
    return summary(c.id);
  }

  // ---- removals: four eyes, then the directory (or by hand)
  async function removalsDecide(id, input, who) {
    const c = getC(id); person(who, 'approve access removals');
    const b = body(input || {}).list('items', { required: true, max: 2000, item: 'str', itemMax: 40, unique: true }).oneOf('decision', ['approve', 'reject'], { required: true }).str('note', { max: 300 })
      .rule((o) => (o.decision === 'reject' && !o.note ? 'note is required: say why the access stays' : null)).done();
    const its = b.items.map((k, i) => {
      const it = itemsC().get(k); if (!it || it.campaign !== c.id) throw httpErr(404, 'items[' + i + ']: no line ' + k);
      if (it.state !== 'removal_pending') throw httpErr(409, 'items[' + i + ']: ' + k + ' is ' + it.state + ' - only a signed "remove" waits for approval');
      if (same(it.decided_by, who.user)) throw httpErr(403, 'four eyes: ' + who.user + ' asked to remove ' + it.user + ' from ' + it.group + ' and cannot also approve it');
      if (same(it.user, who.user)) throw httpErr(403, 'items[' + i + ']: that is your own access');
      return it;
    });
    let removed = 0, manual = 0, failed = 0;
    for (const it of its) {
      it.removal = { decision: b.decision, by: who.user, at: iso(), note: b.note || '' };
      if (b.decision === 'reject') { it.state = 'kept'; it.kept_by_exception = true; itemsC().put(it); continue; }
      const reason = it.privileged_group ? 'privileged group' : it.privileged_account ? 'privileged account' : neverChange().some((x) => same(x, it.user)) ? 'on the never-change list' : !(c.auto_remove && connected()) ? 'automatic removal is off' : null;
      if (reason) { it.state = 'removal_approved'; it.manual_reason = reason + ' - a domain administrator removes it by hand and records it'; manual++; itemsC().put(it); continue; }
      try {
        const W = AD().writer();
        await W.removeFromGroup(it.group_dn, it.user_dn);
        const v = await W.groupMembers(it.group_dn);
        if (v && v.members.some((m) => same(m.sam, it.user))) throw new Error('read back: still a member');
        Object.assign(it, { state: 'removed', removed_at: iso(), removed_by: SYSTEM.user, error: null }); removed++;
        audit(SYSTEM, 'access-reviews.removed', c.id, { group: it.group, user: it.user, approved_by: who.user, asked_by: it.decided_by });
      } catch (e) {
        Object.assign(it, { state: 'removal_failed', error: String(e.message).slice(0, 200) }); failed++;
        warn('remove', 'access reviews: a membership could not be removed', { group: it.group, err: it.error });
      }
      itemsC().put(it);
    }
    audit(who, 'access-reviews.removals.' + b.decision, c.id, { lines: its.length, removed, manual, failed, note: b.note || null });
    return Object.assign(summary(c.id), { result: { removed, manual, failed } });
  }
  function removalsDone(id, input, who) {
    const c = getC(id); person(who, 'record a removal');
    const b = body(input || {}).list('items', { required: true, max: 2000, item: 'str', itemMax: 40, unique: true }).str('directory_ref', { required: true, min: 3, max: 300 }).done();
    if (SECRETISH.test(b.directory_ref)) throw httpErr(400, 'directory_ref looks like it contains a password');
    const its = b.items.map((k, i) => { const it = itemsC().get(k); if (!it || it.campaign !== c.id) throw httpErr(404, 'items[' + i + ']: no line ' + k); if (!['removal_approved', 'removal_failed'].includes(it.state)) throw httpErr(409, 'items[' + i + ']: ' + k + ' is ' + it.state + ' - only an approved removal is recorded'); if (same(it.user, who.user)) throw httpErr(403, 'items[' + i + ']: that is your own access'); return it; });
    for (const it of its) { Object.assign(it, { state: 'removed', removed_at: iso(), removed_by: who.user, manual: true, directory_ref: b.directory_ref, error: null }); itemsC().put(it); }
    audit(who, 'access-reviews.removed.manual', c.id, { lines: its.length, directory_ref: b.directory_ref, removed: its.map((it) => it.group + ':' + it.user) });
    return summary(c.id);
  }

  async function remind(id, who, quiet) {
    const c = getC(id); if (who !== SYSTEM) person(who, 'send reminders'); openCamp(c);
    const N = app.addons && app.addons.privacyOffice && app.addons.privacyOffice.notifier;
    if (!N || typeof N.sendPlatform !== 'function') { if (quiet) return { sent: 0 }; throw httpErr(409, 'no mail relay - set it in Privacy Office -> Notifications'); }
    const open = {}; for (const x of lines(c.id, (y) => y.reviewer && !y.decision)) open[x.reviewer] = (open[x.reviewer] || 0) + 1;
    let sent = 0, skipped = null;
    const week = Math.floor(now() / (7 * DAY));
    for (const [rv, n] of Object.entries(open)) {
      const r = await N.sendPlatform({ key: 'access-review|' + c.id + '|' + rv + '|' + (quiet ? 'start' : who === SYSTEM ? 'w' + week : iso()), event: 'access-review', users: [rv], from_name: (ZYB_ORG.short + ' access reviews'),
        subject: 'Access review ' + c.quarter + ': ' + n + ' membership(s) waiting for you' + (now() > Date.parse(c.due_at) ? ' (overdue)' : ''),
        text: 'Please review the Active Directory group memberships of the people you manage: ' + n + ' line(s) in campaign ' + c.id + ', due ' + c.due_at.slice(0, 10) + '.\n\nIdentity & Microsoft 365 -> Access Reviews -> My reviews. Mark each line keep or remove, then sign the attestation.' });
      if (r.status === 'sent' || r.status === 'duplicate') sent++; else if (r.status === 'skipped') skipped = r.error || 'not sent';
    }
    if (sent) audit(who, 'access-reviews.remind', c.id, { reviewers: sent });
    return Object.assign({ sent, reviewers: Object.keys(open).length }, skipped && !sent ? { note: skipped } : {});
  }

  function close(id, input, who) {
    const c = getC(id); person(who, 'close a campaign'); openCamp(c);
    const b = body(input || {}).str('note', { max: 500 }).done();
    const all = lines(c.id);
    const exceptions = { not_decided: all.filter((x) => !x.decision).length, not_signed: all.filter((x) => x.state === 'decided').length,
      removal_not_approved: all.filter((x) => x.state === 'removal_pending').length, removal_not_done: all.filter((x) => ['removal_approved', 'removal_failed'].includes(x.state)).length };
    Object.assign(c, { status: 'closed', closed_by: who.user, closed_at: iso(), close_note: b.note || '', exceptions });
    camps().put(c);
    audit(who, 'access-reviews.close', c.id, exceptions);
    return summary(c.id);
  }

  function exportCsv(id, who) {
    const c = getC(id), all = lines(c.id);
    const q = (s) => { const t = String(s == null ? '' : s); return /^[=+\-@\t\r]/.test(t) ? "'" + t : t; };
    const cell = (s) => '"' + q(s).replace(/"/g, '""') + '"';
    const out = [['Campaign', 'Group', 'Privileged group', 'User', 'Name', 'Employee', 'Enabled', 'Last sign-in', 'Dormant', 'New since last quarter', 'Manager', 'Reviewer', 'Reviewer source', 'Decision', 'Reason', 'Decided by', 'Decided at', 'Signed at', 'State', 'Removal approved by', 'Removed at', 'Removed by', 'Reference'].map(cell).join(',')];
    for (const x of all) out.push([c.id, x.group, x.privileged_group ? 'yes' : 'no', x.user, x.display_name, x.employee_id, x.enabled ? 'yes' : 'no', x.last_logon || '', x.dormant ? 'yes' : 'no', x.new_since_last === null ? '' : x.new_since_last ? 'yes' : 'no',
      x.manager || '', x.reviewer || '', x.reviewer_source, x.decision || '', x.reason || '', x.decided_by || '', x.decided_at || '', x.signed_at || '', x.state, x.removal ? x.removal.by : '', x.removed_at || '', x.removed_by || '', x.directory_ref || ''].map(cell).join(','));
    for (const a of c.attestations || []) out.push(['', '', '', '', '', '', '', '', '', '', '', a.by, 'attestation', '', a.statement, a.by, a.at, a.at, 'signed', '', '', '', ''].map(cell).join(','));
    audit(who, 'access-reviews.export', c.id, { lines: all.length });
    return { filename: 'access-review-' + c.id + '.csv', csv: out.join('\r\n') };
  }

  // the first day of a quarter: start the campaign when auto_start is on; weekly reminders to reviewers with open lines
  async function tick() {
    const c = cfg(), q = quarterOf(now());
    if (c.auto_start && c.groups.length && connected() && !camps().get('AR-' + q)) {
      try { await start({ quarter: q }, SYSTEM); } catch (e) { warn('auto', 'access reviews: the quarterly campaign could not start', { err: String(e.message).slice(0, 200) }); }
    }
    for (const x of camps().all((y) => y.status === 'open')) await remind(x.id, SYSTEM, false).catch((e) => warn('remind', 'access reviews: reminders not sent', { err: String(e.message).slice(0, 160) }));
  }
  if (!(app.noTimers || opts.noTimer)) { const t = setInterval(guardOf(app, 'access-reviews.tick', tick), 6 * 3600000); if (t.unref) t.unref(); }

  return { list, configure, start, summary, items, decide, sign, reassign, removalsDecide, removalsDone, remind, close, exportCsv, tick, STATEMENT };
}

function registerAccessReviews(srv, app, R) {
  const C = (ctx) => ctx.params.id;
  srv.route('GET', '/access-reviews', (ctx) => { ctx.need('operator'); return R.list(ctx.who); });
  srv.route('POST', '/access-reviews/config', (ctx) => { ctx.need('admin'); return R.configure(ctx.body, ctx.who); });
  srv.route('POST', '/access-reviews', (ctx) => { ctx.need('admin'); return R.start(ctx.body, ctx.who); });
  srv.route('GET', '/access-reviews/:id', (ctx) => { ctx.need('operator'); return R.summary(C(ctx)); });
  srv.route('GET', '/access-reviews/:id/items', (ctx) => { ctx.need('operator'); return R.items(C(ctx), ctx.query, ctx.who); });
  srv.route('GET', '/access-reviews/:id/export', (ctx) => { ctx.need('operator'); return R.exportCsv(C(ctx), ctx.who); });
  srv.route('POST', '/access-reviews/:id/decide', (ctx) => { ctx.need('operator'); return R.decide(C(ctx), ctx.body, ctx.who); });
  srv.route('POST', '/access-reviews/:id/sign', (ctx) => { ctx.need('operator'); return R.sign(C(ctx), ctx.body, ctx.who); });
  srv.route('POST', '/access-reviews/:id/reassign', (ctx) => { ctx.need('admin'); return R.reassign(C(ctx), ctx.body, ctx.who); });
  srv.route('POST', '/access-reviews/:id/removals/decide', (ctx) => { ctx.need('admin'); return R.removalsDecide(C(ctx), ctx.body, ctx.who); });
  srv.route('POST', '/access-reviews/:id/removals/done', (ctx) => { ctx.need('operator'); return R.removalsDone(C(ctx), ctx.body, ctx.who); });
  srv.route('POST', '/access-reviews/:id/remind', (ctx) => { ctx.need('admin'); body(ctx.body).done(); return R.remind(C(ctx), ctx.who, false); });
  srv.route('POST', '/access-reviews/:id/close', (ctx) => { ctx.need('admin'); return R.close(C(ctx), ctx.body, ctx.who); });
}

module.exports = { createAccessReviews, registerAccessReviews, quarterOf };
