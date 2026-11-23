// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * The Privacy Office: PDPL run as its own organisation with its own workflow, apart from IT and GRC work. The rules are
 * Python (pyengine/pdpl_office.py): who the organisation is, where each PDPL finding is routed, deadlines, escalation,
 * recurring duties and the route map. This file validates, decides who may act, stores the tasks and writes the audit.
 *
 *   Organisation  the DPO (PDPL profile), the owner of each PDPL function (Governance), each department's data steward,
 *                 deputy and privacy champion (Programme), plus what the office keeps here: the privacy committee (chair,
 *                 members), the DPO's deputy and the data owner of each system.
 *   Tasks         every finding the PDPL registers raise, and every recurring duty that falls due, is one task routed to a
 *                 named person, with a deadline by severity. Overdue -> the DPO; overdue for longer -> the committee chair.
 *                 "Done" is a claim: the task closes only when the registers no longer show the finding. A risk is accepted
 *                 only by a committee member who is not the assignee, with a reason and an end date (12 months at most).
 *   Re-test       a task marked done is re-checked against the registers on every routing run (every 30 minutes): gone ->
 *                 closed "verified by re-test" with the evidence (which check, when, how many re-checks); still shown
 *                 verify_days (default 3) after the claim -> reopened, the assignee told, escalated to the DPO (level 1 of
 *                 the existing escalation; the committee chair follows when it stays overdue). task.verification holds the state:
 *                 checking | verified | failed.
 *   Route map     the implementation phase by phase, then maintenance, each step read from the registers.
 *
 *   GET  /pdpl/office                    operator  organisation, all tasks, calendar, gaps, route map
 *   GET  /pdpl/office/mine               viewer    my tasks (a data steward may hold the viewer role) + the route map
 *   POST /pdpl/office/config             admin or the DPO  {committee{chair, members[]}, dpo_deputy, owners[], sla_days{}, escalate_days, verify_days}  audited
 *   POST /pdpl/office/run                operator  route now (also every 30 minutes)                          audited
 *   POST /pdpl/office/tasks/:id/ack      the assignee, the DPO or an operator                                  audited
 *   POST /pdpl/office/tasks/:id/done     the assignee, the DPO or an operator  {note}  -> claimed until the registers confirm   audited
 *   POST /pdpl/office/tasks/:id/reassign the DPO or an admin  {user, reason, due?}                             audited
 *   POST /pdpl/office/tasks/:id/accept-risk  a committee member (or the chair) who is not the assignee  {reason, until}       audited
 *   e-mail and Teams notifications, contacts and their settings: engine/pdpl-notify.js
 */
const { guardOf } = require('./errors');
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const isService = (u) => /^(duty|system|ai|svc|service)[:_-]/i.test(String(u || ''));
const low = (v) => String(v || '').trim().toLowerCase();
const SYS = { user: 'system:privacy-office', role: 'system', ip: '' };
const EVERY = 30 * 60000, DAY = 86400000, VERIFY_DAYS = 3;

function createPrivacyOffice(app, PD, opts = {}) {
  const now = opts.now || Date.now, store = app.store;
  const py = opts.py || require('./pyengine').createPyEngine({ python: opts.python || ((app.config && app.config.discovery) || {}).python_bin || '/opt/sentra-siem/pyenv/bin/python3', timeoutMs: 30000, resident: false });
  const tasksC = () => store.collection('pdpl_office_tasks'), cfgC = () => store.collection('pdpl_office_cfg');
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role, ip: who.ip || '', action, target, detail }); };
  const iso = () => new Date(now()).toISOString();
  const cfg = () => cfgC().get('cfg') || { id: 'cfg' };
  const dpo = () => (PD.records('profile')[0] || {}).dpo_user || null;
  const isDpo = (who) => !!dpo() && low(dpo()) === low(who.user);
  let last = null;
  // e-mail / Teams (engine/pdpl-notify.js): optional - an update that did not install it leaves the office working, in-app only
  let N = opts.notifier || null;
  if (!N) { try { N = require('./pdpl-notify').createNotifier(app, { now, sealer: opts.sealer, send: opts.send, teams: opts.teams }); } catch (e) { if (e.code !== 'MODULE_NOT_FOUND') throw e; N = null; } }
  const notifyWarn = (what, e) => { if (app.log && app.log.every) app.log.every('pdpl-office:notify:' + what, 3600000, 'warn', 'Privacy Office notifications: ' + what + ' failed', { err: String(e.message).slice(0, 200) }); };

  async function plan() {
    let findings = [];
    try { findings = (await PD.adapter.findings()) || []; } catch (e) { throw httpErr(409, 'the PDPL registers could not be read (' + String(e.message).slice(0, 160) + ')'); }
    const scans = store.collection('pdpl_discovery').all((x) => x.id !== '_last');
    let camps = []; try { camps = PD.ropaCampaigns ? store.collection('pdpl_ropa_campaigns').all().map((c) => ({ name: c.name, departments: Object.keys(c.departments || {}).length, approved: Object.values(c.departments || {}).filter((d) => d.status === 'approved').length })) : []; } catch (e) { camps = []; /* campaigns not installed: the route map shows the step as not started */ }
    let srcs = 0; try { srcs = store.collection('pdpl_access_keys').all((k) => !k.revoked_at).length; } catch (e) { srcs = 0; /* access log not installed */ }
    const st = store.collection('pdpl_statement').get('statement');
    const signed = st && st.management && st.management.at && now() - Date.parse(st.management.at) <= 365 * 86400000 ? String(st.management.at).slice(0, 10) : null;
    const r = await py.call('pdpl.office_plan', { findings, records: PD.records(), tasks: tasksC().all(), cfg: cfg(), now: now(),
      extra: { scans: scans.length, scans_ok: scans.filter((s) => s.ok).length, campaigns: camps, access_sources: srcs, statement_signed: signed } });
    if (!r || r.ok === false) throw httpErr(409, 'The Privacy Office rules run in Python and Python did not answer (' + ((r && r.error_class) || 'no answer') + ') - run the update so pyengine is installed');
    return r;
  }
  // the re-test of a claim: which check of the registers decides it
  const verifyDays = () => Number(cfg().verify_days) || VERIFY_DAYS;
  function checkOf(t) {
    const tg = t.target || {}, k = String(t.key || '').replace(/^f:/, '');
    return (t.source === 'duty' ? 'recurring duty ' : 'PDPL register check ') + k + (t.requirement ? ' (' + t.requirement + ')' : '') + (tg.name ? ' on ' + (tg.type ? tg.type + ' ' : '') + '"' + String(tg.name).slice(0, 120) + '"' : '');
  }
  // every claimed task is re-checked on every run; returns the tasks whose claim failed (the assignee is told)
  function verify(r) {
    const days = verifyDays(), at = iso(), failed = [];
    const closedNow = new Set(r.events.filter((e) => e.event === 'closed' && e.detail && e.detail.was === 'claimed').map((e) => e.key));
    for (const t of r.tasks) {
      if (t.status === 'claimed') {
        const v = t.verification && t.verification.claim_at === t.claimed_at ? Object.assign({}, t.verification) : { claim_at: t.claimed_at, claimed_by: t.claimed_by, runs: 0, first_check_at: at };
        Object.assign(v, { state: 'checking', check: checkOf(t), runs: (v.runs || 0) + 1, last_check_at: at, last_result: 'the registers still show it', days, deadline: new Date((Date.parse(t.claimed_at) || now()) + days * DAY).toISOString() });
        if (now() >= Date.parse(v.deadline)) {
          Object.assign(v, { state: 'failed', failed_at: at });
          t.status = 'open';
          t.history = (t.history || []).concat([{ at, by: SYS.user, what: 'verification failed: the registers still show it ' + days + ' day(s) after ' + t.claimed_by + ' marked it done (' + v.runs + ' re-check(s): ' + v.check + ') - reopened' }]);
          r.events.push({ event: 'verify_failed', key: t.key, assignee: t.assignee, detail: { claimed_by: t.claimed_by, runs: v.runs, days, check: v.check } });
          if (!(t.escalation > 0)) {   // the existing escalation, level 1: the DPO (the chair follows if it stays overdue)
            const to = (r.org && r.org.dpo) || null;
            t.escalation = 1; t.escalated_to = to; t.history.push({ at, by: SYS.user, what: 'verification failed - escalated to the DPO ' + (to || '(not named)') });
            r.events.push({ event: 'escalated', key: t.key, assignee: t.assignee, detail: { level: 1, to, why: 'verification failed' } });
          }
          failed.push(t);
        }
        t.verification = v;
      } else if (t.status === 'closed' && closedNow.has(t.key)) {
        const v = Object.assign({ claim_at: t.claimed_at, claimed_by: t.claimed_by, runs: 0 }, t.verification || {});
        const ev = 'verified by re-test: ' + checkOf(t) + ' is no longer raised by the PDPL registers at ' + at + ' (' + ((v.runs || 0) + 1) + ' re-check(s) since the claim of ' + String(v.claim_at || '').slice(0, 16) + ')';
        Object.assign(v, { state: 'verified', check: checkOf(t), runs: (v.runs || 0) + 1, last_check_at: at, last_result: 'the registers no longer show it', verified_at: at, evidence: ev });
        t.verification = v; t.closed_reason = 'verified by re-test';
        const h = (t.history || []).slice(), last = h[h.length - 1];
        if (last && /^closed - /.test(last.what)) h[h.length - 1] = Object.assign({}, last, { what: last.what + ' - ' + ev }); else h.push({ at, by: SYS.user, what: ev });
        t.history = h;
        r.events.push({ event: 'verified', key: t.key, assignee: t.assignee, detail: { claimed_by: v.claimed_by || null, runs: v.runs, check: v.check } });
      }
    }
    return failed;
  }
  // route: store what the rules decided, give new tasks an id, re-test the claims, audit every event the run produced
  async function run(who) {
    const r = await plan();
    let n = tasksC().size() + 1;
    for (const t of r.tasks) {
      if (!t.id) { let id = 'PO-' + String(n).padStart(5, '0'); while (tasksC().get(id)) id = 'PO-' + String(++n).padStart(5, '0'); t.id = id; n++; }
    }
    const failed = verify(r);
    for (const t of r.tasks) tasksC().put(t);
    const byKey = new Map(r.tasks.map((t) => [t.key, t.id]));
    for (const e of r.events) audit(who, 'pdpl.office.' + e.event, byKey.get(e.key) || e.key, Object.assign({ assignee: e.assignee || null }, e.detail));
    if (who !== SYS) audit(who, 'pdpl.office.run', 'office', { tasks: r.tasks.filter((t) => t.status !== 'closed').length, events: r.events.length });
    last = { at: iso(), r };
    // telling people is best effort: a mail relay that is down never stops the routing (the outbox keeps the retry)
    if (N) { try { r.notified = (await N.onEvents(r.events, r.tasks, r.org)).queued; } catch (e) { notifyWarn('events', e); } }
    // the assignee is told their "done" was not confirmed (once per claim; in-app the task shows it either way)
    if (N && typeof N.sendPlatform === 'function') for (const t of failed) {
      try { await N.sendPlatform({ key: 'verify|' + t.id + '|' + String(t.verification.claim_at), event: 'verify_failed', users: [...new Set([t.assignee, t.claimed_by].filter(Boolean))],
        subject: 'Privacy Office task ' + t.id + ' is open again: the registers still show it', text: 'Task ' + t.id + ' - ' + String(t.title || '').slice(0, 300) + '\n\nIt was marked done on ' + String(t.claimed_at).slice(0, 10) + ', but ' + t.verification.check + ' still shows it after ' + t.verification.days + ' day(s) (' + t.verification.runs + ' re-checks). It is open again and escalated to the DPO. Fix it in the register; it closes on the next re-check.' }); } catch (e) { notifyWarn('verify', e); }
    }
    return r;
  }
  const strip = (r) => ({ org: r.org, gaps: r.gaps, gaps_ar: r.gaps_ar, calendar: r.calendar, roadmap: r.roadmap, sla_days: r.sla_days, escalate_days: r.escalate_days });
  async function view(who) {
    const r = await plan();
    const t = tasksC().all().sort((a, b) => (a.status === 'closed') - (b.status === 'closed') || String(a.due).localeCompare(String(b.due)));
    return Object.assign(strip(r), { tasks: t, last_run: last && last.at, me: who.user, is_dpo: isDpo(who), can_configure: who.role === 'admin' || isDpo(who), verify_days: verifyDays(),
      totals: { open: t.filter((x) => x.status !== 'closed').length, overdue: t.filter((x) => x.overdue).length, escalated: t.filter((x) => x.status !== 'closed' && x.escalation).length,
        claimed: t.filter((x) => x.status === 'claimed').length, verified: t.filter((x) => x.verification && x.verification.state === 'verified').length,
        verify_failed: t.filter((x) => x.status !== 'closed' && x.verification && x.verification.state === 'failed').length, accepted: t.filter((x) => x.status === 'risk_accepted').length, unassigned: t.filter((x) => x.status !== 'closed' && !x.assignee).length } });
  }
  async function mine(who) {
    const r = await plan();
    const t = tasksC().all((x) => x.status !== 'closed' && (low(x.assignee) === low(who.user) || low(x.escalated_to) === low(who.user)));
    return { tasks: t.sort((a, b) => String(a.due).localeCompare(String(b.due))), roadmap: r.roadmap, me: who.user,
      roles: rolesOf(r.org, who.user), maintain: r.roadmap.maintain };
  }
  function rolesOf(org, u) {
    const out = [];
    if (low(org.dpo) === low(u)) out.push('DPO');
    if (low(org.dpo_deputy) === low(u)) out.push('Deputy DPO');
    if (low(org.committee.chair) === low(u)) out.push('Privacy committee chair');
    if ((org.committee.members || []).some((m) => low(m) === low(u))) out.push('Privacy committee member');
    for (const f of org.functions) { if (low(f.user) === low(u)) out.push('Owner: ' + f.label); if (low(f.deputy) === low(u)) out.push('Deputy: ' + f.label); }
    for (const d of org.departments) for (const k of ['data_steward', 'deputy', 'champion']) if (low(d[k]) === low(u)) out.push(k.replace('_', ' ') + ' - ' + d.department);
    for (const o of org.owners || []) if (low(o.user) === low(u)) out.push('Data owner - ' + o.system);
    return out;
  }
  function task(id) { const t = tasksC().get(id); if (!t) throw httpErr(404, 'no Privacy Office task ' + id); if (t.status === 'closed') throw httpErr(409, id + ' is closed'); return t; }
  const person = (who, what) => { if (isService(who.user)) throw httpErr(403, 'a person ' + what + ', not a service or AI identity'); };
  function mayWork(t, who) {
    person(who, 'works a PDPL task');
    if (low(t.assignee) === low(who.user) || isDpo(who) || who.role === 'operator' || who.role === 'admin') return;
    throw httpErr(403, 'only the assignee (' + (t.assignee || 'nobody') + '), the DPO or an operator works ' + t.id);
  }
  const hist = (t, who, what) => (t.history || []).concat([{ at: iso(), by: who.user, what }]);
  function ack(id, who) {
    const t = task(id); mayWork(t, who);
    const rec = Object.assign({}, t, { status: t.status === 'open' ? 'acknowledged' : t.status, acked_by: who.user, acked_at: iso(), history: hist(t, who, 'acknowledged') });
    tasksC().put(rec); audit(who, 'pdpl.office.ack', id, { key: t.key }); return rec;
  }
  function done(id, b, who) {
    const t = task(id); mayWork(t, who);
    if (t.status === 'risk_accepted') throw httpErr(409, id + ' is under an accepted risk until ' + t.risk_until);
    const at = iso(), days = verifyDays();
    const rec = Object.assign({}, t, { status: 'claimed', claimed_by: who.user, claimed_at: at, claim_note: b.note, history: hist(t, who, 'marked done: ' + b.note + ' - stays open until the registers confirm it'),
      verification: { state: 'checking', claim_at: at, claimed_by: who.user, runs: 0, check: checkOf(t), days, deadline: new Date(now() + days * DAY).toISOString(), last_result: 'waiting for the next re-check (every 30 minutes)' } });
    tasksC().put(rec); audit(who, 'pdpl.office.claim', id, { key: t.key, note: b.note.slice(0, 200) }); return rec;
  }
  function reassign(id, b, who) {
    const t = task(id); person(who, 'reassigns a PDPL task');
    if (!isDpo(who) && who.role !== 'admin') throw httpErr(403, 'the DPO (' + (dpo() || 'not named') + ') or an administrator reassigns PDPL tasks');
    if (isService(b.user)) throw httpErr(400, 'user: a task goes to a person, not a service or AI identity');
    const rec = Object.assign({}, t, { assignee: b.user, assigned_by: who.user, why: 'assigned by ' + who.user + ': ' + b.reason, history: hist(t, who, 'reassigned from ' + (t.assignee || 'nobody') + ' to ' + b.user + ': ' + b.reason) });
    if (b.due) { rec.due_override = b.due; rec.history = hist(rec, who, 'deadline set to ' + b.due); }
    if (low(rec.status) === 'claimed') { rec.status = 'open'; if (rec.verification && rec.verification.state === 'checking') rec.verification = Object.assign({}, rec.verification, { state: 'withdrawn', last_result: 'reassigned before a re-check confirmed it' }); }
    tasksC().put(rec); audit(who, 'pdpl.office.reassign', id, { from: t.assignee || null, to: b.user, due: b.due || null, reason: b.reason.slice(0, 200) }); return rec;
  }
  function acceptRisk(id, b, who) {
    const t = task(id); person(who, 'accepts a PDPL risk');
    const c = cfg().committee || {};
    const onCommittee = low(c.chair) === low(who.user) || (c.members || []).some((m) => low(m) === low(who.user));
    if (!onCommittee) throw httpErr(403, 'only a member of the privacy committee accepts a PDPL risk (set the committee on the Privacy Office page)');
    if (low(t.assignee) === low(who.user)) throw httpErr(403, 'four-eyes: the assignee of ' + id + ' cannot accept its risk');
    if (t.severity === 'critical') throw httpErr(409, 'a critical finding is fixed, not accepted');
    const until = Date.parse(b.until + 'T00:00:00Z');
    if (!(until > now()) || until - now() > 366 * 86400000) throw httpErr(400, 'until must be a date in the next 12 months');
    const rec = Object.assign({}, t, { status: 'risk_accepted', risk_by: who.user, risk_reason: b.reason, risk_until: b.until, escalation: 0, overdue: false, history: hist(t, who, 'risk accepted until ' + b.until + ': ' + b.reason) });
    tasksC().put(rec); audit(who, 'pdpl.office.accept_risk', id, { key: t.key, until: b.until, severity: t.severity, reason: b.reason.slice(0, 200) }); return rec;
  }
  function configure(b, who) {
    person(who, 'sets up the privacy office');
    if (who.role !== 'admin' && !isDpo(who)) throw httpErr(403, 'an administrator or the DPO (' + (dpo() || 'not named') + ') sets up the privacy office');
    const cur = cfg(), rec = Object.assign({}, cur);
    for (const k of ['committee', 'dpo_deputy', 'owners', 'sla_days', 'escalate_days', 'verify_days']) if (b[k] !== undefined) rec[k] = b[k];
    const ppl = [].concat(rec.committee ? [rec.committee.chair].concat(rec.committee.members || []) : [], [rec.dpo_deputy], (rec.owners || []).map((o) => o.user)).filter(Boolean);
    if (ppl.some(isService)) throw httpErr(400, 'the privacy office is people: a service or AI identity cannot hold a role');
    rec.updated_by = who.user; rec.updated_at = iso();
    cfgC().put(rec);
    audit(who, 'pdpl.office.config', 'office', { changed: Object.keys(b).sort(), chair: rec.committee ? rec.committee.chair || null : null, members: rec.committee ? (rec.committee.members || []).length : 0, owners: (rec.owners || []).length, sla_days: rec.sla_days || null, escalate_days: rec.escalate_days || null, verify_days: rec.verify_days || null });
    return rec;
  }
  function start() {
    const tick = guardOf(app, 'pdpl.office.route', async () => {
      await run(SYS);
      if (N) { try { await N.digest(tasksC().all()); await N.retry(); } catch (e) { notifyWarn('digest', e); } }
    });
    const t1 = setTimeout(tick, 90000), t2 = setInterval(tick, EVERY);
    if (t1.unref) t1.unref(); if (t2.unref) t2.unref();
    return () => { clearTimeout(t1); clearInterval(t2); };
  }
  return { run, view, mine, ack, done, reassign, acceptRisk, configure, start, notifier: N, isDpo, digestNow: () => (N ? N.digest(tasksC().all(), true) : { sent: 0 }) };
}

function registerPrivacyOfficeRoutes(srv, app, PO) {
  const { body, param } = require('./check');
  const TID = (ctx) => { const id = param(ctx.params.id, 'id'); if (!/^PO-\d{5,}$/.test(id)) throw httpErr(400, 'id must be a Privacy Office task id (PO-nnnnn)'); return id; };
  const USER = { max: 80, re: /^[A-Za-z0-9._@-]+$/, msg: 'must be a platform user name' };
  srv.route('GET', '/pdpl/office', (ctx) => { ctx.need('operator'); return PO.view(ctx.who); });
  if (PO.notifier) require('./pdpl-notify').registerNotifyRoutes(srv, app, PO.notifier, PO.isDpo);
  srv.route('GET', '/pdpl/office/mine', (ctx) => { ctx.need('viewer'); return PO.mine(ctx.who); });
  srv.route('POST', '/pdpl/office/run', (ctx) => { ctx.need('operator'); return PO.run(ctx.who).then((r) => ({ tasks: r.tasks.filter((t) => t.status !== 'closed').length, events: r.events.length })); });
  srv.route('POST', '/pdpl/office/config', (ctx) => {
    ctx.need('operator');   // an administrator or the DPO - checked in configure
    const b = body(ctx.body).str('dpo_deputy', USER).int('escalate_days', { min: 1, max: 90 }).int('verify_days', { min: 1, max: 30 })
      .rule((o) => { const c = (ctx.body || {}).committee; if (c === undefined) return null; if (!c || typeof c !== 'object' || Array.isArray(c)) return 'committee must be {chair, members[]}';
        if (c.chair != null && !USER.re.test(String(c.chair))) return 'committee.chair ' + USER.msg; if (!Array.isArray(c.members || []) || (c.members || []).length > 20 || (c.members || []).some((m) => !USER.re.test(String(m)))) return 'committee.members must be up to 20 user names';
        o.committee = { chair: c.chair || null, members: [...new Set(c.members || [])] }; return null; })
      .rule((o) => { const w = (ctx.body || {}).owners; if (w === undefined) return null; if (!Array.isArray(w) || w.length > 300) return 'owners must be a list of {system, user} (300 at most)';
        if (w.some((x) => !x || typeof x.system !== 'string' || !x.system.trim() || x.system.length > 120 || !USER.re.test(String(x.user || '')))) return 'each owner needs {system (name), user (user name)}';
        o.owners = w.map((x) => ({ system: x.system.trim(), user: x.user })); return null; })
      .rule((o) => { const s = (ctx.body || {}).sla_days; if (s === undefined) return null; if (!s || typeof s !== 'object') return 'sla_days must be {critical, high, medium, low}';
        const out = {}; for (const k of Object.keys(s)) { if (!['critical', 'high', 'medium', 'low'].includes(k)) return 'sla_days: unknown severity ' + String(k).slice(0, 20); const v = Number(s[k]); if (!Number.isInteger(v) || v < 1 || v > 365) return 'sla_days.' + k + ' must be 1-365 days'; out[k] = v; }
        o.sla_days = out; return null; }).done();
    return PO.configure(b, ctx.who);
  });
  srv.route('POST', '/pdpl/office/tasks/:id/ack', (ctx) => { ctx.need('viewer'); return PO.ack(TID(ctx), ctx.who); },
    { anyRole: 'the assignee may be a data steward with the viewer role - checked in ack' });
  srv.route('POST', '/pdpl/office/tasks/:id/done', (ctx) => { ctx.need('viewer'); return PO.done(TID(ctx), body(ctx.body).str('note', { required: true, min: 10, max: 500 }).done(), ctx.who); },
    { anyRole: 'the assignee may be a data steward with the viewer role - checked in done; it is a claim the registers must confirm' });
  srv.route('POST', '/pdpl/office/tasks/:id/reassign', (ctx) => {
    ctx.need('operator');   // the DPO or an administrator - checked in reassign
    return PO.reassign(TID(ctx), body(ctx.body).str('user', Object.assign({ required: true }, USER)).str('reason', { required: true, min: 5, max: 300 })
      .str('due', { re: /^\d{4}-\d{2}-\d{2}$/, msg: 'due must be a date (YYYY-MM-DD)' }).done(), ctx.who);
  });
  srv.route('POST', '/pdpl/office/tasks/:id/accept-risk', (ctx) => {
    ctx.need('viewer');
    return PO.acceptRisk(TID(ctx), body(ctx.body).str('reason', { required: true, min: 20, max: 1000 }).str('until', { required: true, re: /^\d{4}-\d{2}-\d{2}$/, msg: 'until must be a date (YYYY-MM-DD)' }).done(), ctx.who);
  }, { anyRole: 'a privacy committee member may hold any role - checked in acceptRisk (committee, not the assignee)' });
}

module.exports = { createPrivacyOffice, registerPrivacyOfficeRoutes };
