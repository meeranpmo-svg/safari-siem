// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const { body, param } = require('./check');
const { isHuman } = require('./approve-scopes');
/*
 * Email 24/7 Availability programme (Email -> 24/7 Email Availability, {P} = /api/itam/mail-ops). One programme that keeps mail
 * available around the clock, from the start to the monthly report. It reads what the mail modules already measure (engine/
 * mail-reputation.js: availability against the target and its outages, the mail route, the early-warning alerts - certificates,
 * DNS, SPF, route issues, Exchange health from the SIEM - and the monthly mail reports) and keeps what only people can give,
 * each change approved by a second person:
 *   1 service & 24/7 on-call     the service owner, the escalation manager, at least two on-call engineers, RTO and RPO; the
 *                                availability target (Email Dashboard)
 *   2 mail path mapped           the route (MX, gateway, Exchange, egress) has been checked (Email Route Map)
 *   3 24/7 monitoring            the SMTP availability probe answered in the last 10 minutes; the early-warning check ran in the
 *                                last 2 hours with no monitoring gap (a source it could not read is a gap, never "fine")
 *   4 redundancy                 no high design gap (one MX host, one IP, one /24) and no open critical alert
 *   5 runbooks                   a runbook for each standard failure (MX / DNS, gateway down, queue backlog, database copy /
 *                                failover, certificate expiry, blacklisting, Internet link, hybrid connector, disk full), owner,
 *                                steps and escalation, approved by a different person, reviewed within 12 months
 *   6 maintenance windows        changes are planned: an approved window covering the next 90 days, with impact and rollback
 *   7 failover test              a failover / DR test in the last 6 months that passed within the RTO, approved by a different person
 *   8 post-incident reviews      every outage of the last 90 days has a review (root cause, actions, owner), approved
 *   9 monthly report             an approved mail availability report in the last 35 days (Email Dashboard -> Reports)
 * Nothing here changes a mail server, the gateway or DNS. Every write is audited; a service or AI identity records and approves
 * nothing.
 *   GET  /mail-ops                              operator  the programme: steps, readiness, runbooks, windows, tests, reviews
 *   POST /mail-ops/profile                      admin     {service_owner, escalation, oncall[], rto_min, rpo_min, notes?}      audited
 *   POST /mail-ops/runbooks/:key                operator  {owner, steps, escalation, tools?}  saves a draft                      audited
 *   POST /mail-ops/runbooks/:key/approve        operator  not the author                                                       audited
 *   POST /mail-ops/windows                      operator  {title, start, end, systems, impact, rollback}                         audited
 *   POST /mail-ops/windows/:id/approve          operator  not the requester                                                    audited
 *   POST /mail-ops/tests                        operator  {date, scenario, result, rto_achieved_min, evidence, notes?}           audited
 *   POST /mail-ops/tests/:id/approve            operator  not the recorder                                                     audited
 *   POST /mail-ops/reviews/:oid                 operator  {root_cause, actions, owner}  a review of one outage                   audited
 *   POST /mail-ops/reviews/:oid/approve         operator  not the author                                                       audited
 */
const DAY = 86400000;
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const same = (a, b) => !!a && String(a).trim().toLowerCase() === String(b || '').trim().toLowerCase();
const USER = /^[A-Za-z0-9._@\\-]{2,80}$/;
const DATE = /^\d{4}-\d{2}-\d{2}$/;
const DT = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/;
const STEPS = ['Service, target & 24/7 on-call', 'Mail path mapped', '24/7 monitoring', 'Redundancy', 'Runbooks', 'Maintenance windows', 'Failover test', 'Post-incident reviews', 'Monthly availability report'];
const RUNBOOKS = [
  ['mx-dns', 'MX / DNS failure (MX, SPF, DMARC records wrong or the DNS provider down)'],
  ['gateway-down', 'Email gateway down (Libraesva node not accepting mail)'],
  ['queue-backlog', 'Mail queue backlog (gateway or Exchange transport queues growing)'],
  ['db-failover', 'Exchange database copy failed / DAG failover'],
  ['cert-expiry', 'SMTP / Exchange certificate expired or about to expire'],
  ['blacklisted', 'Outbound IP blacklisted (Spamhaus and others) - mail rejected by recipients'],
  ['isp-link', 'Internet link down at the mail site'],
  ['hybrid-connector', 'Exchange Online hybrid connector failure'],
  ['disk-full', 'Mailbox or transport server disk full'],
];
const RESULTS = ['passed', 'passed_with_issues', 'failed'];
const human = (who, what) => { if (!isHuman(who.user)) throw httpErr(403, 'a person ' + what + ', not a service or AI identity'); };

function createMailOps(app, opts = {}) {
  const now = opts.now || Date.now, col = (n) => app.store.collection(n);
  const P = () => col('mailops'), RB = () => col('mailops_runbooks'), W = () => col('mailops_windows'), TS = () => col('mailops_tests'), RV = () => col('mailops_reviews');
  const iso = (t) => new Date(t == null ? now() : t).toISOString();
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role, ip: who.ip || '', action: 'mailops.' + action, target, detail }); };
  const M = () => (app.addons && app.addons.mailReputation) || null;
  const warn = (k, msg, er) => { if (app.log && app.log.every) app.log.every('mailops:' + k, 600000, 'warn', msg, { err: String((er && er.message) || er || '').slice(0, 200) }); };
  const profile = () => P().get('profile') || null;
  const nextId = (c, pre) => { const n = c().all().length + 1; let id = pre + '-' + String(n).padStart(4, '0'), k = n; while (c().get(id)) id = pre + '-' + String(++k).padStart(4, '0'); return id; };

  function putProfile(src, who) {
    human(who, 'sets the mail service owner and on-call');
    const b = body(src || {}).str('service_owner', { required: true, re: USER, msg: 'service_owner must be a user name' }).str('escalation', { required: true, re: USER, msg: 'escalation must be a user name' })
      .list('oncall', { required: true, max: 20, item: 'str', itemMax: 80, unique: true }).int('rto_min', { required: true, min: 1, max: 10080 }).int('rpo_min', { required: true, min: 0, max: 10080 }).str('notes', { max: 2000 }).done();
    for (const u of b.oncall) if (!USER.test(u)) throw httpErr(400, 'oncall: "' + String(u).slice(0, 40) + '" is not a user name');
    if (b.oncall.length < 2) throw httpErr(400, 'oncall: name at least two engineers - one person cannot cover 24/7');
    const rec = Object.assign({ id: 'profile' }, b, { by: who.user, at: iso() }); P().put(rec); audit(who, 'profile', 'profile', { service_owner: b.service_owner, escalation: b.escalation, oncall: b.oncall.length, rto_min: b.rto_min, rpo_min: b.rpo_min });
    return view();
  }
  // runbooks: one per standard failure; a save is a draft, a different person approves; review again within 12 months
  function saveRunbook(key0, src, who) {
    human(who, 'writes a runbook'); const key = param(key0, 'key'); const def = RUNBOOKS.find((r) => r[0] === key); if (!def) throw httpErr(404, 'no standard failure "' + key + '" - one of: ' + RUNBOOKS.map((r) => r[0]).join(', '));
    const b = body(src || {}).str('owner', { required: true, re: USER, msg: 'owner must be a user name' }).str('steps', { required: true, min: 40, max: 8000 }).str('escalation', { required: true, min: 10, max: 2000 }).str('tools', { max: 2000 }).done();
    const prev = RB().get(key); RB().put(Object.assign({ id: key, title: def[1] }, b, { status: 'draft', author: who.user, saved_at: iso(), approved_by: null, approved_at: null, version: prev ? (prev.version || 1) + 1 : 1 }));
    audit(who, 'runbook.save', key, { owner: b.owner, version: prev ? (prev.version || 1) + 1 : 1 }); return view();
  }
  function approveRunbook(key0, who) {
    human(who, 'approves a runbook'); const key = param(key0, 'key'), r = RB().get(key); if (!r) throw httpErr(404, 'no runbook for ' + key);
    if (r.status === 'approved') throw httpErr(409, 'already approved by ' + r.approved_by); if (same(r.author, who.user)) throw httpErr(403, 'four eyes: ' + who.user + ' wrote this version and cannot approve it');
    RB().put(Object.assign({}, r, { status: 'approved', approved_by: who.user, approved_at: iso() })); audit(who, 'runbook.approve', key, { version: r.version }); return view();
  }
  function addWindow(src, who) {
    human(who, 'plans a maintenance window');
    const b = body(src || {}).str('title', { required: true, min: 5, max: 160 }).str('start', { required: true, re: DT, msg: 'start must be YYYY-MM-DDTHH:MM' }).str('end', { required: true, re: DT, msg: 'end must be YYYY-MM-DDTHH:MM' })
      .list('systems', { required: true, max: 30, item: 'str', itemMax: 80 }).str('impact', { required: true, min: 10, max: 1000 }).str('rollback', { required: true, min: 10, max: 2000 }).done();
    if (b.end <= b.start) throw httpErr(400, 'end must be after start');
    const id = nextId(W, 'MW'); W().put(Object.assign({ id }, b, { status: 'requested', requested_by: who.user, requested_at: iso(), approved_by: null })); audit(who, 'window.request', id, { start: b.start, end: b.end, systems: b.systems.length }); return view();
  }
  function approveWindow(id0, who) {
    human(who, 'approves a maintenance window'); const id = param(id0, 'id'), w = W().get(id); if (!w) throw httpErr(404, 'no maintenance window ' + id);
    if (w.status === 'approved') throw httpErr(409, 'already approved'); if (same(w.requested_by, who.user)) throw httpErr(403, 'four eyes: ' + who.user + ' requested this window and cannot approve it');
    W().put(Object.assign({}, w, { status: 'approved', approved_by: who.user, approved_at: iso() })); audit(who, 'window.approve', id, {}); return view();
  }
  function addTest(src, who) {
    human(who, 'records a failover test');
    const b = body(src || {}).str('date', { required: true, re: DATE, msg: 'date must be YYYY-MM-DD' }).str('scenario', { required: true, min: 10, max: 500 }).oneOf('result', RESULTS, { required: true })
      .int('rto_achieved_min', { required: true, min: 0, max: 100000 }).str('evidence', { required: true, min: 5, max: 500 }).str('notes', { max: 2000 }).done();
    if (b.date > iso().slice(0, 10)) throw httpErr(400, 'date cannot be in the future - record a test after it ran');
    const id = nextId(TS, 'FT'); TS().put(Object.assign({ id }, b, { recorded_by: who.user, recorded_at: iso(), approved_by: null })); audit(who, 'test.record', id, { date: b.date, result: b.result, rto_achieved_min: b.rto_achieved_min }); return view();
  }
  function approveTest(id0, who) {
    human(who, 'approves a failover test'); const id = param(id0, 'id'), x = TS().get(id); if (!x) throw httpErr(404, 'no test ' + id);
    if (x.approved_by) throw httpErr(409, 'already approved'); if (same(x.recorded_by, who.user)) throw httpErr(403, 'four eyes: ' + who.user + ' recorded this test and cannot approve it');
    TS().put(Object.assign({}, x, { approved_by: who.user, approved_at: iso() })); audit(who, 'test.approve', id, { result: x.result }); return view();
  }
  async function outages() {
    const MR = M(); if (!MR) return [];
    try { const a = await MR.availability(); return (a.outages || []).filter((o) => o.start).map((o) => ({ id: 'O-' + o.start, start: o.start, end: o.end || null, minutes: o.minutes, hosts: o.hosts || [] })); }
    catch (er) { warn('outages', 'mail-ops: the outages could not be read', er); return []; }
  }
  async function saveReview(oid0, src, who) {
    human(who, 'writes a post-incident review'); const oid = String(oid0 || ''); if (!/^O-\d{10,14}$/.test(oid)) throw httpErr(400, 'oid is not an outage id (O-<start>)');
    const o = (await outages()).find((x) => x.id === oid); if (!o) throw httpErr(404, 'no recorded outage ' + oid);
    const b = body(src || {}).str('root_cause', { required: true, min: 10, max: 2000 }).str('actions', { required: true, min: 10, max: 4000 }).str('owner', { required: true, re: USER, msg: 'owner must be a user name' }).done();
    RV().put(Object.assign({ id: oid, outage: o }, b, { author: who.user, saved_at: iso(), approved_by: null })); audit(who, 'review.save', oid, { minutes: o.minutes, owner: b.owner }); return view();
  }
  function approveReview(oid0, who) {
    human(who, 'approves a post-incident review'); const oid = String(oid0 || ''); const r = RV().get(oid); if (!r) throw httpErr(404, 'no review for ' + oid);
    if (r.approved_by) throw httpErr(409, 'already approved'); if (same(r.author, who.user)) throw httpErr(403, 'four eyes: ' + who.user + ' wrote this review and cannot approve it');
    RV().put(Object.assign({}, r, { approved_by: who.user, approved_at: iso() })); audit(who, 'review.approve', oid, {}); return view();
  }

  async function facts() {
    const MR = M(), f = { av: null, route: null, alerts: null, reports: [], errors: [] };
    if (!MR) { f.errors.push('the mail modules (Email Dashboard / Route Map) are not installed'); return f; }
    try { f.av = await MR.availability(); } catch (er) { f.errors.push('availability: ' + String(er.message).slice(0, 120)); }
    try { f.route = await MR.routeView(null); } catch (er) { f.errors.push('mail route: ' + String(er.message).slice(0, 120)); }
    try { f.alerts = MR.alertView(); } catch (er) { f.errors.push('alerts: ' + String(er.message).slice(0, 120)); }
    try { f.reports = MR.reports() || []; } catch (er) { f.errors.push('reports: ' + String(er.message).slice(0, 120)); }
    return f;
  }
  async function view() {
    const t = now(), F = await facts(), pr = profile(), av = F.av || {}, cur = av.current || {}, st = (F.alerts && F.alerts.state) || null;
    const openAl = (F.alerts && F.alerts.open) || [], crit = openAl.filter((a) => a.severity === 'critical'), highGaps = (av.gaps || []).filter((g) => g.severity === 'high');
    const rbs = RUNBOOKS.map(([key, title]) => { const r = RB().get(key); const fresh = r && r.status === 'approved' && t - Date.parse(r.approved_at) < 365 * DAY;
      return { key, title, status: r ? r.status : 'missing', fresh: !!fresh, owner: r ? r.owner : null, version: r ? r.version : 0, author: r ? r.author : null, approved_by: r ? r.approved_by : null, approved_at: r ? r.approved_at : null, steps: r ? r.steps : '', escalation: r ? r.escalation : '', tools: r ? r.tools || '' : '' }; });
    const wins = W().all().sort((a, b) => String(b.start).localeCompare(String(a.start)));
    const ahead = iso(t + 90 * DAY).slice(0, 16), nowS = iso(t).slice(0, 16), winOk = wins.some((w) => w.status === 'approved' && w.end >= nowS && w.start <= ahead);
    const tests = TS().all().sort((a, b) => String(b.date).localeCompare(String(a.date)));
    const goodTest = pr && tests.find((x) => x.approved_by && x.result !== 'failed' && x.rto_achieved_min <= pr.rto_min && t - Date.parse(x.date + 'T00:00:00Z') < 183 * DAY);
    const outs = (await outages()).filter((o) => t - o.start < 90 * DAY), revs = outs.map((o) => Object.assign({}, o, { review: RV().get(o.id) || null }));
    const unreviewed = revs.filter((o) => !(o.review && o.review.approved_by));
    const rep = F.reports.filter((r) => r.state === 'approved' && t - (r.approved_at || 0) < 35 * DAY)[0] || null;
    const lanes = F.route && F.route.lanes;
    const probeAge = cur.last_at ? t - cur.last_at : null, alertAge = st ? t - st.at : null;
    const steps = [
      { done: !!pr && !!av.target, what: pr ? 'owner ' + pr.service_owner + ', ' + pr.oncall.length + ' on call, RTO ' + pr.rto_min + ' min, target ' + (av.target || '—') + '%' : 'not set',
        block: !pr ? 'an administrator names the service owner, the escalation manager, at least two on-call engineers and the RTO / RPO' : !av.target ? 'set the availability target on the Email Dashboard' : null, link: null },
      { done: !!lanes, what: lanes ? 'route checked' : 'not checked', block: lanes ? null : 'Email Route Map: add the mail domains in Domains & Hosting and run Check now', link: 'email-route-map.html' },
      { done: probeAge != null && probeAge < 10 * 60000 && alertAge != null && alertAge < 2 * 3600000 && !(st.gaps || []).length,
        what: (probeAge == null ? 'availability probe has not run' : 'probe ' + Math.round(probeAge / 60000) + ' min ago') + ' · ' + (alertAge == null ? 'early warnings never checked' : 'early warnings ' + Math.round(alertAge / 60000) + ' min ago') + ((st && (st.gaps || []).length) ? ' · ' + st.gaps.length + ' source(s) not readable' : ''),
        block: probeAge == null || probeAge >= 10 * 60000 ? 'the SMTP availability probe is not answering - check the platform service and the mail domains (Email Dashboard)' : alertAge == null || alertAge >= 2 * 3600000 ? 'run the early-warning check (Email Dashboard → Alerts → Check now)' : (st.gaps || []).length ? 'monitoring gap: ' + st.gaps.slice(0, 2).join('; ') : null, link: 'email-dashboard.html' },
      { done: !!av.target && !highGaps.length && !crit.length, what: highGaps.length + ' high design gap(s), ' + crit.length + ' critical alert(s) open',
        block: highGaps.length ? highGaps[0].title : crit.length ? 'open critical alert: ' + crit[0].title : !av.target ? 'availability not measured yet' : null, link: 'email-dashboard.html' },
      { done: rbs.every((r) => r.fresh), what: rbs.filter((r) => r.fresh).length + ' of ' + rbs.length + ' runbooks approved and current', block: rbs.some((r) => !r.fresh) ? 'write and approve the runbook for: ' + rbs.filter((r) => !r.fresh).map((r) => r.title.split(' (')[0]).slice(0, 3).join('; ') : null, link: null },
      { done: winOk, what: wins.length ? wins.filter((w) => w.status === 'approved').length + ' approved window(s), ' + wins.filter((w) => w.status === 'requested').length + ' waiting' : 'none planned', block: winOk ? null : 'plan the next maintenance window (impact and rollback) and have a different person approve it', link: null },
      { done: !!goodTest, what: tests.length ? 'last test ' + tests[0].date + ' - ' + tests[0].result.replace(/_/g, ' ') + (tests[0].approved_by ? '' : ' (not approved)') : 'no test recorded', block: goodTest ? null : !pr ? 'set the RTO first (step 1)' : 'run a failover test (e.g. take one gateway or DAG member down), record it with the time to recover, and have a different person approve it - it must pass within the RTO and be less than 6 months old', link: null },
      { done: !unreviewed.length, what: outs.length ? (outs.length - unreviewed.length) + ' of ' + outs.length + ' outage(s) in 90 days reviewed' : 'no outage in 90 days', block: unreviewed.length ? unreviewed.length + ' outage(s) need a post-incident review (root cause, actions, owner) approved by a different person' : null, link: null },
      { done: !!rep, what: rep ? rep.id + ' approved ' + iso(rep.approved_at).slice(0, 10) : 'none in the last 35 days', block: rep ? null : 'prepare the monthly mail availability report and have a different person approve it (Email Dashboard → Reports)', link: 'email-dashboard.html' },
    ].map((x, i) => Object.assign({ n: i + 1, title: STEPS[i] }, x));
    const done = steps.filter((x) => x.done).length;
    return { generated_at: iso(t), readiness: Math.round(done * 100 / steps.length), steps, current_step: (steps.find((x) => !x.done) || {}).n || null,
      profile: pr, availability: { target: av.target || null, windows: (av.windows || []).map((w) => ({ label: w.label, availability: w.availability, state: w.state, budget_left_minutes: w.budget_left_minutes })), up: cur.up === undefined ? null : cur.up, down_since: cur.down_since || null, gaps: av.gaps || [] },
      alerts: openAl.slice(0, 30).map((a) => ({ severity: a.severity, title: a.title, source: a.source, first_seen: a.first_seen })), runbooks: rbs, windows: wins.slice(0, 50), tests: tests.slice(0, 30), outages: revs, reports: F.reports.slice(0, 6), errors: F.errors,
      note: 'The programme reads what the mail modules measure and keeps what only people can give - the on-call team, runbooks, maintenance windows, failover tests and post-incident reviews - each approved by a second person. Nothing here changes a mail server, the gateway or DNS.' };
  }
  return { view, putProfile, saveRunbook, approveRunbook, addWindow, approveWindow, addTest, approveTest, saveReview, approveReview, RUNBOOKS };
}

function registerMailOps(srv, app, X0) {
  const X = X0 && X0.view ? X0 : createMailOps(app, X0 || {});
  app.addons = app.addons || {}; app.addons.mailOps = X;
  const who = (ctx) => Object.assign({ ip: ctx.ip }, ctx.who);
  srv.route('GET', '/mail-ops', (ctx) => { ctx.need('operator'); return X.view(); });
  srv.route('POST', '/mail-ops/profile', (ctx) => { ctx.need('admin'); return X.putProfile(ctx.body, who(ctx)); }, { maxBody: 8192 });
  srv.route('POST', '/mail-ops/runbooks/:key', (ctx) => { ctx.need('operator'); return X.saveRunbook(ctx.params.key, ctx.body, who(ctx)); }, { maxBody: 16384 });
  srv.route('POST', '/mail-ops/runbooks/:key/approve', (ctx) => { ctx.need('operator'); return X.approveRunbook(ctx.params.key, who(ctx)); }, { maxBody: 512 });
  srv.route('POST', '/mail-ops/windows', (ctx) => { ctx.need('operator'); return X.addWindow(ctx.body, who(ctx)); }, { maxBody: 8192 });
  srv.route('POST', '/mail-ops/windows/:id/approve', (ctx) => { ctx.need('operator'); return X.approveWindow(ctx.params.id, who(ctx)); }, { maxBody: 512 });
  srv.route('POST', '/mail-ops/tests', (ctx) => { ctx.need('operator'); return X.addTest(ctx.body, who(ctx)); }, { maxBody: 8192 });
  srv.route('POST', '/mail-ops/tests/:id/approve', (ctx) => { ctx.need('operator'); return X.approveTest(ctx.params.id, who(ctx)); }, { maxBody: 512 });
  srv.route('POST', '/mail-ops/reviews/:oid', (ctx) => { ctx.need('operator'); return X.saveReview(ctx.params.oid, ctx.body, who(ctx)); }, { maxBody: 8192 });
  srv.route('POST', '/mail-ops/reviews/:oid/approve', (ctx) => { ctx.need('operator'); return X.approveReview(ctx.params.oid, who(ctx)); }, { maxBody: 512 });
  return X;
}
module.exports = { createMailOps, registerMailOps, RUNBOOKS };
