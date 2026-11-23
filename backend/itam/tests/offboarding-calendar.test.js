// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Leaver meetings (engine/offboarding.js + engine/m365-licensing.js) against an in-process fake Microsoft Graph calendar: the
// meetings the leaver organises in the window are read (series by their next occurrence, private ones listed, past / not
// organised / no attendees left out); "move" creates each again from the manager's calendar (agenda, attendees without the
// leaver, place, Teams, the repeat pattern from the next occurrence in its own time zone, a numbered series with what is left)
// and only THEN ends the leaver's one - a series with a past stops yesterday, anything else is cancelled with a note naming the
// new organiser; "cancel" only ends them; private meetings are never touched; a retry never sends a second invitation
// (transactionId) or repeats what worked; decide after with four eyes and exclusions; the read-only check. SYNTHETIC data only.
const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('http');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');

const HR = { user: 'hana.syn', role: 'operator' }, MGR = { user: 'faisal.syn', role: 'operator' }, DESK = { user: 'desk.syn', role: 'operator' };
const ADM = { user: 'syed', role: 'admin' }, REQ_ADMIN = { user: 'hana.syn', role: 'admin' }, VIEW = { user: 'vera.syn', role: 'viewer' };
const TENANT = '11111111-2222-3333-4444-555555555555', APPID = '66666666-7777-8888-9999-000000000000', SECRET = 'Synthetic-Graph-Secret-1';
const LEAVER = { name: 'Khalid <b>Al-Harbi</b>', employee_id: 'E-20001', username: 'khalid.harbi', department: 'Claims', last_day: '2026-10-30', manager: 'faisal.syn', reason: 'resignation' };
const A = (addr) => ({ emailAddress: { address: addr, name: addr.split('@')[0] }, type: 'required' });

function fakeGraph() {
  const LV = 'khalid.harbi@corp.syn';
  const st = { calls: [], created: [], cancels: [], patches: [], failCreate: 0, prefer: [], events: {
    S1: { id: 'S1', subject: 'Weekly claims review', type: 'seriesMaster', isOrganizer: true, isCancelled: false, sensitivity: 'normal', isOnlineMeeting: true, onlineMeetingProvider: 'teamsForBusiness', originalStartTimeZone: 'Arab Standard Time',
      start: { dateTime: '2026-01-05T07:00:00.0000000', timeZone: 'UTC' }, end: { dateTime: '2026-01-05T08:00:00.0000000', timeZone: 'UTC' }, location: { displayName: 'Room 4' }, body: { content: '<p>Agenda: open claims</p>' },
      recurrence: { pattern: { type: 'weekly', interval: 1, daysOfWeek: ['monday'] }, range: { type: 'noEnd', startDate: '2026-01-05', recurrenceTimeZone: 'Arab Standard Time' } },
      attendees: [A(LV), A('team@corp.syn'), A('partner@broker.example')], inst: ['2026-11-02', '2026-11-09', '2026-11-16'] },
    S2: { id: 'S2', subject: 'Budget sign-off', type: 'singleInstance', isOrganizer: true, isCancelled: false, sensitivity: 'normal', start: { dateTime: '2026-11-05T09:00:00.0000000', timeZone: 'UTC' }, end: { dateTime: '2026-11-05T10:00:00.0000000', timeZone: 'UTC' }, body: { content: 'Bring numbers' }, attendees: [A('cfo@corp.syn')] },
    S3: { id: 'S3', subject: 'Old one', type: 'singleInstance', isOrganizer: true, isCancelled: false, start: { dateTime: '2026-10-01T09:00:00', timeZone: 'UTC' }, end: { dateTime: '2026-10-01T10:00:00', timeZone: 'UTC' }, attendees: [A('cfo@corp.syn')] },
    S4: { id: 'S4', subject: 'Personal', type: 'singleInstance', isOrganizer: true, isCancelled: false, sensitivity: 'private', start: { dateTime: '2026-11-06T09:00:00', timeZone: 'UTC' }, end: { dateTime: '2026-11-06T10:00:00', timeZone: 'UTC' }, attendees: [A('x@corp.syn')] },
    S5: { id: 'S5', subject: 'Someone else\'s', type: 'singleInstance', isOrganizer: false, isCancelled: false, start: { dateTime: '2026-11-07T09:00:00', timeZone: 'UTC' }, end: { dateTime: '2026-11-07T10:00:00', timeZone: 'UTC' }, attendees: [A('y@corp.syn')] },
    S6: { id: 'S6', subject: 'Onboarding sessions', type: 'seriesMaster', isOrganizer: true, isCancelled: false, sensitivity: 'normal', originalStartTimeZone: 'Arab Standard Time', start: { dateTime: '2026-11-10T06:00:00', timeZone: 'UTC' }, end: { dateTime: '2026-11-10T07:00:00', timeZone: 'UTC' },
      recurrence: { pattern: { type: 'daily', interval: 1 }, range: { type: 'numbered', startDate: '2026-11-10', numberOfOccurrences: 4, recurrenceTimeZone: 'Arab Standard Time' } }, attendees: [A('new.joiner@corp.syn')], inst: ['2026-11-10', '2026-11-11', '2026-11-12', '2026-11-13'] },
    S7: { id: 'S7', subject: 'Focus time', type: 'singleInstance', isOrganizer: true, isCancelled: false, start: { dateTime: '2026-11-03T09:00:00', timeZone: 'UTC' }, end: { dateTime: '2026-11-03T10:00:00', timeZone: 'UTC' }, attendees: [] } }, made: {} };
  const srv = http.createServer((req, res) => { let b = ''; req.on('data', (c) => { b += c; }); req.on('end', () => {
    const u = new URL(req.url, 'http://x'), J = (c, o) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(o === undefined ? '' : JSON.stringify(o)); };
    if (u.pathname === '/' + TENANT + '/oauth2/v2.0/token') return J(200, { access_token: 'tok' });
    const P = u.pathname.replace('/v1.0', ''); st.calls.push(req.method + ' ' + P); if (req.headers.prefer) st.prefer.push(P + ' ' + req.headers.prefer);
    let m;
    if (P === '/organization') return J(200, { value: [{ verifiedDomains: [{ name: 'corp.syn' }] }] });
    if ((m = /^\/users\/([^/]+)$/.exec(P))) { const k = decodeURIComponent(m[1]); return /^(khalid\.harbi|faisal\.syn|omar\.syn)@corp\.syn$/.test(k) ? J(200, { id: 'id-' + k.split('@')[0] }) : J(404, { error: { code: 'Request_ResourceNotFound', message: 'x' } }); }
    if ((m = /^\/users\/khalid\.harbi%40corp\.syn\/events$/.exec(P)) || (m = /^\/users\/khalid\.harbi@corp\.syn\/events$/.exec(P))) return J(200, { value: Object.values(st.events).map((e) => Object.assign({}, e, { body: undefined, inst: undefined })) });
    if ((m = /^\/users\/[^/]+\/events\/([^/]+)\/instances$/.exec(P))) { const e = st.events[decodeURIComponent(m[1])]; const hh = String(e.start.dateTime).slice(11, 19), he = String(e.end.dateTime).slice(11, 19); return J(200, { value: e.inst.map((d, i) => ({ id: e.id + '-' + i, start: { dateTime: d + 'T' + hh, timeZone: e.originalStartTimeZone }, end: { dateTime: d + 'T' + he, timeZone: e.originalStartTimeZone }, isCancelled: false })) }); }
    if ((m = /^\/users\/([^/]+)\/events\/([^/]+)\/cancel$/.exec(P)) && req.method === 'POST') { const e = st.events[decodeURIComponent(m[2])]; e.isCancelled = true; st.cancels.push({ id: e.id, comment: JSON.parse(b).comment }); return J(202); }
    if ((m = /^\/users\/([^/]+)\/events\/([^/]+)$/.exec(P))) {
      const who = decodeURIComponent(m[1]), k = decodeURIComponent(m[2]);
      if (who.startsWith('khalid')) { const e = st.events[k]; if (!e) return J(404, { error: { code: 'x', message: 'x' } });
        if (req.method === 'PATCH') { const p = JSON.parse(b); e.recurrence = p.recurrence; st.patches.push({ id: k, range: p.recurrence.range }); return J(200, e); }
        return J(200, Object.assign({}, e, { inst: undefined })); }
      return st.made[k] ? J(200, st.made[k]) : J(404, { error: { code: 'x', message: 'x' } });
    }
    if ((m = /^\/users\/([^/]+)\/events$/.exec(P)) && req.method === 'POST') {
      const p = JSON.parse(b);
      if (st.failCreate > 0 && p.subject === 'Budget sign-off') { st.failCreate--; return J(503, { error: { code: 'ServiceUnavailable', message: 'try later' } }); }
      const dup = Object.values(st.made).find((x) => x.transactionId === p.transactionId); if (dup) return J(201, dup);
      const id = 'N' + (st.created.length + 1), rec = Object.assign({ id, isOrganizer: true }, p, { owner: decodeURIComponent(m[1]) }); st.made[id] = rec; st.created.push(rec); return J(201, rec);
    }
    J(404, { error: { code: 'x', message: 'no route ' + P } });
  }); });
  return { st, srv };
}

async function setup(t) {
  const clock = { t: Date.parse('2026-10-28T08:00:00Z') };
  const F = fakeGraph(); await new Promise((r) => F.srv.listen(0, '127.0.0.1', r)); t.after(() => F.srv.close());
  const gb = 'http://127.0.0.1:' + F.srv.address().port;
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => clock.t, python: process.env.PYTHON || 'python3', graphLogin: gb, graphBase: gb + '/v1.0' });
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  const post = (p, b, who) => call('POST', p, b, who), get = (p, who = DESK) => call('GET', p, undefined, who);
  assert.equal((await post('/onboarding/ad', { upn_suffix: 'corp.syn' }, ADM)).status, 200);
  let r = await post('/onboarding/m365', { tenant_id: TENANT, client_id: APPID, client_secret: SECRET, calendar_enabled: true, calendar_days: 20 }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /calendar_days must be at least 30/);
  r = await post('/onboarding/m365', { tenant_id: TENANT, client_id: APPID, client_secret: SECRET, calendar_enabled: true }, ADM); assert.equal(r.status, 200, JSON.stringify(r.json)); assert.equal(r.json.calendar_ready, true); assert.equal(r.json.calendar_days, 180);
  async function raise(extra = {}) { const x = await post('/offboarding', Object.assign({}, LEAVER, extra), HR); assert.equal(x.status, 200, JSON.stringify(x.json)); await post('/offboarding/' + x.json.id + '/confirm', { decision: 'confirm' }, MGR); return x.json.id; }
  async function leaver(extra = {}, approve = { decision: 'approve' }) {
    const rid = await raise(extra);
    let x = await post('/offboarding/' + rid + '/approve', approve, ADM); assert.equal(x.status, 200, JSON.stringify(x.json));
    x = await post('/offboarding/' + rid + '/disabled', { directory_ref: 'disabled in ADUC, CHG-9001' }, DESK); assert.equal(x.status, 200, JSON.stringify(x.json));
    return { id: rid, v: x.json };
  }
  return { e, F, clock, post, get, raise, leaver };
}
const auditOf = (e, action) => e.app.store.auditTail(500).filter((x) => x.action === action);

test('default: each meeting is created again by the manager, then the leaver\'s one ends; private ones untouched', async (t) => {
  const { e, F, get, leaver } = await setup(t);
  const { v } = await leaver();
  const c = v.calendar;
  assert.equal(c.status, 'transferred', JSON.stringify(c)); assert.equal(c.owner, 'faisal.syn@corp.syn'); assert.equal(c.decided_with, 'disable approval');
  assert.deepEqual(c.meetings.map((m) => m.id), ['S1', 'S2', 'S4', 'S6'], 'past, not organised and no-attendee ones left out');
  const s1m = c.meetings.find((m) => m.id === 'S1'); assert.equal(s1m.remaining, 3); assert.equal(s1m.external, 1); assert.ok(c.meetings.find((m) => m.id === 'S4').private);
  assert.deepEqual(F.st.created.map((x) => x.subject), ['Weekly claims review', 'Budget sign-off', 'Onboarding sessions']);
  const n1 = F.st.created[0];
  assert.equal(n1.owner, 'faisal.syn@corp.syn'); assert.deepEqual(n1.attendees.map((a) => a.emailAddress.address), ['team@corp.syn', 'partner@broker.example'], 'without the leaver');
  assert.deepEqual(n1.start, { dateTime: '2026-11-02T07:00:00', timeZone: 'Arab Standard Time' }); assert.equal(n1.recurrence.range.startDate, '2026-11-02'); assert.equal(n1.recurrence.range.type, 'noEnd');
  assert.equal(n1.isOnlineMeeting, true); assert.equal(n1.location.displayName, 'Room 4'); assert.ok(n1.transactionId);
  assert.match(n1.body.content, /Khalid &lt;b&gt;Al-Harbi&lt;\/b&gt;, who has left[\s\S]*Agenda: open claims/, 'a line naming who organised it (escaped), then the agenda');
  assert.equal(F.st.created[2].recurrence.range.numberOfOccurrences, 4, 'a numbered series keeps what is left');
  assert.ok(F.st.prefer.some((p) => /instances .*Arab Standard Time/.test(p)), 'occurrences read in the series\' own time zone');
  assert.deepEqual(F.st.patches.map((p) => [p.id, p.range.endDate]), [['S1', '2026-10-27']], 'a series with a past stops yesterday');
  assert.deepEqual(F.st.cancels.map((x) => x.id).sort(), ['S2', 'S6']); assert.match(F.st.cancels[0].comment, /now organised by faisal\.syn@corp\.syn/);
  const ix = (s) => F.st.calls.indexOf(s);
  assert.ok(ix('POST /users/faisal.syn%40corp.syn/events') < ix('POST /users/khalid.harbi%40corp.syn/events/S2/cancel'), 'created before the original ends');
  assert.ok(!F.st.events.S4.isCancelled && !F.st.created.some((x) => x.subject === 'Personal'), 'private meeting never touched');
  assert.ok(v.steps.find((s) => s.key === 'calendar').done);
  const a = auditOf(e, 'offboarding.calendar.transferred')[0]; assert.equal(a.detail.meetings, 3); assert.equal(a.detail.skipped_private, 1); assert.equal(a.detail.approved_by, 'syed');
  assert.equal(auditOf(e, 'offboarding.calendar.read')[0].detail.external_attendees, 1);
  assert.equal((await get('/offboarding')).json.calendar.days, 180);
});

test('cancel only: nothing created, the leaver\'s meetings ended with a note naming the manager', async (t) => {
  const { F, leaver } = await setup(t);
  const { v } = await leaver({}, { decision: 'approve', calendar: 'cancel' });
  assert.equal(v.calendar.status, 'transferred'); assert.equal(v.calendar.mode, 'cancel');
  assert.equal(F.st.created.length, 0); assert.match(F.st.cancels[0].comment, /cancelled\. Contact faisal\.syn@corp\.syn/);
});

test('decide after: the check before the disable, four eyes, exclusions and owner validated, kept with a note', async (t) => {
  const { e, F, post, get, raise } = await setup(t);
  const pid = await raise();
  assert.equal((await post('/offboarding/' + pid + '/calendar/check', {}, VIEW)).status, 403);
  let r = await post('/offboarding/' + pid + '/calendar/check', {}, DESK); assert.equal(r.status, 200); assert.equal(r.json.calendar_check.meetings.length, 4);
  assert.equal(F.st.created.length + F.st.cancels.length, 0, 'a check changes nothing'); assert.equal(auditOf(e, 'offboarding.calendar.check')[0].detail.meetings, 4);
  r = await post('/offboarding/' + pid + '/approve', { decision: 'approve', calendar: 'move' }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /^calendar must be one of/);
  await post('/offboarding/' + pid + '/approve', { decision: 'approve', calendar: 'ask' }, ADM);
  r = await post('/offboarding/' + pid + '/disabled', { directory_ref: 'disabled in ADUC, CHG-9001' }, DESK); assert.equal(r.json.calendar.status, 'proposed');
  assert.equal((await get('/offboarding')).json.counts.calendar_meetings, 4);
  const D = (b, who) => post('/offboarding/' + pid + '/calendar/decide', b, who);
  assert.equal((await D({ decision: 'approve' }, DESK)).status, 403);
  r = await D({ decision: 'approve' }, REQ_ADMIN); assert.equal(r.status, 403); assert.match(r.json.error, /four eyes/);
  r = await D({ decision: 'approve' }, { user: 'khalid.harbi', role: 'admin' }); assert.equal(r.status, 403);
  r = await D({ decision: 'approve', owner: 'khalid.harbi@corp.syn' }, ADM); assert.match(r.json.error, /leaver cannot be the new organiser/);
  r = await D({ decision: 'approve', exclude: ['NOPE'] }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /^exclude:/);
  r = await D({ decision: 'approve', exclude: ['S1', 'S2', 'S6'] }, ADM); assert.equal(r.status, 409, 'only the private one left');
  r = await D({ decision: 'approve', mode: 'archive' }, ADM); assert.match(r.json.error, /^mode must be one of/);
  r = await D({ decision: 'approve', owner: 'omar.syn@corp.syn', exclude: ['S2'] }, ADM); assert.equal(r.status, 200, JSON.stringify(r.json));
  assert.equal(r.json.calendar.status, 'transferred'); assert.ok(F.st.created.every((x) => x.owner === 'omar.syn@corp.syn')); assert.ok(!F.st.events.S2.isCancelled, 'the excluded meeting stays');
  assert.equal(auditOf(e, 'offboarding.calendar.approved')[0].detail.excluded, 1);
});

test('a failed creation keeps the original; the retry sends no second invitation and repeats nothing that worked', async (t) => {
  const { e, F, clock, post, get, leaver } = await setup(t);
  F.st.failCreate = 1;
  const { id, v } = await leaver();
  assert.equal(v.calendar.status, 'approved'); assert.match(v.calendar.error, /partly done - 2 change\(s\) left: create "Budget sign-off"/);
  assert.ok(!F.st.events.S2.isCancelled, 'not ended before its replacement exists');
  assert.equal((await get('/offboarding')).json.counts.calendar_failed, 1);
  clock.t += 3601000; await e.app.addons.offboarding.runDue(null);
  const c = (await get('/offboarding/' + id)).json.calendar; assert.equal(c.status, 'transferred');
  assert.equal(F.st.created.length, 3, 'each meeting created once'); assert.ok(F.st.events.S2.isCancelled);
  assert.equal(F.st.patches.length, 1, 'the series was not ended twice');
  assert.equal((await post('/offboarding/' + id + '/calendar/retry', {}, ADM)).status, 409, 'nothing left to retry');
});
