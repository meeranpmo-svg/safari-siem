// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Office 365 email logs (engine/collect/m365-mailtrace.js + parse/m365.js messageTrace): a message trace record becomes an email event
// with the subject hashed (field and raw), the pull reads the window since the cursor with overlap, drops duplicates, keeps the
// cursor, names the missing permission, refuses an endpoint off Graph; the analysis (direction, blocked inbound, failures, personal
// webmail, large mail, a sender's spike against their OWN 14 days and a heavy but usual sender not flagged); the routes: analyst
// (viewer refused), days validated, audited, the query parses; the pull is admin-only (analyst refused), body fields declared,
// audited, not connected answered 409. SYNTHETIC addresses only.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs'), os = require('node:os'), path = require('node:path');
const M = require('../engine/collect/m365-mailtrace');
const PM = require('../engine/parse/m365');
const { parse } = require('../engine/api/query');
const { fakeApi } = require('./soc-fakes');

const H = 3600e3, DAY = 24 * H, NOW = Date.parse('2026-11-18T09:00:00Z');
const SECRETS = { m365: { tenant: '11111111-1111-1111-1111-111111111111', client_id: '22222222-2222-2222-2222-222222222222', client_secret: 'synthetic-not-a-secret' } };
const ev = (o) => { const r = Object.assign({ id: 'm' + Math.random(), senderAddress: 'syn.lina@corp.example', recipientAddress: 'syn.omar@corp.example', receivedDateTime: new Date(NOW - H).toISOString(), subject: 'Quarterly plan', size: 20000, status: 'Delivered', fromIP: '198.51.100.7' }, o); return PM.parse('', { obj: r }); };

test('parse: a message trace record is an email event; the subject is hashed in the field and the raw line', () => {
  const e = ev({ status: 'Quarantined', senderAddress: 'Bad@Phish.example', subject: 'Invoice overdue' });
  assert.equal(e.category, 'email'); assert.equal(e.host, 'exchange-mailflow'); assert.equal(e.action, 'mail-quarantined'); assert.equal(e.outcome, 'failure');
  assert.equal(e.user, 'bad@phish.example'); assert.equal(e.target_user, 'syn.omar@corp.example'); assert.equal(e.fields.subject_len, '15');
  assert.ok(!e.fields.subject && /^[0-9a-f]{64}$/.test(e.fields.subject_sha256)); assert.ok(!/Invoice overdue/.test(e.raw_body)); assert.deepEqual(e.tags, ['T1566']);
  assert.ok(PM.sniff('', { obj: { senderAddress: 'a', recipientAddress: 'b', receivedDateTime: 'c' } }));
});

function collector(rows, o = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mt-')), asked = [], out = [];
  const graph = { graphGet: async (u) => { asked.push(u); if (o.fail) throw o.fail; return rows; } };
  const parser = { parse: (line, meta) => PM.parse(line, meta) }, pipeline = { emit: (e) => out.push(e) };
  let t = NOW;
  const C = M.createMailTrace({ graph, parser, pipeline, config: Object.assign({ secrets: SECRETS, m365: {} }, o.config || {}), stateDir: dir, now: () => t, log: { warn() {}, info() {}, error() {} } });
  return { C, asked, out, dir, tick: (ms) => { t += ms; } };
}

test('pull: the window since the cursor with overlap, duplicates dropped, cursor kept, permission named, Graph only', async () => {
  const rows = [{ id: 'a', senderAddress: 'x@corp.example', recipientAddress: 'y@outside.example', receivedDateTime: new Date(NOW - H).toISOString(), status: 'Delivered' }, { id: 'b', senderAddress: 'x@corp.example', recipientAddress: 'z@corp.example', receivedDateTime: new Date(NOW - H).toISOString(), status: 'Failed' }];
  const k = collector(rows);
  let r = await k.C.pullNow(); assert.equal(r.records, 2); assert.equal(k.out.length, 2);
  assert.match(decodeURIComponent(k.asked[0]), /^https:\/\/graph\.microsoft\.com\/beta\/admin\/exchange\/tracing\/messageTraces\?\$filter=receivedDateTime ge 2026-11-17T09:00:00\.000Z and receivedDateTime le 2026-11-18T09:00:00\.000Z$/, 'first pull: the last day');
  k.tick(15 * 60e3); r = await k.C.pullNow(); assert.equal(r.records, 0, 'the same traces again are dropped'); assert.equal(k.C.status().duplicates, 2);
  assert.match(decodeURIComponent(k.asked[1]), /ge 2026-11-18T08:30:00\.000Z/, 'from the cursor less 30 minutes');
  assert.equal(JSON.parse(fs.readFileSync(path.join(k.dir, 'm365-mailtrace.json'), 'utf8')).until, NOW + 15 * 60e3, 'cursor kept on disk');
  const d = collector([], { fail: Object.assign(new Error('HTTP 403'), { status: 403 }) });
  await assert.rejects(d.C.pullNow(), /permission not granted: ExchangeMessageTrace\.Read\.All/); assert.match(d.C.status().last_error, /ExchangeMessageTrace/);
  const off = collector([], { config: { m365: { mailtrace_url: 'https://evil.example/collect' } } });
  await assert.rejects(off.C.pullNow(), /must be a graph\.microsoft\.com address/); assert.equal(off.asked.length, 0, 'the token never leaves Graph');
  assert.equal(collector([], { config: { secrets: {} } }).C.enabled(), false, 'not connected: no pull');
  assert.ok(!JSON.stringify(k.C.status()).includes('synthetic-not-a-secret'), 'status carries no secret');
});

function world() {
  const L = [];
  // internal mail every day
  for (let d = 0; d < 21; d++) for (let i = 0; i < 6; i++) L.push(ev({ receivedDateTime: new Date(NOW - d * DAY - i * 60e3 - H).toISOString() }));
  // syn.lina: 1 external a day for 14 days, then 45 in one day to many domains
  for (let d = 8; d <= 20; d++) L.push(ev({ recipientAddress: 'buyer@partner.example', receivedDateTime: new Date(NOW - d * DAY).toISOString() }));
  for (let i = 0; i < 45; i++) L.push(ev({ recipientAddress: 'r' + i + '@d' + (i % 9) + '.example', receivedDateTime: new Date(NOW - 2 * H - i * 60e3).toISOString() }));
  // a newsletter sender that always sends 60 a day: not flagged
  for (let d = 0; d <= 20; d++) for (let i = 0; i < 60; i++) L.push(ev({ senderAddress: 'syn.news@corp.example', recipientAddress: 'c' + i + '@customer.example', receivedDateTime: new Date(NOW - d * DAY - 4 * H - i * 1000).toISOString() }));
  // personal webmail and a large attachment
  L.push(ev({ senderAddress: 'syn.omar@corp.example', recipientAddress: 'omar.home@gmail.com', size: 26 * 1048576 }));
  L.push(ev({ senderAddress: 'syn.omar@corp.example', recipientAddress: 'omar.home@gmail.com' }));
  // inbound blocked and failures
  for (let i = 0; i < 4; i++) L.push(ev({ senderAddress: 'billing@phish.example', recipientAddress: 'syn.lina@corp.example', status: i ? 'FilteredAsSpam' : 'Quarantined' }));
  for (let i = 0; i < 3; i++) L.push(ev({ recipientAddress: 'old@gone.example', status: 'Failed' }));
  return L;
}

test('analysis: direction, blocked inbound, failures, personal webmail, large mail, a spike against the sender\'s own history', () => {
  const r = M.analyse(world(), NOW, { days: 7 });
  assert.deepEqual(r.internal_domains, ['corp.example']);
  assert.ok(r.kpis.internal >= 42 && r.kpis.inbound === 4 && r.kpis.outbound > 400);
  assert.equal(r.kpis.blocked, 4); assert.equal(r.blocked_domains[0].domain, 'phish.example'); assert.equal(r.blocked_domains[0].quarantined, 1);
  assert.equal(r.kpis.failed, 3); assert.equal(r.failed_domains[0].domain, 'gone.example');
  assert.deepEqual(r.personal.map((x) => x.user), ['syn.omar@corp.example']); assert.equal(r.personal[0].messages, 2);
  assert.equal(r.large.length, 1); assert.equal(r.large[0].mb, 26);
  assert.deepEqual(r.spikes.map((x) => x.user), ['syn.lina@corp.example'], 'the newsletter sender is usual, not flagged');
  assert.match(r.spikes[0].why, /48 external messages in one day .* against at most 1 a day/);
  assert.ok(r.insights.some((s) => /personal webmail/.test(s)) && r.insights.some((s) => /quarantined/.test(s)));
  assert.equal(r.series.length, 7); assert.equal(r.hours.length, 24); assert.ok(r.recent.length === 200 && !('subject' in r.recent[0]));
  assert.match(r.note, /not proof of wrongdoing/);
});

test('routes: analyst reads (viewer refused), days validated, audited, the query parses; the pull is admin only', async () => {
  const asked = []; const search = { fetchEvents: async (o) => { parse(o.q); asked.push(o); return world(); } };
  let pulled = 0; const m365Mail = { status: () => ({ enabled: true, ready: true, missing: [] }), enabled: () => true, pullNow: async () => { pulled++; return { ok: true, records: 12 }; } };
  const api = fakeApi({ realRanks: true }); M.register(api, { search, m365Mail, config: {}, log: { warn() {}, error() {} }, now: () => NOW });
  let r = await api.call('GET', '/api/soc/m365/mail', { role: 'viewer' }); assert.equal(r.status, 403);
  r = await api.call('GET', '/api/soc/m365/mail?days=0', { role: 'analyst' }); assert.equal(r.status, 400); assert.match(r.body.error, /days must be/);
  r = await api.call('GET', '/api/soc/m365/mail?days=7', { role: 'analyst', user: 'syn.soc' }); assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.equal(r.body.kpis.spikes, 1); assert.equal(asked[0].from, NOW - 21 * DAY); assert.equal(r.body.collector.ready, true);
  assert.ok(api.audits.some((a) => a.action === 'm365.mail.read' && a.user === 'syn.soc'));
  r = await api.call('GET', '/api/soc/m365/mail/status', { role: 'viewer' }); assert.equal(r.status, 200); assert.equal(r.body.enabled, true);
  r = await api.call('POST', '/api/soc/m365/mail/poll', { role: 'analyst', body: {} }); assert.equal(r.status, 403); assert.equal(pulled, 0);
  r = await api.call('POST', '/api/soc/m365/mail/poll', { role: 'admin', user: 'syn.admin', body: { extra: 1 } }); assert.equal(r.status, 200, JSON.stringify(r.body)); assert.equal(r.body.records, 12);
  assert.ok(api.audits.some((a) => a.action === 'm365.mail.poll' && a.user === 'syn.admin'));
  const api2 = fakeApi({ realRanks: true }); M.register(api2, { search, m365Mail: Object.assign({}, m365Mail, { enabled: () => false }), config: {}, now: () => NOW });
  r = await api2.call('POST', '/api/soc/m365/mail/poll', { role: 'admin', body: {} }); assert.equal(r.status, 409); assert.match(r.body.error, /not connected/);
  const api3 = fakeApi({ realRanks: true }); M.register(api3, { search, m365Mail: Object.assign({}, m365Mail, { pullNow: async () => { throw new Error('HTTP 503 busy'); } }), config: {}, now: () => NOW });
  r = await api3.call('POST', '/api/soc/m365/mail/poll', { role: 'admin', body: {} }); assert.equal(r.status, 502); assert.ok(api3.audits.some((a) => a.action === 'm365.mail.poll' && a.detail && a.detail.ok === false));
});
