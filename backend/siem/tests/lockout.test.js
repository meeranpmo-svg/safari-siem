// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Lockout analyzer (engine/soc/adchanges.js analyzeLockouts / rankLockouts): each 4740 joined with the 4625 / 4771 / 4776
// failures of the same account in the window before it names the likely source computer / process / IP with the evidence
// counts; failures outside the window or of another account do not count; no failure = "none", never a guess; per-account
// history and the repeat ranking; the routes (viewer refused, validation, audit). SYNTHETIC accounts and hosts.
const test = require('node:test');
const assert = require('node:assert/strict');
const W = require('../engine/parse/windows');
const { analyzeLockouts, rankLockouts } = require('../engine/soc/adchanges');

const T = Date.UTC(2026, 10, 10, 8, 0, 0);
let rid = 1;
const win = (id, at, ed, host) => W.parse(JSON.stringify({ Channel: 'Security', EventID: id, TimeCreated: new Date(at).toISOString(), Computer: host || 'DC01.synthetic.test', RecordId: rid++, EventData: ed }));
const lock = (at, user, caller) => win(4740, at, { TargetUserName: user, TargetDomainName: caller, SubjectUserName: 'DC01$', SubjectDomainName: 'SYN' }, 'PDC.synthetic.test');
const f4625 = (at, user, ws, ip, proc, lt, host) => win(4625, at, { TargetUserName: user, TargetDomainName: 'SYN', WorkstationName: ws, IpAddress: ip, ProcessName: proc, LogonType: lt, Status: '0xc000006d', SubStatus: '0xc000006a' }, host);
const f4771 = (at, user, ip) => win(4771, at, { TargetUserName: user, IpAddress: '::ffff:' + ip, Status: '0x18' });
const f4776 = (at, user, ws) => win(4776, at, { TargetUserName: user, Workstation: ws, Status: '0xc000006a' });
const min = 60000;

const fails = [
  // fin.syn: an old password on WS-FIN-07 (Outlook) - 4625 + 4776 name the workstation, 4771 the IP
  f4625(T - 9 * min, 'fin.syn', 'WS-FIN-07', '10.20.1.7', 'C:\\Program Files\\Microsoft Office\\OUTLOOK.EXE', '3', 'FS01.synthetic.test'),
  f4625(T - 6 * min, 'fin.syn', 'WS-FIN-07', '10.20.1.7', 'C:\\Program Files\\Microsoft Office\\OUTLOOK.EXE', '3', 'FS01.synthetic.test'),
  f4776(T - 5 * min, 'fin.syn', 'WS-FIN-07'), f4776(T - 4 * min, 'fin.syn', 'WS-FIN-07'),
  f4771(T - 3 * min, 'fin.syn', '10.20.1.7'), f4771(T - 2 * min, 'fin.syn', '10.20.1.7'),
  f4625(T - 2 * 3600000, 'fin.syn', 'OLD-PC', '10.20.9.9', 'x.exe', '2'),          // outside the 30-minute window
  f4625(T - 5 * min, 'ops.syn', 'WS-OPS-01', '10.20.2.2', 'y.exe', '3'),           // another account
  // svc.syn: a service on APP02 - no caller computer in the 4740, failures name the server and service logons
  f4625(T + 3600000 - 8 * min, 'svc.syn', 'APP02', '10.20.3.2', 'C:\\Windows\\System32\\services.exe', '5', 'APP02.synthetic.test'),
  f4625(T + 3600000 - 7 * min, 'svc.syn', 'APP02', '10.20.3.2', 'C:\\Windows\\System32\\services.exe', '5', 'APP02.synthetic.test'),
  f4625(T + 3600000 - 6 * min, 'svc.syn', 'APP02', '10.20.3.2', 'C:\\Windows\\System32\\services.exe', '5', 'APP02.synthetic.test'),
];
const locks = [lock(T, 'fin.syn', 'WS-FIN-07'), lock(T + 3600000, 'svc.syn', ''), lock(T + 7200000, 'ghost.syn', 'WS-X'), lock(T + 86400000, 'fin.syn', 'WS-FIN-07')];
const fin2 = [f4625(T + 86400000 - 3 * min, 'fin.syn', 'WS-FIN-07', '10.20.1.7', 'OUTLOOK.EXE', '3'), f4771(T + 86400000 - 2 * min, 'fin.syn', '10.20.1.7')];

test('parser: 4740 caller computer, 4625 workstation / process / logon type, 4771 client IP, 4776 workstation', () => {
  assert.equal(locks[0].target_user, 'fin.syn'); assert.equal(locks[0].fields.caller_computer, 'WS-FIN-07');
  assert.equal(fails[0].user, 'fin.syn'); assert.equal(fails[0].fields.workstation, 'WS-FIN-07'); assert.equal(fails[0].fields.logon_type_name, 'network');
  assert.equal(fails[4].src_ip, '10.20.1.7', 'the ::ffff: prefix of 4771 is removed'); assert.equal(fails[2].fields.workstation, 'WS-FIN-07');
});

test('analyzer: likely source with evidence counts, confidence, hints; window and account respected; no evidence is said', () => {
  const r = analyzeLockouts(locks, fails.concat(fin2), { windowMs: 30 * min });
  const fin = r.find((x) => x.account === 'fin.syn' && x.ts === T);
  assert.equal(fin.caller_computer, 'WS-FIN-07');
  assert.deepEqual(fin.evidence.counts, { 4625: 2, 4771: 2, 4776: 2 });
  assert.equal(fin.evidence.failures, 6, 'the 2-hour-old failure and the other account are not counted');
  assert.deepEqual(fin.evidence.computers, [{ name: 'WS-FIN-07', count: 4 }]);
  assert.deepEqual(fin.likely, { computer: 'WS-FIN-07', ip: '10.20.1.7', process: 'outlook.exe', logon_type: 'network', basis: 'caller computer in the 4740 event', confidence: 'high', corroborated: true });
  const svc = r.find((x) => x.account === 'svc.syn');
  assert.equal(svc.caller_computer, ''); assert.equal(svc.likely.computer, 'APP02'); assert.equal(svc.likely.basis, 'most failed sign-ins named this workstation');
  assert.equal(svc.likely.confidence, 'high'); assert.equal(svc.likely.process, 'services.exe'); assert.equal(svc.likely.logon_type, 'service');
  assert.ok(svc.hints.some((h) => /service \/ batch logon/i.test(h)));
  const ghost = r.find((x) => x.account === 'ghost.syn');
  assert.equal(ghost.evidence.failures, 0); assert.equal(ghost.likely.confidence, 'low', 'only the caller name, nothing corroborates it');
  assert.ok(ghost.hints.some((h) => /No failed sign-in/.test(h)));
  assert.equal(analyzeLockouts([lock(T, 'nobody.syn', '')], [])[0].likely.confidence, 'none');
});

test('history and ranking: repeat lockouts first, the recurring source named', () => {
  const r = analyzeLockouts(locks, fails.concat(fin2));
  const rank = rankLockouts(r);
  assert.equal(rank[0].account, 'fin.syn'); assert.equal(rank[0].lockouts, 2); assert.equal(rank[0].repeat, true);
  assert.equal(rank[0].top_source, 'WS-FIN-07'); assert.equal(rank[0].top_source_count, 2); assert.equal(rank[0].recurring_source, true);
  assert.deepEqual(rank.slice(1).map((x) => [x.account, x.repeat]), [['ghost.syn', false], ['svc.syn', false]]);
});

test('routes: viewer refused, analyst reads (account history too), parameters validated, reads audited; the ClickHouse half', async () => {
  const routes = require('../engine/soc/adchanges-routes'), R = {}, seen = [];
  const toRow = (e) => Object.assign({}, e, { ts: new Date(e.ts).toISOString().replace('T', ' ').replace('Z', '') });
  const ch = { query: async (sql, params) => { seen.push({ sql, params }); if (/adchanges:lockouts/.test(sql)) return locks.filter((l) => !params.a.value || l.target_user === params.a.value).map(toRow); if (/adchanges:failures/.test(sql)) return fails.concat(fin2).filter((f) => params.u.value.includes(f.user)).map(toRow); return []; } };
  const st = { collection: () => ({ get: () => null, put: () => null, all: () => [], remove: () => null }) };
  routes.register({ route: (m, p, h) => { R[m + ' ' + p] = h; } }, { ch, state: st, config: {}, log: { info() {}, warn() {}, error() {}, every() {}, child() { return this; } }, noTimers: true });
  const call = async (p, role, query, params) => { const c = { role, user: role + '.syn', query: query || {}, params: params || {}, code: 200, aud: [], audit(a, t, d) { c.aud.push([a, t, d]); }, need(r) { const K = { viewer: 0, analyst: 1, operator: 2, admin: 3 }; if (K[role] < K[r]) { c.code = 403; return false; } return true; }, ok: (x) => { c.res = x; return x; }, fail(code, msg) { c.code = code; c.msg = msg; return { error: msg }; } }; await R['GET /api/soc' + p](c); return c; };
  let c = await call('/ad/lockouts', 'viewer'); assert.equal(c.code, 403);
  c = await call('/ad/lockouts', 'analyst', { hours: '720', window_min: '30' });
  assert.equal(c.code, 200); assert.equal(c.res.total, 4); assert.equal(c.res.ranking[0].account, 'fin.syn');
  const fq = seen.find((x) => /adchanges:failures/.test(x.sql)); assert.deepEqual(fq.params.u.value.sort(), ['fin.syn', 'ghost.syn', 'svc.syn']); assert.equal(fq.params.hw.value, 720 * 60 + 30);
  assert.deepEqual(c.aud[0].slice(0, 2), ['ad.lockouts.view', 'all']); assert.equal(c.aud[0][2].lockouts, 4);
  c = await call('/ad/lockouts/:account', 'analyst', {}, { account: 'fin.syn' });
  assert.equal(c.res.total, 2); assert.equal(c.res.hours, 720); assert.deepEqual(c.aud[0].slice(0, 2), ['ad.lockouts.account', 'fin.syn']);
  c = await call('/ad/lockouts/:account', 'analyst', {}, { account: 'x"); DROP' }); assert.equal(c.code, 400); assert.match(c.msg, /account must be an account name/);
  c = await call('/ad/lockouts', 'analyst', { window_min: '1' }); assert.equal(c.code, 400); assert.match(c.msg, /window_min must be at least 5/);
  c = await call('/ad/lockouts/:account', 'viewer', {}, { account: 'fin.syn' }); assert.equal(c.code, 403);
});
