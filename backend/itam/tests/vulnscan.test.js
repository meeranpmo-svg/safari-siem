// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Internal vulnerability scans (engine/vulnscan.js + engine/gmp.js) through the real routes against a mock gvmd on a unix
// socket: the scope accepts only private ranges; a scan outside the scope or too large is refused; four-eyes approval (never the
// requester, never a service identity); the scan starts only in its window, is stopped when the window ends and its partial
// results are imported; findings are fixed only when a later scan of the host stops reporting them; risk acceptance is
// four-eyes; roles, validation naming the field, audit records, the CSV export, and the GMP allow-list. SYNTHETIC data only.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');
const { startGmpMock } = require('./gmp-mock');
const G = require('../engine/gmp');

const ADM = { user: 'syed', role: 'admin' }, ADM2 = { user: 'sami.syn', role: 'admin' }, OP = { user: 'omar.syn', role: 'operator' }, VIEW = { user: 'vera.syn', role: 'viewer' };
const sealer = { seal: (id, t) => 'SEALED:' + Buffer.from(t).toString('base64'), unseal: (id, e) => Buffer.from(String(e).slice(7), 'base64').toString() };
const F1 = { host: '10.20.1.5', hostname: 'app01.syn', port: '443/tcp', oid: '1.3.6.1.4.1.25623.1.0.900001', name: 'Synthetic TLS weakness', score: 7.5, cves: ['CVE-2099-0001'] };
const F2 = { host: '10.20.1.6', hostname: 'db01.syn', port: '1521/tcp', oid: '1.3.6.1.4.1.25623.1.0.900002', name: 'Synthetic listener exposure <img src=x onerror=alert(1)>', score: 9.8, cves: ['CVE-2099-0002'] };
const LOG = { host: '10.20.1.5', port: 'general/tcp', oid: '1.3.6.1.4.1.25623.1.0.900003', name: 'OS detection (log)', score: 0 };
const LOWQ = { host: '10.20.1.6', port: '80/tcp', oid: '1.3.6.1.4.1.25623.1.0.900004', name: 'Low quality guess', score: 5, qod: 30 };

async function setup(t) {
  let clock = Date.parse('2027-01-10T08:00:00Z');
  const gm = await startGmpMock({ hosts: ['10.20.1.5', '10.20.1.6'], findings: [F1, F2, LOG, LOWQ] }); t.after(() => gm.close());
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, now: () => clock, python: process.env.PYTHON || 'python3', eccFacts: async () => ({}), ndmoCatalogFiles: false, vulnSealer: sealer, gvmFilePassword: () => '' });
  const call = (m, p, body, who) => e.req(m, p, Object.assign(body !== undefined ? { body } : {}, who));
  const V = e.app.addons.vulnscan;
  return { e, gm, V, put: (p, b, who) => call('PUT', p, b, who), post: (p, b, who) => call('POST', p, b, who), get: (p, who = OP) => call('GET', p, undefined, who), tick: (min) => { clock += min * 60000; }, at: () => clock };
}
const audits = (s, action) => s.e.app.store.auditTail(200).filter((x) => x.action === action);
async function connect(s) {
  let r = await s.put('/vulnscan/config', { socket: s.gm.socket, username: 'zyberon', password: 'synthetic-pw' }, ADM); assert.equal(r.status, 200, r.raw);
  r = await s.put('/vulnscan/scope', { allowed: ['10.20.0.0/16'], exclude: ['10.20.9.9'] }, ADM); assert.equal(r.status, 200, r.raw);
}
const win = (s, fromMin, toMin) => ({ window_start: new Date(s.at() + fromMin * 60000).toISOString(), window_end: new Date(s.at() + toMin * 60000).toISOString() });

test('GMP client: only allowed commands, root tag must match, values escaped, the parser keeps entities as text', async () => {
  assert.equal(G.xesc('a<b>&"\''), 'a&lt;b&gt;&amp;&quot;&apos;');
  const n = G.parseXml('<a x="1&amp;2"><b>t &lt;x&gt;</b><![CDATA[<raw>]]><!-- c --></a>');
  assert.equal(n.attrs.x, '1&2'); assert.equal(G.txt(n, 'b'), 't <x>'); assert.equal(n.text, '<raw>');
  assert.throws(() => G.parseXml('<a><b></a>'), /mismatched/);
  const gm = await startGmpMock(); const g = await G.openGmp({ socket: gm.socket });
  await assert.rejects(g.send('delete_task', '<delete_task task_id="x"/>'), /not allowed/);
  await assert.rejects(g.send('get_tasks', '<delete_task/>'), /is not get_tasks/);
  await assert.rejects(g.send('get_version', '<get_version/>'), /refused get_version: Authenticate first/);
  g.close(); await gm.close();
  assert.ok(!gm.st.commands.some((c) => c.name === 'delete_task'), 'a refused command never reaches gvmd');
});

test('settings and scope: admin only, private ranges only, test names the failing step and its fix', async (t) => {
  const s = await setup(t);
  assert.equal((await s.put('/vulnscan/config', { socket: s.gm.socket, username: 'zyberon', password: 'x' }, OP)).status, 403);
  let r = await s.put('/vulnscan/config', { username: 'zyberon' }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /socket or host/);
  r = await s.put('/vulnscan/config', { host: '10.20.0.9', username: 'zyberon' }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /pin/);
  r = await s.put('/vulnscan/config', { socket: 'relative/path', username: 'zyberon' }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /socket/);
  r = await s.put('/vulnscan/scope', { allowed: ['8.8.8.0/24'] }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /allowed: .*RFC 1918/);
  r = await s.put('/vulnscan/scope', { allowed: ['10.0.0.0/7'] }, ADM); assert.equal(r.status, 400);
  r = await s.put('/vulnscan/config', { socket: s.gm.socket, username: 'zyberon', password: 'wrong-pw' }, ADM); assert.equal(r.status, 200);
  assert.ok(!JSON.stringify(r.json).includes('wrong-pw'), 'the password is never returned');
  r = await s.post('/vulnscan/test', {}, ADM); assert.equal(r.json.ok, false);
  const failed = r.json.steps.find((x) => x.status === 'fail'); assert.equal(failed.step, 'Log in'); assert.match(failed.fix, /new-password/);
  await connect(s);
  r = await s.post('/vulnscan/test', {}, ADM); assert.equal(r.status, 200, r.raw); assert.equal(r.json.ok, true, JSON.stringify(r.json.steps));
  assert.deepEqual(r.json.steps.map((x) => x.step).slice(0, 4), ['Connection settings', 'Password', 'Reach gvmd', 'Log in']);
  const au = audits(s, 'vulnscan.config').pop(); assert.equal(au.by, ADM.user); assert.equal(au.detail.password_changed, true); assert.ok(!JSON.stringify(au).includes('synthetic-pw'), 'no password in the audit trail');
  assert.equal(audits(s, 'vulnscan.scope').pop().detail.allowed[0], '10.20.0.0/16');
  r = await s.put('/vulnscan/config', { socket: '/nonexistent/gvmd.sock', username: 'zyberon' }, ADM);
  r = await s.post('/vulnscan/test', {}, ADM); const f2 = r.json.steps.find((x) => x.status === 'fail'); assert.equal(f2.step, 'Reach gvmd'); assert.match(f2.fix, /is Greenbone running/);
});

test('request → four-eyes approval → starts in its window → report imported with drops counted; roles and validation', async (t) => {
  const s = await setup(t); await connect(s);
  assert.equal((await s.post('/vulnscan/scans', Object.assign({ name: 'x', targets: ['10.20.1.0/24'], reason: 'r' }, win(s, 5, 120)), VIEW)).status, 403, 'viewer');
  assert.equal((await s.get('/vulnscan', VIEW)).status, 403, 'viewers do not read vulnerability details');
  let r = await s.post('/vulnscan/scans', Object.assign({ name: 'x', targets: ['192.168.5.0/24'], reason: 'r' }, win(s, 5, 120)), OP); assert.equal(r.status, 400); assert.match(r.json.error, /targets: .*outside the internal scan scope/);
  r = await s.post('/vulnscan/scans', Object.assign({ name: 'x', targets: ['10.20.0.0/16'], reason: 'r' }, win(s, 5, 120)), OP); assert.equal(r.status, 400); assert.match(r.json.error, /more than 4096/);
  r = await s.post('/vulnscan/scans', Object.assign({ name: 'x', targets: ['10.20.1.0/24'], reason: 'r' }, win(s, 5, 60 * 13)), OP); assert.equal(r.status, 400); assert.match(r.json.error, /window_end/);
  r = await s.post('/vulnscan/scans', { name: 'x', targets: ['10.20.1.0/24'], reason: 'r', window_start: 'tomorrow', window_end: 'later' }, OP); assert.equal(r.status, 400); assert.match(r.json.error, /window_start/);
  r = await s.post('/vulnscan/scans', Object.assign({ name: 'Server VLAN (synthetic)', targets: ['10.20.1.0/24'], reason: 'quarterly VAPT (synthetic)', state: 'approved' }, win(s, 5, 120)), OP);
  assert.equal(r.status, 200, r.raw); const id = r.json.id; assert.equal(r.json.state, 'requested', 'undeclared fields are dropped'); assert.equal(r.json.hosts, 254);
  assert.equal(audits(s, 'vulnscan.scan.request').pop().by, OP.user);
  assert.equal((await s.post('/vulnscan/scans/' + id + '/approve', {}, OP)).status, 403, 'an operator who is not a named approver');
  r = await s.post('/vulnscan/scans', Object.assign({ name: 'y', targets: ['10.20.2.0/24'], reason: 'r' }, win(s, 5, 120)), ADM);
  assert.equal((await s.post('/vulnscan/scans/' + r.json.id + '/approve', {}, ADM)).status, 403, 'four-eyes: not the requester');
  assert.equal((await s.post('/vulnscan/scans/' + r.json.id + '/reject', {}, ADM2)).status, 400, 'a rejection needs a note');
  assert.equal((await s.post('/vulnscan/scans/' + r.json.id + '/reject', { note: 'change freeze (synthetic)' }, ADM2)).json.state, 'rejected');
  assert.equal((await s.post('/vulnscan/scans/' + id + '/approve', {}, ADM)).json.state, 'approved');
  assert.equal(audits(s, 'vulnscan.scan.approve').pop().detail.requested_by, OP.user);
  await s.V.tick(); assert.equal((await s.get('/vulnscan/scans/' + id)).json.state, 'approved', 'not before the window opens');
  assert.ok(!s.gm.st.commands.some((c) => c.name === 'create_target'));
  s.tick(6); await s.V.tick();
  let sc = (await s.get('/vulnscan/scans/' + id)).json; assert.equal(sc.state, 'running');
  const tgt = s.gm.st.commands.find((c) => c.name === 'create_target').xml;
  assert.equal(G.txt(tgt, 'hosts'), '10.20.1.0/24'); assert.equal(G.txt(tgt, 'exclude_hosts'), '10.20.9.9', 'the scope exclusions go to Greenbone');
  await s.V.tick(); sc = (await s.get('/vulnscan/scans/' + id)).json; assert.equal(sc.progress, 40);
  s.gm.st.status = 'Done'; await s.V.tick();
  sc = (await s.get('/vulnscan/scans/' + id)).json;
  assert.equal(sc.state, 'done'); assert.deepEqual(sc.counts, { critical: 1, high: 1, medium: 0, low: 0 }); assert.equal(sc.dropped.log, 1); assert.equal(sc.dropped.low_qod, 1); assert.equal(sc.new_findings, 2);
  const v = (await s.get('/vulnscan')).json; assert.equal(v.open_total, 2); assert.equal(v.hosts[0].host, '10.20.1.6');
  assert.ok(audits(s, 'vulnscan.scan.import').length);
});

test('the approved window is enforced: a running scan is stopped at the end and its partial results kept', async (t) => {
  const s = await setup(t); await connect(s);
  const id = (await s.post('/vulnscan/scans', Object.assign({ name: 'x', targets: ['10.20.1.0/24'], reason: 'r' }, win(s, 0, 60)), OP)).json.id;
  await s.post('/vulnscan/scans/' + id + '/approve', {}, ADM);
  await s.V.tick(); s.tick(61); await s.V.tick();
  let sc = (await s.get('/vulnscan/scans/' + id)).json; assert.equal(sc.state, 'stopping'); assert.ok(s.gm.st.commands.some((c) => c.name === 'stop_task'));
  await s.V.tick(); sc = (await s.get('/vulnscan/scans/' + id)).json;
  assert.equal(sc.state, 'stopped'); assert.equal(sc.partial, true); assert.match(sc.history.map((h) => h.what).join(' | '), /window ended/);
  // an approved scan whose window passes before it starts expires
  const id2 = (await s.post('/vulnscan/scans', Object.assign({ name: 'y', targets: ['10.20.3.0/24'], reason: 'r' }, win(s, 10, 20)), OP)).json.id;
  await s.post('/vulnscan/scans/' + id2 + '/approve', {}, ADM); s.tick(30); await s.V.tick();
  assert.equal((await s.get('/vulnscan/scans/' + id2)).json.state, 'expired');
});

test('fixed only when a later scan of the host stops reporting it; risk acceptance is four-eyes; owner; CSV', async (t) => {
  const s = await setup(t); await connect(s);
  const run = async () => {
    const id = (await s.post('/vulnscan/scans', Object.assign({ name: 'x', targets: ['10.20.1.0/24'], reason: 'r' }, win(s, 0, 120)), OP)).json.id;
    await s.post('/vulnscan/scans/' + id + '/approve', {}, ADM); s.gm.st.status = 'Running'; await s.V.tick(); s.gm.st.status = 'Done'; await s.V.tick(); s.tick(130); return id;
  };
  await run();
  let list = (await s.get('/vulnscan/findings')).json; assert.equal(list.total, 2); const crit = list.items[0]; assert.equal(crit.severity, 'critical');
  // second scan: the critical one is gone on a host that was scanned; 10.20.1.5 was not scanned this time
  s.gm.st.findings = [F1]; s.gm.st.hosts = ['10.20.1.6'];
  await run();
  const fx = (await s.get('/vulnscan/findings/' + crit.id)).json; assert.equal(fx.status, 'fixed'); assert.match(fx.history.pop().what, /not reported by .*scanned 10\.20\.1\.6/);
  list = (await s.get('/vulnscan/findings')).json; assert.equal(list.total, 1, 'the finding on a host that was not scanned stays open');
  const hi = list.items[0];
  let r = await s.post('/vulnscan/findings/' + hi.id + '/owner', { owner: 'faris.syn', role: 'admin' }, OP); assert.equal(r.json.owner, 'faris.syn');
  r = await s.post('/vulnscan/findings/' + hi.id + '/accept-risk', { reason: 'compensating control (synthetic)', until: '2029-01-01' }, OP); assert.equal(r.status, 400); assert.match(r.json.error, /until/);
  r = await s.post('/vulnscan/findings/' + hi.id + '/accept-risk', { reason: 'legacy app, isolated VLAN (synthetic)', until: '2027-06-30' }, OP); assert.equal(r.json.risk.state, 'pending');
  assert.equal((await s.post('/vulnscan/findings/' + hi.id + '/risk-decision', { decision: 'approve' }, OP)).status, 403);
  assert.equal((await s.post('/vulnscan/findings/' + hi.id + '/risk-decision', { decision: 'reject' }, ADM)).status, 400, 'rejection needs a note');
  r = await s.post('/vulnscan/findings/' + hi.id + '/risk-decision', { decision: 'approve' }, ADM); assert.equal(r.json.status, 'risk_accepted');
  assert.equal(audits(s, 'vulnscan.finding.risk-approve').pop().detail.requested_by, OP.user);
  assert.equal((await s.get('/vulnscan/findings')).json.total, 0); assert.equal((await s.get('/vulnscan/findings?status=risk_accepted')).json.total, 1);
  assert.equal((await s.get('/vulnscan/findings?sev=bad')).status, 400);
  // the hostile NVT name is data: exported with a formula guard, never interpreted
  s.gm.st.findings = [Object.assign({}, F2, { name: '=HYPERLINK("http://x") synthetic' })]; s.gm.st.hosts = ['10.20.1.6']; await run();
  r = await s.get('/vulnscan/export'); assert.equal(r.status, 200);
  assert.ok(!/(^|,)"=/m.test(r.json.csv), 'no cell starts with ='); assert.equal(audits(s, 'vulnscan.export').pop().by, OP.user);
  assert.equal((await s.get('/vulnscan/export', VIEW)).status, 403);
});
