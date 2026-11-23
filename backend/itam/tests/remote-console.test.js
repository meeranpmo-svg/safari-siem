// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Remote console (engine/remote-console.js, engine/ws.js) through the real routes and the real WebSocket tunnel against a FAKE
// guacd on SYNTHETIC servers: protocols from the register, a request needs a reason, four eyes (the requester never approves,
// a service identity never approves, named approvers), the window, one-time tickets bound to the person, the Guacamole
// handshake with recording on, file transfer and copy off and NO credential sent by the platform, ping answered, file
// instructions dropped, the window closing the session, roles, validation errors and the audit records.
const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const net = require('node:net');
const crypto = require('node:crypto');
const { startApp, SECRET } = require('./helpers');
const { registerDuty } = require('../engine/duty');
const { enc, createParser } = require('../engine/remote-console');

const VIEW = { user: 'vera.syn', role: 'viewer' }, OP = { user: 'nora.syn', role: 'operator' }, OP2 = { user: 'omar.syn', role: 'operator' }, ADM = { user: 'syed', role: 'admin' }, BOT = { user: 'ai:virt-admin', role: 'admin' };

function fakeGuacd() {   // answers select with args, connect with ready, records what it got
  const got = { selects: [], connects: [], after: [] };
  const srv = net.createServer((c) => {
    c.setEncoding('utf8'); const feed = createParser(); let names = null;
    c.on('data', (d) => { for (const x of feed(d)) {
      if (x.op === 'select') { got.selects.push(x.args[0]); names = x.args[0] === 'rdp' ? ['VERSION_1_5_0', 'hostname', 'port', 'username', 'password', 'security', 'ignore-cert', 'disable-copy', 'disable-paste', 'enable-drive', 'enable-sftp', 'recording-path', 'recording-name', 'create-recording-path', 'recording-include-keys'] : ['VERSION_1_5_0', 'hostname', 'port', 'username', 'password', 'enable-sftp', 'disable-copy', 'recording-path', 'recording-name']; c.write(enc('args', ...names)); }
      else if (x.op === 'connect') { const o = {}; names.forEach((n, i) => { o[n] = x.args[i]; }); got.connects.push(o); c.write(enc('ready', '$synthetic-conn') + enc('sync', '1')); }
      else got.after.push(x.op);
    } });
    c.on('error', () => {});
  });
  return new Promise((r) => srv.listen(0, '127.0.0.1', () => r({ srv, port: srv.address().port, got })));
}
function wsOpen(port, path, who) {   // a raw WebSocket client: proxy secret + identity headers like nginx adds
  return new Promise((resolve, reject) => {
    const key = crypto.randomBytes(16).toString('base64');
    const req = http.request({ host: '127.0.0.1', port, path, headers: { Connection: 'Upgrade', Upgrade: 'websocket', 'Sec-WebSocket-Key': key, 'Sec-WebSocket-Version': '13', 'Sec-WebSocket-Protocol': 'guacamole', 'x-sentra-proxy-secret': SECRET, 'x-auth-user': who.user, 'x-auth-role': who.role } });
    req.on('response', (res) => resolve({ status: res.statusCode }));
    req.on('upgrade', (res, sock) => {
      let buf = Buffer.alloc(0); const msgs = [], waiters = [];
      sock.on('data', (d) => { buf = Buffer.concat([buf, d]); while (buf.length >= 2) { let len = buf[1] & 127, off = 2; if (len === 126) { len = buf.readUInt16BE(2); off = 4; } if (buf.length < off + len) break; const op = buf[0] & 15, data = buf.slice(off, off + len); buf = buf.slice(off + len); msgs.push(op === 8 ? { close: data.length > 2 ? data.slice(2).toString() : '' } : data.toString()); waiters.splice(0).forEach((w) => w()); } });
      const send = (t) => { const p = Buffer.from(t), m = crypto.randomBytes(4), h = p.length < 126 ? Buffer.from([0x81, 0x80 | p.length]) : Buffer.from([0x81, 0xfe, p.length >> 8, p.length & 255]); const x = Buffer.alloc(p.length); for (let i = 0; i < p.length; i++) x[i] = p[i] ^ m[i & 3]; sock.write(Buffer.concat([h, m, x])); };
      const until = (fn, ms = 4000) => new Promise((ok, no) => { const t0 = Date.now(); const chk = () => { const hit = msgs.find(fn); if (hit) return ok(hit); if (Date.now() - t0 > ms) return no(new Error('timeout; got ' + JSON.stringify(msgs))); waiters.push(chk); setTimeout(chk, 50); }; chk(); });
      resolve({ status: 101, protocol: res.headers['sec-websocket-protocol'], msgs, send, until, end: () => sock.destroy() });
    });
    req.on('error', reject); req.end();
  });
}

async function setup(t, extra = {}) {
  const g = await fakeGuacd(); t.after(() => g.srv.close());
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, consoleConfig: { enabled: true, guacd_port: g.port, recording_dir: '/tmp/sentra-console-synthetic' }, ...extra });
  const mk = (x) => e.app.assets.create(Object.assign({ status: 'in_use', type: 'server' }, x), ADM).asset.id;
  const id = { win: mk({ name: 'WIN-SYN-1', os: 'Windows Server 2022', mgmt_ip: '10.95.0.10' }), lin: mk({ name: 'SOL-SYN-1', os: 'Solaris 11.4', mgmt_ip: '10.95.0.11' }),
    esx: mk({ name: 'ESX-SYN-1', os: 'VMware ESXi 8.0', mgmt_ip: '10.95.0.12' }), noip: mk({ name: 'SRV-SYN-NOIP' }) };
  const call = (m, p, b, who) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who));
  return { e, g, id, call };
}
const auditOf = (e, action) => e.app.store.auditTail(300).filter((x) => x.action === action);

test('targets and protocols, request validation, four eyes, named approvers, roles', async (t) => {
  const { e, id, call } = await setup(t);
  let r = await call('GET', '/console', undefined, VIEW); assert.equal(r.status, 403, 'viewers never see the console');
  r = await call('GET', '/console', undefined, OP); assert.equal(r.status, 200, r.raw);
  const tg = r.json.targets;
  assert.deepEqual(tg.find((x) => x.id === id.win).protocols.map((p) => p.protocol), ['rdp']);
  assert.deepEqual(tg.find((x) => x.id === id.lin).protocols.map((p) => p.protocol), ['ssh']);
  assert.deepEqual(tg.find((x) => x.id === id.esx).protocols.map((p) => p.protocol), ['ssh', 'web']);
  assert.ok(!tg.some((x) => x.id === id.noip), 'no management IP: not a target');
  r = await call('POST', '/console/requests', { asset_id: id.win, protocol: 'rdp', minutes: 60, reason: 'short' }, OP); assert.equal(r.status, 400); assert.match(r.json.error, /reason must be at least 10/);
  r = await call('POST', '/console/requests', { asset_id: id.win, protocol: 'rdp', minutes: 999, reason: 'patch KB5031 (synthetic)' }, OP); assert.equal(r.status, 400); assert.match(r.json.error, /minutes must be at most 240/);
  r = await call('POST', '/console/requests', { asset_id: id.win, protocol: 'ssh', minutes: 60, reason: 'patch KB5031 (synthetic)' }, OP); assert.equal(r.status, 400); assert.match(r.json.error, /protocol must be one of rdp/);
  r = await call('POST', '/console/requests', { asset_id: id.noip, protocol: 'rdp', minutes: 60, reason: 'patch KB5031 (synthetic)' }, OP); assert.equal(r.status, 404);
  r = await call('POST', '/console/requests', { asset_id: id.win, protocol: 'rdp', minutes: 60, reason: 'patch KB5031 (synthetic)' }, BOT); assert.equal(r.status, 403);
  r = await call('POST', '/console/requests', { asset_id: id.win, protocol: 'rdp', minutes: 60, reason: 'patch KB5031 (synthetic)', by: 'someone.else' }, OP); assert.equal(r.status, 200, r.raw);
  const rq = r.json.request; assert.equal(rq.by, 'nora.syn', 'undeclared fields are dropped'); assert.equal(rq.status, 'pending');
  r = await call('POST', '/console/requests', { asset_id: id.win, protocol: 'rdp', minutes: 60, reason: 'patch KB5031 (synthetic)' }, OP); assert.equal(r.status, 409, 'one open request per server');
  r = await call('POST', '/console/requests/' + rq.id + '/ticket', undefined, OP); assert.equal(r.status, 409); assert.match(r.json.error, /waiting for approval/);
  r = await call('POST', '/console/requests/' + rq.id + '/decide', { decision: 'approve' }, OP); assert.equal(r.status, 403); assert.match(r.json.error, /four eyes/);
  r = await call('POST', '/console/requests/' + rq.id + '/decide', { decision: 'approve' }, BOT); assert.equal(r.status, 403);
  r = await call('POST', '/console/requests/' + rq.id + '/decide', { decision: 'reject' }, OP2); assert.equal(r.status, 400); assert.match(r.json.error, /note is required/);
  r = await call('POST', '/console/config', { approvers: ['syed'] }, OP); assert.equal(r.status, 403, 'settings are admin-only');
  r = await call('POST', '/console/config', { approvers: ['syed'], recording_dir: 'relative/path' }, ADM); assert.equal(r.status, 400);
  r = await call('POST', '/console/config', { approvers: ['syed'] }, ADM); assert.equal(r.status, 200);
  assert.equal((await call('GET', '/console', undefined, OP2)).json.waiting.length, 0, 'not a named approver: nothing waiting');
  r = await call('POST', '/console/requests/' + rq.id + '/decide', { decision: 'approve' }, OP2); assert.equal(r.status, 403); assert.match(r.json.error, /named console approvers/);
  r = await call('POST', '/console/requests/' + rq.id + '/decide', { decision: 'approve', note: 'change CHG-1 (synthetic)' }, ADM); assert.equal(r.status, 200, r.raw);
  assert.equal(r.json.request.status, 'approved'); assert.ok(Date.parse(r.json.request.window_end) - Date.parse(r.json.request.window_start) === 3600000);
  const a = auditOf(e, 'console.approve')[0]; assert.equal(a.by, 'syed'); assert.equal(a.detail.requested_by, 'nora.syn');
  r = await call('POST', '/console/requests/' + rq.id + '/ticket', undefined, ADM); assert.equal(r.status, 403, 'only the requester connects');
  r = await call('POST', '/console/requests/' + rq.id + '/end', { reason: 'done (synthetic)' }, OP2); assert.equal(r.status, 403);
  r = await call('POST', '/console/requests/' + rq.id + '/end', { reason: 'done (synthetic)' }, OP); assert.equal(r.status, 200);
  r = await call('POST', '/console/requests/' + rq.id + '/ticket', undefined, OP); assert.equal(r.status, 409, 'ended: no more connections');
  assert.ok(auditOf(e, 'console.request').length === 1 && auditOf(e, 'console.end').length === 1);
});

test('the tunnel: one-time ticket for the person, handshake with recording, no credentials, ping, no file transfer, window closes it', async (t) => {
  const { e, g, id, call } = await setup(t);
  const rq = (await call('POST', '/console/requests', { asset_id: id.win, protocol: 'rdp', minutes: 30, reason: 'patch KB5031 (synthetic)' }, OP)).json.request;
  await call('POST', '/console/requests/' + rq.id + '/decide', { decision: 'approve' }, OP2);
  let tk = (await call('POST', '/console/requests/' + rq.id + '/ticket', undefined, OP)).json;
  assert.match(tk.token, /^[a-f0-9]{48}$/);
  let w = await wsOpen(e.port, '/api/itam/console/tunnel?token=' + tk.token, OP2); assert.equal(w.status, 403, 'a ticket belongs to the person');
  w = await wsOpen(e.port, '/api/itam/console/tunnel?token=' + tk.token, OP); assert.equal(w.status, 403, 'and it is used once (even a refused use)');
  w = await wsOpen(e.port, '/api/itam/console/tunnel?token=' + tk.token, VIEW); assert.equal(w.status, 403);
  tk = (await call('POST', '/console/requests/' + rq.id + '/ticket', undefined, OP)).json;
  w = await wsOpen(e.port, '/api/itam/console/tunnel?token=' + tk.token + '&width=1600&height=900&dpi=96', OP);
  assert.equal(w.status, 101); assert.equal(w.protocol, 'guacamole');
  const first = await w.until((m) => typeof m === 'string');
  assert.match(first, /^0\.,15\.cs_[a-f0-9]{12};/, 'the tunnel UUID first');
  await w.until((m) => typeof m === 'string' && /4\.sync/.test(m));
  assert.deepEqual(g.got.selects, ['rdp']);
  const c = g.got.connects[0];
  assert.equal(c.hostname, '10.95.0.10'); assert.equal(c.port, '3389'); assert.equal(c.security, 'nla');
  assert.equal(c.username, '', 'the platform sends no user name'); assert.equal(c.password, '', 'and no password: the person types them');
  assert.equal(c['enable-drive'], ''); assert.equal(c['enable-sftp'], ''); assert.equal(c['disable-copy'], 'true');
  assert.equal(c['recording-path'], '/tmp/sentra-console-synthetic'); assert.match(c['recording-name'], new RegExp('^' + rq.id + '-cs_[a-f0-9]{12}\\.guac$')); assert.equal(c['recording-include-keys'], '', 'keystrokes are not recorded');
  w.send(enc('', 'ping', '12345')); await w.until((m) => m === enc('', 'ping', '12345'));
  w.send(enc('file', '1', 'application/octet-stream', 'evil.exe') + enc('mouse', '10', '10', '0'));
  await new Promise((r) => setTimeout(r, 200));
  assert.ok(g.got.after.includes('mouse') && !g.got.after.includes('file') && !g.got.after.includes(''), 'input relayed, file transfer and keep-alives not');
  let v = (await call('GET', '/console', undefined, OP)).json; assert.equal(v.live.length, 1);
  assert.ok(auditOf(e, 'console.session.start')[0].detail.recording);
  // the window ends: the sweep closes the session
  e.app.store.collection('console_requests').patch(rq.id, (x) => { x.window_end = new Date(Date.now() - 1000).toISOString(); });
  e.app.addons.remoteConsole.sweep();
  const closing = await w.until((m) => m && m.close !== undefined);
  assert.equal(closing.close, '521');
  assert.equal(e.app.store.collection('console_requests').get(rq.id).status, 'expired');
  v = (await call('GET', '/console', undefined, OP)).json; assert.equal(v.live.length, 0);
  const end = auditOf(e, 'console.session.end')[0]; assert.match(end.detail.reason, /window ended/);
  const all = JSON.stringify(e.app.store.auditTail(300)) + JSON.stringify(e.logs || []);
  assert.ok(!/password=|"password":"[^"]/.test(all), 'no credential anywhere in the audit or the log');
  let r = await call('GET', '/console/recordings', undefined, OP); assert.equal(r.status, 403, 'recordings are admin-only');
  r = await call('GET', '/console/recordings', undefined, ADM); assert.equal(r.status, 200); assert.equal(r.json.recordings.length, 1);
  r = await call('GET', '/console/recordings/' + r.json.recordings[0].id, undefined, ADM); assert.equal(r.status, 404, 'the fake gateway wrote no file - said, not a crash');
});

test('web consoles are a launcher; the gateway switched off refuses rdp / ssh; a dead gateway is reported', async (t) => {
  const { e, id, call } = await setup(t, { consoleConfig: { enabled: false } });
  const rq = (await call('POST', '/console/requests', { asset_id: id.esx, protocol: 'web', minutes: 15, reason: 'check vSAN health (synthetic)' }, OP)).json.request;
  await call('POST', '/console/requests/' + rq.id + '/decide', { decision: 'approve' }, OP2);
  let r = await call('POST', '/console/requests/' + rq.id + '/ticket', undefined, OP); assert.equal(r.status, 200);
  assert.equal(r.json.url, 'https://10.95.0.12/'); assert.match(r.json.note, /not proxied or recorded/);
  assert.equal(auditOf(e, 'console.web.open').length, 1);
  const rs = (await call('POST', '/console/requests', { asset_id: id.lin, protocol: 'ssh', minutes: 15, reason: 'check zpool (synthetic)' }, OP)).json.request;
  await call('POST', '/console/requests/' + rs.id + '/decide', { decision: 'approve' }, OP2);
  r = await call('POST', '/console/requests/' + rs.id + '/ticket', undefined, OP); assert.equal(r.status, 409); assert.match(r.json.error, /not switched on/);
  await call('POST', '/console/config', { enabled: true, guacd_port: 1 }, ADM);
  const tk = (await call('POST', '/console/requests/' + rs.id + '/ticket', undefined, OP)).json;
  const w = await wsOpen(e.port, '/api/itam/console/tunnel?token=' + tk.token, OP);
  assert.equal(w.status, 101);
  const err = await w.until((m) => typeof m === 'string' && /5\.error/.test(m)); assert.match(err, /not reachable/);
  assert.equal(auditOf(e, 'console.session.fail').length, 1);
});

test('Guacamole parser: code points, split chunks, malformed input', () => {
  const p = createParser();
  assert.deepEqual(p('4.sync,2.'), []);
  const out = p('ab;5.mouse,2.\u{1F600}x,1.1;');
  assert.equal(out.length, 2); assert.deepEqual(out[0].args, ['ab']); assert.deepEqual(out[1].args, ['\u{1F600}x', '1']);
  assert.equal(enc('x', '\u{1F600}'), '1.x,1.\u{1F600};');
  assert.throws(() => createParser()('zz.abc;'), /malformed/);
});

test('a WebSocket from another site is refused before anything is upgraded', async (t) => {
  const { e, id, call } = await setup(t);
  const rq = (await call('POST', '/console/requests', { asset_id: id.win, protocol: 'rdp', minutes: 30, reason: 'patch KB5031 (synthetic)' }, OP)).json.request;
  await call('POST', '/console/requests/' + rq.id + '/decide', { decision: 'approve' }, OP2);
  const tk = (await call('POST', '/console/requests/' + rq.id + '/ticket', undefined, OP)).json;
  const status = await new Promise((resolve) => {
    const r = http.request({ host: '127.0.0.1', port: e.port, path: '/api/itam/console/tunnel?token=' + tk.token, headers: { Connection: 'Upgrade', Upgrade: 'websocket', 'Sec-WebSocket-Key': crypto.randomBytes(16).toString('base64'), 'Sec-WebSocket-Version': '13', Origin: 'https://evil.example', 'x-sentra-proxy-secret': SECRET, 'x-auth-user': OP.user, 'x-auth-role': OP.role } });
    r.on('response', (res) => resolve(res.statusCode)); r.on('upgrade', () => resolve(101)); r.end();
  });
  assert.equal(status, 403);
  const w = await wsOpen(e.port, '/api/itam/console/tunnel?token=' + 'a'.repeat(48), { user: OP.user, role: OP.role });
  assert.equal(w.status, 403, 'an unknown ticket is refused');
});

test('out-of-band console (iDRAC / iLO / XClarity): admin records the controller, same four eyes, launcher only, reachability check', async (t) => {
  const { e, id, call } = await setup(t);
  const dell = e.app.assets.create({ status: 'in_use', type: 'server', name: 'DB-SYN-PHY', vendor: 'Dell', model: 'PowerEdge R750', os: 'Oracle Linux 8', mgmt_ip: '10.95.0.20' }, ADM).asset.id;
  const hpe = e.app.assets.create({ status: 'in_use', type: 'server', name: 'APP-SYN-PHY', vendor: 'HPE', model: 'ProLiant DL380' }, ADM).asset.id;
  const vm = e.app.assets.create({ status: 'in_use', type: 'vm', name: 'VM-SYN-1', mgmt_ip: '10.95.0.30' }, ADM).asset.id;
  let r = await call('GET', '/console', undefined, ADM);
  const ctl = r.json.controllers;
  assert.equal(ctl.find((x) => x.id === dell).suggest, 'idrac'); assert.equal(ctl.find((x) => x.id === hpe).suggest, 'ilo');
  assert.ok(!ctl.some((x) => x.id === vm), 'a VM has no controller of its own');
  assert.equal((await call('GET', '/console', undefined, OP)).json.controllers, undefined, 'the controller list is for administrators');
  // roles and validation
  r = await call('PUT', '/console/bmc/' + dell, { kind: 'idrac', address: '10.95.1.20' }, OP); assert.equal(r.status, 403, 'operators cannot record a controller');
  r = await call('PUT', '/console/bmc/' + dell, { kind: 'idrac', address: '10.95.1.20' }, BOT); assert.equal(r.status, 403, 'a service / AI identity cannot');
  r = await call('PUT', '/console/bmc/' + dell, { kind: 'drac9', address: '10.95.1.20' }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /kind/);
  r = await call('PUT', '/console/bmc/' + dell, { kind: 'idrac', address: 'https://10.95.1.20/login' }, ADM); assert.equal(r.status, 400); assert.match(r.json.error, /address must be the controller IP/);
  r = await call('PUT', '/console/bmc/' + dell, { kind: 'idrac', address: '10.95.1.300' }, ADM); assert.equal(r.status, 400);
  r = await call('PUT', '/console/bmc/' + vm, { kind: 'idrac', address: '10.95.1.30' }, ADM); assert.equal(r.status, 404);
  r = await call('PUT', '/console/bmc/' + dell, { kind: 'idrac', address: '10.95.1.20', password: 'never-stored', by: 'x' }, ADM); assert.equal(r.status, 200, r.raw);
  assert.equal(r.json.bmc.password, undefined, 'undeclared fields are dropped: no credential is kept'); assert.equal(r.json.bmc.by, 'syed'); assert.equal(r.json.bmc.port, 443);
  r = await call('PUT', '/console/bmc/' + hpe, { kind: 'ilo', address: '10.95.1.20' }, ADM); assert.equal(r.status, 409, 'one controller address, one server');
  r = await call('PUT', '/console/bmc/' + hpe, { kind: 'ilo', address: 'ilo-app-syn.example.test', port: 8443 }, ADM); assert.equal(r.status, 200, r.raw);
  const set = auditOf(e, 'console.bmc.set'); assert.equal(set.length, 2); assert.ok(set.some((x) => x.detail.address === '10.95.1.20' && x.detail.kind === 'idrac')); assert.ok(!JSON.stringify(set).includes('never-stored'));
  // targets: the controller is a protocol; a server with only a controller is a target
  r = await call('GET', '/console', undefined, OP);
  const td = r.json.targets.find((x) => x.id === dell), th = r.json.targets.find((x) => x.id === hpe);
  assert.deepEqual(td.protocols.map((p) => p.protocol), ['ssh', 'oob']); assert.equal(td.protocols[1].url, 'https://10.95.1.20/');
  assert.ok(th, 'no management IP but a controller: still reachable out of band'); assert.deepEqual(th.protocols.map((p) => p.protocol), ['oob']);
  assert.equal(th.protocols[0].url, 'https://ilo-app-syn.example.test:8443/');
  // the same four-eyes flow, then a launcher
  const rq = (await call('POST', '/console/requests', { asset_id: dell, protocol: 'oob', minutes: 60, reason: 'firmware update and reboot (synthetic)' }, OP)).json.request;
  assert.equal(rq.kind, 'idrac');
  r = await call('POST', '/console/requests/' + rq.id + '/decide', { decision: 'approve' }, OP); assert.equal(r.status, 403, 'the requester never approves');
  r = await call('POST', '/console/requests/' + rq.id + '/ticket', undefined, OP); assert.equal(r.status, 409);
  await call('POST', '/console/config', { enabled: false }, ADM);
  r = await call('POST', '/console/requests/' + rq.id + '/decide', { decision: 'approve' }, OP2); assert.equal(r.status, 200, r.raw);
  r = await call('POST', '/console/requests/' + rq.id + '/ticket', undefined, OP); assert.equal(r.status, 200, 'works with the gateway off: it is not proxied');
  assert.equal(r.json.url, 'https://10.95.1.20/'); assert.match(r.json.note, /Virtual Console/); assert.match(r.json.note, /not proxied or recorded/); assert.equal(r.json.token, undefined);
  assert.equal(auditOf(e, 'console.oob.open')[0].by, 'nora.syn');
  // reachability: a real TCP connect, nothing more
  const srv = net.createServer((c) => c.destroy()); await new Promise((ok) => srv.listen(0, '127.0.0.1', ok)); t.after(() => srv.close());
  await call('PUT', '/console/bmc/' + dell, { kind: 'idrac', address: '127.0.0.1', port: srv.address().port }, ADM);
  r = await call('POST', '/console/bmc/' + dell + '/check', undefined, VIEW); assert.equal(r.status, 403);
  r = await call('POST', '/console/bmc/' + dell + '/check', undefined, OP); assert.equal(r.status, 200, r.raw); assert.equal(r.json.reachable, true);
  srv.close(); await new Promise((ok) => setTimeout(ok, 50));
  r = await call('POST', '/console/bmc/' + dell + '/check', undefined, OP); assert.equal(r.json.reachable, false); assert.match(r.json.error, /refused|not reachable/);
  // forget
  r = await call('DELETE', '/console/bmc/' + hpe, undefined, OP); assert.equal(r.status, 403);
  r = await call('DELETE', '/console/bmc/' + hpe, undefined, ADM); assert.equal(r.status, 200);
  r = await call('DELETE', '/console/bmc/' + hpe, undefined, ADM); assert.equal(r.status, 404);
  assert.equal(auditOf(e, 'console.bmc.remove').length, 1);
  assert.ok(!(await call('GET', '/console', undefined, OP)).json.targets.some((x) => x.id === hpe), 'controller gone, no management IP: not a target');
});
