// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for the Remote Console (dashboards/server/remote-console.html + vendor/guacamole-common.js) against the REAL ITAM
// engine and its REAL WebSocket tunnel (engine/remote-console.js, engine/ws.js), with a FAKE guacd that asks for credentials
// the way guacd 1.5 does (required → argv streams), on SYNTHETIC servers: request with a reason, the requester cannot approve,
// another operator approves, Connect opens the console, the login box sends the person's own account straight to the gateway
// (never into the audit or the log), the session is live and recorded, Disconnect ends it, a web console is a launcher, the
// admin sees recordings and settings, a viewer is refused, the menu has the page.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node remote-console.test.js
const http = require('http'), net = require('net'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
const { enc, createParser } = require(path.join(ITAM, 'engine', 'remote-console'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const ADM = { user: 'syed', role: 'admin' }, OP = { user: 'nora.syn', role: 'operator' }, OP2 = { user: 'omar.syn', role: 'operator' }, VIEW = { user: 'vera.syn', role: 'viewer' };
const PW = 'Synthetic-Pa55word!';

(async () => {
  const got = { connects: [], argv: {}, after: [] };
  const guacd = net.createServer((c) => {
    c.setEncoding('utf8'); const feed = createParser(); let names = null; const streams = {};
    c.on('data', (d) => { for (const x of feed(d)) {
      if (x.op === 'select') { names = ['VERSION_1_5_0', 'hostname', 'port', 'username', 'password', 'security', 'recording-name']; c.write(enc('args', ...names)); }
      else if (x.op === 'connect') { const o = {}; names.forEach((k, i) => { o[k] = x.args[i]; }); got.connects.push(o); c.write(enc('ready', '$syn') + enc('required', 'username', 'password')); }
      else if (x.op === 'argv') streams[x.args[0]] = x.args[2];
      else if (x.op === 'blob') { got.argv[streams[x.args[0]]] = (got.argv[streams[x.args[0]]] || '') + Buffer.from(x.args[1], 'base64').toString(); }
      else if (x.op === 'end') { if (got.argv.password) c.write(enc('size', '0', '800', '600') + enc('rect', '0', '0', '0', '800', '600') + enc('cfill', '14', '0', '40', '80', '160', '255') + enc('sync', String(Date.now()))); }
      else got.after.push(x.op);
    } });
    c.on('error', () => {});
  });
  await new Promise((r) => guacd.listen(0, '127.0.0.1', r));
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, consoleConfig: { enabled: true, guacd_port: guacd.address().port, recording_dir: '/tmp/sentra-console-synthetic' } });
  const mk = (x) => e.app.assets.create(Object.assign({ status: 'in_use', type: 'server', site: 'HQ' }, x), ADM).asset.id;
  const id = { win: mk({ name: 'WIN-SYN-1', os: 'Windows Server 2022', mgmt_ip: '10.95.0.10' }), esx: mk({ name: 'ESX-SYN-1', os: 'VMware ESXi 8.0', mgmt_ip: '10.95.0.12' }), x: mk({ name: '<img src=x onerror=alert(1)>', os: 'Linux', mgmt_ip: '10.95.0.13' }) };
  const phy = mk({ name: 'DB-SYN-PHY', vendor: 'Dell', model: 'PowerEdge R750' });   // no management IP: only its controller can be reached
  let WHO = OP;
  const hdrs = () => ({ 'x-sentra-proxy-secret': H.SECRET, 'x-auth-user': WHO.user, 'x-auth-role': WHO.role });
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, WHO);
    if (u.pathname.startsWith('/api/itam/')) {
      const up = http.request({ host: '127.0.0.1', port: e.port, method: req.method, path: req.url, headers: Object.assign({}, req.headers, hdrs()) }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); });
      req.pipe(up); return;
    }
    if (u.pathname.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  srv.on('upgrade', (req, sock, head) => {   // what nginx does for /api/itam/console/tunnel: identity headers + Upgrade
    const up = net.connect(e.port, '127.0.0.1', () => {
      const h = Object.assign({}, req.headers, hdrs());
      up.write('GET ' + req.url + ' HTTP/1.1\r\n' + Object.entries(h).map(([k, v]) => k + ': ' + v).join('\r\n') + '\r\n\r\n'); if (head && head.length) up.write(head);
      up.pipe(sock); sock.pipe(up);
    });
    up.on('error', () => sock.destroy()); sock.on('error', () => up.destroy());
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg, ms) => p.waitForFunction(fn, arg, { timeout: ms || 20000 }).then(() => true, () => false);
  try {
    const p = await browser.newPage({ viewport: { width: 1440, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message));
    p.on('dialog', (d) => { errs.push('dialog: ' + d.message()); d.dismiss(); });
    await p.addInitScript(() => { window.open = (u) => { window.__opened = u; return null; }; });
    await p.goto(base + 'remote-console.html?standalone=1');
    ok(await wait(p, () => document.querySelectorAll('#targets .srv').length === 3), 'three servers to connect to');
    ok(/gateway on/.test(await p.textContent('#gw')), 'the gateway is on');
    ok(!(await p.$('#targets img')), 'a hostile server name stays text');
    // request
    await p.click('[data-pick="' + id.win + '"][data-proto="rdp"]');
    ok(await wait(p, () => !document.getElementById('reqform').hidden), 'the request form opens');
    await p.fill('#freason', 'short'); await p.click('#fsend'); ok(await wait(p, () => /10 characters/.test(document.body.textContent)), 'a reason is needed');
    await p.fill('#freason', 'patch KB5031 and reboot (synthetic)'); await p.fill('#fticket', 'CHG-1042'); await p.click('#fsend');
    ok(await wait(p, () => /pending/.test(document.getElementById('mine').textContent)), 'sent for approval');
    ok((await p.$$('#wait [data-approve]')).length === 0, 'the requester has nothing to approve');
    // another operator approves
    WHO = OP2; await p.reload();
    ok(await wait(p, () => document.querySelectorAll('#wait [data-approve]').length === 1), 'waiting for the other operator');
    ok(/asked by nora\.syn/.test(await p.textContent('#wait')), 'who asked');
    await p.click('#wait [data-approve]');
    ok(await wait(p, () => document.querySelectorAll('#wait [data-approve]').length === 0), 'approved');
    // connect as the requester
    WHO = OP; await p.reload();
    ok(await wait(p, () => !!document.querySelector('#mine [data-connect]')), 'Connect is offered inside the window');
    await p.click('#mine [data-connect]');
    ok(await wait(p, () => !document.getElementById('ov').hidden), 'the console opens');
    ok(await wait(p, () => !document.getElementById('cred').hidden && !!document.querySelector('#cred [data-cred="password"]')), 'the gateway asks for the login');
    ok((await p.inputValue('#cred [data-cred="username"]')) === 'nora.syn', 'the account is prefilled with the person, not a stored one');
    await p.fill('#cred [data-cred="password"]', PW); await p.click('#crgo');
    ok(await wait(p, () => /connected/.test(document.getElementById('status').textContent) && /recorded/.test(document.getElementById('ovrec').textContent)), 'connected and marked as recorded');
    ok(got.argv.username === 'nora.syn' && got.argv.password === PW, 'the login went straight to the gateway');
    ok(got.connects[0].username === '' && got.connects[0].password === '' && got.connects[0].hostname === '10.95.0.10', 'the platform sent no credential of its own');
    ok(e.app.store.collection('console_sessions').all(() => true).length === 1, 'the session is recorded in the register');
    await p.mouse.move(700, 500); await p.mouse.down(); await p.mouse.up();
    await new Promise((r) => setTimeout(r, 300)); ok(got.after.includes('mouse'), 'mouse input reaches the server');
    await p.click('#disc');
    ok(await wait(p, () => document.getElementById('ov').hidden), 'Disconnect closes the console');
    await new Promise((r) => setTimeout(r, 600)); ok(!!e.app.store.collection('console_sessions').all(() => true)[0].ended_at, 'the session ended');
    const trail = JSON.stringify(e.app.store.auditTail(300)) + JSON.stringify(e.logs || []) + fs.readdirSync(e.dir).map((f) => { try { return fs.readFileSync(path.join(e.dir, f), 'utf8'); } catch (x) { return ''; } }).join('');
    ok(!trail.includes(PW), 'the password is nowhere in the audit, the log or the store');
    // a web console is a launcher
    await p.click('[data-pick="' + id.esx + '"][data-proto="web"]'); await p.fill('#freason', 'check vSAN health (synthetic)'); await p.click('#fsend');
    ok(await wait(p, () => document.querySelectorAll('#mine .q').length === 2), 'second request');
    // admin: settings and recordings
    WHO = ADM; await p.reload();
    ok(await wait(p, () => !document.getElementById('c-set').hidden && !document.getElementById('c-rec').hidden), 'the admin sees settings and recordings');
    ok(await wait(p, () => /nora\.syn/.test(document.getElementById('recs').textContent)), 'the session is listed with its recording');
    await p.fill('#s-appr', 'syed'); await p.click('#ssave'); ok(await wait(p, () => /saved/.test(document.body.textContent)), 'settings saved');
    ok(await p.evaluate(() => { const a = (window.ZYB_NAV || []).find((x) => x.id === 'srv'); return !!(a && a.pages.some((x) => x.h === 'remote-console.html')); }), 'the menu has the page');
    // out-of-band controller: the admin records it, an operator requests it, another approves, it opens the controller
    ok(await wait(p, () => !document.getElementById('c-oob').hidden && !!document.querySelector('[data-oobrow]')), 'the admin sees the controller list');
    const row = '[data-oobrow="' + phy + '"]';
    ok((await p.inputValue(row + ' [data-ok]')) === 'idrac', 'iDRAC is suggested for a Dell server');
    await p.fill(row + ' [data-oa]', 'https://10.95.1.20/'); await p.click(row + ' [data-oobsave]');
    ok(await wait(p, () => /address must be the controller IP/.test(document.body.textContent)), 'a URL is refused with a message that names the field');
    await p.fill(row + ' [data-oa]', '10.95.1.20'); await p.click(row + ' [data-oobsave]');
    ok(await wait(p, (r) => !!document.querySelector(r + ' [data-oobdel]'), row), 'the controller is saved');
    ok(e.app.store.auditTail(50).some((x) => x.action === 'console.bmc.set' && x.by === 'syed'), 'the change is audited');
    WHO = OP; await p.reload();
    ok(await wait(p, (i) => !!document.querySelector('[data-pick="' + i + '"][data-proto="oob"]'), phy), 'the server now offers its iDRAC console');
    ok(!!(await p.$('[data-bmccheck="' + phy + '"]')), 'the reachability check is offered');
    await p.click('[data-pick="' + phy + '"][data-proto="oob"]');
    ok(/own controller account/.test(await p.textContent('#reqform')) && /POST, BIOS/.test(await p.textContent('#reqform')), 'the form says what it shows and whose login it uses');
    await p.fill('#freason', 'BIOS update and watch the reboot (synthetic)'); await p.click('#fsend');
    ok(await wait(p, () => document.querySelectorAll('#mine .q').length === 3), 'controller console requested');
    WHO = ADM; await p.reload(); ok(await wait(p, () => document.querySelectorAll('#wait [data-approve]').length >= 1), 'waiting for the named approver');
    await p.click('#wait [data-approve]'); await wait(p, () => /Approved/.test(document.body.textContent));
    WHO = OP; await p.reload();
    ok(await wait(p, () => [...document.querySelectorAll('#mine [data-connect]')].some((b) => /iDRAC/.test(b.textContent))), 'Open Dell iDRAC console is offered');
    await p.evaluate(() => [...document.querySelectorAll('#mine [data-connect]')].find((b) => /iDRAC/.test(b.textContent)).click());
    ok(await wait(p, () => window.__opened === 'https://10.95.1.20/'), 'the controller opens in a new tab');
    ok(e.app.store.auditTail(50).some((x) => x.action === 'console.oob.open' && x.by === 'nora.syn'), 'opening it is audited');
    WHO = VIEW; await p.reload();
    ok(await wait(p, () => /operators and administrators/.test(document.getElementById('err').textContent)), 'a viewer is refused');
  } finally { await browser.close(); srv.close(); guacd.close(); await e.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks');
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
