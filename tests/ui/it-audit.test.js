// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for it-audit.html after the same static build the server runs (build-static.js): with data it shows the
// changes matched to approved plans; when a source is missing, refused, failing, or answers 200 with a page instead of
// data (session ended, engine error page) the page never stays on "Loading" - each tile and table says why.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node it-audit.test.js
const http = require('http'), fs = require('fs'), path = require('path'), os = require('os'), cp = require('child_process');
const SRC = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0;
const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
// the build the server serves
const B = fs.mkdtempSync(path.join(os.tmpdir(), 'itaudit-')); fs.mkdirSync(path.join(B, 'vendor'));
fs.readdirSync(SRC).filter((f) => f.endsWith('.html')).forEach((f) => fs.copyFileSync(path.join(SRC, f), path.join(B, f)));
fs.readdirSync(path.join(SRC, 'vendor')).filter((f) => /\.(js|json|css)$/.test(f)).forEach((f) => fs.copyFileSync(path.join(SRC, 'vendor', f), path.join(B, 'vendor', f)));
['zyb-menu.js', 'zyb-dash.js'].forEach((t) => fs.writeFileSync(path.join(B, 'vendor', t), fs.readFileSync(path.join(B, 'vendor/zyb-nav.js'), 'utf8') + '\n' + fs.readFileSync(path.join(B, 'vendor', t), 'utf8')));
cp.execFileSync(process.execPath, [path.join(SRC, 'build-static.js'), B, 't1'], { stdio: 'ignore' });
const now = Date.now();
const DATA = { '/api/soc/audit': { items: [{ at: now - 36e5, by: 'syed', role: 'admin', action: 'netops.device.put', target: 'fw1', ip: '10.0.0.5' }, { at: now - 72e5, by: 'ali', role: 'viewer', action: 'access.denied', target: '/x', ip: '10.0.0.9' }] },
  '/api/soc/netops/evidence/changes': { items: [{ ts: 'x', at: now - 12 * 36e5, host_ip: '10.1.1.1', user: 'admin', message: 'config changed' }, { ts: 'x', at: now - 11 * 36e5, host_ip: '10.9.9.9', user: 'bob', message: 'unplanned' }, { ts: new Date(now - 10 * 36e5).toISOString(), host: 'fw-1', host_ip: '10.1.1.2', user: 'admin', message: 'matched by name' }] },
  '/api/soc/netops/changes': { items: [{ id: 'CP-1', device: 'd1', title: 'x', status: 'approved', decided_at: now - 864e5, decided_by: 'syed', proposed_by: 'ai', source: 'ai' }] },
  '/api/soc/netops/devices': { items: [{ id: 'd1', ip: '10.1.1.1', name: 'FW-1' }] },
  '/api/soc/sysadmin/changes': { items: [{ id: 'SCHG-1', device: 'srv1', title: 'patch', status: 'approved', decided_at: now - 864e5, decided_by: 'syed', proposed_by: 'ali', source: 'user' }] } };
// the engine reads the audit trail from its monthly journals when asked with since=
DATA['/api/soc/audit'].source = 'journal';
let MODE = 'data';
(async () => {
  const srv = http.createServer((q, r) => { const u = q.url.split('?')[0], j = (c, o) => { r.writeHead(c, { 'Content-Type': 'application/json' }); r.end(typeof o === 'string' ? o : JSON.stringify(o)); };
    if (u.endsWith('whoami.json')) return j(200, { user: 'syed', role: 'admin' });
    if (u.startsWith('/api/')) {
      if (MODE === 'cut' && u === '/api/soc/netops/evidence/changes' && /limit=1000/.test(q.url)) { r.writeHead(200, { 'Content-Type': 'text/html' }); return r.end('<html><body><h1>502 Bad Gateway</h1></body></html>'); }
      if (MODE === 'data' || MODE === 'cut') return DATA[u] ? j(200, DATA[u]) : j(404, {});
      if (MODE === 'login') { r.writeHead(200, { 'Content-Type': 'text/html' }); return r.end('<form method="POST" action="/login"><input name="user"><input name="pass" type="password"></form>'); }
      if (MODE === 'html') { r.writeHead(200, { 'Content-Type': 'text/html' }); return r.end('<h1>Bad gateway</h1>'); }
      if (MODE === 'denied') return j(403, { error: 'forbidden' });
      if (MODE === 'engine502') return u === '/api/soc/netops/evidence/changes' ? j(502, { error: 'ClickHouse: Code: 386. DB::Exception: There is no supertype for types String, DateTime (NO_COMMON_TYPE)' }) : DATA[u] ? j(200, DATA[u]) : j(404, {});
      return j(404, { error: 'not installed' }); }
    fs.readFile(path.join(B, u.replace(/^\/dashboards\//, '/')), (e, d) => { if (e) { r.writeHead(404); return r.end(); } r.writeHead(200, { 'Content-Type': u.endsWith('.js') ? 'application/javascript' : u.endsWith('.css') ? 'text/css' : 'text/html' }); r.end(d); }); });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const run = async (mode) => { MODE = mode; const p = await browser.newPage(); p.on('pageerror', (e) => errs.push(mode + ': ' + e.message));
    await p.goto('http://127.0.0.1:' + srv.address().port + '/dashboards/it-audit.html'); await p.waitForFunction(() => !/Loading/.test(document.getElementById('kpi').innerText), null, { timeout: 8000 }).catch(() => {});
    const st = await p.evaluate(() => ({ kpi: document.getElementById('kpi').innerText.replace(/\s+/g, ' '), chg: document.getElementById('chg').innerText, priv: document.getElementById('priv').innerText, plans: document.getElementById('plans').innerText, sync: document.getElementById('sync').innerText }));
    await p.close(); return st; };
  let s = await run('data');
  ok(/NETWORK CONFIG CHANGES 3/i.test(s.kpi) && /WITHOUT APPROVED PLAN 1/i.test(s.kpi), 'data: 3 changes, 1 without plan (one matched by host name): ' + s.kpi);
  ok(/FW-1/.test(s.chg) && /CP-1/.test(s.chg) && /none/.test(s.chg), 'data: change matched to CP-1, the other marked none');
  ok(/SCHG-1/.test(s.plans) && /server/.test(s.plans) && /CP-1/.test(s.plans), 'data: server change plans listed beside network plans: ' + s.plans.slice(0, 200));
  ok(!/restart/.test(s.priv) && /Synced/.test(s.sync), 'data: full-period trail, synced time shown: ' + s.sync);
  ok(/access\.denied/.test(s.priv), 'data: denied access listed');
  s = await run('cut');
  ok(/WITHOUT APPROVED PLAN 1/i.test(s.kpi) && /CP-1/.test(s.chg) && /did not come through as data/.test(s.chg) && /newest 200/.test(s.chg) && /text\/html/.test(s.chg) && /502 Bad Gateway/.test(s.chg), 'the full list cut / not JSON: the newest 200 shown and what came back named: ' + s.chg.slice(-260));
  s = await run('html');
  ok(/got text\/html, \d+ bytes: "Bad gateway/.test(s.chg), 'not JSON: the page names what came back: ' + s.chg.slice(0, 200));
  s = await run('login');
  ok(!/Loading/.test(s.kpi) && /session has ended/.test(s.kpi) && /session has ended/.test(s.chg), 'session ended (login page instead of data): says so, not stuck: ' + s.kpi.slice(0, 160));
  s = await run('html');
  ok(/did not answer with data/.test(s.chg) && /did not answer with data/.test(s.plans), 'error page instead of data: says so');
  s = await run('engine502');
  ok(/ClickHouse: Code: 386/.test(s.chg) && !/HTTP 200/.test(s.chg), 'an engine error (502 with its message) is shown as the engine wrote it, never as "not JSON": ' + s.chg.slice(0, 200));
  s = await run('denied');
  ok(/needs the administrator role/.test(s.priv) && /needs the analyst role/.test(s.chg), 'refused: names the role needed');
  s = await run('missing');
  ok(/not installed/.test(s.chg) && /CHANGE PLANS PENDING –/i.test(s.kpi), 'not installed: says so; pending plans shown as – not 0: ' + s.kpi.slice(-90));
  ok(!errs.length, 'page errors: ' + errs.join(' | '));
  await browser.close(); srv.close(); fs.rmSync(B, { recursive: true, force: true });
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
