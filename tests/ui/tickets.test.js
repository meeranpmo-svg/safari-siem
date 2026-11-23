// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for dashboards/server/tickets.html against the REAL ITAM engine (engine/ticket-intel.js over SYNTHETIC me_tickets) and
// a stubbed SIEM ServiceDesk Plus tickets endpoint: viewer told tickets are for operators; empty state says what to connect; KPI tiles
// (breached, at risk, waiting) filter the list; the age bar and breach risk; recurring problems and duplicates; flow and SLA tables;
// security tickets from the SIEM, and the SIEM not installed says so; ticket detail and AI off -> the error names it; a hostile
// title stays text; menu, installer and the portal redirect.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node tickets.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror="window.__xss=1">';

(async () => {
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true });
  const T = e.app.store.collection('me_tickets'), now = Date.now(), iso = (t) => new Date(t).toISOString(); let seq = 0;
  const put = (o) => T.put(Object.assign({ id: 'mt_syn' + (seq++), title: 'Disk C: 95% full on APP01', priority: 'High', status: 'closed', rule: 'disk', requested_by: 'system:itam', asset_id: 'as_app01', asset_name: 'APP01' }, o));
  let SIEM = 'none', WHO = { user: 'vera.syn', role: 'viewer' };
  const web = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, WHO);
    if (u.pathname.startsWith('/api/itam/')) { const h = Object.assign({}, req.headers, { 'x-sentra-proxy-secret': H.SECRET, 'x-auth-user': WHO.user, 'x-auth-role': WHO.role });
      const up = http.request({ host: '127.0.0.1', port: e.port, method: req.method, path: req.url, headers: h }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); }); req.pipe(up); return; }
    if (u.pathname === '/api/soc/integrations/manageengine/tickets') return SIEM === 'none' ? json(404, { error: 'no route' }) : json(200, { total: 1, items: [{ id: 'sdp:alert:A1', kind: 'alert', ref_id: 'ALR-0000042', request_id: '9001', url: 'https://sdp.example.test/WorkOrder.do?woID=9001', subject: 'Brute force on dana.syn (synthetic)', sdp_status: 'Open', technician: 'omar.syn', created_at: now - 3600e3, last_synced: now - 60e3, reopened: 1 }] });
    if (u.pathname === '/api/soc/integrations/manageengine/status') return json(200, { configured: true });
    if (u.pathname.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => web.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + web.address().port + '/dashboards/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg, { timeout: 15000 }).then(() => true, () => false);
  const open = async (who) => { WHO = who; const p = await browser.newPage({ viewport: { width: 1500, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message)); await p.goto(base + 'tickets.html'); return p; };
  const OP = { user: 'desk.lead', role: 'operator' };
  try {
    let p = await open({ user: 'vera.syn', role: 'viewer' });
    ok(await wait(p, () => /operators and administrators/.test(document.getElementById('msg').innerText)), 'viewer: tickets are for operators'); await p.close();
    p = await open(OP); await wait(p, () => !document.getElementById('main').hidden);
    ok(/No ticket raised yet/.test(await p.evaluate(() => document.getElementById('infra').innerText)), 'empty: says what to connect');
    await p.click('[data-tab="sec"]'); ok(await wait(p, () => /no ServiceDesk Plus integration yet/.test(document.getElementById('sec').innerText)), 'SIEM not installed: says so'); await p.close();
    for (let i = 0; i < 6; i++) { const at = now - (40 - i * 6) * 86400e3; put({ title: 'Disk C: ' + (90 + i) + '% full on APP01', requested_at: iso(at), closed_at: iso(at + (i < 4 ? 30 : 14) * 3600e3) }); }
    put({ id: 'mt_synopen1', title: 'Backup job failed on DB01', status: 'open', asset_id: 'as_db01', asset_name: 'DB01', requested_at: iso(now - 12 * 3600e3), sdp_id: '7001', sdp_status: 'Open' });
    put({ id: 'mt_synopen2', title: 'Backup job failed on DB01 again', status: 'open', asset_id: 'as_db01', asset_name: 'DB01', requested_at: iso(now - 2 * 3600e3) });
    put({ id: 'mt_synlate', title: 'UPS battery fault', priority: 'Urgent', status: 'open', asset_id: 'as_ups', asset_name: 'UPS1', requested_at: iso(now - 6 * 3600e3), rule: 'manual', requested_by: 'nora.syn' });
    put({ id: 'mt_synwait', title: 'Replace switch fan ' + XSS, priority: 'Low', status: 'pending', asset_name: 'SW1', requested_at: iso(now - 3600e3) });
    SIEM = 'ok';
    p = await open(OP); await wait(p, () => !document.getElementById('main').hidden);
    const k = await p.evaluate(() => document.getElementById('kk').innerText);
    ok(/Breached\s*1/.test(k) && /Waiting for approval\s*1/.test(k) && /Security tickets open\s*1/.test(k), 'KPI tiles: ' + k.replace(/\s+/g, ' '));
    const inf = await p.evaluate(() => document.getElementById('infra').innerText);
    ok(/UPS battery fault/.test(inf) && /breached/.test(inf) && /risk 67%/.test(inf), 'age bar, breached and learned risk');
    ok(await p.evaluate(() => !window.__xss), 'hostile title stays text');
    await p.click('[data-f="breach"]'); ok(await wait(p, () => document.querySelectorAll('#infra tr.click').length === 3), 'Breached tile filters (breached + at risk)');
    await p.click('[data-f="wait"]'); ok(await wait(p, () => document.querySelectorAll('#infra tr.click').length === 1 && /Replace switch fan/.test(document.getElementById('infra').innerText)), 'Waiting tile filters');
    await p.click('[data-f="wait"]');
    await p.click('[data-tab="prob"]'); const pr = await p.evaluate(() => document.getElementById('rec').innerText + document.getElementById('dup').innerText);
    ok(/APP01/.test(pr) && /6×/.test(pr) && /DB01/.test(pr) && /alike/.test(pr), 'recurring problem and duplicates');
    await p.click('[data-tab="perf"]'); const pf = await p.evaluate(() => document.getElementById('sla').innerText + document.getElementById('fc').innerText);
    ok(/33%/.test(pf) && /Backlog now 4/.test(pf), 'SLA met % and backlog');
    await p.click('[data-tab="sec"]'); ok(await wait(p, () => /#9001/.test(document.getElementById('sec').innerText) && /reopened 1/.test(document.getElementById('sec').innerText)), 'security tickets from the SIEM');
    await p.click('[data-tab="infra"]'); await p.click('tr[data-open="mt_synlate"]');
    ok(await wait(p, () => document.getElementById('dlg').open && /UPS1/.test(document.getElementById('dlg-b').innerText)), 'ticket detail');
    await p.click('[data-ai]'); ok(await wait(p, () => /AI/.test(document.getElementById('dlg-e').innerText)), 'AI off: the error names it');
    await p.close();
    ok(/ tickets\.html /.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')), 'in the installer');
    ok(/"h": "tickets.html"/.test(fs.readFileSync(path.join(DASH, 'vendor/zyb-nav.js'), 'utf8')), 'menu entry');
    ok(/tickets: 'tickets\.html'/.test(fs.readFileSync(path.join(DASH, 'vendor/zyb-menu.js'), 'utf8')) && /tickets: 'tickets\.html'/.test(fs.readFileSync(path.join(DASH, 'vendor/zyb-early.js'), 'utf8')), 'the portal\'s Tickets opens this page');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); web.close(); e.close(); }
  console.log(`${n - bad}/${n} checks passed`); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
