// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
// Browser test for support-center.html after the static build. The ManageEngine service-desk endpoints (/api/itam/me/*)
// are stubbed with SYNTHETIC tickets. Checks: reachable from the menu, KPI counts, the queue with per-priority "past
// target" ageing, status/priority filters that keep the search box, four-eyes (the server refuses approving your own
// request and the page shows the reason), raising a request validates the title and lands as "waiting", the
// not-connected banner when ServiceDesk Plus has no address, and that an attacker-shaped ticket title is escaped.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node support-center.test.js
'use strict';
const http = require('http'), fs = require('fs'), path = require('path'), os = require('os'), cp = require('child_process');
const SRC = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0;
const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const B = fs.mkdtempSync(path.join(os.tmpdir(), 'supctr-')); fs.mkdirSync(path.join(B, 'vendor'));
fs.readdirSync(SRC).filter((f) => f.endsWith('.html')).forEach((f) => fs.copyFileSync(path.join(SRC, f), path.join(B, f)));
fs.readdirSync(path.join(SRC, 'vendor')).filter((f) => /\.(js|json|css)$/.test(f)).forEach((f) => fs.copyFileSync(path.join(SRC, 'vendor', f), path.join(B, 'vendor', f)));
cp.execFileSync(process.execPath, [path.join(SRC, 'build-static.js'), B, 't1'], { stdio: 'ignore' });

const XSS = '<img src=x onerror="window.__xss=1">';
const iso = (hAgo) => new Date(Date.now() - hAgo * 3600000).toISOString();
let CONFIGURED = true;
const mk = (id, title, status, priority, reqBy, hAgo, extra) => Object.assign({ id, title, status, priority, requested_by: reqBy, requested_at: iso(hAgo), rule: 'manual', asset_name: null }, extra || {});
let TICKETS = [
  mk('mt_1', 'Mailbox over quota ' + XSS, 'pending', 'High', 'nora.syn', 5),
  mk('mt_2', 'Approve my own ' + XSS, 'pending', 'Medium', 'syed', 2),
  mk('mt_3', 'Laptop will not boot', 'open', 'High', 'ali.syn', 72, { sdp_id: '9001', sdp_url: 'https://sdp.example/WorkOrder.do?woID=9001', asset_name: 'LT-204' }),
  mk('mt_4', 'VPN access request', 'open', 'Low', 'huda.syn', 10),
  mk('mt_5', 'Printer jam cleared', 'closed', 'Low', 'ali.syn', 200, { closed_at: iso(190) }),
  mk('mt_6', 'Duplicate request', 'rejected', 'Medium', 'nora.syn', 48, { reason: 'duplicate of mt_3' }),
  mk('mt_7', 'Warranty ends on SRV-11', 'open', 'Medium', 'system', 20, { rule: 'warranty', asset_name: 'SRV-11' }),
];

(async () => {
  const srv = http.createServer((q, r) => {
    const u = q.url.split('?')[0], j = (c, o) => { r.writeHead(c, { 'Content-Type': 'application/json' }); r.end(JSON.stringify(o)); };
    if (u.endsWith('whoami.json')) return j(200, { user: 'syed', role: 'operator' });
    if (u === '/api/itam/me/status') return j(200, { sdp: CONFIGURED ? { base_url: 'https://sdp.example', key_set: true } : { base_url: '', key_set: false }, ec: {}, rules: {}, you: { user: 'syed', role: 'operator' }, tickets: {} });
    if (u === '/api/itam/me/tickets' && q.method === 'GET') return j(200, { tickets: TICKETS });
    if (u === '/api/itam/me/tickets' && q.method === 'POST') { let b = ''; q.on('data', (c) => b += c); q.on('end', () => { var t; try { t = JSON.parse(b); } catch (e) { t = {}; } if (!t.title || t.title.length < 4) return j(400, { error: 'enter a title' }); TICKETS.unshift(mk('mt_new', t.title, 'pending', t.priority || 'Medium', 'syed', 0)); j(200, { ticket: { id: 'mt_new' } }); }); return; }
    let m = u.match(/^\/api\/itam\/me\/tickets\/([^/]+)\/(approve|reject)$/);
    if (m && q.method === 'POST') { const t = TICKETS.find((x) => x.id === m[1]); if (!t) return j(404, { error: 'no such ticket' }); if (t.status !== 'pending') return j(409, { error: 'not waiting for approval' });
      if (m[2] === 'approve') { if (t.requested_by === 'syed') return j(403, { error: 'a second person has to approve a ticket you asked for' }); t.status = 'sending'; return j(200, { ok: true }); }
      let b = ''; q.on('data', (c) => b += c); q.on('end', () => { var x; try { x = JSON.parse(b); } catch (e) { x = {}; } if (!x.reason || x.reason.length < 3) return j(400, { error: 'give a reason' }); t.status = 'rejected'; t.reason = x.reason; j(200, { ok: true }); }); return; }
    if (u.startsWith('/api/')) return j(404, { error: 'not in this test' });
    const f = path.join(B, u === '/' ? 'index.html' : u); if (!f.startsWith(B)) { r.writeHead(403); return r.end(); }
    fs.readFile(f, (e, d) => { if (e) { r.writeHead(404); return r.end(); } r.writeHead(200, { 'Content-Type': u.endsWith('.js') ? 'application/javascript' : u.endsWith('.css') ? 'text/css' : 'text/html' }); r.end(d); });
  });
  await new Promise((res) => srv.listen(0, '127.0.0.1', res));
  const base = 'http://127.0.0.1:' + srv.address().port + '/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const open = async (pg) => { const p = await browser.newPage({ viewport: { width: 1500, height: 950 } }); p.on('pageerror', (e) => errs.push(e.message)); await p.goto(base + (pg || 'support-center.html')); return p; };
  const txt = (p, id) => p.evaluate((i) => (document.getElementById(i) || {}).textContent || '', id);
  const rowCount = (p) => p.evaluate(() => document.querySelectorAll('#rows tbody tr').length);

  // reachable from the menu
  let p = await open('manageengine.html'); await p.waitForTimeout(800);
  const link = await p.evaluate(() => { const a = document.querySelector('a[href="support-center.html"]'); return a ? a.textContent.trim() : null; });
  ok(/Support Center/.test(link || ''), 'menu entry exists: ' + link);
  await p.evaluate(() => document.querySelector('a[href="support-center.html"]').click());
  await p.waitForURL(/support-center\.html/); await p.waitForSelector('#rows table');

  const kp = await txt(p, 'kp');
  ok(/Waiting for approval2/.test(kp), 'pending KPI = 2: ' + kp.replace(/\s+/g, ' ').slice(0, 120));
  ok(/Open at the desk3/.test(kp), 'open KPI = 3 (2 open + 1 sending-less; open+sending)');
  ok(/Past target1/.test(kp), 'one open High ticket (72h) past its 24h target');
  ok(/Rejected \/ failed1/.test(kp), 'rejected KPI = 1');
  ok(await p.evaluate(() => !window.__xss) && !(await p.$('#rows img')), 'ticket titles are escaped, no injected node');

  ok(/Needs attention/i.test(await txt(p, 'attn')) || !(await p.$('#attnc[hidden]')), 'needs-attention panel shown');
  ok(/Mailbox over quota/.test(await txt(p, 'attn')), 'a waiting ticket is in needs-attention');

  // filter: Past target chip -> only the breaching open ticket
  await p.click('#chips [data-f="breach"]'); ok((await rowCount(p)) === 1, 'past-target filter shows the one breaching ticket: ' + (await rowCount(p)));
  await p.click('#chips [data-f=""]'); ok((await rowCount(p)) === TICKETS.length, 'all tickets again');
  // search keeps focus
  await p.fill('#q', 'laptop'); ok((await rowCount(p)) === 1 && await p.evaluate(() => document.activeElement && document.activeElement.id === 'q'), 'search by text keeps focus');
  await p.fill('#q', '');

  // four-eyes: approving your own request is refused by the server, the page shows the reason
  await p.click('#rows tr:has-text("Approve my own") [data-ap]');
  ok(await p.waitForSelector('.toast', { timeout: 3000 }).then((h) => h.textContent()).then((t) => /second person/.test(t)), 'four-eyes: cannot approve your own request');
  // approving someone else's pending request works
  await p.click('#rows tr:has-text("Mailbox over quota") [data-ap]'); await p.waitForTimeout(500);
  ok(TICKETS.find((t) => t.id === 'mt_1').status === 'sending', 'approving another person’s request is sent');

  // new request: title too short refused, then a valid one lands as pending
  await p.evaluate(() => [].forEach.call(document.querySelectorAll('.toast'), (t) => t.remove()));
  await p.click('#new'); await p.waitForSelector('.dlg');
  await p.fill('#d-title', 'ab'); await p.click('.dlg [data-ok]');
  ok(await p.waitForFunction(() => [].some.call(document.querySelectorAll('.toast'), (t) => /at least 4/.test(t.textContent)), null, { timeout: 3000 }).then(() => true).catch(() => false), 'short title refused client-side');
  await p.fill('#d-title', 'New monitor for reception'); await p.selectOption('#d-pr', 'Low'); await p.click('.dlg [data-ok]'); await p.waitForTimeout(500);
  ok(!(await p.$('.dlg')) && TICKETS.some((t) => t.id === 'mt_new' && t.status === 'pending'), 'valid request logged as waiting for approval');
  await p.close();

  // not connected: banner points to the integration page, queue still renders what is held
  CONFIGURED = false; p = await open(); await p.waitForSelector('#banner .empty');
  ok(/not connected/i.test(await txt(p, 'banner')) && /ManageEngine/.test(await txt(p, 'banner')), 'not-connected banner points to the integration page');
  ok((await p.$('#new')) && await p.evaluate(() => document.getElementById('new').hidden), 'New request hidden until ServiceDesk Plus is connected');
  await p.close();

  ok(/support-center\.html/.test(fs.readFileSync(path.join(SRC, 'install-dashboards.sh'), 'utf8')), 'in the installer');
  ok(/servicedesk: 'support-center\.html'/.test(fs.readFileSync(path.join(SRC, 'vendor/zyb-menu.js'), 'utf8')), 'portal servicedesk view redirects here');
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  await browser.close(); srv.close();
  console.log(`${n - bad}/${n} checks passed`); process.exit(bad ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
