// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for soc-live.html (Live Logs) with a SYNTHETIC server-sent event stream and the browser clock under the test's
// control: events listed as they arrive, the rate chart and KPIs, the learned normal band after the 2-minute warm-up, a burst
// named with its source, log patterns (numbers / IPs masked into one shape, a new high-severity shape after the warm-up marked
// new and raised as an indicator), password spray and brute force from failed sign-ins, a source that went quiet, top
// entities and a click that filters, the Copilot question sent with the filter as context and the answer shown as text labelled
// a draft, a hostile message stays text, pause keeps analysing, phone width, no page errors.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node soc-live.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.join(__dirname, '..', '..', 'ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
(async () => {
  let stream = null; const asked = [];
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, { user: 'ana.syn', role: 'analyst' });
    if (u.pathname === '/api/soc/onboard/sources') return json(200, { sources: [{ id: 'fw-1', label: 'Synthetic firewall' }, { id: 'win-1', label: 'Synthetic Windows' }] });
    if (u.pathname === '/api/soc/tail') {
      if (!/text\/event-stream/.test(req.headers.accept || '')) return json(200, { ok: true });   // the page's filter check
      res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', Connection: 'keep-alive' });
      res.write('event: hello\ndata: {}\n\n'); stream = res; return;
    }
    if (u.pathname === '/api/soc/soc/copilot/ask') { let b = ''; req.on('data', (d) => (b += d)); req.on('end', () => { asked.push(JSON.parse(b)); json(200, { answer: 'Synthetic answer <img src=x onerror=window.__ax=1>', conversation: 'CPC-000000000000', steps: [], proposals: [] }); }); return; }
    if (u.pathname.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/soc-live.html?standalone=1';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg, ms) => p.waitForFunction(fn, arg === undefined ? null : arg, { timeout: ms || 15000 }).then(() => true, () => false);
  const T = (p, id) => p.evaluate((i) => document.getElementById(i).textContent, id);
  let seq = 0;
  const send = (ev) => { const now = new Date(CLOCK).toISOString(); stream.write('event: event\ndata: ' + JSON.stringify(Object.assign({ ts: now, rts: now, src_id: 'fw-1', src_type: 'fortigate', severity: 1 }, ev)) + '\n\n'); seq++; };
  let CLOCK = Date.parse('2026-11-18T09:00:00Z');
  try {
    const p = await browser.newPage({ viewport: { width: 1440, height: 1100 } }); p.on('pageerror', (x) => errs.push(x.message));
    await p.clock.install({ time: CLOCK });
    await p.goto(base);
    ok(await wait(p, () => /live/.test(document.getElementById('st').textContent)), 'stream connected');
    // warm-up: 130 seconds of a normal rate (2 events a second, ports and addresses vary - one shape), and a Windows source
    const shown = () => p.evaluate(() => document.querySelectorAll('#rows tr').length);
    for (let s = 0; s < 130; s++) {
      send({ message: 'deny tcp 10.0.' + (s % 200) + '.' + (s % 50) + ':' + (40000 + s) + ' -> 172.16.0.5:443 policy 7', src_ip: '10.0.0.' + (s % 9), dst_port: 443, host: 'FW-SYN-1' });
      send({ message: 'accept udp 10.0.1.' + (s % 30) + ':' + (5000 + s) + ' -> 8.8.8.8:53 policy 3', src_ip: '10.0.1.' + (s % 9), dst_port: 53, host: 'FW-SYN-1' });
      if (s < 40) send({ src_id: 'win-1', src_type: 'windows', message: 'Service Control Manager heartbeat ' + s, host: 'WIN-SYN-1' });
      const want = Math.min(1000, seq); await wait(p, (w) => document.querySelectorAll('#rows tr').length >= w, want);
      CLOCK += 1000; await p.clock.runFor(1000);
    }
    ok(await shown() >= 300, 'events listed as they arrive');
    await p.clock.runFor(2000);
    ok(/events analysed/.test(await T(p, 'an-kp')) && !!(await p.$('#an-rate svg rect')), 'rate chart and KPIs');
    ok(/normal \(/.test(await T(p, 'an-rate')), 'the normal band is learned after the warm-up');
    ok(/deny tcp <ip> -> <ip> policy <n>/.test(await T(p, 'an-pat')), 'numbers and addresses masked into one pattern');
    ok(!/<ip>:<n>|<ip><n>|<ip>\d/.test(await T(p, 'an-pat')), 'an address with its port is one token (the event\'s own address word-bounded)');
    // a burst: 60 events in one second, then the next second rolls the window
    for (let i = 0; i < 60; i++) send({ message: 'deny tcp 10.9.9.9:' + (1000 + i) + ' -> 172.16.0.5:445 policy 9', src_ip: '10.9.9.9', dst_port: 445 });
    await wait(p, (w) => document.querySelectorAll('#rows tr').length >= w, Math.min(1000, seq));
    CLOCK += 1000; await p.clock.runFor(1000); send({ message: 'accept udp 10.0.1.1:5001 -> 8.8.8.8:53 policy 3' });
    // password spray: failed sign-ins for 6 accounts from one address; a new high-severity shape
    for (let i = 0; i < 12; i++) send({ src_id: 'win-1', src_type: 'windows', category: 'authentication', outcome: 'failure', event_code: 4625, user: 'user' + (i % 6) + '.syn', src_ip: '203.0.113.7', severity: 2, message: 'An account failed to log on. Account: user' + (i % 6) + '.syn Source: 203.0.113.7' });
    send({ src_id: 'win-1', src_type: 'windows', severity: 3, message: 'A service was installed in the system: PSEXESVC <img src=x onerror=window.__px=1>', host: 'WIN-SYN-2' });
    await wait(p, (w) => document.querySelectorAll('#rows tr').length >= w, Math.min(1000, seq));
    CLOCK += 2000; await p.clock.runFor(2000);
    const ind = await T(p, 'an-ind');
    ok(/Burst/.test(ind) && /60 events in one second/.test(ind) && /fw-1/.test(ind), 'burst named with its source: ' + ind.slice(0, 300));
    ok(/Password spray/.test(ind) && /6 different accounts from 203\.0\.113\.7/.test(ind), 'password spray from failed sign-ins');
    ok(/New pattern/.test(ind) && /service was installed/.test(ind), 'a new high-severity shape is an indicator');
    ok(/An account failed to log on\. Account: <user> Source: <ip>/.test(await T(p, 'an-pat')) && !/user0\.syn Source/.test(await T(p, 'an-pat')), 'one shape for every account (the event\'s own user and address masked)');
    ok(/new/.test(await T(p, 'an-pat')), 'the new shape is marked new in the patterns');
    ok(!(await p.evaluate(() => window.__px)), 'a hostile message stays text');
    ok(await p.$eval('#rows tr.hit', (r) => /service was installed/.test(r.textContent)).catch(() => false), 'the new-shape row is marked in the list');
    // a source that went quiet: win-1 stopped after its burst; fw-1 keeps going
    for (let s = 0; s < 150; s++) { send({ message: 'accept udp 10.0.1.2:5002 -> 8.8.8.8:53 policy 3' }); CLOCK += 1000; await p.clock.runFor(1000); }
    await wait(p, () => /Source quiet/.test(document.getElementById('an-ind').textContent), undefined, 8000);
    ok(/Source quiet/.test(await T(p, 'an-ind')) && /win-1/.test(await T(p, 'an-ind')), 'a source that went quiet');
    ok(/10\.9\.9\.9/.test(await T(p, 'an-top')) && /445|443|53/.test(await T(p, 'an-top')), 'top source addresses and ports');
    // click a top entity: filters the stream
    await p.click('#an-top [data-filter="ip:10.9.9.9"]'); ok(await wait(p, () => document.getElementById('q').value === 'ip:10.9.9.9'), 'a top entity filters the stream');
    // ask the Copilot about the spray indicator
    await p.click('#an-ind .ind:has-text("Source quiet") [data-ask]');
    ok(await wait(p, () => /AI draft - verify before acting/.test(document.getElementById('an-ai').textContent)), 'the Copilot answer is labelled a draft');
    ok(asked.length === 1 && asked[0].context.page === 'other' && asked[0].context.kind === 'query' && asked[0].context.id === 'src_id:win-1' && /Source quiet/.test(asked[0].question), 'question sent with the filter as context');
    ok(!(await p.evaluate(() => window.__ax)) && /Synthetic answer <img/.test(await T(p, 'an-ai')), 'the answer is shown as text');
    // pause keeps analysing
    const total0 = await p.evaluate(() => document.getElementById('an-kp').textContent);
    await p.click('#pause');
    send({ message: 'accept udp 10.0.1.3:5003 -> 8.8.8.8:53 policy 3' }); await wait(p, () => /Resume \(1 new\)/.test(document.getElementById('pause').textContent));
    CLOCK += 2000; await p.clock.runFor(2000);
    ok(/Resume \(1 new\)/.test(await T(p, 'pause')) && (await T(p, 'an-kp')) !== total0, 'paused: new events wait, the analysis keeps counting them');
    const ph = await browser.newPage({ viewport: { width: 390, height: 900 } }); ph.on('pageerror', (x) => errs.push(x.message)); await ph.goto(base); await wait(ph, () => !!document.getElementById('an-rate'));
    ok(await ph.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), 'phone width: no sideways scroll'); await ph.close();
  } finally { if (stream) stream.end(); await browser.close(); srv.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
