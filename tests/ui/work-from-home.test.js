// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Work From Home page against the REAL engine (engine/remote-work.js), SYNTHETIC people: an employee asks for days and sees the
// request; the department approver sees it waiting and approves (the person who asked is not offered Approve); IT (operator) sees
// the board with today's remote workers, laptop and VPN readiness and the charts; administrators see the policy and the VPN
// indicators with the "not proof" note; a viewer sees neither; hostile text stays text.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node work-from-home.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui'), ITAM = path.resolve(__dirname, '../../backend/itam');
const H = require(path.join(ITAM, 'tests/helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
(async () => {
  const e = await H.startApp({ noAi: true });
  const clock = Date.parse('2026-11-29T06:00:00Z');
  const RW = require(path.join(ITAM, 'engine/remote-work')); RW.registerRemoteWork(e.app.srv, e.app, RW.createRemoteWork(e.app, { now: () => clock, noTimer: true }));
  e.app.discovery = { siem: { call: async () => ({ status: 200, json: { values: [{ v: 'sara.syn', n: 2 }, { v: 'khalid.syn', n: 1 }] } }) } };
  let WHO = { user: 'sara.syn', role: 'viewer' };
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x');
    if (u.pathname === '/dashboards/whoami.json') { res.writeHead(200, { 'Content-Type': 'application/json' }); return res.end(JSON.stringify(WHO)); }
    if (u.pathname.startsWith('/api/itam/')) { const h = Object.assign({}, req.headers, { 'x-sentra-proxy-secret': H.SECRET, 'x-auth-user': WHO.user, 'x-auth-role': WHO.role });
      const up = http.request({ host: '127.0.0.1', port: e.port, method: req.method, path: req.url, headers: h }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); }); req.pipe(up); return; }
    if (u.pathname.startsWith('/api/')) { res.writeHead(404, { 'Content-Type': 'application/json' }); return res.end('{"error":"not in this test"}'); }
    fs.readFile(path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')), (err, d) => { if (err) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch(), errs = [];
  const open = async () => { const p = await browser.newPage({ viewport: { width: 1400, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message)); p.on('dialog', (d) => d.accept('')); await p.goto('http://127.0.0.1:' + srv.address().port + '/dashboards/work-from-home.html?standalone=1'); await p.waitForSelector('#wgo', { timeout: 15000 }); return p; };
  const toast = async (p) => { await p.waitForSelector('.toast', { timeout: 8000 }); const t = await p.$$eval('.toast', (x) => x.map((y) => y.textContent).join(' | ')); await p.$$eval('.toast', (x) => x.forEach((y) => y.remove())); return t; };
  // the approver of Finance (admin sets the policy through the page later; here directly through the API as the admin)
  const PUT = async (b) => { const r = await e.req('PUT', '/remote-work/policy', { user: 'admin.syn', role: 'admin', body: b }); if (r.status !== 200) throw new Error(r.text); };
  await PUT({ max_days_month: 8, notice_days: 0, departments: { finance: { allowed: true, approvers: ['fahad.syn'] } } });
  // 1 an employee (viewer) asks
  let p = await open();
  ok(await p.$eval('#boardw', (x) => x.hidden) && await p.$eval('#polc', (x) => x.hidden), 'a viewer sees no board and no policy');
  ok(/No company laptop is on record for you/.test(await p.textContent('#mine')), 'says when no laptop is on record');
  await p.fill('#wf', '2026-11-29'); await p.fill('#wt', '2026-11-30'); await p.selectOption('#wd', 'finance'); await p.fill('#wr', 'Synthetic reason <img src=x onerror=window.__x=1>');
  await p.click('#wgo'); ok(/WFH-00001 sent/.test(await toast(p)), 'sent');
  await p.waitForFunction(() => /WFH-00001/.test(document.getElementById('myreq').textContent));
  ok(/2 working day\(s\)/.test(await p.textContent('#myreq')) && /pending/.test(await p.textContent('#myreq')), 'my request listed, pending, 2 working days');
  ok(!(await p.$('#myreq img')) && !(await p.evaluate(() => window.__x)), 'hostile text stays text');
  ok(await p.$eval('#waitc', (x) => x.hidden) && !(await p.$('[data-dec]')), 'the person who asked is not offered Approve');
  await p.close();
  // 2 the department approver approves
  WHO = { user: 'fahad.syn', role: 'viewer' }; p = await open(); await p.waitForSelector('#wait [data-dec="approved"]');
  await p.click('#wait [data-dec="approved"]'); ok(/WFH-00001 approved/.test(await toast(p)), 'the approver approves'); await p.close();
  // 3 IT sees the board
  WHO = { user: 'nora.syn', role: 'operator' }; p = await open(); await p.waitForFunction(() => !document.getElementById('boardw').hidden);
  await p.waitForSelector('#nextc[role="img"]');
  const k = await p.textContent('#kp'), td = await p.textContent('#today');
  ok(/At home today\s*1/.test(k) && /No company laptop\s*1/.test(k) && /No VPN logon yet\s*0/.test(k), 'KPIs: at home, no laptop, VPN: ' + k);
  ok(/sara\.syn/.test(td) && /Finance/.test(td) && /none on record/.test(td) && /connected/.test(td), 'today: who, department, laptop, VPN: ' + td);
  ok(await p.$eval('#nextc', (c) => /Approved/.test(c.getAttribute('aria-label'))), 'next working days chart');
  ok(await p.$eval('#indc', (x) => x.hidden) && await p.$eval('#polc', (x) => x.hidden), 'an operator sees no indicators and no policy');
  await p.close();
  // 4 the administrator: indicators with the note, the policy saved from the page
  WHO = { user: 'admin.syn', role: 'admin' }; p = await open(); await p.waitForFunction(() => !document.getElementById('indc').hidden && !document.getElementById('polc').hidden);
  const ind = await p.textContent('#ind'); ok(/not proof/.test(ind) && /khalid\.syn/.test(ind) && !/sara\.syn/.test(ind), 'indicators: VPN without an approved day, with the not-proof note: ' + ind);
  await p.fill('#pm', '6'); await p.click('#psave'); ok(/Policy saved/.test(await toast(p)), 'policy saved');
  ok((await e.req('GET', '/remote-work/policy', { user: 'admin.syn', role: 'admin' })).json.max_days_month === 6, 'saved in the engine');
  await p.close();
  ok(!errs.length, 'page errors: ' + errs.join(' | '));
  await browser.close(); srv.close(); await e.close();
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
