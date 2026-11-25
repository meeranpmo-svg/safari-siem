// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// NDR page: not run yet says so; hosts by itemised risk and the detections (hostile text stays text); an analyst proposes a
// suppression (destination for a beacon, kind for volume); the proposer is not offered Approve, another person is; a viewer is
// told why it is closed. Stub SIEM; addresses SYNTHETIC.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node ndr.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
let ROLE = 'analyst', USER = 'ana.syn', RAN = false, SUP = [];
const RUN = { ran: true, at: '2026-11-25T11:00:00Z', suppressed: 0, errors: [],
  detections: [{ kind: 'beacon', host: '10.1.1.5', dst: '203.0.113.9:443', severity: 'high', why: '40 connections every ~300 s <img src=x onerror=alert(1)>' }, { kind: 'exfil', host: '10.1.1.7', dst: '', severity: 'medium', why: '900 MB out today, usual 21 MB' }],
  hosts: [{ host: '10.1.1.5', risk: 45, reasons: [{ kind: 'beacon', points: 35, why: 'regular' }, { kind: 'country', points: 10, why: 'first traffic' }] }, { host: '10.1.1.7', risk: 30, reasons: [{ kind: 'exfil', points: 30, why: 'volume' }] }] };
const posts = [];
(async () => {
  const srv = http.createServer((req, res) => {
    const u = req.url.split('?')[0]; const json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    const body = (fn) => { let b = ''; req.on('data', (d) => { b += d; }); req.on('end', () => { const j = b ? JSON.parse(b) : null; posts.push([req.method, u, j]); fn(j); }); };
    if (u === '/dashboards/whoami.json') return json(200, { user: USER, role: ROLE });
    if (u === '/api/soc/ndr') return ROLE === 'viewer' ? json(403, { error: 'forbidden' }) : json(200, RAN ? RUN : { ran: false, detections: [], hosts: [], suppressed: 0, errors: [], note: 'NDR has not run yet' });
    if (u === '/api/soc/ndr/suppressions' && req.method === 'GET') return json(200, { suppressions: SUP });
    if (u === '/api/soc/ndr/suppressions') return body((b) => { const s = Object.assign({ id: 'SUP-0000' + (SUP.length + 1), status: 'proposed', proposed_by: USER }, b); SUP.unshift(s); json(200, s); });
    if (/\/decide$/.test(u)) return body((b) => { SUP[0].status = b.decision; json(200, SUP[0]); });
    if (u === '/api/soc/ndr/run') return body(() => { RAN = true; json(200, RUN); });
    if (u.startsWith('/api/')) return json(404, { error: 'not in this test' });
    fs.readFile(path.join(DASH, u.replace(/^\/dashboards\//, '/')), (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.endsWith('.js') ? 'application/javascript' : u.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const URL0 = 'http://127.0.0.1:' + srv.address().port + '/ndr.html?standalone=1';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(); const errs = []; let answers = [];
  const open = async () => { const p = await browser.newPage({ viewport: { width: 1400, height: 900 } }); p.on('pageerror', (x) => errs.push(x.message)); p.on('dialog', (d) => d.accept(answers.length ? answers.shift() : '')); await p.goto(URL0); return p; };
  const toast = async (p) => { await p.waitForSelector('.toast', { timeout: 8000 }); const t = await p.$$eval('.toast', (x) => x.map((e) => e.textContent).join(' | ')); await p.$$eval('.toast', (x) => x.forEach((e) => e.remove())); return t; };
  let p = await open(); await p.waitForFunction(() => /has not run yet/.test(document.body.innerText)); ok(await p.$eval('#run', (b) => b.hidden), 'an analyst does not run it'); await p.close();
  RAN = true; p = await open(); await p.waitForSelector('[data-sup]');
  ok(!(await p.$('img[src="x"]')), 'hostile text stays text');
  ok(/\+35 Beaconing/.test(await p.textContent('#body')) && /10\.1\.1\.5/.test(await p.textContent('#body')), 'risk itemised');
  answers = ['the vendor update check (synthetic)', '2027-01-31']; await p.click('[data-sup="0"]'); ok(/SUP-00001 proposed/.test(await toast(p)), 'proposed');
  const s1 = posts.find((x) => x[1] === '/api/soc/ndr/suppressions'); ok(s1 && s1[2].dst === '203.0.113.9:443' && !s1[2].kind && s1[2].expires === '2027-01-31', 'a beacon is suppressed by destination: ' + JSON.stringify(s1 && s1[2]));
  answers = ['nightly backup to the cloud (synthetic)', '']; await p.click('[data-sup="1"]'); await toast(p);
  const s2 = posts.filter((x) => x[1] === '/api/soc/ndr/suppressions').pop(); ok(s2 && s2[2].kind === 'exfil' && !s2[2].dst, 'volume is suppressed by kind');
  await p.waitForSelector('#body .act .pill'); ok(!(await p.$('[data-dec="approved"]')), 'the proposer is not offered Approve');
  await p.close();
  USER = 'sec.syn'; ROLE = 'admin'; p = await open(); await p.waitForSelector('[data-dec="approved"]'); await p.click('[data-dec="approved"]'); ok(/approved/.test(await toast(p)), 'approved by another person');
  ok(!(await p.$eval('#run', (b) => b.hidden)), 'an operator / admin can run it'); await p.click('#run'); ok(/2 detection/.test(await toast(p)), 'run');
  await p.close();
  ROLE = 'viewer'; USER = 'vera.syn'; p = await open(); await p.waitForFunction(() => /names hosts/.test(document.body.innerText)); ok(true, 'viewer told why'); await p.close();
  ok(!errs.length, 'errors: ' + errs.join(' | '));
  await browser.close(); srv.close();
  console.log(bad ? `${bad}/${n} FAILED` : `OK ${n}/${n} checks`); process.exit(bad ? 1 : 0);
})();
