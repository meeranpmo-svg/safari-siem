// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// FortiGate NAC page: nothing detected says what to switch on; endpoints ranked with itemised reasons (hostile text stays text),
// search and minimum risk filter; an operator proposes authorise (owner + purpose) and quarantine; the proposer is not offered
// Approve, another person is; an approved quarantine is marked carried out. Stub SIEM; MACs and people SYNTHETIC.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node fortigate-nac.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
let USER = 'op.syn', ROLE = 'operator', EMPTY = true, DEC = [];
const E = (mac, risk, reasons, o) => Object.assign({ mac, ip: '10.7.0.5', host: 'PC-' + mac.slice(-2), os: 'Windows', hw: 'Dell', user: '', site: 'Site 7', fortigate: 'FGT-S7', last_seen: '2026-11-25T11:00:00Z', risk, reasons, notes: [], authorised: false, quarantine: null }, o);
const VIEW = () => ({ connected: true, learning: false, sources: { fortigate: 2, switch_ports: 3, switches: 1 }, total: EMPTY ? 0 : 3, sites: [{ site: 'Site 7', endpoints: 3, risky: 1, exposure: 33 }], decisions: DEC,
  endpoints: EMPTY ? [] : [E('aa:00:00:00:00:01', 65, [{ points: 35, code: 'two-sites', why: 'at FGT-S7 and FGT-S8 within 30 min <img src=x onerror=alert(1)>' }, { points: 30, code: 'identity', why: 'reported as windows and then linux' }], { sw: { switch: 'SW-2F-SYN', port: 'GE1/0/4', vlan: '20', desc: 'PRINTER', shared: 1 }, quarantine_steps: { switch: 'SW-2F-SYN', port: 'GE1/0/4', vendor: 'H3C Comware', lines: ['system-view', 'interface GE1/0/4', 'port access vlan 999', 'quit', 'save'], note: 'moves the port to quarantine VLAN 999' } }), E('aa:00:00:00:00:02', 10, [{ points: 10, code: 'unauthorised', why: 'seen for 20 days' }]), E('aa:00:00:00:00:03', 0, [], { authorised: true, host: 'PRINTER' })] });
const posts = [];
(async () => {
  const srv = http.createServer((req, res) => {
    const u = req.url.split('?')[0]; const json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    const body = (fn) => { let b = ''; req.on('data', (d) => { b += d; }); req.on('end', () => { const j = b ? JSON.parse(b) : null; posts.push([req.method, u, j]); fn(j); }); };
    if (u === '/dashboards/whoami.json') return json(200, { user: USER, role: ROLE });
    if (u === '/api/soc/nac/endpoints') return json(200, VIEW());
    if (u === '/api/soc/nac/decisions') return body((b) => { const d = Object.assign({ id: 'NAC-0000' + (DEC.length + 1), status: 'proposed', proposed_by: USER }, b); DEC.unshift(d); json(200, d); });
    if (/\/decide$/.test(u)) return body((b) => { DEC[0].status = b.decision; json(200, DEC[0]); });
    if (/\/done$/.test(u)) return body(() => { DEC[0].status = 'done'; json(200, DEC[0]); });
    if (u.startsWith('/api/')) return json(404, { error: 'not in this test' });
    fs.readFile(path.join(DASH, u.replace(/^\/dashboards\//, '/')), (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.endsWith('.js') ? 'application/javascript' : u.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const URL0 = 'http://127.0.0.1:' + srv.address().port + '/fortigate-nac.html?standalone=1';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(); const errs = []; let answers = [];
  const open = async () => { const p = await browser.newPage({ viewport: { width: 1400, height: 900 } }); p.on('pageerror', (x) => errs.push(x.message)); p.on('dialog', (d) => d.accept(answers.length ? answers.shift() : '')); await p.goto(URL0); return p; };
  const toast = async (p) => { await p.waitForSelector('.toast', { timeout: 8000 }); const t = await p.$$eval('.toast', (x) => x.map((e) => e.textContent).join(' | ')); await p.$$eval('.toast', (x) => x.forEach((e) => e.remove())); return t; };
  let p = await open(); await p.waitForFunction(() => /Device detection/.test(document.body.innerText)); ok(true, 'empty state says what to switch on'); await p.close();
  EMPTY = false; p = await open(); await p.waitForSelector('#body table');
  ok(!(await p.$('img[src="x"]')), 'hostile text stays text');
  ok(/\+35 at FGT-S7 and FGT-S8/.test(await p.textContent('#body')), 'reasons itemised');
  ok(/SW-2F-SYN GE1\/0\/4/.test(await p.textContent('#body')) && /not on a read switch/.test(await p.textContent('#body')), 'switch port column');
  ok(/1 switch\(es\) · 2 seen by FortiGates/.test(await p.textContent('#kp')), 'sources said');
  ok(await p.$$eval('#body tbody tr', (r) => r[0].innerText.includes('aa:00:00:00:00:01')), 'riskiest first');
  await p.selectOption('#min', '30'); ok((await p.$$('#body tbody tr')).length === 1, 'minimum risk filter');
  await p.selectOption('#min', '0'); await p.fill('#q', 'PRINTER'); ok((await p.$$('#body tbody tr')).length === 1, 'search');
  await p.fill('#q', '');
  answers = ['Site 7 office', 'the reception PC (synthetic)']; await p.click('[data-auth="aa:00:00:00:00:02"]'); ok(/NAC-00001 proposed/.test(await toast(p)), 'authorise proposed');
  const a1 = posts.find((x) => x[2] && x[2].action === 'authorise'); ok(a1 && a1[2].owner === 'Site 7 office' && a1[2].mac === 'aa:00:00:00:00:02', 'authorise body');
  answers = ['cloned MAC at two sites (synthetic)']; await p.click('[data-quar="aa:00:00:00:00:01"]'); await toast(p);
  ok(posts.some((x) => x[2] && x[2].action === 'quarantine' && x[2].mac === 'aa:00:00:00:00:01'), 'quarantine proposed');
  await p.waitForFunction(() => /NAC-00002/.test(document.body.innerText), null, { timeout: 8000 }).catch(async () => console.log('BODY', (await p.textContent('#body')).slice(-600))); ok(!(await p.$('[data-dec="approved"]')), 'the proposer is not offered Approve');
  await p.close();
  USER = 'sec.syn'; ROLE = 'admin'; p = await open(); await p.waitForSelector('[data-dec="approved"]'); await p.click('[data-dec="approved"]'); ok(/approved/.test(await toast(p)), 'another person approves');
  await p.waitForSelector('[data-done]'); ok(/port access vlan 999/.test(await p.textContent('#body')) && /H3C Comware/.test(await p.textContent('#body')), 'the exact switch commands are shown for the approved quarantine');
  answers = ['MAC added to the quarantine group in FortiManager (synthetic)']; await p.click('[data-done]'); ok(/done/.test(await toast(p)), 'carried out');
  await p.close();
  ok(!errs.length, 'errors: ' + errs.join(' | '));
  await browser.close(); srv.close();
  console.log(bad ? `${bad}/${n} FAILED` : `OK ${n}/${n} checks`); process.exit(bad ? 1 : 0);
})();
