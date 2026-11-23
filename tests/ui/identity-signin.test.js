// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for identity-signin.html (Platform Admin -> Identity & Sign-in, Overview + Insights tabs) against a stub of the sign-in service's
// /auth/admin/config with SYNTHETIC accounts and events: KPIs (MFA coverage, sign-ins / failures / lockouts in 24 h); the day x
// hour heatmap; ML unusual sign-ins from each account's own baseline (new address, unusual hour); password spraying and
// credential stuffing followed by a success; explainable identity risk (admin without MFA, dormant); recommendations; a
// hostile account name stays text; a non-administrator (403) is told it is for administrators and sees no data.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node identity-signin.test.js [screenshot.png]
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const NOW = Date.now(), H = 3600000, DAY = 24 * H, at = (ms) => new Date(ms).toISOString();
// Riyadh 09:00 = 06:00 UTC: a working-hours sign-in, d days ago
const work = (d, h = 9) => { const x = new Date(NOW - d * DAY); x.setUTCHours(h - 3, 10, 0, 0); return x.getTime(); };
const users = [
  { user: 'ali.syn', name: 'Ali Synthetic', role: 'admin', mfa: false, lastLogin: at(NOW - H) },
  { user: 'mona.syn', name: 'Mona Synthetic', role: 'operator', mfa: true, lastLogin: at(NOW - 2 * H) },
  { user: 'old.syn', name: 'Dormant Synthetic', role: 'viewer', mfa: true, lastLogin: at(NOW - 120 * DAY) },
  { user: '<img src=x onerror=alert(1)>', name: 'Hostile', role: 'viewer', mfa: true, lastLogin: at(NOW - 3 * H) },
  { user: 'gone.syn', role: 'viewer', mfa: false, disabled: true },
];
const ev = [];
for (let d = 12; d >= 1; d--) { ev.push({ event: 'sign-in', at: at(work(d)), user: 'mona.syn', ip: '10.20.0.5', method: 'password', mfa: true }); ev.push({ event: 'sign-in', at: at(work(d, 10)), user: 'ali.syn', ip: '10.20.0.9', method: 'password', mfa: false }); }
ev.push({ event: 'sign-in', at: at(work(0, 3)), user: 'mona.syn', ip: '203.0.113.77', method: 'password', mfa: true });            // 03:00 from a new address
const sp = NOW - 5 * H; for (let i = 0; i < 6; i++) ev.push({ event: 'failure', at: at(sp + i * 30000), user: 'user' + i + '.syn', ip: '198.51.100.23', reason: 'bad password' });   // spraying
const cs = NOW - 2 * H; for (let i = 0; i < 6; i++) ev.push({ event: 'failure', at: at(cs + i * 40000), user: 'ali.syn', ip: '192.0.2.' + (10 + (i % 3)), reason: 'bad password' });
ev.push({ event: 'sign-in', at: at(cs + 20 * 60000), user: 'ali.syn', ip: '192.0.2.10', method: 'password', mfa: false });              // stuffing then success
ev.push({ event: 'lockout', at: at(cs + 5 * 60000), user: 'ali.syn', ip: '192.0.2.11' });
(async () => {
  let WHO = 'admin';
  const srv = http.createServer((req, res) => { const u = req.url.split('?')[0];
    const j = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u === '/auth/whoami' || u === '/dashboards/whoami.json') return j(200, { user: 'syed', role: WHO });
    if (u === '/auth/admin/config') return WHO === 'admin' ? j(200, { users, events: ev, sso: { enabled: false }, mfaPolicy: 'admins', localLogin: 'all', hours: 8 }) : j(403, { error: 'admin only' });
    if (u.startsWith('/api/') || u.startsWith('/auth/')) return j(404, { error: 'not in this test' });
    const f = path.join(DASH, u.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (e, d) => { if (e) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': f.endsWith('.js') ? 'application/javascript' : f.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); }); });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/dashboards/identity-signin.html';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [], dialogs = [];
  const p = await browser.newPage({ viewport: { width: 1440, height: 1100 }, deviceScaleFactor: process.argv[2] ? 2 : 1 });
  p.on('pageerror', (e) => errs.push(e.message)); p.on('dialog', (d) => { dialogs.push(d.message()); d.dismiss(); });
  await p.goto(base); await p.waitForSelector('#kk .t');
  const s = await p.evaluate(() => ({ kk: document.getElementById('kk').innerText.replace(/\s+/g, ' '), heat: document.querySelectorAll('#heat i').length, lit: [...document.querySelectorAll('#heat i')].filter((i) => i.style.background !== 'rgb(22, 27, 38)').length,
    un: document.getElementById('unusual').innerText, att: document.getElementById('attacks').innerText, risk: document.getElementById('risk').innerText, next: document.getElementById('next').innerText,
    ring: document.querySelector('#ring svg').getAttribute('aria-label'), img: !!document.querySelector('main img'), bars: document.querySelectorAll('#bars rect').length }));
  ok(/Active accounts 4/.test(s.kk) && /MFA coverage 75%/.test(s.kk) && /Lockouts \(24 h\) 1/.test(s.kk), 'KPIs: 4 active (disabled excluded), MFA 75%, 1 lockout: ' + s.kk);
  ok(s.heat === 168 && s.lit >= 3 && s.bars > 0, 'heatmap 7 x 24 with lit cells, daily bars: ' + s.heat + '/' + s.lit + '/' + s.bars);
  ok(/mona\.syn/.test(s.un) && /first sign-in from 203\.0\.113\.77/.test(s.un) && /at 3:00, usually 9:00-9:00/.test(s.un), 'ML unusual sign-in: new address and unusual hour from the account\'s baseline: ' + s.un.slice(0, 300));
  ok(/Password spraying/.test(s.att) && /198\.51\.100\.23/.test(s.att) && /6 different accounts/.test(s.att), 'password spraying detected: ' + s.att.slice(0, 200));
  ok(/Credential stuffing/.test(s.att) && /ali\.syn/.test(s.att) && /followed by a successful sign-in/.test(s.att), 'credential stuffing followed by a success: ' + s.att.slice(0, 300));
  ok(/ali\.syn/.test(s.risk.split('\n')[1] || s.risk) && /\+35 administrator without MFA/.test(s.risk) && /targeted by credential stuffing/.test(s.risk) && /dormant/.test(s.risk), 'explainable risk, the admin without MFA first: ' + s.risk.slice(0, 300));
  ok(/Turn MFA on for administrator\(s\) ali\.syn/.test(s.next) && /Investigate ali\.syn/.test(s.next) && /dormant/.test(s.next), 'recommendations: ' + s.next);
  ok(/identity posture \d+ of 100/.test(s.ring) && !s.img, 'posture ring; a hostile account name stays text: ' + s.ring);
  await p.click('#tabs [data-tab="insights"]'); await p.click('[data-utab="newip"]'); ok(/203\.0\.113\.77/.test(await p.textContent('#unusual')), 'New address tab');
  await p.fill('#q', 'old'); ok(/old\.syn/.test(await p.textContent('#risk')) && !/ali\.syn/.test(await p.textContent('#risk')), 'search filters the risk list');
  if (process.argv[2]) { await p.fill('#q', ''); await p.click('[data-utab="all"]'); await p.screenshot({ path: process.argv[2], fullPage: true }); }
  WHO = 'operator'; await p.reload(); await p.waitForSelector('#msg .card');
  ok(/for administrators/.test(await p.textContent('#msg')) && (await p.textContent('#kk')) === '' && /not measured/.test(await p.getAttribute('#ring svg', 'aria-label')), 'non-administrator: told why, no data');
  ok(!errs.length && !dialogs.length, 'no page errors or dialogs: ' + errs.concat(dialogs).join(' | '));
  await browser.close(); srv.close();
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
