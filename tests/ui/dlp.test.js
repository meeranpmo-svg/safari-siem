// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for dlp.html after the static build: totals, channels, policies, data classes, people to review with the
// itemised Why, incidents drill-down, failed panels shown as not read (never 0), the viewer without names, the empty state,
// and the admin schedule. API answers are SYNTHETIC, in the shape engine/reports/dlp.js returns.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node dlp.test.js
const http = require('http'), fs = require('fs'), path = require('path'), os = require('os'), cp = require('child_process');
const SRC = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0;
const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const B = fs.mkdtempSync(path.join(os.tmpdir(), 'dlppage-')); fs.mkdirSync(path.join(B, 'vendor'));
fs.readdirSync(SRC).filter((f) => f.endsWith('.html')).forEach((f) => fs.copyFileSync(path.join(SRC, f), path.join(B, f)));
fs.readdirSync(path.join(SRC, 'vendor')).filter((f) => /\.(js|json|css)$/.test(f)).forEach((f) => fs.copyFileSync(path.join(SRC, 'vendor', f), path.join(B, 'vendor', f)));
['zyb-menu.js', 'zyb-dash.js'].forEach((t) => fs.writeFileSync(path.join(B, 'vendor', t), fs.readFileSync(path.join(B, 'vendor/zyb-nav.js'), 'utf8') + '\n' + fs.readFileSync(path.join(B, 'vendor', t), 'utf8')));
cp.execFileSync(process.execPath, [path.join(SRC, 'build-static.js'), B, 't1'], { stdio: 'ignore' });
const now = Date.now();
const FULL = { generated_at: now, period: { from: now - 30 * 864e5, to: now, label: '30d' }, clickhouse: { ok: true, errors: [] }, available: true, names: true,
  totals: { incidents: 42, left: 6, blocked: 30, encrypted: 2, not_reported: 4, people: 5, hosts: 6, high: 9, after_hours: 7, matches: 1200, tamper: 1 },
  channels: [{ channel: 'usb', incidents: 25, left: 2, blocked: 23 }, { channel: 'web / cloud', incidents: 10, left: 4, blocked: 6 }],
  policies: [{ policy: 'Confidential-USB', incidents: 25, left: 2, blocked: 23, people: 3 }],
  classes: [{ class: 'National ID', incidents: 12, left: 3, sensitive: 'National ID / Iqama / passport' }],
  actions: [], sources: [{ vendor: 'somansa', product: 'Privacy-i', src_id: 'somansa-hq', incidents: 42, last_ms: now - 6e5 }],
  trend: [{ t: now - 2 * 864e5, n: 5, n_left: 1 }, { t: now - 864e5, n: 8, n_left: 2 }],
  users: [{ user: 'fahad', incidents: 15, left: 5, blocked: 10, high: 6, after_hours: 6, matches: 800, channels: ['usb', 'web / cloud'], classes: ['National ID'], hosts: ['fin-pc07'], last_ms: now - 36e5, risk: 85, tamper: 1,
    why: [{ points: 25, reason: '5 incident(s) where the DLP product let the data go' }, { points: 20, reason: 'DLP agent or protection disabled 1 time(s) on this account' }] },
    { user: '<img src=x onerror=alert(1)>', incidents: 1, left: 0, blocked: 1, high: 0, after_hours: 0, matches: 1, channels: ['usb'], classes: [], hosts: [], last_ms: now, risk: 0, tamper: 0, why: [] }],
  hosts: [{ host: 'fin-pc07', incidents: 15, left: 5, people: 1, last_ms: now }], destinations: [{ destination: 'https://files.example/upload', incidents: 3, people: 1 }],
  tamper_events: [{ ts: now - 5e6, user: 'fahad', host: 'fin-pc07', product: 'Privacy-i', message: 'agent stopped' }] };
let ROLE = 'operator', MODE = 'full'; const POSTS = [], GETS = [];
(async () => {
  const srv = http.createServer((q, r) => {
    const u = q.url.split('?')[0], j = (c, o) => { r.writeHead(c, { 'Content-Type': 'application/json' }); r.end(JSON.stringify(o)); };
    if (u.endsWith('whoami.json')) return j(200, { user: 'rasheed', role: ROLE });
    if (u.startsWith('/api/')) {
      GETS.push(q.url);
      if (q.method === 'POST') { let b = ''; q.on('data', (c) => { b += c; }); q.on('end', () => { POSTS.push({ u, b: JSON.parse(b || '{}') }); j(200, { ok: true, status: 'ok' }); }); return; }
      if (u === '/api/soc/dlp/summary') {
        if (MODE === 'empty') return j(200, Object.assign({}, FULL, { available: false, totals: { incidents: 0, left: 0, blocked: 0, encrypted: 0, not_reported: 0, people: 0, hosts: 0, high: 0, after_hours: 0, matches: 0, tamper: 0 }, channels: [], policies: [], classes: [], sources: [], users: [], hosts: [], destinations: [], tamper_events: [] }));
        if (MODE === 'partial') return j(200, Object.assign({}, FULL, { clickhouse: { ok: false, errors: [{ panel: 'policies', error: 'timeout' }] }, policies: null }));
        if (ROLE === 'viewer') return j(200, Object.assign({}, FULL, { names: false, users: null, hosts: null, destinations: null, tamper_events: null }));
        return j(200, FULL);
      }
      if (u === '/api/soc/dlp/events') return j(200, { items: [{ ts: now, product: 'Privacy-i', policy: 'Confidential-USB', channel: 'usb', class: 'National ID', action: 'permitted', file: 'payroll.xlsx', destination: 'E:\\', matches: 37, after_hours: true }] });
      if (u === '/api/soc/dlp/schedule') return j(200, { schedule: { enabled: true, period: 'monthly', at: '07:30', weekday: 0, day_of_month: 1, recipients: ['ciso@as.example'] }, last: { status: 'ok', at: now - 864e5 }, next_at: now + 5 * 864e5, mail: { ok: true, problems: [] } });
      return j(404, {});
    }
    fs.readFile(path.join(B, u.replace(/^\/dashboards\//, '/')), (e, d) => { if (e) { r.writeHead(404); return r.end(); } r.writeHead(200, { 'Content-Type': u.endsWith('.js') ? 'application/javascript' : u.endsWith('.css') ? 'text/css' : 'text/html' }); r.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const url = 'http://127.0.0.1:' + srv.address().port + '/dashboards/dlp.html';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const open = async () => { const p = await browser.newPage(); p.on('pageerror', (e) => errs.push(e.message)); p.on('dialog', (d) => d.accept()); await p.goto(url);
    await p.waitForFunction(() => !/Loading/.test(document.getElementById('kpi').innerText), null, { timeout: 8000 }).catch(() => {}); await p.waitForTimeout(300); return p; };
  const txt = (p, id) => p.evaluate((i) => document.getElementById(i).innerText.replace(/\s+/g, ' '), id);

  let p = await open();
  ok(/INCIDENTS 42/i.test(await txt(p, 'kpi')) && /LET THROUGH 6/i.test(await txt(p, 'kpi')) && /AGENT DISABLED 1/i.test(await txt(p, 'kpi')), 'totals: ' + (await txt(p, 'kpi')).slice(0, 160));
  ok(/usb 25 2 23/.test(await txt(p, 'chan')) && /Confidential-USB/.test(await txt(p, 'pol')) && /National ID \/ Iqama/.test(await txt(p, 'cls')), 'channels, policies, classes');
  ok(/fahad/.test(await txt(p, 'users')) && /agent disabled/.test(await txt(p, 'users')) && /85/.test(await txt(p, 'users')), 'people to review with risk');
  ok(await p.evaluate(() => !document.querySelector('#users img')), 'names escaped');
  ok(/files\.example/.test(await txt(p, 'dest')) && /agent stopped/.test(await txt(p, 'tamper')) && /somansa-hq/.test(await txt(p, 'src')), 'destinations, tamper, sources');
  ok(await p.evaluate(() => document.querySelectorAll('#trend .bars i').length === 2), 'trend bars');
  ok(await p.evaluate(() => { const h = [...document.querySelectorAll('#dl a')].map((a) => a.getAttribute('href')); return h.some((x) => /dlp\/report\.html\?period=30d&download=1$/.test(x)) && h.some((x) => /dlp\/events\.csv\?period=30d$/.test(x)); }), 'report + CSV links');
  await p.click('[data-why="0"]'); await p.waitForTimeout(300);
  ok(/let the data go/.test(await p.evaluate(() => document.body.innerText)) && /Indicators, not proof/.test(await p.evaluate(() => document.body.innerText)), 'Why shows each point');
  await p.keyboard.press('Escape');
  await p.click('[data-ev="user"][data-v="fahad"]'); await p.waitForTimeout(400);
  ok(GETS.some((g) => /\/api\/soc\/dlp\/events\?period=30d&user=fahad/.test(g)) && /payroll\.xlsx/.test(await p.evaluate(() => document.body.innerText)), 'incidents drill-down');
  await p.close();

  ROLE = 'admin'; p = await open();
  ok(await p.evaluate(() => !document.getElementById('schedCard').hidden) && /next/.test(await txt(p, 'sc')), 'admin sees the schedule');
  await p.fill('#s-to', 'ciso@as.example, dpo@as.example'); await p.selectOption('#s-p', 'weekly'); await p.click('#s-save'); await p.waitForTimeout(300);
  const sv = POSTS.find((x) => x.u === '/api/soc/dlp/schedule');
  ok(sv && sv.b.period === 'weekly' && sv.b.recipients.length === 2 && sv.b.enabled === true, 'schedule saved');
  await p.click('#s-now'); await p.waitForTimeout(300);
  ok(POSTS.some((x) => x.u === '/api/soc/dlp/send-now'), 'send now');
  await p.close();

  ROLE = 'viewer'; p = await open();
  ok(/INCIDENTS 42/i.test(await txt(p, 'kpi')) && /operators and administrators see them/.test(await txt(p, 'users')) && !(await p.evaluate(() => /fahad/.test(document.body.innerText))), 'viewer: totals, no names');
  ok(await p.evaluate(() => !document.getElementById('dl').innerHTML && document.getElementById('schedCard').hidden), 'viewer: no downloads, no schedule');
  await p.close();

  ROLE = 'operator'; MODE = 'partial'; p = await open();
  ok(/could not be read/.test(await txt(p, 'pol')) && /Some panels could not be read/.test(await txt(p, 'state')), 'a failed panel says so, never 0');
  await p.close();
  MODE = 'empty'; p = await open();
  ok(/No DLP incident reached the SIEM/.test(await txt(p, 'state')) && /No DLP source has sent/.test(await txt(p, 'src')), 'empty: explains, shows nothing invented');
  await p.close();

  ok(/"h": "dlp\.html"/.test(fs.readFileSync(path.join(SRC, 'vendor/zyb-nav.js'), 'utf8')) && /dlp\.html/.test(fs.readFileSync(path.join(SRC, 'install-dashboards.sh'), 'utf8')), 'in the menu and the installer');
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  await browser.close(); srv.close();
  console.log(`${n - bad}/${n} checks passed`); process.exit(bad ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
