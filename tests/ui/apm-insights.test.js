// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for the Insights tab of apm.html (vendor/zyb-apmx.js). The insights answer is produced by the REAL SIEM module
// (sentra-siem engine/integrations/apm-insights.js) over a SYNTHETIC Applications Manager snapshot and 5-minute samples: the default
// tab, tiles, what to do first (click scrolls to its section), the probable-cause host, problems ranked with the points named, the
// problem drawer, Poll now (operator), Resume opening the Monitors tab on that monitor, reliability, alarm quality, hygiene, the
// trend, viewer (no buttons), not connected, escaping.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node apm-insights.test.js
const http = require('http'), fs = require('fs'), path = require('path'), os = require('os'), cp = require('child_process');
const SRC = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0;
const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const B = fs.mkdtempSync(path.join(os.tmpdir(), 'apmpage-')); fs.mkdirSync(path.join(B, 'vendor'));
fs.readdirSync(SRC).filter((f) => f.endsWith('.html')).forEach((f) => fs.copyFileSync(path.join(SRC, f), path.join(B, f)));
fs.readdirSync(path.join(SRC, 'vendor')).filter((f) => /\.(js|json|css)$/.test(f)).forEach((f) => fs.copyFileSync(path.join(SRC, 'vendor', f), path.join(B, 'vendor', f)));
['zyb-menu.js', 'zyb-dash.js'].forEach((t) => fs.writeFileSync(path.join(B, 'vendor', t), fs.readFileSync(path.join(B, 'vendor/zyb-nav.js'), 'utf8') + '\n' + fs.readFileSync(path.join(B, 'vendor', t), 'utf8')));
cp.execFileSync(process.execPath, [path.join(SRC, 'build-static.js'), B, 't1'], { stdio: 'ignore' });

const SIEM = process.env.SENTRA_SIEM_DIR || path.resolve(__dirname, '../../backend/siem');
const { createState } = require(path.join(SIEM, 'engine/soc/state'));
const X = require(path.join(SIEM, 'engine/integrations/apm-insights'));
const T = Date.now(), SLOT = 300000, D = 86400000;
const series = (k, fn) => Array.from({ length: k }, (_, i) => ({ t: T - (k - i) * SLOT, up: fn(i) ? 1 : 0, h: fn(i) ? 0 : 2 }));
const MON = [
  { id: '101', name: 'ERP web', type: 'URL Monitor', host: 'app01.syn', availability: 'down', health: 'critical', managed: true, last_polled: String(T - 60000), db: false },
  { id: '102', name: 'ERP Tomcat', type: 'Tomcat', host: 'app01.syn', availability: 'down', health: 'critical', managed: true, last_polled: String(T - 60000), db: false },
  { id: '201', name: 'Claims DB', type: 'Oracle DB', host: 'db01.syn', availability: 'up', health: 'critical', managed: true, last_polled: String(T - 3 * 3600000), db: true },
  { id: '301', name: 'Portal API', type: 'REST API', host: 'api01.syn', availability: 'up', health: 'clear', managed: true, last_polled: String(T - 60000), db: false },
  { id: '401', name: '<img src=x onerror=alert(1)>', type: 'URL Monitor', host: 'old.syn', availability: 'up', health: 'clear', managed: false, last_polled: '', db: false }];
const ALARMS = [{ resource_id: '201', name: 'Claims DB', severity: 'critical', attribute: 'Tablespace', message: 'USERS 97 %', time: String(T - 30 * 3600000) }];
let CONF = true, ROLE = 'operator'; const POSTS = [];
const apm = { status: () => ({ configured: CONF, last_sync: T - 60000 }), settings: () => ({ poll_min: 5 }), monitors: () => MON, alarms: () => ALARMS, actions: () => [] };
(async () => {
  const state = await createState({ dir: fs.mkdtempSync(path.join(os.tmpdir(), 'apmx-st-')) });
  const S = state.collection('webtier_samples');
  S.put({ id: '101', s: series(48, (i) => i < 46) }); S.put({ id: '102', s: series(48, (i) => i < 46) }); S.put({ id: '301', s: series(48, (i) => i % 2 === 0) });
  state.collection('apm_alarm_hist').put({ id: '201|Tablespace', resource_id: '201', name: 'Claims DB', attribute: 'Tablespace', episodes: Array.from({ length: 6 }, (_, i) => ({ from: T - (i + 1) * D, to: T - (i + 1) * D + 1800000, severity: 'warning' })), open: null });
  for (let i = 1; i <= 20; i++) state.collection('apm_daily').put({ id: 'd' + i, day: new Date(T - i * D + 3 * 3600000).toISOString().slice(0, 10), at: T - i * D, bad: 0, availability: 99.9 });
  const I = X.createApmInsights({ state, apm, now: () => T }); I.record();
  const now = new Date(T).toISOString();
  const srv = http.createServer((q, r) => {
    const u = q.url.split('?')[0], j = (c, o) => { r.writeHead(c, { 'Content-Type': 'application/json' }); r.end(JSON.stringify(o)); };
    if (u.endsWith('whoami.json')) return j(200, { user: 'oscar.syn', role: ROLE });
    if (u.startsWith('/api/')) {
      if (q.method === 'POST') { let b = ''; q.on('data', (c) => { b += c; }); q.on('end', () => { POSTS.push({ u, b: JSON.parse(b || '{}') }); j(200, { ok: true, status: 'done' }); }); return; }
      const P = '/api/soc/integrations/apm/';
      if (u === P + 'insights') return j(200, I.view());
      if (u === P + 'status') return j(200, CONF ? { configured: true, ok: true, last_sync: now, monitors: 5, db_monitors: 1, down: 2, unmanaged: 1, alarms: { critical: 1, warning: 0, db: 1 }, pending_actions: 0 } : { configured: false, monitors: 0, db_monitors: 0, down: 0, unmanaged: 0, alarms: { critical: 0, warning: 0, db: 0 }, pending_actions: 0 });
      if (u === P + 'monitors') return j(200, { items: CONF ? MON : [] });
      if (u === P + 'alarms') return j(200, { items: CONF ? ALARMS : [] });
      if (u === P + 'actions') return j(200, { items: [] });
      if (u === P + 'coverage') return j(200, { both: [], apm_only: [], siem_only: [] });
      if (u === P + 'settings') return j(403, { error: 'admin only' });
      return j(404, { error: 'not in this test' });
    }
    const f = path.join(B, u === '/' ? 'index.html' : u); if (!f.startsWith(B)) { r.writeHead(403); return r.end(); }
    fs.readFile(f, (e, d) => { if (e) { r.writeHead(404); return r.end(); } r.writeHead(200, { 'Content-Type': u.endsWith('.js') ? 'application/javascript' : u.endsWith('.css') ? 'text/css' : 'text/html' }); r.end(d); });
  });
  await new Promise((res) => srv.listen(0, '127.0.0.1', res));
  const base = 'http://127.0.0.1:' + srv.address().port + '/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const open = async () => { const p = await browser.newPage({ viewport: { width: 1500, height: 950 } }); p.on('pageerror', (e) => errs.push(e.message)); p.on('dialog', (d) => { errs.push('dialog ' + d.message()); d.dismiss(); }); await p.goto(base + 'apm.html'); return p; };
  const txt = (p, id) => p.evaluate((i) => (document.getElementById(i) || {}).textContent || '', id);

  let p = await open();
  await p.waitForSelector('#x-pr');
  ok(await p.evaluate(() => !document.getElementById('tab-in').hidden && document.getElementById('tab-mo').hidden), 'Insights is the default tab');
  const tin = await txt(p, 'tab-in');
  ok(/Down or critical3/i.test(tin) && /Probable-cause hosts1/i.test(tin) && /Flapping1/i.test(tin), 'tiles: ' + tin.slice(0, 200));
  ok(/app01\.syn/.test(await txt(p, 'x-hosts')) && /ERP web/.test(await txt(p, 'x-hosts')) && /ERP Tomcat/.test(await txt(p, 'x-hosts')), 'probable-cause host lists its monitors');
  const first = await p.evaluate(() => document.querySelector('#x-act [data-act]').getAttribute('data-act'));
  ok(first === 'go:hosts', 'first action is the host: ' + first);
  await p.click('#x-act [data-act="go:hosts"]'); await p.waitForTimeout(600);
  ok(await p.evaluate(() => { const r = document.getElementById('x-hosts').getBoundingClientRect(); return r.top < innerHeight && r.bottom > 0; }), 'action scrolls to its section');
  const rows = await p.evaluate(() => [].map.call(document.querySelectorAll('#x-pr tr.xr td:first-child b'), (b) => b.textContent));
  ok(rows.length >= 3 && rows.includes('ERP web') && rows.includes('Claims DB'), 'problems listed: ' + rows.join(', '));
  const why = await p.evaluate(() => document.querySelector('#x-pr tr.xr td:nth-child(3)').getAttribute('title'));
  ok(/^\+\d+ /.test(why || ''), 'impact names its points: ' + why);
  await p.click('#x-pr tr.xr:has-text("ERP web") td:first-child');
  await p.waitForFunction(() => /Impact \d+ \/ 100/.test((document.getElementById('zd-b') || {}).textContent || ''));
  ok(/check the server or VM first/.test(await txt(p, 'zd-b')), 'drawer: next step names the host');
  await p.keyboard.press('Escape');
  await p.click('#x-pr tr.xr:has-text("Claims DB") [data-xpoll]'); await p.waitForTimeout(400);
  ok(POSTS.some((x) => x.u.endsWith('/integrations/apm/actions') && x.b.action === 'poll' && x.b.resource_id === '201'), 'Poll now posts the poll action');
  ok(/Tablespace/.test(await txt(p, 'x-noise')) && /6×/.test(await txt(p, 'x-noise')) && /30 h/.test(await txt(p, 'x-noise')), 'alarm quality: noisy and long-open');
  ok(/flapping/i.test(await txt(p, 'x-rel')) && /Portal API/.test(await txt(p, 'x-rel')), 'reliability shows flapping');
  ok(/Claims DB/.test(await txt(p, 'x-hyg')) && /no maintenance request/.test(await txt(p, 'x-hyg')), 'hygiene: stale and unmanaged');
  ok(await p.evaluate(() => !document.querySelector('#x-hyg img')), 'monitor names are escaped');
  ok(await p.evaluate(() => document.querySelectorAll('#x-trend i').length) >= 20, 'trend bars drawn');
  await p.click('#x-hyg [data-xresume]'); await p.waitForTimeout(300);
  ok(await p.evaluate(() => !document.getElementById('tab-mo').hidden && document.getElementById('q').value === '<img src=x onerror=alert(1)>'), 'Resume opens Monitors on that monitor (its request asks why)');
  await p.close();

  ROLE = 'viewer'; p = await open(); await p.waitForSelector('#x-pr');
  ok(await p.evaluate(() => !document.querySelector('#tab-in [data-xpoll], #tab-in [data-xresume]')), 'viewer: read only');
  await p.close();

  CONF = false; ROLE = 'operator'; p = await open(); await p.waitForFunction(() => /not connected/i.test(document.getElementById('tab-in').textContent));
  ok(!(await p.evaluate(() => document.querySelector('#tab-in tr'))), 'not connected: nothing invented');
  await p.close();

  ok(/vendor\/zyb-apmx\.js/.test(fs.readFileSync(path.join(SRC, 'install-dashboards.sh'), 'utf8')), 'in the installer');
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  await browser.close(); srv.close();
  console.log(`${n - bad}/${n} checks passed`); process.exit(bad ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
