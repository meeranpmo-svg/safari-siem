// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for netflow.html (NetFlow Analytics) after the static build. The answers come from the REAL SIEM engine
// (sentra-siem engine/soc/flow-analytics-routes.js + the flow collector) fed SYNTHETIC NetFlow v5 datagrams (documentation
// address ranges) and a stub ClickHouse that answers each history query by its tag with SYNTHETIC rows. Checks: nothing
// configured says what to configure and shows no number it does not have; an administrator adds an exporter (name escaped)
// and enables the listeners; live traffic and utilisation from the exporter's link speed; a sender not on the allow-list is
// listed; applications, conversations, groups + a bill only from a rate that was set; an alarm and a template preview
// (escaped); forecast days to 80 %; too little pattern history said; security detections; a viewer sees no address and
// no admin form; no page error.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node netflow.test.js
const http = require('http'), fs = require('fs'), path = require('path'), os = require('os'), cp = require('child_process');
const SRC = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0;
const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const B = fs.mkdtempSync(path.join(os.tmpdir(), 'nfpage-')); fs.mkdirSync(path.join(B, 'vendor'));
fs.readdirSync(SRC).filter((f) => f.endsWith('.html')).forEach((f) => fs.copyFileSync(path.join(SRC, f), path.join(B, f)));
fs.readdirSync(path.join(SRC, 'vendor')).filter((f) => /\.(js|json|css)$/.test(f)).forEach((f) => fs.copyFileSync(path.join(SRC, 'vendor', f), path.join(B, 'vendor', f)));
['zyb-menu.js', 'zyb-dash.js'].forEach((t) => fs.writeFileSync(path.join(B, 'vendor', t), fs.readFileSync(path.join(B, 'vendor/zyb-nav.js'), 'utf8') + '\n' + fs.readFileSync(path.join(B, 'vendor', t), 'utf8')));
cp.execFileSync(process.execPath, [path.join(SRC, 'build-static.js'), B, 't1'], { stdio: 'ignore' });

const SIEM = process.env.SENTRA_SIEM_DIR || path.resolve(__dirname, '../../backend/siem');
const { createState } = require(path.join(SIEM, 'engine/soc/state'));
const routes = require(path.join(SIEM, 'engine/soc/flow-analytics-routes'));
const XSS = '<img src=x onerror="window.__xss=1">';

// SYNTHETIC NetFlow v5 datagram (documentation / private ranges only)
function v5(recs) {
  const h = Buffer.alloc(24); h.writeUInt16BE(5, 0); h.writeUInt16BE(recs.length, 2);
  return Buffer.concat([h].concat(recs.map((r) => { const b = Buffer.alloc(48); r.src.split('.').forEach((x, i) => { b[i] = +x; }); r.dst.split('.').forEach((x, i) => { b[4 + i] = +x; });
    b.writeUInt16BE(r.in, 12); b.writeUInt16BE(r.out, 14); b.writeUInt32BE(r.pk, 16); b.writeUInt32BE(r.by, 20); b.writeUInt16BE(r.sp, 32); b.writeUInt16BE(r.dp, 34); b[37] = r.fl || 0x18; b[38] = r.pr || 6; return b; })));
}
const NOW = Date.now(), DAY = 86400000, d0 = Math.floor(NOW / DAY) * DAY - 30 * DAY;
const CH = {
  top_app: [{ k: 'HTTPS', b: 9e9, p: 1, n: 30 }, { k: 'SMB', b: 1e9, p: 1, n: 10 }], top_series: [{ t: 2, k: 'HTTPS', b: 6e8 }],
  if_list: [{ exporter: '192.0.2.1', if_index: 3, dir: 'in', bytes: 9e9, packets: 1, peak: 6e8 }], if_total: [{ k: 1, b: 6e8, n: 9 }],
  talk_src: [{ a: '10.10.1.5', b: 5e8, p: 1, n: 4, peers: 2, apps: ['HTTPS'] }],
  grp_bytes: [{ ip: '10.10.1.5', dir: 'dst', b: 3e9, app: 'HTTPS' }, { ip: '10.10.1.5', dir: 'src', b: 1e9, app: 'HTTPS' }, { ip: '10.20.0.7', dir: 'dst', b: 2e9, app: 'SMB' }],
  fc_peaks: Array.from({ length: 30 }, (_, i) => ({ exporter: '192.0.2.1', if_index: 3, dir: 'in', d: (d0 + i * DAY) / 1000, peak: (30 + i) * 1e6 * 60 / 8 })),
  pat_total: Array.from({ length: 100 }, (_, i) => ({ h: (Math.floor(NOW / 3600000) - 100 + i) * 3600, b: 1e6 })),
};
const ch = { query: async (sql) => { const tag = /^\/\*q:([a-z_0-9]+)\*\//.exec(sql)[1]; return (CH[tag] || []).map((r) => Object.assign({}, r)); }, insertRows: async () => {} };

let ROLE = 'admin'; const POSTS = [];
(async () => {
  const state = await createState({ dir: fs.mkdtempSync(path.join(os.tmpdir(), 'nfpage-st-')) });
  const R = []; const raised = [];
  const N = routes.register({ route: (m, p, h) => { R.push({ m, re: new RegExp('^' + p.replace(/:id/g, '([^/]+)') + '$'), h }); } },
    { state, ch, noTimers: true, config: { clickhouse: { database: 'siem' } }, log: { info() {}, warn() {}, error() {}, every() {} }, alerts: { raise: (a) => { raised.push(a); return { created: true }; } }, intel: { match: () => false } });
  const RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 };
  const srv = http.createServer((q, r) => {
    const [u, qs] = q.url.split('?'), j = (c, o) => { r.writeHead(c, { 'Content-Type': 'application/json' }); r.end(JSON.stringify(o)); };
    if (u.endsWith('whoami.json')) return j(200, { user: 'syed', role: ROLE });
    if (u.startsWith('/api/soc/netflow/')) {
      let b = ''; q.on('data', (c) => { b += c; }); q.on('end', async () => {
        const bodyIn = b ? JSON.parse(b) : {}; if (q.method !== 'GET') POSTS.push({ m: q.method, u, body: bodyIn });
        const rt = R.find((x) => x.m === q.method && x.re.test(u)); if (!rt) return j(404, { error: 'not in this test' });
        const mm = rt.re.exec(u), out = {};
        const ctx = { role: ROLE, user: 'syed', ip: '10.0.0.5', body: bodyIn, params: { id: mm[1] && decodeURIComponent(mm[1]) }, query: Object.fromEntries(new URLSearchParams(qs || '')),
          need(x) { if (RANK[ROLE] < RANK[x]) { out.c = 403; out.e = 'requires ' + x; return false; } return true; }, audit() {}, ok(v) { out.c = 200; out.v = v; }, fail(c, e) { out.c = c; out.e = e; } };
        try { await rt.h(ctx); return out.c === 200 ? j(200, out.v) : j(out.c || 500, { error: out.e }); } catch (e) { return j(500, { error: e.message }); }
      }); return;
    }
    if (u.startsWith('/api/')) return j(404, { error: 'not in this test' });
    const f = path.join(B, u === '/' ? 'index.html' : u); if (!f.startsWith(B)) { r.writeHead(403); return r.end(); }
    fs.readFile(f, (e, d) => { if (e) { r.writeHead(404); return r.end(); } r.writeHead(200, { 'Content-Type': u.endsWith('.js') ? 'application/javascript' : u.endsWith('.css') ? 'text/css' : 'text/html' }); r.end(d); });
  });
  await new Promise((res) => srv.listen(0, '127.0.0.1', res));
  const base = 'http://127.0.0.1:' + srv.address().port + '/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const open = async (hash) => { const p = await browser.newPage({ viewport: { width: 1500, height: 950 } }); p.on('pageerror', (e) => errs.push(e.message)); p.on('dialog', (d) => { errs.push('dialog ' + d.message()); d.dismiss(); }); await p.goto(base + 'netflow.html' + (hash || '')); await p.waitForSelector('#kpis .so-kpi'); return p; };
  const txt = (p, id) => p.evaluate((i) => (document.getElementById(i) || {}).textContent || '', id);

  // 1. nothing configured: what to configure, no invented number
  let p = await open();
  ok(await p.title() === 'NetFlow Analytics', 'title');
  const setup = await txt(p, 'setup');
  ok(/allow-list/.test(setup) && /Enable the flow listeners \(UDP 2055, 4739, 6343\)/.test(setup), 'setup says what to configure: ' + setup.slice(0, 160));
  ok(/Exporters receiving0 \/ 0/.test(await txt(p, 'kpis')), 'KPIs: 0 of 0 exporters, nothing invented');
  await p.waitForFunction(() => /not running/.test((document.querySelector('#tab-live .zyb-chart-empty') || {}).textContent || ''));
  ok(true, 'live chart: empty state says the collector is not running');

  // 2. administrator: exporter (escaped name) + listener settings
  await p.click('[data-tab="set"]'); await p.waitForSelector('#x-save');
  await p.fill('#x-ip', '192.0.2.1'); await p.fill('#x-name', 'RTR-HQ ' + XSS); await p.fill('#x-speeds', '3=100 Gi0/3');
  await p.click('#x-save'); await p.waitForFunction(() => /RTR-HQ/.test(document.getElementById('x-list').textContent));
  ok(POSTS.some((x) => x.u.endsWith('/netflow/exporters') && x.body.ip === '192.0.2.1' && x.body.if_speeds[0].mbps === 100), 'exporter posted with its interface speed');
  ok(await p.evaluate(() => !window.__xss) && !(await p.$('#x-list img')), 'exporter name escaped');
  await p.check('#s-en'); await p.click('#s-save'); await p.waitForTimeout(400);
  ok(POSTS.some((x) => x.u.endsWith('/netflow/settings') && x.body.enabled === true && x.body.ports.netflow === 2055), 'listener settings saved');
  await p.fill('#x-ip', '192.0.2.1'); await p.fill('#x-name', 'bad'); await p.fill('#x-samp', '0'); await p.click('#x-save');
  ok(await p.waitForFunction(() => [].some.call(document.querySelectorAll('.toast'), (t) => /sampling must be at least 1/.test(t.textContent)), null, { timeout: 5000 }).then(() => true, () => false), 'server validation message shown');
  await p.close();

  // 3. synthetic flows through the real collector, one minute closed
  const C = N.collector;
  C.handle(v5([{ src: '10.10.1.5', dst: '198.51.100.7', in: 3, out: 9, pk: 10, by: 4.5e8, sp: 51000, dp: 443 }, { src: '10.20.0.7', dst: '10.30.0.9', in: 5, out: 4, pk: 4, by: 3e8, sp: 50000, dp: 445 }]), '192.0.2.1');
  for (let port = 1; port <= 120; port++) C.handle(v5([{ src: '10.10.1.66', dst: '10.10.1.10', in: 6, out: 4, pk: 1, by: 60, sp: 40000, dp: port, fl: 0x02 }]), '192.0.2.1');
  C.handle(v5([{ src: '10.0.0.1', dst: '10.0.0.2', in: 1, out: 2, pk: 1, by: 1, sp: 1, dp: 2 }]), '198.51.100.66');
  await C.flush(true);
  ok(raised.some((a) => a.rule_id === 'netflow-port-scan'), 'the port scan went to the alert pipeline');

  p = await open();
  ok(!(await txt(p, 'setup')).includes('allow-list'), 'configured: the allow-list step is gone');
  await p.waitForSelector('#lv-if tr[data-if]');
  const row = await p.evaluate(() => document.querySelector('#lv-if tr[data-if]').textContent);
  ok(/Gi0\/3/.test(row) && /100 Mbps/.test(row) && /60 %/.test(row), 'live interface: 4.5e8 bytes in a minute on 100 Mbps = 60 %: ' + row.slice(0, 160));
  ok(await p.evaluate(() => !document.getElementById('c-live').hidden), 'live chart drawn');
  await p.click('#lv-if tr[data-if]');
  ok(await p.waitForFunction(() => /Gi0\/3/.test(document.getElementById('lv-sel').textContent), null, { timeout: 5000 }).then(() => true, () => false), 'interface history opened');
  ok(await p.evaluate(() => !window.__xss), 'no script ran from the exporter name');

  await p.click('[data-tab="set"]'); await p.waitForSelector('[data-add-exp]');
  ok(/198\.51\.100\.66/.test(await txt(p, 'x-unknown')), 'a sender not on the allow-list is listed');
  await p.click('[data-add-exp]'); ok(await p.inputValue('#x-ip') === '198.51.100.66', 'Add fills the form');
  ok(/NetFlow v5/.test(await txt(p, 'x-list')), 'formats seen per exporter');

  await p.click('[data-tab="apps"]'); await p.waitForFunction(() => /HTTPS/.test(document.getElementById('ap-list').textContent));
  ok(/90 %/.test(await txt(p, 'ap-list')), 'application share');

  await p.click('[data-tab="conv"]'); await p.waitForFunction(() => /10\.10\.1\.5/.test(document.getElementById('cv-list').textContent));
  ok(true, 'conversations for an administrator');

  await p.click('[data-tab="groups"]'); await p.waitForSelector('#g-save');
  await p.fill('#g-name', 'Finance'); await p.fill('#g-cidrs', '10.10.0.0/16'); await p.fill('#g-rate', '0.5'); await p.click('#g-save');
  await p.waitForFunction(() => /Finance/.test(document.getElementById('g-use').textContent));
  await p.fill('#g-name', 'Jeddah branch'); await p.selectOption('#g-kind', 'site'); await p.fill('#g-cidrs', '10.20.0.0/16'); await p.click('#g-save');
  await p.waitForFunction(() => /Jeddah branch/.test(document.getElementById('g-use').textContent));
  await p.click('#b-load'); await p.waitForFunction(() => /Finance/.test(document.getElementById('b-bill').textContent));
  const bill = await txt(p, 'b-bill');
  ok(/2\.00 SAR/.test(bill), 'Finance billed 4 GB x 0.5: ' + bill.slice(0, 200));
  ok(/no rate per GB set - not billed/.test(bill), 'a group without a rate is not billed');

  await p.click('[data-tab="alarms"]'); await p.waitForSelector('#al-save');
  await p.fill('#al-name', 'WAN busy'); await p.fill('#al-target', '192.0.2.1#3'); await p.fill('#al-th', '80'); await p.click('#al-save');
  await p.waitForFunction(() => /WAN busy/.test(document.getElementById('al-list').textContent));
  await p.fill('#tp-name', 'NOC'); await p.fill('#tp-subj', 'NOC {{alarm}}'); await p.fill('#tp-body', '<b>{{alarm}}</b> {{value}}'); await p.click('#tp-prev');
  await p.waitForFunction(() => !document.getElementById('tp-out').hidden);
  ok(/Subject: NOC Example alarm/.test(await txt(p, 'tp-out')) && !(await p.$('#tp-out b')), 'template preview shown as text');

  await p.click('[data-tab="fc"]'); await p.waitForSelector('#fc-list tr[data-fc]');
  ok(/21 days/.test(await txt(p, 'fc-list')), 'forecast: days to 80 %');
  await p.click('#fc-list tr[data-fc]'); await p.waitForFunction(() => !document.getElementById('fc-selp').hidden);

  await p.click('[data-tab="pat"]'); await p.waitForFunction(() => /needs two weeks/.test(document.getElementById('p-heat').textContent));
  ok(true, 'patterns: too little history is said');

  await p.click('[data-tab="sec"]'); await p.waitForFunction(() => /probed 120 ports/.test(document.getElementById('sec-list').textContent));
  ok(!!(await p.$('#d-save')), 'admin: detection settings form');
  await p.close();

  // 4. a viewer: aggregates only
  ROLE = 'viewer'; p = await open('#conv');
  await p.waitForFunction(() => /Your role cannot see addresses/.test(document.getElementById('cv-list').textContent));
  await p.click('[data-tab="sec"]'); await p.waitForFunction(() => /analysts and above/.test(document.getElementById('sec-list').textContent));
  await p.click('[data-tab="set"]'); await p.waitForFunction(() => /administrator keeps the exporter allow-list/.test(document.getElementById('x-form').textContent));
  ok(!(await p.$('#x-save')) && !(await p.$('#s-save')) && !(await p.$('#a-save')), 'viewer: no admin form');
  await p.close();

  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  await browser.close(); srv.close();
  console.log(`${n - bad}/${n} checks passed`); process.exit(bad ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
