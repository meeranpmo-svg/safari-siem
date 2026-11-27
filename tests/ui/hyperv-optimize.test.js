// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Hyper-V Optimization (hyperv-optimize.html) with the REAL engine's answer (backend/itam engine/hyperv-optimize.js) over SYNTHETIC
// reports: the score and tiles, what the AI noticed, the charts (balance, 48 h CPU and memory, VM fit, give-back, storage, thin
// provisioning, NICs), the move between two hosts of one site, the recommendations with the filters, the unusual readings; nothing
// reported says what to do; a hostile VM name stays text; POC mode with one ribbon; menu entry and installer.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node hyperv-optimize.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui'), O = require(path.resolve(__dirname, '../../backend/itam/engine/hyperv-optimize'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror=window.PWN=1>';
const DAY = 864e5, NOW = Date.now(), GB = 1024;
function world() {
  const vm = (name, o) => Object.assign({ name, state: 'running', vcpus: 2, mem_assigned_mb: 8 * GB, vhds: [], checkpoints: [] }, o);
  const A = { at: new Date(NOW).toISOString(), host: { name: 'HV-SYN-01', cores: 32, cpu_pct: 60, mem_total_mb: 256 * GB, mem_free_mb: 40 * GB, volumes: [{ name: 'C:\\ClusterStorage\\Volume1', size_gb: 1000, free_gb: 150 }], nics: [{ name: 'NIC1', link_mbps: 1000, rx_bps: 800e6, tx_bps: 700e6 }] },
    vms: [vm('BIG-SYN', { mem_assigned_mb: 64 * GB, vcpus: 8, vhds: [{ path: 'C:\\ClusterStorage\\Volume1\\B\\d.vhdx', size_gb: 100, max_gb: 1300 }] }), vm(XSS, { mem_assigned_mb: 48 * GB }), vm('TIGHT-SYN')] };
  const B = { at: new Date(NOW).toISOString(), host: { name: 'HV-SYN-02', cores: 32, cpu_pct: 10, mem_total_mb: 256 * GB, mem_free_mb: 200 * GB, volumes: [], nics: [] }, vms: [] };
  const daily = []; for (let d = 0; d < 8; d++) daily.push({ id: 'hv-syn-01|' + new Date(NOW - (8 - d) * DAY).toISOString().slice(0, 10), volumes: { 'C:\\ClusterStorage\\Volume1': 820 + d * 5 }, vms: { 'BIG-SYN': { mem_demand_mb: 10 * GB, cpu_pct: 5 }, 'TIGHT-SYN': { mem_demand_mb: 7.9 * GB, cpu_pct: 40 }, [XSS]: { mem_demand_mb: 40 * GB, cpu_pct: 30 } } });
  const samples = Array.from({ length: 30 }, (_, i) => ({ host: 'hv-syn-01', t: NOW - (30 - i) * 900e3, cpu: i === 29 ? 95 : 30 + (i % 3), mem_pct: 84, disk_ms: 4, nics: { NIC1: { rx_bps: 300e6, tx_bps: 200e6 } } }));
  return { latest: [A, B], daily, samples, now: NOW };
}
(async () => {
  let V = O.analyse(world());
  const srv = http.createServer((req, res) => { const u = new URL(req.url, 'http://x'), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, { user: 'vera.syn', role: 'viewer' });
    if (u.pathname === '/api/itam/hyperv/optimize') return json(200, V);
    if (u.pathname.startsWith('/api/')) return json(500, { error: 'down (synthetic)' });
    fs.readFile(path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')), (err, d) => { if (err) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); }); });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/dashboards/hyperv-optimize.html';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch(), errs = [];
  const open = async (q) => { const p = await browser.newPage({ viewport: { width: 1500, height: 1100 } }); p.on('pageerror', (x) => errs.push(x.message)); await p.goto(base + (q || '?standalone=1')); await p.waitForSelector('#main:not([hidden])', { timeout: 15000 }); await p.waitForTimeout(300); return p; };
  try {
    let p = await open();
    const kp = (await p.$eval('#kp', (x) => x.innerText)).replace(/\s+/g, ' ');
    ok(/Hosts 2/.test(kp) && /Memory to give back 51\.5 GB/.test(kp) && /vCPUs to remove 4/.test(kp), 'tiles: ' + kp);
    ok(/optimized/.test(await p.textContent('#gauge')) && /can be given back/.test(await p.textContent('#ins')), 'score and what the AI noticed');
    ok((await p.$$('canvas')).length === 8, 'eight charts');
    ok(!(await p.$eval('#mvc', (x) => x.hidden)) && /HV-SYN-01/.test(await p.textContent('#mv')) && /HV-SYN-02/.test(await p.textContent('#mv')), 'the move between two hosts of one site');
    await p.selectOption('#fk', 'memory-down'); ok((await p.$$('#rec tbody tr')).length >= 1 && /BIG-SYN/.test(await p.textContent('#rec')), 'filter by kind');
    await p.selectOption('#fk', ''); await p.selectOption('#fp', 'high'); ok((await p.$$('#rec tbody tr')).length >= 1, 'filter by priority');
    ok(/CPU %/.test(await p.textContent('#anom')), 'an unusual reading');
    ok(!(await p.evaluate(() => window.PWN)), 'hostile text stays text'); await p.close();
    V = O.analyse({ latest: [] }); p = await open(); ok(/No Hyper-V host reports yet/.test(await p.textContent('#ins')), 'nothing reported: what to do'); await p.close();
    p = await open('?poc=1'); ok((await p.$$('.zyb-poc-r.br')).length === 1 && /HQPSUPERM/.test(await p.textContent('#rec')), 'POC: illustrative hosts, one ribbon');
    if (process.env.SHOT) { await p.waitForTimeout(800); await p.screenshot({ path: process.env.SHOT, fullPage: true }); }
    await p.close();
    ok(fs.readFileSync(path.join(DASH, 'vendor/zyb-nav.js'), 'utf8').includes('"h": "hyperv-optimize.html"') && / hyperv-optimize\.html( |$)/m.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')), 'menu entry and installer');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); }
  console.log((bad ? 'FAILED ' : 'ok ') + (n - bad) + '/' + n + ' hyperv-optimize checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
