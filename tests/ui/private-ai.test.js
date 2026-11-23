// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for private-ai.html against the REAL engine (engine/private-ai.js) with a SYNTHETIC AI server (an OpenAI-compatible
// gateway with Ollama's /api/ps, node_exporter and a DCGM exporter): the health ring and the named deductions with their action,
// the KPIs, the four charts, the models served / loaded / in use, a hostile model name stays text, the hardware table and the
// exporters, the features and failed calls, the monitoring settings saved, check now, the four-eyes model switch (proposed by one
// administrator, the proposer cannot decide, approved by another, applied), an operator reads without the admin controls, a
// viewer is told the page is for operators, the AI briefing is labelled a draft, phone width, the menu entry and the installer.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node private-ai.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers')), B = require(path.join(ITAM, 'engine', 'ai-backend'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const NODE = (idle, total) => ['node_cpu_seconds_total{cpu="0",mode="idle"} ' + idle, 'node_cpu_seconds_total{cpu="0",mode="user"} ' + (total - idle), 'node_memory_MemTotal_bytes 64000000000', 'node_memory_MemAvailable_bytes 16000000000',
  'node_filesystem_size_bytes{device="/dev/sda1",fstype="ext4",mountpoint="/"} 1000000000000', 'node_filesystem_avail_bytes{device="/dev/sda1",fstype="ext4",mountpoint="/"} 300000000000', 'node_load1 2.5'].join('\n');
const DCGM = 'DCGM_FI_DEV_GPU_UTIL{gpu="0",modelName="Synthetic GPU 48GB"} 71\nDCGM_FI_DEV_GPU_TEMP{gpu="0"} 90\nDCGM_FI_DEV_POWER_USAGE{gpu="0"} 250\nDCGM_FI_DEV_FB_USED{gpu="0"} 30720\nDCGM_FI_DEV_FB_FREE{gpu="0"} 18432';
(async () => {
  let cpu = [100, 200];
  const fetch = async (url, init) => { const u = new URL(url), r = (s, b) => ({ status: s, text: async () => (typeof b === 'string' ? b : JSON.stringify(b)) });
    if (u.port === '9100') return r(200, NODE(cpu[0], cpu[1])); if (u.port === '9400') return r(200, DCGM);
    if (u.pathname === '/v1/models') return r(200, { data: [{ id: 'synthetic-local-7b' }, { id: 'synthetic-local-14b' }, { id: 'syn<img src=x onerror=window.__px=1>' }] });
    if (u.pathname === '/api/ps') return r(200, { models: [{ name: 'synthetic-local-7b', size: 5e9, size_vram: 4.8e9 }] });
    if (u.pathname === '/v1/chat/completions') { const q = JSON.parse(init.body); if (/FAIL/.test(JSON.stringify(q.messages))) return r(500, { error: 'synthetic overload' });
      return r(200, { id: 'c', model: q.model, choices: [{ index: 0, finish_reason: 'stop', message: { role: 'assistant', content: 'OK' } }], usage: { prompt_tokens: 10, completion_tokens: 40 } }); }
    return r(404, 'not found'); };
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3', aiFetch: fetch, aiLocalKey: () => '' });
  const ADM = { user: 'syed', role: 'admin' }, c = (m, p, b, w) => e.req(m, p, Object.assign({ body: b }, w || ADM));
  await c('PUT', '/ai-engine', { mode: 'local', local: { api: 'openai', base_url: 'http://10.20.0.40:11434/v1', model: 'synthetic-local-7b' } });
  await c('PUT', '/private-ai/config', { metrics_urls: ['http://10.20.0.40:9100/metrics'], version: 0 });
  await c('POST', '/private-ai/poll', {}); cpu = [150, 400]; await c('POST', '/private-ai/poll', {});
  const C = B.wrap(null), client = new C({ apiKey: 'x' }); B.setFeature('itam.synthetic-feature');
  for (let i = 0; i < 3; i++) await client.messages.create({ model: 'any', max_tokens: 50, messages: [{ role: 'user', content: 'synthetic ' + i }] });
  await client.messages.create({ model: 'any', max_tokens: 50, messages: [{ role: 'user', content: 'FAIL' }] }).catch(() => null /* the failed call is what the page shows */);
  let who = ADM;
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (code, b) => { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, who);
    if (u.pathname.startsWith('/api/itam/')) { const h = Object.assign({}, req.headers, { 'x-sentra-proxy-secret': H.SECRET, 'x-auth-user': who.user, 'x-auth-role': who.role });
      const up = http.request({ host: '127.0.0.1', port: e.port, method: req.method, path: req.url, headers: h }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); }); req.pipe(up); return; }
    if (u.pathname.startsWith('/api/') || u.pathname === '/') return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/private-ai.html?standalone=1';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg === undefined ? null : arg, { timeout: 20000 }).then(() => true, () => false);
  const toast = (p, re) => wait(p, (s) => [...document.querySelectorAll('.toast')].some((t) => new RegExp(s).test(t.textContent)), re);
  const T = (p, id) => p.evaluate((i) => document.getElementById(i).textContent, id);
  try {
    const p = await browser.newPage({ viewport: { width: 1440, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto(base);
    ok(await wait(p, () => document.querySelector('#score svg') && /checks in 24 h/.test(document.getElementById('score').textContent)), 'health ring');
    ok(/Not measured/.test(await T(p, 'ded')) || /−/.test(await T(p, 'ded')), 'deductions listed');
    ok(/answering/.test(await T(p, 'kpi')) && /synthetic-local-7b/.test(await T(p, 'kpi')) && /25%/.test(await T(p, 'kpi')), 'KPIs: gateway, model, failed 25 %');
    ok(await p.evaluate(() => ['ch-gw', 'ch-calls', 'ch-host'].every((i) => document.querySelector('#' + i + ' svg.ch'))), 'gateway, calls and server charts');
    ok(/No GPU exporter/.test(await T(p, 'ch-gpu')), 'no GPU exporter: the chart says what to add');
    const m = await T(p, 'models'); ok(/in use/.test(m) && /loaded/.test(m) && /4\.8 GB/.test(m) && /on disk/.test(m), 'models: in use, loaded with VRAM, on disk');
    ok(!(await p.evaluate(() => window.__px)) && /syn<img/.test(m), 'a hostile model name stays text');
    ok(/CPU/.test(await T(p, 'hw')) && /70 %/.test(await T(p, 'hw')) && /needs 24 hours/.test(await T(p, 'hw')), 'hardware: CPU, disk 70 %, forecast waits for history');
    ok(/itam\.synthetic-feature/.test(await T(p, 'feats')) && /424/.test(await T(p, 'outs')), 'features and the failed call');
    // settings: add the GPU exporter
    ok(await p.$eval('#cfgcard', (x) => !x.hidden), 'an admin sees the settings');
    await p.fill('#c-urls', 'http://10.20.0.40:9100/metrics\nhttp://10.20.0.40:9400/metrics'); await p.click('#cfgsave');
    ok(await toast(p, 'Settings saved'), 'settings saved');
    await p.fill('#c-urls', 'http://8.8.8.8:9100/metrics'); await p.click('#cfgsave'); ok(await toast(p, 'public address'), 'a public exporter address is refused, with the reason');
    await p.click('#pollnow'); ok(await toast(p, 'Checked') && await wait(p, () => document.querySelector('#ch-gpu svg.ch') && /Synthetic GPU 48GB/.test(document.getElementById('hw').textContent)), 'check now: the GPU appears');
    ok(await wait(p, () => /GPU is at 90/.test(document.getElementById('ded').textContent) && /cooling/.test(document.getElementById('ded').textContent)), 'the hot GPU is a named deduction with its action');
    // four eyes
    await p.click('[data-propose="synthetic-local-14b"]'); await p.fill('#f-reason', 'Synthetic: better answers on the bench'); await p.click('#dlgok');
    ok(await toast(p, 'waiting for a second administrator') && await wait(p, () => /You proposed it/.test(document.getElementById('changes').textContent)), 'proposed; the proposer cannot decide');
    ok(!(await p.$('[data-decide]')), 'no approve button for the proposer');
    who = { user: 'amal.syn', role: 'admin' }; await p.reload(); await wait(p, () => !!document.querySelector('[data-decide="approve"]'));
    await p.click('[data-decide="approve"]'); await p.click('#dlgok');
    ok(await toast(p, 'now uses synthetic-local-14b') && await wait(p, () => /applied/.test(document.getElementById('changes').textContent)), 'approved by a second administrator and applied');
    ok(B.status().local.model === 'synthetic-local-14b', 'the AI Engine uses the new model');
    ok(e.app.store.auditTail(300).some((a) => a.action === 'private-ai.model-change.approve' && a.by === 'amal.syn'), 'approval audited');
    // the AI briefing (no AI here: labelled box either way)
    await p.click('#aibrief'); ok(await wait(p, () => /AI draft - verify before use|did not answer/.test(document.getElementById('aiout').textContent)), 'the AI briefing answers in a labelled box');
    // operator and viewer
    who = { user: 'nora.syn', role: 'operator' }; await p.reload(); await wait(p, () => !!document.querySelector('#score svg'));
    ok(await p.$eval('#cfgcard', (x) => x.hidden) && !(await p.$('[data-propose]')) && await p.$eval('#pollnow', (x) => x.hidden), 'an operator reads without the admin controls');
    who = { user: 'vera.syn', role: 'viewer' }; await p.reload();
    ok(await wait(p, () => /operators and administrators only/.test(document.getElementById('err').textContent)), 'a viewer is told the page is for operators');
    who = ADM;
    const ph = await browser.newPage({ viewport: { width: 390, height: 900 } }); ph.on('pageerror', (x) => errs.push(x.message)); await ph.goto(base); await wait(ph, () => !!document.querySelector('#models table'));
    ok(await ph.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), 'phone width: no sideways scroll'); await ph.close();
    ok(/"h": "private-ai.html"/.test(fs.readFileSync(path.join(DASH, 'vendor', 'zyb-nav.js'), 'utf8')) && / private-ai\.html /.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')), 'menu entry and installer');
  } finally { await browser.close(); srv.close(); if (e.app.addons.privateAi) e.app.addons.privateAi.stop(); e.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
