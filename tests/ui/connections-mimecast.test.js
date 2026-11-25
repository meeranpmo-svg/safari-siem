// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Connections & Setup: the Mimecast card (API 2.0 pull collector). With nothing configured it offers Add; Add sends the client
// ID / secret, region and log types to PUT /api/soc/cloud/mimecast and runs the sign-in test at once; a failing step is shown
// as text (hostile text stays text); the row shows types, polls and the last error; Edit keeps the stored secret when left
// empty; Sync polls now. Stub SIEM; tenant, IDs and secrets are SYNTHETIC.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node connections-mimecast.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const KNOWN = ['receipt', 'process', 'delivery', 'av', 'spam', 'impersonation protect', 'url protect', 'attachment protect', 'internal email protect', 'journal'];
let MC = { enabled: false, base_url: 'https://api.services.mimecast.com', types: KNOWN, poll_min: 15, client_id_set: false, client_secret_set: false, known_types: KNOWN, status: { enabled: false, error: 'off' } }, TEST_FAIL = true;
const posts = [];
(async () => {
  const srv = http.createServer((req, res) => {
    const u = req.url.split('?')[0]; const json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    const body = (fn) => { let b = ''; req.on('data', (d) => { b += d; }); req.on('end', () => { const j = b ? JSON.parse(b) : null; posts.push([req.method, u, j]); fn(j); }); };
    if (u === '/dashboards/whoami.json') return json(200, { user: 'admin.syn', role: 'admin' });
    if (u === '/api/soc/cloud/mimecast' && req.method === 'GET') return json(200, MC);
    if (u === '/api/soc/cloud/mimecast' && req.method === 'PUT') return body((b) => {
      if (b.client_id) MC.client_id_set = true; if (b.client_secret) MC.client_secret_set = true; if (b.types) MC.types = b.types; if (b.base_url) MC.base_url = b.base_url; if (b.poll_min) MC.poll_min = b.poll_min; MC.enabled = b.enabled;
      MC.status = { enabled: MC.enabled, polls: 3, records: 120, last_poll_at: '2026-11-25T08:00:00Z', last_error: '' }; json(200, Object.assign({ applied: true }, MC)); });
    if (u === '/api/soc/cloud/mimecast/test') return body(() => json(200, TEST_FAIL
      ? { ok: false, steps: [{ ok: false, text: 'Mimecast refused the client ID / secret <img src=x onerror=alert(1)>' }] }
      : { ok: true, steps: [{ ok: true, text: 'signed in to api.services.mimecast.com' }, { ok: true, text: 'SIEM batch readable for "receipt"' }] }));
    if (u === '/api/soc/cloud/mimecast/sync') return body(() => json(200, { polls: 4, records: 150, last_error: '' }));
    if (u.startsWith('/api/')) return json(404, { error: 'not in this test' });
    fs.readFile(path.join(DASH, u.replace(/^\/dashboards\//, '/')), (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.endsWith('.js') ? 'application/javascript' : u.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(); const page = await browser.newPage({ viewport: { width: 1400, height: 900 } }); const errs = [];
  page.on('pageerror', (x) => errs.push(x.message));
  const toast = async () => { await page.waitForSelector('.toast-zyb', { timeout: 8000 }); const t = await page.$$eval('.toast-zyb', (x) => x.map((e) => e.textContent).join(' | ')); await page.$$eval('.toast-zyb', (x) => x.forEach((e) => e.remove())); return t; };
  await page.goto('http://127.0.0.1:' + srv.address().port + '/connections.html?standalone=1');
  await page.waitForSelector('#cn-mimecast');
  const card = () => page.$eval('#cn-mimecast', (x) => x.innerText.replace(/\s+/g, ' '));
  ok(/Mimecast/.test(await card()) && /No connection yet/.test(await card()), 'card offered, nothing configured: ' + (await card()).slice(0, 200));
  await page.click('#cn-mimecast [data-act=add]'); await page.waitForSelector('#mf input[name=client_id]');
  ok(await page.$eval('#mf input[name=client_secret]', (x) => x.type) === 'password', 'the secret field is masked');
  ok(await page.$eval('#mf input[name=base_url]', (x) => x.value) === 'https://api.services.mimecast.com', 'region prefilled with the global gateway');
  ok(/Read-only/.test(await page.textContent('#mbox, #mf').catch(() => '')) || /Read-only/.test(await page.content()), 'the form says it is read-only');
  await page.fill('#mf input[name=client_id]', 'cid-syn'); await page.fill('#mf input[name=client_secret]', 'mc-secret-syn');
  await page.fill('#mf input[name=types]', 'receipt, av , url protect');
  await page.click('#msave');
  const t1 = await toast();
  const put = posts.find((x) => x[0] === 'PUT');
  ok(put && put[2].client_id === 'cid-syn' && put[2].client_secret === 'mc-secret-syn' && put[2].enabled === true && JSON.stringify(put[2].types) === '["receipt","av","url protect"]' && put[2].poll_min === 15, 'settings sent: ' + JSON.stringify(put && Object.assign({}, put[2], { client_secret: '***' })));
  ok(posts.some((x) => x[1] === '/api/soc/cloud/mimecast/test'), 'tested right after saving');
  ok(/Stopped: Mimecast refused the client ID/.test(t1), 'the failing step is shown: ' + t1);
  ok(!(await page.$('img[src="x"]')), 'hostile text stays text');
  await page.waitForFunction(() => /3 log type\(s\)/.test(document.querySelector('#cn-mimecast').innerText));
  const row = await card(); ok(/api\.services\.mimecast\.com/.test(row) && /3 poll\(s\), 120 record\(s\)/.test(row) && /every 15 min/.test(row), 'row: ' + row.slice(0, 300));
  ok(!(await page.content()).includes('mc-secret-syn'), 'the secret is not on the page');
  // edit: empty ID / secret keep the stored ones; the test passes
  TEST_FAIL = false;
  await page.click('#cn-mimecast [data-act=edit]'); await page.waitForSelector('#mf input[name=client_id]');
  ok(await page.$eval('#mf input[name=types]', (x) => x.value) === 'receipt, av, url protect' && await page.$eval('#mf input[name=client_secret]', (x) => x.value) === '', 'edit prefilled, secret empty');
  await page.click('#msave'); const t2 = await toast();
  const put2 = posts.filter((x) => x[0] === 'PUT').pop(); ok(put2 && !('client_secret' in put2[2]) && !('client_id' in put2[2]), 'empty ID / secret not sent');
  ok(/All 2 checks passed/.test(t2), 'passes: ' + t2);
  ok(!errs.length, 'errors: ' + errs.join(' | '));
  await browser.close(); srv.close();
  console.log(bad ? `${bad}/${n} FAILED` : `OK ${n}/${n} checks`); process.exit(bad ? 1 : 0);
})();
