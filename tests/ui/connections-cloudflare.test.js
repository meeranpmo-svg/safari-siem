// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Connections & Setup: the Cloudflare card (the SIEM's pull collector had no screen - it was set only in the server's files).
// With nothing configured it offers Add; Add sends the domain names (the SIEM looks them up to zone IDs), the account and the
// API token to PUT /api/soc/cloud/cloudflare and runs the step-by-step diagnosis at once; the result names the first failing
// step and its fix; the row shows zones, polls and the last error; Edit keeps the stored token when left empty; Test reruns the
// diagnosis. Stub SIEM; names and tokens are SYNTHETIC.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node connections-cloudflare.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const ZONE = 'b'.repeat(32);
let CF = { enabled: false, account_id: '', zones: [], poll_s: 300, token_set: false, status: { enabled: false } }, DIAG_FAIL = true;
const posts = [];
(async () => {
  const srv = http.createServer((req, res) => {
    const u = req.url.split('?')[0]; const json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    const body = (fn) => { let b = ''; req.on('data', (d) => { b += d; }); req.on('end', () => { const j = b ? JSON.parse(b) : null; posts.push([req.method, u, j]); fn(j); }); };
    if (u === '/dashboards/whoami.json') return json(200, { user: 'syed', role: 'admin' });
    if (u === '/api/soc/cloud/cloudflare' && req.method === 'GET') return json(200, CF);
    if (u === '/api/soc/cloud/cloudflare' && req.method === 'PUT') return body((b) => {
      if ('zones' in b) CF.zones = String(b.zones).split(/[\s,]+/).filter(Boolean).map((z) => (z === 'corp-syn.com' ? ZONE : z));
      if ('account_id' in b) CF.account_id = b.account_id; if (b.api_token) CF.token_set = true; CF.enabled = b.enabled;
      CF.status = { enabled: CF.enabled, polls: 2, records: 40, last_poll_at: '2026-10-29T08:00:00Z' }; json(200, Object.assign({ applied: true }, CF)); });
    if (u === '/api/soc/cloud/cloudflare/diagnose') return body(() => json(200, DIAG_FAIL
      ? { ok: false, steps: [{ step: 'Settings', status: 'ok', detail: 'enabled, 1 zone(s)', fix: '' }, { step: 'Outbound HTTPS to api.cloudflare.com', status: 'fail', detail: 'no connection to api.cloudflare.com:443 <img src=x onerror=alert(1)>', fix: 'Allow outbound HTTPS from the SIEM server to api.cloudflare.com:443' }] }
      : { ok: true, steps: [{ step: 'Settings', status: 'ok', detail: '', fix: '' }, { step: 'Zones', status: 'ok', detail: 'corp-syn.com', fix: '' }] }));
    if (u.startsWith('/api/')) return json(404, { error: 'not in this test' });
    fs.readFile(path.join(DASH, u.replace(/^\/dashboards\//, '/')), (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.endsWith('.js') ? 'application/javascript' : u.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(); const page = await browser.newPage({ viewport: { width: 1400, height: 900 } }); const errs = [];
  page.on('pageerror', (x) => errs.push(x.message));
  const toast = () => page.waitForSelector('.toast-zyb', { timeout: 8000 }).then(() => page.$$eval('.toast-zyb', (x) => x.map((t) => t.textContent).join(' | ')));
  await page.goto('http://127.0.0.1:' + srv.address().port + '/connections.html?standalone=1');
  await page.waitForSelector('#cn-cloudflare');
  const card = () => page.$eval('#cn-cloudflare', (x) => x.innerText.replace(/\s+/g, ' '));
  ok(/Cloudflare/.test(await card()) && /No connection yet/.test(await card()), 'card offered, nothing configured');
  await page.click('#cn-cloudflare [data-act=add]'); await page.waitForSelector('#mf input[name=zones]');
  ok(await page.$eval('#mf input[name=api_token]', (x) => x.type) === 'password', 'the token field is masked');
  ok(/Not the Global API Key/.test(await page.textContent('#mf')), 'the form says which key to use');
  await page.fill('#mf input[name=zones]', 'corp-syn.com'); await page.fill('#mf input[name=api_token]', 'syn-token-123'); await page.fill('#mf input[name=account_id]', 'a'.repeat(32));
  await page.click('#msave');
  const t1 = await toast();
  const put = posts.find((x) => x[0] === 'PUT'); ok(put && put[2].zones === 'corp-syn.com' && put[2].api_token === 'syn-token-123' && put[2].enabled === true, 'domain names and the token sent: ' + JSON.stringify(put && put[2]));
  ok(posts.some((x) => x[1] === '/api/soc/cloud/cloudflare/diagnose'), 'diagnosed right after saving');
  ok(/Stopped at "Outbound HTTPS to api\.cloudflare\.com"/.test(t1) && /Fix: Allow outbound HTTPS/.test(t1), 'the first failing step and its fix: ' + t1);
  ok(!(await page.$('img[src="x"]')), 'hostile text stays text');
  await page.waitForFunction(() => /1 zone\(s\)/.test(document.querySelector('#cn-cloudflare').innerText));
  const row = await card(); ok(/account audit log/.test(row) && /2 poll\(s\), 40 record\(s\)/.test(row), 'row: ' + row.slice(0, 300));
  ok(!(await page.content()).includes('syn-token-123'), 'the token is not on the page');
  // edit: an empty token keeps the stored one; the fix applied, the diagnosis passes
  DIAG_FAIL = false; await page.waitForTimeout(4800);
  await page.click('#cn-cloudflare [data-act=edit]'); await page.waitForSelector('#mf input[name=zones]');
  ok(await page.$eval('#mf input[name=zones]', (x) => x.value) === ZONE && await page.$eval('#mf input[name=api_token]', (x) => x.value) === '', 'edit prefilled, token empty');
  await page.click('#msave'); const t2 = await toast();
  const put2 = posts.filter((x) => x[0] === 'PUT').pop(); ok(put2 && !('api_token' in put2[2]), 'empty token not sent');
  ok(/All 2 checks passed/.test(t2), 'passes after the fix: ' + t2);
  ok(!errs.length, 'errors: ' + errs.join(' | '));
  await browser.close(); srv.close();
  console.log(bad ? `${bad}/${n} FAILED` : `OK ${n}/${n} checks`); process.exit(bad ? 1 : 0);
})();
