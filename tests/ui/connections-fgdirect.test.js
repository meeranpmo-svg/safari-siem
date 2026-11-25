// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Connections & Setup: the standalone FortiGate card - Add sends the DDNS name, port, pinned fingerprint and the key (masked) to
// PUT /api/soc/fortimanager/direct/<name> and polls; the row shows the host and that the certificate is pinned; the key is not
// on the page; Edit keeps the stored key when left empty; Delete removes it. Stub SIEM; names and keys SYNTHETIC.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node connections-fgdirect.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
let DEV = []; const posts = [];
(async () => {
  const srv = http.createServer((req, res) => {
    const u = decodeURIComponent(req.url.split('?')[0]); const json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    const body = (fn) => { let b = ''; req.on('data', (d) => { b += d; }); req.on('end', () => { const j = b ? JSON.parse(b) : null; posts.push([req.method, u, j]); fn(j); }); };
    if (u === '/dashboards/whoami.json') return json(200, { user: 'admin.syn', role: 'admin' });
    if (u === '/api/soc/fortimanager/direct') return json(200, { devices: DEV });
    const m = u.match(/^\/api\/soc\/fortimanager\/direct\/([^/]+)(\/remove)?$/);
    if (m) return body((b) => { if (m[2]) DEV = DEV.filter((x) => x.name !== m[1]); else { DEV = DEV.filter((x) => x.name !== m[1]).concat(Object.assign({ name: m[1], api_key_set: true, enabled: true }, b, { api_key: undefined })); } json(200, { devices: DEV }); });
    if (u === '/api/soc/fortimanager/poll') return body(() => json(200, { devices: DEV.length, last_error: '' }));
    if (u.startsWith('/api/')) return json(404, { error: 'not in this test' });
    fs.readFile(path.join(DASH, u.replace(/^\/dashboards\//, '/')), (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.endsWith('.js') ? 'application/javascript' : u.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(); const page = await browser.newPage({ viewport: { width: 1400, height: 900 } }); const errs = [];
  page.on('pageerror', (x) => errs.push(x.message + ' @ ' + String(x.stack).split('\n').slice(1, 3).join(' '))); page.on('dialog', (d) => d.accept());
  const toast = () => page.waitForSelector('.toast-zyb', { timeout: 8000 }).then(() => page.$$eval('.toast-zyb', (x) => x.map((t) => t.textContent).join(' | ')));
  await page.goto('http://127.0.0.1:' + srv.address().port + '/connections.html?standalone=1');
  await page.waitForSelector('#cn-fgdirect');
  await page.click('#cn-fgdirect [data-act=add]'); await page.waitForSelector('#mf input[name=host]');
  ok(await page.$eval('#mf input[name=api_key]', (x) => x.type) === 'password', 'the key is masked');
  const FPX = Array.from({ length: 32 }, () => 'AB').join(':');
  await page.fill('#mf input[name=name]', 'FGT-SITE-12'); await page.fill('#mf input[name=host]', 'site12.ddns.example'); await page.fill('#mf input[name=port]', '10443');
  await page.fill('#mf input[name=tls_fingerprint]', FPX); await page.fill('#mf input[name=api_key]', 'fg-key-syn'); await page.click('#msave');
  ok(/Saved - polled 1/.test(await toast()), 'saved and polled');
  const put = posts.find((x) => x[0] === 'PUT'); ok(put && put[1].endsWith('/FGT-SITE-12') && put[2].host === 'site12.ddns.example' && put[2].port === 10443 && put[2].tls_fingerprint === FPX && put[2].api_key === 'fg-key-syn', 'body: ' + JSON.stringify(put && Object.assign({}, put[2], { api_key: '***' })));
  await page.waitForFunction(() => /site12\.ddns\.example:10443/.test(document.querySelector('#cn-fgdirect').innerText), null, { timeout: 8000 }).catch(async () => console.log('CARD', (await page.textContent('#cn-fgdirect')).replace(/\s+/g, ' ').slice(0, 400)));
  ok(/certificate pinned/.test(await page.textContent('#cn-fgdirect')), 'row says pinned');
  ok(!(await page.content()).includes('fg-key-syn'), 'the key is not on the page');
  await page.waitForTimeout(4800); await page.$$eval('.toast-zyb', (x) => x.forEach((e) => e.remove()));
  await page.click('#cn-fgdirect [data-act=edit]'); await page.waitForSelector('#mf input[name=host]');
  ok(await page.$eval('#mf input[name=api_key]', (x) => x.value) === '' && await page.$eval('#mf input[name=host]', (x) => x.value) === 'site12.ddns.example', 'edit prefilled, key empty');
  await page.click('#msave'); await toast(); const put2 = posts.filter((x) => x[0] === 'PUT').pop(); ok(put2 && !('api_key' in put2[2]), 'empty key not sent');
  await page.$$eval('.toast-zyb', (x) => x.forEach((e) => e.remove()));
  await page.click('#cn-fgdirect [data-act=del]'); ok(/Removed FGT-SITE-12/.test(await toast()), 'removed');
  ok(!errs.length, 'errors: ' + errs.join(' | '));
  await browser.close(); srv.close();
  console.log(bad ? `${bad}/${n} FAILED` : `OK ${n}/${n} checks`); process.exit(bad ? 1 : 0);
})();
