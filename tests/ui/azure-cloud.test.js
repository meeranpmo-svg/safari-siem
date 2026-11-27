// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Azure Cloud Servers page (azure-cloud.html) against the REAL IT Asset Management engine with a fake Azure, SYNTHETIC servers:
// not connected → the administrator chooses the credentials; Refresh reads Azure; tiles, charts, what the AI noticed, the riskiest
// server first with its reasons; filter chips; add servers to the asset register; an operator proposes a change, the proposer sees
// "another administrator approves", a second administrator approves and it is sent; a viewer sees no tags, no actions, no settings;
// hostile text stays text; menu entry and installer.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node azure-cloud.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui'), ITAM = path.resolve(__dirname, '../../backend/itam');
const H = require(path.join(ITAM, 'tests/helpers')), AZ = require(path.join(ITAM, 'tests/azure-fake'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
(async () => {
  const e = await H.startApp({ noAi: true }), calls = [];
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, azureRequest: AZ.fakeAzure(calls) });
  const ADM = { user: 'admin.syn', role: 'admin' };
  const mk = (label, client, secret) => { const x = e.app.discovery.createCredential({ kind: 'azure', label, target: { tenant_id: AZ.TEN, client_id: client, subscriptions: [AZ.SUB] }, secret: { client_secret: secret } }, ADM); return x.credential ? x.credential.id : x.id; };
  const readId = mk('Azure reader <b>(synthetic)</b>', AZ.APP, 'Synthetic-Read-1'), actId = mk('Azure VM operator (synthetic)', AZ.APP2, 'Synthetic-Act-1');
  let WHO = ADM;
  const srv = http.createServer((req, res) => { const u = new URL(req.url, 'http://x');
    if (u.pathname === '/dashboards/whoami.json') { res.writeHead(200, { 'Content-Type': 'application/json' }); return res.end(JSON.stringify(WHO)); }
    if (u.pathname.startsWith('/api/itam/')) { const h = Object.assign({}, req.headers, { 'x-sentra-proxy-secret': H.SECRET, 'x-auth-user': WHO.user, 'x-auth-role': WHO.role });
      const up = http.request({ host: '127.0.0.1', port: e.port, method: req.method, path: req.url, headers: h }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); }); req.pipe(up); return; }
    if (u.pathname.startsWith('/api/')) { res.writeHead(404, { 'Content-Type': 'application/json' }); return res.end('{}'); }
    fs.readFile(path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')), (err, d) => { if (err) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); }); });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const url = 'http://127.0.0.1:' + srv.address().port + '/dashboards/azure-cloud.html?standalone=1';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch(), errs = [];
  let PROMPT = 'synthetic reason';
  const open = async (sel) => { const p = await browser.newPage({ viewport: { width: 1500, height: 1100 } }); p.on('pageerror', (x) => errs.push(x.message)); p.on('dialog', (d) => d.accept(d.type() === 'prompt' ? PROMPT : undefined)); await p.goto(url); await p.waitForSelector(sel, { timeout: 15000 }); return p; };
  try {
    let p = await open('#conn:not([hidden])');
    ok(/Connect Azure/.test(await p.textContent('#conn')) && !(await p.$eval('#setc', (x) => x.hidden)), 'not connected: the administrator sees the settings');
    ok(!(await p.$('#set b:has-text("(synthetic)")')) && /<b>\(synthetic\)<\/b>/.test(await p.textContent('#set select')), 'hostile text stays text');
    await p.selectOption('#sf [name=credential_id]', readId); await p.selectOption('#sf [name=action_credential_id]', actId); await p.click('#sf button[type=submit]');
    await p.waitForSelector('#rf:not([hidden])'); await p.click('#rf'); await p.waitForSelector('#main:not([hidden])', { timeout: 15000 });
    const kp = (await p.$eval('#kp', (x) => x.innerText)).replace(/\s+/g, ' ');
    ok(/Servers 3/.test(kp) && /Exposed to the internet 1/.test(kp) && /Secure score 70%/.test(kp) && /Advisor savings 413 USD/.test(kp), 'tiles: ' + kp);
    ok((await p.$$('.g3 canvas')).length === 3, 'three charts');
    ok(/management port/.test(await p.textContent('#ins')) && /stopped but still billed/.test(await p.textContent('#ins')), 'what the AI noticed');
    const first = (await p.$eval('#vms tbody tr', (x) => x.innerText)).replace(/\s+/g, ' ');
    ok(/web-syn/.test(first) && /RDP open to the internet/.test(first) && /3 critical/.test(first) && /owner a\.syn/.test(first), 'the riskiest first with its reasons: ' + first);
    await p.click('[data-f="billed"]'); ok((await p.$$('#vms tbody tr')).length === 1 && /app-syn/.test(await p.textContent('#vms')), 'filter: stopped, billed');
    await p.click('[data-f="all"]'); await p.check('[data-reg$="/web-syn"]'); await p.click('#reg');
    await p.waitForFunction(() => document.querySelectorAll('[data-reg]').length === 2, null, { timeout: 8000 });
    const as = e.app.store.collection('assets').all().find((a) => a.name === 'web-syn'); ok(as && as.site === 'Azure uaenorth', 'added to the asset register');
    // admin.syn proposes: cannot approve their own
    PROMPT = 'patch night (synthetic)'; await p.selectOption('[data-act$="/web-syn"]', 'restart');
    await p.waitForFunction(() => /pending/.test(document.getElementById('acts').textContent), null, { timeout: 8000 });
    ok(/another administrator approves/.test(await p.textContent('#acts')) && !(await p.$('[data-dec]')), 'the proposer cannot approve');
    await p.close();
    WHO = { user: 'admin2.syn', role: 'admin' }; p = await open('#acts table'); PROMPT = 'ok (synthetic)';
    await p.click('[data-dec="approve"]'); await p.waitForFunction(() => /sent/.test(document.getElementById('acts').textContent), null, { timeout: 8000 });
    ok(/admin2\.syn/.test(await p.textContent('#acts')) && calls.some((c) => /web-syn\/restart\?/.test(c.url)), 'a second administrator approves: sent to Azure');
    await p.close();
    WHO = { user: 'vera.syn', role: 'viewer' }; p = await open('#main:not([hidden])');
    ok(await p.$eval('#setc', (x) => x.hidden) && !(await p.$('[data-act]')) && !(await p.$('[data-reg]')) && !/owner a\.syn/.test(await p.textContent('#vms')) && await p.$eval('#rf', (x) => x.hidden), 'a viewer: no settings, actions, tags or refresh');
    await p.close();
    ok(fs.readFileSync(path.join(DASH, 'vendor/zyb-nav.js'), 'utf8').includes('"h": "azure-cloud.html"') && / azure-cloud\.html /.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')), 'menu entry and installer');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); await e.close(); }
  console.log((bad ? 'FAILED ' : 'ok ') + (n - bad) + '/' + n + ' azure-cloud checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
