// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('../../brand/index');
// Connections & Setup: the Libraesva ESG card. With nothing configured it offers Add; Add posts the address, API user,
// password and the ESG user to act as to /api/itam/esg/config and tests at once; the row then shows the connection
// (catalogue, mapping, password set, last test); Edit keeps the stored password when the field is left empty; Test and
// Remove call the engine. Stub IT Asset Management; names and passwords are SYNTHETIC.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node connections-esg.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
let ESG = { configured: false, endpoints: {}, catalogue: [], password_set: false, last_test: null };
const posts = [];
const SRC = [{ id: 'esg-hq', kind: 'email-security-gateway', type: 'libraesva', label: 'Libraesva HQ', match_ip: '10.20.5.25', state: 'receiving', last_seen: Date.now() - 60000, events_24h: 1200, created_at: '2026-10-01T00:00:00Z' },
  { id: 'pp-1', kind: 'email-security-gateway', type: 'proofpoint', label: 'Proofpoint', state: 'receiving' }, { id: 'fw-1', kind: 'fortigate', type: 'fortigate', label: 'FW' }];
let alertText = '';
(async () => {
  const srv = http.createServer((req, res) => {
    const u = req.url.split('?')[0]; const json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    const body = (fn) => { let b = ''; req.on('data', (d) => { b += d; }); req.on('end', () => { const j = b ? JSON.parse(b) : null; posts.push([req.method, u, j]); fn(j); }); };
    if (u === '/dashboards/whoami.json') return json(200, { user: 'syed', role: 'admin' });
    if (u === '/api/itam/esg' && req.method === 'GET') return json(200, ESG);
    if (u === '/api/itam/esg/config' && req.method === 'POST') return body((b) => { ESG = Object.assign({}, ESG, { configured: true, base_url: b.base_url, username: b.username, switch_user: b.switch_user || null, password_set: true }); json(200, ESG); });
    if (u === '/api/itam/esg/config' && req.method === 'DELETE') return body(() => { ESG = { configured: false, endpoints: {}, catalogue: [], password_set: false, last_test: null }; json(200, ESG); });
    if (u === '/api/itam/esg/test') return body(() => { ESG.last_test = { at: Date.now(), ok: true }; ESG.catalogue = [1, 2, 3, 4, 5]; json(200, ESG); });
    if (u === '/api/soc/onboard/sources' && req.method === 'GET') return json(200, { sources: SRC });
    if (u === '/api/soc/onboard/sources' && req.method === 'POST') return body((b) => { SRC.push(Object.assign({ type: 'libraesva', state: 'waiting', created_at: new Date().toISOString() }, b)); json(200, { source: b, siem: { ip: ZYB_ORG.platform_addr, host: ZYB_ORG.portal_host, syslog_port: 5514, tls_port: 6514 } }); });
    if (u.startsWith('/api/')) return json(404, { error: 'not in this test' });
    fs.readFile(path.join(DASH, u.replace(/^\/dashboards\//, '/')), (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.endsWith('.js') ? 'application/javascript' : u.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(); const page = await browser.newPage({ viewport: { width: 1400, height: 900 } }); const errs = [];
  page.on('pageerror', (x) => errs.push(x.message)); page.on('dialog', (d) => { if (d.type() === 'alert') alertText = d.message(); d.accept(); });
  await page.goto('http://127.0.0.1:' + srv.address().port + '/connections.html?standalone=1');
  await page.waitForSelector('#cn-esg');
  const card = () => page.$eval('#cn-esg', (x) => x.innerText.replace(/\s+/g, ' '));
  ok(/Libraesva Email Security Gateway/.test(await card()) && /No connection yet/.test(await card()), 'card offered, nothing configured');
  ok(await page.$('#cn-esg a[href="libraesva.html"]'), 'links to the Libraesva page to manage it');
  await page.click('#cn-esg [data-act=add]'); await page.waitForSelector('#mf input[name=base_url]');
  ok(await page.$eval('#mf input[name=password]', (x) => x.type) === 'password', 'password field is masked');
  await page.fill('#mf input[name=base_url]', 'https://esg-syn.corpgroup.test'); await page.fill('#mf input[name=username]', 'zyb-api');
  await page.fill('#mf input[name=password]', 'Synthetic-Pass1'); await page.fill('#mf input[name=switch_user]', 'readonly@corpgroup.test');
  await page.click('#msave');
  await page.waitForFunction(() => /esg-syn\.corpgroup\.test/.test(document.querySelector('#cn-esg').innerText));
  const p1 = posts.find((x) => x[1] === '/api/itam/esg/config' && x[0] === 'POST');
  ok(p1 && p1[2].base_url === 'https://esg-syn.corpgroup.test' && p1[2].password === 'Synthetic-Pass1' && p1[2].switch_user === 'readonly@corpgroup.test', 'config posted');
  ok(posts.some((x) => x[1] === '/api/itam/esg/test'), 'tested right after saving');
  const t = await card(); ok(/acting as readonly@corpgroup\.test/.test(t) && /5 endpoints in the catalogue/.test(t) && /0 of 4 mapped/.test(t) && /1\/1 connected/.test(t), 'row: ' + t.slice(0, 300));
  ok(!(await page.content()).includes('Synthetic-Pass1'), 'the password is not on the page');
  // edit: an empty password keeps the stored one
  await page.click('#cn-esg [data-act=edit]'); await page.waitForSelector('#mf input[name=base_url]');
  ok(await page.$eval('#mf input[name=username]', (x) => x.value) === 'zyb-api' && await page.$eval('#mf input[name=password]', (x) => x.value) === '', 'edit prefilled, password empty');
  await page.fill('#mf input[name=switch_user]', 'ro2@corpgroup.test'); await page.click('#msave');
  await page.waitForFunction(() => /acting as ro2@corpgroup\.test/.test(document.querySelector('#cn-esg').innerText));
  const p2 = posts.filter((x) => x[1] === '/api/itam/esg/config' && x[0] === 'POST').pop(); ok(p2 && !('password' in p2[2]), 'empty password not sent (the stored one is kept)');
  // remove
  await page.click('#cn-esg [data-act=del]');
  await page.waitForFunction(() => /No connection yet/.test(document.querySelector('#cn-esg').innerText));
  ok(posts.some((x) => x[0] === 'DELETE' && x[1] === '/api/itam/esg/config'), 'removed through the engine');
  // the mail log by syslog: registered senders, receiving / waiting, add gives the SIEM address
  await page.waitForSelector('#cn-esglog table');
  const lg = await page.$eval('#cn-esglog', (x) => x.innerText.replace(/\s+/g, ' '));
  ok(/Libraesva HQ/.test(lg) && /sender 10\.20\.5\.25/.test(lg) && /1200 messages in 24 h/.test(lg) && !/Proofpoint|FW/.test(lg) && /not needed \(syslog\)/.test(lg), 'syslog card: Libraesva senders only: ' + lg.slice(0, 300));
  await page.click('#cn-esglog [data-act=add]'); await page.waitForSelector('#mf input[name=match_ip]');
  await page.fill('#mf input[name=id]', 'node2'); await page.fill('#mf input[name=match_ip]', '10.20.5.26'); await page.click('#msave');
  await page.waitForFunction(() => /waiting for the first log line/.test(document.querySelector('#cn-esglog').innerText));
  const sp = posts.find((x) => x[1] === '/api/soc/onboard/sources'); ok(sp && sp[2].id === 'esg-node2' && sp[2].kind === 'email-security-gateway' && sp[2].match_ip === '10.20.5.26', 'sender registered: ' + JSON.stringify(sp && sp[2]));
  await page.waitForTimeout(300);
  ok(new RegExp('Host: ' + ZYB_ORG.platform_addr_re).test(alertText) && /Port: 5514/.test(alertText) && new RegExp(ZYB_ORG.portal_host_re + ' : 6514').test(alertText) && /Log settings/.test(alertText), 'gateway settings shown: ' + alertText);
  ok(!errs.length, 'errors: ' + errs.join(' | '));
  await browser.close(); srv.close();
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
