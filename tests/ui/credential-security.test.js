// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for dashboards/server/credential-security.html against the real engines: IT Asset Management (the
// /security/credentials route on a live app) and the SIEM's engine/soc/credposture.js over a sealed secrets.json.
// Checks the CISO statement says what the data says (and changes when a credential is in clear), the findings, the
// self-test, the disk scan button (admin only), saving the report to the GRC evidence library with its SHA-256, the
// viewer / operator gates, Excel, and that no secret value reaches the page.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node credential-security.test.js
const http = require('http'), fs = require('fs'), os = require('os'), path = require('path'), crypto = require('crypto'), assert = require('assert/strict');
const ITAM = path.resolve(__dirname, '../../backend/itam'), DASH = path.resolve(__dirname, '../../ui');
const SIEM = process.env.SENTRA_SIEM_DIR || path.resolve(__dirname, '../../backend/siem');
const H = require(path.join(ITAM, 'tests/helpers.js'));
let WHO = { user: 'syed', role: 'admin' };
const COMM = 'Synthetic-Community-6620', TOKEN = 'synthetic-fgt-token-4471', DBP = 'Synthetic-DbPass-3390';

(async () => {
  // SIEM: a sealed secrets.json with three devices, behind its real route module
  const sd = fs.mkdtempSync(path.join(os.tmpdir(), 'cs-siem-')); fs.mkdirSync(path.join(sd, 'keys'), { mode: 0o750 }); fs.mkdirSync(path.join(sd, 'state'));
  process.env.SENTRA_SIEM_SECRETS_KEY = path.join(sd, 'keys', 'secrets.key');
  fs.writeFileSync(process.env.SENTRA_SIEM_SECRETS_KEY, crypto.randomBytes(32).toString('hex') + '\n', { mode: 0o440 });
  const SF = require(path.join(SIEM, 'engine/secretfile.js'));
  SF.write(path.join(sd, 'secrets.json'), { clickhouse: { password: 'Synthetic-CH-1' }, netops: { devices: { 'FGT-HQ': { api: { token: TOKEN, tls: { fingerprint256: 'CD'.repeat(32) } } }, 'SW-BR1': { snmp: { version: '2c', community: COMM } } } } });
  const sroutes = {};
  require(path.join(SIEM, 'engine/soc/credposture.js')).register({ route: (m, p, fn) => { sroutes[m + ' ' + p] = fn; } },
    { config: { _paths: { secrets: path.join(sd, 'secrets.json') }, state_dir: path.join(sd, 'state'), data_dir: sd, syslog: { tls: { enabled: true } }, clickhouse: { url: 'http://127.0.0.1:8123' } }, log: { error() {} } });
  // ITAM
  const e = await H.startApp({ noAi: true });
  const secFile = path.join(e.dir, 'secrets.json'); fs.writeFileSync(secFile, JSON.stringify({ proxy_secret: 'x'.repeat(32), anthropic_api_key: 'sk-ant-synthetic-1' }), { mode: 0o640 });
  process.env.SENTRA_ITAM_SECRETS = secFile;
  require(path.join(ITAM, 'engine/grc')).registerGrc(e.app.srv, e.app);
  require(path.join(ITAM, 'engine/cred-posture')).registerCredPosture(e.app.srv, e.app);
  const adm = (m, p, body) => e.req(m, p, { body, user: 'syed', role: 'admin' });
  await adm('POST', '/discovery/credentials', { kind: 'snmp_v3', label: 'Core v3', target: { auth_protocol: 'sha256', priv_protocol: 'aes' }, secret: { user: 'itam', auth_password: 'Synthetic-Auth-1', priv_password: 'Synthetic-Priv-1' } });
  await adm('POST', '/discovery/credentials', { kind: 'db_login', label: 'Oracle ERP', target: { engine: 'oracle', service: 'ERP' }, secret: { username: 'mon', password: DBP } });

  const RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 };
  const srv = http.createServer((req, res) => {
    const u = req.url.split('?')[0];
    if (u === '/dashboards/whoami.json') { res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(WHO)); return; }
    // the shared page scripts ask for the identity, the organisation's modules and the licence: answered in their shape
    const stub = { '/auth/whoami': WHO, '/auth/org': { modules: null }, '/api/itam/licence': { enforcement: { enforced: true, ok: true, gate: 'ok' } } }[u];
    if (stub) { res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(stub)); return; }
    if (u.startsWith('/api/itam/')) {
      const h = Object.assign({}, req.headers, { 'x-sentra-proxy-secret': H.SECRET, 'x-auth-user': WHO.user, 'x-auth-role': WHO.role });
      const up = http.request({ host: '127.0.0.1', port: e.port, method: req.method, path: req.url, headers: h }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); });
      req.pipe(up); return;
    }
    if (u.startsWith('/api/soc/')) {
      const fn = sroutes[req.method + ' ' + u]; let out = null; req.resume();
      if (!fn) { res.writeHead(404); res.end('{}'); return; }
      const ctx = { query: {}, role: WHO.role, user: WHO.user, path: u, need: (r) => { if (RANK[WHO.role] < RANK[r]) { out = [403, { error: 'requires ' + r }]; return false; } return true; }, ok: (b) => { out = [200, b]; }, fail: (s, m) => { out = [s, { error: m }]; }, audit: () => {} };
      Promise.resolve(fn(ctx)).then(() => { res.writeHead(out[0], { 'Content-Type': 'application/json' }); res.end(JSON.stringify(out[1])); });
      return;
    }
    if (u === '/') { res.writeHead(200); res.end('home'); return; }
    fs.readFile(path.join(DASH, u), (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.endsWith('.js') ? 'application/javascript' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/credential-security.html';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch();
  const page = await browser.newPage({ acceptDownloads: true }); const errs = [];
  page.on('pageerror', (x) => errs.push(x.message)); page.on('console', (m) => { if (m.type() === 'error') errs.push(m.text()); });
  let n = 0; const ok = (c, m) => { assert.ok(c, m); n++; };
  const open = async () => { await page.goto('about:blank'); await page.goto(base); await page.waitForFunction(() => !/Loading/.test(document.getElementById('stmt').innerText), null, { timeout: 15000 }); };

  // secrets.json still has the Claude key in clear: the statement must say so
  await open();
  let st = await page.innerText('#stmt');
  ok(/stored in clear/.test(st), 'statement names values in clear: ' + st);
  ok(/encryption self-test passed/i.test(st), 'self-test passed');
  ok(/not encrypted in transit/.test(st), 'SNMPv2c / Oracle without TLS called out');
  const find = await page.innerText('#find');
  ok(/secrets\.json/.test(find) && /SNMPv1\/v2c: SW-BR1/.test(find) && /Oracle ERP/.test(find), 'findings from both engines: ' + find.slice(0, 300));
  ok(/SAMA CSF 3\.3\.9/.test(find), 'controls named');
  // seal, re-read: now "All N stored credentials … encrypted"
  require(path.join(ITAM, 'engine/secret-values')).sealFile(secFile, e.app.config.discovery.vault_key_file);
  await open(); st = await page.innerText('#stmt');
  ok(/All \d+ stored credentials/.test(st) && /AES-256-GCM/.test(st), 'all encrypted: ' + st);
  ok(/readable by design/.test(st), 'proxy secret explained');
  ok((await page.$$('#engines .card')).length === 2, 'both engine cards');
  // disk scan (admin)
  ok(await page.isVisible('#scan'), 'admin sees scan');
  await page.click('#scan');
  await page.waitForFunction(() => /none found in clear/.test(document.getElementById('stmt').innerText) && (document.getElementById('stmt').innerText.match(/none found in clear/g) || []).length >= 2, null, { timeout: 20000 });
  ok(true, 'scan on both engines, none in clear');
  // save to GRC evidence: a real record with the right control and a hash the server checked
  await page.click('#grc');
  await page.waitForFunction(() => /Saved as EVD-/.test(document.body.innerText), null, { timeout: 15000 });
  const ev = (await adm('GET', '/grc/evidence')).json.items[0];
  ok(ev.framework === 'SAMA CSF' && ev.control === '3.3.9' && ev.file && /^[0-9a-f]{64}$/.test(ev.file.sha256), 'evidence stored: ' + JSON.stringify(ev).slice(0, 200));
  const f = (await adm('GET', '/grc/files/' + encodeURIComponent(ev.file.file_id))).json;
  const doc = JSON.parse(Buffer.from(f.content_b64, 'base64').toString());
  ok(doc.reports.itam && doc.reports.siem && /All \d+ stored credentials/.test(doc.statement), 'the saved file is the full report');
  // Excel
  const [dl] = await Promise.all([page.waitForEvent('download'), page.click('#xlsx')]); ok(/credential-security-/.test(dl.suggestedFilename()), 'excel');
  // no secret value anywhere on the page
  const html = await page.content();
  for (const s of [COMM, TOKEN, DBP, 'sk-ant-synthetic-1', 'Synthetic-Auth-1']) ok(!html.includes(s), 'no ' + s.slice(0, 12) + '… on the page');
  // operator: no scan button, can save; viewer: told why there is nothing
  WHO = { user: 'siva', role: 'operator' }; await open();
  ok(!(await page.isVisible('#scan')) && await page.isVisible('#grc'), 'operator: save yes, scan no');
  WHO = { user: 'guest', role: 'viewer' }; await open();
  ok(/operator or admin/.test(await page.innerText('#stmt')), 'viewer: told the role needed');
  ok(errs.filter((x) => !/403/.test(x)).length === 0, 'errors: ' + errs.join(' | '));
  console.log('OK', n, 'checks');
  await browser.close(); srv.close(); await e.close(); process.exit(0);
})().catch((x) => { console.error('FAIL', x.message, (x.stack || '').split('\n').find((l) => /credential-security\.test/.test(l))); process.exit(1); });
