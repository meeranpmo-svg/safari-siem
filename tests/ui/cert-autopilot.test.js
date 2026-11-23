// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Certificates -> Renewal autopilot (certificates.html + vendor/zyb-certpilot.js) against the REAL ITAM certificate lifecycle and
// autopilot (engine/certs.js, cert-issue.js, cert-install.js, cert-autopilot.js; Python rules) with SYNTHETIC endpoints: the default
// tab, coverage ring and brief, KPI tiles that filter, the risk-ranked queue with step chips, a row's detail (steps, fixes, risk
// points), bottlenecks, the learned lead-time table, "Start the N due now" (a manual order lands awaiting the certificate), select +
// switch on automatic renewal (a blocked one refused with its reason), search, a hostile label stays text, a viewer reads only.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node cert-autopilot.test.js
const http = require('http'), fs = require('fs'), os = require('os'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
const { createSealer } = require(path.join(ITAM, 'engine', 'discovery', 'vault'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const DAY = 86400000, now = Date.now();
const PRESENT = {};
const cert = (host, days) => ({ ok: true, subject: host, issuer: 'Synthetic Issuing CA', names: [host], name_ok: true, trusted: true, self_signed: false, not_after: now + days * DAY, not_after_iso: new Date(now + days * DAY).toISOString().slice(0, 10), key_type: 'rsa', key_bits: 2048, serial: 'S-' + host, fingerprint256: 'FP:' + host, chain: ['Synthetic Issuing CA'] });
const stubRead = async (host, port) => PRESENT[host + ':' + port] || { ok: false, error: 'ECONNREFUSED' };

(async () => {
  const e = await H.startApp({ noAi: true });
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sentra-capw-'));
  const sealer = createSealer({ keyFile: path.join(tmp, 'vault.key'), createKey: true, purpose: 'sentra-itam-pki' });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3', readCert: stubRead, certSealer: sealer });
  const C = e.app.addons.certs, OPW = { user: 'nora.syn', role: 'operator' };
  PRESENT['portal.synthetic.test:443'] = cert('portal.synthetic.test', 20);
  PRESENT['vpn.synthetic.test:443'] = cert('vpn.synthetic.test', 120);
  PRESENT['mail.synthetic.test:443'] = cert('mail.synthetic.test', 300);
  const P = C.putEndpoint({ host: 'portal.synthetic.test', port: 443, issuer_kind: 'manual', deploy_target: 'linux-nginx', critical: true, owner: 'ali.syn', label: 'Customer portal <img src=x onerror="window.__xss=1">' }, OPW);
  const VPN = C.putEndpoint({ host: 'vpn.synthetic.test', port: 443, issuer_kind: 'adcs', deploy_target: 'paloalto', owner: 'sara.syn' }, OPW);
  const MAIL = C.putEndpoint({ host: 'mail.synthetic.test', port: 443, issuer_kind: 'manual', deploy_target: 'exchange', owner: 'omar.syn' }, OPW);
  await C.scan(null, OPW);
  let WHO = { user: 'nora.syn', role: 'operator' };
  const srv = http.createServer((rq, res) => {
    const u = new URL(rq.url, 'http://x').pathname, json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u === '/dashboards/whoami.json' || u === '/auth/whoami') return json(200, WHO);
    if (u.startsWith('/api/itam/')) {
      const h = Object.assign({}, rq.headers, { 'x-sentra-proxy-secret': H.SECRET, 'x-auth-user': WHO.user, 'x-auth-role': WHO.role });
      const up = http.request({ host: '127.0.0.1', port: e.port, method: rq.method, path: rq.url, headers: h }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); });
      rq.pipe(up); return;
    }
    if (u.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.replace(/^\/dashboards\//, '')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': f.endsWith('.js') ? 'application/javascript' : f.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/dashboards/certificates.html?standalone=1';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg, { timeout: 30000 }).then(() => true, () => false);
  const toast = (p, re) => wait(p, (s) => [...document.querySelectorAll('.toast-zyb')].some((t) => new RegExp(s).test(t.textContent)), re);
  try {
    const ctx = await browser.newContext({ viewport: { width: 1500, height: 1000 } });
    let p = await ctx.newPage(); p.on('pageerror', (x) => errs.push(x.message)); p.on('dialog', (d) => d.dismiss());
    await p.goto(base);
    ok(await wait(p, () => /renew on their own/.test((document.getElementById('ap') || {}).textContent || '')), 'the autopilot is the default tab with the coverage ring');
    const hero = await p.textContent('#ap');
    ok(/of 3 certificates renew on their own/.test(hero), 'brief: coverage');
    ok(/should be started now/.test(hero), 'brief: start now');
    ok(/Biggest blocker/.test(hero), 'brief: the biggest blocker');
    ok(await p.evaluate(() => !window.__xss && /<img/.test(document.getElementById('apq').textContent)), 'a hostile label stays text');
    const first = await p.$eval('#apq tbody tr', (r) => r.getAttribute('data-apr')); ok(first === P.id, 'the critical certificate with 20 days left ranks first');
    ok(await p.$$eval('#apq tbody tr', (L) => L.every((r) => r.querySelectorAll('[aria-label="renewal steps"] span').length === 5)), 'five step chips per row');
    ok(/AD CS is not configured/.test(await p.textContent('#ap')), 'bottleneck names the blocker');
    ok(/Lead time learned from history/.test(hero) && /default \(no history yet\)/.test(hero), 'lead-time table says it uses defaults');
    // a tile filters
    await p.click('[data-apf="blocked"]'); ok(await wait(p, (id) => { const r = document.querySelectorAll('#apq tbody tr'); return r.length === 1 && r[0].getAttribute('data-apr') === id; }, VPN.id), 'the Blocked tile filters the queue');
    await p.click('[data-apf="all"]');
    // search
    await p.fill('#apq-s', 'mail.synthetic'); ok(await wait(p, () => document.querySelectorAll('#apq tbody tr').length === 1), 'search');
    await p.fill('#apq-s', '');
    // detail
    await p.click('#apq tbody tr[data-apr="' + VPN.id + '"] td:nth-child(3)');
    ok(await wait(p, () => /Renewal steps/.test(document.body.textContent) && /Fix: Issuers -> AD CS/.test(document.body.textContent)), 'row detail lists steps and fixes');
    await p.keyboard.press('Escape');
    // start the due ones (a person does it)
    await p.click('[data-apa="start-due"]');
    ok(await toast(p, 'Starting renewals: \\d+ done'), 'start renewals: toast');
    ok(await wait(p, (id) => { const r = document.querySelector('#apq tr[data-apr="' + id + '"]'); return r && /awaiting-certificate/.test(r.textContent); }, P.id), 'the manual order is in flight, awaiting the certificate');
    // select + switch on automatic renewal: blocked refused with the reason
    await p.check('[data-aps="' + VPN.id + '"]'); await p.check('[data-aps="' + MAIL.id + '"]');
    ok(/2 selected/.test(await p.textContent('#apbar')), 'selection counted');
    await p.click('[data-apa="enable-sel"]');
    ok(await toast(p, 'Automatic renewal: 1 done, 1 refused - ' + VPN.id + ': blocked'), 'enable: one done, the blocked one refused with the reason');
    ok(e.app.store.collection('cert_endpoints').get(MAIL.id).auto_renew === true, 'auto_renew stored');
    ok(e.app.store.auditTail(200).some((x) => x.action === 'certs.autopilot.enable' && x.by === 'nora.syn'), 'audited with the person');
    // a viewer reads only
    WHO = { user: 'vera.syn', role: 'viewer' }; p = await ctx.newPage(); p.on('pageerror', (x) => errs.push(x.message)); await p.goto(base + '&v=2');
    ok(await wait(p, () => /renew on their own/.test((document.getElementById('ap') || {}).textContent || '')), 'a viewer sees the autopilot');
    ok(!(await p.$('[data-apa="start-due"]')) && !(await p.$('[data-aps]')) && /Read-only/.test(await p.textContent('#apbar')), 'no actions for a viewer');
    ok(/operators and administrators/.test(await p.textContent('#ap')), 'the advisor is for operators');
    ok(/zyb-certpilot\.js/.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')), 'installer ships the script');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); await e.close(); fs.rmSync(tmp, { recursive: true, force: true }); }
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n);
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
