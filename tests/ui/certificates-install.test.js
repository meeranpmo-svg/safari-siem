// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Certificates → Installation (phase 3, certificates.html), stubbed ITAM, SYNTHETIC data: jobs with status and actions,
// devices with binding and pinned fingerprint (never the key), Add device posts the declared fields with the key and
// clears it, Propose posts {request_id, target_id, reason, run_after}, Approve / Run / Roll back post to the right job,
// a four-eyes refusal is shown, the step log opens, escaping, not installed / operator-only messages.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node certificates-install.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const POSTS = []; let APPROVE403 = false, INS404 = false;
const sc = (o) => Object.assign({ ok: true, subject: 'vpn.synthetic.test', issuer: 'Synthetic CA', names: ['vpn.synthetic.test'], not_before: Date.now() - 1e10, not_after_iso: '2027-01-01', key_type: 'rsa', key_bits: 2048, trusted: true, chain: ['Synthetic CA'], serial: 'AA', fingerprint256: 'AA:BB' }, o);
const ep = (id, label) => ({ id, label, host: label, port: 443, critical: false, owner: 'Network', issuer_kind: 'adcs', issuer_kind_name: 'AD CS', issuer_kind_set: false, deploy_target: 'paloalto', deploy_target_name: 'Palo Alto', state: 'valid', days_left: 200, renew_by: Date.now(), renewal: null, scan: sc({}) });
const VIEW = () => ({ engine: 'python', connected: true, counts: { valid: 1 }, renewals_open: 0, lead_days: { acme: 30, adcs: 45, manual: 60, self: 30, unknown: 45 }, min_rsa: 2048, policy: {}, automation: { issuance: 'x', installation: 'Palo Alto and FortiGate' },
  endpoints: [ep('CE-0001', 'vpn.synthetic.test')], requests: [{ id: 'CQ-0004', endpoint_id: 'CE-0001', method: 'adcs', key_type: 'rsa', key_bits: 2048, names: ['vpn.synthetic.test'], status: 'issued', requested_by: 'nora.syn', serial: 'S1', not_after: Date.now() + 365 * 864e5 }],
  issuers: { acme: null, adcs: null, vault: 'available' }, renewals: [], findings: [] });
const INS = () => ({ targets: [{ id: 'CT-0001', label: '<img src=x onerror=alert(1)> PA edge', kind: 'paloalto', host: '192.0.2.1', port: 443, pin: 'AA:BB:CC:DD:EE:FF:00:11:22:33:44:55', binding: { type: 'ssl-tls-profile', name: 'GP-Portal' }, key_set: true, last_test: { ok: true, info: { model: 'PA-3220' } } },
  { id: 'CT-0002', label: 'FortiGate users', kind: 'fortigate', host: '192.0.2.2', port: 443, pin: '11:22', binding: { type: 'ssl-vpn' }, key_set: true, last_test: { ok: false, error: 'the device presented a certificate that is not pinned' } }],
  jobs: [{ id: 'CI-0001', request_id: 'CQ-0004', target_id: 'CT-0001', cert_name: 'zyb-vpn-synthetic-test-20271025', names: ['vpn.synthetic.test'], binding: { type: 'ssl-tls-profile', name: 'GP-Portal' }, status: 'proposed', requested_by: 'nora.syn', plan: ['refuse if anyone has uncommitted changes on the firewall', 'import the private key and certificate', 'commit and wait'], warnings: [], steps: [], history: [{ at: '2026-10-25T08:00:00Z', by: 'nora.syn', to: 'proposed', note: 'renewal' }] },
    { id: 'CI-0002', request_id: 'CQ-0003', target_id: 'CT-0002', cert_name: 'zyb-sslvpn-20271025', names: ['sslvpn.synthetic.test'], binding: { type: 'ssl-vpn' }, status: 'approved', requested_by: 'nora.syn', approval: { by: 'sec.approver' }, run_after: '2026-10-26T22:00:00.000Z', plan: [], warnings: [], steps: [], history: [] },
    { id: 'CI-0003', request_id: 'CQ-0002', target_id: 'CT-0001', cert_name: 'zyb-old', names: ['vpn.synthetic.test'], binding: { type: 'ssl-tls-profile', name: 'GP-Portal' }, status: 'verified', previous: 'old-gp-cert', requested_by: 'nora.syn', approval: { by: 'sec.approver' }, plan: [], warnings: [],
      steps: [{ at: '2026-10-20T22:00:01Z', step: 'import key pair zyb-old', ok: true, detail: '<b>encrypted</b>' }, { at: '2026-10-20T22:00:09Z', step: 'verified: vpn.synthetic.test:443 presents the new certificate', ok: true, detail: '' }], history: [] }] });
(async () => {
  const srv = http.createServer((req, res) => {
    const u = decodeURIComponent(req.url.split('?')[0]), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    const body = (fn) => { let b = ''; req.on('data', (c) => { b += c; }); req.on('end', () => { const j = JSON.parse(b || '{}'); POSTS.push([u, j]); fn(j); }); };
    if (u === '/dashboards/whoami.json' || u === '/auth/whoami') return json(200, { user: 'syed', role: 'admin' });
    if (u === '/api/itam/certs') return json(200, VIEW());
    if (u === '/api/itam/certs/install') return INS404 ? json(404, { error: 'not found' }) : json(200, INS());
    if (u === '/api/itam/certs/install/targets') return body((b) => json(200, { id: 'CT-0003', label: b.label }));
    if (u === '/api/itam/certs/install/targets/CT-0001/test') return body(() => json(200, { ok: true, info: { model: 'PA-3220' } }));
    if (u === '/api/itam/certs/install/jobs') return body(() => json(200, { id: 'CI-0004', status: 'proposed' }));
    const m = /^\/api\/itam\/certs\/install\/jobs\/(CI-\d+)\/(approve|reject|cancel|run|rollback)$/.exec(u);
    if (m) return body(() => (APPROVE403 && m[2] === 'approve' ? json(403, { error: 'four-eyes: a different person approves - you proposed this installation' }) : json(200, { id: m[1], status: { approve: 'approved', reject: 'rejected', cancel: 'cancelled', run: 'verified', rollback: 'rolled-back' }[m[2]] })));
    if (u.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.replace(/^\/dashboards\//, '')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (e, d) => { if (e) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': f.endsWith('.js') ? 'application/javascript' : f.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port;
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch();
  try {
    const p = await browser.newPage(); const errs = []; let dialogs = 0; p.on('pageerror', (e) => errs.push(e.message)); p.on('dialog', (d) => { dialogs++; d.dismiss(); });
    await p.goto(base + '/dashboards/certificates.html?standalone=1#install'); await p.waitForSelector('#insjobs table');
    const t = await p.$eval('#v-install', (e) => e.innerText);
    ok(/Waiting for approval/.test(t) && /Approved/.test(t) && /window 2026-10-26 22:00/.test(t) && /Installed - verified by a scan/.test(t), 'job states');
    ok(/PA-3220/.test(t) && /not pinned/.test(t) && /AA:BB:CC:DD/.test(t) && /ssl-tls-profile GP-Portal/.test(t), 'devices, pin, last test');
    ok(await p.$$eval('#v-install img', (a) => a.length) === 0, 'device label escaped');
    // add a device
    await p.click('#tgnew'); await p.waitForSelector('#tgform');
    await p.fill('#tgform input[name=label]', 'FortiGate users 2'); await p.selectOption('#tgform select[name=kind]', 'fortigate');
    ok((await p.$$eval('#tgform select[name=btype] option', (a) => a.map((x) => x.value))).join() === 'ssl-vpn,admin-server-cert,vip,none', 'FortiGate bindings offered');
    await p.fill('#tgform input[name=host]', '192.0.2.9'); await p.fill('#tgform input[name=pin]', 'AB'.repeat(32)); await p.fill('#tgform input[name=api_key]', 'fgt-synthetic-token');
    await p.selectOption('#tgform select[name=endpoint_id]', 'CE-0001'); await p.click('#tgform button[type=submit]'); await p.waitForTimeout(400);
    const tg = POSTS.find((x) => x[0].endsWith('/install/targets'))[1];
    ok(tg.kind === 'fortigate' && tg.binding.type === 'ssl-vpn' && tg.api_key === 'fgt-synthetic-token' && tg.endpoint_id === 'CE-0001' && tg.port === 443, 'device posted: ' + JSON.stringify(Object.assign({}, tg, { api_key: '…' })));
    // propose
    await p.click('#insnew'); await p.waitForSelector('#insform'); await p.fill('#insform input[name=reason]', 'CHG-SYN-12 GP renewal'); await p.fill('#insform input[name=run_after]', '2026-10-27T22:00'); await p.click('#insform button[type=submit]'); await p.waitForTimeout(400);
    const pr = POSTS.find((x) => x[0].endsWith('/install/jobs'))[1];
    ok(pr.request_id === 'CQ-0004' && pr.target_id === 'CT-0001' && pr.reason === 'CHG-SYN-12 GP renewal' && /^2026-10-27T/.test(pr.run_after), 'proposal posted: ' + JSON.stringify(pr));
    // approve: refusal shown, then ok
    APPROVE403 = true; await p.click('[data-ins="approve"][data-id="CI-0001"]'); await p.waitForSelector('#insact');
    ok(/uncommitted changes/.test(await p.evaluate(() => document.getElementById('insact').parentElement.innerText)), 'the plan is shown before approving');
    await p.click('#insact button[type=submit]'); await p.waitForTimeout(400); ok(/four-eyes/.test(await p.$eval('#iamsg', (e) => e.textContent)), 'four-eyes refusal shown');
    APPROVE403 = false; await p.click('#insact button[type=submit]'); await p.waitForTimeout(400);
    ok(POSTS.filter((x) => /CI-0001\/approve$/.test(x[0])).length === 2, 'approve posted');
    await p.click('[data-ins="run"][data-id="CI-0002"]'); await p.waitForSelector('#insact'); await p.click('#insact button[type=submit]'); await p.waitForTimeout(400);
    ok(POSTS.some((x) => /CI-0002\/run$/.test(x[0])), 'run posted');
    await p.click('[data-ins="rollback"][data-id="CI-0003"]'); await p.waitForSelector('#insact'); await p.fill('#insact input[name=note]', 'clients complain'); await p.click('#insact button[type=submit]'); await p.waitForTimeout(400);
    const rb = POSTS.find((x) => /CI-0003\/rollback$/.test(x[0])); ok(rb && rb[1].reason === 'clients complain', 'roll-back posted with a reason');
    // step log
    await p.click('[data-insview="CI-0003"]'); await p.waitForTimeout(300);
    const log = await p.evaluate(() => document.body.innerText); ok(/verified: vpn.synthetic.test:443 presents the new certificate/.test(log), 'step log opens');
    ok(await p.$$eval('b', (a) => a.filter((x) => x.textContent === 'encrypted').length) === 0, 'step detail escaped');
    await p.keyboard.press('Escape');
    await p.click('[data-tgtest="CT-0001"]'); await p.waitForTimeout(300); ok(POSTS.some((x) => /CT-0001\/test$/.test(x[0])), 'device test posted');
    INS404 = true; const p2 = await browser.newPage(); p2.on('pageerror', (e) => errs.push(e.message));
    await p2.goto(base + '/dashboards/certificates.html?standalone=1#install'); await p2.waitForFunction(() => /not installed yet/.test(document.getElementById('insjobs').innerText)); ok(true, 'not installed message');
    ok(!errs.length, 'no page errors: ' + errs.join(' | ')); ok(!dialogs, 'no browser dialogs');
  } finally { await browser.close(); srv.close(); }
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})();
