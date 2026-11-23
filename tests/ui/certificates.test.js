// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// SSL / TLS Certificates (certificates.html), stubbed ITAM, SYNTHETIC data: KPIs, the inventory sorted by days left with
// state badges and search / state filter, the endpoint drawer (certificate detail, scan now, open renewal with a ticket),
// the add-endpoint form posting only the declared fields, renewals moving to the next step (verified never offered),
// cancel needing a reason, discovery proposals added, the admin policy form, escaping and the not-installed state.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node certificates.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const POSTS = []; let GONE = false;
const sc = (o) => Object.assign({ ok: true, subject: 'portal.synthetic.test', issuer: 'Synthetic CA', names: ['portal.synthetic.test'], not_before: Date.now() - 1e10, not_after_iso: '2027-01-01', key_type: 'rsa', key_bits: 2048, trusted: true, chain: ['Synthetic CA'], serial: 'AA', fingerprint256: 'AA:BB' }, o);
const ep = (id, label, state, days, o) => Object.assign({ id, label, host: label, port: 443, critical: false, owner: 'Infra', issuer_kind: 'adcs', issuer_kind_name: 'Microsoft AD CS (internal CA)', issuer_kind_set: false, deploy_target: 'iis', deploy_target_name: 'IIS (Windows)', state, days_left: days, renew_by: Date.now(), renewal: null, scan: sc({}) }, o);
const VIEW = () => ({ engine: 'python', connected: true, counts: { valid: 1, 'renew-due': 0, expiring: 1, expired: 1, unreachable: 1, 'not-scanned': 0 }, renewals_open: 1, lead_days: { acme: 30, adcs: 45, manual: 60, self: 30, unknown: 45 }, min_rsa: 2048, policy: {},
  endpoints: [ep('CE-0001', 'web.synthetic.test', 'valid', 200), ep('CE-0002', '<img src=x onerror=alert(1)>.synthetic.test', 'expired', -3, { critical: true }), ep('CE-0003', 'mail.synthetic.test', 'expiring', 9, { renewal: { id: 'CR-0001', status: 'issued' } }), ep('CE-0004', 'old.synthetic.test', 'unreachable', null, { scan: { ok: false, error: 'ECONNREFUSED' } })],
  requests: [{ id: 'CQ-0001', endpoint_id: 'CE-0003', method: 'acme', key_type: 'rsa', key_bits: 2048, names: ['mail.synthetic.test', '*.mail.synthetic.test'], status: 'awaiting-approval', requested_by: 'nora.syn', approval: { why: ['*.mail.synthetic.test is a wildcard'] } },
    { id: 'CQ-0002', endpoint_id: 'CE-0001', method: 'acme', key_type: 'ec', key_bits: 256, names: ['web.synthetic.test'], status: 'awaiting-dns', requested_by: 'nora.syn', acme: { dns: [{ name: 'web.synthetic.test', record: '_acme-challenge.web.synthetic.test', txt: 'SYNTHETICTXTVALUE123' }] } },
    { id: 'CQ-0003', endpoint_id: 'CE-0004', method: 'manual', key_type: 'rsa', key_bits: 3072, names: ['old.synthetic.test'], status: 'awaiting-certificate', requested_by: 'nora.syn', csr_pem: '-----BEGIN CERTIFICATE REQUEST-----\nSYN\n-----END CERTIFICATE REQUEST-----\n' },
    { id: 'CQ-0004', endpoint_id: 'CE-0002', method: 'adcs', key_type: 'rsa', key_bits: 2048, names: ['x.synthetic.test'], status: 'issued', requested_by: 'nora.syn', serial: 'S1', not_after: Date.now() + 365 * 864e5 },
    { id: 'CQ-0005', endpoint_id: 'CE-0002', method: 'adcs', key_type: 'rsa', key_bits: 2048, names: ['x.synthetic.test'], status: 'failed', requested_by: 'nora.syn', error: 'Denied by Policy Module <b>synthetic</b>' }],
  issuers: { acme: null, adcs: { url: 'https://ca01.synthetic.local/certsrv', template: 'WebServerSyn', username: 'svc-pki', password_set: true }, vault: 'available' },
  renewals: [{ id: 'CR-0001', endpoint_id: 'CE-0003', status: 'issued', opened_by: 'nora.syn', opened_at: '2026-10-20T08:00:00Z', ticket: 'CHG-1' }, { id: 'CR-0002', endpoint_id: 'CE-0001', status: 'verified', opened_by: 'nora.syn', opened_at: '2026-09-01T08:00:00Z' }], findings: [] });
(async () => {
  const srv = http.createServer((req, res) => {
    const u = decodeURIComponent(req.url.split('?')[0]), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    const body = (fn) => { let b = ''; req.on('data', (c) => { b += c; }); req.on('end', () => fn(JSON.parse(b || '{}'))); };
    if (u === '/dashboards/whoami.json' || u === '/auth/whoami') return json(200, { user: 'syed', role: 'admin' });
    if (u.startsWith('/api/itam/certs') && GONE) return json(404, { error: 'not found' });
    if (u === '/api/itam/certs') return json(200, VIEW());
    if (u.startsWith('/api/itam/certs/') && req.method === 'POST') return body((b) => { POSTS.push([u, b]);
      if (u === '/api/itam/certs/scan') return json(200, { scanned: 1, read: 1, failed: 0 });
      if (u === '/api/itam/certs/discover') return json(200, { probed: 8, found: [{ host: '10.99.0.5', port: 443, label: 'SRV-SYN-WEB', subject: 'web.synthetic.test', issuer: 'Synthetic CA', not_after_iso: '2027-01-01', asset_id: 'A1' }], note: 'Proposals only.' });
      if (u === '/api/itam/certs/endpoints') return json(200, Object.assign({ id: 'CE-0009' }, b));
      if (u === '/api/itam/certs/renewals') return json(200, { id: 'CR-0003' });
      if (u === '/api/itam/certs/requests') return json(200, { id: 'CQ-0009', status: 'issued' });
      if (/\/requests\/CQ-\d+\/export$/.test(u)) return json(200, { id: 'CQ-0004', cert_pem: '-----BEGIN CERTIFICATE-----\nSYN\n-----END CERTIFICATE-----\n', chain_pem: '', key_pem: b.include_key ? '-----BEGIN PRIVATE KEY-----\nSYN\n-----END PRIVATE KEY-----\n' : undefined });
      if (/\/requests\/CQ-\d+\/(approve|advance|upload|cancel)$/.test(u)) return json(200, { id: 'CQ-0001', status: 'issued' });
      return json(200, { ok: true }); });
    if (u.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.replace(/^\/dashboards\//, '')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (e, d) => { if (e) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': f.endsWith('.js') ? 'application/javascript' : f.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port;
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch();
  try {
    const p = await browser.newPage(); const errs = []; let dialogs = 0; p.on('pageerror', (e) => errs.push(e.message)); p.on('dialog', (d) => { dialogs++; d.dismiss(); });
    await p.goto(base + '/dashboards/certificates.html?standalone=1#inventory'); await p.waitForSelector('[data-ep]');
    const k = await p.$eval('#kpis', (e) => e.textContent.replace(/\s+/g, ' '));
    ok(/4\s*endpoints/i.test(k) && /1\s*expired/i.test(k) && /1\s*renewals open/i.test(k), 'KPIs: ' + k);
    const order = await p.$$eval('[data-ep]', (a) => a.map((x) => x.dataset.ep));
    ok(order.join() === 'CE-0002,CE-0003,CE-0001,CE-0004', 'sorted by days left, unread last: ' + order);
    ok(await p.$$eval('#inv img', (a) => a.length) === 0 && /<img src=x/.test(await p.$eval('#inv', (e) => e.textContent)), 'labels escaped');
    await p.selectOption('#st', 'expiring'); ok((await p.$$eval('[data-ep]', (a) => a.map((x) => x.dataset.ep))).join() === 'CE-0003', 'state filter'); await p.selectOption('#st', '');
    await p.fill('#q', 'mail'); ok((await p.$$eval('[data-ep]', (a) => a.length)) === 1, 'search'); await p.fill('#q', '');
    // drawer: detail, scan, open renewal
    await p.click('[data-ep="CE-0001"]'); await p.waitForSelector('[data-renew]');
    ok(/AA:BB/.test(await p.evaluate(() => document.body.innerText)) && /RSA 2048/.test(await p.evaluate(() => document.body.innerText)), 'certificate detail');
    await p.click('[data-scan]'); await p.waitForTimeout(300);
    ok(POSTS.some((x) => x[0] === '/api/itam/certs/scan' && x[1].id === 'CE-0001'), 'scan now posts the endpoint');
    await p.click('[data-ep="CE-0001"]'); await p.waitForSelector('[data-renew]'); await p.click('[data-renew]'); await p.waitForSelector('#askf');
    await p.fill('#askf input[name=t]', 'CHG-SYN-9'); await p.click('#askf button[type=submit]'); await p.waitForTimeout(300);
    ok(POSTS.some((x) => x[0] === '/api/itam/certs/renewals' && x[1].endpoint_id === 'CE-0001' && x[1].ticket === 'CHG-SYN-9'), 'renewal opened with ticket');
    // add endpoint
    await p.click('#add'); await p.waitForSelector('#epf'); await p.fill('#epf input[name=host]', 'new.synthetic.test'); await p.fill('#epf input[name=port]', '8443');
    await p.selectOption('#epf select[name=issuer_kind]', 'acme'); await p.selectOption('#epf select[name=deploy_target]', 'linux-nginx'); await p.check('#epf input[name=critical]');
    await p.click('#epf button[type=submit]'); await p.waitForTimeout(400);
    const add = POSTS.find((x) => x[0] === '/api/itam/certs/endpoints');
    ok(add && add[1].host === 'new.synthetic.test' && add[1].port === 8443 && add[1].issuer_kind === 'acme' && add[1].deploy_target === 'linux-nginx' && add[1].critical === true && add[1].sni === undefined, 'add endpoint body: ' + JSON.stringify(add && add[1]));
    ok(POSTS.some((x) => x[0] === '/api/itam/certs/scan' && x[1].id === 'CE-0009'), 'a new endpoint is scanned at once');
    // renewals tab
    await p.click('#tabs [data-tab="renewals"]');
    const rt = await p.$eval('#ren', (e) => e.innerText);
    ok(/Mark installed/.test(rt) && !/Mark verified/i.test(rt) && /Verified by scan/.test(rt) && /never set by hand/.test(rt), 'renewals: next step only, verified by scan');
    await p.click('[data-move="CR-0001"][data-to="installed"]'); await p.waitForTimeout(300);
    ok(POSTS.some((x) => x[0] === '/api/itam/certs/renewals/CR-0001' && x[1].status === 'installed'), 'move to installed');
    await p.click('[data-move="CR-0001"][data-to="cancelled"]'); await p.waitForSelector('#askf'); await p.fill('#askf input[name=t]', 'superseded (synthetic)'); await p.click('#askf button[type=submit]'); await p.waitForTimeout(300);
    ok(POSTS.some((x) => x[0] === '/api/itam/certs/renewals/CR-0001' && x[1].status === 'cancelled' && x[1].note === 'superseded (synthetic)'), 'cancel with reason');
    // issuance: issue form, requests actions, issuers
    await p.click('#tabs [data-tab="inventory"]'); await p.click('[data-ep="CE-0001"]'); await p.waitForSelector('[data-issue]'); await p.click('[data-issue]'); await p.waitForSelector('#issf');
    await p.selectOption('#issf select[name=method]', 'adcs'); await p.fill('#issf textarea[name=names]', 'web.synthetic.test\nweb2.synthetic.test'); await p.selectOption('#issf select[name=key]', 'ec:384');
    await p.click('#issf button[type=submit]'); await p.waitForTimeout(400);
    const iq = POSTS.find((x) => x[0] === '/api/itam/certs/requests');
    ok(iq && iq[1].endpoint_id === 'CE-0001' && iq[1].method === 'adcs' && iq[1].names.join() === 'web.synthetic.test,web2.synthetic.test' && iq[1].key_type === 'ec' && iq[1].key_bits === 384, 'issue request body: ' + JSON.stringify(iq && iq[1]));
    ok(await p.$eval('#v-requests', (e) => !e.hidden), 'goes to the requests tab');
    const rq = await p.$eval('#reqs', (e) => e.textContent);
    ok(/is a wildcard/.test(rq) && /_acme-challenge\.web\.synthetic\.test/.test(rq) && /SYNTHETICTXTVALUE123/.test(rq) && /Denied by Policy Module <b>synthetic<\/b>/.test(rq), 'approval reason, DNS record, error (escaped) shown');
    ok(await p.$$eval('#reqs b', (a) => a.length) === 0, 'error text escaped');
    await p.click('[data-qact="approve"][data-q="CQ-0001"]'); await p.waitForTimeout(300);
    await p.click('[data-qact="dns"][data-q="CQ-0002"]'); await p.waitForTimeout(300);
    ok(POSTS.some((x) => x[0] === '/api/itam/certs/requests/CQ-0001/approve') && POSTS.some((x) => x[0] === '/api/itam/certs/requests/CQ-0002/advance' && x[1].dns_published === true), 'approve and DNS published');
    const [csrDl] = await Promise.all([p.waitForEvent('download'), p.click('[data-qact="csr"][data-q="CQ-0003"]')]);
    ok(csrDl.suggestedFilename() === 'CQ-0003.csr', 'CSR downloads');
    await p.click('[data-qact="paste"][data-q="CQ-0003"]'); await p.waitForSelector('#pastef'); await p.fill('#pastef textarea', '-----BEGIN CERTIFICATE-----\nSYN\n-----END CERTIFICATE-----'); await p.click('#pastef button[type=submit]'); await p.waitForTimeout(300);
    ok(POSTS.some((x) => x[0] === '/api/itam/certs/requests/CQ-0003/upload' && /BEGIN CERTIFICATE/.test(x[1].pem)), 'certificate pasted');
    await p.click('[data-qact="export"][data-q="CQ-0004"]'); await p.waitForSelector('#expf'); await p.check('#expf input[name=key]'); await p.fill('#expf input[name=reason]', 'install on IIS (synthetic)');
    const dls = []; p.on('download', (d) => dls.push(d.suggestedFilename()));
    await p.click('#expf button[type=submit]'); await p.waitForTimeout(800);
    ok(POSTS.some((x) => /CQ-0004\/export$/.test(x[0]) && x[1].include_key === true && x[1].reason === 'install on IIS (synthetic)') && dls.includes('CQ-0004.crt') && dls.includes('CQ-0004.key'), 'export with key downloads files: ' + dls);
    ok(!/PRIVATE KEY/.test(await p.evaluate(() => document.body.innerText)), 'the key is never shown on the page');
    await p.click('#tabs [data-tab="issuers"]');
    ok(/ca01\.synthetic\.local/.test(await p.$eval('#iadcs', (e) => e.textContent)) && /password set/.test(await p.$eval('#iadcs', (e) => e.textContent)), 'AD CS shown without the password');
    await p.selectOption('#acmef select[name=preset]', 'https://acme-staging-v02.api.letsencrypt.org/directory'); await p.fill('#acmef input[name=contact]', 'pki@synthetic.test'); await p.check('#acmef input[name=tos]');
    await p.click('#acmef button[type=submit]'); await p.waitForTimeout(300);
    const ac = POSTS.find((x) => x[0] === '/api/itam/certs/issuers/acme');
    ok(ac && ac[1].directory_url === 'https://acme-staging-v02.api.letsencrypt.org/directory' && ac[1].tos_agreed === true && ac[1].contact === 'pki@synthetic.test' && ac[1].eab_hmac === undefined, 'ACME issuer posted: ' + JSON.stringify(ac && ac[1]));
    // discover
    await p.click('#tabs [data-tab="discover"]'); await p.click('#disc'); await p.waitForSelector('[data-adopt]');
    await p.click('[data-adopt="0"]'); await p.waitForTimeout(300);
    ok(POSTS.some((x) => x[0] === '/api/itam/certs/endpoints' && x[1].host === '10.99.0.5' && x[1].asset_id === 'A1'), 'proposal added');
    // policy
    await p.click('#tabs [data-tab="policy"]'); await p.fill('#polf input[name=manual]', '75'); await p.click('#polf button[type=submit]'); await p.waitForTimeout(300);
    const pol = POSTS.find((x) => x[0] === '/api/itam/certs/policy'); ok(pol && pol[1].lead_days.manual === 75 && pol[1].min_rsa === 2048, 'policy posted');
    ok(!errs.length && !dialogs, 'no page errors, no injected script: ' + errs.join(' | '));
    GONE = true; await p.goto(base + '/dashboards/certificates.html?standalone=1&r=2#inventory'); await p.waitForTimeout(700);
    ok(/not installed/.test(await p.$eval('#inv', (e) => e.textContent)), 'not installed state');
  } finally { await browser.close(); srv.close(); }
  console.log(bad ? 'FAILED ' + bad + '/' + n + ' checks' : 'OK ' + n + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
