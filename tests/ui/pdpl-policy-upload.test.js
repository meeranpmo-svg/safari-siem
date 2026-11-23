// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// PDPL policy set (pdpl-policies.html) against the REAL IT Asset Management engine (engine/duty.js -> pdpl-workflows.js + grc.js,
// Python rules): an operator uploads the Privacy Notice the organisation already has (PDF) and sends it for approval in the same
// step; a renamed file is refused by its content; the uploader, now an admin, is refused by four-eyes; another administrator
// downloads the submitted document, rejects without a reason (refused), then approves; a viewer sees no actions. SYNTHETIC data.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node pdpl-policy-upload.test.js
const http = require('http'), fs = require('fs'), os = require('os'), path = require('path');
const ITAM = path.resolve(__dirname, '../../backend/itam'), DASH = path.resolve(__dirname, '../../ui');
const H = require(path.join(ITAM, 'tests/helpers.js'));
let WHO = { user: 'nora.syn', role: 'operator' }, n = 0, bad = 0;
const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };

(async () => {
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3' });
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, WHO);
    if (u.pathname.startsWith('/api/itam/')) {
      const h = Object.assign({}, req.headers, { 'x-sentra-proxy-secret': H.SECRET, 'x-auth-user': WHO.user, 'x-auth-role': WHO.role });
      const up = http.request({ host: '127.0.0.1', port: e.port, method: req.method, path: req.url, headers: h }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); });
      req.pipe(up); return;
    }
    if (u.pathname.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.pathname); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const url = 'http://127.0.0.1:' + srv.address().port + '/pdpl-policies.html';
  const T = fs.mkdtempSync(path.join(os.tmpdir(), 'pdpl-up-')), PDF = path.join(T, 'Privacy Notice v3.pdf'), FAKE = path.join(T, 'renamed.pdf');
  fs.writeFileSync(PDF, '%PDF-1.7\n1 0 obj << /Type /Catalog >> endobj\ntrailer << >>\n%%EOF\n'); fs.writeFileSync(FAKE, 'MZ this is not a PDF');
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  let page;
  const as = async (who) => { WHO = who; if (page) await page.close(); page = await browser.newPage({ viewport: { width: 1400, height: 950 }, acceptDownloads: true }); page.on('pageerror', (x) => errs.push(x.message)); await page.goto(url); await page.waitForSelector('#list tr[data-id="PP-02"]'); };
  const row = (id) => page.textContent('#list tr[data-id="' + id + '"]');
  try {
    await as({ user: 'nora.syn', role: 'operator' });
    ok(/Upload our policy/.test(await row('PP-02')) && /Start from the full draft/.test(await row('PP-02')), 'a missing policy with a full first draft offers it, and Upload our policy');
    ok(/Start a draft/.test(await row('PP-03')) && !/full draft/.test(await row('PP-03')), 'a missing policy without one offers the outline');
    await page.click('#list tr[data-id="PP-02"] [data-act="upload"]'); await page.waitForSelector('#pu-file');
    await page.setInputFiles('#pu-file', FAKE); await page.click('#pu-go');
    await page.waitForFunction(() => /not a real \.pdf/.test(document.getElementById('pu-msg').textContent)); ok(true, 'a renamed file is refused by its content');
    await page.setInputFiles('#pu-file', PDF); await page.fill('#pu-owner', 'DPO'); ok(await page.isChecked('#pu-submit'), 'submit for approval is the default');
    await page.click('#pu-go'); await page.waitForFunction(() => /in review/.test((document.querySelector('#list tr[data-id="PP-02"]') || {}).textContent || ''));
    ok(/waiting for an administrator/.test(await row('PP-02')), 'the operator sees it waiting for an administrator');
    // the uploader, if an admin, cannot approve it
    await as({ user: 'nora.syn', role: 'admin' });
    await page.click('#list tr[data-id="PP-02"] [data-act="decide"]'); await page.waitForSelector('[data-decide="approve"]');
    await page.click('[data-decide="approve"]'); await page.waitForFunction(() => /four eyes/i.test(document.getElementById('pd-msg').textContent)); ok(true, 'four-eyes: the uploader cannot approve');
    // another administrator: download, reject without a reason (refused), approve
    await as({ user: 'syed', role: 'admin' });
    await page.click('#list tr[data-id="PP-02"] [data-act="decide"]'); await page.waitForSelector('[data-dl]');
    const [dl] = await Promise.all([page.waitForEvent('download'), page.click('[data-dl]')]);
    ok(dl.suggestedFilename() === 'Privacy Notice v3.pdf' && fs.readFileSync(await dl.path()).equals(fs.readFileSync(PDF)), 'the approver downloads exactly the submitted document');
    await page.click('[data-decide="reject"]'); ok(/why it is rejected/.test(await page.textContent('#pd-msg')), 'reject needs a reason');
    await page.fill('#pd-note', 'Reviewed with Legal - approved'); await page.click('[data-decide="approve"]');
    await page.waitForFunction(() => /approved/.test((document.querySelector('#list tr[data-id="PP-02"]') || {}).textContent || ''));
    ok(/Upload new version/.test(await row('PP-02')), 'approved: Upload new version offered');
    ok(/1 \/ 16/.test(await page.textContent('#kpis')), 'counts follow');
    const log = e.app.store.auditTail(80).map((x) => x.action);
    ok(['pdpl.policy.upload', 'pdpl.policy.approve'].every((x) => log.includes(x)), 'upload and approval are audited');
    await as({ user: 'v.syn', role: 'viewer' }); ok(!(await page.$('#list [data-act]')), 'a viewer sees no actions');
    ok(!errs.length, 'page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); e.close(); }
  console.log(bad ? 'FAILED ' + bad + ' of ' + n : 'OK ' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
