// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Libraesva ESG (libraesva.html), stubbed ITAM + SIEM, SYNTHETIC data: syslog tiles / setup steps, connection summary and
// admin form (password never shown), test, mapping from the catalogue, status / queue read on load, quarantine and message
// log by button, generic tables escaped, viewer view, not installed.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node libraesva.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
let MODE = 'admin', SYSLOG = true; const POSTS = [], GETS = [];
const XSS = '<img src=x onerror=alert(1)>';
const CAT = [{ path: '/api/v2/login', methods: ['POST'], summary: '' }, { path: '/api/v2/system/status', methods: ['GET'], summary: 'System status' }, { path: '/api/v2/queue', methods: ['GET'], summary: 'Mail queue' },
  { path: '/api/v2/quarantine', methods: ['GET', 'DELETE'], summary: 'Quarantine' }, { path: '/api/v2/messages', methods: ['GET'], summary: 'Message log' }, { path: '/api/v2/quarantine/{id}/release', methods: ['POST'], summary: '' }];
let CFG = { configured: true, base_url: 'https://esg.corpgroup.test', username: 'api', switch_user: 'readonly', pinned: false, password_set: true, endpoints: { status: '/api/v2/system/status' }, catalogue: CAT, catalogue_source: '/api/v2/',
  last_test: { at: Date.now() - 60000, by: 'nora.syn', ok: true, message: 'logged in; 6 endpoints in the appliance catalogue' } };
(async () => {
  const srv = http.createServer((req, res) => {
    const u = decodeURIComponent(req.url.split('?')[0]), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    const body = (fn) => { let b = ''; req.on('data', (c) => { b += c; }); req.on('end', () => { const j = JSON.parse(b || '{}'); POSTS.push([u, j]); fn(j); }); };
    if (u === '/dashboards/whoami.json' || u === '/auth/whoami') return json(200, { user: 'syed', role: MODE === 'viewer' ? 'viewer' : 'admin' });
    if (MODE === 'none' && u.startsWith('/api/itam')) return json(404, { error: 'not found' });
    if (u === '/api/soc/top') return body(() => json(200, { values: SYSLOG ? [{ v: 'delivered', n: 900 }, { v: 'quarantined', n: 40 }] : [] }));
    if (u === '/api/itam/esg') return json(200, CFG);
    if (u === '/api/itam/esg/config') return body((b) => { CFG = Object.assign({}, CFG, { base_url: b.base_url, username: b.username, switch_user: b.switch_user || null }); json(200, CFG); });
    if (u === '/api/itam/esg/test') return body(() => json(200, CFG));
    if (u === '/api/itam/esg/diagnose') return body(() => json(200, { ok: false, at: '2026-10-29T10:00:00Z', steps: [
      { step: 'Connection settings', status: 'ok', detail: 'https://esg.syn as api', fix: '' }, { step: 'Address (DNS)', status: 'ok', detail: 'esg.syn → 10.20.0.25', fix: '' },
      { step: 'HTTPS and certificate', status: 'fail', detail: 'certificate not trusted <img src=x onerror=alert(1)> SHA-256 AA:BB', fix: 'paste this fingerprint in "Certificate pin"' }] }));
    if (u === '/api/itam/esg/endpoints') return body((b) => { CFG = Object.assign({}, CFG, { endpoints: Object.fromEntries(Object.entries(b).filter(([, v]) => v)) }); json(200, CFG); });
    if (u.startsWith('/api/itam/esg/read/')) { GETS.push(req.url); const k = u.split('/').pop();
      if (MODE === 'viewer' && (k === 'quarantine' || k === 'messages')) return json(403, { error: 'requires operator' });
      const rows = { status: [{ version: '5.6.2', cluster: '{"nodes":2}' }], queue: [{ queue: 'deferred', count: 3 }], quarantine: [{ id: 'q1', from: 'spam@ext.test', subject: 'Invoice ' + XSS }], messages: [{ id: 'm1', sender: 'a@ext.test', status: 'delivered' }] }[k];
      return json(200, { kind: k, path: '/api/v2/' + k, at: Date.now(), rows, total: rows.length, capped: false }); }
    if (u.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.replace(/^\/dashboards\//, '')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (e, d) => { if (e) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': f.endsWith('.js') ? 'application/javascript' : f.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port;
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch();
  try {
    const p = await browser.newPage({ viewport: { width: 1400, height: 1000 } }); const errs = []; p.on('pageerror', (e) => errs.push(e.message));
    let alerted = false; p.on('dialog', (d) => { alerted = true; d.dismiss(); });
    await p.goto(base + '/dashboards/libraesva.html?standalone=1'); await p.waitForSelector('#r-status table');
    ok(/Events \(24 h\)\s*940/.test(await p.textContent('#sys')) && /quarantined\s*40/.test(await p.textContent('#sys')), 'syslog tiles');
    const c = await p.textContent('#conn'); ok(/esg\.corpgroup\.test/.test(c) && /acting as readonly/.test(c) && /logged in; 6 endpoints/.test(c), 'connection summary');
    ok(!(await p.isHidden('#cf')) && (await p.inputValue('#pw')) === '', 'admin form, password never filled in');
    ok(/5\.6\.2/.test(await p.textContent('#r-status')) && GETS.some((g) => g.endsWith('/esg/read/status')), 'status read on load');
    const opts = await p.$$eval('#esg-gets option', (o) => o.map((x) => x.value)); ok(!opts.includes('/api/v2/login') && !opts.some((v) => v.includes('{')) && opts.includes('/api/v2/queue'), 'only concrete GET endpoints offered: ' + opts.join(','));
    await p.fill('#m-queue', '/api/v2/queue'); await p.fill('#m-quarantine', '/api/v2/quarantine'); await p.click('#mf button[type=submit]');
    await p.waitForSelector('#r-queue table'); const mp = POSTS.find((x) => x[0] === '/api/itam/esg/endpoints')[1]; ok(mp.queue === '/api/v2/queue' && mp.status === '/api/v2/system/status' && mp.messages === '', 'mapping saved');
    // the appliance published no catalogue: the paths are typed from its API page (bug fix - the lists were empty and nothing could be mapped)
    CFG = Object.assign({}, CFG, { catalogue: [] }); await p.reload(); await p.waitForSelector('#mapc:not([hidden])');
    ok(/catalogue was not read, so type each read-only GET path/.test(await p.textContent('#mhint')) && (await p.$$('#esg-gets option')).length === 0, 'empty catalogue: the page says to type the path');
    await p.fill('#m-messages', 'http://evil.test/x'); await p.click('#mf button[type=submit]'); ok(/messages.*a path under \/api\/v2\//.test(await p.textContent('#mmsg')), 'a path outside /api/v2/ is refused before sending');
    const nPost = POSTS.filter((x) => x[0] === '/api/itam/esg/endpoints').length;
    await p.fill('#m-messages', '/api/v2/message-log'); await p.click('#mf button[type=submit]'); await p.waitForFunction(() => /Saved/.test(document.getElementById('mmsg').textContent));
    const mp2 = POSTS.filter((x) => x[0] === '/api/itam/esg/endpoints'); ok(mp2.length === nPost + 1 && mp2[mp2.length - 1][1].messages === '/api/v2/message-log', 'a typed path is saved');
    await p.click('#lq'); await p.waitForSelector('#r-quarantine table'); const qt = await p.textContent('#r-quarantine');
    ok(/spam@ext\.test/.test(qt) && /onerror/.test(qt) && !(await p.$('#r-quarantine img')), 'quarantine table, escaped');
    await p.fill('#sk1', 'sender'); await p.fill('#sv1', 'a@ext.test'); await p.click('#sf button[type=submit]'); await p.waitForSelector('#r-messages table');
    ok(GETS.some((g) => /\/esg\/read\/messages\?sender=a%40ext\.test$/.test(g)), 'message log search passes the parameters');
    await p.fill('#burl', 'https://10.10.10.63'); await p.fill('#hn', 'esg.corpgroup.test'); await p.fill('#user', 'api2'); await p.fill('#pw', 'Synthetic-Pass1'); await p.click('#cf button[type=submit]');
    await p.waitForFunction(() => /Saved/.test(document.getElementById('tmsg').textContent)); const cp = POSTS.find((x) => x[0] === '/api/itam/esg/config')[1];
    ok(cp.base_url === 'https://10.10.10.63' && cp.host_name === 'esg.corpgroup.test' && cp.password === 'Synthetic-Pass1' && (await p.inputValue('#pw')) === '', 'config saved, password cleared from the form');
    await p.click('#test'); await p.waitForTimeout(300); ok(POSTS.some((x) => x[0] === '/api/itam/esg/test'), 'test connection');
    await p.click('#diag'); await p.waitForFunction(() => /HTTPS and certificate/.test(document.getElementById('dres').textContent), null, { timeout: 5000 }).catch(() => {});
    const dr = await p.textContent('#dres');
    ok(/Address \(DNS\)/.test(dr) && /Fix: paste this fingerprint/.test(dr) && /Fix the first red step/.test(dr) && !(await p.$('#dres img')), 'diagnose: steps, the fix for the failing one, hostile text stays text');
    ok(!alerted && errs.length === 0, 'no script ran, no page error: ' + errs.join(' | '));
    MODE = 'viewer'; SYSLOG = false; await p.reload(); await p.waitForSelector('#r-status table');
    ok(await p.isHidden('#cf'), 'viewer: no form'); ok(/Remote syslog/.test(await p.textContent('#sys')), 'no syslog: setup steps');
    await p.click('#lq'); await p.waitForFunction(() => /higher role/.test(document.getElementById('r-quarantine').textContent)); ok(true, 'viewer refused quarantine');
    MODE = 'none'; await p.reload(); await p.waitForFunction(() => /not installed/.test(document.getElementById('conn').textContent)); ok(true, 'not installed');
    await p.close();
  } finally { await browser.close(); srv.close(); }
  console.log(`${n - bad}/${n} passed`); process.exit(bad ? 1 : 0);
})();
