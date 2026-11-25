// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Mimecast Actions page: no management app says so; the held queue lists messages (hostile text stays text) and proposes a
// release; the form proposes a sender block; the proposer is not offered Approve; another person approves; Run carries it out.
// Stub SIEM; addresses and people are SYNTHETIC.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node mimecast-actions.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
let USER = 'op.syn', APP = false, ACTS = [];
const KINDS = { 'block-sender': 'Block a sender', 'permit-sender': 'Permit a sender', 'release-held': 'Release a held message', 'reject-held': 'Reject a held message', 'block-url': 'Block a URL (URL Protect)' };
const posts = [];
(async () => {
  const srv = http.createServer((req, res) => {
    const u = req.url.split('?')[0]; const json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    const body = (fn) => { let b = ''; req.on('data', (d) => { b += d; }); req.on('end', () => { const j = b ? JSON.parse(b) : null; posts.push([req.method, u, j]); fn(j); }); };
    if (u === '/dashboards/whoami.json') return json(200, { user: USER, role: 'operator' });
    if (u === '/api/soc/cloud/mimecast/held') return APP ? json(200, { held: [{ id: 'eNoVzs1OgzAAAOBX', received: '2026-11-25T08:00', from: 'x@partner.example', to: 'a@corp.example', subject: 'Invoice <img src=x onerror=alert(1)>', reason: 'Attachment', attachments: true }] }) : json(409, { error: 'no Mimecast management application is stored' });
    if (u === '/api/soc/cloud/mimecast/actions' && req.method === 'GET') return json(200, { actions: ACTS, kinds: KINDS, enabled: APP, app_set: APP });
    if (u === '/api/soc/cloud/mimecast/actions' && req.method === 'POST') return body((b) => { const a = Object.assign({}, b, { message_id: b.id, id: 'MCAC-00000' + (ACTS.length + 1), title: KINDS[b.kind], status: 'proposed', proposed_by: USER }); ACTS.unshift(a); json(200, a); });
    if (/\/decide$/.test(u)) return body((b) => { ACTS[0].status = b.decision; ACTS[0].decided_by = USER; json(200, ACTS[0]); });
    if (/\/run$/.test(u)) return body(() => { ACTS[0].status = 'done'; json(200, ACTS[0]); });
    if (u.startsWith('/api/')) return json(404, { error: 'not in this test' });
    fs.readFile(path.join(DASH, u.replace(/^\/dashboards\//, '/')), (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.endsWith('.js') ? 'application/javascript' : u.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const URL0 = 'http://127.0.0.1:' + srv.address().port + '/mimecast-actions.html?standalone=1';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(); const errs = [];
  const open = async () => { const p = await browser.newPage({ viewport: { width: 1400, height: 900 } }); p.on('pageerror', (x) => errs.push(x.message)); p.on('dialog', (d) => d.accept('vendor confirmed (synthetic)')); await p.goto(URL0); return p; };
  const toast = async (p) => { await p.waitForSelector('.toast', { timeout: 8000 }); const t = await p.$$eval('.toast', (x) => x.map((e) => e.textContent).join(' | ')); await p.$$eval('.toast', (x) => x.forEach((e) => e.remove())); return t; };
  let p = await open();
  await p.waitForFunction(() => /No Mimecast management application/.test(document.body.innerText));
  ok(/no Mimecast management application is stored/.test(await p.textContent('#held')), 'held queue says why it is empty');
  await p.close();
  APP = true; p = await open(); await p.waitForSelector('#held table');
  ok(!(await p.$('img[src="x"]')), 'hostile text stays text');
  await p.click('[data-held="release-held"]'); const t0 = await toast(p); ok(/MCAC-000001 proposed/.test(t0), 'release proposed from the queue: ' + t0);
  const rel = posts.find((x) => x[2] && x[2].kind === 'release-held'); ok(rel && rel[2].id === 'eNoVzs1OgzAAAOBX' && /vendor confirmed/.test(rel[2].reason), 'release body');
  await p.selectOption('#kind', 'block-sender'); await p.fill('#sender', 'evil.example'); await p.fill('#to', 'a@corp.example'); await p.fill('#reason', 'phishing campaign (synthetic)'); await p.click('#send');
  ok(/MCAC-000002 proposed/.test(await toast(p)), 'block proposed');
  const blk = posts.find((x) => x[2] && x[2].kind === 'block-sender'); ok(blk && blk[2].sender === 'evil.example' && blk[2].to === 'a@corp.example' && !('url' in blk[2]), 'block body');
  await p.waitForFunction(() => document.querySelectorAll('#plans .act').length === 2);
  ok(!(await p.$('[data-dec="approved"]')), 'the proposer is not offered Approve');
  await p.close();
  USER = 'sec.syn'; p = await open(); await p.waitForSelector('[data-dec="approved"]');
  await p.click('[data-dec="approved"]'); ok(/approved/.test(await toast(p)), 'approved by another person');
  await p.waitForSelector('[data-run]'); await p.click('[data-run]'); ok(/done in Mimecast/.test(await toast(p)), 'run');
  await p.close();
  ok(!errs.length, 'errors: ' + errs.join(' | '));
  await browser.close(); srv.close();
  console.log(bad ? `${bad}/${n} FAILED` : `OK ${n}/${n} checks`); process.exit(bad ? 1 : 0);
})();
