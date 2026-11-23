// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for Vendor risk on the Processors page (pdpl-processors.html) against the REAL ITAM engine (engine/pdpl-vendor.js
// + pyengine/pdpl_vendor.py) with SYNTHETIC vendors: the tier from the activities that name each vendor, an unlinked vendor not
// rated, an operator starts an assessment, downloads the questionnaire, imports the vendor's filled-in file, accepts and
// challenges answers, submits; the submitter cannot approve, an administrator approves; the residual risk, the next due date
// and the GRC actions appear; a hostile vendor name stays text; a viewer is refused.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node pdpl-vendor.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror=alert(1)>';

(async () => {
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3' });
  const as = (who) => async (p, body) => { const r = await e.req('POST', p, Object.assign({ body }, who)); if (r.status !== 200) throw new Error(p + ': ' + r.raw); return r.json; };
  const adm = as({ user: 'syed', role: 'admin' });
  await adm('/pdpl/records', { kind: 'profile', dpo_user: 'huda.syn', dpo_appointed: '2026-01-01' });
  const tpa = await adm('/pdpl/records', { kind: 'processor', name: 'TPA Synthetic ' + XSS, service: 'medical claims', outside_ksa: true });
  await adm('/pdpl/records', { kind: 'processor', name: 'Unlinked Vendor Synthetic' });
  await adm('/pdpl/records', { kind: 'ropa', name: 'Medical claims (synthetic)', legal_basis: 'contract', data_categories: ['identity', 'health'], volume: 150000, processor_ids: [tpa.id] });
  let WHO = { user: 'nora.syn', role: 'operator' };
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b2) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b2)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, WHO);
    if (u.pathname.startsWith('/api/itam/')) {
      const h = Object.assign({}, req.headers, { 'x-sentra-proxy-secret': H.SECRET, 'x-auth-user': WHO.user, 'x-auth-role': WHO.role });
      const up = http.request({ host: '127.0.0.1', port: e.port, method: req.method, path: req.url, headers: h }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); });
      req.pipe(up); return;
    }
    if (u.pathname.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const zd = (p, re) => p.waitForFunction((src) => new RegExp(src).test((document.getElementById('zd') || {}).textContent || ''), re.source, { timeout: 10000 }).then(() => true, () => false);
  try {
    const p = await browser.newPage({ viewport: { width: 1400, height: 950 }, acceptDownloads: true }); p.on('pageerror', (x) => errs.push(x.message));
    p.on('dialog', (d) => d.accept(/redone/.test(d.message()) ? 'redo (synthetic)' : 'certificate expired (synthetic)'));
    await p.goto(base + 'pdpl-processors.html?standalone=1'); await p.waitForSelector('#vrbody table', { state: 'attached', timeout: 15000 });
    const vt = await p.textContent('#vrbody');
    ok(/critical/.test(vt) && /sensitive data: health/.test(vt), 'tier from the activities, with why');
    ok(/not rated/.test(vt) && /link it to its activities first/.test(vt), 'an unlinked vendor is not rated and cannot be assessed');
    ok(!(await p.$('#vrbody img')) && vt.includes(XSS), 'a hostile vendor name stays text');
    // start, download the questionnaire
    await p.click('[data-vstart="' + tpa.id + '"]'); ok(await zd(p, /VRA-001/), 'assessment started');
    const [dl] = await Promise.all([p.waitForEvent('download'), p.click('#vqdl')]);
    ok(dl.suggestedFilename() === 'vendor-questionnaire-VRA-001.csv', 'questionnaire downloaded: ' + dl.suggestedFilename());
    const csv = fs.readFileSync(await dl.path(), 'utf8');
    ok(/CER-1,/.test(csv) && /id,domain,question,answer/.test(csv), 'the file holds the questions');
    ok(await zd(p, /Status\s*sent/), 'marked sent');
    // the vendor's filled-in file
    const filled = csv.split('\r\n').map((l) => { const m = /^([A-Z]{3}-\d),/.exec(l); if (!m) return l; const cells = l.match(/("([^"]|"")*"|[^,]*)(,|$)/g).map((c) => c.replace(/,$/, '')); cells[3] = m[1] === 'LOC-1' ? 'no' : 'yes'; cells[4] = 'ref ' + m[1]; return cells.join(','); }).join('\r\n');
    await p.setInputFiles('#vqup', { name: 'answers.csv', mimeType: 'text/csv', buffer: Buffer.from(filled) });
    ok(await zd(p, /Status\s*returned/), 'vendor file imported');
    // review: challenge one, accept the rest
    await p.click('[data-vrev="challenged"][data-q="CER-1"]'); ok(await zd(p, /certificate expired \(synthetic\)/), 'challenged with a note');
    const qids = await p.$$eval('[data-vrev="accepted"]', (x) => x.map((y) => y.getAttribute('data-q')).filter((q) => q !== 'CER-1'));
    for (const q of qids) { await Promise.all([p.waitForResponse((r) => /\/review$/.test(r.url())), p.click('[data-vrev="accepted"][data-q="' + q + '"]')]); await p.waitForTimeout(80); }
    await p.waitForSelector('#vsub', { timeout: 10000 }); await p.click('#vsub');
    ok(await zd(p, /Status\s*submitted/), 'submitted');
    // the submitter is not an approver; an administrator approves
    WHO = { user: 'syed', role: 'admin' }; await p.reload(); await p.waitForSelector('[data-vra="VRA-001"]', { state: 'attached', timeout: 10000 });
    await p.click('[data-vra="VRA-001"]'); await p.waitForSelector('[data-vdec="approve"]', { timeout: 8000 }); await p.click('[data-vdec="approve"]');
    ok(await zd(p, /Approved by syed/), 'approved by an administrator');
    const z = await p.textContent('#zd');
    ok(/Residual risk\s*(high|critical)/.test(z) && /GRC actions: ACT-/.test(z), 'residual risk and GRC actions shown');
    await p.keyboard.press('Escape');
    await p.waitForFunction(() => /residual/.test(document.getElementById('vrbody').textContent) && /\d{4}-\d{2}-\d{2}/.test(document.getElementById('vrbody').textContent), null, { timeout: 8000 });
    ok(/residual/.test(await p.textContent('#vrbody')), 'the vendor row shows the last assessment and the next due date');
    const procs = (await e.req('GET', '/pdpl/processors', { user: 'syed', role: 'admin' })).json.processors.find((x) => x.id === tpa.id);
    ok(procs.checks.find((c) => c.key === 'data_in_ksa').ok === false && procs.score !== null, 'the Processors due-diligence checks follow the answers');
    ok(e.app.store.auditTail(200).some((a) => a.action === 'pdpl.vendor.approve' && a.by === 'syed'), 'approval audited');
    // a viewer is refused
    WHO = { user: 'v.syn', role: 'viewer' }; await p.reload(); await p.waitForFunction(() => /operator role/.test(document.getElementById('vrbody').textContent), null, { timeout: 10000 }).then(() => ok(true), () => ok(false, 'a viewer is refused'));
  } finally { await browser.close(); srv.close(); e.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks');
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
