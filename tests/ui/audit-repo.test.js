// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for the Audit Repository (dashboards/server/audit-repo.html + vendor/zyb-arepo.js) against the REAL ITAM engine
// (engine/audit-repo.js) with SYNTHETIC audits: the empty state says what to record; a SAMA report recorded through the drawer, its
// file attached (and downloaded), its management letter imported from Excel (checked first, mapping shown, then imported); the year x
// body matrix filters the findings; a repeat proposal confirmed with a note; closing a finding without evidence refused with the
// reason, with evidence accepted; a hostile title stays text; Excel export; a viewer refused without a broken page; menu + installer.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node audit-repo.test.js
const http = require('http'), fs = require('fs'), os = require('os'), path = require('path'), vm = require('vm');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror="window.__xss=1">';
const OP = { user: 'nora.syn', role: 'operator' }, VIEW = { user: 'vera.syn', role: 'viewer' };
const XL = (() => { const w = { TextEncoder, Blob }; w.window = w; vm.runInNewContext(fs.readFileSync(path.join(DASH, 'vendor', 'zyb-xlsx.js'), 'utf8'), w); return w.zybXlsx; })();

(async () => {
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true });
  const api = async (m, p, body) => { const r = await e.req(m, p, Object.assign(body !== undefined ? { body } : {}, OP)); if (r.status !== 200) throw new Error(p + ': ' + r.raw); return r.json; };
  const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'arepo-'));
  const PDF = path.join(TMP, 'SAMA-inspection-2025.pdf'); fs.writeFileSync(PDF, '%PDF-1.4\n% synthetic\n%%EOF\n');
  const LETTER = path.join(TMP, 'management-letter-2025.xlsx');
  fs.writeFileSync(LETTER, Buffer.from(await XL.build([{ name: 'Findings', columns: ['Ref', 'Observation', 'Details', 'Domain', 'Risk Rating', 'Owner', 'Target Date', 'Status'].map((h) => ({ h })), rows: [
    ['S25-01', 'Periodic user access review for the core insurance system was not performed', 'User access rights were not reviewed', 'Access management', 'High', 'it.ops.syn', '2025-12-31', 'Open'],
    ['S25-02', XSS, 'hostile title (synthetic)', 'Logging', 'Low', 'soc.syn', '2026-12-31', 'Open']] }], { title: 'synthetic' }).arrayBuffer()));
  let WHO = OP;
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
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg, { timeout: 10000 }).then(() => true, () => false);
  const zd = (p, re) => wait(p, (src) => new RegExp(src, 'i').test((document.getElementById('zd') || {}).textContent || ''), re.source);
  try {
    const p = await browser.newPage({ viewport: { width: 1400, height: 950 }, acceptDownloads: true }); p.on('pageerror', (x) => errs.push(x.message));
    p.on('dialog', (d) => { errs.push('dialog: ' + d.message()); d.dismiss(); });
    await p.goto(base + 'audit-repo.html?standalone=1');
    ok(await wait(p, () => !document.getElementById('main').hidden && /No audit recorded yet/.test(document.getElementById('acts').textContent)), 'the empty state says what to record');
    // an earlier year through the API, so there is something to repeat
    const r24 = await api('POST', '/audit-repo/reports', { year: 2024, body: 'sama', kind: 'inspection', title: 'SAMA inspection 2024 (synthetic)', auditor: 'SAMA team (synthetic)', issued: '2024-06-30' });
    await api('POST', '/audit-repo/reports/' + r24.id + '/findings', { ref: 'S24-01', title: 'User access reviews not performed for the core insurance system', condition: 'No periodic review of user access rights', area: 'Access management', rating: 'high', owner: 'it.ops.syn', due: '2024-12-31' });
    // record the 2025 report through the drawer
    await p.click('#new'); await p.waitForSelector('#rpf');
    await p.fill('#rpf-year', '2025'); await p.selectOption('#rpf-body', 'sama'); await p.selectOption('#rpf-kind', 'inspection'); await p.fill('#rpf-title', 'SAMA cyber security inspection 2025 (synthetic)'); await p.fill('#rpf-auditor', 'SAMA inspection team (synthetic)'); await p.fill('#rpf-issued', '2025-07-15');
    await p.click('#rpf button[type=submit]');
    ok(await zd(p, /SAMA cyber security inspection 2025/) && await zd(p, /No file yet/), 'report recorded, its drawer opens');
    // the file
    await p.setInputFiles('#upfile', PDF);
    ok(await zd(p, /SAMA-inspection-2025\.pdf/) && await zd(p, /sha256 [0-9a-f]{12}/), 'file attached with its hash');
    const [dl] = await Promise.all([p.waitForEvent('download'), p.click('[data-dl]')]); ok(dl.suggestedFilename() === 'SAMA-inspection-2025.pdf', 'file downloads');
    // the management letter from Excel: checked first, mapping shown, then imported
    await p.setInputFiles('#impfile', LETTER);
    ok(await wait(p, () => /2 finding\(s\) read/.test((document.getElementById('impres') || {}).textContent || '') && /title ← "Observation"/.test(document.getElementById('impres').textContent) && !!document.getElementById('impgo')), 'the import is checked first and shows the column mapping');
    await p.click('#impgo');
    ok(await zd(p, /Findings \(2\)/), 'two findings imported');
    ok(await p.evaluate(() => !window.__xss) && /<img/.test(await p.textContent('#zd')), 'a hostile title stays text');
    await p.evaluate(() => window.zybDetail.close());
    // overview: actions, matrix, proposals
    ok(await wait(p, () => /looks like an earlier year/i.test(document.getElementById('acts').textContent) || /repeat/i.test(document.getElementById('acts').textContent)), 'actions list the repeat proposals');
    ok(await wait(p, () => document.querySelectorAll('#hm [data-cell]').length === 2), 'the matrix has SAMA 2024 and 2025');
    ok(await wait(p, () => /looks like/.test(document.getElementById('props').textContent) && /S24|ARF-00001/.test(document.getElementById('props').textContent)), 'a repeat is proposed with its reasons');
    ok(/same area/.test(await p.textContent('#props')), 'the reasons are itemised');
    await p.click('#props [data-rep="confirm"]'); await p.waitForSelector('#rdf');
    await p.fill('#rdf-note', 'the 2024 review process was never put in place (synthetic)'); await p.click('#rdf button[type=submit]');
    ok(await wait(p, () => /Confirmed repeats/i.test(document.getElementById('kpis').textContent) && /^1/.test(document.querySelector('[data-f="repeat"] .au-num').textContent)), 'the repeat is confirmed');
    await p.evaluate(() => window.zybDetail.close());
    // the matrix filters the findings
    await p.click('[data-cell="sama|2025"]');
    ok(await wait(p, () => !document.getElementById('t-fd').hidden && document.querySelectorAll('#fl tr[data-fid]').length === 2), 'a matrix cell filters to that year and body');
    ok(/repeat of/.test(await p.textContent('#fl')), 'the repeat is marked in the list');
    // a finding: closing needs evidence
    const fid = await p.$eval('#fl tr[data-fid]', (r) => r.getAttribute('data-fid'));
    await p.click('#fl tr[data-fid="' + fid + '"] td:nth-child(3)'); await p.waitForSelector('#upf');
    await p.selectOption('#upf-status', 'closed'); await p.fill('#upf-note', 'review done (synthetic)'); await p.click('#upf button[type=submit]');
    ok(await wait(p, () => /evidence: closing a finding needs/.test(document.querySelector('#upf [data-msg]').textContent)), 'closing without evidence is refused with the reason');
    await p.fill('#upf-evidence', 'access review sign-off 2026-01 (synthetic)'); await p.click('#upf button[type=submit]');
    ok(await zd(p, /status open -> closed/), 'closed with evidence, written to its history');
    await p.evaluate(() => window.zybDetail.close());
    // the KPI tiles filter
    await p.click('[data-f="open"]'); ok(await wait(p, () => document.querySelectorAll('#fl tr[data-fid]').length >= 1 && /filter: open/.test(document.getElementById('fnote').textContent)), 'a KPI tile filters the findings');
    // Excel export
    const [x] = await Promise.all([p.waitForEvent('download'), p.click('#xlsx')]); ok(/^audit-repository-\d{4}-\d\d-\d\d\.xlsx$/.test(x.suggestedFilename()), 'Excel export: ' + x.suggestedFilename());
    ok(e.app.store.auditTail(300).some((a) => a.action === 'audit-repo.file.download') && e.app.store.auditTail(300).some((a) => a.action === 'audit-repo.export'), 'download and export recorded');
    // a viewer
    WHO = VIEW; await p.reload(); await p.waitForTimeout(1200);
    ok(await p.$eval('#main', (m) => m.hidden) && /operator|403|not loaded/i.test(await p.textContent('body')), 'a viewer is refused and the page says why');
    const nav = fs.readFileSync(path.join(DASH, 'vendor', 'zyb-nav.js'), 'utf8'), inst = fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8');
    ok(/"h": "audit-repo\.html"/.test(nav) && / audit-repo\.html /.test(inst) && /vendor\/zyb-arepo\.js/.test(inst), 'menu entry and installer');
  } finally { await browser.close(); srv.close(); await e.close(); fs.rmSync(TMP, { recursive: true, force: true }); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks');
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
