// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Records of Processing (pdpl-ropa.html) - the data map card, stubbed ITAM, SYNTHETIC data: coverage KPIs, gaps with evidence and fix,
// the map (click an activity highlights its systems; an unmapped system is marked), risk per activity itemised, a suggested activity
// opens the form pre-filled (no legal basis invented) and saving posts it; escaping; discovery not connected is said; the card
// survives /pdpl/data-map failing.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node pdpl-datamap.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const POSTS = []; let FAIL = false, NODISC = false;
const XSS = '<img src=x onerror=alert(1)>';
const ROPA = { total: 1, complete: 0, note: 'synthetic', activities: [{ id: 'PD-ROPA-001', name: 'Claims handling', owner: 'Claims', completeness: 70, legal_basis: 'contract', dpia: 'missing', sensitive: ['health'], sensitive_controls: false, transfers: [], retention_rule: [], recipients: [], reviewed: '2026-06-01', review_due: false, missing: ['retention'], dpia_needed_for: ['health'], consent_purposes: [] }] };
const DMAP = () => ({ generated_at: '2026-11-19T08:00:00Z', coverage: { systems_with_personal_data: 3, mapped: 2, pct: 67 }, counts: { unmapped: 1, transfer: 1, dpia: 1, 'under-declared': 1 },
  activities: [{ id: 'PD-ROPA-001', name: 'Claims handling', declared: ['identity'], found: ['identity', 'health'], systems: [{ id: 'm365:claims', label: 'Claims Site', type: 'sharepoint' }, { id: 'cloud:aws:exp', label: 'claims-exports', type: 'cloud:aws', in_kingdom: false }], unknown_systems: ['LEGACY-CLAIMS'], processors: [], transfers: [], dpia: false, risk: 57, risk_items: [{ points: 20, label: 'personal data leaves the Kingdom with no transfer record' }, { points: 13, label: 'its systems hold health - not declared' }] }],
  systems: [{ id: 'm365:claims', label: 'Claims Site', type: 'sharepoint', cats: ['identity', 'health'], files: 40, mapped: true }, { id: 'cloud:aws:exp', label: 'claims-exports', type: 'cloud:aws', cats: ['financial'], files: 5, in_kingdom: false, public: true, mapped: true }, { id: 'fs:srv1:hr', label: 'HR share ' + XSS, type: 'fileshare', cats: ['financial'], files: 9, mapped: false }],
  processors: [{ id: 'PD-PROCESSOR-001', name: 'Offshore TPA (synthetic)', outside_ksa: true }], countries: ['Germany'],
  findings: [{ type: 'transfer', severity: 'high', activity: { id: 'PD-ROPA-001', name: 'Claims handling' }, system: 'claims-exports', why: 'personal data goes outside the Kingdom ' + XSS, fix: 'record the transfer' },
    { type: 'unmapped', severity: 'medium', activity: null, system: 'HR share', why: 'HR share holds financial (9 item(s)) and no processing activity names it', fix: 'add it to the activity that uses it' }],
  suggestions: [{ system: 'HR share', system_id: 'fs:srv1:hr', type: 'fileshare', draft: { name: 'Processing in HR share', systems: ['HR share'], data_categories: ['financial'], transfer_outside: false }, why: 'the purpose, legal basis and retention are for the steward to state' }],
  discovery: NODISC ? { measured: false } : { measured: true }, note: 'A suggestion is a proposal.' });
(async () => {
  const srv = http.createServer((req, res) => {
    const u = decodeURIComponent(req.url.split('?')[0]), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u === '/dashboards/whoami.json' || u === '/auth/whoami') return json(200, { user: 'huda.syn', role: 'operator' });
    if (u === '/api/itam/pdpl/ropa') return json(200, ROPA);
    if (u === '/api/itam/pdpl/data-map') return FAIL ? json(500, { error: 'internal error', ref: 'E-1' }) : json(200, DMAP());
    if (u === '/api/itam/pdpl/records' && req.method === 'GET') return json(200, { records: [] });
    if (u === '/api/itam/pdpl/records') { let b = ''; req.on('data', (c) => { b += c; }); return req.on('end', () => { POSTS.push(JSON.parse(b)); json(200, { id: 'PD-ROPA-002' }); }); }
    if (u.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.replace(/^\/dashboards\//, '')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (e, d) => { if (e) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': f.endsWith('.js') ? 'application/javascript' : f.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port;
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch();
  try {
    const p = await browser.newPage(); const errs = []; let dialogs = 0; p.on('pageerror', (e) => errs.push(e.message)); p.on('dialog', (d) => { dialogs++; d.dismiss(); });
    await p.goto(base + '/dashboards/pdpl-ropa.html?standalone=1'); await p.waitForSelector('#dmkpi .au-num, #dmkpi div');
    await p.waitForFunction(() => /67 %/.test(document.getElementById('dmkpi').textContent));
    const kpi = await p.textContent('#dmkpi'); ok(/2 \/ 3/.test(kpi), 'mapped systems KPI: ' + kpi); ok(/Transfer \/ DPIA gaps/.test(kpi), 'gap KPI');
    const gaps = await p.textContent('#dm'); ok(/Transfer gap/.test(gaps) && /Not in the register/.test(gaps), 'gaps listed'); ok(/record the transfer/.test(gaps), 'fix shown');
    ok(await p.$$eval('#dm img', (x) => x.length) === 0 && gaps.includes('<img'), 'evidence escaped');
    await p.click('#dm tr[data-act="PD-ROPA-001"]'); await p.waitForSelector('#rform'); ok(true, 'gap row opens the activity');
    await p.keyboard.press('Escape'); await p.evaluate(() => { const c = document.querySelector('[data-zyb-close], .zyb-detail .btn-close'); if (c) c.click(); });
    await p.click('#dmtabs [data-dt="map"]'); const map = await p.textContent('#dm');
    ok(/Processing activities \(1\)/.test(map) && /Systems \(3\)/.test(map), 'map columns'); ok(/Germany/.test(map) && /processor outside KSA/.test(map) && /stored abroad/.test(map), 'outside the Kingdom column');
    ok(await p.$$eval('#dm [data-node="fs:srv1:hr"].bad', (x) => x.length) === 1, 'unmapped system marked'); ok(await p.$$eval('#dm img', (x) => x.length) === 0, 'map escaped');
    await p.click('#dm [data-node="PD-ROPA-001"]'); const hl = await p.$$eval('#dm .nd.hl', (x) => x.map((e) => e.getAttribute('data-node')).sort());
    ok(JSON.stringify(hl) === JSON.stringify(['PD-ROPA-001', 'cloud:aws:exp', 'm365:claims']), 'click highlights linked systems: ' + hl);
    await p.click('#dmtabs [data-dt="risk"]'); const risk = await p.textContent('#dm'); ok(/57/.test(risk) && /\+20 personal data leaves the Kingdom/.test(risk), 'risk itemised'); ok(/unknown: LEGACY-CLAIMS/.test(risk), 'unknown system shown');
    await p.click('#dmtabs [data-dt="drafts"]'); ok(/legal basis and retention are for the steward/.test(await p.textContent('#dm')), 'draft says what discovery cannot know');
    await p.click('#dm [data-draft="0"]'); await p.waitForSelector('#rform');
    const pre = await p.evaluate(() => { const f = document.getElementById('rform'), v = (n) => { const e = f.querySelector('[name="' + n + '"]'); return e ? e.value : null; }; return { name: v('name'), basis: v('legal_basis'), systems: v('systems') }; });
    ok(pre.name === 'Processing in HR share', 'form pre-filled with the draft name: ' + JSON.stringify(pre)); ok(!pre.basis, 'no legal basis invented'); ok(/HR share/.test(pre.systems || ''), 'systems pre-filled');
    await p.evaluate(() => document.getElementById('rform').requestSubmit()); await p.waitForFunction(() => true); await new Promise((r) => setTimeout(r, 400));
    ok(POSTS.length === 1 && POSTS[0].kind === 'ropa' && POSTS[0].name === 'Processing in HR share' && !POSTS[0].id, 'saving posts a new activity: ' + JSON.stringify(POSTS[0]));
    ok(/A suggestion is a proposal/.test(await p.textContent('#dmnote')), 'note shown');
    NODISC = true; await p.click('#refresh'); await p.waitForFunction(() => /No discovery source/.test(document.getElementById('dmnote').textContent)); ok(true, 'discovery not connected is said');
    FAIL = true; await p.click('#refresh'); await new Promise((r) => setTimeout(r, 600)); ok(/Processing activities/.test(await p.textContent('#list').catch(() => '')) || (await p.textContent('#list')).length > 0, 'register still shown when the data map fails');
    ok((await p.textContent('#dm')).trim().length > 0, 'data map card not blank on failure');
    ok(!errs.length, 'no page errors: ' + errs.join('; ')); ok(dialogs === 0, 'no alert ran');
  } finally { await browser.close(); srv.close(); }
  console.log((bad ? 'pdpl-datamap: FAIL ' : 'pdpl-datamap: OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})();
