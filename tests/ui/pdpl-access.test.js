// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Access Intelligence (pdpl-access.html) and the insurer fields on Cross-border transfers, stubbed ITAM, SYNTHETIC data:
// KPIs, journal integrity badge, policy hits as filters, exceptions and indicators with review (own-access refusal shown),
// identity view, connect a source (key shown once) and disconnect, settings posted, escaping, empty state that says what
// to connect, operator-only message; the transfer form carries flow / what is sent and the list shows them.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node pdpl-access.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const POSTS = []; let EMPTY = false, DENY = false, OWN = false;
const XSS = '<img src=x onerror=alert(1)>';
const LABELS = { no_purpose: 'sensitive record opened with no purpose', other_no_reason: 'purpose "other" with no reason', investigation_no_case: 'fraud investigation with no case reference', sensitive_export: 'sensitive record exported or printed', delete: 'record deleted' };
const API = { events: 'POST /agent/access/events', auth: 'Authorization: Bearer <access key>', max: 500, actions: ['view', 'export'], purposes: ['claim_handling', 'other'] };
const VIEW = () => EMPTY ? { totals: { events: 0, sensitive: 0, users: 0, exceptions_open: 0, indicators_open: 0 }, labels: LABELS, exceptions: [], indicators: [], users: [], systems: [], keys: [], chain: { ok: true, length: 0 }, api: API, settings: { min_volume: 50, multiplier: 3, export_limit: 20 }, note: 'Behavioural indicators, not proof of wrongdoing.', findings: [] } : {
  totals: { events: 940, sensitive: 410, users: 12, exceptions_open: 3, indicators_open: 1 }, labels: LABELS, chain: { ok: true, length: 940 }, api: API, findings: [],
  settings: { min_volume: 50, multiplier: 3, export_limit: 20 }, note: 'Behavioural indicators, not proof of wrongdoing.',
  exceptions: [{ id: 'AX-7', at: '2026-10-20T07:00:00.000Z', user: 'ali.syn', system: 'Medical claims (synthetic)', record_ref: 'CL-SYN-2', action: 'view', purpose: null, sensitive: true, categories: ['health'], types: ['no_purpose'], status: 'open' },
    { id: 'AX-8', at: '2026-10-20T07:05:00.000Z', user: 'sara.syn', system: 'Fraud (synthetic)', record_ref: 'CL-SYN-4', action: 'view', purpose: 'fraud_investigation', sensitive: true, categories: [], types: ['investigation_no_case'], status: 'open' },
    { id: 'AX-9', at: '2026-10-20T07:06:00.000Z', user: 'sara.syn', system: 'Fraud (synthetic)', record_ref: XSS, action: 'export', purpose: 'medical_review', reason: XSS, sensitive: true, categories: [], types: ['sensitive_export'], status: 'open' },
    { id: 'AX-3', at: '2026-10-18T07:06:00.000Z', user: 'omar.syn', system: 'Claims', record_ref: 'CL-SYN-1', action: 'delete', purpose: 'claim_handling', sensitive: false, categories: [], types: ['delete'], status: 'justified', review: { by: 'nora.syn', note: 'duplicate claim removed' } }],
  indicators: [{ id: '2026-10-20|ali.syn|volume', day: '2026-10-20', user: 'ali.syn', type: 'volume', n: 80, why: '80 records opened; usual day 10 (median of 11 days); threshold 50', status: 'open' }],
  users: [{ user: 'ali.syn', n: 190, sensitive: 120, exports: 0, days: 12 }], systems: [{ name: 'Medical claims (synthetic)', n: 700 }],
  keys: [{ id: 'AK-001', name: 'Medical claims (synthetic)', events: 700, last_used: '2026-10-20T07:00:00.000Z', revoked_at: null }] };
const TRANS = { note: 'Art. 29', questions: [], purposes: [], transfers: [{ id: 'PD-TRANSFER-001', name: 'Motor treaty (synthetic)', country: 'Germany', basis: 'scc', flow_type: 'reinsurance', counterparty: 'Reinsurer A', data_form: 'identified', sensitive: true, large_scale: false, tia: {}, gaps: ['identified sensitive data to a reinsurer without a recorded reason (send pseudonymised or aggregated bordereaux where the treaty allows)'] }] };
(async () => {
  const srv = http.createServer((req, res) => {
    const u = decodeURIComponent(req.url.split('?')[0]), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    const body = (fn) => { let b = ''; req.on('data', (c) => { b += c; }); req.on('end', () => { const j = JSON.parse(b || '{}'); POSTS.push([u, j]); fn(j); }); };
    if (u === '/dashboards/whoami.json' || u === '/auth/whoami') return json(200, { user: 'syed', role: 'admin' });
    if (u === '/api/itam/pdpl/access') return DENY ? json(403, { error: 'requires operator' }) : json(200, VIEW());
    if (u === '/api/itam/pdpl/access/keys') return body((b) => json(200, { id: 'AK-002', name: b.name, key: 'ak_' + 'b2'.repeat(24), note: 'Shown once' }));
    if (u === '/api/itam/pdpl/access/keys/AK-001/revoke') return body(() => json(200, { id: 'AK-001', revoked: true }));
    if (/^\/api\/itam\/pdpl\/access\/exceptions\/AX-\d+\/review$/.test(u)) return body(() => (OWN ? json(403, { error: 'four-eyes: you cannot review your own access' }) : json(200, { id: 'AX-7', status: 'justified' })));
    if (u === '/api/itam/pdpl/access/indicators/review') return body((b) => json(200, { id: b.id }));
    if (u === '/api/itam/pdpl/access/settings') return body((b) => json(200, b));
    if (u === '/api/itam/pdpl/transfers') return json(200, TRANS);
    if (u === '/api/itam/pdpl/records') return req.method === 'GET' ? json(200, { records: [{ id: 'PD-TRANSFER-001', kind: 'transfer', name: 'Motor treaty (synthetic)', flow_type: 'reinsurance' }] }) : body(() => json(200, { id: 'PD-TRANSFER-001' }));
    if (u.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.replace(/^\/dashboards\//, '')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (e, d) => { if (e) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': f.endsWith('.js') ? 'application/javascript' : f.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port;
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch();
  const last = (end) => [...POSTS].reverse().find((x) => x[0].endsWith(end));
  try {
    const p = await browser.newPage(); const errs = []; let dialogs = 0; p.on('pageerror', (e) => errs.push(e.message)); p.on('dialog', (d) => { dialogs++; d.dismiss(); });
    await p.goto(base + '/dashboards/pdpl-access.html?standalone=1'); await p.waitForSelector('#exc table');
    const all = await p.$eval('main', (e) => e.innerText);
    ok(/940/.test(all) && /410/.test(all) && /journal intact · 940 events/.test(all), 'KPIs and journal integrity');
    ok(/not proof of wrongdoing/.test(all), 'indicators-not-proof framing');
    ok(await p.$$eval('main img', (a) => a.length) === 0, 'record ref / reason escaped');
    ok(await p.$$eval('#exc tbody tr', (a) => a.length) === 3, 'open exceptions only by default');
    await p.selectOption('#excst', 'all'); ok(await p.$$eval('#exc tbody tr', (a) => a.length) === 4, 'all exceptions'); await p.selectOption('#excst', 'open');
    await p.click('[data-pol="investigation_no_case"]'); ok(await p.$$eval('#exc tbody tr', (a) => a.length) === 1 && /CL-SYN-4/.test(await p.$eval('#exc', (e) => e.innerText)), 'policy hit filters');
    await p.click('[data-pol="investigation_no_case"]'); ok(await p.$$eval('#exc tbody tr', (a) => a.length) === 3, 'click again clears the filter');
    ok(/median of 11 days/.test(await p.$eval('#ind', (e) => e.innerText)), 'volume indicator with its reason');
    ok(/ali\.syn/.test(await p.$eval('#users', (e) => e.innerText)) && /Medical claims \(synthetic\) 700/.test(await p.$eval('#users', (e) => e.innerText)), 'identity view and sources');
    // review an exception: own-access refusal shown, then accepted
    OWN = true; await p.click('[data-rev="exc"][data-id="AX-7"]'); await p.waitForSelector('#rform');
    await p.selectOption('#rform-decision', 'justified'); await p.fill('#rform-note', 'open claim CL-SYN-2 assigned to ali'); await p.click('#rform button[type=submit]'); await p.waitForTimeout(400);
    ok(/own access/.test(await p.$eval('#rform [data-msg]', (e) => e.textContent)), 'own-access refusal shown');
    OWN = false; await p.click('#rform button[type=submit]'); await p.waitForTimeout(400);
    let x = last('/exceptions/AX-7/review'); ok(x && x[1].decision === 'justified' && x[1].note === 'open claim CL-SYN-2 assigned to ali', 'exception review posted');
    await p.click('[data-rev="ind"]'); await p.waitForSelector('#rform'); await p.selectOption('#rform-decision', 'escalated'); await p.fill('#rform-note', 'no backlog that day; refer to policy'); await p.click('#rform button[type=submit]'); await p.waitForTimeout(400);
    x = last('/indicators/review'); ok(x && x[1].id === '2026-10-20|ali.syn|volume' && x[1].decision === 'escalated', 'indicator review posted');
    // sources
    await p.fill('#kname', 'Fraud system (synthetic)'); await p.click('#kissue'); await p.waitForSelector('#knewkey');
    ok(/^ak_/.test(await p.$eval('#knewkey', (e) => e.textContent)) && last('/access/keys')[1].name === 'Fraud system (synthetic)', 'source connected, key shown once');
    await p.click('[data-krevoke="AK-001"]'); await p.waitForTimeout(300); ok(POSTS.some((y) => /AK-001\/revoke$/.test(y[0])), 'disconnect posted');
    await p.fill('#sform-min_volume', '80'); await p.click('#sform button[type=submit]'); await p.waitForTimeout(300);
    x = last('/access/settings'); ok(x && x[1].min_volume === 80 && x[1].multiplier === 3, 'settings posted');
    // empty: says what to connect, never invents rows
    EMPTY = true; await p.click('#refresh'); await p.waitForTimeout(400);
    ok(/No connected source yet/.test(await p.$eval('#exc', (e) => e.innerText)), 'empty state says what to connect');
    DENY = true; const p2 = await browser.newPage(); p2.on('pageerror', (e) => errs.push(e.message));
    await p2.goto(base + '/dashboards/pdpl-access.html?standalone=1'); await p2.waitForFunction(() => /operator role/.test(document.getElementById('exc').innerText)); ok(true, 'operator-only message');
    // transfers: flow fields
    await p.goto(base + '/dashboards/pdpl-transfers.html?standalone=1'); await p.waitForSelector('#list table');
    const lt = await p.$eval('#list', (e) => e.innerText); ok(/reinsurance/.test(lt) && /identified/.test(lt) && /reinsurer without a recorded reason/.test(lt), 'flow, data form and the gap listed');
    await p.click('#add'); await p.waitForSelector('#nform');
    await p.fill('#nform-name', 'Treatment abroad (synthetic)'); await p.fill('#nform-country', 'Jordan'); await p.selectOption('#nform-flow_type', 'medical_abroad'); await p.selectOption('#nform-data_form', 'identified');
    await p.click('#nform button[type=submit]'); await p.waitForTimeout(400);
    x = last('/pdpl/records'); ok(x && x[1].flow_type === 'medical_abroad' && x[1].data_form === 'identified' && x[1].kind === 'transfer', 'transfer with flow posted: ' + JSON.stringify(x && x[1]));
    ok(!errs.length, 'no page errors: ' + errs.join(' | ')); ok(!dialogs, 'no browser dialogs');
  } finally { await browser.close(); srv.close(); }
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})();
