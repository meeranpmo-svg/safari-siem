// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Data Catalog (pdpl-catalog.html) and "Find this person" on Data subject requests (pdpl-dsar.html), stubbed ITAM,
// SYNTHETIC data: KPIs, attributes as filters, sources with a failed read, coverage of databases not scanned, suggested
// identifiers confirmed (admin), identifier picked / removed on a column, Scan now posted, escaping, empty state that says
// what to connect; the search form only for a verified open request, posts the type and value, clears the box, shows
// counts per system, refusal shown. Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node pdpl-catalog.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const POSTS = []; let EMPTY = false, ROLE = 'admin', VERIFIED = true, COR409 = false;
const XSS = '<img src=x onerror=alert(1)>';
const COL = (db, src, eng, t, c, kind, attr, cat, sens, conf, id) => ({ id: db + '|dbo|' + t + '|' + c, db, source: src, engine: eng, owner: 'dbo', table: t, column: c, type: 'varchar', rows: 300, kind, attribute: attr, category: cat, sensitive: sens, by: 'name', confirmed: conf, sampled: conf ? 50 : undefined, matched: conf ? 50 : undefined, identifier: id || null });
const CAT = () => EMPTY ? { totals: { sources: 0, columns: 0, attributes: 0, sensitive_columns: 0 }, attributes: [], sources: [], columns: [], columns_total: 0, suggestions: [], id_types: [['national_id', 'National ID']], identifiers: [], coverage: { targets: 0, scanned: 0, failed: 0, not_scanned: [] }, last: null, note: 'n' } : {
  totals: { sources: 4, columns: 3, attributes: 2, sensitive_columns: 1, files: 3, exposed_files: 2 }, last: { at: '2026-10-20T07:00:00Z', by: 'syed' }, note: 'No personal data value is stored or shown.',
  attributes: [{ kind: 'health', attribute: 'Health / diagnosis', category: 'health', sensitive: true, sources: 1, columns: 1 }, { kind: 'national_id', attribute: 'National ID', category: 'identity', sensitive: false, sources: 2, columns: 2 }],
  sources: [{ db: 'sp:s1', label: 'Claims Team (synthetic)', engine: 'sharepoint', host: 'https://syn.sharepoint.com/sites/claims', at: '2026-10-20T07:00:00Z', ok: true, columns: 0, tables: 0, files: 2, files_seen: 120, categories: ['identity'], sensitive: [], identifiers: 0, exposure: { anonymous: 1, external: 0, everyone: 0, organization: 1 } },
    { db: 'mssql|10.8.0.52|1433', label: 'CLAIMS-SQL', engine: 'mssql', host: '10.8.0.52', at: '2026-10-20T07:00:00Z', ok: true, columns: 2, tables: 2, categories: ['health', 'identity'], sensitive: ['health'], identifiers: 1, probe_denied: 1 },
    { db: 'postgres|10.8.0.53|5432', label: XSS, engine: 'postgres', host: '10.8.0.53', at: '2026-10-20T07:00:00Z', ok: true, columns: 1, tables: 1, categories: ['identity'], sensitive: [], identifiers: 0 },
    { db: 'oracle|10.8.0.51|1521', label: 'CORE-ORA', engine: 'oracle', host: '10.8.0.51', ok: false, error: 'unsafe: login can write', columns: 0, tables: 0, categories: [], sensitive: [], identifiers: 0 }],
  columns: [COL('mssql|10.8.0.52|1433', 'CLAIMS-SQL', 'mssql', 'Members', 'NationalId', 'national_id', 'National ID', 'identity', false, true, 'national_id'), COL('mssql|10.8.0.52|1433', 'CLAIMS-SQL', 'mssql', 'Claims', 'DiagCode', 'health', 'Health / diagnosis', 'health', true, null),
    COL('postgres|10.8.0.53|5432', 'CRM-PG', 'postgres', 'customers', 'national_id', 'national_id', 'National ID', 'identity', false, true)], columns_total: 3,
  suggestions: [{ id: 'postgres|10.8.0.53|5432|dbo|customers|national_id', source: 'CRM-PG', table: 'dbo.customers', column: 'national_id', id_type: 'national_id', confirmed: true }],
  id_types: [['national_id', 'National ID'], ['mobile', 'Mobile number']], identifiers: [], coverage: { targets: 4, scanned: 2, failed: 1, not_scanned: [{ key: 'mssql|10.8.0.60|1433', engine: 'mssql', host: 'HR-SQL' }] },
  files: [{ id: 'sp:s1|f1', db: 'sp:s1', source: 'Claims Team (synthetic)', engine: 'sharepoint', name: 'claims-register.docx', path: '/Claims', kinds: { national_id: 40 }, name_kinds: [], by: 'content', attributes: ['National ID'], sensitive: false, exposure: 'anonymous', modified: '2026-10-01T00:00:00Z' },
    { id: 'fs:fs1:D|x', db: 'fs:fs1:D', source: '\\\\fs-syn-01\\HR', engine: 'fileshare', name: XSS, path: 'Payroll', kinds: { iban: 12 }, name_kinds: ['salary'], by: 'content', attributes: ['IBAN / bank account', 'Salary / income'], sensitive: false, exposure: 'everyone' },
    { id: 'sp:s1|f2', db: 'sp:s1', source: 'Claims Team (synthetic)', engine: 'sharepoint', name: 'Passport_scan.pdf', path: '/', kinds: {}, name_kinds: ['passport'], by: 'name', attributes: ['Passport number'], sensitive: false, exposure: 'organization' }], files_total: 3,
  file_status: { linked: true, file_servers: 0, sharepoint: { at: '2026-10-20T07:00:00Z', never: false, errors: ['verified domains: Organization.Read.All not granted - outside recipients cannot be told apart'], running: true, progress: 'SharePoint: Claims Team', last_error: '' } } };
const REQ = () => ({ id: 'PD-DSR-001', ref: 'DSR-SYN-77', type: 'access', channel: 'branch', received: '2026-10-19', stage: 'in_progress', due: '2026-11-18', days_left: 29, overdue: false, identity_verified: VERIFIED, identity_method: 'national_id_in_branch',
  tasks: [{ system: 'CRM-PG', status: 'open', note: 'found by identity search: 2 row(s) in 1 table(s)' }], blockers: [], can_respond: false,
  correlation: [{ at: '2026-10-20T07:30:00Z', by: 'nora.syn', id_type: 'national_id', searched: 2, found_in: ['CRM-PG'], failed: 1, systems: [{ system: 'CRM-PG', ok: true, rows: 2, tables: ['crm.customers'] }, { system: 'CLAIMS-SQL', ok: false, error: 'timeout', rows: 0, tables: [] }] }] });
const DSAR = () => ({ open: 1, overdue: 0, due_7d: 0, note: 'n', refusal_grounds: { legal: 'law' }, types: {}, channels: ['branch'], methods: ['national_id_in_branch'], systems: [], requests: [REQ()] });
(async () => {
  const srv = http.createServer((req, res) => {
    const u = decodeURIComponent(req.url.split('?')[0]), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    const body = (fn) => { let b = ''; req.on('data', (c) => { b += c; }); req.on('end', () => { const j = JSON.parse(b || '{}'); POSTS.push([u, j]); fn(j); }); };
    if (u === '/dashboards/whoami.json' || u === '/auth/whoami') return json(200, { user: 'syed', role: ROLE });
    if (u === '/api/itam/pdpl/catalog') return json(200, CAT());
    if (u === '/api/itam/pdpl/catalog/identifiers') return body((b) => json(200, { id: b.column_id }));
    if (u === '/api/itam/pdpl/discovery/run') return body(() => json(200, { at: 'x', databases: [{}, {}] }));
    if (u === '/api/itam/pdpl/dsar') return json(200, DSAR());
    if (u === '/api/itam/pdpl/records') return json(200, { records: [] });
    if (u === '/api/itam/pdpl/dsar/PD-DSR-001/correlate') return body(() => (COR409 ? json(409, { error: 'no identifier column of type mobile is confirmed in the catalog' }) : json(200, { searched: 2, found_in: ['CRM-PG'], tasks_added: [], failed: 1, systems: [] })));
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
    await p.goto(base + '/dashboards/pdpl-catalog.html?standalone=1'); await p.waitForSelector('#cols table'); await p.waitForTimeout(300);
    const all = await p.$eval('main', (e) => e.innerText);
    ok(/Columns with personal data/i.test(all) && /National ID/.test(all) && /Health \/ diagnosis/.test(all), 'KPIs and attributes');
    ok(/Files with personal data/i.test(all) && /2 read · 1 failed · 4 with a read-only login/.test(all) && /unsafe: login can write/.test(all) && /HR-SQL \(mssql\)/.test(all), 'sources, failure and coverage');
    ok(/may not read - named only/.test(all), 'tables the login may not read are said so');
    ok(await p.$$eval('main img', (a) => a.length) === 0, 'source label escaped');
    ok(!(await p.$eval('#scan', (e) => e.hidden)), 'Scan now for an administrator');
    ok(await p.$$eval('#cols tbody tr', (a) => a.length) === 3, 'all columns');
    ok(await p.$$eval('#files img', (a) => a.length) === 0, 'file name escaped');
    await p.click('[data-attr="health"]'); ok(await p.$$eval('#cols tbody tr', (a) => a.length) === 1, 'attribute filters the columns');
    await p.click('[data-attr="health"]'); await p.selectOption('#fsrc', 'mssql|10.8.0.52|1433'); ok(await p.$$eval('#cols tbody tr', (a) => a.length) === 2, 'source filter');
    await p.selectOption('#fsrc', ''); await p.fill('#fq', 'customers'); ok(await p.$$eval('#cols tbody tr', (a) => a.length) === 1, 'search filter'); await p.fill('#fq', '');
    // files
    const ft = await p.$eval('#files', (e) => e.innerText);
    ok(/claims-register\.docx/.test(ft) && /anonymous link/.test(ft) && /everyone can read/.test(ft) && /by file name only/.test(ft) && /national id x40/.test(ft), 'files with what they hold and their exposure');
    ok(/1 anonymous link/.test(await p.$eval('#sources', (e) => e.innerText)) && /120 looked at/.test(await p.$eval('#sources', (e) => e.innerText)), 'SharePoint source with its exposure');
    ok(/files: not searched by identifier/.test(await p.$eval('#sources', (e) => e.innerText)), 'files are not offered for the identity search');
    const fsu = await p.$eval('#filesetup', (e) => e.innerText);
    ok(/SharePoint scan running/.test(fsu) && /Organization\.Read\.All not granted/.test(fsu) && /FileScanPaths/.test(fsu), 'setup / status messages: running, missing permission, how to turn on file shares');
    await p.selectOption('#fexp', 'exposed'); ok(await p.$$eval('#files tbody tr', (a) => a.length) === 2, 'exposure filter');
    await p.selectOption('#fexp', 'everyone'); ok(await p.$$eval('#files tbody tr', (a) => a.length) === 1, 'readable by everyone');
    await p.selectOption('#fexp', ''); await p.selectOption('#fsrc2', 'sp:s1'); ok(await p.$$eval('#files tbody tr', (a) => a.length) === 2, 'file source filter'); await p.selectOption('#fsrc2', '');
    await p.click('[data-attr="national_id"]'); ok(await p.$$eval('#files tbody tr', (a) => a.length) === 1, 'attribute filters the files too'); await p.click('[data-attr="national_id"]');
    await p.click('[data-setid]'); await p.waitForTimeout(300);
    let x = last('/catalog/identifiers'); ok(x && x[1].column_id === 'postgres|10.8.0.53|5432|dbo|customers|national_id' && x[1].id_type === 'national_id', 'suggestion confirmed');
    await p.selectOption('[data-pick="postgres|10.8.0.53|5432|dbo|customers|national_id"]', 'mobile'); await p.waitForTimeout(300);
    x = last('/catalog/identifiers'); ok(x && x[1].id_type === 'mobile', 'identifier picked on a column');
    await p.click('[data-rmid]'); await p.waitForTimeout(300); x = last('/catalog/identifiers'); ok(x && x[1].remove === true, 'identifier removed');
    await p.click('#scan'); await p.waitForTimeout(300); ok(!!last('/discovery/run'), 'scan posted');
    EMPTY = true; await p.click('#refresh'); await p.waitForTimeout(400);
    ok(/No database scanned yet/.test(await p.$eval('#sources', (e) => e.innerText)) && /Connections & Setup/.test(await p.$eval('#sources', (e) => e.innerText)), 'empty state says what to connect');
    // an operator: no admin controls
    ROLE = 'operator'; EMPTY = false; const p2 = await browser.newPage(); p2.on('pageerror', (e) => errs.push(e.message));
    await p2.goto(base + '/dashboards/pdpl-catalog.html?standalone=1'); await p2.waitForSelector('#cols table'); await p2.waitForTimeout(300);
    ok(await p2.$eval('#scan', (e) => e.hidden) && await p2.$$eval('[data-pick],[data-setid],[data-rmid]', (a) => a.length) === 0, 'operator sees no admin controls');
    // DSAR: find this person
    await p.goto(base + '/dashboards/pdpl-dsar.html?standalone=1'); await p.waitForSelector('#list table');
    await p.click('#list tr[data-id="PD-DSR-001"]'); await p.waitForSelector('#cform');
    const dr = await p.$eval('#zd-b', (e) => e.innerText);
    ok(/CRM-PG: 2 row\(s\) in 1 table\(s\)/.test(dr) && /not read: timeout/.test(dr) && /not stored or logged/.test(dr), 'search history with counts and the failed source');
    ok(await p.$eval('#c-value', (e) => e.getAttribute('autocomplete')) === 'off', 'the identifier box does not remember values');
    await p.selectOption('#c-type', 'national_id'); await p.fill('#c-value', '1012345678'); await p.click('#cform button[type=submit]'); await p.waitForTimeout(500);
    x = last('/correlate'); ok(x && x[1].id_type === 'national_id' && x[1].value === '1012345678', 'search posted');
    await p.waitForSelector('#cform'); ok(await p.$eval('#c-value', (e) => e.value) === '', 'the box is cleared after the search');
    COR409 = true; await p.selectOption('#c-type', 'mobile'); await p.fill('#c-value', '0551234567'); await p.click('#cform button[type=submit]'); await p.waitForTimeout(400);
    ok(/no identifier column of type mobile/.test(await p.$eval('#cform [data-msg]', (e) => e.textContent)), 'refusal shown');
    VERIFIED = false; await p.reload(); await p.waitForSelector('#list table'); await p.click('#list tr[data-id="PD-DSR-001"]'); await p.waitForTimeout(400);
    ok(await p.$$eval('#cform', (a) => a.length) === 0 && /Verify the requester/.test(await p.$eval('#zd-b', (e) => e.innerText)), 'no search before identity is verified');
    ok(!errs.length, 'no page errors: ' + errs.join(' | ')); ok(!dialogs, 'no browser dialogs');
  } finally { await browser.close(); srv.close(); }
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})();
