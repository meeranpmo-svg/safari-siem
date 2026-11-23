// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Workflow Automation (workflow-automation.html) against the REAL engine (engine/workflow-auto.js) with SYNTHETIC people and records:
// an administrator sets who is who; an auditor describes a need, the ML suggestion picks the request type, the request is sent; the
// DBA sees it in the team queue, takes it, collects evidence from the platform (a password field in the record never shows), fulfils
// it through the in-page dialog; the auditor accepts it; HR's leaver request waits for the identity lead, who approves it; an
// administrator schedules a recurring request; a hostile title stays text; no browser dialog, no page error.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node workflow-automation.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
(async () => {
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3' });
  e.app.store.collection('db_inventory').put({ id: 'db1', name: 'CLAIMS-SYN', host: 'dbsrv01.synthetic.test', version: '19c', password: 'Synthetic-DB-Secret-1', status: 'up', updated_at: '2026-11-12T10:00:00Z' });
  let WHO = { user: 'syed', role: 'admin' };
  const srv = http.createServer((req, res) => {
    const u2 = new URL(req.url, 'http://x'), json = (c, b2) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b2)); };
    if (u2.pathname === '/dashboards/whoami.json' || u2.pathname === '/auth/whoami') return json(200, WHO);
    if (u2.pathname.startsWith('/api/itam/')) {
      const h = Object.assign({}, req.headers, { 'x-sentra-proxy-secret': H.SECRET, 'x-auth-user': WHO.user, 'x-auth-role': WHO.role });
      const up = http.request({ host: '127.0.0.1', port: e.port, method: req.method, path: req.url, headers: h }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); });
      req.pipe(up); return;
    }
    if (u2.pathname.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u2.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u2.pathname.endsWith('.js') ? 'application/javascript' : u2.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/workflow-automation.html';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const p = await browser.newPage({ viewport: { width: 1440, height: 950 } });
  p.on('pageerror', (x) => errs.push(x.message)); p.on('dialog', (d) => { errs.push('dialog: ' + d.message()); d.dismiss(); });
  const wait = (fn, a) => p.waitForFunction(fn, a, { timeout: 10000 }).then(() => true, () => false);
  const toastHas = (re) => p.waitForFunction((s) => new RegExp(s).test([...document.querySelectorAll('.toast')].map((t) => t.textContent).join(' ')), re.source, { timeout: 10000 }).then(() => true, () => false);
  const as = async (who) => { WHO = who; await p.goto(base); await p.waitForSelector('#kk .t'); };
  const dialog = async (text) => { await p.waitForSelector('#dlgbg.open'); if (text !== undefined) await p.fill('#dlgtx', text); await p.click('#dlgok'); };
  try {
    // 1. who is who
    await as({ user: 'syed', role: 'admin' });
    ok(!(await p.$eval('#tab-set', (b) => b.hidden)) && !(await p.$eval('#tab-all', (b) => b.hidden)), 'admin: Settings and All requests');
    await p.click('[data-tab="set"]');
    await p.fill('[data-setf="audit"]', 'aud.syn'); await p.fill('[data-sett="dba"]', 'dba.syn, dba2.syn'); await p.fill('[data-sett="identity"]', 'idm.syn'); await p.fill('[data-setl="identity"]', 'idlead.syn');
    await p.click('#set-save'); ok(await toastHas(/Saved/), 'settings saved');
    ok(JSON.stringify(e.app.store.collection('wf_cfg').get('cfg').teams.dba) === '["dba.syn","dba2.syn"]', 'teams stored');
    // 2. the auditor: describe, suggest, send
    await as({ user: 'aud.syn', role: 'viewer' });
    ok(await p.$eval('#tab-set', (b) => b.hidden), 'a viewer has no Settings');
    await p.fill('#need', 'list of database accounts and their privileges'); await p.click('#sugg');
    ok(await wait(() => /Database accounts and privileges review/.test(document.getElementById('suggout').textContent) && !document.getElementById('nform').hidden), 'ML suggests the request type and opens its form');
    ok(await p.$eval('#nf', (s) => s.value) === 'audit' && /Database team/.test(await p.textContent('#nfi')), 'from Audit, to the Database team');
    await p.fill('#n-title', '<img src=x onerror=window.PWN=1>Q4 DB accounts'); await p.click('#n-submit');
    ok(await toastHas(/REQ-\d{4}-\d{4} sent to Database team/), 'request sent');
    ok(await wait(() => !document.getElementById('p-mine').hidden && document.querySelectorAll('#mine tr[data-id]').length === 1), 'My requests shows it');
    ok(/<img src=x/.test(await p.textContent('#mine')) && !(await p.evaluate(() => window.PWN)), 'a hostile title stays text');
    const id = await p.$eval('#mine tr[data-id]', (r) => r.getAttribute('data-id'));
    // 3. the DBA works it
    await as({ user: 'dba.syn', role: 'operator' }); await p.click('[data-tab="queue"]');
    ok(await wait((i) => !!document.querySelector('#queue tr[data-id="' + i + '"]'), id), 'the team queue lists it');
    await p.click('#queue tr[data-id="' + id + '"]'); await p.waitForSelector('#drawer.open [data-act="start"]');
    await p.click('[data-act="start"]'); ok(await wait(() => /in progress/.test(document.getElementById('drb').textContent)), 'taken');
    await p.click('[data-act="evidence"]'); ok(await wait(() => /CLAIMS-SYN/.test(document.getElementById('drb').textContent)), 'evidence collected from the platform, shown as a table');
    ok(!/Synthetic-DB-Secret-1/.test(await p.textContent('#drb')) && /not evidence of compliance/.test(await p.textContent('#drb')), 'no password in the pack; an empty source says it is not evidence');
    await p.click('[data-act="fulfil"]'); await dialog('');
    ok(await toastHas(/needed/) && await p.$eval('#dlgbg', (d) => d.classList.contains('open')), 'Fulfil needs a response; the dialog stays open');
    await p.fill('#dlgtx', 'CLAIMS-SYN accounts are in the evidence pack.'); await p.click('#dlgok');
    ok(await wait(() => /fulfilled/.test(document.getElementById('drb').textContent) && !document.querySelector('[data-act="accept"]')), 'fulfilled; the fulfiller has no Accept');
    // 4. the auditor accepts
    await as({ user: 'aud.syn', role: 'viewer' }); await p.click('[data-tab="mine"]'); await p.click('#mine tr[data-id="' + id + '"]');
    await p.waitForSelector('[data-act="accept"]'); await p.click('[data-act="accept"]'); await dialog('thanks');
    ok(await wait(() => /closed/.test(document.getElementById('drb').textContent)), 'accepted: closed');
    ok(e.app.store.collection('wf_requests').get(id).accepted_by === 'aud.syn', 'recorded who accepted');
    // 5. HR leaver -> the identity lead approves
    await as({ user: 'hr.syn', role: 'viewer' }); await p.selectOption('#nf', 'hr'); await p.click('[data-type="leaver-disable"]');
    await p.fill('#n-details', 'Synthetic leaver, last day today'); await p.click('#n-submit'); ok(await toastHas(/waiting for approval/), 'leaver request waits for approval');
    await as({ user: 'idlead.syn', role: 'operator' }); await p.click('[data-tab="queue"]');
    ok(await wait(() => !document.getElementById('apcard').hidden && document.querySelectorAll('#approvals tr[data-id]').length === 1), 'the lead sees it waiting for approval');
    await p.click('#approvals tr[data-id]'); await p.waitForSelector('[data-act="approve"]'); await p.click('[data-act="approve"]'); await dialog('confirmed with HR');
    ok(await wait(() => /approved by idlead\.syn/.test(document.getElementById('drb').textContent)), 'approved by the lead');
    await p.click('#drx');
    // 6. a schedule
    await as({ user: 'syed', role: 'admin' }); await p.click('[data-tab="auto"]');
    await p.selectOption('#s-type', 'backup-evidence'); await p.selectOption('#s-from', 'audit'); await p.selectOption('#s-every', 'monthly'); await p.fill('#s-next', '2026-12-01');
    await p.click('#s-add'); ok(await toastHas(/Scheduled/) && await wait(() => /Backup success evidence/.test(document.getElementById('scheds').textContent)), 'a monthly schedule added');
    await p.click('[data-tab="all"]'); ok(await wait(() => document.querySelectorAll('#allr tr[data-id]').length === 2), 'All requests: both');
    // flow (rev 2): synthetic history - the wait before the work starts is the bottleneck; demand rises
    { const R = e.app.store.collection('wf_requests'), T0 = Date.now(), HR = 3600000, iso = (ms) => new Date(ms).toISOString(); let k = 0;
      for (let w = 11; w >= 1; w--) for (let j = 0; j < 2 + Math.floor((11 - w) / 3); j++) { const c = T0 - w * 7 * 24 * HR - (j + 1) * 6 * HR, st = c + 30 * HR, fu = st + 4 * HR;
        R.put({ id: 'WF-FLOW-' + (++k), type: 'db-user-review', team: 'dba', from: 'audit', title: 'Flow synthetic ' + k, details: 'synthetic', requester: 'aud.syn', priority: 'normal', status: 'closed', created_at: iso(c), updated_at: iso(c), due: iso(c + 72 * HR),
          fulfilled_at: iso(fu), fulfilled_by: 'dba.syn', closed_at: iso(fu + HR), assignee: 'dba.syn', evidence: [], comments: [], history: [{ at: iso(c), by: 'aud.syn', action: 'created' }, { at: iso(st), by: 'dba.syn', action: 'started' }, { at: iso(fu), by: 'dba.syn', action: 'fulfilled' }, { at: iso(fu + HR), by: 'aud.syn', action: 'accepted' }] }); } }
    await p.reload(); await wait(() => !!document.querySelector('[data-tab="auto"]')); await p.click('[data-tab="auto"]');
    ok(await wait(() => /bottleneck: waiting to be started \(30 h\)/.test(document.getElementById('flowst').textContent)), 'where the time goes: the bottleneck stage');
    const dm = await p.textContent('#flowdm'); ok(/Database/i.test(dm) && /week\(s\) for|—/.test(dm) && !!(await p.$('#flowdm svg polyline')), 'demand next week per team with the 12-week line: ' + dm.slice(0, 200));
    ok(/Database user|database/i.test(await p.textContent('#flowac')) && /evidence collected by the platform|steady|runbook|schedule/.test(await p.textContent('#flowac')), 'what to automate first');
    ok(!errs.length, 'no page errors or browser dialogs: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); await e.close(); }
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
