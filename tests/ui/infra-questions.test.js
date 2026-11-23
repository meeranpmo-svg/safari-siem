// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Questions to the teams on the IT Infrastructure Manager dashboard (dashboards/server/infra-manager.html, section #questions) against
// the REAL SIEM module (engine/ops/questions-routes.js) with SYNTHETIC problem sources (DBA alert center, server and Exchange health,
// network failing): team tiles; the critical problems flagged; a failing source named; the manager asks the DBA from the problem (the
// problem then shows the question); the asker cannot answer; the DBA (approver for eng:dba) acknowledges and answers; the manager
// follows up and closes; viewer sees no Ask; a hostile problem title stays text; other dashboard cards still draw.
// Run: SENTRA_SIEM_DIR=/home/user/sentra-siem PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node infra-questions.test.js
const http = require('http'), fs = require('fs'), os = require('os'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
const SIEM = process.env.SENTRA_SIEM_DIR || path.resolve(__dirname, '../../backend/siem');
const req = (m) => require(path.join(SIEM, 'engine', m));
const { createState } = req('soc/state');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror="window.__xss=1">';
let ROLE = 'viewer', USER = 'vera.syn';
const RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 };

(async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentra-infraq-')), Lq = { info() {}, warn() {}, error() {} }, mails = [];
  const state = createState({ dir: path.join(dir, 'state'), log: Lq });
  state.collection('approvers').put({ id: 'map', scopes: { 'eng:dba': ['dba.one'] } });
  const deps = { state, log: Lq, config: {},
    dbaAlerts: { conditions: () => [{ id: 'tbs|USERS@ODS', instance: 'ODS', level: 'critical', label: 'Tablespace USERS 96 % ' + XSS, metric: 'tbs', value: 96, unit: '%', threshold: 87, since: Date.now() - 3600e3 }, { id: 'arch@ESS', instance: 'ESS', level: 'warning', label: 'Archive lag', metric: 'arch', since: Date.now() - 4 * 3600e3 }], notifySettings: () => ({ recipients: ['dba.syn@example.test'] }) },
    sysadminFindings: (role) => role === 'exchange' ? [{ server: 'EXCH01', server_name: 'EXCH01', scope: 'exchange', severity: 'critical', kind: 'queue', title: 'Mail queue 4,200 (synthetic)', evidence: [] }] : [{ server: 'APP01', server_name: 'APP01', scope: 'windows', severity: 'high', kind: 'disk', title: 'C: 97 % (synthetic)', evidence: [] }],
    netopsFindings: () => { throw new Error('poller offline (synthetic)'); }, reports: { schedules: { mail: async (m) => { mails.push(m); } } } };
  const R = {}, AUD = [];
  const api = { route: (m, p, h) => { R[m + ' ' + p] = { re: new RegExp('^' + p.replace(/:([a-zA-Z]+)/g, '(?<$1>[^/]+)') + '$'), h }; } };
  req('ops/questions-routes').register(api, deps);
  const srv = http.createServer((rq, res) => {
    const url = new URL(rq.url, 'http://x'), u = url.pathname, json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u === '/dashboards/whoami.json') return json(200, { user: USER, role: ROLE });
    const hit = Object.entries(R).find(([k, v]) => k.startsWith(rq.method + ' ') && v.re.test(u));
    if (hit) { let b = ''; rq.on('data', (x) => { b += x; }); rq.on('end', async () => {
      const o = {}, m = hit[1].re.exec(u), ctx = { role: ROLE, user: USER, body: b ? JSON.parse(b) : {}, params: m.groups ? Object.fromEntries(Object.entries(m.groups).map(([k, v]) => [k, decodeURIComponent(v)])) : {}, query: Object.fromEntries(url.searchParams), path: u,
        need(r) { if (RANK[ROLE] < RANK[r]) { o.status = 403; o.error = 'requires ' + r; return false; } return true; }, audit: (a, t, d) => AUD.push({ a, t, d }), ok: (x) => { o.body = x; return x; }, fail(code, msg) { o.status = code; o.error = msg; } };
      try { await hit[1].h(ctx); if (o.status) return json(o.status, { error: o.error || 'refused' }); json(200, o.body); } catch (e) { json(e.code || e.status || 500, { error: e.message }); } }); return; }
    if (u.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.replace(/^\/dashboards\//, '')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (e, d) => { if (e) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': f.endsWith('.js') ? 'application/javascript' : f.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const url = 'http://127.0.0.1:' + srv.address().port + '/dashboards/infra-manager.html?standalone=1';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, a) => p.waitForFunction(fn, a, { timeout: 15000 }).then(() => true, () => false);
  const open = async (role, user) => { ROLE = role; USER = user; const p = await browser.newPage({ viewport: { width: 1500, height: 1100 } }); p.on('pageerror', (e) => errs.push(e.message)); await p.goto(url); await wait(p, () => document.querySelectorAll('#q-teams .t').length === 4); return p; };
  try {
    let p = await open('viewer', 'vera.syn');
    const tiles = await p.evaluate(() => document.getElementById('q-teams').innerText);
    ok(/Database \(DBA\)/.test(tiles) && /Exchange/.test(tiles) && /Network/.test(tiles), 'team tiles');
    const iss = await p.evaluate(() => document.getElementById('q-iss').innerText);
    ok(/Tablespace USERS 96/.test(iss) && /Mail queue 4,200/.test(iss) && !/C: 97/.test(iss), 'critical problems flagged (high hidden)');
    ok(/poller offline/.test(iss), 'a failing source is named');
    ok(!(await p.$('[data-qask]')), 'viewer: no Ask');
    ok(await p.evaluate(() => !window.__xss), 'hostile title stays text');
    await p.check('#q-high'); ok(await wait(p, () => /C: 97/.test(document.getElementById('q-iss').innerText)), 'include high');
    await p.close();
    p = await open('operator', 'infra.mgr');
    await p.click('[data-qask^="dba:"]'); await p.fill('#q-tx', 'Why is USERS at 96 % on ODS, and when will it be extended?'); await p.fill('#q-rt', 'infra.mgr@example.test'); await p.click('#q-dok');
    ok(await wait(p, () => !document.getElementById('q-list').hidden && /Why is USERS at 96/.test(document.getElementById('q-list').innerText)), 'question asked, shown in Questions');
    ok(mails.length === 1 && mails[0].to[0] === 'dba.syn@example.test', 'the DBA is mailed');
    ok(!(await p.$('[data-qans]')), 'the asker has no Answer');
    await p.click('[data-qtab="iss"]'); ok(await wait(p, () => /Q-[A-F0-9]{6}/.test(document.getElementById('q-iss').innerText) && /Waiting/.test(document.getElementById('q-iss').innerText)), 'the problem shows its question');
    await p.close();
    p = await open('operator', 'dba.one'); await p.click('[data-qtab="q"]');
    await p.click('[data-qack]'); ok(await wait(p, () => /Acknowledged/.test(document.getElementById('q-list').innerText)), 'DBA acknowledges');
    await p.click('[data-qans]'); await p.fill('#q-tx', 'Batch load grew USERS; datafile added (+20 GB), now 71 % (synthetic).'); await p.click('#q-dok');
    ok(await wait(p, () => /Answered/.test(document.getElementById('q-list').innerText) && /datafile added/.test(document.getElementById('q-list').innerText)), 'DBA answers');
    ok(!(await p.$('[data-qclose]')), 'the DBA cannot close the manager\'s question');
    await p.close();
    p = await open('operator', 'infra.mgr'); await p.click('[data-qtab="q"]');
    await p.click('[data-qfu]'); await p.fill('#q-tx', 'Will it happen again next month?'); await p.click('#q-dok');
    ok(await wait(p, () => /Follow-up/.test(document.getElementById('q-list').innerText)), 'follow-up re-opens');
    await p.click('[data-qclose]'); await p.fill('#q-tx', 'thanks'); await p.click('#q-dok');
    ok(await wait(p, () => /Closed/.test(document.getElementById('q-list').innerText)), 'closed');
    ok(await p.evaluate(() => document.querySelectorAll('.g .card').length >= 8), 'the other dashboard cards still draw');
    await p.close();
    ok(['ops.question.ask', 'ops.question.ack', 'ops.question.answer', 'ops.question.follow_up', 'ops.question.close'].every((a) => AUD.some((x) => x.a === a)), 'every step audited');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); fs.rmSync(dir, { recursive: true, force: true }); }
  console.log((bad ? 'FAILED ' : 'ok ') + (n - bad) + '/' + n);
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
