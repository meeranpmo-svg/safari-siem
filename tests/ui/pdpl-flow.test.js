// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for the PDPL Automation Flow (pdpl-flow.html) against the REAL engine (engine/automation-flow.js over the PDPL registers,
// the Privacy Office and the PDPL Control Monitor) with SYNTHETIC records (names end .syn / SYN): before anything is recorded every
// stage says what to connect and none is green; after requests, breaches, processing activities, assessments, monitor runs and
// Privacy Office tasks, each stage shows its count, the 30-day and 72-hour clocks put items in the stuck list (oldest first, age,
// owner), the bottleneck is named; a stage opens its page; record text stays text; a viewer is refused gracefully; phone width.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node pdpl-flow.test.js   (SHOTS=dir also saves a screenshot)
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const DAY = 86400000, T0 = Date.parse('2027-03-01T08:00:00Z'), iso = (t) => new Date(t).toISOString();
(async () => {
  let clock = T0;
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, now: () => clock, python: process.env.PYTHON || 'python3' });
  const AF = require(path.join(ITAM, 'engine/automation-flow'));
  if (!e.app.addons.automationFlow) AF.registerAutomationFlow(e.app.srv, e.app, AF.createAutomationFlow(e.app, { now: () => clock }));
  const ADM = { user: 'adam.syn', role: 'admin' }, HEAD = { user: 'hana.syn', role: 'operator' }, LEAD = { user: 'laila.syn', role: 'operator' }, AUD2 = { user: 'adel.syn', role: 'operator' }, OWNER = { user: 'omar.syn', role: 'operator' };
  const api = (m, p, b, w) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, w || LEAD));
  const col = (x) => e.app.store.collection(x);
  let who = LEAD;
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (code, b) => { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, who);
    if (u.pathname.startsWith('/api/itam/')) { const h = Object.assign({}, req.headers, { 'x-sentra-proxy-secret': H.SECRET, 'x-auth-user': who.user, 'x-auth-role': who.role });
      const up = http.request({ host: '127.0.0.1', port: e.port, method: req.method, path: req.url, headers: h }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); }); req.pipe(up); return; }
    if (u.pathname.startsWith('/api/') || u.pathname === '/') return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/pdpl-flow.html';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const wait = (p, fn) => p.waitForFunction(fn, null, { timeout: 30000 }).then(() => true, () => false);
  const drawn = (p) => wait(p, () => document.querySelectorAll('#flow a[data-stage]').length === 8 && document.querySelectorAll('#kk .t').length === 5);
  const stages = (p) => p.evaluate(() => Object.fromEntries([...document.querySelectorAll('#flow a[data-stage], #lanes a[data-stage]')].map((a) => [a.dataset.stage, { status: a.dataset.status, n: (a.querySelector('.n') || {}).textContent, text: a.textContent }])));
  try {
    const p = await browser.newPage({ viewport: { width: 1400, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto(base + '?standalone=1'); ok(await drawn(p), 'the flow draws eight stages and five tiles');
    let S = await stages(p);
    ok(Object.values(S).every((x) => x.status !== 'ok'), 'nothing recorded: no stage is lit as working');
    ok(/no data subject request or breach recorded/.test(S.requests.text) && /consent purpose/.test(S.consent.text), 'a stage with no records says what to connect: ' + S.requests.text);
    ok(S.escalations, 'escalations beside the flow');

    const rec = async (b) => (await api('POST', '/pdpl/records', b)).json.id;
    const d1 = await rec({ kind: 'dsr', ref: 'SYN-REQ-1', type: 'access', received: '2027-01-20' });
    await rec({ kind: 'dsr', ref: 'SYN-REQ-2', type: 'copy', received: '2027-02-27' });
    await rec({ kind: 'dsr', ref: 'SYN-REQ-3', type: 'correction', received: '2027-01-01', responded: '2027-01-11' });
    const b1 = await rec({ kind: 'breach', ref: 'SYN-BR-1', aware_at: iso(T0 - 80 * 3600000).slice(0, 16) });
    const ro = await rec({ kind: 'ropa', name: 'Motor claims SYN', purpose: 'claims', legal_basis: 'contract' });
    await rec({ kind: 'dpia', ropa_id: ro }); await rec({ kind: 'processor', name: 'TPA SYN' });
    col('pdpl_office_tasks').put({ id: 'PO-00001', key: 'f:syn-1', status: 'open', title: 'Synthetic task SYN <img src=x onerror="window.__x=1">', assignee: 'dpo.syn', first_seen: iso(T0 - 20 * DAY), due: iso(T0 - 6 * DAY), overdue: true, escalation: 1, escalated_to: 'dpo.syn' });
    col('pdpl_office_tasks').put({ id: 'PO-00002', key: 'f:syn-2', status: 'closed', title: 'Synthetic done SYN', assignee: 'dpo.syn', first_seen: iso(T0 - 30 * DAY), closed_at: iso(T0 - 18 * DAY) });
    col('pdpl_mon_runs').put({ id: 'RUN-1', at: iso(T0 - DAY), states: { 'S-claims:M01': 'fail', 'S-claims:M02': 'pass' }, drift: [], fixed: [], score: 50, pass: 1, fail: 1, not_measured: 0 });

    await p.goto(base + '?standalone=1'); await drawn(p); S = await stages(p);
    ok(S.requests.n === '3' && S.requests.status === 'part' && /past 30 days/.test(S.requests.text), 'requests & breaches: counted, items stuck: ' + S.requests.text);
    ok(S.ropa.n === '1' && S.assess.n === '2' && S.office.n === '1' && S.closed.n === '1' && /score 50 %/.test(S.monitor.text), 'ropa, assessments, office, closed and monitor counted');
    const pg = await p.evaluate(() => ({ rows: [...document.querySelectorAll('#stuck tr[data-item]')].map((r) => ({ id: r.dataset.item, t: r.textContent })), bn: document.getElementById('bn').textContent,
      xss: window.__x === 1 || !!document.querySelector('img[src="x"]'), raw: document.getElementById('stuck').textContent.includes('<img src=x') }));
    const rq = pg.rows.filter((r) => r.id === d1 || r.id === b1);
    ok(rq.length === 2 && rq[0].id === d1 && /40(\.\d)? d/.test(rq[0].t) && /overdue/.test(rq[0].t) && /30-day clock ended/.test(rq[0].t), 'the 40-day request first, overdue on its 30-day clock: ' + (rq[0] && rq[0].t));
    ok(/72 hours passed/.test(rq[1].t), 'the breach past its 72-hour clock: ' + (rq[1] && rq[1].t));
    ok(pg.rows.some((r) => r.id === 'PO-00001' && /dpo\.syn/.test(r.t) && /20 d/.test(r.t)), 'the Privacy Office task with its assignee and age');
    ok(/Requests & breaches|Privacy Office tasks|DPIA/.test(pg.bn), 'the bottleneck is named: ' + pg.bn);
    ok(!pg.xss && pg.raw, 'record text stays text');
    ok(!(await p.evaluate(() => document.body.textContent.includes('SYN-REQ-1'))), 'the request reference is not shown');
    if (process.env.SHOTS) { await p.waitForTimeout(300); await p.screenshot({ path: path.join(process.env.SHOTS, 'pdpl-flow.png'), fullPage: true }); }
    await Promise.all([p.waitForURL(/pdpl-dsar\.html/, { timeout: 10000 }).catch(() => null), p.click('#flow a[data-stage="requests"]')]); ok(/pdpl-dsar\.html/.test(p.url()), 'a stage opens its page');
    who = { user: 'vera.syn', role: 'viewer' }; await p.goto(base + '?standalone=1');
    ok(await wait(p, () => /an operator or administrator opens it/.test(document.getElementById('err').textContent)), 'a viewer is refused with a message, not a blank page');
    ok(await p.evaluate(() => !document.querySelector('#flow a[data-stage]') && document.getElementById('how').children.length === 8), 'no records shown to a viewer; the stages are still explained');
    who = LEAD;
    const m = await browser.newPage({ viewport: { width: 390, height: 860 } }); m.on('pageerror', (x) => errs.push(x.message));
    await m.goto(base + '?standalone=1'); await drawn(m); ok(await m.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), 'phone width: no sideways scroll');
  } finally { await browser.close(); srv.close(); await e.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
