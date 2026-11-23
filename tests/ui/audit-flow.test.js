// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for the Audit Automation Flow (audit-flow.html) against the REAL engine (engine/automation-flow.js over Audit Command
// Center, the Cyber Security Audit Team, continuous control monitoring) with SYNTHETIC records (names end .syn): before anything is
// recorded every stage says what to connect and none is green; after use-case runs, a proposal and findings moved through the team's
// own engine, each stage shows its count, the stuck items are listed oldest first with age and owner, the bottleneck is named, the
// stuck threshold changes what is stuck; a stage opens its page; record text stays text; a viewer is refused gracefully; phone width.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node audit-flow.test.js   (SHOTS=dir also saves a screenshot)
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
  const base = 'http://127.0.0.1:' + srv.address().port + '/audit-flow.html';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const wait = (p, fn) => p.waitForFunction(fn, null, { timeout: 30000 }).then(() => true, () => false);
  const drawn = (p) => wait(p, () => document.querySelectorAll('#flow a[data-stage]').length === 9 && document.querySelectorAll('#kk .t').length === 5);
  const stages = (p) => p.evaluate(() => Object.fromEntries([...document.querySelectorAll('#flow a[data-stage], #lanes a[data-stage]')].map((a) => [a.dataset.stage, { status: a.dataset.status, n: (a.querySelector('.n') || {}).textContent, text: a.textContent }])));
  try {
    const p = await browser.newPage({ viewport: { width: 1400, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto(base + '?standalone=1'); ok(await drawn(p), 'the flow draws nine stages and five tiles');
    let S = await stages(p);
    ok(Object.values(S).every((x) => x.status !== 'ok'), 'nothing recorded: no stage is lit as working: ' + JSON.stringify(Object.fromEntries(Object.entries(S).map(([k, v]) => [k, v.status]))));
    ok(/no use-case run yet/.test(S.tests.text) && /no records yet/.test(S.tests.text), 'a stage with no records says what to connect: ' + S.tests.text);
    ok(S.escalations && S.evidence && S.attest, 'evidence requests, attestations and escalations beside the flow');

    // synthetic records: use-case runs, a proposal with a hostile title, findings through the Cyber Security Audit Team's engine
    const run = (d, ex) => col('audit_auto_runs').put({ id: iso(T0 - d * DAY), at: iso(T0 - d * DAY), by: LEAD.user, results: { 'UC-01': { n: 10, ex, status: ex ? 'exceptions' : 'effective' }, 'UC-06': { n: 4, ex: 0, status: 'effective' } } });
    run(20, 0); run(10, 2); run(1, 2);
    col('audit_auto_proposals').put({ id: 'AP-001', uc: 'UC-01', team: 'cyber', team_name: 'Cyber Security Audit Team', state: 'proposed', at: iso(T0 - 9 * DAY), by: LEAD.user, title: 'Leavers disabled late SYN <img src=x onerror="window.__x=1">' });
    await api('POST', '/csa/profile', { head_of_audit: HEAD.user, auditors: [LEAD.user, AUD2.user], engagements_per_year: 4 }, ADM);
    const eg = (await api('POST', '/csa/engagements', { title: 'Identity lifecycle SYN', area: 'iam', auditee_dept: 'IT', auditee_owner: OWNER.user, lead: LEAD.user, team: [AUD2.user], objectives: ['Leavers lose access'], scope: 'All leavers', criteria: 'NCA ECC 2-2', start: '2027-01-10', fieldwork_end: '2027-04-30', report_due: '2027-05-15' })).json;
    await (await api('POST', '/csa/engagements/' + eg.id + '/prior-none', { note: 'first audit of this area (synthetic)' }), api('POST', '/csa/engagements/' + eg.id + '/advance', { to: 'fieldwork' }));
    clock = T0 - 30 * DAY;
    const mk = async (title) => (await api('POST', '/csa/engagements/' + eg.id + '/findings', { title, condition: 'c SYN', criteria: 'k', cause: 'x', effect: 'y', recommendation: 'z', rating: 'high', owner: OWNER.user })).json.id;
    const fDraft = await mk('Draft finding SYN'), fIssued = await mk('Issued finding SYN'), fResp = await mk('Responded finding SYN');
    clock += 2 * DAY; for (const id of [fIssued, fResp]) await api('POST', '/csa/findings/' + id + '/issue', {});
    clock += 3 * DAY; await api('POST', '/csa/findings/' + fResp + '/respond', { response: 'agreed SYN', action_plan: 'fix SYN', due: '2027-02-20' }, OWNER);
    clock = T0;

    await p.goto(base + '?standalone=1'); await drawn(p); S = await stages(p);
    ok(S.tests.n === '2' && /3 run\(s\)/.test(S.tests.text) && S.tests.status === 'part', 'use-case tests: counted from the runs, items stuck: ' + S.tests.text);
    ok(S.proposed.n === '1' && S.engaged.n === '3' && S.owners.n === '2', 'proposed, engaged and owners counted: ' + [S.proposed.n, S.engaged.n, S.owners.n].join(','));
    ok(/re-test not yet recorded/.test(S.retest.text), 're-test read defensively: ' + S.retest.text);
    const pg = await p.evaluate(() => ({ groups: [...document.querySelectorAll('#stuck tr[data-group]')].map((r) => r.dataset.group), rows: [...document.querySelectorAll('#stuck tr[data-item]')].map((r) => r.textContent),
      bn: document.getElementById('bn').textContent, bnStage: (document.querySelector('#flow a.bn') || {}).dataset, tiles: document.getElementById('kk').textContent, cyc: document.getElementById('cyc').textContent,
      xss: window.__x === 1 || !!document.querySelector('img[src="x"]'), raw: document.getElementById('stuck').textContent.includes('<img src=x') }));
    ok(pg.groups.includes('owners') && pg.groups.includes('engaged') && pg.groups.includes('proposed') && pg.groups.includes('tests'), 'stuck items grouped by stage: ' + pg.groups.join(','));
    const own = pg.rows.filter((r) => /finding SYN/.test(r) && /omar\.syn/.test(r));
    ok(own.length === 2 && /Issued finding SYN/.test(own[0]) && /28 d/.test(own[0]) && /overdue/.test(own[1]), 'owners: oldest first, age, owner, overdue: ' + own.join(' | '));
    ok(pg.rows.some((r) => /Draft finding SYN/.test(r) && /30 d/.test(r) && /laila\.syn/.test(r)), 'the draft not yet issued, 30 days, with the auditor who raised it');
    ok(/Owners & action plans/.test(pg.bn) && pg.bnStage && pg.bnStage.stage === 'owners', 'the bottleneck is named and marked on the flow: ' + pg.bn);
    ok(/Stages working/.test(pg.tiles) && /Bottleneck/.test(pg.tiles) && /from issued to implemented/.test(pg.cyc), 'tiles and the cycle-time table');
    ok(!pg.xss && pg.raw, 'record text stays text');
    if (process.env.SHOTS) { await p.waitForTimeout(300); await p.screenshot({ path: path.join(process.env.SHOTS, 'audit-flow.png'), fullPage: true }); }
    // the threshold: 30 days leaves the 30-day draft and the overdue finding
    await p.selectOption('#sd', '30'); ok(await wait(p, () => document.querySelectorAll('#stuck tr[data-item]').length === 2), 'stuck after 30 days: only the 30-day draft and the overdue finding');
    await Promise.all([p.waitForURL(/audit-command\.html/, { timeout: 10000 }).catch(() => null), p.click('#flow a[data-stage="tests"]')]); ok(/audit-command\.html/.test(p.url()), 'a stage opens its page');
    // a viewer is refused gracefully
    who = { user: 'vera.syn', role: 'viewer' }; await p.goto(base + '?standalone=1');
    ok(await wait(p, () => /an operator or administrator opens it/.test(document.getElementById('err').textContent)), 'a viewer is refused with a message, not a blank page');
    ok(await p.evaluate(() => !document.querySelector('#flow a[data-stage]') && document.getElementById('how').children.length === 9), 'no records shown to a viewer; the stages are still explained');
    who = LEAD;
    const m = await browser.newPage({ viewport: { width: 390, height: 860 } }); m.on('pageerror', (x) => errs.push(x.message));
    await m.goto(base + '?standalone=1'); await drawn(m); ok(await m.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), 'phone width: no sideways scroll');
  } finally { await browser.close(); srv.close(); await e.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
