// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for Coverage & Query (dashboards/server/asset-coverage.html) against the REAL ITAM engine (engine/asset-coverage.js)
// over SYNTHETIC assets: the coverage ring and per-control cards, not-checked sources said with their reason, heat map cell click ->
// a query, the fix-first list and the asset detail, the query bar (results, a 400 shown), save for the team, an admin schedule,
// the Action Center (operator requests, the same person cannot approve, a different admin approves, owner set), a hostile asset name
// stays text, a viewer reads but cannot request or approve, and the menu has the page.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node asset-coverage.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const ADM = { user: 'syed', role: 'admin' }, OP = { user: 'nora.syn', role: 'operator' }, VIEW = { user: 'vera.syn', role: 'viewer' };
const XSS = '<img src=x onerror=alert(1)>';

(async () => {
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3',
    acovLogCoverage: async () => ({ ok: false, error: 'SIEM not reachable (synthetic test)' }), acovAvail: async () => ({ ok: true, hosts: { '10.70.1.10': { s: 'online', since: Date.now() - 86400000 }, '10.70.1.11': { s: 'offline', since: Date.now() - 600000 } } }), acovSiem: async () => ({ ok: true }) });
  const col = e.app.store.collection('assets');
  const mk = (x, extra) => { const id = e.app.assets.create(Object.assign({ status: 'in_use', type: 'server', site: 'HQ' }, x), ADM).asset.id; col.put(Object.assign({}, col.get(id), extra || {})); return id; };
  const seen = [{ source: 'agent', last_seen: new Date().toISOString() }];
  const id = {
    db: mk({ name: 'DB-SYN-1', mgmt_ip: '10.70.1.10' }, { criticality: 'critical', software: [{ name: 'Kaspersky Endpoint Security for Windows', version: '12.1' }], sources: seen }),
    app: mk({ name: 'APP-SYN-1', mgmt_ip: '10.70.1.11', site: 'DR' }, { criticality: 'high', software: [{ name: 'Kaspersky Endpoint Security for Windows', version: '12.6' }], sources: seen }),
    web: mk({ name: 'WEB-SYN-1', mgmt_ip: '10.70.1.12' }, { software: [{ name: 'Notepad++', version: '8' }], sources: seen }),
    x: mk({ name: XSS, mgmt_ip: '10.70.1.13' }, { software: [{ name: 'Notepad++' }], sources: seen }),
  };
  e.app.store.collection('me_ec_computers').put({ id: 'ec1', name: 'DB-SYN-1', asset_id: id.db, last_contact: Date.now(), critical: 0, agent_version: '11.3' });
  let WHO = ADM;
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
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
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg, { timeout: 20000 }).then(() => true, () => false);
  const txt = (p, sel) => p.textContent(sel);
  try {
    const p = await browser.newPage({ viewport: { width: 1440, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message));
    p.on('dialog', (d) => { errs.push('dialog: ' + d.message()); d.dismiss(); });
    await p.goto(base + 'asset-coverage.html?standalone=1');
    ok(await wait(p, () => !document.getElementById('main').hidden), 'the page loads');
    ok(/%/.test(await txt(p, '#ring')), 'the coverage ring shows a percentage');
    const ctl = await txt(p, '#ctls'); ok(/Endpoint protection/.test(ctl) && /1 weak/.test(ctl) && /2 missing/.test(ctl), 'EDR: one out of date, two missing');
    ok(/SIEM not checked: SIEM not reachable \(synthetic test\)/.test(await txt(p, '#srcwarn')), 'a source not connected is said, with its reason');
    ok(/not measured/.test(ctl), 'backup with no platform reads "not measured", never 0%');
    ok(/Availability monitoring[\s\S]*1 present · 1 weak · 2 missing/.test(ctl), 'availability monitoring: online, offline, two not monitored');
    ok(/DB-SYN-1/.test(await txt(p, '#top')) && /older than 12\.6/.test(await txt(p, '#top')), 'fix first: the critical server with an out-of-date agent');
    ok(await p.evaluate(() => !document.querySelector('img[src="x"]')) && (await txt(p, '#top')).includes(XSS), 'a hostile asset name stays text');
    await p.click('#top [data-asset]'); ok(await wait(p, () => /Endpoint Central/.test(document.body.textContent) && /Seen by: agent/.test(document.body.textContent)), 'asset detail: every control with its source');
    await p.keyboard.press('Escape');
    // heat map cell -> query
    await p.click('#bysite td[data-q*="edr"]');
    ok(await wait(p, () => !document.querySelector('[data-panel="query"]').hidden && /asset\(s\)/.test(document.getElementById('qmeta').textContent)), 'a heat-map cell runs its query');
    ok(/site:"HQ" edr:gap/.test(await p.inputValue('#q')), 'the query is in the box');
    // query bar: a bad field is shown, then a good query
    await p.fill('#q', 'colour:red'); await p.click('#run'); ok(await wait(p, () => /unknown field "colour"/.test(document.getElementById('qres').textContent)), 'a bad query says which field');
    await p.fill('#q', 'type:server edr:missing'); await p.press('#q', 'Enter');
    ok(await wait(p, () => /2 asset\(s\)/.test(document.getElementById('qmeta').textContent)), 'query result count');
    ok(/WEB-SYN-1/.test(await txt(p, '#qres')) && !/APP-SYN-1/.test(await txt(p, '#qres')), 'the right assets');
    ok(/Monitor/.test(await txt(p, '#qres thead')), 'the result has a Monitor column');
    await p.fill('#qname', 'Servers without EDR'); await p.click('#saveq');
    ok(await wait(p, () => /Saved/.test(document.body.textContent)), 'saved for the team');
    await p.click('[data-go="saved"]'); ok(/Servers without EDR/.test(await txt(p, '#saved')), 'the saved query is listed');
    await p.click('[data-sched]'); await p.fill('[data-f="recipients"]', 'infra-team@example.test'); await p.click('[data-savesched]');
    ok(await wait(p, () => /daily 07:30 · on change/.test(document.getElementById('saved').textContent)), 'admin schedules it (on change)');
    await p.click('[data-runnow]'); ok(await wait(p, () => /Run: sent/.test(document.body.textContent)), 'send now goes through the relay');
    ok(await wait(p, () => /sent/.test(document.getElementById('runs').textContent)), 'the run is recorded');
    // Action Center: nora requests, nora cannot approve, syed approves
    WHO = OP; await p.reload(); ok(await wait(p, () => !document.getElementById('main').hidden), 'operator opens the page');
    await p.click('[data-go="actions"]'); await p.selectOption('#ak', 'set_owner'); await p.fill('#aq', 'type:server edr:missing'); await p.fill('#ao', 'Synthetic Infra Team'); await p.fill('#ar', 'servers without EDR need an owner to fix them');
    await p.click('#ago'); ok(await wait(p, () => /pending/.test(document.getElementById('acts').textContent)), 'requested');
    ok(!(await p.$('[data-approve]')) && /waiting for a different person/.test(await txt(p, '#acts')), 'the requester cannot approve');
    WHO = ADM; await p.reload(); ok(await wait(p, () => !document.getElementById('main').hidden), 'admin opens the page');
    await p.click('[data-go="actions"]'); await p.click('[data-approve]');
    ok(await wait(p, () => /Approved by syed/.test(document.getElementById('acts').textContent) && /done/.test(document.getElementById('acts').textContent)), 'approved and run');
    ok(col.get(id.web).owner === 'Synthetic Infra Team', 'the owner is set on the asset');
    ok(e.app.store.auditTail(80).some((x) => x.action === 'asset.coverage.action.approve' && x.by === 'syed'), 'audited');
    const [dl] = await Promise.all([p.waitForEvent('download', { timeout: 10000 }), p.click('#xls')]); ok(/^asset-coverage-\d{4}-\d{2}-\d{2}\.xlsx$/.test(dl.suggestedFilename()), 'Excel export');
    ok(await p.evaluate(() => (window.ZYB_NAV || []).some((a) => (a.pages || []).some((x) => x.h === 'asset-coverage.html'))), 'the menu has the page');
    // viewer: reads, cannot request, approve or save
    WHO = VIEW; await p.reload(); ok(await wait(p, () => !document.getElementById('main').hidden), 'a viewer opens the page');
    await p.click('[data-go="query"]'); await p.fill('#q', 'type:server'); await p.click('#run'); ok(await wait(p, () => /asset\(s\)/.test(document.getElementById('qmeta').textContent)), 'a viewer queries');
    ok(!(await p.isVisible('#saveq')) && !(await p.isVisible('#actq')), 'a viewer cannot save or act');
    await p.click('[data-go="actions"]'); ok(!(await p.isVisible('#newact')) && !(await p.$('[data-approve]')), 'a viewer cannot request or approve');
  } finally { await browser.close(); srv.close(); await e.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks');
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
