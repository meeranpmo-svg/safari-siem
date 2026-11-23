// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for dashboards/server/grc-workspace.html (Risks & Actions) against the real ITAM engine's GRC registers:
// KPIs and "waiting for you", four-eyes close, create, filters, heat map, file evidence, admin acceptance, deep links
// from other pages, viewer read-only, Excel. Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node grc-workspace.test.js
const http = require('http'), fs = require('fs'), path = require('path'), assert = require('assert/strict');
const ITAM = path.resolve(__dirname, '../../backend/itam'), DASH = path.resolve(__dirname, '../../ui');
const H = require(path.join(ITAM, 'tests/helpers.js'));
let WHO = { user: 'rasheed', role: 'operator' };
(async () => {
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/grc')).registerGrc(e.app.srv, e.app);
  { const LCM = require(path.join(ITAM, 'engine/licence')); LCM.registerLicence(e.app.srv, e.app, LCM.createLicence(e.app, {})); }   // every page reads the licence status
  const as = (user, role) => async (m, p, body) => { const r = await e.req(m, p, { body, user, role }); if (r.status >= 300) throw new Error(p + ' ' + r.status + ' ' + r.text); return r.json; };
  const siva = as('siva', 'operator'), syed = as('syed', 'admin');
  await siva('POST', '/grc/actions', { title: 'Enable MFA for VPN', source: 'sama', ref: '3.3.5', owner: 'rasheed', due: '2020-01-01', priority: 'high' });
  const a2 = await siva('POST', '/grc/actions', { title: 'Patch the jump host', owner: 'siva' });
  await siva('POST', '/grc/actions/' + a2.id + '/status', { status: 'done', note: 'patched' });
  await siva('POST', '/grc/risks', { title: 'Ransomware on file servers', owner: 'siva', likelihood: 4, impact: 5, treatment: 'mitigate' });
  await siva('POST', '/grc/risks', { title: 'Vendor support ended', owner: 'siva', likelihood: 2, impact: 4, treatment: 'accept' });
  const pol = (await siva('GET', '/grc/exceptions')).policies[0].doc_id;
  await siva('POST', '/grc/exceptions', { policy_id: pol, title: 'Shared admin on HMI', reason: 'vendor locked', compensating: 'jump host', expires: new Date(Date.now() + 200 * 864e5).toISOString().slice(0, 10) });

  // Workflow Automation (the real engine): what GRC asked the IT teams for - one request late with the DBA team, one fulfilled and waiting for acceptance
  const WFM = require(path.join(ITAM, 'engine/workflow-auto')), W = WFM.createWorkflow(e.app, { noTimer: true }); WFM.registerWorkflow(e.app.srv, e.app, W);
  W.settingsSave({ version: 0, functions: { grc: ['rasheed'] }, teams: { dba: ['dba.syn'], backup: ['bk.syn'] } }, { user: 'syed', role: 'admin', ip: '' });
  const wl = W.create({ type: 'db-audit-trail', from: 'grc', title: 'Audit trail evidence for SAMA 3.3.14 <img src=x onerror=window.__wf=1>', details: 'all production databases', priority: 'high' }, { user: 'rasheed', role: 'operator', ip: '' });
  const wc = e.app.store.collection('wf_requests'), wr = wc.get(wl.id); wr.due = new Date(Date.now() - 3600000).toISOString(); wc.put(wr);
  const wd = W.create({ type: 'backup-evidence', from: 'grc', title: 'Backup success evidence, October', details: 'monthly' }, { user: 'rasheed', role: 'operator', ip: '' });
  W.act(wd.id, 'evidence', { kind: 'note', text: 'report attached' }, { user: 'bk.syn', role: 'operator', ip: '' }); W.act(wd.id, 'fulfil', { response: 'attached' }, { user: 'bk.syn', role: 'operator', ip: '' });

  const srv = http.createServer((req, res) => {
    const u = req.url.split('?')[0];
    if (u === '/dashboards/whoami.json') { res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(WHO)); return; }
    // the page shell (vendor/zyb-dash.js, zyb-modules.js) asks the sign-in service on every page: the session and the
    // organisation's modules - answered here (synthetic); the licence comes from the real licence module registered above
    const stub = { '/auth/whoami': WHO, '/auth/org': { modules: null } }[u];
    if (stub && req.method === 'GET') { res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(stub)); return; }
    if (u.startsWith('/api/itam/')) {
      const h = Object.assign({}, req.headers, { 'x-sentra-proxy-secret': H.SECRET, 'x-auth-user': WHO.user, 'x-auth-role': WHO.role });
      const up = http.request({ host: '127.0.0.1', port: e.port, method: req.method, path: req.url, headers: h }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); });
      req.pipe(up); return;
    }
    if (u === '/') { res.writeHead(200, { 'Content-Type': 'text/html' }); res.end('home'); return; }
    const f = path.join(DASH, u);
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': f.endsWith('.js') ? 'application/javascript' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/grc-workspace.html';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch();
  const page = await browser.newPage(); const errs = []; page.on('response', (r) => { if (r.status() === 404) console.log('404', r.url()); });
  page.on('pageerror', (x) => errs.push(x.message)); page.on('console', (m) => { if (m.type() === 'error') errs.push(m.text()); });
  let n = 0; const ok = (c, m) => { assert.ok(c, m); n++; };
  // the ITAM proxy prefix: check how the engine is mounted (paths sent with or without /api/itam)
  await page.goto('about:blank'); await page.goto(base); await page.waitForSelector('#kk .t', { timeout: 10000 });
  const kk = await page.$$eval('#kk .t', (t) => t.map((x) => x.innerText.replace(/\s+/g, ' ')));
  ok(kk.some((t) => /Open actions 2/i.test(t)), 'open actions tile ' + kk.join(' | '));
  ok(kk.some((t) => /Overdue 1/i.test(t)), 'overdue tile');
  ok(kk.some((t) => /Awaiting verification 1/i.test(t)), 'awaiting tile');
  ok(await page.isVisible('#minecard'), 'waiting for you shown (owner of ACT-0001 + verify ACT-0002)');
  const mine = await page.innerText('#mine'); ok(/ACT-0001/.test(mine) && /ACT-0002/.test(mine), 'mine lists both: ' + mine);
  ok((await page.$$('#atable tbody tr')).length === 2, 'two action rows');
  ok(await page.waitForFunction(() => !document.getElementById('wfcard').hidden && /Backup success evidence/.test(document.getElementById('wfl').textContent), null, { timeout: 10000 }).then(() => true, () => false), 'the Workflow Automation card is shown');
  const wft = await page.innerText('#wfcard');
  ok(/open with the IT teams\s*1/i.test(wft) && /late with the IT teams\s*1/i.test(wft) && /results for you to accept\s*1/i.test(wft), 'Workflow: open / late / to accept counted: ' + wft.replace(/\s+/g, ' ').slice(0, 220));
  ok(/Audit trail evidence for SAMA 3\.3\.14 <img/.test(wft) && !(await page.$('#wfcard img')) && !(await page.evaluate(() => window.__wf)), 'Workflow: the late request listed, a hostile title stays text');
  ok(/raised by you or your function, late with the IT team \+35, high priority \+10/.test(wft) && !!(await page.$('#wfl a[href="workflow-automation.html#req=' + wl.id + '"]')) && !!(await page.$('#wfcard a[href="workflow-automation.html#tab=new"]')), 'Workflow: the points, the link to the request and New request');
  // verify and close ACT-0002 (done by siva, rasheed verifies)
  await page.click('#atable tr[data-open="action:ACT-0002"]'); await page.waitForSelector('#zd:not([hidden])');
  await page.click('button[data-st="closed"]'); await page.fill('#f-note', 'checked the patch level'); await page.click('#f-ok');
  await page.waitForFunction(() => /Awaiting verification\s*0/i.test(document.getElementById('kk').innerText), null, { timeout: 8000 });
  ok(true, 'closed via four eyes');
  // new action from the form
  await page.click('[data-new="action"]'); await page.fill('#f-t', 'Rotate the service account password'); await page.fill('#f-due', '2031-01-01'); await page.click('#f-save');
  await page.waitForFunction(() => /Rotate the service/.test(document.getElementById('atable').innerText) && /Rotate the service/.test(document.getElementById('zd-t').textContent), null, { timeout: 8000 }); ok(true, 'action created and shown'); await page.keyboard.press('Escape'); await page.waitForTimeout(250);
  // tile → filter
  await page.click('#kk .t[data-go="actions:overdue"]'); ok((await page.$$('#atable tbody tr')).length === 1, 'overdue filter');
  // risks tab: heat map + cell filter
  await page.click('#tabs button[data-tab="risks"]'); ok(await page.isVisible('#heat .c[data-cell="4x5"]'), 'heat');
  ok((await page.innerText('#heat [data-cell="4x5"]')).trim() === '1', 'heat cell count');
  await page.click('#heat [data-cell="4x5"]'); ok((await page.$$('#rtable tbody tr')).length === 1, 'cell filter');
  // operator does not see accept
  await page.click('#rtable tbody tr'); ok(!(await page.$('button[data-act="accept"]')), 'operator: no accept'); await page.keyboard.press('Escape'); await page.waitForTimeout(250);
  // evidence: upload a file through the form
  await page.click('#tabs button[data-tab="evidence"]'); await page.click('#cov tr[data-ctl]');
  await page.fill('#f-t', 'CMDB export'); await page.setInputFiles('#f-file', { name: 'cmdb.csv', mimeType: 'text/csv', buffer: Buffer.from('id,name\n1,srv') });
  await page.click('#f-save'); await page.waitForFunction(() => /CMDB export/.test(document.getElementById('etable').innerText), null, { timeout: 8000 });
  ok(/1\/\d+ covered/.test(await page.innerText('#covc')), 'coverage counts');
  // admin: accept the risk, approve the exception
  WHO = { user: 'syed', role: 'admin' };
  await page.goto('about:blank'); await page.goto(base + '#risks'); await page.waitForSelector('#kk .t');
  ok(await page.isVisible('#tab-risks'), 'hash tab kept');
  const m2 = await page.innerText('#mine'); ok(/accept or reject/.test(m2) && /approve or reject/.test(m2), 'admin queue: ' + m2);
  await page.click('#mine tr[data-open^="risk:"]'); await page.click('button[data-act="accept"]'); await page.fill('#f-note', 'budgeted 2027'); await page.click('#f-ok');
  await page.waitForFunction(() => /formally accepted/.test(document.getElementById('treat').innerText) && /1 formally/.test(document.getElementById('treat').innerText), null, { timeout: 8000 }); ok(true, 'accepted');
  // deep link from another page
  await page.goto('about:blank'); await page.goto(base + '#actions?new=1&source=sama&ref=3.3.5&title=MFA'); await page.waitForSelector('#kk .t');
  await page.waitForTimeout(300); ok(/already tracks this: ACT-0001/.test(await page.innerText('body')), 'deep link finds the open action');
  await page.goto('about:blank'); await page.goto(base + '#actions?new=1&source=sama&ref=3.4.1&title=Logging%20gap'); await page.waitForSelector('#f-t');
  ok((await page.inputValue('#f-t')) === 'Logging gap' && (await page.inputValue('#f-ref')) === '3.4.1', 'deep link prefills');
  // live: the platform's gaps feed the registers (stubbed AI CISO collect, synthetic gaps)
  e.app.addons.ciso = { collect: async () => ({ sama: { state: 'live', data: { controls: [{ id: '3.3.9', title: 'Logging and monitoring', status: 'gap' }] } }, grc: { state: 'live', data: { control_status: {} } }, drills: { state: 'live', data: { systems: [] } }, ownership: { state: 'error' } }),
    risks: () => [{ ref: 'duty:DW-SYN-9', severity: 'critical', domain: 'operations', title: 'Firewall cluster out of sync', source: 'AI security engineer' }] };
  await page.goto('about:blank'); await page.goto(base); await page.waitForSelector('#livesync');
  ok(/not read yet/.test(await page.innerText('#livebar')), 'live bar before the first read');
  await page.click('#livesync'); await page.waitForFunction(() => /last read/.test(document.getElementById('livebar').innerText), null, { timeout: 10000 });
  ok(/1 gap\(s\)/.test(await page.innerText('#livebar')) && /SAMA gap/.test(await page.innerText('#atable')) && /3\.3\.9/.test(await page.innerText('#atable')), 'Read now: the SAMA gap is an open action: ' + (await page.innerText('#livebar')));
  await page.click('[data-tab="risks"]'); ok(/Firewall cluster out of sync/.test(await page.innerText('#livecand')), 'live finding offered to rate');
  await page.click('[data-rate="0"]'); await page.waitForSelector('#f-t'); ok((await page.inputValue('#f-t')) === 'Firewall cluster out of sync', 'Rate as a risk prefills the form');
  await page.selectOption('#f-l', '3'); await page.selectOption('#f-i', '4'); await page.click('#f-save'); await page.waitForTimeout(800);
  ok(e.app.store.collection('grc_risks').all((r) => r.source_ref === 'duty:DW-SYN-9').length === 1, 'the rated risk remembers the finding');
  ok(!/Firewall cluster out of sync/.test(await page.innerText('#livecand')), 'a rated finding leaves the list');
  // viewer: read only
  WHO = { user: 'guest', role: 'viewer' };
  await page.goto('about:blank'); await page.goto(base); await page.waitForSelector('#kk .t'); ok(!(await page.$('[data-new]')), 'viewer: no create buttons');
  // excel
  const [dl] = await Promise.all([page.waitForEvent('download'), page.click('#xlsx')]); ok(/grc-actions-/.test(dl.suggestedFilename()), 'excel');
  ok(errs.length === 0, 'errors: ' + errs.join(' | '));
  console.log('OK', n, 'checks');
  await browser.close(); srv.close(); await e.close(); process.exit(0);
})().catch((x) => { console.error('FAIL', x.message, (x.stack||'').split('\n').find((l) => /grcws-test/.test(l))); process.exit(1); });
