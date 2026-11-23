// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for IT Operations & Updates (dashboards/server/update-studio.html) against the REAL ITAM engine
// (engine/update-studio.js) with SYNTHETIC servers, Endpoint Central and vCenter reads: the ring and KPIs; a server no source
// reports on reads "not measured"; a rule opens the servers failing it; a server opens with its rule results and risk reasons;
// samples on three days produce update events on the timeline and in the history; an operator records a change reference and a
// post-update check (a failed check without a note is refused); patches against the SLA; version drift; the administrator saves
// the SLA (a bad order refused); Excel export; a hostile server name stays text; a viewer cannot record or sample.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node update-studio.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const ADM = { user: 'syed', role: 'admin' }, OP = { user: 'nora.syn', role: 'operator' }, VW = { user: 'vera.syn', role: 'viewer' };
const XSS = '<img src=x onerror="window.__xss=1">';
const D = 86400000;

(async () => {
  const e = await H.startApp({ noAi: true });
  const T0 = Date.now() - 3 * D, clock = { t: T0 };
  for (const a of [
    { id: 'a-esx1', name: 'esx1', type: 'server', os: 'VMware ESXi 8.0', criticality: 'high', environment: 'production' },
    { id: 'a-esx2', name: 'esx2', type: 'server', os: 'VMware ESXi 8.0', criticality: 'medium', environment: 'production' },
    { id: 'a-esx3', name: 'esx3-dr', type: 'server', os: 'VMware ESXi 8.0', environment: 'dr' },
    { id: 'a-win1', name: 'WIN-APP01', type: 'server', os: 'Windows Server 2019', criticality: 'critical', environment: 'production' },
    { id: 'a-sol', name: 'SOL-DB01 ' + XSS, type: 'server', os: 'Oracle Solaris 11.4', criticality: 'critical', environment: 'production' },
  ]) e.app.store.collection('assets').put(Object.assign({ status: 'in_use' }, a));
  const W = { hosts: [{ name: 'esx1', version: 'VMware ESXi 8.0.2 build-22380479', cluster: 'C1', platform: 'VC-SYN' }, { name: 'esx2', version: 'VMware ESXi 8.0.3 build-24022510', cluster: 'C1', platform: 'VC-SYN' }, { name: 'esx3-dr', version: 'VMware ESXi 8.0.3 build-24022510', cluster: 'C1', platform: 'VC-SYN' }],
    ec: { computers: [{ name: 'WIN-APP01', asset_id: 'a-win1', health: 'highly vulnerable', missing: 10, critical: 3, installed: 100, last_contact: T0 }], patches: [{ patch_id: '901', name: 'Cumulative security update (synthetic)', severity: 'critical', missing: 2, released: T0 - 30 * D }] } };
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, now: () => clock.t, usHosts: () => W.hosts, usEc: () => W.ec });
  if (e.app.addons.updateHealth) e.app.addons.updateHealth.view = () => ({ pages: [] });
  // three days of samples: day 2 the DR host updates first, day 3 esx2 follows and WIN-APP01 installs patches
  const S = e.app.addons.updateStudio; S.snapshot();
  clock.t = T0 + D; W.hosts[2].version = 'VMware ESXi 8.0.3 build-24585383'; S.snapshot();
  clock.t = T0 + 2 * D; W.hosts[1].version = 'VMware ESXi 8.0.3 build-24585383'; W.ec.computers[0].installed = 104; S.snapshot();
  clock.t = Date.now();
  let WHO = OP;
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
  const url = 'http://127.0.0.1:' + srv.address().port + '/dashboards/update-studio.html';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg, { timeout: 15000 }).then(() => true, () => false);
  const tab = (p, t) => p.click('#tabs [data-tab="' + t + '"]');
  const as = async (p, who) => { WHO = who; await p.goto(url); await wait(p, () => !document.getElementById('main').hidden); };
  const T = (p) => p.textContent('#view');
  try {
    const ctx = await browser.newContext({ viewport: { width: 1440, height: 1000 }, acceptDownloads: true });
    const p = await ctx.newPage(); p.on('pageerror', (x) => errs.push(x.message));
    await as(p, OP);
    ok(/within policy/.test(await p.textContent('#ring')) && /of 5 measured/.test(await p.textContent('#ring')), 'ring with how many are measured');
    ok(/critical patches missing/.test(await p.textContent('#kpis')) && /patches past SLA/.test(await p.textContent('#kpis')), 'KPIs');
    ok(await p.$('#view svg rect title') && /VMware ESXi|esxi/.test(await T(p)), 'timeline of observed updates');
    ok(/VMware ESXi/.test(await T(p)) && /Oracle Solaris/.test(await T(p)), 'platform cards');
    // a rule opens the failing servers
    await p.click('tr[data-rule="UPD-04"]');
    ok(await wait(p, () => document.querySelectorAll('tr[data-srv]').length === 1 && /esx1/.test(document.getElementById('view').textContent)), 'UPD-04 lists the host behind its platform build');
    await p.selectOption('#frule', 'UPD-02');
    ok(await wait(p, () => /SOL-DB01/.test(document.getElementById('view').textContent)), 'the server no source reports on is listed as not reporting');
    await p.click('tr[data-srv="a-sol"]');
    ok(await wait(p, () => /no source reports on this server/.test(document.getElementById('view').textContent)), 'not measured says what to connect');
    await p.selectOption('#frule', ''); await p.click('tr[data-srv="a-win1"]');
    ok(await wait(p, () => /3 critical missing \+30/.test(document.getElementById('view').textContent)), 'risk reasons are itemised');
    // history + close-out
    await tab(p, 'history');
    ok(/esx3-dr/.test(await T(p)) && /esx2/.test(await T(p)) && /WIN-APP01/.test(await T(p)), 'three updates observed');
    ok(/not required/.test(await T(p)) && /missing/.test(await T(p)), 'DR host needs no change reference; production ones do');
    const ev2 = (await e.req('GET', '/updates', OP)).json.events.find((x) => x.asset === 'a-esx2').id;
    await p.click('[data-close="' + ev2 + '"]'); await wait(p, () => document.getElementById('cref'));
    await p.selectOption('#ccheck', 'failed'); await p.click('#csave');
    ok(await wait(p, () => /note is required when the post-update check failed/.test(document.body.textContent)), 'a failed check needs a note');
    await p.fill('#cref', 'CHG-2026-0142'); await p.selectOption('#ccheck', 'passed'); await p.fill('#cnote', 'vMotion back, services up'); await p.click('#csave');
    ok(await wait(p, () => /CHG-2026-0142/.test(document.getElementById('view').textContent) && /nora\.syn/.test(document.getElementById('view').textContent)), 'change reference and check recorded with who');
    // patches, drift
    await tab(p, 'patches'); ok(/Cumulative security update/.test(await T(p)) && /past SLA/.test(await T(p)) && /33 d \/ 15 d/.test(await T(p)), 'patch past its SLA');
    await tab(p, 'drift'); ok(/newest: VMware ESXi 8\.0\.3 build-24585383/.test(await T(p)) && /Hosts behind: esx1/.test(await T(p)), 'version drift');
    // Excel
    const [dl] = await Promise.all([p.waitForEvent('download', { timeout: 10000 }), p.click('#xls')]);
    ok(/^it-operations-updates-\d{4}-\d{2}-\d{2}\.xlsx$/.test(dl.suggestedFilename()), 'Excel export');
    // sample now
    await p.click('#sample'); ok(await wait(p, () => /Sample taken: 5 server/.test(document.body.textContent)), 'operator takes a sample');
    await tab(p, 'policy'); ok(/An administrator sets the policy/.test(await T(p)) && !(await p.$('#psave')), 'operator: policy read-only');
    await tab(p, 'ai'); ok(/AI update analyst is off/.test(await T(p)), 'AI off says why');
    // administrator: SLA
    await as(p, ADM); await tab(p, 'policy');
    await p.fill('#sla-critical', '60'); await p.click('#psave');
    ok(await wait(p, () => /critical <= important/.test(document.body.textContent)), 'a bad SLA order is refused');
    await p.fill('#sla-critical', '10'); await p.click('#psave');
    ok(await wait(p, () => /Policy saved/.test(document.body.textContent)), 'policy saved');
    // viewer
    await as(p, VW); ok(await p.$eval('#sample', (b) => b.hidden), 'viewer: no sample button');
    await tab(p, 'history'); ok(!(await p.$('[data-close]')), 'viewer: cannot record');
    ok(!(await p.evaluate(() => window.__xss)), 'hostile server name stayed text');
    const acts = e.app.store.auditTail(60).map((a) => a.action);
    ok(['updates.closeout', 'updates.sample', 'updates.policy'].every((a) => acts.includes(a)), 'audit records');
    const nav = fs.readFileSync(path.join(DASH, 'vendor', 'zyb-nav.js'), 'utf8');
    ok(/"h": "update-studio.html"/.test(nav) && /update-studio\.html/.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')), 'menu entry and installer');
    ok(/itops: 'update-studio\.html'/.test(fs.readFileSync(path.join(DASH, 'vendor', 'zyb-menu.js'), 'utf8')), 'the portal\'s sample "IT Operations & Updates" opens this page');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); await e.close(); }
  console.log((bad ? 'FAILED ' : 'ok ') + (n - bad) + '/' + n);
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
