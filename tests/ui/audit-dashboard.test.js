// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for the Audit Dashboard (audit-dashboard.html) against the REAL ITAM engine, SYNTHETIC data only: frameworks
// with no assessment read "not assessed" (no score); an assessed SAMA check gets a score and its gap opens in a drawer (a hostile
// note stays text); an overdue Internal Audit finding tops the attention list and links to its team; the teams table and the AI
// programmes render; the CSV export downloads and is recorded; a viewer is refused with the reason; no page error.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node audit-dashboard.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror=alert(1)>';

(async () => {
  const e = await H.startApp({ noAi: true });
  let clock = Date.parse('2027-01-10T08:00:00Z');
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, now: () => clock, python: process.env.PYTHON || 'python3', eccFacts: async () => ({}), ndmoCatalogFiles: false });
  const ADM = { user: 'syed', role: 'admin' }, OP = { user: 'nora.syn', role: 'operator' }, HEAD = { user: 'noura.syn', role: 'operator' }, LEAD = { user: 'faris.syn', role: 'operator' }, OWNER = { user: 'majed.syn', role: 'operator' }, VIEW = { user: 'vera.syn', role: 'viewer' };
  const api = async (m, p, body, who) => { const r = await e.req(m, p, Object.assign({ body }, who)); if (r.status !== 200) throw new Error(p + ': ' + r.raw); return r.json; };
  await api('POST', '/audit-checklist/assess', { id: 'AC-01', status: 'non_compliant', note: XSS + ' no evidence of review (synthetic)' }, OP);
  await api('POST', '/iad/profile', { head_of_audit: HEAD.user, auditors: [LEAD.user] }, ADM);
  const eng = await api('POST', '/iad/engagements', { title: 'Claims (synthetic)', area: 'claims', auditee_dept: 'Claims', auditee_owner: OWNER.user, lead: LEAD.user, objectives: ['o'], scope: 's', start: '2027-01-10', fieldwork_end: '2027-01-31', report_due: '2027-02-15' }, LEAD);
  await (await api('POST', '/iad/engagements/' + eng.id + '/prior-none', { note: 'first audit of this area (synthetic)' }, LEAD), api('POST', '/iad/engagements/' + eng.id + '/advance', { to: 'fieldwork' }, LEAD));
  const f = await api('POST', '/iad/engagements/' + eng.id + '/findings', { title: XSS + ' Claims paid above authority', condition: 'c', criteria: 'cr', cause: 'ca', effect: 'ef', recommendation: 'r', rating: 'high', owner: OWNER.user }, LEAD);
  await api('POST', '/iad/findings/' + f.id + '/issue', {}, LEAD);
  await api('POST', '/iad/findings/' + f.id + '/respond', { response: 'ok', action_plan: 'second approval', due: '2027-01-20' }, OWNER);
  clock += 20 * 86400000;
  { // Workflow Automation (the real engine, the same clock): audit's evidence request late with the DBA team, a backup evidence result to accept
    const W = e.app.addons.workflow, wc = e.app.store.collection('wf_requests');
    W.settingsSave({ version: 0, functions: { audit: ['nora.syn'] }, teams: { dba: ['dba.syn'], backup: ['bk.syn'] } }, { user: 'syed', role: 'admin', ip: '' });
    const late = W.create({ type: 'db-user-review', from: 'audit', title: 'PBC: database accounts <img src=x onerror=window.__wfx=1>', details: 'all DBA accounts', priority: 'high' }, { user: 'nora.syn', role: 'operator', ip: '' });
    const lr = wc.get(late.id); lr.due = new Date(clock - 3600000).toISOString(); wc.put(lr);
    const done = W.create({ type: 'backup-evidence', from: 'audit', title: 'PBC: backup success evidence', details: 'Q4' }, { user: 'nora.syn', role: 'operator', ip: '' });
    W.act(done.id, 'evidence', { kind: 'note', text: 'report attached' }, { user: 'bk.syn', role: 'operator', ip: '' }); W.act(done.id, 'fulfil', { response: 'attached' }, { user: 'bk.syn', role: 'operator', ip: '' }); }
  let WHO = OP;
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b2) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b2)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, WHO);
    if (u.pathname.startsWith('/api/itam/')) {
      const h = Object.assign({}, req.headers, { 'x-sentra-proxy-secret': H.SECRET, 'x-auth-user': WHO.user, 'x-auth-role': WHO.role });
      const up = http.request({ host: '127.0.0.1', port: e.port, method: req.method, path: req.url, headers: h }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); });
      req.pipe(up); return;
    }
    if (u.pathname.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const fl = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')); if (!fl.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(fl, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  try {
    const p = await browser.newPage({ viewport: { width: 1400, height: 1100 }, acceptDownloads: true }); p.on('pageerror', (x) => errs.push(x.message));
    p.on('dialog', (d) => { errs.push('dialog ' + d.message()); d.dismiss(); });
    await p.goto(base + 'audit-dashboard.html?standalone=1'); await p.waitForSelector('#fws .fw', { timeout: 20000 });
    { await p.waitForFunction(() => !document.getElementById('wfcard').hidden && /backup success evidence/.test(document.getElementById('wf').textContent), null, { timeout: 10000 }).catch(() => null);
      const w = await p.textContent('#wfcard');
      ok(/1\s*open with the IT teams/.test(w) && /1\s*late with the IT teams/.test(w) && /1\s*results for you to accept/.test(w) && /100 %\s*IT teams on time \(1 of 1\)/.test(w), 'Workflow Automation: audit\'s evidence requests - open, late, to accept, on time: ' + w.replace(/\s+/g, ' ').slice(0, 240));
      ok(w.indexOf('PBC: database accounts') < w.indexOf('PBC: backup success') && /PBC: database accounts <img/.test(w) && !(await p.$('#wfcard img')) && !(await p.evaluate(() => window.__wfx)) && /late with the IT team \+35, high priority \+10/.test(w), 'Workflow: ranked by points with reasons; a hostile title stays text'); }
    const cards = await p.$$eval('#fws .fw', (x) => x.map((c) => c.textContent));
    ok(cards.length === 6, 'six framework cards (ISO 27001 included): ' + cards.length);
    ok(/PDPL \(SDAIA\)/.test(cards[0]) && /not assessed—not assessed yet/.test(cards[0]), 'PDPL reads not assessed, with no score');
    const samaCard = cards.find((c) => /SAMA Cyber Security Framework/.test(c));
    ok(/\d+%/.test(samaCard) && /gaps/.test(samaCard), 'the assessed SAMA checklist has a score and gaps');
    ok(/1Overdueauditfindings/.test((await p.textContent('#kpis')).replace(/\s+/g, '')), 'the overdue finding is counted');
    ok(/Opencontrol-monitoringexceptions/.test((await p.textContent('#kpis')).replace(/\s+/g, '')) && /PDPLdeadlinesatrisk/.test((await p.textContent('#kpis')).replace(/\s+/g, '')), 'control monitoring and PDPL deadlines have their tiles');
    const first = await p.textContent('#att .bi');
    ok(first.includes(f.id) && /Internal Audit Team/.test(first), 'the overdue Internal Audit finding tops the attention list');
    ok(await p.getAttribute('#att .bi a', 'href') === 'internal-audit-team.html', 'it links to its team');
    ok(!(await p.$('img[src="x"]')), 'hostile text is shown as text');
    await p.click('[data-fw="sama"]'); await p.waitForSelector('#zd', { timeout: 8000 });
    ok(/AC-01/.test(await p.textContent('#zd')) && !(await p.$('#zd img[src="x"]')), 'the SAMA gap opens in the drawer, as text');
    await p.keyboard.press('Escape'); await p.waitForFunction(() => { const z = document.getElementById('zd'); return !z || !z.offsetParent || getComputedStyle(z).display === 'none'; }, null, { timeout: 5000 }).catch(() => {});
    ok(/Internal Audit Team/.test(await p.textContent('#teams')) && /noura\.syn/.test(await p.textContent('#teams')) && /1 overdue/.test(await p.textContent('#teams')), 'the teams table');
    ok(/AI IT Auditor/.test(await p.textContent('#prog')), 'the AI audit programmes');
    // the insight: index (assessed or withheld, said why), breakdown, matrix, delivery, analytics, ranked attention, advisor
    ok(/assurance index/i.test(await p.textContent('#gauge')) && (await p.textContent('#gwhy')).length > 5, 'the assurance index gauge says its state');
    ok((await p.$$('#ix > div')).length >= 1, 'the index breakdown is itemised');
    ok((await p.$$('#mx tbody tr')).length === 6, 'the coverage matrix: one row per framework');
    ok(/Internal Audit Team/.test(await p.textContent('#dlv')) && /%/.test(await p.textContent('#dlv')), 'audit-team delivery');
    ok(/runs/.test(await p.textContent('#an')) && /awaiting review/.test(await p.textContent('#an')), 'the audit analytics card');
    ok(/priority \d+/.test(await p.textContent('#att .bi')) && /days? overdue|severity/.test(await p.textContent('#att .bi')), 'attention ranked, each point itemised');
    ok((await p.$$('#fws .stack')).length === 6 && (await p.$$('#fws .fw .spark, #fws .fw .mut')).length > 0, 'framework distribution bars and trends');
    ok(/Not available/.test(await p.textContent('#ais')), 'the advisor is off until allowed');
    if (process.env.SHOT) await p.screenshot({ path: process.env.SHOT, fullPage: true });
    ok(/Human Resources/.test(await p.textContent('#depts')) && /Not assessed/i.test(await p.textContent('#depts')), 'the departments section');
    const [dl] = await Promise.all([p.waitForEvent('download', { timeout: 10000 }), p.click('#csv')]);
    ok(/^audit-dashboard-\d{4}-\d{2}-\d{2}\.csv$/.test(dl.suggestedFilename()), 'CSV downloaded: ' + dl.suggestedFilename());
    ok(e.app.store.auditTail(50).some((x) => x.action === 'audit-dashboard.export' && x.by === OP.user), 'the export is recorded');
    WHO = VIEW; await p.reload();
    await p.waitForFunction(() => /operator role/.test(document.getElementById('fws').textContent), null, { timeout: 10000 }).then(() => ok(true, 'viewer refused with the reason'), () => ok(false, 'viewer refused with the reason'));
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } catch (x) { ok(false, 'exception: ' + (x && x.stack || x)); }
  await browser.close(); srv.close(); await e.close();
  console.log(bad ? `${bad}/${n} FAILED` : `all ${n} checks passed`);
  process.exit(bad ? 1 : 0);
})();
