// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for the CISO's and the IT Manager's workspaces (dashboards/server/my-workspace.html, tabs "Security" and
// "IT Operations") against the REAL ITAM engines (team workspace, roles, GRC register, role briefs) with the AI CISO and the
// infrastructure overview stubbed with SYNTHETIC figures: an administrator gives each person the job title and the access role; each
// workspace opens on its own tab with the brief, the KPIs, the ranked priorities (points shown, a hostile title stays text) and what is
// not connected; someone with neither title sees neither tab; the CISO tab in Arabic.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node role-workspace.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const ADM = { user: 'syed', role: 'admin' }, CISO = { user: 'ciso.syn', role: 'operator' }, ITM = { user: 'itm.syn', role: 'operator' }, OTHER = { user: 'other.syn', role: 'operator' };
const XSS = '<img src=x onerror="window.__xss=1">';

(async () => {
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true });
  if (e.app.addons.updateHealth) e.app.addons.updateHealth.view = () => ({ pages: [] });
  e.app.addons.ciso = { overview: async () => ({ posture: { overall: 64, grade: 'weak', domains: [{ id: 'detection', name: 'Detection & response', score: 48, measured: true }, { id: 'exposure', name: 'Exposure', score: null, measured: false }] },
    risks: [{ ref: 'duty:SYN-1', severity: 'critical', title: 'Ransomware indicators on a file server (synthetic) ' + XSS, source: 'AI security engineer', domain: 'detection', age_h: 100 }, { ref: 'drill:SYN-2', severity: 'high', title: 'DR drill overdue (synthetic)', source: 'DR drills', domain: 'resilience', age_h: 5 }],
    decisions: [{ ref: 'appr:SYN-9', kind: 'change plan', severity: 'high', title: 'Firewall change plan awaiting approval (synthetic)' }], soc: { open_by_severity: { critical: 2, high: 5 }, sla: { breaching_now: 3 } }, compliance: { sama: { coverage_pct: 71 } }, sources: [{ name: 'Pentest', state: 'error', error: 'not connected' }] }) };
  e.app.addons.infraOverview = { view: () => ({ register: { available: true, servers: { total: 40 }, network: { total: 12 }, warranty: { expired: 2 } }, backup: { available: true, protected_pct: 85, failed: 2, none: 3, stale: 0 },
    patch: { available: false, why: 'ManageEngine is not installed (synthetic)' }, lifecycle: { available: true, eol: 4, soon: 2, isolation_required: 1 }, storage: { available: true, used_pct: 91, failed_disks: 1 }, contracts: { available: true, expired: 1, expiring: 3 } }) };
  const ADR = (o) => Object.assign({ at: new Date(Date.now() - 3600000).toISOString(), reason: 'synthetic' }, o);
  e.app.addons.adManage = { view: (who) => ({ connection: { ok: true, base_dn: 'DC=synthetic,DC=test' }, settings: { enabled: true, delete_enabled: true }, requests: [
    ADR({ id: 'adr_00000000000000a1', status: 'pending', by: 'huda.syn', action: 'delete', summary: 'DELETE coral.syn ' + XSS }), ADR({ id: 'adr_00000000000000a2', status: 'pending', by: 'itm.syn', action: 'enable', summary: 'enable dina.syn' }),
    ADR({ id: 'adr_00000000000000a3', status: 'done', by: 'huda.syn', action: 'disable', summary: 'disable eisa.syn', review: 'pending', emergency: true, decided_by: 'huda.syn' })] }) };
  { const W = e.app.addons.workflow, adm = { user: 'syed', role: 'admin', ip: '' };   // the real Workflow Automation engine, synthetic people
    W.settingsSave({ version: 0, functions: { ciso: ['ciso.syn'] }, teams: { identity: ['idm.syn'], security: ['sec.syn'] }, leads: { identity: ['itm.syn'] } }, adm);
    const cr = W.create({ type: 'cert-status', from: 'ciso', title: 'Certificates expiring in Q1 ' + XSS, details: 'list' }, { user: 'ciso.syn', role: 'operator', ip: '' });
    W.act(cr.id, 'start', {}, { user: 'sec.syn', role: 'operator', ip: '' }); W.act(cr.id, 'fulfil', { response: 'attached' }, { user: 'sec.syn', role: 'operator', ip: '' });
    W.create({ type: 'leaver-disable', from: 'hr', title: 'Leaver synthetic ' + XSS, details: 'last day', priority: 'high' }, { user: 'hr.syn', role: 'viewer', ip: '' }); }
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
  const txt = (p) => p.evaluate(() => document.body.innerText);
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg, { timeout: 15000 }).then(() => true, () => false);
  try {
    const api = async (who, m, p, b) => { const r = await e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, who)); if (r.status !== 200) throw new Error(p + ': ' + r.raw); return r.json; };
    await api(ADM, 'POST', '/workspace/template', { template: 'standard-it' });
    await api(ADM, 'POST', '/workspace/people', { id: 'ciso', name: 'CISO Syn', user: 'ciso.syn', email: 'ciso.syn@corpgroup.test', department: 'cyber-security', role: 'ciso' });
    await api(ADM, 'POST', '/roles/assign', { user: 'ciso.syn', role_id: 'ciso' });
    await api(ADM, 'POST', '/workspace/people', { id: 'itm', name: 'IT Manager Syn', user: 'itm.syn', email: 'itm.syn@corpgroup.test', department: 'infrastructure', role: 'infra-manager' });
    await api(ADM, 'POST', '/roles/assign', { user: 'itm.syn', role_id: 'infra-manager' });
    await api(ADM, 'POST', '/workspace/people', { id: 'other', name: 'Other Syn', user: 'other.syn', email: 'other.syn@corpgroup.test', department: 'infrastructure', role: 'desktop-support-engineer' });
    const d = (n2) => new Date(Date.now() + n2 * 86400000).toISOString().slice(0, 10);
    await api(CISO, 'POST', '/grc/actions', { title: 'Close the synthetic pentest findings', owner: 'ciso.syn', due: d(-4), source: 'manual' });
    // the CISO
    WHO = CISO; const p = await browser.newPage({ viewport: { width: 1440, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto(base + 'dashboards/my-workspace.html');
    ok(await wait(p, () => !!document.querySelector('#tabs [data-tab="ciso"][aria-selected="true"]')), 'the CISO workspace opens on the Security tab');
    ok(await wait(p, () => /Security posture 64 \/ 100/.test((document.getElementById('cisobrief') || {}).textContent || '')), 'the brief: posture');
    ok(/SAMA CSF evidence coverage 71/.test(await p.textContent('#cisobrief')) && /CISO Dashboard/.test(await p.textContent('#cisobrief')), 'the brief: SAMA coverage, links to his pages');
    const k = await p.textContent('#cisokpis'); ok(/64/.test(k) && /critical alerts open/i.test(k), 'KPIs');
    const pr = await p.textContent('#cisoprio'); ok(/1\. ACT-/.test(pr) && /your action, overdue \+60/.test(pr), 'priorities ranked, his overdue action first, points shown');
    ok(/duty:SYN-1/.test(pr) && /appr:SYN-9/.test(pr) && /soc:sla/.test(pr), 'security risk, decision waiting and SLA breach are priorities');
    ok(!(await p.$('#cisoprio img')) && !(await p.evaluate(() => window.__xss)), 'a hostile title stays text');
    ok(await wait(p, () => !!document.getElementById('cisowf')), 'the Security tab has a Workflow Automation card');
    const cw = await p.textContent('#cisowf'); ok(/1\s*results for you to accept/.test(cw) && /late with the IT teams/.test(cw) && /Certificates expiring in Q1 <img/.test(cw) && !(await p.$('#cisowf img')), 'Workflow (CISO): the result waiting for his acceptance; a hostile title stays text: ' + cw.replace(/\s+/g, ' ').slice(0, 200));
    ok(!!(await p.$('#cisowf a[href="workflow-automation.html#tab=new"]')) && /requests needing me/.test(await p.textContent('#cisokpis')) && /Workflow Automation: 0 request\(s\) from you and the CISO office open with the IT teams, 1 result\(s\) waiting for your acceptance/.test(await p.textContent('#cisobrief')) && /Certificates expiring in Q1/.test(await p.textContent('#cisoprio')), 'Workflow (CISO): New request link, the KPI, the brief line and the priority');
    ok(/not measured/.test(await p.textContent('#cisodom')), 'a domain without data says not measured');
    ok(/Pentest: not connected/.test(await txt(p)), 'what is not connected is named');
    ok(!!(await p.$('#tabs [data-tab="risk"]')) && !(await p.$('#tabs [data-tab="itm"]')), 'the CISO also has Risk & Compliance (he manages risk), not IT Operations');
    // the IT Manager
    WHO = ITM; const q = await browser.newPage({ viewport: { width: 1440, height: 1000 } }); q.on('pageerror', (x) => errs.push(x.message));
    await q.goto(base + 'dashboards/my-workspace.html');
    ok(await wait(q, () => !!document.querySelector('#tabs [data-tab="itm"][aria-selected="true"]')), 'the IT Manager workspace opens on the IT Operations tab');
    ok(await wait(q, () => /85 % of servers protected, 2 failed/.test((document.getElementById('itmbrief') || {}).textContent || '')), 'the brief: backups');
    ok(/Patching: not measured/.test(await q.textContent('#itmbrief')) && /ManageEngine is not installed/.test(await txt(q)), 'patching not connected: said, never zero');
    ok(await wait(q, () => !!document.getElementById('itmad')), 'the IT Operations tab has an AD Management card');
    const ad = await q.textContent('#itmad'); ok(/1\s*waiting for your approval/.test(ad) && /1\s*emergency disables to review/.test(ad) && /1\s*your requests waiting/.test(ad), 'AD: waiting for him, reviews, his own requests waiting: ' + ad.replace(/\s+/g, ' ').slice(0, 200));
    ok(/DELETE coral\.syn <img/.test(ad) && !(await q.evaluate(() => window.__xss)), 'AD: a hostile summary stays text');
    ok(!!(await q.$('#itmad a[href="ad-manage.html"].btn')) && /AD changes for me/.test(await q.textContent('#itmkpis')) && /AD Management: 1 change\(s\) waiting for your approval/.test(await q.textContent('#itmbrief')), 'AD: the link, the KPI and the brief line');
    ok(/DELETE coral\.syn/.test(await q.textContent('#itmprio')) && /permanent delete \+10/.test(await q.textContent('#itmprio')) && !/enable dina\.syn/.test(await q.textContent('#itmprio')), 'AD: the delete is a priority with its points; his own request is not');
    ok(await wait(q, () => !!document.getElementById('itmwf')), 'the IT Operations tab has a Workflow Automation card');
    const wf = await q.textContent('#itmwf'); ok(/1\s*waiting for your approval/.test(wf) && /Leaver synthetic <img/.test(wf) && /Identity & access/.test(wf) && !(await q.evaluate(() => window.__xss)), 'Workflow: the leaver request waits for him; a hostile title stays text: ' + wf.replace(/\s+/g, ' ').slice(0, 200));
    ok(!!(await q.$('#itmwf a[href="workflow-automation.html"].btn')) && !!(await q.$('#itmwf a[href^="workflow-automation.html#req=REQ-"]')) && /requests needing me/.test(await q.textContent('#itmkpis')) && /Workflow Automation: 1 request\(s\) waiting for your approval/.test(await q.textContent('#itmbrief')) && /Leaver synthetic/.test(await q.textContent('#itmprio')), 'Workflow: the links, the KPI, the brief line and the priority');
    const qp = await q.textContent('#itmprio'); ok(/backup:failed/.test(qp) && /storage:disks/.test(qp) && /isolation required \+10/.test(qp) && /drill:SYN-2/.test(qp), 'infrastructure priorities with their points');
    ok(!/duty:SYN-1/.test(qp), 'a detection risk is the CISO\'s, not the IT Manager\'s');
    ok(!(await q.$('#tabs [data-tab="ciso"]')), 'no Security tab for the IT Manager');
    // someone with neither title
    WHO = OTHER; const o = await browser.newPage(); o.on('pageerror', (x) => errs.push(x.message)); await o.goto(base + 'dashboards/my-workspace.html');
    ok(await wait(o, () => !!document.querySelector('#tabs [data-tab="overview"]')) && !(await o.$('#tabs [data-tab="ciso"]')) && !(await o.$('#tabs [data-tab="itm"]')), 'no role tab without the title');
    // the CISO in Arabic
    WHO = CISO; await p.evaluate(() => localStorage.setItem('zyb-dash-prefs', JSON.stringify({ lang: 'ar' }))); await p.goto(base + 'dashboards/my-workspace.html');
    ok(await wait(p, () => document.documentElement.dir === 'rtl' && /موجزك/.test((document.getElementById('cisobrief') || {}).textContent || '') && /الأولويات/.test((document.getElementById('cisoprio') || {}).textContent || '')), 'the Security tab in Arabic, right to left');
  } finally { await browser.close(); srv.close(); await e.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks');
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
