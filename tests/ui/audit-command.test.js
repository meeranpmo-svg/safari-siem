// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Audit Command Center (audit-command.html) against the REAL ITAM engines (engine/audit-auto.js over the Cyber Security Audit Team
// engine) with SYNTHETIC leavers: readiness ring and KPIs; use cases with population, exceptions and "not testable"; chips and the team
// filter; the use-case drawer with its exception records (hostile label stays text); Run now proposes findings; an auditor accepts one
// into an engagement in fieldwork (raised as a draft finding in the team) and dismisses another with a reason; follow-up of an overdue
// finding; the administrator saves the automation rules; a viewer is refused; menu entry and installer.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node audit-command.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };

(async () => {
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3' });
  const col = (c) => e.app.store.collection(c), today = new Date().toISOString().slice(0, 10), dayOff = (d) => new Date(Date.now() + d * 86400000).toISOString().slice(0, 10);
  for (let i = 1; i <= 8; i++) { const last = dayOff(-10 - i);
    col('offboarding').put({ id: 'OFF-' + i, username: i === 2 ? '<img src=x onerror="window.__xss=1">' : 'leaver' + i + '.syn', last_day: last, requested_by: 'hr.syn', status: 'completed',
      disable: { approved_by: i === 4 ? 'hr.syn' : 'mgr.syn' }, disabled: i === 2 ? null : { at: last + 'T10:00:00Z' } }); }
  const A = { user: 'laila.syn', role: 'operator' }, ADM = { user: 'syed', role: 'admin' };
  const P = async (p, b, who = A) => { const r = await e.req('POST', p, { body: b, user: who.user, role: who.role }); if (r.status !== 200) throw new Error(p + ' ' + r.status + ' ' + r.raw); return r.json; };
  await P('/csa/profile', { head_of_audit: 'hana.syn', auditors: ['laila.syn', 'adel.syn'], engagements_per_year: 4 }, ADM);
  const E = (await P('/csa/engagements', { title: 'Identity lifecycle (synthetic)', area: 'iam', auditee_dept: 'IT', auditee_owner: 'omar.syn', lead: 'laila.syn', team: ['adel.syn'], objectives: ['Leavers lose access'], scope: 'All leavers', criteria: 'NCA ECC 2-2', start: today, fieldwork_end: dayOff(20), report_due: dayOff(30) })).id;
  await (await P('/csa/engagements/' + E + '/prior-none', { note: 'first audit of this area (synthetic)' }), P('/csa/engagements/' + E + '/advance', { to: 'fieldwork' }));
  const F = (await P('/csa/engagements/' + E + '/findings', { title: 'Firewall rule review not performed (synthetic)', condition: 'c', criteria: 'k', cause: 'x', effect: 'y', recommendation: 'z', rating: 'high', owner: 'omar.syn' })).id;
  await P('/csa/findings/' + F + '/issue', {});
  col('csa_findings').put(Object.assign(col('csa_findings').get(F), { state: 'responded', due: dayOff(-3), response: 'r', action_plan: 'a' }));   // an overdue finding
  let WHO = { user: 'laila.syn', role: 'operator' };
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, WHO);
    if (u.pathname.startsWith('/api/itam/')) {
      const h = Object.assign({}, req.headers, { 'x-sentra-proxy-secret': H.SECRET, 'x-auth-user': WHO.user, 'x-auth-role': WHO.role });
      const up = http.request({ host: '127.0.0.1', port: e.port, method: req.method, path: req.url, headers: h }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); });
      req.pipe(up); return;
    }
    if (u.pathname.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': f.endsWith('.js') ? 'application/javascript' : f.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/dashboards/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg, { timeout: 30000 }).then(() => true, () => false);
  const toast = (p, re) => wait(p, (s) => [...document.querySelectorAll('.toast')].some((t) => new RegExp(s).test(t.textContent)), re);
  let ANS = [];
  const page = async (ctx, f, noMain) => { const p = await ctx.newPage(); p.on('pageerror', (x) => errs.push(x.message)); p.on('dialog', (d) => { const a = ANS.shift(); if (a === undefined) { errs.push('unexpected dialog: ' + d.message()); d.dismiss(); } else d.accept(a); }); await p.goto(base + f + '?standalone=1'); if (!noMain) await p.waitForSelector('#main:not([hidden])', { timeout: 60000 }); return p; };
  try {
    const ctx = await browser.newContext({ viewport: { width: 1500, height: 1000 } });
    let p = await page(ctx, 'audit-command.html');
    ok(/control readiness/.test(await p.textContent('#ring')), 'readiness ring');
    ok(/Use cases tested/.test(await p.textContent('#kpis')) && /Likely to slip/.test(await p.textContent('#kpis')), 'KPIs');
    ok(await wait(p, () => document.querySelectorAll('#ucs tr[data-uc]').length >= 20), 'every use case listed');
    ok(/not testable/.test(await p.textContent('#ucs tr[data-uc="UC-19"]')), 'no DSR records: not testable');
    ok(/2/.test(await p.textContent('#ucs tr[data-uc="UC-01"] td:nth-child(5)')) || /1/.test(await p.textContent('#ucs tr[data-uc="UC-01"] td:nth-child(5)')), 'UC-01 exceptions counted');
    // the visual layer: pipeline, use-case map, framework assurance, risk x result, connect to unlock
    ok((await p.$$('#pipe .pn')).length === 7 && /Findings proposed/.test(await p.textContent('#pipe')), 'the automation pipeline');
    ok((await p.$$('#ucmap [data-uct]')).length >= 20 && (await p.$$('#ucmap .tile.s-exceptions')).length >= 1, 'the use-case map, exceptions marked');
    ok(/NCA ECC/.test(await p.textContent('#fwa')) && /ISO 27001/.test(await p.textContent('#fwa')), 'framework assurance');
    ok((await p.$$('#rmx tbody tr')).length === 3, 'risk x result matrix');
    ok(/would make/.test(await p.textContent('#unl')) && (await p.$$('#unl .unl')).length >= 5 && !/^\s*\d+\s*other/.test(await p.textContent('#unl')), 'connect to unlock: the sources ranked');
    await p.click('#ucmap [data-uct="UC-01"]'); ok(await wait(p, () => /OFF-2/.test(document.getElementById('dlgb').textContent)), 'a tile opens its use case');
    await p.keyboard.press('Escape'); await p.evaluate(() => { const d = document.getElementById('dlg'); if (d) d.hidden = true; });
    await p.click('[data-uf="exceptions"]'); ok(await wait(p, () => [...document.querySelectorAll('#ucs tr[data-uc]')].every((r) => /exceptions/.test(r.textContent)) && document.querySelectorAll('#ucs tr[data-uc]').length >= 2), 'With exceptions chip');
    await p.click('#ucs tr[data-uc="UC-01"]'); ok(await wait(p, () => /OFF-2/.test(document.getElementById('dlgb').textContent) && /Objective/i.test(document.getElementById('dlgb').textContent)), 'use-case drawer with the exception records');
    ok(await p.evaluate(() => !window.__xss && /<img/.test(document.getElementById('dlgb').textContent)), 'a hostile label stays text');
    await p.click('[data-close]'); await p.click('[data-uf="all"]');
    await p.selectOption('#team', 'Internal Audit Team'); ok(await wait(p, () => [...document.querySelectorAll('#ucs tr[data-uc]')].every((r) => /Internal Audit Team/.test(r.textContent))), 'team filter');
    await p.selectOption('#team', '');
    await p.click('#run'); ok(await toast(p, 'Run done'), 'Run now');
    ok(await wait(p, () => document.querySelectorAll('[data-pa]').length >= 2), 'findings proposed');
    ok(await wait(p, (f) => document.getElementById('fups').textContent.includes(f), F), 'the overdue finding is followed up');
    const first = await p.$eval('[data-pa]', (b) => b.getAttribute('data-pa'));
    await p.click('[data-pa="' + first + '"]'); await p.waitForSelector('#aform');
    ok((await p.$$eval('#aform select[name=engagement] option', (o) => o.map((x) => x.value))).includes(E), 'the engagement in fieldwork is offered');
    await p.fill('#aform [name=owner]', 'omar.syn'); await p.click('#aform button[type=submit]'); ok(await toast(p, 'Raised as a draft finding'), 'accepted into the engagement');
    ok((await e.req('GET', '/csa/findings', { user: A.user, role: A.role })).json.some((f) => f.state === 'draft' && /record\(s\) failed/.test(f.title)), 'the team has the draft finding');
    ANS = ['covered by the finding raised just now (synthetic)']; await p.click('[data-pd]'); ok(await toast(p, 'Proposal dismissed'), 'dismissed with a reason');
    ok(/accepted by laila\.syn/.test(await p.textContent('#props')) && /dismissed by laila\.syn/.test(await p.textContent('#props')), 'decisions listed with who decided');
    ok(!(await p.$('#sform button[type=submit]')), 'an operator cannot change the rules');
    if (process.env.SHOT) await p.screenshot({ path: process.env.SHOT, fullPage: true });   // optional: a picture for review
    WHO = ADM; p = await page(ctx, 'audit-command.html');
    await p.fill('#sform [name=escalate_days]', '10'); await p.click('#sform button[type=submit]'); ok(await toast(p, 'Automation rules saved'), 'administrator saves the rules');
    ok(await wait(p, () => document.getElementById('escd').textContent === '10'), 'the new escalation point is shown');
    WHO = { user: 'vera.syn', role: 'viewer' }; p = await page(ctx, 'audit-command.html', true);
    ok(await wait(p, () => /operators and administrators/.test(document.getElementById('err').textContent)), 'a viewer is refused');
    const nav = fs.readFileSync(path.join(DASH, 'vendor', 'zyb-nav.js'), 'utf8');
    ok(/"h": "audit-command.html"/.test(nav) && /audit-command\.html/.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')), 'menu entry and installer');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); await e.close(); }
  console.log((bad ? 'FAILED ' : 'ok ') + (n - bad) + '/' + n);
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
