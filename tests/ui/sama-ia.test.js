// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('../../brand/index');
// Browser test for the SAMA CSF & IA automated assessment (dashboards/server/sama-ia.html) against the REAL ITAM engine
// (engine/sama-ia.js, pyengine/sama_ia_rules.py) over SYNTHETIC facts: the readiness hero and KPIs, the five evidence pillars
// (a pillar filters the requirements), domains, the 32-subdomain maturity grid and its drawer, a hostile evidence text stays
// text, evidence recorded by an operator (a missing field refused with the reason) and approved by the CISO, the ML priorities
// and the trend tab, the IA view, a report drafted from the rules and approved by the CISO, the applicability decision, the
// CSV export, a viewer sees results without names, the menu has the page under Audit.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node sama-ia.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror=alert(1)>';
const OP = { user: 'nora.syn', role: 'operator' }, CISO = { user: 'khalid.syn', role: 'operator' }, ADM = { user: 'syed', role: 'admin' }, VIEW = { user: 'vera.syn', role: 'viewer' };
const FACTS = () => ({
  grc: { available: true, total: 20, reviews_overdue: 0, attested: 15, policies: [], control_status: {} },
  hardening: { available: true, assets: 40, scanned: 38, coverage_pct: 95, score: 82, fail: 30, critical_fail: 2 },
  pentest: { available: true, assets: 12, findings: 4, by_severity: { critical: 0, high: 0 }, internet_facing: 3, exposed_assets: 0 },
  cadence: { available: true, assets: 12, out_of_policy: 3 },
  siem: { available: true, sama: { '3.3.14': 'covered', '3.3.15': 'partial', '3.3.16': 'covered' }, retention_days: 400, logflow: { required: 10, silent: 0, not_onboarded: 0, no_connector: 0 } },
});

(async () => {
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3', samaFacts: async () => FACTS(), eccFacts: async () => FACTS() });
  const api = async (who, m, p, body) => { const r = await e.req(m, p, Object.assign(body !== undefined ? { body } : {}, who)); if (r.status !== 200) throw new Error(p + ': ' + r.raw); return r.json; };
  await api(ADM, 'POST', '/nca-ecc/profile', { ciso_user: CISO.user });
  await api(OP, 'POST', '/sama-ia/run', {});
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
    const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg, { timeout: 10000 }).then(() => true, () => false);
  const zd = (p, re) => wait(p, (src) => new RegExp(src).test((document.getElementById('zd') || {}).textContent || ''), re.source);
  const txt = (p, s) => p.textContent(s);
  try {
    const p = await browser.newPage({ viewport: { width: 1400, height: 950 }, acceptDownloads: true }); p.on('pageerror', (x) => errs.push(x.message));
    p.on('dialog', (d) => { errs.push('dialog: ' + d.message()); d.dismiss(); });
    await p.goto(base + 'sama-ia.html?standalone=1'); await p.waitForSelector('[data-sd]', { timeout: 15000 });
    ok((await p.$$('[data-sd]')).length === 32, 'the 32 SAMA subdomains');
    ok((await p.$$('[data-pil]')).length === 5, 'five evidence pillars');
    ok(/Hardening/.test(await txt(p, '#pillars')) && /SIEM logs/.test(await txt(p, '#pillars')) && /Pentest/.test(await txt(p, '#pillars')) && /GRC/.test(await txt(p, '#pillars')), 'GRC, Hardening, Pentest / VAPT and SIEM logs');
    ok(/subdomains at level 3/.test(await txt(p, '#hero')) && /Gaps/.test(await txt(p, '#kpis')), 'readiness hero and KPIs');
    ok(/indicative, from this register/.test(await txt(p, '.alert-info')), 'indicative, not a regulator rating');
    ok((await p.$$('#doms .bar')).length === 4, 'four domain bars');
    await p.click('[data-pil="hardening"]');
    ok(await wait(p, () => [...document.querySelectorAll('#reg tr[data-r]')].length === 5 && /critical hardening failure/.test(document.querySelector('#reg').textContent)), 'the Hardening pillar filters the requirements');
    await p.click('[data-pil="hardening"]');
    await p.click('[data-sd="3.3.14"]'); ok(await zd(p, /Rule that decided it/) && await zd(p, /every requirement met/), 'the subdomain drawer shows the maturity rule');
    await p.keyboard.press('Escape');
    // evidence recorded by an operator: a missing field refused, then recorded with a hostile string, then approved by the CISO
    await p.fill('#f-q', 'project management'); ok(await wait(p, () => document.querySelectorAll('#reg tr[data-r]').length === 1), 'search');
    await p.click('#reg tr[data-r]'); ok(await zd(p, /Record the evidence/), 'the requirement drawer');
    await p.click('#fc button[type=submit]'); ok(await zd(p, /evidence is required/), 'a missing evidence is refused with the field named');
    await p.fill('#fc-e', 'PSR-2026-04 ' + XSS); await p.click('#fc button[type=submit]');
    ok(await wait(p, () => /waiting for approval/.test(document.querySelector('#reg').textContent)), 'recorded, waiting for approval');
    WHO = CISO; await p.reload(); await p.waitForSelector('[data-sd]'); await p.fill('#f-q', 'project management');
    await p.click('#reg tr[data-r]'); ok(await zd(p, /waiting for the CISO/), 'the CISO sees the pending confirmation');
    ok(!(await p.$('#zd img')) && (await txt(p, '#zd')).includes('<img'), 'a hostile evidence text stays text');
    await p.click('#fdc [data-d="approve"]');
    ok(await wait(p, () => [...document.querySelectorAll('#reg .badge')].some((b) => b.textContent === 'met')), 'approved: met');
    // priorities, trend, IA
    await p.click('[data-tab="pri"]'); ok(await wait(p, () => document.querySelectorAll('#pri tr[data-r]').length > 3 && /chance of a gap next run/.test(document.querySelector('#pri').textContent)), 'ML priorities with every factor shown');
    await p.click('[data-tab="cov"]');
    ok(await wait(p, () => /Verified automatically/.test(document.querySelector('#cov-k').textContent) && /badge-access/.test(document.querySelector('#cov-r').textContent)), 'coverage: the automated share and the recommendations');
    ok(await wait(p, () => document.querySelectorAll('#cov-s a[href]').length > 20 && /hardening\.html/.test(document.querySelector('#cov-s').innerHTML)), 'each subdomain lists the platform pages that support it');
    ok(/Privileged Access|Non-Human Identities|internal Greenbone|HR Offboarding/.test(await txt(p, '#cov-c')), 'the sources to connect are named');
    await p.click('[data-tab="trend"]'); ok(/daily runs/.test(await txt(p, '#trend')), 'the trend tab says how much history it has');
    await p.click('[data-tab="ia"]'); ok(/UTC\/277\/202401/.test(await txt(p, '#ia')) && /IA-277-01/.test(await txt(p, '#iareg')), 'the Insurance Authority view');
    // the report: drafted from the rules by the operator, approved by the CISO
    WHO = OP; await p.reload(); await p.waitForSelector('[data-sd]'); await p.click('[data-tab="rep"]');
    ok(/rules only/.test(await txt(p, '#ais')) && await p.isHidden('#rep-a'), 'AI off: the reason is shown and the AI button hidden');
    await p.click('#rep-r'); ok(await zd(p, /Executive summary/) && await zd(p, /Roadmap/), 'the rule report opens');
    WHO = CISO; await p.reload(); await p.waitForSelector('[data-sd]'); await p.click('[data-tab="rep"]');
    await p.click('#reps tr[data-rep]'); await p.click('#fr [data-d="approve"]');
    ok(await wait(p, () => /approved/.test(document.querySelector('#reps').textContent)), 'the report is approved by the CISO');
    // applicability by an administrator, with a reason
    WHO = ADM; await p.reload(); await p.waitForSelector('#appl'); await p.click('#appl');
    await p.selectOption('#fa-3_3_12', 'not_applicable'); await p.click('#fa button[type=submit]'); ok(await zd(p, /applicability_note/), 'a decision without a reason is refused');
    await p.fill('#fa-n-3_3_12', (ZYB_ORG.short + ' runs no payment system (synthetic)')); await p.click('#fa button[type=submit]');
    ok(await wait(p, () => /3\.3\.13/.test((document.getElementById('hero') || {}).textContent) && !/3\.3\.12/.test(document.getElementById('hero').textContent)), 'only 3.3.13 is left to decide');
    const [dl] = await Promise.all([p.waitForEvent('download'), p.click('#csv')]);
    ok(/^sama-ia-assessment-\d{4}-\d{2}-\d{2}\.csv$/.test(dl.suggestedFilename()), 'CSV export');
    ok(await p.evaluate(() => { const a = (window.ZYB_NAV || []).find((x) => x.id === 'cmp'); return !!(a && a.pages.some((x) => x.h === 'sama-ia.html' && x.g === 'SAMA & Insurance Authority')); }), 'the menu has the page under Compliance -> SAMA & Insurance Authority');
    WHO = VIEW; await p.reload(); await p.waitForSelector('[data-sd]');
    ok(!(await txt(p, 'body')).includes(OP.user) && !(await txt(p, 'body')).includes(CISO.user), 'a viewer sees results without names');
    await p.click('[data-tab="rep"]'); ok(await wait(p, () => /operators and administrators/.test(document.querySelector('#reps').textContent)), 'a viewer is told the reports are not for them');
  } finally { await browser.close(); srv.close(); await e.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks');
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
