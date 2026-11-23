// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for the Compliance Assistant (dashboards/server/compliance-assistant.html + vendor/zyb-assist.js) against the REAL
// ITAM engine (engine/compliance-assist.js, pyengine/assist_rules.py) and the real SAMA / NCA ECC / ISO / NDMO / PDPL registers
// over SYNTHETIC facts: where we stand per framework, what to do first, a suggested question answered, a typed question with
// the requirement explained in plain words, a hostile question stays text, a question it cannot match is not guessed, rating
// and "I meant" teach it, the glossary, the learning card for administrators only, the side panel on the SAMA page scoped to
// SAMA, the menu has the page under Audit.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node compliance-assistant.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror=alert(1)> backups';
const OP = { user: 'nora.syn', role: 'operator' }, ADM = { user: 'syed', role: 'admin' }, VIEW = { user: 'vera.syn', role: 'viewer' };
const FACTS = () => ({
  grc: { available: true, total: 20, reviews_overdue: 0, attested: 15, policies: [], control_status: {} },
  hardening: { available: true, assets: 40, scanned: 38, coverage_pct: 95, score: 82, fail: 30, critical_fail: 2 },
  pentest: { available: true, assets: 12, findings: 4, by_severity: { critical: 0, high: 0 }, internet_facing: 3, exposed_assets: 0 },
  cadence: { available: true, assets: 12, out_of_policy: 3 },
  siem: { available: true, sama: { '3.3.14': 'covered' }, retention_days: 400, logflow: { required: 10, silent: 0, not_onboarded: 0, no_connector: 0 } },
});

(async () => {
  const e = await H.startApp({ noAi: true });
  require(path.join(ITAM, 'engine/duty')).registerDuty(e.app.srv, e.app, { noTimer: true, python: process.env.PYTHON || 'python3', samaFacts: async () => FACTS(), eccFacts: async () => FACTS(), isoFacts: async () => FACTS(), ndmoCatalogFiles: false });
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
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg, { timeout: 15000 }).then(() => true, () => false);
  const outHas = (p, re) => wait(p, (src) => new RegExp(src).test((document.getElementById('as-out') || {}).textContent || ''), re.source);
  const txt = (p, s) => p.textContent(s);
  try {
    const p = await browser.newPage({ viewport: { width: 1400, height: 950 } }); p.on('pageerror', (x) => errs.push(x.message));
    p.on('dialog', (d) => { errs.push('dialog: ' + d.message()); d.dismiss(); });
    await p.goto(base + 'compliance-assistant.html?standalone=1');
    ok(await wait(p, () => document.querySelectorAll('#fws .as-fw').length === 5), 'where we stand: five frameworks');
    ok(/SAMA CSF \+ IA: \d+ of \d+ applicable requirements are done/.test(await txt(p, '#fws')), 'each framework in one plain sentence');
    ok(await wait(p, () => document.querySelectorAll('#first li').length >= 5 && /Why first:/.test(document.getElementById('first').textContent)), 'what to do first, with the reasons');
    ok(await wait(p, () => document.querySelectorAll('#terms [data-term]').length >= 20 && document.querySelectorAll('#states .term').length === 5), 'the glossary and the five states');
    // the tiles open what they show (they were plain boxes): a framework its register, a first item its register, a state or term asks
    const ln = await p.evaluate(() => ({ fw: [...document.querySelectorAll('#fws a.as-fw')].map((a) => a.getAttribute('href')), first: document.querySelectorAll('#first li a[href]').length, gq: document.querySelectorAll('#states [data-gq], #terms [data-gq]').length }));
    ok(ln.fw.join() === 'sama-ia.html,nca-ecc.html,iso27001.html,ndmo.html,pdpl-dashboard.html' && ln.first >= 5 && ln.gq >= 25, 'framework bars and first items link to their register; states and terms ask: ' + JSON.stringify(ln));
    ok(await p.isHidden('#learn-c'), 'the learning card is for administrators only');
    // a suggested question
    await p.click('#sug [data-as-q="What should we fix first?"]');
    ok(await outHas(p, /Do these first/) && /what to do/.test(await txt(p, '#as-out')), 'a suggested question: the priorities');
    // a typed question: the requirement explained, then rated helpful
    await p.fill('#as-q', 'Who approves the cybersecurity strategy evidence?'); await p.click('[data-as-go]');
    ok(await outHas(p, /Approved by the CISO/), 'who approves - from the register');
    ok(await p.$eval('#as-out details.as-m[open]', (d) => /What it asks/i.test(d.textContent) && /What to do next/i.test(d.textContent) && /Evidence an auditor accepts/i.test(d.textContent)), 'the requirement in plain sections');
    ok(/who approves/.test(await txt(p, '#as-out .as-int')), 'understood as: who approves');
    await p.click('#as-out [data-as-fb="yes"]'); ok(await outHas(p, /learns from this/), 'rated helpful');
    // "I meant" correction
    await p.fill('#as-q', 'encryption keys'); await p.press('#as-q', 'Enter');
    ok(await wait(p, () => !!document.querySelector('#as-out [data-as-meant]')), 'answer with the correction box');
    await p.selectOption('#as-out [data-as-meant]', 'evidence'); ok(await outHas(p, /learns from this/), 'I meant: evidence');
    // a hostile question stays text; a framework chosen scopes the answer
    await p.selectOption('#as-fw', 'sama'); await p.fill('#as-q', XSS); await p.click('[data-as-go]');
    ok(await wait(p, () => /SAMA/.test(document.getElementById('as-out').textContent) && !/Thinking/.test(document.getElementById('as-out').textContent)), 'scoped to SAMA');
    ok(!(await p.$('#as-out img')), 'a hostile question stays text');
    // nonsense is not guessed
    await p.selectOption('#as-fw', ''); await p.fill('#as-q', 'xyzzy plugh frobnicate'); await p.click('[data-as-go]');
    ok(await outHas(p, /will not guess/), 'a question it cannot match is not guessed');
    await p.click('#terms [data-term]'); ok(await wait(p, () => /^What does .+ mean for us\?$/.test(document.getElementById('as-q').value)) && await wait(p, () => { const t = document.getElementById('as-out').textContent; return !/Your answer appears here|Thinking/.test(t) && t.trim().length > 20; }), 'a term card asks the assistant about it and the answer appears');
    // the administrator sees what was learned
    WHO = ADM; await p.reload(); ok(await wait(p, () => !document.getElementById('learn-c').hidden && /2 answers rated/.test(document.getElementById('learn').textContent)), 'administrator: what was learned');
    // the side panel on the SAMA page, scoped to SAMA
    WHO = VIEW; await p.goto(base + 'sama-ia.html?standalone=1'); await p.waitForSelector('#as-b');
    await p.click('#as-b'); ok(await p.isVisible('#as-p'), 'the side panel opens');
    await p.click('#as-p [data-as-q="Are we compliant?"]');
    ok(await wait(p, () => /^SAMA CSF \+ IA: \d+ of/.test((document.querySelector('#as-p [data-as-out] .as-sum') || {}).textContent || '')), 'scoped to the page\'s framework');
    await p.click('#as-x'); ok(await p.isHidden('#as-p'), 'closes');
    ok(await p.evaluate(() => { const a = (window.ZYB_NAV || []).find((x) => x.id === 'cmp'); return !!(a && a.pages.some((x) => x.h === 'compliance-assistant.html')); }), 'the menu has the page under Compliance & Frameworks');
  } finally { await browser.close(); srv.close(); await e.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks');
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
