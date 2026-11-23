// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for the AI / ML section of Data Security Posture (data-posture.html) against the REAL IT Asset Management engines
// (engine/data-posture.js + engine/dspm-intel.js) with a stubbed SIEM link, a scripted model and SYNTHETIC records
// (backend/itam/tests/data-posture-fixtures.js): KPIs, the riskiest stores with itemised factors and toxic tags, toxic
// combinations explained, an unusual jump from the daily history, fixes ranked by points given back, the score trend drawn and
// labelled, the advisor's answer shown as text and labelled a draft, a viewer sees tiers and counts but no store name and no
// advisor, the engine without the module says what to update, phone width, no page errors.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node data-posture-ml.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers')), F = require(path.join(ITAM, 'tests', 'data-posture-fixtures'));
const DP = require(path.join(ITAM, 'engine', 'data-posture')), DI = require(path.join(ITAM, 'engine', 'dspm-intel'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
(async () => {
  const T0 = Date.parse('2026-11-08T08:00:00Z'), DAY = 86400000;
  const e = await H.startApp({ noAi: true }), e2 = await H.startApp({ noAi: true });
  e.app.addons.pdpl = require(path.join(ITAM, 'engine', 'pdpl')).createPdpl(e.app, { now: () => T0 });
  F.seedLocal(e.app, T0);
  e.app.settings.update({ external_ai_allowed: true }, { user: 'syed', role: 'admin' });
  // ten days of history: exposed never moved from 0, the score drifting down
  for (let i = 10; i >= 1; i--) { const id = new Date(T0 + 3 * 3600000 - i * DAY).toISOString().slice(0, 10); e.app.store.collection('data_posture_hist').put({ id, at: id + 'T08:00:00.000Z', score: 4 - (10 - i) * 0.2, measured: 12, counts: { exposed: 0, credentials: 3 } }); }
  let asked = 0;
  class Fake { constructor() { this.messages = { create: async () => { asked++; return asked % 2 ? { stop_reason: 'tool_use', usage: { input_tokens: 1, output_tokens: 1 }, content: [{ type: 'tool_use', id: 't' + asked, name: 'dspm_insights', input: {} }] }
    : { stop_reason: 'end_turn', usage: { input_tokens: 1, output_tokens: 1 }, content: [{ type: 'text', text: 'Rotate the key in claimsdocssyn first. <img src=x onerror=window.__ax=1>' }] }; } }; } }
  const P = DP.registerDataPosture(e.app.srv, e.app, DP.createDataPosture(e.app, { now: () => T0, siem: F.fakeSiem(T0), noTimer: true }));
  DI.registerDspmIntel(e.app.srv, e.app, P, { now: () => T0, sdk: Fake, getKey: () => 'sk-ant-synthetic-itam' });
  DP.registerDataPosture(e2.app.srv, e2.app, DP.createDataPosture(e2.app, { now: () => T0, noTimer: true }));   // an engine without the module
  let who = { user: 'nora.syn', role: 'operator' }, eng = e;
  const srv = http.createServer((req, res2) => {
    const u = new URL(req.url, 'http://x'), json = (code, b) => { res2.writeHead(code, { 'Content-Type': 'application/json' }); res2.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, who);
    if (u.pathname.startsWith('/api/itam/')) { const h = Object.assign({}, req.headers, { 'x-sentra-proxy-secret': H.SECRET, 'x-auth-user': who.user, 'x-auth-role': who.role });
      const up = http.request({ host: '127.0.0.1', port: eng.port, method: req.method, path: req.url, headers: h }, (r) => { res2.writeHead(r.statusCode, r.headers); r.pipe(res2); }); req.pipe(up); return; }
    if (u.pathname.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res2.writeHead(403); return res2.end(); }
    fs.readFile(f, (err, d) => { if (err) { res2.writeHead(404); res2.end(); return; } res2.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res2.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/data-posture.html?standalone=1';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg, { timeout: 30000 }).then(() => true, () => false);
  const T = (p, id) => p.textContent('#' + id);
  try {
    const p = await browser.newPage({ viewport: { width: 1500, height: 1100 } }); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto(base);
    ok(await wait(p, () => !!document.querySelector('#mlst tbody tr')), 'the riskiest stores are listed');
    const k = (await T(p, 'mlk')).replace(/\s+/g, ' ');
    ok(/stores holding personal data or secrets/.test(k) && /toxic combinations/.test(k) && /unusual jumps today/.test(k), 'KPIs: ' + k);
    const first = await p.$eval('#mlst tbody tr', (r) => r.textContent);
    ok(/claimsdocssyn/.test(first) && /critical|high/.test(first) && /exposure \+25/.test(first) && /location \+10/.test(first), 'riskiest store first with itemised factors: ' + first.slice(0, 200));
    ok(/Secrets reachable from outside/.test(first) && /Identity \/ financial \/ health data abroad/.test(first), 'toxic tags on the store');
    ok(/claimsdocssyn/.test(await T(p, 'mltoxic')) && /PDPL transfer basis/.test(await T(p, 'mltoxic')), 'toxic combinations explained');
    ok(/Exposed data: 3 against a usual 0 \(it never moved before\)/.test(await T(p, 'mlanom')), 'an unusual jump from the daily history: ' + (await T(p, 'mlanom')).slice(0, 200));
    const fx = await p.$$eval('#mlfix .fx b', (b) => b.map((x) => +x.textContent));
    ok(fx.length >= 3 && fx.every((v, i) => !i || fx[i - 1] >= v), 'fixes ranked by points given back: ' + fx.join(','));
    ok(/over its cap/.test(await T(p, 'mlfix')) || fx[0] > 0, 'a fix explains its gain');
    ok(/Posture score over 11 daily snapshots/.test(await p.getAttribute('#mlfc svg', 'aria-label') || ''), 'score trend drawn and labelled');
    ok(!(await p.$('#mlcard img')), 'no markup from data');
    // the advisor
    ok(await p.evaluate(() => !document.getElementById('mlai').hidden), 'the advisor is offered to an operator');
    await p.fill('#mlq', 'hi'); await p.click('#mlask'); ok(/5 characters/.test(await T(p, 'mlans')), 'a too-short question is refused on the page');
    await p.fill('#mlq', 'Which store should we fix first?'); await p.click('#mlask');
    ok(await wait(p, () => /Rotate the key/.test((document.getElementById('mlansw') || {}).textContent || '')), 'the answer is shown');
    ok(/AI draft - verify before acting/.test(await T(p, 'mlans')) && !(await p.$('#mlans img')) && !(await p.evaluate(() => window.__ax)), 'labelled a draft, shown as text');
    ok(e.app.store.auditTail(200).some((a) => a.action === 'data-posture.ai.ask' && a.by === 'nora.syn'), 'the question is audited in the person\'s name');
    // access graph, suggested labels, redundant / obsolete data
    ok(/risky path/.test(await p.getAttribute('#mlgraph svg', 'aria-label') || '') && !!(await p.$('#mlgraph svg path[stroke="#ef5b6b"]')), 'access graph drawn with risky paths in red');
    ok(/Identity · claimsdocssyn → outside the Kingdom/.test(await T(p, 'mlrisky')), 'risky path named: ' + (await T(p, 'mlrisky')).slice(0, 160));
    const lab = await T(p, 'mllab');
    ok(/claimsdocssyn/.test(lab) && /Restricted/.test(lab) && /mismatch/.test(lab) && /applied by people|Purview|Restricted: health/.test(lab), 'label suggestions with a mismatch');
    const [dl] = await Promise.all([p.waitForEvent('download'), p.click('#labcsv')]);
    const csv = fs.readFileSync(await dl.path(), 'utf8');
    ok(/Suggestions only/.test(csv) && /"claimsdocssyn","cloud:azure","Restricted","yes"/.test(csv), 'labels exported as CSV with the framing: ' + csv.slice(0, 200));
    ok(/files unchanged for 3 years/.test(await T(p, 'mlrot')) && /nothing is deleted/.test(await T(p, 'mlrot')), 'redundant / obsolete data with the note');
    // since yesterday, peers, risk trends
    ok(/first daily snapshot of the stores is today/.test(await T(p, 'mlchg')), 'since yesterday: says the history starts today');
    ok(/7 or more stores/.test(await T(p, 'mlpeer')), 'peers: says when they are compared');
    ok(/Exposed data/.test(await T(p, 'mltr')) && !!(await p.$('#mltrt svg')) && /a week/.test(await T(p, 'mltr')), 'risk trends with sparklines and a slope');
    // what-if: tick the public store measure (0.75 back under the exposed cap)
    const s0 = +(await T(p, 'simv'));
    await p.check('[data-sim="exposed|public_store"]');
    const s1 = +(await T(p, 'simv'));
    ok(Math.abs(s1 - s0 - 0.8) < 0.11, 'what-if: fixing the public store gives back its points: ' + s0 + ' -> ' + s1);
    await p.check('[data-sim="shadow|undeclared_category"]');
    ok(+(await T(p, 'simv')) === s1, 'what-if: a measure under a capped risk gives nothing back yet');
    // remediation plan: drafted by one operator, approved by another, an item claimed, verified only by the data
    ok(await wait(p, () => !document.getElementById('mlplanw').hidden && !!document.getElementById('pldraft')), 'plan panel offered to an operator');
    await p.click('#pldraft');
    ok(await wait(p, () => /DSPM-PLAN-0001/.test(document.getElementById('mlplan').textContent) && /proposed/.test(document.getElementById('mlplan').textContent)), 'a plan is drafted');
    ok(/Waiting for a second person to approve/.test(await T(p, 'mlplan')) && !(await p.$('[data-pldec]')), 'the drafter cannot approve (four-eyes)');
    ok(/claimsdocssyn - Remove public access/.test(await T(p, 'mlplan')) && /HR-Site-SYN - Remove the anonymous links/.test(await T(p, 'mlplan')), 'actions from each store\'s facts');
    who = { user: 'omar.syn', role: 'operator' }; await p.reload();
    ok(await wait(p, () => !!document.querySelector('[data-pldec="approve"]')), 'a second operator sees approve / reject');
    await p.click('[data-pldec="reject"]'); ok(await wait(p, () => /note is required/.test(document.getElementById('plmsg').textContent)), 'reject needs a note');
    await p.click('[data-pldec="approve"]'); ok(await wait(p, () => /approved by omar\.syn/.test(document.getElementById('mlplan').textContent) && /due 2026-12-08/.test(document.getElementById('mlplan').textContent)), 'approved with its due date');
    await p.selectOption('[data-plit="1"]', 'claimed'); await p.fill('.plin input', 'done on the portal'); await p.click('[data-plsave="1"]');
    ok(await wait(p, () => /omar\.syn: done on the portal/.test(document.getElementById('mlplan').textContent) && /claimed/.test(document.getElementById('mlplan').textContent)), 'an item claimed with a note - not verified');
    ok(/0 verified/.test(await T(p, 'mlplan')), 'nothing verified while the data still shows the problem');
    ok(e.app.store.auditTail(300).some((a) => a.action === 'data.posture.plan.approve' && a.by === 'omar.syn'), 'approval audited in the person\'s name');
    if (process.env.SHOT) { await p.waitForTimeout(400); await p.screenshot({ path: process.env.SHOT + '-dspm-ml.png', fullPage: true }); }
    // a viewer: tiers and counts, no store name, no advisor
    who = { user: 'vera.syn', role: 'viewer' };
    const v = await browser.newPage({ viewport: { width: 1300, height: 900 } }); v.on('pageerror', (x) => errs.push(x.message));
    await v.goto(base); ok(await wait(v, () => !!document.getElementById('mlnamed')), 'viewer: tiers shown with the PDPL note');
    const vt = await v.textContent('#mlcard');
    ok(!/claimsdocssyn|HR-Site-SYN/.test(vt) && /credentials exposed: \d+ store/.test(vt), 'viewer: no store name, toxic counts only');
    ok(await v.evaluate(() => document.getElementById('mlai').hidden), 'viewer: no advisor');
    ok(/risky path\(s\)/.test(await v.textContent('#mlgraph')) && !(await v.$('#mlgraph svg')) && !(await v.$('#labcsv')), 'viewer: graph and labels as counts, no export');
    await v.close();
    // an engine without the module
    who = { user: 'nora.syn', role: 'operator' }; eng = e2;
    const o = await browser.newPage({ viewport: { width: 1300, height: 900 } }); o.on('pageerror', (x) => errs.push(x.message));
    await o.goto(base); ok(await wait(o, () => /update IT Asset Management \(engine\/dspm-intel\.js\)/.test(document.getElementById('mlk').textContent)), 'without the module: says what to update');
    await o.close(); eng = e;
    const ph = await browser.newPage({ viewport: { width: 390, height: 900 } }); ph.on('pageerror', (x) => errs.push(x.message));
    await ph.goto(base); await wait(ph, () => !!document.querySelector('#mlst tbody tr'));
    ok(await ph.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), 'phone width: no sideways scroll'); await ph.close();
  } finally { await browser.close(); srv.close(); await e.close(); await e2.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
