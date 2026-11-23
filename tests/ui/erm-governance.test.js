// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for Risk Governance & Models (dashboards/server/erm-governance.html) against the REAL engine
// (backend/itam/engine/erm-governance.js) with SYNTHETIC records entered by named synthetic people (*.syn), clicked through each tab:
//  - empty states say what to enter, no figure is invented;
//  - Models: a model added in the page (with a hostile name that must stay text), a validation by the owner refused (independence),
//    a validation with a finding recorded, the finding closed; a change to the high-tier model asked by one administrator and
//    approved by another (the asker sees no approve button);
//  - Committees: a committee added, its charter asked for by an operator and approved by an administrator, a meeting with an overdue
//    action recorded (quorum computed), the action closed, a delegated authority recorded;
//  - People: a key function with no ready successor flagged, a fit-and-proper attestation, a key risk taker, two survey periods with
//    the change shown;
//  - a viewer reads every tab and has no write button; phone width; no page errors.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node erm-governance.test.js   (SHOTS=dir also saves screenshots)
const http = require('http'), fs = require('fs'), path = require('path');
const ITAM = path.join(__dirname, '..', '..', 'backend', 'itam'), DASH = path.join(__dirname, '..', '..', 'ui');
const H = require(path.join(ITAM, 'tests', 'helpers'));
const G = require(path.join(ITAM, 'engine', 'erm-governance'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
(async () => {
  const e = await H.startApp({ noAi: true });
  G.registerErmGovernance(e.app.srv, e.app, G.createErmGovernance(e.app, { now: () => Date.parse('2026-11-11T08:00:00Z') }));
  const OP = { user: 'nora.syn', role: 'operator' }, ADM = { user: 'adam.syn', role: 'admin' }, ADM2 = { user: 'aisha.syn', role: 'admin' }, VIEW = { user: 'vera.syn', role: 'viewer' };
  const api = (m, p, b, w) => e.req(m, p, Object.assign(b !== undefined ? { body: b } : {}, w || OP));
  let who = OP;
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
  const base = 'http://127.0.0.1:' + srv.address().port + '/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg === undefined ? null : arg, { timeout: 15000 }).then(() => true, () => false);
  const shot = async (p, name) => { if (process.env.SHOTS) { await p.waitForTimeout(300); await p.screenshot({ path: path.join(process.env.SHOTS, name + '.png'), fullPage: true }); } };
  let p;
  const as = async (w, tab) => { who = w; await p.goto('about:blank'); await p.goto(base + 'erm-governance.html?standalone=1'); await wait(p, () => document.querySelectorAll('#kk .t').length === 8); if (tab) await p.click('[data-tab="' + tab + '"]'); };
  const HOSTILE = 'Synthetic IBNR model SYN <img src=x onerror=window.__x=1>';
  try {
    p = await browser.newPage({ viewport: { width: 1400, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message));
    // empty: nothing invented, every area says what to enter
    await as(OP);
    ok(await p.evaluate(() => document.title === 'Risk Governance & Models' && [...document.querySelectorAll('#kk .t .v')].every((v) => v.textContent === '0')), 'header tiles all zero on an empty platform');
    ok(await p.evaluate(() => { const t = document.getElementById('v-sum').textContent; return /No model recorded yet - enter/.test(t) && /No committee recorded yet - enter/.test(t) && /No key function recorded yet - enter/.test(t); }), 'empty states say what to enter');

    // MODELS: added in the page with a hostile name
    await p.click('[data-tab="mod"]');
    await p.fill('#m-name', HOSTILE); await p.fill('#m-purpose', 'Synthetic: IBNR for motor'); await p.selectOption('#m-kind', 'reserving'); await p.fill('#m-owner', 'olga.syn'); await p.fill('#m-dept', 'Synthetic Actuarial');
    await p.selectOption('#m-tier', 'high'); await p.selectOption('#m-status', 'in_use'); await p.click('#m-go');
    ok(await wait(p, () => document.querySelectorAll('tr.mrow').length === 1 && /in use and never validated/.test(document.querySelector('tr.mrow').textContent)), 'the model is listed and flagged never validated');
    ok(await p.evaluate(() => window.__x !== 1 && !document.querySelector('img[src="x"]') && /<img src=x/.test(document.querySelector('tr.mrow').textContent)), 'a hostile name stays text');
    const mid = await p.evaluate(() => document.querySelector('tr.mrow').dataset.id);
    const openVal = async () => { await p.evaluate((id) => { document.querySelector('[data-val="' + id + '"]').closest('details').open = true; }, mid); };
    await openVal(); const V = '[data-val="' + mid + '"] ';
    await p.fill(V + '[data-k="date"]', '2026-10-15'); await p.fill(V + '[data-k="validator"]', 'olga.syn'); await p.selectOption(V + '[data-k="outcome"]', 'fit_with_findings'); await p.fill(V + '[data-k="report_ref"]', 'SYN-VAL-01');
    await p.fill(V + '[data-k="findings"]', 'Synthetic tail factor undocumented | medium | 2026-12-31 | olga.syn'); await p.click('[data-vgo="' + mid + '"]');
    ok(await wait(p, () => /independence: olga\.syn owns/.test(document.getElementById('err').textContent)), 'the owner as validator is refused and the page says why');
    await openVal(); await p.fill(V + '[data-k="date"]', '2026-10-15'); await p.fill(V + '[data-k="validator"]', 'val.syn'); await p.selectOption(V + '[data-k="outcome"]', 'fit_with_findings'); await p.fill(V + '[data-k="report_ref"]', 'SYN-VAL-01');
    await p.fill(V + '[data-k="findings"]', 'Synthetic tail factor undocumented | medium | 2026-12-31 | olga.syn'); await p.click('[data-vgo="' + mid + '"]');
    ok(await wait(p, () => /next due 2027-10-15/.test(document.querySelector('tr.mrow').textContent) && /Synthetic tail factor undocumented/.test(document.getElementById('v-mod').textContent)), 'validation recorded: next due computed, finding listed');
    const fid = await p.evaluate(() => document.querySelector('[data-fclose]').dataset.fclose);
    await p.fill('[data-fn="' + fid + '"]', 'synthetic: documented in the reserving policy'); await p.click('[data-fclose="' + fid + '"]');
    ok(await wait(p, () => /nora\.syn: synthetic: documented/.test(document.getElementById('v-mod').textContent)), 'the finding is closed with its note');
    // a change to the high-tier model in use: asked by one administrator, approved by another
    await as(ADM, 'mod'); await p.evaluate((id) => { document.querySelector('[data-chf="' + id + '"]').closest('details').open = true; }, mid);
    await p.fill('[data-chf="' + mid + '"] [data-k="owner"]', 'otto.syn'); await p.fill('[data-chf="' + mid + '"] [data-k="change"]', 'synthetic: ownership moves to otto'); await p.click('[data-cgo="' + mid + '"]');
    ok(await wait(p, () => /Model changes waiting/.test(document.getElementById('v-mod').textContent) && /Yours - a different administrator decides/.test(document.getElementById('v-mod').textContent) && !document.querySelector('[data-chg]')), 'the asker sees the change waiting and no approve button');
    await as(ADM2, 'mod'); ok(await wait(p, () => !!document.querySelector('[data-chg][data-d="approve"]')), 'another administrator can decide'); await p.click('[data-chg][data-d="approve"]');
    ok(await wait(p, () => !/Model changes waiting/.test(document.getElementById('v-mod').textContent) && /otto\.syn/.test(document.querySelector('tr.mrow').textContent)), 'approved: the owner changed');
    await shot(p, 'erm-governance-models');

    // COMMITTEES
    await as(OP, 'com'); ok(await p.evaluate(() => /No committee recorded yet\. Add the Board/.test(document.getElementById('v-com').textContent)), 'committee empty state');
    await p.fill('#c-name', 'Synthetic Board Risk Committee SYN'); await p.fill('#c-chair', 'ali.syn'); await p.fill('#c-members', 'ali.syn, bea.syn, cem.syn'); await p.fill('#c-quorum', '2'); await p.selectOption('#c-freq', 'quarterly');
    await p.fill('#c-review', '2027-06-30'); await p.fill('#c-mandate', 'Synthetic: oversees the risk appetite'); await p.click('#c-go');
    ok(await wait(p, () => document.querySelectorAll('tr.crow').length === 1 && /the charter is not approved/.test(document.querySelector('tr.crow').textContent)), 'the committee is listed, its charter not approved');
    const cid = await p.evaluate(() => document.querySelector('tr.crow').dataset.id);
    await p.fill('[data-rn="' + cid + '"]', 'synthetic: the 2026 charter'); await p.click('[data-creq="' + cid + '"]');
    ok(await wait(p, () => /Yours - a different administrator approves/.test(document.querySelector('tr.crow').textContent)), 'asked for approval; the asker cannot approve');
    await as(ADM, 'com'); await wait(p, () => !!document.querySelector('[data-cdec][data-d="approve"]')); await p.fill('[data-dn="' + cid + '"]', 'SYN-BOARD-2026/9'); await p.click('[data-cdec][data-d="approve"]');
    ok(await wait(p, () => /v1 approved by adam\.syn/.test(document.querySelector('tr.crow').textContent)), 'the charter is approved by another person');
    await as(OP, 'com'); await p.selectOption('#g-com', cid); await p.fill('#g-date', '2026-11-05'); await p.fill('#g-att', 'ali.syn, bea.syn, guest.syn'); await p.fill('#g-min', 'SYN-MIN-11');
    await p.fill('#g-dec', 'Synthetic: approve the cat limits'); await p.fill('#g-act', 'Synthetic: update the treaty wording | bea.syn | 2026-11-08'); await p.click('#g-go');
    ok(await wait(p, () => /2 of 3 members/.test(document.getElementById('v-com').textContent) && /overdue since 2026-11-08/.test(document.getElementById('v-com').textContent)), 'meeting recorded: quorum computed, the action overdue');
    ok(await p.evaluate(() => /Actionsoverdue1/.test(document.getElementById('kk').textContent.replace(/\s+/g, ''))), 'the header counts the overdue action');
    const aid = await p.evaluate(() => document.querySelector('[data-aclose]').dataset.aclose); await p.fill('[data-an="' + aid + '"]', 'synthetic: wording updated'); await p.click('[data-aclose="' + aid + '"]');
    ok(await wait(p, () => /nora\.syn: synthetic: wording updated/.test(document.getElementById('v-com').textContent)), 'the action is closed with its note');
    await p.fill('#d-holder', 'uma.syn'); await p.selectOption('#d-auth', 'underwriting'); await p.fill('#d-limit', '5000000'); await p.fill('#d-by', 'ceo.syn'); await p.fill('#d-exp', '2026-12-01'); await p.click('#d-go');
    ok(await wait(p, () => /5,000,000 SAR/.test(document.getElementById('v-com').textContent) && /expires on 2026-12-01 \(within 30 days\)/.test(document.getElementById('v-com').textContent)), 'the delegated authority is listed and flagged expiring');
    await shot(p, 'erm-governance-committees');

    // PEOPLE
    await p.click('[data-tab="ppl"]'); ok(await p.evaluate(() => /No key function recorded yet\. Add the CEO/.test(document.getElementById('v-ppl').textContent) && /No survey result entered yet/.test(document.getElementById('v-ppl').textContent)), 'people empty states');
    await p.selectOption('#f-fn', 'cro'); await p.fill('#f-title', 'Synthetic CRO SYN'); await p.fill('#f-holder', 'rita.syn'); await p.fill('#f-succ', 'sam.syn | 1_2_years'); await p.click('#f-go');
    ok(await wait(p, () => /no ready-now successor and no emergency cover/.test(document.getElementById('v-ppl').textContent)), 'no ready successor is flagged');
    await p.fill('#k-name', 'kim.syn'); await p.fill('#k-role', 'Synthetic Head of Investments'); await p.fill('#k-dept', 'Synthetic Investments'); await p.click('#k-go');
    ok(await wait(p, () => /remuneration review not recorded/.test(document.getElementById('v-ppl').textContent)), 'a key risk taker without a remuneration review is flagged');
    await api('POST', '/erm-gov/surveys', { period: '2025', response_rate: 60, tone_at_the_top: 70, speak_up: 55, accountability: 65, risk_awareness: 60 });
    await as(OP, 'ppl'); await p.fill('#s-period', '2026'); await p.fill('#s-rr', '72'); await p.fill('#s-tone_at_the_top', '74'); await p.fill('#s-speak_up', '51'); await p.fill('#s-accountability', '65'); await p.fill('#s-risk_awareness', '66'); await p.click('#s-go');
    ok(await wait(p, () => /vs 2025/.test(document.getElementById('v-ppl').textContent) && /▲ \+4/.test(document.getElementById('v-ppl').textContent) && /▼ -4/.test(document.getElementById('v-ppl').textContent)), 'survey change against the previous period');
    ok(await p.evaluate(() => !document.getElementById('a-go')), 'an operator does not record attestations');
    await as(ADM, 'ppl'); await p.fill('#a-person', 'rita.syn'); await p.fill('#a-on', '2026-11-01'); await p.click('#a-go');
    ok(await wait(p, () => /until 2027-11-01/.test(document.getElementById('v-ppl').textContent)), 'the attestation is valid 12 months by default');
    await p.fill('#a-person', 'adam.syn'); await p.fill('#a-on', '2026-11-01'); await p.click('#a-go');
    ok(await wait(p, () => /cannot attest their own/.test(document.getElementById('err').textContent)), 'attesting oneself is refused and the page says why');
    await shot(p, 'erm-governance-people');

    // overview with flags; a viewer reads every tab and has no write button
    await as(VIEW); ok(await wait(p, () => /never|overdue|no ready-now successor/.test(document.getElementById('v-sum').textContent) && document.querySelectorAll('#v-sum .fl li').length >= 2), 'the overview lists the flags with why');
    const tabs = ['mod', 'com', 'ppl'], seen = {};
    for (const tb of tabs) { await p.click('[data-tab="' + tb + '"]'); seen[tb] = await p.evaluate((id) => ({ rows: document.querySelectorAll('#' + id + ' tbody tr').length, writes: document.querySelectorAll('main button:not([data-tab]):not(#refresh), main .inp').length }), 'v-' + tb); }
    ok(tabs.every((tb) => seen[tb].rows > 0 && seen[tb].writes === 0), 'a viewer reads every tab and has no write button: ' + JSON.stringify(seen));
    ok(await p.evaluate(() => window.__x !== 1 && !document.querySelector('img[src="x"]')), 'no record text ran as markup');
    const m = await browser.newPage({ viewport: { width: 390, height: 860 } }); m.on('pageerror', (x) => errs.push(x.message));
    await m.goto(base + 'erm-governance.html?standalone=1'); await m.waitForTimeout(1200);
    ok(await m.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), 'phone width, no sideways scroll');
  } finally { await browser.close(); srv.close(); await e.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
