// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Enterprise Risk Automation Flow (risk-flow.html) for a company without the business-risk module (Safari's brand: brisk off):
// the flow runs on the GRC risk register through the Risk Command Center - sources, methodology and machine learning stages lit
// from it, the AI / ML band (risks by level, where the risk sits by category, a simulated year), the posture trend, what the AI
// noticed with figures, the note on how this flow runs here, links only to pages the company has, no insurer wording; nothing
// registered: no band. Stubbed API, SYNTHETIC data. Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node risk-flow-register.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const RC = (open) => ({ generated_at: new Date().toISOString(), kpis: { open, high: open ? 3 : 0, over_appetite: open ? 2 : 0, under_rated: open ? 1 : 0, hygiene: open ? 4 : 0, candidates: open ? 5 : 0, scenarios_assessed: 0, deteriorating: open ? 1 : 0 },
  categories: open ? [{ category: 'Cyber', risks: 6, residual: 60, inherent: 90 }, { category: 'Operations', risks: 4, residual: 30, inherent: 45 }] : [],
  simulation: open ? { expected: 2.4, p50: 2, p90: 4, p_any_high: 63, histogram: [{ n: 0, share: 8 }, { n: 1, share: 22 }, { n: 2, share: 30 }, { n: 3, share: 22 }, { n: 4, share: 18 }] } : null,
  posture: { value: open ? 71 : null, history: open ? [{ date: '2026-11-20', posture: 66 }, { date: '2026-11-27', posture: 71 }] : [] }, owner_concentration: open ? { share: 64, why: 'the top 2 owner(s) (20 %) carry 64 % of the residual score' } : { why: 'no open risk' } });
let OPEN = 10;
(async () => {
  const srv = http.createServer((q, r) => { const u = decodeURIComponent(q.url.split('?')[0]), j = (c, o) => { r.writeHead(c, { 'Content-Type': 'application/json' }); r.end(JSON.stringify(o)); };
    if (u.endsWith('whoami.json')) return j(200, { user: 'op.syn', role: 'operator' });
    if (u === '/api/itam/brisk') return j(200, { kpis: { risks: 0, not_rated: 0, class: [0, 0, 0, 0], flagged: 0, metrics: 0, early_warnings: 0, outside_appetite: 0, acceptance_pending: 0 }, imports: {}, insights: { duplicates_total: 0, consistency_total: 0 } });
    if (u === '/api/itam/risk-command') return j(200, RC(OPEN));
    if (u.startsWith('/api/')) return j(404, { error: 'not installed' });
    fs.readFile(path.join(DASH, u.replace(/^\/dashboards\//, '/')), (e, d) => { if (e) { r.writeHead(404); return r.end(); } r.writeHead(200, { 'Content-Type': u.endsWith('.js') ? 'application/javascript' : u.endsWith('.css') ? 'text/css' : 'text/html' }); r.end(d); }); });
  await new Promise((res) => srv.listen(0, '127.0.0.1', res));
  const url = 'http://127.0.0.1:' + srv.address().port + '/dashboards/risk-flow.html?standalone=1';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch(), errs = [];
  const org = JSON.parse(/ZYB_ORG = Object\.freeze\((\{.*?\})\)/.exec(fs.readFileSync(path.join(DASH, 'vendor/zyb-org.js'), 'utf8'))[1]);
  const open = async (brisk) => { const p = await browser.newPage({ viewport: { width: 1400, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message));
    await p.addInitScript((b) => { Object.defineProperty(window, 'ZYB_ORG', { configurable: true, set(v) { this._o = Object.assign({}, v, { modules_off: b ? (v.modules_off || []).concat(['brisk']) : v.modules_off }); }, get() { return this._o; } }); }, brisk);
    await p.goto(url); await p.waitForSelector('#flow svg', { timeout: 15000 }); await p.waitForTimeout(600); return p; };
  try {
    let p = await open(true);
    const st = await p.$$eval('#flow a', (x) => x.map((a) => ({ id: a.getAttribute('data-stage'), href: a.getAttribute('href'), text: a.textContent })));
    const S = Object.fromEntries(st.map((x) => [x.id, x]));
    ok(/10 register risks/.test(S.rate.text) && /3 rated high/.test(S.rate.text) && /1 under-rated/.test(S.ml.text) && /~2\.4 a year/.test(S.ml.text), 'stages lit from the register: ' + S.rate.text + ' | ' + S.ml.text);
    ok(st.every((x) => !(org.pages_off || []).includes(x.href.replace(/[#?].*$/, '').replace(/\.html$/, ''))) && S.src.href === 'risk-command.html', 'links only to pages the company has: ' + st.map((x) => x.href).join(','));
    ok(!/\/10 scenarios|insurer/i.test(await p.textContent('main')), 'no insurer wording');
    const lab = await p.$$eval('#aiband canvas', (x) => x.map((c) => c.getAttribute('aria-label') || ''));
    ok(lab.length === 3 && /Risks by level/.test(lab[0]) && /Where the risk sits/.test(lab[1]) && /Cyber/.test(lab[1]) && /A simulated year/.test(lab[2]), 'AI / ML band from the register: ' + lab.map((l) => l.slice(0, 40)).join(' | '));
    ok(!(await p.$eval('#postc', (x) => x.hidden)), 'posture over time');
    const ins = (await p.$eval('#ins', (x) => x.innerText)).replace(/\s+/g, ' ');
    ok(/2 risks sit above the appetite/.test(ins) && /3 open risks are rated high/.test(ins) && /about 2\.4 risks occur \(P90 4\)/.test(ins) && /63 %/.test(ins) && /5 new risk candidates/.test(ins) && /64 %/.test(ins), 'what the AI noticed: ' + ins);
    ok(!(await p.$eval('#modn', (x) => x.hidden)) && /switched off for/.test(await p.textContent('#modn')), 'how this flow runs here');
    await p.close();
    OPEN = 0; p = await open(true); ok(await p.$eval('#aiband', (x) => x.hidden), 'nothing registered: no band'); await p.close();
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); }
  console.log((bad ? 'FAILED ' : 'ok ') + (n - bad) + '/' + n + ' risk-flow-register checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
