// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for cio-dashboard.html (stubbed API, synthetic data): with sources connected every figure is the live one -
// budget envelopes from the IT budget, last year's spend only when imported, renewals and unused licence seats, posture /
// SAMA / risks / decisions / team / SOC / brief from the AI CISO overview, Applications Manager monitors; with nothing
// connected every card says what to connect (no 0 %, no NaN, no sample); a viewer sees renewals as a count (no cost).
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node cio-dashboard.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
let MODE = 'live', WHO = { user: 'cio.syn', role: 'operator' };
const NOW = Date.now();
const D = {
  '/api/itam/budget': { fy: 2027, currency: 'SAR', summary: { lines: 40, unpriced: 3, total: 71200000, envelope_total: 96000000 },
    envelopes: [{ id: 'it_ops', name: 'IT Operations (Infrastructure & Applications)', envelope: 66000000, proposed: 52300000, capex: 30100000, opex: 22200000, unpriced: 2, over: 0 },
      { id: 'cyber', name: 'Cyber Security', envelope: 30000000, proposed: 18900000, capex: 9000000, opex: 9900000, unpriced: 1, over: 0 }],
    previous: { fy: 2026, approved: 48000000, spent: 36000000 } },
  '/api/itam/ciso/overview': { posture: { overall: 72, grade: 'adequate', measured: 5, of: 6, withheld_why: null, domains: [{ id: 'governance', name: 'Governance', measured: true, score: 80 }, { id: 'sama', name: 'SAMA CSF', measured: true, score: 64 }, { id: 'exposure', name: 'Exposure', measured: false, score: null }] },
    risks: [{ severity: 'critical', title: 'x' }, { severity: 'high' }, { severity: 'high' }], risks_total: 3,
    decisions: [{ title: 'Approve IOS upgrade SW-SYN-01', from: 'AI network engineer', who: 'operator / admin (not the requester)' }],
    team: [{ engine: 'siem', state: 'live', name: 'AI Network Engineer', open: 4, critical: 1, resolved_24h: 6 }, { engine: 'itam', state: 'not_connected' }],
    soc: { mttd_s: 540, mttr_s: 14400, sla: { resolve_compliance_pct: 91.5, breaching_now: 2 } },
    compliance: { sama: { coverage_pct: 78 } }, last_brief: { at: new Date(NOW).toISOString(), kind: 'ai', headline: 'Posture 72/100 - <b>1</b> critical risk' } },
  '/api/itam/support-contracts': { contracts: [{ vendor: 'Cisco', product: 'SmartNet SYN', state: 'expiring', days_left: 20, end: '2026-11-13', cost: 420000 }, { vendor: 'Dell', state: 'active', days_left: 300 }], summary: { contracts: 2, expiring: 1, expired: 0, renewal_cost_90d: 420000 } },
  '/api/itam/licences': { licences: [{ product: 'Visio SYN', seats: 50, used: 30, cost: 100000, compliance: 'under' }, { product: 'Office SYN', seats: 100, used: 100, compliance: 'ok' }] },
  '/api/soc/integrations/apm/status': { configured: true },
  '/api/soc/integrations/apm/monitors': { items: [{ name: 'IIRIS Portal', availability: 'up', managed: true }, { name: 'Claims API', availability: 'down', managed: true }] },
  // Workflow Automation attention(who), synthetic, in the engine's shape
  '/api/itam/workflow/attention': { summary: { approvals: 1, queue_open: 0, overdue: 0, at_risk: 0, to_accept: 0, raised_open: 1, raised_late: 1, functions: ['governance'], all_overdue: 3, recurring: 0,
    teams: [{ team: 'dba', name: 'Database team (DBA)', open: 2, overdue: 2, n: 6, on_time: 5, rate: 0.75 }, { team: 'network', name: 'Network team', open: 1, overdue: 1, n: 2, on_time: 1, rate: 0.5 }, { team: 'apps', name: 'Applications', open: 0, overdue: 0, n: 0, on_time: 0, rate: 0.5 }], items: [] },
    priorities: [{ kind: 'Request approval', ref: 'REQ-2026-0011', text: 'New server for the <b>claims</b> portal - from Administration', page: 'workflow-automation.html#req=REQ-2026-0011', why: [['a business request waiting for your approval', 45]] }] },
};
(async () => {
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, WHO);
    if (u.pathname.startsWith('/api/')) {
      if (MODE === 'none') return json(404, { error: 'not found' });
      let b = D[u.pathname]; if (!b) return json(404, { error: 'not in this test' });
      if (WHO.role === 'viewer' && u.pathname === '/api/itam/support-contracts') b = Object.assign({}, b, { summary: Object.assign({}, b.summary, { renewal_cost_90d: undefined }), contracts: b.contracts.map((c) => Object.assign({}, c, { cost: undefined })) });
      return json(200, b);
    }
    const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (e, d) => { if (e) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': f.endsWith('.js') ? 'application/javascript' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch(), errs = [];
  let page;
  const open = async () => { if (page) await page.close(); page = await browser.newPage({ viewport: { width: 1400, height: 1000 } }); page.on('pageerror', (x) => errs.push(x.message)); await page.goto('http://127.0.0.1:' + srv.address().port + '/dashboards/cio-dashboard.html'); await page.waitForFunction(() => /updated/.test(document.getElementById('up').textContent), null, { timeout: 15000 }); };
  const T = (s) => page.innerText(s), cards = async () => (await T('#rings')) + (await T('#kk')) + (await T('.g'));
  try {
    await open();
    const k = await T('#kk'), rg = await T('#rings');
    ok(/SAR 96\.0M/.test(k) && /SAR 71\.2M proposed from the register · 3 lines need a price/.test(k), 'budget tile from the IT budget');
    ok(/LAST YEAR SPENT\s*75%/i.test(k) && /FY 2026/.test(k), 'last year spent 36 of 48');
    ok(/RENEWALS ≤ 90 DAYS\s*SAR 420k/i.test(k), 'renewal cost for an operator');
    ok(/UNUSED LICENCE SEATS\s*20/i.test(k) && /about SAR 40k a year/.test(k), 'unused seats and their value from the licence cost');
    ok(/CRITICAL RISKS\s*1\s*2 high/i.test(k) && /WAITING FOR A DECISION\s*1/i.test(k), 'risks and decisions from the AI CISO overview');
    ok(/50%/.test(rg) && /78%/.test(rg) && /72/.test(rg) && /adequate · 5 of 6 domains/.test(rg), 'rings: services, SAMA, posture: ' + rg.replace(/\s+/g, ' '));
    ok(/Cyber Security/.test(await T('#bud')) && /CAPEX SAR 9\.0M/.test(await T('#bud')), 'budget by envelope');
    ok(/Exposure\s*not measured/.test(await T('#pos')), 'an unmeasured domain says so');
    ok(/Claims API/.test(await T('#apps')) && /Approve IOS upgrade/.test(await T('#dec')) && /Cisco/.test(await T('#ren')) && /Visio SYN \(20 unused\)/.test(await T('#ren')), 'services, decisions, renewals, licences');
    ok(/AI Network Engineer/.test(await T('#team')) && /itam engine: not connected/.test(await T('#team')), 'team, a disconnected engine named');
    ok(/9 min/.test(await T('#soc')) && /4\.0 h/.test(await T('#soc')) && /91\.5%/.test(await T('#soc')), 'SOC MTTD / MTTR / SLA');
    { const w = await T('#wf'); ok(/3\s*overdue across the IT teams/.test(w) && /75 %\s*fulfilled on time \(6 of 8\)/.test(w) && /1\s*waiting for your approval/.test(w) && /1\s*your requests late/.test(w), 'Workflow Automation: overdue, on time across the teams, approvals, own late: ' + w.replace(/\s+/g, ' ').slice(0, 220));
      ok(w.indexOf('Database team') < w.indexOf('Network team') && !/Applications/.test(w) && /<b>claims<\/b>/.test(w) && !(await page.$('#wf b')) && !!(await page.$('#wf a[href="workflow-automation.html#req=REQ-2026-0011"]')), 'Workflow: teams with work, most overdue first; a hostile title stays text; links to the request'); }
    ok(/<b>1<\/b>/.test(await T('#brief')) && !(await page.$('#brief b b')), 'brief headline shown as text');
    { const cc = await cards(); ok(!/\bNaN\b|\bundefined\b|\bnull\b|[Ss]ample/.test(cc) && await page.isVisible('#live'), 'no NaN / sample; live badge: ' + JSON.stringify((cc.match(/[\s\S]{0,40}(NaN|undefined|null|sample)[\s\S]{0,40}/i) || []).slice(0, 2))); }
    await page.click('#kk [data-go="budget.html"]'); await page.waitForURL(/budget\.html/); ok(true, 'a tile opens its page');

    MODE = 'none'; await open();
    const c = await cards();
    ok(/not measured/.test(await T('#rings')) && !/\b0%/.test(await T('#rings')), 'rings not measured, never 0 %');
    ok(/Workflow Automation is not installed on the server/.test(c), 'Workflow Automation not installed: said, never zeros');
    ok(/IT budget is not installed/.test(c) && /AI CISO overview is not installed/.test(c) && /import last year/.test(c), 'every card says what is missing');
    ok(!/\bNaN\b|\bundefined\b|\bnull\b|[Ss]ample/.test(c) && !(await page.isVisible('#live')), 'no NaN / sample, no live badge');

    MODE = 'live'; WHO = { user: 'nora.syn', role: 'viewer' }; await open();
    ok(/RENEWALS ≤ 90 DAYS\s*1\s/i.test(await T('#kk')) && !/420/.test(await T('#ren')), 'viewer: renewals as a count, no cost');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); }
  console.log(bad ? 'FAILED ' + bad + '/' + n + ' checks' : 'OK ' + n + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
