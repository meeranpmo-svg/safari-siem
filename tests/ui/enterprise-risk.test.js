// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Enterprise Risk Dashboard (enterprise-risk.html) graphics on a STUBBED API with SYNTHETIC data (SYN- codes, invented titles):
// the posture gauge and its 30-day move, the posture trend, where the points go, categories against appetite (bar + appetite mark),
// the business residual-class donut, the inherent heat map and trend, the ranked priorities (by-source donut, score bars),
// scenarios placed on the likelihood x impact grid, the appetite zones donut and section bars; then every chart's empty state,
// both services missing, a viewer refused, escaping of record text, Arabic right to left, and phone width.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node enterprise-risk.test.js   (SHOTS=dir also saves screenshots)
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };

const days = (k, f) => Array.from({ length: k }, (_, i) => Object.assign({ date: '2026-10-' + String(i + 1).padStart(2, '0') }, f(i)));
const RC = {
  posture: { value: 62, move_30d: -4, why: 'synthetic: 100 less the points itemised below', history: days(20, (i) => ({ posture: 70 - Math.round(i / 3), residual: 100 + i })),
    items: [{ label: 'open risks rated high (3 x 6, at most 30)', points: -18, why: 'synthetic' }, { label: 'risks above the appetite (2 x 5, at most 25)', points: -10, why: 'synthetic' }, { label: 'hygiene issues (10 x 1, at most 10)', points: -10, why: 'synthetic' }] },
  kpis: { open: 14, high: 3, over_appetite: 2, scenarios_assessed: 3 },
  urgent: [{ id: 'SYN-R1', title: 'Synthetic ransomware on claims servers <img src=x onerror=window.__x=1>', score: 20, over_appetite: true, owner: 'syn.owner' }, { id: 'SYN-R2', title: 'Synthetic vendor outage', score: 15, over_appetite: false, owner: '' }],
  categories: [{ category: 'Synthetic cyber', risks: 4, residual: 64, high: 2, over: 2, appetite: 12 }, { category: 'Synthetic third party', risks: 5, residual: 40, high: 1, over: 0, appetite: 12 }, { category: 'Synthetic data', risks: 5, residual: 20, high: 0, over: 0, appetite: 10 }],
  scenarios: [{ id: 's1', name: 'Synthetic scenario A', assessed: true, likelihood: 4, impact: 5, residual: 16, band: 'high' }, { id: 's2', name: 'Synthetic scenario B', assessed: true, likelihood: 3, impact: 3, residual: 9, band: 'medium' },
    { id: 's3', name: 'Synthetic scenario C', assessed: true, likelihood: 2, impact: 2, residual: 4, band: 'low' }, { id: 's4', name: 'Synthetic scenario D', assessed: false }],
  heat: { inherent: { '4x5': 2, '3x3': 1 }, residual: {} },
  simulation: { years: 10000, expected: 3.4, p50: 3, p90: 5, high_expected: 1.2, high_p90: 2, p_any_high: 68, why: 'synthetic: 10,000 simulated years',
    histogram: [{ n: 0, share: 2 }, { n: 1, share: 9 }, { n: 2, share: 18 }, { n: 3, share: 24 }, { n: 4, share: 21 }, { n: 5, share: 14 }, { n: 6, share: 8 }, { n: 7, share: 4 }] },
  movers: [{ id: 'SYN-R1', title: 'Synthetic ransomware', owner: 'syn.owner', from: 12, to: 20, change: 8 }, { id: 'SYN-R2', title: 'Synthetic vendor outage', owner: '', from: 16, to: 15, change: -1 }],
  owners: [{ owner: 'syn.owner', risks: 3, residual: 40, high: 2 }, { owner: 'syn.owner2 <b>x</b>', risks: 2, residual: 18, high: 0 }],
  owner_concentration: { share: 69, top: 1, why: 'synthetic: the top 1 owner(s) (20 %) carry 69 % of the residual score' },
};
const heatI = [[1, 0, 0, 0, 0], [0, 2, 1, 0, 0], [0, 1, 3, 2, 0], [0, 0, 1, 2, 1], [0, 0, 0, 1, 2]];   // 17 risks
const BR = {
  kpis: { risks: 17, class: [8, 5, 3, 1], high_inherent: 2, outside_appetite: 2, early_warnings: 1, reported: 5, metrics_with_limits: 7, metrics: 8 },
  heat: { inherent: heatI }, zones: { within_appetite: 3, outside_appetite: 1, outside_tolerance: 1, capacity_breach: 0 },
  sections: [{ section: '1', title: 'Synthetic capital', metrics: 4, reported: 3, outside: 1, warnings: 1 }, { section: '2', title: 'Synthetic liquidity', metrics: 4, reported: 2, outside: 1, warnings: 0 }],
  breaches: [{ id: 'SYN-RAS-1', component: 'Synthetic solvency ratio', responsibility: 'Synthetic Finance', period: '2026-10', zone: 'outside_tolerance', level: 2 }],
  warnings: [{ id: 'SYN-RAS-2', component: 'Synthetic liquidity cover', responsibility: 'Synthetic Treasury', p: 0.6 }],
  history: days(15, (i) => ({ open: 10 + (i % 4), class3: 2 + (i > 9 ? 2 : 0) })),
};
const RISKS = { risks: [{ code: 'SYN-BR-9', title: 'Synthetic claims backlog', residual: 4, status: 'open', inherent: 20, label: 'High (20)', class: 'Class IV', owner: 'syn.owner2' }, { code: 'SYN-BR-3', title: 'Solved one', residual: 3, status: 'solved', inherent: 16 }] };

const CK = (ok, name, detail, hard) => ({ ok, name, detail, hard: !!hard });
const OFF = { generated_at: '2026-11-11T08:00:00Z', loaded: true, how: 'synthetic',
  queue: [{ id: 'RO-ras-breach:SYN-RAS-1:2026-10', kind: 'ras-breach', severity: 'critical', title: 'SYN-RAS-1 Synthetic solvency ratio: outside tolerance in 2026-10, no GRC action tracks it <img src=x onerror=window.__y=1>', step: 'action', params: { metric: 'SYN-RAS-1', period: '2026-10' }, evidence: ['value 2.1 · outside tolerance'],
    supervisor: { verdict: 'passed', checks: [CK(true, 'step allowed', 'on the allow-list'), CK(true, 'metric exists', 'SYN-RAS-1 is in the RAS'), CK(true, 'figures current', 'still outside tolerance')] } },
    { id: 'RO-risk-unwatched:BR-0042', kind: 'risk-unwatched', severity: 'high', title: 'SYN-BR-9 Synthetic claims backlog: Class IV, no appetite metric watches it', step: 'link', params: { metric: 'SYN-RAS-3', risk: 'BR-0042', score: 0.41 }, evidence: ['best match SYN-RAS-3'],
      supervisor: { verdict: 'flagged', checks: [CK(true, 'risk exists', 'BR-0042 is in the register'), CK(false, 'evidence strong enough', 'match score 0.41')] } }],
  held: [{ id: 'RO-x', kind: 'ras-breach', severity: 'high', title: 'SYN-RAS-9 held', step: 'action', params: {}, evidence: [], escalated_to: 'Synthetic Finance', supervisor: { verdict: 'held', checks: [CK(false, 'metric exists', 'SYN-RAS-9 is not in the RAS', true)] } }],
  decided: [], learning: { kinds: { 'risk-unwatched': { decisions: 6, approved: 1, rejected: 5, rate: 0.25, lowered: true, why: '1 approved, 5 rejected - raised one severity lower until people approve more of them' } }, link_threshold: { value: 0.52, why: 'moved by 6 decision(s) on suggested links' } },
  scorecard: [{ key: 'reported', label: 'Appetite metrics reported for the last period', value: 71.4, target: 90, met: false, why: '5 of 7', history: [{ date: '2026-11-09', value: 60 }, { date: '2026-11-10', value: 65 }, { date: '2026-11-11', value: 71.4 }] },
    { key: 'actioned', label: 'Breaches tracked by a GRC action', value: 100, target: 100, met: true, why: '1 of 1', history: [] }, { key: 'caught_early', label: 'Breaches the officer warned of beforehand', value: null, target: 50, met: null, why: 'no breach', history: [] },
    { key: 'decision_days', label: 'Median days from proposal to decision', value: 1.5, target: 0, met: null, lower_is_better: true, why: '4 decided', history: [] }] };
const decided = [];
let mode = 'full', role = 'admin';
const srv = http.createServer((req, res) => {
  const u = new URL(req.url, 'http://x'), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
  if (u.pathname === '/dashboards/whoami.json') return json(200, { user: 'syn.admin', role });
  if (u.pathname === '/api/itam/risk-command') { if (role === 'viewer' && mode === 'refused') return json(403, { error: 'forbidden' }); if (mode === 'missing') return json(404, { error: 'not found' });
    return json(200, mode === 'empty' ? { posture: { value: null, why: 'withheld until the register holds a risk', history: [], items: [] }, kpis: { open: 0, high: 0, over_appetite: 0, scenarios_assessed: 0 }, urgent: [], categories: [], scenarios: [] } : RC); }
  if (u.pathname === '/api/itam/brisk') { if (mode === 'missing') return json(404, { error: 'not found' });
    return json(200, mode === 'empty' ? { kpis: { risks: 0, class: [0, 0, 0, 0], metrics: 0, metrics_with_limits: 0, reported: 0, outside_appetite: 0, early_warnings: 0 }, sections: [], breaches: [], warnings: [], history: [], zones: {} } : BR); }
  if (u.pathname === '/api/itam/brisk/risks') return json(200, mode === 'empty' ? { risks: [] } : RISKS);
  if (u.pathname === '/api/itam/brisk/officer') return mode === 'full' ? json(200, OFF) : json(404, { error: 'not found' });
  // the Enterprise Risk Programme (synthetic): a running cycle, a Board approval with one change since, categories, emerging risks
  const PROG = { '/api/itam/brisk/cycles': { cycles: [{ id: 'RC-2026-Q4', period: '2026-Q4', state: 'open', due: '2026-12-15', progress: { risks: 20, submitted: 13, pct: 65, signed: 1, departments: 3, overdue: 0 } }], departments: [] },
    '/api/itam/brisk/ras/approvals': { approvals: [{ id: 'RY-2026-v1', year: 2026, version: 1, state: 'approved' }], current: { id: 'RY-2026-v1', year: 2026, board_ref: 'Synthetic Board 2026/8', decided_at: '2026-10-20T08:00:00Z', count: 8, drift: { added: [{ id: 'SYN-RAS-9' }], removed: [], limits_changed: [], unchanged: false } }, metrics_now: 9 },
    '/api/itam/brisk/catalogue': { categories: [{ id: 'reserving', name: 'Reserving risk' }, { id: 'technology', name: 'IT and cyber risk' }], risks: [{ id: 'a', category: 'reserving', class: 'Class III' }, { id: 'b', suggested: { id: 'reserving' }, class: 'Class I' }, { id: 'c', category: 'technology', class: 'Class II' }] },
    '/api/itam/brisk/emerging': { emerging: [{ id: 'ER-0001', title: 'Synthetic cyber accumulation <img src=x onerror=window.__y=1>', horizon: '1-3y', impact: 4, trend: 'rising', state: 'watching' }, { id: 'ER-0002', title: 'Synthetic old idea', horizon: '5y+', impact: 2, trend: 'stable', state: 'dismissed' }] } };
  // Workflow Automation attention(who), synthetic, in the engine's shape: the risk function's DR evidence late with Backup & DR, a KRI result to accept
  if (u.pathname === '/api/itam/workflow/attention') return mode === 'full' ? json(200, { summary: { approvals: 0, queue_open: 0, overdue: 0, at_risk: 0, to_accept: 1, raised_open: 2, raised_late: 1, functions: ['risk'], all_overdue: 2, recurring: 0,
      teams: [{ team: 'backup', name: 'Backup & DR', open: 1, overdue: 1, n: 4, on_time: 3, rate: 0.67 }, { team: 'security', name: 'Security engineering', open: 1, overdue: 1, n: 0, on_time: 0, rate: 0.5 }], items: [] },
    priorities: [{ kind: 'Request to accept', ref: 'REQ-2026-0021', text: 'Critical vulnerabilities for the KRI - fulfilled by sec.syn', page: 'workflow-automation.html#req=REQ-2026-0021', why: [['a result waiting for your acceptance', 25]] },
      { kind: 'Request late', ref: 'REQ-2026-0019', text: 'DR test evidence <img src=x onerror=window.__wfx=1> - with Backup & DR, due 2026-11-10 08:00', page: 'workflow-automation.html#req=REQ-2026-0019', why: [['raised by you or your function, late with the IT team', 35], ['high priority', 10]] }] })
    : json(404, { error: 'not found' });
  if (PROG[u.pathname]) return mode === 'full' ? json(200, PROG[u.pathname]) : json(404, { error: 'not found' });
  const dm = /^\/api\/itam\/brisk\/officer\/([^/]+)\/decide$/.exec(u.pathname);
  if (dm && req.method === 'POST') { let b = ''; req.on('data', (c) => { b += c; }); req.on('end', () => { const j = JSON.parse(b || '{}'); decided.push({ id: decodeURIComponent(dm[1]), decision: j.decision, note: j.note }); json(200, { id: decodeURIComponent(dm[1]), status: j.decision === 'approve' ? 'approved' : 'rejected', result: j.decision === 'approve' ? { action: 'ACT-0009' } : null }); }); return; }
  if (u.pathname.startsWith('/api/') || u.pathname === '/') return json(404, { error: 'not in this test' });
  const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
  fs.readFile(f, (e, d) => { if (e) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': f.endsWith('.js') ? 'application/javascript' : f.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
});

(async () => {
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/enterprise-risk.html', SHOTS = process.env.SHOTS;
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch(), errs = [];
  const wait = (p, fn) => p.waitForFunction(fn, null, { timeout: 20000 }).then(() => true, () => false);
  const open = async (p, q) => { await p.goto(base + (q || '?standalone=1')); return wait(p, () => document.querySelector('#prio').children.length > 0 && document.querySelector('#kpis').children.length > 0); };
  try {
    const p = await browser.newPage({ viewport: { width: 1400, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message));
    ok(await open(p), 'the page draws');
    { await wait(p, () => !document.getElementById('wfcard').hidden); const w = await p.textContent('#wfcard');
      ok(/2\s*open with the IT teams/.test(w) && /1\s*late with the IT teams/.test(w) && /1\s*results for you to accept/.test(w) && /75 %\s*IT teams on time \(3 of 4\)/.test(w), 'Workflow Automation: the risk function\'s requests - open, late, to accept, on time: ' + w.replace(/\s+/g, ' ').slice(0, 240));
      ok(w.indexOf('REQ-2026-0019') < w.indexOf('REQ-2026-0021') && /DR test evidence <img/.test(w) && !(await p.$('#wfcard img')) && !(await p.evaluate(() => window.__wfx)) && !!(await p.$('#wf a[href="workflow-automation.html#req=REQ-2026-0019"]')), 'Workflow: ranked by points (45 before 25), a hostile title stays text, linked'); }
    const g = await p.evaluate(() => { const q = (s) => [...document.querySelectorAll(s)], it = document.getElementById('it'), br = document.getElementById('br');
      return { gauge: (it.querySelector('svg.gauge') || {}).getAttribute && it.querySelector('svg.gauge').getAttribute('aria-label'), arcOff: +(it.querySelector('.garc') || { getAttribute: () => -1 }).getAttribute('stroke-dashoffset'),
        move: (it.querySelector('.chip') || {}).textContent || '', spark: it.querySelectorAll('svg.spark path').length, pts: it.querySelectorAll('.hb').length, marks: it.querySelectorAll('.mk').length,
        cat0: (it.querySelectorAll('.hb')[3] || {}).textContent || '', donut: br.querySelectorAll('svg.donut circle.seg').length, heat: q('#br .heat .c').reduce((t, c) => t + (+c.textContent || 0), 0), cells: q('#br .heat .c').length,
        bspark: br.querySelectorAll('svg.spark path[fill="none"]').length, lg: br.querySelector('.lg').textContent,
        prio: q('#prio .pr li').map((li) => +li.querySelector('.sv span').textContent), prioTxt: document.getElementById('prio').textContent, prioDonut: document.querySelectorAll('#prio svg.donut circle.seg').length,
        href: (document.querySelector('#prio .pr a') || {}).getAttribute('href'), dots: q('#scen .heat .dot').length,
        ras: document.querySelectorAll('#ras svg.donut circle.seg').length, sec: q('#ras .sec').length, secPill: (document.querySelector('#ras .sec .pill') || {}).textContent, kpis: document.getElementById('kpis').textContent, icons: q('#kpis .ic .ti').length, xss: window.__x === 1 || !!document.querySelector('#prio img') }; });
    ok(/62 \/ 100/.test(g.gauge) && Math.abs(g.arcOff - Math.PI * 80 * 0.38) < 1, 'IT: the posture gauge reads 62 / 100 and fills 62 % (' + g.gauge + ', ' + g.arcOff + ')');
    ok(/-4/.test(g.move), 'IT: the 30-day move is shown: ' + g.move);
    ok(g.spark >= 2, 'IT: the posture trend is drawn (' + g.spark + ' paths)');
    ok(g.pts === 3 + 3 && g.marks === 3, 'IT: where the points go (3 bars) and 3 categories with an appetite mark (' + g.pts + ' bars, ' + g.marks + ' marks)');
    ok(/Synthetic cyber/.test(g.cat0) && /16/.test(g.cat0) && /▲2/.test(g.cat0), 'IT: the category bar shows its average residual and the risks above appetite: ' + g.cat0);
    ok(g.donut === 4 && /ClassI8ClassII5ClassIII3ClassIV1/.test(g.lg.replace(/\s/g, '')), 'Business: the residual-class donut has four classes with their counts (' + g.donut + ' segments): ' + g.lg);
    ok(g.cells === 25 && g.heat === 17, 'Business: the inherent heat map holds every rated risk (' + g.heat + ' in ' + g.cells + ' cells)');
    ok(g.bspark === 2, 'Business: the open and Class III / IV trend lines are drawn');
    ok(g.prio.length === 5 && g.prio.every((v, i) => i === 0 || g.prio[i - 1] >= v), 'Priorities are ranked by score: ' + g.prio.join(' > '));
    ok(/SYN-BR-9/.test(g.prioTxt) && !/Solved one/.test(g.prioTxt) && /SYN-RAS-1/.test(g.prioTxt) && /SYN-RAS-2/.test(g.prioTxt) && g.prioDonut === 3, 'Priorities: the Class IV risk, the breach and the warning, solved risks left out, the by-source donut');
    ok(g.href === 'risk-studio.html' || /risk-appetite|business-risk/.test(g.href), 'Priorities link to the page that holds the risk: ' + g.href);
    ok(g.dots === 3, 'Scenarios: the three assessed scenarios sit on the grid, the unassessed one does not (' + g.dots + ')');
    ok(g.ras === 4 && g.sec === 2 && g.secPill === '1', 'Appetite: the zones donut (within, outside, tolerance, not reported) and one bar per section');
    ok(/62/.test(g.kpis) && /17/.test(g.kpis) && /4/.test(g.kpis) && g.icons === 7, 'KPI tiles carry their values and icons: ' + g.kpis);
    ok(!g.xss, 'record text is escaped (no element, no script from a title)');
    const lk = await p.evaluate(() => ({ k: [...document.querySelectorAll('#kpis a.k')].map((a) => a.getAttribute('href')), it: [...document.querySelectorAll('#it a.st')].map((a) => a.getAttribute('href')), br: [...document.querySelectorAll('#br a.st')].map((a) => a.getAttribute('href')) }));
    ok(lk.k.join() === 'risk-command.html,risk-studio.html#reg=,risk-studio.html#reg=over,business-risk-register.html,business-risk-register.html#class=34,risk-appetite.html#zone=outside,risk-appetite.html#zone=warning', 'every KPI tile is a link to its filtered list: ' + lk.k.join(' '));
    ok(lk.it.length === 4 && lk.it.includes('risk-studio.html#reg=high') && lk.br.length >= 4 && lk.br.includes('business-risk-register.html#class=hi'), 'the figures in the IT & cyber and Business risk cards link too: ' + JSON.stringify(lk).slice(0, 200));
    ok(await wait(p, () => document.querySelectorAll('#prog .pgp').length === 4 && !document.querySelector('#prog .pgp.off')), 'the programme card: four parts, each from its own source');
    const pg = await p.evaluate(() => ({ t: document.getElementById('prog').textContent, rings: document.querySelectorAll('#prog .pgr svg').length, cats: [...document.querySelectorAll('#prog .pcb')].map((x) => x.textContent), dots: document.querySelectorAll('#prog .pem .d').length, hot: !!document.querySelector('#prog .pem .c.hot .d'), hrefs: [...document.querySelectorAll('#prog .pgp')].map((a) => a.getAttribute('href')), x: window.__y === 1 }));
    ok(pg.rings === 2 && /65%/.test(pg.t) && /13 \/ 20/.test(pg.t) && /1 \/ 3 departments signed/.test(pg.t), 'the assessment cycle: progress ring, assessed and departments signed: ' + pg.t.slice(0, 120));
    ok(/Synthetic Board 2026\/8/.test(pg.t) && /1 changed since/.test(pg.t), 'the RAS Board approval with what changed since');
    ok(pg.cats.length === 2 && /Reserving risk.*12/.test(pg.cats[0]) && /^IT and cyber risk/.test(pg.cats[1]) && /1$/.test(pg.cats[1]), 'insurance categories: recorded and suggested, a Class III / IV badge: ' + JSON.stringify(pg.cats));
    ok(pg.dots === 1 && pg.hot && !pg.x, 'emerging risks: only the watched one, in the near and severe corner; text escaped');
    ok(pg.hrefs.join() === 'risk-cycle.html,ras-manage.html,risk-catalogue.html,risk-catalogue.html', 'each part opens its page');
    const nx = await p.evaluate(() => { const q = (s) => [...document.querySelectorAll(s)];
      return { it: q('#map .em .it').reduce((t, x) => t + +x.textContent, 0), bz: q('#map .em .bz').reduce((t, x) => t + +x.textContent, 0), c45: (q('#map .em .c')[1 * 5 + 4 - 5] || {}).textContent,
        bars: q('#sim svg.hist rect').length, simTxt: document.getElementById('sim').textContent, marks: q('#sim svg.hist text').map((x) => x.textContent).join(' '),
        mv: q('#movers svg circle').length, mvTxt: q('#movers svg text').map((x) => x.textContent).join(' '), own: q('#owners .hb').length, ownTxt: document.getElementById('owners').textContent, ownB: !!document.querySelector('#owners b b') }; });
    ok(nx.it === 3 && nx.bz === 17, 'one risk map: 3 IT & cyber and 17 business risks on the same grid: ' + JSON.stringify(nx).slice(0, 120));
    ok(nx.bars === 8 && /mean 3\.4/.test(nx.marks) && /p90 5/.test(nx.marks) && /68 %/.test(nx.simTxt) && /10,000 simulated years/.test(nx.simTxt), 'next 12 months: the histogram, the mean and p90 marked, the chance of a high-impact risk');
    ok(nx.mv === 4 && /20 \(\+8\)/.test(nx.mvTxt) && /15 \(-1\)/.test(nx.mvTxt), 'what moved: each risk from its score 30 days ago to now');
    // the AI Risk Officer: outcomes, the queue with the supervisor's verdicts, held items with whom they went to, what it learned
    const of = await p.evaluate(() => ({ tiles: document.querySelectorAll('#score .sct > div').length, t0: document.querySelector('#score .sct > div').textContent, spark: document.querySelectorAll('#score svg path').length,
      q: document.querySelectorAll('#queue .oq li').length, v: [...document.querySelectorAll('#queue details summary')].map((x) => x.textContent), btn: document.querySelectorAll('#queue [data-dec]').length, held: document.getElementById('queue').textContent,
      learn: document.getElementById('learn').textContent, xss: window.__y === 1 || !!document.querySelector('#queue img') }));
    ok(of.tiles === 4 && /71\.4 %/.test(of.t0) && /target 90 %/.test(of.t0) && of.spark === 1, 'graded on outcomes: each measure, its target and its trend: ' + of.t0);
    ok(of.q === 3 && /supervisor: passed/.test(of.v[0]) && /supervisor: flagged - match score 0\.41/.test(of.v[1]) && of.btn === 4, 'the queue: each proposal with the supervisor verdict, approve / reject for two (held has none)');
    ok(/escalated to Synthetic Finance/.test(of.held) && /SYN-RAS-9 is not in the RAS/.test(of.held), 'a held proposal: why, and to whom it went');
    ok(/1 approved, 5 rejected - raised one severity lower/.test(of.learn) && /0\.52/.test(of.learn) && !of.xss, 'what it learned; record text escaped');
    await p.click('[data-dec="reject"][data-id="RO-ras-breach:SYN-RAS-1:2026-10"]'); ok(decided.length === 0, 'reject without a reason is not sent');
    await p.fill('[id="on-RO-risk-unwatched:BR-0042"]', 'synthetic: wrong metric'); await p.click('[data-dec="reject"][data-id="RO-risk-unwatched:BR-0042"]');
    await p.click('[data-dec="approve"][data-id="RO-ras-breach:SYN-RAS-1:2026-10"]'); await p.waitForTimeout(400);
    ok(decided.length === 2 && decided[0].decision === 'reject' && decided[0].note === 'synthetic: wrong metric' && decided[1].decision === 'approve', 'decisions sent: ' + JSON.stringify(decided));
    ok(nx.own === 2 && /40 ▲2/.test(nx.ownTxt) && /69 %/.test(nx.ownTxt) && !nx.ownB, 'who carries the risk: owners by residual score, the concentration, an owner name escaped');
    // the first priority link opens its page
    await Promise.all([p.waitForURL(/risk-studio\.html|risk-appetite\.html|business-risk-register\.html/, { timeout: 10000 }).catch(() => null), p.click('#prio .pr li a')]);
    ok(/risk-studio|risk-appetite|business-risk-register/.test(p.url()), 'clicking a priority opens it: ' + p.url());
    await open(p); await Promise.all([p.waitForURL(/business-risk-register\.html#class=34/), p.click('#kpis a.k:nth-child(5)')]);
    ok(/business-risk-register\.html#class=34$/.test(p.url()), 'the Class III / IV tile opens the register with the Class III or IV filter (the filter itself: business-risk.test.js): ' + p.url());
    if (SHOTS) { await open(p); await p.waitForTimeout(1300); await p.screenshot({ path: path.join(SHOTS, 'enterprise-risk.png'), fullPage: true }); }
    // refresh redraws without a second copy of anything
    await open(p); await p.click('#refresh'); await p.waitForTimeout(600); ok(await p.evaluate(() => document.querySelectorAll('#it svg.gauge').length === 1 && document.querySelectorAll('#prio ol.pr').length === 1), 'refresh redraws once');

    // nothing yet: every chart says what is missing, nothing is drawn as if measured
    mode = 'empty'; await p.goto(base + '?standalone=1'); await wait(p, () => /Nothing to act on/.test(document.getElementById('prio').textContent));
    const em = await p.evaluate(() => ({ it: document.getElementById('it').textContent, arc: document.querySelectorAll('#it .garc').length, br: document.getElementById('br').textContent, scen: document.getElementById('scen').textContent, ras: document.getElementById('ras').textContent, k: document.getElementById('kpis').textContent }));
    ok(em.arc === 0 && /—/.test(em.it) && /one snapshot a day/.test(em.it) && /No category yet/.test(em.it), 'empty: no posture arc, the trend and categories say why: ' + em.it.slice(0, 160));
    ok(/No risk register yet/.test(em.br) && /No scenario assessed yet/.test(em.scen) && /No appetite metric yet/.test(em.ras), 'empty: business, scenarios and appetite say what to connect');
    const em2 = await p.evaluate(() => ['sim', 'movers', 'owners'].map((id) => document.getElementById(id).textContent).join(' | '));
    ok(/Not enough rated risks to simulate/.test(em2) && /No score moved in 30 days/.test(em2) && /No owner yet/.test(em2), 'empty: the simulation, movers and owners say why: ' + em2);
    // both services missing, then a viewer refused
    mode = 'missing'; await p.goto(base + '?standalone=1'); await wait(p, () => /not installed/.test(document.getElementById('err').textContent));
    ok(/Risk Command not installed/.test(await p.textContent('#err')) && /Business risk not installed/.test(await p.textContent('#err')) && /not measured/.test(await p.textContent('#it')), 'both services missing: said, page still drawn');
    ok(await p.evaluate(() => document.getElementById('offcard').hidden), 'the officer card hidden where the officer is not installed');
    ok(await p.evaluate(() => document.getElementById('wfcard').hidden), 'Workflow Automation not installed: its card hidden, never zeros');
    ok(await wait(p, () => document.querySelectorAll('#prog .pgp.off').length === 4 && /not available - run the update/.test(document.getElementById('prog').textContent)), 'the programme not installed: each part grey and says what to do, nothing invented');
    mode = 'refused'; role = 'viewer'; await p.goto(base + '?standalone=1'); await wait(p, () => /role cannot open/.test(document.getElementById('err').textContent));
    ok(/Your role cannot open this page/.test(await p.textContent('#err')), 'a refused role is told so');
    mode = 'full'; role = 'admin';

    // Arabic: right to left, chart labels inside the SVG translated, no sideways scroll
    await p.evaluate(() => localStorage.setItem('zyb-dash-prefs', JSON.stringify({ lang: 'ar' })));
    await open(p, '');
    const ar = await p.evaluate(() => ({ dir: document.documentElement.dir, gauge: document.querySelector('#it svg.gauge').getAttribute('aria-label'), sub: document.querySelector('#br svg.donut text:last-of-type').textContent, cap: document.querySelector('#br .heat .cap').textContent, dates: (() => { const x = [...document.querySelectorAll('#it .sparkx span')]; return x.length === 2 && x[0].textContent === '2026-10-01' && x[0].getBoundingClientRect().left < x[1].getBoundingClientRect().left; })(), ltrNum: [...document.querySelectorAll('#br .st bdi')].some((e) => e.textContent === '5 / 7' && getComputedStyle(e).direction === 'ltr'), h3: document.querySelector('#it h3').textContent, wide: document.documentElement.scrollWidth <= innerWidth + 1 }));
    ok(ar.dates && ar.ltrNum, 'Arabic: the trend still reads oldest to newest left to right, and figures like 5 / 7 keep their order');
    ok(ar.dir === 'rtl' && /وضع المخاطر/.test(ar.gauge) && ar.sub === 'المخاطر' && /الأثر/.test(ar.cap) && /90/.test(ar.h3) && /[؀-ۿ]/.test(ar.h3) && ar.wide, 'Arabic: right to left, chart labels translated: ' + JSON.stringify(ar));
    if (SHOTS) { await p.waitForTimeout(1300); await p.screenshot({ path: path.join(SHOTS, 'enterprise-risk-ar.png'), fullPage: true }); }
    await p.evaluate(() => localStorage.setItem('zyb-dash-prefs', JSON.stringify({ lang: 'en' })));

    role = 'viewer'; await p.goto(base + '?standalone=1'); await wait(p, () => document.querySelectorAll('#queue .oq li').length === 3);
    ok(!(await p.$('#queue [data-dec]')), 'a viewer sees the queue, no decision buttons'); role = 'admin';
    // the AI risk automation is one click away: the header button and the AI Risk Officer card open the flow
    await open(p); const fl = await p.evaluate(() => ({ btn: (document.getElementById('aiflow') || {}).getAttribute && document.getElementById('aiflow').getAttribute('href'), txt: (document.getElementById('aiflow') || {}).textContent || '', card: !!document.querySelector('#offcard a[href="risk-flow.html"]') }));
    ok(fl.btn === 'risk-flow.html' && /AI risk automation/.test(fl.txt) && fl.card, 'the header and the AI Risk Officer card link the AI risk automation flow: ' + JSON.stringify(fl));
    // phone
    const m = await browser.newPage({ viewport: { width: 390, height: 860 } }); m.on('pageerror', (x) => errs.push(x.message));
    await open(m); ok(await m.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), 'phone width: no sideways scroll');
    if (SHOTS) { await m.waitForTimeout(1300); await m.screenshot({ path: path.join(SHOTS, 'enterprise-risk-phone.png'), fullPage: true }); }
  } finally { await browser.close(); srv.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
