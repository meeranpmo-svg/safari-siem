// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// NPM Summary (npm-summary.html), stubbed engine, SYNTHETIC devices: every red node shows the reason from its last poll;
// all nodes red at once says it is the path from the engine server; "Poll all now" starts a poll on the engine, follows
// it until the cycle ends and redraws the dots; a viewer is told the role; an engine without the route says to update.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node npm-summary.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
let WHO = { user: 'omar.syn', role: 'operator' }, POLLS = 0, RUNNING = 0, ROUTE = true, UP = false, NOCR = true, BRIEFS = 0;
// the SIEM's NOC intelligence (GET /netops/noc), SYNTHETIC: a gateway down covering two nodes, one anomaly, a forecast; a hostile device name
const NOC = () => ({ at: Date.now(), total: 4, counts: { up: 1, warning: 0, critical: 3, unknown: 0, unpolled: 0 }, estate_score: 42,
  causes: [{ kind: 'device', title: 'GW-SYN (gateway) is down at Jeddah - 2 node(s) behind it', site: 'Jeddah', root: 'gw', nodes: ['gw', 'a', 'b'], check: 'Start with GW-SYN (10.9.9.1): power, uplink, then the nodes behind it.' }],
  attention: [{ id: 'core<1>', name: '<img src=x onerror=alert(1)>core-syn', site: 'Riyadh', score: 55, why: [{ pts: -15, why: 'CPU 93 %' }, { pts: -30, why: 'packet loss 30 %' }] }],
  anomalies: [{ device: 'core<1>', name: 'core-syn', site: 'Riyadh', metric: 'rtt', z: 7.2, value: 80, baseline: 4 }], flapping: [],
  forecast: { items: [{ device: 'core<1>', device_name: 'core-syn', interface: 'Te1/1', days_to_90: 12, peak_now: 76, growth_per_week: 8, days_of_data: 14 }], note: '' },
  sites: [{ site: 'Jeddah', nodes: 3, down: 3, worst: 'critical', score: 0 }, { site: 'Riyadh', nodes: 1, down: 0, worst: 'up', score: 55 }],
  model: { window_h: 24, min_samples: 30, z_alert: 4, learning_nodes: 1 }, ai: { enabled: true }, note: 'Probable causes are leads to check, not verdicts.' });
const node = (id, state, reason) => ({ id, name: id + '.syn.local', vendor: 'cisco-ios', ip: '10.9.0.' + id.length, site: 'Riyadh', role: 'access', state, reason, response_ms: state === 'up' ? 2 : null, last: Date.now() });
const npm = () => { const ns = UP ? [node('sw-syn-1', 'up', ''), node('sw-syn-2', 'critical', 'snmp: timeout')] : [node('sw-syn-1', 'critical', 'no reply to ping from the engine server (3 sent)'), node('sw-syn-2', 'critical', 'no reply to ping from the engine server (3 sent)')];
  const counts = { up: 0, warning: 0, critical: 0, unknown: 0, unpolled: 0 }; ns.forEach((x) => counts[x.state]++);
  return { counts, total: ns.length, vendors: [{ vendor: 'Cisco IOS', count: ns.length, nodes: ns }], interfaces: [], high_interfaces: 0, polled: true, poller: { running: RUNNING > 0, last_cycle_at: Date.now() - 60000 } }; };
(async () => {
  const srv = http.createServer((req, res) => {
    const u = decodeURIComponent(req.url.split('?')[0]), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u === '/dashboards/whoami.json' || u === '/auth/whoami') return json(200, WHO);
    if (u === '/api/soc/netops/noc') return NOCR ? json(200, NOC()) : json(404, { error: 'not found' });
    if (u === '/api/soc/netops/noc/brief' && req.method === 'POST') { BRIEFS++; if (WHO.role === 'viewer') return json(403, { error: 'requires operator role' });
      return json(200, { ok: true, label: 'AI draft - verify', summary: 'Jeddah gateway down <b>bold</b>', priorities: [{ device: 'gw', why: 'gateway down', check: 'power and uplink', team: 'network', verified: true }, { device: 'ghost', why: 'x', check: 'y', verified: false }], watch: ['core-syn CPU'] }); }
    if (u === '/api/soc/netops/npm') { if (RUNNING > 0 && --RUNNING === 0) UP = true; return json(200, npm()); }   // the cycle ends after a few reads
    if (u === '/api/soc/netops/poll' && req.method === 'POST') { if (!ROUTE) return json(404, { error: 'not found' }); if (WHO.role === 'viewer') return json(403, { error: 'requires operator role' }); POLLS++; RUNNING = 2; return json(200, { started: true, running: true, devices: 2 }); }
    // Workflow Automation attention(who), synthetic, in the engine's shape: the network team's queue and a change waiting for approval
    if (u === '/api/itam/workflow/attention') return json(200, { summary: { approvals: 1, queue_open: 2, overdue: 1, at_risk: 0, to_accept: 0, raised_open: 0, raised_late: 0, functions: [], all_overdue: 2, recurring: 0,
        teams: [{ team: 'network', name: 'Network team', open: 2, overdue: 1, n: 5, on_time: 4, rate: 0.71 }], items: [] },
      priorities: [{ kind: 'Request approval', ref: 'REQ-2026-0051', text: 'VLAN 40 for the <img src=x onerror=window.__wfx=1> branch - Network change, from Administration', page: 'workflow-automation.html#req=REQ-2026-0051', why: [['a business request waiting for your approval', 45]] },
        { kind: 'Request overdue', ref: 'REQ-2026-0047', text: 'Network device configuration backups - Network team', page: 'workflow-automation.html#req=REQ-2026-0047', why: [['a request to the IT team past its due date', 40], ['escalated', 10]] }] });
    if (u.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.replace(/^\/dashboards\//, '/'));
    if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (e, d) => { if (e) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': f.endsWith('.js') ? 'application/javascript' : f.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const url = 'http://127.0.0.1:' + srv.address().port + '/dashboards/npm-summary.html?standalone=1';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch(); const errs = [];
  const open = async () => { const p = await browser.newPage({ viewport: { width: 1366, height: 900 } }); p.on('pageerror', (e) => errs.push(e.message)); await p.goto(url); await p.waitForSelector('#tree .node', { timeout: 15000 }); return p; };
  const toastText = (p) => p.evaluate(() => [...document.querySelectorAll('.toast')].map((t) => t.textContent).join(' | '));
  try {
    let p = await open();
    ok(/No device answers the engine server \(2 of 2\)/.test(await p.textContent('#why')), 'all red: says it is the path from the engine server');
    const why = await p.$$eval('#tree .node .why', (a) => a.map((x) => x.textContent));
    ok(why.length === 2 && /no reply to ping/.test(why[0]), 'each red node shows its reason: ' + why.join(' / '));
    ok(/no reply to ping/.test(await p.getAttribute('#tree .node', 'title')), 'the reason is in the tooltip too');
    ok(/last poll \d\d:\d\d/.test(await p.textContent('#up')), 'when the last poll ran');
    { await p.waitForFunction(() => !document.getElementById('wfcard').hidden, null, { timeout: 10000 }).catch(() => null);
      const k = await p.textContent('#wfk'), l = await p.textContent('#wfl');
      ok(/Network team · open\s*2/.test(k) && /Network team · overdue\s*1/.test(k) && /Network team · on time\s*80%/.test(k) && /Waiting for your approval\s*1/.test(k) && /Overdue across IT\s*2/.test(k), 'Workflow Automation: the network team\'s open / overdue / on time, approvals: ' + k.replace(/\s+/g, ' '));
      ok(l.indexOf('REQ-2026-0047') < l.indexOf('REQ-2026-0051') && /<img src=x/.test(l) && !(await p.$('#wfl img')) && !(await p.evaluate(() => window.__wfx)) && !!(await p.$('#wfl a[href="workflow-automation.html#req=REQ-2026-0051"]')), 'Workflow: ranked by points, a hostile title stays text, linked'); }
    ok(await p.isVisible('#pollnow') && /Poll all now/.test(await p.textContent('#pollnow')), 'a Poll all now button next to Refresh');
    await p.click('#pollnow');
    await p.waitForFunction(() => /Poll finished/.test([...document.querySelectorAll('.toast')].map((t) => t.textContent).join(' ')), null, { timeout: 30000 }).catch(() => {});
    ok(POLLS === 1, 'the engine was asked to poll once: ' + POLLS);
    ok(/Poll finished: 1 up, 1 not answering/.test(await toastText(p)), 'followed the poll to the end and reports the result: ' + await toastText(p));
    const dots = await p.$$eval('#tree .node .dot', (a) => a.map((d) => d.className));
    ok(/st-up/.test(dots[0]) && /st-critical/.test(dots[1]), 'dots redrawn after the poll: ' + dots.join(','));
    ok(/1 of 2 nodes are not answering/.test(await p.textContent('#why')), 'banner follows the new result');
    ok(!(await p.isDisabled('#pollnow')), 'the button is usable again');
    await p.close();

    WHO = { user: 'v.syn', role: 'viewer' }; UP = false; p = await open(); await p.click('#pollnow'); await p.waitForTimeout(600);
    ok(/needs the operator role/.test(await toastText(p)) && POLLS === 1, 'viewer: told the role, nothing polled');
    await p.close();
    // ---- NOC intelligence
    WHO = { user: 'omar.syn', role: 'operator' }; p = await open(); await p.waitForSelector('#causes .cause', { timeout: 10000 });
    ok((await p.textContent('#gauge')).includes('42') && /Down 3/.test(await p.textContent('#gauge')), 'network health score and counts from the SIEM');
    ok(/GW-SYN \(gateway\) is down at Jeddah/.test(await p.textContent('#causes')) && /not counted again/.test(await p.textContent('#causes')), 'one probable cause covers the nodes behind it');
    await p.waitForTimeout(400); const ngc = (await p.$$('.ng canvas')).length, ids = await p.$$eval('.ng .ncv', (L) => L.map((x) => (x.querySelector('canvas') || {}).id || x.innerHTML.slice(0, 80)).join(' ')), nli = (await p.$$('#nins li')).length; ok(ngc === 8 && nli >= 1, 'eight charts and what the AI noticed: ' + ngc + ' canvases, ' + nli + ' notes; ' + ids);
    ok(!(await p.$('#npanel img')) && /<img src=x/.test(await p.textContent('#npanel')) && /CPU 93 %/.test(await p.textContent('#npanel')), 'needs attention: itemised reasons, a hostile name shown as text');
    ok((await p.getAttribute('#npanel a', 'href')) === 'node-details.html?id=core%3C1%3E', 'a node opens its details (id encoded)');
    await p.click('#ntabs [data-t="anom"]'); ok(/Response time \(ms\)/.test(await p.textContent('#npanel')) && /7\.2/.test(await p.textContent('#npanel')), 'anomaly against the node\'s own normal, with its z');
    await p.click('#ntabs [data-t="fc"]'); ok(/12 days/.test(await p.textContent('#npanel')) && /Te1\/1/.test(await p.textContent('#npanel')), 'capacity forecast: days to 90 %');
    await p.click('#ntabs [data-t="flap"]'); ok(/Nothing flapping/.test(await p.textContent('#npanel')), 'flapping: honest empty state');
    await p.click('#ntabs [data-t="sites"]'); ok(/Jeddah/.test(await p.textContent('#npanel')), 'site health');
    ok(/1 node\(s\) still building their own baseline/.test(await p.textContent('#nmodel')), 'how much the model has learned is stated');
    await p.click('#ntabs [data-t="ai"]'); await p.click('#askbrief'); await p.waitForSelector('#briefout table', { timeout: 10000 });
    const bt = await p.textContent('#briefout');
    ok(BRIEFS === 1 && /unverified/.test(bt) && /checked/.test(bt) && !(await p.$('#briefout b')), 'AI brief: asked once, unverified rows marked, model text escaped: ' + bt.slice(0, 120));
    await p.close();
    WHO = { user: 'v.syn', role: 'viewer' }; p = await open(); await p.waitForSelector('#causes .cause'); await p.click('#ntabs [data-t="ai"]'); await p.click('#askbrief');
    await p.waitForFunction(() => /operator role/.test(document.getElementById('briefout').textContent), null, { timeout: 8000 }).catch(() => {});
    ok(/needs the operator role/.test(await p.textContent('#briefout')), 'viewer: told the brief needs the operator role'); await p.close();
    NOCR = false; WHO = { user: 'omar.syn', role: 'operator' }; p = await open(); await p.waitForTimeout(800);
    ok(/run the update/.test(await p.textContent('#gauge')) && (await p.$$('#tree .node')).length === 2, 'an engine without the NOC intelligence says to update; the rest of the page still works'); await p.close(); NOCR = true;
    WHO = { user: 'syed', role: 'admin' }; ROUTE = false; p = await open(); await p.click('#pollnow'); await p.waitForTimeout(600);
    ok(/run the update/.test(await toastText(p)), 'an engine without the route says to run the update');
    await p.close();
    ok(!errs.length, 'no page errors: ' + errs.slice(0, 3).join(' | '));
  } finally { await browser.close(); srv.close(); }
  console.log(bad ? 'FAILED ' + bad + '/' + n + ' checks' : 'OK ' + n + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
