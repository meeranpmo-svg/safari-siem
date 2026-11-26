// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for the AI Engineering Team overview (dashboards/server/ai-team.html + vendor/zyb-teamviz.js) over a STUBBED
// duty API with SYNTHETIC engineers: every engineer is on the operations floor, each movement follows its real state
// (radar = patrolling, dots = open work, red = critical, purple = waiting for approval, amber = late, grey = off duty),
// the agent loop on each card lights the steps that hold work, a hostile engineer name stays text, a side that is not
// installed is named, reduced motion stops the movement, and a node opens the engineer's desk.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node ai-team.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.join(__dirname, '..', '..', 'ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const NOW = Date.now();
const eng = (id, name, o) => Object.assign({ id, name, on_duty: true, not_connected: false, late: false, last_error: null, last_patrol: NOW - 120000, open: 0, critical: 0, high: 0, resolved_24h: 0, by_status: {}, ai: { enabled: true, used_today: 3, cap: 50 } }, o);
const SOC = [
  eng('network', 'AI Network Engineer', { open: 4, critical: 1, by_status: { open: 1, investigating: 1, 'awaiting-approval': 2 }, resolved_24h: 3 }),
  eng('security', 'AI Security Engineer', { open: 2, by_status: { diagnosed: 1, approved: 1 } }),
  eng('windows', 'AI Windows Admin', { late: true, open: 1, by_status: { 'fix-applied': 1 } }),
  eng('dba', '<img src=x onerror=alert(1)> DBA', { on_duty: false }),
  eng('apps', 'AI Application Manager', { not_connected: true }),
  eng('exchange', 'AI Exchange Admin', {}),
];
let ITAM_UP = true;
const ITAM = [eng('desk', 'AI Desktop Support', { open: 3, by_status: { open: 3 } }), eng('grc', 'AI GRC Consultant', { ai: { enabled: false } })];

(async () => {
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, { user: 'syn.op', role: 'operator' });
    const m = /^\/api\/(soc|itam)\/duty\/(\w+)/.exec(u.pathname);
    if (m) {
      if (m[1] === 'itam' && !ITAM_UP) return json(404, { error: 'not found' });
      const list = m[1] === 'soc' ? SOC : ITAM;
      if (m[2] === 'engineers') return json(200, { engineers: list, policy: { enabled: true } });
      if (m[2] === 'items') return json(200, { items: [] });
      if (m[2] === 'reports') return json(200, { reports: [] });
      if (m[2] === 'kpis') return json(200, { engineers: [] });
      if (m[2] === 'readiness') return json(200, { engineers: [] });
      return json(200, {});
    }
    if (u.pathname === '/api/soc/db/oracle') return json(200, { generated_at: new Date().toISOString(), instances: [{ instance: 'ORCL1', host: 'ora-syn-01', up: true, role: 'PRIMARY', issues: [] }, { instance: 'HR1', host: 'hr-syn-01', up: false, status: 'MOUNTED', state: 'down', issues: [{ text: 'instance is not open' }], worst_severity: 4 }] });
    if (u.pathname === '/api/itam/db-inventory') return json(200, { servers: [{ id: 'oracle|10.9.1.21|1521', engine: 'oracle', ip: '10.9.1.21', host: 'ORA-SYN-01', server: { instance: 'ORCL1', host_name: 'ora-syn-01' }, totals: { databases: 3, size_mb: 409600 }, notes: [] },
      { id: 'mssql|10.9.0.11|1433', engine: 'mssql', label: 'SQL Server', ip: '10.9.0.11', port: 1433, host: 'SQL-SYN-01', asset_name: 'SQL-SYN-01', server: { version: '15.0' }, totals: { databases: 3, size_mb: 54148 }, notes: [{ severity: 'high', text: 'ArchiveSyn is OFFLINE' }] },
      { id: 'postgres|10.9.0.12|5432', engine: 'postgres', label: 'PostgreSQL', ip: '10.9.0.12', port: 5432, host: 'PG-SYN-01', asset_name: 'PG-SYN-01', server: {}, totals: { databases: 1, size_mb: 1200 }, notes: [] },
      { id: 'mysql|10.9.0.13|3306', engine: 'mysql', label: 'MySQL / MariaDB', ip: '10.9.0.13', port: 3306, host: 'MY-SYN-01', asset_name: 'MY-SYN-01', error: 'Access denied', error_class: 'auth', server: {}, notes: [] }],
      found: [{ engine: 'mysql', label: 'MySQL / MariaDB', ip: '10.9.0.14', host: 'my-syn-02', asset_name: 'MY-SYN-02', next: 'Create the read-only login' }], settings: { interval_h: 6 } });
    if (u.pathname === '/api/itam/discovery/advisor') return json(200, { summary: { coverage_pct: 40, scopes: 2, uncovered: 1 }, proposals: [{ key: 'new:10.30.5.0/24' }],
      scopes: [{ id: 'sc_a', name: 'HQ servers (synthetic)', health: 92, grade: 'good', found: 40, recommendations: [], anomaly: null },
        { id: 'sc_b', name: 'Branch LAN (synthetic)', health: 45, grade: 'poor', found: 8, recommendations: [{ text: 'Check what changed' }], anomaly: { z: -5, text: 'the last run saw 8 device(s), usually 40' } }],
      coverage: [{ subnet: '10.20.1.0/24', covered: true, assets: 3 }, { subnet: '10.30.5.0/24', covered: false, assets: 5 }] });
    if (u.pathname === '/api/itam/cmdb/studio') return json(200, { summary: { cis: 14, confirmed: 9, quality_pct: 71, proposals: 2, spof: 1, duplicates: 1, types: [
      { type: 'server', cis: 5, quality_pct: 88, spof: 1, orphans: 0 }, { type: 'vm', cis: 6, quality_pct: 62, spof: 0, orphans: 2 }, { type: 'network', cis: 3, quality_pct: 30, spof: 0, orphans: 1 },
      { type: '<img src=x onerror=alert(1)>', cis: 0, quality_pct: null, spof: 0, orphans: 0 }] }, pending: [{ id: 'rel_1' }] });
    if (u.pathname === '/api/itam/assist/overview') return json(200, { first: [{}, {}, {}], frameworks: [
      { fw: 'sama', framework: 'SAMA CSF + IA', installed: true, counts: { pct_met: 85, gap: 2, partial: 0, unknown: 1 }, sentence: 'SAMA CSF + IA: 40 of 47 done' },
      { fw: 'ecc', framework: 'NCA ECC', installed: true, counts: { pct_met: 55, gap: 9, partial: 2, unknown: 0 }, sentence: 'NCA ECC: 29 of 53 done' },
      { fw: 'iso', framework: 'ISO/IEC 27001', installed: true, counts: { pct_met: 12, gap: 22, partial: 0, unknown: 80 }, sentence: 'ISO: 14 of 118 done' },
      { fw: 'ndmo', framework: 'NDMO', installed: false, counts: { total: 0 }, sentence: 'NDMO: not installed' },
      { fw: 'pdpl', framework: '<img src=x onerror=alert(1)>', installed: true, counts: { pct_met: 90, gap: 0, partial: 1, unknown: 0 }, sentence: 'PDPL' }] });
    if (u.pathname.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg, { timeout: 15000 }).then(() => true, () => false);
  const node = (p, id) => p.$('.tv-n[data-eng="' + id + '"]');
  const cls = async (p, id) => (await (await node(p, id)).getAttribute('class'));
  try {
    const p = await browser.newPage({ viewport: { width: 1440, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message));
    // the database estates: an organisation that has the DBA engineers (Safari's brand switches them off - checked at the end)
    await p.addInitScript(() => { Object.defineProperty(window, 'ZYB_ORG', { configurable: true, set(v) { this._o = Object.assign({}, v, { engineers_off: [] }); }, get() { return this._o; } }); });
    p.on('dialog', (d) => { errs.push('dialog: ' + d.message()); d.dismiss(); });
    await p.goto(base + 'ai-team.html?standalone=1');
    ok(await wait(p, () => document.querySelectorAll('#floor .tv-n').length === 8), 'all eight engineers on the floor');
    ok(/6 of 8 on duty/.test(await p.textContent('.tv-core')) && /10 open items/.test(await p.textContent('.tv-core')), 'the core: on duty and open work');
    ok(/busy/.test(await cls(p, 'network')) && !!(await p.$('.tv-n[data-eng="network"] .tv-radar')), 'network: working, radar sweeping');
    ok((await p.$$('#floor svg circle[fill="#ff5c5c"]')).length === 1, 'one critical item = one red packet');
    ok((await p.$$('#floor svg circle[fill="#7cc4ff"]')).length === 9, 'the other open items travel as blue packets (4+2+3, late Windows shown amber)');
    ok((await p.$$('#floor svg circle[fill="#d68cf0"]')).length === 2, 'two changes waiting = two purple packets to the approvers');
    ok(!!(await p.$('.tv-n[data-eng="network"] .tv-apr')) && /2 changes waiting/.test(await p.textContent('.tv-hum')), 'approvers: waiting for a decision');
    ok(/warn/.test(await cls(p, 'windows')) && /patrol is late/.test(await p.textContent('.tv-n[data-eng="windows"]')), 'late patrol = amber');
    ok(/tv-off/.test(await cls(p, 'dba')) && /tv-off/.test(await cls(p, 'apps')) && /source not connected/.test(await p.textContent('.tv-n[data-eng="apps"]')), 'off duty / not connected = grey and still');
    ok(/idle/.test(await cls(p, 'exchange')) && /all clear/.test(await p.textContent('.tv-n[data-eng="exchange"]')), 'nothing open = patrolling, all clear');
    ok(!(await p.$('#floor img')) && (await p.textContent('#floor')).includes('<img'), 'a hostile name stays text');
    ok(/agentic AI on/.test(await (await node(p, 'network')).getAttribute('title')) && /rules \+ ML/.test(await (await node(p, 'grc')).getAttribute('title')), 'agentic AI or rules + ML per engineer');
    // the agent loop on the cards
    const loopOn = await p.$$eval('#team .tv-loop', (ls) => ls.map((l) => [...l.querySelectorAll('.tv-step')].map((s) => s.classList.contains('tv-on') ? s.querySelector('.tv-d').textContent : '-').join('')));
    ok(loopOn.length === 8 && loopOn[0] === '11-2--', 'network loop: detect 1, diagnose 1, approve 2 (' + loopOn[0] + ')');
    ok(loopOn[1] === '--1-1-' && loopOn[2] === '-----1', 'security propose + act; Windows verifying');
    ok(/Every movement is live state/.test(await p.textContent('.tv-legend')), 'the legend says nothing is simulated');
    // the AI Oracle DBA's Oracle estate, on this page too
    ok(await wait(p, () => document.querySelectorAll('#ofloor .tv-n').length === 2), 'Oracle estate: every Oracle database around the AI Oracle DBA');
    ok(/AI Oracle DBA/.test(await p.textContent('#ofloor .tv-core')) && /2 Oracle databases/.test(await p.textContent('#oovc')), 'the DBA in the middle, counted');
    ok(/3 DBs · 400\.0 GB/.test(await p.textContent('#ofloor [data-node="i:ORCL1@ora-syn-01"]')) && /tv-bad/.test(await p.getAttribute('#ofloor [data-node="i:HR1@hr-syn-01"]', 'class')), 'health joined with the inventory; a down database is red');
    ok((await p.getAttribute('#ofloor [data-node="i:ORCL1@ora-syn-01"]', 'href')) === 'ai-dba.html', 'a database opens the AI Oracle DBA page');
    // SQL Server, PostgreSQL and MySQL around the database inventory
    ok(await wait(p, () => document.querySelectorAll('#dbfloor .tv-n').length === 4), 'SQL Server, PostgreSQL, MySQL (read, refused) and one found without a login');
    ok(/Database inventory/.test(await p.textContent('#dbfloor .tv-core')) && /2 read · every 6 h/.test(await p.textContent('#dbfloor .tv-core')) && /4 servers/.test(await p.textContent('#dbovc')), 'the inventory in the middle, counted');
    ok(/tv-bad/.test(await p.getAttribute('#dbfloor [data-node="r:mssql|10.9.0.11|1433"]', 'class')) && /SQL Server · 3 DBs/.test(await p.textContent('#dbfloor [data-node="r:mssql|10.9.0.11|1433"]')), 'SQL Server with an offline database: red');
    ok(/tv-idle/.test(await p.getAttribute('#dbfloor [data-node="r:postgres|10.9.0.12|5432"]', 'class')), 'PostgreSQL healthy: radar');
    ok(/login refused/.test(await p.textContent('#dbfloor [data-node="r:mysql|10.9.0.13|3306"]')) && /no login yet/.test(await p.textContent('#dbfloor [data-node="f:mysql@10.9.0.14"]')), 'refused and not-yet-logged-in servers: grey, said');
    ok(/AI Database Administrator is not installed yet/.test(await p.textContent('#dbov')), 'without the engineer installed, the panel says so');
    ok(!/SQL-SYN-01/.test(await p.textContent('#ofloor')), 'the Oracle panel keeps to Oracle');
    // Asset Discovery through Scope Studio
    ok(await wait(p, () => document.querySelectorAll('#sfloor .tv-n').length === 3), 'Scope Studio: two scopes and one uncovered subnet');
    ok(/Asset Discovery/.test(await p.textContent('#sfloor .tv-core')) && /40% of assets covered/.test(await p.textContent('#sfloor .tv-core')), 'coverage in the middle');
    ok(/1 scope proposal waiting for a System Admin/.test(await p.textContent('#sfloor .tv-hum')), 'proposals waiting for a person');
    ok(/tv-idle/.test(await p.getAttribute('#sfloor [data-node="s:sc_a"]', 'class')) && /tv-bad/.test(await p.getAttribute('#sfloor [data-node="s:sc_b"]', 'class')), 'a healthy scope sweeps, one with an anomaly is red');
    ok(/no scope/.test(await p.textContent('#sfloor [data-node="g:10.30.5.0/24"]')) && /tv-off/.test(await p.getAttribute('#sfloor [data-node="g:10.30.5.0/24"]', 'class')), 'a gap is grey and says so');
    ok((await p.getAttribute('#sfloor [data-node="s:sc_a"]', 'href')) === 'scope-studio.html' && /2 scope\(s\) · 1 subnet\(s\) not covered/.test(await p.textContent('#scovc')), 'opens Scope Studio; counted');
    // the Compliance Assistant and the five frameworks
    ok(await wait(p, () => document.querySelectorAll('#dfloor .tv-n').length === 4), 'CMDB Studio: one node per CI type');
    ok(/CMDB Studio/.test(await p.textContent('#dfloor .tv-core')) && /14 CIs · 9 confirmed links · 71% quality/.test(await p.textContent('#dfloor .tv-core')), 'CMDB Studio in the middle');
    ok(/3 relationship proposals waiting for a person/.test(await p.textContent('#dfloor .tv-hum')), 'ML + sensor / AI proposals waiting for a person');
    ok(/tv-idle/.test(await p.getAttribute('#dfloor [data-node="t:server"]', 'class')) && /tv-warn/.test(await p.getAttribute('#dfloor [data-node="t:vm"]', 'class')) && /tv-bad/.test(await p.getAttribute('#dfloor [data-node="t:network"]', 'class')), '88 % radar, 62 % amber, 30 % red');
    ok(/6 CIs · 62% complete/.test(await p.textContent('#dfloor [data-node="t:vm"]')) && (await p.getAttribute('#dfloor [data-node="t:vm"]', 'href')) === 'cmdb-studio.html', 'the numbers in words; opens CMDB Studio');
    ok(!(await p.$('#dfloor img')) && /14 CI\(s\) · 1 single point\(s\) of failure · 1 possible duplicate\(s\)/.test(await p.textContent('#cdovc')), 'a hostile type stays text; counted');
    ok(await wait(p, () => document.querySelectorAll('#cfloor .tv-n').length === 5), 'Compliance Assistant: five frameworks');
    ok(/Compliance Assistant/.test(await p.textContent('#cfloor .tv-core')) && /4 of 5 registers · local ML, no external AI/.test(await p.textContent('#cfloor .tv-core')), 'the assistant in the middle');
    ok(/3 fixes ranked to do first/.test(await p.textContent('#cfloor .tv-hum')), 'the ranked fixes');
    ok(/tv-idle/.test(await p.getAttribute('#cfloor [data-node="f:sama"]', 'class')) && /tv-warn/.test(await p.getAttribute('#cfloor [data-node="f:ecc"]', 'class')) && /tv-bad/.test(await p.getAttribute('#cfloor [data-node="f:iso"]', 'class')) && /tv-off/.test(await p.getAttribute('#cfloor [data-node="f:ndmo"]', 'class')), '85 % radar, 55 % amber, 12 % red, not installed grey');
    ok(/12% done · 22 not done · 80 not checked/.test(await p.textContent('#cfloor [data-node="f:iso"]')), 'the numbers in words');
    ok(/compliance-assistant\.html\?q=Are%20we%20compliant%20with%20NCA%20ECC/.test(await p.getAttribute('#cfloor [data-node="f:ecc"]', 'href')), 'a framework opens the assistant with the question asked');
    ok(!(await p.$('#cfloor img')) && /2 of 4 frameworks at 80 %\+/.test(await p.textContent('#cmovc')), 'a hostile name stays text; counted');
    // a node opens the desk
    ok((await (await node(p, 'network')).getAttribute('href')) === 'network-engineer.html', 'a node links to the engineer\'s desk');
    // title menu: one view at a time, remembered in the address, Back works, Everything shows the whole page
    const vis = (sel) => p.evaluate((q) => { const el = document.querySelector(q); return !!el && el.getClientRects().length > 0; }, sel);
    ok(await vis('#floor') && !(await vis('#kpis')) && !(await vis('#oraov')) && !(await vis('#charters')) && !(await vis('#readiness')), 'opens on Overview, the team picture first');
    ok(await p.getAttribute('#attabs [data-t="home"]', 'aria-selected') === 'true', 'Overview is selected');
    ok(/Team overview/.test(await p.textContent('#atsub button[aria-selected="true"]')), 'its sub-menu opens on Team overview');
    await p.click('#atsub [data-s="status"]');
    ok(await vis('#readiness') && !(await vis('#floor')) && /#view=home&sub=status$/.test(p.url()), 'Status part, in the address');
    await p.click('#attabs [data-t="kpi"]');
    ok(await vis('#kpis') && !(await vis('#floor')) && /#view=kpi$/.test(p.url()) && await p.isHidden('#atsub'), 'KPIs view, in the address; one part = no sub-menu');
    await p.click('#attabs [data-t="est"]');
    ok(await vis('#oraov') && !(await vis('#cmov')) && !(await vis('#kpis')), 'Estates & studios opens on its first part only (shorter page)');
    ok((await p.$$eval('#atsub button', (b) => b.map((x) => x.textContent))).join('|') === 'Oracle estate|SQL Server · PostgreSQL · MySQL|Asset Discovery|CMDB Studio|Compliance Assistant', 'Estates & studios sub-menu: five parts');
    await p.click('#atsub [data-s="compliance"]');
    ok(await vis('#cmov') && !(await vis('#oraov')) && /#view=est&sub=compliance$/.test(p.url()), 'a part opens on its own');
    await p.click('#attabs [data-t="roles"]');
    ok(await vis('#apprs') && !(await vis('#charters')) && !(await vis('#oraov')), 'Roles & approvals view: approvers first');
    await p.click('#atsub [data-s="charters"]');
    ok(await vis('#charters') && !(await vis('#apprs')), 'job descriptions on their own');
    await p.goBack();
    ok(await wait(p, () => document.getElementById('apprs').getClientRects().length > 0 && !document.getElementById('charters').getClientRects().length), 'Back returns to the previous part');
    await p.goBack();
    ok(await wait(p, () => document.getElementById('cmov').getClientRects().length > 0 && !document.getElementById('apprs').getClientRects().length), 'and to the previous view and part');
    await p.click('#attabs [data-t="eng"]');
    ok(await vis('#team') && /\(\d+\)/.test(await p.textContent('#tc-eng')), 'Engineers view, counted on its tab');
    await p.click('#attabs [data-t="all"]');
    ok(await vis('#floor') && await vis('#kpis') && await vis('#charters') && await vis('#allai') && await vis('#oraov') && await vis('#cmov') && await p.isHidden('#atsub'), 'Everything shows the whole page, no sub-menu');
    await p.goto(base + 'ai-team.html?standalone=1#view=how&sub=everything');
    ok(await wait(p, () => document.querySelector('#allai').getClientRects().length > 0 && !document.getElementById('floor').getClientRects().length), 'a link opens its view and part');
    ok(await wait(p, () => document.querySelectorAll('#floor .tv-n').length === 8), 'hidden views still load');
    await p.goto(base + 'ai-team.html?standalone=1'); await wait(p, () => document.querySelectorAll('#floor .tv-n').length === 8);
    // a side not installed is named; reduced motion stops the movement
    ITAM_UP = false; await p.reload();
    ok(await wait(p, () => document.querySelectorAll('#floor .tv-n').length === 6 && /IT Asset side: not installed/.test(document.getElementById('ovc').textContent)), 'a side not installed is named');
    await p.emulateMedia({ reducedMotion: 'reduce' }); await p.reload(); await wait(p, () => document.querySelectorAll('#floor .tv-n').length === 6);
    ok((await p.$$('#floor svg circle')).length === 0 && !(await p.$('.tv-radar')), 'reduced motion: no moving packets or radar');
    ok(!!(await p.$('.tv-n[data-eng="network"] .tv-apr')), 'reduced motion: the state is still shown');
    await p.emulateMedia({ reducedMotion: 'no-preference' }); ITAM_UP = true;
    // phone width: the floor becomes a list
    await p.setViewportSize({ width: 390, height: 900 }); await p.reload(); await wait(p, () => document.querySelectorAll('#floor .tv-n').length === 8);
    ok(await p.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1), 'no horizontal scroll on a phone');
    // the real brand: engineers the organisation does not have (engineers_off, Safari: no DBA) - their estate cards are gone, not read
    const eoff = JSON.parse(fs.readFileSync(path.join(__dirname, '../../brand/brand.json'), 'utf8')).engineers_off || [];
    const q = await browser.newPage({ viewport: { width: 1440, height: 1000 } }); q.on('pageerror', (x) => errs.push(x.message));
    await q.goto(base + 'ai-team.html?standalone=1'); await q.waitForSelector('#team', { state: 'attached' });
    ok((eoff.includes('dba') ? !(await q.$('#oraov')) : !!(await q.$('#oraov'))) && (eoff.includes('sqldba') ? !(await q.$('#dbov')) : !!(await q.$('#dbov'))), 'DBA estate cards follow the brand (engineers_off: ' + eoff.join(',') + ')');
    ok(!/Oracle estate|SQL Server · PostgreSQL/.test(await q.$eval('#atsub', (e) => e.textContent).catch(() => '')) || !eoff.includes('dba'), 'no chip for a removed estate');
    await q.close();
  } finally { await browser.close(); srv.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks');
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
