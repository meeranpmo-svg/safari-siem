// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for app-audit.html with the REAL SIEM module (sentra-siem engine/netops/app-audit.js) over fake availability,
// change-plan state and ClickHouse. Checks: application list, tiles, findings (self-approved change, cleared security log,
// server without logs), the servers / changes / security tabs, deep link #app=, the Excel report sheets, role refusal.
// Run: SENTRA_SIEM_DIR=/home/user/sentra-siem PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node app-audit.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
const SIEM = process.env.SENTRA_SIEM_DIR || path.resolve(__dirname, '../../backend/siem');
const { createAppAudit } = require(path.join(SIEM, 'engine/netops/app-audit'));
let n = 0, bad = 0;
const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };

(async () => {
  const NOW = Date.now(), chTs = (ago) => new Date(NOW - ago).toISOString().replace('T', ' ').replace('Z', '');
  const items = [{ id: 'erp-app1', name: 'ERP-APP1', ip: '10.1.1.11', status: 'online', role: 'primary', availability: { d1: 100, d7: 99.9, d30: 99.9 }, flags: [], days_since_boot: 10 },
    { id: 'erp-app2', name: 'ERP-APP2', ip: '10.1.1.12', status: 'offline', role: 'secondary', availability: { d1: 50, d7: 92, d30: 97 }, flags: ['offline'], days_since_boot: 3 }];
  const groups = [{ key: 'svc:erp', name: 'ERP', members: ['erp-app1', 'erp-app2'], issues: ['no-redundancy-now', 'no-dr'], status: 'degraded', critical: true }];
  const cols = { sysadmin_changes: [{ id: 'SCHG-000002', device: 'erp-app2', title: 'Disable SMBv1', status: 'applied', source: 'user', proposed_by: 'rasheed', proposed_at: NOW - 3600000, decided_by: 'rasheed', decided_at: NOW - 3000000, applied_by: 'rasheed', applied_at: NOW - 2000000 }],
    netops_changes: [], avail_events: [{ host: 'erp-app2', at: NOW - 7200000, from: 'online', to: 'offline' }] };
  const state = { collection: (c) => ({ all: (f) => (cols[c] || []).filter((x) => !f || f(x)) }) };
  const ch = { query: async (sql) => /coverage/.test(sql) ? [{ h: 'erp-app1', ip: '10.1.1.11', c: '900', t: chTs(60000) }]
    : [{ ts: chTs(3600000), host: 'ERP-APP1', host_ip: '10.1.1.11', category: 'policy', action: 'audit-log-cleared', outcome: 'success', severity: 4, user: 'administrator', event_code: '1102', message: 'The audit log was cleared' }] };
  const A = createAppAudit({ av: { view: async () => ({ items, groups }) }, state, ch });
  let ROLE = 'analyst'; const asked = [];
  const srv = http.createServer(async (req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, { user: 'syed', role: ROLE });
    if (u.pathname === '/api/soc/netops/apps/audit') {
      if (ROLE === 'viewer') return json(403, { error: 'analyst or above' });
      const q = Object.fromEntries(u.searchParams); asked.push(q);
      try { return json(200, q.app ? await A.report(q) : await A.list()); } catch (e) { return json(e.code || 500, { error: e.message }); }
    }
    if (u.pathname.startsWith('/api/')) return json(404, { error: 'not in this test' });
    fs.readFile(path.join(DASH, u.pathname), (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(); const ctx = await browser.newContext({ acceptDownloads: true, viewport: { width: 1400, height: 900 } });
  const page = await ctx.newPage(); const errs = [];
  page.on('pageerror', (x) => errs.push(x.message)); page.on('console', (m) => { if (m.type() === 'error' && !/40[34]/.test(m.text())) errs.push(m.text()); });

  await page.goto(base + 'app-audit.html#app=svc%3Aerp'); await page.waitForSelector('#kk .t');
  ok((await page.$eval('#app', (s) => s.value)) === 'svc:erp', 'deep link selects the application');
  ok(asked.some((q) => q.app === 'svc:erp' && q.hours === '168'), 'report asked for the 7-day default');
  const kk = await page.$eval('#kk', (x) => x.innerText.replace(/\s+/g, ' '));
  ok(/Servers 1 \/ 2/i.test(kk) && /Changes 1 1 self-approved/i.test(kk) && /Servers without logs 1/i.test(kk), 'tiles: ' + kk);
  let t = await page.$eval('#body', (x) => x.innerText);
  ok(/SCHG-000002 was approved by its own author \(rasheed\)/.test(t), 'finding: self-approved change');
  ok(/Security log cleared \/ auditing changed on ERP-APP1 by administrator/.test(t), 'finding: cleared security log');
  ok(/ERP-APP2: no log received in the period/.test(t), 'finding: no logs');
  ok(/ERP: running without redundancy now/.test(t), 'finding: redundancy');
  await page.click('[data-tab="servers"]'); t = await page.$eval('#body', (x) => x.innerText);
  ok(/ERP-APP2/.test(t) && /97%/.test(t) && /none/.test(t) && /offline/.test(t), 'servers tab with availability and logs');
  await page.click('[data-tab="changes"]'); t = await page.$eval('#body', (x) => x.innerText);
  ok(/SCHG-000002/.test(t) && /own change/.test(t), 'changes tab marks the self-approved change');
  await page.click('[data-tab="security"]'); t = await page.$eval('#body', (x) => x.innerText);
  ok(/1102/.test(t) && /The audit log was cleared/.test(t), 'security tab');
  const [dl] = await Promise.all([page.waitForEvent('download'), page.click('#xlsx')]);
  const buf = fs.readFileSync(await dl.path()), txt = buf.toString('latin1');
  ok(buf.slice(0, 2).toString() === 'PK' && /^application-audit-ERP-\d{4}-\d\d-\d\d\.xlsx$/.test(dl.suggestedFilename()), 'xlsx: ' + dl.suggestedFilename());
  for (const sh of ['Summary', 'Findings', 'Servers', 'Outages', 'Changes', 'Failed logons', 'Account changes', 'Audit-policy events', 'High-severity events']) ok(txt.includes('name="' + sh + '"'), 'sheet ' + sh);
  ok(asked.some((q) => q.export === '1'), 'export requested as an export (audited)');
  ROLE = 'viewer'; await page.goto(base + 'app-audit.html'); await page.waitForSelector('#body .err');
  ok(/Analysts, operators and administrators only/.test(await page.$eval('#body', (x) => x.innerText)), 'viewer refused');
  ok(!errs.length, 'page errors: ' + errs.join(' | '));
  await browser.close(); srv.close();
  console.log(bad ? 'FAILED ' + bad + ' of ' + n : 'OK ' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
