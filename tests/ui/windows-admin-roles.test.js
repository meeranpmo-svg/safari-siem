// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// AI Windows Server Administrator (windows-admin.html + vendor/zyb-sysadmin.js) over a STUBBED /api/soc/sysadmin with SYNTHETIC servers:
// the Domain controllers and Hyper-V hosts tiles, the domain controllers the Windows agent reports (posture as figures, the PDC
// marked, an old krbtgt password and many domain admins flagged), a tile opens the servers of that kind, the Kind column and filter,
// a hostile server name stays text. Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node windows-admin-roles.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const NOW = new Date().toISOString();
const srv = (id, name, kinds) => ({ id, name, ip: '10.9.1.' + (10 + id.length), site: 'HQ', roles: ['windows'], kinds, winrm: { ssl: false, port: 5985 }, logins: { windows: 'windows: svc.syn' }, findings: 0, worst: null, last_check: NOW, source: 'manual' });
const SV = [srv('dc01', 'DC-SYN-01', ['dc']), srv('dc02', 'DC-SYN-02', ['dc']), srv('hv01', 'HV-SYN-01', ['hyperv']), srv('fs01', '<img src=x onerror=window.PWN=1>', [])];
const OV = { role: 'windows', servers: 4, with_login: 4, checked: 4, from_itam: 0, findings: [], by_severity: { high: 1 }, health: { interval_min: 15, last_run: Date.now() }, helper: { available: true }, ai: { enabled: true }, changes_pending: 0,
  kinds: { dc: 2, hyperv: 1, member: 1 },
  agent_dcs: [{ host: 'dc-syn-01', ip: '10.9.1.10', at: NOW, primary: true, domain: 'corp.syn.test', domain_mode: 'Windows2016Domain', forest_mode: 'Windows2016Forest', krbtgt_age_days: 1500, recycle_bin: false, domain_admins: 9, pwd_min_length: 8, lockout_threshold: 0 },
    { host: 'dc-syn-02', ip: '10.9.1.12', at: NOW, primary: false, domain: 'corp.syn.test', domain_mode: 'Windows2016Domain', forest_mode: 'Windows2016Forest', krbtgt_age_days: 1500, recycle_bin: false, domain_admins: 9, pwd_min_length: 8, lockout_threshold: 0 }] };
(async () => {
  const server = http.createServer((req, res) => { const u = new URL(req.url, 'http://x'), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, { user: 'nora.syn', role: 'operator' });
    if (u.pathname === '/api/soc/sysadmin/overview') return json(200, OV);
    if (u.pathname === '/api/soc/sysadmin/targets') return json(200, { items: SV });
    if (u.pathname.startsWith('/api/')) return json(200, {});
    fs.readFile(path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')), (err, d) => { if (err) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); }); });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch(), errs = [];
  try {
    const p = await browser.newPage({ viewport: { width: 1440, height: 1000 } }); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto('http://127.0.0.1:' + server.address().port + '/dashboards/windows-admin.html?standalone=1'); await p.waitForSelector('#kpis .kf[data-kind="dc"]', { timeout: 15000 });
    ok(/Domain controllers\s*2/.test(await p.textContent('#kpis .kf[data-kind="dc"]')) && /Hyper-V hosts\s*1/.test(await p.textContent('#kpis .kf[data-kind="hyperv"]')), 'domain controller and Hyper-V tiles');
    const dc = await p.textContent('#dcs');
    ok(/dc-syn-01/.test(dc) && /PDC/.test(dc) && /1500 days/.test(dc) && /corp\.syn\.test/.test(dc) && /never/.test(dc), 'the domain controllers the agent reports, with their posture');
    ok(await p.$eval('#dcs tbody tr', (r) => !!r.querySelector('.pill.warn')), 'an old krbtgt password / many domain admins flagged');
    await p.click('#kpis .kf[data-kind="dc"]'); await p.waitForSelector('#servers table');
    const names = await p.$$eval('#servers tbody tr', (L) => L.map((r) => r.cells[0].textContent.trim()));
    ok(JSON.stringify(names) === '["DC-SYN-01","DC-SYN-02"]' && (await p.$eval('#kindsel', (s) => s.value)) === 'dc', 'a tile opens the servers of that kind: ' + names.join(','));
    await p.selectOption('#kindsel', ''); const all = await p.$$eval('#servers tbody tr', (L) => L.length); ok(all === 4, 'every server');
    ok(/Hyper-V/.test(await p.textContent('#servers tbody tr:nth-child(3)')) && /member/.test(await p.textContent('#servers')), 'the Kind column');
    await p.selectOption('#kindsel', 'member'); ok((await p.$$('#servers tbody tr')).length === 1, 'member servers only');
    ok(!(await p.evaluate(() => window.PWN)), 'hostile text stays text');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); server.close(); }
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
