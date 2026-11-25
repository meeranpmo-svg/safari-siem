// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// AI Engineering Team page with the organisation's own engineers: the FortiGate, Network Access, NDR, Mimecast, Voice, Hyper-V and
// Aramco CCC engineers from both engines are shown, each linked to its own page, with what is missing. Stub engines; SYNTHETIC.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node ai-team-estate.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const E = (id, name, engine, st) => ({ id, name, engine, status: st, checks: [{ name: 'Connected', ok: st !== 'blocked', detail: st === 'blocked' ? 'not set up' : 'ok', fix: st === 'blocked' ? 'Integration Hub' : '' }], to_fix: st === 'blocked' ? [{ name: 'Connected', fix: 'Integration Hub' }] : [] });
const SOC = { generated: Date.now(), engineers: [E('fortigate', 'AI Firewall Engineer (FortiGate)', 'siem', 'ready'), E('nac', 'AI Network Access Engineer', 'siem', 'partial'), E('ndr', 'AI NDR Analyst', 'siem', 'ready'), E('mimecast', 'AI Email Security Engineer (Mimecast)', 'siem', 'blocked')], ready: 2, of: 4 };
const ITAM = { generated: Date.now(), engineers: [E('voice', 'AI Voice Engineer (Cisco CUCM)', 'itam', 'ready'), E('hyperv', 'AI Hyper-V Administrator', 'itam', 'blocked'), E('aramco', 'AI Aramco CCC Officer', 'itam', 'partial')], ready: 1, of: 3 };
(async () => {
  const srv = http.createServer((req, res) => {
    const u = req.url.split('?')[0]; const json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u === '/dashboards/whoami.json') return json(200, { user: 'admin.syn', role: 'admin' });
    if (u === '/api/soc/duty/readiness') return json(200, SOC);
    if (u === '/api/itam/duty/readiness') return json(200, ITAM);
    if (/\/duty\/intel$/.test(u)) return json(200, { sections: [], items: 0 });
    if (/\/duty\/(engineers|items|kpis|reports|policy)$/.test(u)) return json(200, { engineers: [], items: [], kpis: {}, reports: [], policy: {} });
    if (u.startsWith('/api/')) return json(404, { error: 'not in this test' });
    fs.readFile(path.join(DASH, u.replace(/^\/dashboards\//, '/')), (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.endsWith('.js') ? 'application/javascript' : u.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(); const p = await browser.newPage({ viewport: { width: 1400, height: 900 } }); const errs = [];
  p.on('pageerror', (x) => errs.push(x.message));
  await p.goto('http://127.0.0.1:' + srv.address().port + '/ai-team.html?standalone=1#view=home&sub=status');
  await p.waitForFunction(() => /AI Firewall Engineer/.test(document.body.innerText), null, { timeout: 15000 });
  const txt = await p.evaluate(() => document.body.innerText);
  for (const nm of ['AI Firewall Engineer (FortiGate)', 'AI Network Access Engineer', 'AI NDR Analyst', 'AI Email Security Engineer (Mimecast)', 'AI Voice Engineer (Cisco CUCM)', 'AI Hyper-V Administrator', 'AI Aramco CCC Officer']) ok(txt.includes(nm), nm + ' shown');
  const links = await p.$$eval('a[href]', (a) => a.map((x) => x.getAttribute('href')));
  for (const h of ['fortigate-fleet.html', 'fortigate-nac.html', 'ndr.html', 'mimecast-actions.html', 'cucm.html', 'hyperv.html', 'aramco-ccc.html']) ok(links.some((l) => l.indexOf(h) === 0), 'link to ' + h);
  ok(/Integration Hub/.test(txt), 'what is missing is said');
  ok(!errs.length, 'errors: ' + errs.join(' | '));
  await browser.close(); srv.close();
  console.log(bad ? `${bad}/${n} FAILED` : `OK ${n}/${n} checks`); process.exit(bad ? 1 : 0);
})();
