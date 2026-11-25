// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Connections & Setup: the CrowdStrike Falcon card lists Falcon log sources (the connector host that sends CEF syslog),
// receiving vs waiting, no password; Add registers the connector host through POST /onboard/sources and shows the
// connector settings (never asking for the Falcon secret). The Hyper-V card lists the hosts that reported, stale after
// two days, opens a set-up guide with the read-only PowerShell for THIS portal, and an admin can forget a host. With the
// organisation's real brand setting, cards whose page the sector switches off (Kaspersky, Zscaler, Oracle) are not offered.
// Stub APIs; names and addresses are SYNTHETIC. Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node connections-edr-hyperv.test.js
const http = require('http'), fs = require('fs'), os = require('os'), path = require('path'), { execFileSync } = require('child_process');
const ROOT = path.resolve(__dirname, '../..'), DASH = path.join(ROOT, 'ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const D = 86400000;
let SRC = [{ id: 'cs-falcon', kind: 'crowdstrike-falcon', type: 'cef', label: 'Falcon (synthetic)', match_ip: '10.0.0.61', state: 'receiving', last_seen: Date.now() - 60000, events_24h: 17, created_at: '2026-11-01T00:00:00Z' },
  { id: 'fw-1', kind: 'fortigate', type: 'fortigate', label: 'FW', state: 'receiving' }];
let HV = [{ id: 'hv-syn-01', host: 'HV-SYN-01', ip: '10.0.0.71', site: 'HQ', vms: 12, via: 'agent', at: new Date(Date.now() - 3600000).toISOString() },
  { id: 'hv-syn-02', host: 'HV-SYN-02', ip: '10.0.0.72', site: 'Remote', vms: 4, via: 'import', by: 'admin.syn', at: new Date(Date.now() - 5 * D).toISOString() }];
let posted = null, forgot = null, ORGJS = null;
(async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'hub-')), REAL = path.join(tmp, 'zyb-org.js');
  execFileSync(process.execPath, [path.join(ROOT, 'tools/brand/apply-brand.js'), '--ui-out', REAL]);
  const srv = http.createServer((req, res) => {
    const u = req.url.split('?')[0]; const json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    const body = (fn) => { let b = ''; req.on('data', (d) => { b += d; }); req.on('end', () => fn(b ? JSON.parse(b) : {})); };
    if (u === '/dashboards/whoami.json') return json(200, { user: 'admin.syn', role: 'admin' });
    if (u === '/api/soc/onboard/sources' && req.method === 'GET') return json(200, { sources: SRC });
    if (u === '/api/soc/onboard/sources' && req.method === 'POST') return body((b) => { posted = b; SRC.push(Object.assign({ state: 'waiting', created_at: new Date().toISOString() }, b)); json(200, { source: b, siem: { ip: '10.0.0.5', syslog_port: 5514 } }); });
    if (u === '/api/itam/discovery/hyperv/hosts') return json(200, { hosts: HV, scopes: [{ id: 'sc1', name: 'Servers (synthetic)', site: 'HQ', targets: ['10.0.0.0/24'] }] });
    const m = /^\/api\/itam\/discovery\/hyperv\/hosts\/([^/]+)\/forget$/.exec(u);
    if (m && req.method === 'POST') return body(() => { forgot = decodeURIComponent(m[1]); HV = HV.filter((h) => h.id !== forgot); json(200, { ok: true }); });
    if (u.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const rel = u.replace(/^\/dashboards\//, '/'), f = rel === '/vendor/zyb-org.js' && ORGJS ? ORGJS : path.join(DASH, rel);
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.endsWith('.js') ? 'application/javascript' : u.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/connections.html?standalone=1';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(); const page = await browser.newPage({ viewport: { width: 1400, height: 900 } }); const errs = [];
  page.on('pageerror', (x) => errs.push(x.message));
  let alertText = ''; page.on('dialog', (d) => { alertText = d.message(); d.accept(); });
  await page.goto(base);
  // ---- CrowdStrike Falcon
  await page.waitForSelector('#cn-edr table');
  let t = await page.$eval('#cn-edr', (x) => x.innerText.replace(/\s+/g, ' '));
  ok(/CrowdStrike Falcon/.test(t) && /Falcon \(synthetic\)/.test(t) && /connector host 10\.0\.0\.61/.test(t) && /17 events/.test(t) && !/FW/.test(t), 'Falcon source listed, nothing else: ' + t.slice(0, 260));
  await page.click('#cn-edr [data-act=add]'); await page.waitForSelector('#mf');
  const form = await page.$eval('#mf', (x) => ({ text: x.innerText, names: [...x.querySelectorAll('input,select,textarea')].map((i) => i.name) }));
  ok(/Event streams: Read/.test(form.text) && !form.names.some((x) => /secret|password|key/i.test(x)), 'the form explains the API client and never asks for the Falcon secret: ' + form.names.join(','));
  await page.fill('#mf input[name=id]', 'hq'); await page.fill('#mf input[name=match_ip]', '10.0.0.62');
  await page.click('#msave'); await page.waitForTimeout(800);
  ok(posted && posted.kind === 'crowdstrike-falcon' && posted.id === 'cs-hq' && posted.match_ip === '10.0.0.62', 'registered with the cs- prefix and the Falcon parser: ' + JSON.stringify(posted));
  ok(/output_format = cef/.test(alertText) && /host = 10\.0\.0\.5/.test(alertText) && /port = 5514/.test(alertText) && /protocol = tcp/.test(alertText), 'the connector settings are shown: ' + alertText.slice(0, 200));
  await page.waitForFunction(() => /waiting for the first event/.test(document.querySelector('#cn-edr').innerText)); ok(true, 'the new source reads waiting');
  // ---- Hyper-V
  t = await page.$eval('#cn-hyperv', (x) => x.innerText.replace(/\s+/g, ' '));
  ok(/HV-SYN-01/.test(t) && /12 VMs/.test(t) && /reported by the host/.test(t) && /HV-SYN-02/.test(t) && /imported by admin\.syn/.test(t), 'reporting hosts listed: ' + t.slice(0, 300));
  ok(/last report .* ago/.test(t) || /stale/i.test(t), 'a host silent for days is flagged');
  await page.click('#cn-hyperv [data-act=add]'); await page.waitForSelector('#hv-ps');
  const g = await page.evaluate(() => ({ ps: document.getElementById('hv-ps').textContent, body: document.querySelector('#modal').innerText }));
  ok(/Get-VM/.test(g.ps) && g.ps.includes('https://' + new URL(base).host + '/itam-agent/hyperv') && /Servers \(synthetic\)/.test(g.body), 'the guide carries the read-only script for this portal and the scopes that accept reports');
  ok(!/Set-VM|Stop-VM|Remove-VM|New-VM/.test(g.ps), 'the script only reads');
  await page.click('#modal [data-close]'); await page.waitForTimeout(200);
  const del = await page.$('#cn-hyperv [data-act=del][data-id="hv-syn-02"]');
  ok(!!del, 'an admin can forget a host'); if (del) { await del.click(); await page.waitForTimeout(800); }
  ok(forgot === 'hv-syn-02', 'forget called for that host: ' + forgot);
  // ---- the organisation's real brand setting: cards for switched-off pages are not offered
  ORGJS = REAL; await page.goto(base); await page.waitForSelector('#cn-edr');
  const ids = await page.$$eval('[id^=cn-]', (x) => x.map((e) => e.id));
  const off = JSON.parse(fs.readFileSync(path.join(ROOT, 'brand/brand.json'), 'utf8')).pages_off;
  ok(off.includes('ai-ksc-engineer') ? !ids.includes('cn-ksc') : true, 'Kaspersky card hidden when its page is off');
  ok(off.includes('ai-zscaler-engineer') ? !ids.includes('cn-zscaler') : true, 'Zscaler card hidden when its page is off');
  ok(ids.includes('cn-edr') && ids.includes('cn-hyperv'), 'CrowdStrike and Hyper-V offered: ' + ids.join(','));
  ok(!errs.length, 'errors: ' + errs.join(' | '));
  await browser.close(); srv.close(); fs.rmSync(tmp, { recursive: true, force: true });
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
