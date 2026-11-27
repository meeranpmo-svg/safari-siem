// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Agents & Downloads (agents.html) with the packages really built (ui/build-agents.py) and stubbed APIs, SYNTHETIC data: every
// package with its size, SHA-256 and a download that serves the same bytes; the asset agent steps with the fingerprint and the
// install command for this portal; an administrator creates one-time keys (shown once) and a Windows SIEM source (token and
// commands shown once); operators see the connected agents with the silent ones; a viewer sees no key or source form; hostile
// names stay text; menu entry and installer.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node agents.test.js
const http = require('http'), fs = require('fs'), os = require('os'), path = require('path'), crypto = require('crypto');
const { execFileSync } = require('child_process');
const ROOT = path.resolve(__dirname, '../..'), DASH = path.join(ROOT, 'ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror=window.PWN=1>';
const STAGE = fs.mkdtempSync(path.join(os.tmpdir(), 'agents-ui-')); execFileSync('python3', [path.join(DASH, 'build-agents.py'), STAGE, ROOT]);
let WHO = { user: 'admin.syn', role: 'admin' }; const POSTS = [];
(async () => {
  const srv = http.createServer((q, r) => { const u = decodeURIComponent(q.url.split('?')[0]), j = (c, o) => { r.writeHead(c, { 'Content-Type': 'application/json' }); r.end(JSON.stringify(o)); };
    const body = (fn) => { let b = ''; q.on('data', (d) => { b += d; }); q.on('end', () => { const x = b ? JSON.parse(b) : {}; POSTS.push([u, x]); fn(x); }); };
    if (u.endsWith('whoami.json')) return j(200, WHO);
    if (u === '/api/itam/settings/agent-tokens') return body(() => j(200, { token: 'synthetic-' + crypto.randomBytes(6).toString('hex'), expires_at: '2026-11-28T10:00:00Z' }));
    if (u === '/api/soc/onboard/sources' && q.method === 'GET') return j(200, { sites: [{ id: 'hq', name: 'Riyadh HQ' }, { id: 'jubail', name: 'Jubail project' }] });
    if (u === '/api/soc/onboard/sources') return body((x) => j(200, { source: { id: x.id }, token: 'synthetic-ingest-token', instructions: [{ title: 'On the server', lang: 'en', body: '.\\install-agent.ps1 -CollectorUrl https://soc.example.test -SourceId ' + x.id }] }));
    if (u === '/api/itam/agents') return j(200, { agents: [{ name: 'SITE-PC-SYN-01', platform: 'windows', site: 'Jubail', enrolled_at: '2026-11-20T08:00:00Z', last_report_at: '2026-11-27T06:00:00Z', stale: false, status: 'active' }, { name: XSS, platform: 'windows', site: '', stale: true, status: 'active' }] });
    if (u.startsWith('/api/')) return j(404, { error: 'not in this test' });
    const rel = u.replace(/^\/dashboards\//, '/'), f = rel.startsWith('/agents/') ? path.join(STAGE, rel) : path.join(DASH, rel);
    fs.readFile(f, (e, d) => { if (e) { r.writeHead(404); return r.end(); } r.writeHead(200, { 'Content-Type': f.endsWith('.js') ? 'application/javascript' : f.endsWith('.json') ? 'application/json' : f.endsWith('.css') ? 'text/css' : f.endsWith('.html') ? 'text/html' : 'application/octet-stream' }); r.end(d); }); });
  await new Promise((res) => srv.listen(0, '127.0.0.1', res));
  const base = 'http://127.0.0.1:' + srv.address().port + '/dashboards/', url = base + 'agents.html?standalone=1';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch(), errs = [];
  const open = async () => { const p = await browser.newPage({ viewport: { width: 1400, height: 1000 }, acceptDownloads: true }); p.on('pageerror', (x) => errs.push(x.message)); await p.goto(url); await p.waitForSelector('#pk [data-dl], #pk .empty', { timeout: 15000 }); return p; };
  try {
    const M = JSON.parse(fs.readFileSync(path.join(STAGE, 'agents/manifest.json'), 'utf8'));
    let p = await open();
    const cards = await p.$$eval('#pk .card', (x) => x.map((c) => c.innerText));
    ok(cards.length === 5 && M.items.every((i) => cards.some((c) => c.includes(i.sha256) && c.includes(i.file))), 'every package with its SHA-256');
    const [dl] = await Promise.all([p.waitForEvent('download'), p.click('[data-dl="asset-windows"]')]);
    const got = fs.readFileSync(await dl.path()); ok(crypto.createHash('sha256').update(got).digest('hex') === M.items.find((i) => i.id === 'asset-windows').sha256, 'the download is the file the manifest describes');
    const a = await p.$eval('#asset', (x) => x.innerText);
    ok(a.includes(M.items.find((i) => i.id === 'asset-windows').sha256.toUpperCase()) && /Get-FileHash/.test(a) && /-Server https:\/\/[^ ]+\/agent -Install/.test(a), 'asset steps: fingerprint and the install command for this portal');
    await p.fill('#tf [name=site]', 'Jubail project site'); await p.fill('#tf [name=n]', '3'); await p.click('#tf button[type=submit]');
    await p.waitForSelector('#tout pre'); const keys = (await p.textContent('#tout pre')).trim().split('\n');
    ok(keys.length === 3 && keys.every((k) => /^synthetic-/.test(k)) && /not shown again/.test(await p.textContent('#tout')), 'three one-time keys shown once');
    ok(POSTS.filter((x) => x[0] === '/api/itam/settings/agent-tokens').every((x) => x[1].note === 'Asset agent: Jubail project site' && x[1].site === 'Jubail project site'), 'keys noted with the site');
    await p.fill('#sf [name=sid]', 'win-jubail-01'); await p.selectOption('#sf [name=site]', 'jubail'); await p.click('#sf button[type=submit]'); await p.waitForSelector('#sout pre');
    const so = await p.textContent('#sout'); ok(/synthetic-ingest-token/.test(so) && /install-agent\.ps1/.test(so) && /once/.test(so), 'Windows SIEM source: token and command shown once');
    ok(POSTS.some((x) => x[0] === '/api/soc/onboard/sources' && x[1].kind === 'windows' && x[1].id === 'win-jubail-01' && x[1].site === 'jubail'), 'the source is created as a Windows source on its site');
    await p.waitForSelector('#ag table'); const ag = await p.textContent('#ag');
    ok(/SITE-PC-SYN-01/.test(ag) && /reporting/.test(ag) && /silent/.test(ag) && /2 agents · 1 silent/.test(await p.textContent('#agn')), 'connected agents with the silent one');
    ok(!(await p.evaluate(() => window.PWN)) && /<img src=x/.test(ag), 'a hostile name stays text');
    await p.close();
    WHO = { user: 'vera.syn', role: 'viewer' }; p = await open();
    ok(!(await p.$('#tf')) && !(await p.$('#sf')) && await p.$eval('#agc', (x) => x.hidden) && (await p.$$('[data-dl]')).length === 5, 'a viewer downloads but creates no key or source and does not list agents'); await p.close();
    const nav = fs.readFileSync(path.join(DASH, 'vendor/zyb-nav.js'), 'utf8'); ok(nav.includes('"h": "agents.html"') && / agents\.html /.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')), 'menu entry and installer');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); }
  console.log((bad ? 'FAILED ' : 'ok ') + (n - bad) + '/' + n + ' agents checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
