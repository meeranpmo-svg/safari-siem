// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Front-end wiring audit: the real IT Asset Management engine (every add-on registered, as the installers do on the
// server) and the real SIEM engine (fake ClickHouse, listeners off) behind an nginx-like proxy; every dashboard page is
// opened in Chromium and every request it makes is recorded with its status. Output: report.json next to this file.
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const { spawn } = require('node:child_process');

// paths: this folder is shield/tools/frontend-audit; the SIEM checkout sits next to shield unless SENTRA_SIEM_DIR says otherwise
const ITAM = path.resolve(__dirname, '../../backend/itam'), DASH = path.resolve(__dirname, '../../ui');
const SIEM = process.env.SENTRA_SIEM_DIR || path.resolve(__dirname, '../../backend/siem');
const OUT = process.env.OUT_DIR || __dirname;
const SECRET = 'synthetic-proxy-secret-0123456789';
const SIEM_PORT = 19120;
const ITAM_SECRET = require(path.join(ITAM, 'tests/helpers.js')).SECRET;

async function startSiem() {
  const { startFakeCH } = require(path.join(SIEM, 'tests/helpers/fake-ch.js'));
  const ch = await startFakeCH();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wire-siem-'));
  const cfg = {
    data_dir: dir, state_dir: path.join(dir, 'state'), spool_dir: path.join(dir, 'spool'), log_level: 'error',
    api: { host: '127.0.0.1', port: SIEM_PORT },
    syslog: { udp: { enabled: false, port: 0 }, tcp: { enabled: false, port: 0 }, tls: { enabled: false } },
    clickhouse: { url: ch.url || ('http://127.0.0.1:' + ch.port), database: 'siem', user: 'x' },
  };
  fs.writeFileSync(path.join(dir, 'config.json'), JSON.stringify(cfg));
  fs.writeFileSync(path.join(dir, 'secrets.json'), JSON.stringify({ proxy_secret: SECRET }), { mode: 0o600 });
  const p = spawn(process.execPath, ['-e', `require(${JSON.stringify(path.join(SIEM, 'engine/main.js'))}).main().catch((e)=>{console.error(e);process.exit(1)})`],
    { env: Object.assign({}, process.env, { SENTRA_SIEM_CONFIG: path.join(dir, 'config.json'), SENTRA_SIEM_SECRETS: path.join(dir, 'secrets.json'), SENTRA_SIEM_DATA: dir }), stdio: ['ignore', 'pipe', 'pipe'] });
  let log = ''; p.stdout.on('data', (d) => { log += d; }); p.stderr.on('data', (d) => { log += d; });
  for (let i = 0; i < 100; i++) {
    const ok = await new Promise((r) => { const q = http.get({ host: '127.0.0.1', port: SIEM_PORT, path: '/api/soc/health' }, (res) => { res.resume(); r(res.statusCode < 500); }); q.on('error', () => r(false)); });
    if (ok) return { proc: p, ch, log: () => log };
    await new Promise((r) => setTimeout(r, 200));
  }
  throw new Error('SIEM did not start:\n' + log.slice(-3000));
}

async function startItam() {
  const { startApp } = require(path.join(ITAM, 'tests/helpers.js'));
  const e = await startApp({ noAi: true, config: { discovery: { python_bin: 'python3' } } });
  const lines = fs.readdirSync(path.join(ITAM, 'install')).filter((f) => /^add-.*\.sh$/.test(f)).map((f) => fs.readFileSync(path.join(ITAM, 'install', f), 'utf8'))
    .map((t) => (/^LINE="\s*require\('\.\/([^']+)'\)\.(register[A-Za-z]+)\(/m.exec(t) || [])).filter((m) => m[1]);
  const registered = [], failed = [], skipped = [];
  const mainSrc = fs.readFileSync(path.join(ITAM, 'engine/main.js'), 'utf8');
  for (const [, mod, fn] of lines) {
    if (mainSrc.includes('.' + fn + '(')) { skipped.push(fn); continue; }
    try { require(path.join(ITAM, 'engine', mod))[fn](e.app.srv, e.app); registered.push(fn); } catch (err) { failed.push(fn + ': ' + err.message); }
  }
  return { e, registered, failed, skipped };
}

function startProxy(itamPort) {
  const seen = [];
  const srv = http.createServer((req, res) => {
    const u = req.url.split('?')[0];
    let port = null;
    if (u.startsWith('/api/itam/')) port = itamPort; else if (u.startsWith('/api/soc')) port = SIEM_PORT;
    if (port) {
      const h = Object.assign({}, req.headers, { 'x-sentra-proxy-secret': port === SIEM_PORT ? SECRET : ITAM_SECRET, 'x-auth-user': 'syed', 'x-auth-role': 'admin' });
      const up = http.request({ host: '127.0.0.1', port, method: req.method, path: req.url, headers: h }, (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); });
      up.on('error', () => { res.writeHead(502); res.end(); });
      req.pipe(up); return;
    }
    if (u.startsWith('/api/') || u.startsWith('/auth/')) { seen.push(u); res.writeHead(599, { 'Content-Type': 'application/json' }); res.end('{"error":"not served by the engines in this audit"}'); return; }
    let f = path.join(DASH, decodeURIComponent(u === '/' ? '/index.html' : u));
    if (!f.startsWith(DASH)) { res.writeHead(403); res.end(); return; }
    if (!fs.existsSync(f) && fs.existsSync(f + '.html')) f += '.html';
    fs.readFile(f, (err, data) => {
      if (err) { res.writeHead(404); res.end('missing ' + u); return; }
      const ext = path.extname(f);
      res.writeHead(200, { 'Content-Type': { '.html': 'text/html', '.js': 'application/javascript', '.css': 'text/css', '.json': 'application/json', '.svg': 'image/svg+xml' }[ext] || 'application/octet-stream' });
      res.end(data);
    });
  });
  return new Promise((r) => srv.listen(0, '127.0.0.1', () => r({ srv, port: srv.address().port, seen })));
}

(async () => {
  const siem = await startSiem();
  const itam = await startItam();
  const proxy = await startProxy(itam.e.port);
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch({ executablePath: process.env.CHROME || undefined });
  const pages = fs.readdirSync(DASH).filter((f) => f.endsWith('.html')).sort().filter((f) => !process.env.ONLY || process.env.ONLY.split(',').includes(f));
  const report = { itam: { registered: itam.registered, failed: itam.failed, already_in_main: itam.skipped }, pages: {} };
  for (const name of pages) {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    const reqs = [], errors = [];
    page.on('response', (r) => { const u = new URL(r.url()); if (u.port === String(proxy.port) && (u.pathname.startsWith('/api/') || u.pathname.startsWith('/auth/'))) reqs.push({ m: r.request().method(), p: u.pathname + (u.search || ''), s: r.status() }); });
    page.on('requestfailed', (r) => { const u = new URL(r.url()); if (u.port === String(proxy.port)) reqs.push({ m: r.method(), p: u.pathname, s: 'failed' }); });
    page.on('pageerror', (e) => errors.push('pageerror: ' + String(e.message).slice(0, 300)));
    page.on('console', (m) => { if (m.type() === 'error') errors.push('console: ' + m.text().slice(0, 300)); });
    try {
      await page.goto(`http://127.0.0.1:${proxy.port}/${name}`, { waitUntil: 'load', timeout: 20000 });
      await page.waitForTimeout(3500);
    } catch (e) { errors.push('load: ' + e.message.slice(0, 200)); }
    let text = '';
    try { text = await page.evaluate(() => document.body ? document.body.innerText : ''); } catch (e) { /* closed */ }
    const flags = (text.match(/[^\n]*(not installed|not connected|not set up|isn't installed|could not load|failed to load|HTTP 404|error 404)[^\n]*/gi) || []).slice(0, 8).map((x) => x.slice(0, 200));
    report.pages[name] = { requests: reqs, errors: errors.slice(0, 20), flags };
    await ctx.close();
    process.stdout.write('.');
  }
  await browser.close();
  fs.writeFileSync(path.join(OUT, 'report.json'), JSON.stringify(report, null, 1));
  console.log('\nwritten', Object.keys(report.pages).length, 'pages; itam add-ons registered', itam.registered.length, 'failed', itam.failed.length);
  fs.writeFileSync(path.join(OUT, 'siem.log'), siem.log());
  siem.proc.kill(); await itam.e.close(); proxy.srv.close(); try { siem.ch.close && siem.ch.close(); } catch (e) { /* */ }
  process.exit(0);
})().catch((e) => { console.error(e); process.exit(1); });
