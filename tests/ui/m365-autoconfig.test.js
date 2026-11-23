// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// m365-autoconfig.html against the REAL SIEM module (sentra-siem engine/collect/m365-autoconfig.js + m365-security.js) with a SYNTHETIC
// Graph snapshot and a scripted model: the four steps, each permission granted / not from the token, the admin-consent link (only
// Microsoft addresses), the grant script for the missing permissions (admin) with download, the baseline checks with their fixes;
// a template is refused until a break-glass account is recorded, then shown report-only with the account excluded and downloadable;
// the AI plan with an unverified step marked; an analyst sees no admin actions, a viewer is refused; a hostile policy name stays
// text; phone width; the menu entry, installer and the old portal's "MS Security Auto-Config" redirect.
// Run: SENTRA_SIEM_DIR=/home/user/sentra-siem PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node m365-autoconfig.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const SIEM = process.env.SENTRA_SIEM_DIR || path.resolve(__dirname, '../../backend/siem');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror="window.__xss=1">';
const { createState } = require(path.join(SIEM, 'engine/soc/state'));
const { PERMS } = require(path.join(SIEM, 'engine/collect/m365-graph'));
const { fakeApi, tmpDir, quietLog } = require(path.join(SIEM, 'tests/soc-fakes'));
const TEN = '11111111-2222-3333-4444-555555555555', CID = '66666666-7777-8888-9999-000000000000', BG = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee', NOW = Date.now(), D = 864e5;
const use = (id, name, input) => ({ type: 'tool_use', id, name, input }), turn = (content) => ({ content, stop_reason: 'tool_use', usage: { input_tokens: 40, output_tokens: 10 } });
(async () => {
  const dir = tmpDir(), state = createState({ dir, log: quietLog }), script = [];
  const snap = { configured: true, updated: new Date(NOW).toISOString(), signins: [], blocks: { secureScore: { ok: true }, mfa: { ok: true }, conditionalAccess: { ok: true }, riskyUsers: { ok: false, perm: 'IdentityRiskyUser.Read.All', error: 'permission not granted' } },
    security: { secureScore: { ok: true, data: { current: 38, max: 100, lowest: [] } }, mfa: { ok: true, data: { users: 40, registered: 30, notRegistered: [{ name: 'Admin Syn', upn: 'admin.syn@as.test', admin: true }] } },
      conditionalAccess: { ok: true, data: [{ name: 'Require MFA for administrators ' + XSS, state: 'enabled', modified: new Date(NOW - 90 * D).toISOString() }] }, riskyUsers: { ok: false } } };
  const roles = Object.values(PERMS).join(' + ').split(' + ').filter((p) => p !== 'IdentityRiskyUser.Read.All' && p !== 'IdentityRiskEvent.Read.All');
  const graph = { status: () => ({ enabled: true, ready: true, blocks: snap.blocks, granted: { roles, at: NOW } }), data: () => snap, PERMS, syncNow: async () => snap };
  const config = { m365: {}, soc_analyst: {}, ai_limits: { per_user_hour: 100, per_user_day: 1000, daily_tokens: 1e9, max_prompt_chars: 1e6 } };
  Object.defineProperty(config, 'secrets', { value: { m365: { tenant: TEN, client_id: CID, client_secret: 'very-secret-synthetic' }, netops: { anthropic_api_key: 'sk-ant-synthetic-for-tests' } } });
  class FakeAnthropic { constructor() { this.messages = { create: async () => { const r = script.shift(); if (!r) throw new Error('script ended'); return r; } }; } }
  const api = fakeApi({ realRanks: true }), deps = { state, m365Graph: graph, config, log: quietLog, sdk: FakeAnthropic };
  require(path.join(SIEM, 'engine/collect/m365-autoconfig')).register(api, deps);
  api.route('POST', '/api/soc/m365/sync', async () => ({ ok: true }));   // the existing sync route, stubbed: nothing to sync against
  let WHO = { user: 'syed', role: 'admin' };
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, WHO);
    if (u.pathname.startsWith('/api/soc/')) { let b = ''; req.on('data', (c) => { b += c; }); req.on('end', async () => { const r = await api.call(req.method, u.pathname + u.search, { role: WHO.role, user: WHO.user, body: b ? JSON.parse(b) : undefined }); json(r.status, r.body); }); return; }
    if (u.pathname.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': u.pathname.endsWith('.js') ? 'application/javascript' : u.pathname.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const url = 'http://127.0.0.1:' + srv.address().port + '/dashboards/m365-autoconfig.html';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const wait = (p, fn, arg) => p.waitForFunction(fn, arg, { timeout: 20000 }).then(() => true, () => false);
  try {
    const p = await browser.newPage({ viewport: { width: 1500, height: 1000 }, acceptDownloads: true }); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto(url); ok(await wait(p, () => !document.getElementById('main').hidden && document.querySelectorAll('#steps .step').length === 4), 'four steps');
    ok(/Graph permissions granted.*partly/i.test(await p.textContent('#steps')) && /2 missing: IdentityRiskyUser\.Read\.All, IdentityRiskEvent\.Read\.All/.test(await p.textContent('#steps')), 'the missing permissions named');
    ok(/read from the sign-in token/.test(await p.textContent('#psrc')), 'exact, from the token');
    const href = await p.$eval('#pact a', (a) => a.href); ok(href === 'https://login.microsoftonline.com/' + TEN + '/adminconsent?client_id=' + CID, 'the admin-consent link');
    ok(!/very-secret/.test(await p.content()), 'the secret is never on the page');
    await p.click('#getscr'); ok(await wait(p, () => /AppRoleAssignment/.test((document.getElementById('scrtxt') || {}).textContent || '')), 'the grant script');
    ok(/'IdentityRiskyUser\.Read\.All', 'IdentityRiskEvent\.Read\.All'/.test(await p.textContent('#scrtxt')) && !/'User\.Read\.All'/.test(await p.textContent('#scrtxt')), 'only the missing permissions');
    const [d1] = await Promise.all([p.waitForEvent('download', { timeout: 10000 }), p.click('#dlscr')]); ok(d1.suggestedFilename() === 'grant-missing-graph-permissions.ps1', 'script download');
    const hard = await p.textContent('#hard');
    ok(/Every administrator registered for MFA\s*failed/.test(hard) && /Block legacy authentication\s*failed/.test(hard), 'baseline checks with their state');
    ok(!(await p.evaluate(() => window.__xss)) && /<img src=x/.test(hard), 'a hostile policy name stays text');
    ok(await p.$$eval('#hard a', (L) => L.length > 0 && L.every((a) => /^https:\/\/(entra|security)\.microsoft\.com\//.test(a.href) && a.rel.includes('noopener'))), 'fix links go only to Microsoft');
    await p.click('[data-tpl="legacy"]'); ok(await wait(p, () => /break-glass/.test(document.body.textContent) && document.querySelector('.toast')), 'a template is refused until a break-glass account is recorded');
    await p.fill('[data-bgid]', 'not-a-guid'); await p.fill('[data-bglabel]', 'Emergency 1 (synthetic)'); await p.click('#bgsave');
    ok(await wait(p, () => /object ID/.test([...document.querySelectorAll('.toast')].map((t) => t.textContent).join(' '))), 'validation names the field');
    await p.fill('[data-bgid]', BG); await p.click('#bgsave'); ok(await wait(p, (bg) => document.getElementById('bg').textContent.includes(bg), BG), 'break-glass account recorded');
    ok(api.audits.some((a) => a.action === 'm365.autoconfig.breakglass'), 'audited');
    await p.click('[data-tpl="legacy"]'); ok(await wait(p, () => /enabledForReportingButNotEnforced/.test(document.getElementById('tpl').textContent)), 'the template is report-only');
    ok((await p.textContent('#tpl')).includes(BG) && /New-MgIdentityConditionalAccessPolicy/.test(await p.textContent('#tpl')), 'it excludes the break-glass account and says how to import it');
    const [d2] = await Promise.all([p.waitForEvent('download', { timeout: 10000 }), p.click('#dltpl')]); ok(d2.suggestedFilename() === 'legacy.json', 'template download');
    // AI plan
    script.push(turn([use('a', 'readiness', {}), use('b', 'hardening', {})]), turn([use('c', 'submit_plan', { summary: 'Close the legacy gap ' + XSS, steps: [{ title: 'Block legacy authentication', why: 'no policy', how: 'Import legacy.json report-only', ref: 'ca-legacy' }, { title: 'Invented', why: 'x', how: 'x', ref: 'made-up' }] })]));
    await p.fill('#focus', 'legacy'); await p.click('#plan');
    ok(await wait(p, () => /Close the legacy gap/.test(document.getElementById('ai').textContent)), 'the AI plan appears');
    ok(/from the checks/.test(await p.textContent('#ai')) && /unverified - no check returned made-up/.test(await p.textContent('#ai')), 'an unverified step is marked');
    ok(!(await p.evaluate(() => window.__xss)) && !(await p.$('#ai a')), 'model text stays text, no links');
    // analyst / viewer
    WHO = { user: 'ana.syn', role: 'analyst' }; await p.goto(url); await wait(p, () => !document.getElementById('main').hidden);
    ok(!(await p.$('#getscr')) && !(await p.$('[data-tpl]')) && !(await p.$('#bgsave')) && !(await p.$('#plan')), 'an analyst sees no admin or operator actions');
    WHO = { user: 'vera.syn', role: 'viewer' }; await p.goto(url); ok(await wait(p, () => /for analysts and above/.test(document.getElementById('err').textContent)), 'a viewer is refused with the reason');
    WHO = { user: 'syed', role: 'admin' };
    const ph = await browser.newPage({ viewport: { width: 390, height: 900 } }); await ph.goto(url); await wait(ph, () => !document.getElementById('main').hidden);
    ok(await ph.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1), 'phone width: no sideways scroll'); await ph.close();
    const nav = fs.readFileSync(path.join(DASH, 'vendor', 'zyb-nav.js'), 'utf8');
    ok(/"h": "m365-autoconfig.html"/.test(nav) && / m365-autoconfig\.html /.test(fs.readFileSync(path.join(DASH, 'install-dashboards.sh'), 'utf8')), 'menu entry and installer');
    ok(/msauto: 'm365-autoconfig\.html'/.test(fs.readFileSync(path.join(DASH, 'vendor', 'zyb-menu.js'), 'utf8')) && /msauto: 'm365-autoconfig\.html'/.test(fs.readFileSync(path.join(DASH, 'vendor', 'zyb-early.js'), 'utf8')), 'the old portal\'s "MS Security Auto-Config" opens this page');
    ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); fs.rmSync(dir, { recursive: true, force: true }); }
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n);
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
