// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for the One-way Audio Troubleshooter (voice-troubleshoot.html) against the REAL SIEM netops routes
// (sentra-siem engine/netops/routes.js + voice.js + evidence.js) over a fake log database holding SYNTHETIC voice sessions: a
// phone picked by name from the asset register, the direction buttons, the ranked causes (SIP ALG with one-way audio) with
// fix and rollback as text, the phone / call manager checks, a change plan proposed by an operator, validation, the viewer
// refused, the menu entry, and a hostile value staying text.
// Run: SENTRA_SIEM_DIR=/home/user/sentra-siem PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node voice-troubleshoot.test.js
const http = require('http'), fs = require('fs'), os = require('os'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
const SIEM = process.env.SENTRA_SIEM_DIR || path.resolve(__dirname, '../../backend/siem');
const routes = require(path.join(SIEM, 'engine/netops/routes'));
const { createState } = require(path.join(SIEM, 'engine/soc/state'));
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const XSS = '<img src=x onerror=alert(1)>';
const A = '10.30.1.25', B = '10.0.20.40';
const FG = { id: 'fg-br', name: 'FG-BRANCH-SYN', vendor: 'fortigate', ip: '10.30.0.1' };

(async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'voice-ui-')), state = await createState({ dir: path.join(dir, 'state') });
  const config = { netops: { enabled: false } }; Object.defineProperty(config, 'secrets', { value: {}, enumerable: false, writable: true });
  const facts = { vendor: 'fortigate', at: Date.now(), settings: { default_voip_alg_mode: 'proxy-based' }, session_helper: [{ id: 13, name: 'sip', protocol: 17, port: 5060 }], services: [{ name: 'CISCO-RTP', udp: '16384-32767' }],
    policies: [{ id: 21, name: 'voice-out', status: 'enable', action: 'accept', srcintf: ['voice'], dstintf: ['to-DC'], service: ['CISCO-RTP'] }, { id: 22, name: 'voice-in', status: 'enable', action: 'accept', srcintf: ['to-DC'], dstintf: ['voice'], service: ['CISCO-RTP'] }] };
  const poller = { snapshot: (id) => (id === FG.id ? { security: { facts }, system: { cpu_pct: 20, mem_pct: 40 } } : null), snapshots: () => ({}), stats: () => ({}), forget() {}, start() {} };
  const queries = [];
  const ch = { query: async (sql, params) => {
    if (/a_signalling/.test(sql)) { queries.push(params); return [
      { vendor: 'fortigate', firewall: 'FG-BRANCH-SYN', firewall_ip: FG.ip, direction: 'a_to_b', kind: 'rtp', action: 'accept', sessions: 14, oneway: 11, nat_ip: '', peer: B, sample: `${A}:20480 → ${B}:24576 ${XSS}` },
      { vendor: 'fortigate', firewall: 'FG-BRANCH-SYN', firewall_ip: FG.ip, direction: 'a_signalling', kind: 'sip', action: 'accept', sessions: 6, oneway: 0, nat_ip: '', peer: '10.0.5.10', sample: `${A}:5060 → 10.0.5.10:5060` }]; }
    return [];
  } };
  const N = routes.createNetops({ state, config, log: { info() {}, warn() {}, error() {} }, poller, ch });
  N.inventory.put(Object.assign({ site: 'Branch', poll: {} }, FG), 'syed');
  const R = []; routes.register({ route: (m, p, h) => R.push({ m, re: new RegExp('^' + p.replace(/:(\w+)/g, '(?<$1>[^/]+)') + '$'), h }) }, { state, config, log: { error() {}, info() {} }, netops: N });
  const RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 }, audits = [];
  let WHO = { user: 'omar.syn', role: 'operator' };
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u.pathname === '/dashboards/whoami.json') return json(200, WHO);
    if (u.pathname === '/api/itam/assets') return json(200, { items: [{ id: 'PH-1', name: 'SEP-RECEPTION-SYN', ip: A, site: 'Branch', type: 'phone' }, { id: 'PH-2', name: 'no ip phone', type: 'phone' }] });
    if (u.pathname.startsWith('/api/soc/netops')) {
      let raw = ''; req.on('data', (d) => { raw += d; }); req.on('end', async () => {
        const r = R.find((x) => x.m === req.method && x.re.test(u.pathname)); if (!r) return json(404, { error: 'not found' });
        const out = {}, role = WHO.role, ctx = { role, user: WHO.user, body: raw ? JSON.parse(raw) : undefined, params: Object.assign({}, u.pathname.match(r.re).groups), query: Object.fromEntries(u.searchParams), path: u.pathname,
          need(x) { if (RANK[role] < RANK[x]) { out.status = 403; out.error = 'requires ' + x + ' role'; return false; } return true; }, audit: (a, t, d) => audits.push([a, t, d, WHO.user]), ok(b) { out.status = 200; out.body = b; }, fail(c, m) { out.status = c; out.error = m; } };
        try { const rv = await r.h(ctx); if (rv !== undefined && !out.status) { out.status = 200; out.body = rv; } } catch (e) { out.status = e.status || e.code || 500; out.error = e.message; }
        json(out.status || 500, out.status === 200 ? out.body : { error: out.error });
      }); return;
    }
    if (u.pathname.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u.pathname.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': f.endsWith('.js') ? 'application/javascript' : f.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/dashboards/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  try {
    const p = await browser.newPage({ viewport: { width: 1400, height: 950 } }); p.on('pageerror', (x) => errs.push(x.message));
    await p.goto(base + 'voice-troubleshoot.html?standalone=1'); await p.waitForSelector('#go');
    await p.waitForFunction(() => /1 IP phones/.test(document.getElementById('phnote').textContent), null, { timeout: 8000 }).then(() => ok(true), () => ok(false, 'phones from the asset register offered'));
    // validation in the page
    await p.fill('#a', 'phone?'); await p.click('#go'); await p.waitForSelector('.toast');
    ok(/phone A/.test(await p.textContent('.toast')), 'a bad entry is refused before anything is sent');
    // pick phone A by name, far end by IP, "phone A hears nothing"
    await p.fill('#a', 'SEP-RECEPTION-SYN · Branch'); await p.fill('#b', B); await p.click('[data-hear="a_cannot_hear_b"]'); await p.click('#go');
    await p.waitForSelector('#sum', { state: 'attached', timeout: 15000 });
    ok(queries.length === 1 && queries[0].a.value === A && queries[0].b.value === B, 'the phone name became its IP; the addresses go to the log query as parameters');
    ok(/audio 10\.0\.20\.40 → 10\.30\.1\.25 is lost/.test(await p.textContent('#sum')) && /SIP ALG/.test(await p.textContent('#sum')), 'summary: which direction is lost, most likely cause: ' + await p.textContent('#sum'));
    ok(await p.$('.cause[data-cause="sip-alg"]') && /high confidence/.test(await p.textContent('.cause[data-cause="sip-alg"]')), 'SIP ALG cause, high confidence');
    ok(/set default-voip-alg-mode kernel-helper-based/.test(await p.textContent('.cause[data-cause="sip-alg"] pre.scr')) && /delete 13/.test(await p.textContent('.cause[data-cause="sip-alg"] pre.scr')), 'the FortiOS fix');
    ok(/proxy-based/.test(await p.$eval('.cause[data-cause="sip-alg"] details pre', (x) => x.textContent)), 'with its rollback');
    ok(!(await p.$('#out img')) && (await p.textContent('#out')).includes(XSS), 'a hostile log value stays text');
    ok(/Call Statistics/.test(await p.textContent('.manual')) && (await p.$$eval('.manual tbody tr', (r) => r.length)) === 4, 'phone and call manager checks');
    ok(/FG-BRANCH-SYN/.test(await p.textContent('.path')), 'the path names the firewall that saw the voice');
    // propose the fix as a change plan (operator)
    await p.click('.cause[data-cause="sip-alg"] [data-propose]');
    await p.waitForFunction(() => /Proposed CHG-|Proposed /.test((document.querySelector('.cause[data-cause="sip-alg"] [data-propose]') || {}).textContent || ''), null, { timeout: 8000 }).then(() => ok(true), () => ok(false, 'proposed as a change plan'));
    ok(N.changes.list({}).some((c) => /SIP ALG/.test(c.title) && c.proposed_by === 'omar.syn'), 'the change plan is recorded for another engineer to approve');
    ok(audits.some((a) => a[0] === 'netops.voice.diagnose' && a[2].a === A && a[2].hear === 'a_cannot_hear_b'), 'the run is audited with who and what');
    // the menu
    ok(await p.evaluate(() => (window.ZYB_NAV || []).some((ar) => ar.pages.some((x) => x.h === 'voice-troubleshoot.html'))), 'menu entry');
    // a viewer cannot run it
    WHO = { user: 'vera.syn', role: 'viewer' }; await p.reload(); await p.waitForSelector('#denied:not([hidden])', { state: 'attached', timeout: 8000 });
    ok(await p.$eval('#go', (b) => b.disabled), 'a viewer cannot run the diagnosis');
  } finally { await browser.close(); srv.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks');
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
