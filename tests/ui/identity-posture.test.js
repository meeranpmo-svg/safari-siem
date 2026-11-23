// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Password & MFA Posture (identity-posture.html), stubbed ITAM API answered by the REAL engine (backend/itam/engine/
// identity-posture.js) over a fake SIEM with SYNTHETIC people, so the page is tested against the payload the server really
// sends: the tiles, the ranked remediation list (administrators without MFA first, a link only to fixed pages), the domain
// policy against the baseline, the fine-grained policies, the account tabs, MFA and Conditional Access, the lockouts; hostile
// names stay text; an administrator changes the baseline with a reason (sent as the server expects) or resets it; an operator
// sees no inputs; a viewer is told the role; nothing connected = each section says what to connect and no figure is shown;
// an older server says to run the update. No browser dialog anywhere.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node identity-posture.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
const { createIdentityPosture } = require('../../backend/itam/engine/identity-posture');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
let WHO = { user: 'syed.syn', role: 'admin' }, MODE = 'live', POSTS = [];
const T = Date.now(), DAY = 86400000, ago = (d) => new Date(T - d * DAY).toISOString();
const U = (sam, o) => Object.assign({ sam, name: sam.replace('.syn', ' Synthetic'), disabled: false, privileged: false, service_account: false, pwd_never_expires: false, pwd_not_required: false, pwd_last_set: ago(30) }, o);
const AD = { available: true, synced: ago(0.1), domain: 'corp-hq.example', policy: { min_length: 8, history: 24, max_age_days: 0, min_age_days: 1, complexity: true, reversible: false, lockout_threshold: 0, lockout_minutes: 30, lockout_window_minutes: 30 },
  users: [U('alia.syn'), U('badr.syn', { privileged: true, pwd_never_expires: true }), U('carl.syn', { pwd_not_required: true, name: '<img src=x onerror=window.PWN=1>Carl' }), U('dina.syn', { pwd_last_set: ago(400) }), U('svc-backup-syn', { service_account: true, pwd_never_expires: true })] };
const M365 = { available: true, updated: ago(0.05), blocks: {}, mfa: { users: 10, registered: 7, notRegistered: [{ name: 'Badr Synthetic', upn: 'badr.syn@corp-hq.example', admin: true }, { name: '<b>Hala</b> Synthetic', upn: 'hala.syn@corp-hq.example', admin: false }, { name: 'Imad Synthetic', upn: 'imad.syn@corp-hq.example', admin: false }] },
  conditional_access: [{ name: 'Require MFA for admins', state: 'enabledForReportingButNotEnforced', modified: ago(40) }, { name: 'Block legacy authentication', state: 'enabled', modified: ago(10) }] };
const siem = async (m, p, b) => {
  if (MODE === 'none') throw Object.assign(new Error('the SIEM is not linked to IT Asset Management (discovery.siem in the ITAM configuration)'), { notConnected: true });
  if (p === '/audit/evidence/ad') return AD;
  if (p === '/audit/evidence/m365') return M365;
  if (p === '/histogram') return { buckets: Array.from({ length: 30 }, (_, i) => ({ t: T - (29 - i) * DAY, n: i === 29 ? 12 : i % 7 === 0 ? 1 : 0 })) };
  if (p === '/top' && b.field === 'target_user') return { values: [{ v: 'gina.syn', n: 12 }, { v: 'alia.syn', n: 3 }] };
  return { values: [{ v: '<i>WS-SYN-07</i>', n: 12 }] };
};
const fgpp = async () => { if (MODE === 'none') throw Object.assign(new Error('the directory connection is not set (HR Onboarding -> Directory settings)'), { notConnected: true });
  return { readable: true, items: [{ name: 'PSO-Legacy-Syn', precedence: 20, applies_to: 2, min_length: 6, history: 0, max_age_days: 0, min_age_days: 0, complexity: false, reversible: true, lockout_threshold: 0, lockout_minutes: 0, lockout_window_minutes: 0 }] }; };
const mem = {}; const store = { collection: (c) => ({ get: (id) => (mem[c] || {})[id] || null, put: (r) => { (mem[c] = mem[c] || {})[r.id] = r; return r; } }) };
const app = { store, audit: () => { /* the engine's audit is covered by its node test */ } };
const X = createIdentityPosture(app, { siem, fgpp });
(async () => {
  const srv = http.createServer((req, res) => {
    const u = decodeURIComponent(req.url.split('?')[0]), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    let raw = ''; req.on('data', (d) => { raw += d; }); req.on('end', async () => {
      const body = raw ? JSON.parse(raw) : {}, q = Object.fromEntries(new URL(req.url, 'http://x').searchParams);
      if (req.method === 'POST' && u.startsWith('/api/')) POSTS.push([u, body, WHO.user]);
      if (u === '/auth/whoami' || u === '/dashboards/whoami.json') return json(200, WHO);
      try {
        if (u === '/api/itam/identity-posture') { if (MODE === 'old') return json(404, { error: 'not found' }); if (WHO.role === 'viewer') return json(403, { error: 'requires role operator' }); return json(200, await X.report(q, WHO)); }
        if (u === '/api/itam/identity-posture/baseline') { if (WHO.role !== 'admin') return json(403, { error: 'requires role admin' }); return json(200, X.saveBaseline(body, WHO)); }
      } catch (e) { return json(e.status || 500, { error: e.status ? e.message : 'internal error' }); }
      if (u.startsWith('/api/') || u.startsWith('/auth/')) return json(404, { error: 'not in this test' });
      const f = path.join(DASH, u.replace(/^\/dashboards\//, '/'));
      if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
      fs.readFile(f, (e, d) => { if (e) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': f.endsWith('.js') ? 'application/javascript' : f.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
    });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/dashboards/identity-posture.html?standalone=1';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch(); const errs = [];
  const open = async () => { const p = await browser.newPage({ viewport: { width: 1440, height: 950 } }); p.on('pageerror', (e) => errs.push(e.message)); p.on('dialog', (d) => { errs.push('dialog: ' + d.message()); d.dismiss(); }); await p.goto(base); await p.waitForSelector('#kpis .t, #err .warn', { timeout: 15000 }); return p; };
  const txt = (p, s) => p.textContent(s);
  const toastIs = (p, re) => p.waitForFunction((r) => new RegExp(r).test([...document.querySelectorAll('.toast')].map((t) => t.textContent).join(' | ')), re.source, { timeout: 8000 }).then(() => true, () => false);
  const last = (pth) => POSTS.filter((x) => x[0] === pth).pop();
  try {
    let p = await open();
    ok(/Password & MFA Posture/.test(await p.title()), 'the title');
    ok(/Report only/.test(await txt(p, 'main')) && /second administrator approves/.test(await txt(p, 'main')), 'says it is report only and where changes are made');
    const k = (await p.innerText('#kpis')).replace(/\s+/g, ' ');
    ok(/Domain policy 50%/.test(k) && /MFA registered 70%/.test(k) && /Admins without MFA 1/.test(k) && /Password not required 1/.test(k) && /Lockouts \(30 days\) 17/.test(k), 'the tiles: ' + k);
    ok(/AD sync \(SIEM\): read/.test(await txt(p, '#sources')) && /Directory connection: read/.test(await txt(p, '#sources')), 'the sources are shown as read');
    const acts = await p.$$eval('#remed .act', (a) => a.map((x) => x.textContent));
    ok(acts.length >= 6 && /^1\s*critical\s*Administrator\(s\) without MFA registered/.test(acts[0]), 'ranked: administrators without MFA first: ' + acts[0]);
    ok(/PASSWD_NOTREQD/.test(acts[1]) && /NCA ECC 2-2-3/.test(acts[1]) && /SAMA CSF 3\.3\.5/.test(acts[1]), 'each item cites the control');
    ok(acts.some((a) => /Fine-grained policy PSO-Legacy-Syn: reversible encryption is on/.test(a)), 'a weak fine-grained policy is ranked');
    const links = await p.$$eval('#remed a', (a) => [...new Set(a.map((x) => x.getAttribute('href')))]);
    ok(links.length && links.every((h) => /^(ad-audit|m365-security|ad-manage|identity-signin|ad-exchange)\.html$/.test(h)), 'links only to fixed pages: ' + links.join(','));
    ok(/Minimum password length/.test(await txt(p, '#policy')) && /below/.test(await txt(p, '#policy')) && /0 \(never locks\)/.test(await txt(p, '#policy')), 'the policy against the baseline');
    ok(/PSO-Legacy-Syn/.test(await txt(p, '#fgpp')) && /applies to 2/.test(await txt(p, '#fgpp')), 'fine-grained policies listed');
    ok(/badr\.syn/.test(await txt(p, '#accts')) && /privileged/.test(await txt(p, '#accts')) && /svc-backup-syn/.test(await txt(p, '#accts')), 'never-expiring passwords, privileged and service marked');
    await p.click('[data-tab=not_required]'); ok(/<img src=x onerror=window\.PWN=1>Carl/.test(await txt(p, '#accts')), 'password not required, a hostile name as text');
    await p.click('[data-tab=old]'); ok(/dina\.syn/.test(await txt(p, '#accts')) && /400/.test(await txt(p, '#accts')), 'old passwords with their age');
    const m = await txt(p, '#mfa');
    ok(/7 of 10 people registered MFA/.test(m) && /badr\.syn@corp-hq\.example/.test(m) && /<b>Hala<\/b> Synthetic/.test(m) && !(await p.$('#mfa b b')), 'MFA: the admin without MFA, names as text');
    ok(/Enforcing MFA \(by name\):\s*none/.test(m) && /Report-only, not enforced:\s*Require MFA for admins/.test(m) && /not which methods/.test(m), 'Conditional Access by name, methods not held said');
    const l = await txt(p, '#locks'); ok(/17\s*lockouts in 30 days/.test(l) && /gina\.syn/.test(l) && /<i>WS-SYN-07<\/i>/.test(l), 'lockouts: total, top account, caller computer as text');
    ok((await p.$$('#locks .bars i')).length === 30, 'one bar per day');
    // the baseline: admin
    await p.fill('[data-knob=min_length]', '12'); await p.click('#b-save');
    ok(await toastIs(p, /at least 5 characters/) && !last('/api/itam/identity-posture/baseline'), 'a reason is required');
    await p.fill('#b-reason', 'risk acceptance RA-12 (synthetic)'); await p.click('#b-save');
    ok(await toastIs(p, /Baseline saved/), 'saved');
    const sv = last('/api/itam/identity-posture/baseline'); ok(sv && sv[1].reason === 'risk acceptance RA-12 (synthetic)' && JSON.stringify(sv[1].values) === '{"min_length":12}', 'only the changed value is sent, as a number: ' + JSON.stringify(sv && sv[1]));
    await p.waitForFunction(() => /Last changed by syed\.syn/.test(document.getElementById('base').textContent), null, { timeout: 8000 });
    ok(/changed/.test(await txt(p, '#base')) && /Always required, not adjustable/.test(await txt(p, '#base')), 'the changed value is marked; the fixed rules are listed');
    await p.fill('[data-knob=min_length]', '4'); await p.fill('#b-reason', 'too short (synthetic)'); await p.click('#b-save');
    ok(await toastIs(p, /min_length must be at least 8/), 'the server refusal is shown, naming the field');
    await p.fill('#b-reason', 'back to default (synthetic)'); await p.click('#b-reset');
    ok(await toastIs(p, /Back to the platform defaults/) && last('/api/itam/identity-posture/baseline')[1].reset === true, 'reset sent');
    await p.close();
    // operator: reads, no inputs
    WHO = { user: 'nora.syn', role: 'operator' }; p = await open();
    ok(!(await p.$('[data-knob]')) && !(await p.$('#b-save')) && /changed by an administrator/.test(await txt(p, '#base')), 'an operator sees the baseline without inputs'); await p.close();
    WHO = { user: 'vera.syn', role: 'viewer' }; p = await open();
    ok(/needs the operator role \(it names people\)/.test(await txt(p, '#err')), 'a viewer is told the role'); await p.close();
    // nothing connected
    WHO = { user: 'syed.syn', role: 'admin' }; MODE = 'none'; await X.report({ refresh: '1' }, WHO); p = await open();
    const k2 = (await p.innerText('#kpis')).replace(/\s+/g, ' ');
    ok(/Domain policy not read/.test(k2) && /MFA registered not read/.test(k2) && /Admins without MFA not read/.test(k2) && !/\b0%/.test(k2), 'nothing connected: no figure is shown: ' + k2);
    ok(/connect Active Directory to the SIEM/.test(await txt(p, '#policy')) && /connect Microsoft 365 to the SIEM/.test(await txt(p, '#mfa')) && /event 4740/.test(await txt(p, '#locks')) && /directory connection is not set/.test(await txt(p, '#fgpp')), 'each section says what to connect');
    ok(/no source is connected yet/.test(await txt(p, '#remed')), 'no remediation invented'); await p.close();
    MODE = 'old'; p = await open(); ok(/run the update/.test(await txt(p, '#err')), 'an older server: run the update'); await p.close();
    ok(!(await (await browser.newPage()).evaluate(() => window.PWN)), 'no script ran from a name');
    ok(!errs.length, 'no page errors or dialogs: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); }
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
