// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// AD Audit (ad-audit.html) - the AD changes, Lockout analyzer and Policy changes tabs, stubbed SIEM API, SYNTHETIC domain
// synthetic.test: changes list old -> new; a kind tile and the filters reach the API; an ACL change opens with the ACEs added
// and removed; personal data stays hidden; a hostile value stays text; the lockout ranking opens an account's history and a
// lockout its evidence; policy changes show old -> new; a GPO report opens its setting-level diff; "Snapshot" posts and a
// refusal is explained; a 403 is explained; no browser dialog, no page error.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node ad-audit-changes.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const Q = [], POSTS = [];
let DENY = false, SNAP_CODE = 200;
const SDDL_OLD = 'O:DAG:DAD:PAI(A;;GA;;;DA)', SDDL_NEW = 'O:DAG:DAD:PAI(A;;GA;;;DA)(A;;GA;;;S-1-5-21-1-2-3-4242)';
const CHANGES = [
  { at: '2026-11-10T09:00:00.000Z', dc: 'dc01.synthetic.test', event_code: '5136', op: 'modified', kind: 'acl', object_class: 'container', object_type: 'container', object_dn: 'CN=AdminSDHolder,CN=System,DC=synthetic,DC=test', object_name: 'AdminSDHolder', attribute: 'nTSecurityDescriptor', who: 'adm.syn', old: SDDL_OLD, new: SDDL_NEW, old_values: [SDDL_OLD], new_values: [SDDL_NEW], privileged_object: true, severity: 3,
    summary: 'Permissions on AdminSDHolder: 1 entry added, 0 removed - RISKY: Allow S-1-5-21-1-2-3-4242: Full control',
    detail: { acl: { sddl_old: SDDL_OLD, sddl_new: SDDL_NEW, owner_old: 'Domain Admins', owner_new: 'Domain Admins', owner_changed: false, inheritance_old: 'blocked', inheritance_new: 'blocked', inheritance_changed: false, inherited_changes: 0,
      added: [{ trustee: 'S-1-5-21-1-2-3-4242', type: 'Allow', rights: 'Full control', object: '', risky: true, text: 'Allow S-1-5-21-1-2-3-4242: Full control' }], removed: [], risky: ['Allow S-1-5-21-1-2-3-4242: Full control'] } } },
  { at: '2026-11-10T08:00:00.000Z', dc: 'dc01.synthetic.test', event_code: '5136', op: 'modified', kind: 'attribute', object_class: 'user', object_type: 'user', object_dn: 'CN=Finance Synthetic,OU=Staff,DC=synthetic,DC=test', object_name: 'Finance Synthetic', attribute: 'title', who: 'hr.syn', old: 'Analyst', new: '<img src=x onerror=window.PWN=1>Senior', old_values: ['Analyst'], new_values: ['<img src=x onerror=window.PWN=1>Senior'], severity: 1, summary: 'user Finance Synthetic: title Analyst → Senior', detail: null },
  { at: '2026-11-10T07:00:00.000Z', dc: 'dc01.synthetic.test', event_code: '5136', op: 'modified', kind: 'attribute', object_class: 'user', object_type: 'user', object_dn: 'CN=Finance Synthetic,OU=Staff,DC=synthetic,DC=test', object_name: 'Finance Synthetic', attribute: 'mobile', who: 'hr.syn', old: '', new: '', masked: true, old_values: ['(personal data - value not shown)'], new_values: ['(personal data - value not shown)'], severity: 1, summary: 'user Finance Synthetic: mobile changed (personal data - value not shown)', detail: null },
  { at: '2026-11-10T06:00:00.000Z', dc: 'dc01.synthetic.test', event_code: '5136', op: 'modified', kind: 'gpo', object_class: 'groupPolicyContainer', object_type: 'gpo', object_dn: 'CN={6AC1786C-016F-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC=synthetic,DC=test', object_name: '{6AC1786C-016F-11D2-945F-00C04FB984F9}', attribute: 'versionNumber', who: 'adm.syn', gpo_guid: '6AC1786C-016F-11D2-945F-00C04FB984F9', gpo_name: 'Synthetic Servers Policy', old: '196615', new: '196616', severity: 2,
    summary: 'GPO 6AC1786C-016F-11D2-945F-00C04FB984F9: versionNumber (computer settings edited)', detail: { gpo: { guid: '6AC1786C-016F-11D2-945F-00C04FB984F9', attribute: 'versionNumber', version_old: { user: 3, computer: 7 }, version_new: { user: 3, computer: 8 }, changed_side: 'computer', setting_level: 'Which SETTING changed (old → new) needs the GPO report: see Policy changes → GPO setting changes.' } } }];
const COUNTS = { total: 4, acl: 1, gpo: 1, 'gpo-link': 0, dns: 0, schema: 0, attribute: 2, object: 0, access: 0, privileged: 1, risky: 1 };
const LOCKS = [{ at: '2026-11-10T08:00:00.000Z', account: 'fin.syn', dc: 'pdc.synthetic.test', caller_computer: 'WS-FIN-07', window_min: 30, hints: ['Service / batch logon: a Windows service or scheduled task still uses the old password.'],
  likely: { computer: 'WS-FIN-07', ip: '10.20.1.7', process: 'outlook.exe', logon_type: 'network', basis: 'caller computer in the 4740 event', confidence: 'high', corroborated: true },
  evidence: { failures: 6, counts: { 4625: 2, 4771: 2, 4776: 2 }, computers: [{ name: 'WS-FIN-07', count: 4 }], ips: [{ name: '10.20.1.7', count: 4 }], processes: [{ name: 'outlook.exe', count: 2 }], logon_types: [{ name: 'network', count: 2 }], servers: [{ name: 'fs01.synthetic.test', count: 2 }], reasons: [{ name: 'bad password', count: 6 }] } }];
const RANK = [{ account: 'fin.syn', lockouts: 2, repeat: true, first: '2026-11-09T08:00:00.000Z', last: '2026-11-10T08:00:00.000Z', top_source: 'WS-FIN-07', top_source_count: 2, recurring_source: true, sources: [], ips: [{ name: '10.20.1.7', count: 2 }], dcs: [] }];
const POLICY = { available: true, hours: 168, items: [
  { at: '2026-11-10T05:00:00.000Z', type: 'domain-policy', event_code: '4739', dc: 'dc01.synthetic.test', who: 'adm.syn', policy: 'Lockout Policy', domain: 'SYN', settings: [{ setting: 'LockoutThreshold', old: '5', new: '0' }] },
  { at: '2026-11-10T04:00:00.000Z', type: 'audit-policy', event_code: '4719', dc: 'dc01.synthetic.test', who: 'dc01$', category: 'DS Access', subcategory: 'Directory Service Changes', changes: 'Success removed', removed: true, applied_by_gpo: true }],
  gpo_changes: [CHANGES[3]], gpo_snapshots: [{ id: 'gpo-6ac1786c-016f-11d2-945f-00c04fb984f9-2', guid: '6AC1786C-016F-11D2-945F-00C04FB984F9', name: 'Synthetic Servers Policy', at: '2026-11-10T06:10:00.000Z', by: 'ad-changes (automatic)', settings: 42, previous: 'gpo-6ac1786c-016f-11d2-945f-00c04fb984f9-1', diff_count: 1 }],
  snapshot: { enabled: true, server: 'dc01', reason: '' } };
(async () => {
  const srv = http.createServer((q, r) => {
    const u = q.url.split('?')[0], j = (c, o) => { r.writeHead(c, { 'Content-Type': 'application/json' }); r.end(JSON.stringify(o)); };
    let raw = ''; q.on('data', (d) => { raw += d; }); q.on('end', () => {
      if (u.endsWith('whoami.json')) return j(200, { user: 'syed', role: 'analyst' });
      if (u.startsWith('/api/soc/ad/')) { Q.push(q.method + ' ' + q.url); if (DENY) return j(403, { error: 'forbidden' }); }
      if (u === '/api/soc/identity/summary') return j(403, { error: 'admin only' });   // an analyst: the directory snapshot is for admins, the new tabs still work
      if (u === '/api/soc/ad/changes') { const qs = new URLSearchParams(q.url.split('?')[1]); const k = qs.get('kind'); const L = CHANGES.filter((c) => !k || c.kind === k || (k === 'gpo' && c.kind === 'gpo-link')); return j(200, { available: true, hours: Number(qs.get('hours')), counts: COUNTS, classes: [{ name: 'user', count: 2 }, { name: 'container', count: 1 }, { name: 'groupPolicyContainer', count: 1 }], total: L.length, items: L, note: 'Needs "Audit Directory Service Changes" on the domain controllers.' }); }
      if (u === '/api/soc/ad/lockouts' || u.startsWith('/api/soc/ad/lockouts/')) return j(200, { available: true, hours: 168, window_min: 30, total: LOCKS.length, items: LOCKS, ranking: RANK });
      if (u === '/api/soc/ad/policy-changes') return j(200, POLICY);
      if (u.startsWith('/api/soc/ad/gpo/snapshots/')) return j(200, { id: 'gpo-6ac1786c-016f-11d2-945f-00c04fb984f9-2', guid: '6AC1786C-016F-11D2-945F-00C04FB984F9', name: 'Synthetic Servers Policy', at: '2026-11-10T06:10:00.000Z', by: 'ad-changes (automatic)', previous: 'gpo-6ac1786c-016f-11d2-945f-00c04fb984f9-1',
        diff: [{ setting: 'Computer / Security / Account [MinimumPasswordLength]', change: 'changed', old: 'SettingNumber=8; Type=Password', new: 'SettingNumber=14; Type=Password' }] });
      if (u === '/api/soc/ad/gpo/snapshot') { POSTS.push(raw); return SNAP_CODE === 200 ? j(200, { server: 'dc01', snapshots: [{ id: 'x', guid: 'g', diff: [{}, {}] }] }) : j(SNAP_CODE, { error: 'operator role required' }); }
      if (u === '/api/soc/search') return j(200, { rows: [], total: 0 });
      if (u === '/api/soc/histogram') return j(200, { buckets: [] });
      if (u.startsWith('/api/')) return j(404, { error: 'not in this test' });
      fs.readFile(path.join(DASH, u.replace(/^\/dashboards\//, '/')), (e, d) => { if (e) { r.writeHead(404); return r.end(); } r.writeHead(200, { 'Content-Type': u.endsWith('.js') ? 'application/javascript' : u.endsWith('.css') ? 'text/css' : 'text/html' }); r.end(d); });
    });
  });
  await new Promise((res) => srv.listen(0, '127.0.0.1', res));
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const p = await browser.newPage({ viewport: { width: 1500, height: 900 } }); p.on('pageerror', (e) => errs.push(e.message)); p.on('dialog', (d) => { errs.push('dialog: ' + d.message()); d.dismiss(); });
  const wait = (fn, a) => p.waitForFunction(fn, a, { timeout: 10000 }).then(() => true, () => false);
  const body = () => p.evaluate(() => document.body.innerText);
  const drawer = () => p.evaluate(() => (document.getElementById('zd-b') || {}).innerText || '');
  const shut = () => p.evaluate(() => window.zybDetail.close());
  const waitQ = async (re) => { for (let i = 0; i < 200; i++) { if (re.test(Q[Q.length - 1] || '')) return true; await new Promise((r) => setTimeout(r, 50)); } return false; };
  const base = 'http://127.0.0.1:' + await new Promise((r) => r(srv.address().port));
  try {
    await p.goto(base + '/ad-audit.html?standalone=1');
    await p.waitForSelector('[data-tab="adc"]');
    // ---- AD changes
    await p.click('[data-tab="adc"]');
    ok(await wait(() => document.querySelectorAll('#adc tr[data-adc]').length === 4), 'the AD changes tab lists the changes');
    ok(/hours=168/.test(Q.find((x) => /ad\/changes/.test(x)) || ''), 'the period (7 days) is sent as hours');
    const t = await p.textContent('#adc');
    ok(/Analyst/.test(t) && /→/.test(t) && /changed \(personal data, value not shown\)/.test(t), 'old → new values; the personal-data attribute shows no value');
    ok(/Synthetic Servers Policy/.test(t) && /privileged/.test(t), 'GPO named, privileged object flagged');
    ok(/<img src=x/.test(t) && !(await p.evaluate(() => window.PWN)) && !(await p.$('#adc img')), 'a hostile value stays text');
    ok(/Needs "Audit Directory Service Changes"/.test(await p.textContent('#adc-note')), 'what the data needs is said');
    await p.click('#adck [data-adk="acl"]');
    ok(await waitQ(/kind=acl/), 'a kind tile filters through the API');
    await p.selectOption('#adc-kind', ''); await p.fill('#adc-who', 'hr.syn'); await p.check('#adc-priv'); await p.click('#adc-go');
    ok(await waitQ(/who=hr\.syn.*privileged=1|privileged=1.*who=hr\.syn/), 'the filters reach the API (who, privileged only)');
    ok((await p.$$eval('#adc-cls option', (o) => o.map((x) => x.value))).includes('groupPolicyContainer'), 'the object-class filter lists the classes seen');
    await p.click('#adc tr[data-adc="0"]');
    ok(await wait(() => /Entries added \(1\)/.test((document.getElementById('zd-b') || {}).innerText || '')), 'an ACL change opens with the entries added');
    const dz = await drawer();
    ok(/S-1-5-21-1-2-3-4242/.test(dz) && /risky/.test(dz) && /Entries removed \(0\)/.test(dz) && dz.includes(SDDL_NEW), 'trustee, rights, risk and the SDDL old / new');
    await shut();
    await p.click('#adc tr[data-adc="3"]'); ok(await wait(() => /Version \(computer \/ user\)/.test(document.getElementById('zd-b').innerText)) && /7 \/ 3 → 8 \/ 3/.test(await drawer()) && /GPO report/.test(await drawer()), 'a GPO change explains version and that settings need the report');
    await p.click('#zd-b [data-goto="pol"]');
    ok(await wait(() => !document.getElementById('tab-pol').hidden && document.querySelectorAll('#pol tr').length > 1), 'Open Policy changes goes to the tab');
    // ---- Policy changes
    const pol = await p.textContent('#pol');
    ok(/LockoutThreshold/.test(pol) && /5→0/.test(pol.replace(/\s/g, '')) && /auditing removed/.test(pol) && /by Group Policy/.test(pol), 'domain policy old → new, audit removal, applied by GPO');
    ok(/Synthetic Servers Policy/.test(await p.textContent('#gpc')) && /dc01/.test(await p.textContent('#gps-st')), 'GPO changes in AD and where the reports are read');
    await p.click('#gps tr[data-gs="0"]');
    ok(await wait(() => /Settings changed \(1\)/.test((document.getElementById('zd-b') || {}).innerText || '')) && /MinimumPasswordLength/.test(await drawer()) && /SettingNumber=14/.test(await drawer()), 'a GPO report opens its setting-level old → new');
    await shut();
    await p.click('#gps-take'); ok(await wait(() => /2 setting change/.test(document.body.innerText)) && POSTS.length === 1, 'Snapshot posts and says what it found');
    SNAP_CODE = 403; await p.click('#gps-take'); ok(await wait(() => /operator role needed/.test(document.body.innerText)), 'a refusal is explained');
    // ---- Lockout analyzer
    await p.click('[data-tab="lock"]');
    ok(await wait(() => document.querySelectorAll('#lk tr[data-lk]').length === 1 && document.querySelectorAll('#rank tr[data-rk]').length === 1), 'lockouts and the repeat ranking');
    const lk = await p.textContent('#lk'); ok(/WS-FIN-07/.test(lk) && /10\.20\.1\.7/.test(lk) && /outlook\.exe/.test(lk) && /high/.test(lk) && /2 · 2 · 2/.test(lk), 'likely source, IP, process, confidence, evidence counts');
    ok(/repeat/.test(await p.textContent('#rank')), 'a repeat lockout is marked');
    await p.click('#rank tr[data-rk="0"]'); ok(await waitQ(/\/ad\/lockouts\/fin\.syn\?/) && await wait(() => /Lockout history of fin\.syn/.test(document.getElementById('lk-t').textContent)) && /Lockout history of fin\.syn/.test(await p.textContent('#lk-t')), 'a ranked account opens its lockout history');
    await p.click('#lk tr[data-lk="0"]');
    ok(await wait(() => /Workstations named/.test((document.getElementById('zd-b') || {}).innerText || '')) && /caller computer in the 4740 event/.test(await drawer()) && /What to check/.test(await drawer()), 'a lockout opens its evidence and what to check');
    await shut();
    await p.click('#lk-all'); ok(await waitQ(/\/ad\/lockouts\?/), 'back to all accounts');
    // ---- refused
    DENY = true; await p.selectOption('#per', '24h');
    ok(await wait(() => /needs the analyst role/.test(document.getElementById('rank').innerText)) && /hours=24/.test(Q[Q.length - 1]), 'a 403 is explained (and the period change reloads the open tab)');
    ok(!errs.length, 'no page errors or dialogs: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); }
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
