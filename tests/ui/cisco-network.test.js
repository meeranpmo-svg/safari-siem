// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Cisco Network Inventory (cisco-network.html), stubbed engines, SYNTHETIC devices: every Cisco IOS / ASA device in the
// AI Network Engineer is listed (other vendors are not); model / serial / version come from CLI facts, else from the SNMP
// sysDescr (labelled), else "not read" - never guessed; support coverage joined by serial; tiles filter; "Read" asks the
// engine for show version / inventory and the row updates; a refused read shows why in the row; viewer told the role;
// CSV is formula-safe; with no Cisco device the page says what to add. Also: the portal's own Cisco Device Inventory
// (UCS / Unified CM) page links here. Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node cisco-network.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui'), LIVE = path.resolve(__dirname, '../../repos/live/portal');
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
let WHO = { user: 'omar.syn', role: 'operator' }, EMPTY = false, PSCFG = true; const POSTS = []; let PSCHECKS = 0;
const DEVS = () => EMPTY ? [] : [
  { id: 'sw1', name: 'dc-rack2-sw1.syn.local', vendor: 'cisco-ios', ip: '10.9.1.1', site: 'Riyadh DC', role: 'access', credentials: { ssh: true }, ssh_hostkey: true, cli_facts: { version: '17.9.4', model: 'C9300-48P', serials: ['FOC111SYN', 'FOC222SYN'], stack: [{}, {}], at: Date.now() }, last: { at: Date.now(), ok: true, system: { version: 'Cisco IOS XE Software, Version 17.09.04' } } },
  { id: 'sw2', name: 'f1-c1-sw1.syn.local', vendor: 'cisco-ios', ip: '10.9.1.2', site: 'Riyadh HQ', role: 'access', credentials: {}, last: { at: Date.now(), ok: true, system: { version: 'Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), Version 15.2(7)E3, RELEASE SOFTWARE (fc3)' } } },
  { id: 'sw3', name: '=cmd-sw3', vendor: 'cisco-ios', ip: '10.9.1.3', site: 'Jeddah', role: 'core', credentials: {}, last: { at: Date.now(), ok: false, system: null } },
  { id: 'fw1', name: 'asa-syn', vendor: 'cisco-asa', ip: '10.9.0.1', site: 'Riyadh DC', role: 'firewall', last: null },
  { id: 'pa1', name: 'pa-syn', vendor: 'paloalto', ip: '10.9.0.2' }];
(async () => {
  const srv = http.createServer((req, res) => {
    const u = decodeURIComponent(req.url.split('?')[0]), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u === '/dashboards/whoami.json' || u === '/auth/whoami') return json(200, WHO);
    if (u === '/api/soc/netops/devices') return json(200, { items: DEVS() });
    if (u === '/api/itam/cisco-support/report') return json(200, { rows: [{ serial: 'FOC111SYN', status: 'covered', end: '2027-03-31' }, { serial: 'X', mgmt_ip: '10.9.1.3', status: 'expired', end: '2025-01-01' }] });
    const PSV = { api: { enabled: PSCFG, secret_set: PSCFG }, last_check: new Date().toISOString(), note: 'Advisories that Cisco PSIRT lists.', devices: [{ id: 'sw1', key: 'iosxe:17.9.4' }, { id: 'sw2', key: 'ios:15.2(7)E3' }, { id: 'sw3', key: null }, { id: 'fw1', key: null }],
      versions: [{ key: 'iosxe:17.9.4', ostype: 'iosxe', version: '17.9.4', at: new Date().toISOString(), count: 2, by_sir: { Critical: 1, Medium: 1 }, worst: 'Critical', advisories: [{ id: 'cisco-sa-syn-webui', title: '<b>IOS XE Web UI (SYN)</b>', sir: 'Critical', cvss: 10, cves: ['CVE-2023-20198'], first_fixed: ['17.9.4a'], published: '2023-10-16', url: 'https://sec.cloudapps.cisco.com/x' }, { id: 'cisco-sa-syn-2', title: 'Medium SYN', sir: 'Medium', cvss: 5.3, cves: [], first_fixed: [], url: '' }] },
        { key: 'ios:15.2(7)E3', ostype: 'ios', version: '15.2(7)E3', at: new Date().toISOString(), count: 0, by_sir: {}, advisories: [] }] };
    if (u === '/api/itam/cisco-support/psirt') return json(200, PSV);
    if (u === '/api/itam/cisco-support/psirt/check' && req.method === 'POST') { PSCHECKS++; if (WHO.role === 'viewer') return json(403, { error: 'requires operator' }); return json(200, { check: { ok: true, advisories: 2, versions: 2, without_version: 2 }, psirt: PSV }); }
    const m = /^\/api\/soc\/netops\/devices\/([^/]+)\/cli\/facts$/.exec(u);
    if (m && req.method === 'POST') { POSTS.push(m[1]); if (WHO.role === 'viewer') return json(403, { error: 'requires operator role' }); if (m[1] === 'sw3') return json(502, { error: 'SSH login not set for this device' }); return setTimeout(() => json(200, { version: '15.2(7)E3', model: 'WS-C2960X-48FPD-L', serials: ['FOC333SYN'], at: Date.now() }), 150); }
    if (u.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = u.startsWith('/dashboards/') ? path.join(DASH, u.slice(12)) : u === '/' ? path.join(LIVE, 'index.html') : path.join(LIVE, u);
    if (!f.startsWith(DASH) && !f.startsWith(LIVE)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (e, d) => { if (e) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': f.endsWith('.js') ? 'application/javascript' : f.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port;
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch(); const errs = [];
  const open = async () => { const ctx = await browser.newContext({ viewport: { width: 1500, height: 900 }, acceptDownloads: true }); const p = await ctx.newPage(); p.on('pageerror', (e) => errs.push(e.message)); await p.goto(base + '/dashboards/cisco-network.html?standalone=1'); await p.waitForSelector('#tbl table, #tbl .empty:not(:empty)', { timeout: 15000 }); await p.waitForTimeout(300); return p; };
  const row = (p, name) => p.evaluate((nm) => { const tr = [...document.querySelectorAll('#tbl tbody tr')].find((x) => x.textContent.includes(nm)); return tr ? tr.innerText.replace(/\s+/g, ' ') : ''; }, name);
  try {
    let p = await open();
    ok((await p.$$('#tbl tbody tr')).length === 4 && !(await row(p, 'pa-syn')), 'every Cisco IOS / ASA device, not the Palo Alto');
    const r1 = await row(p, 'dc-rack2-sw1');
    ok(/C9300-48P/.test(r1) && /FOC111SYN/.test(r1) && /FOC222SYN/.test(r1) && /stack of 2/.test(r1) && /17\.9\.4/.test(r1) && /CLI/.test(r1) && /covered/.test(r1) && /2027-03-31/.test(r1), 'CLI facts: model, both stack serials, version, support: ' + r1);
    const r2 = await row(p, 'f1-c1-sw1');
    ok(/15\.2\(7\)E3/.test(r2) && /SNMP/.test(r2) && /C2960X/.test(r2) && /not read/.test(r2), 'SNMP sysDescr: version and platform labelled SNMP; serial not read (not guessed): ' + r2);
    const r3 = await row(p, '=cmd-sw3');
    ok(/not answering/.test(r3) && /expired/.test(r3), 'not answering, support matched by IP: ' + r3);
    ok(/not polled/.test(await row(p, 'asa-syn')), 'never polled says so');
    const k = await p.textContent('#kk');
    const ks = k.replace(/\s+/g, ''); ok(/Ciscodevices4/.test(ks) && /Versionnotread2/.test(ks) && /Noserialnumber3/.test(ks), 'tiles: ' + k.replace(/\s+/g, ' '));
    ok(/1 Critical/.test(r1) && /1 Medium/.test(r1) && /none published/.test(await row(p, 'f1-c1-sw1')) && /version not read/.test(await row(p, 'asa-syn')), 'advisories per device: counts by impact, none, version not read');
    ok(/Critical\/highadvisories1/.test((await p.textContent('#kk')).replace(/\s+/g, '')), 'tile: devices with critical / high advisories');
    await p.click('[data-adv="iosxe:17.9.4"]'); await p.waitForTimeout(300);
    const dr = await p.evaluate(() => document.body.innerText);
    ok(/IOS XE Web UI \(SYN\)/.test(dr) && /CVE-2023-20198/.test(dr) && /17\.9\.4a/.test(dr) && /dc-rack2-sw1/.test(dr), 'advisory list: title, CVE, first fixed, devices on that version');
    ok(!(await p.$('#zd b:not(table b)')) || !(await p.evaluate(() => [...document.querySelectorAll('#zd b')].some((b) => b.textContent === 'IOS XE Web UI (SYN)' && b.parentElement.tagName === 'B'))), 'advisory titles escaped');
    await p.keyboard.press('Escape'); await p.waitForTimeout(200);
    await p.click('#pscheck'); await p.waitForFunction(() => /advisory\(ies\)/.test([...document.querySelectorAll('.toast')].map((t) => t.textContent).join(' ')), null, { timeout: 5000 }).catch(() => {});
    ok(PSCHECKS === 1, 'Check Cisco advisories asks the engine');
    await p.click('[data-tile="noser"]'); await p.waitForTimeout(150);
    ok((await p.$$('#tbl tbody tr')).length === 3, 'a tile filters the table');
    await p.click('[data-tile="noser"]');
    ok(/15\.2\(7\)E3/.test(await p.textContent('#vers')) && /C9300-48P/.test(await p.textContent('#models')), 'versions and models summarised');
    await p.click('[data-facts="sw2"]'); await p.waitForFunction(() => /WS-C2960X-48FPD-L/.test(document.querySelector('#tbl').textContent), null, { timeout: 5000 }).catch(() => {});
    const r2b = await row(p, 'f1-c1-sw1');
    ok(POSTS.includes('sw2') && /WS-C2960X-48FPD-L/.test(r2b) && /FOC333SYN/.test(r2b) && /CLI/.test(r2b), 'Read: show version / inventory over SSH, the row updates: ' + r2b);
    POSTS.length = 0;
    await p.click('#readall'); await p.waitForFunction(() => !document.querySelector('#readall').disabled, null, { timeout: 10000 }).catch(() => {});
    ok(POSTS.sort().join(',') === 'fw1,sw3', 'Read all reads only the devices not read yet: ' + POSTS.join(','));
    ok(/SSH login not set/.test(await row(p, '=cmd-sw3')), 'a refused read shows the reason in its row');
    const [dl] = await Promise.all([p.waitForEvent('download'), p.click('#csv')]);
    const csv = fs.readFileSync(await dl.path(), 'utf8');
    ok(/"'=cmd-sw3"/.test(csv) && /FOC111SYN FOC222SYN/.test(csv), 'CSV, formula-safe');
    await p.context().close();
    WHO = { user: 'v.syn', role: 'viewer' }; p = await open(); POSTS.length = 0;
    await p.click('[data-facts="sw2"]'); await p.waitForTimeout(500);
    ok(/needs the operator role/.test(await row(p, 'f1-c1-sw1')), 'viewer: told the role');
    await p.context().close();
    WHO = { user: 'omar.syn', role: 'operator' }; PSCFG = false; p = await open();
    ok(/Security advisories need the Cisco API/.test(await p.textContent('#why')) && /Cisco API not configured/.test(await row(p, 'dc-rack2-sw1')), 'Cisco API not configured: says where to set it up');
    await p.context().close(); PSCFG = true;
    EMPTY = true; p = await open();
    ok(/No Cisco switch, router or firewall/.test(await p.textContent('#tbl')), 'no Cisco device: says what to add');
    await p.context().close();
    // the portal's Cisco Device Inventory entry opens the live Cisco Updates devices view (switches, routers, ASAs from the
    // AI Network Engineer; it links this page - tested in cisco-update.test.js) - the old UCS / CUCM-only portal view is no longer shown
    if (fs.existsSync(path.join(LIVE, 'index.html'))) {
      const c = await browser.newContext({ viewport: { width: 1366, height: 800 } }), q = await c.newPage(); q.on('pageerror', (e) => errs.push('portal: ' + e.message));
      await q.goto(base + '/'); await q.waitForSelector('li.zyb-area', { state: 'attached', timeout: 20000 });
      await Promise.all([q.waitForURL(/cisco-update\.html(%23|#)view(%3D|=)devices/, { timeout: 10000 }).catch(() => null), q.evaluate(() => setView('upd-inventory'))]);   // eslint-disable-line no-undef
      ok(/cisco-update\.html(%23|#)view(%3D|=)devices/.test(q.url()), 'portal Cisco Device Inventory opens the live Cisco Updates devices view (switches, routers, ASAs), not the old UCS / CUCM-only view: ' + q.url());
      await c.close();
    }
    ok(!errs.length, 'no page errors: ' + errs.slice(0, 3).join(' | '));
  } finally { await browser.close(); srv.close(); }
  console.log(bad ? 'FAILED ' + bad + '/' + n + ' checks' : 'OK ' + n + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
