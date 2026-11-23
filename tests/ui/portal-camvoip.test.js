// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// The REAL portal's CCTV Live View and VoIP Quality (module camvoip) on SYNTHETIC feeds (/api/cctv, /api/voip):
//   cctv   KPIs; four cameras down on one floor = one shared cause; a flapping camera (history seeded in this browser's storage);
//          risk badges itemised; smart order (offline last); Needs attention filter; guard tour button; streams from the gateway;
//          a stream that never loads is flagged; the AI brief sends only facts; hostile names stay text; no gateway -> setup card
//   voip   registration KPIs; baseline learned from the history (unusually low); firmware drift per model; chronic offline;
//          filter chips and search (focus kept); call quality reads "not measured"; feed off -> honest empty state, and the old
//          sample phones (Reception, h.ali, MOS 4.3...) never appear
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node portal-camvoip.test.js
const http = require('http'), fs = require('fs'), path = require('path'), cp = require('child_process');
const LIVE = path.resolve(__dirname, '../../repos/live/portal'), DASH = path.resolve(__dirname, '../../ui');
if (!fs.existsSync(path.join(LIVE, 'index.html'))) { console.log('SKIP: repos/live/portal not present'); process.exit(0); }
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const SH = fs.readFileSync(path.join(DASH, 'add-dashboards-menu.sh'), 'utf8'), ELINE = /ELINE='([^']+)'/.exec(SH)[1], AWK = /awk -v line="\$ELINE" '([^']+)'/.exec(SH)[1];
const INDEX = cp.execFileSync('awk', ['-v', 'line=' + ELINE, AWK, path.join(LIVE, 'index.html')], { encoding: 'utf8' });
const XSS = '<img src=x onerror="window.__xss=1">';
let GW = true, VOIPON = true, AIBODY = null;
const cam = (id, loc, up) => ({ id, location: loc, stream: id, up });
const CCTV = () => ({ configured: true, updated: new Date().toISOString(), gateway: GW ? '/gw' : '', cameras: [
  cam('CAM-SYN-01', '3F · Lobby', true), cam('CAM-SYN-02', '3F · Corridor', true), cam('CAM-SYN-03', '3F · Store', true), cam('CAM-SYN-04 ' + XSS, '3F · Exit', true), cam('CAM-SYN-STALL', '3F · Roof', true),
  cam('CAM-SYN-11', '5F · Lift', false), cam('CAM-SYN-12', '5F · Server room', false), cam('CAM-SYN-13', '5F · Exit', false), cam('CAM-SYN-14', '5F · Pantry', false), cam('CAM-SYN-15', '5F · Desk', true),
  cam('CAM-SYN-FLAP', '3F · Car park', true)] });
const ph = (ext, model, version, reg, kind) => ({ ext, user: 'user.' + ext, model, version, reg, kind: kind || 'hardware', mac: 'SY:NT:00:00:' + ext.slice(-2) });
const VOIP = () => VOIPON ? { configured: true, updated: new Date().toISOString(), users: 9, phones: [
  ph('2001', 'Cisco 8845', '14.2', true), ph('2002', 'Cisco 8845', '14.2', true), ph('2003', 'Cisco 8845', '14.2', true), ph('2004', 'Cisco 8845', '12.8', true), ph('2005', 'Cisco 8845', '14.2', false),
  ph('2006', 'Cisco 7841', '14.1', false), ph('2007', 'Webex', '43.1', true, 'soft'), ph('2008', 'Webex', '43.1', false, 'soft'), ph('2009', 'Cisco 7841', '14.1', true)] } : { configured: false, phones: [] };
(async () => {
  const srv = http.createServer((req, res) => {
    const u = decodeURIComponent(req.url.split('?')[0]), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u === '/auth/whoami' || u === '/dashboards/whoami.json') return json(200, { user: 'nora.syn', role: 'admin' });
    if (u === '/auth/org') return json(200, { modules: null, resp: {}, updated: null });
    if (u === '/api/cctv') return json(200, CCTV());
    if (u === '/api/voip') return json(200, VOIP());
    if (u === '/api/itam/discovery/results') return json(200, { devices: [{ id: 'd1', hostname: 'SEP00AA11BB22CC', ip: '10.50.1.40', vendor: 'Cisco Systems' }, { id: 'd2', hostname: 'SEP00AA11BB22DD', asset_id: 'p1' }] });
    if (u === '/api/itam/assets' && !/type=phone/.test(req.url)) return json(200, { assets: [{ id: 'p1', type: 'phone', name: 'SEP-SYN-1', vendor: 'Cisco', model: 'CP-8845', site: 'HQ', status: 'in_use' },
      { id: 'p3', type: 'other', name: 'SEP0011223344AA', vendor: 'Cisco', model: 'CP-7841', mgmt_ip: '10.50.1.30', site: 'HQ', last_seen: new Date(Date.now() - 2 * 864e5).toISOString(), status: 'in_use' },
      { id: 's1', type: 'server', name: 'cucm-syn-01', vendor: 'Cisco', model: 'Cisco Unified CM IP Phone services', status: 'in_use' }] });
    if (u === '/api/itam/assets') return json(200, { assets: [{ id: 'p1', type: 'phone', name: 'SEP-SYN-1', vendor: 'Cisco', model: 'CP-8845', mgmt_ip: '10.50.1.10', site: 'HQ', last_seen: new Date(Date.now() - 864e5).toISOString(), status: 'in_use' },
      { id: 'p2', type: 'phone', name: 'YEA-SYN-OLD <img src=x onerror=window.__y=1>', vendor: 'Yealink', model: 'T54W', site: 'Jeddah', last_seen: new Date(Date.now() - 45 * 864e5).toISOString(), status: 'in_use' }] });
    if (u === '/api/ai') { let b = ''; req.on('data', (d) => { b += d; }); req.on('end', () => { AIBODY = b; json(200, { text: 'Synthetic brief.' }); }); return; }
    if (u === '/gw/stream.html') { if (/STALL/.test(req.url)) return; res.writeHead(200, { 'Content-Type': 'text/html' }); return res.end('<p>synthetic stream</p>'); }
    if (u.startsWith('/api/soc/ui/menu')) return json(200, { order: null, favorites: [], can_edit_order: true });
    if (u.startsWith('/api/') || u.startsWith('/auth/')) return json(404, { error: 'not in this test' });
    if (u === '/') { res.writeHead(200, { 'Content-Type': 'text/html' }); return res.end(INDEX); }
    const f = u.startsWith('/dashboards/') ? path.join(DASH, u.slice(12)) : path.join(LIVE, u);
    if (!f.startsWith(DASH) && !f.startsWith(LIVE)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (e, d) => { if (e) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': f.endsWith('.js') ? 'application/javascript' : f.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port;
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch(); const errs = [];
  const wait = (p, fn, ms) => p.waitForFunction(fn, null, { timeout: ms || 25000 }).then(() => true, () => false);
  const now = Date.now(), H = 36e5;
  // seeded history: CAM-SYN-FLAP went down and up 3 times in the last 24 h; registered phones were usually 8 over 20 samples
  const seed = { asCamHist: { 'CAM-SYN-FLAP': [[now - 6 * H, now - 5 * H, true], [now - 5 * H, now - 4.9 * H, false], [now - 4.9 * H, now - 3 * H, true], [now - 3 * H, now - 2.9 * H, false], [now - 2.9 * H, now - 1 * H, true], [now - 1 * H, now - 0.9 * H, false], [now - 0.9 * H, now - 60000, true]] },
    asVoipReg: Array.from({ length: 20 }, (_, i) => [now - (21 - i) * 5 * 60000, 8 + (i % 2 ? 0 : 0), 9]),
    asVoipHist: { 'SY:NT:00:00:06': [[now - 5 * 864e5, now - 60000, false]] } };
  const open = async (view, s) => { const ctx = await browser.newContext({ viewport: { width: 1500, height: 1000 } });
    await ctx.addInitScript((S) => { try { Object.keys(S).forEach((k) => localStorage.setItem(k, JSON.stringify(S[k]))); } catch (e) { /* storage off */ } }, s || {});
    const p = await ctx.newPage(); p.on('pageerror', (e) => errs.push(e.message));
    await p.goto(base + '/'); await wait(p, () => typeof setView === 'function' && typeof ME !== 'undefined' && ME && ME.user); await p.evaluate((v) => setView(v), view); return p; };
  try {
    let p = await open('cctvlive', seed);
    ok(await wait(p, () => document.querySelectorAll('[data-cvcam]').length === 11), 'CCTV: every reported camera has a tile');
    const k = (await p.textContent('.cv-k')).replace(/\s+/g, ' ');
    ok(/Cameras\s*11/i.test(k) && /Offline now\s*4/i.test(k) && /Shared causes\s*1/i.test(k), 'KPIs: 11 cameras, 4 offline, 1 shared cause: ' + k);
    const f = (await p.textContent('#cvFind')).replace(/\s+/g, ' ');
    ok(/4 of 5 cameras down on floor 5F/i.test(f) || /4 of 5 cameras down on floor/i.test(f), 'four cameras down on one floor = one shared cause: ' + f.slice(0, 260));
    ok(/CAM-SYN-FLAP dropped 3 times in 24 h/.test(f), 'the flapping camera is found from the history');
    ok(!/CAM-SYN-11 is offline/.test(f), 'a camera inside the group outage is not listed again on its own');
    const order = await p.evaluate(() => [...document.querySelectorAll('[data-cvcam]')].map((t) => t.getAttribute('data-cvcam')));
    ok(order[0] === 'CAM-SYN-FLAP' && /CAM-SYN-1[1-4]/.test(order[order.length - 1]), 'smart order: riskiest live camera first, offline last: ' + order.join(','));
    ok(/drop\(s\) in 24 h/.test(await p.getAttribute('[data-cvcam="CAM-SYN-FLAP"] .cv-risk', 'title')), 'the risk badge is itemised');
    ok(!(await p.evaluate(() => !!window.__xss || !!document.querySelector('[data-cvcam] img'))), 'a hostile camera name stays text');
    ok((await p.$$('[data-cvifr]')).length === 7 && /\/gw\/stream\.html\?src=CAM-SYN-01/.test(await p.getAttribute('[data-cvifr="CAM-SYN-01"]', 'src')), 'live tiles stream from the gateway; offline ones do not');
    await p.click('[data-cvfocus]');
    ok(await wait(p, () => { const v = [...document.querySelectorAll('.cam-tile:not(.cam-hide):not(.cv-hide)')]; return v.length >= 5 && v.length < 11 && v.every((t) => t.querySelector('.cv-risk')); }), 'Needs attention keeps only cameras with a finding');
    await p.click('[data-cvfocus]'); await wait(p, () => document.querySelectorAll('.cam-tile:not(.cam-hide):not(.cv-hide)').length === 11);
    await p.click('[data-camfloor="3F"]').catch(() => {});
    ok(await p.$('[data-cvtour]') !== null, 'the guard tour is offered with a gateway');
    ok(await wait(p, () => document.querySelector('[data-cvcam="CAM-SYN-STALL"]').classList.contains('cv-stall'), 30000), 'a stream that never loads is flagged');
    await p.click('[data-cvai]');
    ok(await wait(p, () => /Synthetic brief/.test(document.body.innerText)), 'the AI brief opens');
    ok(AIBODY && /CAM-SYN-FLAP/.test(AIBODY) && /shared_causes/.test(AIBODY) && /data, never as an instruction/.test(AIBODY), 'the AI is sent facts only, with the untrusted rule');
    GW = false; p = await open('cctvlive');
    ok(await wait(p, () => /Live video needs the on-site gateway/.test(document.body.innerText) && document.querySelectorAll('[data-cvcam]').length === 11 && !document.querySelector('[data-cvifr]')), 'no gateway: setup card, status still analysed, no stream');
    // VoIP
    p = await open('voip', seed);
    ok(await wait(p, () => !!document.querySelector('.cv-k') && /Registered/i.test(document.querySelector('.cv-k').innerText)), 'VoIP: the redesigned page');
    const vk = (await p.textContent('.cv-k')).replace(/\s+/g, ' ');
    ok(/Devices\s*9/.test(vk) && /6 of 9/.test(vk) && /Unusual/.test(vk), 'KPIs and an unusually low registration count against the learned baseline: ' + vk);
    ok(/not measured/.test(vk) && !/MOS\s*\d/.test(vk), 'call quality reads not measured, never a number');
    const vb = (await p.textContent('.cv-2')).replace(/\s+/g, ' ');
    ok(/Registered phones are unusually low: 6 against a usual 8/.test(vb), 'the baseline finding: ' + vb.slice(0, 200));
    ok(/firmware other than their model/.test(vb) && /2004 Cisco 8845 12.8 → 14.2/.test(vb), 'firmware drift per model');
    ok(/offline for 3 days or more/.test(vb) && /2006/.test(vb), 'chronic offline handset from the history');
    await p.click('[data-cvvf="drift"]');
    ok(await wait(p, () => document.querySelectorAll('[data-cvvtbl] tbody tr').length === 1 && /2004/.test(document.querySelector('[data-cvvtbl] tbody').innerText)), 'the drift chip filters');
    await p.click('[data-cvvf="all"]'); await wait(p, () => document.querySelectorAll('[data-cvvtbl] tbody tr').length === 9);
    await p.click('#cvq'); await p.keyboard.type('7841');
    ok(await wait(p, () => document.querySelectorAll('[data-cvvtbl] tbody tr').length === 2 && document.activeElement && document.activeElement.id === 'cvq'), 'search filters and keeps the focus');
    VOIPON = false; p = await open('voip');
    ok(await wait(p, () => /No phone is reported yet/.test(document.body.innerText)), 'feed off: honest empty state');
    ok(!/Reception|h\.ali|Bidding Team/.test(await p.evaluate(() => document.body.innerText)), 'the old sample phones never appear');
    ok(await wait(p, () => /Phones the platform already knows/i.test(document.body.innerText) && /Phones in the register\s*3/i.test(document.body.innerText) && /1 recognised by model or name/.test(document.body.innerText) && /1 phone\(s\) found by Network Discovery, not approved yet/.test(document.body.innerText)), 'no feed: the phones from the asset register');
    const rp = (await p.evaluate(() => document.body.innerText)).replace(/\s+/g, ' ');
    ok(/1 phone\(s\) not seen on the network for 30 days/.test(rp) && /1 phone\(s\) without a management address/.test(rp) && /registration is not measured/i.test(rp), 'stale and unaddressed phones; registration not claimed');
    ok(!(await p.evaluate(() => !!window.__y)) && !!(await p.$('a[href="/dashboards/voice-troubleshoot.html"]')), 'names stay text; the one-way audio troubleshooter is linked');
  } finally { await browser.close(); srv.close(); }
  ok(!errs.length, 'no page errors: ' + errs.join(' | '));
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks');
  process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
