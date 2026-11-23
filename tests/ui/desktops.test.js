// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// User Desktops (desktops.html) and Desktop Patch Management (desktop-patches.html): an engineer assigned to branches opens on
// "my branches", filters by branch card / state chip / search, starts remote support with a reason (commands shown as text,
// copied), closes the session with an outcome, reads one desktop's patches; the AI Desktop Support card shows its queue. An
// admin saves the remote-support link and the engineers' branches. Patch Management: compliance by branch, tick patches,
// deploy to a branch (sent for approval) and scan. Branch cards show the branch's printers; the Printers page filters by
// branch (cards, drop-down, ?branch=, the engineer's own branches) and counts the tiles for it. A viewer sees branch counts only. Stubbed API, SYNTHETIC data.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node desktops.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0, WHO = { user: 'faisal.syn', role: 'operator' };
const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
const asked = [], posted = [];
const BR = [{ branch: 'Dammam Branch', desktops: 1, agent_offline: 0, agent_missing: 0, critical_missing: 0, compliance_pct: 100, tickets: 0 }, { branch: 'Riyadh HQ', desktops: 2, agent_offline: 1, agent_missing: 0, critical_missing: 1, compliance_pct: 50, tickets: 1 }];
const DESK = [
  { id: 'a-1', asset_id: 'a-1', resource_id: '301', name: 'RUH-PC-001', user: 'ali.syn', branch: 'Riyadh HQ', ip: '10.20.1.11', os: 'Windows 11', agent: 'live', last_contact: Date.parse('2026-10-27T05:00:00Z'), patch: { health: 'highly vulnerable', missing: 14, critical: 3 }, tickets: 1 },
  { id: 'ec:302', asset_id: null, resource_id: '302', name: 'RUH-PC-002', user: 'noura.syn', branch: 'Riyadh HQ', ip: '10.20.1.12', os: 'Windows 10', agent: 'offline', patch: { health: 'healthy', missing: 0, critical: 0 }, tickets: 0 },
  { id: 'a-9', asset_id: 'a-9', resource_id: null, name: 'DMM-LT-009', user: '<b>khalid</b>', branch: 'Dammam Branch', ip: '', os: '', agent: 'missing', patch: { health: null, missing: null, critical: null }, tickets: 0 }];
let settings = { remote: { ec_url: '', msra: true, rdp: true }, engineers: [{ user: 'faisal.syn', branches: ['Riyadh HQ'] }] };
const sessions = [];
(async () => {
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x'), json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    const body = () => new Promise((r) => { let b = ''; req.on('data', (c) => { b += c; }); req.on('end', () => r(b ? JSON.parse(b) : {})); });
    const p = u.pathname;
    if (p === '/dashboards/whoami.json') return json(200, WHO);
    if (p === '/api/itam/desktops') {
      asked.push(Object.fromEntries(u.searchParams));
      const b = u.searchParams.get('branch'), st = u.searchParams.get('state'), q = (u.searchParams.get('q') || '').toLowerCase();
      const want = b === 'mine' ? ['Riyadh HQ'] : b ? [b] : null;
      const rows = DESK.filter((d) => (!want || want.includes(d.branch)) && (!st || (st === 'offline' && d.agent === 'offline') || (st === 'no_agent' && d.agent === 'missing')) && (!q || (d.name + d.user).toLowerCase().includes(q)));
      return json(200, { generated_at: '2026-10-27T06:00:00Z', branches: BR, my_branches: ['Riyadh HQ'], total: 3, shown: rows.length, desktops: rows, source: { ec_configured: true, last_sync: { at: '2026-10-27T05:30:00Z' } } });
    }
    if (p === '/api/itam/desktops/summary') return json(200, { branches: BR });
    if (p === '/api/itam/desktops/settings' && req.method === 'GET') return json(200, settings);
    if (p === '/api/itam/desktops/settings' && req.method === 'POST') return body().then((b) => { posted.push(['settings', b]); settings = Object.assign({}, b); json(200, settings); });
    if (p === '/api/itam/desktops/remote/sessions') return json(200, { sessions });
    if (/^\/api\/itam\/desktops\/[^/]+\/remote$/.test(p)) return body().then((b) => { posted.push(['remote', b]); const s = { id: 'rs_1', desktop: 'RUH-PC-001', branch: 'Riyadh HQ', end_user: 'ali.syn', engineer: 'faisal.syn', reason: b.reason, ticket: b.ticket || null, status: 'open', started_at: '2026-10-27T06:01:00Z' }; sessions.push(s);
      json(200, { session: s, links: [{ kind: 'endpointcentral', label: 'Endpoint Central remote control', url: 'https://ec.syn.test/rc?resourceId=301' }], commands: [{ kind: 'msra', label: 'Windows Remote Assistance', command: 'msra /offerra <img src=x>ruh-pc-001' }], consent: 'Tell the user' }); });
    if (/^\/api\/itam\/desktops\/remote\/[^/]+\/end$/.test(p)) return body().then((b) => { posted.push(['end', b]); Object.assign(sessions[0], { status: 'closed', outcome: b.outcome, note: b.note }); json(200, { session: sessions[0] }); });
    if (/^\/api\/itam\/desktops\/[^/]+\/patches$/.test(p)) return json(200, { desktop: { id: 'a-1', name: 'RUH-PC-001', branch: 'Riyadh HQ' }, missing: 1, patches: [{ patch_id: '9001', name: 'KB5044284 Cumulative Update', severity: 'critical', status: 'missing' }] });
    if (p === '/api/itam/desktops/patches') return json(200, { available: true, counts: { patches: 2, missing: 1, critical_missing: 1, important_missing: 0 }, patches: [{ patch_id: '9001', name: 'KB5044284 Cumulative Update', severity: 'critical', missing: 40, installed: 200, released: Date.parse('2026-10-08') }, { patch_id: '9002', name: 'Adobe Reader', severity: 'moderate', missing: 0, installed: 240 }] });
    if (/^\/api\/itam\/desktops\/patches\/(deploy|scan)$/.test(p)) return body().then((b) => { posted.push([p.split('/').pop(), b]); json(200, { requests: [{ id: 'ma_1', label: 'Install patches', computers: 2, status: 'pending' }], computers: 2, without_agent: 0, approval: 'a different person approves each request' }); });
    if (p === '/api/soc/printers') return json(200, { summary: { total: 3, ok: 1, warning: 1, error: 0, offline: 1, toner_low: 0, pages_today: 30, pages_30d: 900 }, stats: {}, items: [
      { id: 'pr1', name: 'RUH-XRX-01', ip: '10.20.9.1', site: 'Riyadh HQ', status: 'offline', issues: [], pages_today: 10, pages_30d: 300, snapshot: {} },
      { id: 'pr2', name: 'RUH-XRX-02', ip: '10.20.9.2', site: 'Riyadh HQ', status: 'warning', issues: [{ level: 'warn', text: 'Paper jam' }], pages_today: 15, pages_30d: 400, snapshot: {} },
      { id: 'pr3', name: 'DMM-XRX-01', ip: '10.40.9.1', site: 'Dammam Branch', status: 'ok', issues: [], pages_today: 5, pages_30d: 200, snapshot: {} }] });
    if (p.startsWith('/api/soc/printers/')) return json(404, { error: 'not in this test' });
    if (p === '/api/itam/me/desk') return json(200, { config: { mode: 'suggest' }, triage: [{}, {}], desktops: { items: [{}] }, patch_proposals: [{ status: 'pending' }] });
    if (p.startsWith('/api/')) return json(404, { error: 'not found' });
    const f = path.join(DASH, p.replace(/^\/dashboards\//, '/')); if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (err, d) => { if (err) { res.writeHead(404); res.end(); return; } res.writeHead(200, { 'Content-Type': p.endsWith('.js') ? 'application/javascript' : p.endsWith('.css') ? 'text/css' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const ctx = await browser.newContext({ viewport: { width: 1400, height: 950 } }); await ctx.grantPermissions(['clipboard-read', 'clipboard-write']);
  const base = 'http://127.0.0.1:' + srv.address().port + '/dashboards/';
  let page;
  const open = async (who, file) => { WHO = who; if (page) await page.close(); page = await ctx.newPage(); page.on('pageerror', (x) => errs.push(x.message)); await page.goto(base + file); await page.waitForTimeout(400); };
  const txt = (sel) => page.$eval(sel, (x) => x.innerText.replace(/\s+/g, ' '));
  try {
    await open({ user: 'faisal.syn', role: 'operator' }, 'desktops.html');
    await page.waitForSelector('[data-rem]');
    ok(asked[0].branch === 'mine', 'an engineer with assigned branches opens on them: ' + JSON.stringify(asked[0]));
    ok(/RUH-PC-001/.test(await txt('#list')) && !/DMM-LT-009/.test(await txt('#list')), 'only my branch listed');
    ok(/My branches \(Riyadh HQ\)/.test(await txt('#fb')), 'branch filter offers my branches');
    ok(/50% compliant/.test(await txt('#br')) && /1 agent offline/.test(await txt('#br')), 'branch cards with compliance and problems');
    await page.click('[data-br="Dammam Branch"]'); await page.waitForFunction(() => /DMM-LT-009/.test(document.getElementById('list').innerText));
    ok(asked[asked.length - 1].branch === 'Dammam Branch', 'clicking a branch filters');
    await page.waitForFunction(() => /2 printers/.test(document.getElementById('br').innerText));
    ok(/2 printers · 1 offline · 1 need attention/.test(await txt('#br')) && await page.$('#br a[href="printers.html?branch=Riyadh%20HQ"]'), 'branch card shows its printers with a link to Printers');
    ok(!(await page.$('#list b b')) && /<b>khalid<\/b>/.test(await txt('#list')), 'values are escaped');
    ok(/no agent/.test(await txt('#list')) && !(await page.$('[data-pat="a-9"]')), 'a desktop without the agent says so and has no Patches button');
    await page.click('[data-br="Dammam Branch"]'); await page.click('[data-st="offline"]'); await page.waitForFunction(() => !/RUH-PC-001/.test(document.getElementById('list').innerText));
    ok(asked[asked.length - 1].state === 'offline' && /RUH-PC-002/.test(await txt('#list')), 'state chip filters');
    await page.click('[data-st=""]'); await page.fill('#q', 'ali'); await page.waitForFunction(() => /RUH-PC-001/.test(document.getElementById('list').innerText) && !/RUH-PC-002/.test(document.getElementById('list').innerText));
    ok(asked[asked.length - 1].q === 'ali', 'search');
    ok(/suggest/.test(await txt('#ai')) && /2 tickets waiting/.test(await txt('#ai')) && /1 patch installs proposed/.test(await txt('#ai')), 'AI Desktop Support card');
    // remote support
    await page.click('[data-rem="a-1"]'); await page.waitForSelector('#r-why');
    await page.fill('#r-why', 'no'); await page.click('#r-go'); ok(/at least 5/.test(await txt('#r-out')), 'a reason is required');
    await page.fill('#r-why', 'Outlook asks for the password'); await page.fill('#r-tk', 'SDP-4412'); await page.click('#r-go'); await page.waitForSelector('#r-c0');
    const rp = posted.find((x) => x[0] === 'remote'); ok(rp && rp[1].reason === 'Outlook asks for the password' && rp[1].ticket === 'SDP-4412', 'reason and ticket sent');
    ok(/<img src=x>/.test(await page.textContent('#r-c0')) && !(await page.$('#r-out img')), 'the command is text');
    ok(await page.$('#r-out a[href="https://ec.syn.test/rc?resourceId=301"][target="_blank"][rel~="noopener"]'), 'Endpoint Central remote-control link');
    await page.click('[data-copycmd="r-c0"]'); ok(/msra \/offerra/.test(await page.evaluate(() => navigator.clipboard.readText())), 'Copy puts the command on the clipboard');
    await page.keyboard.press('Escape');
    await page.waitForFunction(() => /Outlook asks for the password/.test(document.getElementById('rs').innerText));
    await page.click('[data-end="rs_1"]'); await page.waitForSelector('#e-go'); await page.selectOption('#e-out', 'resolved'); await page.fill('#e-note', 'cleared cached credentials'); await page.click('#e-go');
    await page.waitForFunction(() => /resolved/.test(document.getElementById('rs').innerText));
    const ep = posted.find((x) => x[0] === 'end'); ok(ep && ep[1].outcome === 'resolved' && ep[1].note === 'cleared cached credentials', 'session closed with the outcome');
    await page.click('[data-pat="a-1"]'); await page.waitForFunction(() => /KB5044284/.test(document.getElementById('zd-b').innerText));
    ok(/critical/.test(await txt('#zd-b')), 'one desktop\'s patches'); await page.keyboard.press('Escape');
    ok(await page.isHidden('#setc'), 'an engineer has no settings');
    // admin settings
    await open({ user: 'syed', role: 'admin' }, 'desktops.html'); await page.waitForSelector('#s-eng');
    await page.waitForFunction(() => /faisal\.syn: Riyadh HQ/.test(document.getElementById('s-eng').value));
    await page.fill('#s-ec', 'https://ec.syn.test/rc?resourceId={resource_id}'); await page.fill('#s-eng', 'faisal.syn: Riyadh HQ, Dammam Branch\nomar.syn: Jeddah Branch');
    await page.uncheck('#s-rdp'); await page.click('#s-save'); await page.waitForFunction(() => /Settings saved/.test(document.body.innerText));
    const sp = posted.find((x) => x[0] === 'settings')[1];
    ok(sp.remote.ec_url === 'https://ec.syn.test/rc?resourceId={resource_id}' && sp.remote.rdp === false && sp.engineers.length === 2 && sp.engineers[0].branches.join('|') === 'Riyadh HQ|Dammam Branch', 'settings sent: ' + JSON.stringify(sp).slice(0, 200));
    await page.fill('#s-eng', 'no colon here'); await page.click('#s-save'); ok(/line 1/.test(await txt('#s-err')), 'a bad line is named');
    // patch management
    await open({ user: 'faisal.syn', role: 'operator' }, 'desktop-patches.html'); await page.waitForSelector('[data-pid="9001"]');
    ok(/Critical missing 1/i.test(await txt('#kk')), 'tiles'); ok(/Riyadh HQ[\s\S]*50%/.test(await txt('#br')), 'compliance by branch');
    ok(!(await page.$('[data-pid="9002"]')), 'only patches missing somewhere by default');
    ok(await page.isDisabled('#dep'), 'nothing ticked: deploy disabled');
    await page.check('[data-pid="9001"]'); await page.selectOption('#db', 'Riyadh HQ'); await page.fill('#dr', 'October cumulative update'); await page.click('#dep');
    await page.waitForFunction(() => /ma_1/.test(document.getElementById('dout').innerText));
    const dp = posted.find((x) => x[0] === 'deploy')[1]; ok(dp.branch === 'Riyadh HQ' && dp.patch_ids.join() === '9001' && dp.reason === 'October cumulative update', 'deploy request: ' + JSON.stringify(dp));
    ok(/different person approves/.test(await txt('#dout')), 'says it waits for approval');
    await page.click('#scan'); await page.waitForTimeout(200); const sc = posted.find((x) => x[0] === 'scan'); ok(sc && !sc[1].patch_ids, 'branch scan request');
    // printers by branch: the engineer opens on their branches; cards, drop-down and ?branch= filter; tiles follow the branch
    settings = { remote: settings.remote, engineers: [{ user: 'faisal.syn', branches: ['Riyadh HQ'] }] };
    await open({ user: 'faisal.syn', role: 'operator' }, 'printers.html'); await page.waitForFunction(() => /RUH-XRX-01/.test(document.getElementById('tbl').innerText) && !/DMM-XRX-01/.test(document.getElementById('tbl').innerText));
    ok(/My branches \(Riyadh HQ\)/.test(await txt('#fb')), 'printers: my branches offered and chosen');
    ok(/Printers 2/.test(await txt('#kpi')) && /Offline 1/.test(await txt('#kpi')), 'printers: tiles counted for the branch: ' + (await txt('#kpi')));
    await page.click('[data-br="Dammam Branch"]'); await page.waitForFunction(() => /DMM-XRX-01/.test(document.getElementById('tbl').innerText) && !/RUH-XRX/.test(document.getElementById('tbl').innerText));
    ok(true, 'printers: a branch card filters');
    await page.selectOption('#fb', ''); await page.waitForFunction(() => /3 of 3/.test(document.getElementById('cnt').innerText)); ok(true, 'printers: all branches');
    await open({ user: 'faisal.syn', role: 'operator' }, 'printers.html?branch=Dammam%20Branch'); await page.waitForFunction(() => /1 of 3/.test(document.getElementById('cnt').innerText));
    { const tb = await txt('#tbl'); ok(/DMM-XRX-01/.test(tb), 'printers: ?branch= opens filtered, over the engineer\'s own branches (link from User Desktops)'); }
    // viewer
    await open({ user: 'v.syn', role: 'viewer' }, 'desktops.html'); await page.waitForFunction(() => /Riyadh HQ/.test(document.getElementById('br').innerText));
    ok(await page.isVisible('#denied') && await page.isHidden('#listc'), 'a viewer sees branch counts only');
    await open({ user: 'v.syn', role: 'viewer' }, 'desktop-patches.html'); ok(await page.isVisible('#denied') && await page.isHidden('#body'), 'a viewer cannot use Patch Management');
    ok(!errs.length, 'page errors: ' + errs.join(' | '));
  } finally { await browser.close(); srv.close(); }
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
