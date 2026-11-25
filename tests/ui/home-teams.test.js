// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('../../brand/index');
// Browser test for the home page team homes (dashboards/server/index.html): Global Admin sees the three team cards and all
// 19 workspaces and may open any team's home; a person lands on their own team's home from their job role (built-in role
// id, a custom "Application ..." role, or what the role manages); their tiles, queue and AI engineers count only their
// team's items; the real the organisation and Zyberon logos are shown; a missing source says so.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node home-teams.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const DASH = path.resolve(__dirname, '../../ui');
let n = 0, bad = 0;
const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };

// the organisation's brand setting decides what the home shows: no SAMA tile or Business Risk workspace where they are switched off
// (modules_off), its company look on by default unless company_look is false, its own pages in place of switched-off ones (pages_off)
const MOFF = ZYB_ORG.modules_off || [], POFF = ZYB_ORG.pages_off || [], SAMA_ON = !MOFF.includes('fw-sama'), BRISK_ON = !MOFF.includes('brisk'), LOOK_DEF = ZYB_ORG.company_look !== false;
let GATE = 'admin', ME = null, DUTY = true, SOCOV = 'ok';
const OVERVIEW = { generated_at: Date.now(), open: { total: 17, by_severity: [1, 4, 5, 4, 3], unassigned: 6, bands: { 'act-now': 2, investigate: 5, review: 4, low: 3, 'likely-noise': 3 }, new_24h: 9 },
  mtta_min: 42, mttr_min: 1500, act_now: [{ id: 'al-1', rule_name: '<img src=x onerror=alert(1)> Brute force on VPN (synthetic)', priority: 96, severity: 4, entities: ['vpn-gw-syn', 'user.syn'], summary: 'synthetic' }, { id: 'al/2', rule_name: 'Impossible travel (synthetic)', priority: 88, severity: 3, entities: ['user2.syn'] }],
  xdr: { summary: {}, top: [{ id: 'x1', title: 'Phishing to workstation (synthetic)', score: 91, domains: ['email', 'endpoint'] }] }, ueba: { top: [{ id: 'u1', name: 'user3.syn', type: 'user', score: 77, tier: 'high' }] },
  ai: { drafts: 4, agreement_pct: null }, model: { days: 14, alerts: 320 }, sources_connected: { xdr: true, ueba: true } };
const SIEM_ITEMS = [
  { id: 'a', engineer: 'network', severity: 'critical', status: 'open' }, { id: 'b', engineer: 'network', severity: 'low', status: 'awaiting-approval' },
  { id: 'c', engineer: 'siem', severity: 'high', status: 'open' }, { id: 'd', engineer: 'security', severity: 'high', status: 'awaiting-approval' },
  { id: 'e', engineer: 'apps', severity: 'high', status: 'open' }, { id: 'f', engineer: 'dba', severity: 'medium', status: 'open' },
  { id: 'g', engineer: 'pdpl', severity: 'medium', status: 'open' }, { id: 'h', engineer: 'itaudit', severity: 'low', status: 'open' }];
const ENG = [{ id: 'network', name: 'AI Network Engineer' }, { id: 'security', name: 'AI Security Engineer' }, { id: 'siem', name: 'AI SIEM Engineer' }, { id: 'apps', name: 'AI Application Manager' }, { id: 'dba', name: 'AI Oracle DBA' }, { id: 'windows', name: 'AI Windows Server Administrator', enabled: false }];

(async () => {
  const srv = http.createServer((req, res) => {
    const u = decodeURIComponent(req.url.split('?')[0]), json = (c, o) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(o)); };
    if (u === '/dashboards/whoami.json') return json(200, { user: 'syed', role: GATE });
    if (u === '/api/itam/roles/me') return ME ? json(200, ME) : json(404, { error: 'not installed' });
    if (u === '/api/soc/duty/items') return DUTY ? json(200, { items: SIEM_ITEMS }) : json(404, {});
    if (u === '/api/soc/duty/engineers') return DUTY ? json(200, { engineers: ENG }) : json(404, {});
    if (u === '/api/soc/soc/overview') return SOCOV === 'ok' ? json(200, OVERVIEW) : json(503, { error: 'down' });
    if (u === '/api/soc/approvals') return DUTY ? json(200, { items: [{ status: 'pending' }] }) : json(404, {});
    if (u.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = path.join(DASH, u === '/' ? 'index.html' : u.replace(/^\/dashboards\//, '/'));
    if (!f.startsWith(DASH)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (e, d) => { if (e) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': u.endsWith('.js') ? 'application/javascript' : 'text/html' }); res.end(d); });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/index.html';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch(), errs = [];
  const open = async (q, settle) => {
    const page = await browser.newPage({ viewport: { width: 1400, height: 1000 } }); page.on('pageerror', (e) => errs.push(e.message));
    await page.goto(base + (q || '')); await page.waitForFunction(() => window.zybHomeTeams && !/Loading/.test(document.getElementById('st-ai').textContent));
    await page.waitForTimeout(settle || 300);
    return page;
  };
  const state = (page) => page.evaluate(() => {
    const vis = (id) => !document.getElementById(id).hidden, v = (id) => document.querySelector('#' + id + ' .v').textContent;
    return { label: document.getElementById('teamlabel').textContent, ws: [...document.querySelectorAll('.wk')].map((w) => w.dataset.ws), teams: document.querySelectorAll('.tm').length,
      teambar: vis('teambar'), duo: vis('duo'), tiles: [...document.querySelectorAll('.st')].filter((s) => !s.hidden && !s.closest('#grc')).map((s) => s.id), grc: [...document.querySelectorAll('#grc .st')].map((s) => s.id + '=' + s.querySelector('.v').textContent), brand: document.getElementById('zsplate').textContent + '|' + document.title + '|' + document.querySelector('.ttl .org').textContent, dec: v('st-dec'), prob: v('st-prob'), ai: v('st-ai'),
      engs: [...document.querySelectorAll('#engs .row b')].map((b) => b.textContent), queue: [...document.querySelectorAll('#tq .row span')].map((s) => s.textContent),
      quick: [...document.querySelectorAll('.qa')].map((a) => a.getAttribute('href')), also: [...document.querySelectorAll('#also a')].map((a) => a.getAttribute('href')),
      open: Object.fromEntries([...document.querySelectorAll('[data-open]')].map((b) => [b.dataset.open, b.textContent])),
      logo: (document.querySelector('#orglogo img') || {}).src || '', zlogo: (document.querySelector('#mark img') || {}).src || '', zfoot: !!document.querySelector('#zfoot img') };
  });

  // ---- Global Admin: every workspace, in menu order (PDPL has its own menu group and workspace since the PDPL pages split out)
  const ALL_WS = ['cmd', 'soc', 'pt', 'eps', 'usr', 'net', 'srv', 'stor', 'db', 'eud', 'app', 'ast', 'grc', 'brisk', 'cmp', 'pdpl', 'aud', 'adm', 'ai'].filter((w) => w !== 'brisk' || BRISK_ON);
  let page = await open(); let s = await state(page);
  ok(s.label === 'Global Admin' && s.teams === 6 && JSON.stringify(s.ws) === JSON.stringify(ALL_WS) && s.teambar && !s.duo, 'global admin: 6 team cards (Data Privacy and Audit & Assurance separate from Risk & Compliance), ' + ALL_WS.length + ' workspaces (Business Risk where the organisation has it, Compliance, Data Privacy, Audit and Pentest have their own; printers and voice under Workplace), team switcher: ' + JSON.stringify({ l: s.label, t: s.teams, w: s.ws, b: s.teambar }));
  ok(s.tiles.length === 5, 'global: 5 live tiles');
  ok(s.dec === '3' && s.prob === '3', 'global counts everything (2 awaiting + 1 SOC approval; 3 critical/high): ' + s.dec + ' / ' + s.prob);
  ok(JSON.stringify(s.open) === '{"infra":"3","cyber":"2","app":"2","risk":"0","privacy":"1","audit":"1"}', 'team cards: open items per team (dba counts for infra and apps): ' + JSON.stringify(s.open));
  ok(/^data:image\/(webp|png|jpeg|svg\+xml);base64,/.test(s.logo) && /^data:image\/webp;base64,/.test(s.zlogo) && s.zfoot, ('real ' + ZYB_ORG.short + ' and Zyberon logos shown'));
  ok(await page.evaluate(() => document.querySelector('#orglogo img').alt) === ZYB_ORG.name, 'logo alt text');
  const gb = await page.evaluate(() => ({ brand: document.getElementById('zsplate').textContent, title: document.title, grc: [...document.querySelectorAll('#grc .st')].map((t) => [t.id, t.getAttribute('href'), t.querySelector('.v').textContent]) }));
  ok(gb.brand === 'ZYBERON SENTRA' && /^Zyberon Sentra — IT Operations & Cyber Security Automation & Monitoring Platform$/.test(gb.title), 'brand: ZYBERON SENTRA first, the platform name in the tab: ' + gb.brand + ' | ' + gb.title);
  const GRC = SAMA_ON ? [['grc-er', 'enterprise-risk.html'], ['grc-sama', 'sama-audit.html'], ['grc-nca-ecc', 'nca-ecc.html'], ['grc-pdpl', 'pdpl-dashboard.html'], ['grc-ndmo', 'ndmo.html']]
    : [['grc-nca-ecc', 'nca-ecc.html'], ['grc-iso27001', 'iso27001.html'], ['grc-pdpl', 'pdpl-dashboard.html'], ['grc-aramco', 'aramco-ccc.html'], ['grc-ndmo', 'ndmo.html']];   // not under SAMA: NCA ECC, ISO 27001, PDPL, Aramco CCC, NDMO
  ok(gb.grc.map((x) => x[0]).join() === GRC.map((x) => x[0]).join() && gb.grc.map((x) => x[1]).join() === GRC.map((x) => x[1]).join() && !gb.grc.some((x) => POFF.includes(x[1].replace(/\.html$/, ''))),
    'compliance tiles for the frameworks the organisation is under, each opening its dashboard: ' + JSON.stringify(gb.grc.map((x) => x[0])));
  ok(await page.waitForFunction(() => [...document.querySelectorAll('#grc .st .v')].every((v) => v.textContent !== 'Loading…'), null, { timeout: 15000 }).then(() => true, () => false), 'every GRC tile answered');
  const gv = await page.evaluate(() => [...document.querySelectorAll('#grc .st .v')].map((v) => v.textContent));
  ok(gv.every((v) => /^(\d+%|\d+ \/ 100|not assessed|not connected|no access|not installed|not reachable)$/.test(v)) && !gv.includes('0%'), 'a real score or why there is none - never an invented 0: ' + gv.join(' | '));
  // brand colours switch: the Zyberon Sentra design by default; the organisation green when switched on, kept after a reload
  // brand colours switch (the page tests run with the platform's own design as the default; sector-profile.test.js checks
  // the organisation's default): the company look when switched on, saved, and back
  // the switch starts at the organisation's default (company_look) and flips both ways; each choice is saved
  const look = () => page.evaluate(() => ({ media: document.getElementById('orgBrand').media + '|' + document.getElementById('orgLight').media, on: document.documentElement.classList.contains('org-brand'),
    sw: document.getElementById('brandsw').getAttribute('aria-checked'), side: (document.querySelector('#zyb-side [data-zyb-brandsw]') || {}).getAttribute ? document.querySelector('#zyb-side [data-zyb-brandsw]').getAttribute('aria-checked') : null,
    saved: JSON.parse(localStorage.getItem('zyb-dash-prefs') || '{}').brand }));
  let L = await look();
  ok(L.on === LOOK_DEF && L.sw === String(LOOK_DEF), 'brand: the ' + (LOOK_DEF ? ZYB_ORG.short + ' colours' : 'platform design') + ' by default (company_look): ' + JSON.stringify(L));
  if (!LOOK_DEF) { await page.click('#brandsw'); L = await look(); }
  ok(L.on && /\ball\b/.test(L.media), ('brand: the ' + ZYB_ORG.short + ' colours on'));
  ok(await page.evaluate(() => getComputedStyle(document.querySelector('main .btn.pri')).backgroundColor) === 'rgb(' + [1, 3, 5].map((i) => parseInt(ZYB_ORG.colors.primary.slice(i, i + 2), 16)).join(', ') + ')', ('brand: the primary action is in the ' + ZYB_ORG.short + ' colour (brand setting colors.primary)'));
  await page.click('#brandsw'); L = await look();
  ok(!L.on && L.media === 'not all|not all' && L.saved === 'off', 'brand: switched to the platform design and saved: ' + JSON.stringify(L));
  // the same switch in the menu: one choice for the menu and the page
  await page.click('#zyb-side [data-zyb-brandsw]'); L = await look();
  ok(L.on && L.sw === 'true' && L.saved === 'org', 'brand: the menu switch turns the page and the menu to the company colours, the page switch follows and it is saved: ' + JSON.stringify(L));
  await page.click('#brandsw'); L = await look();
  ok(L.side === 'false' && !L.on, 'brand: the page switch turns it off in the menu too');
  const regs = await page.evaluate(() => { const r = document.getElementById('regs'), b = r.getBoundingClientRect(), f = document.querySelector('.foot').getBoundingClientRect();
    return { shown: !r.hidden, href: r.getAttribute('href'), alts: [...r.querySelectorAll('img')].map((i) => i.alt), h: Math.round(r.querySelector('img').getBoundingClientRect().height), right: Math.round(f.right - b.right) }; });
  ok(regs.shown && regs.href === 'compliance-map.html' && regs.alts.join('|') === (ZYB_ORG.frameworks.includes('nca') ? 'National Cybersecurity Authority (NCA)' : ''), 'the frameworks of the brand setting in the footer (a regulator mark where there is one), linking to the Compliance Map: ' + JSON.stringify(regs));
  ok(regs.h <= 28 && regs.right <= 2, 'regulator logos small (<=28px) and at the bottom right: ' + regs.h + 'px, ' + regs.right + 'px from the right');
  ok(s.quick.includes('roles.html') && s.quick.includes('connections.html'), 'global quick actions: ' + s.quick);
  await Promise.all([page.waitForURL(/team=cyber/), page.click('.tm[data-team="cyber"]')]); await page.waitForFunction(() => window.zybHomeTeams && document.getElementById('teamlabel')); await page.waitForFunction(() => document.getElementById('teamlabel').textContent === 'Cyber Security team');
  ok(/team=cyber/.test(page.url()), 'a team card opens that team home');
  await page.close();

  // ---- admin previewing a team home
  page = await open('?team=cyber'); s = await state(page);
  ok(s.label === 'Cyber Security team' && JSON.stringify(s.ws) === '["soc","pt","eps","usr"]' && s.teams === 0 && s.duo, 'cyber home: its 4 workspaces (incident response inside Security Operations), no team cards: ' + s.ws);
  ok(JSON.stringify(s.tiles) === '["st-dec","st-prob","st-ai"]', 'cyber tiles: decisions, problems, AI engineers (no server / database tiles): ' + s.tiles);
  ok(s.dec === '2' && s.prob === '1', 'cyber counts only its engineers (+ SOC approval): ' + s.dec + ' / ' + s.prob);
  ok(JSON.stringify(s.engs) === '["AI Security Engineer","AI SIEM Engineer"]', 'cyber AI engineers: ' + s.engs);
  ok(JSON.stringify(s.queue) === '["1","1","0"]', 'cyber queue: ' + s.queue);
  ok(s.teambar && (await page.evaluate(() => document.querySelector('#teambar a.on').dataset.team)) === 'cyber', 'admin keeps the switcher, cyber marked current');
  { const soc = await page.evaluate(() => [...document.querySelectorAll('.wk[data-ws="soc"] li a')].map((a) => a.getAttribute('href')));
    ok(soc.length >= 25 - POFF.length && soc.length >= 20 && !soc.some((h) => POFF.includes(h.replace(/\.html$/, ''))) && ['soc-live.html', 'incident-response.html', 'soar.html', 'dfir.html', 'alarm-rules.html'].every((h) => soc.includes(h)),
      'team workspaces list every page the organisation uses (Security Operations: monitor, investigate, respond (incident response, playbooks, SOAR, DFIR) and the SIEM platform with Alarm Inbox Rules): ' + soc.length); }
  ok(s.also.length >= 1 && s.also.length <= 4 && !s.also.some((h) => POFF.includes(h.replace(/\.html$/, ''))), 'also-useful links (none the organisation switched off): ' + s.also);
  ok(JSON.stringify(await page.evaluate(() => [...document.querySelectorAll('#teambar a')].map((a) => a.dataset.team))) === '["all","infra","cyber","soc","app","risk","privacy","audit","pentest","network","virt","windows","exchange","backup"]', 'switcher offers the department homes, then each engineer home');
  await page.close();

  // ---- the two new homes, previewed by an admin
  page = await open('?team=privacy'); s = await state(page);
  ok(s.label === 'Data Privacy team' && JSON.stringify(s.ws) === '["pdpl"]' && s.quick.includes('pdpl-dsar.html') && s.quick.includes('pdpl-breach.html'), 'data privacy home: PDPL workspace and quick actions: ' + JSON.stringify({ l: s.label, w: s.ws, q: s.quick }));
  await page.close();
  page = await open('?team=audit'); s = await state(page);
  ok(s.label === 'Audit & Assurance team' && JSON.stringify(s.ws) === '["aud"]' && s.quick.includes('audit-command.html'), 'audit home: Audit workspace and quick actions: ' + JSON.stringify({ l: s.label, w: s.ws, q: s.quick }));
  await page.close();
  page = await open('?team=risk'); s = await state(page);
  ok(s.label === 'Risk & Compliance team' && JSON.stringify(s.ws) === '["grc","cmp"]', 'risk home no longer carries privacy and audit: ' + s.ws);
  await page.close();

  // ---- an operator lands on their own team; ?team= cannot switch them
  GATE = 'operator'; ME = { role: { id: 'network-admin', name: 'Network Admin', base: 'operator', functions: { network: 'manage' } } };
  page = await open('?team=cyber'); s = await state(page);
  ok(s.label === 'IT Infrastructure team' && JSON.stringify(s.ws) === '["srv","db","net","stor"]' && !s.teambar, 'network admin: infrastructure home, no switcher, ?team ignored: ' + s.label);
  ok(s.dec === '1' && s.prob === '1', 'infra counts network + dba items only: ' + s.dec + ' / ' + s.prob);
  ok(JSON.stringify(s.engs) === '["AI Network Engineer","AI Oracle DBA","AI Windows Server Administrator"]', 'infra AI engineers: ' + s.engs);
  ok(await page.evaluate(() => document.querySelector('#engs .row:last-child span').textContent) === 'off', 'a switched-off AI engineer says off');
  ok(s.ai === '2', 'infra AI on duty: 2 of 3 active: ' + s.ai);
  ok(s.quick.includes('capacity.html') && (POFF.includes('sdwan') ? !s.quick.includes('sdwan.html') : s.quick.includes('sdwan.html')), 'infra quick actions (SD-WAN only where the organisation has it): ' + s.quick);
  await page.close();

  ME = { role: { id: 'r-17', name: 'Application Admin', base: 'operator', functions: { servers: 'manage' } } };
  page = await open(); s = await state(page);
  ok(s.label === 'Applications team' && JSON.stringify(s.ws) === '["app","db","usr"]', 'a custom "Application Admin" role gets the Applications home: ' + s.label);
  ok(JSON.stringify(s.tiles) === '["st-dec","st-prob","st-db","st-ai"]' && s.prob === '1', 'applications tiles and counts');
  await page.close();

  ME = { role: { id: 'r-9', name: 'Threat Hunters', base: 'operator', functions: { soc: 'manage' } } };
  page = await open(); ok((await state(page)).label === 'Security Operations (SOC) team', 'a custom role that manages only the SOC gets the SOC home'); await page.close();
  ME = { role: { id: 'r-10', name: 'Security Team', base: 'operator', functions: { soc: 'manage', identity: 'manage' } } };
  page = await open(); ok((await state(page)).label === 'Cyber Security team', 'a wider security role (SOC and identity) keeps the Cyber Security home'); await page.close();
  ME = { role: { id: 'dpo', name: 'Data Protection Officer', base: 'operator', functions: {} } };
  page = await open(); ok((await state(page)).label === 'Data Privacy team', 'the DPO lands on the Data Privacy home'); await page.close();
  ME = { role: { id: 'internal-auditor', name: 'Internal Auditor', base: 'viewer', functions: {} } };
  page = await open(); ok((await state(page)).label === 'Audit & Assurance team', 'the internal auditor lands on the Audit home'); await page.close();
  ME = { role: { id: 'r-31', name: 'Privacy Desk', base: 'operator', functions: { privacy: 'manage' } } };
  page = await open(); ok((await state(page)).label === 'Data Privacy team', 'a custom role that manages privacy gets the Data Privacy home'); await page.close();
  // ---- the SOC home: the SOC analyst lands there; the SOC at a glance from the SIEM
  GATE = 'operator'; ME = { role: { id: 'soc-analyst', name: 'SOC Analyst', base: 'operator', functions: { soc: 'manage', incidents: 'manage' } } };
  page = await open('', 800); s = await state(page);
  ok(s.label === 'Security Operations (SOC) team' && JSON.stringify(s.ws) === '["soc"]' && !s.teambar, 'SOC analyst: lands on the SOC home, SOC workspace only: ' + JSON.stringify({ l: s.label, w: s.ws }));
  let soc = await page.evaluate(() => ({ shown: !document.getElementById('socp').hidden, tiles: [...document.querySelectorAll('#soc-k .st')].map((t) => t.querySelector('.l').textContent + '=' + t.querySelector('.v').textContent),
    act: [...document.querySelectorAll('#soc-act a.row')].map((a) => a.getAttribute('href')), img: !!document.querySelector('#socp img'), actText: document.getElementById('soc-act').textContent,
    xu: [...document.querySelectorAll('#soc-xu a.row')].map((a) => a.getAttribute('href')), note: document.getElementById('soc-note').textContent }));
  ok(soc.shown && JSON.stringify(soc.tiles) === '["Open alerts=17","Act now=2","Unassigned=6","New in 24 h=9","Time to acknowledge=42 min","AI triage=4 to review"]', 'SOC tiles from the SIEM overview: ' + JSON.stringify(soc.tiles));
  ok(JSON.stringify(soc.act) === '["soc-alerts.html?id=al-1","soc-alerts.html?id=al%2F2"]' && !soc.img && /<img src=x/.test(soc.actText), 'act-now rows open the alert; a hostile rule name is shown as text, never markup: ' + soc.act);
  ok(JSON.stringify(soc.xu) === '["soc-xdr.html","soc-ueba.html?entity=u1"]' && /320 alerts over 14 days/.test(soc.note), 'XDR incident and risky user rows; where the figures came from');
  ok(s.dec === '2' && s.quick.includes('soc-alerts.html') && s.quick.includes('soc-hunt.html'), 'SOC home counts the SOC approvals and offers the SOC quick actions: ' + s.dec);
  await page.close();
  SOCOV = 'down'; page = await open('', 800);
  soc = await page.evaluate(() => ({ v: document.querySelector('#soc-k .st .v').textContent, act: document.getElementById('soc-act').textContent }));
  ok(soc.v === 'not reachable' && /until the SIEM answers/.test(soc.act), 'SIEM down: the SOC panel says so (never 0): ' + soc.v);
  await page.close(); SOCOV = 'ok';
  ME = { role: { id: 'cyber-security-admin', name: 'Cyber Security Admin', base: 'operator', functions: { soc: 'manage', identity: 'manage', vuln: 'manage' } } };
  page = await open(); ok(await page.evaluate(() => document.getElementById('socp').hidden) && (await state(page)).label === 'Cyber Security team', 'the Cyber Security home has no SOC panel'); await page.close();
  GATE = 'admin'; ME = null; page = await open('?team=soc', 800); ok((await state(page)).label === 'Security Operations (SOC) team' && await page.evaluate(() => !document.getElementById('socp').hidden), 'an administrator can preview the SOC home'); await page.close();
  GATE = 'operator';

  // ---- engineer homes: one engineer, one home, only their own pages
  // the organisation's estate (brand pages_off): Hyper-V instead of VMware / Nutanix, Microsoft 365 + Mimecast instead of Exchange servers
  const OFFP = ZYB_ORG.pages_off || [], HYPERV = OFFP.includes('vsphere-studio') && OFFP.includes('nutanix-vms'), M365 = OFFP.includes('exchange-servers') && OFFP.includes('exchange-hybrid');
  const ENGHOME = [['pentest-engineer', 'vuln', 'Penetration Testing team', 'vapt-center.html'], ['network-engineer', 'network', 'Network Engineering team', 'network-dashboard.html'],
    ['virtualization-admin', 'virtualization', 'Virtualization team', HYPERV ? 'hyperv.html' : 'vsphere-studio.html'], ['windows-admin', 'windows', 'Windows Servers team', 'windows-servers.html'],
    ['exchange-admin', 'exchange', M365 ? 'Email & Microsoft 365 team' : 'Exchange & Mail team', M365 ? 'mimecast-actions.html' : 'exchange-servers.html'], ['backup-admin', 'backup', 'Backup & Storage team', 'backup.html']];
  for (const [id, fn, label, q] of ENGHOME) {
    ME = { role: { id, name: label, base: 'operator', functions: { [fn]: 'manage' } } };
    page = await open('?team=cyber'); s = await state(page);
    ok(s.label === label && !s.teambar && s.quick.includes(q), id + ': lands on its own home, no switcher, ?team ignored: ' + JSON.stringify({ l: s.label, q: s.quick }));
    await page.close();
  }
  if (HYPERV || M365) {   // nothing of a platform the organisation does not run on those homes
    for (const [id, fn, bad] of [['virtualization-admin', 'virtualization', /vsphere|nutanix|vmware/i], ['exchange-admin', 'exchange', /exchange-(servers|hybrid|admin)|email-route-map|libraesva/i]]) {
      if ((fn === 'virtualization' && !HYPERV) || (fn === 'exchange' && !M365)) continue;
      ME = { role: { id, name: id, base: 'operator', functions: { [fn]: 'manage' } } };
      page = await open(); const st = await state(page), txt = await page.evaluate(() => [...document.querySelectorAll('.qa'), document.getElementById('teamlabel')].map((e) => e.textContent).join(' ') + ' ' + ((document.querySelector('.greet') || {}).textContent || '')), hrefs = st.quick.concat(st.also).join(' ');
      { const w = (fn === 'virtualization' ? /.{0,40}(VMware|Nutanix).{0,40}/ : /.{0,40}(Exchange servers|Exchange Hybrid).{0,40}/).exec(txt); ok(!bad.test(hrefs) && !w, id + ': no page or wording for a platform the organisation does not run: ' + ((hrefs.match(bad) || [])[0] || '') + ' ' + (w ? w[0] : '')); }
      await page.close();
    }
  }
  ME = { role: { id: 'windows-admin', name: 'Windows Server Admin', base: 'operator', functions: { windows: 'manage' } } };
  page = await open(); s = await state(page);
  const links = await page.evaluate(() => [...document.querySelectorAll('.wk li a')].map((a) => a.getAttribute('href')));
  ok(JSON.stringify(s.ws) === '["srv","ai","usr"]' && links.includes('windows-servers.html') && links.includes('ad-exchange.html') && !links.includes('vmware-servers.html') && !links.includes('exchange-servers.html'),
    'windows home lists only the Windows pages, grouped by section: ' + JSON.stringify({ w: s.ws, links }));
  ok(JSON.stringify(s.engs) === '["AI Windows Server Administrator"]' && (await page.evaluate(() => document.querySelector('#engs a.row').getAttribute('href'))) === 'windows-admin.html', 'its AI engineer, linked to its own page (not the AI Team page it cannot open)');
  await page.close();
  ME = { role: { id: 'network-engineer', name: 'Network Engineer', base: 'operator', functions: { network: 'manage' } } };
  page = await open(); s = await state(page);
  ok(s.dec === '1' && s.prob === '1' && JSON.stringify(s.engs) === '["AI Network Engineer"]', 'network home counts only the network items (1 awaiting, 1 critical): ' + s.dec + ' / ' + s.prob);
  await page.close();
  ME = { role: { id: 'backup-admin', name: 'Backup Admin', base: 'operator', functions: { backup: 'manage' } } };
  page = await open(); ok(/No AI engineer works on this area yet/.test(await page.textContent('#engs')), 'backup home: says no AI engineer covers it (never an empty box)'); await page.close();
  GATE = 'admin'; ME = null;
  page = await open('?team=exchange'); s = await state(page);
  ok(s.label === (M365 ? 'Email & Microsoft 365 team' : 'Exchange & Mail team') && s.teambar, 'an administrator can preview an engineer home: ' + s.label); await page.close();
  GATE = 'operator';

  ME = { role: { id: 'system-admin', name: 'System Admin', base: 'admin', functions: {} } };
  page = await open(); ok((await state(page)).label === 'Global Admin', 'a role with admin base is Global Admin'); await page.close();

  // ---- sources missing: honest tiles and an honest team panel
  GATE = 'operator'; ME = { role: { id: 'soc-analyst', name: 'SOC Analyst', base: 'operator', functions: { soc: 'manage' } } }; DUTY = false;
  page = await open(); s = await state(page);
  ok(s.dec === 'not installed' && s.ai === 'not installed', 'no duty engine: tiles say not installed: ' + s.dec + ' / ' + s.ai);
  ok(/not installed/.test(await page.textContent('#engs')) && /no queue/.test(await page.textContent('#tq')), 'team panels say why they are empty');
  await page.close(); GATE = 'admin'; ME = null;
  page = await open(); ok(JSON.stringify((await state(page)).open) === '{"infra":"—","cyber":"—","app":"—","risk":"—","privacy":"—","audit":"—"}', 'not connected: team cards show — (never 0)');
  await page.screenshot({ path: process.env.SHOT || '/dev/null', fullPage: false }).catch(() => {});
  await page.close();

  ok(!errs.length, 'page errors: ' + errs.join(' | '));
  await browser.close(); srv.close();
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks');
  process.exit(bad ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
