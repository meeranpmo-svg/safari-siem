// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Browser test for vendor/zyb-navsplit.js: the portal's catch-all "More" group (43 pages) is split into one main menu
// group per function (APM, ITAM, Discovery, SIEM, Infrastructure Automation, ...), existing groups receive their pages,
// the rest stays under "Other tools"; nothing outside "More" moves; the portal's tree is rebuilt (or our own toggle when
// the portal has none); a page a module adds late is re-homed; every page is still there and still clickable.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node navsplit.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const VENDOR = path.resolve(__dirname, '../../ui/vendor');
let n = 0, bad = 0;
const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };

const MORE = [['bulk-add', 'Add Devices (bulk)'], ['detval', 'Detection Validation'], ['apm-map', 'Service Map'], ['apm-svc', 'Services and Traces'], ['apm-traces', 'Distributed Traces'],
  ['apm-synth', 'Synthetic Monitoring'], ['apm-rum', 'Real-User Monitoring'], ['apm-slo', 'Service-Level Objectives'], ['apm-apps', 'Discovered Applications'], ['apm-settings', 'APM Settings'],
  ['itam-assets', 'ITAM Inventory'], ['itam-cmdb', 'ITAM CMDB & Dependencies'], ['itam-software', 'ITAM Software & Licences'], ['itam-discovery', 'ITAM Discovery'], ['itam-stocktake', 'ITAM Stocktake'],
  ['itam-ai', 'ITAM AI Findings'], ['itam-settings', 'ITAM Settings'], ['discovery-scopes', 'Discovery Scopes'], ['discovery-results', 'Discovery Results'], ['discovery-runs', 'Discovery Runs'],
  ['discovery-credentials', 'Discovery Credentials'], ['soc-dashboard', 'SIEM SOC Overview'], ['soc-search', 'SIEM Event Search'], ['soc-alerts', 'SIEM Alert Queue'], ['soc-cases', 'SIEM Cases'],
  ['soc-rules', 'SIEM Detection Rules'], ['soc-sources', 'SIEM Log Source Health'], ['infra-overview', 'Infrastructure Overview'], ['infra-hosts', 'Linux Hosts'], ['infra-network', 'Network Devices & Config Backups'],
  ['infra-db', 'Database Instances'], ['infra-incidents', 'Automation Incidents'], ['infra-settings', 'Automation Settings'], ['wifi-heat', 'Wi-Fi Heatmap'], ['backup-jobs', 'Backup Jobs'],
  ['sama-gaps', 'SAMA Gap Tracker'], ['risk-reg', 'Risk Register'], ['users-adm', 'User Administration'], ['platform-health', 'Platform Health'], ['kiosk', 'Wall Kiosk'], ['zz-misc', 'Zeta Utility'],
  ['ip-plan', 'Subnet Planner'], ['legacy', 'Legacy Tools']];
const PAGE = (withTree) => `<!doctype html><html><head><meta charset="utf-8"><style>.tree-hidden{display:none}</style></head><body><ul class="nav">
<li class="nav-group" data-en="Command Center">Command Center<span class="chev">▸</span></li><li data-en="Home" data-view="home"><span class="ico">🏠</span> Home</li>
<li class="nav-group" data-en="Security Operations (SOC)">Security Operations (SOC)<span class="chev">▸</span></li><li data-en="Alarm Inbox" data-view="alarms"><span class="ico">🔔</span> Alarm Inbox</li>
<li class="nav-group" data-en="More"><span class="ico">▦</span> More <span class="zyb-cnt">43</span><span class="chev">▸</span></li>
${MORE.map(m => `<li data-en="${m[1]}" data-view="${m[0]}"><span class="ico">•</span> ${m[1].replace(/&/g, '&amp;')}</li>`).join('\n')}
<li class="nav-group" data-en="Reports & Administration">Reports &amp; Administration<span class="chev">▸</span></li><li data-en="Reports" data-view="reports"><span class="ico">📄</span> Reports</li>
</ul><div id="clicked"></div>
<script>
document.querySelector('.nav').addEventListener('click', function (e) { var li = e.target.closest('li[data-view]'); if (li) document.getElementById('clicked').textContent = li.dataset.view; });
${withTree ? `window.TREE_CALLS = 0;
function initNavTree(){ var nav=document.querySelector('.nav'); if(!nav||nav._tree) return; nav._tree=true; window.TREE_CALLS++;
  var groups=[]; [].forEach.call(nav.children, function(li){ if(li.classList.contains('nav-group')) groups.push({h:li,kids:[]}); else if(groups.length) groups[groups.length-1].kids.push(li); });
  var saved={}; try{ saved=JSON.parse(localStorage.getItem('nav_tree')||'{}')||{}; }catch(e){}
  groups.forEach(function(g){ var k=g.h.dataset.en; var set=function(o){ g.h.classList.toggle('open',o); g.kids.forEach(function(x){ x.classList.toggle('tree-hidden',!o); }); };
    set(saved.hasOwnProperty(k)?!!saved[k]:true); g.h.onclick=function(){ set(!g.h.classList.contains('open')); }; }); }
initNavTree();` : ''}
</script><script src="/vendor/zyb-navsplit.js"></script></body></html>`;

(async () => {
  let MODE = true;
  const srv = http.createServer((req, res) => {
    const u = req.url.split('?')[0], glyph = /glyph=1/.test(req.url);
    if (u === '/') { res.writeHead(200, { 'Content-Type': 'text/html' }); const pg = PAGE(MODE); return res.end(glyph ? pg.replace('<li class="nav-group" data-en="More"><span class="ico">▦</span> More', '<li class="nav-group"><span class="ico">▦</span> More') : pg); }
    if (u.startsWith('/vendor/')) { const f = path.join(VENDOR, path.basename(u)); return fs.readFile(f, (e, d) => { if (e) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': 'application/javascript' }); res.end(d); }); }
    res.writeHead(404); res.end();
  });
  await new Promise(r => srv.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + srv.address().port + '/';
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright');
  const browser = await chromium.launch();
  const groupsOf = (page) => page.evaluate(() => { const out = {}; let g = null; [...document.querySelector('.nav').children].forEach(li => { if (li.classList.contains('nav-group')) { g = li.dataset.en; out[g] = []; } else if (g) out[g].push(li.dataset.view); }); return out; });

  // ---- A: a portal with its tree code ----
  let page = await browser.newPage(); const errs = []; page.on('pageerror', e => errs.push(e.message));
  await page.goto(base); await page.waitForFunction(() => !document.querySelector('.nav li.nav-group[data-en="More"]'));
  let G = await groupsOf(page);
  const names = Object.keys(G);
  ok(!G.More, 'no "More" group left');
  ok(names.join('|') === ['Command Center', 'Security Operations (SOC)', 'Application Performance (APM)', 'IT Asset Management', 'Discovery & Onboarding', 'Infrastructure Automation', 'Network & Servers', 'Governance & Compliance', 'Other tools', 'Reports & Administration'].join('|'), 'groups in function order, in place of More: ' + names.join(' | '));
  ok(['apm-map', 'apm-svc', 'apm-traces', 'apm-synth', 'apm-rum', 'apm-slo', 'apm-apps', 'apm-settings'].every(v => G['Application Performance (APM)'].includes(v)) && G['Application Performance (APM)'].length === 8, 'APM: the 8 APM pages incl. APM Settings: ' + G['Application Performance (APM)']);
  ok(G['IT Asset Management'].length === 7 && G['IT Asset Management'].includes('itam-discovery') && G['IT Asset Management'].includes('itam-settings'), 'ITAM: all 7 ITAM pages (ITAM Discovery and Settings stay with ITAM): ' + G['IT Asset Management']);
  ok(G['Discovery & Onboarding'].join(',') === 'bulk-add,discovery-scopes,discovery-results,discovery-runs,discovery-credentials', 'Discovery & Onboarding: bulk add + 4 discovery pages: ' + G['Discovery & Onboarding']);
  ok(['detval', 'soc-dashboard', 'soc-search', 'soc-alerts', 'soc-cases', 'soc-rules', 'soc-sources'].every(v => G['Security Operations (SOC)'].includes(v)) && G['Security Operations (SOC)'][0] === 'alarms' && !G['Security Operations (SIEM)'], 'SIEM pages + Detection Validation join the existing Security Operations (SOC) group, after its own pages');
  ok(G['Infrastructure Automation'].length === 6, 'Infrastructure Automation: 6 pages: ' + G['Infrastructure Automation']);
  ok(G['Network & Servers'].join(',') === 'wifi-heat,backup-jobs' && G['Governance & Compliance'].join(',') === 'sama-gaps,risk-reg', 'network / governance pages placed');
  ok(G['Reports & Administration'].join(',') === 'reports,users-adm,platform-health' && !G['Platform & Settings'], 'admin pages join the existing Reports & Administration group (alias), no duplicate group');
  ok(G['Other tools'].join(',') === 'legacy,ip-plan,kiosk,zz-misc', 'unmatched pages under Other tools, alphabetical: ' + G['Other tools']);
  ok(G['Command Center'].join(',') === 'home' && G['Reports & Administration'][0] === 'reports', 'pages outside More not moved; receiving groups keep their own pages first');
  const all = Object.values(G).flat();
  ok(all.length === MORE.length + 3 && new Set(all).size === all.length, 'every page still there exactly once: ' + all.length);
  ok(await page.evaluate(() => { const h = document.querySelector('.nav li.nav-group[data-en="IT Asset Management"]'); return /IT Asset Management/.test(h.textContent) && h.querySelector('.zyb-cnt').textContent === '7' && !!h.querySelector('.chev') && !!h.querySelector('.ico'); }), 'new heading looks like the portal’s (icon, count 7, chevron)');
  ok(await page.evaluate(() => window.TREE_CALLS >= 2), 'portal tree rebuilt over the new groups');
  ok(await page.evaluate(() => document.querySelector('.nav li[data-view="apm-map"]').classList.contains('tree-hidden') && !document.querySelector('.nav li[data-view="home"]').classList.contains('tree-hidden')), 'new groups closed on a first visit; existing ones keep their state');
  await page.click('.nav li.nav-group[data-en="Application Performance (APM)"]');
  ok(await page.evaluate(() => !document.querySelector('.nav li[data-view="apm-map"]').classList.contains('tree-hidden')), 'clicking a new group heading opens it');
  await page.click('.nav li[data-view="apm-rum"]');
  ok(await page.evaluate(() => document.getElementById('clicked').textContent === 'apm-rum'), 'a moved page is still clickable (portal handler sees it)');
  // a module adds a page late, after an anchor in "Other tools", and one after an anchor now in APM
  await page.evaluate(() => { const nav = document.querySelector('.nav'); const mk = (v, t) => { const li = document.createElement('li'); li.dataset.view = v; li.dataset.en = t; li.textContent = t; return li; };
    const a = nav.querySelector('li[data-view="legacy"]'); a.after(mk('itam-reports', 'ITAM Reports')); nav.querySelector('li[data-view="apm-slo"]').after(mk('apm-alerts', 'APM Alerts')); });
  await page.waitForTimeout(600); G = await groupsOf(page);
  ok(G['IT Asset Management'].includes('itam-reports') && !G['Other tools'].includes('itam-reports'), 'a late page that landed in Other tools is re-homed: ' + G['IT Asset Management']);
  ok(G['Application Performance (APM)'].includes('apm-alerts'), 'a late page after an APM anchor stays in APM');
  ok(await page.evaluate(() => document.querySelectorAll('.nav li.nav-group[data-en="Other tools"]').length === 1), 'still one Other tools group');
  ok(!errs.length, 'page errors (A): ' + errs.join(' | '));
  await page.close();

  // ---- A2: heading with an icon glyph and a count, no data-en (a newer sidebar) ----
  const page2 = await browser.newPage();
  await page2.goto(base + '?glyph=1'); await page2.waitForTimeout(800);
  ok(await page2.evaluate(() => !!document.querySelector('.nav li.nav-group[data-en="Application Performance (APM)"]') && !window.zybNavSplit.diag().groups.some(g => /^More\b/.test(g))), 'heading "▦ More 43" without data-en is still found and split: ' + JSON.stringify(await page2.evaluate(() => window.zybNavSplit && window.zybNavSplit.diag())));
  await page2.close();

  // ---- B: a portal without tree code: our own toggle ----
  MODE = false; page = await browser.newPage(); const errs2 = []; page.on('pageerror', e => errs2.push(e.message));
  await page.goto(base); await page.waitForFunction(() => !document.querySelector('.nav li.nav-group[data-en="More"]'));
  ok(await page.evaluate(() => document.querySelector('.nav li[data-view="itam-cmdb"]').classList.contains('tree-hidden')), 'no portal tree: new group starts closed');
  await page.click('.nav li.nav-group[data-en="IT Asset Management"]');
  ok(await page.evaluate(() => !document.querySelector('.nav li[data-view="itam-cmdb"]').classList.contains('tree-hidden') && JSON.parse(localStorage.getItem('nav_tree'))['IT Asset Management'] === true), 'our toggle opens it and remembers');
  await page.reload(); await page.waitForFunction(() => !document.querySelector('.nav li.nav-group[data-en="More"]'));
  ok(await page.evaluate(() => !document.querySelector('.nav li[data-view="itam-cmdb"]').classList.contains('tree-hidden')), 'open state survives a reload');
  ok(!errs2.length, 'page errors (B): ' + errs2.join(' | '));
  await browser.close(); srv.close();
  console.log(bad ? 'FAILED ' + bad + ' of ' + n : 'OK ' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
