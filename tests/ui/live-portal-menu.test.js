// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// The menu over the REAL portal (repos/live/portal: the portal's own index.html + app.js, copied from the server)
// on a 14-inch laptop (1366 x 768) and a big screen (1920 x 1080): no second menu of old portal sections, every portal page
// inside a workspace, no database page twice (sample-data / same-subject portal pages hidden), Start here and a long
// workspace folded so the menu fits, the header on one line. Skips when the live copy is not in the repository.
// Run: PLAYWRIGHT=/opt/node22/lib/node_modules/playwright node live-portal-menu.test.js
const http = require('http'), fs = require('fs'), path = require('path');
const LIVE = path.resolve(__dirname, '../../repos/live/portal'), DASH = path.resolve(__dirname, '../../ui');
if (!fs.existsSync(path.join(LIVE, 'index.html'))) { console.log('SKIP: repos/live/portal not present'); process.exit(0); }
let n = 0, bad = 0; const ok = (c, m) => { n++; if (!c) { bad++; console.log('FAIL', m); } };
(async () => {
  const srv = http.createServer((req, res) => { const u = decodeURIComponent(req.url.split('?')[0]); const json = (c, b) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(b)); };
    if (u === '/dashboards/whoami.json' || u === '/auth/whoami') return json(200, { user: 'syed', role: 'admin' });
    if (u.startsWith('/api/soc/ui/menu')) return json(200, { order: null, favorites: [], can_edit_order: true });
    if (u.startsWith('/api/')) return json(404, { error: 'not in this test' });
    const f = u.startsWith('/dashboards/') ? path.join(DASH, u.slice(12)) : u === '/' ? path.join(LIVE, 'index.html') : path.join(LIVE, u);
    if (!f.startsWith(DASH) && !f.startsWith(LIVE)) { res.writeHead(403); return res.end(); }
    fs.readFile(f, (e, d) => { if (e) { res.writeHead(404); return res.end(); } res.writeHead(200, { 'Content-Type': f.endsWith('.js') ? 'application/javascript' : f.endsWith('.css') ? 'text/css' : f.endsWith('.json') ? 'application/json' : 'text/html' }); res.end(d); }); });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const { chromium } = require(process.env.PLAYWRIGHT || 'playwright'); const browser = await chromium.launch();
  for (const [W, H] of [[1366, 768], [1920, 1080]]) {
    const p = await browser.newPage({ viewport: { width: W, height: H } }); const errs = []; p.on('pageerror', (e) => errs.push(e.message));
    await p.goto('http://127.0.0.1:' + srv.address().port + '/'); await p.waitForSelector('li.zyb-area[data-zyb-area="db"]', { timeout: 20000 }); await p.waitForTimeout(2500);
    const st = await p.evaluate(() => { const nav = document.querySelector('ul.nav'), vis = (li) => !!li.offsetParent;
      const heads = [...nav.querySelectorAll(':scope > li.nav-group')].filter((h) => vis(h) && !h.getAttribute('data-zyb-menu')).map((h) => h.getAttribute('data-en') || h.textContent.trim());
      const loose = [...nav.querySelectorAll(':scope > li[data-view]')].filter((li) => !li.hasAttribute('data-zyb-moved') && !li.hasAttribute('data-zyb-dup')).map((li) => li.getAttribute('data-view'));
      const dbVis = [...nav.querySelectorAll('li[data-zyb-area="db"], li[data-zyb-moved="db"]')].filter((li) => !li.hasAttribute('data-zyb-dup')).map((li) => (li.getAttribute('data-en') || li.textContent).trim());
      return { heads, loose, dbVis, rows: [...nav.children].filter((li) => vis(li) && !li.classList.contains('zyb-sub')).length, dup: ['dbperf', 'db-oracle', 'databases'].map((v) => { const l = nav.querySelector('li[data-view="' + v + '"]'); return l ? l.hasAttribute('data-zyb-dup') : true; }),
        renamed: (nav.querySelector('li[data-view="infra-db"]') || {}).textContent || '', topH: Math.round(document.querySelector('.topbar').getBoundingClientRect().height) }; });
    // no page twice: outside Start here (which repeats the set-up pages on purpose) no two visible items open the same page,
    // and no two visible items carry the same name
    const dupe = await p.evaluate(() => { const L = window.ZYB_EARLY_LIVE || {}, nav = document.querySelector('ul.nav'), T = {}, N = {}, out = [];
      [...nav.querySelectorAll('li')].filter((li) => !li.classList.contains('nav-group') && !li.classList.contains('zyb-area') && !li.classList.contains('zyb-sg') && !li.classList.contains('zyb-lbl') && !li.hasAttribute('data-zyb-dup') && (li.getAttribute('data-view') || li.getAttribute('data-zyb-href')))
        .forEach((li) => { const v = li.getAttribute('data-view'), lab = (li.getAttribute('data-en') || li.textContent).replace(/\s+/g, ' ').trim(), t = li.getAttribute('data-zyb-href') || (v && L[v] ? '/dashboards/' + L[v] : 'portal:' + v), k = lab.toLowerCase();
          if (li.getAttribute('data-zyb-moved') !== 'start') { if (T[t]) out.push(lab + ' and ' + T[t] + ' both open ' + t); else T[t] = lab; }
          if (N[k]) out.push('"' + lab + '" twice'); else N[k] = 1; });
      return out; });
    ok(!dupe.length, W + ': no duplicate menu entries: ' + dupe.join('; '));
    const ren = await p.evaluate(() => ((document.querySelector('li[data-view="alarmrules"]') || {}).textContent || '').trim());
    ok(/Alarm Inbox Rules/.test(ren), W + ': the portal alarm rules are named apart from SIEM Detection Rules: ' + ren);
    ok(!st.heads.length, W + ': no old portal section left visible: ' + st.heads.join(', '));
    ok(!st.loose.length, W + ': every portal page is inside a workspace or Start here: ' + st.loose.join(', '));
    ok(st.dup.every(Boolean), W + ': Database Performance Analyzer (sample data), Oracle Database Health and Databases are hidden as duplicates');
    ok(new Set(st.dbVis).size === st.dbVis.length, W + ': no database page twice: ' + st.dbVis.join(' | '));
    ok(/PostgreSQL \/ MySQL Health/.test(st.renamed), W + ': Infrastructure Automation database page renamed: ' + st.renamed.trim());
    ok(st.rows <= 40, W + ': the menu fits (' + st.rows + ' rows with every workspace closed)');
    if (W === 1366) ok(st.topH <= 80, 'laptop: header on one line (' + st.topH + ' px)');
    await p.evaluate(() => document.querySelector('li.zyb-area[data-zyb-area="grc"]').click()); await p.waitForTimeout(300);
    const grcL = await p.evaluate(() => [...document.querySelectorAll('li[data-zyb-area="grc"]')].filter((li) => li.offsetParent).map((li) => (li.className.includes('zyb-sg') ? '#' : '') + (li.getAttribute('data-en') || li.textContent).trim())); const grc = grcL.filter((x) => x[0] !== '#').length;   // sub-menu headings are labels, not rows to scroll past
    // a long workspace folds the PORTAL's pages under one "More …" row and never hides one of our dashboards, so the rows
    // in sight are the workspace row + every dashboard of ours registered for it in zyb-nav.js + that one More row (a
    // fixed "16 rows" stopped holding the day the workspace got its 15th dashboard of ours - the fold was right)
    const fold = await p.evaluate(() => { const nav = document.querySelector('ul.nav'), vis = (li) => !!li.offsetParent, area = (window.ZYB_NAV || []).find((a) => a.id === 'grc') || { pages: [] };
      const ours = area.pages.map((pg) => pg.h), mine = [...nav.querySelectorAll('li.zyb-sub[data-zyb-area="grc"]')].filter((li) => !li.hasAttribute('data-zyb-moved') && !li.classList.contains('zyb-sg') && li.getAttribute('data-zyb-menu') !== 'areamore');
      const hidden = ours.filter((h) => !mine.some((li) => vis(li) && (li.getAttribute('data-zyb-href') || '').split('?')[0].endsWith(h)));
      const portal = [...nav.querySelectorAll('li[data-zyb-moved="grc"]')].filter((li) => !li.getAttribute('data-zyb-menu') && !li.hasAttribute('data-zyb-dup'));
      const tg = nav.querySelector('li[data-zyb-menu="areamore"][data-zyb-area="grc"]'), row = nav.querySelector('li.zyb-area[data-zyb-area="grc"]');
      const r = (el) => el.getBoundingClientRect(), last = tg && vis(tg) ? tg : mine.filter(vis).pop();
      return { ours: ours.length, hidden, portal: portal.length, portalShown: portal.filter(vis).map((li) => (li.getAttribute('data-en') || li.textContent).trim()), more: tg && vis(tg) ? tg.textContent.trim() : '',
        span: row && last ? Math.round(r(last).bottom - r(row).top) : 1e9, vh: innerHeight }; });
    ok(fold.ours >= 1 && !fold.hidden.length, W + ': every Risk & Governance dashboard of ours stays in sight (' + fold.ours + ' registered; hidden: ' + fold.hidden.join(', ') + ')');
    ok(fold.portal >= 4 && !fold.portalShown.length && fold.more === 'More in Risk & Governance (' + fold.portal + ')', W + ': the portal pages are folded under one row (' + fold.portal + ' portal pages; shown: ' + fold.portalShown.join(', ') + '; toggle: ' + fold.more + ')');
    ok(grc === 1 + fold.ours + 1, W + ': a long workspace is folded (' + grc + ' visible rows = workspace + ' + fold.ours + ' dashboards + More: ' + grcL.join(' | ') + ')');
    ok(fold.span <= fold.vh, W + ': the open workspace fits the screen (' + fold.span + ' of ' + fold.vh + ' px)');
    // the More row unfolds the portal pages and folds them again (and the choice is remembered)
    await p.evaluate(() => document.querySelector('li[data-zyb-menu="areamore"][data-zyb-area="grc"]')?.click()); await p.waitForTimeout(200);
    const unf = await p.evaluate(() => ({ shown: [...document.querySelectorAll('li[data-zyb-moved="grc"]')].filter((li) => !li.getAttribute('data-zyb-menu') && !li.hasAttribute('data-zyb-dup') && li.offsetParent).length, st: localStorage.getItem('zyb-areamore') }));
    ok(unf.shown === fold.portal && /"grc":true/.test(unf.st || ''), W + ': More unfolds every portal page (' + unf.shown + ' of ' + fold.portal + ', remembered ' + unf.st + ')');
    await p.evaluate(() => document.querySelector('li[data-zyb-menu="areamore"][data-zyb-area="grc"]')?.click()); await p.waitForTimeout(200);
    const ref = await p.evaluate(() => [...document.querySelectorAll('li[data-zyb-moved="grc"]')].filter((li) => !li.getAttribute('data-zyb-menu') && !li.hasAttribute('data-zyb-dup') && li.offsetParent).length);
    ok(ref === 0, W + ': More folds them again (' + ref + ' still shown)');
    // whatever is Cisco sits in Network (the portal had its Cisco Update pages under Servers & Cloud); sub-menus inside
    // Governance (GRC / Regulators & frameworks / Audit) and Servers & Virtualization (Servers / Virtualization)
    const mv = await p.evaluate(() => { const nav = document.querySelector('ul.nav');
      const cisco = [...nav.querySelectorAll('li[data-view]')].filter((li) => /\bcisco\b/i.test(li.getAttribute('data-en') || li.textContent));
      const sg = (id) => [...nav.querySelectorAll('li.zyb-sg[data-zyb-area="' + id + '"]')].map((x) => x.textContent.trim());
      return { cisco: cisco.map((li) => (li.getAttribute('data-en') || '') + '=' + (li.getAttribute('data-zyb-moved') || li.getAttribute('data-zyb-area') || 'portal group')), grc: sg('grc'), srv: sg('srv') }; });
    ok(mv.cisco.length >= 6 && mv.cisco.every((x) => /=net$/.test(x)), W + ': every Cisco page is under Network: ' + mv.cisco.join(' | '));
    ok(mv.grc.join() === 'Overview,Identify & assess,Treat & track,Registers & reports,Policies & roles', W + ': Risk & Governance sub-menus: ' + mv.grc.join(', '));
    ok(mv.srv.join() === 'Servers,Mail servers,Server administration,Virtualization,Capacity & power', W + ': Servers & Virtualization sub-menus: ' + mv.srv.join(', '));
    const bul = await p.evaluate(() => { const pe = (el, w) => { const c = getComputedStyle(el, w); return c.display !== 'none' && c.content !== 'none' && c.content !== 'normal'; };
      const hs = [...document.querySelectorAll('ul.nav li.zyb-sg')], rows = [...document.querySelectorAll('ul.nav li.zyb-sub:not(.zyb-sg)')];
      return { heads: hs.length, dotted: hs.filter((h) => pe(h, '::after') || pe(h, '::before')).map((h) => h.textContent.trim()), modern: document.documentElement.classList.contains('zyb-modern'), rowDots: rows.filter((r) => pe(r, '::after') || pe(r, '::before')).length }; });
    ok(bul.heads > 0 && !bul.dotted.length, W + ': sub-menu headings have no bullet or tree line: ' + bul.dotted.join(', '));
    // each sub-menu heading has a coloured icon and opens / hides its own pages (remembered); the other heading is untouched
    const sgt = await p.evaluate(() => { const nav = document.querySelector('ul.nav');
      nav.querySelector('li.zyb-area[data-zyb-area="srv"]').click();
      const vis = (g) => [...nav.querySelectorAll('li.zyb-sub[data-zyb-g="srv|' + g + '"]:not(.zyb-sg)')].filter((li) => li.offsetParent).length;
      const h = nav.querySelector('li.zyb-sg[data-zyb-g="srv|Virtualization"]'), before = vis('Virtualization'), servers = vis('Servers');
      const icon = !!h.querySelector('.zyb-sgi svg') && !!h.style.getPropertyValue('--sc');
      h.click(); const shut = vis('Virtualization'), serversAfter = vis('Servers'), saved = JSON.stringify(localStorage);
      h.click(); const again = vis('Virtualization');
      return { icon, before, shut, servers, serversAfter, again, saved: /srv\|Virtualization/.test(saved), expanded: h.getAttribute('aria-expanded') }; });
    ok(sgt.icon && sgt.before > 0 && sgt.shut === 0 && sgt.serversAfter === sgt.servers && sgt.again === sgt.before && sgt.saved && sgt.expanded === 'true', W + ': a sub-menu heading opens / hides its pages, with a coloured icon, remembered: ' + JSON.stringify(sgt));
    // the portal's IT Infrastructure Manager dashboard (sample telemetry): its entry hidden, ours shown, and opening it any
    // other way (landing page, a link, setView) goes to the live page
    const inf = await p.evaluate(() => { const nav = document.querySelector('ul.nav'), li = nav.querySelector('li[data-view="infradash"]');
      return { has: !!li, dup: li ? li.getAttribute('data-zyb-dup') || '' : '', ours: !!nav.querySelector('li[data-zyb-menu][data-zyb-href="/dashboards/infra-manager.html"]') }; });
    if (inf.has) ok(/infra-manager\.html/.test(inf.dup) && inf.ours, W + ': the sample IT Infrastructure Manager page is replaced by the live one in the menu: ' + JSON.stringify(inf));
    // the CIO and CISO role dashboards (budget, programmes, risk register typed in): replaced by the CIO Dashboard and AI CISO
    const rd = await p.evaluate(() => { const nav = document.querySelector('ul.nav'); return [['ciodash', 'cio-dashboard.html'], ['cisodash', 'ciso-dashboard.html']].map(([v, h]) => { const li = nav.querySelector('li[data-view="' + v + '"]');
      return { v, has: !!li, dup: li ? li.getAttribute('data-zyb-dup') || '' : '', ours: !!nav.querySelector('li[data-zyb-menu][data-zyb-href="/dashboards/' + h + '"]'), h }; }); });
    for (const x of rd) if (x.has) ok(x.dup.includes(x.h) && x.ours, W + ': ' + x.v + ' replaced by ' + x.h + ': ' + JSON.stringify(x));
    if (inf.has && W === 1366) {
      await p.evaluate(() => { try { window.setView('infradash'); } catch (e) { /* the redirect replaces the portal view */ } }); await p.waitForTimeout(1500);
      const where = await p.evaluate(() => { const f = document.querySelector('iframe'); let fp = ''; try { fp = f ? f.contentWindow.location.pathname : ''; } catch (e) { /* cross-origin */ } return location.pathname + ' ' + fp; });
      ok(/infra-manager\.html/.test(where), 'opening infradash lands on the live page: ' + where);
      for (const [v, h] of [['ciodash', 'cio-dashboard.html'], ['cisodash', 'ciso-dashboard.html'], ['siemlive', 'soc-live.html'], ['spo', 'sharepoint.html']]) {   // Live SIEM Stream: the AI / ML stream page; SharePoint & OneDrive: one merged page
        await p.goto('http://127.0.0.1:' + srv.address().port + '/'); await p.waitForSelector('li.zyb-area[data-zyb-area="db"]', { timeout: 20000 }); await p.waitForTimeout(1500);
        await p.evaluate((v) => { try { window.setView(v); } catch (e) { /* the redirect replaces the portal view */ } }, v); await p.waitForTimeout(1500);
        const w2 = await p.evaluate(() => { const f = document.querySelector('iframe'); let fp = ''; try { fp = f ? f.contentWindow.location.pathname : ''; } catch (e) { /* cross-origin */ } return location.pathname + ' ' + fp; });
        ok(w2.includes(h), 'opening ' + v + ' lands on ' + h + ': ' + w2);
      }
    }
    ok(!errs.length, W + ': no page errors: ' + errs.slice(0, 3).join(' | '));
    await p.close();
  }
  /* no portal page shows sample telemetry: every view is opened with the menu active - it either lands on a live page
     (/dashboards/…, or the live portal page it is aliased to) or its own text carries no sample marker */
  {
    const p = await browser.newPage({ viewport: { width: 1400, height: 900 } }); const errs = []; p.on('pageerror', (e) => errs.push(e.message));
    const base = 'http://127.0.0.1:' + srv.address().port + '/';
    await p.goto(base); await p.waitForSelector('li.zyb-area[data-zyb-area="db"]', { state: 'attached', timeout: 20000 }); await p.waitForTimeout(2000);
    const views = await p.evaluate(() => [...document.querySelectorAll('li[data-view]')].map((li) => li.getAttribute('data-view')).concat(['node', 'scm']));
    const SAMPLE = /SAMPLE TELEMETRY|SAMPLE DATA|SAMPLE HEALTH|SAMPLE CONTENT|SAMPLE REGISTER|POC sample|Sample record|BUDGET & PROGRAMMES: SAMPLE/;
    const left = [];
    for (const v of [...new Set(views)]) {
      if (!/^\/$/.test(await p.evaluate(() => location.pathname))) { await p.goto(base); await p.waitForTimeout(1500); }
      const r = await p.evaluate(async (v) => { try { window.setView(v); } catch (e) { /* a redirect replaces the view */ } await new Promise((x) => setTimeout(x, 300));
        const f = document.querySelector('iframe'); let fp = ''; try { fp = f && f.offsetParent ? f.contentWindow.location.pathname : ''; } catch (e) { /* cross-origin */ }
        const host = document.querySelector('#viewFocus') || document.body; return { where: location.pathname + ' ' + fp, text: /\/dashboards\//.test(location.pathname + fp) ? '' : host.innerText }; }, v);
      const m = SAMPLE.exec(r.text); if (m) left.push(v + ': ' + m[0]);
    }
    ok(!left.length, 'no portal page shows sample data (' + views.length + ' opened): ' + left.join(' | '));
    await p.goto(base); await p.waitForTimeout(1500);
    const al = await p.evaluate(async () => { window.setView('assetreg'); await new Promise((x) => setTimeout(x, 600)); const f = document.querySelector('iframe'); let fp = ''; try { fp = f ? (f.getAttribute('src') || '') + ' ' + f.contentWindow.location.pathname : ''; } catch (e) { /* cross-origin */ } return { where: location.pathname + location.hash + ' ' + fp, cur: typeof currentView !== 'undefined' ? currentView : '', dup: (document.querySelector('li[data-view="assetreg"]') || {}).getAttribute ? document.querySelector('li[data-view="assetreg"]').getAttribute('data-zyb-dup') : '' }; });
    ok((al.cur === 'itam-assets' || /inventory\.html/.test(al.where)) && /itam-assets/.test(al.dup || ''), 'IT Asset Register opens the live ITAM Inventory (now the Inventory page) and its entry is hidden: ' + JSON.stringify(al));
    ok(!errs.length, 'sweep: no page errors: ' + errs.slice(0, 3).join(' | '));
    await p.close();
  }
  /* settings a browser remembered from earlier menus (an old "Dashboards" fold, a portal section opened in one-section mode,
     a workspace left open): every heading and every workspace row stays visible, and every workspace opens and closes */
  const p = await browser.newPage({ viewport: { width: 1366, height: 768 } });
  await p.goto('http://127.0.0.1:' + srv.address().port + '/');
  const STATES = { none: {}, 'old Dashboards fold': { 'zyb-pmenu': '{"open":{"db":true},"dash_closed":true}' }, 'portal section open': { as_nav_open: 'Infrastructure Automation', 'zyb-pmenu': '{"open":{"net":true}}' },
    'all sections': { as_nav_mode: 'all', nav_tree: '{"Dashboards":false}' }, 'both': { as_nav_open: '', 'zyb-pmenu': '{"open":{"db":true},"dash_closed":true}' } };
  for (const [name, ls] of Object.entries(STATES)) {
    await p.evaluate((ls) => { localStorage.clear(); for (const k in ls) localStorage.setItem(k, ls[k]); }, ls);
    await p.reload(); await p.waitForSelector('li.zyb-area[data-zyb-area="db"]', { state: 'attached', timeout: 20000 }); await p.waitForTimeout(2500);
    const r = await p.evaluate(async () => { const nav = document.querySelector('ul.nav'), v = (l) => !!l.offsetParent, wait = () => new Promise((x) => setTimeout(x, 150));
      const lbl = [...nav.querySelectorAll('li.zyb-lbl')].filter((l) => !v(l)).map((l) => l.textContent.trim());
      const rows = [...nav.querySelectorAll('li.zyb-area')], hidden = rows.filter((l) => !v(l)).map((l) => l.getAttribute('data-zyb-area'));
      const start = [...nav.querySelectorAll('li[data-zyb-start]:not([data-zyb-startmore])')].filter((l) => !v(l)).map((l) => l.textContent.trim() + (true ? ' ' + [...l.attributes].map((a) => a.name + '=' + a.value).join(' ') + ' cls=' + l.className + ' disp=' + getComputedStyle(l).display : ''));
      const broken = [];
      for (const row of rows) { const id = row.getAttribute('data-zyb-area'), subs = () => [...nav.querySelectorAll('li.zyb-sub[data-zyb-area="' + id + '"]')].filter(v).length;
        if (row.classList.contains('zyb-open')) { row.click(); await wait(); }
        const c0 = subs(); row.click(); await wait(); const o = subs(); row.click(); await wait(); const c1 = subs();
        if (c0 || !o || c1) broken.push(id + ' ' + c0 + '/' + o + '/' + c1); }
      return { lbl, hidden, start, broken, n: rows.length }; });
    ok(!r.lbl.length, name + ': every heading visible: hidden ' + r.lbl.join(', '));
    ok(r.n === 19 && !r.hidden.length, name + ': every workspace row visible (' + r.n + '): hidden ' + r.hidden.join(', '));
    ok(!r.start.length, name + ': Start here visible: hidden ' + r.start.join(', '));
    ok(!r.broken.length, name + ': every workspace opens and closes: ' + r.broken.join(' | '));
  }
  await p.close();
  await browser.close(); srv.close();
  console.log((bad ? 'FAILED ' : 'OK ') + (n - bad) + '/' + n + ' checks'); process.exit(bad ? 1 : 0);
})().catch((x) => { console.error(x); process.exit(1); });
