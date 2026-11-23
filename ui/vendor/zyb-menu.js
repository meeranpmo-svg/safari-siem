// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
/* zyb-menu.js - compact Zyberon + the organisation brand header, and a "Dashboards" group to the portal sidebar (ul.nav), styled like the existing menu items.
 * Loaded by the portal pages (one <script> line added by add-dashboards-menu.sh). Items are plain links to
 * /dashboards/*.html; clicks are handled here so the portal's own page switching never sees them.
 * When no sidebar is found within 10 s, a small "Dashboards" button is shown instead. */
/* Modern | Classic for the portal pages (vendor/zyb-look.js + zyb-look.css): the class is set at once so the page does not
 * repaint later, then the switch and its styles load. */
(function () {
  'use strict';
  if (window.__zybLookLoad) return; window.__zybLookLoad = true;
  var h = document.documentElement;
  h.classList.add('zyb-modern');   // one look (zyb-look.js): the old Classic choice is retired
  var LOOKV = '__ZYB_BUILD__';
  if (!window.zybLook && !document.querySelector('script[src*="zyb-look.js"]')) {
    var s = document.createElement('script'); s.src = '/dashboards/vendor/zyb-look.js' + (LOOKV.indexOf('__') ? '?v=' + LOOKV : ''); (document.head || h).appendChild(s);
  }
})();

/* English only for now: the portal's own Arabic (toggleLang / applyLang / LANG in its app.js, the "عربي" header button) is
 * kept as it is but not offered. While ARABIC_ON is false the button is hidden and a portal left in Arabic is shown in English
 * (the saved choice, noc_lang, is not touched). Same switch as vendor/zyb-dash.js ARABIC_ON - set both to true together. */
(function () {
  'use strict';
  if (window.__zybEnOnly) return; window.__zybEnOnly = true;
  var ARABIC_ON = true;   // on: the person's choice (sign-in page or Customize) applies to the portal too
  if (window.ZYB_ARABIC === undefined) window.ZYB_ARABIC = ARABIC_ON;
  if (window.ZYB_ARABIC === true) return;
  var css = document.createElement('style'); css.textContent = '#langToggle{display:none!important}'; (document.head || document.documentElement).appendChild(css);
  function en() {
    try {
      // LANG and applyLang are the portal's globals (let / function in app.js); a portal without them is left alone
      if (typeof LANG !== 'undefined' && LANG === 'ar' && typeof applyLang === 'function') { LANG = 'en'; applyLang(); }   // eslint-disable-line no-undef
    } catch (e) { /* not the portal page: nothing to switch */ }
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', en); else en();
  window.addEventListener('load', en);
})();

/* The portal's AI panels all call aiAsk() → POST /api/ai, a route of the old hub that this server does not have: nginx
 * answers with an HTML page and the panel showed 'Unexpected token "<" … is not valid JSON'. The same call, but an answer
 * that is not JSON (or a 404 / 405 / 502) says in words that the portal assistant is not connected and where the platform's
 * AI engineers are. A JSON answer from a real /api/ai is passed through unchanged. Nothing else is sent. */
(function () {
  'use strict';
  if (window.__zybAiAsk) return; window.__zybAiAsk = true;
  var NOT = 'The portal\'s built-in AI assistant is not connected on this server (no /api/ai route). The AI engineers and the AI IT / Cyber Security Auditors run in AI & Automation → AI Engineering Team and AI Auditors.';
  function wrap() {
    if (typeof window.aiAsk !== 'function' || window.aiAsk.__zyb) return;
    var shim = async function (system, prompt, max) {
      var r = await fetch('/api/ai', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ system: system, prompt: prompt, max: max || 1400 }) });
      var txt = await r.text(), j = null;
      try { j = JSON.parse(txt); } catch (e) { j = null; }   // an HTML error page: handled below
      if (!j) throw new Error(r.status === 401 || r.status === 403 ? 'Not allowed to use the AI assistant (HTTP ' + r.status + ').' : NOT);
      if (j.error) throw new Error(j.error);
      return j.text || '';
    };
    shim.__zyb = true;
    try { window.aiAsk = shim; } catch (e) { /* not writable: the portal keeps its own */ }
  }
  wrap(); if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', wrap); setTimeout(wrap, 1500);
})();

/* Clicks on everything this script adds to the menu are routed from the WINDOW, in the capture phase - before any listener
 * the portal's own sidebar code puts on the document or the menu. A newer portal sidebar handles clicks on the whole menu
 * there and stopped them before they reached our items, so the Dashboards pages, workspaces and favorites could not be
 * clicked. An element we handle carries its handler as el._zybClick; everything else is left to the portal untouched. */
(function () {
  'use strict';
  if (window.__zybRoute) return; window.__zybRoute = true;
  function owner(t) { for (var el = t; el && el.nodeType === 1; el = el.parentNode) if (typeof el._zybClick === 'function') return el; return null; }
  window.addEventListener('click', function (e) { var el = owner(e.target); if (el) el._zybClick(e); }, true);
  window.addEventListener('keydown', function (e) {
    if (e.key !== 'Enter' && e.key !== ' ') return;
    var el = e.target && typeof e.target._zybClick === 'function' && e.target.tagName !== 'BUTTON' ? e.target : null;   // a button gets its own click
    if (el) el._zybClick(e);
  }, true);
})();

(function () {
  'use strict';
  if (window.__zybMenu) return; window.__zybMenu = true;
  // a page's compliance frameworks for its tooltip (zyb-nav.js): "\nSAMA 3.3.14 · 3.3.5 | NCA 2-12 | PDPL Art. 19"
  function fwLine(fw) { var t = window.zybFwTags ? window.zybFwTags(fw) : []; return t.length ? '\n' + t.map(function (x) { return x.short + ' ' + x.codes.map(function (c) { return c[0]; }).join(' · '); }).join(' | ') : ''; }
  /* the menu comes from vendor/zyb-nav.js (one registry for the portal menu, the dashboard sidebar and the home page):
     a "Dashboards" group with one collapsible row per workspace, pages indented under it. Open/closed is remembered. */
  var BASE = '/dashboards/', PKEY = 'zyb-pmenu', BUILD0 = '__ZYB_BUILD__';
  // a portal page whose live twin is another portal page: the IT Asset Register falls back to a sample row when its own
  // inventory file is missing; ITAM Inventory reads the live register
  var ALIAS = window.ZYB_PORTAL_ALIAS = { assetreg: 'itam-assets' };
  var SVG = {
    home: '<path d="M3 11 12 4l9 7"/><path d="M5 10v10h14V10"/>', chev: '<path d="m9 6 6 6-6 6"/>',
    gear: '<circle cx="12" cy="12" r="3"/><path d="M12 2v3M12 19v3M4.2 4.2l2.1 2.1M17.7 17.7l2.1 2.1M2 12h3M19 12h3M4.2 19.8l2.1-2.1M17.7 6.3l2.1-2.1"/>',
    device: '<rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8M12 16v4"/>',
    work: '<rect x="3" y="7" width="18" height="13" rx="2"/><path d="M9 7V5h6v2M3 13h18"/>',
    grid: '<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/>'
  };
  // "Start here": the pages flagged start:true in the registry (zyb-nav.js) - shown once, at the top, not again in their area
  var START_ICON = { 'my-workspace.html': ['<circle cx="12" cy="8" r="4"/><path d="M4 21c0-4 4-6 8-6s8 2 8 6"/>', '#f2cc0c'], 'my-work.html': [SVG.work, '#5794f2'], 'connections.html': [SVG.gear, '#73bf69'], 'ai-team.html': [SVG.grid, '#b877d9'],
    'add-server.html': ['<path d="M12 5v14M5 12h14"/>', '#73bf69'], 'network-discovery.html': ['<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="4"/><path d="M12 12l6-6"/>', '#73bf69'] };
  // set-up first: connections, then finding the assets (the portal's discovery pages join here too - see startUp), then the team
  var START_ORDER = ['my-workspace.html', 'my-work.html', 'connections.html', 'add-server.html', 'network-discovery.html', 'ai-team.html'];
  function startPages() { var out = []; (window.ZYB_NAV || []).forEach(function (a) { a.pages.forEach(function (p) { if (p.start) out.push(p); }); });
    var rk = function (p) { var i = START_ORDER.indexOf(p.h); return i < 0 ? 99 : i; }; return out.sort(function (a, b) { return rk(a) - rk(b); }); }
  function headLabel(hd) { var h = (window.ZYB_HEADS || []).filter(function (x) { return x[0] === hd; })[0]; return h ? h[1] : ''; }
  function labelLi(text, key) { var l = document.createElement('li'); l.className = 'zyb-lbl'; l.setAttribute('data-zyb-menu', 'label'); if (key) l.setAttribute('data-zyb-hd', key); l.setAttribute('data-en', text); l.setAttribute('role', 'presentation'); l.textContent = text; return l; }
  function svg(p) { return '<svg viewBox="0 0 24 24" aria-hidden="true" focusable="false">' + p + '</svg>'; }
  function pload() { try { return JSON.parse(localStorage.getItem(PKEY) || '{}') || {}; } catch (e) { return {}; } }
  function psave(s) { try { localStorage.setItem(PKEY, JSON.stringify(s)); } catch (e) { /* storage blocked */ } }
  (function loadNav() {
    if (window.ZYB_NAV || document.querySelector('script[src*="zyb-nav.js"]')) return;
    var add = function (f, then) { var s = document.createElement('script'); s.src = BASE + 'vendor/' + f + (BUILD0.indexOf('__') ? '?v=' + BUILD0 : ''); if (then) s.onload = s.onerror = then; (document.head || document.documentElement).appendChild(s); };
    // the registry names the company through the brand setting (vendor/zyb-org.js): on a portal page that does not carry it
    // yet (the installed build has it built in, and add-dashboards-menu.sh adds the tag) it is fetched first
    if (!window.ZYB_ORG) add('zyb-org.js', function () { add('zyb-nav.js'); }); else add('zyb-nav.js');
  })();
  (function menuCss() {
    if (document.getElementById('zyb-pmenu-css')) return;
    var c = document.createElement('style'); c.id = 'zyb-pmenu-css';
    // no list bullets anywhere in the menu (the portal's own items are plain <li> and some themes give them a marker)
    c.textContent = 'ul.nav,ul.nav ul{list-style:none!important;padding-left:0}ul.nav li{list-style:none!important}ul.nav li::marker{content:none!important;font-size:0}ul.nav li .ico.zyb-noico{display:none!important}'
      + 'ul.nav li.zyb-area{display:flex!important;align-items:center;gap:9px;cursor:pointer;user-select:none}'
      + 'ul.nav li.zyb-area .zyb-aic,ul.nav li[data-zyb-menu] .zyb-aic{width:22px;height:22px;border-radius:6px;display:inline-grid;place-items:center;flex:0 0 auto;background:color-mix(in srgb,var(--c,#8C93A1) 16%,transparent);color:var(--c,#aab1bd)}'
      + 'ul.nav li .zyb-aic svg,ul.nav li.zyb-area .zyb-chv{width:13px;height:13px;fill:none;stroke:currentColor;stroke-width:2;stroke-linecap:round;stroke-linejoin:round}'
      + 'ul.nav li.zyb-area .zyb-an{flex:1;min-width:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;font-weight:600}'
      + 'ul.nav li.zyb-area .zyb-cnt{font-size:10.5px;line-height:16px;opacity:.65;border:1px solid rgba(255,255,255,.16);border-radius:999px;padding:0 6px}'
      + 'ul.nav li.zyb-area .zyb-chv{opacity:.55;transition:transform .15s;flex:0 0 auto}ul.nav li.zyb-area.zyb-open .zyb-chv{transform:rotate(90deg)}'
      + 'ul.nav li.zyb-sub{position:relative;padding-left:46px!important;font-size:.93em;opacity:.86}ul.nav li.zyb-sub:hover,ul.nav li.zyb-sub:focus-visible{opacity:1}'
      + 'ul.nav li.zyb-sub::before{content:"";position:absolute;left:27px;top:0;bottom:0;border-left:1px solid rgba(255,255,255,.12)}'
      + 'ul.nav li.zyb-sub.zyb-sg::before,ul.nav li.zyb-sub.zyb-sg::after{display:none!important;content:none!important}'   /* a sub-menu heading: no bullet, no tree line */
      + 'ul.nav li.zyb-sg{cursor:pointer;gap:7px;font-size:10px!important;font-weight:700;text-transform:uppercase;letter-spacing:.07em;opacity:.8!important;padding-top:7px!important;padding-bottom:2px!important;min-height:0!important;background:none!important}ul.nav li.zyb-sg:hover{opacity:1!important}'
      + 'ul.nav li.zyb-sg .zyb-sgi{display:inline-flex;align-items:center;justify-content:center;width:18px;height:18px;border-radius:5px;background:color-mix(in srgb,var(--sc) 18%,transparent);flex:none}ul.nav li.zyb-sg .zyb-sgi svg{width:12px;height:12px;stroke:var(--sc);fill:none;stroke-width:2;stroke-linecap:round;stroke-linejoin:round}'
      + 'ul.nav li.zyb-sg .zyb-sgt{flex:1}ul.nav li.zyb-sg .zyb-sgc{width:11px;height:11px;stroke:currentColor;fill:none;stroke-width:2;transition:transform .15s;transform:rotate(90deg)}ul.nav li.zyb-sg.zyb-sgshut .zyb-sgc{transform:rotate(0)}ul.nav.nav li.zyb-sub.zyb-sub[data-zyb-sgcol][data-zyb-g]{display:none!important}'
      + 'ul.nav:not(.zyb-sm-open):not(.zyb-editing) li[data-zyb-startmore]{display:none!important}ul.nav li.zyb-sm-tg{font-size:12px!important;opacity:.75;cursor:pointer;padding-left:30px!important}ul.nav li.zyb-sm-tg::after{content:" ▸"}ul.nav.zyb-sm-open li.zyb-sm-tg::after{content:" ▾"}ul.nav li[data-zyb-startmore]{padding-left:30px!important}'
      + 'ul.nav li.as-navmode{display:none!important}'
      + 'ul.nav:not(.zyb-editing) li.zyb-sub.zyb-sub[data-zyb-more]:not([data-zyb-moreopen]):not([data-zyb-col]):not(.tree-hidden):not([data-zyb-dup]){display:none!important}ul.nav li.zyb-sm-tg.zyb-more-open::after{content:" ▾"}'   /* the portal's one-section switch: the workspaces already open one at a time */
      + 'ul.nav li.nav-group.zyb-empty{display:none!important}ul.nav:not(.zyb-editing) li[data-zyb-dup]{display:none!important}ul.nav.zyb-editing li[data-zyb-dup],html ul.nav.zyb-editing li.zyb-sub[data-zyb-dup]{opacity:.5!important}'
      + 'ul.nav li.zyb-lbl{list-style:none;font:700 10.5px/1 system-ui,sans-serif;letter-spacing:.1em;text-transform:uppercase;color:#7d8794;padding:12px 12px 6px;cursor:default}'
      + 'ul.nav li.zyb-lbl.tree-hidden,ul.nav li.zyb-area.tree-hidden,ul.nav li.zyb-link.tree-hidden,ul.nav li.zyb-sub.tree-hidden,ul.nav li.zyb-merged.tree-hidden{display:none!important}'   /* the portal collapsed Dashboards */
      /* the portal's one-section mode (ZS-NAVAUTO) hides everything after a closed portal heading with .nav-hid: the five
         headings and Start here are ours and never belong to a portal section */
      + 'ul.nav li.zyb-lbl.nav-hid:not([data-zyb-gc]){display:block!important}ul.nav li[data-zyb-start].nav-hid:not([data-zyb-gc]):not([data-zyb-startmore]){display:flex!important}'
      + 'ul.nav li[data-zyb-gc]{display:none!important}ul.nav li .zyb-chev{float:right;opacity:.6;margin-left:6px}'
      /* a page of an OPEN workspace is shown whatever way the portal hides collapsed items (an inline display:none or the hidden
         attribute set by its collapse tree, which our rows already override): the workspace's own open / closed state decides */
      + 'ul.nav li.zyb-sub:not([data-zyb-col]):not(.tree-hidden):not([data-zyb-dup]){display:flex!important;align-items:center}'
      + 'ul.nav li[data-zyb-col]{display:none!important}ul.nav li.zyb-link{display:flex!important;align-items:center;gap:9px}ul.nav li.zyb-link>.zyb-star{margin-left:auto}';
    (document.head || document.documentElement).appendChild(c);
  })();

  /* The original flat menu, item for item (pages added since follow it). Used ONLY as the safety net when the page list
     cannot load - the interface itself is always the Modern menu. */
  var CLASSIC = [
    ['head-of-it.html', '📊', 'IT Command Center (Head of IT)'],
    ['soc-tickets.html', '🛡️', 'SIEM Health & SLA (CISO)'],
    ['soc-live.html', '⚡', 'SIEM Live Logs (real time)'],
    ['soc-sources.html', '🔌', 'SIEM Log Sources & Windows Agents'],
    ['log-assurance.html', '📶', 'Log Flow Assurance'],
    ['soc-ueba.html', '👤', 'SOC User Behaviour (UEBA)'],
    ['soc-response.html', '✅', 'SOC Response: Playbooks & Approvals'],
    ['soc-xdr.html', '🧩', 'SOC XDR (cross-domain incidents)'],
    ['soc-lr.html', '⚖️', 'SIEM vs LogRhythm'],
    ['soc-intel.html', '🌐', 'SOC Threat Intel & After-hours'],
    ['network-engineer.html', '🤖', 'AI Network Engineer'],
    ['windows-admin.html', '🪟', 'AI Windows Server Administrator'],
    ['exchange-admin.html', '📧', 'AI Exchange Server Administrator'],
    ['server-availability.html', '🟢', 'Server Availability'],
    ['end-user-devices.html', '💻', 'End-User Devices (Infra Asst. Manager)'],
    ['ad-exchange.html', '🏛️', 'AD & Exchange (live)'],
    ['threats-by-department.html', '🎯', 'Threats by Department'],
    ['ad-audit.html', '🧾', 'Active Directory Audit'],
    ['add-server.html', '➕', 'Add a Server or Network Device (Asset Discovery)'],
    ['network-discovery.html', '🛰️', 'Network Discovery - add many devices (IP range / subnet / CSV)'],
    ['manageengine.html', '🎫', 'ManageEngine - ServiceDesk Plus tickets & Endpoint Central (approvals)'],
    ['capacity.html', '📈', 'Capacity Planning - VMware & Nutanix'],
    ['support-contracts.html', '🛡', 'Support Contracts - all vendors'],
    ['licence-audit.html', '🧮', 'Licensing Audit'],
    ['printers.html', '🖨️', 'Printers (Xerox / SAFEQ)'],
    ['m365.html', '☁️', 'Microsoft 365 (live)'],
    ['virtualization.html', '🖥️', 'Virtualization (vCenter & Nutanix)'],
    ['storage.html', '🗄️', 'Storage (NetApp, HPE MSA)'],
    ['reconcile.html', '🔀', 'Server & Asset Reconciliation'],
    ['budget.html', '💰', 'IT Budget (CAPEX / OPEX)'],
    ['backup.html', '💾', 'Backup Coverage (NetBackup, Veeam, Cohesity)'],
    ['lifecycle.html', '⏳', 'End of Life & Isolation'],
    ['platform.html', '🩺', 'Platform Health & Backup'],
    ['roles.html', '🧩', 'Roles & Functions'],
    ['it-audit.html', '📋', 'IT Audit'],
    ['audit-log.html', '🔐', 'Audit Log'],
    ['network-flows.html', '🌐', 'Network Flows'],
    ['apm-claims-portal.html', '⏱️', 'Claims Portal Performance'],
    ['portal-traffic.html', '📈', 'Portal Traffic Overview'],
    ['', '🗂️', 'All dashboards']
  ];
  var CLASSIC_NEW = { 'asset-ownership.html': '🏷️', 'ai-ciso.html': '🧭', 'ai-dba.html': '🛢️', 'ai-sql-dba.html': '🗄️', 'ai-app-manager.html': '📦', 'ai-grc-consultant.html': '⚖️', 'ai-virt-admin.html': '🖥️', 'virt-power.html': '⏻', 'handover.html': '🤝', 'log-assurance.html': '📶', 'ai-team.html': '🤖', 'noc-overview.html': '🛰️', 'nutanix-vms.html': '🧱', 'db-performance.html': '🗃️', 'desk-support.html': '🧑‍💻',
    'ai-security-engineer.html': '🔥', 'sdwan.html': '🔗', 'npm-summary.html': '📶', 'wireless.html': '📡', 'pentest.html': '🗡️', 'vuln-scans.html': '🎯', 'vapt-studio.html': '🛡️', 'grc-policies.html': '📜', 'grc-workspace.html': '🎯', 'credential-security.html': '🔐', 'databases.html': '🗄️', 'oracle-tuning.html': '🛠️', 'db-servers.html': '🖥️', 'db-audit.html': '🔍', 'app-audit.html': '📋', 'compliance-map.html': '🧭', 'live-compliance.html': '🛡️', 'domains.html': '🌐', 'dr-replication.html': '🔄', 'dr-studio.html': '🛰️', 'vsphere-studio.html': '🧊', 'db-replication.html': '🔁', 'user-management.html': '👥', 'applications.html': '🧩',
    'sama-compliance.html': '🏦', 'dr-drills.html': '🔄', 'dfir.html': '🔬', 'detection-validation.html': '🧪' };
  // one interface for everyone (Modern); the old Classic choice is cleared. The classic list is kept only as the safety
  // net when the page list could not load (window.__zybMenuFallback) - never a user choice.
  try { localStorage.removeItem('zyb-ui'); } catch (e) { /* storage blocked */ }
  function uiMode() { return 'modern'; }
  /* the style selector is retired (one interface): remove one left on the page by an older copy of this script */
  function uiSwitch() { var s = document.getElementById('zyb-ui-sel'); if (s) s.remove(); }

  /* the "Dashboards" heading opens / closes everything under it, like the portal's own headings, in both styles. Our
     handler runs first and stops the portal's (which may have been attached to an earlier copy of the heading). */
  function headToggle(nav, head) {
    /* the heading itself is no longer drawn (zyb-vivid.css), so a fold remembered from before could never be undone: it hid
       every workspace row while the open workspace's pages stayed, and nothing could be collapsed. Start open, forget it. */
    var st = pload(), closed = false; if (st.dash_closed) { delete st.dash_closed; psave(st); }
    var chev = document.createElement('span'); chev.className = 'chev zyb-chev'; head.appendChild(chev);
    var apply = function () {
      head.classList.toggle('open', !closed); chev.textContent = closed ? '▸' : '▾'; head.setAttribute('aria-expanded', String(!closed));
      var x = head.nextElementSibling;
      while (x && !x.classList.contains('nav-group')) { if ((/^(item|area|switch)$/.test(x.getAttribute('data-zyb-menu') || '') || x.hasAttribute('data-zyb-start')) && !x.classList.contains('zyb-merged')) { if (closed) x.setAttribute('data-zyb-gc', ''); else x.removeAttribute('data-zyb-gc'); } x = x.nextElementSibling; }
    };
    var fire = function (e) { e.preventDefault(); e.stopPropagation(); if (e.stopImmediatePropagation) e.stopImmediatePropagation(); closed = !closed; var s2 = pload(); s2.dash_closed = closed; psave(s2); apply(); };
    head.setAttribute('role', 'button'); head.tabIndex = 0; head.style.cursor = 'pointer';
    head._zybClick = fire; head.addEventListener('click', fire, true);
    head.addEventListener('keydown', function (e) { if (e.key === 'Enter' || e.key === ' ') fire(e); }, true);
    apply();
  }

  function addClassic(nav) {
    var sampleGroup = nav.querySelector('li.nav-group'), sampleItem = nav.querySelector('li[data-view]');
    var head = document.createElement('li');
    head.className = sampleGroup ? sampleGroup.className : 'nav-group';
    head.setAttribute('data-en', 'Dashboards'); head.setAttribute('data-zyb-menu', 'group');
    head.textContent = 'Dashboards';
    var frag = document.createDocumentFragment(); frag.appendChild(head);
    var have = {}; CLASSIC.forEach(function (it) { have[it[0]] = 1; });
    var extra = [];
    (window.ZYB_NAV || []).forEach(function (a) { a.pages.forEach(function (p) { if (!have[p.h]) extra.push([p.h, CLASSIC_NEW[p.h] || '📄', p.t]); }); });
    CLASSIC.slice(0, -1).concat(extra).concat(CLASSIC.slice(-1)).forEach(function (it) { frag.appendChild(makeItem(it, sampleItem, 'item')); });

    nav.insertBefore(frag, nav.firstChild);
    headToggle(nav, head);
    infraItem(nav);
    return true;
  }

  function go(e, href) { e.preventDefault(); e.stopPropagation(); if (e.stopImmediatePropagation) e.stopImmediatePropagation(); if (!window.zybDash || !window.zybDash.open(href)) window.location.href = href; }

  function addToNav(nav, classic) {
    if (nav.querySelector('[data-zyb-menu="group"]')) return true;
    if (classic || uiMode() === 'classic') return addClassic(nav);
    var areas = window.ZYB_NAV; if (!areas || !areas.length) return false;      // wait until the registry has loaded
    var sampleGroup = nav.querySelector('li.nav-group'), sampleItem = nav.querySelector('li[data-view]');
    var st = pload(), open = st.open || {};
    var head = document.createElement('li');
    head.className = sampleGroup ? sampleGroup.className : 'nav-group';
    head.setAttribute('data-en', 'Dashboards'); head.setAttribute('data-zyb-menu', 'group');
    head.textContent = 'Dashboards';
    var frag = document.createDocumentFragment(); frag.appendChild(head);
    frag.appendChild(makeItem(['', SVG.home, 'All dashboards'], sampleItem, 'item', '#8C93A1'));
    var sp = startPages();
    if (sp.length) { frag.appendChild(labelLi('Start here')); sp.forEach(function (p) { var ic = START_ICON[p.h] || [SVG.home, '#8C93A1']; frag.appendChild(makeItem([p.h, ic[0], p.s], sampleItem, 'item', ic[1])); }); }
    var merged = null, lastHd = '';
    areas.forEach(function (a) {
      // (the AI workspace no longer joins the portal's AI group: the portal's AI pages move into this workspace instead)
      if (a.hd && a.hd !== lastHd) { lastHd = a.hd; var hl = headLabel(a.hd); if (hl) frag.appendChild(labelLi(hl, a.hd)); }   // the five headings
      var pages = a.pages.filter(function (p) { return !p.start; });   // a Start-here page is not repeated in its area
      var row = document.createElement('li'), isOpen = open[a.id] === undefined ? a.id === 'cmd' && window.innerHeight >= 950 : !!open[a.id];   // 15 areas: closed (with their count) until opened, Command Center open; the choice is remembered
      row.className = ((sampleItem ? sampleItem.className.replace(/\bactive\b/g, '').trim() : '') + ' zyb-area' + (isOpen ? ' zyb-open' : '')).trim();
      row.setAttribute('data-zyb-menu', 'area'); row.setAttribute('data-zyb-area', a.id); row.setAttribute('data-en', a.name);
      row.setAttribute('role', 'button'); row.setAttribute('aria-expanded', String(isOpen)); row.tabIndex = 0; row.style.setProperty('--c', a.c);
      row.innerHTML = '<span class="zyb-aic">' + svg(a.icon) + '</span><span class="zyb-an"></span><span class="zyb-cnt">' + pages.length + '</span><svg class="zyb-chv" viewBox="0 0 24 24" aria-hidden="true">' + SVG.chev + '</svg>';
      row.querySelector('.zyb-an').textContent = a.sn || a.name; row.title = a.name;
      var toggle = function (e) {
        e.preventDefault(); e.stopPropagation(); if (e.stopImmediatePropagation) e.stopImmediatePropagation();
        var o = !row.classList.contains('zyb-open');
        if (o) [].forEach.call(nav.querySelectorAll('li.zyb-area.zyb-open'), function (r) {   // one workspace open at a time: the menu stays short and in order
          if (r === row) return; var id = r.getAttribute('data-zyb-area'); r.classList.remove('zyb-open'); r.setAttribute('aria-expanded', 'false'); open[id] = false;
          [].forEach.call(nav.querySelectorAll('li.zyb-sub[data-zyb-area="' + id + '"]'), function (li) { li.setAttribute('data-zyb-col', ''); }); });
        row.classList.toggle('zyb-open', o); row.setAttribute('aria-expanded', String(o));
        [].forEach.call(nav.querySelectorAll('li.zyb-sub[data-zyb-area="' + a.id + '"]'), function (li) { if (o) { li.removeAttribute('data-zyb-col'); li.hidden = false; if (li.style.display === 'none') li.style.removeProperty('display'); } else li.setAttribute('data-zyb-col', ''); });
        open[a.id] = o; st.open = open; psave(st);
      };
      row._zybClick = toggle; row.addEventListener('click', toggle, true);
      row.addEventListener('keydown', function (e) { if (e.key === 'Enter' || e.key === ' ') toggle(e); }, true);
      frag.appendChild(row);
      var lastG = null;
      pages.forEach(function (p) {
        // a sub-menu inside the workspace (zyb-nav.js page field g: GRC / Regulators & frameworks / Audit, Servers / Virtualization)
        if (p.g && p.g !== lastG) {
          // the heading opens / hides its pages (remembered per heading); a coloured icon from zybSgStyle (zyb-nav.js)
          var sgk = a.id + '|' + p.g, sgShut = !!((st.sgshut || {})[sgk]), sy = window.zybSgStyle ? window.zybSgStyle(p.g) : { c: '#6b7280', icon: '' };
          var sg = document.createElement('li'); sg.className = 'zyb-sub zyb-sg' + (sgShut ? ' zyb-sgshut' : ''); sg.setAttribute('data-zyb-area', a.id); sg.setAttribute('data-zyb-g', sgk);
          sg.setAttribute('role', 'button'); sg.tabIndex = 0; sg.setAttribute('aria-expanded', String(!sgShut)); sg.title = p.g + ' - open / hide'; sg.style.setProperty('--sc', sy.c);
          sg.innerHTML = '<span class="zyb-sgi"><svg viewBox="0 0 24 24" aria-hidden="true">' + sy.icon + '</svg></span><span class="zyb-sgt"></span><svg class="zyb-sgc" viewBox="0 0 24 24" aria-hidden="true">' + SVG.chev + '</svg>';
          sg.querySelector('.zyb-sgt').textContent = p.g;
          (function (sg, sgk) {
            var flip = function (e) {
              e.preventDefault(); e.stopPropagation(); if (e.stopImmediatePropagation) e.stopImmediatePropagation();
              var shut = !sg.classList.contains('zyb-sgshut'), s2 = pload(); s2.sgshut = s2.sgshut || {};
              sg.classList.toggle('zyb-sgshut', shut); sg.setAttribute('aria-expanded', String(!shut));
              [].forEach.call(nav.querySelectorAll('li.zyb-sub[data-zyb-g="' + sgk.replace(/"/g, '\\"') + '"]:not(.zyb-sg)'), function (li) { if (shut) li.setAttribute('data-zyb-sgcol', ''); else li.removeAttribute('data-zyb-sgcol'); });
              if (shut) s2.sgshut[sgk] = true; else delete s2.sgshut[sgk]; psave(s2); st.sgshut = s2.sgshut;
            };
            sg.addEventListener('click', flip, true); sg.addEventListener('keydown', function (e) { if (e.key === 'Enter' || e.key === ' ') flip(e); }, true);
          })(sg, sgk);
          if (!isOpen) sg.setAttribute('data-zyb-col', '');
          frag.appendChild(sg);
        }
        lastG = p.g || null;
        var li = makeItem([p.h, '', p.s], sampleItem, 'item'); li.classList.add('zyb-sub'); li.setAttribute('data-zyb-area', a.id); li.title = p.t + fwLine(p.fw);
        if (p.g) { var gk = a.id + '|' + p.g; li.setAttribute('data-zyb-g', gk); if ((st.sgshut || {})[gk]) li.setAttribute('data-zyb-sgcol', ''); }
        if (!isOpen) li.setAttribute('data-zyb-col', '');
        frag.appendChild(li);
      });
    });

    nav.insertBefore(frag, nav.firstChild);
    headToggle(nav, head);
    if (merged) mergeIntoPortalGroup(nav, merged.head, merged.area, sampleItem);
    infraItem(nav);
    return true;
  }
  /* One AI & Automation place: when the portal already has an "AI & Automation" group, the AI engineers, the team
     overview and the playbooks join THAT group (after its own items) instead of a second workspace beside it. */
  function gname(li) { var c = li.cloneNode(true); [].forEach.call(c.querySelectorAll('.chev,.badge,.zyb-mv,svg'), function (x) { x.remove(); }); return (li.getAttribute('data-en') || c.textContent).replace(/[▸▾▼►▶▲△▽]/g, '').replace(/\s+\d+$/, '').replace(/\s+/g, ' ').trim(); }
  function portalAiGroup(nav) {
    return [].filter.call(nav.children, function (li) { return li.classList.contains('nav-group') && !li.getAttribute('data-zyb-menu') && /^ai\s*(&|and)\s*automation$/i.test(gname(li)); })[0] || null;
  }
  function mergeIntoPortalGroup(nav, head, area, sampleItem) {
    var kids = [], x = head.nextElementSibling;
    while (x && !x.classList.contains('nav-group')) { if (!x.getAttribute('data-zyb-menu')) kids.push(x); x = x.nextElementSibling; }
    var after = kids.length ? kids[kids.length - 1] : head, ours = [];
    area.pages.filter(function (p) { return !p.start; }).forEach(function (p) {   // Start-here pages are already at the top
      var li = makeItem([p.h, svg(area.icon), p.s], sampleItem, 'item', area.c); li.classList.add('zyb-merged'); li.setAttribute('data-zyb-area', area.id); li.title = p.t + ' — dashboard' + fwLine(p.fw);
      after.parentNode.insertBefore(li, after.nextSibling); after = li; ours.push(li);
    });
    // hide / show with the portal's own items when the portal collapses the group, however it does it
    var ref = kids[0];
    if (ref) {
      var sync = function () { var hide = ref.classList.contains('tree-hidden') || getComputedStyle(ref).display === 'none'; ours.forEach(function (li) { li.classList.toggle('tree-hidden', hide); }); };
      sync(); new MutationObserver(sync).observe(ref, { attributes: true, attributeFilter: ['class', 'style', 'hidden'] });
    }
  }
  /* the End-User Devices dashboard also sits in the portal's infrastructure section, right under "IT Infrastructure Dashboard" */
  var INFRA = ['end-user-devices.html', SVG.device, 'End-User Devices'];
  /* the portal's own "AD & Exchange" page shows fixed sample data: its menu entry opens the live dashboard instead */
  var LIVE = { adex: 'ad-exchange.html', 'itam-assets': 'inventory.html', 'itam-ai': 'ai-findings.html', 'itam-stocktake': 'stocktake.html', itam: 'itam-overview.html', costopt: 'cost-optimisation.html', budget: 'budget.html#exec', 'itam-settings': 'itam-settings.html', 'itam-software': 'software-studio.html', cloudsrv: 'servers.html', ups: 'facilities.html#ups', door: 'door-access.html', printers: 'printers.html', ipam: 'ipam.html', ncm: 'ncm.html', m365sec: 'm365-security.html', branchnet: 'branch-connectivity.html', 'dash-fac': 'facilities.html', 'intune': 'mdm.html', 'dash-soc': 'soc-overview.html', 'agents': 'ai-team.html', 'managed': 'service-agreement.html', 'infra-wanopt': 'wan-optimization.html', 'upd-overview': 'cisco-update.html', 'upd-inventory': 'cisco-update.html#view=devices', 'upd-advisories': 'cisco-update.html#view=advisories', 'upd-plans': 'cisco-update.html#view=plans', 'upd-policy': 'cisco-update.html#view=policy', 'upd-connections': 'cisco-update.html#view=connections', command: 'executive-dashboard.html', posture: 'risk-command.html', servicedesk: 'support-center.html', support: 'support-center.html', 'dash-net': 'network-dashboard.html', infradash: 'infra-manager.html', ciodash: 'cio-dashboard.html', cisodash: 'ciso-dashboard.html', ciso: 'executive-dashboard.html', status: 'live-status.html', home: 'index.html', phishsim: 'phishing-simulation.html', brandprot: 'brand-protection.html', forensics: 'dfir.html', ir: 'incident-response.html', soar: 'soar.html', tickets: 'tickets.html', cctv: 'cctv.html', appsec: 'appsec.html', apppt: 'apppt.html', crosswalk: 'crosswalk.html', gapall: 'gap-analysis.html', 'dash-grc': 'grc-dashboard.html', 'dash-vuln': 'vuln-dashboard.html', scanlive: 'live-scan.html', webapi: 'webapps.html', mobile: 'mobile-test.html', iso: 'iso-lifecycle.html', ecc: 'ecc-studio.html', roadmap: 'roadmap.html', risk: 'risk-assess.html', 'siem-sama': 'sama-siem.html', maturity: 'maturity-level.html', netcfg: 'network-config-audit.html', roles: 'roles-raci.html', ncaaudit: 'nca-it-audit.html', ndmostudio: 'ndmo-studio.html', ndmo: 'ndmo-studio.html', pdpl: 'pdpl-studio.html', chain: 'compliance-flow.html', fwlib: 'framework-library.html', aigov: 'ai-governance.html', infraai: 'infra-ai.html', bcm: 'bcm-matrix.html', grc: 'compliance-overview.html', contcomp: 'continuous-compliance.html', validation: 'control-validation.html', custody: 'evidence-custody.html', docs: 'compliance-docs.html', controls: 'security-controls.html', archer: 'grc-register.html', iafw: 'ia-resilience.html', irm: 'insider-risk.html', sama: 'sama-audit.html', 'sama-validation': 'sama-audit.html', 'discovery': 'discovery-studio.html', 'itam-discovery': 'discovery-studio.html', 'discovery-results': 'discovery-studio.html#view=res', 'discovery-runs': 'discovery-studio.html#view=runs', 'discovery-credentials': 'discovery-studio.html#view=cred', 'discovery-scopes': 'scope-studio.html', 'vuln-assets': 'scanned-assets.html', repcenter: 'report-center.html', notify: 'notify-center.html', alarmrules: 'alarm-rules.html', 'soc-rules': 'alarm-rules.html', signin: 'identity-signin.html', users: 'user-management.html', twin: 'digital-twin.html',   // the portal's role dashboards (infra / CIO / CISO) showed sample telemetry
    /* portal pages that draw sample telemetry / typed-in figures (found by rendering every portal view): the live page
       that reads the same subject from the platform's collectors */
    sam: 'apm.html', npmmon: 'npm-summary.html', npm: 'npm-summary.html', netperf: 'branch-connectivity.html', traffic: 'netflow.html', udt: 'rogue-detection.html', wireless: 'wireless.html', dbperf: 'db-performance.html', exchmgmt: 'exchange-admin.html', datagov: 'dlp.html',
    detstudio: 'detection-validation.html', node: 'server-availability.html', scm: 'manageengine.html', 'dash-rep': 'platform.html', 'dash-m365': 'm365-dashboard.html', portmap: 'switch-port-map.html', topology: 'network-map.html', logs: 'log-monitor.html', siemlive: 'soc-live.html', spo: 'sharepoint.html#activity', changelog: 'change-log.html', hunt: 'soc-hunt.html', rogue: 'rogue-detection.html', security: 'security-center.html', soc: 'security-center.html', noc: 'ops-wall.html?view=sites', aisoc: 'ai-soc-analyst.html', socops: 'soc-performance.html', msauto: 'm365-autoconfig.html', wazuh: 'soc-console.html', 'tiw-darkweb': 'dark-web-watch.html', nac: 'network-access.html', itops: 'update-studio.html', netinv: 'infra-inventory.html', 'dash-srv': 'servers-dashboard.html', wall: 'ops-wall.html', 'itam-cmdb': 'cmdb-deps.html', implplan: 'impl-plan.html', browsing: 'browsing-monitor.html', configure: 'device-config.html',
    aiteam: 'ai-team.html', aiops: 'aiops.html', repl: 'dr-studio.html', virtualization: 'vsphere-studio.html' };   // the portal's AI Team reviews called the old hub's /api/ai, absent here: the live AI Engineering Team (with the AI auditors)
  function liveRedirects(nav) {
    Object.keys(LIVE).forEach(function (v) {
      var li = nav.querySelector('li[data-view="' + v + '"]'); if (!li || li.getAttribute('data-zyb-live')) return;
      var href = BASE + LIVE[v]; li.setAttribute('data-zyb-live', '1'); li.setAttribute('data-zyb-href', href);
      li._zybClick = function (e) { go(e, href); };
      li.addEventListener('click', li._zybClick, true);
      li.addEventListener('keydown', function (e) { if (e.key === 'Enter' || e.key === ' ') go(e, href); }, true);
    });
    /* its settings get their own entry right under it */
    var ad = nav.querySelector('li[data-view="adex"]');
    if (ad && !nav.querySelector('[data-zyb-menu="adcfg"]')) ad.parentNode.insertBefore(makeItem(['ad-exchange.html#config', SVG.gear, 'AD & Exchange Configuration'], ad, 'adcfg'), ad.nextSibling);
    /* Microsoft 365: the connection (tenant, app, secret) is set on the live page */
    var ms = nav.querySelector('li[data-view="m365"]');
    if (ms && !nav.querySelector('[data-zyb-menu="m365cfg"]')) ms.parentNode.insertBefore(makeItem(['m365.html#config', SVG.gear, 'Microsoft 365 Configuration'], ms, 'm365cfg'), ms.nextSibling);
  }
  /* "Everything in this section" cards and other [data-gotoview] tiles: always open their page (the portal wires them on
     some pages only); pages listed in LIVE open the live dashboard */
  if (!window.__zybGoto) {
    window.__zybGoto = true;
    document.addEventListener('click', function (e) {
      var el = e.target && e.target.closest && e.target.closest('[data-gotoview]'); if (!el || el.closest('#zd')) return;
      var v = el.getAttribute('data-gotoview'); if (!v) return; if (ALIAS[v]) v = ALIAS[v];
      if (LIVE[v]) { go(e, BASE + LIVE[v]); return; }
      if (typeof el.onclick === 'function') return;   // the portal handles this one
      try { if (typeof window.setView === 'function') { e.preventDefault(); window.setView(v); window.scrollTo(0, 0); } } catch (er) { /* leave it to the portal */ }
    }, true);
    if (typeof window.setView === 'function' && !window.setView.__zyb) {   // any other way of opening the sample page goes to the live one too
      var sv = window.setView; window.setView = function (v) { if (ALIAS[v]) v = ALIAS[v]; if (LIVE[v]) { if (!window.zybDash || !window.zybDash.open(BASE + LIVE[v])) window.location.href = BASE + LIVE[v]; return; } if (window.zybDash) window.zybDash.close(); var a = [].slice.call(arguments); a[0] = v; return sv.apply(this, a); }; window.setView.__zyb = true;
    }
  }
  function infraItem(nav) {
    liveRedirects(nav);
    if (nav.querySelector('[data-zyb-menu="infra"]')) return;
    if ((window.ZYB_NAV || []).some(function (a) { return a.pages.some(function (p) { return p.h === INFRA[0]; }); })) return;   // already a page of a workspace
    var anchor = nav.querySelector('li[data-en="IT Infrastructure Dashboard"]') || [].filter.call(nav.querySelectorAll('li.nav-group'), function (g) { return /infra/i.test(g.getAttribute('data-en') || g.textContent); })[0];
    if (!anchor) return;
    anchor.parentNode.insertBefore(makeItem(INFRA, nav.querySelector('li[data-view]'), 'infra'), anchor.nextSibling);
  }
  function makeItem(it, sampleItem, kind, color) {
      var li = document.createElement('li');
      if (sampleItem) { li.className = sampleItem.className.replace(/\bactive\b/g, '').trim(); }
      li.setAttribute('data-en', it[2]); li.setAttribute('data-zyb-menu', kind);
      li.setAttribute('role', 'link'); li.tabIndex = 0;
      if (it[1] && it[1].charAt(0) !== '<') {   // classic: the emoji, exactly as the original menu drew it
        var em = document.createElement('span'); em.className = 'ico'; em.textContent = it[1]; li.appendChild(em); li.appendChild(document.createTextNode(' '));
      } else if (it[1]) {   // fixed line icon (a constant above, never data)
        li.classList.add('zyb-link'); if (color) li.style.setProperty('--c', color);
        var ico = document.createElement('span'); ico.className = 'zyb-aic'; ico.innerHTML = svg(it[1]); li.appendChild(ico);
      }
      li.appendChild(document.createTextNode(it[2]));
      var href = BASE + it[0];
      li.setAttribute('data-zyb-href', href);
      li._zybClick = function (e) { go(e, href); };
      li.addEventListener('click', li._zybClick, true);
      li.addEventListener('keydown', function (e) { if (e.key === 'Enter' || e.key === ' ') go(e, href); }, true);
      return li;
  }

  function fallbackButton() {
    if (document.getElementById('zyb-dash-btn')) return;
    var a = document.createElement('a');
    a.id = 'zyb-dash-btn'; a.href = BASE; a.textContent = 'Dashboards';
    a.style.cssText = 'position:fixed;right:16px;bottom:16px;z-index:9999;background:#D7262D;color:#fff;font:600 13px/1 system-ui,sans-serif;padding:10px 14px;border-radius:999px;text-decoration:none;box-shadow:0 8px 24px rgba(0,0,0,.4)';
    document.body.appendChild(a);
  }


  /* ---- compact brand header: replaces the two large white logo boxes at the top of the sidebar ---- */
  function isLogo(img) { return /zyberon-logo|(^|\/)logo\.webp/i.test(img.getAttribute('src') || ''); }
  function boxOf(img, side) {
    /* the logo's own card: climb while the parent still holds only this logo (stop at the sidebar) */
    var el = img;
    for (var i = 0; i < 3 && el.parentElement && el.parentElement !== side; i++) {
      var p = el.parentElement; if (p.querySelectorAll('img').length > 1 || p.querySelector('ul.nav,input')) break; el = p;
    }
    return el;
  }
  function brandOn() { document.documentElement.classList.add('zyb-brand-on'); }   // zyb-early.js hides the old logos until then
  function brand(nav) {
    if (document.getElementById('zyb-brand')) return;
    var side = nav.parentElement, logos = [];
    for (var up = 0; side && side !== document.body && up < 6; up++) {
      var nr = nav.getBoundingClientRect();
      /* only the logos above the menu, in the menu's own column (never a logo in the page content) */
      logos = [].filter.call(side.querySelectorAll('img'), function (im) { if (!isLogo(im) || im.closest('#zyb-brand')) return false; var r = im.getBoundingClientRect(); return r.bottom <= nr.top + 4 && r.left >= nr.left - 60 && r.right <= nr.right + 60; });
      if (logos.length) break; side = side.parentElement;
    }
    if (!logos.length) { brandOn(); return; }
    var boxes = logos.map(function (im) { return boxOf(im, side); });
    var css = document.createElement('style'); css.id = 'zyb-brand-css';
    css.textContent = '#zyb-brand{display:flex;flex-direction:column;align-items:flex-start;gap:8px;padding:14px 14px 12px;margin:0 0 10px;border-bottom:1px solid rgba(255,255,255,.08)}'
      + '#zyb-brand .zb-chip{background:#fff;border-radius:8px;padding:6px 10px;display:flex;max-width:100%;box-sizing:border-box}'
      + '#zyb-brand .zb-chip img{display:block;height:34px;width:auto;max-width:100%;object-fit:contain}'
      + '#zyb-brand .zb-lbl{font:600 9px/1.3 ui-monospace,SFMono-Regular,Consolas,monospace;letter-spacing:.06em;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;text-transform:uppercase;color:rgba(232,238,247,.6);max-width:100%}'
      + '[data-zyb-hidden]{display:none!important}';
    document.head.appendChild(css);
    var b = document.createElement('div'); b.id = 'zyb-brand';
    b.innerHTML = ('<span class="zb-chip"><img alt="' + ZYB_ORG.name + '"></span><span class="zb-lbl">Security, Operations &amp; GRC</span>');
    boxes[0].parentNode.insertBefore(b, boxes[0]);
    /* the logo comes inline from zyb-brand.js (never a cached old /logo.webp); the header is shown once it has loaded */
    var im = b.querySelector('img'), done = false;
    var show = function () { if (done) return; done = true; brandOn(); };
    im.addEventListener('load', show); im.addEventListener('error', show); setTimeout(show, 3000);
    var setSrc = function () { im.src = (window.ZYB_ORG && window.ZYB_ORG.logo) || ('/logo.webp?v=' + BUILD0); };
    if (window.ZYB_BRAND) setSrc();
    else { var sc = document.createElement('script'); sc.src = BASE + 'vendor/zyb-brand.js?v=' + BUILD0; sc.onload = setSrc; sc.onerror = setSrc; document.head.appendChild(sc); }
    boxes.forEach(function (x) { x.setAttribute('data-zyb-hidden', ''); });
    /* the old tagline under the logos */
    [].forEach.call(side.querySelectorAll('div,span,p,small'), function (el) {
      if (!el.closest('#zyb-brand') && !el.children.length && /^\s*security,\s*operations\s*&\s*grc\s*$/i.test(el.textContent)) el.setAttribute('data-zyb-hidden', '');
    });
  }

  /* the portal's own menu (its groups and views, not ours) is saved for the dashboard pages, so their sidebar, Ctrl+K
     search and home page can list the portal's pages too. Same origin, so localStorage is shared; refreshed on each visit. */
  var snapT = null, lastSnap = '';
  function snapshot(nav) {
    clearTimeout(snapT);
    snapT = setTimeout(function () {
      try {
        var out = [], grp = null;
        var txt = function (li) { var c = li.cloneNode(true); [].forEach.call(c.querySelectorAll('.ico,.badge,.zyb-star,.zyb-mv,svg'), function (x) { x.remove(); }); return (li.getAttribute('data-en') || c.textContent).replace(/[▸▾▼►▶▲△▽]/g, '').replace(/\s+/g, ' ').trim(); };
        var gtxt = function (li) { return txt(li).replace(/\s+\d+$/, ''); };   // a group heading may end in its item count; a page name may end in a number
        [].forEach.call(nav.children, function (li) {
          if (li.tagName !== 'LI' || li.getAttribute('data-zyb-menu')) return;      // our own entries are not the portal's
          if (li.classList.contains('nav-group')) { grp = { name: gtxt(li).slice(0, 80), items: [] }; out.push(grp); return; }
          var v = li.getAttribute('data-view'); if (!v) return;
          if (!grp) { grp = { name: 'Portal', items: [] }; out.push(grp); }
          var ic = li.querySelector('.ico'); grp.items.push({ v: v.slice(0, 80), l: txt(li).slice(0, 120), i: ic ? ic.textContent.trim().slice(0, 4) : '' });
        });
        out = out.filter(function (g) { return g.items.length && g.name; });
        var j = JSON.stringify(out);
        if (out.length && j !== lastSnap) { lastSnap = j; localStorage.setItem('zyb-portal-nav', JSON.stringify({ at: Date.now(), groups: out })); }
      } catch (e) { /* storage blocked: the dashboards list only their own pages */ }
    }, 400);
  }
  /* ONE SCREEN: a dashboard opens INSIDE the portal - in the portal's content area, beside the portal's own sidebar and under
     its header - instead of replacing the whole page with the dashboards' own menu and header (two looks, a jump on every
     click). The dashboard runs in a same-origin frame, where zyb-dash.js draws only its compact top bar. The address reads
     /?zybdash=<page>, so Back / Forward / refresh / a bookmark land on the same dashboard. A portal page clicked in the menu
     closes it. Narrow screens (< 901 px) keep the full-page dashboard, which is built for phones. */
  (function host() {
    if (window.zybDash) return;
    var H = null, FR = null, CUR = '', SAFE = /^\/dashboards\/(?:[A-Za-z0-9_-]+\.html)?(?:[?#][\w=&%.:,+-]*)?$/;
    var wide = function () { return window.innerWidth >= 901; };
    function sideEl() { var nav = document.querySelector('ul.nav'); if (!nav) return null; for (var el = nav; el && el !== document.body; el = el.parentElement) { var r = el.getBoundingClientRect(); if (r.height >= window.innerHeight * 0.6 && r.width < window.innerWidth * 0.5) return el; } return nav; }
    function headTop() { var t = 0; [].forEach.call(document.querySelectorAll('header, .topbar, .navbar, [class*="topbar"]'), function (h) { if (H && H.contains(h)) return; var cs = getComputedStyle(h), r = h.getBoundingClientRect(); if (/fixed|sticky/.test(cs.position) && r.top <= 1 && r.height < 140 && r.width > window.innerWidth * 0.5) t = Math.max(t, r.bottom); }); return Math.round(t); }
    function place() { if (!H) return; var s = sideEl(), l = 0; if (s) { var r = s.getBoundingClientRect(); if (r.right > 0 && r.right < window.innerWidth * 0.5) l = Math.round(r.right); } H.style.left = l + 'px'; H.style.top = headTop() + 'px'; }
    function mark(page) {   // the open dashboard is highlighted in the portal menu, like a portal page
      [].forEach.call(document.querySelectorAll('ul.nav [data-zyb-href]'), function (li) { var on = page && li.getAttribute('data-zyb-href') === page; li.classList.toggle('zyb-on', !!on); if (on) li.setAttribute('aria-current', 'page'); else li.removeAttribute('aria-current'); });
    }
    function build() {
      H = document.createElement('div'); H.id = 'zyb-dash-host';
      H.setAttribute('style', 'position:fixed;right:0;bottom:0;left:0;top:0;z-index:40;background:var(--v-bg,#111217);display:none');
      FR = document.createElement('iframe'); FR.title = 'Dashboard'; FR.setAttribute('style', 'border:0;width:100%;height:100%;display:block;background:transparent');
      H.appendChild(FR); document.body.appendChild(H);
      var st = document.createElement('style'); st.textContent = 'ul.nav li.zyb-on{background:rgba(87,148,242,.16)!important;box-shadow:inset 3px 0 0 #5794f2}html.zyb-dash-open body{overflow:hidden}'; document.head.appendChild(st);
      FR.addEventListener('load', function () {   // a link inside the dashboard: follow it in the address bar; a portal link leaves the frame
        var p = ''; try { p = FR.contentWindow.location.pathname + FR.contentWindow.location.search + FR.contentWindow.location.hash; } catch (e) { return; }
        if (!SAFE.test(p)) { if (FR.contentWindow.location.pathname.indexOf('/dashboards/') !== 0) { close(true); window.location.href = p; } return; }
        if (p !== CUR) { CUR = p; try { history.replaceState({ zybdash: p }, '', '/?zybdash=' + encodeURIComponent(p.slice(12))); } catch (e) { /* keep the address */ } }
        mark(p.split(/[?#]/)[0]);
        try { document.title = FR.contentWindow.document.title || document.title; } catch (e) { /* keep the title */ }
      });
      window.addEventListener('resize', function () { if (!wide() && H.style.display !== 'none') { var p = CUR; close(true); window.location.href = p; } else place(); });
      if (window.ResizeObserver) { var s = sideEl(); if (s) new ResizeObserver(place).observe(s); }
    }
    function open(href, noPush) {
      if (!wide() || !document.body) return false;
      href = String(href || ''); if (href.indexOf('/dashboards/') !== 0) href = '/dashboards/' + href.replace(/^\.?\//, '');
      if (!SAFE.test(href)) return false;
      if (!H) build();
      place(); H.style.display = 'block'; document.documentElement.classList.add('zyb-dash-open');
      if (CUR !== href) { CUR = href; FR.src = href; }
      if (!noPush) try { history.pushState({ zybdash: href }, '', '/?zybdash=' + encodeURIComponent(href.slice(12))); } catch (e) { /* keep the address */ }
      mark(href.split(/[?#]/)[0]);
      return true;
    }
    function close(quiet) {
      if (!H || H.style.display === 'none') return;
      H.style.display = 'none'; document.documentElement.classList.remove('zyb-dash-open'); mark('');
      if (!quiet) try { if (/[?&]zybdash=/.test(location.search)) history.pushState({}, '', '/'); } catch (e) { /* keep the address */ }
    }
    window.zybDash = { open: open, close: close, isOpen: function () { return !!H && H.style.display !== 'none'; } };
    window.addEventListener('popstate', function (e) { var d = e.state && e.state.zybdash; if (d) open(d, true); else close(true); });
    // a portal page clicked in the menu (not one of ours): the portal shows it, the dashboard steps aside
    window.addEventListener('click', function (e) { var li = e.target && e.target.closest && e.target.closest('ul.nav li[data-view]'); if (li && !li.getAttribute('data-zyb-href') && !li.getAttribute('data-zyb-menu')) close(); }, true);
    // /?zybdash=<page>: open it once the portal has drawn (a bookmark, Back after leaving, or a dashboard opened on its own)
    var m = /[?&]zybdash=([^&#]+)/.exec(location.search);
    if (m) { var want = '/dashboards/' + decodeURIComponent(m[1]).replace(/^\/+/, ''), n = 0;
      // cannot host it (phone width, or an address that is not a dashboard page): open it on its own, marked so it stays there
      var alone = function () { var ok = SAFE.test(want.split('#')[0].replace(/[?].*$/, '')); window.location.replace(ok ? want.split('#')[0] + (want.indexOf('?') >= 0 ? '&' : '?') + 'standalone=1' + (want.indexOf('#') >= 0 ? want.slice(want.indexOf('#')) : '') : '/dashboards/'); };
      (function tryOpen() { if (document.body && (document.querySelector('ul.nav') || n > 20)) { if (!open(want, true)) alone(); document.documentElement.classList.remove('zyb-early-dash'); return; } n++; setTimeout(tryOpen, 150); })(); }
  })();

  /* /?zybview=<view>: a dashboard's link to a portal page opens that view once the portal has started */
  (function deepLink() {
    var m = /[?&]zybview=([^&#]+)/.exec(location.search); if (!m) return;
    var v = decodeURIComponent(m[1]), n = 0;
    try { var u = new URL(location.href); u.searchParams.delete('zybview'); history.replaceState(history.state, '', u.pathname + u.search + u.hash); } catch (e) { /* keep the address */ }
    (function tryOpen() {
      var li = document.querySelector('ul.nav li[data-view="' + (window.CSS && CSS.escape ? CSS.escape(v) : v.replace(/"/g, '')) + '"]');
      if (typeof window.setView === 'function' && li) { try { window.setView(v); li.scrollIntoView({ block: 'nearest' }); } catch (e) { li.click(); } return; }
      if (li && ++n > 8) { li.click(); return; }
      if (n++ < 60) setTimeout(tryOpen, 250);
    })();
  })();

  var tries = 0;
  function attempt() {
    var nav = document.querySelector('ul.nav');
    if (nav && addToNav(nav)) {
      try { brand(nav); } catch (e) { brandOn(); /* the logos stay as they are - shown again */ }
      snapshot(nav);
      try { uiSwitch(); } catch (e) { /* no theme selector on this page */ }
      /* the portal may redraw its menu (language switch, collapse): put the group back when it disappears */
      new MutationObserver(function () { var n = document.querySelector('ul.nav'); if (n && !n.querySelector('[data-zyb-menu="group"]')) addToNav(n, !!window.__zybMenuFallback); else if (n) infraItem(n); if (n && !document.getElementById('zyb-brand')) { try { brand(n); } catch (e) { /* portal function not available on this page: carry on without it */ } } if (n) snapshot(n); })
        .observe(document.body, { childList: true, subtree: true });
      return;
    }
    if (nav && tries >= 12 && addToNav(nav, true)) { tries = 0; window.__zybMenuFallback = true; attempt(); return; }   // page list missing: the classic menu, never an empty one
    if (++tries > 40) { fallbackButton(); return; }
    setTimeout(attempt, 250);
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', attempt); else attempt();
})();

/* ===================== favorites (every user) + menu order (admin) =====================
 * Stored on the server through the SIEM API (GET /api/soc/ui/menu, PUT /api/soc/ui/menu/favorites, PUT|DELETE
 * /api/soc/ui/menu/order — identity from the portal login). If that API is not available yet, favorites are kept in
 * this browser only and the admin ordering is hidden (the role cannot be checked without the server). */
(function () {
  'use strict';
  if (window.__zybPrefs) return; window.__zybPrefs = true;
  var API = '/api/soc/ui/menu', LS = 'zyb-menu-favs', state = { favs: [], order: null, canEdit: false, server: false, editing: false };

  function keyOf(li) { var v = li.getAttribute('data-view'); if (v) return v; var h = li.getAttribute('data-zyb-href'); return h ? 'link:' + h : ''; }
  function labelOf(li) { var c = li.cloneNode(true); [].forEach.call(c.querySelectorAll('.ico,.badge,.zyb-star,.zyb-mv'), function (x) { x.remove(); }); return (li.getAttribute('data-en') || c.textContent).trim(); }
  function nav() { return document.querySelector('ul.nav'); }
  function items(n) { return [].filter.call(n.children, function (li) { return li.tagName === 'LI' && !li.classList.contains('nav-group') && keyOf(li) && li.getAttribute('data-zyb-menu') !== 'fav'; }); }
  /* portal pages an admin may move (the Dashboards workspaces keep their own pages): anything that is not ours, plus pages
     already moved into a workspace (data-zyb-moved) */
  function movable(li) { return li && li.tagName === 'LI' && !li.classList.contains('nav-group') && !!keyOf(li) && (!li.getAttribute('data-zyb-menu') || li.hasAttribute('data-zyb-moved')); }
  /* default places, used until an admin saves an order of their own (v2): Database Health (Infrastructure Automation's
     database page) belongs with the database pages */
  var DEFAULT_PLACE = { 'infra-db': 'area:db' };
  function areaRow(n, id) { return n.querySelector('li.zyb-area[data-zyb-area="' + id + '"]'); }
  function areaEnd(n, id) { var row = areaRow(n, id); if (!row) return null; var x = row, nx = row.nextElementSibling;
    while (nx && !nx.classList.contains('nav-group') && !nx.classList.contains('zyb-area') && nx.getAttribute('data-zyb-area') === id) { x = nx; nx = nx.nextElementSibling; } return x; }
  /* put a portal page into a Dashboards workspace: it becomes one of the workspace's sub-items, so the workspace's own
     open / close toggle hides and shows it (that toggle looks the items up when it is clicked) */
  function intoArea(n, li, id, before) {
    var row = areaRow(n, id); if (!row) return false;
    li.classList.add('zyb-sub'); li.setAttribute('data-zyb-area', id); li.setAttribute('data-zyb-moved', id);
    li.classList.remove('tree-hidden'); li.removeAttribute('data-zyb-gc');
    if (row.classList.contains('zyb-open')) li.removeAttribute('data-zyb-col'); else li.setAttribute('data-zyb-col', '');
    if (before && before !== li) n.insertBefore(li, before); else { var end = areaEnd(n, id); n.insertBefore(li, end ? end.nextElementSibling : row.nextElementSibling); }
    return true;
  }
  function outOfArea(li) { if (!li.hasAttribute('data-zyb-moved')) return; li.classList.remove('zyb-sub'); li.removeAttribute('data-zyb-area'); li.removeAttribute('data-zyb-moved'); li.removeAttribute('data-zyb-col'); }
  function heads(n) { return [].filter.call(n.children, function (li) { return li.classList.contains('nav-group') && li.getAttribute('data-zyb-menu') !== 'favgroup'; }); }
  /* the portal's collapse tree (initNavTree) records which pages belong to each heading once, when it is built. After a page
     moves to another group or into a workspace, that record is stale: collapsing a group hid pages now in other groups and
     opening it did not show its own, so the menu looked frozen. Rebuild it after every move (initNavTree is idempotent:
     one onclick per heading, the open / closed state comes back from nav_tree). */
  function retree() { var n = nav(); if (!n || typeof window.initNavTree !== 'function') return; try { n._tree = false; window.initNavTree(); } catch (e) { /* the menu stays as it is */ } }
  function groupName(h) { return labelOf(h).replace(/[▸▾▼►▶▲△▽]/g, '').replace(/\s+\d+\s*$/, '').trim(); }   /* without the arrows and a trailing count */
  function req(method, url, body) {
    return fetch(url, { method: method, credentials: 'same-origin', headers: body ? { 'Content-Type': 'application/json' } : {}, body: body ? JSON.stringify(body) : undefined })
      .then(function (r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); });
  }
  function toast(msg) {
    var t = document.getElementById('zyb-toast'); if (!t) { t = document.createElement('div'); t.id = 'zyb-toast'; document.body.appendChild(t); }
    t.textContent = msg; t.className = 'show'; clearTimeout(t._h); t._h = setTimeout(function () { t.className = ''; }, 2600);
  }

  var css = document.createElement('style');
  css.textContent = '.zyb-star{float:right;background:none;border:0;color:rgba(232,238,247,.35);font-size:14px;line-height:1;padding:2px 4px;cursor:pointer;opacity:0;transition:opacity .12s}'
    + 'ul.nav li:hover>.zyb-star,ul.nav li:focus-within>.zyb-star,.zyb-star.on{opacity:1}.zyb-star.on{color:#F2C14E}.zyb-star:focus-visible{outline:2px solid #fff;opacity:1}'
    + '.zyb-mv{float:right;display:none;gap:2px}.zyb-editing .zyb-mv{display:inline-flex}.zyb-editing .zyb-star{display:none}'
    + '.zyb-mv button{background:rgba(255,255,255,.08);border:1px solid rgba(255,255,255,.14);color:#e8eef7;border-radius:5px;width:22px;height:20px;font-size:10px;line-height:1;cursor:pointer;padding:0}.zyb-mv button:hover{background:rgba(255,255,255,.16)}'
    + '.zyb-editing li[draggable=true]{cursor:grab}.zyb-dragging{opacity:.45}.zyb-dz-b{box-shadow:inset 0 2px 0 #4D8DFF}.zyb-dz-a{box-shadow:inset 0 -2px 0 #4D8DFF}.zyb-dz-in{outline:2px dashed #4D8DFF;outline-offset:-2px}'
    + '#zyb-editbar{display:flex;gap:6px;flex-wrap:wrap;align-items:center;margin:6px 8px 8px;font:500 11.5px system-ui,sans-serif;color:rgba(232,238,247,.7)}'
    + '#zyb-editbar button{background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.14);color:#e8eef7;border-radius:7px;padding:5px 9px;font:600 11.5px system-ui,sans-serif;cursor:pointer}'
    + '#zyb-editbar button.pri{background:#D7262D;border-color:#D7262D}#zyb-editbar .hint{flex-basis:100%;opacity:.75}'
    + '#zyb-toast{position:fixed;left:50%;bottom:22px;transform:translateX(-50%) translateY(20px);background:#141821;color:#e8eef7;border:1px solid #2a3140;border-radius:9px;padding:9px 14px;font:500 13px system-ui,sans-serif;opacity:0;transition:all .2s;z-index:10000;pointer-events:none}#zyb-toast.show{opacity:1;transform:translateX(-50%)}';
  document.head.appendChild(css);

  /* ---- favorites */
  function saveFavs() {
    if (state.server) req('PUT', API + '/favorites', { items: state.favs }).catch(function () { toast('Favorites could not be saved - try again'); });
    else { try { localStorage.setItem(LS, JSON.stringify(state.favs)); } catch (e) { /* storage blocked */ } }
  }
  function drawFavs() {
    var n = nav(); if (!n) return;
    [].forEach.call(n.querySelectorAll('[data-zyb-menu="fav"],[data-zyb-menu="favgroup"]'), function (x) { x.remove(); });
    var byKey = {}; items(n).forEach(function (li) { byKey[keyOf(li)] = li; });
    var list = state.favs.filter(function (k) { return byKey[k]; });
    [].forEach.call(n.querySelectorAll('.zyb-star'), function (b) { var on = state.favs.indexOf(b._key) >= 0; b.classList.toggle('on', on); b.textContent = on ? '★' : '☆'; b.setAttribute('aria-label', (on ? 'Remove ' : 'Add ') + b._label + (on ? ' from favorites' : ' to favorites')); b.setAttribute('aria-pressed', String(on)); });
    if (!list.length) return;
    var g0 = n.querySelector('li.nav-group'), h = document.createElement('li');
    h.className = g0 ? g0.className : 'nav-group'; h.setAttribute('data-zyb-menu', 'favgroup'); h.setAttribute('data-en', 'Favorites'); h.textContent = 'Favorites';
    var frag = document.createDocumentFragment(); frag.appendChild(h);
    list.forEach(function (k) {
      var src = byKey[k], li = src.cloneNode(true);
      li.removeAttribute('id'); li.removeAttribute('data-view'); li.removeAttribute('data-zyb-col'); li.classList.remove('active', 'zyb-sub'); li.setAttribute('data-zyb-menu', 'fav');
      [].forEach.call(li.querySelectorAll('.zyb-star,.zyb-mv,[id]'), function (x) { if (x.classList.contains('zyb-star') || x.classList.contains('zyb-mv')) x.remove(); else x.removeAttribute('id'); });
      li.tabIndex = 0; li.setAttribute('role', 'link');
      var open = function (e) { e.preventDefault(); e.stopPropagation(); if (e.stopImmediatePropagation) e.stopImmediatePropagation(); src.click(); };
      li._zybClick = open; li.addEventListener('click', open, true);
      li.addEventListener('keydown', function (e) { if (e.key === 'Enter' || e.key === ' ') open(e); }, true);
      frag.appendChild(li);
    });
    n.insertBefore(frag, n.firstChild);
  }
  function decorate() {
    var n = nav(); if (!n) return;
    items(n).forEach(function (li) {
      if (li.querySelector(':scope>.zyb-star')) return;
      var b = document.createElement('button'); b.type = 'button'; b.className = 'zyb-star'; b._key = keyOf(li); b._label = labelOf(li);
      b._zybClick = function (e) {
        e.preventDefault(); e.stopPropagation(); if (e.stopImmediatePropagation) e.stopImmediatePropagation();
        var i = state.favs.indexOf(b._key); if (i >= 0) state.favs.splice(i, 1); else if (state.favs.length < 30) state.favs.push(b._key); else { toast('At most 30 favorites'); return; }
        saveFavs(); drawFavs(); toast(i >= 0 ? 'Removed from favorites' : 'Added to favorites');
      };
      b.addEventListener('click', b._zybClick, true);
      li.appendChild(b);
      if (state.canEdit && !/^(item|area)$/.test(li.getAttribute('data-zyb-menu') || '')) li.appendChild(mover(li, false));   // the Dashboards workspaces keep their own order
    });
    if (state.canEdit) heads(n).forEach(function (h) { if (!h.querySelector(':scope>.zyb-mv')) h.appendChild(mover(h, true)); });
  }

  /* ---- admin ordering: groups move with their items, items move inside their group */
  function blockOf(h) { var out = [h], x = h.nextElementSibling; while (x && !x.classList.contains('nav-group')) { if (x.getAttribute('data-zyb-menu') !== 'fav') out.push(x); x = x.nextElementSibling; } return out; }
  function mover(el, isGroup) {
    var w = document.createElement('span'); w.className = 'zyb-mv';
    [['▲', -1, 'up'], ['▼', 1, 'down']].forEach(function (d) {
      var b = document.createElement('button'); b.type = 'button'; b.textContent = d[0]; b.setAttribute('aria-label', 'Move ' + (isGroup ? 'group ' : '') + labelOf(el) + ' ' + d[2]);
      b._zybClick = function (e) { e.preventDefault(); e.stopPropagation(); if (e.stopImmediatePropagation) e.stopImmediatePropagation(); isGroup ? moveGroup(el, d[1]) : moveItem(el, d[1]); };
      b.addEventListener('click', b._zybClick, true);
      w.appendChild(b);
    });
    return w;
  }
  function moveItem(li, dir) {
    var sib = dir < 0 ? li.previousElementSibling : li.nextElementSibling;
    if (!sib || sib.classList.contains('nav-group')) return;
    if (dir < 0) li.parentNode.insertBefore(li, sib); else li.parentNode.insertBefore(sib, li);
  }
  function moveGroup(h, dir) {
    var n = nav(), hs = heads(n), i = hs.indexOf(h), j = i + dir; if (j < 0 || j >= hs.length) return;
    var mine = blockOf(h), other = blockOf(hs[j]);
    if (dir < 0) mine.forEach(function (x) { n.insertBefore(x, other[0]); });
    else { var after = other[other.length - 1].nextElementSibling; mine.forEach(function (x) { n.insertBefore(x, after); }); }
  }
  function currentOrder() {
    var n = nav();
    var gs = heads(n).map(function (h) { return { name: groupName(h).slice(0, 120), items: blockOf(h).slice(1).filter(function (li) { return !li.hasAttribute('data-zyb-moved'); }).map(keyOf).filter(Boolean) }; }).filter(function (g) { return g.name; });
    [].forEach.call(n.querySelectorAll('li.zyb-area[data-zyb-area]'), function (row) { var id = row.getAttribute('data-zyb-area');
      var ks = [].map.call(n.querySelectorAll('li[data-zyb-moved="' + id + '"]'), keyOf).filter(Boolean); if (ks.length) gs.push({ name: 'area:' + id, items: ks }); });
    return gs;
  }
  function applyOrder(order) {
    var n = nav(); if (!n || !order || !order.groups) return;
    var hs = heads(n), byName = {}; hs.forEach(function (h) { byName[groupName(h).toLowerCase()] = h; });
    var anchor = null, placed = {}, all = {}, claimed = {};
    items(n).forEach(function (li) { if (movable(li)) all[keyOf(li)] = li; });
    order.groups.forEach(function (g) { if (byName[String(g.name).toLowerCase()] || /^area:/.test(g.name)) (g.items || []).forEach(function (k) { if (all[k]) claimed[k] = g.name; }); });
    order.groups.forEach(function (g) {
      if (/^area:/.test(g.name)) return;
      var h = byName[String(g.name).toLowerCase()]; if (!h) return;
      var blk = blockOf(h), byKey = {};
      if (h.getAttribute('data-zyb-menu') === 'group') {   // the Dashboards group moves as one block, workspaces intact
        n.insertBefore(h, anchor ? anchor.nextElementSibling : firstGroupSlot(n)); var l0 = h;
        blk.slice(1).forEach(function (li) { n.insertBefore(li, l0.nextElementSibling); l0 = li; }); anchor = l0; return;
      }
      blk.slice(1).forEach(function (li) { byKey[keyOf(li)] = li; });
      var ordered = g.items.map(function (k) { return claimed[k] === g.name ? (byKey[k] || all[k]) : byKey[k]; }).filter(Boolean);
      ordered.forEach(outOfArea);
      blk.slice(1).forEach(function (li) { if (ordered.indexOf(li) < 0 && !(claimed[keyOf(li)] && claimed[keyOf(li)] !== g.name)) ordered.push(li); });   /* items added since: keep, at the end; items the order moved elsewhere: leave */
      var target = anchor ? anchor.nextElementSibling : firstGroupSlot(n);
      n.insertBefore(h, target); var last = h;
      ordered.forEach(function (li) { n.insertBefore(li, last.nextElementSibling); last = li; });
      anchor = last; placed[groupName(h).toLowerCase()] = true;
    });
    order.groups.forEach(function (g) { var m = /^area:(.+)$/.exec(g.name); if (!m) return; (g.items || []).forEach(function (k) { if (all[k]) intoArea(n, all[k], m[1]); }); });
    retree();
  }
  /* default places (DEFAULT_PLACE) - only while no admin has saved a v2 order, and never for a page that order places itself */
  function applyDefaults() {
    var n = nav(), moved = false; if (!n) return; if (state.order && state.order.v >= 2) return;
    var listed = {}; (state.order && state.order.groups || []).forEach(function (g) { (g.items || []).forEach(function (k) { listed[k] = 1; }); });   /* a saved order that places it anywhere wins */
    Object.keys(DEFAULT_PLACE).forEach(function (k) { if (listed[k]) return; var m = /^area:(.+)$/.exec(DEFAULT_PLACE[k]); if (!m) return;
      var li = items(n).filter(function (x) { return keyOf(x) === k && movable(x); })[0]; if (li && li.getAttribute('data-zyb-moved') !== m[1] && intoArea(n, li, m[1])) moved = true; });
    if (moved) retree();
  }
  /* every database page lives under Databases: a portal page whose name says database / Oracle / SQL / DBA / tablespace /
     Data Guard / GoldenGate / RMAN goes into the Databases workspace wherever it was, a saved order included (the business
     rule: "whatever is related to databases is under Databases") */
  var DB_PAGE = /\b(databases?|oracle|sql|dba|db|tablespaces?|data\s*guard|goldengate|rman|asm|pl\/sql|mysql|postgres(ql)?|mssql)\b/i;
  // the same rule for the other main menus that own a whole subject: printers and voice / video under Workplace & Desktops
  // (first match wins, databases first)
  var AREA_RULES = [['db', DB_PAGE], ['eud', /\b(printers?|printing|print\s*(server|queue)s?|toner|mfp|copiers?)\b/i],
    ['eud', /\b(uc|unified\s*communications?|voip|voice|telephony|ip\s*phones?|cucm|call\s*manager|webex|video\s*conferenc\w*|contact\s*cent(er|re))\b/i],
    // whatever is Cisco (the portal's Cisco Update pages: overview, device inventory, advisories, plans, policy, connections)
    // belongs to Network, not to Servers & Cloud; Cisco voice pages matched UC just above
    ['net', /\bcisco\b/i],
    // every personal-data and data-management page under Data Privacy (PDPL · NDMO)
    ['pdpl', /\b(pdpl|personal\s*data|privacy|data\s*subjects?|dsars?|consents?|ropa|records\s*of\s*processing|dpia)\b/i],
    ['pdpl', /\b(ndmo|data\s*management\s*office|data\s*governance|data\s*quality|master\s*data|metadata)\b/i]];
  /* one place per subject: every other portal page joins the workspace of its subject, so the portal's own groups (Security
     Operations, Network & Servers, Governance …) stop repeating the workspaces. Most specific first; a page an admin placed in
     a saved order stays where they put it; a page that matches nothing stays in its portal group. */
  var SUBJECT_RULES = [
    ['pt', /\b(pen[- ]?test\w*|penetration|red team|vulnerabilit\w*|vapt|vuln\w*|attack simulation|breach and attack)\b/i],
    ['soc', /\b(incidents?|playbooks?|forensics?|dfir|response actions?)\b/i],
    ['usr', /\b(active directory|exchange|microsoft 365|m365|office 365|entra|azure ad|identit(y|ies)|ad (users?|groups?|audit|health))\b/i],
    ['eps', /\b(e-?mails?|mail\w*|phishing|dlp|data loss|endpoints?|kaspersky|zscaler|anti-?virus|edr|web filter\w*|proxy)\b/i],
    ['stor', /\b(storage|backups?|nas|san|disaster recovery|dr (site|drills?)|replication)\b/i],
    ['srv', /\b(servers?|virtual\w*|vmware|vcenter|vsphere|nutanix|hyper-?v|esxi|capacity|linux hosts?|windows hosts?|vms?)\b/i],
    ['net', /\b(network\w*|switch\w*|routers?|firewalls?|wi-?fi|wireless|sd-?wan|npm|topology|vpn|dns|domains?|bandwidth|netflow|flows?)\b/i],
    ['app', /\b(applications?|apm|service maps?|traces?|tracing|synthetic|real[- ]user|transactions?|web apps?|portal traffic|slos?)\b/i],
    ['ast', /\b(itam|assets?|cmdb|licen[cs]\w*|stocktake|inventory|contracts?|budget|costs?|end of life|eol|warrant\w*)\b/i],
    ['aud', /\b(audits?|auditors?|audit trail)\b/i],
    ['cmp', /\b(complian\w*|sama|nca|ecc|iso ?27001|controls?|frameworks?|crosswalk|maturity)\b/i],
    ['grc', /\b(grc|polic(y|ies)|risks?|governance)\b/i],
    ['eud', /\b(desktops?|laptops?|end[- ]users?|help ?desk|service desk|tickets?|manageengine|patch\w*)\b/i],
    ['soc', /\b(siem|soc|alerts?|alarms?|events?|logs?|log sources?|detections?|cases|threats?|ueba|xdr|hunt\w*|intel\w*|security)\b/i],
    ['adm', /\b(settings?|admin\w*|integrations?|platform|roles?|health|user management|tokens?|api keys?)\b/i],
    ['ai', /\b(ai|automation|engineers?|copilot|assistant)\b/i],
    ['cmd', /\b(home|overview|command cent(er|re)|noc|executive|leadership|morning brief\w*|briefings?|welcome|wall ?board)\b/i]];
  // the portal's own section headings → the workspace that owns the subject (used only for a page no name rule places)
  var HEAD_AREA = [[/^command cent(er|re)|^overview$|^home$/i, 'cmd'], [/^ai\b|automation$/i, 'ai'], [/security operations|^soc$|siem/i, 'soc'], [/incidents?|threats?/i, 'soc'],
    [/vulnerab|testing|pen ?test/i, 'pt'], [/identity|data protection|microsoft 365|users?$/i, 'usr'], [/audit/i, 'aud'], [/complian/i, 'cmp'], [/risk|governance|grc/i, 'grc'], [/^network/i, 'net'],
    [/servers?|cloud|virtual|infrastructure automation/i, 'srv'], [/storage|backup|disaster/i, 'stor'], [/databases?/i, 'db'], [/assets?|licen[cs]|cost|budget/i, 'ast'],
    [/service management|itsm|help ?desk|facilit|devices?/i, 'eud'], [/print/i, 'eud'], [/application|apm/i, 'app'], [/reports?|administration|settings|platform|other tools|discovery|onboarding/i, 'adm']];
  function subjectPages(n) {
    var listed = {}, moved = false; (state.order && state.order.groups || []).forEach(function (g) { (g.items || []).forEach(function (k) { listed[k] = 1; }); });
    items(n).forEach(function (li) { if (!movable(li) || li.hasAttribute('data-zyb-moved') || listed[keyOf(li)]) return; var lab = labelOf(li), done = false;
      for (var i = 0; i < SUBJECT_RULES.length; i++) { if (!SUBJECT_RULES[i][1].test(lab)) continue; if (areaRow(n, SUBJECT_RULES[i][0]) && intoArea(n, li, SUBJECT_RULES[i][0])) { moved = true; done = true; } break; }
      // no rule for its name: it goes where its portal heading belongs, so no second menu of old portal sections is left
      if (!done) { var h = li.previousElementSibling; while (h && !h.classList.contains('nav-group')) h = h.previousElementSibling;
        var hn = h && !h.getAttribute('data-zyb-menu') ? groupName(h) : '', id = '';
        for (var j = 0; j < HEAD_AREA.length && hn; j++) if (HEAD_AREA[j][0].test(hn)) { id = HEAD_AREA[j][1]; break; }
        if (id && areaRow(n, id) && intoArea(n, li, id)) moved = true; } });
    return moved;
  }
  /* no page twice: a portal page with the same name as one of our dashboards is hidden (ours is the live page), and a second
     portal page with the same name as an earlier one is hidden too. Names compare without case, punctuation, "&"/"and" and a
     plural s. An admin editing the menu sees everything (ul.nav.zyb-editing), and "Copy menu list" reports what was hidden. */
  function normName(t) { return String(t || '').toLowerCase().replace(/\(.*?\)/g, ' ').replace(/&/g, ' and ').replace(/[^a-z0-9\u0600-\u06ff]+/g, ' ').replace(/\b(\w{3,})s\b/g, '$1').replace(/\s+/g, ' ').trim(); }
  /* portal pages that one of our dashboards replaces under another name (same subject, live data): hidden like a
     same-name duplicate. dbperf and the infra / CIO / CISO role dashboards draw sample telemetry; db-oracle reads the Oracle collector that All Databases shows. */
  var ALIAS = window.ZYB_PORTAL_ALIAS || {};   // portal page -> its live portal twin (set by the menu block above)
  var COVERED = { 'itam-assets': ['/dashboards/inventory.html', 'Inventory'], 'itam-discovery': ['/dashboards/discovery-studio.html', 'Discovery Studio'], adex: ['/dashboards/ad-exchange.html', 'AD & Exchange'], printers: ['/dashboards/printers.html', 'Printers'], 'soc-dashboard': ['/dashboards/soc-overview.html', 'SOC Overview'], 'soc-alerts': ['/dashboards/soc-alerts.html', 'Alert Queue'], 'itam-ai': ['/dashboards/ai-findings.html', 'AI Findings'], 'itam-stocktake': ['/dashboards/stocktake.html', 'Stocktake'], itam: ['/dashboards/itam-overview.html', 'IT Asset Management'], costopt: ['/dashboards/cost-optimisation.html', 'Cost Optimisation'], budget: ['/dashboards/budget.html', 'IT Budget'], 'itam-settings': ['/dashboards/itam-settings.html', 'ITAM Settings'], 'itam-software': ['/dashboards/software-studio.html', 'Software & Licences'], cloudsrv: ['/dashboards/servers.html', 'Servers (no cloud estate)'], ups: ['/dashboards/facilities.html#ups', 'Facilities & Devices - UPS'], door: ['/dashboards/door-access.html', 'Door Access'], dbperf: ['/dashboards/db-performance.html', 'Database Performance'], ipam: ['/dashboards/ipam.html', 'IP Address Management'], m365sec: ['/dashboards/m365-security.html', 'Microsoft 365 Security'], branchnet: ['/dashboards/branch-connectivity.html', 'Branch Connectivity'], 'dash-fac': ['/dashboards/facilities.html', 'Facilities & Devices'], 'intune': ['/dashboards/mdm.html', 'Endpoint & Mobile Management'], 'dash-soc': ['/dashboards/soc-overview.html', 'Security Operations Overview'], 'agents': ['/dashboards/ai-team.html', 'AI Engineering Team'], 'managed': ['/dashboards/service-agreement.html', 'Service Agreement'], 'infra-wanopt': ['/dashboards/wan-optimization.html', 'WAN Optimization'], 'upd-overview': ['/dashboards/cisco-update.html', 'Cisco Updates'], 'upd-inventory': ['/dashboards/cisco-update.html#view=devices', 'Cisco Updates'], 'upd-advisories': ['/dashboards/cisco-update.html#view=advisories', 'Cisco Updates'], 'upd-plans': ['/dashboards/cisco-update.html#view=plans', 'Cisco Updates'], 'upd-policy': ['/dashboards/cisco-update.html#view=policy', 'Cisco Updates'], 'upd-connections': ['/dashboards/cisco-update.html#view=connections', 'Cisco Updates'], command: ['/dashboards/executive-dashboard.html', 'Executive Dashboard'], posture: ['/dashboards/risk-command.html', 'Risk Command Center'], servicedesk: ['/dashboards/support-center.html', 'Support Center'], support: ['/dashboards/support-center.html', 'Support Center'], 'dash-net': ['/dashboards/network-dashboard.html', 'Network Dashboard'], ncm: ['/dashboards/ncm.html', 'Network Config Management'], netcfg: ['/dashboards/network-config-audit.html', 'Network Config Audit'], roles: ['/dashboards/roles-raci.html', 'Roles & RACI'], ncaaudit: ['/dashboards/nca-it-audit.html', 'NCA IT Audit'], ndmostudio: ['/dashboards/ndmo-studio.html', 'NDMO Studio'], ndmo: ['/dashboards/ndmo-studio.html', 'NDMO Studio'], pdpl: ['/dashboards/pdpl-studio.html', 'PDPL Studio'], chain: ['/dashboards/compliance-flow.html', 'Compliance Automation Flow'], 'db-oracle': ['/dashboards/databases.html', 'All Databases'],
    infradash: ['/dashboards/infra-manager.html', 'IT Infrastructure Manager'], ciodash: ['/dashboards/cio-dashboard.html', 'CIO Dashboard'], cisodash: ['/dashboards/ciso-dashboard.html', 'CISO Dashboard'], ciso: ['/dashboards/executive-dashboard.html', 'Executive Dashboard'], status: ['/dashboards/live-status.html', 'Live Status'], home: ['/dashboards/index.html', 'Home'], phishsim: ['/dashboards/phishing-simulation.html', 'Phishing Simulation'], brandprot: ['/dashboards/brand-protection.html', 'Brand Protection'], forensics: ['/dashboards/dfir.html', 'DFIR'], ir: ['/dashboards/incident-response.html', 'Incident Response Center'], soar: ['/dashboards/soar.html', 'SOAR - Automated Response'], tickets: ['/dashboards/tickets.html', 'Tickets'], cctv: ['/dashboards/cctv.html', 'CCTV / NVR'], appsec: ['/dashboards/appsec.html', 'AppSec & Code Review'], apppt: ['/dashboards/apppt.html', 'Application Pen Testing'], crosswalk: ['/dashboards/crosswalk.html', 'Framework Crosswalk'], gapall: ['/dashboards/gap-analysis.html', 'Gap Analysis - All Frameworks'], 'dash-grc': ['/dashboards/grc-dashboard.html', 'GRC Dashboard'], 'dash-vuln': ['/dashboards/vuln-dashboard.html', 'Vulnerability & Testing Dashboard'], scanlive: ['/dashboards/live-scan.html', 'Live Scan Engine & Attack Simulation'], webapi: ['/dashboards/webapps.html', 'Applications, Web Servers & APIs'], mobile: ['/dashboards/mobile-test.html', 'Mobile Application Testing'], iso: ['/dashboards/iso-lifecycle.html', 'ISO 27001 Lifecycle'], ecc: ['/dashboards/ecc-studio.html', 'NCA ECC Compliance Studio'], roadmap: ['/dashboards/roadmap.html', 'Remediation Roadmap'], risk: ['/dashboards/risk-assess.html', 'Automated Risk Assessment'], 'siem-sama': ['/dashboards/sama-siem.html', 'SAMA coverage from SIEM evidence'], maturity: ['/dashboards/maturity-level.html', 'Cybersecurity Maturity Level'], fwlib: ['/dashboards/framework-library.html', 'Regulatory Framework Library'], aigov: ['/dashboards/ai-governance.html', 'AI Governance'], bcm: ['/dashboards/bcm-matrix.html', 'Business Continuity & DR Matrix'], grc: ['/dashboards/compliance-overview.html', 'Compliance Overview'], contcomp: ['/dashboards/continuous-compliance.html', 'Continuous Compliance & Auto-Remediation'], validation: ['/dashboards/control-validation.html', 'Control Validation'], custody: ['/dashboards/evidence-custody.html', 'Evidence & Chain of Custody'], docs: ['/dashboards/compliance-docs.html', 'Compliance Documents & Evidence'], controls: ['/dashboards/security-controls.html', 'Security Controls \u2192 Compliance'], archer: ['/dashboards/grc-register.html', 'GRC Register'], iafw: ['/dashboards/ia-resilience.html', 'IA Cyber & Operational Resilience'], irm: ['/dashboards/insider-risk.html', 'Insider Risk'], sama: ['/dashboards/sama-audit.html', 'SAMA CSF'], 'sama-validation': ['/dashboards/sama-audit.html', 'SAMA CSF'], 'discovery': ['/dashboards/discovery-studio.html', 'Discovery Studio'], 'itam-discovery': ['/dashboards/discovery-studio.html', 'Discovery Studio'], 'discovery-results': ['/dashboards/discovery-studio.html#view=res', 'Discovery Studio - results'], 'discovery-runs': ['/dashboards/discovery-studio.html#view=runs', 'Discovery Studio - runs'], 'discovery-credentials': ['/dashboards/discovery-studio.html#view=cred', 'Discovery Studio - credentials'], 'discovery-scopes': ['/dashboards/scope-studio.html', 'Scope Studio'], 'vuln-assets': ['/dashboards/scanned-assets.html', 'Scanned Assets'], repcenter: ['/dashboards/report-center.html', 'Reporting Center'], notify: ['/dashboards/notify-center.html', 'Notification & Escalation'],   // the portal's role dashboards showed sample telemetry
    sam: ['/dashboards/apm.html', 'Applications Manager'], npmmon: ['/dashboards/npm-summary.html', 'NOC Summary'], alarmrules: ['/dashboards/alarm-rules.html', 'Alarm Inbox Rules'], signin: ['/dashboards/identity-signin.html', 'Identity & Sign-in'], users: ['/dashboards/user-management.html', 'User Management'], twin: ['/dashboards/digital-twin.html', 'Digital Twin'], 'soc-rules': ['/dashboards/alarm-rules.html', 'Alarm Inbox Rules'], npm: ['/dashboards/npm-summary.html', 'NOC Summary'], exchmgmt: ['/dashboards/exchange-admin.html', 'AI Exchange Admin'], datagov: ['/dashboards/dlp.html', 'Data Loss Prevention'],
    detstudio: ['/dashboards/detection-validation.html', 'Detection Validation'], node: ['/dashboards/server-availability.html', 'Server Availability'], scm: ['/dashboards/manageengine.html', 'ManageEngine'], 'dash-rep': ['/dashboards/platform.html', 'Platform Health'], 'dash-m365': ['/dashboards/m365-dashboard.html', 'Microsoft 365, Users & Endpoints'], portmap: ['/dashboards/switch-port-map.html', 'Switch Port Map'], topology: ['/dashboards/network-map.html', 'Intelligent Network Map'], logs: ['/dashboards/log-monitor.html', 'Log Monitor & Analysis'], siemlive: ['/dashboards/soc-live.html', 'Live SIEM Stream'], spo: ['/dashboards/sharepoint.html', 'SharePoint & OneDrive'], changelog: ['/dashboards/change-log.html', 'Change Log & NOC↔SOC Correlation'], hunt: ['/dashboards/soc-hunt.html', 'Threat Hunting & Search'], rogue: ['/dashboards/rogue-detection.html', 'Advanced Rogue Detection'], security: ['/dashboards/security-center.html', 'Security Center'], soc: ['/dashboards/security-center.html', 'Security Center'], noc: ['/dashboards/ops-wall.html', 'Operations Wall'], aisoc: ['/dashboards/ai-soc-analyst.html', 'AI SOC Analyst'], socops: ['/dashboards/soc-performance.html', 'SOC Performance & Operations'], msauto: ['/dashboards/m365-autoconfig.html', 'Microsoft Security Auto-Configuration'], wazuh: ['/dashboards/soc-console.html', 'SOC Console'], 'tiw-darkweb': ['/dashboards/dark-web-watch.html', 'Dark Web Watch'], nac: ['/dashboards/network-access.html', 'Network Access Control'], itops: ['/dashboards/update-studio.html', 'IT Operations & Updates'], netinv: ['/dashboards/infra-inventory.html', 'Infrastructure Inventory'], 'dash-srv': ['/dashboards/servers-dashboard.html', 'Servers, Cloud & Applications'], wall: ['/dashboards/ops-wall.html', 'Operations Wall'], 'itam-cmdb': ['/dashboards/cmdb-deps.html', 'CMDB & Dependencies'], implplan: ['/dashboards/impl-plan.html', 'Implementation Plan & Budget'], browsing: ['/dashboards/browsing-monitor.html', 'Browsing Traffic'], configure: ['/dashboards/device-config.html', 'Device Configuration'],
    aiteam: ['/dashboards/ai-team.html', 'AI Engineering Team'], aiops: ['/dashboards/aiops.html', 'AIOps Center'], repl: ['/dashboards/dr-studio.html', 'DR Studio'], virtualization: ['/dashboards/vsphere-studio.html', 'vSphere Studio'] };   // the portal's AIOps waited on the old hub's /api/autoremed
  // a portal page whose name reads like one of ours but is a different thing: a clearer name, in English and Arabic
  var RENAME = { 'infra-db': ['PostgreSQL / MySQL Health', 'صحة PostgreSQL / MySQL'], alarmrules: ['Alarm Inbox Rules', 'قواعد صندوق الإنذارات'] };   // alarmrules = the portal's in-browser alarm rules; SIEM Detection Rules = the engine's
  function renamePages(n) {
    Object.keys(RENAME).forEach(function (v) { var li = n.querySelector('li[data-view="' + v + '"]'); if (!li || li.getAttribute('data-zyb-renamed')) return;
      var en = RENAME[v][0], walk = document.createTreeWalker(li, NodeFilter.SHOW_TEXT, null), last = null;
      for (var t = walk.nextNode(); t; t = walk.nextNode()) { if (t.parentNode && t.parentNode.classList && (t.parentNode.classList.contains('ico') || t.parentNode.classList.contains('badge'))) continue; if (t.nodeValue.trim()) last = t; }
      if (last) last.nodeValue = ' ' + en; li.setAttribute('data-en', en); li.setAttribute('data-zyb-renamed', '1');
      try { var D = window.X_AR = window.X_AR || {}; D[en] = RENAME[v][1]; if (typeof AR !== 'undefined') AR[en] = RENAME[v][1]; } catch (e) { /* no Arabic map */ } });
  }
  function hideDuplicates(n) {
    renamePages(n);
    var ours = {}; (window.ZYB_NAV || []).forEach(function (a) { a.pages.forEach(function (p) { [p._en ? p._en.s : p.s, p._en ? p._en.t : p.t].forEach(function (x) { var k = normName(x); if (k) ours[k] = '/dashboards/' + p.h;
      var ab = /\(([^)]{2,40})\)/.exec(x || ''); if (ab && normName(ab[1])) ours[normName(ab[1])] = '/dashboards/' + p.h; }); }); });   /* "User Behaviour (UEBA)" also answers to UEBA */
    var seen = {};
    items(n).forEach(function (li) {
      if (li.getAttribute('data-zyb-menu') && !li.hasAttribute('data-zyb-moved')) return;   // our own pages are the reference
      if (START_DUP[li.getAttribute('data-view') || '']) { li.setAttribute('data-zyb-dup', 'same page as Discovery Studio / Scope Studio'); return; }   // the old Start here copies
      if (li.hasAttribute('data-zyb-start')) { li.removeAttribute('data-zyb-dup'); return; }   // set-up pages are never hidden, also when they redirect to a dashboard
      // replaced by one of our dashboards (also when its entry already redirects there): one menu entry, ours
      var al = ALIAS[li.getAttribute('data-view') || ''];
      if (al && n.querySelector('li[data-view="' + al + '"]')) { li.setAttribute('data-zyb-dup', 'replaced by the live portal page ' + al); return; }
      var cov = COVERED[li.getAttribute('data-view') || ''];
      if (cov && n.querySelector('li[data-zyb-menu][data-zyb-href="' + cov[0] + '"]')) { li.setAttribute('data-zyb-dup', 'replaced by the dashboard ' + cov[1] + ' (' + cov[0] + ')'); return; }
      if (li.getAttribute('data-zyb-live')) return;   // set-up pages are never hidden as a duplicate                                         // already opens the live dashboard
      var k = normName(labelOf(li)), why = '';
      if (k && ours[k]) why = 'same name as the dashboard ' + ours[k];
      else if (k && seen[k] && seen[k] !== keyOf(li)) why = 'same name as another portal page (' + seen[k] + ')';
      if (k && !seen[k]) seen[k] = keyOf(li);
      if (why) li.setAttribute('data-zyb-dup', why); else li.removeAttribute('data-zyb-dup');
    });
  }
  /* "Copy menu list" (admins): the menu exactly as drawn - headings, workspaces, every page with its key, where it came from and
     whether it is hidden - copied to the clipboard and saved as a text file, so a misplaced or duplicated page can be named */
  function menuList() {
    var n = nav(); if (!n) return '';
    var out = ['Menu as drawn ' + new Date().toISOString().slice(0, 16).replace('T', ' ') + ' UTC (' + location.host + ')', ''];
    [].forEach.call(n.children, function (li) {
      if (li.tagName !== 'LI') return;
      var lab = labelOf(li).replace(/\s+/g, ' '), hid = getComputedStyle(li).display === 'none';
      if (li.classList.contains('nav-group')) { out.push('## ' + groupName(li) + (li.classList.contains('zyb-empty') ? '   [portal group, empty - hidden]' : '')); return; }
      if (li.classList.contains('zyb-lbl')) { out.push('', '=== ' + lab.toUpperCase() + ' ==='); return; }
      if (li.classList.contains('zyb-area')) { out.push('  [' + li.getAttribute('data-zyb-area') + '] ' + (li.querySelector('.zyb-an') || li).textContent); return; }
      var tag = [];
      if (li.getAttribute('data-view')) tag.push('portal:' + li.getAttribute('data-view'));
      else if (li.getAttribute('data-zyb-href')) tag.push(li.getAttribute('data-zyb-href'));
      if (li.hasAttribute('data-zyb-moved')) tag.push('moved into ' + li.getAttribute('data-zyb-moved'));
      if (li.getAttribute('data-zyb-dup')) tag.push('HIDDEN DUPLICATE: ' + li.getAttribute('data-zyb-dup'));
      else if (hid && !li.hasAttribute('data-zyb-col')) tag.push('hidden');
      out.push((li.getAttribute('data-zyb-area') ? '      - ' : '    - ') + lab + '   (' + tag.join(' · ') + ')');
    });
    return out.join('\n') + '\n';
  }
  function copyMenuList() {
    var t = menuList(); if (!t) return;
    try { if (navigator.clipboard) navigator.clipboard.writeText(t).catch(function () { /* the file below still has it */ }); } catch (e) { /* no clipboard */ }
    try { var a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([t], { type: 'text/plain' })); a.download = 'menu-list-' + new Date().toISOString().slice(0, 10) + '.txt'; document.body.appendChild(a); a.click(); setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 500); } catch (e) { /* clipboard only */ }
    toast('Menu list copied and saved as a file - send it to report a misplaced or duplicated page');
  }
  // a portal heading whose pages all moved into workspaces is hidden (shown again as soon as a page lands under it)
  function hideEmptyHeads(n) {
    heads(n).forEach(function (h) { if (h.getAttribute('data-zyb-menu')) return; var x = h.nextElementSibling, any = false;
      while (x && !x.classList.contains('nav-group')) { if (x.tagName === 'LI' && !x.hasAttribute('data-zyb-moved') && !x.getAttribute('data-zyb-menu') && !x.hasAttribute('data-zyb-dup')) { any = true; break; } x = x.nextElementSibling; }
      h.classList.toggle('zyb-empty', !any); });
  }
  /* a page's own settings entry (AD & Exchange / Microsoft 365 Configuration) follows its page into the workspace, so it is
     never left behind under an otherwise empty portal heading */
  function followSettings(n) {
    var moved = false;
    [['adcfg', 'adex'], ['m365cfg', 'm365']].forEach(function (x) {
      var cfg = n.querySelector('li[data-zyb-menu="' + x[0] + '"]'), src = n.querySelector('li[data-view="' + x[1] + '"]'); if (!cfg || !src) return;
      var id = src.getAttribute('data-zyb-moved');
      if (id && (cfg.getAttribute('data-zyb-area') !== id || cfg.previousElementSibling !== src)) { if (intoArea(n, cfg, id, src.nextElementSibling)) moved = true; }
    });
    return moved;
  }
  /* "Start here" holds everything needed to set the platform up: Connections & Setup, adding servers / devices, and the
     portal's asset discovery pages (Asset Discovery, Scopes, Credentials, Results, Runs, bulk add). They are moved under
     Start here wherever they were - the same business rule as Databases, so a saved order cannot scatter them again. */
  // Asset Discovery and Discovery Scopes are NOT here: they open Discovery Studio and Scope Studio, which have their own menu
  // entries, so a Start here copy was the same page twice (the duplicate-menu check); the copies are hidden as duplicates
  var START_VIEWS = ['connect', 'discovery-credentials', 'discovery-results', 'discovery-runs', 'connect-bulk', 'bulk-add'];
  var START_DUP = { discovery: 1, 'discovery-scopes': 1 };
  // the first stays in sight; the rest fold under one row so Start here fits a 14-inch laptop screen
  var START_MAIN = { connect: 1 };
  var START_LABEL = /^(discovery (credentials|results|runs)|bulk add( devices)?|add devices( in bulk)?)$/i;
  function startUp(n) {
    var first = n.querySelector('li[data-zyb-menu="item"][data-zyb-href$="/add-server.html"]') || n.querySelector('li[data-zyb-menu="item"][data-zyb-href$="/network-discovery.html"]');
    var conn = n.querySelector('li[data-zyb-menu="item"][data-zyb-href$="/connections.html"]'); if (!first && !conn) return false;
    items(n).forEach(function (li) { if (START_DUP[li.getAttribute('data-view') || '']) { li.removeAttribute('data-zyb-start'); li.removeAttribute('data-zyb-startmore'); li.setAttribute('data-zyb-dup', 'start-dup'); } });
    var want = items(n).filter(function (li) { if (li.getAttribute('data-zyb-menu') && !li.hasAttribute('data-zyb-moved')) return false; var v = li.getAttribute('data-view') || '';
      if (START_DUP[v]) return false;
      return START_VIEWS.indexOf(v) >= 0 || START_LABEL.test(labelOf(li).replace(/\s+/g, ' ')); });
    if (!want.length) return false;
    var rk = function (li) { var i = START_VIEWS.indexOf(li.getAttribute('data-view') || ''); return i < 0 ? 50 : i; };
    want.sort(function (a, b) { return rk(a) - rk(b) || labelOf(a).localeCompare(labelOf(b)); });
    var before = first || conn.nextElementSibling, changed = false;
    for (var i = want.length - 1; i >= 0; i--) { var li = want[i];
      if (li.getAttribute('data-zyb-moved') !== 'start') changed = true;
      li.classList.remove('zyb-sub', 'tree-hidden'); li.removeAttribute('data-zyb-area'); li.removeAttribute('data-zyb-col'); li.removeAttribute('data-zyb-gc');
      li.setAttribute('data-zyb-moved', 'start'); li.setAttribute('data-zyb-start', '');
      if (li.nextElementSibling !== before) { n.insertBefore(li, before); changed = true; }
      before = li; }
    startFold(n, want);
    return changed;
  }
  function startFold(n, list) {
    var more = list.filter(function (li) { return !START_MAIN[li.getAttribute('data-view') || '']; });
    list.forEach(function (li) { if (START_MAIN[li.getAttribute('data-view') || '']) li.removeAttribute('data-zyb-startmore'); else li.setAttribute('data-zyb-startmore', ''); });
    var tg = n.querySelector('li[data-zyb-menu="startmore"]');
    if (!more.length) { if (tg) tg.remove(); return; }
    if (!tg) {
      tg = document.createElement('li'); tg.className = 'zyb-link zyb-sm-tg'; tg.setAttribute('data-zyb-menu', 'startmore'); tg.setAttribute('data-zyb-start', ''); tg.setAttribute('role', 'button'); tg.tabIndex = 0;
      var flip = function (e) { e.preventDefault(); e.stopPropagation(); var o = !n.classList.contains('zyb-sm-open'); n.classList.toggle('zyb-sm-open', o); tg.setAttribute('aria-expanded', String(o)); try { localStorage.setItem('zyb-startmore', o ? '1' : '0'); } catch (x) { /* storage blocked */ } };
      tg._zybClick = flip; tg.addEventListener('click', flip, true); tg.addEventListener('keydown', function (e) { if (e.key === 'Enter' || e.key === ' ') flip(e); }, true);
      var open = false; try { open = localStorage.getItem('zyb-startmore') === '1'; } catch (x) { /* storage blocked */ }
      if (more.some(function (li) { return li.classList.contains('active'); })) open = true;   // the page being looked at is one of them
      n.classList.toggle('zyb-sm-open', open); tg.setAttribute('aria-expanded', String(open));
    }
    tg.textContent = 'More set-up pages (' + more.length + ')'; tg.title = 'Discovery credentials, results, runs and bulk add';
    if (tg.nextElementSibling !== more[0]) n.insertBefore(tg, more[0]);
  }
  // the portal gives many pages a bullet character ("•") as their icon: in the menu that reads as a bulleted list, so a
  // bullet-only icon is hidden (the label stays aligned by the item's padding); a real emoji / icon is kept
  var BULLET = /^[\u2022\u00b7\u2219\u25cf\u25cb\u25e6\u25aa\u25ab\u2023\u2043\-\u2013\u2014*]$/;
  function noBullets(n) { [].forEach.call(n.querySelectorAll('li .ico'), function (ic) { if (BULLET.test(String(ic.textContent || '').trim())) ic.classList.add('zyb-noico'); }); }
  function dbPagesToDb() {
    var n = nav(); if (!n || state.editing) return;
    var moved = startUp(n);
    items(n).forEach(function (li) { if (!movable(li) || li.hasAttribute('data-zyb-start')) return; var lab = labelOf(li);
      for (var i = 0; i < AREA_RULES.length; i++) { var id = AREA_RULES[i][0]; if (!AREA_RULES[i][1].test(lab)) continue; if (li.getAttribute('data-zyb-moved') !== id && areaRow(n, id) && intoArea(n, li, id)) moved = true; break; } });
    if (subjectPages(n)) moved = true;
    if (followSettings(n)) moved = true;
    if (moved) retree();
    hideDuplicates(n);
    hideEmptyHeads(n);
    noBullets(n);
    sortMoved(n);
    areaFold(n);
    recount(n);
  }
  /* inside a workspace its own dashboards keep their curated order; the portal pages moved in follow them, A to Z */
  function sortMoved(n) {
    [].forEach.call(n.querySelectorAll('li.zyb-area[data-zyb-area]'), function (row) { var id = row.getAttribute('data-zyb-area');
      var mv = [].filter.call(n.querySelectorAll('li[data-zyb-moved="' + id + '"]'), function (li) { return !li.getAttribute('data-zyb-menu'); });
      if (mv.length < 2) return;
      var sorted = mv.slice().sort(function (a, b) { return labelOf(a).localeCompare(labelOf(b)); });
      if (sorted.every(function (li, i) { return li === mv[i]; })) return;
      var end = areaEnd(n, id), after = end ? end.nextElementSibling : null;
      sorted.forEach(function (li) { n.insertBefore(li, after); var cfg = { adex: 'adcfg', m365: 'm365cfg' }[li.getAttribute('data-view')], c = cfg && n.querySelector('li[data-zyb-menu="' + cfg + '"]');
        if (c && c.getAttribute('data-zyb-area') === id) n.insertBefore(c, after); }); });
  }
  /* a long workspace (more than 14 pages) keeps our dashboards in sight and folds the portal's pages under one
     "More … (n)" row, so a workspace fits a 14-inch laptop screen; the open / closed choice is remembered per workspace */
  var FOLD_AT = 14;
  function areaFold(n) {
    var st = {}; try { st = JSON.parse(localStorage.getItem('zyb-areamore') || '{}') || {}; } catch (e) { st = {}; }
    [].forEach.call(n.querySelectorAll('li.zyb-area[data-zyb-area]'), function (row) { var id = row.getAttribute('data-zyb-area');
      var all = [].filter.call(n.querySelectorAll('li.zyb-sub[data-zyb-area="' + id + '"]'), function (li) { return !li.hasAttribute('data-zyb-dup') && li.getAttribute('data-zyb-menu') !== 'areamore'; });
      var mv = all.filter(function (li) { return li.getAttribute('data-zyb-moved') === id && !li.getAttribute('data-zyb-menu'); });
      var tg = n.querySelector('li[data-zyb-menu="areamore"][data-zyb-area="' + id + '"]');
      if (all.length <= FOLD_AT || mv.length < 4) { if (tg) tg.remove(); mv.forEach(function (li) { li.removeAttribute('data-zyb-more'); }); return; }
      var open = !!st[id] || mv.some(function (li) { return li.classList.contains('active'); });
      if (!tg) {
        tg = document.createElement('li'); tg.className = 'zyb-sub zyb-link zyb-sm-tg'; tg.setAttribute('data-zyb-menu', 'areamore'); tg.setAttribute('data-zyb-area', id); tg.setAttribute('role', 'button'); tg.tabIndex = 0;
        if (!row.classList.contains('zyb-open')) tg.setAttribute('data-zyb-col', '');
        var flip = function (e) { e.preventDefault(); e.stopPropagation(); var s2 = {}; try { s2 = JSON.parse(localStorage.getItem('zyb-areamore') || '{}') || {}; } catch (x) { s2 = {}; }
          s2[id] = !tg.classList.contains('zyb-more-open'); try { localStorage.setItem('zyb-areamore', JSON.stringify(s2)); } catch (x) { /* storage blocked */ } paint(s2[id]); };
        tg._zybClick = flip; tg.addEventListener('click', flip, true); tg.addEventListener('keydown', function (e) { if (e.key === 'Enter' || e.key === ' ') flip(e); }, true);
      }
      var label = labelOf(row).replace(/\s*\d+\s*$/, '');
      function paint(o) { tg.classList.toggle('zyb-more-open', !!o); tg.setAttribute('aria-expanded', String(!!o)); tg.textContent = 'More in ' + label + ' (' + mv.length + ')';
        mv.forEach(function (li) { li.setAttribute('data-zyb-more', id); if (o) li.setAttribute('data-zyb-moreopen', ''); else li.removeAttribute('data-zyb-moreopen'); }); }
      paint(open);
      if (tg.nextElementSibling !== mv[0]) n.insertBefore(tg, mv[0]);
    });
  }
  // each workspace shows how many pages it really holds, the portal pages moved into it included (duplicates hidden excluded)
  function recount(n) {
    [].forEach.call(n.querySelectorAll('li.zyb-area[data-zyb-area]'), function (row) { var c = row.querySelector('.zyb-cnt'); if (!c) return;
      var k = [].filter.call(n.querySelectorAll('li.zyb-sub[data-zyb-area="' + row.getAttribute('data-zyb-area') + '"]'), function (li) { return !li.hasAttribute('data-zyb-dup') && li.getAttribute('data-zyb-menu') !== 'areamore' && !li.classList.contains('zyb-sg'); }).length;   // a sub-menu heading is not a page
      if (k && String(k) !== c.textContent) c.textContent = k; });
  }
  /* saved area placements again when the portal or the Dashboards menu (re)draws late */
  function reapplyAreas() {
    var n = nav(), moved = false; if (!n || state.editing) return;
    (state.order && state.order.groups || []).forEach(function (g) { var m = /^area:(.+)$/.exec(g.name); if (!m) return;
      (g.items || []).forEach(function (k) { var li = items(n).filter(function (x) { return keyOf(x) === k && movable(x) && !x.hasAttribute('data-zyb-start'); })[0]; if (li && li.getAttribute('data-zyb-moved') !== m[1] && intoArea(n, li, m[1])) moved = true; }); });
    if (moved) retree();
    applyDefaults();
    dbPagesToDb();
  }

  /* ---- drag and drop (admin, while editing): drop on a page = before / after it (into its group or workspace), on a
     group heading = end of that group, on a workspace row = end of that workspace. The arrows stay for the keyboard. */
  var drag = null;
  function clearMarks() { var n = nav(); if (n) [].forEach.call(n.querySelectorAll('.zyb-dz-b,.zyb-dz-a,.zyb-dz-in'), function (x) { x.classList.remove('zyb-dz-b', 'zyb-dz-a', 'zyb-dz-in'); }); }
  function dropTarget(e) { var t = e.target && e.target.closest ? e.target.closest('ul.nav > li') : null; if (!t || t === drag) return null;
    if (/fav/.test(t.getAttribute('data-zyb-menu') || '')) return null; return t; }
  function wireDnD() {
    var n = nav(); if (!n || n._zybDnD) return; n._zybDnD = true;
    n.addEventListener('dragstart', function (e) { if (!state.editing) return; var li = e.target && e.target.closest ? e.target.closest('ul.nav > li') : null;
      if (!movable(li)) { e.preventDefault(); return; } drag = li; li.classList.add('zyb-dragging'); try { e.dataTransfer.effectAllowed = 'move'; e.dataTransfer.setData('text/plain', keyOf(li)); } catch (er) { /* drag data not supported by this browser: dragging still reorders */ } });
    n.addEventListener('dragover', function (e) { if (!state.editing || !drag) return; var t = dropTarget(e); clearMarks(); if (!t) return; e.preventDefault();
      if (t.classList.contains('nav-group') || t.classList.contains('zyb-area')) t.classList.add('zyb-dz-in');
      else { var r = t.getBoundingClientRect(); t.classList.add(e.clientY < r.top + r.height / 2 ? 'zyb-dz-b' : 'zyb-dz-a'); } });
    n.addEventListener('dragleave', function (e) { if (e.target === n) clearMarks(); });
    n.addEventListener('drop', function (e) { if (!state.editing || !drag) return; var t = dropTarget(e); e.preventDefault(); clearMarks(); if (!t) return; moveTo(drag, t, e); });
    n.addEventListener('dragend', function () { if (drag) drag.classList.remove('zyb-dragging'); drag = null; clearMarks(); });
  }
  function moveTo(li, t, e) {
    var n = nav(), r = t.getBoundingClientRect(), after = e && e.clientY >= r.top + r.height / 2;
    if (t.classList.contains('zyb-area')) { intoArea(n, li, t.getAttribute('data-zyb-area')); }
    else if (t.classList.contains('nav-group')) { outOfArea(li); var blk = blockOf(t), last = blk[blk.length - 1]; n.insertBefore(li, last.nextElementSibling); }
    else if (t.getAttribute('data-zyb-area')) { var id = t.getAttribute('data-zyb-area'); outOfArea(li); intoArea(n, li, id, after ? t.nextElementSibling : t); }
    else { outOfArea(li); n.insertBefore(li, after ? t.nextElementSibling : t); }
    retree(); li.classList.remove('tree-hidden'); li.removeAttribute('data-zyb-gc'); if (!li.hasAttribute('data-zyb-moved')) li.removeAttribute('data-zyb-col');
    toast('Moved ' + labelOf(li) + ' - press "Save order for everyone" to keep it');
  }
  function setDraggable(on) { var n = nav(); if (!n) return; items(n).forEach(function (li) { if (movable(li)) { if (on) li.setAttribute('draggable', 'true'); else li.removeAttribute('draggable'); } }); }
  function firstGroupSlot(n) { var x = n.firstElementChild; while (x && /fav/.test(x.getAttribute('data-zyb-menu') || '')) x = x.nextElementSibling; return x; }
  function editBar(on) {
    var bar = document.getElementById('zyb-editbar'), n = nav(); if (!n) return;
    if (!bar) {
      bar = document.createElement('div'); bar.id = 'zyb-editbar'; n.parentNode.insertBefore(bar, n);
    }
    bar.innerHTML = on
      ? '<button class="pri" data-a="save" type="button">Save order for everyone</button><button data-a="cancel" type="button">Cancel</button><button data-a="reset" type="button">Reset to default</button><span class="hint">Drag a page onto another page, a group heading or a workspace to move it there, or use ▲ ▼. Everyone sees the saved order.</span>'
      : '<button data-a="edit" type="button">Edit menu order</button><button data-a="list" type="button" title="Copy the menu as drawn (headings, pages, what was moved or hidden) to report a problem">Copy menu list</button>';
    bar.onclick = bar._zybClick = function (e) {
      var a = e.target.getAttribute && e.target.getAttribute('data-a'); if (!a) return;
      e.stopPropagation(); if (e.stopImmediatePropagation) e.stopImmediatePropagation();   // handled once (routed from the window)
      if (a === 'edit') { state.editing = true; state.before = currentOrder(); n.classList.add('zyb-editing'); wireDnD(); setDraggable(true); editBar(true); }
      if (a === 'list') { copyMenuList(); return; }
      if (a === 'cancel') { applyOrder({ groups: state.before }); stopEdit(); }
      if (a === 'save') { var ord = currentOrder(); req('PUT', API + '/order', { groups: ord, v: 2 }).then(function (d) { state.order = (d && d.order) || { groups: ord, v: 2 }; toast('Menu order saved for everyone'); stopEdit(); }).catch(function (err) { toast('Not saved (' + err.message + ')'); }); }
      if (a === 'reset') req('DELETE', API + '/order').then(function () { toast('Default order restored - reloading'); setTimeout(function () { location.reload(); }, 900); }).catch(function (err) { toast('Not reset (' + err.message + ')'); });
    };
  }
  function stopEdit() { state.editing = false; retree(); var n = nav(); if (n) n.classList.remove('zyb-editing'); setDraggable(false); clearMarks(); editBar(false); }

  function start() {
    var n = nav(); if (!n) { setTimeout(start, 300); return; }
    req('GET', API).then(function (d) {
      state.server = true; state.favs = Array.isArray(d.favorites) ? d.favorites.slice(0, 30) : []; state.order = d.order; state.canEdit = !!d.can_edit_order;
    }).catch(function () {
      state.server = false; try { state.favs = JSON.parse(localStorage.getItem(LS) || '[]').slice(0, 30); } catch (e) { state.favs = []; }
    }).then(function () {
      if (state.order) applyOrder(state.order);
      applyDefaults(); dbPagesToDb();
      decorate(); drawFavs(); if (state.canEdit) editBar(false);
      document.documentElement.classList.add('zyb-menu-on');   // zyb-early.js kept the menu invisible until it was arranged
      /* the portal may redraw its menu: decorate new items again */
      new MutationObserver(function () { var m = nav(); if (m && items(m).some(function (li) { return !li.querySelector(':scope>.zyb-star'); })) { decorate(); drawFavs(); reapplyAreas(); if (state.editing) setDraggable(true); } })
        .observe(document.body, { childList: true, subtree: true });
    });
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', function () { setTimeout(start, 400); }); else setTimeout(start, 400);
})();

/* home page additions (signed-in user under the greeting, server stats, SIEM log flow, city temperature) and the
   CISO dashboard panel (SIEM health, tickets from SIEM alerts, SLA violations) */
(function () {
  var BUILD = '__ZYB_BUILD__';
  if (BUILD.indexOf('__')) window.ZYB_BUILD = BUILD;   // vendor/zyb-update.js: the build this page runs, to notice the next one
  window.ZYB_ERR_QUIET = true;   // the portal: errors are reported to Platform Health, the portal keeps its own messages
  ['zyb-errors.js', 'zyb-update.js', 'zyb-navsplit.js', 'zyb-home.js', 'zyb-sla.js', 'zyb-avail.js', 'zyb-itamdel.js', 'zyb-netinv.js', 'zyb-m365.js', 'zyb-siem.js', 'zyb-assetreg.js', 'zyb-discprog.js', 'zyb-roles.js', 'zyb-modules.js', 'zyb-siemconn.js', 'zyb-discovery.js', 'zyb-tiles.js', 'zyb-assetlinks.js', 'zyb-itamcols.js', 'zyb-display.js', 'zyb-fullview.js'].forEach(function (f) {
    if (document.querySelector('script[src*="/dashboards/vendor/' + f + '"]')) return;
    // ?v=<deploy stamp> (install-dashboards.sh writes it): a browser or proxy cache can never keep running last week's add-ons
    var s = document.createElement('script'); s.src = '/dashboards/vendor/' + f + (BUILD.indexOf('__') ? '?v=' + BUILD : ''); s.defer = true; (document.head || document.documentElement).appendChild(s);
  });
})();
