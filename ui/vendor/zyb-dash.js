// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
/* zyb-dash.js - shared by every dashboard page: the app shell (sidebar menu, breadcrumb top bar, Ctrl+K search) and per-user look settings
 * (colour theme, accent colour, font, text size). Settings are kept in this browser (localStorage) and applied before the
 * page draws; saving reloads the page so the charts redraw with the new colours. Loaded in <head>. */
(function () {
  'use strict';
  // Brand colours: Zyberon Sentra (default) or the organisation green, one choice for the menu, the main page and the sign-in page,
  // saved in zyb-dash-prefs.brand. window.zybBrand(on) changes it and tells the page ('zyb-brand' event) so it can repaint.
  try {
    var bp = function () { try { return JSON.parse(localStorage.getItem('zyb-dash-prefs') || '{}') || {}; } catch (e) { return {}; } };
    // the company look is the default (brand setting: company_look false = the Zyberon Sentra design unless switched on)
    var lookDef = !(window.ZYB_ORG && window.ZYB_ORG.company_look === false);
    window.zybBrandOn = function () { var b = bp().brand; return b === 'org' || (b !== 'off' && lookDef); };
    window.zybBrand = function (on) {
      var p = bp(); p.brand = on ? 'org' : 'off';
      try { localStorage.setItem('zyb-dash-prefs', JSON.stringify(p)); } catch (e) { /* no storage: this visit only */ }
      document.documentElement.classList.toggle('org-brand', !!on); document.documentElement.classList.toggle('org-light', !!on && window.zybBrandLookIs() === 'light');
      if (on) lookTheme(bp().brandLook === 'light' ? 'light' : 'dark');
      [].forEach.call(document.querySelectorAll('[data-zyb-brandsw]'), function (b) { b.setAttribute('aria-checked', String(!!on)); });
      [].forEach.call(document.querySelectorAll('[data-zyb-looksw]'), function (b) { b.hidden = !on; });   // dark / light is a choice within the company look
      try { window.dispatchEvent(new CustomEvent('zyb-brand', { detail: { on: !!on, look: window.zybBrandLookIs() } })); } catch (e) { /* very old browser: the page repaints on the next load */ }
    };
    // the company look drives the platform theme's surfaces too, so turning on "Light look" makes every page light - not just the
    // accents (data-zyb-theme=light is what paints the pages light; vendor/zyb-theme.css). Only when the company look is on.
    function curTheme() { try { return localStorage.getItem('noc_theme') || 'dark'; } catch (e) { return 'dark'; } }
    function lookTheme(lk) { if (!window.zybBrandOn || !window.zybBrandOn()) return;
      // light look -> light theme; dark look -> only step back from light (a Dark or Midnight theme the person chose is left alone)
      var want = lk === 'light' ? 'light' : (curTheme() === 'light' ? 'dark' : null); if (!want) return;
      try { localStorage.setItem('noc_theme', want); } catch (e) { /* no storage: this visit only */ }
      try { if (window.zybTheme && window.zybTheme.apply) window.zybTheme.apply(want); } catch (e) { /* theme layer not ready: the next load applies it */ } }
    // the company look has two faces: dark (the default) or light like the company website; saved in zyb-dash-prefs.brandLook
    // the platform's Light theme (localStorage noc_theme, vendor/zyb-look.js) always shows the light face: a dark company look on a
    // light page mixed a navy wash into a light background (the home page in the Light theme)
    var platLight = function () { try { return localStorage.getItem('noc_theme') === 'light' || document.documentElement.getAttribute('data-zyb-theme') === 'light'; } catch (e) { return false; /* no storage: the saved choice decides */ } };
    window.zybBrandLookIs = function () { return bp().brandLook === 'light' || platLight() ? 'light' : 'dark'; };
    window.zybBrandLook = function (look) {
      var p = bp(); p.brandLook = look === 'light' ? 'light' : 'dark';
      try { localStorage.setItem('zyb-dash-prefs', JSON.stringify(p)); } catch (e) { /* no storage: this visit only */ }
      lookTheme(look === 'light' ? 'light' : 'dark');
      var on = window.zybBrandOn(), lk = window.zybBrandLookIs(); document.documentElement.classList.toggle('org-light', on && lk === 'light');
      [].forEach.call(document.querySelectorAll('[data-zyb-looksw]'), function (b) { b.setAttribute('aria-checked', String(lk === 'light')); });
      try { window.dispatchEvent(new CustomEvent('zyb-brand', { detail: { on: on, look: lk } })); } catch (e) { /* very old browser: the page repaints on the next load */ }
    };
    if (window.zybBrandOn()) { document.documentElement.classList.add('org-brand'); if (window.zybBrandLookIs() === 'light') document.documentElement.classList.add('org-light');
      if (bp().brandLook === 'light') lookTheme('light'); }
    // the theme switched while the page is open: the company look follows (and the page's own handler, e.g. the home page, repaints)
    try { new MutationObserver(function () { var on = window.zybBrandOn(), lk = window.zybBrandLookIs(); if (document.documentElement.classList.contains('org-light') === (on && lk === 'light')) return;
      document.documentElement.classList.toggle('org-light', on && lk === 'light');
      [].forEach.call(document.querySelectorAll('[data-zyb-looksw]'), function (b) { b.setAttribute('aria-checked', String(lk === 'light')); });
      try { window.dispatchEvent(new CustomEvent('zyb-brand', { detail: { on: on, look: lk } })); } catch (e) { /* very old browser: the next load repaints */ } })
      .observe(document.documentElement, { attributes: true, attributeFilter: ['data-zyb-theme'] }); } catch (e) { /* no MutationObserver: the next load applies the theme */ }
  } catch (e) { /* the default design */ }
  // display controls + data freshness (vendor/zyb-display.js), loaded while the head is parsed so it sees the page's
  // first data requests too
  try { if (!window.__zybDisplay && document.readyState === 'loading') document.write('<script src="vendor/zyb-display.js?v=' + encodeURIComponent((document.currentScript && /[?&]v=([^&]+)/.exec(document.currentScript.src) || [])[1] || '1') + '"><\/script>'); } catch (e) { /* no display controls */ }
  // the brand setting (vendor/zyb-org.js): every page carries its tag before this script; a page that does not (an older
  // copy, a page added without it) still gets it here, ahead of the registry that names the company through it
  try { if (!window.ZYB_ORG && document.readyState === 'loading' && !document.querySelector('script[src*="zyb-org.js"]')) document.write('<script src="vendor/zyb-org.js?v=' + encodeURIComponent((document.currentScript && /[?&]v=([^&]+)/.exec(document.currentScript.src) || [])[1] || '1') + '"><\/script>'); } catch (e) { /* the page's own tag is the normal path */ }
  // the dashboard registry (vendor/zyb-nav.js): menu, breadcrumb, search and the home page all read it
  try { if (!window.ZYB_NAV && document.readyState === 'loading' && !document.querySelector('script[src*="zyb-nav.js"]')) document.write('<script src="vendor/zyb-nav.js?v=' + encodeURIComponent((document.currentScript && /[?&]v=([^&]+)/.exec(document.currentScript.src) || [])[1] || '1') + '"><\/script>'); } catch (e) { /* menu falls back to the top bar only */ }
  // the module subscription (vendor/zyb-modules.js), right after the registry it narrows: pages outside the organisation's subscription leave the menu
  try { if (!window.ZybModules && document.readyState === 'loading' && !document.querySelector('script[src*="zyb-modules.js"]')) document.write('<script src="vendor/zyb-modules.js?v=' + encodeURIComponent((document.currentScript && /[?&]v=([^&]+)/.exec(document.currentScript.src) || [])[1] || '1') + '"><\/script>'); } catch (e) { /* no subscription filter: every page shows */ }
  var KEY = 'zyb-dash-prefs';
  // Arabic (zyb-lang.js, zyb-pdpl-ar.js, pyengine/pdpl_ar.py) is on: each person picks English or Arabic on the sign-in page
  // (login-skin/zyb-login.js) or in Customize -> Language; the choice is kept in this browser. Same switch as zyb-menu.js.
  var ARABIC_ON = true;
  if (window.ZYB_ARABIC === undefined) window.ZYB_ARABIC = ARABIC_ON;
  // the Tabler look (vendor/zyb-tabler.css, under html.zyb-tb): loaded here so it is in place before the page draws
  var VER = encodeURIComponent((document.currentScript && /[?&]v=([^&]+)/.exec(document.currentScript.src) || [])[1] || '1');
  try { if (document.head && !document.getElementById('zyb-tabler-css')) { var tl = document.createElement('link'); tl.id = 'zyb-tabler-css'; tl.rel = 'stylesheet'; tl.href = 'vendor/zyb-tabler.css?v=' + VER; document.head.appendChild(tl); } } catch (e) { /* original look */ }
  // POC mode (vendor/zyb-poc.js): only while the menu's "POC data" switch is on in this browser, or ?poc=1 - pages that have
  // illustrative data draw from it with the POC ribbon, every change is refused; loaded before the page's own requests
  try { var pocOn = /[?&]poc=1(&|$)/.test(location.search) || localStorage.getItem('zyb-poc') === '1'; if (pocOn && !window.zybPoc && document.readyState === 'loading') document.write('<script src="vendor/zyb-poc-data.js?v=' + VER + '"><\/script><script src="vendor/zyb-poc-rec.js?v=' + VER + '"><\/script><script src="vendor/zyb-poc-soc.js?v=' + VER + '"><\/script><script src="vendor/zyb-poc-itam.js?v=' + VER + '"><\/script><script src="vendor/zyb-poc.js?v=' + VER + '"><\/script>'); } catch (e) { /* storage blocked: POC stays off, the page shows live data */ }
  // every Refresh button says it did something: it spins while the page reloads its data and a short note gives the time - a
  // refresh that brings the same figures otherwise looks like a button that does nothing
  try {
    document.addEventListener('click', function (e) {
      var b = e.target && e.target.closest && e.target.closest('button'); if (!b) return;
      var id = b.id || '', tx = (b.textContent || '').trim();
      if (!/^(refresh|rf|zi-refresh|sv-refresh|rfr|reload)$/i.test(id) && !/^(⟳|↻)\s*Refresh$|^Refresh$/i.test(tx)) return;
      if (!document.getElementById('zyb-rf-style')) { var st = document.createElement('style'); st.id = 'zyb-rf-style'; st.setAttribute('data-zyb-theme', 'skip');
        st.textContent = '@keyframes zybspin{to{transform:rotate(360deg)}}button.zyb-rf-busy{opacity:.75}button.zyb-rf-busy::before{content:"";display:inline-block;width:11px;height:11px;margin-right:6px;border:2px solid currentColor;border-right-color:transparent;border-radius:50%;vertical-align:-1px;animation:zybspin .7s linear infinite}'
          + '#zyb-rf-note{position:fixed;right:18px;bottom:18px;z-index:99998;background:#13261b;border:1px solid #2f7d4a;color:#9fe2b3;border-radius:9px;padding:7px 12px;font:13px "Segoe UI",system-ui,sans-serif;box-shadow:0 6px 20px rgba(0,0,0,.35)}';
        document.head.appendChild(st); }
      b.classList.add('zyb-rf-busy');
      setTimeout(function () { b.classList.remove('zyb-rf-busy'); var n = document.getElementById('zyb-rf-note'); if (!n) { n = document.createElement('div'); n.id = 'zyb-rf-note'; n.setAttribute('role', 'status'); document.body.appendChild(n); }
        n.textContent = '\u2713 Refreshed ' + new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }); n.hidden = false; clearTimeout(n._t); n._t = setTimeout(function () { n.hidden = true; }, 2500); }, 900);
    }, true);
  } catch (e) { /* no feedback: the buttons still work */ }
  // error handling for the page (vendor/zyb-errors.js): first, so an error while the page draws is already caught
  // menu hide / show (Ctrl+B), full screen and an easy-to-grab menu scrollbar (vendor/zyb-fullview.js)
  try { if (!window.zybFullview) { var zf = document.createElement('script'); zf.src = 'vendor/zyb-fullview.js?v=' + VER; zf.defer = true; (document.head || document.documentElement).appendChild(zf); } } catch (e) { /* the page works without it */ }
  try { if (!window.zybErrors) { if (document.readyState === 'loading') document.write('<script src="vendor/zyb-errors.js?v=' + VER + '"><\/script>'); else { var ze = document.createElement('script'); ze.src = 'vendor/zyb-errors.js?v=' + VER; (document.head || document.documentElement).appendChild(ze); } } } catch (e) { /* the page works without it */ }
  // printing / Save as PDF: a clean white report look with the company logo on every page (vendor/zyb-print.js)
  try { if (!window.__zybPrint) { var zp = document.createElement('script'); zp.src = 'vendor/zyb-print.js?v=' + VER; zp.defer = true; (document.head || document.documentElement).appendChild(zp); } } catch (e) { /* the page prints with its own look */ }
  // a new version shows by itself after an update, in every browser (vendor/zyb-update.js reads /dashboards/build.json)
  try { if (!window.zybUpdate) { if (/^\d{8,}$/.test(VER)) window.ZYB_BUILD = VER; var zu = document.createElement('script'); zu.src = 'vendor/zyb-update.js?v=' + VER; zu.defer = true; (document.head || document.documentElement).appendChild(zu); } } catch (e) { /* the page works without it: Ctrl+F5 shows a new version */ }
  // one vocabulary, English or Arabic (vendor/zyb-lang.js): loaded before the page draws so the direction is right from the start
  try { if (!window.zybLang) { if (document.readyState === 'loading') document.write('<script src="vendor/zyb-lang.js?v=' + VER + '"><\/script>'); else { var zl = document.createElement('script'); zl.src = 'vendor/zyb-lang.js?v=' + VER; (document.head || document.documentElement).appendChild(zl); } } } catch (e) { /* English only */ }
  // clickable KPI tiles everywhere (vendor/zyb-click.js) and the Excel writer (vendor/zyb-xlsx.js): not needed before the
  // page paints, so they load after it
  try { ['zyb-click.js', 'zyb-xlsx.js'].forEach(function (f) { var el = document.createElement('script'); el.src = 'vendor/' + f + '?v=' + VER; el.async = true; (document.head || document.documentElement).appendChild(el); }); } catch (e) { /* tiles stay as they are */ }
  // Modern | Classic (vendor/zyb-look.js): one switch for the portal pages and every dashboard, set before the page paints
  try { if (!window.zybLook) { document.documentElement.classList.add('zyb-modern');
    if (document.readyState === 'loading') document.write('<script src="vendor/zyb-look.js?v=' + VER + '"><\/script>'); else { var zk = document.createElement('script'); zk.src = 'vendor/zyb-look.js?v=' + VER; (document.head || document.documentElement).appendChild(zk); } } } catch (e) { /* Classic */ }
  // the Tabler look is the base of both (Classic = Tabler as before; Modern restyles on top of it)
  var LANGS = { 'en': 'English', 'ar': 'العربية' };
  // approvers (Roles & Functions): may this person approve infra / security even though they are not an administrator?
  // window.zybApproves(scope) answers from the job role (/api/itam/roles/me), cached for the browser session; pages show
  // their Approve buttons when it is true. The SERVER decides - this only stops hiding a button the server would accept.
  // When the answer arrives after the page drew, 'zyb-approves' is fired so a page can redraw.
  (function () {
    var KEYA = 'zyb-approves', A = null;
    try { A = JSON.parse(sessionStorage.getItem(KEYA) || 'null'); } catch (e) { A = null; }
    // an engineer scope (eng:<id>) is also covered by its group (approvers/scopes.js on the server)
    var GRP = { 'eng:virt': 'infra', 'eng:network': 'infra', 'eng:windows': 'infra', 'eng:exchange': 'infra', 'eng:desktop': 'infra', 'eng:security': 'security', 'eng:soc': 'security', 'eng:ksc': 'security', 'eng:zscaler': 'security', 'eng:dfir': 'security', 'eng:pentest': 'security' };
    window.zybApproves = function (scope) { return !!(A && (A.indexOf(scope) >= 0 || (GRP[scope] && A.indexOf(GRP[scope]) >= 0))); };
    try {
      var x = new XMLHttpRequest(); x.open('GET', '/api/itam/roles/me'); x.withCredentials = true; x.timeout = 15000;
      x.onload = function () {
        var j = null; try { j = JSON.parse(x.responseText); } catch (e) { j = null; }
        var nA = (x.status === 200 && j && j.role && Array.isArray(j.role.approves)) ? j.role.approves.slice() : [];
        var changed = JSON.stringify(nA) !== JSON.stringify(A || []); A = nA;
        try { sessionStorage.setItem(KEYA, JSON.stringify(A)); } catch (e) { /* storage blocked */ }
        if (changed) { try { window.dispatchEvent(new Event('zyb-approves')); } catch (e) { /* old browser */ } }
      };
      x.send();
    } catch (e) { /* no job roles: administrators approve, as before */ }
  })();
  var THEMES = {
    'default': { name: 'Default' },
    'midnight': { name: 'Midnight blue', bg: '#0b1020', panel: '#121a2e', line: '#24304a', text: '#d6deeb', bright: '#ffffff', dim: '#8b97ad' },
    'graphite': { name: 'Graphite', bg: '#111111', panel: '#1b1b1b', line: '#2d2d2d', text: '#dedede', bright: '#ffffff', dim: '#9a9a9a' },
    'forest': { name: 'Forest green', bg: '#06130c', panel: '#0c1f14', line: '#1d3a28', text: '#d7e8dc', bright: '#ffffff', dim: '#8fb39b' },
    'contrast': { name: 'High contrast', bg: '#000000', panel: '#0a0a0a', line: '#5a5a5a', text: '#ffffff', bright: '#ffffff', dim: '#cfcfcf' }
  };
  var FONTS = {
    'default': ['Default', ''],
    'system': ['System', 'system-ui, -apple-system, "Segoe UI", sans-serif'],
    'segoe': ['Segoe UI', '"Segoe UI", Arial, sans-serif'],
    'tahoma': ['Tahoma (good for Arabic)', 'Tahoma, "Segoe UI", Arial, sans-serif'],
    'arial': ['Arial', 'Arial, Helvetica, sans-serif'],
    'georgia': ['Georgia (serif)', 'Georgia, "Times New Roman", serif'],
    'mono': ['Consolas (monospace)', 'Consolas, "Courier New", monospace']
  };
  var SIZES = { 'auto': 'Fit to screen (automatic)', '80': 'Compact', '90': 'Small', '100': 'Normal', '110': 'Large', '125': 'Extra large', '150': 'Huge (wall / TV)' };
  // "Fit to screen" (the default): pages use the full width of a large display and text/controls grow in steps with it, so a
  // 65-inch 4K screen is not a narrow column of small text; on small screens wide tables scroll inside their card. Zoom
  // steps are by viewport width, which html zoom does not change, so the step never flips back and forth.
  var FIT_CSS = '@media(min-width:1700px){html.zyb-fit main[data-zyb-fluid]{max-width:none!important;padding-left:clamp(16px,1.6vw,48px)!important;padding-right:clamp(16px,1.6vw,48px)!important}}'
    // grow only on a wall / TV: very wide AND not already scaled by the operating system. A QHD or 4K desk monitor (Windows at
    // 125-150 %, or 2560 px at 100 %) stays at normal size - the old steps from 2200 px made every page on those far too big.
    + '@media(min-width:3400px) and (max-resolution:1.1dppx){html.zyb-fit{zoom:1.35}}@media(min-width:4600px) and (max-resolution:1.1dppx){html.zyb-fit{zoom:1.9}}'
    + '@media(max-width:900px){html.zyb-fit main .card,html.zyb-fit main section.card{overflow-x:auto}}';
  var ACCENTS = ['#3274D9', '#D7262D', '#1F9D55', '#F2994A', '#9B51E0', '#00A3BF'];

  function load() { try { return JSON.parse(localStorage.getItem(KEY) || '{}') || {}; } catch (e) { return {}; } }
  function save(p) { try { localStorage.setItem(KEY, JSON.stringify(p)); return true; } catch (e) { return false; } }

  /* ---- apply: inline custom properties on <html> beat every :root rule, so it works on all dashboards */
  function apply(p) {
    var r = document.documentElement.style, t = THEMES[p.theme] || THEMES['default'];
    document.documentElement.classList.add('zyb-tb');
    ['--bg', '--canvas', '--ink', '--panel', '--panel-head', '--raise', '--line', '--line-strong', '--edge', '--grid', '--border', '--text', '--text2', '--title', '--text-bright', '--mute', '--text-dim', '--input']
      .forEach(function (v) { r.removeProperty(v); });
    var pt = 'dark'; try { pt = localStorage.getItem('noc_theme') || 'dark'; } catch (e) { pt = 'dark'; }
    if (t.bg && pt !== 'light' && pt !== 'midnight') {   // the portal's Light / Midnight theme wins over a dark colour choice
      [['--bg', t.bg], ['--canvas', t.bg], ['--ink', t.bg], ['--input', t.bg], ['--panel', t.panel], ['--panel-head', t.panel], ['--raise', t.panel],
        ['--line', t.line], ['--line-strong', t.line], ['--edge', t.line], ['--grid', t.line], ['--border', t.line],
        ['--text', t.text], ['--text2', t.text], ['--title', t.bright], ['--text-bright', t.bright], ['--mute', t.dim], ['--text-dim', t.dim]]
        .forEach(function (x) { r.setProperty(x[0], x[1]); });
    }
    ['--accent', '--blue', '--cyan'].forEach(function (v) { r.removeProperty(v); });
    if (p.accent && /^#[0-9a-f]{6}$/i.test(p.accent)) { r.setProperty('--accent', p.accent); r.setProperty('--blue', p.accent); r.setProperty('--cyan', p.accent); }
    var f = FONTS[p.font] && FONTS[p.font][1], st = document.getElementById('zyb-dash-font');
    if (!st) { st = document.createElement('style'); st.id = 'zyb-dash-font'; (document.head || document.documentElement).appendChild(st); }
    var fit = !p.size || p.size === 'auto';
    document.documentElement.classList.toggle('zyb-fit', fit);
    st.textContent = (f ? 'body,body button,body input,body select,body table,body h1,body h2,body h3{font-family:' + f + '!important}' : '')
      + (fit ? FIT_CSS : (p.size !== '100' ? 'html{zoom:' + (Number(p.size) / 100) + '}' : ''));
  }
  var prefs = load(); apply(prefs);
  // pages cap their width (main{max-width:1180-1500px}); only those wide layouts are allowed to fill a big screen -
  // a deliberately narrow page (a form, under 1100 px) keeps its reading width
  function markFluid() {
    try { [].forEach.call(document.querySelectorAll('main'), function (m) { if (m.hasAttribute('data-zyb-fluid')) return; var w = parseFloat(getComputedStyle(m).maxWidth); if (w >= 1100) m.setAttribute('data-zyb-fluid', ''); }); } catch (e) { /* layout as designed */ }
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', markFluid); else markFluid();

  /* ---- app shell: sidebar menu (from vendor/zyb-nav.js), top bar with breadcrumb, Ctrl+K search, Customize.
     Inside an iframe (a dashboard embedded in the portal, which has its own menu) only the compact top bar is drawn. */
  var EMB = false; try { EMB = window.self !== window.top; } catch (e) { EMB = true; }
  /* ONE SCREEN: a dashboard opened on its own (a bookmark, a typed link, a link in a mail) moves into the portal, which shows
     it in its content area beside the portal menu (zyb-menu.js, /?zybdash=). Not when: inside the portal already, a phone-width
     window, a wall display (?display=1), ?standalone=1, or a browser that has never opened the portal with the menu add-on
     (no zyb-portal-nav). If the portal did not take the page within 15 s, the page stays as it is - never a loop. */
  if (!EMB && /^\/dashboards\/[A-Za-z0-9_-]*(\.html)?$/.test(location.pathname)) {
    try {
      var q0 = location.search + location.hash, page0 = (location.pathname.replace(/^\/dashboards\//, '') || 'index.html');
      var portal0 = !!localStorage.getItem('zyb-portal-nav'), last0 = JSON.parse(sessionStorage.getItem('zyb-dash-moved') || 'null');
      if (portal0 && window.innerWidth >= 901 && !/[?&#](standalone|display)=1/.test(q0) && !(last0 && last0.p === page0 && Date.now() - last0.t < 15000)) {
        sessionStorage.setItem('zyb-dash-moved', JSON.stringify({ p: page0, t: Date.now() }));
        window.__zybMoving = true;   // the shell draws nothing more: the page is on its way into the portal
        location.replace('/?zybdash=' + encodeURIComponent(page0 + q0));
      }
    } catch (e) { /* storage blocked: stay standalone */ }
  }
  /* One interface for everyone: the Modern shell (menu, breadcrumb, search). The old Classic style and its switches are
     gone; a browser that still holds the old 'classic' choice is simply moved to Modern. */
  var UI = 'modern';
  try { localStorage.removeItem('zyb-ui'); } catch (e) { /* storage blocked */ }
  // no layout jump: the menu's width and the top bar's height are reserved before the page draws, and released once
  // the real menu and bar are in place (bar())
  try {
    if (document.head) {
      var rail0 = false; try { rail0 = !!(JSON.parse(localStorage.getItem('zyb-side') || '{}') || {}).rail; } catch (e) { rail0 = false; }
      var pre0 = document.createElement('style'); pre0.id = 'zyb-pre';
      pre0.textContent = (EMB ? '' : '@media(min-width:901px){body{padding-left:' + (rail0 ? 68 : 264) + 'px}}') + 'body{padding-top:52px}';
      document.head.appendChild(pre0);
    }
  } catch (e) { /* nothing reserved */ }
  var SKEY = 'zyb-side', ACC = (prefs.accent && /^#[0-9a-f]{6}$/i.test(prefs.accent)) ? prefs.accent : '#D7262D';
  function sload() { try { return JSON.parse(localStorage.getItem(SKEY) || '{}') || {}; } catch (e) { return {}; } }
  function ssave(s) { try { localStorage.setItem(SKEY, JSON.stringify(s)); } catch (e) { /* storage blocked: defaults next time */ } }
  function esc0(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); }
  var ICO = {
    home: '<path d="M3 11 12 4l9 7"/><path d="M5 10v10h14V10"/>', chev: '<path d="m9 6 6 6-6 6"/>', search: '<circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/>',
    back: '<path d="M15 6l-6 6 6 6"/>', menu: '<path d="M4 6h16M4 12h16M4 18h16"/>', rail: '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M9 4v16"/>', gear: '<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z"/>'
  };
  ICO.out = '<path d="M15 4h4v16h-4"/><path d="M10 8l-4 4 4 4"/><path d="M6 12h10"/>';
  /* Sign out: ends the session at the portal's sign-in service, then opens the sign-in page. The routes are tried in turn
     and the result is checked with /auth/whoami, so the page only says "signed out" when the session really ended; a
     sign-in service without any of these routes is told to the person rather than pretending. */
  function signOut(btn) {
    var tries = [['POST', '/auth/logout'], ['POST', '/logout'], ['GET', '/logout'], ['POST', '/auth/signout']];
    var label = btn ? btn.innerHTML : ''; if (btn) { btn.disabled = true; }
    try { sessionStorage.clear(); } catch (e) { /* storage blocked */ }
    // what a page cached about the estate (device inventory, the last live search) does not outlive the session; display
    // preferences (theme, language, font) stay
    try { Object.keys(localStorage).filter(function (k) { return /^(net_|zyb-live|zyb-cache|zyb-q)/.test(k); }).forEach(function (k) { localStorage.removeItem(k); }); } catch (e) { /* storage blocked */ }
    var gone = function () { return fetch('/auth/whoami', { credentials: 'include', cache: 'no-store' }).then(function (r) { return r.status === 401 || r.status === 403; }).catch(function () { return false; }); };
    var step = function (i) {
      if (i >= tries.length) { if (btn) { btn.disabled = false; btn.innerHTML = label; } var t = document.createElement('div'); t.id = 'zyb-out-msg'; t.setAttribute('role', 'alert'); t.textContent = 'Sign out did not end the session: the sign-in service has no sign-out route the dashboards know. Close the browser to end the session, and ask the platform administrator to add one.'; t.style.cssText = 'position:fixed;top:60px;right:16px;max-width:380px;background:#1f242d;color:#ECEEF2;border:1px solid #b45309;border-radius:10px;padding:12px 14px;z-index:10001;font:13px system-ui,sans-serif'; document.body.appendChild(t); setTimeout(function () { t.remove(); }, 12000); return; }
      fetch(tries[i][1], { method: tries[i][0], credentials: 'include', cache: 'no-store', redirect: 'manual' }).catch(function () { return null; })
        .then(gone).then(function (out) { if (out) location.href = '/login'; else step(i + 1); });
    };
    step(0);
  }
  window.zybSignOut = signOut;
  function ic(p, cls) { return '<svg class="' + (cls || 'zi') + '" viewBox="0 0 24 24" aria-hidden="true">' + p + '</svg>'; }
  function navReg() { return window.ZYB_NAV || []; }
  function here() { return (location.pathname.split('/').pop() || 'index.html'); }
  /* the portal's own pages (its groups and views): saved by zyb-menu.js whenever the portal is opened, otherwise read
     from the portal's page itself. A link opens that view in the portal (/?zybview=<view>, handled by zyb-menu.js). */
  var PN = null, PNW = [];
  ICO.grid = '<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/>';
  function portalHref(v) { return '/?zybview=' + encodeURIComponent(v); }
  function portalParse(nav) {
    var out = [], grp = null;
    var txt = function (li) { var c = li.cloneNode(true); [].forEach.call(c.querySelectorAll('.ico,.badge,svg'), function (x) { x.remove(); }); return (li.getAttribute('data-en') || c.textContent).replace(/[▸▾▼►▶▲△▽]/g, '').replace(/\s+/g, ' ').trim(); };
        var gtxt = function (li) { return txt(li).replace(/\s+\d+$/, ''); };   // a group heading may end in its item count; a page name may end in a number
    [].forEach.call(nav.children, function (li) {
      if (li.tagName !== 'LI' || li.getAttribute('data-zyb-menu')) return;
      if (li.classList.contains('nav-group')) { grp = { name: gtxt(li), items: [] }; out.push(grp); return; }
      var v = li.getAttribute('data-view'); if (!v) return;
      if (!grp) { grp = { name: 'Portal', items: [] }; out.push(grp); }
      grp.items.push({ v: v, l: txt(li) });
    });
    return out.filter(function (g) { return g.items.length && g.name; });
  }
  function portalNav(cb) {
    if (PN) { cb(PN); return; }
    PNW.push(cb); if (PNW.length > 1) return;
    var done = function (g) { PN = (g || []).filter(function (x) { return x && x.name && x.items && x.items.length; }).slice(0, 40); var w = PNW; PNW = []; w.forEach(function (f) { try { f(PN); } catch (e) { /* one listener must not stop the others */ } }); };
    try { var j = JSON.parse(localStorage.getItem('zyb-portal-nav') || 'null'); if (j && j.groups && j.groups.length) { done(j.groups); return; } } catch (e) { /* no snapshot */ }
    var x = new XMLHttpRequest(); x.open('GET', '/'); x.timeout = 8000;
    x.onload = function () {
      try {
        var nav = new DOMParser().parseFromString(x.responseText, 'text/html').querySelector('ul.nav'), g = nav ? portalParse(nav) : [];
        if (g.length) { try { localStorage.setItem('zyb-portal-nav', JSON.stringify({ at: Date.now(), groups: g, from: 'page' })); } catch (e) { /* storage blocked */ } }   // read once, not on every page
        done(g);
      } catch (e) { done([]); }
    };
    x.onerror = x.ontimeout = function () { done([]); };
    try { x.send(); } catch (e) { done([]); }
  }
  window.zybPortalNav = function (cb) { portalNav(function (g) { cb(g, portalHref); }); };
  function findPage(h) { var r = null; navReg().forEach(function (a) { a.pages.forEach(function (p) { if (p.h === h) r = { a: a, p: p }; }); }); return r; }

  /* ---- one search engine for the sidebar filter and Ctrl+K. Each word may match in any order: the start of a word in the
     menu label (best), the label, an acronym of the label (cmdb, vapt), the full title, the description / keywords; then a
     synonym of the word (llm -> AI, mfa -> sign-in, cve -> vulnerability); then one typo or two swapped letters. Recently
     opened pages rank first among equals. The index is built once per list; a keystroke only scans it. */
  var SYN = { llm: ['ai engine'], model: ['ai engine'], claude: ['ai engine'], anthropic: ['ai engine'], openai: ['ai engine'], ollama: ['ai engine'], gpt: ['ai engine'], chatgpt: ['ai engine'],
    vuln: ['vulnerab'], vulns: ['vulnerab'], cve: ['vulnerab'], cves: ['vulnerab'], scan: ['scan', 'vapt'], pentest: ['penetration', 'vapt'], pt: ['penetration'],
    mfa: ['sign-in', 'identity'], '2fa': ['sign-in', 'identity'], otp: ['sign-in', 'identity'], sso: ['sign-in', 'identity'], login: ['sign-in', 'identity'], logon: ['sign-in'], users: ['user management', 'identity'], accounts: ['user management', 'identity'],
    ad: ['active directory'], o365: ['microsoft 365', 'm365'], office: ['microsoft 365'], outlook: ['exchange', 'email'], mail: ['email', 'exchange'], fw: ['firewall'], palo: ['palo alto', 'firewall'], forti: ['fortigate', 'firewall'],
    db: ['database'], dba: ['database', 'dba'], oracle: ['oracle', 'database'], sql: ['sql', 'database'], vm: ['virtual'], vms: ['virtual'], esxi: ['vsphere', 'vmware', 'virtual'], hypervisor: ['virtual'],
    siem: ['soc', 'security operations', 'siem'], alerts: ['alert', 'alarm'], incidents: ['incident'], privacy: ['pdpl'], gdpr: ['pdpl'], personal: ['pdpl'], dpo: ['pdpl'], dlp: ['data loss', 'dlp'],
    cert: ['certificate'], certs: ['certificate'], ssl: ['certificate'], tls: ['certificate'], pki: ['certificate'], dr: ['disaster', 'replication', 'dr'], backups: ['backup'], cmdb: ['cmdb', 'configuration'],
    password: ['credential'], passwords: ['credential'], secrets: ['credential', 'secret'], keys: ['credential'], ticket: ['ticket', 'service desk'], tickets: ['ticket', 'service desk'], helpdesk: ['support', 'ticket'],
    kpi: ['dashboard', 'kpi'], report: ['report'], reports: ['report'], licence: ['licen'], license: ['licen'], licenses: ['licen'], compliance: ['compliance', 'grc'], audit: ['audit'], risk: ['risk'],
    settings: ['settings', 'admin', 'configuration'], config: ['configuration', 'settings'], switch: ['switch'], network: ['network'], wifi: ['wireless', 'network access'], nac: ['network access'] };
  function srN(v) { return String(v == null ? '' : v).toLowerCase().replace(/[’']/g, ''); }
  function srW(v) { return srN(v).split(/[^a-z0-9؀-ۿ]+/).filter(Boolean); }
  // one edit (insert / delete / substitute) or two neighbouring letters swapped; words of 4+ letters only
  function srNear(a, b) {
    if (a.length < 4 || b.length < 4 || Math.abs(a.length - b.length) > 1) return false;
    if (a.length === b.length) { var d = []; for (var k = 0; k < a.length; k++) if (a[k] !== b[k]) d.push(k); if (d.length === 1) return true; return d.length === 2 && d[1] === d[0] + 1 && a[d[0]] === b[d[1]] && a[d[1]] === b[d[0]]; }
    var i = 0, j = 0, e = 0; while (i < a.length && j < b.length) { if (a[i] === b[j]) { i++; j++; continue; } if (++e > 1) return false; if (a.length > b.length) i++; else j++; } return true;
  }
  function srPrep(x) {
    var s = srN(x.s), sw = srW(x.s), codes = {};
    Object.keys(x.fw || {}).forEach(function (k) { (x.fw[k] || []).forEach(function (c) { codes[String(c).toLowerCase().replace(/\s+/g, '')] = 1; }); });
    return { x: x, kw: (Array.isArray(x.kl) ? x.kl : []).map(srN), s: s, sw: sw, acr: sw.map(function (w) { return w[0]; }).join(''), t: srN(x.t), tw: srW(x.t).concat(srW(x.k)), k: srN([x.s, x.t, x.d, x.k, x.a && x.a.name, x.fk].join(' ')), codes: codes };
  }
  function srTier(r, q) {
    if (r.sw.some(function (w) { return w.indexOf(q) === 0; })) return 0;
    if (r.s.indexOf(q) >= 0 || (q.length >= 2 && r.acr.indexOf(q) === 0)) return 1;
    if (r.kw.some(function (k) { return k === q || k.indexOf(q + ' ') === 0 || (q.length >= 3 && k.indexOf(q) === 0); })) return 1;   // the page's own keywords
    if (r.t.indexOf(q) >= 0) return 2;
    if (r.k.indexOf(q) >= 0) return 3;
    return -1;
  }
  function srWord(r, q) {
    var p = srTier(r, q); if (p >= 0) return p;
    var best = -1; (SYN[q] || []).forEach(function (alt) { var pa = srTier(r, alt); if (pa >= 0 && (best < 0 || pa + 2 < best)) best = pa + 2; }); if (best >= 0) return best;
    if (q.length >= 4 && r.sw.concat(r.tw).some(function (w) { return srNear(w, q) || (w.length > q.length && srNear(w.slice(0, q.length), q)); })) return 5;
    return -1;
  }
  function srRecent() { try { var m = {}; (JSON.parse(localStorage.getItem('zyb-recent') || '[]') || []).forEach(function (x, i) { if (x && x.h && m[x.h] == null) m[x.h] = i; }); return m; } catch (e) { return {}; /* storage blocked: no recency boost */ } }
  function srRank(idx, v, limit) {
    v = srN(v).trim(); if (!v) return [];
    var w = v.split(/\s+/), code = v.replace(/\s+/g, ''), rec = srRecent();
    return idx.map(function (r) {
      if (code && r.codes[code]) return { r: r, sc: -1 };   // a framework code (3.3.14, 2-12, Art. 20) matches exactly
      var sc = 0; for (var i = 0; i < w.length; i++) { var p = srWord(r, w[i]); if (p < 0) return null; sc += p; }
      if (rec[r.x.h] != null) sc -= 0.6 - Math.min(0.5, rec[r.x.h] * 0.04);
      return { r: r, sc: sc };
    }).filter(Boolean).sort(function (a, b) { return a.sc - b.sc || a.r.s.length - b.r.s.length; }).slice(0, limit || 40).map(function (o) { return o.r.x; });
  }
  window.zybSearch = { prep: srPrep, rank: srRank, near: srNear };

  var cssPolish = ''
    /* polish shared by every page: calm scrollbars, focus rings, numbers that line up, gentle card lift */
    + 'html{-webkit-font-smoothing:antialiased;-moz-osx-font-smoothing:grayscale;scroll-padding-top:64px}'
    + '*{scrollbar-width:thin;scrollbar-color:#343a47 transparent}::-webkit-scrollbar{width:10px;height:10px}::-webkit-scrollbar-thumb{background:#2c313c;border-radius:10px;border:2px solid transparent;background-clip:padding-box}::-webkit-scrollbar-thumb:hover{background-color:#3d4351}'
    + '::selection{background:rgba(121,184,255,.32)}:focus-visible{outline:2px solid ' + ACC + ';outline-offset:2px}'
    + 'td,.n,.v{font-variant-numeric:tabular-nums}main .card{transition:border-color .15s,box-shadow .15s}main .card:hover{box-shadow:0 10px 28px rgba(0,0,0,.22)}';
  var css = ''
    /* top bar */
    + '#zyb-bar{position:sticky;top:0;z-index:50;display:flex;align-items:center;gap:8px;min-height:52px;padding:8px 16px;background:rgba(11,12,16,.82);backdrop-filter:saturate(140%) blur(10px);-webkit-backdrop-filter:saturate(140%) blur(10px);border-bottom:1px solid #20242d;font:500 13px "Segoe UI",system-ui,-apple-system,sans-serif;color:#e6e9ef}'
    + '#zyb-bar .zi{width:16px;height:16px;fill:none;stroke:currentColor;stroke-width:2;stroke-linecap:round;stroke-linejoin:round;flex:0 0 auto}'
    + '#zyb-bar>button,#zyb-bar>a.zb-btn{display:inline-flex;align-items:center;gap:7px;height:34px;white-space:nowrap;flex:0 0 auto;background:#14171e;border:1px solid #272b35;color:#dfe3ea;border-radius:9px;padding:0 11px;font:600 12.5px "Segoe UI",system-ui,sans-serif;text-decoration:none;cursor:pointer;transition:border-color .15s,background .15s}'
    + '#zyb-bar>button:hover,#zyb-bar>a.zb-btn:hover{border-color:#454b59;background:#181c24}#zyb-bar .zb-ico{width:34px;padding:0;justify-content:center}#zyb-bar .sp{flex:1}'
    + '#zyb-menu-btn{display:none!important}'
    + '.zb-crumb{display:flex;align-items:center;gap:6px;min-width:0;color:#8C93A1;font-size:13px;margin-left:4px}.zb-crumb a{color:#8C93A1;text-decoration:none}.zb-crumb a:hover{color:#fff}'
    + '.zb-fw{display:inline-flex;flex:0 0 auto;gap:4px;margin-left:8px;text-decoration:none!important;min-width:0;overflow:hidden}.zb-fw i{--c:#8C93A1;font:600 10.5px ui-monospace,Consolas,monospace;font-style:normal;color:color-mix(in srgb,var(--c) 85%,#fff);background:color-mix(in srgb,var(--c) 12%,transparent);border:1px solid color-mix(in srgb,var(--c) 32%,transparent);border-radius:5px;padding:1px 5px;white-space:nowrap}.zb-fw:hover i{border-color:var(--c)}'
    + '.zb-crumb .zi{width:13px!important;height:13px!important;opacity:.6}.zb-crumb b{color:#fff;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.zb-crumb .zb-dot{width:8px;height:8px;border-radius:50%;flex:0 0 auto}'
    + '#zyb-find-btn{min-width:230px;justify-content:flex-start!important;color:#8C93A1!important}#zyb-find-btn kbd{margin-left:auto;font:600 10.5px ui-monospace,Consolas,monospace;color:#8C93A1;border:1px solid #2c313c;border-bottom-width:2px;border-radius:5px;padding:1px 6px;background:#0f1116}'
    + '@media(max-width:1100px){#zyb-find-btn{min-width:0}.zb-fw{display:none!important}#zyb-find-btn span,#zyb-find-btn kbd{display:none}}@media(max-width:640px){.zb-crumb .zb-mid{display:none}#zyb-cz-btn span,#zyb-out span{display:none}}'
    /* sidebar */
    + 'body.zyb-has-side{padding-left:264px;transition:padding-left .18s ease}body.zyb-has-side.zyb-rail{padding-left:68px}'
    + '#zyb-side{position:fixed;left:0;top:0;bottom:0;width:264px;z-index:60;display:flex;flex-direction:column;background:linear-gradient(180deg,#0e1016,#0b0c10);border-right:1px solid #1e222b;font:500 13px "Segoe UI",system-ui,-apple-system,sans-serif;color:#c9ced8;transition:width .18s ease,transform .2s ease}'
    + '#zyb-side .zi{width:17px;height:17px;fill:none;stroke:currentColor;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round;flex:0 0 auto}'
    + '.zs-brand{display:flex;align-items:center;gap:10px;padding:14px 12px 12px 14px;border-bottom:1px solid #1a1d25}'
    + '.zs-logo{display:flex;align-items:center;gap:11px;min-width:0;flex:1;text-decoration:none;color:#fff}.zs-mark{width:36px;height:36px;border-radius:10px;display:grid;place-items:center;background:#161921;border:1px solid #262a34;flex:0 0 auto}.zs-mark img{width:24px;height:auto}'
    + '.zs-logo b{display:block;font-size:14px;letter-spacing:.01em;white-space:nowrap}.zs-logo small{display:block;font:600 9.5px ui-monospace,Consolas,monospace;letter-spacing:.1em;text-transform:uppercase;color:' + ACC + ';white-space:normal;line-height:1.35;margin-top:2px}'
    + '.zs-pin{width:30px;height:30px;border-radius:8px;border:1px solid transparent;background:none;color:#7d8493;cursor:pointer;display:grid;place-items:center;flex:0 0 auto}.zs-pin:hover{background:#161921;border-color:#262a34;color:#fff}'
    + '.zs-find{position:relative;margin:12px 12px 6px}.zs-find .zi{position:absolute;left:10px;top:50%;transform:translateY(-50%);width:15px!important;height:15px!important;color:#6f7685}'
    + '.zs-find input{width:100%;box-sizing:border-box;height:34px;padding:0 10px 0 32px;border-radius:9px;border:1px solid #23272f;background:#0b0d12;color:#e6e9ef;font:13px "Segoe UI",system-ui,sans-serif;outline:none}.zs-find input:focus{border-color:#3a404d}'
    + '.zs-nav{flex:1;overflow-y:auto;padding:6px 8px 16px}'
    + '.zs-lbl{font:600 10px ui-monospace,Consolas,monospace;letter-spacing:.14em;text-transform:uppercase;color:#5f6675;padding:14px 10px 6px}'
    + '.zs-home,.zs-ah,.zs-it{display:flex;align-items:center;gap:10px;width:100%;box-sizing:border-box;border:0;background:none;color:inherit;text-decoration:none;font:inherit;text-align:left;cursor:pointer;border-radius:8px}'
    + '.zs-home{padding:8px 10px;color:#dfe3ea}.zs-home:hover,.zs-ah:hover{background:#151821;color:#fff}.zs-home.on{background:#171a23;color:#fff}'
    + '#zyb-side ul,#zyb-side li{list-style:none!important}#zyb-side li::marker{content:none!important}.zs-area{margin-top:2px}.zs-ah{padding:8px 10px;color:#c9ced8}.zs-ic{width:26px;height:26px;border-radius:7px;display:grid;place-items:center;flex:0 0 auto;background:color-mix(in srgb,var(--c) 14%,transparent);color:var(--c)}.zs-ic .zi{width:15px!important;height:15px!important}'
    + '.zs-an{flex:1;min-width:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;font-weight:600}.zs-n{font-style:normal;font-size:11px;color:#6b7280;background:#13161d;border:1px solid #20242c;border-radius:999px;padding:0 7px}'
    + '.zs-ch{width:14px!important;height:14px!important;color:#5f6675;transition:transform .15s}.zs-area.open .zs-ch{transform:rotate(90deg)}'
    + '.zs-sg{display:flex;align-items:center;gap:7px;width:100%;border:0;background:transparent;font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:#8b93a3;padding:8px 8px 3px;cursor:pointer;text-align:left}.zs-sgw:first-child .zs-sg{padding-top:2px}'
    + '.zs-sg:hover{color:#c9d1dc}.zs-sgi{display:inline-flex;align-items:center;justify-content:center;width:18px;height:18px;border-radius:5px;background:color-mix(in srgb,var(--sc) 18%,transparent);flex:none}.zs-sgi .zs-sgv{width:12px;height:12px;stroke:var(--sc);fill:none;stroke-width:2;stroke-linecap:round;stroke-linejoin:round}'
    + '.zs-sgt{flex:1}.zs-sg .zs-sgc{width:12px;height:12px;stroke:currentColor;fill:none;stroke-width:2;transition:transform .15s;transform:rotate(90deg)}.zs-sgw.shut .zs-sgc{transform:rotate(0)}.zs-sgw.shut .zs-sgb{display:none}#zyb-side.zs-q-on .zs-sgw.shut .zs-sgb{display:block}'
    + '.zs-items{display:none;position:relative;margin:2px 0 6px 22px;padding-left:12px;border-left:1px solid #1f232c}.zs-area.open .zs-items{display:block}'
    + '.zs-it{position:relative;padding:6px 10px;color:#9aa1ae;font-size:12.8px;line-height:1.35}.zs-it:hover{color:#fff;background:#141720}'
    + '.zs-it.on{color:#fff;background:color-mix(in srgb,' + ACC + ' 14%,#12141a);font-weight:600}.zs-it.on::before{content:"";position:absolute;left:-13px;top:6px;bottom:6px;width:2px;border-radius:2px;background:' + ACC + '}'
    + '.zs-it mark{background:rgba(227,179,65,.3);color:inherit;border-radius:3px}.zs-empty{color:#6b7280;padding:14px 10px;font-size:12.5px}'
    + '.zs-best{margin:0 12px 8px;border:1px solid #23272f;border-radius:10px;background:#0b0d12;padding:4px}.zs-bh{display:flex;justify-content:space-between;font-size:10.5px;color:#6f7685;padding:4px 8px;text-transform:uppercase;letter-spacing:.4px}.zs-best a{display:block;padding:6px 8px;border-radius:7px;color:#e6e9ef;text-decoration:none}.zs-best a b{display:block;font-weight:600;font-size:13px}.zs-best a small{display:block;color:#7c8394;font-size:11px}.zs-best a.on,.zs-best a:hover{background:#1a1f29}body.zyb-rail .zs-best{display:none!important}'
    + '.zs-brandsw[hidden]{display:none!important}.zs-brandsw{flex:1 1 100%;display:flex;align-items:center;gap:9px;height:32px;padding:0 10px;border-radius:8px;border:1px solid #23272f;background:transparent;color:#aab1bd;font:500 12.5px inherit;font-family:inherit;cursor:pointer}.zs-brandsw:hover{color:#fff}'
    + '.zs-brandsw i{position:relative;width:26px;height:14px;border-radius:999px;background:#2a2e35;flex:0 0 auto}.zs-brandsw i:after{content:"";position:absolute;top:2px;left:2px;width:10px;height:10px;border-radius:50%;background:#fff;transition:left .15s}'
    + '.zs-brandsw[aria-checked=true] i{background:#1E7A44}.zs-brandsw[aria-checked=true] i:after{left:14px}.zs-brandsw:focus-visible{outline:2px solid #4CB37A;outline-offset:2px}body.zyb-rail .zs-brandsw span{display:none!important}'
    + '.zs-foot{border-top:1px solid #1a1d25;padding:10px 12px;display:flex;flex-wrap:wrap;gap:8px}.zs-foot a{flex:1;display:flex;align-items:center;justify-content:center;gap:7px;height:32px;border-radius:8px;border:1px solid #23272f;color:#aab1bd;text-decoration:none;font-size:12.5px}.zs-foot a:hover{color:#fff;border-color:#3a404d}'
    /* collapsed icon rail */
    + 'body.zyb-rail #zyb-side{width:68px}body.zyb-rail .zs-logo span,body.zyb-rail .zs-find,body.zyb-rail .zs-an,body.zyb-rail .zs-n,body.zyb-rail .zs-ch,body.zyb-rail .zs-items,body.zyb-rail .zs-lbl,body.zyb-rail .zs-home span,body.zyb-rail .zs-foot span{display:none!important}'
    + 'body.zyb-rail .zs-brand{flex-direction:column;padding:12px 8px}body.zyb-rail .zs-ah,body.zyb-rail .zs-home{justify-content:center;padding:8px 0}body.zyb-rail .zs-pin .zi{transform:scaleX(-1)}'
    /* phones / narrow windows: the menu becomes a drawer */
    + '#zyb-scrim{position:fixed;inset:0;background:rgba(0,0,0,.5);z-index:59;display:none}'
    + '@media(max-width:900px){body.zyb-has-side,body.zyb-has-side.zyb-rail{padding-left:0}#zyb-side{transform:translateX(-100%);width:280px!important;box-shadow:20px 0 50px rgba(0,0,0,.5)}'
    + 'body.zyb-side-open #zyb-side{transform:none}body.zyb-side-open #zyb-scrim{display:block}#zyb-menu-btn{display:inline-flex!important}.zs-pin{display:none!important}'
    + 'body.zyb-rail .zs-logo span,body.zyb-rail .zs-find,body.zyb-rail .zs-an,body.zyb-rail .zs-n,body.zyb-rail .zs-ch,body.zyb-rail .zs-lbl,body.zyb-rail .zs-home span,body.zyb-rail .zs-foot span{display:revert!important}body.zyb-rail .zs-area.open .zs-items{display:block!important}}'
    /* Ctrl+K palette */
    + '#zyb-pal{position:fixed;inset:0;z-index:90;display:flex;align-items:flex-start;justify-content:center;padding:12vh 16px 16px;background:rgba(5,6,9,.6);-webkit-backdrop-filter:blur(3px);backdrop-filter:blur(3px)}#zyb-pal[hidden]{display:none}'
    + '#zyb-pal .zp{width:min(640px,100%);background:#11131a;border:1px solid #2a2f3a;border-radius:14px;box-shadow:0 30px 80px rgba(0,0,0,.6);overflow:hidden;font:13.5px "Segoe UI",system-ui,sans-serif;color:#e6e9ef}'
    + '#zyb-pal .zp-in{display:flex;align-items:center;gap:10px;padding:0 14px;border-bottom:1px solid #20242d}#zyb-pal .zp-in .zi{width:18px;height:18px;fill:none;stroke:#7d8493;stroke-width:2}'
    + '#zyb-pal input{flex:1;height:52px;border:0;background:none;color:#fff;font:16px "Segoe UI",system-ui,sans-serif;outline:none}#zyb-pal kbd{font:600 10.5px ui-monospace,Consolas,monospace;color:#8C93A1;border:1px solid #2c313c;border-radius:5px;padding:1px 6px}'
    + '#zyb-pal ul{list-style:none;margin:0;padding:6px;max-height:min(420px,56vh);overflow-y:auto}#zyb-pal li{display:flex;align-items:center;gap:11px;padding:9px 10px;border-radius:9px;cursor:pointer}'
    + '#zyb-pal li.on{background:#1a1e28}#zyb-pal li .zs-ic{width:28px;height:28px}#zyb-pal li b{display:block;font-weight:600;color:#fff}#zyb-pal li small{display:block;color:#8C93A1;font-size:12px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:480px}'
    + '#zyb-pal li em{margin-left:auto;font-style:normal;font-size:11px;color:#6b7280;white-space:nowrap}#zyb-pal .zp-none{padding:22px;text-align:center;color:#8C93A1}#zyb-pal .zp-ft{display:flex;gap:14px;padding:8px 14px;border-top:1px solid #20242d;color:#6b7280;font-size:11.5px}'
    /* Customize panel */
    + '#zyb-cz{position:absolute;right:14px;top:calc(100% + 6px);width:min(340px,calc(100vw - 28px));background:#12141a;border:1px solid #2a2e38;border-radius:12px;padding:14px;box-shadow:0 20px 50px rgba(0,0,0,.55);display:grid;gap:12px;z-index:70}'
    + '#zyb-cz[hidden]{display:none}#zyb-cz h4{margin:0;font:600 14px system-ui,sans-serif;color:#fff}#zyb-cz label{display:grid;gap:5px;font:500 12px system-ui,sans-serif;color:#aab1bf}'
    + '#zyb-cz select{background:#0b0c10;color:#e6e9ef;border:1px solid #2a2e38;border-radius:7px;padding:7px 8px;font:500 13px system-ui,sans-serif}'
    + '#zyb-cz .sw{display:flex;gap:7px;flex-wrap:wrap;align-items:center}#zyb-cz .sw button{width:26px;height:26px;border-radius:50%;border:2px solid transparent;padding:0;cursor:pointer}#zyb-cz .sw button[aria-pressed="true"]{border-color:#fff}'
    + '#zyb-cz input[type=color]{width:34px;height:28px;border:1px solid #2a2e38;border-radius:7px;background:#0b0c10;padding:2px;cursor:pointer}'
    + '#zyb-cz .act{display:flex;gap:8px;justify-content:flex-end}#zyb-cz .act button{background:#161920;border:1px solid #2a2e38;color:#e6e9ef;border-radius:7px;padding:7px 12px;font:600 12.5px system-ui,sans-serif;cursor:pointer}#zyb-cz .act .pri{background:#D7262D;border-color:#D7262D}'
    + '#zyb-cz .note{font:400 11.5px system-ui,sans-serif;color:#8a91a0;margin:0}'
    /* other fixed widgets: the display controls move right of the menu; a wall display (kiosk) gets the full width */
    + 'body.zyb-has-side #zdp,body.zyb-has-side #zdp-pop{left:278px}body.zyb-has-side.zyb-rail #zdp,body.zyb-has-side.zyb-rail #zdp-pop{left:80px}'
    + '@media(max-width:900px){body.zyb-has-side #zdp,body.zyb-has-side #zdp-pop{left:12px}}body.zyb-side-open #zdp,body.zyb-side-open #zdp-pop{display:none!important}body.zdp-kiosk.zyb-has-side{padding-left:0!important}body.zdp-kiosk #zyb-scrim{display:none!important}'
    + '@media(prefers-reduced-motion:reduce){#zyb-side,body.zyb-has-side,.zs-ch{transition:none}}';

  var cssClassic = 'body.zyb-classic #zyb-bar{position:relative;display:flex;align-items:center;gap:8px;flex-wrap:wrap;min-height:0;padding:8px 14px;background:#0b0c10;backdrop-filter:none;-webkit-backdrop-filter:none;border-bottom:1px solid #23262e;font:500 13px system-ui,-apple-system,"Segoe UI",sans-serif;color:#e6e9ef;z-index:40}'
    + 'body.zyb-classic #zyb-bar>button,body.zyb-classic #zyb-bar>a.zb-btn{display:inline-flex;align-items:center;gap:6px;height:auto;width:auto;background:#161920;border:1px solid #2a2e38;color:#e6e9ef;border-radius:7px;padding:6px 11px;font:600 12.5px system-ui,-apple-system,"Segoe UI",sans-serif;text-decoration:none;cursor:pointer}'
    + 'body.zyb-classic #zyb-bar>button:hover,body.zyb-classic #zyb-bar>a.zb-btn:hover{border-color:#4a5060;background:#161920}body.zyb-classic #zyb-bar>button:focus-visible,body.zyb-classic #zyb-bar>a.zb-btn:focus-visible{outline:2px solid #fff;outline-offset:1px}';
  function opt(map, sel, label) { return Object.keys(map).map(function (k) { var n = label ? label(map[k]) : map[k]; return '<option value="' + k + '"' + (k === sel ? ' selected' : '') + '>' + n + '</option>'; }).join(''); }
  function back() {
    var ref = document.referrer, same = false;
    try { same = ref && new URL(ref).origin === location.origin && new URL(ref).pathname !== location.pathname; } catch (e) { same = false; }
    if (same && history.length > 1) history.back(); else location.href = './';
  }
  /* recently opened pages: a per-browser convenience for the home page */
  function remember() {
    var h = here(); if (!findPage(h)) return;
    try { var r = JSON.parse(localStorage.getItem('zyb-recent') || '[]') || []; r = r.filter(function (x) { return x && x.h !== h; }); r.unshift({ h: h, at: Date.now() }); localStorage.setItem('zyb-recent', JSON.stringify(r.slice(0, 12))); } catch (e) { /* storage blocked */ }
  }

  /* ---- sidebar */
  function side() {
    if (window.__zybMoving) return;
    var reg = navReg(); if (EMB || !reg.length || document.getElementById('zyb-side')) return;
    var st = sload(), cur = here(), me = findPage(cur), open = st.open || {};
    if (me && open[me.a.id] === undefined) open[me.a.id] = true;    // the area of this page starts open
    var logo = window.__zybLogo ? '<img src="' + window.__zybLogo + '" alt="">' : '';
    // the pages of a workspace, under their sub-menu headings: each heading has a coloured icon and opens / hides its pages
    // (remembered per heading; the heading holding the current page always opens)
    var sgShut = st.sgshut || {};
    function sgItems(a, pages) {
      var out = '', open1 = false;
      pages.forEach(function (p, j) {
        var on = p.h === cur, first = j === 0 || pages[j - 1].g !== p.g;
        if (first && p.g) {
          if (open1) out += '</div></div>';
          var k = a.id + '|' + p.g, mine = pages.some(function (x) { return x.g === p.g && x.h === cur; }), shut = !!sgShut[k] && !mine, sy = window.zybSgStyle ? window.zybSgStyle(p.g) : { c: '#6b7280', icon: '' };
          out += '<div class="zs-sgw' + (shut ? ' shut' : '') + '" data-sg="' + esc0(k) + '" style="--sc:' + esc0(sy.c) + '"><button type="button" class="zs-sg" aria-expanded="' + (!shut) + '" title="' + esc0(p.g) + ' - open / hide"><span class="zs-sgi">' + ic(sy.icon, 'zs-sgv') + '</span><span class="zs-sgt">' + esc0(p.g) + '</span>' + ic(ICO.chev, 'zs-sgc') + '</button><div class="zs-sgb">';
          open1 = true;
        } else if (first && !p.g && open1) { out += '</div></div>'; open1 = false; }
        out += '<a class="zs-it' + (on ? ' on' : '') + '" href="' + esc0(p.h) + '" title="' + esc0(p.t + (window.zybFwTags && window.zybFwTags(p.fw).length ? '\n' + fwTip(window.zybFwTags(p.fw)) : '')) + '"' + (on ? ' aria-current="page"' : '') + '>' + esc0(p.s) + '</a>';
      });
      return out + (open1 ? '</div></div>' : '');
    }
    var h = ('<div class="zs-brand"><a class="zs-logo" href="./" title="Zyberon Sentra — IT Operations &amp; Cyber Security Automation &amp; Monitoring Platform — ' + ZYB_ORG.short + ' — home"><span class="zs-mark">') + logo + ('</span><span><b>Zyberon Sentra</b><small>' + ZYB_ORG.name + '</small></span></a>')
      + '<button type="button" class="zs-pin" id="zs-pin" title="Collapse menu" aria-label="Collapse menu">' + ic(ICO.rail) + '</button></div>'
      // the organisation's own logo on a card under the platform name - shown only with its colours on (vendor/zyb-color.css)
      + (ZYB_ORG.logo && /^data:image\/(png|webp|jpeg|svg\+xml);base64,/.test(ZYB_ORG.logo) ? '<a class="zs-orgcard" hidden href="./" aria-label="' + esc0(ZYB_ORG.name) + ' - home"><img src="' + ZYB_ORG.logo + '" alt="' + esc0(ZYB_ORG.name) + '" style="max-height:44px;max-width:100%;height:auto;width:auto"></a>' : '')
      + '<div class="zs-find">' + ic(ICO.search) + '<input id="zs-q" type="search" placeholder="Filter menu…" aria-label="Filter menu" autocomplete="off"></div>'
      + '<nav class="zs-nav" id="zs-nav" aria-label="Dashboards"><a class="zs-home' + (cur === 'index.html' ? ' on' : '') + '" href="./" title="Home"' + (cur === 'index.html' ? ' aria-current="page"' : '') + '>' + ic(ICO.home) + '<span>Home</span></a>'
      // start here: the pages flagged start:true in the registry (zyb-nav.js), shown once - not again inside their workspace
      + '<div class="zs-lbl">Start here</div>' + [].concat.apply([], reg.map(function (a) { return a.pages.filter(function (p) { return p.start; }); })).map(function (p) { return [p.h, p.s, { 'my-work.html': ICO.home, 'connections.html': ICO.gear }[p.h] || ICO.grid]; }).map(function (x) {
        return '<a class="zs-home' + (cur === x[0] ? ' on' : '') + '" href="' + x[0] + '" title="' + esc0(x[1]) + '"' + (cur === x[0] ? ' aria-current="page"' : '') + '>' + ic(x[2]) + '<span>' + esc0(x[1]) + '</span></a>'; }).join('')
      + reg.map(function (a, i) {
        // the five headings (zyb-nav.js ZYB_HEADS), each drawn before its first workspace
        var hd = a.hd && (i === 0 || reg[i - 1].hd !== a.hd) ? ((window.ZYB_HEADS || []).filter(function (x) { return x[0] === a.hd; })[0] || [])[1] : (i === 0 ? 'Workspaces' : '');
        var pages = a.pages.filter(function (p) { return !p.start; });
        return (hd ? '<div class="zs-lbl">' + esc0(hd) + '</div>' : '') + '<div class="zs-area' + (open[a.id] ? ' open' : '') + '" data-a="' + esc0(a.id) + '" style="--c:' + esc0(a.c) + '">'
          + '<button type="button" class="zs-ah" aria-expanded="' + (!!open[a.id]) + '" title="' + esc0(a.name) + '"><span class="zs-ic">' + ic(a.icon) + '</span><span class="zs-an">' + esc0(a.sn || a.name) + '</span><i class="zs-n">' + pages.length + '</i>' + ic(ICO.chev, 'zi zs-ch') + '</button>'
          + '<div class="zs-items">' + sgItems(a, pages) + '</div></div>';
      }).join('') + '<div class="zs-empty" id="zs-empty" hidden>No page matches.</div></nav>'
      + '<div class="zs-foot"><button type="button" class="zs-brandsw" data-zyb-brandsw role="switch" aria-checked="' + (!!(window.zybBrandOn && window.zybBrandOn())) + ('" title="Brand colours: Zyberon Sentra or ' + ZYB_ORG.short + '"><i></i><span>' + ZYB_ORG.short + ' colours</span></button>') + '<button type="button" class="zs-brandsw" data-zyb-looksw role="switch" aria-checked="' + (!!(window.zybBrandLookIs && window.zybBrandLookIs() === 'light')) + '" title="Company look: dark, or light like the company website"' + (window.zybBrandOn && window.zybBrandOn() ? '' : ' hidden') + '><i></i><span>Light look</span></button>'
      + '<button type="button" class="zs-brandsw" data-zyb-pocsw role="switch" aria-checked="' + !!window.zybPoc + '" title="POC data: illustrative data with a POC ribbon for presentations - nothing can be changed while it is on"><i></i><span>POC data</span></button>'
      + '<a href="/?zybportal=1" title="Portal home">' + ic(ICO.back) + '<span>Portal home</span></a></div>';
    var el = document.createElement('aside'); el.id = 'zyb-side'; el.setAttribute('aria-label', 'Dashboards menu'); el.innerHTML = h;
    var bsw = el.querySelector('[data-zyb-brandsw]'); if (bsw) bsw.addEventListener('click', function () { if (window.zybBrand) window.zybBrand(!window.zybBrandOn()); });
    var psw = el.querySelector('[data-zyb-pocsw]'); if (psw) psw.addEventListener('click', function () { try { if (window.zybPoc) localStorage.removeItem('zyb-poc'); else localStorage.setItem('zyb-poc', '1'); } catch (e) { /* storage blocked: nothing to switch */ } location.href = location.href.replace(/([?&])poc=1(&|$)/, '$1').replace(/[?&]$/, ''); });
    var lsw = el.querySelector('[data-zyb-looksw]'); if (lsw) lsw.addEventListener('click', function () { if (window.zybBrandLook) window.zybBrandLook(window.zybBrandLookIs() === 'light' ? 'dark' : 'light'); });
    var scrim = document.createElement('div'); scrim.id = 'zyb-scrim';
    document.body.insertBefore(scrim, document.body.firstChild); document.body.insertBefore(el, document.body.firstChild);
    document.body.classList.add('zyb-has-side'); if (st.rail) document.body.classList.add('zyb-rail');
    var on = el.querySelector('.zs-it.on'); if (on) { try { on.scrollIntoView({ block: 'center' }); } catch (e) { /* old browser */ } }
    portalNav(function (groups) {
      if (!groups.length || el.querySelector('.zs-portal')) return;
      // the portal's own "AI & Automation" pages join our AI & Automation workspace: one place, not two
      var aiBox = el.querySelector('.zs-area[data-a="ai"] .zs-items');
      if (aiBox) groups = groups.filter(function (g) {
        if (!/^ai\s*(&|and)\s*automation$/i.test(g.name)) return true;
        aiBox.insertAdjacentHTML('beforeend', g.items.map(function (it) { return '<a class="zs-it" href="' + esc0(portalHref(it.v)) + '" title="' + esc0(it.l + ' — opens in the portal') + '">' + esc0(it.l) + ' <span style="opacity:.55;font-size:10.5px">portal</span></a>'; }).join(''));
        var n = el.querySelector('.zs-area[data-a="ai"] .zs-n'); if (n) n.textContent = aiBox.querySelectorAll('.zs-it').length;
        return false;
      });
      if (!groups.length) return;
      var html = '<div class="zs-lbl zs-portal">Portal</div>' + groups.map(function (g, i) {
        var id = 'p' + i, op = !!open[id];
        return '<div class="zs-area' + (op ? ' open' : '') + '" data-a="' + id + '" style="--c:#8C93A1"><button type="button" class="zs-ah" aria-expanded="' + op + '" title="' + esc0(g.name) + '"><span class="zs-ic">' + ic(ICO.grid) + '</span><span class="zs-an">' + esc0(g.name) + '</span><i class="zs-n">' + g.items.length + '</i>' + ic(ICO.chev, 'zi zs-ch') + '</button>'
          + '<div class="zs-items">' + g.items.map(function (it) { return '<a class="zs-it" href="' + esc0(portalHref(it.v)) + '" title="' + esc0(it.l + ' — opens in the portal') + '">' + esc0(it.l) + '</a>'; }).join('') + '</div></div>';
      }).join('');
      document.getElementById('zs-empty').insertAdjacentHTML('beforebegin', html);
    });
    el.addEventListener('click', function (e) {
      var sgb = e.target.closest('.zs-sg');
      if (sgb) { var w = sgb.parentNode, k = w.getAttribute('data-sg'), shut = !w.classList.contains('shut'); w.classList.toggle('shut', shut); sgb.setAttribute('aria-expanded', String(!shut)); if (shut) sgShut[k] = true; else delete sgShut[k]; st.sgshut = sgShut; ssave(st); return; }
      var ah = e.target.closest('.zs-ah'); if (!ah) return;
      var ar = ah.parentNode, id = ar.getAttribute('data-a');
      if (document.body.classList.contains('zyb-rail') && window.innerWidth > 900) { document.body.classList.remove('zyb-rail'); st.rail = false; ar.classList.add('open'); open[id] = true; }
      else { var o = !ar.classList.contains('open'); ar.classList.toggle('open', o); open[id] = o; }
      ah.setAttribute('aria-expanded', String(ar.classList.contains('open'))); st.open = open; ssave(st);
    });
    document.getElementById('zs-pin').onclick = function () { var r = !document.body.classList.contains('zyb-rail'); document.body.classList.toggle('zyb-rail', r); st.rail = r; ssave(st); };
    scrim.onclick = function () { document.body.classList.remove('zyb-side-open'); };
    var q = document.getElementById('zs-q'), best = document.createElement('div'), SI = null, SN = -1, bsel = 0, bres = [], raf = 0;
    best.className = 'zs-best'; best.id = 'zs-best'; best.hidden = true; best.setAttribute('role', 'listbox'); best.setAttribute('aria-label', 'Best matches');
    q.parentNode.insertAdjacentElement('afterend', best);
    // the sidebar's own links (registry pages, sub-menus, portal pages added later), indexed once - rebuilt only when links are added
    var sideIndex = function () {
      var its = el.querySelectorAll('.zs-it'); if (SI && its.length === SN) return SI; SN = its.length;
      SI = [].map.call(its, function (it) { var h = it.getAttribute('href'), f = findPage(h), ar = it.closest('.zs-area'), an = ar ? (ar.querySelector('.zs-an') || {}).textContent : '';
        if (!it.getAttribute('data-l')) it.setAttribute('data-l', it.textContent);
        var r = srPrep({ h: h, s: it.getAttribute('data-l'), t: f ? f.p.t : (it.getAttribute('title') || ''), d: f ? f.p.d : '', k: f && f.p.k ? f.p.k.join(' ') : '', kl: f && f.p.k ? f.p.k : [], fw: f ? f.p.fw : null, fk: f ? fwKey(f.p.fw) : '', a: { name: an } }); r.el = it; return r; });
      return SI;
    };
    var hl = function (it, v) { var s0 = it.getAttribute('data-l') || it.textContent, w = srN(v).split(/\s+/).filter(function (x) { return x.length > 1; }), sl = s0.toLowerCase(), i = -1, n = 0;
      w.forEach(function (x) { var j = sl.indexOf(x); if (j >= 0 && (i < 0 || x.length > n)) { i = j; n = x.length; } });
      it.innerHTML = i < 0 ? esc0(s0) : esc0(s0.slice(0, i)) + '<mark>' + esc0(s0.slice(i, i + n)) + '</mark>' + esc0(s0.slice(i + n)); };
    var bmark = function () { [].forEach.call(best.querySelectorAll('a'), function (x, i) { x.classList.toggle('on', i === bsel); x.setAttribute('aria-selected', String(i === bsel)); }); };
    var run = function () {
      raf = 0; var v = q.value.trim(), idx = sideIndex(), any = false;
      el.classList.toggle('zs-q-on', !!v);   // while filtering, every heading's pages show
      var hits = v ? srRank(idx, v, 1000) : null, set = {};
      if (hits) hits.forEach(function (x) { set[x.h + '|' + x.s] = 1; });
      idx.forEach(function (r) { var hit = !hits || !!set[r.x.h + '|' + r.x.s]; r.el.hidden = !hit; if (v) hl(r.el, v); else r.el.textContent = r.el.getAttribute('data-l'); });
      [].forEach.call(el.querySelectorAll('.zs-area'), function (ar) {
        var n = ar.querySelectorAll('.zs-it:not([hidden])').length;
        [].forEach.call(ar.querySelectorAll('.zs-sg'), function (g) { g.hidden = !!v; });   // sub-menu headings only when not searching
        ar.hidden = !!v && !n; if (v && n) ar.classList.add('open'); else if (!v) ar.classList.toggle('open', !!open[ar.getAttribute('data-a')]);
        if (n) any = true;
      });
      // best matches, ranked, at the top: arrow keys move, Enter opens the highlighted one
      var seen = {}; bres = (hits || []).filter(function (x) { if (seen[x.h]) return false; seen[x.h] = 1; return true; }).slice(0, 6); bsel = 0;
      best.hidden = !bres.length;
      best.innerHTML = bres.length ? '<div class="zs-bh">Best matches <span>↑↓ Enter</span></div>' + bres.map(function (x, i) { return '<a role="option" href="' + esc0(x.h) + '"' + (i === 0 ? ' class="on" aria-selected="true"' : '') + '><b>' + esc0(x.s) + '</b><small>' + esc0(x.a.name || '') + '</small></a>'; }).join('') : '';
      document.getElementById('zs-empty').hidden = any || !v;
      document.getElementById('zs-empty').textContent = 'No page matches “' + v + '” - try fewer words, or Ctrl+K to search descriptions.';
    };
    q.addEventListener('input', function () { if (!raf) raf = (window.requestAnimationFrame || setTimeout)(run); });
    q.addEventListener('keydown', function (e) {
      if (e.key === 'Escape') { q.value = ''; run(); }
      else if (e.key === 'ArrowDown' && bres.length) { e.preventDefault(); bsel = Math.min(bsel + 1, bres.length - 1); bmark(); }
      else if (e.key === 'ArrowUp' && bres.length) { e.preventDefault(); bsel = Math.max(bsel - 1, 0); bmark(); }
      else if (e.key === 'Enter') { if (raf) run(); var x = bres[bsel]; if (x && q.value.trim()) { if (e.ctrlKey || e.metaKey) window.open(x.h, '_blank'); else location.href = x.h; } }
    });
  }

  /* ---- Ctrl+K: jump to any dashboard */
  var pal = null;
  function palette() {
    if (!pal) {
      pal = document.createElement('div'); pal.id = 'zyb-pal'; pal.hidden = true;
      pal.innerHTML = '<div class="zp" role="dialog" aria-modal="true" aria-label="Go to a dashboard"><div class="zp-in">' + ic(ICO.search) + '<input id="zp-q" type="search" placeholder="Go to a dashboard…" autocomplete="off" aria-label="Search dashboards"><kbd>Esc</kbd></div><ul id="zp-l" role="listbox"></ul>'
        + '<div class="zp-ft"><span>↑↓ move</span><span>Enter open</span><span>Ctrl+Enter new tab</span></div></div>';
      document.body.appendChild(pal);
      var q = pal.querySelector('#zp-q'), l = pal.querySelector('#zp-l'), sel = 0, res = [];
      var listAll = function () {
        var all = [{ h: './', s: 'Home', t: 'All dashboards', a: { name: 'Dashboards', c: '#8C93A1', icon: ICO.home } }];
        navReg().forEach(function (a) { a.pages.forEach(function (p) { all.push({ h: p.h, s: p.s, t: p.t, d: p.d, k: (p.k || []).join(' '), kl: p.k || [], fw: p.fw, a: a }); }); });
        (PN || []).forEach(function (g) { var ar = { name: 'Portal', c: '#8C93A1', icon: ICO.grid }; g.items.forEach(function (it) { all.push({ h: portalHref(it.v), s: it.l, t: it.l, d: g.name + ' — portal page', a: ar }); }); });
        return all;
      };
      // the search index is built once (lower-cased text, label words, framework codes) and rebuilt only when the portal menu arrives -
      // a keystroke only scans it, so the palette stays instant with several hundred dashboards
      var IDX = null, index = function () { if (!IDX) IDX = listAll().map(function (x) { return srPrep(Object.assign({ fk: fwKey(x.fw) }, x)); }); return IDX; };
      portalNav(function () { IDX = null; if (pal && !pal.hidden) pal._draw(); });
      var draw = function () {
        var v = q.value.trim();
        if (v) res = srRank(index(), v, 40);
        else { var rec = srRecent(), all = index().map(function (r) { return r.x; }); res = all.filter(function (x) { return rec[x.h] != null; }).sort(function (a, b) { return rec[a.h] - rec[b.h]; }).slice(0, 8).concat(all.filter(function (x) { return rec[x.h] == null; })).slice(0, 40); }
        sel = 0;
        l.innerHTML = (!v && res.length ? '<div class="zp-none" style="padding:6px 14px;text-align:left">Recent first - type to search every page, its description and keywords</div>' : '') + (res.length ? res.map(function (x, i) { return '<li role="option" data-i="' + i + '"' + (i === 0 ? ' class="on" aria-selected="true"' : '') + '><span class="zs-ic" style="--c:' + esc0(x.a.c) + '">' + ic(x.a.icon) + '</span><span style="min-width:0"><b>' + esc0(x.s) + '</b><small>' + esc0(x.d || x.t) + '</small></span><em>' + esc0(x.a.sn || x.a.name) + '</em></li>'; }).join('') : '<div class="zp-none">No dashboard matches “' + esc0(q.value) + '”.</div>');
      };
      var mark = function () { [].forEach.call(l.querySelectorAll('li[data-i]'), function (li, i) { li.classList.toggle('on', i === sel); li.setAttribute('aria-selected', String(i === sel)); if (i === sel) li.scrollIntoView({ block: 'nearest' }); }); };
      var go = function (i, nt) { var x = res[i]; if (!x) return; if (nt) window.open(x.h, '_blank'); else location.href = x.h; };
      q.addEventListener('input', draw);
      q.addEventListener('keydown', function (e) {
        if (e.key === 'ArrowDown') { e.preventDefault(); sel = Math.min(sel + 1, res.length - 1); mark(); }
        else if (e.key === 'ArrowUp') { e.preventDefault(); sel = Math.max(sel - 1, 0); mark(); }
        else if (e.key === 'Enter') { e.preventDefault(); go(sel, e.ctrlKey || e.metaKey); }
        else if (e.key === 'Escape') { e.preventDefault(); pal.hidden = true; }
      });
      l.addEventListener('click', function (e) { var li = e.target.closest('li[data-i]'); if (li) go(+li.getAttribute('data-i'), e.ctrlKey || e.metaKey); });
      pal.addEventListener('click', function (e) { if (e.target === pal) pal.hidden = true; });
      pal._draw = draw;
    }
    pal.hidden = false; var qi = pal.querySelector('#zp-q'); qi.value = ''; pal._draw(); qi.focus();
  }

  // framework tags as tooltip lines ("SAMA 3.3.14 Logging and Monitoring Management") and as search words
  function fwTip(tg) { return tg.map(function (t) { return t.codes.map(function (c) { return t.short + ' ' + c[0] + ' - ' + c[1]; }).join('\n'); }).join('\n'); }
  function fwKey(fw) { return window.zybFwTags ? window.zybFwTags(fw).map(function (t) { return t.k + ' ' + t.short + ' ' + t.codes.map(function (c) { return c[0]; }).join(' '); }).join(' ') : ''; }

  /* ---- top bar */
  function bar() {
    if (window.__zybMoving || !document.body) return;
    if (document.getElementById('zyb-bar')) return;
    var CL = UI === 'classic';
    var st = document.createElement('style'); st.id = 'zyb-shell-css'; st.textContent = (CL ? '' : cssPolish) + css + (CL ? cssClassic : ''); document.head.appendChild(st);
    if (CL) document.body.classList.add('zyb-classic'); else side();
    remember();
    var me = findPage(here()), isIndex = here() === 'index.html' && /\/dashboards\//.test(location.pathname + '/');
    // the compliance frameworks this page supports (zyb-nav.js fw), full domain names on hover, one click to the map
    var fwt = me && window.zybFwTags ? window.zybFwTags(me.p.fw) : [];
    var fwb = fwt.length ? '<a class="zb-fw" href="compliance-map.html#' + encodeURIComponent(me.p.h) + '" title="' + esc0('Supports (evidence or control, not a certification):\n' + fwTip(fwt)) + '">'
      + fwt.map(function (t) { return '<i style="--c:' + esc0(t.c) + '">' + esc0(t.short) + '</i>'; }).join('') + '</a>' : '';   // names only: the codes are in the tooltip, on the home cards and on the map
    var crumb = '<nav class="zb-crumb" aria-label="Breadcrumb"><a href="./">Home</a>'
      + (me ? ic(ICO.chev) + '<span class="zb-mid" style="display:inline-flex;align-items:center;gap:6px"><span class="zb-dot" style="background:' + esc0(me.a.c) + '"></span>' + esc0(me.a.sn || me.a.name) + '</span>' + ic(ICO.chev) + '<b>' + esc0(me.p.s) + '</b>' + fwb
        : (isIndex ? '' : ic(ICO.chev) + '<b>' + esc0((document.title || '').replace(/\s*[—|-]\s*Zyberon.*$/i, '')) + '</b>')) + '</nav>';
    var b = document.createElement('div'); b.id = 'zyb-bar';
    b.innerHTML = (CL
      ? '<button type="button" id="zyb-back">← Back</button>' + (isIndex ? '<a class="zb-btn" href="/?zybportal=1">Portal home</a>' : '<a class="zb-btn" href="./">All dashboards</a>')
        + '<span class="sp"></span>'
        + '<button type="button" id="zyb-cz-btn" aria-expanded="false" aria-controls="zyb-cz">Customize</button><button type="button" id="zyb-out">Sign out</button>'
      : '<button type="button" class="zb-ico" id="zyb-menu-btn" aria-label="Open menu">' + ic(ICO.menu) + '</button>'
        + '<button type="button" class="zb-ico" id="zyb-back" title="Back" aria-label="Back">' + ic(ICO.back) + '</button>'
        + (EMB ? '<a class="zb-btn" href="./">All dashboards</a>' : '') + crumb
        + '<span class="sp"></span><button type="button" id="zyb-find-btn" aria-label="Search dashboards (Ctrl+K)">' + ic(ICO.search) + '<span>Search dashboards…</span><kbd>Ctrl K</kbd></button>'

        + '<button type="button" id="zyb-cz-btn" aria-expanded="false" aria-controls="zyb-cz">' + ic(ICO.gear) + '<span>Customize</span></button>'
        + '<button type="button" id="zyb-out" title="Sign out" aria-label="Sign out">' + ic(ICO.out) + '<span>Sign out</span></button>')
      + '<div id="zyb-cz" hidden role="dialog" aria-label="Customize dashboards"><h4>Customize dashboards</h4>'
      + (window.ZYB_ARABIC === true ? '<label>Language<select id="zyb-de">' + opt(LANGS, prefs.lang === 'ar' ? 'ar' : 'en') + '</select></label>' : '')
      + '<label>Colour theme<select id="zyb-th">' + opt(THEMES, prefs.theme || 'default', function (t) { return t.name; }) + '</select></label>'
      + '<label>Accent colour<span class="sw" id="zyb-ac">' + ACCENTS.map(function (c) { return '<button type="button" data-c="' + c + '" style="background:' + c + '" aria-label="Accent ' + c + '" aria-pressed="' + (prefs.accent === c) + '"></button>'; }).join('')
      + '<input type="color" id="zyb-acc" value="' + (prefs.accent || '#3274D9') + '" aria-label="Other accent colour"></span></label>'
      + '<label>Font<select id="zyb-fo">' + opt(FONTS, prefs.font || 'default', function (f) { return f[0]; }) + '</select></label>'
      + '<label>Text size<select id="zyb-sz">' + opt(SIZES, prefs.size || 'auto') + '</select></label>'
      + '<p class="note">Applies to all dashboards, for you, in this browser.</p>'
      + '<div class="act"><button type="button" id="zyb-rs">Reset</button><button type="button" id="zyb-cc">Cancel</button><button type="button" class="pri" id="zyb-sv">Save</button></div></div>';
    var sideEl = document.getElementById('zyb-side');
    if (sideEl) document.body.insertBefore(b, sideEl.nextSibling.nextSibling); else document.body.insertBefore(b, document.body.firstChild);
    var pre = document.getElementById('zyb-pre'); if (pre) pre.remove();   // the real menu and bar are in place now
    var panel = document.getElementById('zyb-cz'), btn = document.getElementById('zyb-cz-btn'), draft = JSON.parse(JSON.stringify(prefs));
    function preview() { apply(draft); }
    function close(restore) { panel.hidden = true; btn.setAttribute('aria-expanded', 'false'); if (restore) { draft = JSON.parse(JSON.stringify(prefs)); apply(prefs); } }
    document.getElementById('zyb-back').onclick = back;
    document.getElementById('zyb-out').onclick = function () { signOut(this); };
    var mb = document.getElementById('zyb-menu-btn'), fb = document.getElementById('zyb-find-btn');
    if (mb) mb.onclick = function () { document.body.classList.toggle('zyb-side-open'); };
    if (fb) fb.onclick = palette;
    btn.onclick = function () { var open = panel.hidden; panel.hidden = !open; btn.setAttribute('aria-expanded', String(open)); if (open) { var f = panel.querySelector('select,input,button'); if (f) f.focus(); } };
    if (document.getElementById('zyb-de')) document.getElementById('zyb-de').onchange = function () { draft.lang = this.value; };   // applied on Save (the page reloads)
    document.getElementById('zyb-th').onchange = function () { draft.theme = this.value; preview(); };
    document.getElementById('zyb-fo').onchange = function () { draft.font = this.value; preview(); };
    document.getElementById('zyb-sz').onchange = function () { draft.size = this.value; preview(); };
    document.getElementById('zyb-acc').oninput = function () { draft.accent = this.value; [].forEach.call(document.querySelectorAll('#zyb-ac button'), function (x) { x.setAttribute('aria-pressed', 'false'); }); preview(); };
    document.getElementById('zyb-ac').onclick = function (e) { var c = e.target.getAttribute && e.target.getAttribute('data-c'); if (!c) return; draft.accent = c; [].forEach.call(this.querySelectorAll('button'), function (x) { x.setAttribute('aria-pressed', String(x === e.target)); }); document.getElementById('zyb-acc').value = c; preview(); };
    document.getElementById('zyb-cc').onclick = function () { close(true); };
    document.getElementById('zyb-rs').onclick = function () { draft = {}; save({}); location.reload(); };
    document.getElementById('zyb-sv').onclick = function () { prefs = draft; save(prefs); location.reload(); };
    document.addEventListener('keydown', function (e) {
      if (e.key === 'Escape' && !panel.hidden) { close(true); btn.focus(); }
      if (e.key === 'Escape' && document.body.classList.contains('zyb-side-open')) document.body.classList.remove('zyb-side-open');
      if ((e.ctrlKey || e.metaKey) && !e.altKey && !e.shiftKey && (e.key === 'k' || e.key === 'K')) { e.preventDefault(); if (pal && !pal.hidden) pal.hidden = true; else palette(); }
    });
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', bar); else bar();

  /* ---- details panel: window.zybDetail.open(eyebrow, title, html). Closed by ← Back, Esc, the browser's Back button
     or a click beside it. Helpers kv / tbl / sec / pill / esc build the body. Pages call it from their own click handlers. */
  var dcss = '.zd-click{cursor:pointer}.zd-click:hover{filter:brightness(1.15)}tr.zd-click:hover td{background:rgba(255,255,255,.04)}'
    + '#zd{position:fixed;inset:0;z-index:80;font-family:inherit}#zd[hidden]{display:none}#zd .zd-bg{position:absolute;inset:0;background:rgba(0,0,0,.45)}'
    + '#zd .zd-p{position:absolute;top:0;right:0;bottom:0;width:min(580px,100%);background:var(--panel,#181b1f);color:var(--text,#d8d9da);border-left:1px solid var(--border,var(--edge,var(--line,#2e3440)));box-shadow:-20px 0 50px rgba(0,0,0,.5);display:flex;flex-direction:column;animation:zdIn .18s ease-out}'
    + '@keyframes zdIn{from{transform:translateX(24px);opacity:0}to{transform:none;opacity:1}}'
    + '#zd .zd-h{display:flex;align-items:flex-start;gap:12px;padding:14px 18px;border-bottom:1px solid var(--edge,var(--line,#2e3440))}'
    + '#zd .zd-back{background:var(--bg,#111);border:1px solid var(--border,var(--edge,#2e3440));color:var(--title,var(--text,#fff));border-radius:6px;padding:7px 12px;font:600 13px system-ui,-apple-system,"Segoe UI",sans-serif;cursor:pointer;white-space:nowrap}'
    + '#zd .zd-back:hover,#zd .zd-back:focus-visible{border-color:var(--accent,#5794f2);outline:none}'
    + '#zd .zd-eye{font:500 11px ui-monospace,Consolas,monospace;color:var(--mute,#8e8e9e);text-transform:uppercase;letter-spacing:.06em}'
    + '#zd h2{margin:2px 0 0;font:600 17px/1.3 system-ui,-apple-system,"Segoe UI",sans-serif;color:var(--title,var(--text,#fff))}'
    + '#zd .zd-b{padding:14px 18px 28px;overflow-y:auto;font-size:13px;line-height:1.5}#zd .zd-b p{margin:0 0 10px}#zd .zd-b a{color:var(--cyan,var(--c1,#5794f2))}#zd .zd-dim{color:var(--mute,#8e8e9e)}'
    + '#zd .zd-kv{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px;margin:0 0 14px}#zd .zd-kv div{border:1px solid var(--edge,var(--line,#2e3440));border-radius:6px;padding:8px 10px;min-width:0}'
    + '#zd .zd-kv dt{font-size:11px;color:var(--mute,#8e8e9e)}#zd .zd-kv dd{margin:2px 0 0;color:var(--title,var(--text,#fff));font-weight:600;overflow-wrap:anywhere}'
    + '#zd .zd-s{margin-top:16px}#zd .zd-s h3{font:600 13px system-ui,sans-serif;margin:0 0 8px;color:var(--title,var(--text,#fff))}'
    + '#zd .zd-tw{overflow-x:auto}#zd table{width:100%;border-collapse:collapse;font-size:12.5px}#zd th{text-align:left;color:var(--mute,#8e8e9e);font-weight:500;padding:6px 8px;border-bottom:1px solid var(--edge,var(--line,#2e3440));white-space:nowrap}'
    + '#zd td{padding:6px 8px;border-bottom:1px solid var(--edge,var(--line,#2e3440));overflow-wrap:anywhere}#zd .n{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}'
    + '#zd .zd-pill{display:inline-block;padding:1px 8px;border-radius:10px;font-size:11.5px;font-weight:600;white-space:nowrap}#zd .zd-ok{background:rgba(86,166,75,.18);color:#7fd36f}#zd .zd-warn{background:rgba(242,204,12,.16);color:#f2cc0c}#zd .zd-bad{background:rgba(224,47,68,.18);color:#ff7383}#zd .zd-info{background:rgba(87,148,242,.16);color:#8ab8ff}'
    + '#zd .zd-bar{height:8px;border-radius:4px;background:var(--edge,#2e3440);overflow:hidden;min-width:60px}#zd .zd-bar i{display:block;height:100%;background:var(--cyan,var(--c1,#5794f2))}'
    + '@media (max-width:560px){#zd .zd-kv{grid-template-columns:minmax(0,1fr)}}';
  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); }
  var dw = null, lastFocus = null;
  function ensure() {
    if (dw) return dw;
    var st = document.createElement('style'); st.textContent = dcss; document.head.appendChild(st);
    dw = document.createElement('div'); dw.id = 'zd'; dw.hidden = true;
    dw.innerHTML = '<div class="zd-bg" data-zd-close></div><aside class="zd-p" role="dialog" aria-modal="true" aria-labelledby="zd-t"><div class="zd-h">'
      + '<button type="button" class="zd-back" data-zd-close>← Back</button><div><div class="zd-eye" id="zd-e"></div><h2 id="zd-t"></h2></div></div><div class="zd-b" id="zd-b"></div></aside>';
    document.body.appendChild(dw);
    dw.addEventListener('click', function (e) { if (e.target.closest('[data-zd-close]')) close(); });
    document.addEventListener('keydown', function (e) { if (e.key === 'Escape' && !dw.hidden) close(); });
    window.addEventListener('popstate', function () { if (!dw.hidden) close(true); });
    return dw;
  }
  function open(eyebrow, title, html) {
    ensure();
    var was = !dw.hidden;
    document.getElementById('zd-e').textContent = eyebrow || ''; document.getElementById('zd-t').textContent = title || '';
    document.getElementById('zd-b').innerHTML = html || ''; document.getElementById('zd-b').scrollTop = 0;
    if (!was) { lastFocus = document.activeElement; dw.hidden = false; try { window.history.pushState({ zd: 1 }, ''); } catch (e) { /* address bar not updated (sandboxed frame): the page works without it */ } }
    dw.querySelector('.zd-back').focus();
  }
  function close(fromPop) {
    if (!dw || dw.hidden) return;
    dw.hidden = true;
    if (!fromPop && window.history.state && window.history.state.zd) { try { window.history.back(); } catch (e) { /* no history entry to go back to: the drawer is closed anyway */ } }
    if (lastFocus && lastFocus.focus) { try { lastFocus.focus(); } catch (e) { /* element already gone: nothing to focus */ } }
  }
  var NUMH = /^(#|%|Flows|Allowed|Denied|Share|Bytes|Packets|Calls|Errors|Requests|Hits|Visits|Visitors|Count|Avg|Average response|Heap used|Now|Before|Change|Value|Users|Sessions|Sent|Rate|Incidents|Uptime|ms)\b/i;
  window.zybDetail = {
    open: open, close: close, esc: esc,
    kv: function (rows) { return '<dl class="zd-kv">' + rows.map(function (r) { return '<div><dt>' + esc(r[0]) + '</dt><dd>' + r[1] + '</dd></div>'; }).join('') + '</dl>'; },
    tbl: function (head, rows) {
      var num = head.map(function (h) { return NUMH.test(h); });
      return '<div class="zd-tw"><table><thead><tr>' + head.map(function (h, i) { return '<th' + (num[i] ? ' class="n"' : '') + '>' + esc(h) + '</th>'; }).join('') + '</tr></thead><tbody>'
        + rows.map(function (r) { return '<tr>' + r.map(function (c, i) { return '<td' + (num[i] ? ' class="n"' : '') + '>' + c + '</td>'; }).join('') + '</tr>'; }).join('') + '</tbody></table></div>';
    },
    sec: function (t, body) { return '<section class="zd-s"><h3>' + esc(t) + '</h3>' + body + '</section>'; },
    pill: function (text, kind) { return '<span class="zd-pill zd-' + esc(String(kind || 'info').replace(/[^a-z0-9_-]/gi, '')) + '">' + esc(text) + '</span>'; },
    bar: function (frac) { return '<div class="zd-bar"><i style="width:' + Math.max(0, Math.min(100, frac * 100)).toFixed(1) + '%"></i></div>'; },
    /* make matching elements look and act clickable (keyboard too) */
    mark: function (root, sel) { [].forEach.call((root || document).querySelectorAll(sel), function (el) { el.classList.add('zd-click'); if (!el.hasAttribute('tabindex')) el.setAttribute('tabindex', '0'); }); }
  };
  document.addEventListener('keydown', function (e) { if ((e.key === 'Enter' || e.key === ' ') && e.target.classList && e.target.classList.contains('zd-click')) { e.preventDefault(); e.target.dispatchEvent(new MouseEvent('click', { bubbles: true })); } });
})();

/* ===== Zyberon footer — injected on every dashboard (one place, all pages) ===== */
(function () {
  var LOGO = "data:image/webp;base64,UklGRigIAABXRUJQVlA4WAoAAAAQAAAAXwAATQAAQUxQSK4DAAABoChJtmnb6uNzbdu2bdu2bdu2bdu2j23b5sUe972331pzzPkDETEBMGoy5ODhQ5IePr00D7R2Pe0QFOTr6ebsaGdjY/P969evNkYdHP/r5Nje2KY/JO+jmiYaKt79SczrzIyUTiJpo6eYQGMDf+I+bgKjNTOleVIdWqsFEPdDaxivkSFJwnxzaC1qT9w/CkGyt/WhOedT4vavBLlSV1pDs+kZ4o5vDrm+NYPOTcSdNQBSZW7ODZ3TDWyzIZVjB+jtm0ncOyDTr30FoLdZHHFfMZfJsyd0Vw4g7nd5II/hRFHoLmJL3O6lIE/AIOjP+YS4I+pAnkuloN/0DHGndoY0YWMhchNx/x4Lae5UhMgZBrYVkCVmuilE9s8k7iOQ5WkNCG0RT9x3rSRJXGgBoVWDiPtLAcjxvgHEFnMgbq/ykCJttTXE5n5B3FENIMWPlhBsfoG4U7tChqxteSB6O3H/Gg0ZnDpB+DxiXwwJfh0oAOFDs9l2QwKvXhDfPpm4L5rzGU4Xg/jaYcT9LBfYAoeAsbQbcf8oAqZfdKUMGPN9IG6v8mCuEzQBnJY3iTusHrgLVgDrQeJObAe1VxB3Rn+oPf431++JULtHOnEvgdqNY4h7O9Su6Efcp0zVKmxD3LesoXTOx8T9Ji+UNjtD3DbFoPZm4vaqALVnGbhC6kDtQVnEHNcKardJJOa0nlC7ZigxZ4+C2qVciNkwC2rnfUvca6C2xXXi3g/F9xH3BQvFlhL3o5xQe8wvro8FoXbXNGJ2LgW1G0YTs39VqF3Bh5ijm0Dtwt+JOaUL1M75iJizh0Ft0zPEbJgNxTcT93ooPou4j5iIKtZtUAEpBmdz3bKE2Dwrw4jsGkjQNomY3+WF2J729N/YkWy1Q4nZqSSEVrzwh4z/2WbJU9qNmIOrQ6T1vCjS+qg0R74PxJzQEiLbfiKdnq3FWd0m5sz+EFjiUBbpTp4kyuQwMRtmQL/puAASui+HmFXEvQn66z8m0c/Lipj0h+usma5865NJvE8bfb0ziPl5Lujt7USsyZP0NI0lZqdi0Fnhwh/i3mOtqVYYMYfWgHbLmREk4ZPSWioejOdJ6QDtLd6RnJ4tNACV9iUy/B4LzYV3pZOsiWO1ADWOpwlbCs1DPEniP9sstQB1T6cI+bkQWqvfJMnvFdcE1NwdrM+nNzTmXBJL0rs00gYUGnLBI1WL79oi+H+LnvakYvI4c20ActUevvXOdy9/j/eHBhSE1sLTF89Rcf7MAgBWUDggVAQAADAYAJ0BKmAATgA+MRSHQqIhDVTPABABglsbNZAAhHw5/pP5M9uFUjo35F/jp8uVg/m33m/dTMAvCv0b/N/cB2gPMA/Rb/GdQDzAftF+yXvS+h7/reoP/T/8L1gHoAeWH+qvwLftJ/3P9v8Av62//DrAOBd+ivqQPp2LQsbLvAaA38q/1/Wl9AD9MzBj27VvtmNAxHFNWZkUU6rn/ifoNwpiKCCRNXyBpADUpXf6FSXnDJIDh/zijmjN7iXB87DIUSIaDXEKQw7rKDAA/luBR/trU/63+XCeBO/JB4/ADXK9Jvr0yXrq/ACsMxfFdS8kX9GlxXByq7AuLe26CxgF2wL+gvhOGqE0HmCtODGDD3VMBMfP1PMg6+dXrIBa54ztwwQW6uG+nU/CqBaY/6v+5n60/4De7KNPd1pLtc0gsNh/pzDy6sq6KNCbbUNlUN6cFrCo1E2+W51ZAQPwjgn9AuXVgE/Di+Tdn/jecaILKBiJHjDh0oBIcd0JELw7ukQIaTpyVgoT5yGZ3fe0mxIUkhvZh7cR19BKt8SYrzf3Bbt3QeVdVz6FNk4t/Qk2wqrYrK53tQkM4MIV+kc9McJLA3M9OgBJGM1VM/BW78HHs/iM6M7+lUPSEeJec+jRt80eBh7Ep9heyWeIiWND7RZktKd18vU3fJVa0spPYr++ZFBPJln8AGMp3W3QzdbsBZ07ezivlmPdDn6/h9gAA2q0qkd1+tYQbciWlZjQkt7T3MgiS5mnwXbDhjbscpWWo1ACn//NX//6wT/+rs//+rKsujQn8f88yaViIrjS+Jtqr326/9fZumczeXxgXmHW5p87ouvtGvewSvWNGEYFzze0YKY1QaX8UxXvOr3DmBoci7f4AgiZHsJJIfo2zGzotzuALKeau3vatVdi0MT8FhRBwR0T4wrdf+Pkp5fEZ8dU9heYykU4LflYPifCk5amtdMoeQACjn7yx74w3SNOwVzd6NFdI4b1t6GLcL7GpBeGe5QfdjcQXaNSiVmco1Yp2X5ixnLjfAFW4di187rQmZWHPllQh7Pa7PrQ8t2t7mBcSzFSBubicFgJ6P0GEKk29Z+IpzkLL4cP/Q0Jn//uadADFgEHhuHI1cpaI/hTAszJT27ZnvB32s7XuVur/LO4Hh1StDsUz9vSwJvz4WiZhs7RIf+b+aUgAJJ1o0gJVPkACjwT6Qim1P5S1CWQoiAgWidFr96mZQjYIYxxOhi3mUx6sA8qMAwW8QyFVtX6+e/pc6BsMcm9bfAOMJSQSwy4c83C3sF+6pFMDhWW+FkeheaJp7iuyLisqh2AWiWKf9kH3AeWfh7BRLoTwJ93m0v/Vgx6lofr5RrDxUcLOFHxVvYXZ12X5u1v2Hxwy72G5CnZhfd+Mla5miM4O43zxLJzJhrtEjZHqRwUL3qVC9ggh4fOtYjkRLFXCWGBrokGXf3URtLH7vVbxcmynM/eiaQaLblnwzmAAAA=";
  window.__zybLogo = LOGO;   // the sidebar and the home page use the same mark
  function addFooter() {
    try {
      if (document.getElementById("zyb-footer")) return;              // never double up
      var f = document.createElement("footer");
      f.id = "zyb-footer"; f.setAttribute("role", "contentinfo");
      f.style.cssText = "margin:30px 0 0;padding:16px 16px 24px;text-align:center;" +
        "font:500 12px \"Segoe UI\",system-ui,sans-serif;color:#8C93A1;line-height:1.55;" +
        "border-top:1px solid rgba(255,255,255,.08)";
      f.innerHTML = "<img src=\"" + LOGO + "\" alt=\"Zyberon\" style=\"height:16px;vertical-align:middle;margin-right:8px;opacity:.92\">" +
        "<span>&copy; 2026 <b style=\"color:#C3CAD6\">Citynet Work &amp; Zyberon Information Technology</b>, Saudi Arabia \u2014 Unified IT &amp; Cyber Security Automation Solution " +
        "\u00b7 Powered by <b style=\"color:#C3CAD6\">CityNet IT &amp; Cyber Security Company</b>, Saudi Arabia</span>";
      (document.body || document.documentElement).appendChild(f);
    } catch (e) { /* a footer must never break a page */ }
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", addFooter); else addFooter();
})();

// Platform licence (sentra-itam engine/licence.js): during the grace period administrators see a banner with the reason and the
// date it locks; once locked every page shows why and where an administrator installs a licence (Platform Administration ->
// Modules & Solutions stays usable). Fails quietly: a licence endpoint that cannot be reached never blocks or breaks a page.
(function () {
  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); }
  function show(st) {
    var E = st && st.enforcement; if (!E || !E.enforced || E.gate === 'ok') return;
    var onAdmin = /solution-admin\.html$/.test(location.pathname);
    var d = document.createElement('div'); d.id = 'zybLicence'; d.setAttribute('role', 'alert');
    if (E.gate === 'grace') {
      // the banner can be closed (button, not an inline handler - CSP): hidden for 7 days in this browser, and only until the
      // next day in the last 7 days before the platform locks, so nobody is surprised by the lock. The lock screen cannot be closed.
      var HK = 'zyb-licence-hidden', left = Number(E.grace_days_left) || 0, hid = 0;
      try { hid = Number(localStorage.getItem(HK)) || 0; } catch (e) { hid = 0; /* storage blocked: the banner shows */ }
      if (hid > Date.now()) return;
      d.style.cssText = 'position:sticky;top:0;z-index:9990;background:#7a4b00;color:#fff;padding:8px 44px 8px 16px;font:13px/1.4 system-ui,sans-serif';
      d.innerHTML = '<b>Licence problem:</b> ' + esc(E.reason) + '. The platform keeps working until ' + esc(String(E.grace_until || '').slice(0, 10)) + ' (' + esc(E.grace_days_left) + ' days), then locks. An administrator installs a licence from Citynet in <a style="color:#fff" href="/solution-admin.html">Modules &amp; Solutions</a>.';
      var x = document.createElement('button'); x.type = 'button'; x.id = 'zybLicenceClose'; x.setAttribute('aria-label', 'Close the licence message'); x.title = left > 7 ? 'Hide for 7 days' : 'Hide until tomorrow'; x.textContent = '\u2715';
      x.style.cssText = 'position:absolute;top:50%;inset-inline-end:10px;transform:translateY(-50%);background:transparent;border:1px solid rgba(255,255,255,.5);color:#fff;border-radius:6px;width:26px;height:26px;cursor:pointer;font:14px/1 system-ui,sans-serif';
      x.addEventListener('click', function () { var t = new Date(); if (left > 7) t = new Date(Date.now() + 7 * 86400000); else { t.setHours(24, 0, 0, 0); }
        try { localStorage.setItem(HK, String(t.getTime())); } catch (e) { /* storage blocked: closed for this page only */ } d.remove(); });
      d.appendChild(x);
      (document.body || document.documentElement).insertBefore(d, (document.body || document.documentElement).firstChild);
    } else if (!onAdmin) {
      d.style.cssText = 'position:fixed;inset:0;z-index:10100;background:rgba(10,14,24,.96);color:#fff;display:flex;align-items:center;justify-content:center;padding:16px;font:15px/1.5 system-ui,sans-serif';
      d.innerHTML = '<div style="max-width:560px"><h2 style="margin:0 0 8px">The platform licence is not valid</h2><p>' + esc(E.reason) + '.</p><p>Log collection and detection keep running. An administrator installs a valid licence from Citynet in <a style="color:#9cf" href="/solution-admin.html">Platform Administration &rarr; Modules &amp; Solutions</a>.</p><p style="opacity:.7">This server: ' + esc(st.fingerprint) + '</p></div>';
      (document.body || document.documentElement).appendChild(d);
    }
  }
  function run() {
    try { fetch('/api/itam/licence', { credentials: 'include', cache: 'no-store', zybQuiet: true })
      .then(function (r) { return r.ok ? r.json() : null; }).then(show)
      .catch(function () { /* licence status unreachable: never block a page on it */ }); } catch (e) { /* no fetch in this browser: nothing to show */ }
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', run); else run();
})();
