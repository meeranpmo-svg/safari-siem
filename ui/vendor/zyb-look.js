// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
/* zyb-look.js - ONE look for every screen (portal pages, the portal menu and the dashboards): the Modern base
 * (vendor/zyb-look.css under html.zyb-modern) with Grafana Vivid on top (vendor/zyb-vivid.css). The old Classic look is
 * retired: with it the portal and its menu were drawn in the old style while the dashboards inside them were Vivid, so the
 * menu and the pages never matched. A browser that still remembers "classic" is moved to Modern and the switch is gone.
 * Loaded by zyb-dash.js (dashboards) and zyb-menu.js (portal pages). window.zybLook = {get, set} (kept for old callers). */
(function () {
  'use strict';
  if (window.zybLook) return;
  var KEY = 'zyb-look';
  var me = document.currentScript, src = (me && me.src) || '';
  var dir = src ? src.replace(/[^/]*(\?.*)?$/, '') : '/dashboards/vendor/', ver = (/[?&]v=([^&]+)/.exec(src) || [])[1] || '';
  try { if (localStorage.getItem(KEY) === 'classic') localStorage.removeItem(KEY); } catch (e) { /* storage blocked */ }
  function get() { return 'modern'; }
  var cur = get();
  function apply(v) {
    cur = v; var h = document.documentElement;
    h.classList.toggle('zyb-modern', v === 'modern'); h.classList.toggle('zyb-classic-look', v === 'classic');
    [].forEach.call(document.querySelectorAll('.zyb-lk button'), function (b) { b.setAttribute('aria-pressed', String(b.getAttribute('data-lk') === v)); });
  }
  function set() {
    var v = 'modern';
    try { localStorage.setItem(KEY, v); } catch (e) { /* storage blocked: this page only */ }
    apply(v);
    try { window.dispatchEvent(new CustomEvent('zyb-look', { detail: v })); } catch (e) { /* old browser */ }
  }
  apply(cur);
  // zyb-early.js keeps the portal invisible until these style sheets are in (html.zyb-look-ready), so a first sign-in on an
  // empty cache never shows the old green portal for a moment; a sheet that fails to load counts as done (never a blank page)
  var pend = 0, ready = function () { if (--pend <= 0) document.documentElement.classList.add('zyb-look-ready'); };
  var track = function (l) { pend++; l.addEventListener('load', ready); l.addEventListener('error', ready); };
  if (!document.getElementById('zyb-look-css')) {
    var l = document.createElement('link'); l.id = 'zyb-look-css'; l.rel = 'stylesheet'; l.href = dir + 'zyb-look.css' + (ver ? '?v=' + ver : '');
    track(l); (document.head || document.documentElement).appendChild(l);
  }
  // Grafana Vivid (the chosen look): colourful menu workspaces and KPI panels, on top of the Modern base
  if (!document.getElementById('zyb-vivid-css')) {
    var lv = document.createElement('link'); lv.id = 'zyb-vivid-css'; lv.rel = 'stylesheet'; lv.href = dir + 'zyb-vivid.css' + (ver ? '?v=' + ver : '');
    track(lv); (document.head || document.documentElement).appendChild(lv);
  }
  // the colourful layer (vendor/zyb-color.css) on top of Vivid: on unless the brand setting says "colourful": false
  if (!document.getElementById('zyb-color-css') && !(window.ZYB_ORG && window.ZYB_ORG.colourful === false)) {
    document.documentElement.classList.add('zyb-color');
    var lc = document.createElement('link'); lc.id = 'zyb-color-css'; lc.rel = 'stylesheet'; lc.href = dir + 'zyb-color.css' + (ver ? '?v=' + ver : '');
    track(lc); (document.head || document.documentElement).appendChild(lc);
  }
  // the portal's theme switch (🌙 Dark NOC · ⬛ Midnight · ☀️ Light) for every screen: html[data-zyb-theme] + Tabler's
  // data-bs-theme, from localStorage noc_theme (the portal's own key), set before the page paints (vendor/zyb-theme.css)
  if (!document.getElementById('zyb-theme-css')) {
    var lt = document.createElement('link'); lt.id = 'zyb-theme-css'; lt.rel = 'stylesheet'; lt.href = dir + 'zyb-theme.css' + (ver ? '?v=' + ver : '');
    track(lt); (document.head || document.documentElement).appendChild(lt);
  }
  if (!pend) document.documentElement.classList.add('zyb-look-ready');
  var THEMES = { dark: 1, midnight: 1, light: 1 };
  function themeNow() { var t = 'dark'; try { t = localStorage.getItem('noc_theme') || 'dark'; } catch (e) { t = 'dark'; } return THEMES[t] ? t : 'dark'; }
  function applyTheme(t) {
    t = THEMES[t] ? t : 'dark'; var h = document.documentElement;
    if (h.getAttribute('data-zyb-theme') === t) return;
    h.setAttribute('data-zyb-theme', t); h.setAttribute('data-bs-theme', t === 'light' ? 'light' : 'dark');
    try { window.dispatchEvent(new CustomEvent('zyb-theme', { detail: t })); } catch (e) { /* old browser */ }
  }
  applyTheme(themeNow());
  window.zybTheme = { get: themeNow, apply: applyTheme };
  // literal colours written for a dark screen get their Light counterpart (vendor/zyb-theme.js) - dashboards and portal
  if (!window.zybThemeFix && !document.getElementById('zyb-theme-js')) {
    var tj = document.createElement('script'); tj.id = 'zyb-theme-js'; tj.src = dir + 'zyb-theme.js' + (ver ? '?v=' + ver : ''); (document.head || document.documentElement).appendChild(tj);
  }
  // another page or the portal around this dashboard changed it (the storage event reaches every other same-origin page)
  window.addEventListener('storage', function (e) { if (e.key === KEY) apply('modern'); if (e.key === 'noc_theme') applyTheme(themeNow()); });
  // the portal's own switch is on this page: follow it at once (the storage event does not fire in the page that wrote it)
  document.addEventListener('change', function (e) { if (e.target && e.target.id === 'themeSel') setTimeout(function () { applyTheme(themeNow()); }, 0); }, true);

  // the Modern | Classic switch is retired: remove one an older copy of this script left in a top bar
  function unmount() { [].forEach.call(document.querySelectorAll('.zyb-lk'), function (x) { x.remove(); }); }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', unmount); else unmount();

  window.zybLook = { get: function () { return cur; }, set: set, theme: function () { return themeNow(); } };
  // AI / ML labels on every page get one recognisable badge (vendor/zyb-color.css .zyb-ai): short labels only - a section's small
  // tag, a pill, an eyebrow - whose words say AI, ML, machine learning, learned, anomaly or forecast. Decoration only.
  (function () {
    var RX = /(^|[^a-z])(ai|ml|ai\s*\/\s*ml|machine learning|learned|anomal\w*|forecast\w*)([^a-z]|$)/i, SEL = 'h2 .c, h2 .tag, .pill, .chip, .badge, .eb .ai, [class*="-ml"], [data-ai]';
    function tag(root) { var L = (root || document).querySelectorAll ? (root || document).querySelectorAll(SEL) : [];
      for (var i = 0; i < L.length; i++) { var e = L[i], t = (e.textContent || '').trim(); if (t && t.length <= 48 && !e.classList.contains('zyb-ai') && RX.test(t) && !e.querySelector('button,input,select,a')) e.classList.add('zyb-ai'); } }
    var pend = false; function soon() { if (pend) return; pend = true; (window.requestAnimationFrame || setTimeout)(function () { pend = false; try { tag(document); } catch (e) { /* decoration only */ } }); }
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', soon); else soon();
    try { new MutationObserver(soon).observe(document.documentElement, { childList: true, subtree: true }); } catch (e) { /* no MutationObserver: tagged once at load */ }
  })();
})();
