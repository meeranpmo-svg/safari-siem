// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
/* zyb-print.js - loaded on every page by zyb-dash.js. Printing a page (Ctrl+P, "Save as PDF", or a page's own Print button) used to
 * copy the dark screen theme into the PDF: grey panels, black text on dark sections, the menu and buttons. This sheet applies only to
 * print and gives every page one clean report look:
 *   - white page and surfaces, dark text, hairline borders; the colour variables every page family uses (--bg/--panel/--text...,
 *     --d-bg/--d-panel/--d-ink..., --pn/--tx..., Tabler --tblr-*) are remapped, so the page's own layout prints unchanged
 *   - status colours (ok / warn / bad / info), heat-map cells, bars and charts keep their colour (print-color-adjust: exact)
 *   - the menu, the top bar, buttons and form controls are not printed
 *   - a header with the company logo and name (the shared report brand an administrator sets under AI Pentest Engineer ->
 *     Report letterhead, signature & stamp), the page title and when it was printed. Without access to the brand (a viewer) the
 *     header shows the page title and date only - no name is ever made up.
 * The brand is read once per browser session and kept in sessionStorage (a large logo is kept in memory only). */
(function () {
  'use strict';
  if (window.__zybPrint) return; window.__zybPrint = true;
  var CSS = '@media print{'
    + '@page{margin:12mm}'
    + ':root,html,html.zyb-modern,html.org-brand,body,[data-bs-theme]{color-scheme:light!important;'
    // the live theme layers (zyb-vivid.css --v-*, zyb-look.css / zyb-theme.css --m-* / --x-* and their shared names, zyb-secops.css --so-*)
    + '--v-bg:#fff!important;--v-side:#fff!important;--v-bar:#fff!important;--v-panel:#fff!important;--v-panel2:#f6f8fb!important;--v-input:#fff!important;--v-ink:#111!important;--v-ink2:#222!important;--v-sub:#444!important;--v-mute:#555!important;--v-lbl:#555!important;--v-line:#c9d1dc!important;--v-line2:#c9d1dc!important;--v-line3:#c9d1dc!important;--v-ok:#1e7d3a!important;--v-warn:#a15c07!important;--v-crit:#b42318!important;--v-info:#1f5fa8!important;'
    + '--m-bg:#fff!important;--m-surf:#fff!important;--m-surf2:#f6f8fb!important;--m-surf3:#f6f8fb!important;--m-ink:#111!important;--m-ink2:#222!important;--m-mute:#555!important;--m-line:#c9d1dc!important;--m-line2:#c9d1dc!important;--m-ok:#1e7d3a!important;--m-warn:#a15c07!important;--m-crit:#b42318!important;--m-info:#1f5fa8!important;'
    + '--x-surf:#fff!important;--x-soft:#f6f8fb!important;--x-ink:#111!important;--x-mute:#555!important;--x-line:#c9d1dc!important;--x-ok:#1e7d3a!important;--x-warn:#a15c07!important;--x-crit:#b42318!important;--x-info:#1f5fa8!important;'
    + '--so-bg:#fff!important;--so-panel:#fff!important;--so-panel2:#f6f8fb!important;--so-ink:#111!important;--so-mute:#555!important;--so-line:#c9d1dc!important;'
    + '--canvas:#fff!important;--panel-head:#f6f8fb!important;--input:#fff!important;--ink:#111!important;--text2:#222!important;--text-bright:#111!important;--text-dim:#555!important;--line:#c9d1dc!important;--line-strong:#9aa6b6!important;--grid:#e3e8ef!important;--soft:#f6f8fb!important;--pn2:#fff!important;--top:#fff!important;'
    + '--tblr-bg-forms:#fff!important;--tblr-bg-surface-tertiary:#f6f8fb!important;--tblr-border-color-translucent:#c9d1dc!important;--tblr-emphasis-color:#111!important;--tblr-heading-color:#0b1b33!important;--tblr-secondary-color:#555!important;'
    + '--bg:#fff!important;--panel:#fff!important;--raise:#f6f8fb!important;--text:#111!important;--title:#0b1b33!important;--mute:#555!important;--border:#c9d1dc!important;--edge:#c9d1dc!important;'
    + '--d-bg:#fff!important;--d-panel:#fff!important;--d-raise:#f6f8fb!important;--d-ink:#111!important;--d-mute:#555!important;--d-line:#c9d1dc!important;'
    + '--pn:#fff!important;--rs:#f6f8fb!important;--tx:#111!important;--mu:#555!important;--ln:#c9d1dc!important;'
    + '--ok:#1e7d3a!important;--warn:#a15c07!important;--bad:#b42318!important;--info:#1f5fa8!important;--d-ok:#1e7d3a!important;--d-warn:#a15c07!important;--d-bad:#b42318!important;'
    + '--tblr-body-bg:#fff!important;--tblr-bg-surface:#fff!important;--tblr-bg-surface-secondary:#f6f8fb!important;--tblr-body-color:#111!important;--tblr-border-color:#c9d1dc!important;--tblr-secondary:#555!important;--tblr-muted:#555!important}'
    + 'html,body,html.zyb-modern body,html:not(#zyb-x) body{background:#fff!important;color:#111!important}'
    + '*{-webkit-print-color-adjust:exact!important;print-color-adjust:exact!important;box-shadow:none!important;text-shadow:none!important}'
    + '#zyb-bar,#zyb-side,#zyb-scrim,#zyb-pal,#zyb-cz,#zyb-pre,.zyb-toast,[role=status],button,.btn,select,input,textarea,dialog:not([open]),[data-noprint]{display:none!important}'
    + 'body{padding:0!important;margin:0!important}main,.page,.page-wrapper,.container,.container-xl,.wrap{max-width:none!important;padding-left:0!important;padding-right:0!important;margin-left:0!important;margin-right:0!important}'
    + 'html:not(#zyb-x) :is(.card,.t,.src,.tk,.ph>div,.st>div,.nx,.k>div,.k>.card,section.card,.panel,.tile,.stat,.kpi,.kpis .kpi,.noc-stat){background:#fff!important;color:#111!important;border:1px solid #c9d1dc!important}'
    + 'html:not(#zyb-x) :is(h1,h2,h3,h4,h5,h6,.title){color:#0b1b33!important}'
    + 'html:not(#zyb-x) :is(p,li,td,label,dd,dt,.v,b,strong){color:#111!important}html:not(#zyb-x) :is(.muted,.mute,.hint,.sm,.small,.s,.l,.sub,.meta,.c,.eb,.text-secondary,.text-muted){color:#555!important}'
    + 'html:not(#zyb-x) table{border-collapse:collapse!important;background:#fff!important}html:not(#zyb-x) th{background:#eef2f7!important;color:#111!important}html:not(#zyb-x) :is(th,td){border-color:#c9d1dc!important}'
    + 'a{color:#1f5fa8!important;text-decoration:none!important}html:not(#zyb-x) a.lk,html:not(#zyb-x) a.t{color:#111!important}'
    + '.card,tr,.tk,.nx,svg,img,figure{break-inside:avoid;page-break-inside:avoid}h1,h2,h3{break-after:avoid;page-break-after:avoid}'
    + '#zyb-print-head{display:flex!important}'
    + '}'
    + '#zyb-print-head{display:none;align-items:center;gap:14px;border-bottom:2px solid #0b1b33;padding:0 0 8px;margin:0 0 14px;font:13px Arial,sans-serif;color:#111;background:#fff}'
    + '#zyb-print-head img{max-height:44px;max-width:200px}#zyb-print-head .zph-o{font-weight:700;font-size:15px;color:#0b1b33}#zyb-print-head .zph-t{color:#333}#zyb-print-head .zph-d{margin-left:auto;color:#555;font-size:11px;text-align:right}';
  try { var st = document.createElement('style'); st.id = 'zyb-print-css'; st.textContent = CSS; (document.head || document.documentElement).appendChild(st); } catch (e) { /* no head yet: printing keeps the page's own look */ }

  var KEY = 'zyb-brand-v1', brand = null;
  function head() {
    if (!document.body) return null;
    var h = document.getElementById('zyb-print-head');
    if (!h) { h = document.createElement('div'); h.id = 'zyb-print-head'; h.setAttribute('aria-hidden', 'true'); document.body.insertBefore(h, document.body.firstChild); }
    h.textContent = '';
    if (brand && brand.logo && /^data:image\/(png|jpe?g|webp|svg\+xml);base64,/.test(brand.logo)) { var im = document.createElement('img'); im.src = brand.logo; im.alt = ''; h.appendChild(im); }
    var mid = document.createElement('div');
    if (brand && brand.name) { var o = document.createElement('div'); o.className = 'zph-o'; o.textContent = brand.name; mid.appendChild(o); }
    var t = document.createElement('div'); t.className = 'zph-t';
    var h1 = document.querySelector('main h1, h1'); t.textContent = (h1 && h1.textContent.trim()) || document.title || ''; mid.appendChild(t);
    h.appendChild(mid);
    var d = document.createElement('div'); d.className = 'zph-d'; d.textContent = 'Printed ' + new Date().toLocaleString() + (brand && brand.name ? '\nConfidential' : ''); d.style.whiteSpace = 'pre-line'; h.appendChild(d);
    return h;
  }
  function setBrand(b) { brand = b; head(); }
  try { var c = sessionStorage.getItem(KEY); if (c) brand = JSON.parse(c); } catch (e) { brand = null; /* no storage: read it again below */ }
  if (!brand) {
    try {
      var x = new XMLHttpRequest(); x.open('GET', '/api/itam/pentest/report-brand'); x.withCredentials = true; x.timeout = 15000; x.zybQuiet = true;
      x.onload = function () {
        if (x.status !== 200) { brand = { name: '', logo: '' }; return; }   // a viewer or no brand set: header without a name
        var j = null; try { j = JSON.parse(x.responseText); } catch (e) { j = null; /* not JSON: no brand */ }
        var b = { name: (j && j.org_name) || '', logo: (j && j.letterhead) || '' };
        try { if (b.logo.length < 1500000) sessionStorage.setItem(KEY, JSON.stringify(b)); } catch (e) { /* storage full: kept in memory for this page */ }
        setBrand(b);
      };
      x.onerror = x.ontimeout = function () { brand = { name: '', logo: '' }; /* unreachable: header without a name */ };
      x.send();
    } catch (e) { brand = { name: '', logo: '' }; /* no XHR: header without a name */ }
  }
  // the header is (re)built just before printing so it carries the current title and time
  window.addEventListener('beforeprint', head);
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', head); else head();
  window.zybPrintHead = head;
})();
