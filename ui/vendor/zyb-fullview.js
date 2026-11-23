// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
/* zyb-fullview.js - the menu out of the way when you need the screen, on the portal and on every dashboard page:
 *   - Hide / show the menu: the ☰ button, or Ctrl+B (Cmd+B on a Mac). Remembered in this browser. A dashboard page shown
 *     inside the portal passes Ctrl+B up to the portal.
 *   - Full screen: the ⛶ button hides the menu and puts the browser in full screen; Esc (or ⛶ again) brings both back.
 *   - The menu scrolls on its own with a scrollbar you can see and grab; scrolling it never scrolls the page behind it,
 *     and the page that is open is kept in view in the menu.
 * Loaded by zyb-menu.js (portal) and zyb-dash.js (dashboard pages). Nothing is sent anywhere. */
(function () {
  'use strict';
  if (window.zybFullview) return;
  var EMB = false; try { EMB = window.self !== window.top; } catch (e) { EMB = true; }
  var KEY = 'zyb-side-hidden';
  var get = function () { try { return localStorage.getItem(KEY) === '1'; } catch (e) { return false; } };
  var put = function (v) { try { localStorage.setItem(KEY, v ? '1' : '0'); } catch (e) { /* storage blocked: the choice lasts for this page only */ } };
  var portal = function () { return document.querySelector('aside.side'); }, dash = function () { return document.getElementById('zyb-side'); };
  var narrow = function () { return window.matchMedia('(max-width:900px)').matches; };

  function css() {
    if (document.getElementById('zyb-fv-css')) return;
    var c = document.createElement('style'); c.id = 'zyb-fv-css';
    c.textContent =
      // a scrollbar you can see and grab; the wheel stays in the menu
      'aside.side,#zyb-side .zs-nav{overscroll-behavior:contain;scrollbar-width:auto;scrollbar-color:rgba(255,255,255,.34) transparent;scrollbar-gutter:stable}'
      + 'aside.side::-webkit-scrollbar,#zyb-side .zs-nav::-webkit-scrollbar{width:11px}'
      + 'aside.side::-webkit-scrollbar-thumb,#zyb-side .zs-nav::-webkit-scrollbar-thumb{background:rgba(255,255,255,.30);border-radius:8px;border:2px solid transparent;background-clip:padding-box}'
      + 'aside.side::-webkit-scrollbar-thumb:hover,#zyb-side .zs-nav::-webkit-scrollbar-thumb:hover{background:rgba(255,255,255,.5);background-clip:padding-box}'
      // dashboard pages: the menu fully hidden (the portal has its own nav-hidden)
      + 'body.zyb-side-hidden #zyb-side{display:none!important}body.zyb-side-hidden.zyb-has-side,body.zyb-side-hidden.zyb-has-side.zyb-rail{padding-left:0!important}'
      + 'body.zyb-side-hidden #zdp,body.zyb-side-hidden #zdp-pop{left:12px!important}'
      + '.zyb-fv-btn{display:inline-flex;align-items:center;justify-content:center;min-width:34px;height:34px;padding:0 9px;border-radius:8px;border:1px solid rgba(255,255,255,.14);background:rgba(255,255,255,.04);color:inherit;font:600 15px system-ui,sans-serif;cursor:pointer}'
      + '.zyb-fv-btn:hover{border-color:rgba(255,255,255,.32)}.zyb-fv-btn:focus-visible{outline:2px solid #fff;outline-offset:1px}'
      // shown only while the menu is hidden on a dashboard page, so it can always be brought back
      + '#zyb-fv-open{position:fixed;left:10px;top:10px;z-index:80;display:none;background:#14171f}body.zyb-side-hidden #zyb-fv-open{display:inline-flex}'
      + '@media print{.zyb-fv-btn{display:none!important}}';
    (document.head || document.documentElement).appendChild(c);
  }

  function isHidden() { var p = portal(); if (p) return document.body.classList.contains('nav-hidden'); return document.body.classList.contains('zyb-side-hidden'); }
  function setHidden(v) {
    var p = portal();
    if (p) {   // the portal's own switch (☰ = #navToggle) stores nav_hidden; on a narrow screen ☰ is a drawer and is left alone
      if (narrow()) { document.body.classList.toggle('nav-open', !v); return; }
      if (isHidden() !== v) { var b = document.getElementById('navToggle'); if (b) b.click(); else document.body.classList.toggle('nav-hidden', v); }
    } else if (dash()) { document.body.classList.toggle('zyb-side-hidden', v); }
    put(v); label();
  }
  function toggle() { if (EMB && !portal() && !dash()) { try { if (window.parent.zybFullview) return window.parent.zybFullview.toggle(); } catch (e) { /* not the portal */ } } setHidden(!isHidden()); }

  var before = null;
  function full() {
    var d = document, inFull = !!(d.fullscreenElement || d.webkitFullscreenElement);
    if (inFull) { (d.exitFullscreen || d.webkitExitFullscreen || function () {}).call(d); return; }
    before = isHidden(); setHidden(true);
    var el = d.documentElement, rq = el.requestFullscreen || el.webkitRequestFullscreen;
    if (rq) { try { var pr = rq.call(el); if (pr && pr.catch) pr.catch(function () { /* the browser refused: the menu stays hidden */ }); } catch (e) { /* idem */ } }
  }
  function onFull() { var d = document; if (!(d.fullscreenElement || d.webkitFullscreenElement) && before !== null) { setHidden(before); before = null; } label(); }

  function label() {
    var h = isHidden(), f = !!(document.fullscreenElement || document.webkitFullscreenElement);
    [].forEach.call(document.querySelectorAll('[data-zyb-fv="menu"]'), function (b) { b.title = (h ? 'Show the menu' : 'Hide the menu') + ' (Ctrl+B)'; b.setAttribute('aria-pressed', String(h)); b.setAttribute('aria-label', b.title); });
    [].forEach.call(document.querySelectorAll('[data-zyb-fv="full"]'), function (b) { b.title = f ? 'Leave full screen (Esc)' : 'Full screen: hide the menu and use the whole screen'; b.setAttribute('aria-label', b.title); b.textContent = f ? '🗗' : '⛶'; });
  }
  function btn(kind, txt) { var b = document.createElement('button'); b.type = 'button'; b.className = 'zyb-fv-btn'; b.setAttribute('data-zyb-fv', kind); b.textContent = txt; return b; }

  function install() {
    if (!document.body) return;
    css();
    var p = portal(), d = dash();
    if (p) {   // portal: ☰ already hides / shows; a full-screen button next to it, and the shortcut named on ☰
      var nt = document.getElementById('navToggle');
      if (nt) { nt.setAttribute('data-zyb-fv', 'menu'); if (!document.querySelector('[data-zyb-fv="full"]')) nt.parentNode.insertBefore(btn('full', '⛶'), nt.nextSibling); }
      var on = p.querySelector('li.active, li.zyb-on, li[aria-current="page"]'); if (on && on.scrollIntoView) { try { on.scrollIntoView({ block: 'nearest' }); } catch (e) { /* old browser */ } }
    } else if (d) {
      document.body.classList.toggle('zyb-side-hidden', get());
      var bar = document.getElementById('zyb-bar');
      if (bar && !bar.querySelector('[data-zyb-fv]')) { var m = btn('menu', '☰'); bar.insertBefore(m, bar.firstChild); m.insertAdjacentElement('afterend', btn('full', '⛶')); }
      if (!document.getElementById('zyb-fv-open')) { var o = btn('menu', '☰'); o.id = 'zyb-fv-open'; document.body.appendChild(o); }
      var a = d.querySelector('.zs-it.on'); if (a && a.scrollIntoView) { try { a.scrollIntoView({ block: 'nearest' }); } catch (e) { /* old browser */ } }
    } else if (!EMB) return;
    label();
  }

  document.addEventListener('click', function (e) {
    var b = e.target && e.target.closest && e.target.closest('[data-zyb-fv]'); if (!b) return;
    if (b.getAttribute('data-zyb-fv') === 'full') { e.preventDefault(); full(); return; }
    if (b.id === 'navToggle') { setTimeout(function () { put(document.body.classList.contains('nav-hidden')); label(); }, 0); return; }   // the portal handles its own ☰
    e.preventDefault(); toggle();
  });
  document.addEventListener('keydown', function (e) {
    if (!(e.ctrlKey || e.metaKey) || e.altKey || e.shiftKey || String(e.key).toLowerCase() !== 'b') return;
    var t = e.target, tag = t && t.tagName; if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' || (t && t.isContentEditable)) return;   // Ctrl+B in a text field stays the field's
    e.preventDefault(); toggle();
  });
  document.addEventListener('fullscreenchange', onFull); document.addEventListener('webkitfullscreenchange', onFull);
  window.zybFullview = { toggle: toggle, hide: function () { setHidden(true); }, show: function () { setHidden(false); }, full: full, hidden: isHidden };
  // the menus are built after load (zyb-menu / zyb-dash): try a few times, then keep labels in step
  [0, 400, 1500, 4000].forEach(function (ms) { setTimeout(install, ms); });
})();
