// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
/* zyb-display.js - production display controls on every portal page and dashboard (bottom-left):
 *   ● data freshness   every /api/ answer the page receives is counted: "Live · updated 14:02:31" while answers keep
 *                      arriving, amber when nothing new has come for a while, red when a data source is failing
 *                      (which one, and since when) - so a number on screen is never trusted without its age
 *   ⛶ Full screen      the browser's full screen (Esc leaves)
 *   ⧉ Detach           this page in its own window for a wall screen / second monitor, in wall-display mode
 * Wall-display mode (the detached window, or ?display=1 in any page address):
 *   menus and top bars hidden, the screen kept awake, the page refreshed every N minutes (the data, not just the
 *   picture), a clock, and optionally a rotation through several pages: ?display=1&rotate=<page>,<page>&every=60
 *   (pages by their address, e.g. server-availability.html, /#soc). "Exit" returns to the normal page.
 * Nothing is sent anywhere; the counts come from the answers the page already gets. Loaded by zyb-menu.js (portal
 * pages) and zyb-dash.js (dashboards). */
(function () {
  'use strict';
  if (window.__zybDisplay) return; window.__zybDisplay = true;
  // readable drop-down lists everywhere (portal pages and dashboards): on Windows the open list of a dark <select> was
  // drawn white with light text, so the choices could not be read. Dark list, light text, a visible highlight.
  try {
    var dd = document.createElement('style'); dd.id = 'zyb-select-css';
    dd.textContent = 'select{color-scheme:dark}select option,select optgroup{background-color:#1b2230;color:#eef2f7}'
      + 'select option:checked{background-color:#2f6feb;color:#fff}select option:disabled{color:#8b97ad}';
    (document.head || document.documentElement).appendChild(dd);
  } catch (e) { /* styling only */ }
  var Q = new URLSearchParams(location.search), H = location.hash || '';
  var KIOSK = Q.get('display') === '1' || /(^|[#&])display=1/.test(H);
  var REFRESH_MIN = Math.max(1, Math.min(60, Number(Q.get('refresh')) || 5));
  // rotation pages come from the URL, so anyone can craft the link: keep only pages of this portal (same origin, http/s).
  // A javascript: or outside address would otherwise run script in the portal or send the viewer to another site.
  function sameSite(p) { try { var u = new URL(p, location.href); return (u.protocol === 'https:' || u.protocol === 'http:') && u.origin === location.origin; } catch (e) { return false; } }
  var ROT = (Q.get('rotate') || '').split(',').map(function (s) { return s.trim(); }).filter(Boolean).filter(sameSite).slice(0, 20);
  var EVERY = Math.max(15, Math.min(3600, Number(Q.get('every')) || 60));
  var S = { ok: 0, lastOk: 0, fails: {}, firstAt: Date.now() };

  // ---- watch the page's own API answers (fetch + XMLHttpRequest); nothing is changed or re-sent ----
  function isApi(u) { try { var x = new URL(u, location.href); return x.origin === location.origin && /^\/(api|agent)\//.test(x.pathname); } catch (e) { return false; } }
  function key(u) { try { var x = new URL(u, location.href); return x.pathname.replace(/\/[0-9a-f-]{8,}|\/\d+/gi, '/…').slice(0, 80); } catch (e) { return String(u).slice(0, 80); } }
  function note(u, status) {
    if (!isApi(u)) return;
    var k = key(u);
    if (status >= 200 && status < 400) { S.ok++; S.lastOk = Date.now(); delete S.fails[k]; }
    else if (status !== 401 && status !== 403 && status !== 404) { var f = S.fails[k] || { since: Date.now(), n: 0 }; f.n++; f.status = status; f.at = Date.now(); S.fails[k] = f; }
    paint();
  }
  if (typeof window.fetch === 'function') {
    var of = window.fetch;
    window.fetch = function (input, init) {
      var u = typeof input === 'string' ? input : input && input.url;
      return of.apply(this, arguments).then(function (r) { note(u, r.status); return r; }, function (e) { note(u, 0); throw e; });
    };
  }
  if (window.XMLHttpRequest) {
    var oo = XMLHttpRequest.prototype.open, os = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.open = function (m, u) { this.__zdu = u; return oo.apply(this, arguments); };
    XMLHttpRequest.prototype.send = function () { var x = this; x.addEventListener('loadend', function () { note(x.__zdu, x.status); }); return os.apply(this, arguments); };
  }

  // ---- UI ----
  var CSS = '#zdp{position:fixed;left:12px;bottom:12px;z-index:99990;display:flex;gap:6px;align-items:center;font:600 12px "Segoe UI",system-ui,sans-serif}'
    + '#zdp button,#zdp .zdp-st{background:rgba(16,20,28,.92);color:#e6e9ef;border:1px solid rgba(255,255,255,.16);border-radius:9px;padding:6px 10px;cursor:pointer;font:inherit;min-height:32px}'
    + '#zdp button:hover{border-color:rgba(121,184,255,.7)}#zdp button:focus-visible{outline:2px solid #fff;outline-offset:1px}#zdp .zdp-st{cursor:help;display:inline-flex;align-items:center;gap:7px;font-weight:500}'
    + '#zdp .zdp-st i{width:9px;height:9px;border-radius:50%;display:inline-block;background:#6e7681}#zdp .ok i{background:#3fb950}#zdp .warn i{background:#e3b341}#zdp .bad i{background:#f85149;box-shadow:0 0 0 3px rgba(248,81,73,.3)}'
    + '#zdp .bad{border-color:rgba(248,81,73,.6)}#zdp-pop{position:fixed;left:12px;bottom:56px;z-index:99991;background:#141922;color:#e6e9ef;border:1px solid #2e3440;border-radius:10px;padding:12px 14px;max-width:min(460px,calc(100vw - 24px));font:13px "Segoe UI",system-ui,sans-serif;box-shadow:0 10px 30px rgba(0,0,0,.5)}'
    + '#zdp-pop b{color:#fff}#zdp-pop ul{margin:6px 0 0 18px;padding:0}#zdp-pop .m{color:#9aa4b2;font-size:12px;margin-top:6px}'
    + 'body.zdp-kiosk #zyb-bar,body.zdp-kiosk aside,body.zdp-kiosk .sidebar,body.zdp-kiosk .side,body.zdp-kiosk .topbar,body.zdp-kiosk .app>header,body.zdp-kiosk header.top,body.zdp-kiosk #zyb-menu-btn{display:none!important}'
    + 'body.zdp-kiosk .app{grid-template-columns:1fr!important}body.zdp-kiosk{cursor:default}'
    + '#zdp-clock{position:fixed;right:16px;top:10px;z-index:99990;font:600 15px "Segoe UI",system-ui,sans-serif;color:#e6e9ef;background:rgba(16,20,28,.75);border-radius:8px;padding:4px 10px}'
    + '@media print{#zdp,#zdp-pop,#zdp-clock{display:none!important}}';
  function hhmm(t) { return t ? new Date(t).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) : '—'; }
  function ago(t) { var s = Math.round((Date.now() - t) / 1000); return s < 60 ? s + ' s' : s < 3600 ? Math.round(s / 60) + ' min' : Math.round(s / 3600) + ' h'; }
  function state() {
    var fails = Object.keys(S.fails), age = S.lastOk ? Date.now() - S.lastOk : null;
    if (fails.length) return { cls: 'bad', text: 'Data may be out of date', tip: fails };
    if (!S.lastOk) return { cls: '', text: Date.now() - S.firstAt > 30000 ? 'Waiting for the next update' : 'Loading…' };
    if (age > 15 * 60000) return { cls: 'warn', text: 'Last update ' + ago(S.lastOk) + ' ago' };
    return { cls: 'ok', text: 'Live · updated ' + hhmm(S.lastOk) };
  }
  var box = null, stEl = null;
  function build() {
    if (box || !document.body) return;
    var st = document.createElement('style'); st.id = 'zdp-css'; st.textContent = CSS; document.head.appendChild(st);
    box = document.createElement('div'); box.id = 'zdp'; box.setAttribute('role', 'group'); box.setAttribute('aria-label', 'Display');
    box.innerHTML = '<span class="zdp-st" tabindex="0" role="button" aria-live="polite"><i></i><span></span></span>'
      + '<button type="button" data-zdp="fs" title="Full screen (Esc to leave)" aria-label="Full screen">⛶</button>'
      + (KIOSK ? '<button type="button" data-zdp="exit" title="Leave wall-display mode">Exit display</button>' : '<button type="button" data-zdp="detach" title="Open this page in its own window, for a wall screen or second monitor">⧉ Detach</button>');
    document.body.appendChild(box); stEl = box.querySelector('.zdp-st');
    stEl.onclick = pop; stEl.onkeydown = function (e) { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); pop(); } };
    box.onclick = function (e) {
      var b = e.target.closest && e.target.closest('[data-zdp]'); if (!b) return;
      var a = b.getAttribute('data-zdp');
      if (a === 'fs') { if (document.fullscreenElement) document.exitFullscreen(); else if (document.documentElement.requestFullscreen) document.documentElement.requestFullscreen().catch(function () { /* the browser refused full screen: the page stays as it is */ }); }
      if (a === 'detach') detach();
      if (a === 'exit') { var u = new URL(location.href); u.searchParams.delete('display'); u.searchParams.delete('rotate'); u.searchParams.delete('every'); u.searchParams.delete('refresh'); u.hash = u.hash.replace(/[#&]?display=1/, ''); if (window.opener && !window.opener.closed) window.close(); else location.href = u.toString(); }
    };
    paint();
  }
  function paint() {
    if (!stEl) return;
    var s = state(); stEl.className = 'zdp-st ' + s.cls; stEl.querySelector('span').textContent = s.text;
    stEl.title = s.tip ? 'Not answering: ' + s.tip.join(', ') : 'Every data request on this page answered; click for details';
    if (document.getElementById('zdp-pop')) pop(true);
  }
  function pop(refresh) {
    var p = document.getElementById('zdp-pop');
    if (p && !refresh) { p.remove(); return; }
    if (!p) { p = document.createElement('div'); p.id = 'zdp-pop'; p.setAttribute('role', 'dialog'); p.setAttribute('aria-label', 'Data freshness'); document.body.appendChild(p); }
    var f = Object.keys(S.fails);
    p.innerHTML = '<b>Data freshness on this page</b><div class="m">Last good answer: ' + (S.lastOk ? hhmm(S.lastOk) + ' (' + ago(S.lastOk) + ' ago)' : 'none yet') + ' · ' + S.ok + ' answers since the page opened</div>'
      + (f.length ? '<div style="margin-top:8px;color:#ff7b72">Not answering - figures from these sources may be old:</div><ul>' + f.map(function (k) { var x = S.fails[k]; return '<li><span style="font-family:Consolas,monospace">' + k.replace(/[&<>]/g, '') + '</span> - ' + (x.status ? 'HTTP ' + x.status : 'no connection') + ', since ' + hhmm(x.since) + (x.n > 1 ? ' (' + x.n + ' tries)' : '') + '</li>'; }).join('') + '</ul>' : '<div class="m" style="color:#56d364">Every source answered on its last request.</div>')
      + (KIOSK ? '<div class="m">Wall display: refreshes every ' + REFRESH_MIN + ' min' + (ROT.length ? ', rotating ' + ROT.length + ' pages every ' + EVERY + ' s' : '') + '.</div>' : '<div class="m">Detach opens this page on its own for a wall screen (menus hidden, refreshed every 5 minutes, screen kept awake).</div>');
  }
  function detach() {
    var u = new URL(location.href); u.searchParams.set('display', '1');
    var w = window.open(u.toString(), 'zyb-display-' + Math.random().toString(36).slice(2, 7), 'popup=yes,width=' + Math.min(screen.availWidth || 1600, 1920) + ',height=' + Math.min(screen.availHeight || 900, 1080));
    if (!w) location.href = u.toString();   // pop-up blocked: open it here instead
  }

  // ---- wall-display mode ----
  var lock = null;
  function wake() { try { if (navigator.wakeLock && !document.hidden) navigator.wakeLock.request('screen').then(function (l) { lock = l; }).catch(function () { /* the browser refused to keep the screen awake: the wall still refreshes */ }); } catch (e) { /* not supported */ } }
  function kiosk() {
    document.body.classList.add('zdp-kiosk');
    var c = document.createElement('div'); c.id = 'zdp-clock'; c.setAttribute('aria-hidden', 'true'); document.body.appendChild(c);
    setInterval(function () { c.textContent = new Date().toLocaleString([], { weekday: 'short', hour: '2-digit', minute: '2-digit' }); }, 1000);
    wake(); document.addEventListener('visibilitychange', function () { if (!document.hidden && !lock) wake(); });
    if (ROT.length > 1) {
      var i = Math.max(0, ROT.findIndex(function (p) { return location.href.indexOf(p) >= 0; }));
      setTimeout(function () {
        var next = ROT[(i + 1) % ROT.length], u = new URL(next, location.href);
        if (!sameSite(u.href)) return;
        u.searchParams.set('display', '1'); u.searchParams.set('rotate', ROT.join(',')); u.searchParams.set('every', String(EVERY)); u.searchParams.set('refresh', String(REFRESH_MIN));
        location.href = u.toString();
      }, EVERY * 1000);
    } else {
      // refresh the data, but never while a dialog or an input is in use, and not while the sources are failing
      // (a reload would only replace the last good figures with an error page)
      setInterval(function () {
        var busy = document.activeElement && /INPUT|TEXTAREA|SELECT/.test(document.activeElement.tagName);
        if (!busy && !Object.keys(S.fails).length) location.reload();
      }, REFRESH_MIN * 60000);
    }
  }
  setInterval(paint, 15000);
  function start() { build(); if (KIOSK) kiosk(); }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start); else start();
  window.__zybDisplayState = S;
})();
