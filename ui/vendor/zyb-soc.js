// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
/* zyb-soc.js - shared by the SOC dashboard pages (soc-*.html): calls to the SIEM API (/api/soc, the portal session),
 * the signed-in role, and small display helpers. Everything shown comes from the SIEM; when it cannot be reached a page
 * says so and shows nothing else. Writes are allowed for operators / admins and the SIEM enforces the same rules. */
(function () {
  'use strict';
  var Z = window.zybDetail || {}, esc = Z.esc || function (s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); };
  var RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 }, ROLE = 'viewer', USER = '', ready = [];
  function req(m, p, b) {
    return new Promise(function (ok, bad) {
      var x = new XMLHttpRequest(); x.open(m, '/api/soc' + p); x.withCredentials = true; x.timeout = 120000;
      if (b) x.setRequestHeader('Content-Type', 'application/json');
      x.onload = function () { var j = null; try { j = JSON.parse(x.responseText); } catch (e) { /* not JSON */ }
        if (x.status >= 200 && x.status < 300 && j) ok(j);
        else bad(Object.assign(new Error((j && (j.error || (j.errors && j.errors.join('; ')))) || (x.status >= 200 && x.status < 300 ? 'the SIEM did not answer JSON' : 'HTTP ' + x.status)), { status: x.status })); };
      x.onerror = x.ontimeout = function () { bad(Object.assign(new Error('the SIEM is not reachable'), { status: 0 })); };
      x.send(b ? JSON.stringify(b) : null);
    });
  }
  function errHtml(e, what) {
    var t = e.status === 404 ? 'The SIEM on the server does not have ' + (what || 'this') + ' yet - run the update (update-all.ps1).' : e.status === 403 ? 'Your role cannot see this.' : e.status === 401 ? 'Sign in to the portal again.' : e.message;
    return '<p class="err">' + esc(t) + '</p>';
  }
  function toast(t) { var d = document.createElement('div'); d.className = 'toast'; d.setAttribute('role', 'status'); d.textContent = t; document.body.appendChild(d); setTimeout(function () { d.remove(); }, 5000); }
  function ms(v) { if (v == null || v === '' || v === 0) return NaN; if (typeof v === 'number') return v < 1e11 ? v * 1000 : v; var s = String(v); if (/^\d+$/.test(s)) { var n = +s; return n < 1e11 ? n * 1000 : n; } if (/^\d{4}-\d\d-\d\d \d\d:\d\d/.test(s)) s = s.replace(' ', 'T') + 'Z'; return Date.parse(s); }
  function dt(v) { var x = ms(v); if (isNaN(x)) return '–'; return new Date(x).toLocaleString('en-GB', { day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit' }); }
  function ago(v) { var x = ms(v); if (isNaN(x)) return 'never'; var s = Math.max(0, (Date.now() - x) / 1000); return s < 60 ? 'just now' : s < 3600 ? Math.round(s / 60) + ' min ago' : s < 86400 ? Math.round(s / 3600) + ' h ago' : Math.round(s / 86400) + ' d ago'; }
  function n(v) { var x = +v; return isFinite(x) ? Math.round(x).toLocaleString('en-US') : '–'; }
  var SEVN = ['info', 'low', 'medium', 'high', 'critical'];
  function sev(s) { var i = typeof s === 'number' ? Math.max(0, Math.min(4, Math.round(s))) : Math.max(0, SEVN.indexOf(String(s || '').toLowerCase())); return '<span class="pill sev ' + (i >= 4 ? 'bad' : i === 3 ? 'bad' : i === 2 ? 'warn' : 'info') + '">' + SEVN[i] + '</span>'; }
  function pill(t, cls) { return '<span class="pill ' + (cls || '') + '">' + esc(t) + '</span>'; }
  function tile(l, v, s, cls, act) { return '<button type="button" class="t ' + (cls || '') + '"' + (act ? ' data-act="' + esc(act) + '"' : '') + '><div class="l">' + esc(l) + '</div><div class="v">' + esc(String(v)) + '</div><div class="s">' + esc(s || '') + '</div></button>'; }
  function tabs(names) { [].forEach.call(document.querySelectorAll('[data-tab]'), function (b) { b.onclick = function () { show(b.getAttribute('data-tab')); }; }); function show(t) { [].forEach.call(document.querySelectorAll('[data-tab]'), function (b) { b.classList.toggle('on', b.getAttribute('data-tab') === t); }); names.forEach(function (x) { var el = document.getElementById('tab-' + x); if (el) el.hidden = x !== t; }); try { history.replaceState(null, '', '#' + t); } catch (e) { /* file */ } } var h = (location.hash || '').slice(1); if (names.indexOf(h) >= 0) show(h); return show; }
  var w = new XMLHttpRequest(); w.open('GET', '/dashboards/whoami.json');
  var done = function () { var f = ready; ready = null; f.forEach(function (fn) { fn(); }); };
  w.onload = function () { try { var j = JSON.parse(w.responseText); var r = String(j.role || '').toLowerCase(); if (RANK[r] != null) ROLE = r; USER = String(j.user || j.username || ''); } catch (e) { /* viewer */ } done(); };
  w.onerror = done; w.send();
  window.zybSoc = {
    req: req, errHtml: errHtml, toast: toast, dt: dt, ago: ago, n: n, sev: sev, pill: pill, tile: tile, tabs: tabs, esc: esc, ms: ms,
    can: function (r) { return RANK[ROLE] >= RANK[r]; }, role: function () { return ROLE; }, user: function () { return USER; },
    ready: function (fn) { if (ready) ready.push(fn); else fn(); },
  };
})();
