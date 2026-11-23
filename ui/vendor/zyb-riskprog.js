// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
/* zyb-riskprog.js - shared by the Enterprise Risk Programme pages (risk-cycle, ras-manage, risk-catalogue, risk-reports): requests to
 * /api/itam marked as handled by the page (zybQuiet), escaping, the signed-in role, messages, tabs and the class / zone colours.
 * Every value that reaches innerHTML goes through esc(). The server decides every permission; the role here only hides buttons. */
(function () {
  'use strict';
  var RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 }, ROLE = 'viewer', ME = '';
  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); }
  function $(id) { return document.getElementById(id); }
  function req(m, u, b) {
    return new Promise(function (ok, bad) {
      var x = new XMLHttpRequest(); x.open(m, '/api/itam' + u); x.withCredentials = true; x.timeout = 120000; x.zybQuiet = true;
      if (b) x.setRequestHeader('Content-Type', 'application/json');
      x.onload = function () { var j = null; try { j = JSON.parse(x.responseText); } catch (e) { j = null; /* not JSON: reported by the status below */ }
        if (x.status >= 200 && x.status < 300 && j) return ok(j);
        bad(Object.assign(new Error(x.status === 401 || x.status === 403 ? ((j && j.error) || 'your role cannot do this') : x.status === 404 && !(j && j.error && /no /.test(j.error)) ? 'the Enterprise Risk Programme is not installed on this server yet - run the update' : (j && j.error) || ('HTTP ' + x.status)), { status: x.status })); };
      x.onerror = x.ontimeout = function () { bad(new Error('IT Asset Management is not reachable')); };
      x.send(b ? JSON.stringify(b) : null);
    });
  }
  function toast(t) { var d = document.createElement('div'); d.className = 'rp-toast'; d.setAttribute('role', 'status'); d.textContent = t; document.body.appendChild(d); setTimeout(function () { d.remove(); }, 5000); }
  function whoami(cb) {
    var w = new XMLHttpRequest(); w.open('GET', '/dashboards/whoami.json'); w.zybQuiet = true;
    w.onload = function () { try { var j = JSON.parse(w.responseText); ROLE = j.role || 'viewer'; ME = j.user || ''; } catch (e) { ROLE = 'viewer'; /* unknown identity: least privilege */ } cb(); };
    w.onerror = function () { cb(); /* no identity: the server still refuses what the role cannot do */ }; w.send();
  }
  function can(r) { return RANK[ROLE] >= RANK[r]; }
  function val(id) { var e = $(id); return e ? String(e.value || '').trim() : ''; }
  var CLS = { 'Class I': '#2fb344', 'Class II': '#6366f1', 'Class III': '#f59f00', 'Class IV': '#e5484d' };
  function pill(text, col) { return '<span class="rp-pill" style="--c:' + esc(col || '#5b6478') + '">' + esc(text) + '</span>'; }
  function cls(c) { return c ? pill(c, CLS[c]) : '<span class="rp-mu">not rated</span>'; }
  function opts(list, cur, label) { return list.map(function (x) { var v = typeof x === 'object' ? x.id : x; return '<option value="' + esc(v) + '"' + (String(v) === String(cur) ? ' selected' : '') + '>' + esc(label ? label(x) : v) + '</option>'; }).join(''); }
  function bar(p, col) { p = Math.max(0, Math.min(100, Number(p) || 0)); return '<span class="rp-bar" role="img" aria-label="' + p + ' %"><i style="width:' + p + '%;background:' + esc(col || '#3fb950') + '"></i></span>'; }
  window.ZRP = { esc: esc, $: $, req: req, toast: toast, whoami: whoami, can: can, me: function () { return ME; }, role: function () { return ROLE; }, val: val, pill: pill, cls: cls, opts: opts, bar: bar, CLS: CLS };
})();
