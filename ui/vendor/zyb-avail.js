// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
/* zyb-avail.js - live server status inside portal lists (e.g. Asset Discovery results). Loaded by zyb-menu.js.
 * Wherever a page shows a list of IP addresses (3 or more), each IP gets: a coloured status ("Online 12 d 4 h" /
 * "Offline 2 h"), and buttons: Details (opens Server Availability), Check now (operator), or Monitor (admin, when the
 * server is not monitored yet). Data: /api/soc/netops/avail/map, refreshed every 60 s. */
(function () {
  'use strict';
  if (window.__zybAvail || /^\/dashboards\//.test(location.pathname)) return; window.__zybAvail = true;
  var API = '/api/soc/netops/avail', MAP = null, ROLE = 'viewer', RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 }, IPRE = /^\s*(\d{1,3}(?:\.\d{1,3}){3})\s*$/;
  function can(r) { return RANK[ROLE] >= RANK[r]; }
  function req(m, p, b) { return new Promise(function (ok, bad) { var x = new XMLHttpRequest(); x.open(m, API + p); x.withCredentials = true; x.timeout = 15000; if (b) x.setRequestHeader('Content-Type', 'application/json'); x.onload = function () { var j = null; try { j = JSON.parse(x.responseText); } catch (e) { /* not JSON: treated as no data */ } if (x.status >= 200 && x.status < 300) ok(j); else bad(new Error((j && j.error) || 'HTTP ' + x.status)); }; x.onerror = x.ontimeout = function () { bad(new Error('SIEM not reachable')); }; x.send(b ? JSON.stringify(b) : null); }); }
  function dur(ms) { var s = Math.max(0, Math.round(ms / 1000)), d = Math.floor(s / 86400), h = Math.floor(s % 86400 / 3600), m = Math.floor(s % 3600 / 60); return d ? d + ' d ' + h + ' h' : h ? h + ' h ' + m + ' m' : m + ' m'; }
  var CSS = '.zav{display:flex;align-items:center;gap:6px;flex-wrap:wrap;margin-top:4px;font:600 11.5px system-ui,-apple-system,"Segoe UI",sans-serif;white-space:nowrap}'
    + '.zav .d{width:8px;height:8px;border-radius:50%;display:inline-block}.zav.on .d{background:#3fb950}.zav.off .d{background:#f85149;box-shadow:0 0 0 3px rgba(248,81,73,.25)}.zav.un .d{background:#6e7681}'
    + '.zav.on .l{color:#56d364}.zav.off .l{color:#ff7b72}.zav.un .l{color:#9aa4b2}.zav .l small{font-weight:400;opacity:.8}'
    + '.zav button{font:600 11px system-ui,sans-serif;padding:2px 8px;border-radius:6px;border:1px solid rgba(255,255,255,.18);background:rgba(255,255,255,.06);color:inherit;cursor:pointer}.zav button:hover{border-color:rgba(255,255,255,.4)}.zav button:focus-visible{outline:2px solid #fff;outline-offset:1px}'
    + '.zav-toast{position:fixed;bottom:16px;left:50%;transform:translateX(-50%);background:#1f242d;color:#e6e9ef;border:1px solid #2e3440;border-radius:9px;padding:9px 14px;z-index:99999;font:13px system-ui,sans-serif}';
  function toast(t) { var d = document.createElement('div'); d.className = 'zav-toast'; d.textContent = t; document.body.appendChild(d); setTimeout(function () { d.remove(); }, 4000); }
  function css() { if (document.getElementById('zav-css')) return; var s = document.createElement('style'); s.id = 'zav-css'; s.textContent = CSS; document.head.appendChild(s); }
  function ipCells() {
    var out = [];
    [].forEach.call(document.querySelectorAll('[data-zav-ip]'), function (el) { if (el.offsetParent) out.push([el, el.getAttribute('data-zav-ip')]); });
    [].forEach.call(document.querySelectorAll('td,div,span,code'), function (el) {
      if (el.hasAttribute('data-zav-ip') || el.children.length || el.closest('nav,aside,ul.nav,#zd,.zav,#zyb-home,#zyb-sla')) return;
      var m = IPRE.exec(el.textContent || ''); if (m && el.offsetParent) out.push([el, m[1]]);
    });
    return out;
  }
  function rowName(el) { // the first text cell of the same row, used as the server name when adding it
    var row = el.closest('tr') || (el.parentElement && el.parentElement.parentElement); if (!row) return '';
    var first = row.querySelector('td,div'); var t = first ? first.firstChild && first.firstChild.nodeType === 3 ? first.firstChild.nodeValue.trim() : first.textContent.trim() : ''; return IPRE.test(t) ? '' : t.slice(0, 120);
  }
  function badge(ip, el) {
    el.setAttribute('data-zav-ip', ip);
    var inside = el.tagName === 'TD'; // a bare table cell: the badge goes inside it (never between cells)
    var s = MAP[ip], b = inside ? el.querySelector(':scope > .zav') : (el.nextElementSibling && el.nextElementSibling.classList.contains('zav') ? el.nextElementSibling : null);
    var cls = !s ? 'un' : s.s === 'online' ? 'on' : s.s === 'offline' ? 'off' : 'un';
    var label = !s ? 'Not monitored' : s.s === 'unknown' ? 'Not checked yet' : (s.s === 'online' ? 'Online' : 'Offline') + (s.since ? ' <small>' + dur(Date.now() - s.since) + '</small>' : '');
    var html = '<span class="d"></span><span class="l">' + label + '</span>' + (s ? '<button type="button" data-zav="det">Details</button>' + (can('operator') ? '<button type="button" data-zav="chk">Check now</button>' : '') : (can('admin') ? '<button type="button" data-zav="add">Monitor</button>' : ''));
    if (!b) { b = document.createElement('div'); if (inside) el.appendChild(b); else el.parentNode.insertBefore(b, el.nextSibling); }
    b.className = 'zav ' + cls; b.setAttribute('data-ip', ip); if (b.innerHTML !== html) b.innerHTML = html;
  }
  var busy = false;
  function paint() {
    if (!MAP || busy) return; busy = true;
    try { var cells = ipCells(); if (cells.length >= 3) { css(); cells.forEach(function (c) { badge(c[1], c[0]); }); } } finally { setTimeout(function () { busy = false; }, 0); }
  }
  document.addEventListener('click', function (e) {
    var b = e.target.closest('.zav button'); if (!b) return; e.preventDefault(); e.stopPropagation();
    var box = b.closest('.zav'), ip = box.getAttribute('data-ip'), a = b.getAttribute('data-zav'), host = box.parentElement && box.parentElement.closest('[data-zav-ip]') || box.previousElementSibling;
    if (a === 'det') { window.open('/dashboards/server-availability.html#' + encodeURIComponent(ip), '_blank', 'noopener'); return; }
    if (a === 'chk') { b.disabled = true; req('GET', '').then(function (v) { var h = v.items.filter(function (x) { return x.ip === ip; })[0]; return h ? req('POST', '/hosts/' + encodeURIComponent(h.id) + '/check') : null; }).then(function (s) { if (s) { MAP[ip] = { s: s.status, since: s.since }; toast(ip + ' is ' + s.status); paint(); } }).catch(function (er) { toast(er.message); b.disabled = false; }); return; }
    if (a === 'add') { var name = host ? rowName(host) : ''; b.disabled = true; req('POST', '/hosts', { ip: ip, name: name || ip }).then(function (h) { MAP[ip] = { s: 'unknown' }; paint(); toast((h.name || ip) + ' added — first check within a minute'); }).catch(function (er) { toast(er.message); b.disabled = false; }); }
  }, true);
  function refresh() { req('GET', '/map').then(function (j) { MAP = (j && j.hosts) || {}; paint(); }).catch(function () { /* a background refresh: the panel keeps its last state and the next refresh retries */ }); }
  function boot() {
    var x = new XMLHttpRequest(); x.open('GET', '/dashboards/whoami.json'); x.onload = function () { try { var j = JSON.parse(x.responseText); var rl = String(j.role || '').toLowerCase(); if (RANK[rl] != null) ROLE = rl; } catch (e) { /* not JSON: treated as no data */ } refresh(); }; x.onerror = refresh; x.send();
    setInterval(function () { if (!document.hidden) refresh(); }, 60000);
    var t = null; new MutationObserver(function (ms) { for (var i = 0; i < ms.length; i++) { if (ms[i].target.closest && ms[i].target.closest('.zav')) continue; if (!t) t = setTimeout(function () { t = null; paint(); }, 600); return; } }).observe(document.body, { childList: true, subtree: true });
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot); else boot();
})();
