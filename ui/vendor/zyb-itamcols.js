// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
/* zyb-itamcols.js - four extra columns in IT Asset Management > Inventory, after "Asset":
 *   IP address  the management IP, else the addresses discovery saw (more on hover)
 *   Host        the server a VM runs on (vCenter / Nutanix placement, a link to that asset when it is in the inventory)
 *   VM name     the name in vCenter / Prism, which often differs from the guest host name
 *   Online      Server Availability's ping result when the server is monitored ("Online 12 d 4 h" / "Offline 2 h");
 *               otherwise a VM's power state from the last vCenter / Prism sync; otherwise "Not monitored" - never a guess
 * Data: GET /api/itam/inventory-facts (engine/inventory-facts.js), GET /api/soc/netops/avail/map (servers) and GET
 * /api/soc/netops/devices (switches / routers / firewalls polled by the AI Network Engineer), every 60 s.
 * Works over the existing ITAM page without changing it (rows are found by data-itam-asset). Loaded by zyb-menu.js;
 * when the engine add-on is not installed the columns say so once instead of showing blanks. */
(function () {
  'use strict';
  if (window.__zybItamCols || /^\/dashboards\//.test(location.pathname)) return; window.__zybItamCols = true;
  var FACTS = null, MISSING = false, AV = null, ND = null, BUSY = false, EVERY = 60000;
  function E(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); }
  function get(url) { return new Promise(function (ok) { var x = new XMLHttpRequest(); x.open('GET', url); x.withCredentials = true; x.timeout = 20000; x.onload = function () { var j = null; try { j = JSON.parse(x.responseText); } catch (e) { /* not JSON: treated as no data */ } ok({ status: x.status, j: j }); }; x.onerror = x.ontimeout = function () { ok({ status: 0, j: null }); }; x.send(); }); }
  function ar() { try { return typeof LANG !== 'undefined' && LANG === 'ar'; } catch (e) { return false; } }
  var AR = { 'IP address': 'عنوان IP', 'Host': 'المضيف', 'VM name': 'اسم الجهاز الافتراضي', 'Online': 'الاتصال', 'Online ': 'متصل ', 'Offline ': 'غير متصل ', 'Not monitored': 'غير مراقَب', 'Not checked yet': 'لم يُفحص بعد', 'Powered on': 'قيد التشغيل', 'Powered off': 'متوقف', 'Suspended': 'معلّق', 'Power state unknown': 'حالة التشغيل غير معروفة', 'as of': 'حتى' };
  function T(s) { return ar() && AR[s] ? AR[s] : s; }
  function dur(ms) { var s = Math.max(0, Math.round(ms / 1000)), d = Math.floor(s / 86400), h = Math.floor(s % 86400 / 3600), m = Math.floor(s % 3600 / 60); return d ? d + ' d ' + h + ' h' : h ? h + ' h ' + m + ' m' : m + ' m'; }
  function when(iso) { var t = Date.parse(iso || ''); return isFinite(t) ? new Date(t).toLocaleString() : ''; }
  var CSS = '.zic-ip{font-family:ui-monospace,Consolas,monospace;font-size:11.5px;unicode-bidi:isolate;direction:ltr}.zic-more{color:#9aa4b2;font-size:10.5px;margin-inline-start:4px}'
    + '.zic-on,.zic-off,.zic-un,.zic-pw{display:inline-flex;align-items:center;gap:5px;font:600 11.5px system-ui,sans-serif;white-space:nowrap}.zic-on i,.zic-off i,.zic-un i,.zic-pw i{width:8px;height:8px;border-radius:50%;display:inline-block}'
    + '.zic-on{color:#56d364}.zic-on i{background:#3fb950}.zic-off{color:#ff7b72}.zic-off i{background:#f85149}.zic-un{color:#9aa4b2}.zic-un i{background:#6e7681}.zic-pw{color:#9fd8ff}.zic-pw i{background:#58a6ff}'
    + '.zic-sub{display:block;color:#9aa4b2;font-size:10.5px;font-weight:400;margin-top:2px}.zic-h{color:#79b8ff;cursor:pointer;text-decoration:underline dotted}.zic-note{color:#9aa4b2;font-size:11.5px;margin:4px 0 8px}';
  function css() { if (document.getElementById('zic-css')) return; var s = document.createElement('style'); s.id = 'zic-css'; s.textContent = CSS; document.head.appendChild(s); }

  function root() { return document.getElementById('itam-root'); }
  function nameCell(tr) { var tds = tr.children; for (var i = 0; i < tds.length; i++) if (tds[i].querySelector('b')) return i; return -1; }
  function online(f, ip) {
    var a = ip && AV ? AV[ip] : null, out = '';
    if (!a && ip && ND && ND[ip]) a = ND[ip];   // network device: the AI Network Engineer's last ping
    if (a) out = a.s === 'online' ? '<span class="zic-on"><i></i>' + E(T('Online ')) + (a.since ? '<small>' + E(dur(Date.now() - a.since)) + '</small>' : '') + '</span>'
      : a.s === 'offline' ? '<span class="zic-off"><i></i>' + E(T('Offline ')) + (a.since ? '<small>' + E(dur(Date.now() - a.since)) + '</small>' : '') + '</span>'
      : '<span class="zic-un"><i></i>' + E(T('Not checked yet')) + '</span>';
    if (f && f.power) {
      var p = f.power === 'on' ? T('Powered on') : f.power === 'off' ? T('Powered off') : f.power === 'suspended' ? T('Suspended') : T('Power state unknown');
      var tip = (f.source === 'nutanix' ? 'Nutanix Prism' : 'vCenter') + (f.platform ? ' ' + f.platform : '') + ': ' + (f.power_raw || '') + (f.power_at ? ' - ' + T('as of') + ' ' + when(f.power_at) : '');
      out += a ? '<span class="zic-sub" title="' + E(tip) + '">' + E(p) + '</span>' : '<span class="zic-' + (f.power === 'on' ? 'on' : f.power === 'off' ? 'off' : 'un') + '" title="' + E(tip) + '"><i></i>' + E(p) + '</span>';
    }
    return out || '<span class="zic-un" title="' + E('Add this server to Server Availability to see whether it answers') + '"><i></i>' + E(T('Not monitored')) + '</span>';
  }
  function cells(id) {
    var f = FACTS && FACTS[id], ip = f && f.ip;
    var ipc = ip ? '<bdi class="zic-ip">' + E(ip) + '</bdi>' + (f.ips && f.ips.length > 1 ? '<span class="zic-more" title="' + E(f.ips.join(', ')) + '">+' + (f.ips.length - 1) + '</span>' : '') : '<span class="muted">—</span>';
    var host = f && f.host_name ? (f.host_id ? '<span class="zic-h" data-zic-open="' + E(f.host_id) + '">' + E(f.host_name) + '</span>' : E(f.host_name)) : '<span class="muted">—</span>';
    var vm = f && f.vm_name ? E(f.vm_name) : '<span class="muted">—</span>';
    return [ipc, host, vm, online(f, ip)];
  }
  function paint() {
    var r = root(); if (!r) return;
    var trs = r.querySelectorAll('tr[data-itam-asset]'); if (!trs.length) return;
    css();
    var table = trs[0].closest('table'), idx = nameCell(trs[0]); if (!table || idx < 0) return;
    var head = table.querySelector('thead tr');
    if (head && !head.querySelector('[data-zic]')) {
      var ref = head.children[idx];
      ['IP address', 'Host', 'VM name', 'Online'].slice().reverse().forEach(function (h) { var th = document.createElement('th'); th.setAttribute('data-zic', '1'); th.textContent = T(h); ref.parentNode.insertBefore(th, ref.nextSibling); });
    }
    if (MISSING && !r.querySelector('.zic-note')) { var n = document.createElement('div'); n.className = 'zic-note'; n.textContent = 'Host, VM name and discovered IPs need the inventory-columns engine add-on (run the server update).'; table.parentNode.insertBefore(n, table); }
    [].forEach.call(trs, function (tr) {
      var id = tr.getAttribute('data-itam-asset'), c = cells(id), key = c.join('|'), have = tr.querySelectorAll('td[data-zic]');
      if (have.length === 4) { if (tr.getAttribute('data-zic-k') !== key) { for (var j = 0; j < 4; j++) have[j].innerHTML = c[j]; tr.setAttribute('data-zic-k', key); } return; }
      var i = nameCell(tr); if (i < 0) return;
      var after = tr.children[i];
      c.slice().reverse().forEach(function (h) { var td = document.createElement('td'); td.setAttribute('data-zic', '1'); td.innerHTML = h; after.parentNode.insertBefore(td, after.nextSibling); });
      tr.setAttribute('data-zic-k', key);
    });
  }
  function refresh() {
    if (BUSY || !root()) return; BUSY = true;
    Promise.all([MISSING ? Promise.resolve(null) : get('/api/itam/inventory-facts'), get('/api/soc/netops/avail/map'), get('/api/soc/netops/devices')]).then(function (x) {
      BUSY = false;
      if (x[0]) { if (x[0].status === 404) MISSING = true; else if (x[0].j && x[0].j.assets) FACTS = x[0].j.assets; }
      if (x[1] && x[1].j && x[1].j.hosts) AV = x[1].j.hosts;
      if (x[2] && x[2].j && x[2].j.items) { ND = {}; x[2].j.items.forEach(function (d) { var l = d.last; if (!d.ip) return; ND[d.ip] = !l ? { s: 'unknown' } : { s: l.loss_pct != null && l.loss_pct >= 100 ? 'offline' : l.rtt_ms != null || l.ok ? 'online' : 'offline' }; }); }
      paint();
    });
  }
  // a click on a host name opens that asset's row (the ITAM page opens its drawer on a row click)
  document.addEventListener('click', function (ev) {
    var h = ev.target && ev.target.closest && ev.target.closest('[data-zic-open]'); if (!h) return;
    ev.stopPropagation(); ev.preventDefault();
    var r = root(), tr = r && r.querySelector('tr[data-itam-asset="' + String(h.getAttribute('data-zic-open')).replace(/["\\]/g, '') + '"]');
    if (tr) { tr.scrollIntoView({ block: 'center' }); var b = tr.querySelector('b'); (b || tr).click(); }
  }, true);
  function boot() {
    var t = null, seen = false;
    new MutationObserver(function () {
      var r = root();
      if (!r) { seen = false; return; }
      if (!seen) { seen = true; refresh(); }
      if (!t) t = setTimeout(function () { t = null; paint(); }, 200);
    }).observe(document.body, { childList: true, subtree: true });
    setInterval(refresh, EVERY);
    refresh();
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot); else boot();
})();
