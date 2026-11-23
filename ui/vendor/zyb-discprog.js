// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
/* zyb-discprog.js - live progress of Asset Discovery scans on the Asset Discovery page: which scope, what it is doing
 * (directories / ping / probing addresses / reading SNMP), addresses done of total, devices answering, devices found,
 * time running, speed and estimated time left, and Cancel for admins. Reads GET /api/itam/discovery/runs every 3 s
 * while a scan runs (every 20 s otherwise); a finished scan stays on the panel for 10 minutes with its result.
 * Loaded by zyb-menu.js. */
(function () {
  'use strict';
  if (window.__zybDiscProg) return; window.__zybDiscProg = true;
  var API = '/api/itam/discovery', RUNS = [], ADMIN = null, TIMER = null, HIDE = {}, LAST = 0;
  var PH = { ping: 'Ping sweep', probe: 'Probing addresses (ports + SNMP)', snmp: 'Reading device details over SNMP' };
  var MN = { ad: 'Active Directory', vcenter: 'vCenter', cucm: 'Cisco CUCM', azure: 'Azure', aws: 'AWS', arp: 'ARP table', hyperv: 'Hyper-V', icmp: 'Ping', sweep: 'Port probe', snmp: 'SNMP', arp_snmp: 'MACs from ARP tables' };
  function E(v) { return String(v == null ? '' : v).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); }
  function req(m, p) { return fetch(API + p, { method: m, credentials: 'include', cache: 'no-store', headers: { 'Content-Type': 'application/json' }, body: m === 'POST' ? '{}' : undefined }).then(function (r) { return r.json().catch(function () { return {}; }).then(function (j) { if (!r.ok) throw new Error(j.error || ('HTTP ' + r.status)); return j; }); }); }
  function dur(s) { s = Math.max(0, Math.round(s)); var h = Math.floor(s / 3600), m = Math.floor(s % 3600 / 60), x = s % 60; return h ? h + ' h ' + m + ' min' : m ? m + ' min ' + x + ' s' : x + ' s'; }
  function onPage() { return !!document.getElementById('dsc-root'); }
  function css() {
    if (document.getElementById('zdp-css')) return;
    var s = document.createElement('style'); s.id = 'zdp-css';
    s.textContent = '#zdp{position:fixed;right:16px;bottom:16px;z-index:9999;width:min(420px,calc(100vw - 32px));max-height:70vh;overflow:auto;background:var(--panel,#13151B);color:var(--txt,#ECEEF2);border:1px solid var(--line,#2E3440);border-radius:12px;box-shadow:0 12px 40px rgba(0,0,0,.45);font:13px/1.45 "Segoe UI",system-ui,sans-serif}'
      + '#zdp .hd{display:flex;align-items:center;gap:8px;padding:10px 12px;border-bottom:1px solid var(--line,#2E3440);font-weight:700}#zdp .hd span{flex:1}#zdp button{border:1px solid var(--line,#2E3440);background:transparent;color:inherit;border-radius:6px;padding:3px 9px;cursor:pointer;font-size:12px}'
      + '#zdp .run{padding:10px 12px;border-bottom:1px solid rgba(255,255,255,.06)}#zdp .run:last-child{border-bottom:0}#zdp .bar{height:8px;border-radius:5px;background:rgba(255,255,255,.08);overflow:hidden;margin:6px 0}#zdp .bar i{display:block;height:100%;background:#3fb950;transition:width .6s}'
      + '#zdp .m{color:var(--muted,#8C93A1);font-size:11.5px}#zdp .g{display:grid;grid-template-columns:repeat(3,1fr);gap:6px;margin-top:6px}#zdp .g b{display:block;font-size:15px}#zdp .ok{color:#56d364}#zdp .bad{color:#ff7b72}#zdp.min .run{display:none}';
    document.head.appendChild(s);
  }
  function view(r) {
    var p = r.progress || {}, now = Date.now(), t0 = Date.parse(r.started_at) || now, el = ((r.finished_at ? Date.parse(r.finished_at) : now) - t0) / 1000;
    var running = r.status === 'running', snmp = p.phase === 'snmp' && p.snmp_total, done = snmp ? p.snmp_done || 0 : p.hosts_done || 0, total = snmp ? p.snmp_total : p.hosts_total || 0;
    var pct = total ? Math.min(100, Math.round(done * 100 / total)) : (running ? 0 : 100);
    var rate = !snmp && p.hosts_done && el > 5 ? p.hosts_done / el : null, left = rate && total ? (total - done) / rate : null;
    var stats = Object.keys(r.stats || {}).map(function (k) { var s = r.stats[k] || {}; return (MN[k] || k) + ': ' + (s.ok === false ? '<span class="bad">' + E(s.error_class || 'failed') + '</span>' : '<span class="ok">' + E(String(s.seen != null ? s.seen : s.alive != null ? s.alive : s.responders != null ? s.responders + ' answered' : s.collected != null ? s.collected : s.joined != null ? s.joined : 'done')) + '</span>'); }).join(' · ');
    var phase = running ? (PH[p.phase] || (total ? 'Scanning addresses' : 'Reading directories (AD / vCenter / cloud)')) : r.status === 'completed' ? 'Finished' : r.status === 'cancelled' ? 'Cancelled' : r.status === 'window_closed' ? 'Stopped: outside the scan window' : (r.status || 'done');
    return '<div class="run" data-run="' + E(r.id) + '"><div style="display:flex;gap:8px;align-items:center"><b style="flex:1">' + E(r.scope_name || r.scope_id) + '</b>'
      + (running && ADMIN ? '<button type="button" data-zdp-cancel="' + E(r.id) + '">Cancel</button>' : '') + (!running ? '<button type="button" data-zdp-hide="' + E(r.id) + '" title="Hide">✕</button>' : '') + '</div>'
      + '<div class="m">' + E(phase) + (r.site ? ' · ' + E(r.site) : '') + '</div>'
      + (total || running ? '<div class="bar"><i style="width:' + pct + '%;' + (running ? '' : 'background:#58a6ff') + '"></i></div><div class="m">' + (total ? done + ' of ' + total + (snmp ? ' devices read' : ' addresses') + ' · ' + pct + '%' : 'working…') + '</div>' : '')
      + '<div class="g"><div><b>' + (p.alive != null ? p.alive : '–') + '</b><span class="m">answering</span></div><div><b>' + (r.devices_seen || 0) + '</b><span class="m">devices found</span></div><div><b>' + (r.devices_new || 0) + '</b><span class="m">new</span></div></div>'
      + '<div class="m" style="margin-top:6px">running ' + dur(el) + (rate ? ' · ' + rate.toFixed(1) + ' addresses/s' : '') + (left != null && running ? ' · about ' + dur(left) + ' left' : '') + '</div>'
      + (stats ? '<div class="m" style="margin-top:4px">' + stats + '</div>' : '')
      + ((r.methods_blocked || []).length ? '<div class="m" style="margin-top:4px">not run: ' + r.methods_blocked.map(function (b) { return E((MN[b.method] || b.method) + ' (' + b.reason + ')'); }).join('; ') + '</div>' : '') + '</div>';
  }
  function draw() {
    var box = document.getElementById('zdp');
    var show = RUNS.filter(function (r) { return !HIDE[r.id] && (r.status === 'running' || (r.finished_at && Date.now() - Date.parse(r.finished_at) < 10 * 60000)); });
    if (!onPage() || !show.length) { if (box) box.remove(); return; }
    css();
    if (!box) { box = document.createElement('div'); box.id = 'zdp'; box.setAttribute('role', 'status'); box.setAttribute('aria-live', 'polite'); document.body.appendChild(box); }
    var n = show.filter(function (r) { return r.status === 'running'; }).length;
    box.innerHTML = '<div class="hd"><span>🔎 Discovery ' + (n ? n + ' scan' + (n > 1 ? 's' : '') + ' running' : 'finished') + '</span><button type="button" data-zdp-min>' + (box.classList.contains('min') ? '▴' : '▾') + '</button></div>' + show.map(view).join('');
  }
  function poll() {
    if (!onPage()) { draw(); schedule(5000); return; }
    req('GET', '/runs?limit=10').then(function (j) { RUNS = (j && j.runs) || []; draw(); }).catch(function () { /* not reachable / no rights */ })
      .then(function () { schedule(RUNS.some(function (r) { return r.status === 'running'; }) ? 3000 : 20000); });
  }
  function schedule(ms) { clearTimeout(TIMER); TIMER = setTimeout(poll, document.hidden ? Math.max(ms, 15000) : ms); }
  document.addEventListener('click', function (e) {
    var t = e.target; if (!t || !t.closest) return;
    var c = t.closest('[data-zdp-cancel]'); if (c) { if (!confirm('Cancel this discovery scan? Devices found so far are kept.')) return; c.disabled = true; req('POST', '/runs/' + encodeURIComponent(c.getAttribute('data-zdp-cancel')) + '/cancel').then(poll, function (er) { c.disabled = false; alert(er.message); }); return; }
    var h = t.closest('[data-zdp-hide]'); if (h) { HIDE[h.getAttribute('data-zdp-hide')] = 1; draw(); return; }
    if (t.closest('[data-zdp-min]')) { var b = document.getElementById('zdp'); if (b) { b.classList.toggle('min'); draw(); } return; }
    // a scope was just started: look right away
    if (t.closest('[data-dsc-run], [data-dsc-scope-run]') || /\bRun\b/.test((t.closest('button') || {}).textContent || '')) { if (Date.now() - LAST > 1000) { LAST = Date.now(); setTimeout(poll, 1200); } }
  }, true);
  /* a link to the vCenter / Nutanix platforms page right above the Asset Discovery page (those platforms feed it) */
  function platformsLink() {
    var root = document.getElementById('dsc-root'); if (!root || document.getElementById('zdp-virt')) return;
    var b = document.createElement('div'); b.id = 'zdp-virt';
    b.style.cssText = 'display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin:0 0 10px;padding:9px 12px;border:1px solid var(--line,#2E3440);border-radius:10px;background:var(--panel,#13151B);font:13px "Segoe UI",system-ui,sans-serif';
    b.innerHTML = '<span style="flex:1;min-width:200px">🖥️ <b>VMware vCenter &amp; Nutanix Prism</b> <span style="color:var(--muted,#8C93A1)">— add any number of vCenters and Nutanix Prism here; their hosts and VMs come into these results and the inventory automatically.</span></span><a href="/dashboards/virtualization.html" style="padding:6px 12px;border-radius:7px;border:1px solid var(--line,#2E3440);color:inherit;text-decoration:none;font-weight:600">Open platforms →</a>';
    root.parentNode.insertBefore(b, root);
  }
  setInterval(platformsLink, 1500);
  fetch('/api/itam/status', { credentials: 'include' }).then(function (r) { return r.json(); }).then(function (j) { ADMIN = !!(j && j.me && j.me.role === 'admin'); }).catch(function () { ADMIN = false; });
  poll();
})();
