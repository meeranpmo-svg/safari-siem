// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
/* zyb-live.js - "Fetch now" for the live VMware / Nutanix counters (ITAM POST /virt/capacity/live: host and VM CPU and
 * memory in use, state, power - read-only) and the "live" line the Virtualization, Capacity and Nutanix VMs pages show.
 *   zybVirtLive.fetch(button, done(report))   fetch now; operator or admin (a viewer is told it needs an operator)
 *   zybVirtLive.line(report)                  "Live counters 10:42:13 (25 s ago) · every 60 s" (HTML-escaped text)
 *   zybVirtLive.newest(report | platform)     the newest read time: a full collection or a live fetch, whichever is later  */
(function () {
  'use strict';
  function ago(t) { var s = Math.max(0, Math.round((Date.now() - Date.parse(t)) / 1000)); return s < 90 ? s + ' s ago' : s < 5400 ? Math.round(s / 60) + ' min ago' : Math.round(s / 3600) + ' h ago'; }
  function line(r) {
    if (!r || !r.platforms) return '';
    var P = r.platforms.filter(function (p) { return p.at; }), L = P.map(function (p) { return p.live_at; }).filter(Boolean).sort();
    var sec = r.settings && r.settings.live_sec, err = P.filter(function (p) { return p.live_error; }).map(function (p) { return p.label + ': ' + p.live_error; });
    var t = L.length ? 'Live counters ' + new Date(L[L.length - 1]).toLocaleTimeString('en-GB') + ' (' + ago(L[L.length - 1]) + ')' : P.length ? 'Live counters not read yet' : '';
    if (t) t += sec ? ' · every ' + Math.max(30, sec) + ' s' : ' · automatic live read off';
    return t + (err.length ? ' · not live: ' + err.join('; ') : '');
  }
  function fetchNow(btn, done) {
    var label = btn ? btn.textContent : '';
    if (btn) { btn.disabled = true; btn.textContent = 'Fetching…'; }
    var x = new XMLHttpRequest(); x.open('POST', '/api/itam/virt/capacity/live'); x.withCredentials = true; x.timeout = 120000; x.setRequestHeader('Content-Type', 'application/json');
    var end = function (msg, r) { if (btn) { btn.disabled = false; btn.textContent = label; } if (msg) toast(msg); if (r && done) done(r); };
    x.onload = function () {
      var j = null; try { j = JSON.parse(x.responseText); } catch (e) { /* not JSON */ }
      if (x.status === 403) return end('Fetching live counters needs an operator or administrator.');
      if (x.status === 404) return end('Live counters are not installed on the server yet - run the update (update-platform.ps1).');
      if (x.status < 200 || x.status >= 300 || !j) return end((j && j.error) || 'Fetch failed (HTTP ' + x.status + ')');
      var res = Array.isArray(j.results) ? j.results : [];
      end(j.results && j.results.skipped ? 'A full collection is running - the counters arrive with it.' : res.length ? res.map(function (r) { return r.label + ': ' + (r.ok ? r.hosts + ' hosts, ' + r.vms + ' VMs updated' : r.error); }).join(' · ') : 'No platform connected.', j.report);
    };
    x.onerror = x.ontimeout = function () { end('IT Asset Management is not reachable'); };
    x.send('{}');
  }
  function toast(t) { var d = document.createElement('div'); d.setAttribute('role', 'status'); d.textContent = t;
    d.style.cssText = 'position:fixed;bottom:16px;left:50%;transform:translateX(-50%);background:#1f242d;color:#ECEEF2;border:1px solid #2e3440;border-radius:9px;padding:9px 14px;z-index:9999;max-width:90vw;font:13px "Segoe UI",system-ui,sans-serif';
    document.body.appendChild(d); setTimeout(function () { d.remove(); }, 7000); }
  // "collected 14 min ago" has to move when Fetch now succeeds: a live fetch re-reads the counters from the same platform
  function newest(x) {
    if (!x) return null;
    var P = x.platforms ? x.platforms : [x], t = [];
    P.forEach(function (p) { if (p.at) t.push(p.at); if (p.live_at) t.push(p.live_at); });
    if (x.last_run && x.last_run.at) t.push(x.last_run.at);
    t = t.filter(function (v) { return !isNaN(Date.parse(v)); }).sort(function (a, b) { return Date.parse(a) - Date.parse(b); });
    return t.length ? t[t.length - 1] : null;
  }
  window.zybVirtLive = { fetch: fetchNow, line: line, newest: newest };
})();
