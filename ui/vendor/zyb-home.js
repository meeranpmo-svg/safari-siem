// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
/* zyb-home.js - portal home page additions, loaded by zyb-menu.js on every portal page; acts only where the
 * "Good morning / afternoon / evening" greeting is shown:
 *   - the signed-in user's name under the greeting (from /dashboards/whoami.json, set by nginx from the portal login)
 *   - this server's CPU, memory and log storage, the SIEM's total log size and daily log flow, and the city temperature (from /dashboards/sysinfo.json, written every
 *     30 s by zyb-sysinfo on the server). Refreshes every 30 s while the home page is open. */
(function () {
  'use strict';
  if (window.__zybHome) return; window.__zybHome = true;
  var GREET = /^\s*(good\s+(morning|afternoon|evening)|صباح الخير|مساء الخير)\b/i;
  var who = null, whoTried = false, info = null, infoErr = '', timer = null, webTemp = null, webTried = false;

  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); }
  function gb(b) { var t = b / 1073741824; return t >= 1024 ? (t / 1024).toFixed(2) + ' TB' : t >= 100 ? t.toFixed(0) + ' GB' : t.toFixed(1) + ' GB'; }
  function lvl(p) { return p >= 90 ? 'crit' : p >= 75 ? 'warn' : 'ok'; }
  function dur(s) { var d = Math.floor(s / 86400), h = Math.floor(s % 86400 / 3600); return d ? d + ' d ' + h + ' h' : h + ' h ' + Math.floor(s % 3600 / 60) + ' m'; }
  function big(n) { n = Number(n) || 0; return n >= 1e9 ? (n / 1e9).toFixed(2) + ' B' : n >= 1e6 ? (n / 1e6).toFixed(1) + ' M' : n >= 1e3 ? (n / 1e3).toFixed(1) + ' K' : String(Math.round(n)); }
  function siemTile(sm, logDisk) {
    if (!sm) return '<div class="zh-t zh-w"><div class="zh-k"><span>SIEM logs</span></div><div class="zh-s">Log size not collected yet: the server stats job has no SIEM reader - run the update (update-platform.ps1).</div></div>';
    if (sm.error) return '<div class="zh-t zh-w"><div class="zh-k"><span>SIEM logs</span></div><div class="zh-s">Log size unavailable: ' + esc(sm.error) + '</div></div>';
    var days = sm.days || [], today = new Date().toISOString().slice(0, 10), td = null, yd = null;
    days.forEach(function (d) { if (d.day === today) td = d; });
    if (days.length > 1) yd = days[days.length - (td ? 2 : 1)];
    var full = days.filter(function (d) { return d.day !== today; }), avg = full.length ? full.reduce(function (a, d) { return a + d.events; }, 0) / full.length : 0;
    var avgB = full.length ? full.reduce(function (a, d) { return a + d.bytes; }, 0) / full.length : 0;
    var ratio = sm.events && sm.events.raw ? sm.events.disk / sm.events.raw : 0.15, perDay = avgB * ratio;
    var left = logDisk && perDay > 0 ? Math.floor(logDisk.avail / perDay) : null;
    var mx = Math.max.apply(null, days.map(function (d) { return d.events; }).concat([1]));
    var bars = days.map(function (d) { return '<i class="' + (d.day === today ? 'td' : '') + '" style="height:' + Math.max(2, d.events / mx * 100).toFixed(1) + '%" title="' + esc(d.day + ': ' + d.events.toLocaleString() + ' events, ' + gb(d.bytes) + ' received, ' + d.sources + ' sources' + (d.errors ? ', ' + d.errors.toLocaleString() + ' parse errors' : '')) + '"></i>'; }).join('');
    var oldestDays = sm.oldest ? Math.round((Date.now() - Date.parse(sm.oldest + 'T00:00:00Z')) / 864e5) : null;
    return '<div class="zh-t zh-w"><div class="zh-k"><span>SIEM logs · daily flow</span><span>' + esc(sm.db) + '</span></div>'
      + '<div class="zh-row"><div><b>' + gb((sm.total || {}).disk || 0) + '</b><span>stored on disk</span></div>'
      + '<div><b>' + big((sm.events || {}).rows) + '</b><span>events kept</span></div>'
      + '<div><b>' + (td ? big(td.events) : '0') + '</b><span>today so far</span></div>'
      + (yd ? '<div><b>' + big(yd.events) + '</b><span>yesterday</span></div>' : '')
      + '<div><b>' + big(avg) + '</b><span>per day (average)</span></div></div>'
      + '<div class="zh-ch" role="img" aria-label="Events per day, last ' + days.length + ' days">' + bars + '</div>'
      + '<div class="zh-ax"><span>' + esc(days.length ? days[0].day.slice(5) : '') + '</span><span>today</span></div>'
      + '<div class="zh-s">' + (oldestDays != null ? 'Oldest log ' + esc(sm.oldest) + ' (' + oldestDays + ' of ' + sm.retention_days + ' days kept)' : 'Keeping ' + sm.retention_days + ' days')
      + (left != null ? ' · ' + (left < 30 ? '<span class="t-crit">' : left < 90 ? '<span class="t-warn">' : '<span>') + 'log disk full in about ' + (left > 999 ? '999+' : left) + ' days at this rate</span>' : '')
      + (yd && yd.errors ? ' · ' + yd.errors.toLocaleString() + ' parse errors yesterday' : '') + '</div></div>';
  }
  function pretty(login) {
    var base = String(login).split('@')[0].split('\\').pop();
    return base.split(/[._-]+/).filter(Boolean).map(function (w) { return w.charAt(0).toUpperCase() + w.slice(1); }).join(' ') || base;
  }
  var ROLE = { admin: 'Administrator', operator: 'Operator', analyst: 'Analyst', viewer: 'Viewer' };
  var WMO = [[0, 'Clear sky', '☀️'], [1, 'Mainly clear', '🌤️'], [2, 'Partly cloudy', '⛅'], [3, 'Overcast', '☁️'], [48, 'Fog', '🌫️'], [57, 'Drizzle', '🌦️'], [67, 'Rain', '🌧️'], [77, 'Snow', '🌨️'], [82, 'Rain showers', '🌦️'], [86, 'Snow showers', '🌨️'], [99, 'Thunderstorm', '⛈️']];
  function wx(code) { if (code == null) return ['', '🌡️']; for (var i = 0; i < WMO.length; i++) if (code <= WMO[i][0]) return [WMO[i][1], WMO[i][2]]; return ['', '🌡️']; }

  function getJSON(url, ms) {
    return new Promise(function (ok, bad) {
      var x = new XMLHttpRequest(), t = setTimeout(function () { x.abort(); bad(new Error('timeout')); }, ms || 6000);
      x.open('GET', url + (url.indexOf('?') < 0 ? '?' : '&') + '_=' + Date.now()); x.withCredentials = url.charAt(0) === '/';
      x.onload = function () { clearTimeout(t); if (x.status !== 200) return bad(new Error('HTTP ' + x.status)); try { ok(JSON.parse(x.responseText)); } catch (e) { bad(e); } };
      x.onerror = function () { clearTimeout(t); bad(new Error('network')); };
      x.send();
    });
  }
  function loadWho() {
    if (whoTried) return; whoTried = true;
    getJSON('/dashboards/whoami.json').then(function (j) { if (j && j.user) who = j; draw(); })
      .catch(function () { getJSON('/api/soc/ui/menu').then(function (j) { if (j && j.user) who = { user: j.user, role: j.can_edit_order ? 'admin' : '' }; draw(); }).catch(function () { /* identity unknown: treated as signed out of the menu extras */ }); });
  }
  function loadInfo() {
    getJSON('/dashboards/sysinfo.json').then(function (j) { info = j; infoErr = ''; draw(); if (j.weather && j.weather.temp == null) loadWebTemp(j.weather.city); })
      .catch(function (e) { infoErr = /404/.test(e.message) ? 'missing' : 'error'; draw(); });
  }
  /* the server may have no internet; try the temperature from the browser instead (once) */
  function loadWebTemp() {
    if (webTried) return; webTried = true;
    getJSON('https://api.open-meteo.com/v1/forecast?latitude=24.7136&longitude=46.6753&current=temperature_2m,relative_humidity_2m,apparent_temperature,weather_code', 5000)
      .then(function (j) { var c = j && j.current; if (c && c.temperature_2m != null) { webTemp = { temp: c.temperature_2m, feels: c.apparent_temperature, humidity: c.relative_humidity_2m, code: c.weather_code }; draw(); } })
      .catch(function () { /* weather is optional: the tile stays empty */ });
  }

  var CSS = '#zyb-who{margin:6px 0 2px;display:flex;align-items:center;gap:10px;flex-wrap:wrap}'
    + '#zyb-who .zw-n{font-size:1.25em;font-weight:700;color:inherit;letter-spacing:.01em}'
    + '#zyb-who .zw-r{font:600 11px/1 system-ui,-apple-system,"Segoe UI",sans-serif;padding:4px 8px;border-radius:999px;background:rgba(215,38,45,.16);color:#ff8a8f;border:1px solid rgba(215,38,45,.35)}'
    + '#zyb-who .zw-l{font-size:12px;opacity:.65}'
    + '#zyb-home{margin:14px 0;padding:14px;border:1px solid rgba(255,255,255,.09);border-radius:12px;background:rgba(255,255,255,.025);font-family:system-ui,-apple-system,"Segoe UI",sans-serif;color:inherit}'
    + '#zyb-home .zh-h{display:flex;align-items:baseline;gap:10px;flex-wrap:wrap;margin:0 0 12px}#zyb-home .zh-h b{font-size:14px}#zyb-home .zh-h span{font-size:12px;opacity:.6}#zyb-home .zh-h .zh-sp{flex:1}'
    + '#zyb-home .zh-g{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:10px}'
    + '#zyb-home .zh-t{border:1px solid rgba(255,255,255,.08);border-radius:10px;padding:12px;background:rgba(0,0,0,.18);min-width:0}'
    + '#zyb-home .zh-k{font-size:11px;text-transform:uppercase;letter-spacing:.07em;opacity:.65;display:flex;justify-content:space-between;gap:8px}'
    + '#zyb-home .zh-v{font-size:26px;font-weight:700;margin:4px 0 6px;font-variant-numeric:tabular-nums;line-height:1.1}#zyb-home .zh-v small{font-size:13px;font-weight:600;opacity:.7;margin-left:3px}'
    + '#zyb-home .zh-b{height:6px;border-radius:3px;background:rgba(255,255,255,.08);overflow:hidden}#zyb-home .zh-b i{display:block;height:100%;border-radius:3px}'
    + '#zyb-home .ok{background:#3fb950}#zyb-home .warn{background:#d29922}#zyb-home .crit{background:#f85149}#zyb-home .t-ok{color:#56d364}#zyb-home .t-warn{color:#e3b341}#zyb-home .t-crit{color:#ff7b72}'
    + '#zyb-home .zh-s{font-size:12px;opacity:.7;margin-top:6px;overflow-wrap:anywhere}#zyb-home .zh-d{margin-top:8px;display:grid;gap:6px}#zyb-home .zh-d div{font-size:11.5px;opacity:.8;display:grid;grid-template-columns:minmax(0,1fr) auto;gap:2px 8px}'
    + '#zyb-home .zh-d .zh-b{grid-column:1/-1;height:4px}#zyb-home .zh-m{font-size:12.5px;opacity:.75}'
    + '#zyb-home .zh-w{grid-column:span 2}@media (max-width:720px){#zyb-home .zh-w{grid-column:auto}}'
    + '#zyb-home .zh-row{display:flex;gap:16px;flex-wrap:wrap;margin:2px 0 8px}#zyb-home .zh-row div{min-width:0}#zyb-home .zh-row b{display:block;font-size:20px;font-variant-numeric:tabular-nums}#zyb-home .zh-row span{font-size:11px;opacity:.65}'
    + '#zyb-home .zh-ch{display:flex;align-items:flex-end;gap:3px;height:64px;margin-top:4px}#zyb-home .zh-ch i{flex:1;min-width:4px;background:#3987e5;border-radius:2px 2px 0 0;opacity:.85}#zyb-home .zh-ch i.td{background:#d7262d}#zyb-home .zh-ch i:hover{opacity:1}'
    + '#zyb-home .zh-ax{display:flex;justify-content:space-between;font-size:10.5px;opacity:.55;margin-top:3px}';

  function tile(label, value, unit, pct, sub, extra) {
    var l = pct == null ? '' : lvl(pct);
    return '<div class="zh-t"><div class="zh-k"><span>' + label + '</span>' + (extra || '') + '</div><div class="zh-v' + (l ? ' t-' + l : '') + '">' + value + (unit ? '<small>' + unit + '</small>' : '') + '</div>'
      + (pct == null ? '' : '<div class="zh-b"><i class="' + l + '" style="width:' + Math.min(100, Math.max(0, pct)).toFixed(1) + '%"></i></div>') + '<div class="zh-s">' + sub + '</div></div>';
  }
  function panelHTML() {
    if (infoErr === 'missing') return '<div class="zh-m">Server stats are not installed yet. On the server run: <code>sudo bash install-sysinfo.sh</code></div>';
    if (!info) return '<div class="zh-m">' + (infoErr ? 'Server stats are unavailable right now.' : 'Loading server stats…') + '</div>';
    var c = info.cpu || {}, m = info.mem || {}, age = Math.max(0, Math.round(Date.now() / 1000 - info.time));
    var mu = m.total ? (m.total - m.avail) / m.total * 100 : 0;
    var disks = (info.disks || []).slice().sort(function (a, b) { return (/logs/.test(b.role) ? 1 : 0) - (/logs/.test(a.role) ? 1 : 0); });
    var main = disks[0], dp = main && main.total ? main.used / (main.used + main.avail) * 100 : null;
    var dlist = disks.length > 1 ? '<div class="zh-d">' + disks.map(function (d) { var p = d.used / (d.used + d.avail) * 100; return '<div><span>' + esc(d.mount) + (/logs/.test(d.role) ? ' · logs' : '') + '</span><span>' + p.toFixed(0) + ' %</span><div class="zh-b"><i class="' + lvl(p) + '" style="width:' + p.toFixed(1) + '%"></i></div></div>'; }).join('') + '</div>' : '';
    var w = info.weather || {}, wt = w.temp != null ? w : webTemp, wd = wt ? wx(wt.code) : null;
    var stale = age > 120 ? ' · <span class="t-warn">not updated for ' + Math.round(age / 60) + ' min</span>' : '';
    return '<div class="zh-h"><b>Log server · ' + esc(info.host) + '</b><span>' + esc(info.os || '') + ' · up ' + dur(info.uptime || 0) + '</span><span class="zh-sp"></span><span>updated ' + (age < 60 ? age + ' s' : Math.round(age / 60) + ' min') + ' ago' + stale + '</span></div>'
      + '<div class="zh-g">'
      + tile('CPU', (c.pct || 0).toFixed(0), '%', c.pct, (c.cores || '?') + ' cores · load ' + (c.load || []).map(function (x) { return Number(x).toFixed(2); }).join(' / ') + (c.iowait >= 10 ? ' · <span class="t-warn">disk wait ' + c.iowait.toFixed(0) + ' %</span>' : ''))
      + tile('Memory', mu.toFixed(0), '%', mu, gb(m.total - m.avail) + ' used of ' + gb(m.total) + (m.swap_total ? ' · swap ' + gb(m.swap_total - m.swap_free) : ''))
      + (main ? tile('Log storage', dp.toFixed(0), '%', dp, gb(main.avail) + ' free of ' + gb(main.used + main.avail) + ' · ' + esc(main.mount), '') .replace('</div></div>', '</div>' + dlist + '</div>') : tile('Log storage', '–', '', null, 'no disk information'))
      + tile(esc(w.city || 'City') + ' temperature', wt ? Math.round(wt.temp) : '–', wt ? '°C' : '', null,
        wt ? (wd[1] + ' ' + esc(wd[0]) + (wt.feels != null ? ' · feels ' + Math.round(wt.feels) + '°' : '') + (wt.humidity != null ? ' · humidity ' + Math.round(wt.humidity) + ' %' : '')) : 'unavailable (no internet access from the server or this browser)')
      + siemTile(info.siem, main)
      + '</div>';
  }

  function findGreeting() {
    var best = null;
    [].forEach.call(document.querySelectorAll('h1,h2,h3,h4,div,span,p,strong,b'), function (el) {
      if (el.children.length > 2 || el.closest('nav,aside,ul.nav,#zyb-home,#zyb-who,#zyb-brand')) return;
      var t = el.textContent; if (t.length > 80 || !GREET.test(t)) return;
      if (!el.offsetParent && getComputedStyle(el).position !== 'fixed') return;
      if (!best || best.contains(el)) best = el;
    });
    return best;
  }
  function heroOf(g) {
    var a = g;
    for (var i = 0; i < 7 && a.parentElement && a.parentElement !== document.body; i++) {
      var p = a.parentElement; if (p.querySelector('ul.nav') || p.getBoundingClientRect().height > 460) break; a = p;
    }
    return a;
  }
  // Team Workspace: a person with a profile lands on their own workspace once per browser session (they turn it off on that page)
  var landTried = false;
  function landOnce() {
    if (landTried) return; landTried = true;
    try { if (sessionStorage.getItem('zyb_ws_landed')) return; sessionStorage.setItem('zyb_ws_landed', '1'); if (localStorage.getItem('zyb_ws_landing') === '0') return; }
    catch (e) { return; /* storage blocked: stay on the home page */ }
    var x = new XMLHttpRequest(); x.open('GET', '/api/itam/workspace/me'); x.withCredentials = true; x.timeout = 8000; x.zybQuiet = true;
    x.onload = function () { var j = null; try { j = JSON.parse(x.responseText); } catch (e) { j = null; /* not installed: stay on the home page */ } if (x.status === 200 && j && j.profile) location.assign('/dashboards/my-workspace.html'); };
    x.send();
  }
  var busy = false;
  function draw() {
    if (busy) return; busy = true;
    try {
      var g = findGreeting(), panel = document.getElementById('zyb-home'), wl = document.getElementById('zyb-who');
      if (!g) { if (panel) panel.remove(); if (wl) wl.remove(); stop(); return; }
      if (!document.getElementById('zyb-home-css')) { var st = document.createElement('style'); st.id = 'zyb-home-css'; st.textContent = CSS; document.head.appendChild(st); }
      loadWho(); start(); landOnce();
      if (who && who.user) {
        if (!wl || wl.previousElementSibling !== g) { if (wl) wl.remove(); wl = document.createElement('div'); wl.id = 'zyb-who'; g.parentNode.insertBefore(wl, g.nextSibling); }
        var html = '<span class="zw-n">' + esc(pretty(who.user)) + '</span>' + (who.role ? '<span class="zw-r">' + esc(ROLE[who.role] || who.role) + '</span>' : '') + '<span class="zw-l">signed in as ' + esc(who.user) + '</span>';
        if (wl.innerHTML !== html) wl.innerHTML = html;
      }
      var hero = heroOf(g);
      if (!panel || !panel.isConnected || panel.previousElementSibling !== hero) { if (panel) panel.remove(); panel = document.createElement('section'); panel.id = 'zyb-home'; panel.setAttribute('aria-label', 'Log server and city temperature'); hero.parentNode.insertBefore(panel, hero.nextSibling); }
      var ph = panelHTML(); if (panel.innerHTML !== ph) panel.innerHTML = ph;
    } finally { setTimeout(function () { busy = false; }, 0); }
  }
  function start() { if (timer) return; loadInfo(); timer = setInterval(function () { if (!document.hidden) loadInfo(); }, 30000); }
  function stop() { if (timer) { clearInterval(timer); timer = null; } }

  var pend = null;
  function soon() { if (pend) return; pend = setTimeout(function () { pend = null; draw(); }, 400); }
  function boot() { draw(); new MutationObserver(function (ms) { for (var i = 0; i < ms.length; i++) { var t = ms[i].target; if (t.closest && t.closest('#zyb-home,#zyb-who')) continue; soon(); return; } }).observe(document.body, { childList: true, subtree: true, characterData: true }); }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot); else boot();
})();
