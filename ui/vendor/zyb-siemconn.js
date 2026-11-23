// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
/* zyb-siemconn.js - SIEM collectors for switches, routers and firewalls on the Switches / Firewall pages (and their rows
 * in Infrastructure Inventory). Under each device's IP: whether the SIEM receives its logs (logs arriving / connected,
 * no logs yet / not connected) and, for administrators, "Connect to SIEM". Connecting:
 *   1. the device becomes an IT Asset Management asset if it is not one yet (a discovered device is approved; a hand-added
 *      one is registered as a network device),
 *   2. its SIEM site is set (one of discovery.siem.site_map),
 *   3. IT Asset Management creates the SIEM log source (POST /api/itam/discovery/connect - Cisco, FortiGate, Palo Alto,
 *      ... or generic syslog), and the SIEM's own configuration steps for that device type are shown (logging host /
 *      syslog settings to paste on the device).
 * "Connect all to SIEM" does the same for every device on the page that is not connected yet. Nothing is changed on the
 * devices themselves. Status: /api/itam/discovery/connect + /api/soc/onboard/sources, refreshed every 60 s.
 * Loaded by zyb-menu.js. */
(function () {
  'use strict';
  if (window.__zybSiemConn || /^\/dashboards\//.test(location.pathname)) return; window.__zybSiemConn = true;
  var IPRE = /^\s*(\d{1,3}(?:\.\d{1,3}){3})\b/, MAP = {}, ADMIN = false, SITES = ['Riyadh HQ', 'Jeddah DR', 'Riyadh Olaya', 'Alkhobar'], CAT = null;
  var KINDS = [['cisco', 'Cisco switch / router / AP (syslog)'], ['cisco-asa-ftd', 'Cisco ASA / Firepower'], ['fortigate', 'Fortinet FortiGate'], ['palo-alto', 'Palo Alto Networks'], ['check-point', 'Check Point'], ['sophos-firewall', 'Sophos firewall'], ['sonicwall', 'SonicWall'], ['f5-bigip', 'F5 BIG-IP'], ['syslog', 'Other device (generic syslog)']];
  function E(v) { return String(v == null ? '' : v).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); }
  function call(m, url, b) {
    return fetch(url, { method: m, credentials: 'include', cache: 'no-store', headers: b ? { 'Content-Type': 'application/json' } : {}, body: b ? JSON.stringify(b) : undefined }).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (j) { if (!r.ok) throw Object.assign(new Error((j && (j.error || (j.errors && j.errors.join('; ')))) || ('HTTP ' + r.status)), { status: r.status }); return j; });
    });
  }
  function view() { try { return typeof currentView !== 'undefined' ? currentView : ''; } catch (e) { return ''; } }   // eslint-disable-line no-undef
  function rows() { try { return typeof NET_ASSETS !== 'undefined' && Array.isArray(NET_ASSETS) ? NET_ASSETS : []; } catch (e) { return []; } }   // eslint-disable-line no-undef
  function netRow(ip) { return rows().filter(function (r) { return r.ip === ip && (r.cat === 'switch' || r.cat === 'firewall'); })[0] || null; }
  function onPage() { var v = view(); return v === 'switches' || v === 'firewall' || v === 'netinv'; }
  function toast(m) { try { if (typeof infoToast === 'function') { infoToast(m); return; } } catch (e) { /* none */ } }   // eslint-disable-line no-undef
  function guessKind(r) {
    var t = ((r && (r.vendor + ' ' + r.role + ' ' + r.name)) || '').toLowerCase(), fw = r && r.cat === 'firewall';
    if (/forti/.test(t)) return 'fortigate'; if (/palo|pan-os/.test(t)) return 'palo-alto'; if (/check ?point/.test(t)) return 'check-point'; if (/sophos/.test(t)) return 'sophos-firewall'; if (/sonicwall/.test(t)) return 'sonicwall'; if (/\bf5\b|big-?ip/.test(t)) return 'f5-bigip';
    if (/cisco/.test(t)) return fw || /asa|firepower|ftd/.test(t) ? 'cisco-asa-ftd' : 'cisco';
    return 'syslog';
  }
  function guessSite(r) { var s = (r && r.site) || ''; if (SITES.indexOf(s) >= 0) return s; var t = s.toLowerCase(); return /jed|\bdr\b/.test(t) ? 'Jeddah DR' : /olaya/.test(t) ? 'Riyadh Olaya' : /khobar/.test(t) ? 'Alkhobar' : 'Riyadh HQ'; }
  function css() {
    if (document.getElementById('zsc-css')) return;
    var s = document.createElement('style'); s.id = 'zsc-css';
    s.textContent = '.zsc{display:flex;align-items:center;gap:6px;flex-wrap:wrap;margin-top:4px;font:600 11.5px system-ui,"Segoe UI",sans-serif;white-space:nowrap}.zsc .d{width:8px;height:8px;border-radius:50%;display:inline-block;background:#6e7681}'
      + '.zsc.ok .d{background:#3fb950}.zsc.ok .l{color:#56d364}.zsc.wait .d{background:#e3b341}.zsc.wait .l{color:#e3b341}.zsc.no .l{color:#9aa4b2}.zsc button{font:600 11px system-ui,sans-serif;padding:2px 8px;border-radius:6px;border:1px solid rgba(255,255,255,.18);background:rgba(88,166,255,.12);color:inherit;cursor:pointer}'
      + '#zsc-ov{position:fixed;inset:0;background:rgba(0,0,0,.55);z-index:100000;display:flex;align-items:flex-start;justify-content:center;padding:50px 16px;overflow:auto}#zsc-box{background:var(--panel,#13151B);color:var(--txt,#ECEEF2);border:1px solid var(--line,#2E3440);border-radius:12px;padding:16px;width:min(760px,100%);box-shadow:0 20px 60px rgba(0,0,0,.5);font:13px/1.5 "Segoe UI",system-ui,sans-serif}'
      + '#zsc-box h3{margin:0 0 10px;font-size:16px}#zsc-box label{display:flex;flex-direction:column;gap:4px;font-size:12px;color:var(--muted,#8C93A1);margin:8px 0}#zsc-box select{padding:7px 9px;border:1px solid var(--line,#2E3440);border-radius:6px;background:#0b0c10;color:inherit}'
      + '#zsc-box pre{white-space:pre-wrap;word-break:break-all;background:#0b0c10;border:1px solid #2e3440;border-radius:8px;padding:10px;font-size:12px}#zsc-box .btns{display:flex;gap:8px;margin-top:12px;flex-wrap:wrap}#zsc-box button{padding:7px 14px;border-radius:7px;border:1px solid var(--line,#2E3440);background:transparent;color:inherit;cursor:pointer;font-weight:600}#zsc-box button.pri{background:#238636;border-color:#238636;color:#fff}'
      + '#zsc-box .kv{display:grid;grid-template-columns:140px 1fr;gap:4px 10px;font-size:12.5px}#zsc-box .kv b{color:var(--muted,#8C93A1);font-weight:500}#zsc-box .err{color:#ff7b72}#zsc-box .m{color:var(--muted,#8C93A1);font-size:12px}#zsc-box table{width:100%;border-collapse:collapse;font-size:12.5px}#zsc-box td,#zsc-box th{padding:4px 6px;border-bottom:1px solid rgba(255,255,255,.06);text-align:left}';
    document.head.appendChild(s);
  }
  function load() {
    return Promise.all([call('GET', '/api/itam/discovery/connect').catch(function (e) { if (e.status === 403) ADMIN = false; return null; }), call('GET', '/api/soc/onboard/sources').catch(function () { return null; })]).then(function (R) {
      var m = {};
      ((R[1] && R[1].sources) || []).forEach(function (s) { if (s.match_ip) m[s.match_ip] = { source_id: s.id, kind: s.kind, state: s.state || 'waiting', last_seen: s.last_seen }; });
      ((R[0] && R[0].connections) || []).forEach(function (c) { if (c.mgmt_ip) m[c.mgmt_ip] = Object.assign({ source_id: c.source_id, kind: c.kind, asset_id: c.asset_id }, m[c.mgmt_ip] || {}, { state: (m[c.mgmt_ip] && m[c.mgmt_ip].state) || c.state || 'waiting' }); });
      MAP = m; paint();
    });
  }
  function ipCells() {
    var out = [];
    [].forEach.call(document.querySelectorAll('td'), function (td) {
      if (td.closest('#zsc-ov,#zd,nav,aside')) return;
      var ip = td.getAttribute('data-zav-ip'); if (!ip) { var f = td.firstChild; var m = IPRE.exec(f && f.nodeType === 3 ? f.nodeValue : (td.children.length ? '' : td.textContent)); ip = m && m[1]; }
      if (ip && td.offsetParent) out.push([td, ip]);
    });
    return out;
  }
  function paint() {
    if (!onPage()) return;
    var cells = ipCells().filter(function (c) { return netRow(c[1]); }); if (!cells.length) return;
    css();
    cells.forEach(function (c) {
      var s = MAP[c[1]], cls = !s ? 'no' : s.state === 'receiving' ? 'ok' : 'wait';
      var lbl = !s ? 'SIEM: not connected' : s.state === 'receiving' ? 'SIEM: logs arriving' : s.state === 'silent' ? 'SIEM: no logs recently' : 'SIEM: connected · no logs yet';
      var html = '<span class="d"></span><span class="l">' + lbl + '</span>' + (ADMIN ? (!s ? '<button type="button" data-zsc="go" data-ip="' + E(c[1]) + '">🔗 Connect to SIEM</button>' : s.state !== 'receiving' ? '<button type="button" data-zsc="go" data-ip="' + E(c[1]) + '">Setup steps</button>' : '') : '');
      var b = c[0].querySelector(':scope > .zsc'); if (!b) { b = document.createElement('div'); c[0].appendChild(b); }
      b.className = 'zsc ' + cls; if (b.innerHTML !== html) b.innerHTML = html;
    });
    allButton();
  }
  function candidates() {
    var v = view(), cat = v === 'firewall' ? 'firewall' : v === 'switches' ? 'switch' : null;
    return rows().filter(function (r) { return r.ip && (cat ? r.cat === cat : r.cat === 'switch' || r.cat === 'firewall') && !MAP[r.ip]; });
  }
  function allButton() {
    var v = view(); if (!ADMIN || (v !== 'switches' && v !== 'firewall')) return;
    var head = document.querySelector('.vhead'); if (!head) return;
    var n = candidates().length, b = head.querySelector('[data-zsc="all"]');
    if (!b) { b = document.createElement('button'); b.type = 'button'; b.className = 'btn'; b.setAttribute('data-zsc', 'all'); b.style.cssText = 'padding:6px 14px;font-size:12px;font-weight:700;margin-left:8px'; var sp = head.querySelector('.vspacer'); head.insertBefore(b, sp ? sp.nextSibling : null); }
    var t = '🔗 Connect all to SIEM (' + n + ')'; if (b.textContent !== t) b.textContent = t; b.disabled = !n; b.title = n ? 'Create SIEM log sources for every device here that is not connected yet' : 'every device here is connected to the SIEM';
  }
  function modal(html) { closeModal(); var ov = document.createElement('div'); ov.id = 'zsc-ov'; ov.innerHTML = '<div id="zsc-box" role="dialog" aria-modal="true">' + html + '</div>'; ov.addEventListener('click', function (e) { if (e.target === ov) closeModal(); }); document.body.appendChild(ov); var f = ov.querySelector('select,button.pri'); if (f) f.focus(); }
  function closeModal() { var o = document.getElementById('zsc-ov'); if (o) o.remove(); }
  function siteSel(r) { return '<label>SIEM site<select id="zsc-site">' + SITES.map(function (x) { return '<option' + (x === guessSite(r) ? ' selected' : '') + '>' + E(x) + '</option>'; }).join('') + '</select></label>'; }
  function kindSel(k) { return '<label>Collector (log format)<select id="zsc-kind">' + KINDS.map(function (x) { return '<option value="' + x[0] + '"' + (x[0] === k ? ' selected' : '') + '>' + E(x[1]) + '</option>'; }).join('') + '</select></label>'; }
  function steps(r) {
    var st = function (x) { return typeof x === 'string' ? x : (x && (x.en || x.text)) || ''; };
    return (r.instructions || []).map(function (i, n) { return '<div style="margin:10px 0"><div style="display:flex;gap:8px;align-items:center"><b>' + E(i.title || 'Configuration') + '</b><button type="button" data-zsc="copy" data-n="' + n + '" style="padding:2px 9px;font-size:11px">Copy</button></div><pre id="zsc-pre-' + n + '">' + E(i.body) + '</pre></div>'; }).join('')
      + ((r.steps || []).length ? '<ol>' + r.steps.map(function (x) { return '<li>' + E(st(x)) + '</li>'; }).join('') + '</ol>' : '')
      + (r.network ? '<p class="m">Network: ' + E(typeof r.network === 'string' ? r.network : JSON.stringify(r.network)) + '</p>' : '')
      + '<p class="m">Logs show up under SIEM → Search within a few minutes of the device being configured; this page then shows "SIEM: logs arriving".</p>';
  }
  function open(ip) {
    var r = netRow(ip); if (!r) return;
    var s = MAP[ip];
    if (s) {
      modal('<h3>' + E(r.name) + ' · SIEM</h3><div class="kv"><b>IP</b><span>' + E(ip) + '</span><b>SIEM log source</b><span>' + E(s.source_id) + '</span><b>Collector</b><span>' + E(s.kind || '') + '</span><b>State</b><span>' + E(s.state === 'receiving' ? 'logs arriving' : 'connected, no logs received yet') + '</span></div>'
        + '<p class="m">Configuration steps for this collector:</p><div id="zsc-out">Loading…</div><div class="btns"><button type="button" data-zsc="close">Close</button></div>');
      call('GET', '/api/soc/onboard/catalog').then(function (c) { var k = ((c && c.kinds) || (c && c.catalog) || []).filter(function (x) { return x.id === s.kind || x.kind === s.kind; })[0]; var o = document.getElementById('zsc-out'); if (o) o.innerHTML = k ? steps(k) : '<p class="m">Point the device\'s syslog (UDP/TCP 514) at the SIEM server for site ' + E(s.site || '') + '. Exact steps: SIEM → Onboarding → ' + E(s.kind || 'syslog') + '.</p>'; }).catch(function () { var o = document.getElementById('zsc-out'); if (o) o.innerHTML = '<p class="m">Open SIEM → Onboarding → ' + E(s.kind || 'syslog') + ' for the steps.</p>'; });
      return;
    }
    modal('<h3>🔗 Connect ' + E(r.name) + ' to the SIEM</h3><div class="kv"><b>Device</b><span>' + E(r.name) + '</span><b>IP</b><span>' + E(ip) + '</span><b>Vendor / model</b><span>' + E(r.vendor || '–') + '</span><b>Inventory</b><span>' + E(r.source === 'itam' ? 'IT Asset Management asset' : r.source === 'disc' ? 'discovered, not approved yet: it will be approved into IT Asset Management' : 'added here: it will be registered in IT Asset Management') + '</span></div>'
      + siteSel(r) + kindSel(guessKind(r)) + '<div class="btns"><button type="button" class="pri" data-zsc="do" data-ip="' + E(ip) + '">Connect to SIEM</button><button type="button" data-zsc="close">Cancel</button></div><div id="zsc-out"></div>');
  }
  // the ITAM asset for this inventory row: existing, approved from discovery, or registered now
  function ensureAsset(r) {
    if (r.asset_id) return Promise.resolve(r.asset_id);
    var find = function () { return call('GET', '/api/itam/assets?limit=5000&q=' + encodeURIComponent(r.ip)).then(function (j) { var a = ((j && j.assets) || []).filter(function (x) { return x.mgmt_ip === r.ip; })[0]; return a && a.id; }); };
    if (r.source === 'disc') return call('POST', '/api/itam/discovery/results/' + encodeURIComponent(String(r.id).slice(5)) + '/approve', {}).then(function (j) { return j.asset_id; }, function (e) { if (e.status === 409) return find(); throw e; });
    return find().then(function (id) { if (id) return id; return call('POST', '/api/itam/assets', { type: 'network', name: r.name, mgmt_ip: r.ip, vendor: r.vendor || '', site: r.site || '', status: 'in_use', tags: [r.cat === 'firewall' ? 'firewall' : 'switch'] }).then(function (j) { var a = j && (j.asset || j); return a && a.id; }); });
  }
  function connectOne(r, site, kind) {
    return ensureAsset(r).then(function (id) {
      if (!id) throw new Error('could not register the device in IT Asset Management');
      return call('POST', '/api/itam/assets/' + encodeURIComponent(id), { site: site }).catch(function () { return null; }).then(function () { return call('POST', '/api/itam/discovery/connect', { asset_id: id, kind: kind }); });
    });
  }
  function doOne(b) {
    var ip = b.getAttribute('data-ip'), r = netRow(ip); if (!r) return;
    var site = document.getElementById('zsc-site').value, kind = document.getElementById('zsc-kind').value, out = document.getElementById('zsc-out');
    b.disabled = true; b.textContent = 'Connecting…';
    connectOne(r, site, kind).then(function (res) {
      b.textContent = 'Connected as ' + res.source_id; MAP[ip] = { source_id: res.source_id, kind: res.kind, state: 'waiting' }; paint();
      out.innerHTML = '<p style="color:#56d364">SIEM log source <b>' + E(res.source_id) + '</b> created. Now configure the device:</p>' + steps(res);
      toast(r.name + ' connected to the SIEM as ' + res.source_id);
    }).catch(function (e) {
      b.disabled = false; b.textContent = 'Connect to SIEM';
      out.innerHTML = '<p class="err">' + E(e.status === 403 ? 'Only IT Asset Management administrators can connect devices to the SIEM.' : e.message) + '</p>' + (/site/.test(e.message || '') ? '<p class="m">Pick one of the SIEM sites above; new site names are added in IT Asset Management (discovery.siem.site_map).</p>' : '');
    });
  }
  function openAll() {
    var L = candidates(); if (!L.length) return;
    modal('<h3>🔗 Connect ' + L.length + ' device' + (L.length > 1 ? 's' : '') + ' to the SIEM</h3><p class="m">Each device becomes a SIEM log source; the collector is chosen from its vendor (Cisco, FortiGate, ...). A device whose site is not a SIEM site uses the site below.</p>'
      + siteSel({}) + '<table><thead><tr><th>Device</th><th>IP</th><th>Collector</th><th>Site</th></tr></thead><tbody>' + L.map(function (r) { return '<tr data-zsc-row="' + E(r.ip) + '"><td>' + E(r.name) + '</td><td>' + E(r.ip) + '</td><td>' + E(guessKind(r)) + '</td><td>' + E(SITES.indexOf(r.site) >= 0 ? r.site : '(site below)') + '</td></tr>'; }).join('') + '</tbody></table>'
      + '<div class="btns"><button type="button" class="pri" data-zsc="doall">Connect all</button><button type="button" data-zsc="close">Cancel</button></div><div id="zsc-out"></div>');
  }
  function doAll(b) {
    var L = candidates(), fallback = document.getElementById('zsc-site').value, out = document.getElementById('zsc-out'), ok = 0, fail = [], firstOf = {};
    b.disabled = true;
    var next = function (i) {
      if (i >= L.length) {
        b.textContent = 'Done'; paint();
        out.innerHTML = '<p>' + ok + ' connected' + (fail.length ? ', <span class="err">' + fail.length + ' failed</span>' : '') + '.</p>' + (fail.length ? '<ul>' + fail.map(function (f) { return '<li class="err">' + E(f) + '</li>'; }).join('') + '</ul>' : '')
          + Object.keys(firstOf).map(function (k) { return '<h4 style="margin:14px 0 4px">' + E(k) + ' devices: configuration</h4>' + steps(firstOf[k]); }).join('');
        toast(ok + ' devices connected to the SIEM'); return;
      }
      var r = L[i], k = guessKind(r), tr = document.querySelector('[data-zsc-row="' + r.ip + '"]');
      b.textContent = 'Connecting ' + (i + 1) + ' of ' + L.length + '…';
      connectOne(r, SITES.indexOf(r.site) >= 0 ? r.site : fallback, k).then(function (res) { ok++; MAP[r.ip] = { source_id: res.source_id, kind: k, state: 'waiting' }; if (!firstOf[k]) firstOf[k] = res; if (tr) tr.style.color = '#56d364'; },
        function (e) { fail.push(r.name + ' (' + r.ip + '): ' + e.message); if (tr) tr.style.color = '#ff7b72'; }).then(function () { next(i + 1); });
    };
    next(0);
  }
  function copy(b) { var t = document.getElementById('zsc-pre-' + b.getAttribute('data-n')); if (!t) return; var done = function () { b.textContent = 'Copied'; }; if (navigator.clipboard) navigator.clipboard.writeText(t.textContent).then(done, function () {}); }
  document.addEventListener('click', function (e) {
    var b = e.target && e.target.closest && e.target.closest('[data-zsc]'); if (!b) return;
    e.preventDefault(); e.stopPropagation(); if (e.stopImmediatePropagation) e.stopImmediatePropagation();
    var a = b.getAttribute('data-zsc');
    if (a === 'go') open(b.getAttribute('data-ip')); else if (a === 'do') doOne(b); else if (a === 'all') openAll(); else if (a === 'doall') doAll(b); else if (a === 'copy') copy(b); else if (a === 'close') closeModal();
  }, true);
  document.addEventListener('keydown', function (e) { if (e.key === 'Escape') closeModal(); });
  call('GET', '/api/itam/status').then(function (j) { ADMIN = !!(j && j.me && j.me.role === 'admin'); paint(); }).catch(function () { ADMIN = false; });
  load(); setInterval(function () { if (!document.hidden && onPage()) load(); }, 60000);
  var t = null; new MutationObserver(function (ms) { for (var i = 0; i < ms.length; i++) { var x = ms[i].target; if (x.closest && x.closest('.zsc,#zsc-ov')) continue; if (!t) t = setTimeout(function () { t = null; paint(); }, 700); return; } }).observe(document.documentElement, { childList: true, subtree: true });
  window.__zybSiemConnTest = { guessKind: guessKind, guessSite: guessSite };
})();
