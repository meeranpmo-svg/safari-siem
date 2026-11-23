// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
/* zyb-attacksurface.js - Continuous Attack Surface page (attack-surface.html). Reads /api/itam/attack-surface: the external surface,
 * its APIs and exposed services, and the "what changed" feed diffed on every run. Read-only; a test is proposed on the AI-Driven
 * Attack Chain or the VAPT Workflow (four-eyes), never fired here. No inline handlers; every value is escaped; requests are zybQuiet. */
(function () {
  'use strict';
  var esc = function (v) { return String(v == null ? '' : v).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); };
  var $ = function (id) { return document.getElementById(id); };
  var RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 }, ROLE = 'viewer', V = null, FLT = '';
  function req(m, u, b) { return new Promise(function (ok, bad) { var x = new XMLHttpRequest(); x.open(m, '/api/itam' + u); x.withCredentials = true; x.timeout = 120000; x.zybQuiet = true; if (b) x.setRequestHeader('Content-Type', 'application/json');
    x.onload = function () { var j = null; try { j = JSON.parse(x.responseText); } catch (e) { j = null; /* not JSON: shown as the HTTP status */ } if (x.status >= 200 && x.status < 300 && j) return ok(j); bad(Object.assign(new Error((j && j.error) || ('HTTP ' + x.status)), { status: x.status })); };
    x.onerror = x.ontimeout = function () { bad(Object.assign(new Error('IT Asset Management is not reachable'), { status: 0 })); }; x.send(b ? JSON.stringify(b) : null); }); }
  function toast(t) { var d = document.createElement('div'); d.setAttribute('role', 'status'); d.style.cssText = 'position:fixed;bottom:18px;left:50%;transform:translateX(-50%);background:#1d2430;border:1px solid #2e3747;border-radius:10px;padding:10px 16px;z-index:9999;max-width:90vw'; d.textContent = t; document.body.appendChild(d); setTimeout(function () { d.remove(); }, 6000); }
  function tile(l, v, s, c) { return '<div class="t ' + (c || '') + '"><div class="l">' + esc(l) + '</div><div class="v">' + esc(v) + '</div><div class="s">' + esc(s || '') + '</div></div>'; }
  function pill(t, c) { return '<span class="pill ' + (c || '') + '">' + esc(t) + '</span>'; }
  var BANDC = { critical: 'bad', high: 'bad', medium: 'warn', low: 'info' }, SEVC = { critical: 'bad', high: 'bad', medium: 'warn', low: 'info', info: '' };
  var op = function () { return RANK[ROLE] >= RANK.operator; };
  function load() { return req('GET', '/attack-surface').then(function (v) { V = v; $('main').hidden = false; $('err').innerHTML = ''; draw(); }, function (e) { $('main').hidden = true;
    $('err').innerHTML = '<div class="card"><p>' + esc(e.status === 403 ? 'Addresses and services are internal: operators and administrators only.' : e.status === 404 ? 'Attack Surface is not installed yet - run the platform update.' : e.message) + '</p></div>'; }); }
  function draw() { var v = V, k = v.kpis;
    $('snap').hidden = ROLE !== 'admin';
    $('kk').innerHTML = tile('Exposed assets', k.exposed, 'internet-facing or external findings', k.exposed ? 'warn' : 'ok') + tile('Critical exposure', k.critical, 'exploitable + high value', k.critical ? 'bad' : 'ok')
      + tile('APIs', k.apis, 'reachable API / web services') + tile('Risky services', k.risky_services, 'RDP / SMB / DB / admin exposed', k.risky_services ? 'bad' : 'ok')
      + tile('Shadow surface', k.shadow, 'reachable, not in the register', k.shadow ? 'warn' : 'ok') + tile('Changes', k.changes, 'since the last snapshot', k.changes ? 'warn' : '');
    var ch = v.changes;
    $('chc').textContent = ch.first ? 'first run - the feed starts at the next snapshot' : ch.since ? 'since ' + ch.since.replace('T', ' ') : '';
    $('changes').innerHTML = ch.first ? '<div class="empty">The first snapshot is being recorded. What changed appears from the next run - and whenever the surface changes.</div>'
      : ch.items.length ? ch.items.map(function (x) { return '<div class="nx"><span class="pill ' + (SEVC[x.severity] || '') + '">' + esc((x.kind || '').replace(/_/g, ' ')) + '</span><div style="flex:1">' + esc(x.text) + '</div>' + (op() && !/^shadow/.test(x.id) ? '<a href="#" data-open="' + esc(x.id) + '">open</a>' : '') + '</div>'; }).join('') : '<div class="empty">No change since the last snapshot.</div>';
    $('apc').textContent = v.apis.length + ' reachable';
    $('apis').innerHTML = v.apis.length ? '<table><thead><tr><th>API</th><th>Asset</th><th>Port</th><th>Why</th></tr></thead><tbody>' + v.apis.slice(0, 200).map(function (a) { return '<tr><td><b>' + esc(a.name) + '</b></td><td>' + esc(a.asset) + '</td><td>' + esc(a.port) + '</td><td class="small">' + esc(a.why) + '</td></tr>'; }).join('') + '</tbody></table>' : '<div class="empty">No API surface detected.</div>';
    var L = v.surface.filter(function (r) { return !FLT || (FLT === 'critical' ? r.band === 'critical' : FLT === 'api' ? r.apis.length : FLT === 'risky' ? r.services.some(function (x) { return x.risk; }) : FLT === 'shadow' ? r.shadow : FLT === 'findings' ? r.open_findings : true); });
    $('sc').textContent = L.length + ' of ' + v.surface.length;
    $('surface').innerHTML = L.length ? '<table><thead><tr><th>Asset</th><th>Exposure</th><th>Exposed services</th><th>Worst finding</th><th>Seen</th></tr></thead><tbody>' + L.slice(0, 800).map(function (r) {
      return '<tr data-open="' + esc(r.id) + '" style="cursor:pointer"><td><b>' + esc(r.name) + '</b>' + (r.shadow ? ' ' + pill('shadow', 'warn') : '') + (r.critical ? ' ' + pill('critical asset', 'bad') : '') + (r.sensitive ? ' ' + pill('sensitive', 'bad') : '') + '<div class="hint">' + esc([r.type, r.ips.join(', '), r.site].filter(Boolean).join(' · ')) + '</div></td>'
        + '<td>' + pill(r.exposure + ' ' + r.band, BANDC[r.band]) + '</td><td class="small">' + (r.services.length ? r.services.map(function (x) { return '<span class="pill ' + (x.risk ? 'bad' : x.api ? 'info' : '') + '">' + esc(x.name) + '</span>'; }).join(' ') : '—') + '</td>'
        + '<td class="small">' + (r.worst ? pill(r.worst.severity, SEVC[r.worst.severity]) + esc(r.worst.title) : '—') + '</td><td class="small">' + esc(r.last_seen ? r.last_seen.slice(0, 10) : '—') + '</td></tr>'; }).join('') + '</tbody></table>' : '<div class="empty">No asset matches.</div>';
    $('note').textContent = v.note; $('up').textContent = 'Updated ' + String(v.generated_at).slice(11, 16) + ' UTC' + (v.connected ? '' : ' · scanners not connected');
  }
  function openOne(id) { if (String(id).indexOf('shadow:') === 0) { toast('Shadow surface: approve it in Discovery Studio so it has an owner, then it joins the register.'); return; }
    req('GET', '/attack-surface/' + encodeURIComponent(id)).then(function (r) {
      $('dlgt').textContent = r.name; var chain = r.chain_link || '/ai-pentest';
      var h = '<div class="muted small">' + esc([r.type, r.ips.join(', '), r.site, r.owner].filter(Boolean).join(' · ')) + '</div>'
        + '<p class="small">Exposure <b>' + esc(r.exposure) + '/100 (' + esc(r.band) + ')</b>' + (r.critical ? ' · business-critical' : '') + (r.sensitive ? ' · sensitive data' : '') + '</p>'
        + '<div class="card" style="margin:0 0 8px"><b>Required actions</b> <span class="hint">' + esc((r.actions || []).length ? (r.actions.length + ' - worst first') : '') + '</span>' + ((r.actions || []).length ? '<ol style="margin:6px 0 0;padding-left:20px">' + r.actions.map(function (a) { return '<li style="margin:0 0 8px">' + pill(a.severity, SEVC[a.severity] || '') + ' <b>' + esc(a.action) + '</b>'
          + (a.why ? '<div class="small muted">Why: ' + esc(a.why) + '</div>' : '') + (a.verify ? '<div class="small muted">Verify: ' + esc(a.verify) + '</div>' : '') + '<div class="small muted">From: ' + esc(a.finding ? a.finding + ' (' + a.source + ')' : a.source) + (a.cves && a.cves.length ? ' · ' + esc(a.cves.join(', ')) : '') + '</div></li>'; }).join('') + '</ol>' : '<div class="small muted">' + esc(r.actions_note || 'No action required.') + '</div>') + '</div>'
        + '<div class="card" style="margin:0 0 8px"><b>Why this exposure</b>' + (r.why || []).map(function (w) { return '<div class="small">+' + esc(w.points) + ' · ' + esc(w.text) + '</div>'; }).join('') + '</div>'
        + '<b>Exposed services</b><table><thead><tr><th>Service</th><th>Port</th><th>Evidence</th></tr></thead><tbody>' + (r.services.length ? r.services.map(function (x) { return '<tr><td>' + esc(x.name) + (x.risk ? ' ' + pill('risky', 'bad') : '') + (x.api ? ' ' + pill('API', 'info') : '') + '</td><td>' + esc(x.port) + '</td><td class="small">' + esc(x.evidence) + '</td></tr>'; }).join('') : '<tr><td colspan="3">None recorded</td></tr>') + '</tbody></table>'
        + (r.chain_entry && r.chain_entry.length ? '<b>AI-Driven Attack Chain from here</b><table><thead><tr><th>To (crown jewel)</th><th>Risk</th><th>Path</th></tr></thead><tbody>' + r.chain_entry.map(function (p) { return '<tr><td>' + esc(p.target) + '</td><td>' + pill(p.score + ' ' + p.band, BANDC[p.band]) + '</td><td class="small">' + esc((p.stages || []).map(function (s) { return s.device || s.to || s.role; }).join(' → ')) + '</td></tr>'; }).join('') + '</tbody></table>' : '')
        + '<p class="small">' + esc(r.note) + ' <a href="ai-pentest.html">AI-Driven Attack Chain</a> · <a href="vapt-workflow.html">VAPT Workflow</a></p>';
      $('dlgb').innerHTML = h; $('dlg').showModal();
    }, function (e) { toast(e.message); }); }
  document.addEventListener('click', function (ev) { var t = ev.target, x;
    if ((x = t.closest('[data-open]'))) { ev.preventDefault(); return openOne(x.getAttribute('data-open')); }
    if (t.id === 'dlgx') return $('dlg').close();
    if (t.id === 'snap') { t.disabled = true; return req('POST', '/attack-surface/snapshot', {}).then(function (r) { toast('Snapshot recorded · ' + r.changes + ' change(s)'); load(); }, function (e) { toast(e.message); }).then(function () { t.disabled = false; }); }
    if (t.id === 'refresh') return load(); });
  $('flt').addEventListener('change', function () { FLT = $('flt').value; draw(); });
  (function () { var w = new XMLHttpRequest(); w.open('GET', '/dashboards/whoami.json'); w.zybQuiet = true; w.onload = function () { try { var j = JSON.parse(w.responseText), r = String(j.role || '').toLowerCase(); if (RANK[r] != null) ROLE = r; } catch (e) { /* not signed in: viewer */ } load(); }; w.onerror = load; w.send(); })();
})();
