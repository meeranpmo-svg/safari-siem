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
    charts(v);
    $('note').textContent = v.note; $('up').textContent = 'Updated ' + String(v.generated_at).slice(11, 16) + ' UTC' + (v.connected ? '' : ' · scanners not connected');
  }
  function charts(v) {
    var C = window.zybCharts, S = v.surface; if (!C) return;
    var top = S.slice().sort(function (a, b) { return b.exposure - a.exposure; }).slice(0, 12);
    if (top.length) C.bars($('cv-exp'), top.map(function (r) { return r.name; }), [{ label: 'Exposure', data: top.map(function (r) { return r.exposure; }), colors: top.map(function (r) { return r.band === 'critical' ? 'crit' : r.band === 'high' ? 'warn' : r.band === 'medium' ? 'purple' : 'acc'; }) }], { horizontal: true, title: 'Exposure by asset' }); else C.empty($('cv-exp'), 'Nothing exposed.');
    var sv = {}; S.forEach(function (r) { r.services.forEach(function (x) { sv[x.name] = (sv[x.name] || 0) + 1; }); }); var sk = Object.keys(sv).sort(function (a, b) { return sv[b] - sv[a]; }).slice(0, 8);
    if (sk.length) C.ring($('cv-svc'), sk, sk.map(function (k) { return sv[k]; }), ['crit', 'warn', 'purple', 'acc', 'teal', 'ok', 'mute', 'warn'], { v: S.reduce(function (n, r) { return n + r.services.length; }, 0), l: 'services' }, { title: 'Exposed services' }); else C.empty($('cv-svc'), 'No exposed service.');
    var st = {}; S.forEach(function (r) { var k = r.site || (r.shadow ? 'Shadow (no record)' : 'No site'); var x = st[k] = st[k] || { n: 0, c: 0 }; x.n++; if (r.band === 'critical' || r.band === 'high') x.c++; }); var stk = Object.keys(st).sort(function (a, b) { return st[b].n - st[a].n; }).slice(0, 10);
    if (stk.length) C.bars($('cv-site'), stk, [{ label: 'Exposed', data: stk.map(function (k) { return st[k].n; }), color: 'acc' }, { label: 'Critical / high', data: stk.map(function (k) { return st[k].c; }), color: 'crit' }], { title: 'By site' }); else C.empty($('cv-site'), 'Nothing exposed.');
    var T = v.trend || []; if (T.length > 1) C.area($('cv-trend'), T.map(function (t) { return String(t.day).slice(5, 10); }), [{ label: 'Exposed', data: T.map(function (t) { return t.exposed; }) }, { label: 'APIs', data: T.map(function (t) { return t.apis; }) }, { label: 'Critical', data: T.map(function (t) { return t.critical; }) }], { title: 'Trend' }); else C.empty($('cv-trend'), 'The trend starts after the second snapshot.');
    var I = [], risky = S.filter(function (r) { return r.services.some(function (x) { return x.risk; }); });
    if (risky.length) I.push(['crit', risky.length + ' asset(s) expose a management or database service to the internet', risky.slice(0, 5).map(function (r) { return r.name + ' (' + r.services.filter(function (x) { return x.risk; }).map(function (x) { return x.name; }).join(', ') + ')'; }).join('; ') + '. These are the first ports attackers try - close them or put them behind the VPN.']);
    var ex = S.filter(function (r) { return r.worst && (r.worst.cves || []).length && (r.worst.severity === 'critical' || r.worst.severity === 'high'); });
    if (ex.length) I.push(['crit', ex.length + ' internet-facing asset(s) with a high or critical CVE', ex.slice(0, 4).map(function (r) { return r.name + ': ' + r.worst.cves[0]; }).join('; ') + '. Patch these before anything else - they are reachable and known.']);
    var sh = S.filter(function (r) { return r.shadow; }); if (sh.length) I.push(['warn', sh.length + ' reachable address(es) not in the asset register', 'Shadow IT has no owner and no patching. Approve them in Discovery Studio or close them.']);
    var cr = S.filter(function (r) { return (r.critical || r.sensitive) && r.services.length; }); if (cr.length) I.push(['warn', cr.length + ' business-critical or sensitive-data asset(s) reachable from the internet', 'They are entry points to a crown jewel - see the AI-Driven Attack Chain for the path.']);
    if (v.apis.length) I.push(['info', v.apis.length + ' API / web service(s) exposed', 'Each should sit behind authentication and a WAF, and log its use.']);
    var chg = (v.changes && v.changes.items) || []; if (chg.length) I.push(['info', chg.length + ' change(s) since the last snapshot', 'New exposure is something to verify, not a result: ' + chg.slice(0, 3).map(function (c) { return c.text; }).join('; ') + '.']);
    $('ins').innerHTML = I.length ? I.map(function (x) { return '<li><span class="dot ' + x[0] + '"></span><div><b>' + esc(x[1]) + '</b><div class="muted small">' + esc(x[2]) + '</div></div></li>'; }).join('') : '<li><span class="dot info"></span><div>Nothing stands out.</div></li>';
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
