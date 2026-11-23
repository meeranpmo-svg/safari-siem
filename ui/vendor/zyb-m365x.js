// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
/* Microsoft 365 -> Insights tab (m365.html) over the SIEM's GET /api/soc/m365/insights: what to do first (ranked, each with the page
 * that does it), licence seats to reclaim and the consumption forecast, identities ranked by explainable risk, sign-in patterns
 * (impossible travel, one address failing across many accounts, a 7 x 24 heatmap in Riyadh time, failures per app), stale and
 * never-used guests, unusual changes learned from the daily history, and the read-only AI Microsoft 365 analyst. People are
 * counted, not named, for viewers (PDPL). Delegated listeners; every value is escaped. */
(function () {
  'use strict';
  var $ = function (id) { return document.getElementById(id); };
  var esc = function (s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); };
  var A = null, busy = false, DOW = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
  function req(m, url, b) {
    return new Promise(function (ok, bad) {
      var x = new XMLHttpRequest(); x.open(m, url); x.withCredentials = true; x.timeout = 120000; x.zybQuiet = true; if (b) x.setRequestHeader('Content-Type', 'application/json');
      x.onload = function () { var j = null; try { j = JSON.parse(x.responseText); } catch (e) { /* not JSON: reported below */ } if (x.status >= 200 && x.status < 300 && j) return ok(j); bad(Object.assign(new Error((j && (j.error || (j.errors && j.errors[0]))) || ('HTTP ' + x.status)), { status: x.status })); };
      x.onerror = x.ontimeout = function () { bad(new Error('the SIEM is not reachable')); }; x.send(b ? JSON.stringify(b) : null);
    });
  }
  var card = function (title, body, sub) { return '<div class="card"><h2>' + title + (sub ? ' <span class="c">' + esc(sub) + '</span>' : '') + '</h2>' + body + '</div>'; };
  var empty = function (t) { return '<div class="empty">' + esc(t) + '</div>'; };
  var hidden = function (x) { return x && x.hidden; };
  function heatmap(H) {
    var mx = Math.max.apply(null, [].concat.apply([], H).concat([1])), cell = function (n) { var a = n ? 0.15 + 0.85 * n / mx : 0; return '<td title="' + n + ' sign-in(s)" style="width:3.4%;height:16px;padding:0;background:rgba(87,148,242,' + a.toFixed(2) + ')"></td>'; };
    return '<table style="width:100%;border-collapse:separate;border-spacing:2px" aria-label="sign-ins by day and hour"><tbody>' + H.map(function (row, d) { return '<tr><td class="muted" style="width:36px;font-size:11px;padding:0 4px">' + DOW[d] + '</td>' + row.map(cell).join('') + '</tr>'; }).join('')
      + '<tr><td></td>' + Array.from({ length: 24 }, function (_, h) { return '<td class="muted" style="font-size:9px;text-align:center;padding:0">' + (h % 3 ? '' : h) + '</td>'; }).join('') + '</tr></tbody></table>';
  }
  function draw() {
    var h = $('m365x'); if (!h || !A) return;
    if (!A.configured) { h.innerHTML = card('🧠 Insights', empty('Microsoft 365 is not connected yet - set the connection in Configuration.')); return; }
    var out = '';
    out += card('✅ What to do first', A.actions.length ? '<ol style="margin:0;padding-left:20px">' + A.actions.slice(0, 12).map(function (a) { return '<li style="margin-bottom:6px"><b>' + esc(a.title) + '</b><div class="muted" style="font-size:12px">' + esc(a.detail) + (a.link ? ' · <a href="' + esc(a.link) + '">open</a>' : '') + '</div></li>'; }).join('') + '</ol>' : empty('Nothing needs action - every check is clean.'), 'ranked by impact');
    var L = A.licences || [];   // the engine already leaves out free / trial SKUs ('free' here is the count of unused seats)
    out += card('🎫 Licence seats', L.length ? '<div class="tw"><table><thead><tr><th>Subscription</th><th>Used</th><th>Reclaimable</th><th>Renews</th><th>Forecast (learned)</th></tr></thead><tbody>' + L.map(function (l) {
      var f = l.forecast || {};
      return '<tr><td><b>' + esc(l.sku) + '</b></td><td>' + esc(l.consumed) + ' / ' + esc(l.total) + '</td><td>' + (l.reclaimable ? '<b>' + esc(l.reclaimable) + '</b> <span class="muted">(' + esc(l.on_disabled || 0) + ' disabled · ' + esc(l.idle_90d || 0) + ' idle 90 d)</span>' : '<span class="muted">0</span>') + '</td><td>' + (l.days != null ? esc(l.days) + ' days' : '—') + '</td><td>' + (f.days_to_full != null ? 'full in about ' + esc(f.days_to_full) + ' days (+' + esc(f.per_day) + '/day)' : '<span class="muted">' + esc(f.note || f.why || 'not growing') + '</span>') + '</td></tr>';
    }).join('') + '</tbody></table></div>' : empty('No paid subscription read (Graph permission LicenseManagement.Read.All).'), 'seats on disabled or 90-day-idle accounts can be reclaimed');
    var I = A.identities;
    out += card('🧑‍💼 Identities by risk', hidden(I) ? empty(I.count + ' account(s) carry risk points (' + I.high + ' high) - names are shown to analysts and above.') : I.length ? '<div class="tw"><table><thead><tr><th>Account</th><th>Risk</th><th>Why (every point)</th></tr></thead><tbody>' + I.slice(0, 40).map(function (r) {
      return '<tr><td><b>' + esc(r.name) + '</b><div class="muted mono">' + esc(r.upn) + '</div></td><td><span class="pill ' + (r.level === 'high' ? 'bad' : r.level === 'medium' ? 'warn' : '') + '">' + esc(r.score) + ' · ' + esc(r.level) + '</span></td><td class="muted" style="font-size:12px">' + r.why.map(esc).join(' · ') + '</td></tr>';
    }).join('') + '</tbody></table></div>' : empty('No account carries risk points.'), 'explainable: each point is named');
    var P = A.signin_patterns;
    if (P) {
      var tr = P.impossible_travel || [], sp = P.spray || [];
      out += card('🌍 Sign-in patterns', '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:14px">'
        + '<div><div class="muted" style="font-size:12px;margin-bottom:4px">Successful sign-ins by day and hour (Riyadh) · ' + esc(P.off_hours) + ' outside working hours (' + esc(P.off_hours_pct == null ? '—' : P.off_hours_pct + '%') + ')</div>' + heatmap(P.heat || []) + '</div>'
        + '<div><b>Impossible travel</b> ' + (tr.length ? '<span class="pill bad">' + tr.length + '</span>' : '<span class="pill ok">none</span>') + '<div style="font-size:12.5px;margin-top:4px">' + tr.slice(0, 8).map(function (x) { return '<div>' + (x.upn ? '<span class="mono">' + esc(x.upn) + '</span> ' : '') + esc(x.from) + ' → ' + esc(x.to) + ' in ' + esc(x.minutes) + ' min</div>'; }).join('') + '</div>'
        + '<div style="margin-top:10px"><b>One address failing on many accounts</b> ' + (sp.length ? '<span class="pill bad">' + sp.length + '</span>' : '<span class="pill ok">none</span>') + '<div style="font-size:12.5px;margin-top:4px">' + sp.slice(0, 8).map(function (x) { return '<div>' + (x.ip ? '<span class="mono">' + esc(x.ip) + '</span> ' : '') + esc(x.accounts) + ' accounts · ' + esc(x.failures) + ' failures' + (x.location ? ' · ' + esc(x.location) : '') + '</div>'; }).join('') + '</div></div>'
        + '<div style="margin-top:10px"><b>Failures by app</b><div style="font-size:12.5px;margin-top:4px">' + (P.apps || []).filter(function (x) { return x.failed; }).slice(0, 6).map(function (x) { return '<div>' + esc(x.app) + ' · ' + esc(x.failed) + ' of ' + esc(x.total) + ' (' + esc(x.fail_pct) + '%)</div>'; }).join('') + '</div></div></div></div>'
        + '<p class="note">' + esc(P.why) + '</p>');
    }
    var G = A.guests;
    if (G) out += card('🧳 Guest accounts', !G.readable ? empty('Last sign-in is not readable (Graph AuditLog.Read.All / Entra ID P1) - guests cannot be judged stale.') : typeof G.never === 'number' ? empty(G.total + ' guests · ' + G.stale + ' stale (90 days) · ' + G.never + ' never signed in - names for analysts and above.')
      : '<div>' + esc(G.total) + ' guests · <b>' + esc(G.stale.length) + '</b> stale (no sign-in for 90 days) · <b>' + esc(G.never.length) + '</b> never signed in</div><div class="muted" style="font-size:12px;margin-top:6px">' + G.stale.concat(G.never).slice(0, 20).map(function (g) { return esc(g.name) + ' <span class="mono">' + esc(g.upn) + '</span>'; }).join(' · ') + '</div><p class="note">Remove them through an access review: <a href="access-reviews.html">Access Reviews</a>.</p>', 'enabled guests');
    if ((A.anomalies || []).length) out += card('📈 Unusual changes (learned)', A.anomalies.map(function (a) { return '<div>' + esc(a.text) + ' <span class="muted">(' + esc(a.z) + ' standard deviations from the last 30 days)</span></div>'; }).join(''));
    out += card('🤖 Microsoft 365 analyst (AI)', !A.named ? empty('The analyst works for analysts and above.') : !(A.ai && A.ai.enabled) ? empty('Not available: ' + ((A.ai && A.ai.reason) || '')) : '<form id="m365xf" style="display:flex;gap:8px"><input id="m365xq" maxlength="1500" style="flex:1" placeholder="Which accounts should we look at first, and why?" aria-label="Question for the Microsoft 365 analyst"><button type="submit">Ask</button></form><div id="m365xa" style="margin-top:8px"></div>', 'read-only - it cannot change anything');
    h.innerHTML = out;
  }
  function load() {
    if (busy) return; busy = true;
    return req('GET', '/api/soc/m365/insights').then(function (a) { A = a; draw(); }, function (e) { var h = $('m365x'); if (h) h.innerHTML = card('🧠 Insights', empty(e.status === 404 ? 'The insights are not on the SIEM yet - run the SIEM update.' : 'Could not load: ' + e.message)); }).then(function () { busy = false; });
  }
  document.addEventListener('submit', function (ev) {
    if (ev.target.id !== 'm365xf') return; ev.preventDefault(); var q = $('m365xq').value.trim(); if (!q) return; $('m365xa').innerHTML = '<div class="empty">Thinking…</div>';
    req('POST', '/api/soc/m365/insights/ask', { question: q }).then(function (r) { $('m365xa').innerHTML = '<div style="white-space:pre-wrap">' + esc(r.answer) + '</div>'; }, function (e) { $('m365xa').innerHTML = '<div class="err">' + esc(e.message) + '</div>'; });
  });
  window.zybM365x = { load: load };
  var t = $('tab-ins'); if (t && !t.hidden) load();
})();
