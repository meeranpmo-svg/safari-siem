// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
/* Microsoft 365 Security page (m365-security.html) over the SIEM's GET /api/soc/m365/security: KPI tiles that open their tab, ranked
 * actions with the Microsoft page that does each (fixed entra / security.microsoft.com links only), Secure Score ring with the weakest
 * controls and the daily trend, and tabs - people at risk (every point in the drawer), detection + alert chains, Defender alerts,
 * risk detections, Conditional Access, MFA, coverage. Names are for analysts and above. Delegated listeners; every value escaped. */
(function () {
  'use strict';
  var $ = function (id) { return document.getElementById(id); };
  var Z = window.zybDetail;
  var esc = function (s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); };
  var V = null, TAB = 'people', Q = '', SEV = '', OPENONLY = true;
  var MS = /^https:\/\/(entra|security)\.microsoft\.com\//;
  function req(m, url, b) {
    return new Promise(function (ok, bad) {
      var x = new XMLHttpRequest(); x.open(m, url); x.withCredentials = true; x.timeout = 120000; x.zybQuiet = true; if (b) x.setRequestHeader('Content-Type', 'application/json');
      x.onload = function () { var j = null; try { j = JSON.parse(x.responseText); } catch (e) { /* not JSON: reported below */ } if (x.status >= 200 && x.status < 300 && j) return ok(j); bad(Object.assign(new Error((j && j.error) || ('HTTP ' + x.status)), { status: x.status })); };
      x.onerror = x.ontimeout = function () { bad(new Error('the SIEM is not reachable')); }; x.send(b ? JSON.stringify(b) : null);
    });
  }
  function toast(t) { var d = document.createElement('div'); d.className = 'toast-zyb'; d.setAttribute('role', 'status'); d.textContent = t; document.body.appendChild(d); setTimeout(function () { d.remove(); }, 5000); }
  var when = function (s) { var t = s ? Date.parse(s) : NaN; return isFinite(t) ? new Date(t).toISOString().slice(0, 16).replace('T', ' ') : '—'; };
  var nr = function (v, suf) { return v == null ? 'not read' : v + (suf || ''); };
  var badge = function (t, c) { return '<span class="badge bg-' + (c || 'secondary') + '-lt">' + esc(t) + '</span>'; };
  var SB = { high: 'red', medium: 'orange', low: 'yellow', informational: 'secondary' };
  var link = function (u, t) { return u && MS.test(u) ? '<a href="' + esc(u) + '" target="_blank" rel="noopener noreferrer" class="btn btn-sm mt-1"><i class="ti ti-external-link me-1"></i>' + esc(t || 'Open in Microsoft') + '</a>' : ''; };
  function tile(v, l, cls, go) { return '<div class="col-6 col-md-3 col-xl"><div class="card card-sm"' + (go ? ' data-go="' + esc(go) + '" role="button" tabindex="0"' : '') + '><div class="card-body"><div class="au-num' + (cls ? ' ' + cls : '') + '">' + esc(v == null ? '—' : v) + '</div><div class="au-lbl">' + esc(l) + '</div></div></div></div>'; }
  function table(cols, rows, attr, empty) {
    if (!rows || !rows.length) return '<div class="card-body text-secondary">' + esc(empty || 'Nothing to show.') + '</div>';
    return '<div class="table-responsive"><table class="table table-vcenter card-table table-sm"><thead><tr>' + cols.map(function (c) { return '<th>' + esc(c[0]) + '</th>'; }).join('') + '</tr></thead><tbody>'
      + rows.map(function (r, i) { return '<tr' + (attr ? ' ' + attr(r, i) : '') + '>' + cols.map(function (c) { return '<td>' + c[1](r) + '</td>'; }).join('') + '</tr>'; }).join('') + '</tbody></table></div>';
  }
  var hidden = function (x, what) { return x && x.hidden ? '<div class="card-body text-secondary">' + esc(x.count) + ' ' + esc(what) + ' - names are shown to analysts and above (PDPL).</div>' : null; };
  var notRead = function (key) { var c = (V.coverage || []).filter(function (x) { return x.key === key; })[0]; return '<div class="card-body"><div class="alert alert-warning mb-0">Not read from Microsoft Graph' + (c && c.perm ? ' - grant <span class="mono">' + esc(c.perm) + '</span> to the SIEM\'s Entra ID app and give admin consent' : '') + '. This is not zero: nothing was read.</div></div>'; };
  var TABS = [['people', 'People at risk'], ['chains', 'Attack chains'], ['alerts', 'Defender alerts'], ['detections', 'Risk detections'], ['access', 'Conditional Access'], ['mfa', 'MFA'], ['coverage', 'Coverage']];
  var GO = { admins: 'mfa', mfa: 'mfa', chains: 'chains', risky: 'people', alerts: 'alerts', access: 'access', people: 'people', coverage: 'coverage', score: null, trend: null };

  function load() {
    return req('GET', '/api/soc/m365/security').then(function (v) { V = v; $('err').innerHTML = ''; $('main').hidden = false; draw(); })
      .catch(function (e) { $('main').hidden = true; $('err').innerHTML = '<div class="alert alert-warning">' + esc(e.status === 404 ? 'This SIEM does not have the Microsoft 365 Security analysis yet - update the SIEM.' : e.message) + '</div>'; $('up').textContent = 'not loaded'; });
  }
  function draw() {
    $('up').textContent = V.updated ? 'Graph read ' + when(V.updated) + ' UTC' : '';
    if (!V.configured) { $('kpis').innerHTML = ''; $('acts').innerHTML = '<span class="text-secondary">' + esc(V.note) + '</span>'; $('score').innerHTML = '<span class="text-secondary">Not connected.</span>'; $('tabs').innerHTML = ''; $('th').innerHTML = ''; $('tb').innerHTML = ''; $('note').textContent = ''; return; }
    var k = V.kpis;
    $('kpis').innerHTML = tile(nr(k.score_pct, '%'), 'Secure Score', k.score_pct != null && k.score_pct < 50 ? 'text-orange' : '', null) + tile(nr(k.mfa_pct, '%'), 'MFA coverage', k.mfa_pct != null && k.mfa_pct < 95 ? 'text-orange' : '', 'mfa')
      + tile(nr(k.admins_no_mfa), 'Admins without MFA', k.admins_no_mfa ? 'text-red' : 'text-green', 'mfa') + tile(nr(k.risky_high), 'Users at high risk', k.risky_high ? 'text-red' : '', 'people')
      + tile(nr(k.alerts_open_high), 'Open high alerts', k.alerts_open_high ? 'text-red' : '', 'alerts') + tile(k.chains, 'Detection + alert chains', k.chains ? 'text-red' : '', 'chains')
      + tile(nr(k.ca_enabled), 'CA policies enforced', k.ca_enabled === 0 ? 'text-red' : '', 'access') + tile(k.not_read, 'Datasets not read', k.not_read ? 'text-orange' : 'text-green', 'coverage');
    var pr = function (p) { return p >= 80 ? 'p-hi' : p >= 50 ? 'p-md' : 'p-lo'; };
    $('acts').innerHTML = V.actions.length ? V.actions.map(function (a) { return '<div class="act ' + pr(a.priority) + '"><b>' + esc(a.title) + '</b><div class="mut">' + esc(a.detail) + '</div>' + (GO[a.filter] ? '<button type="button" class="btn btn-sm mt-1 me-1" data-go="' + esc(GO[a.filter]) + '">Show</button>' : '') + link(a.link) + '</div>'; }).join('') : '<span class="text-green">Nothing needs action in what Graph returned.</span>';
    var s = V.score;
    if (s) { var c = s.pct >= 70 ? '#2fb344' : s.pct >= 45 ? '#f59f00' : '#d63939', H = (V.history || []).filter(function (h) { return h.score_pct != null; }), mx = Math.max.apply(null, H.map(function (h) { return h.score_pct; }).concat([1]));
      $('score').innerHTML = '<div class="row g-2 align-items-center"><div class="col-auto"><div class="ring" style="background:conic-gradient(' + c + ' ' + (s.pct * 3.6) + 'deg,rgba(255,255,255,.08) 0)"><div><div><div class="au-num">' + esc(s.pct) + '%</div><div class="mut">' + esc(s.current) + ' / ' + esc(s.max) + '</div></div></div></div></div>'
        + '<div class="col"><div class="au-lbl mb-1">Weakest controls - where the points are</div>' + (s.weakest.length ? s.weakest.slice(0, 6).map(function (w) { return '<div class="small"><span class="chip">' + esc(w.category || '—') + '</span> ' + esc(w.control) + ' <span class="mut">' + esc(w.score == null ? '' : w.score + ' pts') + '</span></div>'; }).join('') : '<span class="mut">Graph listed no control scores.</span>') + '</div></div>'
        + (H.length ? '<div class="au-lbl mt-3">Daily trend</div><div class="spark" aria-label="Secure Score history">' + H.slice(-60).map(function (h) { return '<i title="' + esc(h.day + ': ' + h.score_pct + '%') + '" style="height:' + Math.max(4, h.score_pct / mx * 100) + '%"></i>'; }).join('') + '</div>' : '')
        + '<div class="mut mt-1">' + esc(s.trend.why || ((s.trend.per_week > 0 ? '+' : '') + s.trend.per_week + ' points a week over ' + s.trend.samples + ' samples' + (s.trend.z != null ? ' · today vs the last 30 days: z ' + s.trend.z : ''))) + '</div>' + link(V.links.score, 'Open Secure Score'); }
    else $('score').innerHTML = notRead('secureScore');
    $('tabs').innerHTML = TABS.map(function (t) { return '<li class="nav-item"><a class="nav-link' + (t[0] === TAB ? ' active' : '') + '" href="#' + t[0] + '" data-tab="' + t[0] + '" role="tab">' + esc(t[1]) + '</a></li>'; }).join('');
    drawTab(); $('askc').hidden = !V.named; $('note').textContent = V.note;
  }
  function bars(L, key, lab) { var mx = Math.max.apply(null, L.map(function (x) { return x.n; }).concat([1])); return L.length ? L.slice(0, 12).map(function (x) { return '<div class="hb"><span title="' + esc(x[key]) + '">' + esc(x[key]) + '</span><div class="bar"><i style="width:' + (x.n / mx * 100) + '%;background:#4299e1"></i></div><b class="small">' + esc(x.n) + '</b></div>'; }).join('') : '<span class="mut">None.</span>'; }
  function drawTab() {
    var th = '', tb = '';
    if (TAB === 'people') {
      th = '<h3 class="card-title">People at risk <span class="mut">one score per person - Entra ID risk, MFA, open alerts, detections, failed sign-ins</span></h3><div class="card-actions"><input class="form-control form-control-sm" id="q" type="search" placeholder="Search name or account" aria-label="Search people" value="' + esc(Q) + '"></div>';
      tb = hidden(V.people, 'person(s) scored, ' + (V.people.high || 0) + ' high') || table([['Person', function (p) { return '<b>' + esc(p.name || p.upn) + '</b><div class="mut">' + esc(p.upn) + '</div>'; }],
        ['Score', function (p) { return '<div class="d-flex align-items-center gap-2"><b>' + esc(p.score) + '</b><div class="bar" style="width:80px"><i style="width:' + p.score + '%;background:' + (p.level === 'high' ? '#d63939' : p.level === 'medium' ? '#f59f00' : '#4299e1') + '"></i></div></div>'; }],
        ['Level', function (p) { return badge(p.level, SB[p.level]); }], ['Why', function (p) { return '<span class="small" title="' + esc(p.why.map(function (w) { return '+' + w.points + ' ' + w.text; }).join('\n')) + '">' + esc(p.why.slice(0, 2).map(function (w) { return w.text; }).join(' · ')) + (p.why.length > 2 ? ' …' : '') + '</span>'; }],
        ['Sources', function (p) { return p.sources.map(function (s2) { return '<span class="chip">' + esc(s2) + '</span>'; }).join(''); }]],
        V.people.filter(function (p) { return !Q || (p.upn + ' ' + p.name).toLowerCase().indexOf(Q) >= 0; }), function (p) { return 'class="rowc" data-person="' + esc(p.upn) + '"'; }, 'No person has a risk signal in what Graph returned.');
    } else if (TAB === 'chains') {
      th = '<h3 class="card-title">Attack chains <span class="mut">a risk detection and a Defender alert on the same account within 24 hours</span></h3>';
      tb = hidden(V.chains, 'chain(s)') || table([['Account', function (c) { return '<b>' + esc(c.upn) + '</b>'; }], ['Risk detection', function (c) { return esc(c.detection) + '<div class="mut">' + esc(when(c.detected)) + '</div>'; }], ['Defender alert', function (c) { return badge(c.severity, SB[c.severity]) + ' ' + esc(c.alert) + '<div class="mut">' + esc(when(c.alerted)) + '</div>'; }], ['Apart', function (c) { return esc(c.hours_apart) + ' h'; }]],
        V.chains, null, 'No account has both a risk detection and a Defender alert within 24 hours.') + (Array.isArray(V.chains) && V.chains.length ? '<div class="card-body pt-0 mut">Treat each as one incident: confirm with the person, revoke sessions and reset the password if it was not them.</div>' : '');
    } else if (TAB === 'alerts') {
      if (!V.alerts) { th = '<h3 class="card-title">Defender alerts</h3>'; tb = notRead('defenderAlerts'); }
      else { var A = V.alerts;
        th = '<h3 class="card-title">Defender alerts <span class="mut">' + esc(A.open) + ' open of ' + esc(A.total) + (A.oldest_open_days != null ? ' · oldest open ' + A.oldest_open_days + ' days' : '') + '</span></h3><div class="card-actions d-flex gap-2 flex-wrap">'
          + ['', 'high', 'medium', 'low'].map(function (s2) { return '<button type="button" class="btn btn-sm' + (SEV === s2 ? ' btn-primary' : '') + '" data-sev="' + s2 + '">' + esc(s2 || 'all') + (s2 ? ' ' + A.by_severity[s2] : '') + '</button>'; }).join('')
          + '<label class="form-check form-switch mb-0 ms-2"><input class="form-check-input" type="checkbox" id="openonly"' + (OPENONLY ? ' checked' : '') + '><span class="form-check-label small">open only</span></label>' + link(V.links.alerts, 'Defender portal') + '</div>';
        tb = '<div class="card-body pb-0"><div class="row g-3"><div class="col-md-6"><div class="au-lbl mb-1">By category</div>' + bars(A.by_category, 'category') + '</div><div class="col-md-6"><div class="au-lbl mb-1">By product</div>' + bars(A.by_product, 'product') + '</div></div></div>'
          + table([['Severity', function (a) { return badge(a.severity, SB[a.severity]); }], ['Alert', function (a) { return esc(a.title) + '<div class="mut">' + esc(a.category) + ' · ' + esc(a.product) + '</div>'; }], ['Status', function (a) { return a.open ? badge(a.status, 'orange') : badge(a.status, 'green'); }], ['Account', function (a) { return esc(a.user || '—'); }], ['Age', function (a) { return esc(a.age_days) + ' d'; }]],
            A.list.filter(function (a) { return (!SEV || a.severity === SEV) && (!OPENONLY || a.open); }), null, 'No alert matches.'); }
    } else if (TAB === 'detections') {
      th = '<h3 class="card-title">Risk detections ' + (V.detections ? '<span class="mut">' + esc(V.detections.open) + ' open of ' + esc(V.detections.total) + '</span>' : '') + '</h3><div class="card-actions">' + link(V.links.detections, 'Identity Protection') + '</div>';
      tb = !V.detections ? notRead('riskDetections') : '<div class="card-body"><div class="row g-3"><div class="col-md-6"><div class="au-lbl mb-1">By type</div>' + bars(V.detections.by_type, 'type') + '</div><div class="col-md-6"><div class="au-lbl mb-1">By country</div>' + bars(V.detections.by_country, 'country') + '</div></div></div>'
        + (hidden(V.detections.recent, 'recent detection(s)') || table([['When', function (x) { return esc(when(x.when)); }], ['Account', function (x) { return esc(x.upn); }], ['Type', function (x) { return esc(x.type); }], ['Level', function (x) { return badge(x.level, SB[x.level]); }], ['State', function (x) { return esc(x.state); }], ['Where', function (x) { return esc(x.where || '—') + (x.ip ? '<div class="mut mono">' + esc(x.ip) + '</div>' : ''); }]], V.detections.recent, null, 'No detection.'));
    } else if (TAB === 'access') {
      th = '<h3 class="card-title">Conditional Access</h3><div class="card-actions">' + link(V.links.ca, 'Conditional Access policies') + '</div>';
      if (!V.access) tb = notRead('conditionalAccess');
      else { var C = V.access;
        tb = '<div class="card-body"><div class="d-flex gap-3 flex-wrap mb-3">' + badge(C.enabled + ' enforced', C.enabled ? 'green' : 'red') + badge(C.report_only + ' report-only', 'orange') + badge(C.disabled + ' off', 'secondary') + '</div>'
          + '<div class="au-lbl mb-1">Baseline protections <span class="mut">(matched by policy name only)</span></div>' + C.baseline.map(function (b) { return '<div class="small mb-1">' + (b.found ? '<span class="text-green">✓</span> ' : b.report_only ? '<span class="text-orange">◐</span> ' : '<span class="text-red">✗</span> ') + '<b>' + esc(b.label) + '</b> <span class="mut">' + esc(b.found ? 'enforced by "' + b.found + '"' : b.report_only ? 'only report-only: "' + b.report_only + '"' : 'no enforced policy with a matching name') + '</span></div>'; }).join('')
          + '<div class="mut mt-1">' + esc(C.note) + '</div>'
          + (C.stale_report_only.length ? '<div class="au-lbl mt-3 mb-1">Report-only for 30+ days</div>' + C.stale_report_only.map(function (p) { return '<div class="small">' + esc(p.name) + ' <span class="mut">' + esc(p.days) + ' days</span></div>'; }).join('') : '')
          + (C.recent_changes.length ? '<div class="au-lbl mt-3 mb-1">Changed in the last 7 days - confirm each was approved</div>' + C.recent_changes.map(function (p) { return '<div class="small">' + esc(p.name) + ' <span class="mut">' + esc(p.state) + ' · ' + esc(when(p.modified)) + '</span></div>'; }).join('') : '') + '</div>'
          + table([['Policy', function (p) { return esc(p.name); }], ['State', function (p) { return p.state === 'enabled' ? badge('enforced', 'green') : p.state === 'disabled' ? badge('off', 'secondary') : badge('report-only', 'orange'); }], ['Last change', function (p) { return esc(when(p.modified)); }]], C.policies, null, 'No Conditional Access policy exists.'); }
    } else if (TAB === 'mfa') {
      th = '<h3 class="card-title">MFA registration</h3><div class="card-actions">' + link(V.links.mfa, 'Registration details') + '</div>';
      if (!V.mfa) tb = notRead('mfa');
      else { var M = V.mfa;
        tb = '<div class="card-body"><div class="d-flex align-items-center gap-3"><div class="au-num">' + esc(M.pct) + '%</div><div class="flex-fill"><div class="bar"><i style="width:' + M.pct + '%;background:' + (M.pct >= 95 ? '#2fb344' : '#f59f00') + '"></i></div><div class="mut mt-1">' + esc(M.registered) + ' of ' + esc(M.users) + ' members registered · ' + esc(M.not_registered) + ' not</div></div></div></div>'
          + '<div class="card-body pt-0"><div class="au-lbl mb-1">Administrators without MFA (first)</div>' + (M.admins.hidden ? '<span class="mut">' + esc(M.admins.count) + ' - names for analysts and above.</span>' : M.admins.length ? M.admins.map(function (u) { return '<div class="small text-red">' + esc(u.name) + ' <span class="mono">' + esc(u.upn) + '</span></div>'; }).join('') : '<span class="text-green small">None.</span>') + '</div>'
          + (hidden(M.list, 'member(s) without MFA') || table([['Member', function (u) { return esc(u.name); }], ['Account', function (u) { return '<span class="mono">' + esc(u.upn) + '</span>'; }], ['Admin', function (u) { return u.admin ? badge('admin', 'red') : ''; }]], M.list, null, 'Every member has MFA.')); }
    } else if (TAB === 'coverage') {
      th = '<h3 class="card-title">What Microsoft Graph gave the SIEM</h3>';
      tb = table([['Dataset', function (c) { return '<b>' + esc(c.label) + '</b>'; }], ['Status', function (c) { return c.ok ? badge(c.stale_since ? 'read (stale since ' + when(c.stale_since) + ')' : 'read', c.stale_since ? 'orange' : 'green') : badge('not read', 'red'); }], ['Permission to grant', function (c) { return c.ok ? '' : '<span class="mono small">' + esc(c.perm || '') + '</span><div class="mut">' + esc(c.error || '') + '</div>'; }]], V.coverage, null, '')
        + '<div class="card-body pt-0 mut">Grant each permission as an <b>Application</b> permission on the SIEM\'s Entra ID app, then <b>Grant admin consent</b>. The SIEM reads Graph every 15 minutes.</div>';
    }
    $('th').innerHTML = th; $('tb').innerHTML = tb;
  }
  function person(upn) {
    var p = (Array.isArray(V.people) ? V.people : []).filter(function (x) { return x.upn === upn; })[0]; if (!p) return;
    var al = V.alerts && Array.isArray(V.alerts.list) ? V.alerts.list.filter(function (a) { return String(a.user).toLowerCase() === upn.toLowerCase(); }) : [], de = V.detections && Array.isArray(V.detections.recent) ? V.detections.recent.filter(function (x) { return String(x.upn).toLowerCase() === upn.toLowerCase(); }) : [];
    Z.open('Person at risk', p.name || p.upn, '<div class="mb-2"><span class="au-num">' + esc(p.score) + '</span> / 100 ' + badge(p.level, SB[p.level]) + '</div>' + Z.kv(p.why.map(function (w) { return ['+' + w.points, esc(w.text)]; }))
      + (al.length ? '<div class="au-lbl mt-3">Defender alerts</div>' + al.map(function (a) { return '<div class="small">' + badge(a.severity, SB[a.severity]) + ' ' + esc(a.title) + ' <span class="mut">' + esc(a.status) + ' · ' + esc(when(a.created)) + '</span></div>'; }).join('') : '')
      + (de.length ? '<div class="au-lbl mt-3">Risk detections</div>' + de.map(function (x) { return '<div class="small">' + esc(x.type) + ' <span class="mut">' + esc(x.level) + ' · ' + esc(x.where || '') + ' · ' + esc(when(x.when)) + '</span></div>'; }).join('') : '')
      + '<div class="mut mt-3">Indicators, not proof: confirm with the person before acting. Revoking sessions, resetting a password or confirming compromise is done in Microsoft Entra ID.</div>' + link(V.links.risky, 'Open Risky users'));
  }
  function csv() {
    var L = Array.isArray(V.people) ? V.people : [], q = function (v) { var s2 = String(v == null ? '' : v); if (/^[=+\-@\t\r]/.test(s2)) s2 = "'" + s2; return '"' + s2.replace(/"/g, '""') + '"'; };
    if (!L.length) return toast(V.people && V.people.hidden ? 'Names are for analysts and above' : 'Nothing to export');
    var lines = [['account', 'name', 'score', 'level', 'sources', 'why'].map(q).join(',')].concat(L.map(function (p) { return [p.upn, p.name, p.score, p.level, p.sources.join(' '), p.why.map(function (w) { return '+' + w.points + ' ' + w.text; }).join('; ')].map(q).join(','); }));
    var a = document.createElement('a'); a.href = URL.createObjectURL(new Blob(['# Microsoft 365 Security - people at risk, Graph read ' + (V.updated || '') + '. Indicators, not proof.\n' + lines.join('\n') + '\n'], { type: 'text/csv' })); a.download = 'm365-security-' + new Date().toISOString().slice(0, 10) + '.csv'; document.body.appendChild(a); a.click(); a.remove();
  }
  document.addEventListener('click', function (ev) {
    var b;
    if ((b = ev.target.closest('[data-tab]'))) { ev.preventDefault(); TAB = b.getAttribute('data-tab'); return draw(); }
    if ((b = ev.target.closest('[data-go]'))) { TAB = b.getAttribute('data-go'); draw(); return $('tabs').scrollIntoView({ behavior: 'smooth' }); }
    if ((b = ev.target.closest('[data-sev]'))) { SEV = b.getAttribute('data-sev'); return drawTab(); }
    if ((b = ev.target.closest('[data-person]'))) return person(b.getAttribute('data-person'));
  });
  document.addEventListener('change', function (ev) { if (ev.target.id === 'openonly') { OPENONLY = ev.target.checked; drawTab(); } });
  document.addEventListener('input', function (ev) { if (ev.target.id === 'q') { Q = ev.target.value.toLowerCase(); var pos = ev.target.selectionStart; drawTab(); var q = $('q'); if (q) { q.focus(); q.setSelectionRange(pos, pos); } } });
  document.addEventListener('keydown', function (ev) { if (ev.key === 'Enter' && ev.target.matches && ev.target.matches('[data-go]')) ev.target.click(); });
  $('refresh').addEventListener('click', load); $('csv').addEventListener('click', csv);
  $('af').addEventListener('submit', function (ev) { ev.preventDefault(); $('aa').innerHTML = '<span class="mut">Thinking…</span>'; req('POST', '/api/soc/m365/insights/ask', { question: $('af-q').value }).then(function (r) { $('aa').innerHTML = '<div style="white-space:pre-wrap">' + esc(r.answer) + '</div>'; }).catch(function (e) { $('aa').innerHTML = '<div class="alert alert-warning mb-0">' + esc(e.message) + '</div>'; }); });
  var h = (location.hash || '').slice(1); if (TABS.some(function (t) { return t[0] === h; })) TAB = h;
  load();
})();
