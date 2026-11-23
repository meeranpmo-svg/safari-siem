// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
/* Certificates -> Renewal autopilot (GET /api/itam/certs/autopilot). How far each certificate renews without a person, what
 * stops it and the one fix that automates the most; the lead time learned from this platform's own history; risk itemised;
 * bulk actions people take (switch automatic renewal on, start renewals now, propose firewall installs - a second person
 * approves those). No inline handlers: one delegated click listener. Every value is escaped. */
(function () {
  'use strict';
  var $ = function (id) { return document.getElementById(id); };
  var esc = function (s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); };
  var V = null, F = 'all', Q = '', SEL = {}, WHO = null, busy = false;
  var LV = { full: ['Fully automatic', 'green'], ready: ['Ready to automate', 'teal'], assisted: ['Needs a person', 'yellow'], blocked: ['Blocked', 'red'] };
  var MD = { auto: ['#0ca678', 'automatic'], approval: ['#4299e1', 'a second person approves'], person: ['#f59f00', 'a person does this'], blocked: ['#d63939', 'blocked'] };
  var STEP = { scanned: 'Scan', issued: 'Issue', names: 'Names', installed: 'Install', verified: 'Verify' };
  function req(m, p, b) {
    return new Promise(function (ok, bad) {
      var x = new XMLHttpRequest(); x.open(m, '/api/itam' + p); x.withCredentials = true; x.timeout = 120000; x.zybQuiet = true; if (b) x.setRequestHeader('Content-Type', 'application/json');
      x.onload = function () { var j = null; try { j = JSON.parse(x.responseText); } catch (e) { /* not JSON: reported below */ } if (x.status >= 200 && x.status < 300 && j) return ok(j); bad(Object.assign(new Error((j && j.error) || ('HTTP ' + x.status)), { status: x.status })); };
      x.onerror = x.ontimeout = function () { bad(new Error('IT Asset Management is not reachable')); }; x.send(b ? JSON.stringify(b) : null);
    });
  }
  function toast(t) { var d = document.createElement('div'); d.className = 'toast-zyb'; d.setAttribute('role', 'status'); d.textContent = t; document.body.appendChild(d); setTimeout(function () { d.remove(); }, 5000); }
  var role = function () { return (WHO && WHO.role) || 'viewer'; }, isOp = function () { return role() === 'operator' || role() === 'admin'; };
  function ring(p) { var r = 46, c = 2 * Math.PI * r, v = p == null ? 0 : p, col = p == null ? '#4a5162' : p >= 70 ? '#0ca678' : p >= 35 ? '#f59f00' : '#d63939';
    return '<svg viewBox="0 0 120 120" width="150" height="150" role="img" aria-label="Automation coverage"><circle cx="60" cy="60" r="' + r + '" fill="none" stroke="rgba(255,255,255,.08)" stroke-width="11"/><circle cx="60" cy="60" r="' + r + '" fill="none" stroke="' + col + '" stroke-width="11" stroke-linecap="round" stroke-dasharray="' + (c * v / 100).toFixed(1) + ' ' + c.toFixed(1) + '" transform="rotate(-90 60 60)"/><text x="60" y="62" text-anchor="middle" font-size="25" font-weight="800" fill="currentColor">' + (p == null ? '—' : p + '%') + '</text><text x="60" y="80" text-anchor="middle" font-size="8.5" fill="#8b93a4">renew on their own</text></svg>'; }
  function tile(v, l, cls, f, t) { return '<div class="col-6 col-md-3 col-xl"><div class="card card-sm" data-apf="' + esc(f) + '" role="button" tabindex="0" title="' + esc(t || 'Show these') + '"' + (F === f ? ' style="outline:1px solid #4299e1"' : '') + '><div class="card-body"><div class="au-num' + (cls ? ' ' + cls : '') + '">' + esc(v == null ? '—' : v) + '</div><div class="au-lbl">' + esc(l) + '</div></div></div></div>'; }
  function chips(r) { return '<div class="d-flex gap-1" aria-label="renewal steps">' + r.steps.map(function (s) { var m = MD[s.mode] || MD.auto; return '<span title="' + esc(STEP[s.step] + ': ' + m[1] + ' - ' + s.detail + (s.fix ? ' · Fix: ' + s.fix : '')) + '" style="display:inline-block;font-size:10.5px;padding:1px 6px;border-radius:9px;border:1px solid ' + m[0] + ';color:' + m[0] + '">' + esc(STEP[s.step]) + '</span>'; }).join('') + '</div>'; }
  function match(r) {
    if (F === 'start' && !r.start_now) return false; if (F === 'risk' && r.risk < 40) return false; if (F === 'flight' && !r.in_flight) return false; if (F === 'install' && !r.install_ready) return false;
    if (LV[F] && r.level !== F) return false;
    return !Q || (r.label + ' ' + r.host + ' ' + r.owner + ' ' + r.issuer_name + ' ' + r.id).toLowerCase().indexOf(Q) >= 0;
  }
  function rows() { return V.queue.filter(match); }
  function drawQueue() {
    var L = rows(), ids = L.map(function (r) { return r.id; }), n = Object.keys(SEL).filter(function (k) { return SEL[k] && ids.indexOf(k) >= 0; }).length;
    $('apq').innerHTML = L.length ? '<table class="table table-vcenter card-table table-sm"><thead><tr>' + (isOp() ? '<th><input class="form-check-input" type="checkbox" id="apall" aria-label="Select all shown"' + (n && n === L.length ? ' checked' : '') + '></th>' : '') + '<th>Risk</th><th>Certificate</th><th>Expires</th><th>Automation</th><th>Steps</th><th>Lead · slack</th><th>Start by</th><th>Now</th></tr></thead><tbody>' + L.slice(0, 300).map(function (r) {
      var lv = LV[r.level], rc = r.risk >= 60 ? '#d63939' : r.risk >= 40 ? '#f76707' : r.risk >= 20 ? '#f59f00' : '#0ca678';
      return '<tr class="rowc" data-apr="' + esc(r.id) + '">' + (isOp() ? '<td><input class="form-check-input" type="checkbox" data-aps="' + esc(r.id) + '" aria-label="Select ' + esc(r.label) + '"' + (SEL[r.id] ? ' checked' : '') + '></td>' : '')
        + '<td style="min-width:90px"><div class="d-flex align-items-center gap-2"><b>' + esc(r.risk) + '</b><div style="flex:1;height:6px;border-radius:3px;background:rgba(255,255,255,.08)"><i style="display:block;height:100%;width:' + r.risk + '%;background:' + rc + ';border-radius:3px"></i></div></div></td>'
        + '<td><b>' + esc(r.label) + '</b>' + (r.critical ? ' <span class="badge bg-red-lt">critical</span>' : '') + '<div class="small text-secondary">' + esc(r.issuer_name) + ' · ' + esc(r.deploy) + (r.owner ? ' · ' + esc(r.owner) : '') + '</div></td>'
        + '<td>' + (r.days_left == null ? '<span class="text-secondary">' + esc(r.state) + '</span>' : '<span class="badge bg-' + (r.days_left < 0 ? 'red' : r.days_left <= 14 ? 'orange' : r.days_left <= 45 ? 'yellow' : 'green') + '-lt">' + (r.days_left < 0 ? 'expired' : esc(r.days_left) + ' d') + '</span><div class="small text-secondary">' + esc(r.expires) + '</div>') + '</td>'
        + '<td><span class="badge bg-' + lv[1] + '-lt">' + esc(lv[0]) + '</span>' + (r.auto_renew ? '<div class="small text-secondary">auto-renew on</div>' : '') + '</td><td>' + chips(r) + '</td>'
        + '<td class="small">' + esc(r.lead_days) + ' d · <b class="' + (r.slack_days != null && r.slack_days < 0 ? 'text-red' : r.slack_days != null && r.slack_days < 7 ? 'text-orange' : '') + '">' + (r.slack_days == null ? '—' : esc(r.slack_days) + ' d') + '</b></td>'
        + '<td class="small">' + esc(r.start_by || '—') + (r.start_now ? ' <span class="badge bg-orange-lt">start now</span>' : '') + '</td>'
        + '<td class="small">' + (r.in_flight ? '<span class="badge bg-blue-lt">' + esc(r.in_flight.id + ' · ' + r.in_flight.status) + '</span>' : r.install_ready ? '<span class="badge bg-teal-lt">ready to install</span>' : '') + '</td></tr>';
    }).join('') + '</tbody></table>' : '<div class="card-body text-secondary">' + (V.queue.length ? 'Nothing matches this filter.' : 'No certificate endpoints yet - add them on Endpoints, or switch on automatic discovery (Discover).') + '</div>';
    var sel = Object.keys(SEL).filter(function (k) { return SEL[k]; });
    $('apbar').innerHTML = isOp() ? '<span class="text-secondary small me-auto">' + (sel.length ? sel.length + ' selected' : 'Select certificates for a bulk action, or use the buttons above.') + '</span>' + (sel.length ? '<button type="button" class="btn btn-sm" data-apa="enable-sel">Switch on automatic renewal</button><button type="button" class="btn btn-sm btn-primary" data-apa="start-sel">Start renewal now</button>' : '') : '<span class="text-secondary small">Read-only: actions need the operator role.</span>';
  }
  function draw() {
    var h = $('ap'); if (!h) return;
    if (!V.installed) { h.innerHTML = '<div class="alert alert-warning">' + esc((V.notes || []).join('; ') || 'The certificate lifecycle module is not installed.') + '</div>'; return; }
    var k = V.kpis, M = V.model, ready = V.queue.filter(function (r) { return r.level === 'ready'; }), start = V.queue.filter(function (r) { return r.start_now && r.level !== 'blocked'; });
    var mx = Math.max.apply(null, V.calendar.map(function (w) { return w.starts; }).concat([1]));
    h.innerHTML = '<div class="card mb-3" style="background:radial-gradient(900px 260px at 0% -30%,rgba(12,166,120,.18),transparent),radial-gradient(700px 240px at 100% 130%,rgba(66,153,225,.16),transparent),var(--tblr-bg-surface)"><div class="card-body"><div class="row g-3 align-items-center">'
      + '<div class="col-md-auto text-center">' + ring(k.coverage) + '</div><div class="col"><h3 class="mb-2"><i class="ti ti-robot me-1"></i>Renewal autopilot</h3><ul class="mb-2 ps-3">' + V.brief.map(function (l) { return '<li>' + esc(l) + '</li>'; }).join('') + '</ul>'
      + (isOp() ? '<div class="d-flex flex-wrap gap-2">' + (ready.length ? '<button type="button" class="btn btn-sm" data-apa="enable-ready"><i class="ti ti-player-play me-1"></i>Automate the ' + ready.length + ' ready</button>' : '') + (start.length ? '<button type="button" class="btn btn-sm btn-primary" data-apa="start-due"><i class="ti ti-refresh me-1"></i>Start the ' + start.length + ' due now</button>' : '') + (k.install_ready ? '<button type="button" class="btn btn-sm" data-apa="install"><i class="ti ti-plug-connected me-1"></i>Propose ' + k.install_ready + ' firewall install(s)</button>' : '') + '</div>' : '')
      + '<div class="small text-secondary mt-2">' + esc(V.note) + '</div></div></div></div></div>'
      + '<div class="row row-cards mb-3">' + tile(k.full, 'Fully automatic', 'text-green', 'full') + tile(k.ready, 'Ready to automate', 'text-teal', 'ready', 'Every step can run unattended - switch automatic renewal on') + tile(k.assisted, 'Needs a person', 'text-yellow', 'assisted') + tile(k.blocked, 'Blocked', k.blocked ? 'text-red' : '', 'blocked')
      + tile(k.start_now, 'Start now', k.start_now ? 'text-orange' : '', 'start', 'Expiry less the predicted lead time and margin has passed') + tile(k.at_risk, 'At risk (40+)', k.at_risk ? 'text-red' : '', 'risk') + tile(k.in_flight, 'In flight', '', 'flight') + tile(k.on_time_pct == null ? '—' : k.on_time_pct + '%', 'Renewed on time (90 d)', '', 'all', k.renewed_90d + ' renewal(s) verified in 90 days') + '</div>'
      + '<div class="card mb-3"><div class="card-header"><h3 class="card-title">Renewal queue <span class="text-secondary small">ranked by risk</span></h3><div class="card-actions d-flex gap-2"><input class="form-control form-control-sm" id="apq-s" type="search" placeholder="Search certificates" aria-label="Search certificates" value="' + esc(Q) + '"><select class="form-select form-select-sm" id="apq-f" aria-label="Filter">' + [['all', 'All'], ['start', 'Start now'], ['risk', 'At risk'], ['flight', 'In flight'], ['install', 'Ready to install'], ['full', 'Fully automatic'], ['ready', 'Ready to automate'], ['assisted', 'Needs a person'], ['blocked', 'Blocked']].map(function (o) { return '<option value="' + o[0] + '"' + (F === o[0] ? ' selected' : '') + '>' + o[1] + '</option>'; }).join('') + '</select></div></div>'
      + '<div class="card-body py-2 d-flex gap-2 align-items-center border-bottom" id="apbar"></div><div class="table-responsive" id="apq"></div><div class="card-footer small text-secondary">Steps: <span style="color:#0ca678">automatic</span> · <span style="color:#4299e1">a second person approves</span> · <span style="color:#f59f00">a person does it</span> · <span style="color:#d63939">blocked</span> - hover a step for the reason and the fix. Click a row for the detail.</div></div>'
      + '<div class="row g-3 mb-3"><div class="col-lg-6"><div class="card h-100"><div class="card-header"><h3 class="card-title"><i class="ti ti-traffic-cone me-1"></i>What holds automation back</h3></div><div class="card-body">' + (V.bottlenecks.length ? V.bottlenecks.map(function (b) { return '<div class="mb-2 p-2 rounded" style="border-left:3px solid ' + MD[b.mode][0] + ';background:rgba(255,255,255,.02)"><div class="d-flex"><b class="me-auto">' + esc(STEP[b.step]) + ': ' + esc(b.detail) + '</b><span class="badge bg-secondary-lt">' + esc(b.count) + ' certificate(s)</span></div><div class="small">' + esc(b.fix) + '</div></div>'; }).join('') : '<span class="text-secondary">Nothing - every certificate can renew unattended.</span>') + '</div></div></div>'
      + '<div class="col-lg-6 d-flex flex-column gap-3"><div class="card"><div class="card-header"><h3 class="card-title"><i class="ti ti-calendar-stats me-1"></i>Renewals to start · next 13 weeks</h3></div><div class="card-body"><div class="bars" style="height:70px">' + V.calendar.map(function (w) { return '<span title="' + esc('week of ' + w.week + ': ' + w.starts) + '" style="height:' + Math.max(3, w.starts / mx * 100) + '%;background:' + (w.starts ? '#4299e1' : 'rgba(255,255,255,.08)') + '"></span>'; }).join('') + '</div><div class="d-flex justify-content-between small text-secondary mt-1"><span>' + esc(V.calendar[0].week) + '</span><span>' + esc(V.calendar[12].week) + '</span></div></div></div>'
      + '<div class="card"><div class="card-header"><h3 class="card-title"><i class="ti ti-chart-dots-3 me-1"></i>Lead time learned from history</h3></div><table class="table table-sm card-table"><thead><tr><th>Step</th><th>Median</th><th>P90</th><th>Failure</th><th>Source</th></tr></thead><tbody>'
      + ['acme', 'adcs', 'manual'].map(function (m) { var x = M.issue[m]; return '<tr><td>Issue · ' + esc({ acme: 'ACME', adcs: 'AD CS', manual: 'ordered' }[m]) + '</td><td>' + esc(x.median) + ' d</td><td>' + esc(x.p90) + ' d</td><td>' + esc(x.failure_rate) + '%</td><td class="small text-secondary">' + esc(x.source) + '</td></tr>'; }).join('')
      + '<tr><td>Install approval</td><td>' + esc(M.approval.median) + ' d</td><td>' + esc(M.approval.p90) + ' d</td><td></td><td class="small text-secondary">' + esc(M.approval.source) + '</td></tr>'
      + ['paloalto', 'fortigate'].map(function (kk) { var x = M.install[kk]; return '<tr><td>Install · ' + (kk === 'paloalto' ? 'Palo Alto' : 'FortiGate') + '</td><td>' + esc(x.median) + ' d</td><td>' + esc(x.p90) + ' d</td><td></td><td class="small text-secondary">' + esc(x.source) + '</td></tr>'; }).join('')
      + '</tbody></table><div class="card-footer small text-secondary">' + esc(M.why) + ' Safety margin ' + esc(V.settings.margin_days) + ' days' + (role() === 'admin' ? ' · <a href="#" data-apa="margin">change</a>' : '') + '.</div></div></div></div>'
      + '<div class="card mb-3"><div class="card-header"><h3 class="card-title"><i class="ti ti-sparkles me-1"></i>PKI advisor (AI)</h3><div class="card-actions small text-secondary">' + esc(V.ai && V.ai.enabled ? 'read-only, answers from the autopilot' : 'not available: ' + ((V.ai && V.ai.reason) || '')) + '</div></div><div class="card-body">' + (!isOp() ? '<span class="text-secondary">The advisor works for operators and administrators.</span>' : '<form id="apaf" class="d-flex gap-2"><input class="form-control" id="apaq" maxlength="1500" placeholder="Which renewals first, and which one fix automates the most?" aria-label="Question for the PKI advisor"><button type="submit" class="btn btn-primary"' + (V.ai && V.ai.enabled ? '' : ' disabled') + '>Ask</button></form><div id="apaa" class="mt-2"></div>') + '</div></div>';
    drawQueue();
  }
  function detail(id) {
    var r = V.queue.filter(function (x) { return x.id === id; })[0]; if (!r || !window.zybDetail) return;
    window.zybDetail.open('Renewal autopilot', r.label, '<div class="mb-2"><span class="badge bg-' + LV[r.level][1] + '-lt">' + esc(LV[r.level][0]) + '</span> ' + esc(r.host + ':' + r.port) + ' · ' + esc(r.issuer_name) + ' · expires ' + esc(r.expires || '—') + '</div>'
      + '<h4>Renewal steps</h4><ol class="ps-3">' + r.steps.map(function (s) { var m = MD[s.mode]; return '<li class="mb-1"><b style="color:' + m[0] + '">' + esc(STEP[s.step]) + '</b> - ' + esc(m[1]) + ': ' + esc(s.detail) + (s.fix ? '<div class="small">Fix: ' + esc(s.fix) + '</div>' : '') + '</li>'; }).join('') + '</ol>'
      + '<h4>Risk ' + esc(r.risk) + ' / 100</h4>' + (r.risk_why.length ? '<ul class="ps-3">' + r.risk_why.map(function (x) { return '<li>' + esc(x.label) + ' <b>+' + esc(x.points) + '</b></li>'; }).join('') + '</ul>' : '<p class="text-secondary">No risk points.</p>')
      + '<p class="small text-secondary">Predicted lead ' + esc(r.lead_days) + ' days (P90 of this platform\'s history) · slack ' + esc(r.slack_days == null ? '—' : r.slack_days) + ' days · start by ' + esc(r.start_by || '—') + '.</p>');
  }
  function act(path, body, label) {
    if (busy) return; busy = true; toast(label + '…');
    return req('POST', path, body).then(function (r) {
      var res = r.results || [], ok = res.filter(function (x) { return x.ok; }).length, no = res.filter(function (x) { return !x.ok; });
      toast(label + ': ' + ok + ' done' + (no.length ? ', ' + no.length + ' refused - ' + no.slice(0, 2).map(function (x) { return x.id + ': ' + x.error; }).join('; ') : '') + (r.note && !res.length ? ' - ' + r.note : ''));
      SEL = {}; return load();
    }).catch(function (e) { toast(e.status === 403 ? label + ' needs the operator role.' : e.message); }).then(function () { busy = false; });
  }
  function load() {
    var w = WHO ? Promise.resolve(WHO) : fetch('whoami.json', { credentials: 'same-origin', zybQuiet: true }).then(function (x) { return x.ok ? x.json() : {}; }).catch(function () { return {}; });
    return w.then(function (u) { WHO = u || {}; return req('GET', '/certs/autopilot'); }).then(function (v) { V = v; draw(); })
      .catch(function (e) { var h = $('ap'); if (h) h.innerHTML = '<div class="alert alert-warning">' + esc(e.status === 404 ? 'The renewal autopilot is not installed yet - run the update.' : 'Could not load the renewal autopilot: ' + e.message) + '</div>'; });
  }
  document.addEventListener('click', function (ev) {
    var t = ev.target; if (!$('ap') || !$('ap').contains(t)) return;
    var f = t.closest('[data-apf]'); if (f) { F = f.getAttribute('data-apf'); draw(); return; }
    if (t.matches('[data-aps]')) { SEL[t.getAttribute('data-aps')] = t.checked; drawQueue(); return; }
    if (t.id === 'apall') { rows().forEach(function (r) { SEL[r.id] = t.checked; }); drawQueue(); return; }
    var a = t.closest('[data-apa]');
    if (a) {
      ev.preventDefault(); var k = a.getAttribute('data-apa'), sel = Object.keys(SEL).filter(function (x) { return SEL[x]; });
      if (k === 'enable-ready') return act('/certs/autopilot/enable', { ids: V.queue.filter(function (r) { return r.level === 'ready'; }).map(function (r) { return r.id; }).slice(0, 200) }, 'Automatic renewal');
      if (k === 'start-due') return act('/certs/autopilot/start', { ids: V.queue.filter(function (r) { return r.start_now && r.level !== 'blocked'; }).map(function (r) { return r.id; }).slice(0, 50) }, 'Starting renewals');
      if (k === 'install') return act('/certs/autopilot/propose-installs', {}, 'Proposing installations');
      if (k === 'enable-sel') return act('/certs/autopilot/enable', { ids: sel.slice(0, 200) }, 'Automatic renewal');
      if (k === 'start-sel') return act('/certs/autopilot/start', { ids: sel.slice(0, 50) }, 'Starting renewals');
      if (k === 'margin') { var m = window.prompt('Safety margin in days (0-60), added to the predicted lead time:', String(V.settings.margin_days)); if (m == null) return; return req('POST', '/certs/autopilot/settings', { margin_days: Number(m), version: V.settings.version }).then(function () { toast('Margin saved'); return load(); }).catch(function (e) { toast(e.message); }); }
      return;
    }
    if (t.closest('input,button,a,select')) return;
    var row = t.closest('[data-apr]'); if (row) detail(row.getAttribute('data-apr'));
  });
  document.addEventListener('input', function (ev) { if (ev.target.id === 'apq-s') { Q = ev.target.value.trim().toLowerCase(); drawQueue(); } });
  document.addEventListener('change', function (ev) { if (ev.target.id === 'apq-f') { F = ev.target.value; draw(); } });
  document.addEventListener('submit', function (ev) {
    if (ev.target.id !== 'apaf') return; ev.preventDefault(); var q = $('apaq').value.trim(); if (!q) return; $('apaa').innerHTML = '<span class="text-secondary">Thinking…</span>';
    req('POST', '/certs/autopilot/ask', { question: q }).then(function (r) { $('apaa').innerHTML = '<div style="white-space:pre-wrap">' + esc(r.answer) + '</div>' + (r.injection_signals && r.injection_signals.length ? '<div class="small text-orange">Some records looked like instructions to the AI and were treated as data.</div>' : ''); })
      .catch(function (e) { $('apaa').innerHTML = '<span class="text-red">' + esc(e.message) + '</span>'; });
  });
  window.zybCertPilot = { load: load };
  var sec = $('v-autopilot'); if (sec && !sec.hidden) load();
})();
