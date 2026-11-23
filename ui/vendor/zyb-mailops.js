// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
/* zyb-mailops.js - 24/7 Email Availability (mail-ops.html). Reads /api/itam/mail-ops: nine steps, each showing what is done and
 * what blocks it; the engine enforces the roles and four eyes. No inline handlers; every value escaped; requests zybQuiet. */
(function () {
  'use strict';
  var $ = function (i) { return document.getElementById(i); };
  var esc = function (v) { return String(v == null ? '' : v).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); };
  var S = { me: '', role: 'viewer', v: null, step: null, okFn: null };
  function req(m, u, b) { return new Promise(function (ok, bad) { var x = new XMLHttpRequest(); x.open(m, '/api/itam' + u); x.withCredentials = true; x.timeout = 90000; x.zybQuiet = true; if (b !== undefined) x.setRequestHeader('Content-Type', 'application/json');
    x.onload = function () { var j = null; try { j = JSON.parse(x.responseText); } catch (e) { j = null; } if (x.status >= 200 && x.status < 300 && j) return ok(j); bad(Object.assign(new Error((j && j.error) || ('HTTP ' + x.status)), { status: x.status })); };
    x.onerror = x.ontimeout = function () { bad(Object.assign(new Error('IT Asset Management is not reachable'), { status: 0 })); }; x.send(b !== undefined ? JSON.stringify(b) : null); }); }
  function toast(t) { var d = document.createElement('div'); d.className = 'toast'; d.setAttribute('role', 'status'); d.textContent = t; document.body.appendChild(d); setTimeout(function () { d.remove(); }, 6000); }
  var pill = function (t, c) { return '<span class="pill ' + (c || '') + '">' + esc(t) + '</span>'; };
  var val = function (i) { var el = $(i); return el ? String(el.value || '').trim() : ''; };
  var fld = function (id, label, type, extra, v) { var inp = type === 'textarea' ? '<textarea id="' + id + '">' + esc(v || '') + '</textarea>' : type === 'select' ? '<select id="' + id + '">' + extra + '</select>' : '<input id="' + id + '" type="' + (type || 'text') + '" value="' + esc(v == null ? '' : v) + '">'; return '<label class="f" for="' + id + '">' + esc(label) + inp + '</label>'; };
  function ask(title, html, okText, fn) { $('dlgt').textContent = title; $('dlgb').innerHTML = html; $('dlgok').textContent = okText || 'Save'; S.okFn = fn; $('dlgbg').classList.add('open'); var f = $('dlgb').querySelector('input,textarea,select'); if (f) f.focus(); }
  function closeDlg() { $('dlgbg').classList.remove('open'); S.okFn = null; }
  function act(path, b, msg) { return req('POST', path, b || {}).then(function (v) { S.v = v; if (msg) toast(msg); draw(); return true; }, function (er) { toast('Not done: ' + er.message); return false; }); }
  var admin = function () { return S.role === 'admin'; };
  var SEVC = { critical: 'late', high: 'late', medium: 's-awaiting_approval', low: '', info: '' };

  function load() { return req('GET', '/mail-ops').then(function (v) { S.v = v; $('err').innerHTML = ''; if (S.step == null) S.step = v.current_step || 1; draw(); }, function (er) {
    $('steps').innerHTML = ''; $('panel').innerHTML = '';
    $('err').innerHTML = '<div class="block">' + esc(er.status === 403 ? 'The 24/7 email programme is for the mail team: operators and administrators (it names the on-call people).' : er.status === 404 ? 'The 24/7 email programme is not installed yet - run the platform update.' : er.message) + '</div>'; }); }
  function draw() {
    var v = S.v; $('ready').textContent = 'Readiness ' + v.readiness + '%'; $('ready').className = 'pill ' + (v.readiness === 100 ? 's-closed' : v.readiness >= 60 ? 's-awaiting_approval' : 'late');
    $('steps').innerHTML = v.steps.map(function (s) { return '<li class="' + (s.done ? 'done' : v.current_step === s.n ? 'now' : '') + '"><button type="button" data-step="' + s.n + '"' + (S.step === s.n ? ' aria-current="step"' : '') + '><span class="n">' + (s.done ? '✓' : s.n) + '</span><span><span class="t1">' + esc(s.title) + '</span><span class="t2">' + esc(s.what || '') + '</span></span></button></li>'; }).join('');
    var cur = v.steps[S.step - 1], h = '<div class="card"><h2>' + S.step + '. ' + esc(cur.title) + '</h2>' + (cur.block ? '<div class="block">Next: ' + esc(cur.block) + (cur.link ? ' <a href="' + esc(cur.link) + '">open</a>' : '') + '</div>' : '<div class="okb">Done - ' + esc(cur.what) + '</div>');
    h += [p1, p2, p3, p4, p5, p6, p7, p8, p9][S.step - 1](v) + (v.errors && v.errors.length ? '<p class="note">Not readable: ' + esc(v.errors.join('; ')) + '</p>' : '') + '</div>';
    $('panel').innerHTML = h;
  }
  function p1(v) {
    var p = v.profile, h = '<div class="gd">Who owns mail, who is on call around the clock and how fast service must come back. At least two on-call engineers - one person cannot cover 24/7. The availability target is set on the Email Dashboard (' + esc(v.availability.target ? v.availability.target + '%' : 'not set') + ').</div>';
    if (p) h += '<dl class="kv"><dt>Service owner</dt><dd>' + esc(p.service_owner) + '</dd><dt>Escalation</dt><dd>' + esc(p.escalation) + '</dd><dt>On call</dt><dd>' + esc(p.oncall.join(', ')) + '</dd><dt>RTO / RPO</dt><dd>' + esc(p.rto_min + ' min / ' + p.rpo_min + ' min') + '</dd>' + (p.notes ? '<dt>Notes</dt><dd>' + esc(p.notes) + '</dd>' : '') + '<dt>Set by</dt><dd>' + esc(p.by + ' ' + String(p.at).slice(0, 10)) + '</dd></dl>';
    if (!admin()) return h + '<p class="note">An administrator sets these.</p>';
    p = p || { service_owner: '', escalation: '', oncall: [], rto_min: 30, rpo_min: 0, notes: '' };
    return h + '<div class="grid2"><div>' + fld('p-own', 'Service owner (user name)', 'text', '', p.service_owner) + fld('p-esc', 'Escalation manager (user name)', 'text', '', p.escalation) + fld('p-onc', 'On-call engineers (user names, comma separated)', 'text', '', p.oncall.join(', ')) + '</div><div>'
      + fld('p-rto', 'RTO - minutes to restore mail', 'number', '', p.rto_min) + fld('p-rpo', 'RPO - minutes of mail that may be lost', 'number', '', p.rpo_min) + fld('p-notes', 'Notes (rota, phone bridge, vendor support numbers)', 'textarea', '', p.notes) + '</div></div><div class="bar" style="margin-top:10px"><button type="button" class="pri" id="p-save">Save</button></div>';
  }
  function p2() { return '<div class="gd">The whole mail path - DNS (MX, SPF, DMARC), each Internet link, the email gateway, Exchange and Exchange Online, and the egress IPs - is mapped and checked on the Email Route Map. A broken hop there is shown with its fix.</div><div class="bar"><a href="email-route-map.html"><button type="button">Open the Email Route Map</button></a></div>'; }
  function p3(v) {
    var w = v.availability.windows || [];
    return '<div class="gd">Mail is checked every minute (an MX host answering SMTP) and the early-warning check looks at certificates, DNS, SPF, the route and Exchange health from the SIEM. A source the check could not read is a monitoring gap, never "fine". New warnings are e-mailed to the mail team.</div>'
      + '<dl class="kv"><dt>Mail now</dt><dd>' + (v.availability.up === true ? pill('up', 's-closed') : v.availability.up === false ? pill('down since ' + new Date(v.availability.down_since).toISOString().slice(0, 16).replace('T', ' '), 'late') : pill('not measured')) + '</dd>'
      + w.map(function (x) { return '<dt>' + esc(x.label) + '</dt><dd>' + esc(x.availability == null ? 'not measurable yet' : x.availability + '%') + ' ' + pill(String(x.state || '').replace(/_/g, ' '), x.state === 'met' ? 's-closed' : x.state === 'breached' ? 'late' : '') + (x.budget_left_minutes != null ? ' <span class="muted">' + esc(x.budget_left_minutes) + ' min of downtime budget left</span>' : '') + '</dd>'; }).join('') + '</dl>'
      + '<div class="bar" style="margin-top:10px"><a href="email-dashboard.html"><button type="button">Open the Email Dashboard</button></a></div>';
  }
  function p4(v) {
    var g = (v.availability.gaps || []).filter(function (x) { return x.severity !== 'info'; }), a = v.alerts || [];
    return '<div class="gd">No single point of failure on the mail path (two MX hosts on separate servers, ideally separate sites and Internet links), and no critical warning left open.</div>'
      + '<h4>Design gaps</h4>' + (g.length ? g.map(function (x) { return '<div class="nx">' + pill(x.severity, SEVC[x.severity]) + ' ' + esc(x.title) + (x.fix && x.fix.length ? '<div class="sugg">' + esc(x.fix.join(' · ')) + '</div>' : '') + '</div>'; }).join('') : '<div class="empty">None.</div>')
      + '<h4>Open early warnings</h4>' + (a.length ? a.map(function (x) { return '<div class="nx">' + pill(x.severity, SEVC[x.severity]) + ' ' + esc(x.title) + ' <span class="muted">' + esc(x.source) + '</span></div>'; }).join('') : '<div class="empty">None open.</div>');
  }
  function p5(v) {
    return '<div class="gd">A runbook for every standard mail failure: who owns it, the steps, and when and whom to escalate. A saved runbook is a draft until a different person approves it; review it again within 12 months.</div>'
      + '<div class="tw"><table><thead><tr><th>Failure</th><th>Status</th><th>Owner</th><th>Approved</th><th></th></tr></thead><tbody>' + v.runbooks.map(function (r) {
        return '<tr><td>' + esc(r.title) + '</td><td>' + pill(r.fresh ? 'approved' : r.status === 'approved' ? 'review due' : r.status, r.fresh ? 's-closed' : r.status === 'draft' ? 's-awaiting_approval' : 'late') + '</td><td>' + esc(r.owner || '—') + '</td><td class="muted">' + esc(r.approved_by ? r.approved_by + ' ' + String(r.approved_at).slice(0, 10) : '—') + '</td><td class="res"><button type="button" class="sm" data-rb="' + esc(r.key) + '">' + (r.status === 'missing' ? 'Write' : 'Open') + '</button>'
          + (r.status === 'draft' && r.author !== S.me ? '<button type="button" class="sm" data-rba="' + esc(r.key) + '">Approve</button>' : '') + '</td></tr>'; }).join('') + '</tbody></table></div>';
  }
  function p6(v) {
    return '<div class="gd">Every change to the mail path is planned in a window with its impact and rollback, approved by a different person. Patch gateway and Exchange nodes one at a time so maintenance never stops mail.</div><div class="bar"><button type="button" class="pri" id="w-new">+ Plan a window</button></div>'
      + (v.windows.length ? '<div class="tw"><table><thead><tr><th>Window</th><th>When</th><th>Systems</th><th>Status</th><th></th></tr></thead><tbody>' + v.windows.map(function (w) {
        return '<tr><td>' + esc(w.title) + '<div class="sugg"><b>Impact:</b> ' + esc(w.impact) + '<br><b>Rollback:</b> ' + esc(w.rollback) + '</div></td><td class="mono">' + esc(w.start.replace('T', ' ') + ' → ' + w.end.replace('T', ' ')) + '</td><td>' + esc(w.systems.join(', ')) + '</td><td>' + pill(w.status, w.status === 'approved' ? 's-closed' : 's-awaiting_approval') + '<div class="muted">' + esc(w.requested_by) + (w.approved_by ? ' → ' + esc(w.approved_by) : '') + '</div></td><td>' + (w.status !== 'approved' && w.requested_by !== S.me ? '<button type="button" class="sm" data-wa="' + esc(w.id) + '">Approve</button>' : '') + '</td></tr>'; }).join('') + '</tbody></table></div>' : '<div class="empty">No window planned yet.</div>');
  }
  function p7(v) {
    var rto = v.profile ? v.profile.rto_min : null;
    return '<div class="gd">Prove failover works: take one gateway node or DAG member down on purpose, time how long mail takes to recover and record it. It counts when it passed within the RTO' + (rto != null ? ' (' + rto + ' min)' : '') + ', is less than 6 months old and a different person approved it.</div><div class="bar"><button type="button" class="pri" id="t-new">+ Record a test</button></div>'
      + (v.tests.length ? '<div class="tw"><table><thead><tr><th>Date</th><th>Scenario</th><th>Result</th><th>Recovered in</th><th>Approved</th><th></th></tr></thead><tbody>' + v.tests.map(function (x) {
        return '<tr><td class="mono">' + esc(x.date) + '</td><td>' + esc(x.scenario) + '<div class="sugg">' + esc(x.evidence) + '</div></td><td>' + pill(x.result.replace(/_/g, ' '), x.result === 'passed' ? 's-closed' : x.result === 'failed' ? 'late' : 's-awaiting_approval') + '</td><td>' + esc(x.rto_achieved_min + ' min') + (rto != null && x.rto_achieved_min > rto ? ' ' + pill('over RTO', 'late') : '') + '</td><td class="muted">' + esc(x.approved_by || '—') + '</td><td>' + (!x.approved_by && x.recorded_by !== S.me ? '<button type="button" class="sm" data-ta="' + esc(x.id) + '">Approve</button>' : '') + '</td></tr>'; }).join('') + '</tbody></table></div>' : '<div class="empty">No failover test recorded yet.</div>');
  }
  function p8(v) {
    return '<div class="gd">Every outage the availability check recorded in the last 90 days gets a review: the root cause, the actions that stop it happening again and their owner - approved by a different person.</div>'
      + (v.outages.length ? '<div class="tw"><table><thead><tr><th>Outage</th><th>Minutes</th><th>Review</th><th></th></tr></thead><tbody>' + v.outages.map(function (o) { var r = o.review;
        return '<tr><td class="mono">' + esc(new Date(o.start).toISOString().slice(0, 16).replace('T', ' ')) + '<div class="muted">' + esc((o.hosts || []).join(', ')) + '</div></td><td>' + esc(o.minutes) + '</td><td>' + (r ? esc(r.root_cause) + '<div class="sugg"><b>Actions:</b> ' + esc(r.actions) + ' · <b>Owner:</b> ' + esc(r.owner) + '</div>' + pill(r.approved_by ? 'approved by ' + r.approved_by : 'awaiting approval', r.approved_by ? 's-closed' : 's-awaiting_approval') : pill('no review', 'late')) + '</td><td class="res">'
          + (!(r && r.approved_by) ? '<button type="button" class="sm" data-rv="' + esc(o.id) + '">' + (r ? 'Edit' : 'Write review') + '</button>' : '') + (r && !r.approved_by && r.author !== S.me ? '<button type="button" class="sm" data-rva="' + esc(o.id) + '">Approve</button>' : '') + '</td></tr>'; }).join('') + '</tbody></table></div>' : '<div class="empty">No outage in the last 90 days.</div>');
  }
  function p9(v) {
    return '<div class="gd">Each month the mail availability report - availability against the target, outages, route findings and reputation - is prepared and approved by a different person on the Email Dashboard (Reports). It is the evidence for management and the regulator.</div>'
      + (v.reports.length ? '<table><thead><tr><th>Report</th><th>Status</th><th>Approved by</th></tr></thead><tbody>' + v.reports.map(function (r) { return '<tr><td class="mono">' + esc(r.id) + '</td><td>' + pill(r.state, r.state === 'approved' ? 's-closed' : '') + '</td><td>' + esc(r.approved_by || '—') + '</td></tr>'; }).join('') + '</tbody></table>' : '<div class="empty">No report prepared yet.</div>')
      + '<div class="bar" style="margin-top:10px"><a href="email-dashboard.html"><button type="button">Open the Email Dashboard</button></a></div>';
  }

  document.addEventListener('click', function (ev) {
    var t = ev.target, b;
    if ((b = t.closest('[data-step]'))) { S.step = Number(b.getAttribute('data-step')); draw(); return; }
    if (t.id === 'p-save') { act('/mail-ops/profile', { service_owner: val('p-own'), escalation: val('p-esc'), oncall: val('p-onc').split(/[,;\s]+/).filter(Boolean), rto_min: Number(val('p-rto')), rpo_min: Number(val('p-rpo')), notes: val('p-notes') }, 'Saved'); return; }
    if ((b = t.closest('[data-rb]'))) { var key = b.getAttribute('data-rb'), r = S.v.runbooks.filter(function (x) { return x.key === key; })[0];
      ask(r.title, fld('d-own', 'Owner (user name)', 'text', '', r.owner || '') + fld('d-steps', 'Steps (what to check and do, in order)', 'textarea', '', r.steps) + fld('d-esc', 'Escalation (when and whom)', 'textarea', '', r.escalation) + fld('d-tools', 'Tools and contacts (optional)', 'textarea', '', r.tools) + (r.status === 'approved' ? '<p class="note">Saving a change makes it a draft again until a different person approves it.</p>' : ''), 'Save draft', function () {
        act('/mail-ops/runbooks/' + encodeURIComponent(key), { owner: val('d-own'), steps: val('d-steps'), escalation: val('d-esc'), tools: val('d-tools') }, 'Runbook saved - a different person approves it'); return true; }); return; }
    if ((b = t.closest('[data-rba]'))) { act('/mail-ops/runbooks/' + encodeURIComponent(b.getAttribute('data-rba')) + '/approve', {}, 'Runbook approved'); return; }
    if (t.id === 'w-new') { ask('Plan a maintenance window', fld('d-title', 'What', 'text') + '<div class="grid2">' + fld('d-start', 'Start', 'datetime-local') + fld('d-end', 'End', 'datetime-local') + '</div>' + fld('d-sys', 'Systems (comma separated)', 'text') + fld('d-imp', 'Impact on mail', 'textarea') + fld('d-rb', 'Rollback', 'textarea'), 'Request', function () {
      act('/mail-ops/windows', { title: val('d-title'), start: val('d-start').slice(0, 16), end: val('d-end').slice(0, 16), systems: val('d-sys').split(/[,;]+/).map(function (x) { return x.trim(); }).filter(Boolean), impact: val('d-imp'), rollback: val('d-rb') }, 'Window requested - a different person approves it'); return true; }); return; }
    if ((b = t.closest('[data-wa]'))) { act('/mail-ops/windows/' + encodeURIComponent(b.getAttribute('data-wa')) + '/approve', {}, 'Window approved'); return; }
    if (t.id === 't-new') { ask('Record a failover test', fld('d-date', 'Date', 'date') + fld('d-scn', 'Scenario', 'text') + fld('d-res', 'Result', 'select', '<option value="passed">Passed</option><option value="passed_with_issues">Passed with issues</option><option value="failed">Failed</option>') + fld('d-rto', 'Minutes until mail recovered', 'number') + fld('d-ev', 'Evidence (change number, report)', 'text') + fld('d-notes', 'Notes', 'textarea'), 'Record', function () {
      act('/mail-ops/tests', { date: val('d-date'), scenario: val('d-scn'), result: val('d-res'), rto_achieved_min: Number(val('d-rto')), evidence: val('d-ev'), notes: val('d-notes') }, 'Test recorded - a different person approves it'); return true; }); return; }
    if ((b = t.closest('[data-ta]'))) { act('/mail-ops/tests/' + encodeURIComponent(b.getAttribute('data-ta')) + '/approve', {}, 'Test approved'); return; }
    if ((b = t.closest('[data-rv]'))) { var oid = b.getAttribute('data-rv'), o = S.v.outages.filter(function (x) { return x.id === oid; })[0], rv = o.review || {};
      ask('Review of the outage ' + new Date(o.start).toISOString().slice(0, 16).replace('T', ' '), fld('d-rc', 'Root cause', 'textarea', '', rv.root_cause) + fld('d-act', 'Actions (what stops it happening again)', 'textarea', '', rv.actions) + fld('d-own', 'Owner of the actions (user name)', 'text', '', rv.owner), 'Save', function () {
        act('/mail-ops/reviews/' + encodeURIComponent(oid), { root_cause: val('d-rc'), actions: val('d-act'), owner: val('d-own') }, 'Review saved - a different person approves it'); return true; }); return; }
    if ((b = t.closest('[data-rva]'))) { act('/mail-ops/reviews/' + encodeURIComponent(b.getAttribute('data-rva')) + '/approve', {}, 'Review approved'); return; }
  });
  $('refresh').addEventListener('click', function () { load(); });
  $('dlgno').addEventListener('click', closeDlg);
  $('dlgok').addEventListener('click', function () { if (S.okFn && S.okFn() !== false) closeDlg(); });
  var w = new XMLHttpRequest(); w.open('GET', '/dashboards/whoami.json'); w.zybQuiet = true; w.timeout = 10000;
  w.onload = function () { try { var j = JSON.parse(w.responseText); S.role = j.role || 'viewer'; S.me = j.user || ''; $('me').textContent = S.me; } catch (e) { S.role = 'viewer'; /* no identity: the engine still enforces roles */ } load(); };
  w.onerror = w.ontimeout = function () { load(); /* identity unknown: the engine still enforces roles */ }; w.send();
})();
