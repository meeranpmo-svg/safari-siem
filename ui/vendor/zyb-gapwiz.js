// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
/* zyb-gapwiz.js - the gap-assessment wizard shared by Start a PDPL Gap Assessment (pdpl-gap-start.html) and Start an NCA ECC Gap
 * Assessment (nca-gap-start.html) and Start an ISO 27001 Gap Assessment (iso-gap-start.html). <body data-fw="pdpl|nca|iso|sama|ndmo"> picks
 * the framework: its API (/api/itam/pdpl/gap, /api/itam/nca-ecc/gap, /api/itam/iso27001/gap, /api/itam/sama-ia/gap, /api/itam/ndmo/gap; also sama-gap-start.html, ndmo-gap-start.html)
 * and its wording below. Seven steps, each showing what is done and what blocks it; the engine (engine/gap-engagement.js) enforces the
 * team, the approver (DPO / CISO) and four eyes. No inline handlers; every value escaped; requests zybQuiet. */
(function () {
  'use strict';
  var $ = function (i) { return document.getElementById(i); };
  var esc = function (v) { return String(v == null ? '' : v).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); };
  var CFGS = {
    pdpl: { base: '/pdpl/gap', who: 'PDPL team', profile: 'PDPL → Programme (profile)', s1: 'the departments and systems whose personal data is assessed',
      s2: 'the standard PDPL evidence list - each item with the article it proves', s3: 'A snapshot of what the PDPL registers hold before anyone answers - the questionnaire suggests answers from them. An empty register is shown as empty: it is a finding, not a zero to hide.',
      s4: 'The 40-question PDPL Self-Assessment over the 24 requirements, with the article for each. Every yes / partial needs its evidence and every no / not applicable a note. It is answered and submitted on the Self-Assessment page; the DPO (or an administrator) approves it there - never the person who submitted it.',
      s4btn: 'Start the self-assessment for this engagement', s5: 'Every question answered no, partial or left unanswered is a gap.' },
    nca: { base: '/nca-ecc/gap', who: 'cybersecurity team', profile: 'NCA ECC → Profile', s1: 'the departments and systems the cybersecurity controls cover',
      s2: 'the standard NCA ECC evidence list across the five domains - each item with the ECC subdomain it proves', s3: 'A snapshot of the NCA ECC control register before anyone records anything: which evidence sources are connected and how the controls stand. A source that is not connected leaves its controls "not measured" - a finding, never a pass.',
      s4: 'The NCA ECC-1:2018 control register. A control is verified by the platform\'s own evidence, or a person records it on the NCA ECC page (evidence for compliant / partial, a note for non-compliant / not applicable) and the CISO (or an administrator) approves it there - never the person who recorded it. The review is complete when no control is pending, not measured or without evidence. Automated evidence of a gap is never hidden by a confirmation.',
      s4btn: 'Link the NCA ECC register to this engagement', s5: 'Every control whose result is gap or partial is a gap.' },
    iso: { base: '/iso27001/gap', who: 'ISMS team', profile: 'ISO 27001 → Profile', s1: 'the departments, sites and systems inside the ISMS scope',
      s2: 'the documented information ISO/IEC 27001:2022 requires and the key Annex A records - each item with its clause or control', s3: 'A snapshot of the ISMS register before anyone records anything: how the clauses and Annex A controls stand, whether the Statement of Applicability is approved, and which evidence sources are connected. A source that is not connected leaves its controls "not measured" - a finding, never a pass.',
      s4: 'The ISMS register: clauses 4-10 and the 93 Annex A controls. An item is verified by the platform\'s own evidence, or a person records it on the ISO 27001 page (evidence for met / partial, a note for not met / not applicable) and the ISMS manager (or an administrator) approves it there - never the person who recorded it. The review is complete when nothing is pending, not measured or without evidence.',
      s4btn: 'Link the ISMS register to this engagement', s5: 'Every clause or Annex A control whose result is gap or partial is a gap.' },
    sama: { base: '/sama-ia/gap', who: 'cybersecurity team', profile: 'NCA ECC → Profile (the CISO is shared with the SAMA register)', s1: 'the departments and systems the SAMA Cyber Security Framework covers',
      s2: 'the standard SAMA CSF evidence list across the four domains and the Insurance Authority cyber circular - each item with its section', s3: 'A snapshot of the SAMA register before anyone records anything: how the requirements stand, the maturity against the target level, whether a CISO is named, and which evidence sources are connected. A source that is not connected leaves its requirements "not measured" - a finding, never a pass.',
      s4: 'The SAMA CSF register (with the Insurance Authority cyber circular). A requirement is verified by the platform\'s own evidence - the same evidence as the NCA ECC register - or a person records it on the SAMA CSF page (evidence for compliant / partial, a note for non-compliant / not applicable) and the CISO (or an administrator) approves it there - never the person who recorded it. The review is complete when nothing is pending, not measured or without evidence.',
      s4btn: 'Link the SAMA register to this engagement', s5: 'Every requirement whose result is gap or partial is a gap.' },
    ndmo: { base: '/ndmo/gap', who: 'data management team', profile: 'NDMO → Profile', s1: 'the departments, data domains and systems whose data management is assessed',
      s2: 'the standard NDMO evidence list - one item per data management domain, plus the strategy', s3: 'A snapshot of the NDMO register before anyone records anything: how the controls stand, the maturity of each of the 15 domains (0-5), whether a Chief Data Officer is named and how many official NDMO controls are imported and mapped. A domain at level 0 is a finding, not a zero to hide.',
      s4: 'The NDMO register over the 15 domains of the Data Management and Personal Data Protection Standards. A control is passed by the platform\'s own evidence, or a person records it on the NDMO page (evidence for compliant / partial, a note for non-compliant / not applicable) and the Chief Data Officer (or an administrator) approves it there - never the person who recorded it. The review is complete when nothing is pending or without evidence.',
      s4btn: 'Link the NDMO register to this engagement', s5: 'Every control whose result is gap or partial is a gap.' } };
  var FW = (document.body && document.body.getAttribute('data-fw')) || 'pdpl', C = CFGS[FW] || CFGS.pdpl;
  var S = { me: '', list: null, e: null, step: 1, dept: '', okFn: null };
  function req(m, u, b) { return new Promise(function (ok, bad) { var x = new XMLHttpRequest(); x.open(m, '/api/itam' + u); x.withCredentials = true; x.timeout = 90000; x.zybQuiet = true; if (b !== undefined) x.setRequestHeader('Content-Type', 'application/json');
    x.onload = function () { var j = null; try { j = JSON.parse(x.responseText); } catch (e) { j = null; } if (x.status >= 200 && x.status < 300 && j) return ok(j); bad(Object.assign(new Error((j && j.error) || ('HTTP ' + x.status)), { status: x.status })); };
    x.onerror = x.ontimeout = function () { bad(Object.assign(new Error('IT Asset Management is not reachable'), { status: 0 })); }; x.send(b !== undefined ? JSON.stringify(b) : null); }); }
  function toast(t) { var d = document.createElement('div'); d.className = 'toast'; d.setAttribute('role', 'status'); d.textContent = t; document.body.appendChild(d); setTimeout(function () { d.remove(); }, 6000); }
  var pill = function (t, c) { return '<span class="pill ' + (c || '') + '">' + esc(t) + '</span>'; };
  var val = function (i) { var el = $(i); return el ? String(el.value || '').trim() : ''; };
  var csv = function (s) { return s.split(/[,;\n]+/).map(function (x) { return x.trim(); }).filter(Boolean); };
  var fld = function (id, label, type, extra, v) { var inp = type === 'textarea' ? '<textarea id="' + id + '">' + esc(v || '') + '</textarea>' : type === 'select' ? '<select id="' + id + '">' + extra + '</select>' : '<input id="' + id + '" type="' + (type || 'text') + '" value="' + esc(v == null ? '' : v) + '">'; return '<label class="f" for="' + id + '">' + esc(label) + inp + '</label>'; };
  function ask(title, html, okText, fn) { $('dlgt').textContent = title; $('dlgb').innerHTML = html; $('dlgok').textContent = okText || 'OK'; S.okFn = fn; $('dlgbg').classList.add('open'); var f = $('dlgb').querySelector('input,textarea,select'); if (f) f.focus(); }
  function closeDlg() { $('dlgbg').classList.remove('open'); S.okFn = null; }
  function act(path, b, msg) { return req('POST', path, b || {}).then(function (r) { if (msg) toast(msg); return load(r && r.id).then(function () { return r; }); }, function (er) { toast('Not done: ' + er.message); return null; }); }

  function load(id) {
    var want = id || (S.e && S.e.id);
    return req('GET', C.base).then(function (L) { S.list = L; $('err').innerHTML = '';
      var sel = $('pick'); sel.hidden = L.engagements.length < 2; sel.innerHTML = L.engagements.map(function (x) { return '<option value="' + esc(x.id) + '">' + esc(x.id + ' · ' + x.name + ' (' + x.status + ')') + '</option>'; }).join('');
      if (want && (!L.current || L.current.id !== want) && L.engagements.some(function (x) { return x.id === want; })) return req('GET', C.base + '/' + encodeURIComponent(want)).then(function (e) { S.e = e; });
      S.e = L.current; return null;
    }).then(function () { if (S.e) { $('pick').value = S.e.id; if (!id && S.step === 1 && S.e.current_step) S.step = S.e.current_step; } draw(); }, function (er) {
      $('steps').innerHTML = ''; $('panel').innerHTML = '';
      $('err').innerHTML = '<div class="block">' + esc(er.status === 403 ? 'The gap assessment is for the ' + C.who + ': operators (assessors) and administrators.' : er.status === 404 ? 'This gap assessment is not installed yet - run the platform update.' : er.message) + '</div>'; });
  }
  function draw() {
    var e = S.e, steps = e ? e.steps : S.list.steps.map(function (t, i) { return { n: i + 1, title: t, done: false, what: i ? '' : 'not started', block: i ? 'open the gap assessment first' : null }; });
    $('steps').innerHTML = steps.map(function (s) { var cls = s.done ? 'done' : (e && e.current_step === s.n) || (!e && s.n === 1) ? 'now' : '';
      return '<li class="' + cls + '"><button type="button" data-step="' + s.n + '"' + (S.step === s.n ? ' aria-current="step"' : '') + '><span class="n">' + (s.done ? '✓' : s.n) + '</span><span><span class="t1">' + esc(s.title) + '</span><span class="t2">' + esc(s.what || '') + '</span></span></button></li>'; }).join('');
    var cur = steps[S.step - 1], h = '<div class="card"><h2>' + S.step + '. ' + esc(cur.title) + (e ? ' <span class="c">' + esc(e.id + ' · ' + e.name) + '</span>' : '') + '</h2>' + (cur.block ? '<div class="block">Next: ' + esc(cur.block) + '</div>' : cur.done ? '<div class="okb">Done - ' + esc(cur.what) + '</div>' : '');
    h += [p1, p2, p3, p4, p5, p6, p7][S.step - 1](e) + '</div>';
    $('panel').innerHTML = h;
  }
  // AI / ML panels: suggestions, clusters, forecast, evidence analytics - computed by the engine from this engagement only
  function aiNote() { return '<p class="muted" style="font-size:11.5px">Suggestions are computed from the register and this engagement; a person decides every rating, and the plan and the report are theirs.</p>'; }
  function clustersH(e) { var c = e.intel && e.intel.clusters; if (!c || !c.length) return '';
    return '<div class="ml"><h4>Gaps with one cause</h4><p class="muted">Fixing the cause closes the group together - plan them as one action.</p><ul>' + c.map(function (x) { return '<li><b>' + esc(x.gaps.length) + ' gaps</b> · ' + esc(x.cause) + ' <span class="mono muted">' + esc(x.gaps.join(', ')) + '</span></li>'; }).join('') + '</ul></div>'; }
  function forecastH(e) { var f = e.intel && e.intel.forecast; if (!f) return '<p class="muted">The forecast appears once gaps have owners and target dates.</p>';
    return '<div class="ml"><h4>Score forecast if the plan is delivered on time</h4><table><thead><tr><th>By</th><th>Gaps closed</th><th>Score</th></tr></thead><tbody><tr><td>now</td><td>0</td><td>' + esc(f.from) + '%</td></tr>' + f.points.map(function (p) { return '<tr><td>' + esc(p.date) + '</td><td>' + esc(p.gaps_closed) + '</td><td>' + esc(p.score) + '%</td></tr>'; }).join('') + '</tbody></table>' + (f.note ? '<p class="muted">' + esc(f.note) + '</p>' : '') + '</div>'; }
  function evidH(e) { var v = e.intel && e.intel.evidence; if (!v || !v.departments || !v.departments.length) return '';
    return '<div class="ml"><h4>Evidence by department</h4>' + (v.slowest ? '<p>' + esc(v.slowest) + '</p>' : '') + '<table><thead><tr><th>Department</th><th>Requests</th><th>Answered</th><th>Accepted</th><th>Returned</th><th>Overdue</th></tr></thead><tbody>' + v.departments.map(function (d) { return '<tr><td>' + esc(d.department) + '</td><td>' + esc(d.total) + '</td><td>' + esc(d.response_pct) + '%</td><td>' + esc(d.accepted) + '</td><td>' + esc(d.returned) + '</td><td>' + (d.overdue ? pill(d.overdue, 'late') : '0') + '</td></tr>'; }).join('') + '</tbody></table></div>'; }
  function compareH(e) { var c = e.compare;
    var h = '<div class="ml"><h4>Previous years</h4>';
    if (!c) return h + '<p class="muted">No earlier report imported. Import last year\'s gap report (this platform\'s Excel / CSV export, or a consultant\'s spreadsheet) to see recurring, new and closed gaps.</p><div class="bar"><button type="button" id="h-imp">Import a previous report</button><button type="button" id="h-list">Imported reports</button></div></div>';
    var row = function (x, extra) { return '<tr><td class="mono">' + esc(x.id) + '</td><td>' + esc(x.text) + '</td><td>' + esc(extra || '') + '</td></tr>'; };
    return h + '<p>Compared with <b>' + esc(c.with.label) + '</b> (' + esc(c.with.year) + ', ' + esc(c.with.rows) + ' rows).</p><div class="bar">' + pill('recurring ' + c.recurring.length, c.recurring.length ? 'late' : '') + pill('new ' + c.new.length, 's-awaiting_approval') + pill('closed since ' + c.closed.length, 's-closed') + '</div>'
      + (c.recurring.length ? '<h4>Recurring - a gap last time too</h4><table><thead><tr><th>Gap</th><th>Requirement</th><th>Last time</th></tr></thead><tbody>' + c.recurring.map(function (x) { return row(x, [x.before.result, x.before.risk, x.before.owner].filter(Boolean).join(' · ')); }).join('') + '</tbody></table>' : '')
      + (c.closed.length ? '<h4>Closed since</h4><table><thead><tr><th>Gap</th><th>Requirement</th><th>Last time</th></tr></thead><tbody>' + c.closed.map(function (x) { return row(x, x.result); }).join('') + '</tbody></table>' : '')
      + '<p class="muted">' + esc(c.note) + '</p><div class="bar"><button type="button" id="h-imp">Import a previous report</button><button type="button" id="h-list">Imported reports</button></div></div>'; }
  function p1(e) {
    var ed = !e || e.status === 'setup', x = e || { name: '', lead: S.me, assessors: [], sponsor: '', departments: [], systems: [], scope_note: '', start: new Date().toISOString().slice(0, 10), target: '' };
    var dpo = (S.list && S.list.approver) || null, an = (S.list && S.list.approver_name) || 'approver';
    var h = '<div class="gd">Name who leads the assessment and who assesses, and fix the scope: ' + esc(C.s1) + '. The ' + esc(an) + ' named in the profile approves the review and the report' + (dpo ? ' - currently <b>' + esc(dpo) + '</b>.' : ' - <b>no ' + esc(an) + ' is named yet</b>: name one in ' + esc(C.profile) + ' before step 4.') + '</div>';
    if (!ed) return h + '<dl class="kv"><dt>Lead</dt><dd>' + esc(e.lead) + '</dd><dt>Assessors</dt><dd>' + esc(e.assessors.join(', ') || '—') + '</dd><dt>Sponsor</dt><dd>' + esc(e.sponsor || '—') + '</dd><dt>Departments</dt><dd>' + esc(e.departments.join(', ')) + '</dd><dt>Systems</dt><dd>' + esc(e.systems.join(', ') || '—') + '</dd><dt>Scope note</dt><dd>' + esc(e.scope_note || '—') + '</dd><dt>Period</dt><dd>' + esc(e.start + ' → ' + e.target) + '</dd></dl><p class="note">The scope is fixed once the kick-off has gone out.</p>';
    return h + '<div class="grid2"><div>' + fld('g-name', 'Name of the assessment', 'text', '', x.name) + fld('g-lead', 'Lead assessor (user name)', 'text', '', x.lead) + fld('g-ass', 'Assessors (user names, comma separated)', 'text', '', x.assessors.join(', ')) + fld('g-spon', 'Sponsor (user name, optional)', 'text', '', x.sponsor) + '</div><div>'
      + fld('g-dept', 'Departments in scope (comma separated)', 'textarea', '', x.departments.join(', ')) + fld('g-sys', 'Systems in scope (optional)', 'text', '', x.systems.join(', ')) + '<div class="grid2">' + fld('g-start', 'Start', 'date', '', x.start) + fld('g-target', 'Target date for the report', 'date', '', x.target) + '</div></div></div>'
      + fld('g-note', 'Scope note (optional)', 'textarea', '', x.scope_note) + '<div class="bar" style="margin-top:10px"><button type="button" class="pri" id="g-save">' + (e ? 'Save the scope' : 'Open the gap assessment') + '</button></div>';
  }
  function p2(e) {
    if (!e) return '<div class="empty">Open the gap assessment in step 1 first.</div>';
    var h = '<div class="gd">The kick-off sends ' + esc(C.s2) + ' to every department in scope. As evidence comes back, record it as received with its reference, then accept it or return it with what is missing.</div>';
    if (e.status === 'setup') return h + '<p>' + esc(e.departments.length) + ' department(s) × ' + esc(S.list.evidence_catalogue.length) + ' standard items = ' + (e.departments.length * S.list.evidence_catalogue.length) + ' requests.</p><div class="bar">' + fld('k-due', 'Evidence due by', 'date', '', '') + '<button type="button" class="pri" id="k-send" style="align-self:flex-end">Send the kick-off</button></div>';
    var es = e.evidence_status, list = e.evidence.filter(function (x) { return !S.dept || x.department === S.dept; });
    h += '<div class="bar">' + ['requested', 'received', 'accepted', 'returned', 'na'].map(function (s) { return pill(s + ' ' + es[s], s === 'accepted' ? 's-closed' : s === 'returned' ? 'late' : s === 'received' ? 's-awaiting_approval' : ''); }).join('')
      + '<span class="sp" style="flex:1"></span><select id="k-dept" aria-label="Department"><option value="">All departments</option>' + e.departments.map(function (d) { return '<option' + (d === S.dept ? ' selected' : '') + '>' + esc(d) + '</option>'; }).join('') + '</select></div>';
    var cl = e.status === 'closed';
    h += evidH(e);
    return h + '<div class="tw"><table><thead><tr><th>Ref</th><th>Department</th><th>Evidence</th><th>Reference</th><th>Status</th><th>Reference / note</th><th></th></tr></thead><tbody>' + list.map(function (x) {
      return '<tr><td class="mono">' + esc(x.id) + '</td><td>' + esc(x.department) + '</td><td>' + esc(x.what) + '</td><td class="muted">' + esc(x.ref) + '</td><td>' + pill(x.status, x.status === 'accepted' ? 's-closed' : x.status === 'returned' ? 'late' : '') + '</td><td class="muted">' + esc(x.reference || '') + (x.note ? '<br>' + esc(x.note) : '') + '</td><td class="res">'
        + (cl ? '' : '<button type="button" class="sm" data-ev="received" data-id="' + esc(x.id) + '">Received</button><button type="button" class="sm" data-ev="accepted" data-id="' + esc(x.id) + '">Accept</button><button type="button" class="sm" data-ev="returned" data-id="' + esc(x.id) + '">Return</button><button type="button" class="sm" data-ev="na" data-id="' + esc(x.id) + '">N/A</button>') + '</td></tr>'; }).join('') + '</tbody></table></div>';
  }
  function p3(e) {
    if (!e) return '<div class="empty">Open the gap assessment in step 1 first.</div>';
    var h = '<div class="gd">' + esc(C.s3) + '</div>';
    if (!e.baseline) return h + (e.status === 'setup' ? '' : '<div class="bar"><button type="button" class="pri" id="b-take">Take the baseline</button></div>');
    var b = e.baseline, rows = (b.table || []).map(function (r) { return '<tr><td>' + esc(r.label) + '</td><td>' + (r.flag ? pill(r.flag_text || 'empty', 'late') : esc(r.text != null ? r.text : r.value)) + '</td><td>' + (r.flag && r.fix ? '<a href="' + esc(r.fix) + '">fix it</a>' : '') + '</td></tr>'; }).join('');
    return h + '<p class="muted">Taken ' + esc(b.at.slice(0, 16).replace('T', ' ')) + ' by ' + esc(b.by) + (b.summary ? ' · ' + esc(b.summary) : '') + '</p><div class="tw"><table><thead><tr><th>Item</th><th>Value</th><th></th></tr></thead><tbody>' + rows + '</tbody></table></div>'
      + (e.status !== 'closed' && !e.review ? '<div class="bar" style="margin-top:8px"><button type="button" id="b-take">Take it again</button></div>' : '');
  }
  function p4(e) {
    if (!e) return '<div class="empty">Open the gap assessment in step 1 first.</div>';
    var h = '<div class="gd">' + esc(C.s4) + '</div>', a = e.review;
    if (!a) return h + (e.baseline ? '<div class="bar"><button type="button" class="pri" id="a-start">' + esc(C.s4btn) + '</button></div>' : '');
    h += '<dl class="kv"><dt>Review</dt><dd>' + esc(a.id + ' · ' + a.label) + '</dd><dt>Status</dt><dd>' + pill(a.done ? 'complete' : a.status, a.done ? 's-closed' : 's-awaiting_approval') + '</dd><dt>Assessed</dt><dd>' + esc(a.progress ? a.progress.answered + ' of ' + a.progress.total : '—') + '</dd><dt>Score</dt><dd>' + esc(a.score == null ? '—' : a.score + '%') + '</dd>' + (a.submitted_by ? '<dt>Submitted by</dt><dd>' + esc(a.submitted_by) + '</dd>' : '') + (a.approved_by ? '<dt>Approver</dt><dd>' + esc(a.approved_by) + '</dd>' : '') + '</dl>';
    if (a.chapters && a.chapters.length) h += '<h4>By area</h4><table><thead><tr><th>Area</th><th>Score</th><th>Gaps</th></tr></thead><tbody>' + a.chapters.map(function (c) { return '<tr><td>' + esc(c.area) + '</td><td>' + esc(c.score == null ? '—' : c.score + '%') + '</td><td>' + esc(c.gaps) + '</td></tr>'; }).join('') + '</tbody></table>';
    return h + (!a.done && a.link ? '<div class="bar" style="margin-top:10px"><a href="' + esc(a.link.href) + '"><button type="button" class="pri">' + esc(a.link.text) + '</button></a></div>' : '');
  }
  function lv(r) { return r ? pill(r.level + ' ' + r.score, r.level === 'critical' || r.level === 'high' ? 'late' : r.level === 'medium' ? 's-awaiting_approval' : '') : pill('not rated'); }
  function p5(e) {
    if (!e) return '<div class="empty">Open the gap assessment in step 1 first.</div>';
    var h = '<div class="gd">' + esc(C.s5) + ' Rate each one: likelihood and impact (1-5, risk = likelihood × impact: 15+ critical, 10+ high, 5+ medium), the root cause, the recommendation, the owner and the target date.</div>';
    if (!(e.review && e.review.done) && !e.plan) return h;
    if (!e.gaps.length) return h + '<div class="okb">No gaps were found.</div>';
    var g = e.gap_levels, sg = (e.intel && e.intel.suggestions) || {};
    h += clustersH(e) + compareH(e);
    return h + aiNote() + '<div class="bar">' + pill('critical ' + g.critical, 'late') + pill('high ' + g.high, 'late') + pill('medium ' + g.medium, 's-awaiting_approval') + pill('low ' + g.low) + '</div><div class="tw"><table><thead><tr><th>Gap</th><th>Requirement</th><th>Question</th><th>Answer</th><th>Risk</th><th>Owner · target</th><th></th></tr></thead><tbody>' + e.gaps.map(function (x) {
      return '<tr><td class="mono">' + esc(x.id) + '</td><td>' + esc(x.req) + '<div class="muted">' + esc(x.ref) + '</div></td><td>' + esc(x.text) + (x.rating ? '<div class="sugg"><b>Root cause:</b> ' + esc(x.rating.root_cause) + '<br><b>Recommendation:</b> ' + esc(x.rating.recommendation) + '</div>' : '') + '</td><td>' + pill(x.answer, 'late') + '</td><td>' + lv(x.risk) + (!x.rating && sg[x.id] ? '<div class="sugg">suggested ' + esc(sg[x.id].likelihood + ' × ' + sg[x.id].impact) + '</div>' : '') + '</td><td>' + (x.rating ? esc(x.rating.owner + ' · ' + x.rating.target) : '—') + '</td><td>' + (e.plan ? '' : '<button type="button" class="sm" data-rate="' + esc(x.id) + '">' + (x.rating ? 'Edit' : 'Rate') + '</button>') + '</td></tr>'; }).join('') + '</tbody></table></div>';
  }
  function p6(e) {
    if (!e) return '<div class="empty">Open the gap assessment in step 1 first.</div>';
    var h = '<div class="gd">Publishing writes each gap\'s owner, target date, priority, root cause and recommendation onto its GRC remediation action, so the plan is tracked - and verified closed by a second person - with every other action.</div>';
    if (e.plan) return h + '<p>Published ' + esc(e.plan.at.slice(0, 16).replace('T', ' ')) + ' by ' + esc(e.plan.by) + ': <b>' + esc(e.plan.actions.length) + '</b> GRC action(s) ' + esc(e.plan.actions.join(', ')) + '.</p>' + (e.plan.failed.length ? '<div class="block">Not written: ' + esc(e.plan.failed.join('; ')) + '</div>' : '') + '<a href="grc-register.html">Open the GRC register →</a>' + forecastH(e);
    var by = {}; e.gaps.forEach(function (g) { if (g.rating) { by[g.rating.owner] = by[g.rating.owner] || []; by[g.rating.owner].push(g); } });
    var rows = Object.keys(by).sort().map(function (o) { return '<tr><td>' + esc(o) + '</td><td>' + esc(by[o].length) + '</td><td>' + esc(by[o].map(function (g) { return g.id + ' (' + g.rating.target + ')'; }).join(', ')) + '</td></tr>'; }).join('');
    h += forecastH(e);
    return h + (rows ? '<table><thead><tr><th>Owner</th><th>Gaps</th><th>Due</th></tr></thead><tbody>' + rows + '</tbody></table>' : '') + (e.review && e.review.done ? '<div class="bar" style="margin-top:10px"><button type="button" class="pri" id="pl-pub">Publish the remediation plan</button></div>' : '');
  }
  function p7(e) {
    if (!e) return '<div class="empty">Open the gap assessment in step 1 first.</div>';
    var h = '<div class="gd">The lead assessor writes the executive summary and signs the report; the ' + esc(e.approver_name || 'approver') + ' (or an administrator) approves it - never the person who signed. The report prints on white with the company logo.</div>', cl = e.status === 'closed';
    h += '<div class="bar"><button type="button" id="r-html">Report (print / PDF)</button><button type="button" id="r-xlsx">Export to Excel</button><button type="button" id="r-csv">Gap register CSV</button></div>' + compareH(e);
    if (!e.plan) return h;
    var ai = e.intel && e.intel.ai;
    if (!e.signed_by) h += '<div class="ml"><h4>AI draft of the summary</h4>' + (ai && ai.enabled ? '<p class="muted">Drafted from this engagement\'s own facts (scope, review score, gaps, plan). It stays a draft: you read it, edit it and adopt it - nothing is signed by it.</p><div class="bar"><button type="button" id="r-ai">Draft the summary with AI</button>' + (e.ai_draft ? '<button type="button" id="r-adopt">Use the draft in the summary</button>' : '') + '</div>' + (e.ai_draft ? '<div class="sugg" style="white-space:pre-wrap;margin-top:6px">' + esc(e.ai_draft.text) + '</div><p class="muted">Drafted ' + esc(String(e.ai_draft.at).slice(0, 16).replace('T', ' ')) + ' for ' + esc(e.ai_draft.requested_by) + (e.ai_draft.model ? ' · ' + esc(e.ai_draft.model) : '') + '</p>' : '') : '<p class="muted">' + esc((ai && ai.reason) || 'AI is not available') + '. The summary is written by hand.</p>') + '</div>';
    h += fld('r-sum', 'Executive summary', 'textarea', '', e.summary || '');
    if (!e.signed_by) h += '<div class="bar" style="margin-top:8px"><button type="button" id="r-save">Save the summary</button><button type="button" class="pri" id="r-sign">Save and sign the report</button></div>';
    else h += '<p>Signed by <b>' + esc(e.signed_by) + '</b> ' + esc(String(e.signed_at).slice(0, 10)) + '.' + (e.approved_by ? ' Approved by <b>' + esc(e.approved_by) + '</b> ' + esc(String(e.approved_at).slice(0, 10)) + ' - the engagement is closed.' : '') + '</p>' + (cl ? '' : '<div class="bar"><button type="button" class="pri" id="r-appr">Approve the report</button>' + (e.signed_by === S.me ? '<span class="muted">You signed it - a different person approves it (four eyes).</span>' : '') + '</div>');
    return h;
  }
  function report(fmt) { var e = S.e; req('GET', C.base + '/' + encodeURIComponent(e.id) + '/report?format=' + fmt).then(function (r) {
    if (fmt === 'json') { if (!window.zybXlsx) { toast('The Excel writer did not load - refresh the page'); return; } xlsxOf(r); return; }
    if (fmt === 'csv') { var a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([r.csv], { type: 'text/csv' })); a.download = r.filename; document.body.appendChild(a); a.click(); setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 1000); return; }
    var w = window.open('', '_blank'); if (w) { w.document.open(); w.document.write(r.html); w.document.close(); } }, function (er) { toast(er.message); }); }

  function xlsxOf(r) {
    var g = r.engagement, cmp = r.compare, sheets = [
      { name: 'Gaps', columns: [{ h: 'Gap', w: 14 }, { h: C.reqLabel || 'Requirement', w: 24 }, { h: 'Area', w: 20 }, { h: 'Reference', w: 18 }, { h: 'Text', w: 50 }, { h: 'Result', w: 10 }, { h: 'Likelihood', t: 'n' }, { h: 'Impact', t: 'n' }, { h: 'Risk', w: 10 }, { h: 'Risk score', t: 'n' }, { h: 'Root cause', w: 36 }, { h: 'Recommendation', w: 36 }, { h: 'Owner', w: 16 }, { h: 'Target', t: 'd' }],
        rows: r.gaps.map(function (x) { return [x.id, x.requirement, x.area, x.reference, x.text, x.result, x.likelihood, x.impact, x.risk || 'not rated', x.risk_score, x.root_cause, x.recommendation, x.owner, x.target]; }) },
      { name: 'Areas', columns: [{ h: 'Area', w: 40 }, { h: 'Score', t: 'n' }, { h: 'Gaps', t: 'n' }], rows: (r.chapters || []).map(function (c) { return [c.area, c.score, c.gaps]; }) },
      { name: 'Evidence', columns: [{ h: 'Ref', w: 12 }, { h: 'Department', w: 18 }, { h: 'Evidence', w: 50 }, { h: 'Reference', w: 18 }, { h: 'Due', t: 'd' }, { h: 'Status', w: 12 }, { h: 'Reference / note', w: 36 }], rows: (r.evidence || []).map(function (x) { return [x.id, x.department, x.what, x.ref, x.due, x.status, x.reference || x.note || '']; }) }];
    if (cmp) sheets.push({ name: 'Year on year', columns: [{ h: 'Change', w: 12 }, { h: 'Gap', w: 14 }, { h: 'Text', w: 50 }, { h: 'Last time (' + cmp.with.year + ')', w: 30 }],
      rows: cmp.recurring.map(function (x) { return ['recurring', x.id, x.text, [x.before.result, x.before.risk, x.before.owner].filter(Boolean).join(' · ')]; }).concat(cmp.new.map(function (x) { return ['new', x.id, x.text, '']; }), cmp.closed.map(function (x) { return ['closed since', x.id, x.text, x.result]; })) });
    window.zybXlsx.download(r.filename, sheets, { title: r.title, filter: g.id + ' (' + g.status + ')' + (g.approved_by ? ', approved by ' + g.approved_by : '') + ' - ' + r.disclaimer, by: S.me || 'unknown' });
    toast('Excel exported'); }
  function readB64(file) { return new Promise(function (ok, bad) { var fr = new FileReader(); fr.onload = function () { ok(String(fr.result).split(',')[1] || ''); }; fr.onerror = function () { bad(new Error('the file could not be read')); }; fr.readAsDataURL(file); }); }
  function histDlg() { var y = new Date().getFullYear() - 1;
    ask('Import a previous gap report', '<p class="muted">An Excel (.xlsx) or CSV file with one row per gap. The columns are found by their headings: gap / control / clause id or requirement text (needed), and result, risk, owner, target, root cause, recommendation, area if present. Only the rows and the file\'s fingerprint (SHA-256) are kept, not the file.</p>' + fld('h-file', 'File', 'file', 'accept=".xlsx,.csv"') + '<div class="grid2">' + fld('h-year', 'Year of the report', 'number', 'min="2010" max="2100"', y) + fld('h-label', 'Label (optional)', 'text', '', '') + '</div>', 'Import', function () {
      var f = $('h-file') && $('h-file').files && $('h-file').files[0], yr = Number(val('h-year'));
      if (!f) { toast('Choose the file.'); return false; } if (!/\.(xlsx|csv)$/i.test(f.name)) { toast('An .xlsx or .csv file.'); return false; } if (f.size > 25 * 1024 * 1024) { toast('The file is over 25 MB.'); return false; } if (!(yr >= 2010 && yr <= 2100)) { toast('The year of the report is needed.'); return false; }
      readB64(f).then(function (b64) { var body = { filename: f.name, data_b64: b64, year: yr }; if (val('h-label')) body.label = val('h-label'); return req('POST', C.base + '/history/import', body); })
        .then(function (r) { var n = r.reports.filter(function (x) { return x.year === yr; })[0]; toast('Imported ' + (n ? n.rows + ' rows (' + n.columns.join(', ') + ')' : '')); return load(S.e && S.e.id); }, function (er) { toast('Not imported: ' + er.message); }); return true; }); }
  function histList() { req('GET', C.base + '/history').then(function (r) {
    ask('Imported reports', r.reports.length ? '<table><thead><tr><th>Year</th><th>Label</th><th>Rows</th><th>File</th><th>By</th><th></th></tr></thead><tbody>' + r.reports.map(function (x) { return '<tr><td>' + esc(x.year) + '</td><td>' + esc(x.label) + '</td><td>' + esc(x.rows) + '</td><td>' + esc(x.filename) + '<div class="muted mono">' + esc(x.sha256) + '</div></td><td>' + esc(x.by + ' ' + String(x.at).slice(0, 10)) + '</td><td><button type="button" class="sm" data-hrm="' + esc(x.id) + '">Remove</button></td></tr>'; }).join('') + '</tbody></table><p class="muted">An administrator removes an import.</p>' : '<p class="muted">None yet.</p>', 'Close', function () { return true; }); }, function (er) { toast(er.message); }); }

  document.addEventListener('click', function (ev) {
    var t = ev.target, b, e = S.e, P = e ? C.base + '/' + encodeURIComponent(e.id) : '';
    if ((b = t.closest('[data-step]'))) { S.step = Number(b.getAttribute('data-step')); draw(); return; }
    if (t.id === 'g-save') { var body = { name: val('g-name'), lead: val('g-lead'), assessors: csv(val('g-ass')), departments: csv(val('g-dept')), systems: csv(val('g-sys')), scope_note: val('g-note'), start: val('g-start'), target: val('g-target') }; if (val('g-spon')) body.sponsor = val('g-spon');
      if (!body.name || !body.lead || !body.departments.length || !body.target) { toast('Name, lead, at least one department and the target date are needed.'); return; }
      if (e) act(P + '/scope', body, 'Scope saved'); else req('POST', C.base, body).then(function (r) { toast(r.id + ' opened - send the kick-off next'); S.step = 2; return load(r.id); }, function (er) { toast('Not done: ' + er.message); }); return; }
    if (t.id === 'k-send') { if (!val('k-due')) { toast('Choose the date the evidence is due.'); return; } act(P + '/kickoff', { due: val('k-due') }, 'Kick-off sent'); return; }
    if ((b = t.closest('[data-ev]'))) { var st = b.getAttribute('data-ev'), rid = b.getAttribute('data-id'), path = P + '/evidence/' + encodeURIComponent(rid);
      if (st === 'accepted') { act(path, { status: 'accepted' }, rid + ' accepted'); return; }
      var isRef = st === 'received'; ask((isRef ? 'Received ' : st === 'na' ? 'Not applicable ' : 'Return ') + rid, fld('d-x', isRef ? 'Reference (document, register or link)' : st === 'na' ? 'Why it does not apply' : 'What is missing', isRef ? 'text' : 'textarea'), 'Save', function () {
        if (!val('d-x')) { toast('This is needed.'); return false; } var o = { status: st }; o[isRef ? 'reference' : 'note'] = val('d-x'); act(path, o, rid + ': ' + st); return true; }); return; }
    if (t.id === 'b-take') { act(P + '/baseline', {}, 'Baseline taken'); return; }
    if (t.id === 'a-start') { act(P + '/review', {}, 'Review linked'); return; }
    if ((b = t.closest('[data-rate]'))) { var gid = b.getAttribute('data-rate'), g = e.gaps.filter(function (x) { return x.id === gid; })[0] || {}, r0 = g.rating || {}, su = (e.intel && e.intel.suggestions && e.intel.suggestions[gid]) || null;
      var opt = function (v) { return [1, 2, 3, 4, 5].map(function (n) { return '<option' + (n === v ? ' selected' : '') + '>' + n + '</option>'; }).join(''); };
      ask('Rate ' + gid, '<p class="muted">' + esc(g.text) + '</p>' + (su ? '<div class="sugg" id="d-su"><b>Suggested:</b> likelihood ' + esc(su.likelihood) + ' × impact ' + esc(su.impact) + ' - ' + esc((su.why || []).join('; ')) + ' <button type="button" class="sm" id="d-use">Use the suggestion</button></div>' : '') + '<div class="grid2">' + fld('d-l', 'Likelihood (1-5)', 'select', opt(r0.likelihood || (su && su.likelihood) || 3)) + fld('d-i', 'Impact (1-5)', 'select', opt(r0.impact || (su && su.impact) || 3)) + '</div>' + fld('d-rc', 'Root cause', 'textarea', '', r0.root_cause) + fld('d-rec', 'Recommendation', 'textarea', '', r0.recommendation) + '<div class="grid2">' + fld('d-o', 'Owner (user name)', 'text', '', r0.owner) + fld('d-t', 'Target date', 'date', '', r0.target) + '</div>', 'Save', function () {
        act(P + '/gaps/' + encodeURIComponent(gid), { likelihood: Number(val('d-l')), impact: Number(val('d-i')), root_cause: val('d-rc'), recommendation: val('d-rec'), owner: val('d-o'), target: val('d-t') }, gid + ' rated'); return true; }); return; }
    if (t.id === 'pl-pub') { act(P + '/plan', {}, 'Remediation plan published to the GRC actions'); return; }
    if (t.id === 'r-save') { act(P + '/report/summary', { summary: val('r-sum') }, 'Summary saved'); return; }
    if (t.id === 'r-sign') { var s0 = val('r-sum'); (s0 && s0 !== (e.summary || '') ? req('POST', P + '/report/summary', { summary: s0 }) : Promise.resolve()).then(function () { return act(P + '/report/sign', {}, 'Report signed - ' + (e.approver_name || 'the approver') + ' approves it'); }, function (er) { toast('Not done: ' + er.message); }); return; }
    if (t.id === 'r-appr') { act(P + '/report/approve', {}, 'Report approved - the gap assessment is closed'); return; }
    if (t.id === 'r-html') { report('html'); return; } if (t.id === 'r-csv') { report('csv'); return; } if (t.id === 'r-xlsx') { report('json'); return; }
    if (t.id === 'd-use') { var gs = e && e.intel && e.intel.suggestions, sid = ($('dlgt').textContent || '').replace(/^Rate /, ''), s1 = gs && gs[sid]; if (s1) { $('d-l').value = String(s1.likelihood); $('d-i').value = String(s1.impact); } return; }
    if (t.id === 'r-ai') { t.disabled = true; req('POST', P + '/report/ai-draft', {}).then(function () { toast('Draft ready - read it before using it'); return load(e.id); }, function (er) { t.disabled = false; toast('No draft: ' + er.message); }); return; }
    if (t.id === 'r-adopt') { var sb = $('r-sum'); if (sb && e.ai_draft) { sb.value = e.ai_draft.text; sb.focus(); toast('The draft is in the summary - edit it, then save'); } return; }
    if (t.id === 'h-imp') { histDlg(); return; } if (t.id === 'h-list') { histList(); return; }
    if ((b = t.closest('[data-hrm]'))) { var hid = b.getAttribute('data-hrm'); req('POST', C.base + '/history/' + encodeURIComponent(hid) + '/remove', {}).then(function () { toast(hid + ' removed'); closeDlg(); return load(e && e.id); }, function (er) { toast('Not removed: ' + er.message); }); return; }
  });
  document.addEventListener('change', function (ev) { if (ev.target.id === 'k-dept') { S.dept = ev.target.value; draw(); } if (ev.target.id === 'pick') { S.step = 1; load(ev.target.value); } });
  $('refresh').addEventListener('click', function () { load(); });
  $('dlgno').addEventListener('click', closeDlg);
  $('dlgok').addEventListener('click', function () { if (S.okFn && S.okFn() !== false) closeDlg(); });
  req('GET', '/roles/me').then(function (r) { S.me = (r && r.user) || ''; $('me').textContent = S.me; }, function () { /* the name is only shown; the engine decides */ }).then(function () { load(); });
})();
