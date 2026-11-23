// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
/* zyb-arepo.js - Audit Repository (audit-repo.html) over /api/itam/audit-repo: previous years' audits and inspections, their report files
 * and findings, the year x body matrix, repeat proposals a person decides, systemic areas, carried-forward findings, Excel import of a
 * management letter and Excel export of the register. Every value is escaped; nothing here decides - people do. */
(function () {
  'use strict';
  var P = window.zybPdpl, Z = window.zybDetail, esc = P.esc, $ = P.$;
  var V = null, TAB = 'ov', F = { chip: null, body: '', year: '', status: '', q: '' }, CUR = null, PEND = null;
  var RB = { critical: 'red', high: 'orange', medium: 'yellow', low: 'blue' }, SB = { open: 'orange', in_progress: 'yellow', closed: 'green', risk_accepted: 'purple', not_agreed: 'secondary' };
  var ST = { open: 'open', in_progress: 'in progress', closed: 'closed', risk_accepted: 'risk accepted', not_agreed: 'not agreed' };
  function dt(s) { return s ? String(s).slice(0, 10) : '—'; }
  function b64(buf) { var u = new Uint8Array(buf), s = '', i; for (i = 0; i < u.length; i += 32768) s += String.fromCharCode.apply(null, u.subarray(i, i + 32768)); return btoa(s); }
  function sha256(buf) { return window.crypto && crypto.subtle ? crypto.subtle.digest('SHA-256', buf).then(function (h) { return [].map.call(new Uint8Array(h), function (x) { return ('0' + x.toString(16)).slice(-2); }).join(''); }) : Promise.resolve(''); }
  function readFile(f, asText) { return new Promise(function (ok, bad) { var r = new FileReader(); r.onload = function () { ok(r.result); }; r.onerror = function () { bad(new Error('the file could not be read in the browser')); }; if (asText) r.readAsText(f); else r.readAsArrayBuffer(f); }); }
  function load() {
    return P.req('GET', '/audit-repo').then(function (v) { V = v; $('err').innerHTML = ''; $('main').hidden = false; draw(); if (CUR) reopen(); })
      .catch(function (e) { $('main').hidden = true; P.fail($('err'), e); $('up').textContent = 'not loaded'; });
  }
  function bodyName(k) { return (V.bodies_catalogue || {})[k] || k; }
  function chip(f, v, l, cls) { return '<div class="col-6 col-md-3 col-xl" data-f="' + esc(f) + '" role="button" tabindex="0" aria-pressed="' + (F.chip === f || (f === 'all' && !F.chip)) + '"><div class="card card-sm"><div class="card-body"><div class="au-num' + (cls ? ' ' + cls : '') + '">' + esc(v == null ? '—' : v) + '</div><div class="au-lbl">' + esc(l) + '</div></div></div></div>'; }
  function draw() {
    var k = V.kpis; $('up').textContent = 'as of ' + String(V.generated_at).slice(0, 16).replace('T', ' ') + ' UTC';
    $('kpis').innerHTML = chip('all', k.findings, 'Findings, ' + k.reports + ' report(s), ' + k.years + ' year(s)', '') + chip('open', k.open, 'Still open', k.open ? 'text-orange' : 'text-green') + chip('overdue', k.overdue, 'Past their due date', k.overdue ? 'text-red' : 'text-green')
      + chip('carried', k.carried, 'Carried forward from earlier years', k.carried ? 'text-orange' : 'text-green') + chip('repeat', k.repeats, 'Confirmed repeats', k.repeats ? 'text-red' : 'text-green') + chip('proposals', k.proposals, 'Possible repeats to decide', k.proposals ? 'text-orange' : '')
      + chip('closed', k.closure_rate == null ? '—' : k.closure_rate + '%', 'Closure rate (smoothed)', '');
    $('acts').innerHTML = V.actions.length ? V.actions.map(function (a) { return '<div class="act ' + (a.priority >= 80 ? 'p-hi' : a.priority >= 50 ? 'p-md' : 'p-lo') + '" data-act="' + esc(a.filter) + '" role="button" tabindex="0"><b>' + esc(a.title) + '</b><div class="mut">' + esc(a.detail) + '</div></div>'; }).join('')
      : (V.kpis.findings ? '<div class="text-green">Nothing outstanding: no open finding is overdue, carried forward or a repeat.</div>' : '<div class="mut">No audit recorded yet. Record last years\' SAMA, Insurance Authority, NCA, external and internal audit reports with <b>Record an audit report</b>, then import each management letter\'s findings from Excel.</div>');
    var M = V.matrix; $('hm').innerHTML = M.rows.length ? '<table class="table table-sm hm mb-0"><thead><tr><th>Body</th>' + M.years.map(function (y) { return '<th>' + esc(y) + '</th>'; }).join('') + '</tr></thead><tbody>' + M.rows.map(function (r) {
      return '<tr><th class="text-nowrap">' + esc(r.name) + '</th>' + r.cells.map(function (c, i) { return '<td>' + (c ? '<span class="c' + (c.open ? ' o' : '') + (c.repeats ? ' r' : '') + '" data-cell="' + esc(r.body) + '|' + esc(M.years[i]) + '" role="button" tabindex="0" title="' + esc(c.findings + ' finding(s), ' + c.open + ' open, ' + c.repeats + ' repeat(s)') + '"><b>' + esc(c.findings) + '</b>' + (c.open ? '<div class="mut">' + esc(c.open) + ' open</div>' : '') + '</span>' : '<span class="c n mut">—</span>') + '</td>'; }).join('') + '</tr>'; }).join('') + '</tbody></table>' : '<div class="mut">The matrix fills as reports are recorded.</div>';
    var Y = V.by_year.slice().reverse(), mx = Math.max.apply(null, Y.map(function (y) { return y.findings; }).concat([1]));
    $('yy').innerHTML = Y.length ? '<div class="yb" aria-label="findings per year">' + Y.map(function (y) { return '<div title="' + esc(y.findings + ' finding(s), ' + y.open + ' open') + '"><span class="small">' + esc(y.findings) + '</span><i style="height:' + Math.max(2, Math.round((y.findings - y.open) / mx * 100)) + '%"></i>' + (y.open ? '<i class="o" style="height:' + Math.round(y.open / mx * 100) + '%;border-radius:0"></i>' : '') + '<span class="mut">' + esc(y.year) + '</span></div>'; }).join('') + '</div>'
      + P.table([['Year', function (y) { return '<b>' + esc(y.year) + '</b>'; }], ['Findings', function (y) { return esc(y.findings) + ' <span class="mut">' + esc(y.by_rating.critical + y.by_rating.high) + ' critical/high</span>'; }], ['Closed', function (y) { return y.closure_rate == null ? '—' : esc(y.closure_rate) + '%'; }], ['Median days to close', function (y) { return esc(y.median_days_to_close == null ? '—' : y.median_days_to_close); }], ['Repeats', function (y) { return y.repeats ? P.badge(y.repeats + ' repeat', 'red') : '—'; }]], V.by_year)
      + (V.trend ? '<div class="mut mt-2">Findings per year are <b>' + esc(V.trend.direction) + '</b> (' + esc(V.trend.per_year > 0 ? '+' : '') + esc(V.trend.per_year) + ' a year over ' + esc(V.trend.years) + ' years). Closure rates are smoothed so one closure never reads 100 %.</div>' : '<div class="mut mt-2">A trend needs three years with findings.</div>') : '<div class="mut">No year recorded yet.</div>';
    $('sys').innerHTML = V.systemic.length ? V.systemic.map(function (s) { return '<div class="mb-2" data-area="' + esc(s.area) + '" role="button" tabindex="0"><b>' + esc(s.area) + '</b> ' + P.badge(s.years.length + ' years', 'red') + ' <span class="mut">' + esc(s.years.join(', ')) + ' · ' + esc(s.findings) + ' finding(s), ' + esc(s.open) + ' open</span></div>'; }).join('') + '<div class="mut">A weakness found year after year needs a programme with a root cause, not another ticket.</div>' : '<div class="mut">No area has findings in three or more years.</div>';
    $('props').innerHTML = V.proposals.length ? V.proposals.slice(0, 30).map(function (p) { return '<div class="cand"><div><b>' + esc(p.finding) + '</b> · ' + esc(bodyName(p.body)) + ' ' + esc(p.year) + ' · ' + esc(p.title) + '</div>' + p.candidates.map(function (c) {
      return '<div class="d-flex flex-wrap align-items-center gap-2 mt-1"><span class="mut">looks like</span><b>' + esc(c.of) + '</b><span>' + esc(bodyName(c.body)) + ' ' + esc(c.year) + ' · ' + esc(c.title) + '</span>' + P.badge('score ' + c.score, c.score >= 0.7 ? 'red' : 'orange') + '<span class="mut">' + esc(c.why.join(' · ')) + '</span><button type="button" class="btn btn-sm btn-danger" data-rep="confirm" data-f2="' + esc(p.finding) + '" data-of="' + esc(c.of) + '">Confirm repeat</button><button type="button" class="btn btn-sm" data-rep="reject" data-f2="' + esc(p.finding) + '" data-of="' + esc(c.of) + '">Not a repeat</button></div>'; }).join('') + '</div>'; }).join('')
      : '<div class="mut">No likely repeat to decide. Proposals compare each finding with earlier years\' findings: words in common, the same area and shared controls.</div>';
    var years = V.findings.map(function (f) { return f.year; }).filter(function (y, i, a) { return a.indexOf(y) === i; }).sort(function (a, b) { return b - a; });
    keepSel('f-body', [['', 'All bodies']].concat(V.by_body.map(function (b) { return [b.body, b.name]; })), F.body); keepSel('f-year', [['', 'All years']].concat(years.map(function (y) { return [String(y), String(y)]; })), F.year);
    keepSel('f-status', [['', 'Any status']].concat(V.statuses.map(function (s) { return [s, ST[s] || s]; })), F.status);
    drawFindings();
    $('rl').innerHTML = P.table([['Year', function (r) { return '<b>' + esc(r.year) + '</b>'; }], ['Body', function (r) { return esc(r.body_name) + '<div class="mut">' + esc(r.kind.replace(/_/g, ' ')) + '</div>'; }], ['Report', function (r) { return esc(r.title) + '<div class="mut">' + esc(r.auditor) + '</div>'; }], ['Issued', function (r) { return esc(dt(r.issued)); }],
      ['Status', function (r) { return P.badge(r.status, r.status === 'final' ? 'green' : 'secondary'); }], ['Files', function (r) { return r.files.length ? P.badge(r.files.length + ' file(s)', 'blue') : P.badge('no file', 'orange'); }], ['Findings', function (r) { var L = V.findings.filter(function (f) { return f.report === r.id; }); return esc(L.length) + (L.length ? ' <span class="mut">' + esc(L.filter(function (f) { return f.status === 'open' || f.status === 'in_progress'; }).length) + ' open</span>' : ''); }]],
      V.reports, function (r) { return 'class="rowc" data-rep-id="' + esc(r.id) + '"'; }, 'No audit report recorded yet - Record an audit report.');
    $('note').textContent = V.note;
  }
  function keepSel(id, opts, cur) { $(id).innerHTML = opts.map(function (o) { return '<option value="' + esc(o[0]) + '"' + (o[0] === cur ? ' selected' : '') + '>' + esc(o[1]) + '</option>'; }).join(''); }
  function chipTest(f) {
    var open = f.status === 'open' || f.status === 'in_progress';
    switch (F.chip) { case 'open': return open; case 'overdue': return f.overdue; case 'carried': return V.carried.indexOf(f.id) >= 0; case 'repeat': return f.repeat_of.length > 0; case 'proposals': return f.candidates && f.candidates.length > 0;
      case 'closed': return !open; case 'late': return open && f.late_risk && f.late_risk.p >= 70; case 'unowned': return open && (!f.owner || !f.due); default: return true; }
  }
  function shown() {
    var q = F.q.toLowerCase();
    return V.findings.filter(function (f) { return chipTest(f) && (!F.body || f.body === F.body) && (!F.year || String(f.year) === F.year) && (!F.status || f.status === F.status) && (!F.area || String(f.area).toLowerCase() === F.area.toLowerCase())
      && (!q || [f.id, f.ref, f.title, f.area, f.owner].join(' ').toLowerCase().indexOf(q) >= 0); });
  }
  function drawFindings() {
    var L = shown();
    $('fnote').innerHTML = esc(L.length + ' of ' + V.findings.length + ' finding(s)') + (F.chip || F.area ? ' · filter: ' + esc(F.area || F.chip) + ' <button type="button" class="btn btn-sm btn-ghost-secondary" id="clr">clear</button>' : '');
    $('fl').innerHTML = P.table([['Finding', function (f) { return '<b>' + esc(f.id) + '</b><div class="mut">' + esc(f.ref || '') + '</div>'; }], ['Year · body', function (f) { return esc(f.year) + ' · ' + esc(bodyName(f.body)); }],
      ['Title', function (f) { return esc(f.title) + (f.area ? '<div class="mut">' + esc(f.area) + '</div>' : '') + (f.repeat_of.length ? ' ' + P.badge('repeat of ' + f.repeat_of.join(', '), 'red') : '') + (f.candidates && f.candidates.length ? ' ' + P.badge('possible repeat', 'orange') : ''); }],
      ['Rating', function (f) { return P.badge(f.rating, RB[f.rating]); }], ['Status', function (f) { return P.badge(ST[f.status] || f.status, SB[f.status]) + (f.overdue ? '<div class="text-red small">' + esc(f.days_overdue) + ' days overdue</div>' : ''); }],
      ['Owner · due', function (f) { return esc(f.owner || '—') + '<div class="mut">' + esc(dt(f.due)) + '</div>'; }], ['Late risk', function (f) { return f.late_risk ? '<span title="' + esc(f.late_risk.basis) + '">' + esc(f.late_risk.p) + '%</span>' : '—'; }]],
      L, function (f) { return 'class="rowc" data-fid="' + esc(f.id) + '"'; }, V.findings.length ? 'No finding matches the filter.' : 'No finding recorded yet - open a report and import its findings from Excel.');
  }
  function tab(t) { TAB = t; [].slice.call(document.querySelectorAll('[data-tab]')).forEach(function (a) { a.classList.toggle('active', a.getAttribute('data-tab') === t); }); ['ov', 'fd', 'rp', 'ai'].forEach(function (k) { $('t-' + k).hidden = k !== t; });
    if (t === 'ai') P.req('GET', '/audit-repo/ai/status').then(function (s) { $('ais').textContent = s.enabled ? 'available (' + s.model + ')' : 'Not available: ' + s.reason; }).catch(function (e) { $('ais').textContent = P.why(e); }); }
  function setChip(c) { F.chip = F.chip === c || c === 'all' ? null : c; F.area = ''; draw(); tab('fd'); }

  /* ---------- report drawer ---------- */
  var RF = [['year', 'num', 'Audit year', true], ['body', 'sel', 'Body', true, []], ['kind', 'sel', 'Kind', true, []], ['title', 'text', 'Title', true], ['auditor', 'text', 'Auditor (firm or team)', true], ['issued', 'date', 'Issued (report date)'], ['scope', 'area', 'Scope'], ['notes', 'area', 'Notes']];
  function reportForm(r) { RF[1][4] = Object.keys(V.bodies_catalogue).map(function (k) { return [k, V.bodies_catalogue[k]]; }); RF[2][4] = V.kinds.map(function (k) { return [k, k.replace(/_/g, ' ')]; }); return P.form('rpf', r ? RF.concat([['status', 'sel', 'Status', false, [['draft', 'draft'], ['final', 'final']]]]) : RF, r || { year: new Date().getFullYear() - 1 }, r ? 'Save changes' : 'Record the report'); }
  function newReport() { CUR = null; Z.open('Record an audit report', 'one report per audit or inspection', reportForm(null)); wireForm('rpf', function (b) { return P.req('POST', '/audit-repo/reports', b).then(function (r) { P.toast(r.id + ' recorded'); CUR = { kind: 'r', id: r.id }; return load(); }); }); }
  function openReport(id) {
    var r = V.reports.filter(function (x) { return x.id === id; })[0]; if (!r) return; CUR = { kind: 'r', id: id };
    var L = V.findings.filter(function (f) { return f.report === id; });
    Z.open(r.id + ' · ' + r.body_name + ' ' + r.year, r.title, Z.kv([['Auditor', esc(r.auditor)], ['Kind', esc(r.kind.replace(/_/g, ' '))], ['Issued', esc(dt(r.issued))], ['Status', esc(r.status)], ['Scope', esc(r.scope || '—')]])
      + '<div class="au-lbl mt-3 mb-1">Report files <span class="mut">(kept on this server)</span></div>' + (r.files.length ? r.files.map(function (f) { return '<div class="d-flex gap-2 align-items-center mb-1"><i class="ti ti-file"></i><span>' + esc(f.filename) + '</span><span class="mut">' + esc(Math.round(f.size / 1024)) + ' KB · sha256 ' + esc(f.sha256.slice(0, 12)) + '… · ' + esc(f.by) + '</span><button type="button" class="btn btn-sm" data-dl="' + esc(f.id) + '" data-name="' + esc(f.filename) + '">Download</button></div>'; }).join('') : '<div class="mut">No file yet - attach the signed report.</div>')
      + '<button type="button" class="btn btn-sm mt-1" id="up1"><i class="ti ti-upload me-1"></i>Attach a file</button>'
      + '<div class="au-lbl mt-3 mb-1">Findings (' + L.length + ')</div>' + P.table([['', function (f) { return '<b>' + esc(f.ref || f.id) + '</b>'; }], ['', function (f) { return esc(f.title); }], ['', function (f) { return P.badge(f.rating, RB[f.rating]) + ' ' + P.badge(ST[f.status] || f.status, SB[f.status]); }]], L, function (f) { return 'class="rowc" data-fid="' + esc(f.id) + '"'; }, 'No finding yet.')
      + '<div class="d-flex flex-wrap gap-2 mt-2"><button type="button" class="btn btn-sm btn-primary" id="imp1"><i class="ti ti-file-import me-1"></i>Import findings from Excel / CSV</button><button type="button" class="btn btn-sm" id="add1"><i class="ti ti-plus me-1"></i>Add one finding</button><button type="button" class="btn btn-sm" id="edit1">Edit the report</button></div>'
      + '<div class="mut mt-1">An import maps the letter\'s own headings (Observation, Risk rating, Target date, Status, Domain …). It is checked first: one bad line and nothing is imported, with every problem listed.</div><div id="impres" class="mt-2"></div>');
  }
  function editReport() { var r = V.reports.filter(function (x) { return x.id === CUR.id; })[0]; Z.open('Edit ' + r.id, r.title, reportForm(r)); wireForm('rpf', function (b) { return P.req('POST', '/audit-repo/reports/' + encodeURIComponent(r.id), b).then(function () { P.toast('Saved'); return load(); }); }); }
  var FF = [['ref', 'text', 'Auditor\'s reference'], ['title', 'text', 'Finding', true], ['condition', 'area', 'Condition (what was found)'], ['area', 'text', 'Area / domain'], ['controls', 'list', 'Controls (comma separated, e.g. SAMA 3.3.5)'], ['rating', 'sel', 'Rating', true, [['critical', 'critical'], ['high', 'high'], ['medium', 'medium'], ['low', 'low']]], ['owner', 'text', 'Owner'], ['due', 'date', 'Due date'], ['response', 'area', 'Management response']];
  function addFinding() { var rid = CUR.id; Z.open('Add a finding', rid, P.form('fdf', FF, {}, 'Add the finding')); wireForm('fdf', function (b) { return P.req('POST', '/audit-repo/reports/' + encodeURIComponent(rid) + '/findings', b).then(function (f) { P.toast(f.id + ' recorded'); CUR = { kind: 'r', id: rid }; return load(); }); }); }
  function importFile(f) {
    var rid = CUR.id, xl = /\.xlsx$/i.test(f.name), out = document.getElementById('impres');
    readFile(f, !xl).then(function (d) { var b = xl ? { xlsx_b64: b64(d), filename: f.name } : { csv: d }; PEND = { rid: rid, b: b, name: f.name }; return P.req('POST', '/audit-repo/reports/' + encodeURIComponent(rid) + '/findings/import', Object.assign({ dry_run: true }, b)); })
      .then(function (r) { if (!out) return; var map = Object.keys(r.columns).map(function (k) { return k + ' ← "' + r.columns[k] + '"'; }).join(' · ');
        out.innerHTML = '<div class="alert ' + (r.errors.length ? 'alert-warning' : 'alert-info') + ' mb-0"><b>' + esc(PEND.name) + '</b>: ' + esc(r.rows) + ' finding(s) read. <div class="mut">Columns: ' + esc(map) + '</div>' + (r.errors.length ? '<div class="mt-2">Nothing will be imported until these lines are fixed:</div>' + P.table([['Line', function (e) { return esc(e.line); }], ['Problem', function (e) { return esc(e.error); }]], r.errors) : '<button type="button" class="btn btn-sm btn-primary mt-2" id="impgo">Import ' + esc(r.rows) + ' finding(s)</button>') + '</div>'; })
      .catch(function (e) { if (out) out.innerHTML = '<div class="alert alert-warning mb-0">' + esc(P.why(e)) + '</div>'; });
  }
  function importGo() { var p = PEND; if (!p) return; P.req('POST', '/audit-repo/reports/' + encodeURIComponent(p.rid) + '/findings/import', p.b).then(function (r) { PEND = null; P.toast(r.imported + ' finding(s) imported'); CUR = { kind: 'r', id: p.rid }; return load(); }).catch(function (e) { P.toast(P.why(e)); }); }
  function attach(f) {
    var rid = CUR.id; if (f.size > 16 * 1024 * 1024) return P.toast('The file is larger than 16 MB');
    readFile(f).then(function (d) { return sha256(d).then(function (h) { return P.req('POST', '/audit-repo/reports/' + encodeURIComponent(rid) + '/files', Object.assign({ filename: f.name, content_b64: b64(d) }, h ? { sha256: h } : {})); }); })
      .then(function () { P.toast(f.name + ' attached'); CUR = { kind: 'r', id: rid }; return load(); }).catch(function (e) { P.toast(P.why(e)); });
  }
  function download(id, name) {
    P.req('GET', '/audit-repo/files/' + encodeURIComponent(id)).then(function (f) { var bin = atob(f.content_b64), u = new Uint8Array(bin.length); for (var i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
      // octet-stream: the browser saves the file, it never renders it here (a report file is outside content)
      var a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([u], { type: 'application/octet-stream' })); a.download = name || f.filename; document.body.appendChild(a); a.click(); a.remove(); P.toast('Downloaded ' + f.filename + ' (recorded)'); }).catch(function (e) { P.toast(P.why(e)); });
  }

  /* ---------- finding drawer ---------- */
  function openFinding(id) {
    var f = V.findings.filter(function (x) { return x.id === id; })[0]; if (!f) return; CUR = { kind: 'f', id: id };
    var open = f.status === 'open' || f.status === 'in_progress', rep = V.reports.filter(function (r) { return r.id === f.report; })[0] || {};
    Z.open(f.id + (f.ref ? ' · ' + f.ref : ''), bodyName(f.body) + ' ' + f.year + ' · ' + (rep.title || f.report), '<div class="fs-4 mb-2">' + esc(f.title) + '</div>' + Z.kv([['Rating', P.badge(f.rating, RB[f.rating])], ['Status', P.badge(ST[f.status] || f.status, SB[f.status]) + (f.overdue ? ' <span class="text-red">' + esc(f.days_overdue) + ' days overdue</span>' : '')], ['Area', esc(f.area || '—')], ['Controls', esc((f.controls || []).join(', ') || '—')],
      ['Owner', esc(f.owner || '—')], ['Due', esc(dt(f.due))], ['Closed', f.closed_at ? esc(dt(f.closed_at) + ' by ' + (f.closed_by || '—') + ' - evidence: ' + (f.evidence || '')) : '—'], ['Late risk', f.late_risk ? esc(f.late_risk.p + '% - ' + f.late_risk.basis) : '—'], ['Repeat of', f.repeat_of.length ? esc(f.repeat_of.join(', ')) : '—'], ['GRC action', esc(f.action || '—')]])
      + (f.condition ? '<div class="au-lbl mt-3">Condition</div><div style="white-space:pre-wrap">' + esc(f.condition) + '</div>' : '') + (f.response ? '<div class="au-lbl mt-3">Management response</div><div style="white-space:pre-wrap">' + esc(f.response) + '</div>' : '')
      + (f.candidates && f.candidates.length ? '<div class="au-lbl mt-3">Looks like an earlier year\'s finding</div>' + f.candidates.map(function (c) { return '<div class="cand"><b>' + esc(c.of) + '</b> ' + esc(bodyName(c.body) + ' ' + c.year) + ' · ' + esc(c.title) + ' ' + P.badge('score ' + c.score, 'orange') + '<div class="mut">' + esc(c.why.join(' · ')) + '</div><button type="button" class="btn btn-sm btn-danger mt-1" data-rep="confirm" data-f2="' + esc(f.id) + '" data-of="' + esc(c.of) + '">Confirm repeat</button> <button type="button" class="btn btn-sm mt-1" data-rep="reject" data-f2="' + esc(f.id) + '" data-of="' + esc(c.of) + '">Not a repeat</button></div>'; }).join('') : '')
      + '<div class="au-lbl mt-3 mb-1">Update</div>' + P.form('upf', [['status', 'sel', 'Status', false, V.statuses.map(function (s) { return [s, ST[s] || s]; })], ['owner', 'text', 'Owner'], ['due', 'date', 'Due date'], ['rating', 'sel', 'Rating', false, V.ratings.map(function (r) { return [r, r]; })], ['evidence', 'area', 'Closure evidence (required to close)'], ['note', 'area', 'Note (why)', true]], { status: f.status, owner: f.owner, due: f.due, rating: f.rating }, 'Save the update')
      + (open && !f.action ? '<button type="button" class="btn btn-sm btn-warning mt-2" id="toact"><i class="ti ti-checklist me-1"></i>Raise a GRC remediation action</button>' : '')
      + '<div class="au-lbl mt-3">History</div>' + (f.history || []).slice().reverse().map(function (h) { return '<div class="mut">' + esc(String(h.at).slice(0, 16).replace('T', ' ')) + ' · ' + esc(h.by) + ' · ' + esc(h.what) + '</div>'; }).join(''));
    wireForm('upf', function (b) { ['status', 'owner', 'due', 'rating'].forEach(function (k) { if (b[k] === f[k]) delete b[k]; }); return P.req('POST', '/audit-repo/findings/' + encodeURIComponent(f.id), b).then(function () { P.toast('Saved'); return load(); }); });
  }
  function decide(btn) {
    var dec = btn.getAttribute('data-rep'), fid = btn.getAttribute('data-f2'), of = btn.getAttribute('data-of');
    Z.open((dec === 'confirm' ? 'Confirm repeat' : 'Not a repeat') + ' · ' + fid, 'of ' + of, P.form('rdf', [['note', 'area', dec === 'confirm' ? 'Why it is the same weakness (what the first fix missed)' : 'Why it is a different issue', true]], {}, dec === 'confirm' ? 'Confirm the repeat' : 'Record: not a repeat'));
    wireForm('rdf', function (b) { return P.req('POST', '/audit-repo/findings/' + encodeURIComponent(fid) + '/repeat', { of: of, decision: dec, note: b.note }).then(function () { P.toast(dec === 'confirm' ? 'Repeat confirmed' : 'Recorded as not a repeat'); CUR = { kind: 'f', id: fid }; return load(); }); });
  }
  function wireForm(id, fn) { var fm = document.getElementById(id); if (!fm) return; fm.addEventListener('submit', function (ev) { ev.preventDefault(); P.msg(fm, ''); fn(P.body(fm)).catch(function (e) { P.msg(fm, P.why(e)); }); }); }
  // after a save the open drawer is redrawn from the fresh register; a drawer the user closed stays closed
  function reopen() { var d = document.getElementById('zd'); if (!d || d.hidden) { CUR = null; return; } if (CUR.kind === 'r') openReport(CUR.id); else openFinding(CUR.id); }
  function exportX() { P.req('GET', '/audit-repo/export').then(function (x) { if (!window.zybXlsx) throw new Error('the Excel writer did not load'); return window.zybXlsx.who().then(function (by) { window.zybXlsx.download(x.filename, x.sheets, { title: 'Audit Repository', by: by }); P.toast('Exported ' + x.filename + ' (recorded)'); }); }).catch(function (e) { P.toast(P.why(e)); }); }

  document.addEventListener('click', function (ev) {
    var b;
    if ((b = ev.target.closest('[data-tab]'))) { ev.preventDefault(); return tab(b.getAttribute('data-tab')); }
    if ((b = ev.target.closest('[data-f]'))) return setChip(b.getAttribute('data-f'));
    if ((b = ev.target.closest('[data-act]'))) {
      var a = b.getAttribute('data-act');
      if (a === 'nofile') return tab('rp');
      if (a === 'systemic') { var el = $('sys'); return el && el.scrollIntoView({ behavior: 'smooth' }); }
      F.chip = null; return setChip(a);
    }
    if ((b = ev.target.closest('[data-cell]'))) { var c = b.getAttribute('data-cell').split('|'); F.chip = null; F.area = ''; F.body = c[0]; F.year = c[1]; draw(); return tab('fd'); }
    if ((b = ev.target.closest('[data-area]'))) { F.chip = null; F.area = b.getAttribute('data-area'); draw(); return tab('fd'); }
    if ((b = ev.target.closest('[data-rep]'))) return decide(b);
    if ((b = ev.target.closest('[data-dl]'))) return download(b.getAttribute('data-dl'), b.getAttribute('data-name'));
    if ((b = ev.target.closest('[data-rep-id]'))) return openReport(b.getAttribute('data-rep-id'));
    if ((b = ev.target.closest('[data-fid]'))) return openFinding(b.getAttribute('data-fid'));
    if (ev.target.closest('#clr')) { F.chip = null; F.area = ''; return draw(); }
    if (ev.target.closest('#up1')) { $('upfile').value = ''; return $('upfile').click(); }
    if (ev.target.closest('#imp1')) { $('impfile').value = ''; return $('impfile').click(); }
    if (ev.target.closest('#impgo')) return importGo();
    if (ev.target.closest('#add1')) return addFinding();
    if (ev.target.closest('#edit1')) return editReport();
    if (ev.target.closest('#toact')) return P.req('POST', '/audit-repo/findings/' + encodeURIComponent(CUR.id) + '/to-action', {}).then(function (r) { P.toast('Action ' + r.action.id + ' raised in the GRC register'); return load(); }).catch(function (e) { P.toast(P.why(e)); });
  });
  document.addEventListener('keydown', function (ev) { if (ev.key === 'Enter' && ev.target.matches && ev.target.matches('[data-f],[data-act],[data-cell],[data-area]')) ev.target.click(); });
  ['f-body', 'f-year', 'f-status'].forEach(function (id) { $(id).addEventListener('change', function () { F[id.slice(2)] = $(id).value; drawFindings(); }); });
  $('q').addEventListener('input', function () { F.q = $('q').value; drawFindings(); });
  $('upfile').addEventListener('change', function () { if ($('upfile').files[0]) attach($('upfile').files[0]); });
  $('impfile').addEventListener('change', function () { if ($('impfile').files[0]) importFile($('impfile').files[0]); });
  $('new').addEventListener('click', newReport); $('refresh').addEventListener('click', load); $('xlsx').addEventListener('click', exportX);
  $('af').addEventListener('submit', function (ev) { ev.preventDefault(); $('aa').innerHTML = '<span class="mut">Thinking…</span>'; P.req('POST', '/audit-repo/ask', { question: $('af-q').value }).then(function (r) { $('aa').innerHTML = '<div style="white-space:pre-wrap">' + esc(r.answer) + '</div>'; }).catch(function (e) { $('aa').innerHTML = '<div class="alert alert-warning mb-0">' + esc(P.why(e)) + '</div>'; }); });
  var h = (location.hash || '').slice(1); if (['ov', 'fd', 'rp', 'ai'].indexOf(h) >= 0) tab(h);
  load();
})();
