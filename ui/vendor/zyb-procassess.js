// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
/* zyb-procassess.js - Process Risk Assessments page (risk-assessments.html). Reads /api/itam/process-assessment. A risk officer
 * creates an assessment and records findings; a different person in Risk approves (four eyes). No inline handlers; values escaped. */
(function () {
  'use strict';
  var esc = function (v) { return String(v == null ? '' : v).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); };
  var $ = function (id) { return document.getElementById(id); };
  var RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 }, ROLE = 'viewer', V = null, D = null, CUR = null, OK = null;
  function req(m, u, b) { return new Promise(function (ok, bad) { var x = new XMLHttpRequest(); x.open(m, '/api/itam' + u); x.withCredentials = true; x.timeout = 60000; x.zybQuiet = true; if (b) x.setRequestHeader('Content-Type', 'application/json');
    x.onload = function () { var j = null; try { j = JSON.parse(x.responseText); } catch (e) { j = null; } if (x.status >= 200 && x.status < 300 && j) return ok(j); bad(Object.assign(new Error((j && j.error) || ('HTTP ' + x.status)), { status: x.status })); };
    x.onerror = x.ontimeout = function () { bad(Object.assign(new Error('IT Asset Management is not reachable'), { status: 0 })); }; x.send(b ? JSON.stringify(b) : null); }); }
  function toast(t) { var d = document.createElement('div'); d.setAttribute('role', 'status'); d.style.cssText = 'position:fixed;bottom:18px;left:50%;transform:translateX(-50%);background:#1d2430;border:1px solid #2e3747;border-radius:10px;padding:10px 16px;z-index:9999;max-width:90vw'; d.textContent = t; document.body.appendChild(d); setTimeout(function () { d.remove(); }, 6000); }
  function tile(l, v, s, c) { return '<div class="t ' + (c || '') + '"><div class="l">' + esc(l) + '</div><div class="v">' + esc(v) + '</div><div class="s">' + esc(s || '') + '</div></div>'; }
  function pill(t, c) { return '<span class="pill ' + (c || '') + '">' + esc(t) + '</span>'; }
  var BC = { critical: 'bad', high: 'bad', medium: 'warn', low: 'info', not_rated: '', resolved: 'ok' }, STC = { draft: '', in_review: 'info', approved: 'ok', closed: '' };
  var op = function () { return RANK[ROLE] >= RANK.operator; }, adm = function () { return ROLE === 'admin'; };
  function field(f) { var id = 'f-' + f[0], t = f[2] || 'text';
    var inp = t === 'area' ? '<textarea id="' + id + '" rows="3">' + esc(f[4] == null ? '' : f[4]) + '</textarea>' : t === 'sel' ? '<select id="' + id + '">' + f[3].map(function (o) { return '<option value="' + esc(o[0]) + '"' + (o[0] === String(f[4]) ? ' selected' : '') + '>' + esc(o[1]) + '</option>'; }).join('') + '</select>' : '<input id="' + id + '" type="' + (t === 'date' ? 'date' : t === 'num' ? 'number' : 'text') + '" value="' + esc(f[4] == null ? '' : f[4]) + '">';
    return '<label for="' + id + '">' + esc(f[1]) + '</label><div>' + inp + (f[5] ? '<div class="muted small">' + esc(f[5]) + '</div>' : '') + '</div>'; }
  function dlg(title, fields, extra, onOk, okText) { $('dlgt').textContent = title; $('dlgb').innerHTML = (extra || '') + '<div class="form">' + fields.map(field).join('') + '</div>'; OK = onOk; $('dlgok').textContent = okText || 'Save'; $('dlg').showModal(); }
  function val(n) { var el = $('f-' + n); return el ? el.value.trim() : ''; }
  function save(p, b, msg) { $('dlgok').disabled = true; return req('POST', p, b).then(function (d) { D = d; $('dlg').close(); toast(msg || 'Saved (audited)'); if (CUR) drawDet(); else load(); return d; }, function (e) { toast(e.message); }).then(function (x) { $('dlgok').disabled = false; return x; }); }

  function load() { return req('GET', '/process-assessment').then(function (v) { V = v; $('main').hidden = false; $('err').innerHTML = ''; drawList(); }, function (e) { $('main').hidden = true;
    $('err').innerHTML = '<div class="card"><p>' + esc(e.status === 403 ? 'Risk assessments are internal: operators (Risk) and administrators.' : e.status === 404 ? 'Risk Assessments is not installed yet - run the platform update.' : e.message) + '</p></div>'; }); }
  function drawList() { var v = V, k = v.kpis; $('newb').hidden = !op();
    $('kk').innerHTML = tile('Assessments', k.assessments, k.open + ' open') + tile('In review', k.in_review, 'awaiting approval', k.in_review ? 'warn' : '') + tile('Critical', k.critical, 'highest rating', k.critical ? 'bad' : 'ok') + tile('Open findings', k.open_findings, 'across assessments', k.open_findings ? 'warn' : 'ok');
    $('lc').textContent = v.assessments.length + ' assessment(s)'; $('up').textContent = 'Updated ' + String(v.generated_at).slice(11, 16) + ' UTC';
    $('list').innerHTML = v.assessments.length ? '<table><thead><tr><th>Assessment</th><th>Process</th><th>Owner</th><th>Rating</th><th>Findings</th><th>Status</th></tr></thead><tbody>' + v.assessments.map(function (a) {
      return '<tr data-open="' + esc(a.id) + '" style="cursor:pointer"><td><b>' + esc(a.title) + '</b><div class="hint">' + esc(a.period || '') + '</div></td><td>' + esc(a.process_name) + '</td><td>' + esc(a.owner || '—') + '</td><td>' + pill(a.band === 'not_rated' ? 'not rated' : a.band + (a.rating ? ' (' + a.rating + ')' : ''), BC[a.band]) + '</td><td>' + esc(a.open_findings) + ' open / ' + esc(a.findings) + '</td><td>' + pill(a.status, STC[a.status]) + '</td></tr>'; }).join('') + '</tbody></table>'
      : '<div class="empty">No assessment yet. ' + (op() ? 'Click + New assessment to start a deep-dive.' : 'A risk officer starts one.') + '</div>'; }
  function openDet(id) { CUR = id; req('GET', '/process-assessment/' + encodeURIComponent(id)).then(function (d) { D = d; $('listv').hidden = true; $('detv').hidden = false; drawDet(); }, function (e) { toast(e.message); }); }
  function drawDet() { var d = D; $('dk').textContent = d.process_name + (d.period ? ' · ' + d.period : '') + ' · ' + d.status; $('dt').textContent = d.title;
    $('dkk').innerHTML = tile('Overall rating', d.band === 'not_rated' ? 'not rated' : d.band + (d.rating ? ' (' + d.rating + ')' : ''), d.rating_note, BC[d.band]) + tile('Status', d.status, d.history.approved_by ? 'approved by ' + d.history.approved_by : 'by ' + d.history.by, STC[d.status]) + tile('Owner', d.owner || '—', 'process owner') + tile('Findings', d.findings.length, d.findings.filter(function (f) { return f.status !== 'closed'; }).length + ' open');
    $('obj').innerHTML = '<p><b>Objective:</b> ' + esc(d.objective || '—') + '</p><p><b>Scope:</b> ' + esc(d.scope || '—') + '</p>' + (d.areas.length ? '<p class="small muted"><b>Suggested focus areas:</b> ' + esc(d.areas.join(' · ')) + '</p>' : '');
    var canEdit = op() && (d.status === 'draft');
    var acts = '';
    if (op() && d.status === 'draft') acts += '<button type="button" data-a="edit">Edit header</button><button type="button" data-a="submit">Submit for review</button>';
    if (adm() && d.status === 'in_review') acts += '<button type="button" data-a="approve">Approve (four eyes)</button>';
    if (adm() && (d.status === 'approved' || d.status === 'in_review' || d.status === 'closed')) acts += '<button type="button" data-a="reopen">Reopen</button>';
    $('acts').innerHTML = op() ? acts : '<span class="hint">A risk officer and an administrator work the assessment.</span>';
    $('addf').hidden = !canEdit; $('fc').textContent = d.findings.length + ' finding(s)';
    $('finds').innerHTML = d.findings.length ? '<table><thead><tr><th>Area</th><th>Observation</th><th>L×I</th><th>Rating</th><th>Owner / due</th><th>Status</th><th></th></tr></thead><tbody>' + d.findings.map(function (f) {
      return '<tr><td><b>' + esc(f.area) + '</b></td><td class="small">' + esc(f.observation) + '<div class="hint">' + esc(f.recommendation) + '</div></td><td>' + esc(f.likelihood) + '×' + esc(f.impact) + '</td><td>' + pill(f.band + ' (' + f.rating + ')', BC[f.band]) + '</td><td class="small">' + esc(f.owner || '—') + (f.due ? '<div class="hint">due ' + esc(f.due) + '</div>' : '') + '</td><td>' + pill(f.status, f.status === 'closed' ? 'ok' : f.status === 'in_progress' ? 'info' : 'warn') + '</td>'
        + '<td><div class="acts">' + (canEdit ? '<button type="button" data-ef="' + esc(f.id) + '">Edit</button>' : '') + (op() && !f.grc_action ? '<button type="button" data-af="' + esc(f.id) + '">Raise action</button>' : f.grc_action ? pill(f.grc_action, 'info') : '') + '</div></td></tr>'; }).join('') + '</tbody></table>' : '<div class="empty">No finding yet.' + (canEdit ? ' Click + Add finding.' : '') + '</div>'; }
  function headerForm(a) { a = a || {}; var P = (V.processes || []).map(function (x) { return [x.key, x.name]; });
    dlg(a.id ? 'Edit assessment' : 'New assessment', [['title', 'Title', 'text', '', a.title], ['process', 'Process', 'sel', P, a.process || 'procurement'], ['owner', 'Owner', 'text', '', a.owner, 'user name'], ['period', 'Period', 'text', '', a.period, 'e.g. 2026-Q1'], ['objective', 'Objective', 'area', '', a.objective], ['scope', 'Scope', 'area', '', a.scope]], '',
      function () { var b = { title: val('title'), process: val('process'), owner: val('owner') || undefined, period: val('period') || undefined, objective: val('objective') || undefined, scope: val('scope') || undefined }; var isNew = !a.id; if (a.id) b.id = a.id; save('/process-assessment', b, 'Saved (audited)').then(function (d) { if (isNew && d && d.id) openDet(d.id); }); }, a.id ? 'Save' : 'Create'); }
  function findingForm(f) { f = f || {};
    dlg(f.id ? 'Edit finding' : 'Add finding', [['area', 'Area', 'text', '', f.area, D.areas.length ? 'e.g. ' + D.areas[0] : ''], ['observation', 'Observation', 'area', '', f.observation], ['likelihood', 'Likelihood (1-5)', 'num', '', f.likelihood], ['impact', 'Impact (1-5)', 'num', '', f.impact], ['root_cause', 'Root cause', 'area', '', f.root_cause], ['recommendation', 'Recommendation', 'area', '', f.recommendation], ['owner', 'Owner', 'text', '', f.owner, 'user name'], ['due', 'Due', 'date', '', f.due], ['status', 'Status', 'sel', (D.finding_statuses || ['open', 'in_progress', 'closed']).map(function (s) { return [s, s]; }), f.status || 'open']], '',
      function () { var b = { area: val('area'), observation: val('observation'), likelihood: Number(val('likelihood')), impact: Number(val('impact')), root_cause: val('root_cause') || undefined, recommendation: val('recommendation'), owner: val('owner') || undefined, due: val('due') || undefined, status: val('status') }; if (f.id) b.id = f.id; save('/process-assessment/' + CUR + '/findings', b, 'Finding saved (audited)'); }, 'Save'); }
  function doA(a) { var P = '/process-assessment/' + CUR;
    if (a === 'edit') return headerForm(D);
    if (a === 'submit') return save(P + '/submit', {}, 'Submitted for review');
    if (a === 'approve') return save(P + '/approve', {}, 'Approved (four eyes)');
    if (a === 'reopen') return dlg('Reopen assessment', [['reason', 'Reason', 'text', '', '']], '<p class="small">Reopening returns it to draft; it must be re-approved.</p>', function () { save(P + '/reopen', { reason: val('reason') }, 'Reopened (audited)'); }, 'Reopen'); }
  document.addEventListener('click', function (ev) { var t = ev.target, x;
    if (t.id === 'newb') return headerForm(null);
    if ((x = t.closest('tr[data-open]'))) return openDet(x.getAttribute('data-open'));
    if (t.id === 'back') { $('detv').hidden = true; $('listv').hidden = false; CUR = null; return load(); }
    if (t.id === 'addf') return findingForm(null);
    if ((x = t.closest('[data-ef]'))) { var f = D.findings.filter(function (y) { return y.id === x.getAttribute('data-ef'); })[0]; return findingForm(f); }
    if ((x = t.closest('[data-af]'))) return req('POST', '/process-assessment/' + CUR + '/findings/' + encodeURIComponent(x.getAttribute('data-af')) + '/action', {}).then(function (d) { D = d; drawDet(); toast('GRC action raised'); }, function (e) { toast(e.message); });
    if ((x = t.closest('[data-a]'))) return doA(x.getAttribute('data-a'));
    if (t.id === 'dlgok' && OK) return OK(); if (t.id === 'dlgx') return $('dlg').close();
    if (t.id === 'refresh') return CUR ? openDet(CUR) : load();
    if (t.id === 'rep') return req('GET', '/process-assessment/' + CUR + '/report?format=html').then(function (r) { var u = URL.createObjectURL(new Blob([r.html], { type: 'text/html' })); if (!window.open(u, '_blank', 'noopener')) toast('Allow pop-ups to open the report'); setTimeout(function () { URL.revokeObjectURL(u); }, 60000); toast('Recorded in the audit trail'); }, function (e) { toast(e.message); }); });
  document.addEventListener('change', function (ev) { if (ev.target.id === 'f-process') { /* focus-area hint updates on next open; no action needed */ } });
  (function () { var w = new XMLHttpRequest(); w.open('GET', '/dashboards/whoami.json'); w.zybQuiet = true; w.onload = function () { try { var j = JSON.parse(w.responseText), r = String(j.role || '').toLowerCase(); if (RANK[r] != null) ROLE = r; } catch (e) { /* viewer */ } load(); }; w.onerror = load; w.send(); })();
})();
