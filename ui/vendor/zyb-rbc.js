// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
/* zyb-rbc.js - RBC Assessment page (rbc-assessment.html). Reads /api/itam/brisk/rbc. Finance uploads the IA RBC Own Funds & Solvency
 * workbook per period; the engine reads every schedule and explains it; a different person in Risk approves (four eyes).
 * No inline handlers; every value escaped; requests zybQuiet. */
(function () {
  'use strict';
  var esc = function (v) { return String(v == null ? '' : v).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); };
  var $ = function (id) { return document.getElementById(id); };
  var RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 }, ROLE = 'viewer', ME = '', V = null, SEL = null, D = null, OK = null;
  function req(m, u, b) { return new Promise(function (ok, bad) { var x = new XMLHttpRequest(); x.open(m, '/api/itam' + u); x.withCredentials = true; x.timeout = 120000; x.zybQuiet = true; if (b) x.setRequestHeader('Content-Type', 'application/json');
    x.onload = function () { var j = null; try { j = JSON.parse(x.responseText); } catch (e) { j = null; } if (x.status >= 200 && x.status < 300 && j) return ok(j); bad(Object.assign(new Error((j && j.error) || ('HTTP ' + x.status)), { status: x.status })); };
    x.onerror = x.ontimeout = function () { bad(Object.assign(new Error('IT Asset Management is not reachable'), { status: 0 })); }; x.send(b ? JSON.stringify(b) : null); }); }
  function toast(t) { var d = document.createElement('div'); d.setAttribute('role', 'status'); d.style.cssText = 'position:fixed;bottom:18px;left:50%;transform:translateX(-50%);background:#1d2430;border:1px solid #2e3747;border-radius:10px;padding:10px 16px;z-index:9999;max-width:90vw'; d.textContent = t; document.body.appendChild(d); setTimeout(function () { d.remove(); }, 6000); }
  function tile(l, v, s, c) { return '<div class="t ' + (c || '') + '"><div class="l">' + esc(l) + '</div><div class="v">' + esc(v) + '</div><div class="s">' + esc(s || '') + '</div></div>'; }
  function pill(t, c) { return '<span class="pill ' + (c || '') + '">' + esc(t) + '</span>'; }
  var LV = { ok: 'ok', watch: 'warn', bad: 'bad', info: 'info' };
  var op = function () { return RANK[ROLE] >= RANK.operator; }, adm = function () { return ROLE === 'admin'; };
  function n0(x) { return x == null ? '—' : Math.round(x).toLocaleString('en-US'); }
  function pc(x) { return x == null ? '—' : x + '%'; }
  function tbl(head, rows, empty) { return rows.length ? '<table><thead><tr>' + head.map(function (h) { return '<th>' + esc(h) + '</th>'; }).join('') + '</tr></thead><tbody>' + rows.join('') + '</tbody></table>' : '<div class="empty">' + esc(empty || 'Nothing in the workbook') + '</div>'; }
  function tr(cells) { return '<tr>' + cells.map(function (c) { return '<td>' + esc(c) + '</td>'; }).join('') + '</tr>'; }

  function load() { return req('GET', '/brisk/rbc').then(function (v) { V = v; $('main').hidden = false; $('err').innerHTML = ''; if (!SEL && v.latest) SEL = v.latest.id; draw(); if (SEL) open(SEL); else $('det').innerHTML = ''; }, function (e) { $('main').hidden = true;
    $('err').innerHTML = '<div class="card"><p>' + esc(e.status === 403 ? 'RBC figures are internal: operators (Finance) and administrators (Risk).' : e.status === 404 ? 'RBC Assessment is not installed yet - run the platform update.' : e.message) + '</p></div>'; }); }
  function draw() { var v = V; $('upl').hidden = !op(); $('setb').hidden = !adm(); $('note').textContent = v.note || ''; $('up').textContent = 'Target ' + Math.round(v.settings.target_ratio * 100) + '%';
    $('pc').textContent = v.periods.length + ' uploaded';
    $('periods').innerHTML = v.periods.length ? tbl(['Period', 'Company', 'Solvency ratio', 'MCR cover', 'Alerts', 'Status', 'Uploaded by'], v.periods.map(function (p) {
      return '<tr data-id="' + esc(p.id) + '" style="cursor:pointer' + (p.id === SEL ? ';background:rgba(121,184,255,.08)' : '') + '"><td><b>' + esc(p.period) + '</b></td><td>' + esc(p.company) + '</td><td>' + esc(pc(p.solvency_ratio)) + '</td><td>' + esc(pc(p.mcr_cover)) + '</td><td>' + (p.alerts ? pill(p.alerts + ' alert', 'bad') : '') + (p.watch ? pill(p.watch + ' watch', 'warn') : '') + (!p.alerts && !p.watch ? pill('clear', 'ok') : '') + '</td><td>' + pill(p.status, p.status === 'approved' ? 'ok' : 'info') + (p.approved_by ? ' <span class="small muted">' + esc(p.approved_by) + '</span>' : '') + '</td><td>' + esc(p.uploaded_by) + '</td></tr>'; })) : '<div class="empty">No RBC assessment uploaded yet. ' + (op() ? 'Use <b>Upload workbook</b> with the IA "RBC Own Funds and Solvency Assessment" file for a period (e.g. 2025 year end, 2026 Q1).' : 'Finance uploads the IA workbook for each period.') + '</div>';
    var s = v.series; $('series').innerHTML = s.measured ? 'Solvency ratio across approved periods: ' + s.points.map(function (p) { return esc(p.period) + ' ' + esc(p.ratio) + '%'; }).join(' → ') + ' · slope ' + esc(s.slope_pts_per_quarter) + ' pts a quarter' + (s.warning ? ' · <b style="color:var(--warn)">' + esc(s.warning) + '</b>' : '') : 'Trend across periods: ' + esc(s.why);
  }
  function open(id) { SEL = id; return req('GET', '/brisk/rbc/' + encodeURIComponent(id)).then(function (d) { D = d; detail(); if (V) draw(); }, function (e) { toast(e.message); }); }
  function detail() { var d = D, f = d.figures, ins = d.insights;
    var lvl = function (k) { var i = ins.filter(function (x) { return x.key === k; })[0]; return i ? LV[i.level] : ''; };
    var acts = '<div class="acts" style="margin:0 0 10px">' + '<button type="button" data-act="html">Report (print / PDF)</button><button type="button" data-act="csv">CSV</button>'
      + (adm() && d.status !== 'approved' && d.uploaded_by !== ME ? '<button type="button" data-act="approve">Approve</button>' : '') + (adm() && d.status !== 'approved' && d.uploaded_by === ME ? '<span class="hint">You uploaded this period - a different person approves it (four eyes).</span>' : '')
      + (adm() && d.status === 'approved' ? '<button type="button" data-act="reopen">Reopen</button>' : '') + '</div>';
    var h = '<div class="card"><h2>' + esc(d.period) + ' <span class="c">' + esc(d.company || '') + (d.company_type ? ' · ' + esc(d.company_type) : '') + ' · ' + esc(d.filename) + '</span>' + pill(d.status, d.status === 'approved' ? 'ok' : 'info') + '</h2>' + acts
      + '<div class="k">' + tile('Solvency ratio', pc(d.solvency_ratio), 'eligible own funds / RBC', lvl('ratio')) + tile('MCR cover', pc(d.mcr_cover), 'eligible own funds / MCR', lvl('mcr'))
      + tile('Eligible own funds', n0(d.own_funds), 'after adjustments') + tile('RBC', n0(d.rbc), 'required capital') + tile('Headroom', n0(f.eligible_own_funds.current != null && f.rbc.current != null ? f.eligible_own_funds.current - f.rbc.current : null), 'above 100% RBC', lvl('headroom')) + '</div>'
      + '<h2>Insights</h2>' + ins.map(function (i) { return '<div class="nx">' + pill(i.level, LV[i.level]) + '<div>' + esc(i.text) + '</div></div>'; }).join('') + '</div>';
    var both = function (lbl, x) { return tr([lbl, n0(x.current), n0(x.prior)]); }, cur = d.period_label || 'Current', pri = d.prior_label || 'Prior';
    h += '<div class="g2"><div class="card"><h2>Schedules 1 &amp; 2 · solvency position</h2>' + tbl(['Item', cur, pri], [both('MCR', f.mcr), both('RBC', f.rbc), both('Total assets', f.total_assets), both('Total liabilities', f.total_liabilities), both('Regulatory adjustments', f.regulatory_adjustments), both('Own funds', f.own_funds), both('Eligible own funds', f.eligible_own_funds),
      tr(['Solvency ratio', pc(d.solvency_ratio), f.solvency_ratio.prior != null ? Math.round(f.solvency_ratio.prior * 1000) / 10 + '%' : '—'])]) + '</div>';
    h += '<div class="card"><h2>Schedules 3–5 · own funds by tier</h2>' + tbl(['Tier', 'Basic', 'Ancillary', 'Total (' + cur + ')', 'Total (' + pri + ')'], f.tiers.map(function (t) { return tr(['Tier ' + t.tier, n0(t.basic.current), n0(t.ancillary.current), n0(t.total.current), n0(t.total.prior)]); }).concat([both('Total own funds', f.total_own_funds).replace('<tr><td>Total own funds</td>', '<tr><td>Total own funds</td><td></td><td></td>')]))
      + (f.components.length ? '<h2 style="margin-top:12px">Tier components</h2>' + tbl(['Tier', 'Component', cur, pri], f.components.map(function (c) { return tr([c.tier, c.label, n0(c.current), n0(c.prior)]); })) : '') + '</div></div>';
    h += '<div class="g2"><div class="card"><h2>Schedule 6 · eligible own funds adjustments</h2>' + tbl(['Adjustment', cur, pri], f.adjustments.map(function (a) { return both(a.item, a); }).concat([both('Total adjustments', f.total_adjustments), both('Eligible before adjustments', f.eligible_before), both('Eligible after adjustments', f.eligible_after)])) + '</div>';
    h += '<div class="card"><h2>Template checks <span class="c">' + d.checks.length + '</span></h2>' + tbl(['Check', 'Cell', 'Column', 'Result'], d.checks.map(function (c) { return '<tr><td>' + esc(c.label) + '</td><td>' + esc(c.ref) + '</td><td>' + esc(c.column) + '</td><td>' + pill(c.result, c.result === 'PASS' ? 'ok' : 'bad') + '</td></tr>'; }), 'No PASS / FAIL checks found in the workbook') + '</div></div>';
    var pj = d.projection;
    h += '<div class="card"><h2>Financial projection</h2>' + (pj ? tbl(['Item'].concat(pj.columns), pj.lines.map(function (l) { return tr([l.label].concat(pj.columns.map(function (c) { var x = l.values[c]; return x == null ? '—' : Math.abs(x) < 5 ? Math.round(x * 1000) / 10 + '%' : n0(x); }))); })) : '<div class="empty">The workbook has no financial projection sheet.</div>') + '</div>';
    h += '<div class="card"><h2>Board and management questions</h2>' + tbl(['Question', 'Answer', 'Note'], d.questions.map(function (q) { return '<tr><td>' + esc(q.question) + '</td><td>' + pill(q.answer, /^(yes|نعم)$/i.test(q.answer) ? 'ok' : /^(no|لا)$/i.test(q.answer) ? 'warn' : 'info') + '</td><td>' + esc(q.note) + '</td></tr>'; }), 'No answers in the Instructions sheet') + '<p class="hint">SHA-256 of the uploaded file ' + esc(d.sha256.slice(0, 16)) + '… · only the figures are kept, not the file.' + (d.reopen_reason ? ' Reopened: ' + esc(d.reopen_reason) : '') + '</p></div>';
    $('det').innerHTML = h;
  }
  function dl(name, text, type) { var a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([text], { type: type })); a.download = name; document.body.appendChild(a); a.click(); setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 1000); }
  function act(a) { var id = D && D.id; if (!id) return;
    if (a === 'html' || a === 'csv') return req('GET', '/brisk/rbc/' + encodeURIComponent(id) + '/report?format=' + a).then(function (r) { if (a === 'csv') return dl(r.filename, r.csv, 'text/csv'); var w = window.open('', '_blank'); if (w) { var d = w.document; d.title = r.filename || 'Report'; d.body.style.margin = '0'; var fr = d.createElement('iframe'); fr.setAttribute('sandbox', 'allow-modals'); fr.style.cssText = 'border:0;width:100vw;height:100vh;display:block;background:#fff'; d.body.appendChild(fr); fr.srcdoc = r.html; } else dl(r.filename, r.html, 'text/html'); }, function (e) { toast(e.message); });
    if (a === 'approve') return req('POST', '/brisk/rbc/' + encodeURIComponent(id) + '/approve', {}).then(function () { toast('Approved'); return load(); }, function (e) { toast(e.message); });
    if (a === 'reopen') { $('dlgt').textContent = 'Reopen ' + D.period; $('dlgb').innerHTML = '<div class="form"><label for="f-reason">Reason</label><textarea id="f-reason" rows="3"></textarea></div>'; $('dlgok').textContent = 'Reopen';
      OK = function () { return req('POST', '/brisk/rbc/' + encodeURIComponent(id) + '/reopen', { reason: $('f-reason').value.trim() }).then(function () { $('dlg').close(); toast('Reopened'); return load(); }); }; $('dlg').showModal(); }
  }
  function settings() { var s = V.settings; $('dlgt').textContent = 'RBC settings'; $('dlgok').textContent = 'Save';
    $('dlgb').innerHTML = '<div class="form"><label for="f-tgt">Target ratio %</label><input id="f-tgt" type="number" step="5" value="' + esc(Math.round(s.target_ratio * 100)) + '"><label for="f-q">Goodwill + intangibles flag % of Tier 1</label><input id="f-q" type="number" step="1" value="' + esc(s.quality_pct) + '"></div>';
    OK = function () { return req('POST', '/brisk/rbc/settings', { target_ratio: Number($('f-tgt').value) / 100, quality_pct: Number($('f-q').value) }).then(function () { $('dlg').close(); toast('Saved'); return load(); }); }; $('dlg').showModal(); }
  function upload(file) {
    if (!file) return; if (!/\.xlsx$/i.test(file.name)) return toast('Upload the .xlsx workbook');
    var r = new FileReader(); r.onload = function () { var b64 = String(r.result).split(',')[1] || ''; toast('Reading ' + file.name + '…');
      req('POST', '/brisk/rbc/import', { filename: file.name, xlsx_b64: b64 }).then(function (d) { SEL = d.id; toast(d.period + ' read: solvency ratio ' + pc(d.solvency_ratio)); return load(); }, function (e) { toast(e.message); }); };
    r.onerror = function () { toast('The file could not be read in the browser'); }; r.readAsDataURL(file); }
  document.addEventListener('click', function (e) { var t = e.target.closest('[data-id],[data-act]'); if (!t) return; if (t.dataset.act) return act(t.dataset.act); if (t.dataset.id) open(t.dataset.id); });
  $('upb').addEventListener('click', function () { $('file').click(); });
  $('file').addEventListener('change', function () { upload(this.files && this.files[0]); this.value = ''; });
  $('setb').addEventListener('click', settings); $('refresh').addEventListener('click', load);
  $('dlgx').addEventListener('click', function () { $('dlg').close(); });
  $('dlgok').addEventListener('click', function () { if (OK) Promise.resolve(OK()).catch(function (e) { toast(e.message); }); });
  var w = new XMLHttpRequest(); w.open('GET', '/dashboards/whoami.json'); w.zybQuiet = true; w.timeout = 10000;
  w.onload = function () { try { var j = JSON.parse(w.responseText); ROLE = j.role || 'viewer'; ME = j.user || ''; } catch (e) { ROLE = 'viewer'; /* no identity: read-only */ } load(); };
  w.onerror = w.ontimeout = function () { load(); /* identity unknown: the engine still enforces roles */ }; w.send();
})();
