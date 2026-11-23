// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
/* SharePoint & OneDrive page (sharepoint.html) over the SIEM's GET /api/soc/m365/files/insights: KPI tiles that filter, ranked
 * actions, the sharing breakdown, the trend across runs, sites / OneDrives ranked with coverage, files ranked by exposure with every
 * point on hover and in the detail, folders where personal data concentrates, CSV export (counts only), Read now (admin). Names
 * are for analysts and above. Delegated listeners; every value is escaped. */
(function () {
  'use strict';
  var $ = function (id) { return document.getElementById(id); };
  var Z = window.zybDetail;
  var esc = function (s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); };
  var V = null, ROLE = 'viewer', F = '', Q = '';
  var SH = { anonymous: ['anonymous link', '#d63939'], external: ['outside the organisation', '#f76707'], organization: ['whole organisation', '#f59f00'], none: ['not shared', '#0ca678'], unknown: ['sharing not read', '#868e96'] };
  function req(m, url, b) {
    return new Promise(function (ok, bad) {
      var x = new XMLHttpRequest(); x.open(m, url); x.withCredentials = true; x.timeout = 120000; x.zybQuiet = true; if (b) x.setRequestHeader('Content-Type', 'application/json');
      x.onload = function () { var j = null; try { j = JSON.parse(x.responseText); } catch (e) { /* not JSON: reported below */ } if (x.status >= 200 && x.status < 300 && j) return ok(j); bad(Object.assign(new Error((j && (j.error || (j.errors && j.errors[0]))) || ('HTTP ' + x.status)), { status: x.status })); };
      x.onerror = x.ontimeout = function () { bad(new Error('the SIEM is not reachable')); }; x.send(b ? JSON.stringify(b) : null);
    });
  }
  function toast(t) { var d = document.createElement('div'); d.className = 'toast-zyb'; d.setAttribute('role', 'status'); d.textContent = t; document.body.appendChild(d); setTimeout(function () { d.remove(); }, 5000); }
  var when = function (s) { var t = s ? Date.parse(s) : NaN; return isFinite(t) ? new Date(t).toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' }) : '—'; };
  function tile(v, l, cls, f) { return '<div class="col-6 col-md-3 col-xl"><div class="card card-sm"' + (f ? ' data-f="' + esc(f) + '" role="button" tabindex="0" aria-pressed="' + (F === f) + '" title="Show these files"' : '') + '><div class="card-body"><div class="au-num' + (cls ? ' ' + cls : '') + '">' + esc(v) + '</div><div class="au-lbl">' + esc(l) + '</div></div></div></div>'; }
  var shareKey = function (f) { return f.shared == null ? 'unknown' : f.shared; };
  function match(f) {
    if (F === 'anonymous' && f.shared !== 'anonymous') return false; if (F === 'external' && f.shared !== 'external') return false; if (F === 'unknown' && f.shared != null) return false;
    if (F === 'high' && f.score < 60) return false; if (F === 'old' && !f.old) return false;
    return !Q || [f.name, f.path, f.source_label, f.kinds.join(' ')].join(' ').toLowerCase().indexOf(Q) >= 0;
  }
  function draw() {
    var k = V.kpis;
    $('kpis').innerHTML = tile(k.sources, 'Sites & OneDrives read', '', '') + tile(k.files_seen, 'Files seen', '', '') + tile(k.sensitive, 'Files with personal data', '', '') + tile(k.anonymous, 'Anonymous links', k.anonymous ? 'text-red' : '', 'anonymous')
      + tile(k.external, 'Shared outside', k.external ? 'text-orange' : '', 'external') + tile(k.unknown_sharing, 'Sharing not read', '', 'unknown') + tile(k.high, 'High exposure (60+)', k.high ? 'text-red' : '', 'high') + tile(k.old, 'Unchanged 3 years', '', 'old');
    var pr = function (p) { return p >= 80 ? 'p-hi' : p >= 50 ? 'p-md' : 'p-lo'; };
    $('acts').innerHTML = V.never ? '<span class="text-secondary">The discovery has not run yet. ' + esc((V.status && V.status.last_error) || 'An administrator switches it on (SIEM config m365.files.enabled) or presses Read now; it needs Sites.Read.All on the Microsoft 365 app.') + '</span>'
      : V.actions.length ? V.actions.map(function (a) { return '<div class="act ' + pr(a.priority) + '"><b>' + esc(a.title) + '</b><div class="mut">' + esc(a.detail) + '</div></div>'; }).join('') : '<span class="text-secondary">Nothing needs action.</span>';
    var tot = 0, keys = ['anonymous', 'external', 'organization', 'none', 'unknown']; keys.forEach(function (x) { tot += V.sharing[x] || 0; });
    $('share').innerHTML = tot ? '<div class="bar mb-2" aria-label="sharing breakdown">' + keys.map(function (x) { var n = V.sharing[x] || 0; return n ? '<i title="' + esc(SH[x][0] + ': ' + n) + '" style="width:' + (n / tot * 100) + '%;background:' + SH[x][1] + '"></i>' : ''; }).join('') + '</div>'
      + keys.map(function (x) { return '<div class="d-flex justify-content-between small"><span><span style="color:' + SH[x][1] + '">■</span> ' + esc(SH[x][0]) + '</span><b>' + esc(V.sharing[x] || 0) + '</b></div>'; }).join('')
      + '<div class="mt-2 small">' + Object.keys(V.categories).map(function (c) { return '<span class="badge bg-secondary-lt me-1">' + esc(c) + ' ' + esc(V.categories[c]) + '</span>'; }).join('') + '</div>' : '<span class="text-secondary">No file with personal data found.</span>';
    var T = V.trend, mx = Math.max.apply(null, T.history.map(function (h) { return h.exposed; }).concat([1]));
    $('trend').innerHTML = T.runs ? '<div class="d-flex align-items-end gap-1" style="height:50px" aria-label="exposed files per run">' + T.history.map(function (h) { return '<i title="' + esc(when(h.at) + ': ' + h.exposed + ' exposed of ' + h.sensitive) + '" style="flex:1;display:block;border-radius:2px 2px 0 0;background:#f76707;height:' + Math.max(3, h.exposed / mx * 100) + '%"></i>'; }).join('') + '</div>'
      + '<div class="small mt-2">' + esc(T.runs) + ' run(s) kept' + (T.previous ? ' · last run before this: ' + esc(T.previous.exposed) + ' exposed of ' + esc(T.previous.sensitive) : '') + (T.unusual ? ' · <b class="text-orange">unusual jump (robust z ' + esc(T.unusual.z) + ')</b>' : '') + '</div>' : '<span class="text-secondary">One sample is kept per discovery run; the trend appears from the second run.</span>';
    if (V.limited) { ['srcs', 'files'].forEach(function (id) { $(id).innerHTML = '<div class="card-body text-secondary">File names, folders and sites say where personal data lies: analysts and above see them.</div>'; }); $('folders').innerHTML = ''; $('note').textContent = V.note; return; }
    $('srcs').innerHTML = V.sources.length ? '<table class="table table-vcenter card-table"><thead><tr><th>Site / OneDrive</th><th>Files seen</th><th>Personal data</th><th>Exposed</th><th>Exposure</th><th>Coverage</th></tr></thead><tbody>' + V.sources.map(function (s) {
      var c = s.coverage, gaps = [].concat(c.truncated ? ['limit reached'] : [], c.unreadable ? [c.unreadable + ' unreadable'] : [], c.errors);
      return '<tr class="rowc" data-src="' + esc(s.key) + '"><td><b>' + esc(s.label) + '</b><div class="mut">' + (s.kind === 'onedrive' ? 'OneDrive' : 'SharePoint') + (/^https:\/\//i.test(s.url || '') ? ' · <a href="' + esc(s.url) + '" target="_blank" rel="noopener noreferrer">open</a>' : '') + '</div></td><td>' + esc(s.files_seen) + '</td><td>' + esc(s.sensitive) + '</td><td>' + (s.exposed ? '<span class="badge bg-red-lt">' + esc(s.exposed) + '</span>' : '0') + '</td><td><b>' + esc(s.risk) + '</b></td><td class="small">' + (gaps.length ? '<span class="text-orange">' + esc(gaps.join(' · ')) + '</span>' : '<span class="text-green">complete</span>') + '</td></tr>';
    }).join('') + '</tbody></table>' : '<div class="card-body text-secondary">No site read yet.</div>';
    drawFiles();
    $('folders').innerHTML = V.folders.length ? V.folders.map(function (f) { return '<div class="d-flex justify-content-between small mb-1"><span class="mono">' + esc(f.folder) + '</span><span>' + esc(f.files) + ' file(s)' + (f.exposed ? ' · <b class="text-red">' + esc(f.exposed) + ' exposed</b>' : '') + '</span></div>'; }).join('') : '<span class="text-secondary">—</span>';
    $('note').textContent = V.note + (V.errors.length ? ' Not read: ' + V.errors.join('; ') : '');
  }
  function drawFiles() {
    var L = V.files.filter(match);
    $('files').innerHTML = L.length ? '<table class="table table-vcenter card-table table-sm"><thead><tr><th>Exposure</th><th>File</th><th>Holds</th><th>Shared</th><th>Modified</th></tr></thead><tbody>' + L.slice(0, 300).map(function (f, i) {
      var sk = SH[shareKey(f)];
      return '<tr class="rowc" data-file="' + V.files.indexOf(f) + '"><td title="' + esc(f.why.map(function (w) { return w.text + ' +' + w.points; }).join('\n')) + '"><b style="color:' + (f.score >= 60 ? '#d63939' : f.score >= 35 ? '#f59f00' : '#0ca678') + '">' + esc(f.score) + '</b></td><td><b>' + esc(f.name) + '</b><div class="mut mono">' + esc(f.source_label + ' › ' + (f.path || '/')) + '</div></td>'
        + '<td>' + f.kinds.map(function (x) { return '<span class="badge bg-secondary-lt me-1">' + esc(x) + '</span>'; }).join('') + '</td><td><span class="badge" style="background:' + sk[1] + '22;color:' + sk[1] + '">' + esc(sk[0]) + '</span></td><td class="small">' + esc(when(f.modified)) + (f.old ? ' <span class="badge bg-yellow-lt">3 y+</span>' : '') + '</td></tr>';
    }).join('') + '</tbody></table>' : '<div class="card-body text-secondary">' + (V.files.length ? 'No file matches.' : 'No file with personal data found.') + '</div>';
  }
  function load() {
    var w = new Promise(function (ok) { var x = new XMLHttpRequest(); x.open('GET', '/dashboards/whoami.json'); x.onload = function () { try { ok(JSON.parse(x.responseText)); } catch (e) { ok(null); } }; x.onerror = function () { ok(null); }; x.send(); });
    return w.then(function (me) { ROLE = String((me && me.role) || 'viewer').toLowerCase(); return req('GET', '/api/soc/m365/files/insights'); }).then(function (v) {
      V = v; $('err').hidden = true; $('main').hidden = false; $('run').hidden = ROLE !== 'admin'; draw();
      $('up').textContent = v.read_at ? 'read ' + when(v.read_at) : (v.status && v.status.running ? 'reading now…' : 'not read yet'); })
      .catch(function (e) { $('main').hidden = true; $('err').hidden = false; $('err').textContent = e.status === 404 ? 'The insights are not on the SIEM yet - run the SIEM update.' : 'Could not load: ' + e.message; });
  }
  document.addEventListener('click', function (ev) {
    var t = ev.target; if (!t.closest) return;
    var f = t.closest('[data-f]'); if (f && f.getAttribute('data-f')) { var v = f.getAttribute('data-f'); F = F === v ? '' : v; draw(); $('files').scrollIntoView({ behavior: 'smooth' }); return; }
    var fr = t.closest('[data-file]'); if (fr && !t.closest('a')) { var x = V.files[Number(fr.getAttribute('data-file'))]; if (!x) return;
      Z.open('SharePoint & OneDrive', x.name, '<div class="mb-2 mono small">' + esc(x.source_label + ' › ' + (x.path || '/')) + '</div><h4>Exposure ' + esc(x.score) + ' / 100</h4><ul>' + x.why.map(function (w) { return '<li>' + esc(w.text) + ' <b>+' + esc(w.points) + '</b></li>'; }).join('') + '</ul><p class="small text-secondary">Holds: ' + esc(x.kinds.join(', ')) + ' · modified ' + esc(when(x.modified)) + '. Only counts per kind are kept - never a value. Remove an anonymous or outside link in SharePoint / OneDrive sharing, then read again.</p>'); return; }
    var sr = t.closest('[data-src]'); if (sr && !t.closest('a')) { var s = V.sources.filter(function (y) { return y.key === sr.getAttribute('data-src'); })[0]; if (s) { Q = String(s.label).toLowerCase(); $('q').value = s.label; drawFiles(); $('files').scrollIntoView({ behavior: 'smooth' }); } return; }
    if (t.closest('#refresh')) { load(); return; }
    if (t.closest('#run')) { req('POST', '/api/soc/pii/sharepoint/run', {}).then(function (r) { toast(r.started ? 'Reading every site now - this can take a while' : (r.reason || 'A read is already running')); }, function (e) { toast(e.message); }); return; }
    if (t.closest('#csv')) { if (!V || V.limited) { toast('Analysts and above export the files'); return; }
      var cell = function (v) { v = String(v == null ? '' : v); if (/^[=+\-@]/.test(v)) v = "'" + v; return '"' + v.replace(/"/g, '""') + '"'; };
      var rows = [['exposure', 'site_or_onedrive', 'folder', 'file', 'holds', 'shared', 'modified', 'why']].concat(V.files.filter(match).map(function (x) { return [x.score, x.source_label, x.path, x.name, x.kinds.join(' '), shareKey(x), x.modified || '', x.why.map(function (w) { return w.text + ' +' + w.points; }).join('; ')]; }));
      var blob = new Blob([rows.map(function (r) { return r.map(cell).join(','); }).join('\r\n')], { type: 'text/csv' }), u = URL.createObjectURL(blob), a = document.createElement('a'); a.href = u; a.download = 'sharepoint-onedrive-' + new Date().toISOString().slice(0, 10) + '.csv'; document.body.appendChild(a); a.click(); setTimeout(function () { URL.revokeObjectURL(u); a.remove(); }, 500); }
  });
  $('q').addEventListener('input', function () { Q = this.value.trim().toLowerCase(); drawFiles(); });
  load();
})();

/* Activity tab (GET /api/soc/m365/files/activity, analysts and above): sharing, mass downloads, after hours, external sharing from the
 * Office 365 unified audit log the SIEM collects, each user against their own history. The old portal page "SharePoint & OneDrive"
 * opens here (#activity). Behavioural indicators for a person to review, not proof (PDPL). */
(function () {
  'use strict';
  var $ = function (id) { return document.getElementById(id); };
  var esc = function (s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); };
  var A = null, LOADED = false, ROLE = 'viewer', RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 };
  var SC = { anonymous: ['Anyone with the link', 'bg-red-lt'], external: ['Outside the organisation', 'bg-orange-lt'], organisation: ['Whole organisation', 'bg-yellow-lt'], internal: ['Specific people inside', 'bg-secondary-lt'] };
  var dt = function (s) { var t = Date.parse(s); return isFinite(t) ? new Date(t).toLocaleString('en-GB', { day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit' }) : '-'; };
  function req(url) { return new Promise(function (ok, bad) { var x = new XMLHttpRequest(); x.open('GET', url); x.withCredentials = true; x.timeout = 120000; x.zybQuiet = true;
    x.onload = function () { var j = null; try { j = JSON.parse(x.responseText); } catch (e) { j = null; /* not JSON: reported below */ } if (x.status >= 200 && x.status < 300 && j) ok(j); else bad(Object.assign(new Error((j && j.error) || 'HTTP ' + x.status), { status: x.status })); };
    x.onerror = x.ontimeout = function () { bad(Object.assign(new Error('the SIEM is not reachable'), { status: 0 })); }; x.send(null); }); }
  function tile(v, l, warn) { return '<div class="col-6 col-md-4 col-xl-2"><div class="card card-sm"><div class="card-body"><div class="au-num"' + (warn && v ? ' style="color:#d63939"' : '') + '>' + esc(v) + '</div><div class="au-lbl">' + esc(l) + '</div></div></div></div>'; }
  function tab(t) {
    document.body.classList.toggle('sp-act', t === 'activity');
    [].forEach.call(document.querySelectorAll('[data-sptab]'), function (a) { var on = a.getAttribute('data-sptab') === t; a.classList.toggle('active', on); a.setAttribute('aria-selected', String(on)); });
    try { history.replaceState(null, '', '#' + t); } catch (e) { /* file: keep the address */ }
    if (t === 'activity' && !LOADED) load();
  }
  function draw() {
    var k = A.kpis;
    $('akpis').innerHTML = tile(k.mass_downloads, 'mass downloads', true) + tile(k.external, 'external / anonymous shares', true) + tile(k.anonymous_used, 'anonymous link uses', true) + tile(k.after_hours_users, 'after-hours changes', true) + tile(k.shares, 'sharing actions') + tile(k.active_users, 'active users');
    $('adl').innerHTML = A.downloads.length ? A.downloads.map(function (x) { return '<div class="act p-hi"><b>' + esc(x.user) + '</b> · ' + esc(x.files) + ' files (' + esc(x.distinct) + ' distinct) at ' + esc(dt(x.hour)) + '<div class="mut">' + esc(x.why) + (x.sites.length ? ' · ' + x.sites.map(esc).join(', ') : '') + '</div></div>'; }).join('') : '<div class="text-secondary">No user downloaded far more than usual in this window.</div>';
    $('aah').innerHTML = A.after_hours.length ? A.after_hours.map(function (x) { return '<div class="act p-md"><b>' + esc(x.user) + '</b> · ' + esc(x.after_hours) + ' after-hours actions<div class="mut">' + esc(x.why) + '</div></div>'; }).join('') : '<div class="text-secondary">No change in anyone\'s after-hours file activity.</div>';
    $('aext').innerHTML = A.external.length ? '<table class="table table-vcenter card-table table-sm"><thead><tr><th>When</th><th>Who</th><th>File</th><th>Scope</th><th>With</th></tr></thead><tbody>' + A.external.map(function (x) { return '<tr><td class="mut">' + esc(dt(x.at)) + '</td><td>' + esc(x.user) + '</td><td><b>' + esc(x.file) + '</b><div class="mut mono">' + esc(x.site) + '</div></td><td><span class="badge ' + SC[x.scope][1] + '">' + esc(SC[x.scope][0]) + '</span></td><td class="mono small">' + esc(x.target || '-') + '</td></tr>'; }).join('') + '</tbody></table>' : '<div class="card-body text-secondary">Nothing was shared outside the organisation or by an anonymous link in this window.</div>';
    $('aused').innerHTML = A.anonymous_used.length ? A.anonymous_used.map(function (x) { return '<div class="d-flex justify-content-between small mb-1"><span>' + esc(x.file) + '</span><b>' + esc(x.uses) + '</b></div>'; }).join('') : '<div class="text-secondary small">No anonymous link was opened.</div>';
    var S = A.series, mx = Math.max.apply(null, S.map(function (x) { return x.events; }).concat([1]));
    $('aday').innerHTML = '<div class="d-flex align-items-end gap-1" style="height:70px" role="img" aria-label="' + esc('File events per day: ' + S.map(function (x) { return x.day + ' ' + x.events; }).join(', ')) + '">' + S.map(function (x) { return '<div title="' + esc(x.day + ': ' + x.events + ' events, ' + x.downloads + ' downloads, ' + x.shares + ' shares') + '" style="flex:1;background:#4299e1;opacity:.75;height:' + Math.max(2, 70 * x.events / mx) + 'px;border-radius:3px 3px 0 0"></div>'; }).join('') + '</div><div class="d-flex justify-content-between mut mt-1"><span>' + esc(S.length ? S[0].day : '') + '</span><span>' + esc(S.length ? S[S.length - 1].day : '') + '</span></div>';
    drawShare();
    $('anote').textContent = A.note + (A.truncated ? ' The window held more events than one read takes: shorten it to see everything.' : '') + ' Tenant domains: ' + A.internal_domains.join(', ') + '.';
    $('aup').textContent = A.events + ' file events read';
  }
  function drawShare() {
    var q = ($('aq').value || '').toLowerCase(), sc = $('ascope').value;
    var L = A.sharing.filter(function (x) { return (!sc || x.scope === sc) && (!q || (x.user + ' ' + x.file + ' ' + x.site + ' ' + (x.target || '')).toLowerCase().indexOf(q) >= 0); });
    $('ashare').innerHTML = L.length ? '<table class="table table-vcenter card-table table-sm"><thead><tr><th>When</th><th>Who</th><th>Operation</th><th>File</th><th>Scope</th><th>With</th></tr></thead><tbody>' + L.map(function (x) { return '<tr><td class="mut">' + esc(dt(x.at)) + '</td><td>' + esc(x.user) + '</td><td class="small">' + esc(x.operation) + '</td><td>' + esc(x.file) + '</td><td><span class="badge ' + SC[x.scope][1] + '">' + esc(SC[x.scope][0]) + '</span></td><td class="mono small">' + esc(x.target || '-') + '</td></tr>'; }).join('') + '</tbody></table>' : '<div class="card-body text-secondary">No sharing matches.</div>';
  }
  function load() {
    LOADED = true;
    if ((RANK[ROLE] || 0) < RANK.analyst) { $('amain').hidden = true; $('aerr').hidden = false; $('aerr').textContent = 'File activity names people: it is shown to analysts and above (PDPL).'; return; }
    $('aup').textContent = 'reading…';
    req('/api/soc/m365/files/activity?days=' + encodeURIComponent($('adays').value)).then(function (r) { A = r; $('aerr').hidden = true; $('amain').hidden = false; draw(); }, function (e) {
      $('amain').hidden = true; $('aerr').hidden = false; $('aup').textContent = '';
      $('aerr').textContent = e.status === 404 ? 'File activity arrives with the SIEM update - run update-all.ps1.' : e.status === 503 ? 'The SIEM event store is not available.' : e.status === 403 ? 'Your role cannot see file activity.' : 'Could not read file activity: ' + e.message; });
  }
  document.addEventListener('click', function (ev) { var a = ev.target.closest && ev.target.closest('[data-sptab]'); if (a) { ev.preventDefault(); tab(a.getAttribute('data-sptab')); } });
  document.addEventListener('change', function (ev) { if (ev.target.id === 'adays') load(); if (ev.target.id === 'ascope' && A) drawShare(); });
  document.addEventListener('input', function (ev) { if (ev.target.id === 'aq' && A) drawShare(); });
  var w = new XMLHttpRequest(); w.open('GET', '/dashboards/whoami.json'); w.zybQuiet = true;
  w.onload = function () { try { ROLE = String(JSON.parse(w.responseText).role || 'viewer').toLowerCase(); } catch (e) { ROLE = 'viewer'; /* no identity: least privilege */ } tab(location.hash === '#activity' ? 'activity' : 'content'); };
  w.onerror = function () { tab(location.hash === '#activity' ? 'activity' : 'content'); }; w.send();
})();
