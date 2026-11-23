// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
/* Network Configuration Management page (ncm.html) over the SIEM's GET /api/soc/netops/ncm. Devices ranked by an itemised risk;
 * backup health; versions with authorised / unauthorised / off-hours; line diff (against the golden baseline by default, or any two
 * versions); set the golden baseline (operator); download a version (operator, audited); back up now (operator); the weekly change
 * sparkline and the unusual-week flag learned from each device's own history. Delegated listeners; every value is escaped. */
(function () {
  'use strict';
  var $ = function (id) { return document.getElementById(id); };
  var Z = window.zybDetail;
  var esc = function (s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); };
  var V = null, ROLE = 'viewer', F = '', Q = '', RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 };
  var can = function (r) { return (RANK[ROLE] || 0) >= RANK[r]; };
  function req(m, p, b) {
    return new Promise(function (ok, bad) {
      var x = new XMLHttpRequest(); x.open(m, '/api/soc/netops' + p); x.withCredentials = true; x.timeout = 300000; x.zybQuiet = true; if (b) x.setRequestHeader('Content-Type', 'application/json');
      x.onload = function () { var j = null; try { j = JSON.parse(x.responseText); } catch (e) { /* not JSON: reported below */ } if (x.status >= 200 && x.status < 300 && j) return ok(j); bad(Object.assign(new Error((j && (j.error || (j.errors && j.errors[0]))) || ('HTTP ' + x.status)), { status: x.status })); };
      x.onerror = x.ontimeout = function () { bad(new Error('the SIEM is not reachable')); }; x.send(b ? JSON.stringify(b) : null);
    });
  }
  function toast(t) { var d = document.createElement('div'); d.className = 'toast-zyb'; d.setAttribute('role', 'status'); d.textContent = t; document.body.appendChild(d); setTimeout(function () { d.remove(); }, 5000); }
  var when = function (ms) { return ms ? new Date(ms).toLocaleString('en-GB', { day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit' }) : '—'; };
  var BK = { ok: ['backed up', 'green'], stale: ['stale', 'yellow'], failing: ['failing', 'red'], never: ['never read', 'red'] };
  function tile(v, l, cls, f, t) { return '<div class="col-6 col-md-3 col-xl"><div class="card card-sm"' + (f ? ' data-f="' + esc(f) + '" role="button" tabindex="0" aria-pressed="' + (F === f) + '" title="' + esc(t || 'Show these') + '"' : '') + '><div class="card-body"><div class="au-num' + (cls ? ' ' + cls : '') + '">' + esc(v) + '</div><div class="au-lbl">' + esc(l) + '</div></div></div></div>'; }
  function match(d) {
    if (F === 'failing' && !(d.backup === 'failing' || d.backup === 'never')) return false; if (F === 'stale' && d.backup !== 'stale') return false;
    if (F === 'unauth' && !d.unauthorised_30d) return false; if (F === 'drift' && !(d.drift && d.drift.added + d.drift.removed)) return false; if (F === 'nogold' && d.golden) return false;
    return !Q || [d.name, d.site, d.vendor, d.role, d.id].join(' ').toLowerCase().indexOf(Q) >= 0;
  }
  function draw() {
    var k = V.kpis;
    $('kpis').innerHTML = tile(k.devices, 'Devices', '', '') + tile(k.backed_up, 'Backed up (26 h)', 'text-green', '') + tile(k.failing, 'Backup failing', k.failing ? 'text-red' : '', 'failing') + tile(k.stale, 'Stale backup', k.stale ? 'text-yellow' : '', 'stale')
      + tile(k.changes_30d, 'Changes (30 d)', '', '') + tile(k.unauthorised_30d, 'Unauthorised (30 d)', k.unauthorised_30d ? 'text-red' : '', 'unauth', 'Changes with no approved change plan') + tile(k.drifted, 'Drifted from golden', k.drifted ? 'text-orange' : '', 'drift') + tile(k.no_golden, 'No golden baseline', '', 'nogold');
    if (V.limited) { $('devs').innerHTML = '<div class="card-body text-secondary">Device names and configurations are for analysts and above.</div>'; $('recent').innerHTML = ''; $('note').textContent = V.note; return; }
    var L = V.devices.filter(match);
    $('devs').innerHTML = L.length ? '<table class="table table-vcenter card-table"><thead><tr><th>Risk</th><th>Device</th><th>Backup</th><th>Versions</th><th>Changes (30 d)</th><th>Golden · drift</th><th>Weekly changes (12 w)</th></tr></thead><tbody>' + L.map(function (d) {
      var b = BK[d.backup] || [d.backup, 'secondary'], mx = Math.max.apply(null, d.weekly.concat([1])), rc = d.risk >= 40 ? '#d63939' : d.risk >= 20 ? '#f59f00' : '#0ca678';
      return '<tr class="rowc" data-dev="' + esc(d.id) + '"><td title="' + esc(d.risk_why.map(function (x) { return x.label + ' +' + x.points; }).join('\n')) + '"><b style="color:' + rc + '">' + esc(d.risk) + '</b></td>'
        + '<td><b>' + esc(d.name) + '</b><div class="mut">' + esc([d.vendor, d.role, d.site].filter(Boolean).join(' · ')) + '</div></td>'
        + '<td><span class="badge bg-' + b[1] + '-lt">' + esc(b[0]) + '</span><div class="mut">' + (d.last_read ? 'read ' + esc(when(d.last_read)) : esc(d.error || '')) + '</div></td>'
        + '<td>' + esc(d.versions) + '</td><td>' + esc(d.changes_30d) + (d.unauthorised_30d ? ' <span class="badge bg-red-lt">' + esc(d.unauthorised_30d) + ' unauthorised</span>' : '') + '<div class="mut">' + (d.last_change ? 'last ' + esc(when(d.last_change)) : 'no change') + '</div></td>'
        + '<td>' + (d.golden ? (d.drift && d.drift.added + d.drift.removed ? '<span class="badge bg-orange-lt">+' + esc(d.drift.added) + ' −' + esc(d.drift.removed) + ' lines</span>' : '<span class="badge bg-green-lt">matches golden</span>') : '<span class="mut">not set</span>') + '</td>'
        + '<td><div class="spark" title="changes per week, oldest to newest">' + d.weekly.map(function (n) { return '<i style="height:' + Math.max(2, n / mx * 100) + '%;' + (n ? '' : 'opacity:.2') + '"></i>'; }).join('') + '</div>' + (d.unusual_week ? '<span class="badge bg-orange-lt mt-1">unusual week</span>' : '') + '</td></tr>';
    }).join('') + '</tbody></table>' : '<div class="card-body text-secondary">' + (V.devices.length ? 'No device matches.' : 'No configuration has been read yet. Add a read-only SSH login for each Cisco device in the AI Network Engineer (Devices) and trust its host key; configurations are read once a day.') + '</div>';
    $('recent').innerHTML = V.recent.length ? V.recent.map(function (r) { return '<div class="tl ' + esc(r.kind) + '"><b>' + esc(r.name) + '</b> · ' + esc(when(r.first_seen)) + ' · ' + (r.kind === 'authorised' ? '<span class="badge bg-green-lt">authorised</span> ' + esc(r.plan.id + ' ' + r.plan.title) : '<span class="badge bg-red-lt">no change plan</span>') + (r.off_hours ? ' <span class="badge bg-orange-lt">outside working hours</span>' : '') + ' <a href="#" data-diff="' + esc(r.device) + '" data-b="' + esc(r.sha256) + '">see the diff</a></div>'; }).join('') : '<span class="text-secondary">No configuration changed in 30 days.</span>';
    $('backup').hidden = !can('operator'); $('note').textContent = V.note;
  }
  function diffHtml(d) {
    var rows = d.lines.map(function (l) { return '<div class="' + (l.op === '+' ? 'a' : l.op === '-' ? 'r' : 'c') + '">' + esc((l.op === ' ' ? '  ' : l.op + ' ') + l.t) + '</div>'; }).join('');
    return '<div class="mb-2"><span class="badge bg-green-lt">+' + esc(d.added) + '</span> <span class="badge bg-red-lt">−' + esc(d.removed) + '</span> <span class="mut">' + esc(when(d.from.first_seen)) + ' → ' + esc(when(d.to.first_seen)) + (d.note ? ' · ' + esc(d.note) : '') + '</span></div><div class="diff" aria-label="configuration diff">' + rows + '</div>';
  }
  function openDev(id, b) {
    var d = V.devices.filter(function (x) { return x.id === id; })[0]; if (!d) return;
    Z.open('Network Config Management', d.name, '<div id="nd"><span class="text-secondary">Loading the versions…</span></div>');
    Promise.all([req('GET', '/ncm/' + encodeURIComponent(id) + '/versions'), req('GET', '/ncm/' + encodeURIComponent(id) + '/diff' + (b ? '?b=' + encodeURIComponent(b) : '')).catch(function (e) { return { _err: e.message }; })]).then(function (r) {
      var vs = r[0].versions, df = r[1], h = $('nd'); if (!h) return;
      h.innerHTML = '<div class="mb-2">' + d.risk_why.map(function (x) { return '<span class="badge bg-secondary-lt me-1">' + esc(x.label) + ' +' + esc(x.points) + '</span>'; }).join('') + '</div>'
        + '<h4>Versions</h4><table class="table table-sm"><tbody>' + vs.map(function (v) {
          return '<tr><td class="mono small">' + esc(v.sha256.slice(0, 12)) + '</td><td class="small">' + esc(when(v.first_seen)) + '</td><td>' + (v.kind === 'baseline' ? '<span class="badge bg-secondary-lt">first copy</span>' : v.kind === 'authorised' ? '<span class="badge bg-green-lt">' + esc(v.plan.id) + '</span>' : '<span class="badge bg-red-lt">no change plan</span>') + (v.off_hours ? ' <span class="badge bg-orange-lt">off-hours</span>' : '') + (v.golden ? ' <span class="badge bg-blue-lt">golden</span>' : '') + '</td>'
            + '<td class="text-end">' + '<a href="#" data-cmp="' + esc(id) + '" data-sha="' + esc(v.sha256) + '">compare</a>' + (can('operator') && !v.golden ? ' · <a href="#" data-gold="' + esc(id) + '" data-sha="' + esc(v.sha256) + '">set golden</a>' : '') + (can('operator') ? ' · <a href="#" data-dl="' + esc(id) + '" data-sha="' + esc(v.sha256) + '">download</a>' : '') + '</td></tr>';
        }).join('') + '</tbody></table><h4>' + (d.golden && !b ? 'Drift from the golden baseline' : 'Latest change') + '</h4><div id="ndiff">' + (df._err ? '<span class="text-secondary">' + esc(df._err) + '</span>' : diffHtml(df)) + '</div>';
    }, function (e) { var h = $('nd'); if (h) h.innerHTML = '<span class="text-red">' + esc(e.message) + '</span>'; });
  }
  function load() {
    var w = new Promise(function (ok) { var x = new XMLHttpRequest(); x.open('GET', '/dashboards/whoami.json'); x.onload = function () { try { ok(JSON.parse(x.responseText)); } catch (e) { ok(null); } }; x.onerror = function () { ok(null); }; x.send(); });
    return w.then(function (me) { ROLE = String((me && me.role) || 'viewer').toLowerCase(); return req('GET', '/ncm'); }).then(function (v) { V = v; $('err').hidden = true; $('main').hidden = false; draw(); $('up').textContent = 'updated ' + new Date().toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' }); })
      .catch(function (e) { $('main').hidden = true; $('err').hidden = false; $('err').textContent = e.status === 404 ? 'Network Configuration Management is not on the SIEM yet - run the SIEM update.' : 'Could not load: ' + e.message; });
  }
  document.addEventListener('click', function (ev) {
    var t = ev.target; if (!t.closest) return;
    var f = t.closest('[data-f]'); if (f && f.getAttribute('data-f')) { var v = f.getAttribute('data-f'); F = F === v ? '' : v; draw(); return; }
    var df = t.closest('[data-diff]'); if (df) { ev.preventDefault(); openDev(df.getAttribute('data-diff'), df.getAttribute('data-b')); return; }
    var cm = t.closest('[data-cmp]'); if (cm) { ev.preventDefault(); var id = cm.getAttribute('data-cmp'), d = V.devices.filter(function (x) { return x.id === id; })[0];
      req('GET', '/ncm/' + encodeURIComponent(id) + '/diff?a=' + encodeURIComponent(cm.getAttribute('data-sha'))).then(function (r) { var h = $('ndiff'); if (h) { h.innerHTML = diffHtml(r); h.previousElementSibling.textContent = 'This version → the latest'; } }, function (e) { toast(e.message); }); return; }
    var g = t.closest('[data-gold]'); if (g) { ev.preventDefault(); var gid = g.getAttribute('data-gold'); req('POST', '/ncm/' + encodeURIComponent(gid) + '/golden', { sha256: g.getAttribute('data-sha') }).then(function () { toast('Golden baseline set'); return load().then(function () { openDev(gid); }); }, function (e) { toast(e.message); }); return; }
    var dl = t.closest('[data-dl]'); if (dl) { ev.preventDefault(); req('GET', '/ncm/' + encodeURIComponent(dl.getAttribute('data-dl')) + '/text?sha=' + encodeURIComponent(dl.getAttribute('data-sha'))).then(function (r) {
      var b = new Blob([r.text], { type: 'text/plain' }), u = URL.createObjectURL(b), a = document.createElement('a'); a.href = u; a.download = dl.getAttribute('data-dl') + '-' + r.sha256.slice(0, 12) + '.cfg'; document.body.appendChild(a); a.click(); setTimeout(function () { URL.revokeObjectURL(u); a.remove(); }, 500); }, function (e) { toast(e.message); }); return; }
    var row = t.closest('[data-dev]'); if (row) { openDev(row.getAttribute('data-dev')); return; }
    if (t.closest('#refresh')) { load(); return; }
    if (t.closest('#backup')) { var bt = $('backup'); bt.disabled = true; toast('Reading every configuration now - this can take a few minutes…'); req('POST', '/ncm/backup', {}).then(function (r) { toast(r.read + ' read · ' + r.failed + ' failed · ' + (r.versions_added || 0) + ' new version(s)'); bt.disabled = false; load(); }, function (e) { toast(e.message); bt.disabled = false; }); }
  });
  $('q').addEventListener('input', function () { Q = this.value.trim().toLowerCase(); draw(); });
  load();
})();
