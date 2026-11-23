// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
/* zyb-rcsa.js - RCSA Collection page (rcsa.html). Reads /api/itam/rcsa. The Risk team opens a campaign, issues each owner a private
 * link (copied from here and sent by e-mail), and accepts or rejects the proposals that come back. The link itself is shown once, at
 * issue time - it is a credential for that owner's risks, so it is never listed again (re-issue to get a new one). No inline
 * handlers; every value escaped; requests zybQuiet. */
(function () {
  'use strict';
  var esc = function (v) { return String(v == null ? '' : v).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); };
  var $ = function (id) { return document.getElementById(id); };
  var RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 }, ROLE = 'viewer', V = null, D = null, RS = null, CUR = null, OK = null;
  function req(m, u, b) { return new Promise(function (ok, bad) { var x = new XMLHttpRequest(); x.open(m, '/api/itam' + u); x.withCredentials = true; x.timeout = 60000; x.zybQuiet = true; if (b) x.setRequestHeader('Content-Type', 'application/json');
    x.onload = function () { var j = null; try { j = JSON.parse(x.responseText); } catch (e) { j = null; /* not JSON: shown as the status */ } if (x.status >= 200 && x.status < 300 && j) return ok(j); bad(Object.assign(new Error((j && j.error) || ('HTTP ' + x.status)), { status: x.status })); };
    x.onerror = x.ontimeout = function () { bad(Object.assign(new Error('IT Asset Management is not reachable'), { status: 0 })); }; x.send(b ? JSON.stringify(b) : null); }); }
  function toast(t) { var d = document.createElement('div'); d.setAttribute('role', 'status'); d.style.cssText = 'position:fixed;bottom:18px;left:50%;transform:translateX(-50%);background:#1d2430;border:1px solid #2e3747;border-radius:10px;padding:10px 16px;z-index:9999;max-width:90vw'; d.textContent = t; document.body.appendChild(d); setTimeout(function () { d.remove(); }, 6000); }
  function tile(l, v, s, c) { return '<div class="t ' + (c || '') + '"><div class="l">' + esc(l) + '</div><div class="v">' + esc(v) + '</div><div class="s">' + esc(s || '') + '</div></div>'; }
  function pill(t, c) { return '<span class="pill ' + (c || '') + '">' + esc(t) + '</span>'; }
  var adm = function () { return ROLE === 'admin'; };
  function dlg(title, html, onOk, okText) { $('dlgt').textContent = title; $('dlgb').innerHTML = html; OK = onOk || null; $('dlgok').hidden = !onOk; $('dlgok').textContent = okText || 'Save'; $('dlg').showModal(); }
  function val(n) { var el = $('f-' + n); return el ? el.value.trim() : ''; }

  function load() { return req('GET', '/rcsa').then(function (v) { V = v; $('main').hidden = false; $('err').innerHTML = ''; drawList(); }, function (e) { $('main').hidden = true;
    $('err').innerHTML = '<div class="card"><p>' + esc(e.status === 403 ? 'RCSA campaigns are internal: operators and the Risk team.' : e.status === 404 ? 'RCSA Collection is not installed yet - run the platform update.' : e.message) + '</p></div>'; }); }
  function drawList() { var v = V, k = v.kpis; $('newb').hidden = !adm();
    $('kk').innerHTML = tile('Campaigns', k.campaigns, k.open + ' open') + tile('Waiting for review', k.pending, 'owner responses', k.pending ? 'warn' : 'ok') + tile('Risk owners', k.owners, 'across campaigns');
    $('lc').textContent = v.campaigns.length + ' campaign(s)'; $('up').textContent = 'Updated ' + String(v.generated_at).slice(11, 16) + ' UTC';
    $('list').innerHTML = v.campaigns.length ? '<table><thead><tr><th>Campaign</th><th>Period</th><th>Due</th><th>Owners</th><th>Responses</th><th>Status</th></tr></thead><tbody>' + v.campaigns.map(function (c) {
      return '<tr data-open="' + esc(c.id) + '" style="cursor:pointer"><td><b>' + esc(c.title) + '</b><div class="hint">' + esc(c.id + ' · ' + c.kind.toUpperCase()) + '</div></td><td>' + esc(c.period) + '</td><td>' + esc(c.due) + '</td><td>' + esc(c.owners) + '</td><td>' + esc(c.pending) + ' to review · ' + esc(c.accepted) + ' accepted</td><td>' + pill(c.status, c.status === 'open' ? 'info' : '') + '</td></tr>'; }).join('') + '</tbody></table>'
      : '<div class="empty">No campaign yet. ' + (adm() ? 'Open one: owners are taken from the GRC register automatically.' : 'The Risk team opens one.') + '</div>'; }
  function openDet(id) { CUR = id; Promise.all([req('GET', '/rcsa/' + encodeURIComponent(id)), req('GET', '/rcsa/' + encodeURIComponent(id) + '/responses')]).then(function (r) { D = r[0]; RS = r[1]; $('listv').hidden = true; $('detv').hidden = false; drawDet(); }, function (e) { toast(e.message); }); }
  function arrow(a, b) { if (a == null || b == null) return ''; return b > a ? '<span class="up">▲</span>' : b < a ? '<span class="down">▼</span>' : '='; }
  function drawDet() { var d = D, r = d.responses, open = d.status === 'open';
    $('dk').textContent = d.id + ' · ' + d.kind.toUpperCase() + ' · ' + d.period + ' · due ' + d.due; $('dt').textContent = d.title; $('closeb').hidden = !(adm() && open);
    $('dkk').innerHTML = tile('Owners', d.owners.length, d.owners.filter(function (o) { return o.issued && !o.revoked; }).length + ' with a live link') + tile('Responded', d.owners.filter(function (o) { return o.responded; }).length, 'of ' + d.owners.length + ' owners') + tile('To review', r.pending, r.accepted + ' accepted, ' + r.rejected + ' rejected', r.pending ? 'warn' : 'ok') + tile('Status', d.status, open ? 'links work until ' + d.due : 'links no longer work', open ? 'info' : '');
    $('owners').innerHTML = d.owners.length ? '<table><thead><tr><th>Owner</th><th>Risks</th><th>Link</th><th>Responses</th><th></th></tr></thead><tbody>' + d.owners.map(function (o) {
      var st = o.revoked ? pill('revoked', 'bad') : o.issued ? pill('link issued', 'ok') : pill('no link yet');
      return '<tr><td><b>' + esc(o.name) + '</b></td><td>' + esc(o.risks) + '</td><td>' + st + '</td><td>' + esc(o.responded) + (o.pending ? ' · ' + esc(o.pending) + ' to review' : '') + '</td><td><div class="acts">'
        + (adm() && open ? '<button type="button" data-link="' + esc(o.name) + '">' + (o.issued ? 'Re-issue link' : 'Issue link') + '</button>' : '') + (adm() && open && o.issued && !o.revoked ? '<button type="button" data-revoke="' + esc(o.key) + '">Revoke</button>' : '') + '</div></td></tr>'; }).join('') + '</tbody></table>' : '<div class="empty">No owner. Set owners on the risks in the GRC register.</div>';
    $('rc').textContent = RS.items.length + ' response(s)';
    $('resp').innerHTML = RS.items.length ? '<table><thead><tr><th>Risk</th><th>Owner</th><th>Current → proposed</th><th>Controls / comment</th><th>Status</th><th></th></tr></thead><tbody>' + RS.items.map(function (x) { var c = x.current || {}, p = x.proposed || {};
      return '<tr><td><b>' + esc(x.title) + '</b><div class="hint">' + esc(x.risk) + '</div></td><td>' + esc(x.owner_name) + '<div class="hint">' + esc(String(x.submitted_at).slice(0, 16).replace('T', ' ')) + '</div></td>'
        + '<td><div class="cmp">L ' + esc(c.likelihood) + ' <span class="arr">→</span> <b>' + esc(p.likelihood) + '</b> ' + arrow(c.likelihood, p.likelihood) + '</div><div class="cmp">I ' + esc(c.impact) + ' <span class="arr">→</span> <b>' + esc(p.impact) + '</b> ' + arrow(c.impact, p.impact) + '</div>'
        + (p.residual_likelihood ? '<div class="cmp hint">residual ' + esc(c.residual_likelihood || '—') + '×' + esc(c.residual_impact || '—') + ' → ' + esc(p.residual_likelihood) + '×' + esc(p.residual_impact) + '</div>' : '') + '</td>'
        + '<td class="small">' + ((p.controls || []).length ? esc(p.controls.join('; ')) : '—') + (p.comment ? '<div class="hint">' + esc(p.comment) + '</div>' : '') + '</td>'
        + '<td>' + pill(x.status, x.status === 'accepted' ? 'ok' : x.status === 'rejected' ? 'bad' : 'warn') + (x.reason ? '<div class="hint">' + esc(x.reason) + '</div>' : '') + '</td>'
        + '<td><div class="acts">' + (adm() && x.status === 'pending' ? '<button type="button" data-accept="' + esc(x.id) + '">Accept into register</button><button type="button" data-reject="' + esc(x.id) + '">Reject</button>' : '') + '</div></td></tr>'; }).join('') + '</tbody></table>' : '<div class="empty">No response yet.</div>'; }
  function newCampaign() { var d = new Date(Date.now() + 21 * 86400000).toISOString().slice(0, 10);
    dlg('Open an RCSA campaign', '<div class="form"><label for="f-title">Title</label><input id="f-title" value="RCSA ' + esc(new Date().getFullYear()) + '"><label for="f-period">Period</label><input id="f-period" placeholder="e.g. 2026-Q4"><label for="f-due">Due date</label><input id="f-due" type="date" value="' + esc(d) + '"><label for="f-kind">Kind</label><select id="f-kind"><option value="rcsa">RCSA - re-assess register risks</option><option value="ras">RAS - appetite metric figures</option><option value="rbc">RBC - capital inputs</option></select></div><p class="small muted">Owners are taken from the GRC register (the owner of each open risk). Links expire on the due date (at most 30 days).</p>',
      function () { $('dlgok').disabled = true; req('POST', '/rcsa', { title: val('title'), period: val('period'), due: val('due'), kind: val('kind') }).then(function (d2) { $('dlg').close(); toast('Campaign opened (audited)'); openDet(d2.id); }, function (e) { toast(e.message); }).then(function () { $('dlgok').disabled = false; }); }, 'Open'); }
  function showLink(r) { var url = location.origin + r.path;
    dlg('Link for ' + r.owner, '<p class="small">Send this link to <b>' + esc(r.owner) + '</b> by e-mail. It opens their own risks only, needs no login and expires <b>' + esc(String(r.expires).slice(0, 10)) + '</b>. It is shown only now - re-issue to get a new one (the old one keeps working until revoked).</p><div class="lnk" id="lnk">' + esc(url) + '</div><div class="acts"><button type="button" id="copyl">Copy link</button><a id="mail" href="#">Open in e-mail</a></div>');
    var subj = encodeURIComponent('Risk & Control Self-Assessment - your input'), bodyTxt = encodeURIComponent('Dear ' + r.owner + ',\n\nPlease re-assess the risks you own using this private link (no login needed). It expires on ' + String(r.expires).slice(0, 10) + '.\n\n' + url + '\n\nThank you,\nRisk Management');
    $('mail').setAttribute('href', 'mailto:?subject=' + subj + '&body=' + bodyTxt);
    $('copyl').addEventListener('click', function () { var done = function () { toast('Link copied'); }; if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(url).then(done, function () { toast('Select the link and copy it'); }); else toast('Select the link and copy it'); }); }
  document.addEventListener('click', function (ev) { var t = ev.target, x;
    if (t.id === 'newb') return newCampaign();
    if ((x = t.closest('tr[data-open]'))) return openDet(x.getAttribute('data-open'));
    if (t.id === 'back') { $('detv').hidden = true; $('listv').hidden = false; CUR = null; return load(); }
    if ((x = t.closest('[data-link]'))) return req('POST', '/rcsa/' + CUR + '/link', { owner: x.getAttribute('data-link') }).then(function (r) { showLink(r); openDet(CUR); }, function (e) { toast(e.message); });
    if ((x = t.closest('[data-revoke]'))) return req('POST', '/rcsa/' + CUR + '/link/' + encodeURIComponent(x.getAttribute('data-revoke')) + '/revoke', {}).then(function () { toast('Link revoked - it no longer opens'); openDet(CUR); }, function (e) { toast(e.message); });
    if ((x = t.closest('[data-accept]'))) return req('POST', '/rcsa/responses/' + encodeURIComponent(x.getAttribute('data-accept')) + '/accept', {}).then(function () { toast('Accepted - the register now carries the new rating (audited)'); openDet(CUR); }, function (e) { toast(e.message); });
    if ((x = t.closest('[data-reject]'))) { var rid = x.getAttribute('data-reject'); return dlg('Reject this response', '<div class="form"><label for="f-reason">Reason</label><input id="f-reason" placeholder="tell the owner why"></div>', function () { req('POST', '/rcsa/responses/' + encodeURIComponent(rid) + '/reject', { reason: val('reason') }).then(function () { $('dlg').close(); toast('Rejected (audited)'); openDet(CUR); }, function (e) { toast(e.message); }); }, 'Reject'); }
    if (t.id === 'closeb') return req('POST', '/rcsa/' + CUR + '/close', {}).then(function () { toast('Campaign closed - the links no longer work'); openDet(CUR); }, function (e) { toast(e.message); });
    if (t.id === 'dlgok' && OK) return OK(); if (t.id === 'dlgx') return $('dlg').close();
    if (t.id === 'refresh') return CUR ? openDet(CUR) : load(); });
  (function () { var w = new XMLHttpRequest(); w.open('GET', '/dashboards/whoami.json'); w.zybQuiet = true; w.onload = function () { try { var j = JSON.parse(w.responseText), r = String(j.role || '').toLowerCase(); if (RANK[r] != null) ROLE = r; } catch (e) { /* not signed in: viewer */ } load(); }; w.onerror = load; w.send(); })();
})();
