// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
/* zyb-roadmap.js - the Implementation Roadmap pages (pdpl-roadmap.html, ndmo-roadmap.html, iso-roadmap.html). The page names its
 * framework in <main data-fw="…">; everything else is here so the pages cannot drift apart. Reads /api/itam/impl/:fw; an operator
 * sets owner, due date, status and evidence of a task (POST /impl/:fw/task/:id), an administrator the target date. Measured tasks
 * come from the modules' own records and cannot be marked done by hand - the page says "claimed" when someone tries.
 * No inline handlers; every value is escaped; requests the page handles itself are marked zybQuiet. */
(function () {
  'use strict';
  var main = document.querySelector('main[data-fw]'); if (!main) return;
  var FW = main.getAttribute('data-fw'), esc = window.zybDetail.esc, $ = function (id) { return document.getElementById(id); };
  var RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 }, ROLE = 'viewer', V = null, PH = '', FLT = '', OPEN = null;
  var PAGES = { pdpl: 'PDPL', ndmo: 'NDMO', iso: 'ISO/IEC 27001', nca: 'NCA ECC', sama: 'SAMA CSF' };
  function req(m, u, b) { return new Promise(function (ok, bad) { var x = new XMLHttpRequest(); x.open(m, '/api/itam' + u); x.withCredentials = true; x.timeout = 60000; x.zybQuiet = true; if (b) x.setRequestHeader('Content-Type', 'application/json');
    x.onload = function () { var j = null; try { j = JSON.parse(x.responseText); } catch (e) { j = null; /* not JSON: shown as the HTTP status */ } if (x.status >= 200 && x.status < 300 && j) return ok(j); bad(Object.assign(new Error((j && j.error) || ('HTTP ' + x.status)), { status: x.status })); };
    x.onerror = x.ontimeout = function () { bad(Object.assign(new Error('IT Asset Management is not reachable'), { status: 0 })); }; x.send(b ? JSON.stringify(b) : null); }); }
  function toast(t) { var d = document.createElement('div'); d.setAttribute('role', 'status'); d.style.cssText = 'position:fixed;bottom:18px;left:50%;transform:translateX(-50%);background:#1d2430;border:1px solid #2e3747;border-radius:10px;padding:10px 16px;z-index:9999;max-width:90vw'; d.textContent = t; document.body.appendChild(d); setTimeout(function () { d.remove(); }, 5000); }
  var ST = { done: ['done', 'ok'], in_progress: ['in progress', 'info'], not_started: ['not started', ''], not_applicable: ['not applicable', 'info'] };
  function col(p) { return p >= 100 ? 'var(--ok)' : p >= 50 ? 'var(--info)' : p > 0 ? 'var(--warn)' : '#3a4152'; }
  function tile(l, v, s, c) { return '<div class="t ' + (c || '') + '"><div class="l">' + esc(l) + '</div><div class="v">' + esc(v) + '</div><div class="s">' + esc(s || '') + '</div></div>'; }
  function spark(H) { if (!H || H.length < 2) return '<div class="muted small">The progress line starts after a second daily snapshot.</div>';
    var W = 340, Hh = 50, x = function (i) { return 4 + i / (H.length - 1) * (W - 8); }, y = function (v) { return Hh - 4 - v / 100 * (Hh - 8); };
    return '<svg viewBox="0 0 ' + W + ' ' + Hh + '" style="display:block;width:100%;height:50px" role="img" aria-label="Progress over time"><polyline points="' + H.map(function (h, i) { return x(i).toFixed(1) + ',' + y(h.progress).toFixed(1); }).join(' ') + '" fill="none" stroke="#79b8ff" stroke-width="2"/></svg><div class="muted small">' + esc(H[0].day + ' → ' + H[H.length - 1].day) + '</div>'; }
  function visible(t) { if (PH && t.phase !== PH) return false; var open = t.status !== 'done' && t.status !== 'not_applicable';
    return !FLT || (FLT === 'open' && open) || (FLT === 'overdue' && t.overdue) || (FLT === 'blocked' && open && t.blocked_by.length) || (FLT === 'claimed' && t.claimed) || (FLT === 'manual' && t.source === 'manual'); }
  function draw() {
    var v = V, can = RANK[ROLE] >= RANK.operator, adm = ROLE === 'admin';
    $('lead').textContent = 'From the first day to compliant and kept compliant - ' + v.total + ' tasks in ' + v.phases.length + ' phases, ' + v.measured + ' measured from the ' + v.name + ' modules\' own records. Owner: the ' + v.owner_role + '.';
    var late = v.late_days, fcS = v.forecast.finish ? (v.target ? (late > 0 ? late + ' days after the target' : (-late) + ' days before the target') : 'no target set') : v.forecast.why;
    $('kk').innerHTML = tile('Progress', v.progress + '%', v.done + ' of ' + v.total + ' tasks done', v.progress >= 85 ? 'ok' : v.progress >= 40 ? 'warn' : 'bad')
      + tile('Forecast finish', v.forecast.finish || '—', fcS, v.forecast.finish ? (v.target && late > 0 ? 'bad' : 'ok') : '') + tile('Target', v.target || '—', v.start ? 'started ' + v.start : 'not started', '')
      + tile('Overdue', v.overdue.length, 'tasks past their due date', v.overdue.length ? 'bad' : 'ok') + tile('Blocked', v.blocked, 'waiting for other tasks', v.blocked ? 'warn' : 'ok') + tile('Claimed', v.claimed.length, 'marked done, records disagree', v.claimed.length ? 'warn' : 'ok');
    $('phases').innerHTML = v.phases.map(function (p, i) { return '<div data-ph="' + esc(p.phase) + '"' + (PH === p.phase ? ' class="on"' : '') + ' role="button" tabindex="0" title="' + esc('Show only ' + p.phase) + '"><span class="muted small">' + (i + 1) + '</span> <b>' + esc(p.phase) + '</b><span class="muted small">' + esc(p.done + ' of ' + p.tasks + ' done') + '</span><div class="bar"><i style="width:' + p.progress + '%;background:' + col(p.progress) + '"></i></div></div>'; }).join('');
    $('next').innerHTML = v.next.length ? v.next.map(function (n, i) { return '<div class="nx"><span class="pill ' + (n.overdue ? 'bad' : 'info') + '">' + (i + 1) + '</span><div style="flex:1"><b>' + esc(n.title) + '</b><div class="muted small">' + esc(n.why + (n.owner ? ' · owner ' + n.owner : ' · no owner yet')) + '</div></div><a href="' + esc(n.page) + '">Open →</a></div>'; }).join('') : '<div class="empty">Every task is done or waiting for another.</div>';
    var cp = v.critical_path.map(function (id) { var t = v.tasks.filter(function (x) { return x.id === id; })[0]; return t ? t.title : id; });
    $('fc').innerHTML = '<div class="small">' + esc(v.forecast.why) + '</div>' + spark(v.history)
      + (cp.length ? '<div class="small" style="margin-top:8px"><b>Critical path</b> <span class="muted">(the longest chain still open - shorten it to finish earlier)</span><div>' + esc(cp.join(' → ')) + '</div></div>' : '')
      + (adm ? '<div class="form" style="margin-top:10px"><label for="tg">Target date</label><div style="display:flex;gap:6px"><input type="date" id="tg" value="' + esc(v.target || '') + '"><button type="button" id="tgs">Set</button></div></div>' : '');
    var L = v.tasks.filter(visible);
    $('tc').textContent = L.length + ' of ' + v.tasks.length;
    $('tasks').innerHTML = L.length ? L.map(function (t, i) { var st = ST[t.status] || [t.status, ''];
      return '<div class="tk" data-task="' + esc(t.id) + '" role="button" tabindex="0"><span class="n" style="background:' + col(t.progress) + '33;color:' + col(t.progress) + '">' + (v.tasks.indexOf(t) + 1) + '</span>'
        + '<div><div class="ttl">' + esc(t.title) + '</div><div class="sub">' + esc(t.phase + ' · ' + t.ref) + '</div><div class="sub">' + esc(t.evidence || (t.source === 'manual' ? 'set by a person' : '')) + '</div></div>'
        + '<div><span class="pill ' + st[1] + '">' + esc(st[0]) + '</span>' + (t.overdue ? '<span class="pill bad">overdue</span>' : '') + (t.claimed ? '<span class="pill warn" title="marked done by a person, but the records do not show it yet">claimed</span>' : '') + (t.blocked_by.length && t.status !== 'done' ? '<span class="pill" title="' + esc('waits for: ' + t.blocked_by.join(', ')) + '">blocked</span>' : '') + '<div class="bar"><i style="width:' + t.progress + '%;background:' + col(t.progress) + '"></i></div></div>'
        + '<div class="small">' + esc(t.owner ? t.owner : 'no owner') + '<div class="muted">' + esc(t.due ? 'due ' + t.due : 'no due date') + '</div></div>'
        + '<div class="small"><span class="pill">' + esc(t.source) + '</span><div><a href="' + esc(t.page) + '">Open page →</a></div></div></div>'; }).join('') : '<div class="empty">No task matches.</div>';
    $('note').textContent = v.note; $('up').textContent = 'Updated ' + String(v.at).slice(11, 16) + ' UTC';
  }
  function openTask(id) { var t = V.tasks.filter(function (x) { return x.id === id; })[0]; if (!t) return; OPEN = id; var can = RANK[ROLE] >= RANK.operator;
    $('dlgt').textContent = t.title;
    $('dlgb').innerHTML = '<div class="muted small">' + esc(t.phase + ' · ' + t.ref) + '</div><p class="small">' + (t.source === 'measured' ? '<b>Measured</b> from the module\'s records: ' + esc(t.evidence) + '. Do the work on <a href="' + esc(t.page) + '">its page</a>; the status follows the records.' : '<b>Set by a person</b> - the platform holds no record for this task, so whoever does it records it here with evidence.') + '</p>'
      + (t.blocked_by.length ? '<p class="small">Waits for: ' + esc(t.blocked_by.map(function (b) { var x = V.tasks.filter(function (y) { return y.id === b; })[0]; return x ? x.title : b; }).join(', ')) + '</p>' : '')
      + (t.updated_by ? '<p class="muted small">Last updated by ' + esc(t.updated_by) + ' ' + esc(String(t.updated_at || '').slice(0, 16).replace('T', ' ')) + '</p>' : '')
      + (can ? '<div class="form"><label for="f-st">Status</label><select id="f-st"><option value="">(unchanged)</option>' + ['not_started', 'in_progress', 'done', 'not_applicable'].map(function (s) { return '<option value="' + s + '"' + (t.source === 'manual' && t.status === s ? ' selected' : '') + '>' + esc(ST[s][0]) + '</option>'; }).join('') + '</select>'
        + '<label for="f-ow">Owner</label><input id="f-ow" maxlength="120" value="' + esc(t.owner || '') + '" placeholder="user name"><label for="f-du">Due</label><input id="f-du" type="date" value="' + esc(t.due || '') + '">'
        + '<label for="f-ev">Evidence</label><input id="f-ev" maxlength="1000" value="' + esc(t.manual_evidence || '') + '" placeholder="where it can be seen (document, record, link)"><label for="f-no">Note</label><input id="f-no" maxlength="500" value="' + esc(t.note || '') + '" placeholder="required for not applicable"></div>'
        + (t.source === 'measured' ? '<p class="muted small">A measured task can only be marked done by its records - marking it done here shows as "claimed".</p>' : '') : '<p class="muted small">Operators and administrators update the plan.</p>');
    $('dlgok').hidden = !can; $('dlg').showModal(); }
  function saveTask() { var b = {}, st = $('f-st').value, ow = $('f-ow').value.trim(), du = $('f-du').value, ev = $('f-ev').value.trim(), no = $('f-no').value.trim(), t = V.tasks.filter(function (x) { return x.id === OPEN; })[0];
    if (st) b.status = st; if (ow !== (t.owner || '')) b.owner = ow; if (du && du !== t.due) b.due = du; if (ev !== (t.manual_evidence || '')) b.evidence = ev; if (no !== (t.note || '')) b.note = no;
    if (b.status === 'done' && !ev) { toast('Evidence: say where the work can be seen.'); $('f-ev').focus(); return; } if (b.status === 'done') b.evidence = ev;
    if (b.status === 'not_applicable' && !no) { toast('Note: say why the task does not apply.'); $('f-no').focus(); return; } if (b.status === 'not_applicable') b.note = no;
    if (!Object.keys(b).length) { $('dlg').close(); return; }
    $('dlgok').disabled = true; req('POST', '/impl/' + FW + '/task/' + encodeURIComponent(OPEN), b).then(function (v) { V = v; draw(); $('dlg').close(); toast('Saved (audited)'); }, function (e) { toast(e.message); }).then(function () { $('dlgok').disabled = false; }); }
  function load() { req('GET', '/impl/' + FW).then(function (v) { V = v; $('main').hidden = false; $('err').innerHTML = ''; draw(); }, function (e) { $('main').hidden = true;
    $('err').innerHTML = '<div class="card"><p>' + esc(e.status === 404 ? 'The ' + (PAGES[FW] || FW) + ' roadmap is not installed yet - run the platform update.' : e.message) + '</p></div>'; }); }
  document.addEventListener('click', function (ev) { var t = ev.target;
    var ph = t.closest('[data-ph]'); if (ph) { var p = ph.getAttribute('data-ph'); PH = PH === p ? '' : p; draw(); return; }
    var tk = t.closest('[data-task]'); if (tk && !t.closest('a')) { openTask(tk.getAttribute('data-task')); return; }
    if (t.id === 'dlgx') { $('dlg').close(); return; } if (t.id === 'dlgok') { saveTask(); return; }
    if (t.id === 'refresh') { load(); return; }
    if (t.id === 'tgs') { var d = $('tg').value; if (!d) { toast('Choose a target date.'); return; } req('POST', '/impl/' + FW + '/target', { target: d }).then(function (v) { V = v; draw(); toast('Target set (audited)'); }, function (e) { toast(e.message); }); } });
  document.addEventListener('keydown', function (ev) { if (ev.key !== 'Enter') return; var el = ev.target.closest && ev.target.closest('[data-task],[data-ph]'); if (el) { ev.preventDefault(); el.click(); } });
  $('flt').addEventListener('change', function () { FLT = $('flt').value; draw(); });
  (function () { var w = new XMLHttpRequest(); w.open('GET', '/dashboards/whoami.json'); w.zybQuiet = true; w.onload = function () { try { var j = JSON.parse(w.responseText), r = String(j.role || '').toLowerCase(); if (RANK[r] != null) ROLE = r; } catch (e) { /* not signed in: viewer */ } load(); }; w.onerror = load; w.send(); })();
})();
