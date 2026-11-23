// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
/* zyb-duty.js - the AI engineer's DUTY DESK panel, on every AI engineer page.
 * Mount: <div data-zyb-duty="network|security|windows|exchange|pentest|desktop" data-api="/api/soc|/api/itam"></div>
 * Shows whether the engineer is on duty (last patrol, late, not connected, AI budget), its work queue by state, and per
 * work item: evidence, the engineer's investigation, the AI analysis, linked change plans, ticket and full history.
 * People act on an item here: assign to me, note, snooze (with a reason), close (one of four codes, with a reason),
 * investigate now (with AI where it is enabled), raise a ServiceDesk ticket. The engineer never executes a change:
 * plans are approved and applied in the engineer's own change workflow. Every value is escaped. */
(function () {
  'use strict';
  // a work item in the page language: engineers whose rules write Arabic (the PDPL consultant) send title_ar / recommendation_ar
  var AR = !!(window.zybLang && window.zybLang.lang === 'ar');
  var tl = function (x) { return AR && x.title_ar ? x.title_ar : x.title; };
  if (window.__zybDuty) return; window.__zybDuty = true;
  var RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 }, ROLE = 'viewer', WHO = '';
  var ST = {
    open: ['New', 'info'], investigating: ['Investigating', 'info'], diagnosed: ['Diagnosed', 'warn'], 'needs-human': ['Needs a person', 'bad'],
    'awaiting-approval': ['Waiting for approval', 'acc'], approved: ['Approved — apply it', 'info'], 'fix-applied': ['Verifying the fix', 'info'],
    snoozed: ['Snoozed', 'mut'], resolved: ['Resolved', 'ok'], closed: ['Closed', 'mut']
  };
  var FILTERS = [['open', 'All open'], ['needs-human', 'Needs a person'], ['diagnosed', 'Diagnosed'], ['awaiting-approval', 'Waiting for approval'], ['approved', 'Approved'], ['fix-applied', 'Verifying'], ['snoozed', 'Snoozed'], ['resolved', 'Resolved'], ['closed', 'Closed']];
  var SEVC = { critical: 'bad', high: 'warn', medium: 'info', low: 'mut' };

  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); }
  function can(r) { return RANK[ROLE] >= RANK[r]; }
  function ago(t) { if (!t) return 'never'; var s = Math.max(0, (Date.now() - t) / 1000); return s < 90 ? Math.round(s) + ' s ago' : s < 5400 ? Math.round(s / 60) + ' min ago' : s < 172800 ? Math.round(s / 3600) + ' h ago' : Math.round(s / 86400) + ' d ago'; }
  function when(t) { return t ? new Date(t).toLocaleString('en-GB', { day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit' }) : '—'; }
  function pill(text, kind) { return '<span class="zdt-p zdt-' + esc(kind || 'mut') + '">' + esc(text) + '</span>'; }
  function stPill(s) { var x = ST[s] || [s, 'mut']; return pill(x[0], x[1]); }
  function req(api, m, p, b) {
    return new Promise(function (ok, bad) {
      var x = new XMLHttpRequest(); x.open(m, api + p); x.withCredentials = true; x.timeout = /investigate/.test(p) ? 300000 : 60000;
      if (b) x.setRequestHeader('Content-Type', 'application/json');
      x.onload = function () { var j = null; try { j = JSON.parse(x.responseText); } catch (e) { /* not JSON */ }
        if (x.status >= 200 && x.status < 300) return ok(j);
        bad(Object.assign(new Error((j && ((j.errors && j.errors.join('; ')) || j.error)) || ('HTTP ' + x.status)), { status: x.status })); };
      x.onerror = x.ontimeout = function () { bad(new Error('not reachable')); };
      x.send(b ? JSON.stringify(b) : (m === 'POST' || m === 'PUT' ? '{}' : null));
    });
  }
  function toast(t) { var d = document.createElement('div'); d.className = 'zdt-toast'; d.textContent = t; document.body.appendChild(d); setTimeout(function () { d.remove(); }, 4200); }

  var CSS = '.zdt{background:var(--panel,#13151B);border:1px solid var(--edge,#252933);border-radius:12px;padding:14px;margin:0 0 12px;color:var(--text,#ECEEF2);font:14px/1.45 "Segoe UI",system-ui,sans-serif}'
    + '.zdt h2{margin:0;font-size:15px;color:var(--title,#fff);display:flex;align-items:center;gap:8px;flex-wrap:wrap}'
    + '.zdt-hd{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:10px}.zdt-hd .sp{flex:1}'
    + '.zdt-dot{width:10px;height:10px;border-radius:50%;display:inline-block;box-shadow:0 0 0 3px rgba(255,255,255,.04)}'
    + '.zdt-sub{color:var(--mute,#8C93A1);font-size:12.5px}'
    + '.zdt-b{font:600 12.5px "Segoe UI",system-ui,sans-serif;background:var(--raise,#1A1D25);color:var(--text,#ECEEF2);border:1px solid var(--border,#2E3440);border-radius:7px;padding:6px 11px;cursor:pointer}.zdt-b:hover{border-color:#4a5162}.zdt-b.pri{background:#17313a;border-color:#2b6b7e;color:#9fe6f5}.zdt-b:disabled{opacity:.5;cursor:default}'
    + '.zdt-k{display:flex;gap:6px;flex-wrap:wrap;margin:0 0 10px}.zdt-k button{display:inline-flex;align-items:center;gap:6px;background:var(--raise,#1A1D25);border:1px solid var(--edge,#252933);color:var(--text,#ECEEF2);border-radius:999px;padding:4px 11px;font:600 12px "Segoe UI",system-ui,sans-serif;cursor:pointer}'
    + '.zdt-k button b{font-weight:800}.zdt-k button.on{background:#e7eaf0;color:#0a0b0f;border-color:#e7eaf0}.zdt-k button:hover{border-color:#4a5162}'
    + '.zdt table{width:100%;border-collapse:collapse;font-size:13px}.zdt th{text-align:left;font-weight:500;color:var(--mute,#8C93A1);padding:6px 8px;border-bottom:1px solid var(--edge,#252933);white-space:nowrap}'
    + '.zdt td{padding:7px 8px;border-bottom:1px solid rgba(255,255,255,.05);vertical-align:middle}.zdt tr.zdt-r{cursor:pointer}.zdt tr.zdt-r:hover td{background:rgba(255,255,255,.035)}'
    + '.zdt-tw{overflow-x:auto}.zdt-e{color:var(--mute,#8C93A1);padding:12px 0}.zdt-mono{font-family:Consolas,monospace;font-size:12px}'
    + '.zdt-p{display:inline-block;padding:1px 8px;border-radius:999px;font-size:11px;font-weight:700;white-space:nowrap}'
    + '.zdt-ok{background:rgba(63,185,80,.15);color:#3fb950}.zdt-warn{background:rgba(227,179,65,.15);color:#e3b341}.zdt-bad{background:rgba(255,123,114,.16);color:#ff7b72}.zdt-info{background:rgba(121,184,255,.15);color:#79b8ff}.zdt-acc{background:rgba(163,113,247,.16);color:#c8a6ff}.zdt-mut{background:rgba(140,147,161,.16);color:#a3a9b5}'
    + '.zdt-note{color:var(--mute,#8C93A1);font-size:12px;margin-top:8px}'
    + '.zdt-f{display:grid;gap:7px;margin-top:8px}.zdt-f input,.zdt-f select,.zdt-f textarea{background:#0b0c10;color:#ECEEF2;border:1px solid #2E3440;border-radius:7px;padding:7px 9px;font:13px "Segoe UI",system-ui,sans-serif;width:100%;box-sizing:border-box}'
    + '.zdt-acts{display:flex;gap:6px;flex-wrap:wrap;margin-top:10px}.zdt-hist{list-style:none;margin:0;padding:0}.zdt-hist li{padding:5px 0;border-bottom:1px solid rgba(255,255,255,.05);font-size:12.5px}.zdt-hist b{color:#fff}'
    + '.zdt-ai{white-space:pre-wrap;background:#0f1116;border:1px solid #23272f;border-radius:8px;padding:10px;font-size:12.8px;max-height:420px;overflow:auto}'
    + '.zdt-kp{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:8px;margin:0 0 10px}.zdt-kt{background:var(--raise,#1A1D25);border:1px solid var(--edge,#252933);border-left-width:3px;border-radius:9px;padding:8px 10px;cursor:pointer;text-align:left;color:inherit;font:inherit}.zdt-kt:hover{border-color:#4a5162}'
    + '.zdt-kt .l{font-size:11px;color:var(--mute,#8C93A1);line-height:1.25}.zdt-kt .v{font-size:19px;font-weight:700;color:var(--title,#fff);margin-top:2px}.zdt-kt .v small{font-size:11px;color:var(--mute,#8C93A1);font-weight:500}'
    + '.zdt-kt.ok{border-left-color:#3fb950}.zdt-kt.warn{border-left-color:#e3b341}.zdt-kt.bad{border-left-color:#ff7b72}.zdt-kt.na{border-left-color:#4b5262}.zdt-kt.info{border-left-color:#79b8ff}'
    + '.zdt-toast{position:fixed;bottom:16px;left:50%;transform:translateX(-50%);background:#1f242d;border:1px solid #2e3440;border-radius:9px;padding:9px 14px;z-index:99999;color:#ECEEF2;font:13px "Segoe UI",system-ui,sans-serif}';

  // the engineer's job description and approvals (vendor/zyb-charter.js, loaded the first time it is asked for)
  function charter(eng) {
    var show = function () { var C = window.zybCharter, Z = window.zybDetail, c = C && C.get(eng); if (!Z) return; Z.open('Role & approvals', c ? c.name : eng, C ? C.html(eng) : '<p>The charter could not be loaded.</p>'); };
    if (window.zybCharter) { show(); return; }
    var me = document.querySelector('script[src*="zyb-duty.js"]'), v = me && /[?&]v=([^&]+)/.exec(me.src);
    var s = document.createElement('script'); s.src = '/dashboards/vendor/zyb-charter.js' + (v ? '?v=' + v[1] : ''); s.onload = show; s.onerror = show; document.head.appendChild(s);
  }
  function mount(el) {
    var eng = el.getAttribute('data-zyb-duty'), api = el.getAttribute('data-api') || '/api/soc', S = { f: 'open', items: [], me: null, codes: {} };
    el.className = (el.className ? el.className + ' ' : '') + 'zdt';
    el.innerHTML = '<div class="zdt-hd"><span class="zdt-dot" id="zdt-dot-' + esc(eng) + '" style="background:#6b7280"></span><h2>Duty desk <span class="zdt-sub" data-x="sub">loading…</span></h2><span class="sp"></span>'
      + '<span data-x="tools"></span></div><div class="zdt-kp" data-x="kpi"></div><div class="zdt-k" data-x="chips"></div><div class="zdt-tw" data-x="body"><div class="zdt-e">Loading…</div></div>'
      + '<p class="zdt-note">' + (eng === 'dba' || eng === 'apps'
        ? 'This engineer patrols on its own, opens a work item for each problem and recommends the next step. It never changes anything and proposes nothing for execution: the DBA / application owner decides.'
        : eng === 'virt' ? 'This administrator checks vCenter and Prism every hour with read-only accounts, opens a work item for each problem and writes the change plan (PowerCLI / acli). It never changes a platform: an administrator who did not ask for it approves the plan, a person applies it, and the next collection verifies it.'
        : eng === 'siem' ? 'This engineer checks every 10 minutes that each asset that should log is logging. It opens a work item for each silent asset, each asset waiting for its device configuration (with the exact configuration) and each log sender missing from the inventory, and closes it when the logs arrive. It never configures a device: the device administrator applies the configuration.'
        : eng === 'grc' ? 'This consultant patrols the compliance records on its own, opens a work item for each gap with its recommendation and framework clauses, and resolves it only when the records show the gap closed. It never approves, signs off or attests: drafts are decided by an administrator, drills are signed off by a second person.'
        : eng === 'pentest' ? 'This engineer assesses the attack surface from data already collected and never starts a test: engagements need an administrator\'s authorisation and a second administrator\'s approval.'
        : eng === 'desktop' ? 'This engineer patrols on its own and requests patch installations; an administrator other than the requester approves before Endpoint Central installs anything.'
        : 'This engineer patrols on its own, opens a work item for each problem, investigates it read-only and proposes the fix. It never changes anything itself: change plans are approved by an administrator (never the one who asked) and applied by a person, then the engineer re-checks.')
        + ' <a href="ai-team.html#charters" style="color:inherit">Roles &amp; approvals →</a></p>';
    var $ = function (k) { return el.querySelector('[data-x="' + k + '"]'); };

    function head() {
      var m = S.me; if (!m) { $('sub').textContent = 'not available — run the engine update'; return; }
      var dot = !m.on_duty ? '#6b7280' : m.not_connected ? '#6b7280' : m.late || m.last_error ? '#e3b341' : '#3fb950';
      el.querySelector('.zdt-dot').style.background = dot;
      var bits = [!m.on_duty ? 'off duty' : m.not_connected ? 'on duty · its source is not connected yet' : 'on duty · last patrol ' + ago(m.last_patrol) + (m.late ? ' (late)' : '')];
      if (m.ai) bits.push(m.ai.enabled ? 'AI analysis ' + m.ai.used_today + '/' + m.ai.cap + ' today' : 'AI analysis off' + (m.ai.reason ? ' (' + m.ai.reason + ')' : ''));
      if (m.last_error) bits.push('last problem: ' + m.last_error);
      $('sub').textContent = bits.join(' · ');
      $('tools').innerHTML = (can('operator') ? '<button type="button" class="zdt-b" data-a="patrol">⟳ Patrol now</button> ' : '') + '<button type="button" class="zdt-b" data-a="kpi">📈 KPIs</button> <button type="button" class="zdt-b" data-a="report">Shift report</button> <button type="button" class="zdt-b" data-a="charter">📋 Role &amp; approvals</button>';
      var b = m.by_status || {};
      $('chips').innerHTML = FILTERS.map(function (f) {
        var n = f[0] === 'open' ? m.open : f[0] === 'resolved' ? m.resolved_24h : f[0] === 'closed' ? null : (b[f[0]] || 0);
        if (n === 0 && f[0] !== 'open' && f[0] !== S.f) return '';
        return '<button type="button" data-f="' + esc(f[0]) + '"' + (S.f === f[0] ? ' class="on"' : '') + '>' + esc(f[1]) + (n != null ? ' <b>' + esc(n) + '</b>' : '') + (f[0] === 'resolved' ? ' <span style="opacity:.7">24h</span>' : '') + '</button>';
      }).join('') + (m.critical ? '<span class="zdt-p zdt-bad" style="align-self:center">' + esc(m.critical) + ' critical</span>' : '');
    }
    function body() {
      var it = S.items;
      if (!it.length) { $('body').innerHTML = '<div class="zdt-e">' + (S.f === 'open' ? (S.me && S.me.not_connected ? 'Nothing to work on yet: this engineer\'s data source is not connected.' : 'No open work. The engineer will open an item at the next patrol if it finds a problem.') : 'Nothing in this state.') + '</div>'; return; }
      $('body').innerHTML = '<table><thead><tr><th>Severity</th><th>Problem</th><th>Target</th><th>State</th><th>First seen</th><th>Owner</th><th></th></tr></thead><tbody>' + it.map(function (x) {
        return '<tr class="zdt-r" data-id="' + esc(x.id) + '"><td>' + pill(x.severity, SEVC[x.severity]) + '</td><td>' + esc(tl(x)) + (x.reopened ? ' <span class="zdt-p zdt-warn" title="came back after it was fixed">back ×' + esc(x.reopened) + '</span>' : '') + '</td>'
          + '<td>' + esc((x.target && x.target.name) || '') + (x.site ? ' <span class="zdt-sub">' + esc(x.site) + '</span>' : '') + '</td><td>' + stPill(x.status) + '</td><td title="' + esc(when(x.first_seen)) + '">' + esc(ago(x.first_seen)) + '</td>'
          + '<td>' + esc(x.owner || '—') + '</td><td class="zdt-mono">' + esc((x.changes || []).join(' ')) + (x.ticket ? ' #' + esc(x.ticket.request_id) : '') + '</td></tr>';
      }).join('') + '</tbody></table>';
    }
    function load() {
      return Promise.all([req(api, 'GET', '/duty/engineers'), req(api, 'GET', '/duty/items?engineer=' + encodeURIComponent(eng) + '&status=' + encodeURIComponent(S.f) + '&limit=300')]).then(function (R) {
        S.me = ((R[0] && R[0].engineers) || []).filter(function (e) { return e.id === eng; })[0] || null; S.codes = (R[0] && R[0].close_codes) || {};
        S.items = (R[1] && R[1].items) || []; head(); body(); loadKpi();
      }).catch(function (e) { $('sub').textContent = e.status === 404 ? 'not installed — run the engine update' : e.message; $('body').innerHTML = ''; });
    }

    /* KPIs (30 days, from the engine's /duty/kpis): a strip of tiles; click → every KPI, the engineer's own measures, targets */
    var KST = { ok: ['on target', 'ok'], warn: ['close', 'warn'], bad: ['off target', 'bad'], na: ['not measured', 'mut'], info: ['', 'info'] };
    function kv(k) { return k.value == null ? '—' : (Math.round(k.value * 10) / 10).toLocaleString() + (k.unit ? (k.unit === '%' ? '%' : ' ' + k.unit) : ''); }
    function tgt(k) { return k.target == null ? '' : (k.dir === 'min' ? '≥ ' : '≤ ') + k.target + (k.unit ? (k.unit === '%' ? '%' : ' ' + k.unit) : ''); }
    function drawKpi() {
      var K = S.kpi, box = $('kpi'); if (!K) { box.innerHTML = ''; return; }
      var pick = ['open_serious', 'sla_pct', 'approval_h', 'fix_h'].map(function (id) { return K.kpis.filter(function (k) { return k.id === id; })[0]; }).filter(Boolean).concat((K.domain || []).slice(0, 2));
      box.innerHTML = '<button type="button" class="zdt-kt ' + (K.score == null ? 'na' : K.score >= 85 ? 'ok' : K.score >= 60 ? 'warn' : 'bad') + '" data-a="kpi"><div class="l">KPI score · ' + esc(K.days) + ' days</div><div class="v">' + (K.score == null ? '—' : esc(K.score)) + ' <small>' + (K.score == null ? 'not measured yet' : esc(K.measured) + ' KPIs measured') + '</small></div></button>'
        + pick.map(function (k) { return '<button type="button" class="zdt-kt ' + esc(k.status) + '" data-a="kpi" title="' + esc((k.detail || '') + (k.target != null ? ' · target ' + tgt(k) : '')) + '"><div class="l">' + esc(k.label) + '</div><div class="v">' + esc(kv(k)) + ' <small>' + esc(k.target != null ? 'target ' + tgt(k) : '') + '</small></div></button>'; }).join('');
    }
    function loadKpi() { return req(api, 'GET', '/duty/kpis?engineer=' + encodeURIComponent(eng) + '&days=30').then(function (r) { S.kpi = (r && r.engineers && r.engineers[0]) || null; drawKpi(); }).catch(function () { S.kpi = null; drawKpi(); }); }
    function kpiPanel() {
      var K = S.kpi, Z = window.zybDetail; if (!K || !Z) return;
      var row = function (k, own) { var st = KST[k.status] || KST.na; return '<tr><td>' + esc(k.label) + (k.detail ? '<div class="zd-dim" style="font-size:11.5px">' + esc(k.detail) + '</div>' : '') + '</td><td class="n"><b>' + esc(kv(k)) + '</b></td><td class="n">' + esc(tgt(k) || '—') + '</td><td>' + (st[0] ? pill(st[0], st[1]) : '') + '</td></tr>'; };
      var h = '<p>Measured from this engineer\'s work items over the last ' + esc(K.days) + ' days: what it found, how fast it was diagnosed, how fast a <b>person</b> responded and approved the fix, whether the fix held. A KPI with nothing to measure says so: it never counts as on target.</p>'
        + Z.sec('Service KPIs', '<div class="zd-tw"><table><thead><tr><th>KPI</th><th class="n">Now</th><th class="n">Target</th><th></th></tr></thead><tbody>' + K.kpis.map(function (k) { return row(k); }).join('') + '</tbody></table></div>')
        + Z.sec('The engineer\'s own measures (open now)', (K.domain || []).length ? '<div class="zd-tw"><table><thead><tr><th>Measure</th><th class="n">Now</th><th class="n">Target</th><th></th></tr></thead><tbody>' + K.domain.map(function (k) { return row(k, true); }).join('') + '</tbody></table></div>' : '<p class="zd-dim">Nothing open.</p>')
        + Z.sec('In the window', '<p>' + esc(K.counts.opened) + ' problems found · ' + esc(K.counts.resolved) + ' resolved (' + esc(K.counts.verified_fixed) + ' verified by a re-check) · ' + esc(K.counts.open) + ' open · ' + esc(K.counts.awaiting_approval) + ' waiting for approval.</p>');
      if (can('admin')) h += Z.sec('Targets for this engineer (administrator)', '<div class="zdt-f" style="grid-template-columns:repeat(auto-fit,minmax(170px,1fr))">' + K.kpis.map(function (k) { return '<label style="font-size:11.5px;color:var(--mute,#8C93A1)">' + esc(k.label) + ' (' + (k.dir === 'min' ? 'at least' : 'at most') + (k.unit ? ', ' + esc(k.unit) : '') + ')<input type="number" min="0" step="any" data-kt="' + esc(k.id) + '" value="' + esc(k.target) + '"></label>'; }).join('') + '</div><div class="zdt-acts"><button type="button" class="zdt-b pri" data-kts="1">Save targets</button></div><p class="zd-dim">Saved in the duty policy and written to the audit log.</p>');
      Z.open('KPIs · ' + K.days + ' days', K.name, h);
      var bt = document.querySelector('#zd [data-kts]');
      if (bt) bt.addEventListener('click', function () {
        bt.disabled = true;
        req(api, 'GET', '/duty/policy').then(function (P) {
          var all = Object.assign({}, (P && P.kpi_targets) || {}), mine = {};
          [].forEach.call(document.querySelectorAll('#zd [data-kt]'), function (i) { if (i.value !== '') mine[i.getAttribute('data-kt')] = Number(i.value); });
          all[eng] = mine;
          return req(api, 'PUT', '/duty/policy', { kpi_targets: all });
        }).then(function () { toast('Targets saved'); return loadKpi(); }).then(kpiPanel).catch(function (e) { bt.disabled = false; toast(e.message); });
      });
    }
    function detail(id) {
      req(api, 'GET', '/duty/items/' + encodeURIComponent(id)).then(function (x) {
        var Z = window.zybDetail; if (!Z) return;
        var h = Z.kv([['Work item', esc(x.id)], ['State', stPill(x.status)], ['Severity', pill(x.severity, SEVC[x.severity])], ['Target', esc((x.target && x.target.name) || '—')],
          ['Site', esc(x.site || '—')], ['Owner', esc(x.owner || 'unassigned')], ['First seen', esc(when(x.first_seen))], ['Last seen', esc(when(x.last_seen)) + ' · ' + esc(x.seen_count || 1) + ' patrol(s)'],
          ['Came back', esc(x.reopened || 0) + ' time(s)'], ['Ticket', x.ticket ? esc('ServiceDesk Plus #' + x.ticket.request_id) : (x.ticket_queued ? 'queued' : '—')]]);
        if ((x.evidence || []).length) h += Z.sec('Evidence', '<ul style="margin:0;padding-left:18px">' + x.evidence.map(function (e) { return '<li>' + esc(e) + '</li>'; }).join('') + '</ul>');
        if (x.recommendation) h += Z.sec('Recommendation', '<p>' + esc(AR && x.recommendation_ar ? x.recommendation_ar : x.recommendation) + '</p>');
        if (x.investigation) {
          var inv = x.investigation;
          h += Z.sec('Investigation · ' + when(inv.at), '<p>' + esc(inv.summary) + '</p>'
            + ((inv.checks || []).length ? '<table><thead><tr><th>Check</th><th>Result</th><th>Detail</th></tr></thead><tbody>' + inv.checks.map(function (c) { return '<tr><td>' + esc(c.name) + '</td><td>' + pill(c.status, c.status === 'ok' ? 'ok' : c.status === 'fail' ? 'bad' : c.status === 'warn' ? 'warn' : 'mut') + '</td><td>' + esc(c.detail) + '</td></tr>'; }).join('') + '</tbody></table>' : '')
            + ((inv.causes || []).length ? '<p style="margin-top:8px"><b>Likely cause' + (inv.causes.length > 1 ? 's' : '') + '</b></p><ol style="margin:0;padding-left:18px">' + inv.causes.map(function (c) { return '<li>' + esc(AR && c.cause === x.title && x.title_ar ? x.title_ar : c.cause) + (c.confidence ? ' <span class="zdt-sub">(' + esc(c.confidence) + ')</span>' : '') + (c.fix ? '<br><span class="zdt-sub">Fix: ' + esc(AR && c.fix === x.recommendation && x.recommendation_ar ? x.recommendation_ar : c.fix) + '</span>' : '') + '</li>'; }).join('') + '</ol>' : ''));
        }
        if (x.ai) h += Z.sec('AI analysis · ' + when(x.ai.at), x.ai.error ? '<p class="zdt-sub">The AI analysis failed: ' + esc(x.ai.error) + '</p>' : '<div class="zdt-ai">' + esc(x.ai.answer) + '</div><p class="zdt-sub">' + esc(x.ai.steps || 0) + ' investigation step(s)' + (x.ai.model ? ' · ' + esc(x.ai.model) : '') + '</p>');
        if ((x.changes || []).length) h += Z.sec('Proposed fix', '<p>Change plan' + (x.changes.length > 1 ? 's' : '') + ' <b class="zdt-mono">' + esc(x.changes.join(', ')) + '</b> — recorded for approval. An administrator approves it in this engineer\'s change list and a person applies it; then the engineer re-checks the target.</p>');
        h += Z.sec('History', '<ul class="zdt-hist">' + (x.history || []).slice().reverse().map(function (e) { return '<li><b>' + esc(e.action) + '</b> · ' + esc(when(e.at)) + ' · ' + esc(e.by || '') + (e.note ? '<br><span class="zdt-sub">' + esc(e.note) + '</span>' : '') + '</li>'; }).join('') + '</ul>');
        var term = x.status === 'resolved' || x.status === 'closed';
        if (can('operator') && !term) {
          h += Z.sec('Act on it', '<div class="zdt-acts">'
            + (x.owner !== WHO ? '<button type="button" class="zdt-b" data-d="assign">Assign to me</button>' : '')
            + '<button type="button" class="zdt-b" data-d="investigate">Investigate now</button>'
            + (S.me && S.me.ai && S.me.ai.enabled ? '<button type="button" class="zdt-b pri" data-d="ai">Investigate with AI</button>' : '')
            + (api.indexOf('/api/soc') === 0 && !x.ticket ? '<button type="button" class="zdt-b" data-d="ticket">Raise ServiceDesk ticket</button>' : '')
            + '<button type="button" class="zdt-b" data-d="f-note">Add a note</button><button type="button" class="zdt-b" data-d="f-snooze">Snooze</button><button type="button" class="zdt-b" data-d="f-close">Close</button></div><div data-d="form"></div>');
        }
        Z.open(S.me ? S.me.name : 'AI engineer', tl(x), h);
        var box = document.getElementById('zd'); if (!box) return;
        box.onclick = function (ev) {
          var a = ev.target.closest && ev.target.closest('[data-d]'); if (!a || a.getAttribute('data-d') === 'form') return;
          var d = a.getAttribute('data-d'), form = box.querySelector('[data-d="form"]'), P = '/duty/items/' + encodeURIComponent(x.id);
          var act = function (path, b, msg) { a.disabled = true; req(api, 'POST', P + path, b).then(function () { toast(msg); load(); detail(x.id); }).catch(function (e) { a.disabled = false; toast(e.message); }); };
          if (d === 'assign') act('/assign', {}, 'Assigned to you');
          else if (d === 'investigate') act('/investigate', { ai: false }, 'Investigated');
          else if (d === 'ai') { toast('The AI is investigating — this can take a minute or two'); act('/investigate', { ai: true }, 'AI analysis done'); }
          else if (d === 'ticket') act('/ticket', {}, 'Ticket raised');
          else if (d === 'f-note') form.innerHTML = '<div class="zdt-f"><textarea rows="3" data-i="text" placeholder="What did you check or do?"></textarea><div><button type="button" class="zdt-b pri" data-d="do-note">Save note</button></div></div>';
          else if (d === 'f-snooze') form.innerHTML = '<div class="zdt-f"><select data-i="hours"><option value="4">4 hours</option><option value="24">1 day</option><option value="72">3 days</option><option value="168">1 week</option></select><input data-i="reason" placeholder="Why can it wait? (required)"><div><button type="button" class="zdt-b pri" data-d="do-snooze">Snooze</button></div></div>';
          else if (d === 'f-close') form.innerHTML = '<div class="zdt-f"><select data-i="code">' + Object.keys(S.codes).map(function (k) { return '<option value="' + esc(k) + '">' + esc(k) + ' — ' + esc(S.codes[k]) + '</option>'; }).join('') + '</select><input data-i="reason" placeholder="Reason (required)"><div><button type="button" class="zdt-b pri" data-d="do-close">Close</button></div></div>';
          else if (d === 'do-note') { var t = form.querySelector('[data-i="text"]').value.trim(); if (!t) { toast('Write a note'); return; } act('/note', { text: t }, 'Note saved'); }
          else if (d === 'do-snooze') { var r = form.querySelector('[data-i="reason"]').value.trim(); if (!r) { toast('A reason is required'); return; } act('/snooze', { hours: Number(form.querySelector('[data-i="hours"]').value), reason: r }, 'Snoozed'); }
          else if (d === 'do-close') { var r2 = form.querySelector('[data-i="reason"]').value.trim(); if (!r2) { toast('A reason is required'); return; } act('/close', { code: form.querySelector('[data-i="code"]').value, reason: r2 }, 'Closed'); }
        };
      }).catch(function (e) { toast(e.message); });
    }
    function report() {
      req(api, 'POST', '/duty/reports', { engineer: eng }).then(function (r) {
        var R = r.report, Z = window.zybDetail; if (!Z || !R) return;
        var lst = function (a) { return a.length ? '<ul style="margin:0;padding-left:18px">' + a.map(function (x) { return '<li>' + pill(x.severity, SEVC[x.severity]) + ' ' + esc(tl(x)) + (x.target ? ' <span class="zdt-sub">' + esc(x.target) + '</span>' : '') + '</li>'; }).join('') + '</ul>' : '<p class="zdt-sub">none</p>'; };
        Z.open('Shift handover · ' + R.day, R.engineer_name, '<div class="zdt-ai">' + esc(R.summary) + '</div>' + Z.sec('Waiting for approval', lst(R.awaiting_approval)) + Z.sec('Approved, not yet applied', lst(R.approved_not_applied)) + Z.sec('Needs a person', lst(R.needs_human)));
      }).catch(function (e) {
        // a viewer cannot make a report: show the latest saved one
        req(api, 'GET', '/duty/reports?engineer=' + encodeURIComponent(eng) + '&limit=1').then(function (r) { var R = r.reports && r.reports[0]; if (!R) { toast('No shift report yet (one is made every morning)'); return; } window.zybDetail.open('Shift handover · ' + R.day, R.engineer_name, '<div class="zdt-ai">' + esc(R.summary) + '</div>'); }).catch(function () { toast(e.message); });
      });
    }
    el.addEventListener('click', function (ev) {
      var f = ev.target.closest('[data-f]'); if (f) { S.f = f.getAttribute('data-f'); load(); return; }
      var a = ev.target.closest('[data-a]');
      if (a && a.getAttribute('data-a') === 'patrol') { a.disabled = true; req(api, 'POST', '/duty/patrol', { engineer: eng }).then(function (r) { toast('Patrol done: ' + (r.opened || 0) + ' new, ' + (r.reopened || 0) + ' back, ' + (r.cleared || 0) + ' resolved'); load(); }).catch(function (e) { toast(e.message); }).then(function () { a.disabled = false; }); return; }
      if (a && a.getAttribute('data-a') === 'report') { report(); return; }
      if (a && a.getAttribute('data-a') === 'kpi') { kpiPanel(); return; }
      if (a && a.getAttribute('data-a') === 'charter') { charter(eng); return; }
      var row = ev.target.closest('tr.zdt-r'); if (row) detail(row.getAttribute('data-id'));
    });
    // a link from My Work (page.html#item=<id>) opens that work item straight away
    var hm = /[#&]item=([A-Za-z0-9_.:-]{1,80})/.exec(location.hash || ''); if (hm) setTimeout(function () { detail(hm[1]); el.scrollIntoView({ block: 'start' }); }, 300);
    load(); setInterval(function () { var zd = document.getElementById('zd'); if (!document.hidden && (!zd || zd.hidden)) load(); }, 60000);   // not while a work item is open
  }

  function start() {
    var els = document.querySelectorAll('[data-zyb-duty]'); if (!els.length) return;
    var st = document.createElement('style'); st.textContent = CSS; document.head.appendChild(st);
    var w = new XMLHttpRequest(); w.open('GET', '/dashboards/whoami.json');
    var go = function () { [].forEach.call(els, mount); };
    w.onload = function () { try { var j = JSON.parse(w.responseText), r = String(j.role || '').toLowerCase(); if (RANK[r] != null) ROLE = r; WHO = j.user || j.name || ''; } catch (e) { /* viewer */ } go(); };
    w.onerror = go; w.send();
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start); else start();
})();
