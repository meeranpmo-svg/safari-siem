// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
/* zyb-teamhome.js - the AI Engineering Team overview (ai-team.html, Overview tab): one screen that says how the AI team is doing.
 *   readiness gauge   share of the engineers on duty, connected to their source and patrolling on time
 *   tiles             engineers on duty, open work, critical / high, waiting for a person, fixed in 24 h, AI calls used today
 *   what we noticed   plain-language notes worked out from the live figures (busiest desk, late patrols, sources not
 *                     connected, approvals waiting, work that keeps coming back) - indicators, the desk has the evidence
 *   team by function  every engineer as a tile under its function (security operations, network, servers and cloud, identity,
 *                     email, GRC and compliance, audit), with filters and a search; a tile opens the engineer's desk
 *   charts            open work by engineer and stage, the work pipeline, workload by function, patrol state, service score
 * Everything comes from the duty engines' own answers (GET {side}/duty/engineers, /duty/items, /duty/kpis); nothing is invented
 * here. Text from the engines is escaped before it reaches the page.
 *   zybTeamHome.draw(el, { crew, items, kpis, down, meta, open(engineerId) })
 */
(function () {
  'use strict';
  var esc = function (s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); };
  // the function each engineer belongs to; an engineer not listed here goes under "Operations"
  var FUNCS = [
    ['soc', 'Security operations', 'shield-lock', 'red', ['security', 'ndr', 'siem', 'cutover', 'pentest', 'fortigate', 'ksc', 'zscaler']],
    ['net', 'Network', 'network', 'azure', ['network', 'nac', 'hvnet', 'voice']],
    ['srv', 'Servers, cloud & capacity', 'server-2', 'blue', ['windows', 'hyperv', 'virt', 'capacity', 'azure', 'apps', 'sqldba', 'dba', 'desktop', 'register']],
    ['idn', 'Identity & access', 'key', 'orange', ['nhi', 'pamofficer', 'pki']],
    ['mail', 'Email & collaboration', 'mail', 'yellow', ['mimecast', 'mailflow', 'exchange']],
    ['grc', 'GRC, compliance & risk', 'scale', 'green', ['grc', 'pdpl', 'ndmo', 'nca-ecc', 'iso27001', 'aramco', 'riskofficer', 'compliance']],
    ['aud', 'Audit', 'file-search', 'teal', ['itaudit', 'cyberaudit', 'ia', 'csa', 'iad']],
    ['ops', 'Operations', 'robot', 'purple', []]];
  var FN = {}; FUNCS.forEach(function (f) { f[4].forEach(function (id) { FN[id] = f[0]; }); });
  var fnOf = function (id) { return FN[id] || 'ops'; };
  var STAGES = [['open', 'New', 'acc'], ['investigating', 'Investigating', 'teal'], ['diagnosed', 'Diagnosed', 'indigo'], ['needs-human', 'Needs a person', 'crit'],
    ['awaiting-approval', 'Waiting for approval', 'purple'], ['approved', 'Approved - to apply', 'pink'], ['fix-applied', 'Verifying the fix', 'ok'], ['snoozed', 'Snoozed', 'mute']];
  var SEVN = { critical: 4, high: 3, medium: 2, low: 1 };
  function ago(t) { if (!t) return 'never'; var s = Math.max(0, (Date.now() - t) / 1000); return s < 90 ? Math.round(s) + ' s ago' : s < 5400 ? Math.round(s / 60) + ' min ago' : s < 172800 ? Math.round(s / 3600) + ' h ago' : Math.round(s / 86400) + ' d ago'; }
  function stateOf(e) { return !e.on_duty ? 'off' : e.not_connected ? 'nc' : (e.late || e.last_error) ? 'late' : 'ok'; }
  var STN = { ok: ['Patrolling on time', 'green'], late: ['Late or failed patrol', 'yellow'], nc: ['Source not connected', 'orange'], off: ['Off duty', 'secondary'] };
  // when a work item was first seen, whatever the engine calls it
  function since(x) { var t = x.first_seen || x.created_at || x.opened_at || x.at; if (typeof t === 'string') t = Date.parse(t); if (!t && x.age_h != null) t = Date.now() - x.age_h * 3600000; return t || 0; }
  function css() {
    if (document.getElementById('zth-css')) return;
    var s = document.createElement('style'); s.id = 'zth-css';
    s.textContent = '.zth-tiles{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px;height:100%}@media(max-width:575px){.zth-tiles{grid-template-columns:repeat(2,minmax(0,1fr))}}'
      + '.zth-tile{border:1px solid var(--tblr-border-color);border-radius:10px;padding:12px 14px;background:var(--tblr-bg-surface)}.zth-tile .v{font-size:26px;font-weight:700;line-height:1.1}.zth-tile .l{font-size:12px;color:var(--tblr-secondary)}.zth-tile .s{font-size:11px;color:var(--tblr-secondary);margin-top:2px}'
      + '.zth-gauge{display:flex;align-items:center;gap:16px}.zth-gauge svg{flex:none}'
      + '.zth-ins li{margin-bottom:8px;line-height:1.4}.zth-ins i{margin-right:6px}'
      + '.zth-fn{margin-bottom:18px}.zth-fn h4{display:flex;align-items:center;gap:8px;font-size:14px;margin:0 0 8px}.zth-fn h4 .c{font-weight:400;color:var(--tblr-secondary);font-size:12px}'
      + '.zth-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(230px,1fr));gap:10px}'
      + '.zth-eng{display:flex;gap:10px;align-items:flex-start;border:1px solid var(--tblr-border-color);border-left:3px solid var(--zc,#5794f2);border-radius:8px;padding:10px;background:var(--tblr-bg-surface);cursor:pointer;text-align:left;width:100%;color:inherit}'
      + '.zth-eng:hover,.zth-eng:focus-visible{border-color:var(--tblr-primary);outline:none;box-shadow:0 0 0 2px rgba(87,148,242,.25)}'
      + '.zth-eng .n{font-weight:600;font-size:13px;line-height:1.25;overflow-wrap:anywhere}.zth-eng .m{font-size:11px;color:var(--tblr-secondary);margin-top:2px}'
      + '.zth-eng .b{display:flex;gap:4px;flex-wrap:wrap;margin-top:6px}.zth-eng .b span{font-size:11px;padding:1px 6px;border-radius:9px;background:rgba(127,127,127,.15)}'
      + '.zth-eng .b .cr{background:rgba(242,73,92,.2);color:#ff8a96}.zth-eng .b .ap{background:rgba(184,119,217,.2);color:#d6a6ef}.zth-eng .b .fx{background:rgba(115,191,105,.18);color:#9fdc96}'
      + '.zth-bar{display:flex;height:5px;border-radius:3px;overflow:hidden;margin-top:7px;background:rgba(127,127,127,.15)}.zth-bar i{display:block;height:100%}'
      + '.zth-ch{position:relative;height:280px}.zth-ch.tall{height:380px}'
      + '.zth-filters{display:flex;flex-wrap:wrap;gap:6px;align-items:center}.zth-filters .btn{padding:3px 10px;font-size:12px}.zth-filters .btn.on{background:var(--tblr-primary);color:#fff;border-color:var(--tblr-primary)}';
    document.head.appendChild(s);
  }
  function gauge(v) {
    var R = 46, L = 2 * Math.PI * R, col = v == null ? '#4a5162' : v >= 85 ? '#2fd47a' : v >= 60 ? '#e3b341' : '#ff7b72', f = v == null ? 0 : Math.max(0, Math.min(100, v)) / 100;
    return '<svg width="116" height="116" viewBox="0 0 116 116" role="img" aria-label="Team readiness ' + (v == null ? 'not known' : v + ' percent') + '"><circle cx="58" cy="58" r="' + R + '" fill="none" stroke="rgba(127,127,127,.2)" stroke-width="11"/>'
      + '<circle cx="58" cy="58" r="' + R + '" fill="none" stroke="' + col + '" stroke-width="11" stroke-linecap="round" stroke-dasharray="' + (L * f).toFixed(1) + ' ' + L.toFixed(1) + '" transform="rotate(-90 58 58)"/>'
      + '<text x="58" y="56" text-anchor="middle" font-size="26" font-weight="700" fill="currentColor">' + (v == null ? '—' : v) + '</text><text x="58" y="76" text-anchor="middle" font-size="11" fill="#8e8e8e">' + (v == null ? '' : '% ready') + '</text></svg>';
  }
  var C = function () { return window.zybCharts; };

  function analyse(o) {
    var crew = o.crew || [], items = o.items || [], K = {};
    K.total = crew.length;
    K.on = crew.filter(function (e) { return e.on_duty; }).length;
    K.byState = { ok: 0, late: 0, nc: 0, off: 0 }; crew.forEach(function (e) { K.byState[stateOf(e)]++; });
    K.ready = K.total ? Math.round(100 * K.byState.ok / K.total) : null;
    K.open = crew.reduce(function (a, e) { return a + (e.open || 0); }, 0);
    K.crit = crew.reduce(function (a, e) { return a + (e.critical || 0); }, 0);
    K.high = crew.reduce(function (a, e) { return a + (e.high || 0); }, 0);
    K.appr = crew.reduce(function (a, e) { var b = e.by_status || {}; return a + (b['awaiting-approval'] || 0) + (b.approved || 0) + (b['needs-human'] || 0); }, 0);
    K.fixed = crew.reduce(function (a, e) { return a + (e.resolved_24h || 0); }, 0);
    var ai = crew.filter(function (e) { return e.ai && e.ai.enabled; });
    K.aiUsed = ai.reduce(function (a, e) { return a + (Number(e.ai.used_today) || 0); }, 0); K.aiCap = ai.reduce(function (a, e) { return a + (Number(e.ai.cap) || 0); }, 0); K.aiOn = ai.length;
    K.stage = {}; STAGES.forEach(function (s) { K.stage[s[0]] = 0; }); crew.forEach(function (e) { var b = e.by_status || {}; Object.keys(b).forEach(function (k) { if (k in K.stage) K.stage[k] += b[k] || 0; }); });
    K.byFn = {}; FUNCS.forEach(function (f) { K.byFn[f[0]] = { n: 0, open: 0, crit: 0 }; }); crew.forEach(function (e) { var f = K.byFn[fnOf(e.id)]; f.n++; f.open += e.open || 0; f.crit += e.critical || 0; });
    // what we noticed: each note is a figure from the engines put in words, the busiest first
    var N = [], busy = crew.filter(function (e) { return e.open; }).sort(function (a, b) { return (b.critical || 0) - (a.critical || 0) || (b.open || 0) - (a.open || 0); });
    if (!K.total) N.push(['info-circle', 'secondary', 'No AI engineer has reported yet: the duty engines are not answering or not installed - see the notes above the team.']);
    if (K.crit) { var cr = crew.filter(function (e) { return e.critical; }).map(function (e) { return e.short + ' (' + e.critical + ')'; }); N.push(['alert-octagon', 'red', K.crit + ' critical item(s) open - ' + cr.slice(0, 4).join(', ') + (cr.length > 4 ? ' and ' + (cr.length - 4) + ' more' : '') + '. Start there.']); }
    if (K.appr) { var w = items.filter(function (x) { return x.status === 'awaiting-approval'; }).sort(function (a, b) { return since(a) - since(b); })[0];
      N.push(['user-check', 'purple', K.appr + ' item(s) wait for a person (approval, an approved fix to apply, or a decision)' + (w && since(w) ? ' - the oldest approval has waited ' + ago(since(w)).replace(' ago', '') : '') + '. Nothing changes on a system until a named person decides.']); }
    if (busy.length && busy[0].open >= 3) { var tot = K.open || 1; N.push(['flame', 'orange', busy[0].short + ' carries the most open work: ' + busy[0].open + ' item(s), ' + Math.round(100 * busy[0].open / tot) + '% of the team\'s.']); }
    if (K.byState.late) N.push(['clock-exclamation', 'yellow', K.byState.late + ' engineer(s) patrolled late or hit a problem on the last patrol: ' + crew.filter(function (e) { return stateOf(e) === 'late'; }).map(function (e) { return e.short; }).slice(0, 4).join(', ') + '. Their view may be out of date.']);
    if (K.byState.nc) N.push(['plug-connected-x', 'orange', K.byState.nc + ' engineer(s) are on duty but their source is not connected yet: ' + crew.filter(function (e) { return stateOf(e) === 'nc'; }).map(function (e) { return e.short; }).slice(0, 4).join(', ') + '. Connect it on Connections & Setup.']);
    if (K.byState.off) N.push(['moon', 'secondary', K.byState.off + ' engineer(s) off duty - they do not patrol until switched on.']);
    var fl = Object.keys(K.byFn).map(function (k) { return [k, K.byFn[k]]; }).filter(function (x) { return x[1].open; }).sort(function (a, b) { return b[1].open - a[1].open; })[0];
    if (fl && K.open) { var fd = FUNCS.filter(function (f) { return f[0] === fl[0]; })[0]; N.push(['chart-pie', 'azure', fd[1] + ' holds ' + Math.round(100 * fl[1].open / K.open) + '% of the open work (' + fl[1].open + ' of ' + K.open + ').']); }
    if (K.fixed) N.push(['circle-check', 'green', K.fixed + ' item(s) fixed and verified in the last 24 h.']);
    if (K.aiCap && K.aiUsed / K.aiCap >= 0.8) N.push(['sparkles', 'yellow', 'AI use today is at ' + Math.round(100 * K.aiUsed / K.aiCap) + '% of the daily budget (' + K.aiUsed + ' of ' + K.aiCap + '): engineers fall back to their rules when it runs out.']);
    if (K.total && !K.crit && !K.appr && !K.byState.late && !K.byState.nc) N.push(['mood-smile', 'green', 'Every engineer on duty is patrolling on time and nothing waits for a person.']);
    K.notes = N; return K;
  }

  function engTile(e, meta) {
    var m = meta[e.id] || ['robot', '#', 'purple'], st = STN[stateOf(e)], b = e.by_status || {}, appr = (b['awaiting-approval'] || 0) + (b.approved || 0) + (b['needs-human'] || 0);
    var tot = STAGES.reduce(function (a, s) { return a + (b[s[0]] || 0); }, 0);
    var bar = tot ? '<div class="zth-bar" aria-hidden="true">' + STAGES.filter(function (s) { return b[s[0]]; }).map(function (s) { return '<i style="width:' + (100 * b[s[0]] / tot).toFixed(1) + '%;background:' + C().color(s[2]) + '" title="' + esc(s[1] + ': ' + b[s[0]]) + '"></i>'; }).join('') + '</div>' : '';
    var col = { red: '#f2495c', azure: '#45aaf2', blue: '#5794f2', orange: '#ff9830', yellow: '#fade2a', green: '#73bf69', teal: '#2bc8b9', purple: '#b877d9', pink: '#e86bbf', cyan: '#3fc1d3', indigo: '#8f8ff5', lime: '#a6d96a' }[m[2]] || '#5794f2';
    return '<button type="button" class="zth-eng" style="--zc:' + col + '" data-zth-open="' + esc(e.id) + '" title="Open the ' + esc(e.name) + ' desk">'
      + '<span class="avatar avatar-sm bg-' + esc(m[2]) + '-lt"><i class="ti ti-' + esc(m[0]) + '"></i></span><span style="min-width:0;flex:1">'
      + '<div class="n">' + esc(e.short) + '</div><div class="m"><span class="status-dot status-' + st[1] + (st[1] === 'green' ? ' status-dot-animated' : '') + ' me-1"></span>' + esc(st[0]) + (e.on_duty && e.last_patrol ? ' · ' + esc(ago(e.last_patrol)) : '') + '</div>'
      + '<div class="b"><span>' + esc(e.open || 0) + ' open</span>' + (e.critical ? '<span class="cr">' + esc(e.critical) + ' critical</span>' : '') + (appr ? '<span class="ap">' + esc(appr) + ' for a person</span>' : '') + (e.resolved_24h ? '<span class="fx">' + esc(e.resolved_24h) + ' fixed 24 h</span>' : '')
      + (e.ai ? '<span title="AI calls today">' + (e.ai.enabled ? '✦ ' + esc(e.ai.used_today || 0) + '/' + esc(e.ai.cap || 0) : 'rules only') + '</span>' : '') + '</div>' + bar + '</span></button>';
  }

  function draw(el, o) {
    css(); o = o || {}; var meta = o.meta || {};
    var crew = (o.crew || []).map(function (e) { return Object.assign({}, e, { short: String(e.short || e.name || e.id).replace(/^AI\s+/, '') }); });
    var items = o.items || [], K = analyse({ crew: crew, items: items });
    var st = el.__zth || (el.__zth = { fn: '', q: '', only: '' });
    var tile = function (v, l, s, cls) { return '<div class="zth-tile"><div class="v' + (cls ? ' ' + cls : '') + '">' + esc(v) + '</div><div class="l">' + esc(l) + '</div>' + (s ? '<div class="s">' + esc(s) + '</div>' : '') + '</div>'; };
    var down = (o.down || []).length ? '<div class="alert alert-warning py-2 small mb-3"><i class="ti ti-alert-triangle me-1"></i>' + o.down.map(esc).join(' · ') + '</div>' : '';
    var needRows = items.filter(function (x) { return x.status === 'awaiting-approval' || x.status === 'approved' || x.status === 'needs-human'; })
      .sort(function (a, b) { return (SEVN[b.severity] || 0) - (SEVN[a.severity] || 0) || since(a) - since(b); });
    el.innerHTML = down
      + '<div class="row g-3 mb-3"><div class="col-xl-3 col-md-5"><div class="card h-100"><div class="card-body zth-gauge">' + gauge(K.ready) + '<div><div class="fw-semibold">Team readiness</div><div class="small text-secondary">' + K.byState.ok + ' of ' + K.total + ' engineers on duty, connected and patrolling on time</div>'
      + '<div class="small mt-2">' + ['ok', 'late', 'nc', 'off'].filter(function (k) { return K.byState[k]; }).map(function (k) { return '<span class="me-2 d-inline-block"><span class="status-dot status-' + STN[k][1] + ' me-1"></span>' + K.byState[k] + ' ' + esc(STN[k][0].toLowerCase()) + '</span>'; }).join('') + '</div></div></div></div></div>'
      + '<div class="col-xl-9 col-md-7"><div class="zth-tiles" id="zth-kp">'
      + tile(K.on + ' / ' + K.total, 'Engineers on duty', K.byState.nc ? K.byState.nc + ' waiting for a source' : 'across both engines')
      + tile(K.open, 'Open work', K.stage.investigating + ' being investigated')
      + tile(K.crit, 'Critical', K.high + ' high', K.crit ? 'text-red' : '')
      + tile(K.appr, 'Waiting for a person', 'approve, apply or decide', K.appr ? 'text-purple' : '')
      + tile(K.fixed, 'Fixed in 24 h', 'verified after the change', K.fixed ? 'text-green' : '')
      + tile(K.aiCap ? K.aiUsed + ' / ' + K.aiCap : '—', 'AI calls today', K.aiOn + ' engineer(s) with AI on') + '</div></div></div>'
      + '<div class="row g-3 mb-3"><div class="col-lg-7"><div class="card h-100"><div class="card-header"><h3 class="card-title"><i class="ti ti-sparkles me-2 text-purple"></i>What the team noticed</h3><span class="card-actions small text-secondary">worked out from the live figures</span></div><div class="card-body"><ul class="list-unstyled mb-0 zth-ins" id="zth-ins">'
      + K.notes.map(function (n) { return '<li><i class="ti ti-' + n[0] + ' text-' + n[1] + '"></i>' + esc(n[2]) + '</li>'; }).join('') + '</ul></div></div></div>'
      + '<div class="col-lg-5"><div class="card h-100"><div class="card-header"><h3 class="card-title"><i class="ti ti-user-check me-2 text-purple"></i>For a person now</h3><span class="card-actions small text-secondary">' + needRows.length + ' item(s)</span></div><div class="list-group list-group-flush" id="zth-need">'
      + (needRows.length ? needRows.slice(0, 6).map(function (x) { var t = since(x); return '<a href="#" class="list-group-item list-group-item-action py-2 rowc" data-id="' + esc(x.id) + '" data-eng="' + esc(x.engineer) + '" data-api="' + esc(x.api || '') + '"><div class="d-flex gap-2 align-items-center"><span class="badge flex-shrink-0 bg-' + ({ critical: 'red', high: 'orange', medium: 'yellow', low: 'secondary' }[x.severity] || 'secondary') + '-lt">' + esc(x.severity || '-') + '</span><span class="text-truncate fw-semibold">' + esc(x.title || x.target || x.kind || x.id) + '</span></div><div class="small text-secondary">' + esc(String(x.engineer_name || x.engineer || '').replace(/^AI\s+/, '')) + ' · ' + esc(({ 'awaiting-approval': 'waiting for approval', approved: 'approved - apply it', 'needs-human': 'needs a person' })[x.status] || x.status) + (t ? ' · ' + esc(ago(t)) : '') + '</div></a>'; }).join('')
        : '<div class="list-group-item text-secondary"><i class="ti ti-circle-check text-green me-1"></i>Nothing waits for a person right now.</div>') + '</div></div></div></div>'
      + '<div class="card mb-3"><div class="card-header flex-wrap gap-2"><h3 class="card-title"><i class="ti ti-users-group me-2"></i>The team by function</h3><div class="card-actions zth-filters" id="zth-f">'
      + '<button type="button" class="btn' + (st.fn ? '' : ' on') + '" data-zth-fn="">All ' + K.total + '</button>' + FUNCS.filter(function (f) { return K.byFn[f[0]].n; }).map(function (f) { return '<button type="button" class="btn' + (st.fn === f[0] ? ' on' : '') + '" data-zth-fn="' + f[0] + '"><i class="ti ti-' + f[2] + ' me-1"></i>' + esc(f[1]) + ' ' + K.byFn[f[0]].n + '</button>'; }).join('')
      + '<select class="form-select form-select-sm" style="width:auto" id="zth-only" aria-label="Show"><option value="">Everyone</option><option value="work"' + (st.only === 'work' ? ' selected' : '') + '>With open work</option><option value="person"' + (st.only === 'person' ? ' selected' : '') + '>Waiting for a person</option><option value="attn"' + (st.only === 'attn' ? ' selected' : '') + '>Late, not connected or off</option></select>'
      + '<input class="form-control form-control-sm" style="width:170px" id="zth-q" placeholder="Find an engineer" aria-label="Find an engineer" value="' + esc(st.q) + '"></div></div><div class="card-body" id="zth-team"></div></div>'
      + '<div class="row g-3 mb-3"><div class="col-xl-7"><div class="card h-100"><div class="card-header"><h3 class="card-title">Open work by engineer and stage</h3><span class="card-actions small text-secondary">click a bar to open the desk</span></div><div class="card-body"><div class="zth-ch tall"><canvas id="zth-c1"></canvas></div></div></div></div>'
      + '<div class="col-xl-5"><div class="card h-100"><div class="card-header"><h3 class="card-title">Work pipeline</h3><span class="card-actions small text-secondary">where the open work is in the agent loop</span></div><div class="card-body"><div class="zth-ch tall"><canvas id="zth-c2"></canvas></div></div></div></div></div>'
      + '<div class="row g-3 mb-3"><div class="col-lg-4"><div class="card h-100"><div class="card-header"><h3 class="card-title">Open work by function</h3></div><div class="card-body"><div class="zth-ch"><canvas id="zth-c3"></canvas></div></div></div></div>'
      + '<div class="col-lg-4"><div class="card h-100"><div class="card-header"><h3 class="card-title">Patrol state</h3></div><div class="card-body"><div class="zth-ch"><canvas id="zth-c4"></canvas></div></div></div></div>'
      + '<div class="col-lg-4"><div class="card h-100"><div class="card-header"><h3 class="card-title">Service score (30 days)</h3></div><div class="card-body"><div class="zth-ch"><canvas id="zth-c5"></canvas></div></div></div></div></div>';

    function team() {
      var q = st.q.toLowerCase(), list = crew.filter(function (e) {
        if (st.fn && fnOf(e.id) !== st.fn) return false; if (q && String(e.name + ' ' + e.id).toLowerCase().indexOf(q) < 0) return false;
        var b = e.by_status || {}, s = stateOf(e);
        if (st.only === 'work' && !e.open) return false; if (st.only === 'person' && !((b['awaiting-approval'] || 0) + (b.approved || 0) + (b['needs-human'] || 0))) return false; if (st.only === 'attn' && s === 'ok') return false;
        return true; });
      var html = FUNCS.map(function (f) { var L = list.filter(function (e) { return fnOf(e.id) === f[0]; }).sort(function (a, b) { return (b.critical || 0) - (a.critical || 0) || (b.open || 0) - (a.open || 0) || String(a.short).localeCompare(String(b.short)); }); if (!L.length) return '';
        var F = K.byFn[f[0]]; return '<div class="zth-fn"><h4><i class="ti ti-' + f[2] + ' text-' + f[3] + '"></i>' + esc(f[1]) + ' <span class="c">' + F.n + ' engineer(s) · ' + F.open + ' open' + (F.crit ? ' · ' + F.crit + ' critical' : '') + '</span></h4><div class="zth-grid">' + L.map(function (e) { return engTile(e, meta); }).join('') + '</div></div>'; }).join('');
      el.querySelector('#zth-team').innerHTML = html || '<div class="text-secondary">' + (crew.length ? 'No engineer matches.' : 'No engineer has reported yet.') + '</div>';
    }
    team();
    el.querySelector('#zth-f').addEventListener('click', function (ev) { var b = ev.target.closest('[data-zth-fn]'); if (!b) return; st.fn = b.getAttribute('data-zth-fn'); [].forEach.call(el.querySelectorAll('[data-zth-fn]'), function (x) { x.classList.toggle('on', x === b); }); team(); });
    el.querySelector('#zth-q').addEventListener('input', function () { st.q = this.value; team(); });
    el.querySelector('#zth-only').addEventListener('change', function () { st.only = this.value; team(); });
    // a tile opens the engineer's desk; a work item (class rowc) is opened by the page's own handler, which shows its investigation
    if (!el.__zthClick) { el.__zthClick = true; el.addEventListener('click', function (ev) { var t = ev.target.closest('[data-zth-open]'); if (t && el.__zthOpen) el.__zthOpen(t.getAttribute('data-zth-open')); if (ev.target.closest('a.rowc')) ev.preventDefault(); }); }
    el.__zthOpen = o.open;

    var Ch = C(); if (!Ch) return K;
    var busy = crew.filter(function (e) { return e.open; }).sort(function (a, b) { return (b.open || 0) - (a.open || 0); }).slice(0, 14);
    var c1 = el.querySelector('#zth-c1'), c2 = el.querySelector('#zth-c2'), c3 = el.querySelector('#zth-c3'), c4 = el.querySelector('#zth-c4'), c5 = el.querySelector('#zth-c5');
    if (busy.length) Ch.bars(c1, busy.map(function (e) { return e.short.length > 34 ? e.short.slice(0, 33) + '…' : e.short; }), STAGES.map(function (s) { return { label: s[1], data: busy.map(function (e) { return (e.by_status || {})[s[0]] || 0; }), color: s[2] }; }).filter(function (s) { return s.data.some(Boolean); }),
      { stacked: true, horizontal: true, title: 'Open work by engineer and stage', onClick: function (i) { if (o.open) o.open(busy[i].id); } });
    else Ch.empty(c1, 'No open work on any desk.');
    if (K.open) Ch.bars(c2, STAGES.map(function (s) { return s[1]; }), [{ label: 'Items', data: STAGES.map(function (s) { return K.stage[s[0]]; }), colors: STAGES.map(function (s) { return s[2]; }) }], { horizontal: true, title: 'Work pipeline' });
    else Ch.empty(c2, 'Nothing in the pipeline.');
    var fns = FUNCS.filter(function (f) { return K.byFn[f[0]].open; });
    if (fns.length) Ch.ring(c3, fns.map(function (f) { return f[1]; }), fns.map(function (f) { return K.byFn[f[0]].open; }), fns.map(function (f) { return { red: 'crit', azure: 'acc', blue: 'indigo', orange: 'warn', yellow: 'yellow', green: 'ok', teal: 'teal', purple: 'purple' }[f[3]]; }), { v: K.open, l: 'open' }, { title: 'Open work by function' });
    else Ch.empty(c3, 'No open work.');
    if (K.total) Ch.ring(c4, ['On time', 'Late / failed', 'Not connected', 'Off duty'], [K.byState.ok, K.byState.late, K.byState.nc, K.byState.off], ['ok', 'yellow', 'warn', 'mute'], { v: K.total, l: 'engineers' }, { title: 'Patrol state' });
    else Ch.empty(c4, 'No engineer has reported yet.');
    var sc = (o.kpis || []).filter(function (k) { return k.score != null; }).sort(function (a, b) { return a.score - b.score; }).slice(0, 10);
    if (sc.length) Ch.bars(c5, sc.map(function (k) { var n = String(k.name || k.engineer).replace(/^AI\s+/, ''); return n.length > 26 ? n.slice(0, 25) + '…' : n; }), [{ label: 'Score', data: sc.map(function (k) { return k.score; }), colors: sc.map(function (k) { return k.score >= 85 ? 'ok' : k.score >= 60 ? 'yellow' : 'crit'; }) }], { horizontal: true, title: 'Service score, lowest first' });
    else Ch.empty(c5, 'No service score yet - it appears after the engines have measured 30 days of work.');
    return K;
  }
  window.zybTeamHome = { draw: draw, analyse: analyse, fnOf: fnOf, FUNCS: FUNCS };
})();
