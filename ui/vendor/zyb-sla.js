// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
/* zyb-sla.js - CISO view: SIEM health (engine, log database, collectors, log sources, server hardware via sysinfo.json)
 * and "SIEM tickets & SLA": tickets (cases) opened from SIEM alerts, how fast they are acknowledged and
 * resolved, and every SLA violation. Live data from the SIEM API (same login as the portal):
 *   GET /api/soc/metrics?from&to   totals, MTTA / MTTR, SLA compliance, breaching_now, at_risk
 *   GET /api/soc/cases?status=all  the tickets themselves (sla_state per ticket)
 *   GET /api/soc/health, /api/soc/sources, /dashboards/sysinfo.json   SIEM, collector, log source and hardware status
 * window.zybSLA.render(el, {mode:'full'|'compact'}). On the portal it also adds the compact panel to the CISO
 * (Executive Security) dashboard. SLA policy per severity is the SIEM's (engine/soc/cases.js, config "sla"). */
(function () {
  'use strict';
  if (window.zybSLA) return;
  var API = '/api/soc';
  var SEV = { 4: 'Critical', 3: 'High', 2: 'Medium', 1: 'Low', 0: 'Low' }, SEVC = { 4: '#f85149', 3: '#ff9830', 2: '#e3b341', 1: '#58a6ff', 0: '#58a6ff' };
  var DEF = { 4: [1, 24], 3: [4, 72], 2: [24, 168], 1: [72, 720], 0: [72, 720] };
  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); }
  function dur(ms) {
    if (ms == null || !isFinite(ms)) return '–'; var neg = ms < 0; ms = Math.abs(ms);
    var m = Math.round(ms / 60000), d = Math.floor(m / 1440), h = Math.floor(m % 1440 / 60), mm = m % 60;
    return (neg ? '-' : '') + (d ? d + ' d ' + h + ' h' : h ? h + ' h ' + mm + ' m' : mm + ' m');
  }
  function dt(ms) { if (!ms) return '–'; var d = new Date(ms); return d.toLocaleDateString([], { day: '2-digit', month: 'short' }) + ' ' + d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }); }
  function sevName(s) { return SEV[s >= 4 ? 4 : s] || 'Low'; }
  function sevPill(s) { var k = s >= 4 ? 4 : s; return '<span class="zs-sev" style="--c:' + SEVC[k] + '">' + sevName(s) + '</span>'; }
  function getJSON(url) {
    return new Promise(function (ok, bad) {
      var x = new XMLHttpRequest(); x.open('GET', url); x.withCredentials = true; x.timeout = 15000;
      x.onload = function () { if (x.status !== 200) return bad(new Error(x.status === 401 ? 'sign-in required' : x.status === 403 ? 'your role cannot read SIEM cases' : 'SIEM API error ' + x.status)); try { ok(JSON.parse(x.responseText)); } catch (e) { bad(new Error('the SIEM API did not answer with data')); } };
      x.onerror = x.ontimeout = function () { bad(new Error('the SIEM API is not reachable')); };
      x.send();
    });
  }

  var CSS = '.zs{font-family:system-ui,-apple-system,"Segoe UI",sans-serif;color:inherit}.zs *{box-sizing:border-box}'
    + '.zs-ban{display:flex;gap:12px;align-items:flex-start;border-radius:10px;padding:12px 14px;margin:0 0 12px;border:1px solid}.zs-ban b{display:block;font-size:14px}.zs-ban span{font-size:12.5px;opacity:.85}'
    + '.zs-ban.bad{background:rgba(248,81,73,.12);border-color:rgba(248,81,73,.55)}.zs-ban.bad b{color:#ff7b72}.zs-ban.warn{background:rgba(227,179,65,.10);border-color:rgba(227,179,65,.5)}.zs-ban.warn b{color:#e3b341}.zs-ban.ok{background:rgba(63,185,80,.10);border-color:rgba(63,185,80,.45)}.zs-ban.ok b{color:#56d364}'
    + '.zs-ban .zs-i{font-size:20px;line-height:1}.zs-ban.bad .zs-i{animation:zsP 1.6s ease-in-out infinite}@keyframes zsP{50%{opacity:.35}}@media (prefers-reduced-motion:reduce){.zs-ban.bad .zs-i{animation:none}}'
    + '.zs-k{display:grid;grid-template-columns:repeat(auto-fit,minmax(128px,1fr));gap:10px;margin:0 0 12px}'
    + '.zs-t{border:1px solid rgba(255,255,255,.09);border-radius:10px;padding:11px 12px;background:rgba(255,255,255,.03);min-width:0;cursor:pointer;text-align:left;color:inherit;font:inherit}.zs-t:hover,.zs-t:focus-visible{border-color:rgba(255,255,255,.3);outline:none}'
    + '.zs-t .l{font-size:11px;text-transform:uppercase;letter-spacing:.06em;opacity:.65}.zs-t .v{font-size:24px;font-weight:700;margin:3px 0 2px;font-variant-numeric:tabular-nums}.zs-t .s{font-size:11.5px;opacity:.7}'
    + '.zs-t.bad .v{color:#ff7b72}.zs-t.warn .v{color:#e3b341}.zs-t.ok .v{color:#56d364}'
    + '.zs-g{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}.zs-g .wide{grid-column:1/-1}@media (max-width:900px){.zs-g{grid-template-columns:minmax(0,1fr)}}'
    + '.zs-p{border:1px solid rgba(255,255,255,.09);border-radius:10px;padding:12px;background:rgba(255,255,255,.02);min-width:0}.zs-p h3{margin:0 0 8px;font-size:13.5px;font-weight:600}.zs-p h3 small{font-weight:400;opacity:.6;margin-left:6px}'
    + '.zs-tw{overflow-x:auto}.zs table{width:100%;border-collapse:collapse;font-size:12.5px}.zs th{text-align:left;font-weight:500;opacity:.65;padding:6px 8px;border-bottom:1px solid rgba(255,255,255,.1);white-space:nowrap}'
    + '.zs td{padding:6px 8px;border-bottom:1px solid rgba(255,255,255,.06);vertical-align:top}.zs td.n,.zs th.n{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}.zs tbody tr[data-case]{cursor:pointer}.zs tbody tr[data-case]:hover td{background:rgba(255,255,255,.04)}'
    + '.zs-sev{display:inline-block;font-size:11px;font-weight:700;padding:1px 7px;border-radius:9px;color:var(--c);background:color-mix(in srgb,var(--c) 18%,transparent);white-space:nowrap}'
    + '.zs-pl{display:inline-block;font-size:11px;font-weight:600;padding:1px 7px;border-radius:9px;white-space:nowrap}.zs-pl.bad{background:rgba(248,81,73,.18);color:#ff7b72}.zs-pl.warn{background:rgba(227,179,65,.16);color:#e3b341}.zs-pl.ok{background:rgba(63,185,80,.16);color:#56d364}.zs-pl.mute{background:rgba(255,255,255,.08);opacity:.8}'
    + '.zs-ch{display:flex;align-items:flex-end;gap:3px;height:90px}.zs-ch div{flex:1;display:flex;flex-direction:column;justify-content:flex-end;gap:1px;min-width:3px;height:100%}.zs-ch i{display:block;border-radius:2px 2px 0 0}.zs-ax{display:flex;justify-content:space-between;font-size:10.5px;opacity:.55;margin-top:3px}'
    + '.zs-lg{display:flex;gap:12px;font-size:11.5px;opacity:.75;margin-top:6px}.zs-lg i{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:5px;vertical-align:-1px}'
    + '.zs-m{font-size:12.5px;opacity:.75;padding:6px 0}.zs-more{display:inline-block;margin-top:10px;font-size:12.5px;color:#58a6ff;text-decoration:none}.zs-more:hover{text-decoration:underline}'
    + '.zs-hd{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin:0 0 10px}.zs-hd h2{margin:0;font-size:15px}.zs-hd .sp{flex:1}.zs-hd span{font-size:12px;opacity:.6}'
    + '.zs-seg{display:inline-flex;border:1px solid rgba(255,255,255,.15);border-radius:7px;overflow:hidden}.zs-seg button{background:none;border:0;color:inherit;font:600 12px system-ui,sans-serif;padding:5px 10px;cursor:pointer;opacity:.7}.zs-seg button[aria-pressed="true"]{background:rgba(255,255,255,.12);opacity:1}';
  function css() { if (document.getElementById('zs-css')) return; var s = document.createElement('style'); s.id = 'zs-css'; s.textContent = CSS; document.head.appendChild(s); }

  function slaOf(c) {
    var k = c.severity >= 4 ? 4 : c.severity | 0;
    var ack = c.sla && c.sla.ack_due ? c.sla.ack_due - c.created : DEF[k][0] * 3600000, res = c.sla && c.sla.resolve_due ? c.sla.resolve_due - c.created : DEF[k][1] * 3600000;
    return { ack: ack, res: res };
  }
  function stateOf(c, now) {
    var s = c.sla_state || {}, closed = c.status === 'closed';
    if (s.resolve_breached) return closed ? ['resolved late', 'bad'] : ['resolution overdue ' + dur(-(s.resolve_remaining_ms || 0)), 'bad'];
    if (s.ack_breached && !closed) return ['response overdue', 'bad'];
    if (s.ack_breached) return ['late response', 'warn'];
    if (closed) return ['within SLA', 'ok'];
    var p = slaOf(c), left = s.resolve_remaining_ms;
    if (left != null && left < 0.25 * p.res) return ['due in ' + dur(left), 'warn'];
    return ['due in ' + dur(left), 'mute'];
  }

  function model(m, cases, days) {
    var now = Date.now(), from = now - days * 864e5, items = (cases && cases.items) || [];
    var inP = items.filter(function (c) { return c.created >= from; }), open = items.filter(function (c) { return c.status !== 'closed'; });
    var bySev = [4, 3, 2, 1].map(function (k) {
      var f = function (c) { return (c.severity >= 4 ? 4 : c.severity <= 1 ? 1 : c.severity) === k; };
      var created = inP.filter(f), closed = created.filter(function (c) { return c.status === 'closed' && c.closed; });
      var times = closed.map(function (c) { return c.closed - c.created; }).sort(function (a, b) { return a - b; });
      var br = created.filter(function (c) { var s = c.sla_state || {}; return s.ack_breached || s.resolve_breached; }).length;
      var pol = created[0] || open.filter(f)[0];
      return { k: k, created: created.length, open: open.filter(f).length, mttr: times.length ? times.reduce(function (a, b) { return a + b; }, 0) / times.length : null, breaches: br, pol: pol ? slaOf(pol) : { ack: DEF[k][0] * 36e5, res: DEF[k][1] * 36e5 } };
    });
    var dayMap = {}; for (var i = days - 1; i >= 0; i--) { var d = new Date(now - i * 864e5).toISOString().slice(0, 10); dayMap[d] = { day: d, created: 0, closed: 0, breached: 0 }; }
    items.forEach(function (c) {
      var d = new Date(c.created).toISOString().slice(0, 10); if (dayMap[d]) { dayMap[d].created++; var s = c.sla_state || {}; if (s.ack_breached || s.resolve_breached) dayMap[d].breached++; }
      if (c.closed) { var e = new Date(c.closed).toISOString().slice(0, 10); if (dayMap[e]) dayMap[e].closed++; }
    });
    var breaching = open.filter(function (c) { var s = c.sla_state || {}; return s.ack_breached || s.resolve_breached; }).sort(function (a, b) { return b.severity - a.severity || a.created - b.created; });
    var atRisk = open.filter(function (c) { var s = c.sla_state || {}; return !s.ack_breached && !s.resolve_breached && stateOf(c, now)[1] === 'warn'; });
    return { m: m || {}, items: items, inP: inP, open: open, bySev: bySev, perDay: Object.keys(dayMap).map(function (k) { return dayMap[k]; }), breaching: breaching, atRisk: atRisk, days: days,
      resolvedRecent: items.filter(function (c) { return c.status === 'closed' && c.closed; }).sort(function (a, b) { return b.closed - a.closed; }).slice(0, 10) };
  }

  function banner(D) {
    var n = (D.m.sla && D.m.sla.breached != null) ? D.m.sla.breached : D.breaching.length, r = (D.m.sla && D.m.sla.at_risk != null) ? D.m.sla.at_risk : D.atRisk.length;
    if (n) {
      var top = D.breaching.slice(0, 3).map(function (c) { return esc(c.id) + ' (' + sevName(c.severity) + ')'; }).join(', ');
      return '<div class="zs-ban bad" role="alert"><span class="zs-i">⚠</span><div><b>' + n + ' ticket' + (n > 1 ? 's are' : ' is') + ' breaching the SLA right now</b><span>' + top + (D.breaching.length > 3 ? ' and ' + (D.breaching.length - 3) + ' more' : '') + (r ? ' · ' + r + ' more close to breaching' : '') + '</span></div></div>';
    }
    if (r) return '<div class="zs-ban warn" role="status"><span class="zs-i">⏳</span><div><b>No SLA violations, but ' + r + ' ticket' + (r > 1 ? 's are' : ' is') + ' close to the deadline</b><span>Less than a quarter of the time to resolve is left.</span></div></div>';
    return '<div class="zs-ban ok" role="status"><span class="zs-i">✓</span><div><b>No SLA violations</b><span>Every open SIEM ticket is within its response and resolution time.</span></div></div>';
  }
  function kpis(D) {
    var m = D.m, t = m.totals || {}, s = m.sla || {}, mr = (m.mttr && m.mttr.cases) || {}, ma = (m.mtta && m.mtta.cases) || {};
    var comp = s.resolve_compliance_pct, ack = s.ack_compliance_pct;
    function tile(id, l, v, sub, cls) { return '<button type="button" class="zs-t ' + (cls || '') + '" data-kpi="' + id + '"><div class="l">' + l + '</div><div class="v">' + v + '</div><div class="s">' + sub + '</div></button>'; }
    return '<div class="zs-k">'
      + tile('open', 'Open tickets', t.cases_open != null ? t.cases_open : D.open.length, (t.unassigned_open != null ? t.unassigned_open + ' alerts unassigned' : 'from SIEM alerts'))
      + tile('created', 'Opened', t.cases_created != null ? t.cases_created : D.inP.length, 'from SIEM alerts, last ' + D.days + ' d')
      + tile('closed', 'Resolved', t.cases_closed != null ? t.cases_closed : '–', 'last ' + D.days + ' d')
      + tile('mttr', 'Time to resolve', dur(mr.avg_ms), 'average · median ' + dur(mr.median_ms))
      + tile('mtta', 'Time to respond', dur(ma.avg_ms), 'average first response')
      + tile('sla', 'SLA met', comp != null ? comp + ' %' : '–', 'resolution · response ' + (ack != null ? ack + ' %' : '–'), comp == null ? '' : comp >= 95 ? 'ok' : comp >= 85 ? 'warn' : 'bad')
      + tile('breach', 'Breaching now', s.breached != null ? s.breached : D.breaching.length, (s.at_risk || D.atRisk.length) + ' at risk', (s.breached || D.breaching.length) ? 'bad' : 'ok')
      + '</div>';
  }
  function caseRows(list, cols) {
    var now = Date.now();
    if (!list.length) return '<div class="zs-m">None.</div>';
    return '<div class="zs-tw"><table><thead><tr><th>Ticket</th><th>Title</th><th>Severity</th>' + (cols === 'resolved' ? '<th class="n">Resolved in</th><th>SLA</th>' : '<th>Status</th><th>Owner</th><th class="n">Age</th><th>SLA</th>') + '</tr></thead><tbody>'
      + list.map(function (c) {
        var st = stateOf(c, now);
        return '<tr data-case="' + esc(c.id) + '" tabindex="0"><td>' + esc(c.id) + '</td><td>' + esc(c.title) + '</td><td>' + sevPill(c.severity) + '</td>'
          + (cols === 'resolved' ? '<td class="n">' + dur(c.closed - c.created) + '</td>' : '<td>' + esc(c.status) + '</td><td>' + esc(c.owner || 'unassigned') + '</td><td class="n">' + dur(now - c.created) + '</td>')
          + '<td><span class="zs-pl ' + st[1] + '">' + esc(st[0]) + '</span></td></tr>';
      }).join('') + '</tbody></table></div>';
  }
  function sevTable(D) {
    return '<div class="zs-tw"><table><thead><tr><th>Severity</th><th class="n">Respond within</th><th class="n">Resolve within</th><th class="n">Opened</th><th class="n">Open now</th><th class="n">Avg time to resolve</th><th class="n">SLA breaches</th></tr></thead><tbody>'
      + D.bySev.map(function (r) { return '<tr><td>' + sevPill(r.k) + '</td><td class="n">' + dur(r.pol.ack) + '</td><td class="n">' + dur(r.pol.res) + '</td><td class="n">' + r.created + '</td><td class="n">' + r.open + '</td><td class="n">' + dur(r.mttr) + '</td><td class="n">' + (r.breaches ? '<span class="zs-pl bad">' + r.breaches + '</span>' : '0') + '</td></tr>'; }).join('') + '</tbody></table></div>';
  }
  function chart(D) {
    var mx = Math.max.apply(null, D.perDay.map(function (d) { return Math.max(d.created, d.closed); }).concat([1]));
    return '<div class="zs-ch" role="img" aria-label="Tickets opened and resolved per day">' + D.perDay.map(function (d) {
      return '<div title="' + esc(d.day + ': ' + d.created + ' opened, ' + d.closed + ' resolved' + (d.breached ? ', ' + d.breached + ' breached SLA' : '')) + '"><i style="height:' + (d.created / mx * 100) + '%;background:' + (d.breached ? '#f85149' : '#3987e5') + '"></i><i style="height:' + (d.closed / mx * 50) + '%;background:#3fb950;opacity:.75"></i></div>';
    }).join('') + '</div><div class="zs-ax"><span>' + esc(D.perDay[0].day.slice(5)) + '</span><span>today</span></div>'
      + '<div class="zs-lg"><span><i style="background:#3987e5"></i>opened</span><span><i style="background:#f85149"></i>opened, breached SLA</span><span><i style="background:#3fb950"></i>resolved (half scale)</span></div>';
  }

  /* ---- SIEM health: engine, database, collectors, log sources, hardware */
  function hstate(H, S, X, O) {
    var issues = [], now = Date.now(), h = H || {}, src = (S && S.sources) || [], x = X || null;
    // /onboard/sources knows whether a source EVER sent (log history), /sources only since engine start / today: a source
    // registered but never connected is "not connected yet", not "stopped sending"
    var ever = {}; ((O && O.sources) || []).forEach(function (o) { ever[o.id] = o.state; });
    var hasO = !!(O && O.sources);
    if (!H) issues.push(['bad', 'SIEM engine is not answering']);
    else {
      if (h.status !== 'ok') issues.push(['bad', 'SIEM engine reports a problem (' + esc(h.status) + ')']);
      if (h.clickhouse && h.clickhouse.ok === false) issues.push(['bad', 'Log database (ClickHouse) is not responding']);
      if (h.spool && h.spool.bytes > 0) issues.push(['warn', 'Logs are queued on disk waiting for the database (' + Math.round(h.spool.bytes / 1048576) + ' MB)']);
      if (h.integrity && h.integrity.ok === false) issues.push(['bad', 'Log integrity check failed']);
      if (h.detector && h.detector.running === false) issues.push(['bad', 'Detection engine is not running']);
      (h.collectors || []).forEach(function (c) { if (c.ok === false) issues.push(['bad', 'Collector ' + esc(c.name) + ': ' + esc(c.error || 'not working')]); });
      if (h.eps && h.eps.m1 === 0) issues.push(['warn', 'No logs received in the last minute']);
    }
    var quiet = src.filter(function (s) { return s.status === 'silent' && s.configured && ever[s.src_id] !== 'receiving'; });
    var never = quiet.filter(function (s) { return hasO ? ever[s.src_id] === 'waiting' : !s.last_seen; });
    var silent = quiet.filter(function (s) { return never.indexOf(s) < 0; }), errs = src.filter(function (s) { return s.status === 'errors'; });
    var names = function (L) { return L.slice(0, 4).map(function (s) { return esc(s.src_id); }).join(', ') + (L.length > 4 ? '…' : ''); };
    if (silent.length) issues.push(['bad', silent.length + ' log source' + (silent.length > 1 ? 's have' : ' has') + ' stopped sending: ' + names(silent)]);
    if (never.length) issues.push(['warn', never.length + ' registered log source' + (never.length > 1 ? 's have' : ' has') + (hasO ? ' never sent anything (not connected yet)' : ' sent nothing today') + ': ' + names(never) + ' - <a href="/dashboards/soc-sources.html" style="color:inherit;text-decoration:underline">connect from Log Sources</a>']);
    if (errs.length) issues.push(['warn', errs.length + ' log source' + (errs.length > 1 ? 's have' : ' has') + ' many unreadable logs']);
    if (x) {
      var age = now / 1000 - x.time, mu = x.mem && x.mem.total ? (x.mem.total - x.mem.avail) / x.mem.total * 100 : 0;
      if (age > 300) issues.push(['warn', 'Server stats not updated for ' + Math.round(age / 60) + ' min']);
      if (x.cpu && x.cpu.pct >= 90) issues.push(['warn', 'Server CPU at ' + Math.round(x.cpu.pct) + ' %']);
      if (mu >= 90) issues.push(['warn', 'Server memory at ' + Math.round(mu) + ' %']);
      (x.disks || []).forEach(function (d) { var p = d.used / (d.used + d.avail) * 100; if (p >= 85) issues.push([p >= 95 ? 'bad' : 'warn', 'Disk ' + esc(d.mount) + (/logs/.test(d.role) ? ' (log storage)' : '') + ' is ' + Math.round(p) + ' % full']); });
      if (x.cpu && x.cpu.iowait >= 20) issues.push(['warn', 'Disk is slow (CPU waiting on disk ' + Math.round(x.cpu.iowait) + ' %)']);
    }
    return { issues: issues, silent: silent, never: never, errs: errs, src: src, ever: ever, hasO: hasO };
  }
  function healthHTML(H, S, X, O) {
    var st = hstate(H, S, X, O), bad = st.issues.filter(function (i) { return i[0] === 'bad'; }).length, h = H || {};
    var ban = !st.issues.length ? '<div class="zs-ban ok" role="status"><span class="zs-i">✓</span><div><b>SIEM is working normally</b><span>Engine, log database, collectors, log sources and server hardware are healthy.</span></div></div>'
      : '<div class="zs-ban ' + (bad ? 'bad' : 'warn') + '" role="' + (bad ? 'alert' : 'status') + '"><span class="zs-i">' + (bad ? '⚠' : '⏳') + '</span><div><b>' + (bad ? 'SIEM needs attention' : 'SIEM is working, with warnings') + '</b><span>' + st.issues.map(function (i) { return i[1]; }).join(' · ') + '</span></div></div>';
    var cols = (h.collectors || []).filter(function (c) { return c.enabled; }), cok = cols.filter(function (c) { return c.ok; }).length;
    var active = st.src.filter(function (s) { return s.status === 'ok'; }).length;
    var x = X || {}, mu = x.mem && x.mem.total ? (x.mem.total - x.mem.avail) / x.mem.total * 100 : null;
    var ld = (x.disks || []).filter(function (d) { return /logs/.test(d.role); })[0] || (x.disks || [])[0], dp = ld ? ld.used / (ld.used + ld.avail) * 100 : null;
    var hw = X ? Math.max(x.cpu ? x.cpu.pct : 0, mu || 0, dp || 0) : null;
    function tile(id, l, v, sub, cls) { return '<button type="button" class="zs-t ' + (cls || '') + '" data-health="' + id + '"><div class="l">' + l + '</div><div class="v">' + v + '</div><div class="s">' + sub + '</div></button>'; }
    return ban + '<div class="zs-k">'
      + tile('engine', 'SIEM engine', H ? (h.status === 'ok' ? 'Running' : 'Degraded') : 'Down', H && h.engine ? 'up ' + dur((h.engine.uptime_s || 0) * 1000) + (h.clickhouse ? ' · database ' + (h.clickhouse.ok ? 'OK' : 'down') : '') : 'no answer from the engine', H ? (h.status === 'ok' ? 'ok' : 'bad') : 'bad')
      + tile('flow', 'Log flow', H && h.eps ? (Math.round(h.eps.m1 || 0)).toLocaleString() : '–', 'events per second' + (h.spool && h.spool.bytes > 0 ? ' · backlog queued' : ''), H && h.eps && h.eps.m1 > 0 ? 'ok' : 'warn')
      + tile('collectors', 'Collectors', cols.length ? cok + ' / ' + cols.length : '–', 'listening / enabled', cols.length && cok === cols.length ? 'ok' : cols.length ? 'bad' : '')
      + tile('sources', 'Log sources', st.src.length ? active + ' / ' + st.src.length : '–', st.silent.length ? st.silent.length + ' silent' : 'all sending', st.silent.length ? 'bad' : st.src.length ? 'ok' : '')
      + tile('detect', 'Detection', h.detector && h.detector.running ? (h.detector.rules != null ? h.detector.rules : 'on') : 'off', h.detector && h.detector.running ? 'rules loaded' : 'detection engine not running', h.detector && h.detector.running ? 'ok' : 'bad')
      + tile('hardware', 'Server hardware', X ? (hw >= 90 ? 'Check' : 'Healthy') : '–', X ? 'CPU ' + Math.round(x.cpu.pct) + ' % · memory ' + Math.round(mu) + ' %' + (dp != null ? ' · disk ' + Math.round(dp) + ' %' : '') : 'server stats not installed', X ? (hw >= 90 ? 'bad' : hw >= 75 ? 'warn' : 'ok') : '')
      + '</div>';
  }
  function healthDetails(id, H, S, X, O) {
    var Z = window.zybDetail; if (!Z) { location.href = '/dashboards/soc-tickets.html'; return; }
    var h = H || {}, st = hstate(H, S, X, O), now = Date.now(), x = X || {};
    var pill = function (ok, t) { return '<span class="zd-pill zd-' + (ok === true ? 'ok' : ok === false ? 'bad' : 'info') + '">' + esc(t) + '</span>'; };
    if (id === 'sources') {
      Z.open('SIEM health', 'Log sources', Z.kv([['Sending', String(st.src.filter(function (s) { return s.status === 'ok'; }).length)], ['Stopped sending', String(st.silent.length)], ['Never connected', String(st.never.length)], ['Unreadable logs', String(st.errs.length)], ['Total', String(st.src.length)]])
        + Z.tbl(['Source', 'Type', 'Status', 'Last log', 'Events today'], st.src.slice().sort(function (a, b) { return (a.status === 'ok') - (b.status === 'ok') || String(a.src_id).localeCompare(b.src_id); }).map(function (s) {
          var nv = st.never.indexOf(s) >= 0, stp = st.silent.indexOf(s) >= 0;
          return [esc(s.src_id), esc(s.src_type || s.type), nv ? pill(null, 'never connected') : stp ? pill(false, 'stopped') : pill(s.status === 'ok' ? true : null, s.status === 'ok' ? 'sending' : s.status), s.last_seen ? dur(now - s.last_seen) + ' ago' : 'never', s.events_today != null ? Number(s.events_today).toLocaleString() : '–'];
        })));
      return;
    }
    if (id === 'collectors' || id === 'flow') {
      Z.open('SIEM health', id === 'flow' ? 'Log flow' : 'Collectors', Z.kv([['Events per second (1 min)', h.eps ? String(Math.round(h.eps.m1 || 0)) : '–'], ['Now (10 s)', h.eps ? String(Math.round(h.eps.now || 0)) : '–'], ['Queued for database', h.spool ? Math.round((h.spool.bytes || 0) / 1048576) + ' MB' : '–'], ['Integrity', h.integrity ? (h.integrity.ok === false ? 'failed' : 'OK') : '–']])
        + Z.tbl(['Collector', 'Address', 'Status', 'Events/s'], (h.collectors || []).map(function (c) { return [esc(c.name), esc(c.bind || ''), c.enabled ? pill(c.ok, c.ok ? 'working' : (c.error || 'not working')) : pill(null, 'disabled'), c.eps != null ? String(c.eps) : '–']; })));
      return;
    }
    if (id === 'hardware') {
      if (!X) { Z.open('SIEM health', 'Server hardware', '<p>Server stats are not installed. On the server run <code>sudo bash install-sysinfo.sh</code>.</p>'); return; }
      var mu = (x.mem.total - x.mem.avail) / x.mem.total * 100;
      Z.open('SIEM health', 'Server hardware · ' + x.host, Z.kv([['CPU', Math.round(x.cpu.pct) + ' % of ' + x.cpu.cores + ' cores'], ['Load (1/5/15 min)', (x.cpu.load || []).join(' / ')], ['Memory', Math.round(mu) + ' % of ' + (x.mem.total / 1073741824).toFixed(1) + ' GB'], ['Disk wait', (x.cpu.iowait || 0) + ' %'], ['Uptime', dur(x.uptime * 1000)], ['Operating system', esc(x.os)]])
        + Z.sec('Disks', Z.tbl(['Mount', 'Used for', 'Used %', 'Free'], (x.disks || []).map(function (d) { var p = d.used / (d.used + d.avail) * 100; return [esc(d.mount), esc(d.role.replace('+', ' and ')), '<span class="zd-pill zd-' + (p >= 90 ? 'bad' : p >= 75 ? 'warn' : 'ok') + '">' + p.toFixed(0) + ' %</span>', (d.avail / 1073741824).toFixed(0) + ' GB']; }))));
      return;
    }
    Z.open('SIEM health', id === 'detect' ? 'Detection engine' : 'SIEM engine', Z.kv([['Status', esc(h.status || 'down')], ['Version', esc(h.engine && h.engine.version || '–')], ['Uptime', h.engine ? dur(h.engine.uptime_s * 1000) : '–'], ['Engine memory', h.engine ? h.engine.rss_mb + ' MB' : '–'], ['Log database', h.clickhouse ? (h.clickhouse.ok ? 'OK' : 'not responding') : '–'], ['Detection', h.detector && h.detector.running ? (h.detector.rules || 0) + ' rules · ' + (h.detector.alerts || 0) + ' alerts' : 'not running']])
      + (st.issues.length ? Z.sec('Issues', '<ul>' + st.issues.map(function (i) { return '<li>' + i[1] + '</li>'; }).join('') + '</ul>') : '<p>No issues.</p>'));
  }

  function details(c) {
    var Z = window.zybDetail, now = Date.now(), s = c.sla_state || {}, p = slaOf(c), st = stateOf(c, now);
    if (!Z) return;
    var tl = [['Opened', c.created], ['First response', c.acked_at], ['Resolved', c.closed]].map(function (x) { return [x[0], dt(x[1]), x[1] && x[0] !== 'Opened' ? dur(x[1] - c.created) + ' after opening' : '']; });
    Z.open('SIEM ticket · ' + sevName(c.severity), c.id + ' · ' + (c.title || ''),
      Z.kv([['Status', esc(c.status)], ['Owner', esc(c.owner || 'unassigned')], ['SLA', '<span class="zd-pill zd-' + (st[1] === 'mute' ? 'info' : st[1]) + '">' + esc(st[0]) + '</span>'], ['Severity', esc(sevName(c.severity))],
        ['Respond by', dt(s.ack_due || c.created + p.ack) + (s.ack_breached ? ' · missed' : '')], ['Resolve by', dt(s.resolve_due || c.created + p.res) + (s.resolve_breached ? ' · missed' : '')]])
      + (c.description ? '<p>' + esc(c.description).slice(0, 1200) + '</p>' : '')
      + Z.sec('Timeline', Z.tbl(['Step', 'When', ''], tl))
      + (c.resolution ? Z.sec('Resolution', '<p>' + esc(c.resolution) + (c.resolution_note ? ' · ' + esc(c.resolution_note) : '') + '</p>') : '')
      + (c.tasks && c.tasks.length ? Z.sec('Tasks', Z.tbl(['Task', 'Done'], c.tasks.slice(0, 20).map(function (t) { return [esc(t.title), t.done ? '✓ ' + esc(t.by || '') : '']; }))) : '')
      + (c.alert_ids && c.alert_ids.length ? '<p class="zd-dim">From ' + c.alert_ids.length + ' SIEM alert' + (c.alert_ids.length > 1 ? 's' : '') + '.</p>' : ''));
  }
  function kpiDetails(id, D) {
    var Z = window.zybDetail; if (!Z) { location.href = '/dashboards/soc-tickets.html'; return; }
    var lists = { open: ['Open tickets', D.open.slice().sort(function (a, b) { return b.severity - a.severity; })], created: ['Opened in the last ' + D.days + ' days', D.inP], closed: ['Resolved', D.resolvedRecent],
      mttr: ['Time to resolve, most recent', D.resolvedRecent], mtta: ['Open tickets', D.open], sla: ['Tickets that breached SLA', D.inP.filter(function (c) { var s = c.sla_state || {}; return s.ack_breached || s.resolve_breached; })],
      breach: ['Breaching SLA now', D.breaching.concat(D.atRisk)] };
    var L = lists[id] || lists.open;
    Z.open('SIEM tickets & SLA', L[0], (id === 'sla' || id === 'mttr' ? sevTable(D).replace('<div class="zs-tw">', '<div class="zs zs-tw">') : '')
      + '<div class="zs">' + caseRows(L[1].slice(0, 100), id === 'closed' || id === 'mttr' ? 'resolved' : '') + '</div>');
  }

  function render(el, opt) {
    opt = opt || {}; css();
    var mode = opt.mode || 'full', days = opt.days || 30, D = null, HL = null, loaded = false;
    el.classList.add('zs');
    function draw() {
      if (!loaded) return;
      var hsec = '<div class="zs-hd" style="margin-top:2px"><h2>SIEM health</h2><span>engine, collectors, log sources, server hardware</span></div>' + healthHTML(HL && HL.h, HL && HL.s, HL && HL.x, HL && HL.o)
        + '<div class="zs-hd" style="margin-top:16px"><h2>Tickets from SIEM alerts</h2><span>last ' + days + ' days</span></div>';
      if (!D) { el.innerHTML = (mode === 'full' ? '' : '<div class="zs-hd"><h2>SIEM health, tickets &amp; SLA</h2><span class="sp"></span><a class="zs-more" style="margin:0" href="/dashboards/soc-tickets.html">Open full view →</a></div>') + hsec + '<div class="zs-m">Cannot load SIEM tickets' + (HL && HL.err ? ': ' + esc(HL.err) : '') + '.</div>'; return; }
      var head = mode === 'full' ? '' : '<div class="zs-hd"><h2>SIEM health, tickets &amp; SLA</h2><span>live from the SIEM</span><span class="sp"></span><a class="zs-more" style="margin:0" href="/dashboards/soc-tickets.html">Open full view →</a></div>';
      var body = hsec + banner(D) + kpis(D);
      if (mode === 'full') {
        body += '<div class="zs-g">'
          + '<section class="zs-p wide"><h3>Breaching SLA now<small>' + D.breaching.length + '</small></h3>' + caseRows(D.breaching) + '</section>'
          + '<section class="zs-p"><h3>SLA by severity<small>last ' + days + ' days</small></h3>' + sevTable(D) + '</section>'
          + '<section class="zs-p"><h3>Tickets per day<small>opened from SIEM alerts and resolved</small></h3>' + chart(D) + '</section>'
          + '<section class="zs-p wide"><h3>Close to breaching<small>less than 25 % of the time left</small></h3>' + caseRows(D.atRisk) + '</section>'
          + '<section class="zs-p wide"><h3>All open tickets<small>' + D.open.length + '</small></h3>' + caseRows(D.open.slice().sort(function (a, b) { return ((a.sla_state || {}).resolve_remaining_ms || 0) - ((b.sla_state || {}).resolve_remaining_ms || 0); }).slice(0, 100)) + '</section>'
          + '<section class="zs-p wide"><h3>Recently resolved</h3>' + caseRows(D.resolvedRecent, 'resolved') + '</section></div>';
      } else if (D.breaching.length) {
        body += '<section class="zs-p"><h3>Breaching SLA now</h3>' + caseRows(D.breaching.slice(0, 5)) + '</section>';
      }
      el.innerHTML = head + body;
    }
    function soft(p) { return p.then(function (v) { return v; }, function () { return null; }); }
    function load() {
      var to = Date.now(), from = to - days * 864e5;
      return Promise.all([soft(getJSON(API + '/health')), soft(getJSON(API + '/sources')), soft(getJSON('/dashboards/sysinfo.json?_=' + to)), soft(getJSON(API + '/onboard/sources')),
        getJSON(API + '/metrics?from=' + from + '&to=' + to).then(function (m) { return getJSON(API + '/cases?status=all&limit=500&sort=-created').then(function (c) { return [m, c]; }); }).catch(function (e) { return { err: e.message }; })])
        .then(function (r) {
          HL = { h: r[0], s: r[1], x: r[2], o: r[3] }; loaded = true;
          if (r[4] && r[4].err) { D = null; HL.err = r[4].err; } else { D = model(r[4][0], r[4][1], days); }
          draw(); if (opt.onload) opt.onload(D, HL);
        });
    }
    el.addEventListener('click', function (e) {
      var r = e.target.closest('tr[data-case]'); if (r && D) { var c = D.items.filter(function (x) { return x.id === r.getAttribute('data-case'); })[0]; if (c) { if (window.zybDetail) details(c); else location.href = '/dashboards/soc-tickets.html#' + encodeURIComponent(c.id); } return; }
      var k = e.target.closest('[data-kpi]'); if (k && D) { kpiDetails(k.getAttribute('data-kpi'), D); return; }
      var hk = e.target.closest('[data-health]'); if (hk && HL) healthDetails(hk.getAttribute('data-health'), HL.h, HL.s, HL.x, HL.o);
    });
    el.addEventListener('keydown', function (e) { if (e.key === 'Enter' && e.target.matches && e.target.matches('tr[data-case]')) e.target.click(); });
    load();
    var iv = setInterval(function () { if (!el.isConnected) return clearInterval(iv); if (!document.hidden) load(); }, 60000);
    return { reload: function (d) { if (d) days = d; return load(); }, data: function () { return D; }, open: function (id) { var c = D && D.items.filter(function (x) { return x.id === id; })[0]; if (c) details(c); } };
  }
  window.zybSLA = { render: render };

  /* ---- on the portal: add the compact panel to the CISO / Executive Security dashboard */
  if (/^\/dashboards\//.test(location.pathname)) return;
  var HEAD = /^\s*(executive security dashboard|ciso dashboard|ciso overview|executive command center)\b/i, panel = null;
  function findHead() {
    var best = null;
    [].forEach.call(document.querySelectorAll('h1,h2,h3,.vh-title,[class*="title"]'), function (h) {
      if (best || h.closest('nav,aside,ul.nav,#zyb-sla') || h.textContent.length > 90 || !HEAD.test(h.textContent)) return;
      if (h.offsetParent) best = h;
    });
    return best;
  }
  function blockOf(h) { var a = h; for (var i = 0; i < 5 && a.parentElement && a.parentElement !== document.body; i++) { var p = a.parentElement; if (p.querySelector('ul.nav') || p.getBoundingClientRect().height > 220) break; a = p; } return a; }
  function check() {
    var h = findHead();
    if (!h) { if (panel) { panel.remove(); panel = null; } return; }
    var b = blockOf(h);
    if (panel && panel.isConnected && panel.previousElementSibling === b) return;
    if (panel) panel.remove();
    panel = document.createElement('section'); panel.id = 'zyb-sla'; panel.style.cssText = 'margin:12px 0 14px;padding:14px;border:1px solid rgba(255,255,255,.09);border-radius:12px;background:rgba(255,255,255,.02)';
    b.parentNode.insertBefore(panel, b.nextSibling); render(panel, { mode: 'compact' });
  }
  var t = null;
  function boot() { check(); new MutationObserver(function (ms) { for (var i = 0; i < ms.length; i++) { if (ms[i].target.closest && ms[i].target.closest('#zyb-sla')) continue; if (!t) t = setTimeout(function () { t = null; check(); }, 500); return; } }).observe(document.body, { childList: true, subtree: true }); }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot); else boot();
})();
