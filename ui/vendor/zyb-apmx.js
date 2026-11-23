// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
/* Applications Manager - Insights tab (apm.html #tab-in) over the SIEM's GET /api/soc/integrations/apm/insights: what to do first, hosts
 * that are the probable cause, problems ranked with every point named, reliability per monitor (availability, outages, MTTR, MTBF,
 * flapping), noisy and long-open alarms, stale and forgotten-unmanaged monitors, the daily trend. Poll now goes through the existing APM
 * action; Resume opens the Monitors tab on that monitor, whose request asks why and waits for a second person. Delegated listeners; every value escaped. */
(function () {
  'use strict';
  var el = document.getElementById('tab-in'); if (!el || !window.zybSoc) return;
  var S = window.zybSoc, Z = window.zybDetail, esc = S.esc, V = null;
  var lvc = function (l) { return l === 'high' ? 'bad' : l === 'medium' ? 'warn' : ''; };
  function bar(p, cls) { return '<span style="display:inline-block;width:70px;height:7px;border-radius:4px;background:rgba(255,255,255,.08);vertical-align:middle;overflow:hidden"><i style="display:block;height:100%;width:' + Math.max(0, Math.min(100, p)) + '%;background:var(--' + (cls || 'info') + ',#4299e1)"></i></span>'; }
  function sec(id, title, body) { return '<div class="card" id="' + id + '"><h2>' + title + '</h2>' + body + '</div>'; }
  function load() {
    return S.req('GET', '/integrations/apm/insights').then(function (v) { V = v; draw(); })
      .catch(function (e) { el.innerHTML = '<div class="card">' + (e.status === 404 ? '<div class="empty">The Applications Manager insights are not on this SIEM yet - run the SIEM update.</div>' : S.errHtml(e, 'Applications Manager insights')) + '</div>'; });
  }
  function draw() {
    if (!V.configured) { el.innerHTML = '<div class="card"><div class="empty">' + esc(V.reason || 'Not connected') + '</div></div>'; return; }
    var k = V.kpis, T = V.trend;
    var tiles = '<div class="k">' + S.tile('Availability', k.availability == null ? '—' : k.availability + ' %', 'average over the samples kept', k.availability != null && k.availability < 99 ? 'warn' : 'ok', 'go:rel')
      + S.tile('Down or critical', T.today_bad, T.usual == null ? 'no history yet' : 'usually ' + T.usual, T.today_bad ? 'bad' : 'ok', 'go:pr') + S.tile('Probable-cause hosts', k.cause_hosts, 'several monitors down together', k.cause_hosts ? 'bad' : 'ok', 'go:hosts')
      + S.tile('Flapping', k.flapping, 'up / down every few minutes', k.flapping ? 'warn' : 'ok', 'go:rel') + S.tile('Noisy alarms', k.noisy, '5+ times in 7 days', k.noisy ? 'warn' : 'ok', 'go:noise')
      + S.tile('Critical > 24 h', k.long_open, 'open alarms nobody acted on', k.long_open ? 'bad' : 'ok', 'go:noise') + S.tile('Stale / unmanaged', k.stale + ' / ' + k.unmanaged, 'not polled · not watched', k.stale || k.unmanaged ? 'warn' : 'ok', 'go:hyg') + '</div>';
    var acts = V.actions.length ? V.actions.map(function (a) { return '<div class="fd ' + (a.priority >= 80 ? 'bad' : a.priority >= 50 ? 'warn' : 'info') + '" style="border-left:3px solid;padding:6px 10px;margin:6px 0;cursor:pointer" data-act="go:' + esc({ hosts: 'hosts', down: 'pr', problems: 'pr', long: 'noise', trend: 'trend', flapping: 'rel', noisy: 'noise', stale: 'hyg', unmanaged: 'hyg' }[a.filter] || 'pr') + '"><b>' + esc(a.title) + '</b><div class="muted small">' + esc(a.detail) + '</div></div>'; }).join('') : '<div class="empty">Nothing needs action: every managed monitor is up and clear.</div>';
    var hosts = V.hosts.length ? V.hosts.map(function (h) { return '<div class="card" style="margin:6px 0"><b>🖥 ' + esc(h.host) + '</b> ' + S.pill(h.monitors.length + ' monitors down', 'bad') + '<div class="muted small">' + esc(h.why) + '</div><div class="small">' + h.monitors.map(function (m) { return esc(m.name) + ' <span class="muted">' + esc(m.type) + '</span>'; }).join(' · ') + '</div></div>'; }).join('') : '<div class="empty">No host has several monitors down at once.</div>';
    var pr = V.problems.length ? '<div class="tw"><table><thead><tr><th>Monitor</th><th>State</th><th>Impact</th><th>Since</th><th></th></tr></thead><tbody>' + V.problems.map(function (p, i) {
      return '<tr class="xr" data-px="' + i + '" style="cursor:pointer"><td><b>' + esc(p.name) + '</b><div class="muted small">' + esc(p.type) + ' · ' + esc(p.host || '—') + (p.db ? ' · database' : '') + (p.cause_host ? ' · host is the probable cause' : '') + '</div></td><td>' + S.pill(p.state, p.state === 'down' || p.state === 'critical' ? 'bad' : 'warn') + '</td>'
        + '<td title="' + esc(p.why.map(function (w) { return '+' + w.points + ' ' + w.text; }).join('\n')) + '">' + S.pill(p.score + ' ' + p.level, lvc(p.level)) + '</td><td class="small">' + esc(S.ago(p.since)) + '</td><td>' + (S.can('operator') ? '<button type="button" data-xpoll="' + esc(p.id) + '">Poll now</button>' : '') + '</td></tr>'; }).join('') + '</tbody></table></div>' : '<div class="empty">No problem: every managed monitor is up and clear.</div>';
    var rel = V.reliability.length ? '<div class="tw"><table><thead><tr><th>Monitor</th><th>Availability</th><th>Outages</th><th>MTTR</th><th>MTBF</th><th></th></tr></thead><tbody>' + V.reliability.slice(0, 60).map(function (r) {
      return '<tr><td>' + esc(r.name) + '<div class="muted small">' + esc(r.type) + ' · ' + esc(r.host || '—') + '</div></td><td>' + (r.availability == null ? '<span class="muted">needs 12 samples</span>' : bar(r.availability, r.availability >= 99 ? 'ok' : r.availability >= 95 ? 'warn' : 'bad') + ' ' + esc(r.availability) + ' %') + '</td><td>' + esc(r.episodes) + '</td><td>' + esc(r.mttr_min == null ? '—' : r.mttr_min + ' min') + '</td><td>' + esc(r.mtbf_h == null ? '—' : r.mtbf_h + ' h') + '</td><td>' + (r.flapping ? S.pill('flapping', 'warn') : '') + '</td></tr>'; }).join('') + '</tbody></table></div><p class="muted small">From the 5-minute samples the SIEM keeps (7 days). MTTR = average minutes down per outage; MTBF = hours of watching per outage.</p>' : '<div class="empty">No samples yet - the SIEM samples every monitor every 5 minutes.</div>';
    var noise = (V.long_open.length ? '<h3>Critical for more than a day</h3>' + V.long_open.map(function (a) { return '<div class="small">' + S.pill(a.hours + ' h', 'bad') + ' <b>' + esc(a.name) + '</b> · ' + esc(a.attribute) + ' <span class="muted">' + esc(a.message) + '</span></div>'; }).join('') : '')
      + (V.noisy.length ? '<h3>Noisy - 5+ times in 7 days</h3>' + V.noisy.map(function (a) { return '<div class="small">' + S.pill(a.episodes_7d + '×', 'warn') + ' <b>' + esc(a.name) + '</b> · ' + esc(a.attribute) + (a.median_min != null ? ' <span class="muted">lasts about ' + esc(a.median_min) + ' min</span>' : '') + '</div>'; }).join('') + '<p class="muted small">Tune these in Applications Manager (threshold, consecutive polls) so a real problem stands out.</p>' : '')
      || '<div class="empty">No noisy or long-open alarm.</div>';
    var hyg = (V.stale.length ? '<h3>Not polled recently</h3>' + V.stale.map(function (m) { return '<div class="small">' + S.pill(m.minutes + ' min', 'warn') + ' <b>' + esc(m.name) + '</b> ' + esc(m.host || '') + (S.can('operator') ? ' <button type="button" data-xpoll="' + esc(m.id) + '">Poll now</button>' : '') + '</div>'; }).join('') : '')
      + (V.unmanaged.length ? '<h3>Unmanaged - alerts nobody</h3>' + V.unmanaged.map(function (m) { return '<div class="small"><b>' + esc(m.name) + '</b> ' + esc(m.host || '') + ' ' + (m.maintenance_request ? S.pill('maintenance request open', '') : S.pill('no maintenance request', 'warn') + (S.can('operator') ? ' <button type="button" data-xresume="' + esc(m.name) + '">Resume…</button>' : '')) + '</div>'; }).join('') : '')
      || '<div class="empty">Every monitor is polled and managed.</div>';
    var H = T.history || [], mx = Math.max.apply(null, H.map(function (h) { return h.bad; }).concat([1]));
    var trend = H.length ? '<div style="display:flex;align-items:flex-end;gap:2px;height:60px">' + H.map(function (h) { return '<i title="' + esc(h.day + ': ' + h.bad + ' down / critical') + '" style="flex:1;display:block;background:' + (h.bad ? 'var(--bad,#d63939)' : 'var(--ok,#2fb344)') + ';height:' + Math.max(4, h.bad / mx * 100) + '%;border-radius:2px 2px 0 0"></i>'; }).join('') + '</div><p class="muted small">' + esc(T.why || ('Today ' + T.today_bad + ' against a usual ' + T.usual + (T.z != null ? ' (robust z ' + T.z + ')' : ''))) + '</p>' : '<div class="empty">The trend starts with the first day of samples.</div>';
    el.innerHTML = tiles + '<div style="display:grid;grid-template-columns:minmax(0,3fr) minmax(0,2fr);gap:12px">' + sec('x-act', '🧭 What to do first', acts) + sec('x-trend', '📈 Down or critical per day', trend) + '</div>'
      + sec('x-hosts', '🖥 Probable-cause hosts', hosts) + sec('x-pr', '🚦 Problems, ranked by impact', pr) + sec('x-rel', '📊 Reliability per monitor', rel)
      + '<div style="display:grid;grid-template-columns:1fr 1fr;gap:12px">' + sec('x-noise', '🔔 Alarm quality', noise) + sec('x-hyg', '🧹 Monitoring hygiene', hyg) + '</div><p class="muted small">' + esc(V.note) + '</p>';
  }
  function problem(i) {
    var p = V.problems[i]; if (!p) return;
    Z.open('Applications Manager · problem', p.name, Z.kv([['Type', esc(p.type)], ['Host', esc(p.host || '—')], ['State', esc(p.state)], ['Since', esc(S.dt(p.since))], ['Open alarms', esc(p.alarms)]])
      + '<h3>Impact ' + esc(p.score) + ' / 100</h3>' + p.why.map(function (w) { return '<div class="small">+' + esc(w.points) + ' ' + esc(w.text) + '</div>'; }).join('')
      + (p.message ? '<h3>Applications Manager says</h3><div class="small">' + esc(p.message) + '</div>' : '')
      + '<h3>Next step</h3><div class="small">' + esc(p.suggest === 'host' ? 'Several monitors on ' + p.host + ' are down: check the server or VM first, then Poll now to confirm.' : p.suggest === 'tune' ? 'It flaps: review the threshold / timeout in Applications Manager.' : 'Poll now to confirm, then fix the cause; plan maintenance from the Monitors tab if work is planned.') + '</div>'
      + (S.can('operator') ? '<p><button type="button" data-xpoll="' + esc(p.id) + '">Poll now</button></p>' : ''));
  }
  el.addEventListener('click', function (ev) {
    var b;
    if ((b = ev.target.closest('[data-act^="go:"]'))) { var t = document.getElementById('x-' + b.getAttribute('data-act').slice(3)); if (t) t.scrollIntoView({ behavior: 'smooth' }); return; }
    if ((b = ev.target.closest('[data-xpoll]'))) { ev.stopPropagation(); return S.req('POST', '/integrations/apm/actions', { action: 'poll', resource_id: b.getAttribute('data-xpoll') }).then(function () { S.toast('Poll requested from Applications Manager'); }).catch(function (e) { S.toast(e.message); }); }
    // Resume goes through the Monitors tab's own request (it asks why; a second person approves)
    if ((b = ev.target.closest('[data-xresume]'))) { var q = document.getElementById('q'); document.querySelector('[data-tab="mo"]').click(); if (q) { q.value = b.getAttribute('data-xresume'); q.dispatchEvent(new Event('input', { bubbles: true })); } return; }
    if ((b = ev.target.closest('tr[data-px]'))) return problem(+b.getAttribute('data-px'));
  });
  document.addEventListener('click', function (ev) { var b = ev.target.closest('#zd [data-xpoll]'); if (b) S.req('POST', '/integrations/apm/actions', { action: 'poll', resource_id: b.getAttribute('data-xpoll') }).then(function () { S.toast('Poll requested from Applications Manager'); }).catch(function (e) { S.toast(e.message); }); });
  load(); setInterval(function () { if (!el.hidden) load(); }, 120000);
})();
