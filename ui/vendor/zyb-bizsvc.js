// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
/* Business Services -> Insights (above the server list). Computed in the browser from GET /api/itam/service-map, nothing stored:
 *   coverage ring      servers a source could read / all servers; decisions taken / servers with business services
 *   decision queue     proposed servers ranked by a points score (confirmed database / ERP / mail / directory / web / app server,
 *                      several business services, in the asset register) - every point named
 *   learned from peers servers whose confirmed services match (Jaccard >= 0.6) a server an administrator already decided: the
 *                      peers' decision is suggested, with the peer and the similarity - a suggestion, the administrator decides
 *   single instances   a product that runs on exactly one server (no second copy anywhere)
 *   stack mix          servers per kind of software
 *   blind spots        servers no source could read, grouped by the first reason
 * Clicking a server, product or blind spot fills the page's own search box. Every value is escaped; no inline handlers. */
(function () {
  'use strict';
  var $ = function (id) { return document.getElementById(id); };
  var esc = function (s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); };
  var W = { database: 30, erp: 25, mail: 25, directory: 25, app: 20, web: 15, messaging: 15, platform: 5 };
  var KC = { database: '#5794f2', web: '#2dc7b3', app: '#b877d9', erp: '#ff9830', mail: '#fade2a', directory: '#73bf69', messaging: '#ff7383', platform: '#8e939c' };
  function conf(x) { return x.services.filter(function (s) { return s.confidence === 'confirmed' && s.kind !== 'access'; }); }
  function ids(x) { var o = {}; conf(x).forEach(function (s) { o[s.id] = 1; }); return o; }
  function jac(a, b) { var k = Object.keys(a), u = {}, i = 0; k.concat(Object.keys(b)).forEach(function (x) { u[x] = 1; }); k.forEach(function (x) { if (b[x]) i++; }); var n = Object.keys(u).length; return n ? i / n : 0; }
  function score(x) {
    var why = [], seen = {};
    conf(x).forEach(function (s) { if (W[s.kind] && !seen[s.kind]) { seen[s.kind] = 1; why.push([s.kind_label + ' (' + s.label + ')', W[s.kind]]); } });
    var n = x.business.length; if (n >= 2) why.push([n + ' business services on one server', 10]);
    if (x.asset) why.push(['in the asset register', 5]);
    var t = why.reduce(function (a, w) { return a + w[1]; }, 0); return { score: Math.min(100, t), why: why };
  }
  function ring(p, label) { var r = 34, c = 2 * Math.PI * r, v = p == null ? 0 : p, col = p == null ? '#4a5162' : p >= 80 ? '#73bf69' : p >= 50 ? '#ff9830' : '#f2495c';
    return '<svg viewBox="0 0 90 90" width="96" height="96" role="img" aria-label="' + esc(label) + '"><circle cx="45" cy="45" r="' + r + '" fill="none" stroke="#2a2e35" stroke-width="9"/><circle cx="45" cy="45" r="' + r + '" fill="none" stroke="' + col + '" stroke-width="9" stroke-linecap="round" stroke-dasharray="' + (c * v / 100).toFixed(1) + ' ' + c.toFixed(1) + '" transform="rotate(-90 45 45)"/><text x="45" y="50" text-anchor="middle" font-size="17" font-weight="700" fill="#fff">' + (p == null ? '—' : p + '%') + '</text></svg>'; }
  function find(q) { var i = $('q'); if (!i) return; i.value = q; i.dispatchEvent(new Event('input')); i.scrollIntoView({ behavior: 'smooth', block: 'center' }); }
  function draw(V) {
    var h = $('bizi'); if (!h) return;
    var S = V.servers || [], n = S.length;
    if (!n) { h.innerHTML = ''; return; }
    var checked = S.filter(function (x) { return x.checked; }).length, withBiz = S.filter(function (x) { return x.business.length; }), decided = withBiz.filter(function (x) { return x.state === 'confirmed' || x.state === 'not_critical'; }).length;
    var cov = Math.round(checked / n * 100), dec = withBiz.length ? Math.round(decided / withBiz.length * 100) : null;
    var done = S.filter(function (x) { return x.state === 'confirmed' || x.state === 'not_critical'; });
    var queue = S.filter(function (x) { return x.state === 'proposed'; }).map(function (x) {
      var sc = score(x), mine = ids(x), best = null;
      done.forEach(function (d) { var j = jac(mine, ids(d)); if (j >= 0.6 && (!best || j > best.j)) best = { j: j, d: d }; });
      return { x: x, sc: sc, peer: best };
    }).sort(function (a, b) { return b.sc.score - a.sc.score; });
    var prod = {}; S.forEach(function (x) { conf(x).forEach(function (s) { (prod[s.id] = prod[s.id] || { label: s.label, kind: s.kind, hosts: [] }).hosts.push(x.host); }); });
    var single = Object.keys(prod).map(function (k) { return prod[k]; }).filter(function (p) { return p.hosts.length === 1 && W[p.kind] >= 15; }).sort(function (a, b) { return W[b.kind] - W[a.kind]; });
    var mix = {}; S.forEach(function (x) { var seen = {}; conf(x).forEach(function (s) { if (!seen[s.kind]) { seen[s.kind] = 1; mix[s.kind] = (mix[s.kind] || 0) + 1; } }); });
    var mk = Object.keys(mix).sort(function (a, b) { return mix[b] - mix[a]; }), mx = Math.max.apply(null, mk.map(function (k) { return mix[k]; }).concat([1]));
    var blind = {}; S.filter(function (x) { return !x.checked; }).forEach(function (x) { var c = (x.coverage || []).filter(function (y) { return !y.ok && y.why; })[0], r = c ? c.source + ': ' + c.why : 'no source'; (blind[r] = blind[r] || []).push(x.host); });
    var bk = Object.keys(blind).sort(function (a, b) { return blind[b].length - blind[a].length; });
    var card = function (t, body) { return '<div class="card" style="margin:0"><h2>' + t + '</h2>' + body + '</div>'; };
    h.innerHTML = '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(340px,1fr));gap:12px;margin:0 0 12px">'
      + card('Coverage and decisions', '<div style="display:flex;gap:18px;align-items:center;flex-wrap:wrap"><div style="text-align:center">' + ring(cov, 'servers read') + '<div class="muted">servers read (' + checked + ' of ' + n + ')</div></div><div style="text-align:center">' + ring(dec, 'decisions taken') + '<div class="muted">decisions taken (' + decided + ' of ' + withBiz.length + ')</div></div></div>')
      + card('Decide next <span class="c">ranked, with the points</span>', queue.length ? '<ol style="margin:0;padding-left:18px">' + queue.slice(0, 8).map(function (q) { return '<li style="margin-bottom:6px"><a href="#" data-bq="' + esc(q.x.host) + '"><b>' + esc(q.x.host) + '</b></a> <b>' + q.sc.score + '</b><div class="muted" style="font-size:12px">' + q.sc.why.map(function (w) { return esc(w[0]) + ' +' + w[1]; }).join(' · ') + '</div>' + (q.peer ? '<div style="font-size:12px">Like <b>' + esc(q.peer.d.host) + '</b> (' + Math.round(q.peer.j * 100) + '% same software), which was decided <b>' + (q.peer.d.state === 'confirmed' ? 'business-critical' : 'not critical') + '</b> - suggested, you decide.</div>' : '') + '</li>'; }).join('') + '</ol>' : '<div class="muted">Nothing waits for a decision.</div>')
      + card('Only one copy <span class="c">a product on exactly one server</span>', single.length ? single.slice(0, 10).map(function (p) { return '<div style="margin-bottom:4px"><span style="color:' + (KC[p.kind] || '#8e939c') + '">●</span> <a href="#" data-bq="' + esc(p.label) + '">' + esc(p.label) + '</a> <span class="muted">on ' + esc(p.hosts[0]) + ' - no second server runs it</span></div>'; }).join('') : '<div class="muted">Every business product runs on two or more servers.</div>')
      + card('Stack mix <span class="c">servers per kind</span>', mk.length ? mk.map(function (k) { return '<div style="display:grid;grid-template-columns:130px 1fr 34px;gap:8px;align-items:center;font-size:12.5px;margin-bottom:4px"><span>' + esc((V.kinds || {})[k] || k) + '</span><span style="height:8px;border-radius:4px;background:#2a2e35;overflow:hidden"><i style="display:block;height:100%;width:' + Math.round(mix[k] / mx * 100) + '%;background:' + (KC[k] || '#8e939c') + '"></i></span><b>' + mix[k] + '</b></div>'; }).join('') : '<div class="muted">No confirmed software yet.</div>')
      + (bk.length ? card('Blind spots <span class="c">servers no source could read</span>', bk.slice(0, 6).map(function (r) { return '<div style="margin-bottom:6px"><b>' + blind[r].length + '</b> · ' + esc(r) + '<div class="muted" style="font-size:12px">' + blind[r].slice(0, 6).map(function (x) { return '<a href="#" data-bq="' + esc(x) + '">' + esc(x) + '</a>'; }).join(', ') + (blind[r].length > 6 ? ' …' : '') + '</div></div>'; }).join('')) : '')
      + '</div>';
  }
  function load() {
    var x = new XMLHttpRequest(); x.open('GET', '/api/itam/service-map'); x.withCredentials = true; x.zybQuiet = true;
    x.onload = function () { var j = null; try { j = JSON.parse(x.responseText); } catch (e) { /* the page itself says why it could not load */ } if (x.status === 200 && j) draw(j); };
    x.onerror = function () { /* the page itself reports the failure */ }; x.send();
  }
  document.addEventListener('click', function (e) { var a = e.target.closest && e.target.closest('[data-bq]'); if (!a) return; e.preventDefault(); find(a.getAttribute('data-bq')); });
  // the page re-reads after a look, a decision or a refresh: follow its server list (debounced), not a timer
  var T = null, last = '';
  function watch() { var el = $('srv'); if (!el || !window.MutationObserver) return; new MutationObserver(function () { var sig = $('up') ? $('up').textContent + '|' + el.querySelectorAll('tr').length + '|' + (el.textContent.match(/business-critical|proposed/g) || []).join('') : ''; if (sig === last) return; last = sig; clearTimeout(T); T = setTimeout(load, 300); }).observe(el, { childList: true, subtree: true }); }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', function () { watch(); load(); }); else { watch(); load(); }
})();
