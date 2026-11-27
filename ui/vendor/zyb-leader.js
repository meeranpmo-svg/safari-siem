// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
/* zyb-leader.js - the "✦ AI / ML" section of the CIO Dashboard and the IT Infrastructure Manager page, over
 * /api/itam/leader-intel/{cio|infra} (operator) and /leader-intel/ask (operator, a person). Inline SVG only (no library);
 * every value that reaches innerHTML is escaped; model text is escaped and never made into links.
 *   window.zybLeader.mount(element, 'cio' | 'infra')  draws the section into element and returns {reload}
 * CIO: what to decide this week (ranked, with why), the 12-month renewal wave (licences and contracts per month, the peak
 * named), budget forecast per envelope (P50, P90, ceiling, chance over), security posture trend, infrastructure health.
 * Infra: health index with an itemised bar per area and its trend, the storage forecast (when 85 % / 95 % is reached),
 * unusual days, the ranked worklist, the area trend lines. Both: ask the advisor. */
(function () {
  'use strict';
  if (window.zybLeader) return;
  var CSS = '.zl{display:grid;gap:12px;margin:0 0 12px}.zl .card{background:var(--panel,#13151B);border:1px solid var(--edge,#252933);border-radius:12px;padding:14px;min-width:0}'
    + '.zl h2{margin:0 0 10px;font-size:15px;color:var(--title,#fff);display:flex;gap:8px;align-items:center;flex-wrap:wrap}.zl h2 .c{color:var(--mute,#8C93A1);font-weight:400;font-size:12px}'
    + '.zl .g2{display:grid;grid-template-columns:3fr 2fr;gap:12px}.zl .g3{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:12px}@media(max-width:1000px){.zl .g2{grid-template-columns:1fr}}'
    + '.zl svg{display:block;width:100%;height:auto}.zl .wl{display:flex;gap:10px;align-items:flex-start;padding:8px 0;border-top:1px solid var(--edge,#252933)}.zl .wl:first-child{border-top:0}'
    + '.zl .wl .no{min-width:26px;height:26px;border-radius:8px;display:grid;place-items:center;font-weight:800;font-size:12px;color:#0B0C10}.zl .wl b{display:block;color:var(--title,#fff);font-size:13.5px}.zl .wl span{color:var(--mute,#8C93A1);font-size:12px}'
    + '.zl .wl a{margin-left:auto;color:var(--info,#79b8ff);text-decoration:none;font-size:12.5px;white-space:nowrap}.zl .muted{color:var(--mute,#8C93A1)}.zl .empty{color:var(--mute,#8C93A1);padding:8px 0}'
    + '.zl .ar{display:grid;grid-template-columns:minmax(150px,1.3fr) 2fr 44px 92px;gap:10px;align-items:center;padding:6px 0;border-top:1px solid var(--edge,#252933);font-size:13px}.zl .ar:first-child{border-top:0}'
    + '.zl .ar .tr{height:10px;border-radius:6px;background:rgba(255,255,255,.07);overflow:hidden}.zl .ar .tr i{display:block;height:100%;border-radius:6px}.zl .ar .s{font-weight:800;text-align:right}.zl .ar .d{font-size:11.5px;color:var(--mute,#8C93A1);text-align:right}'
    + '.zl .big{font-size:34px;font-weight:800;line-height:1}.zl .pill{display:inline-block;font-size:11px;font-weight:700;padding:1px 8px;border-radius:9px;background:rgba(255,255,255,.08)}'
    + '.zl form{display:flex;gap:8px;flex-wrap:wrap}.zl input[type=search]{flex:1;min-width:200px;background:#0b0c10;color:var(--text,#ECEEF2);border:1px solid var(--border,#2E3440);border-radius:8px;padding:8px 10px;font:13px "Segoe UI",system-ui,sans-serif}'
    + '.zl .ans{white-space:pre-wrap;background:var(--raise,#1A1D25);border:1px solid var(--edge,#252933);border-radius:10px;padding:10px 12px;margin-top:8px}.zl .lgd{display:flex;gap:12px;flex-wrap:wrap;font-size:12px;color:var(--mute,#8C93A1);margin-top:6px}.zl .lgd i{display:inline-block;width:10px;height:10px;border-radius:3px;margin-right:5px;vertical-align:-1px}';
  var st = document.createElement('style'); st.textContent = CSS; (document.head || document.documentElement).appendChild(st);
  var esc = function (s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); };
  var N = function (x) { return x == null ? '—' : Number(x).toLocaleString('en-US'); };
  var K = function (x) { if (x == null) return '—'; var a = Math.abs(x); return a >= 1e6 ? (x / 1e6).toFixed(a >= 1e7 ? 0 : 1) + 'M' : a >= 1e3 ? Math.round(x / 1e3) + 'k' : String(Math.round(x)); };
  var col = function (s) { return s == null ? '#6b7280' : s >= 85 ? '#3fb950' : s >= 70 ? '#79b8ff' : s >= 50 ? '#e3b341' : '#ff7b72'; };
  var rank = function (s) { return s >= 85 ? '#ff7b72' : s >= 70 ? '#e3b341' : '#79b8ff'; };
  function req(m, p, b) {
    return new Promise(function (ok, bad) {
      var x = new XMLHttpRequest(); x.open(m, '/api/itam' + p); x.withCredentials = true; x.timeout = 120000; x.zybQuiet = true; if (b) x.setRequestHeader('Content-Type', 'application/json');
      x.onload = function () { var j = null; try { j = JSON.parse(x.responseText); } catch (e) { /* not JSON: reported below */ } if (x.status >= 200 && x.status < 300 && j) ok(j); else bad(Object.assign(new Error((j && (j.message || j.error)) || 'HTTP ' + x.status), { status: x.status })); };
      x.onerror = x.ontimeout = function () { bad(Object.assign(new Error('not reachable'), { status: 0 })); }; x.send(b ? JSON.stringify(b) : null);
    });
  }
  function worklist(L, emptyTxt) {
    return L.length ? L.map(function (w, i) { return '<div class="wl"><span class="no" style="background:' + rank(w.score) + '">' + (i + 1) + '</span><div><b>' + esc(w.title) + '</b><span>' + esc(w.why) + '</span></div>' + (w.link ? '<a href="' + esc(w.link) + '">Open →</a>' : '') + '</div>'; }).join('') : '<div class="empty">' + esc(emptyTxt) + '</div>';
  }
  function wave(R) {
    var M = R.months, W = 640, H = 210, L = 44, B = 30, T = 14, mx = Math.max(1, Math.max.apply(null, M.map(function (m) { return m.amount; }))), bw = (W - L - 10) / M.length;
    var o = '<svg viewBox="0 0 ' + W + ' ' + H + '" role="img" aria-label="Renewals by month, next 12 months, total ' + N(R.total) + '">';
    [0, 0.5, 1].forEach(function (f) { var y = T + (1 - f) * (H - T - B); o += '<line x1="' + L + '" x2="' + (W - 6) + '" y1="' + y.toFixed(1) + '" y2="' + y.toFixed(1) + '" stroke="#252933"/><text x="' + (L - 6) + '" y="' + (y + 3).toFixed(1) + '" text-anchor="end" font-size="10" fill="#8C93A1">' + K(mx * f) + '</text>'; });
    M.forEach(function (m, i) {
      var x = L + i * bw + 4, lic = m.list.filter(function (z) { return z.kind === 'licence'; }).reduce(function (n, z) { return n + (z.amount || 0); }, 0), con = m.amount - lic, y0 = H - B;
      var hl = lic / mx * (H - T - B), hc = con / mx * (H - T - B), peak = R.peak && R.peak.month === m.month;
      if (hc > 0) o += '<rect x="' + x.toFixed(1) + '" y="' + (y0 - hc).toFixed(1) + '" width="' + (bw - 8).toFixed(1) + '" height="' + hc.toFixed(1) + '" rx="3" fill="#a371f7"><title>' + esc(m.month + ' contracts ' + N(con)) + '</title></rect>';
      if (hl > 0) o += '<rect x="' + x.toFixed(1) + '" y="' + (y0 - hc - hl).toFixed(1) + '" width="' + (bw - 8).toFixed(1) + '" height="' + hl.toFixed(1) + '" rx="3" fill="#56d4dd"><title>' + esc(m.month + ' licences ' + N(lic)) + '</title></rect>';
      if (m.unpriced) o += '<circle cx="' + (x + (bw - 8) / 2).toFixed(1) + '" cy="' + (y0 - hc - hl - 7).toFixed(1) + '" r="4" fill="#e3b341"><title>' + m.unpriced + ' renewal(s) with no cost</title></circle>';
      if (peak) o += '<text x="' + (x + (bw - 8) / 2).toFixed(1) + '" y="' + (y0 - hc - hl - 14).toFixed(1) + '" text-anchor="middle" font-size="10" font-weight="700" fill="#fff">peak</text>';
      o += '<text x="' + (x + (bw - 8) / 2).toFixed(1) + '" y="' + (H - 12) + '" text-anchor="middle" font-size="10" fill="#8C93A1">' + esc(m.month.slice(5)) + '</text>';
    });
    return o + '</svg><div class="lgd"><span><i style="background:#56d4dd"></i>licences</span><span><i style="background:#a371f7"></i>support contracts</span><span><i style="background:#e3b341;border-radius:50%"></i>no cost recorded</span></div>';
  }
  function bullets(B) {
    if (!B) return '<div class="empty">The budget forecast appears once the IT Budget has approved lines with spend (Budgets → ✦ AI / ML).</div>';
    if (!B.envelopes.length) return '<div class="empty">' + esc(B.why) + '</div>';
    return B.envelopes.map(function (e) {
      var mx = Math.max(e.p90 || 0, e.ceiling || 0, 1) * 1.08, x = function (v) { return (100 * v / mx).toFixed(1) + '%'; }, p = e.p_over_ceiling, c = p == null ? '#8C93A1' : p >= 50 ? '#ff7b72' : p >= 20 ? '#e3b341' : '#3fb950';
      return '<div style="margin:6px 0 12px"><div style="display:flex;justify-content:space-between;font-size:13px"><b>' + (e.envelope === 'cyber' ? 'Cyber Security' : 'IT Operations') + '</b><span class="pill" style="color:' + c + '">' + (p == null ? 'no ceiling' : p + '% chance over') + '</span></div>'
        + '<div style="position:relative;height:16px;background:rgba(255,255,255,.06);border-radius:8px;margin:6px 0 3px" role="img" aria-label="P50 ' + N(e.p50) + ', P90 ' + N(e.p90) + ', ceiling ' + N(e.ceiling) + '">'
        + '<i style="position:absolute;left:0;top:0;bottom:0;width:' + x(e.p90) + ';background:' + c + ';opacity:.28;border-radius:8px"></i><i style="position:absolute;left:0;top:3px;bottom:3px;width:' + x(e.p50) + ';background:' + c + ';border-radius:6px"></i>'
        + (e.ceiling ? '<i style="position:absolute;left:' + x(e.ceiling) + ';top:-3px;bottom:-3px;width:2px;background:#fff"></i>' : '') + '</div>'
        + '<div class="muted" style="font-size:11.5px">most likely ' + N(e.p50) + ' · could reach ' + N(e.p90) + ' · ceiling ' + N(e.ceiling) + '</div></div>';
    }).join('') + '<div class="muted" style="font-size:11.5px">' + esc(B.why) + '</div>';
  }
  function line(pts, key, w, h, opt) {
    opt = opt || {}; var P = pts.filter(function (p) { return p[key] != null; }); if (P.length < 2) return '';
    var mn = opt.min != null ? opt.min : Math.min.apply(null, P.map(function (p) { return p[key]; })), mx = opt.max != null ? opt.max : Math.max.apply(null, P.map(function (p) { return p[key]; }));
    if (mx - mn < 5) { mn -= 3; mx += 3; }
    var X = function (i) { return 4 + i * (w - 8) / (P.length - 1); }, Y = function (v) { return h - 4 - (v - mn) / (mx - mn || 1) * (h - 8); };
    var d = P.map(function (p, i) { return (i ? 'L' : 'M') + X(i).toFixed(1) + ' ' + Y(p[key]).toFixed(1); }).join(''), last = P[P.length - 1][key], c = opt.color || col(last);
    return '<path d="' + d + 'L' + X(P.length - 1).toFixed(1) + ' ' + h + 'L4 ' + h + 'Z" fill="' + c + '" fill-opacity=".12"/><path d="' + d + '" fill="none" stroke="' + c + '" stroke-width="2.2" stroke-linejoin="round"/><circle cx="' + X(P.length - 1).toFixed(1) + '" cy="' + Y(last).toFixed(1) + '" r="3.5" fill="' + c + '"/>';
  }
  function areas(H) {
    return H.areas.map(function (a) {
      var tr = a.trend && a.trend.n ? a.trend : null, arrow = tr ? (tr.direction === 'rising' ? '▲' : tr.direction === 'falling' ? '▼' : '■') : '', tc = tr ? (tr.direction === 'rising' ? '#3fb950' : tr.direction === 'falling' ? '#ff7b72' : '#8C93A1') : '#8C93A1';
      return '<div class="ar" title="' + esc(a.why + (a.items || []).map(function (i) { return '\n' + i.label + ' (' + i.points + ')'; }).join('')) + '"><a href="' + esc(a.link || '#') + '" style="color:inherit;text-decoration:none">' + esc(a.name) + '</a>'
        + '<div class="tr">' + (a.measured ? '<i style="width:' + a.score + '%;background:' + col(a.score) + '"></i>' : '') + '</div><span class="s" style="color:' + col(a.score) + '">' + (a.measured ? a.score : '—') + '</span>'
        + '<span class="d">' + (a.measured ? (tr && tr.slope_per_week != null ? '<span style="color:' + tc + '">' + arrow + ' ' + (tr.slope_per_week > 0 ? '+' : '') + tr.slope_per_week + '/wk</span>' : 'trend after 3 days') : 'not measured') + '</span></div>';
    }).join('');
  }
  function gauge(v, label) {
    var r = 46, C = Math.PI * r, f = v == null ? 0 : v / 100;
    return '<svg viewBox="0 0 120 72" style="max-width:190px" role="img" aria-label="' + esc(label + ': ' + (v == null ? 'not measurable' : v + ' of 100')) + '"><path d="M14 64 A46 46 0 0 1 106 64" fill="none" stroke="rgba(255,255,255,.08)" stroke-width="11" stroke-linecap="round"/>'
      + (v == null ? '' : '<path d="M14 64 A46 46 0 0 1 106 64" fill="none" stroke="' + col(v) + '" stroke-width="11" stroke-linecap="round" stroke-dasharray="' + (C * f).toFixed(1) + ' ' + C.toFixed(1) + '"/>')
      + '<text x="60" y="58" text-anchor="middle" font-size="24" font-weight="800" fill="#fff">' + (v == null ? '—' : v) + '</text></svg>';
  }
  function storageChart(F, hist) {
    if (!F.measured) return '<div class="empty">' + esc(F.why) + '</div>';
    var P = hist.filter(function (h) { return h.storage_used != null; }), W = 420, H = 150, T = 8, B = 20, mn = 0, mx = 100, n = P.length, extra = 0;
    var t85 = F.at85 && F.at85.date ? Math.max(0, Math.round((Date.parse(F.at85.date) - Date.now()) / 864e5)) : null; if (t85 != null && t85 > 0) extra = Math.min(180, t85);
    var span = Math.max(1, n - 1 + extra), X = function (i) { return 30 + i * (W - 40) / span; }, Y = function (v) { return T + (mx - v) / (mx - mn) * (H - T - B); };
    var o = '<svg viewBox="0 0 ' + W + ' ' + H + '" role="img" aria-label="Storage used ' + F.used_pct + '%">';
    o += '<rect x="30" y="' + Y(100) + '" width="' + (W - 40) + '" height="' + (Y(95) - Y(100)) + '" fill="rgba(255,123,114,.12)"/><rect x="30" y="' + Y(95) + '" width="' + (W - 40) + '" height="' + (Y(85) - Y(95)) + '" fill="rgba(227,179,65,.10)"/>';
    [0, 50, 85, 95].forEach(function (v) { o += '<text x="24" y="' + (Y(v) + 3).toFixed(1) + '" text-anchor="end" font-size="10" fill="#8C93A1">' + v + '%</text>'; });
    if (n >= 2) { var d = P.map(function (p, i) { return (i ? 'L' : 'M') + X(i).toFixed(1) + ' ' + Y(p.storage_used).toFixed(1); }).join(''); o += '<path d="' + d + '" fill="none" stroke="#79b8ff" stroke-width="2.2"/>'; }
    if (extra) o += '<line x1="' + X(n - 1).toFixed(1) + '" y1="' + Y(F.used_pct).toFixed(1) + '" x2="' + X(n - 1 + extra).toFixed(1) + '" y2="' + Y(85).toFixed(1) + '" stroke="#e3b341" stroke-width="2" stroke-dasharray="5 4"/><circle cx="' + X(n - 1 + extra).toFixed(1) + '" cy="' + Y(85).toFixed(1) + '" r="4" fill="#e3b341"/>';
    o += '<circle cx="' + X(Math.max(0, n - 1)).toFixed(1) + '" cy="' + Y(F.used_pct).toFixed(1) + '" r="4" fill="#fff"/></svg>';
    var w = function (r) { return r ? (r.date ? esc(r.date) : '<span class="muted">not at this pace</span>') : '—'; };
    return o + '<div style="display:flex;gap:16px;flex-wrap:wrap;font-size:13px;margin-top:4px"><span>Now <b>' + F.used_pct + '%</b></span><span>85 % around <b>' + w(F.at85) + '</b></span><span>95 % around <b>' + w(F.at95) + '</b></span></div>'
      + '<div class="muted" style="font-size:11.5px">' + esc(F.at85 && F.at85.why || (F.trend && F.trend.why) || '') + '</div>';
  }
  function trendsSvg(hist, areasL) {
    var C = { backup: '#3fb950', patch: '#79b8ff', lifecycle: '#a371f7', storage: '#e3b341', contracts: '#56d4dd' }, P = hist.filter(function (h) { return h.overall != null || h.backup != null; });
    if (P.length < 2) return '<div class="empty">Trends appear after the second daily snapshot (' + P.length + ' so far).</div>';
    var o = '<svg viewBox="0 0 640 170" role="img" aria-label="Health per area over ' + P.length + ' days">'; [0, 50, 100].forEach(function (v) { var y = 4 + (100 - v) / 100 * 162; o += '<line x1="0" x2="640" y1="' + y + '" y2="' + y + '" stroke="#252933"/>'; });
    areasL.forEach(function (a) { o += line(P, a.id, 640, 170, { min: 0, max: 100, color: C[a.id] || '#8C93A1' }).replace(/fill-opacity="\.12"/, 'fill-opacity="0"'); });
    return o + '</svg><div class="lgd">' + areasL.map(function (a) { return '<span><i style="background:' + (C[a.id] || '#8C93A1') + '"></i>' + esc(a.name) + '</span>'; }).join('') + '</div>';
  }
  function askBox(id) {
    return '<div class="card"><h2>Ask the advisor <span class="c">reads only the figures above · proposes, never changes anything · operators and administrators</span></h2><form id="' + id + '-f"><input type="search" id="' + id + '-q" maxlength="2000" aria-label="Question for the advisor" placeholder="e.g. What should we fix first, and what is coming in renewals next quarter?"><button type="submit">Ask</button></form><div id="' + id + '-a"></div></div>';
  }
  function wireAsk(id) {
    var f = document.getElementById(id + '-f'); if (!f) return;
    f.addEventListener('submit', function (ev) {
      ev.preventDefault(); var q = document.getElementById(id + '-q').value.trim(), out = document.getElementById(id + '-a'); if (q.length < 5) return;
      out.innerHTML = '<div class="muted">Thinking…</div>';
      req('POST', '/leader-intel/ask', { question: q }).then(function (j) { out.innerHTML = '<div class="ans">' + esc(j.answer || '') + '</div>' + (j.injection_signals && j.injection_signals.length ? '<div class="muted" style="font-size:11.5px">Some data read looked like instructions; it was treated as data.</div>' : ''); },
        function (e) { out.innerHTML = '<div class="empty" style="color:#ff7b72">' + esc(e.status === 424 ? 'The AI advisor is not configured: ' + e.message : e.message) + '</div>'; });
    });
  }
  function drawCio(el, V) {
    var P = V.posture, I = V.infra, R = V.renewals;
    el.innerHTML = '<div class="zl"><div class="g2"><div class="card"><h2>✦ Decide this week <span class="c">ranked by money and risk · ' + V.this_week.length + '</span></h2>' + worklist(V.this_week, 'Nothing needs a decision this week from the figures the platform holds.') + '</div>'
      + '<div class="card"><h2>Budget forecast <span class="c">Monte Carlo · <a href="budget.html#ai" style="color:#79b8ff;text-decoration:none">details →</a></span></h2>' + bullets(V.budget) + '</div></div>'
      + '<div class="g2"><div class="card"><h2>Renewal wave — next 12 months <span class="c">' + N(R.total) + ' SAR across ' + R.items + ' renewals' + (R.unpriced ? ' · ' + R.unpriced + ' with no cost' : '') + (R.peak ? ' · peak ' + esc(R.peak.month) + ' (' + R.peak.share_pct + '%)' : '') + '</span></h2>' + (R.items ? wave(R) : '<div class="empty">No licence or support contract ends in the next 12 months.</div>')
      + '<div class="muted" style="font-size:11.5px;margin-top:4px">By quarter: ' + R.by_quarter.map(function (q, i) { return 'Q+' + (i + 1) + ' ' + K(q); }).join(' · ') + '</div></div>'
      + '<div class="card"><h2>Security & infrastructure</h2><div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;text-align:center">'
      + '<div>' + gauge(P ? P.overall : null, 'Security posture') + '<div class="muted" style="font-size:12px">Security posture' + (P && P.change_30d != null ? ' · <span style="color:' + (P.change_30d >= 0 ? '#3fb950' : '#ff7b72') + '">' + (P.change_30d >= 0 ? '▲ +' : '▼ ') + P.change_30d + ' in 30 d</span>' : '') + '</div></div>'
      + '<div>' + gauge(I.overall, 'Infrastructure health') + '<div class="muted" style="font-size:12px">Infrastructure health · ' + I.measured + ' of ' + I.of + ' areas</div></div></div>'
      + (P && P.points.length >= 2 ? '<svg viewBox="0 0 400 70" style="margin-top:8px" role="img" aria-label="Security posture trend">' + line(P.points, 'overall', 400, 70) + '</svg>' : '<div class="muted" style="font-size:11.5px;margin-top:8px">' + (P ? 'The posture trend appears after the second day.' : 'The AI CISO has not recorded a posture yet.') + '</div>')
      + '</div></div>' + askBox('zlc') + '</div>';
    wireAsk('zlc');
  }
  function drawInfra(el, V) {
    var H = V.health, F = V.storage_forecast, weak = H.areas.filter(function (a) { return a.measured; }).sort(function (a, b) { return a.score - b.score; })[0];
    el.innerHTML = '<div class="zl"><div class="g2"><div class="card"><h2>✦ Infrastructure health index <span class="c">every point itemised · hover an area</span></h2>'
      + '<div style="display:grid;grid-template-columns:200px 1fr;gap:14px;align-items:center"><div style="text-align:center">' + gauge(H.overall, 'Infrastructure health') + '<div class="muted" style="font-size:12px">' + esc(H.overall == null ? H.withheld_why : H.measured + ' of ' + H.of + ' areas measured' + (weak ? ' · weakest: ' + weak.name : '')) + '</div></div><div>' + areas(H) + '</div></div></div>'
      + '<div class="card"><h2>Fix first <span class="c">ranked · ' + V.worklist.length + '</span></h2>' + worklist(V.worklist, 'Nothing urgent in the figures the platform holds.') + '</div></div>'
      + '<div class="g3"><div class="card"><h2>Storage forecast <span class="c">projection from past pace, not a promise</span></h2>' + storageChart(F, V.history) + '</div>'
      + '<div class="card"><h2>Health per area over time</h2>' + trendsSvg(V.history, H.areas) + '</div>'
      + '<div class="card"><h2>Unusual days <span class="c">robust z of the day-to-day change</span></h2>' + (V.unusual.length ? V.unusual.map(function (u) { return '<div class="wl"><span class="no" style="background:' + (u.change < 0 ? '#ff7b72' : '#3fb950') + '">' + (u.change < 0 ? '▼' : '▲') + '</span><div><b>' + esc(u.name) + '</b><span>' + esc(u.why) + '</span></div></div>'; }).join('') : '<div class="empty">No area moved unusually today (judged once 8 days of history exist).</div>') + '</div></div>'
      + askBox('zli') + '</div>';
    wireAsk('zli');
  }
  function mount(el, kind) {
    if (!el) return null;
    function load() {
      el.innerHTML = '<div class="zl"><div class="card"><div class="empty">Loading the ✦ AI / ML view…</div></div></div>';
      return req('GET', '/leader-intel/' + kind).then(function (V) { (kind === 'cio' ? drawCio : drawInfra)(el, V); },
        function (e) { el.innerHTML = '<div class="zl"><div class="card"><div class="empty">' + esc(e.status === 403 ? 'The ✦ AI / ML view is for operators and administrators.' : e.status === 404 ? 'Leadership intelligence is not installed on the server yet - run the platform update.' : 'Could not load the ✦ AI / ML view: ' + e.message) + '</div></div></div>'; });
    }
    load(); return { reload: load };
  }
  window.zybLeader = { mount: mount };
})();
