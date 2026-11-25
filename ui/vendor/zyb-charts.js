// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
/* zyb-charts.js - one chart layer for the Security Operations pages, on Chart.js (vendor/chart.umd.js) in the approved
 * Vivid-dark look: colours come from the --v-* tokens (zyb-vivid.css), so the Dark / Midnight / Light theme switch applies.
 * Meaning of colour is fixed: red = act now, orange = watch, green = fine, blue = information.
 *
 *   zybCharts.area(canvas, labels, [{label, data, color?, fill?}], opts)        trend lines with a soft fill
 *   zybCharts.bars(canvas, labels, [{label, data, color?}], {stacked, horizontal})
 *   zybCharts.ring(canvas, labels, data, colors, centre)                         doughnut with the total in the middle
 *   zybCharts.empty(canvas, text)                                               an empty state; the canvas stays for the next draw
 *   zybCharts.color(name)                                                        a token: ok warn crit acc purple teal pink mute
 * Each chart sets role="img" and an aria-label that reads its data, and is destroyed before being redrawn on the same canvas.
 * With Chart.js missing the canvas is replaced by a plain text summary - a page never breaks because of a chart. */
(function () {
  'use strict';
  var made = new WeakMap();
  function tok(name, dflt) {
    var v = '';
    try { v = getComputedStyle(document.documentElement).getPropertyValue('--v-' + name).trim(); } catch (e) { v = ''; /* no computed style (old browser): the default below */ }
    return v || dflt;
  }
  var DEF = { ok: '#73bf69', warn: '#ff9830', crit: '#f2495c', acc: '#5794f2', purple: '#b877d9', teal: '#2bc8b9', pink: '#e86bbf', indigo: '#8f8ff5', yellow: '#fade2a', mute: '#8e8e8e', line: '#24272e', ink: '#d8d9da' };
  function color(n) { return tok(n, DEF[n] || n); }
  function alpha(hex, a) {
    var m = /^#([0-9a-f]{6})$/i.exec(String(hex).trim()); if (!m) return hex;
    var v = parseInt(m[1], 16); return 'rgba(' + (v >> 16 & 255) + ',' + (v >> 8 & 255) + ',' + (v & 255) + ',' + a + ')';
  }
  var PALETTE = ['acc', 'purple', 'teal', 'warn', 'pink', 'indigo', 'ok', 'yellow', 'crit'];
  function pal(i) { return color(PALETTE[i % PALETTE.length]); }
  function describe(labels, sets) {
    return sets.map(function (s) { return (s.label ? s.label + ': ' : '') + labels.map(function (l, i) { return l + ' ' + (s.data[i] == null ? '-' : s.data[i]); }).join(', '); }).join('; ');
  }
  function fallback(c, text) { var p = document.createElement('p'); p.className = 'muted small'; p.textContent = text; if (c.parentNode) c.parentNode.replaceChild(p, c); }
  function base(horizontal) {
    var ink = color('ink'), grid = alpha(color('mute'), 0.15);
    return {
      responsive: true, maintainAspectRatio: false, animation: { duration: 350 },
      interaction: { mode: 'index', intersect: false },
      plugins: { legend: { labels: { color: ink, boxWidth: 10, boxHeight: 10, usePointStyle: true, font: { size: 11 } } },
        tooltip: { backgroundColor: 'rgba(17,18,23,.95)', borderColor: color('line'), borderWidth: 1, titleColor: ink, bodyColor: ink, padding: 8 } },
      scales: { x: { grid: { color: horizontal ? grid : 'transparent' }, ticks: { color: color('mute'), font: { size: 10.5 }, maxRotation: 0, autoSkip: true, precision: 0 } },
        y: { grid: { color: horizontal ? 'transparent' : grid }, ticks: { color: color('mute'), font: { size: 10.5 }, precision: 0 }, beginAtZero: true } },
    };
  }
  // an empty state that keeps the canvas, so the next refresh can draw on it again
  function empty(c, text) {
    if (!c) return;
    var old = made.get(c); if (old) { old.destroy(); made.delete(c); }
    c.hidden = true;
    var m = c.parentNode && c.parentNode.querySelector('.zyb-chart-empty');
    if (!m && c.parentNode) { m = document.createElement('div'); m.className = 'so-empty zyb-chart-empty'; c.parentNode.appendChild(m); }
    if (m) { m.hidden = false; m.textContent = text; }
  }
  function draw(c, cfg, summary) {
    if (!c) return null;
    c.hidden = false;
    var em = c.parentNode && c.parentNode.querySelector('.zyb-chart-empty'); if (em) em.hidden = true;
    c.setAttribute('role', 'img'); c.setAttribute('aria-label', summary.slice(0, 900));
    if (typeof window.Chart !== 'function') { fallback(c, summary); return null; }
    var old = made.get(c); if (old) old.destroy();
    var ch = new window.Chart(c.getContext('2d'), cfg); made.set(c, ch); return ch;
  }
  function area(c, labels, sets, o) {
    o = o || {};
    var ds = sets.map(function (s, i) { var col = s.color ? color(s.color) : pal(i);
      return { type: s.type || 'line', label: s.label, data: s.data, borderColor: col, backgroundColor: s.type === 'bar' ? alpha(col, 0.75) : alpha(col, 0.18), fill: s.fill !== false && s.type !== 'bar',
        tension: 0.35, pointRadius: 0, pointHoverRadius: 4, borderWidth: s.type === 'bar' ? 0 : 2, stack: s.stack, borderRadius: s.type === 'bar' ? 3 : 0, order: s.type === 'bar' ? 2 : 1 }; });
    var opt = base(false); if (o.stacked) { opt.scales.x.stacked = true; opt.scales.y.stacked = true; }
    return draw(c, { type: 'line', data: { labels: labels, datasets: ds }, options: opt }, (o.title ? o.title + '. ' : '') + describe(labels, sets));
  }
  function bars(c, labels, sets, o) {
    o = o || {};
    var ds = sets.map(function (s, i) { var col = s.colors ? s.colors.map(color) : s.color ? color(s.color) : pal(i);
      return { label: s.label, data: s.data, backgroundColor: Array.isArray(col) ? col.map(function (x) { return alpha(x, 0.85); }) : alpha(col, 0.85), borderRadius: 4, maxBarThickness: 26 }; });
    var opt = base(!!o.horizontal); if (o.horizontal) opt.indexAxis = 'y';
    if (o.stacked) { opt.scales.x.stacked = true; opt.scales.y.stacked = true; }
    if (sets.length < 2) opt.plugins.legend.display = false;
    if (o.horizontal) { opt.scales.x.beginAtZero = true; opt.scales.y.ticks.autoSkip = false; }
    if (o.onClick) opt.onClick = function (e, els) { if (els && els.length) o.onClick(els[0].index); };
    return draw(c, { type: 'bar', data: { labels: labels, datasets: ds }, options: opt }, (o.title ? o.title + '. ' : '') + describe(labels, sets));
  }
  function ring(c, labels, data, colors, centre, o) {
    o = o || {};
    var cols = (data || []).map(function (x, i) { var c = colors && colors[i]; return c ? color(c) : pal(i); });   // no colour given = the palette, never Chart.js's black
    var opt = base(false); delete opt.scales; opt.cutout = '72%'; opt.plugins.legend.position = 'right';
    if (o.onClick) opt.onClick = function (e, els) { if (els && els.length) o.onClick(els[0].index); };
    var centreText = { id: 'centre', afterDraw: function (ch) {
      if (centre == null) return; var a = ch.chartArea, x = (a.left + a.right) / 2, y = (a.top + a.bottom) / 2, g = ch.ctx;
      g.save(); g.fillStyle = color('ink'); g.textAlign = 'center'; g.textBaseline = 'middle'; g.font = '700 22px Inter, system-ui, sans-serif'; g.fillText(String(centre.v), x, y - 6);
      g.fillStyle = color('mute'); g.font = '11px Inter, system-ui, sans-serif'; g.fillText(String(centre.l || ''), x, y + 14); g.restore(); } };
    return draw(c, { type: 'doughnut', data: { labels: labels, datasets: [{ data: data, backgroundColor: cols, borderColor: 'transparent', hoverOffset: 4 }] }, options: opt, plugins: [centreText] },
      (o.title ? o.title + '. ' : '') + describe(labels, [{ data: data }]));
  }
  window.zybCharts = { area: area, bars: bars, ring: ring, empty: empty, color: color, alpha: alpha };
})();
