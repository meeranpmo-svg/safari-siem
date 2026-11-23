// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
// One compliance language on the register pages (PDPL, NDMO; NCA ECC draws the same): fully compliant, partially compliant,
// not compliant, not assessed - with the share of each for the whole register and for each domain / area. The figures come
// from the engine (engine/compliance-levels.js: {status, counts, pct, applicable}); this file only draws them, escaped.
(function () {
  'use strict';
  var esc = function (s) { return String(s === undefined || s === null ? '' : s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); };
  var SEG = [['fully', '#0ca30c', 'Fully compliant', 'green'], ['partially', '#fab219', 'Partially compliant', 'yellow'], ['not', '#d03b3b', 'Not compliant', 'red'], ['not_assessed', '#6b7280', 'Not assessed', 'secondary']];
  var ST = { fully_compliant: ['Fully compliant', 'green', '#0ca30c'], partially_compliant: ['Partially compliant', 'yellow', '#fab219'], not_compliant: ['Not compliant', 'red', '#d03b3b'], not_assessed: ['Not assessed', 'secondary', '#6b7280'], not_applicable: ['Not applicable', 'secondary', '#374151'] };
  var LV = { fully: ST.fully_compliant, partially: ST.partially_compliant, not: ST.not_compliant, not_assessed: ST.not_assessed, not_applicable: ST.not_applicable };
  try {
    if (!document.getElementById('zl-css')) {
      var st = document.createElement('style'); st.id = 'zl-css';
      st.textContent = '.zl-bar{display:flex;height:8px;border-radius:4px;overflow:hidden;background:rgba(255,255,255,.06);margin-top:6px}.zl-bar span{display:block;height:100%}'
        + '.zl-pcts{font-size:10.5px;margin-top:4px;line-height:1.35}.zl-pcts b{font-weight:700}.zl-card{display:block;width:100%;text-align:left;border:1px solid var(--tblr-border-color);border-left-width:4px;border-radius:8px;padding:8px 10px;background:transparent;color:inherit;height:100%}'
        + '.zl-legend{display:flex;flex-wrap:wrap;gap:10px;font-size:11.5px;margin-top:6px}.zl-legend i{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:4px;vertical-align:-1px}';
      document.head.appendChild(st);
    }
  } catch (e) { /* drawn without the extra styles */ }
  function label(st) { return (ST[st] || [st || '—'])[0]; }
  function badge(st) { var x = ST[st] || LV[st] || [st, 'secondary']; return '<span class="badge bg-' + x[1] + '-lt">' + esc(x[0]) + '</span>'; }
  function bar(n) {
    if (!n || !n.applicable) return '<div class="zl-bar"></div>';
    return '<div class="zl-bar">' + SEG.filter(function (g) { return n.pct[g[0]]; }).map(function (g) { return '<span style="width:' + n.pct[g[0]] + '%;background:' + g[1] + '" title="' + esc(g[2] + ': ' + n.pct[g[0]] + '% (' + n.counts[g[0]] + ' of ' + n.applicable + ')') + '"></span>'; }).join('') + '</div>';
  }
  function pcts(n) {
    if (!n || !n.applicable) return '<div class="zl-pcts text-secondary">not applicable</div>';
    return '<div class="zl-pcts">' + SEG.map(function (g) { return '<span class="me-2" style="color:' + g[1] + '">' + esc(g[2].replace(' compliant', '')) + ' <b>' + esc(n.pct[g[0]]) + '%</b></span>'; }).join('') + '</div>';
  }
  // the overall status and the four shares as tiles, with the item counts ("noun" = requirements / controls)
  function tiles(n, tile, noun) {
    if (!n) return '';
    var c = n.counts || {}, p = n.pct || {};
    return tile(label(n.status), 'Overall (fully / partially / not compliant)', n.status === 'fully_compliant' ? 'text-green' : n.status === 'not_compliant' ? 'text-red' : n.status === 'partially_compliant' ? 'text-yellow' : '')
      + tile((p.fully || 0) + '%', 'Fully compliant (' + (c.fully || 0) + ' ' + noun + ')', 'text-green') + tile((p.partially || 0) + '%', 'Partially compliant (' + (c.partially || 0) + ')', 'text-yellow')
      + tile((p.not || 0) + '%', 'Not compliant (' + (c.not || 0) + ')', c.not ? 'text-red' : '') + tile((p.not_assessed || 0) + '%', 'Not assessed yet (' + (c.not_assessed || 0) + ')');
  }
  // one card per group (domain / area): name, status, four-part bar and percentages; attr(g) adds a data attribute for clicks
  function groups(list, attr) {
    return '<div class="row g-2">' + (list || []).map(function (g) {
      return '<div class="col-6 col-md-4 col-xl-3"><button type="button" class="zl-card" style="border-left-color:' + ((ST[g.status] || [])[2] || '#6b7280') + '"' + (attr ? ' ' + attr(g) : '') + '><div class="d-flex justify-content-between gap-1"><b class="small text-truncate" title="' + esc(g.name) + '">' + esc(g.name) + '</b><span class="text-secondary" style="font-size:11px;white-space:nowrap">' + esc(label(g.status)) + '</span></div>' + bar(g) + pcts(g) + '</button></div>';
    }).join('') + '</div>';
  }
  function legend(note) { return '<div class="zl-legend">' + SEG.map(function (g) { return '<span><i style="background:' + g[1] + '"></i>' + esc(g[2]) + '</span>'; }).join('') + (note ? '<span class="text-secondary">' + esc(note) + '</span>' : '') + '</div>'; }
  window.zybLevels = { bar: bar, pcts: pcts, tiles: tiles, groups: groups, legend: legend, badge: badge, label: label };
})();
