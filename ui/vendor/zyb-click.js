// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
/* zyb-click.js - every KPI tile on every dashboard opens what it counts, without each page wiring it by hand. A tile the
 * page has not made interactive itself (no button, link, data-* action of its own) is matched by its label against what
 * the page holds, in this order:
 *   1. a filter option with the same meaning (tile "Overdue" -> the "Overdue" option of a filter): the filter is set and
 *      the list scrolled into view; clicking the tile again clears it. The active tile is outlined.
 *   2. a tab with that name -> the tab opens.
 *   3. a section with that heading -> it scrolls into view and is briefly highlighted.
 * A tile with nothing behind it stays as it is - it never pretends to be clickable. Reads nothing from the server,
 * changes nothing: it only uses the page's own filters, tabs and sections. Loaded by zyb-dash.js. */
(function () {
  'use strict';
  if (window.__zybClick) return; window.__zybClick = true;
  var TILE = '.k .t,.kpis .kpi,.noc-stat,.x-tile,.tiles .t,#tiles .t,#kk .t';
  var STOP = { the: 1, of: 1, and: 1, in: 1, on: 1, a: 1, an: 1, to: 1, with: 1, within: 1, days: 1, day: 1, all: 1, total: 1, count: 1, number: 1 };
  function words(s) {
    return String(s || '').toLowerCase().replace(/[\u2264\u2265<>]/g, ' ').replace(/[^a-z0-9\u0600-\u06ff]+/g, ' ').trim().split(' ')
      .filter(function (w) { return w && !STOP[w] && !/^\d+$/.test(w); }).map(function (w) { return w.length > 3 ? w.replace(/(ies)$/, 'y').replace(/s$/, '') : w; });
  }
  // how well a candidate's text means the tile's label: 3 same words, 2 one contains the other, 0 nothing
  function score(label, text) {
    var a = words(label), b = words(text); if (!a.length || !b.length) return 0;
    if (a.join(' ') === b.join(' ')) return 3;
    var has = function (x, y) { return x.every(function (w) { return y.indexOf(w) >= 0; }); };
    return has(a, b) || has(b, a) ? 2 : 0;
  }
  function labelOf(t) { var l = t.querySelector('.l,.lbl,.label,.k-l,.name,.title,.nm'); return (l ? l.textContent : (t.firstElementChild || t).textContent || '').trim(); }
  function own(t) {
    if (t.matches('button,a,[role=button],[onclick]') || t.closest('a,button')) return true;
    for (var i = 0; i < t.attributes.length; i++) { var n = t.attributes[i].name; if (n.indexOf('data-') === 0 && n !== 'data-zc') return true; }
    return !!t.querySelector('a,button,select,input');
  }
  function visible(el) { return !!(el.offsetParent || el.getClientRects().length); }
  function target(t) {
    var lab = labelOf(t); if (!lab || lab.length > 60) return null;
    var best = null, bs = 0;
    [].forEach.call(document.querySelectorAll('select'), function (s) {
      if (s.closest('#_dm,.zyb-drawer,[role=dialog]') || s.multiple) return;
      [].forEach.call(s.options, function (o) { if (!o.value) return; var sc = score(lab, o.textContent); if (sc > bs) { bs = sc; best = { kind: 'opt', el: s, value: o.value }; } });
    });
    if (best) return best;
    var tab = null;
    [].forEach.call(document.querySelectorAll('[role=tab],[data-tab],.tabs button'), function (b) { if (!tab && score(lab, b.textContent) >= 2) tab = b; });
    if (tab) return { kind: 'tab', el: tab };
    var sec = null;
    [].forEach.call(document.querySelectorAll('main h2,main h3,.card h2,.card h3'), function (h) { if (!sec && !t.contains(h) && score(lab, (h.firstChild && h.firstChild.textContent) || h.textContent) >= 2) sec = h; });
    if (sec) return { kind: 'sec', el: sec };
    return null;
  }
  function fire(el) { ['input', 'change'].forEach(function (n) { el.dispatchEvent(new Event(n, { bubbles: true })); }); }
  function go(t) {
    var g = target(t); if (!g) return;
    if (g.kind === 'opt') {
      var on = g.el.value === g.value; g.el.value = on ? (g.el.options[0] ? g.el.options[0].value : '') : g.value; fire(g.el);
      var card = g.el.closest('.card,section') || g.el; card.scrollIntoView({ behavior: 'smooth', block: 'start' });
    } else if (g.kind === 'tab') { if (!g.el.hidden) { g.el.click(); g.el.scrollIntoView({ behavior: 'smooth', block: 'nearest' }); } }
    else { var c = g.el.closest('.card,section') || g.el; c.scrollIntoView({ behavior: 'smooth', block: 'start' }); c.classList.remove('zc-flash'); void c.offsetWidth; c.classList.add('zc-flash'); }
    setTimeout(mark, 60);
  }
  function mark() {
    [].forEach.call(document.querySelectorAll(TILE), function (t) {
      if (own(t)) return;
      var g = target(t);
      if (!g) { if (t.getAttribute('data-zc')) { t.removeAttribute('data-zc'); t.removeAttribute('tabindex'); t.removeAttribute('role'); t.classList.remove('zc-on'); } return; }
      if (!t.getAttribute('data-zc')) {
        t.setAttribute('data-zc', g.kind); t.setAttribute('tabindex', '0'); t.setAttribute('role', 'button');
        t.title = g.kind === 'opt' ? 'Show these in the list (click again for all)' : g.kind === 'tab' ? 'Open this tab' : 'Go to this section';
      }
      t.classList.toggle('zc-on', g.kind === 'opt' && g.el.value === g.value);
    });
  }
  var st = document.createElement('style');
  st.textContent = '[data-zc]{cursor:pointer;transition:border-color .12s,transform .12s}[data-zc]:hover{border-color:#4a5162!important;transform:translateY(-1px)}[data-zc]:focus-visible{outline:2px solid var(--info,#79b8ff);outline-offset:2px}'
    + '.zc-on{border-color:var(--info,#79b8ff)!important;box-shadow:inset 0 0 0 1px var(--info,#79b8ff)}@keyframes zcf{0%{box-shadow:0 0 0 2px var(--info,#79b8ff)}100%{box-shadow:0 0 0 0 transparent}}.zc-flash{animation:zcf 1.4s ease-out}';
  (document.head || document.documentElement).appendChild(st);
  document.addEventListener('click', function (e) { var t = e.target.closest && e.target.closest('[data-zc]'); if (t) go(t); });
  document.addEventListener('keydown', function (e) { if (e.key !== 'Enter' && e.key !== ' ') return; var t = e.target.closest && e.target.closest('[data-zc]'); if (t) { e.preventDefault(); go(t); } });
  document.addEventListener('change', function (e) { if (e.target && e.target.tagName === 'SELECT') setTimeout(mark, 30); }, true);
  var pend = 0;
  function soon() { if (pend) return; pend = setTimeout(function () { pend = 0; mark(); }, 120); }
  function start() { mark(); try { new MutationObserver(soon).observe(document.body, { childList: true, subtree: true }); } catch (e) { /* old browser: marked once */ } }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start); else start();
})();
