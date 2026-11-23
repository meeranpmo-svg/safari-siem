// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
/* zyb-tiles.js - every KPI tile in the portal opens the records behind its number. A tile is matched by its label
 * (Open alarms, Critical, SLA breached, Open offences, Log sources, Silent, Events indexed, Auto-handled 24h ...) and a
 * click (or Enter) opens the page that lists exactly those records, with the filter set: the Alarm Inbox filtered to
 * critical / SLA-breached / unassigned alarms, the SIEM alert queue, cases or log sources filtered the same way, a SIEM
 * search over the period. Clicking a tile that is already the active filter clears it. Tiles with no page behind them
 * Any other tile opens what it counts on its own page: the tab, the rows of the table that carry its word (click
 * again for all), the section, or the page in the menu (auto()). Reads nothing,
 * writes nothing - it only navigates. Loaded by zyb-menu.js. */
(function () {
  'use strict';
  if (window.__zybTiles) return; window.__zybTiles = true;
  var SEL = '.noc-stat,.x-tile,.cc-k,.kpi,[class$="-tile"],[class*="-tile "]';
  var EXTRA = '', ALM0 = { status: 'open', sev: 'all', minRbp: 0, q: '', mine: false, covered: false };
  /* globals of the portal's app.js are lexical (let / function), reachable by name from here but not through window */
  function cur() { try { return currentView; } catch (e) { return ''; } }                                   // eslint-disable-line no-undef
  function go(v) { try { if (cur() === v) renderFocus(); else setView(v); } catch (e) { /* view not in this build */ } } // eslint-disable-line no-undef
  function almF() { try { return _alarmFilter; } catch (e) { return null; } }                                // eslint-disable-line no-undef
  function hasSoc() { return typeof window.asSocTile === 'function'; }

  /* Alarm Inbox: filters it has (status / severity / mine / covered) are set directly; SLA-breached and unassigned are
     applied on top of its own filter list (EXTRA), and cleared as soon as the analyst changes a filter themselves. */
  try {
    var origVis = _alarmVisible;                                                                              // eslint-disable-line no-undef
    _alarmVisible = function () {                                                                             // eslint-disable-line no-undef
      var r = origVis.apply(this, arguments);
      try {
        if (EXTRA === 'breached') r = r.filter(function (a) { return _alarmBreached(a); });                  // eslint-disable-line no-undef
        else if (EXTRA === 'unassigned') r = r.filter(function (a) { return !a.owner; });
        else if (EXTRA === 'covered') r = r.filter(function (a) { return a.coveredBy; });
      } catch (e) { /* keep the inbox's own list */ }
      return r;
    };
  } catch (e) { /* this portal build has no Alarm Inbox */ }
  function almSame(f, x) { var a = almF(); if (!a) return false; for (var k in ALM0) if (String(a[k]) !== String(f[k] === undefined ? ALM0[k] : f[k])) return false; return EXTRA === (x || ''); }
  function alm(f, x) {
    return {
      on: function () { return cur() === 'alarms' && almSame(f, x); },
      go: function () {
        var a = almF(); if (!a) return go('alarms');
        var off = cur() === 'alarms' && almSame(f, x), n = off ? ALM0 : Object.assign({}, ALM0, f);
        for (var k in ALM0) a[k] = n[k];
        EXTRA = off ? '' : (x || ''); go('alarms');
      },
    };
  }
  var SOCV = { al: 'soc-alerts', ca: 'soc-cases', ru: 'soc-rules', so: 'soc-sources' };
  /* SIEM module: the current module exposes asSocTile (same filters as its own tiles). An older copy of the module in the
     portal does not, so its own filter controls are set instead - exactly what an analyst would click. */
  var SOCDOM = {
    'al:open': [['socaf', 'status', 'open'], ['socaf', 'sev', '0'], ['socaf', 'who', 'any']], 'al:crit': [['socaf', 'status', 'open'], ['socaf', 'sev', '3'], ['socaf', 'who', 'any']],
    'al:new': [['socaf', 'status', 'new'], ['socaf', 'sev', '0'], ['socaf', 'who', 'any']], 'al:all': [['socaf', 'status', 'all'], ['socaf', 'sev', '0'], ['socaf', 'who', 'any']],
    'al:none': [['socaf', 'status', 'open'], ['socaf', 'sev', '0'], ['socaf', 'who', 'none']],
    'ca:active': [['soccf', 'status', 'active']], 'ca:sla': [['soccf', 'status', 'active']],
    'ru:all': [['socrf', '1', 'all']], 'ru:noisy': [['socrf', '1', 'noisy']],
    'so:all': [['socsf', 'all']], 'so:silent': [['socsf', 'silent']], 'so:errors': [['socsf', 'errors']], 'so:ok': [['socsf', 'ok']],
  };
  function socDom(act) {
    var steps = (SOCDOM[act] || []).slice(), tries = 0;
    go(SOCV[act.split(':')[0]]);
    (function next() {
      if (!steps.length) return;
      var s = steps[0], el = s.length === 2 ? document.querySelector('[data-' + s[0] + '="' + s[1] + '"]') : document.querySelector('select[data-' + s[0] + '="' + s[1] + '"]');
      if (!el) { if (++tries < 30) setTimeout(next, 100); return; }
      steps.shift(); tries = 0;
      if (s.length === 2) { if (!el.classList.contains('on')) el.click(); }
      else if (el.value !== s[2] && [].some.call(el.options, function (o) { return o.value === s[2]; })) { el.value = s[2]; el.dispatchEvent(new Event('change', { bubbles: true })); }
      setTimeout(next, 150);
    })();
  }
  function soc(act) { return { go: function () { if (hasSoc()) window.asSocTile(act); else socDom(act); } }; }
  function search(q, range) { return { go: function () { if (typeof window.asSocSearch === 'function') window.asSocSearch(q, range || period()); else go('soc-search'); } }; }
  function view(v) { return { go: function () { go(v); } }; }
  /* a tile whose records are listed further down the same page: scroll to that card (found by its icon, which is the
     same in English and Arabic) and, for a severity tile, show only the rows of that severity - click again for all */
  var ONPAGE = '', ONCARD = null;
  function card(anchor, rowRe, col) {
    var key = String(anchor) + (rowRe ? rowRe.source : '');
    function target() {
      if (typeof anchor === 'string') { var h = [].filter.call(document.querySelectorAll('.card h3, .x-card h3'), function (x) { return x.textContent.indexOf(anchor) >= 0; })[0]; return h ? h.closest('.card,.x-card') : null; }
      var t = [].filter.call(document.querySelectorAll('.section-title'), function (x) { return anchor.test(x.textContent); })[0], n = t && t.nextElementSibling;
      for (var i = 0; n && i < 3; i++, n = n.nextElementSibling) { if (n.matches('table') || n.querySelector('table')) return n; if (n.classList.contains('section-title')) break; }
      return t || null;
    }
    return {
      on: function () { if (ONCARD && !ONCARD.isConnected) { ONPAGE = ''; ONCARD = null; } return ONPAGE === key; },
      go: function () {
        var c = target(); if (!c) return; var off = ONPAGE === key && ONCARD === c;
        if (ONCARD && ONCARD !== c && ONCARD.isConnected) [].forEach.call(ONCARD.querySelectorAll('tbody tr'), function (tr) { tr.style.display = ''; });
        ONPAGE = off ? '' : key; ONCARD = off ? null : c;
        [].forEach.call(c.querySelectorAll('tbody tr'), function (tr) { var cell = tr.cells[col || 0]; tr.style.display = !off && rowRe && tr.cells.length > 1 && cell && !rowRe.test(cell.textContent) ? 'none' : ''; });
        var top = c.previousElementSibling && c.previousElementSibling.classList.contains('section-title') ? c.previousElementSibling : c;
        top.scrollIntoView({ behavior: 'smooth', block: 'start' }); c.style.transition = 'box-shadow .3s'; c.style.boxShadow = '0 0 0 2px var(--accent2,#4D8DFF)'; setTimeout(function () { c.style.boxShadow = ''; }, 1600);
      },
    };
  }
  /* Automation Agents: show only the agent cards that match (findings needing action = a red finding, awaiting approval =
     the agent has queued work, auto-handled = it acted this cycle); click again to show all agents */
  var AGF = '';
  function agents(kind, test) {
    return {
      on: function () { return AGF === kind && !!document.querySelector('.as-agent[data-zybhid]'); },
      go: function () {
        var off = AGF === kind; AGF = off ? '' : kind; var first = null;
        [].forEach.call(document.querySelectorAll('.as-agent'), function (c) { var show = off || test(c); c.style.display = show ? '' : 'none'; if (show) c.removeAttribute('data-zybhid'); else c.setAttribute('data-zybhid', '1'); if (show && !first) first = c; });
        if (first) first.scrollIntoView({ behavior: 'smooth', block: 'start' });
      },
    };
  }
  function hasDot(c, hex) { return [].some.call(c.querySelectorAll('span'), function (x) { return x.textContent === '●' && (x.getAttribute('style') || '').toLowerCase().indexOf(hex) >= 0; }); }
  function click(sel) { return { go: function () { var b = document.querySelector(sel); if (b) b.click(); } }; }

  /* a page tab (data-*tab button), then optionally the section under it */
  function tab(k, then) {
    return { go: function () {
      var b = [].filter.call(document.querySelectorAll('#viewFocus button'), function (x) { return [].some.call(x.attributes, function (a) { return /^data-[a-z0-9]*tab$/.test(a.name) && a.value === k; }); })[0];
      if (b) b.click();
      if (then) setTimeout(function () { var h = [].filter.call(document.querySelectorAll('#viewFocus .section-title, #viewFocus h3'), function (x) { return then.test(x.textContent); })[0]; if (h) flash(h); }, 80);
    } };
  }
  function flash(el) { var c = el.closest('.card,.x-card') || el; try { c.scrollIntoView({ behavior: 'smooth', block: 'start' }); } catch (e) { c.scrollIntoView(); } c.style.transition = 'box-shadow .3s'; c.style.boxShadow = '0 0 0 2px var(--accent2,#4D8DFF)'; setTimeout(function () { c.style.boxShadow = ''; }, 1600); }

  /* EVERY other tile: worked out from the page itself, so a tile added later is clickable without an entry here.
     Order: a tab of this page whose name shares a word with the tile → the rows of a table below that carry the tile's
     word (shown alone, click again for all) → a section heading below → a page in the menu → the first table / card
     below the tiles. It only points at what the portal already shows; a tile with nothing to point at stays plain. */
  var STOP = { the: 1, a: 1, an: 1, of: 1, by: 1, to: 1, in: 1, on: 1, for: 1, and: 1, or: 1, with: 1, from: 1, at: 1, this: 1, last: 1, total: 1, all: 1, ahead: 1, now: 1, '24h': 1, '7d': 1, '30d': 1, days: 1 };
  function words(s) { return String(s || '').toLowerCase().replace(/[^a-z0-9\s-]/g, ' ').split(/[\s-]+/).filter(function (w) { return w.length > 1 && !STOP[w] && !/^\d+$/.test(w); }); }
  function stem(w) { return w.replace(/ies$/, 'y').replace(/(ses|xes)$/, 's').replace(/([^s])s$/, '$1'); }
  function overlap(a, b) { var A = a.map(stem), n = 0; b.map(stem).forEach(function (w) { if (A.indexOf(w) >= 0) n++; }); return n; }
  function after(el, x) { return !!(el.compareDocumentPosition(x) & Node.DOCUMENT_POSITION_FOLLOWING); }
  function rootOf(el) { return el.closest('#_dm, .modal, [role=dialog]') || document.getElementById('viewFocus') || document.body; }
  function best(list, w, min) { var b = null, bs = min || 0; list.forEach(function (x) { var s = overlap(words(x.textContent), w); if (s > bs) { bs = s; b = x; } }); return b; }
  // "Compliant" is not "Non-compliant". No regex lookbehind: Safari before 16.4 throws on it, so the word before is checked by hand.
  function rx(p) { var e = p.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/\s+/g, '[\\s_-]+'), re = new RegExp('(^|[^a-z0-9])' + e + 's?(?=$|[^a-z0-9])', 'gi');
    return { test: function (s) { s = String(s == null ? '' : s); re.lastIndex = 0; var m; while ((m = re.exec(s))) { var at = m.index + m[1].length; if (!/no[nt][\s_-]$/i.test(s.slice(Math.max(0, at - 4), at))) return true; re.lastIndex = m.index + 1; } return false; } }; }
  var AUTOKEY = '', AUTOT = null;
  function unfilter() { if (AUTOT && AUTOT.isConnected) [].forEach.call(AUTOT.querySelectorAll('tbody tr[data-zybf]'), function (tr) { tr.style.display = ''; tr.removeAttribute('data-zybf'); }); AUTOKEY = ''; AUTOT = null; }
  function auto(el, l) {
    var w = words(l); if (!w.length) return null;
    var root = rootOf(el), v = cur();
    // 1 a tab of this page
    var tabs = [].filter.call(root.querySelectorAll('button,[role=tab]'), function (b) { return b.getAttribute('role') === 'tab' || [].some.call(b.attributes, function (a) { return /^data-[a-z0-9]*tab$/.test(a.name); }); });
    var tb = best(tabs, w);
    if (tb && /\bghost\b/.test(tb.className)) return { go: function () { unfilter(); tb.click(); } };
    // 2 rows of a table below carrying the label (the whole label, or its words when it is one or two words)
    var phrases = [w.join(' ')]; if (w.length <= 2) w.forEach(function (x) { if (x.length > 2 && phrases.indexOf(x) < 0) phrases.push(x); });
    var tables = [].filter.call(root.querySelectorAll('table'), function (t) { return after(el, t) && t.tBodies[0] && t.tBodies[0].rows.length > 1; });
    var whole = /^(total|all|registered|entities|recorded|distinct)\b/i.test(l); // counts the whole table: scroll to it, filter nothing
    for (var i = 0; !whole && i < phrases.length; i++) {
      var re = rx(phrases[i]);
      for (var j = 0; j < tables.length; j++) {
        var rows = [].filter.call(tables[j].tBodies[0].rows, function (r) { return r.cells.length > 1; }), hit = rows.filter(function (r) { return re.test(r.textContent); });
        if (hit.length && hit.length < rows.length) return (function (tbl, rows, hit, key) {
          return { on: function () { return AUTOKEY === key && AUTOT === tbl && tbl.isConnected; },
            go: function () { var off = AUTOKEY === key && AUTOT === tbl; unfilter(); if (!off) { AUTOKEY = key; AUTOT = tbl; rows.forEach(function (r) { if (hit.indexOf(r) < 0) { r.style.display = 'none'; r.setAttribute('data-zybf', '1'); } }); } flash(tbl); } };
        })(tables[j], rows, hit, v + '|' + l);
      }
    }
    // 3 a section heading below
    var hd = best([].filter.call(root.querySelectorAll('.section-title, h2, h3, h4, .card-title'), function (h) { return after(el, h) && !h.closest(SEL); }), w);
    if (hd) return { go: function () { flash(hd); } };
    // 4 a page in the menu that is about this (at least two shared words, or the whole one-word label)
    var nav = best([].filter.call(document.querySelectorAll('li[data-view]'), function (li) { return li.getAttribute('data-view') !== v && li.offsetParent !== null; }), w, Math.min(2, w.length) - 1);
    if (nav) return view(nav.getAttribute('data-view'));
    // 5 the first table / card below the tiles
    var first = [].filter.call(root.querySelectorAll('table, .card, .x-card'), function (x) { return after(el, x) && !x.closest(SEL) && !x.querySelector(SEL); })[0];
    if (first) return { go: function () { flash(first); } };
    return null;
  }

  /* [view the tile is on (null = any), label pattern, target]. First match wins; labels are compared in lower case. */
  var MAP = [
    ['notify', /^policies$/, tab('policies')],
    ['notify', /^people reachable$|^rota entries ahead$/, tab('groups')],
    ['notify', /^maintenance windows$/, tab('maint')],
    ['notify', /^accepted by the hub$/, tab('log', /delivery receipts/i)],
    ['notify', /^not sent$/, tab('log', /routing|decid/i)],
    ['agents', /^findings needing action$/, agents('bad', function (c) { return hasDot(c, '#e8556b'); })],
    ['agents', /^findings this cycle$/, agents('any', function (c) { return [].some.call(c.querySelectorAll('span'), function (x) { return x.textContent === '●'; }); })],
    ['agents', /^awaiting approval$/, click('[data-agqueue]')],
    ['agents', /^actions auto-handled$/, agents('auto', function (c) { return [].some.call(c.querySelectorAll('.stpill.ok'), function (x) { return parseInt(x.textContent, 10) > 0; }); })],
    ['agents', /^agents enabled$/, agents('on', function (c) { var i = c.querySelector('[data-agon]'); return !i || i.checked; })],
    ['agents', /^completed a cycle$/, card('📜')],
    ['siemlive', /^critical alarms?$/, card('🚨', /critical/i)],
    ['siemlive', /^high alarms?$/, card('🚨', /high/i)],
    ['siemlive', /^open alarms?/, card('🚨')],
    ['siemlive', /^events in window$/, card('📜')],
    ['siemlive', /^active sources$/, card('🎯')],
    ['soc', /^open incidents$/, card(/active security incidents/i)],
    ['soc', /^critical$/, card(/active security incidents/i, /critical/i, 1)],
    ['soc', /^threats blocked/, card(/live threat feed/i, /block|clean|quarantin|isolat/i, 5)],
    [null, /^open incidents$/, view('ir')],
    [null, /^(threats )?blocked( 24h| \(24h\))?$|^threats blocked/, view('security')],
    [null, /^(phishing blocked|malware blocked)/, view('m365sec')],
    [null, /^risky users$/, view('m365sec')],
    [null, /^secure score$/, view('m365sec')],
    [null, /^mfa (coverage|registration)$|^users without mfa$/, view('m365sec')],
    [null, /^rogue devices$/, view('rogue')],
    [null, /^live feeds$/, view('status')],
    [null, /^m365 users$|^user accounts$/, view('users')],
    [null, /^phones registered$/, view('voip')],
    [null, /^inventory assets$/, view('itam')],
    [null, /^vms running$|^virtual machines$/, view('virtualization')],
    ['alarms', /^open alarms?$/, alm({})],
    ['alarms', /^critical$/, alm({ sev: 'critical' })],
    ['alarms', /^high$/, alm({ sev: 'high' })],
    ['alarms', /^medium$/, alm({ sev: 'medium' })],
    ['alarms', /^low$/, alm({ sev: 'low' })],
    ['alarms', /^sla breached$/, alm({}, 'breached')],
    ['alarms', /^unassigned$/, alm({}, 'unassigned')],
    ['alarms', /^mine$/, alm({ mine: true })],
    ['alarms', /^covered by a rule$/, alm({ covered: true }, 'covered')],
    ['alarms', /^closed/, alm({ status: 'closed' })],
    [null, /^critical alarms?$/, alm({ sev: 'critical' })],
    [null, /^high alarms?$/, alm({ sev: 'high' })],
    [null, /^open alarms?\b/, alm({})],
    [null, /^(alarms? )?sla breach(ed|es)?$/, alm({}, 'breached')],
    [null, /^unassigned alarms?$/, alm({}, 'unassigned')],
    [null, /^open offen[cs]es$/, soc('al:open')],
    [/^(home|overview|command)$/, /^critical$/, soc('al:crit')],
    [/^dash-soc$|^socoverview$|^siemlive$|^soc$|^security$/, /^critical$/, soc('al:crit')],
    [null, /^open alerts$/, soc('al:open')],
    [null, /^(critical or high|critical\/high)(, open)?( alerts)?$/, soc('al:crit')],
    [null, /^(new|unacknowledged) alerts$/, soc('al:new')],
    [/^soc-attack-summary$/, /^alerts$/, soc('al:all')],
    [null, /^(open cases|cases open)$/, soc('ca:active')],
    [null, /^(sla overdue|overdue cases)$/, soc('ca:sla')],
    [null, /^(log source coverage|log sources|active sources|hosts reporting|sources reporting|reporting sources)$/, soc('so:all')],
    ['soc-sources', /^reporting$/, soc('so:ok')],
    [null, /^(silent( sources| log sources)?|sources silent)$/, soc('so:silent')],
    [null, /^parse errors$/, soc('so:errors')],
    [null, /^(events indexed|events in window|security events|events today|events per second.*|eps)$/, search('')],
    [null, /^(actions )?auto-handled( 24h)?$/, view('soar')],
    [null, /^(automation agents)$/, view('agents')],
    [null, /^monitoring model$/, view('soc-after-hours')],
    [null, /^retention$/, view('soc-sources')],
    [null, /^(detection rules|rules)$/, soc('ru:all')],
    [null, /^noisy rules$/, soc('ru:noisy')],
  ];
  function label(el) {
    var k = el.querySelector(':scope > .k, :scope > .l, :scope > .k-label, :scope > .lbl, :scope > .label, :scope > .x-small');
    var txt = (k ? k.textContent : '').replace(/\s+/g, ' ').trim();
    return (rev()[txt] || txt).toLowerCase();
  }
  /* Arabic: the label on screen is the translation, so map it back to the English key through the portal's dictionaries */
  var REV = null;
  function rev() {
    var n = window.X_AR ? Object.keys(window.X_AR).length : 0;
    if (REV && REV.__n === n) return REV; REV = { __n: n };
    var add = function (d) { if (d && typeof d === 'object') for (var k in d) if (typeof d[k] === 'string') REV[d[k].trim()] = k; };
    try { add(AR); } catch (e) { /* no base dictionary */ }                                                   // eslint-disable-line no-undef
    add(window.X_AR); return REV;
  }
  function find(el) {
    var l = label(el), v = cur(); if (!l) return null;
    for (var i = 0; i < MAP.length; i++) { var m = MAP[i]; if (m[0] && !(typeof m[0] === 'string' ? m[0] === v : m[0].test(v))) continue; if (m[1].test(l)) return m[2]; }
    return auto(el, l);
  }
  /* a tile that already does something (its own filter, link or handler) is left alone */
  function owned(el) { return el.onclick || el.hasAttribute('data-kpi-go') || el.hasAttribute('data-go') || el.hasAttribute('data-almchip') || el.hasAttribute('data-soct') || el.hasAttribute('data-view') || el.closest('a,button,[onclick],[data-soct],[data-almchip]') || el.querySelector('a,button,select,input'); }
  function scan() {
    var list = document.querySelectorAll(SEL);
    for (var i = 0; i < list.length; i++) {
      var el = list[i]; if (el.getAttribute('data-zybt') === 'no') continue;
      if (owned(el)) { if (el.getAttribute('data-zybt') === '1') { el.classList.remove('zyb-ct', 'on'); el.removeAttribute('aria-pressed'); } el.setAttribute('data-zybt', 'no'); continue; }
      var t = find(el);
      if (!t) { if (el.getAttribute('data-zybt') === '1') { el.classList.remove('zyb-ct', 'on'); el.removeAttribute('data-zybt'); el.removeAttribute('role'); el.removeAttribute('tabindex'); } continue; }
      if (!el.hasAttribute('data-zybt')) { el.setAttribute('data-zybt', '1'); el.setAttribute('role', 'button'); el.setAttribute('tabindex', '0'); el.classList.add('zyb-ct'); }
      var on = !!(t.on && t.on()); el.classList.toggle('on', on); el.setAttribute('aria-pressed', on ? 'true' : 'false');
      el.title = on ? 'Showing these - click to clear' : 'Click to show these';
    }
  }
  function fire(el) { var t = find(el); if (!t) return; try { t.go(); } catch (e) { /* never break the page */ } setTimeout(scan, 60); }
  document.addEventListener('click', function (ev) { var el = ev.target.closest && ev.target.closest('[data-zybt="1"]'); if (el && !ev.target.closest('a,button,select,input')) fire(el); });
  /* a table row whose only action is its 🔎 button (SIEM log sources: search this source's events) opens on a click
     anywhere in the row, not just on the small button */
  var ROWBTN = 'button[data-socsrcq]';
  document.addEventListener('click', function (ev) {
    var t = ev.target; if (!t.closest || t.closest('a,button,select,input,label,[data-zybt="1"]')) return;
    var tr = t.closest('tr'), b = tr && tr.querySelector(ROWBTN); if (b) b.click();
  });
  document.addEventListener('keydown', function (ev) { if ((ev.key === 'Enter' || ev.key === ' ') && ev.target && ev.target.getAttribute && ev.target.getAttribute('data-zybt') === '1') { ev.preventDefault(); fire(ev.target); } });
  /* the analyst's own change of an inbox filter replaces a tile's extra filter */
  document.addEventListener('change', function (ev) { if (EXTRA && cur() === 'alarms' && ev.target && /^(SELECT|INPUT)$/.test(ev.target.tagName) && !ev.target.closest('[data-zybt]')) EXTRA = ''; }, true);
  var st = document.createElement('style');
  st.textContent = 'tr:has(' + ROWBTN + '){cursor:pointer}tr:has(' + ROWBTN + '):hover td{background:rgba(255,255,255,.035)}.zyb-ct{cursor:pointer;transition:transform .15s,border-color .15s,box-shadow .15s}.zyb-ct:hover{transform:translateY(-1px);border-color:var(--accent2,#4D8DFF)!important}'
    + '.zyb-ct:focus-visible{outline:2px solid #fff;outline-offset:2px}.zyb-ct.on{box-shadow:inset 0 0 0 2px var(--accent2,#4D8DFF),0 0 0 3px rgba(77,141,255,.16)!important}';
  document.head.appendChild(st);
  var tm = 0, mo = new MutationObserver(function () { clearTimeout(tm); tm = setTimeout(scan, 120); });
  function start() { scan(); mo.observe(document.body, { childList: true, subtree: true }); }
  if (document.body) start(); else document.addEventListener('DOMContentLoaded', start);
})();
