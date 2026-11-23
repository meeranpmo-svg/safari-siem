// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
/* zyb-navsplit.js - the portal's catch-all "More" group (43 pages: APM, ITAM, discovery, SIEM, automation and odd pages
 * that modules inserted after an item that happened to sit there) becomes one main menu group per FUNCTION.
 *
 * Each page in "More" is moved to the first group in SPLIT whose rule matches its label or view id. A group that already
 * exists in the portal under that name (or one of its aliases) receives the pages; otherwise it is created where "More"
 * was, in SPLIT order, looking like the portal's own headings (the "More" heading is cloned). Pages that match nothing
 * stay together under "Other tools", alphabetical. Pages are moved, never copied or hidden, and nothing outside "More" /
 * "Other tools" is touched, so a page that is already in a real group stays where it is.
 *
 * Runs at load and again when the menu changes (modules add their pages late): a page a module adds after an anchor
 * that is now in a new group lands in that group by itself; one that lands in "Other tools" is re-homed on the next pass.
 * After moving, the portal's collapse tree is rebuilt (initNavTree, when the portal has it) with the new groups closed on
 * a first visit; without it each new heading gets its own open / close toggle. The admin menu order (zyb-menu.js) can
 * then order the new groups like any other. */
(function () {
  'use strict';
  if (window.__zybNavSplit) return; window.__zybNavSplit = true;
  var SPLIT = [
    { name: 'Application Performance (APM)', ar: 'أداء التطبيقات', also: [], rx: /\b(apm|service map|services? and traces|traces?|tracing|synthetic|real[- ]user|rum|service[- ]level|slos?|discovered applications?|transactions?)\b/i, view: /^apm/i },
    { name: 'IT Asset Management', ar: 'إدارة أصول تقنية المعلومات', also: ['ITAM', 'Assets & Licences', 'IT Assets'], rx: /\b(itam|cmdb|stocktake|software (and|&) licen[cs]es?|licen[cs]es?|asset register|inventory)\b/i, view: /^itam/i },
    { name: 'Discovery & Onboarding', ar: 'الاكتشاف والإضافة', also: [], rx: /\b(discovery|add devices?|bulk|onboard\w*|scopes?|credentials)\b/i, view: /^discovery/i },
    { name: 'Security Operations (SIEM)', ar: 'العمليات الأمنية', also: ['Security Operations (SOC)', 'Security Operations', 'SIEM'], rx: /\b(siem|soc|alert queue|event search|detection (rules|validation)|log sources?|cases|xdr|ueba|threat|attack simulation)\b/i, view: /^(soc-|siem|detection|xdr|ueba)/i },
    { name: 'Infrastructure Automation', ar: 'أتمتة البنية التحتية', also: [], rx: /\b(infrastructure automation|automation|linux hosts?|config(uration)? backups?|drift|probes?)\b/i, view: /^infra-/i },
    { name: 'Network & Servers', ar: 'الشبكات والخوادم', also: ['Network', 'Servers & Cloud'], rx: /\b(network|switch\w*|firewalls?|wi-?fi|wireless|sd-?wan|servers?|virtual\w*|storage|backups?|databases?)\b/i, view: null },
    { name: 'Governance & Compliance', ar: 'الحوكمة والامتثال', also: ['Compliance', 'Governance & Compliance'], rx: /\b(complian\w*|grc|polic(y|ies)|audit|risks?|sama|nca|pdpl|controls?)\b/i, view: null },
    { name: 'Platform & Settings', ar: 'المنصة والإعدادات', also: ['Reports & Administration', 'Platform Administration'], rx: /\b(settings?|admin\w*|integrations?|platform|users?|roles?|health)\b/i, view: null },
  ];
  var CATCH = /^(more|more items|others?|other tools|المزيد|أخرى|أدوات أخرى)$/i, OTHER = 'Other tools', busy = false, timer = null;

  function nav() { return document.querySelector('ul.nav'); }
  function isHead(li) { return li.classList && li.classList.contains('nav-group'); }
  function gname(h) { var c = h.cloneNode(true); [].forEach.call(c.querySelectorAll('.chev,.zyb-chev,.badge,.zyb-cnt,.zyb-mv,.zyb-star,svg'), function (x) { x.remove(); });
    return (h.getAttribute('data-en') || c.textContent || '').replace(/[▸▾▼►▶▲△▽]/g, '').trim().replace(/^[^A-Za-z\u0600-\u06FF]+/, '').replace(/\s*\d+\s*$/, '').trim(); }
  function label(li) { var c = li.cloneNode(true); [].forEach.call(c.querySelectorAll('.ico,.badge,.zyb-star,.zyb-mv'), function (x) { x.remove(); }); return (li.getAttribute('data-en') || c.textContent || '').trim(); }
  function blocks(n) { var out = [], cur = null; [].forEach.call(n.children, function (li) { if (isHead(li)) { cur = { h: li, name: gname(li), kids: [] }; out.push(cur); } else if (cur && li.tagName === 'LI' && (li.getAttribute('data-view') || li.getAttribute('data-zyb-href'))) cur.kids.push(li); }); return out; }
  function home(li) { var hay = label(li), v = li.getAttribute('data-view') || ''; for (var i = 0; i < SPLIT.length; i++) if (SPLIT[i].rx.test(hay) || (SPLIT[i].view && SPLIT[i].view.test(v))) return SPLIT[i]; return null; }
  function tr(en, ar) { try { var D = window.X_AR = window.X_AR || {}; if (!(en in D)) D[en] = ar; if (typeof AR !== 'undefined' && !(en in AR)) AR[en] = ar; } catch (e) { /* portal function not available on this page: carry on without it */ } }

  // a heading that looks like the portal's own: the "More" heading cloned (listeners are not cloned), label and count replaced
  function makeHead(tpl, name) {
    var h = tpl.cloneNode(true);
    h.removeAttribute('id'); h.classList.remove('open'); h.setAttribute('data-en', name); h.setAttribute('data-zyb-split', '1');
    var done = false, walk = document.createTreeWalker(h, NodeFilter.SHOW_TEXT, null);
    for (var t = walk.nextNode(); t; t = walk.nextNode()) { if (!done && CATCH.test(t.nodeValue.trim())) { t.nodeValue = t.nodeValue.replace(t.nodeValue.trim(), name); done = true; } }
    if (!done) { var lab = document.createTextNode(name); h.insertBefore(lab, h.firstChild); }
    return h;
  }
  function setCount(h, n) { var walk = document.createTreeWalker(h, NodeFilter.SHOW_TEXT, null); for (var t = walk.nextNode(); t; t = walk.nextNode()) { if (/^\s*\d+\s*$/.test(t.nodeValue)) { t.nodeValue = t.nodeValue.replace(/\d+/, String(n)); return; } } }

  function split() {
    var n = nav(); if (!n || busy) return 0;
    var bs = blocks(n), more = bs.filter(function (b) { return CATCH.test(b.name) && b.h.getAttribute('data-zyb-menu') == null; });
    if (!more.length) return 0;
    busy = true; var moved = 0, created = [];
    try {
      var byName = {}; bs.forEach(function (b) { byName[b.name.toLowerCase()] = b; });
      more.forEach(function (m) {
        var plan = {}, left = [];
        m.kids.forEach(function (li) { var g = home(li); if (g) (plan[g.name] = plan[g.name] || []).push(li); else left.push(li); });
        // new groups take the place of "More": each one (heading + pages) goes just before the old heading, in SPLIT order
        SPLIT.forEach(function (g) {
          var lis = plan[g.name]; if (!lis) return;
          tr(g.name, g.ar);
          var dest = [g.name].concat(g.also).map(function (x) { return byName[x.toLowerCase()]; }).filter(function (b) { return b && b !== m && !CATCH.test(b.name); })[0];
          if (dest) { var last = dest.kids.length ? dest.kids[dest.kids.length - 1] : dest.h; lis.forEach(function (li) { last.parentNode.insertBefore(li, last.nextSibling); last = li; dest.kids.push(li); moved++; }); setCount(dest.h, dest.kids.length); return; }
          var h = makeHead(m.h, g.name); n.insertBefore(h, m.h);
          lis.forEach(function (li) { n.insertBefore(li, m.h); moved++; });
          setCount(h, lis.length); byName[g.name.toLowerCase()] = { h: h, name: g.name, kids: lis.slice() }; created.push(g.name);
        });
        // what matched nothing: one "Other tools" group, alphabetical, after the new groups (a cloned heading: no stale handler)
        if (left.length) {
          left.sort(function (a, b) { return label(a).localeCompare(label(b)); });
          var oh = makeHead(m.h, OTHER); tr(OTHER, 'أدوات أخرى');
          n.insertBefore(oh, m.h); left.forEach(function (li) { n.insertBefore(li, m.h); });
          setCount(oh, left.length); created.push(OTHER);
        }
        m.h.remove();
      });
      if (moved || created.length) rebuildTree(n, created);
    } catch (e) { /* never break the menu */ }
    setTimeout(function () { busy = false; }, 0);
    return moved;
  }

  function rebuildTree(n, created) {
    var saved = {}; try { saved = JSON.parse(localStorage.getItem('nav_tree') || '{}') || {}; } catch (e) { /* browser storage blocked (private window): the page works without it */ }
    created.forEach(function (name) { if (!Object.prototype.hasOwnProperty.call(saved, name)) saved[name] = false; });   // closed on a first visit, like the portal's own groups
    try { localStorage.setItem('nav_tree', JSON.stringify(saved)); } catch (e) { /* browser storage blocked (private window): the page works without it */ }
    if (typeof window.initNavTree === 'function') { try { n._tree = false; window.initNavTree(); return; } catch (e) { /* portal function not available on this page: carry on without it */ } }
    // no portal tree code: our own toggle on the headings we made
    [].forEach.call(n.querySelectorAll('li.nav-group[data-zyb-split]'), function (h) {
      if (h._zybSplitT) return; h._zybSplitT = true;
      var name = h.getAttribute('data-en');
      var set = function (open) { h.classList.toggle('open', open); var x = h.nextElementSibling; while (x && !isHead(x)) { x.classList.toggle('tree-hidden', !open); x = x.nextElementSibling; } };
      set(!!saved[name]); h.style.cursor = 'pointer';
      h.addEventListener('click', function (e) { e.preventDefault(); e.stopPropagation(); var o = !h.classList.contains('open'); set(o); try { var s = JSON.parse(localStorage.getItem('nav_tree') || '{}') || {}; s[name] = o; localStorage.setItem('nav_tree', JSON.stringify(s)); } catch (er) { /* browser storage blocked (private window): the page works without it */ } }, true);
    });
  }

  function start() {
    var n = nav(); if (!n) { setTimeout(start, 300); return; }
    split();
    if (window.MutationObserver) new MutationObserver(function () { if (busy) return; clearTimeout(timer); timer = setTimeout(split, 250); }).observe(n, { childList: true });
  }
  // zybNavSplit.diag() in the browser console: what the splitter sees, so a portal whose menu is built differently can be fixed
  function diag() {
    var n = nav(); if (!n) return { menu: 'no ul.nav found - this portal draws its sidebar differently' };
    var bs = blocks(n);
    return { menu: 'ul.nav', groups: bs.map(function (b) { return b.name + ' (' + b.kids.length + ')'; }), catchAllFound: bs.some(function (b) { return CATCH.test(b.name); }),
      splitGroups: [].map.call(n.querySelectorAll('li.nav-group[data-zyb-split]'), function (h) { return h.getAttribute('data-en'); }),
      moreHeadingHtml: (function () { var h = [].filter.call(n.querySelectorAll('li,div,button,a'), function (x) { return /^\W*(more|المزيد)\b/i.test((x.textContent || '').trim()) && (x.textContent || '').length < 40; })[0]; return h ? h.outerHTML.slice(0, 600) : null; })() };
  }
  window.zybNavSplit = { split: split, diag: diag, SPLIT: SPLIT };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start); else start();
})();
