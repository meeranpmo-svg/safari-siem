// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
/* zyb-itamdel.js - IT Asset Management add-ons (admins). Loaded by zyb-menu.js on portal pages.
 * Delete: a "Delete" button in the asset drawer, "Select / Delete selected" on the inventory table, and in Asset
 * Discovery a "Delete" next to every Connect / Onboard to SIEM / Open asset button and on each connected SIEM source.
 * All open one confirmation dialog (reason required; what discovery should do if it finds the device again).
 * Connect to SIEM: before the connection is made, a dialog shows which SIEM the device will be connected to (node name,
 * server, portal, version, status, listening collectors and ports) and the device itself; the admin confirms or cancels.
 * Clickable overview: on the IT Asset Management dashboard every tile, bar and legend row opens the inventory filtered
 * to those assets (type, status, site, source, networked / off-network) or the matching page (findings, licences).
 * Categories: "Add asset" requires a Category (Servers / Cloud / Network devices / End-user devices / Other); the Type list
 * narrows to that category and network devices get a role (firewall, switch, router, ...). Cloud and the role are saved
 * as tags ("cloud", "firewall", ...). The inventory gets category chips, the overview an "Assets by category" card.
 * Calls the ITAM engine:
 *   POST /api/itam/assets/:id/delete   and   POST /api/itam/bulk/assets/delete   (engine/asset-delete.js)
 * Works over the existing ITAM page without changing it: rows and the drawer are found by their data-itam-* attributes. */
(function () {
  'use strict';
  if (window.__zybItamDel || /^\/dashboards\//.test(location.pathname)) return; window.__zybItamDel = true;
  var API = '/api/itam', ADMIN = null, ASKED = 0, SEL = {}, PICK = false, GONE = {}, BUSY = false;
  function E(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); }
  function req(m, p, b) { return new Promise(function (ok) { var x = new XMLHttpRequest(); x.open(m, API + p); x.withCredentials = true; x.timeout = 120000; if (b) x.setRequestHeader('Content-Type', 'application/json'); x.onload = function () { var j = null; try { j = JSON.parse(x.responseText); } catch (e) { /* not JSON: treated as no data */ } ok({ status: x.status, ok: x.status >= 200 && x.status < 300, j: j }); }; x.onerror = x.ontimeout = function () { ok({ status: 0, ok: false, j: { error: 'IT Asset Management is not reachable' } }); }; x.send(b ? JSON.stringify(b) : null); }); }
  function toast(t) { try { if (typeof infoToast === 'function') { infoToast(t); return; } } catch (e) { /* portal function not available on this page: carry on without it */ } var d = document.createElement('div'); d.className = 'zid-toast'; d.textContent = t; document.body.appendChild(d); setTimeout(function () { d.remove(); }, 4500); }
  var CSS = '.zid-btn{font:600 11.5px system-ui,-apple-system,"Segoe UI",sans-serif;padding:4px 10px;border-radius:8px;border:1px solid rgba(255,110,127,.55);background:rgba(255,110,127,.08);color:#ff8a95;cursor:pointer}.zid-btn:hover{background:rgba(255,110,127,.18)}.zid-btn[disabled]{opacity:.45;cursor:not-allowed}.zid-btn.ghost{border-color:rgba(255,255,255,.2);background:rgba(255,255,255,.05);color:inherit}'
    + '.zid-bar{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin:0 0 8px;font:12px system-ui,sans-serif}.zid-row{display:flex;gap:6px;flex-wrap:wrap;margin-top:6px}.zid-sel{width:15px;height:15px;cursor:pointer;margin:0 8px 0 0;vertical-align:middle}.zia-chips{display:flex;gap:6px;flex-wrap:wrap;margin:0 0 8px}.zia-chip.on{border-color:#4fc3f7;background:rgba(79,195,247,.16)}.zia-chip b{opacity:.75;margin-inline-start:4px}'
    + '.zid-ov{position:fixed;inset:0;background:rgba(0,0,0,.55);z-index:100000;display:flex;align-items:center;justify-content:center;padding:16px}.zid-dlg{background:#141922;color:#e6e9ef;border:1px solid rgba(255,110,127,.45);border-radius:12px;max-width:520px;width:100%;padding:18px 18px 16px;font:13px/1.45 system-ui,-apple-system,"Segoe UI",sans-serif;box-shadow:0 20px 60px rgba(0,0,0,.5)}'
    + '.zid-dlg h3{margin:0 0 8px;color:#ff8a95;font-size:16px}.zid-dlg .m{color:#9aa4b2;font-size:12px;margin:6px 0}.zid-dlg ul{margin:6px 0 4px 18px;padding:0;max-height:120px;overflow:auto;font-size:12px}.zid-dlg input[type=text]{width:100%;box-sizing:border-box;margin-top:4px;padding:8px 10px;border-radius:8px;border:1px solid #2e3440;background:#0d1117;color:inherit;font:inherit}'
    + '.zid-dlg label.r{display:flex;gap:8px;align-items:center;margin-top:4px;font-size:12.5px}.zid-dlg .acts{display:flex;gap:8px;justify-content:flex-end;margin-top:14px}.zid-go{background:#c62f3e;border:1px solid #c62f3e;color:#fff;border-radius:8px;padding:7px 14px;font-weight:700;cursor:pointer}.zid-go[disabled]{opacity:.5}.zid-err{color:#ff8a95;font-size:12px;margin-top:8px;min-height:1em}'
    + '.zid-toast{position:fixed;bottom:16px;left:50%;transform:translateX(-50%);background:#1f242d;color:#e6e9ef;border:1px solid #2e3440;border-radius:9px;padding:9px 14px;z-index:100001;font:13px system-ui,sans-serif}'
    + ':root[data-theme="light"] .zid-dlg{background:#fff;color:#1b1f24;border-color:#e6a1a8}:root[data-theme="light"] .zid-dlg input[type=text]{background:#f6f8fa;border-color:#d0d7de}';
  function css() { if (document.getElementById('zid-css')) return; var s = document.createElement('style'); s.id = 'zid-css'; s.textContent = CSS; document.head.appendChild(s); }

  var NAMES = {};
  function root() { return document.getElementById('itam-root'); }
  function page() { return root() || document.getElementById('dsc-root'); }
  function cssId(v) { return window.CSS && CSS.escape ? CSS.escape(v) : String(v).replace(/["\\]/g, '\\$&'); }
  function cells(tr) { return tr ? [].map.call(tr.querySelectorAll('td'), function (td) { return td.textContent.replace(/\s+/g, ' ').trim(); }) : []; }
  function rows() { var r = root(); return r ? [].slice.call(r.querySelectorAll('tr[data-itam-asset]')) : []; }
  function nativeSel() { var r = root(); return r ? r.querySelector('[data-itam-lcsel]') : null; } /* newer ITAM pages have their own row checkboxes */
  function selected() {
    if (nativeSel()) return [].slice.call(root().querySelectorAll('[data-itam-lcsel]:checked')).map(function (c) { return c.getAttribute('data-itam-lcsel'); });
    return Object.keys(SEL).filter(function (k) { return SEL[k] && !GONE[k]; });
  }
  function rowName(id) { var tr = root() && root().querySelector('tr[data-itam-asset="' + cssId(id) + '"]'); var b = tr && tr.querySelector('b'); return b ? b.textContent.trim() : NAMES[id] || id; }
  function drawerId() { /* the open asset drawer: its action buttons carry data-itam-id */
    var r = root(); if (!r) return null; var b = r.querySelector('[data-itam-act][data-itam-id]'); return b ? { id: b.getAttribute('data-itam-id'), btn: b } : null;
  }

  var CONN = null, CONN_AT = 0;
  function connections() { /* connected SIEM sources: source id → asset (their table rows carry no asset id) */
    if (Date.now() - CONN_AT < 30000) return; CONN_AT = Date.now();
    req('GET', '/discovery/connect').then(function (x) { if (!x.ok || !x.j) return; var m = {}; (x.j.connections || []).forEach(function (c) { if (c.source_id && c.asset_id) m[c.source_id] = { id: c.asset_id, name: c.name || c.asset_id }; }); CONN = m; paint(); });
  }
  function delBtn(id, label) { var b = document.createElement('button'); b.type = 'button'; b.className = 'zid-btn zid-dsc'; b.style.marginInlineStart = '6px'; b.setAttribute('data-zid', 'one'); b.setAttribute('data-id', id); b.title = 'Delete this asset from the inventory'; b.textContent = label || '🗑 Delete'; return b; }
  function paintDiscovery() { /* Asset Discovery: Delete next to Connect / Onboard / Open asset, and on connected SIEM sources */
    var dr = document.getElementById('dsc-root'); if (!dr) return;
    [].forEach.call(dr.querySelectorAll('[data-dsc-asset]'), function (o) {
      var id = o.getAttribute('data-dsc-asset'); if (!id) return;
      if (GONE[id]) { o.style.display = 'none'; if (o.nextElementSibling && o.nextElementSibling.classList.contains('zid-dsc')) o.nextElementSibling.remove(); return; }
      var nx = o.nextElementSibling; if (nx && nx.classList.contains('zid-dsc')) return;
      o.parentNode.insertBefore(delBtn(id, '🗑 Delete asset'), o.nextSibling);
    });
    connections();
    if (CONN) [].forEach.call(dr.querySelectorAll('tr'), function (tr) {
      if (tr.querySelector('[data-dsc-connect]')) return; var c = cells(tr), hit = c.length >= 3 && CONN[c[1]]; if (!hit) return;
      NAMES[hit.id] = hit.name; if (GONE[hit.id]) { tr.style.display = 'none'; return; }
      if (tr.querySelector('.zid-dsc')) return;
      var tds = tr.querySelectorAll('td'); tds[tds.length - 1].appendChild(delBtn(hit.id));
    });
    [].forEach.call(dr.querySelectorAll('[data-dsc-connect]'), function (c) {
      var id = c.getAttribute('data-dsc-connect'), tr = c.closest('tr'); if (!id) return;
      if (tr) { NAMES[id] = cells(tr)[0] || id; if (GONE[id]) { tr.style.display = 'none'; return; } }
      var nx = c.nextElementSibling; if (nx && nx.classList.contains('zid-dsc')) return;
      c.parentNode.insertBefore(delBtn(id), c.nextSibling);
    });
  }
  /* ---- clickable overview: tiles, bars and legend rows open the filtered inventory ---- */
  var TYPES = ['server', 'vm', 'workstation', 'laptop', 'network', 'printer', 'phone', 'storage', 'ups', 'mobile', 'peripheral', 'software', 'licence', 'other'];
  var STATUSES = ['in_use', 'in_stock', 'in_repair', 'retired', 'lost', 'disposed'];
  var SRC = { sensor: 'Site sensor', agent: 'Endpoint agent', vcenter: 'vCenter', discovery: 'Asset Discovery', manual: 'Manual / barcode', import: 'Import' };
  function tr(en) { var d = window.X_AR || {}; return Object.prototype.hasOwnProperty.call(d, en) ? d[en] : en; }
  function keyOf(list, label) { for (var i = 0; i < list.length; i++) if (label === list[i] || label === tr(list[i])) return list[i]; return null; }
  function srcKey(label) { for (var k in SRC) if (label === SRC[k] || label === tr(SRC[k]) || label === k) return k; return null; }
  function view() { try { return typeof currentView !== 'undefined' ? currentView : ''; } catch (e) { return ''; } }
  function goView(v) { try { if (typeof setView === 'function') { setView(v); return; } } catch (e) { /* portal function not available on this page: carry on without it */ } var b = document.createElement('button'); b.setAttribute('data-itam-go', v); b.style.display = 'none'; (root() || document.body).appendChild(b); b.click(); b.remove(); }
  function drill(filters) { /* open the inventory, clear its filters, then set the requested ones through the page's own controls */
    goView('itam-assets');
    var want = { q: '', type: '', site: '', source: '', owner: '', status: '', net: '', lc: '' }, t0 = Date.now(), n = 0;
    for (var k in filters) want[k] = filters[k];
    (function step() {
      var r = root(); if (!r || !r.querySelector('[data-itam-filter]')) { if (Date.now() - t0 < 8000) setTimeout(step, 120); return; }
      for (var f in want) {
        var el = r.querySelector('[data-itam-filter="' + f + '"]'); if (!el || el.value === want[f]) continue;
        if (el.tagName === 'SELECT' && ![].some.call(el.options, function (o) { return o.value === want[f]; })) continue; // not offered on this page
        if (++n > 12) return;
        el.value = want[f]; el.dispatchEvent(new Event('change', { bubbles: true })); setTimeout(step, 60); return; // the page re-renders after each change
      }
      var first = r.querySelector('tr[data-itam-asset]'); if (first && first.scrollIntoView) first.closest('table').scrollIntoView({ block: 'start', behavior: 'smooth' });
    })();
  }
  function clickable(el, title, action) { el.setAttribute('data-zia', '1'); el.zia = action; el.style.cursor = 'pointer'; el.setAttribute('role', 'button'); el.setAttribute('tabindex', '0'); el.setAttribute('title', title); }
  function cardOf(h3text) { var r = root(); if (!r) return null; var hs = r.querySelectorAll('.card h3'); for (var i = 0; i < hs.length; i++) { var own = [].filter.call(hs[i].childNodes, function (n) { return n.nodeType === 3; }).map(function (n) { return n.nodeValue; }).join('').trim().replace(/^\S+\s+/, ''); if (own === h3text || own === tr(h3text)) return hs[i].parentNode; } return null; }
  function barRows(card, onRow) { /* the overview bar charts: one label <text x=0> per 26 px row → transparent click target over the row */
    var svg = card && card.querySelector('svg'); if (!svg || svg.querySelector('[data-zia]')) return;
    [].forEach.call(svg.querySelectorAll('text[x="0"]'), function (t) {
      var y = +t.getAttribute('y') - 14, label = t.textContent.trim(), act = onRow(label); if (!act) return;
      var hit = document.createElementNS('http://www.w3.org/2000/svg', 'rect'); hit.setAttribute('x', '0'); hit.setAttribute('y', String(y)); hit.setAttribute('width', '320'); hit.setAttribute('height', '26'); hit.setAttribute('fill', 'transparent');
      var ti = document.createElementNS('http://www.w3.org/2000/svg', 'title'); ti.textContent = 'Show ' + label; hit.appendChild(ti); clickable(hit, 'Show ' + label, act); svg.appendChild(hit);
    });
  }
  function legendRows(card, onRow) { if (!card) return; [].forEach.call(card.querySelectorAll('div[style*="display:flex;align-items:center;gap:7px"]'), function (row) { if (row.hasAttribute('data-zia')) return; var sp = row.querySelectorAll('span')[1], label = sp ? sp.textContent.trim() : '', act = onRow(label); if (act) clickable(row, 'Show ' + label, act); }); }
  function paintOverview() {
    var r = root(); if (!r || !/^itam(-overview)?$/.test(view()) || !r.querySelector('.itam-stats')) return;
    if (!document.getElementById('zia-css')) { var st = document.createElement('style'); st.id = 'zia-css'; st.textContent = '#itam-root [data-zia]:hover{filter:brightness(1.25)}#itam-root .noc-stat[data-zia]:hover,#itam-root div[data-zia]:hover{outline:1px solid rgba(79,195,247,.55);border-radius:10px}#itam-root [data-zia]:focus-visible{outline:2px solid #4fc3f7;outline-offset:2px}'; document.head.appendChild(st); }
    var TILE = { 'Assets': function () { drill({}); }, 'Networked': function () { drill({ net: '1' }); }, 'Off-network': function () { drill({ net: '0' }); },
      'Warranty expiring': function () { goView('itam-ai'); }, 'EOL approaching': function () { goView('itam-ai'); }, 'Open AI findings': function () { goView('itam-ai'); },
      'Licences': function () { goView('itam-software'); }, 'Compliant': function () { goView('itam-software'); }, 'Over-deployed': function () { goView('itam-software'); }, 'Under-used': function () { goView('itam-software'); } };
    [].forEach.call(r.querySelectorAll('.itam-stats .noc-stat'), function (t) { if (t.hasAttribute('data-zia')) return; var k = t.querySelector('.k'), label = k ? k.textContent.trim() : ''; for (var en in TILE) if (label === en || label === tr(en)) { clickable(t, 'Open: ' + label, TILE[en]); return; } });
    barRows(cardOf('Assets by type'), function (l) { var k = keyOf(TYPES, l); return k && function () { drill({ type: k }); }; });
    barRows(cardOf('Assets by site'), function (l) { return l && l !== '(unknown)' && function () { drill({ site: l }); }; });
    barRows(cardOf('Discovery coverage'), function (l) { var k = srcKey(l); return k && function () { drill({ source: k }); }; });
    legendRows(cardOf('Assets by status'), function (l) { var k = keyOf(STATUSES, l); return k && function () { drill({ status: k }); }; });
    legendRows(cardOf('Networked vs off-network'), function (l) { return l === 'Networked' || l === tr('Networked') ? function () { drill({ net: '1' }); } : l === 'Off-network' || l === tr('Off-network') ? function () { drill({ net: '0' }); } : null; });
    var ai = cardOf('AI findings'); if (ai) [].forEach.call(ai.querySelectorAll('tr'), function (row) { if (!row.hasAttribute('data-zia') && row.querySelector('td')) clickable(row, 'Review these findings', function () { goView('itam-ai'); }); });
  }
  /* ---- categories: Servers / Cloud / Network devices / End-user devices / Other ---- */
  var CATS = [
    { k: 'servers', l: 'Servers', types: ['server', 'vm', 'storage'] },
    { k: 'cloud', l: 'Cloud', types: ['vm', 'server', 'storage', 'software'] },
    { k: 'network', l: 'Network devices', types: ['network'] },
    { k: 'enduser', l: 'End-user devices', types: ['workstation', 'laptop', 'mobile', 'phone', 'printer', 'peripheral'] },
    { k: 'other', l: 'Other', types: ['ups', 'software', 'licence', 'other'] }];
  var ROLES = [['firewall', 'Firewall'], ['switch', 'Switch'], ['router', 'Router'], ['access-point', 'Wireless access point'], ['wireless-controller', 'Wireless controller'], ['load-balancer', 'Load balancer'], ['sd-wan', 'SD-WAN appliance'], ['vpn', 'VPN gateway']];
  var ADD = { cat: '', role: '' }, CHIP = '', AMAP = null, AMAP_AT = 0;
  function catOf(a) {
    var tags = (a.tags || []).map(function (t) { return String(t).toLowerCase(); });
    if (tags.indexOf('cloud') >= 0 || (a.discovery && a.discovery['class'] === 'cloud')) return 'cloud';
    for (var i = 0; i < CATS.length; i++) if (CATS[i].k !== 'cloud' && CATS[i].types.indexOf(a.type) >= 0) return CATS[i].k;
    return 'other';
  }
  function catLabel(k) { for (var i = 0; i < CATS.length; i++) if (CATS[i].k === k) return CATS[i].l; return k; }
  function assetMap(cb) { /* id → category for every asset (one request, refreshed every 30 s) */
    if (AMAP && Date.now() - AMAP_AT < 30000) { if (cb) cb(AMAP); return; }
    AMAP_AT = Date.now(); req('GET', '/assets?limit=5000').then(function (x) { if (!x.ok || !x.j) return; var m = {}; (x.j.assets || []).forEach(function (a) { m[a.id] = catOf(a); }); AMAP = m; if (cb) cb(m); paint(); });
  }
  function selHTML(id, list, val, blank) { return '<select id="' + id + '">' + (blank ? '<option value="">' + E(blank) + '</option>' : '') + list.map(function (o) { return '<option value="' + E(o[0]) + '"' + (o[0] === val ? ' selected' : '') + '>' + E(o[1]) + '</option>'; }).join('') + '</select>'; }
  function narrowTypes() {
    var t = document.getElementById('itam_add_type'); if (!t) return; var c = null; CATS.forEach(function (x) { if (x.k === ADD.cat) c = x; });
    [].forEach.call(t.options, function (o) { var ok = !c || c.types.indexOf(o.value) >= 0; o.hidden = !ok; o.disabled = !ok; });
    if (c && c.types.indexOf(t.value) < 0) t.value = c.types[0];
    var rl = document.getElementById('zia-role-wrap'); if (rl) rl.style.display = ADD.cat === 'network' ? '' : 'none';
  }
  function paintAddForm() {
    var t = document.getElementById('itam_add_type'); if (!t) { ADD = { cat: '', role: '' }; return; }
    if (document.getElementById('zia_cat')) return;
    var lab = t.closest('label') || t.parentNode, st = 'display:flex;flex-direction:column;gap:4px;font-size:11.5px;color:var(--muted)';
    var c = document.createElement('label'); c.setAttribute('style', st); c.className = 'zia-cat';
    c.innerHTML = 'Category <b style="color:#ff8a95">*</b>' + selHTML('zia_cat', CATS.map(function (x) { return [x.k, x.l]; }), ADD.cat, '— choose —');
    var r = document.createElement('label'); r.setAttribute('style', st); r.id = 'zia-role-wrap'; r.className = 'zia-cat';
    r.innerHTML = 'Network device role' + selHTML('zia_role', ROLES, ADD.role, '— choose —');
    lab.parentNode.insertBefore(c, lab); lab.parentNode.insertBefore(r, lab.nextSibling);
    narrowTypes();
  }
  function paintChips() {
    var r = root(); if (!r || view() !== 'itam-assets') return; var trs = rows(); if (!trs.length) return;
    css(); assetMap();
    var table = trs[0].closest('table'); if (!table) return;
    var counts = { '': trs.length }; trs.forEach(function (tr) { var k = AMAP && AMAP[tr.getAttribute('data-itam-asset')]; if (k) counts[k] = (counts[k] || 0) + 1; });
    var html = [['', 'All']].concat(CATS.map(function (x) { return [x.k, x.l]; })).map(function (o) { return '<button type="button" class="zid-btn ghost zia-chip' + (CHIP === o[0] ? ' on' : '') + '" data-zchip="' + o[0] + '">' + E(o[1]) + (AMAP ? ' <b>' + (counts[o[0]] || 0) + '</b>' : '') + '</button>'; }).join('');
    var bar = r.querySelector('.zia-chips'); if (!bar) { bar = document.createElement('div'); bar.className = 'zia-chips'; table.parentNode.insertBefore(bar, table.parentNode.querySelector(':scope > .zid-bar') || table); }
    if (bar.getAttribute('data-h') !== html) { bar.innerHTML = html; bar.setAttribute('data-h', html); }
    trs.forEach(function (tr) { var id = tr.getAttribute('data-itam-asset'); if (GONE[id]) return; var show = !CHIP || !AMAP || AMAP[id] === CHIP; tr.style.display = show ? '' : 'none'; });
  }
  function paintCatCard() {
    var r = root(); if (!r || !/^itam(-overview)?$/.test(view()) || !r.querySelector('.itam-stats') || r.querySelector('.zia-catcard')) return;
    assetMap(function (m) {
      var r2 = root(); if (!r2 || r2.querySelector('.zia-catcard')) return; var st = r2.querySelector('.itam-stats'); if (!st) return;
      var n = {}; for (var id in m) n[m[id]] = (n[m[id]] || 0) + 1;
      var d = document.createElement('div'); d.className = 'card zia-catcard';
      d.innerHTML = '<h3>🗂️ Assets by category</h3><div class="itam-stats">' + CATS.map(function (x) { return '<div class="noc-stat" data-zcat="' + x.k + '"><div class="v">' + (n[x.k] || 0) + '</div><div class="k">' + E(x.l) + '</div></div>'; }).join('') + '</div>';
      st.parentNode.insertBefore(d, st.nextSibling);
      [].forEach.call(d.querySelectorAll('[data-zcat]'), function (t) { var k = t.getAttribute('data-zcat'); clickable(t, 'Show ' + catLabel(k), function () { CHIP = k; drill({}); }); });
    });
  }
  /* add the category/role tags to the new asset (the page's own Save posts to /api/itam/assets) */
  if (window.fetch && !window.fetch.__zia) {
    var of = window.fetch;
    window.fetch = function (u, o) {
      try {
        var url = typeof u === 'string' ? u : (u && u.url) || '';
        if (o && /^post$/i.test(o.method || '') && /\/api\/itam\/assets$/.test(url.split('?')[0]) && ADD.cat && typeof o.body === 'string') {
          var b = JSON.parse(o.body), tags = Array.isArray(b.tags) ? b.tags.slice() : [];
          if (ADD.cat === 'cloud' && tags.indexOf('cloud') < 0) tags.push('cloud');
          if (ADD.cat === 'network' && ADD.role && tags.indexOf(ADD.role) < 0) tags.push(ADD.role);
          if (tags.length) { b.tags = tags; o = Object.assign({}, o, { body: JSON.stringify(b) }); }
          AMAP_AT = 0;
        }
      } catch (e) { /* not a JSON body: the request is sent as it is */ }
      return of.call(this, u, o);
    };
    window.fetch.__zia = true;
  }
  function paint() {
    try { paintOverview(); paintCatCard(); paintAddForm(); paintChips(); } catch (e) { if (window.console) console.warn('IT asset add-ons: a card did not draw', e); }
    if (ADMIN === true && document.getElementById('dsc-root')) { css(); paintDiscovery(); }
    var r = root(); if (!r || ADMIN !== true) return; css();
    rows().forEach(function (tr) { if (GONE[tr.getAttribute('data-itam-asset')]) tr.style.display = 'none'; });
    // drawer: one Delete button under the lifecycle buttons
    var d = drawerId();
    if (d && GONE[d.id]) { var c = r.querySelector('[data-itam="closedrawer"]'); if (c) c.click(); }
    else if (d && !r.querySelector('.zid-drawer')) {
      { var host = d.btn.parentElement, last = host; while (last.nextElementSibling && last.nextElementSibling.querySelector && last.nextElementSibling.querySelector('[data-itam-act]')) last = last.nextElementSibling; var row = document.createElement('div'); row.className = 'zid-row zid-drawer'; row.innerHTML = '<button type="button" class="zid-btn" data-zid="one" data-id="' + E(d.id) + '">🗑 Delete asset</button>'; last.parentNode.insertBefore(row, last.nextSibling); }
    }
    // inventory table: select + delete selected
    var trs = rows(); if (!trs.length) return;
    var table = trs[0].closest('table'); if (!table) return;
    var own = !nativeSel();
    if (own && PICK) trs.forEach(function (tr) { var td = tr.querySelector('td'); if (td && !td.querySelector('.zid-sel')) { var id = tr.getAttribute('data-itam-asset'); var cb = document.createElement('input'); cb.type = 'checkbox'; cb.className = 'zid-sel'; cb.setAttribute('data-id', id); cb.checked = !!SEL[id]; cb.setAttribute('aria-label', 'Select for delete'); td.insertBefore(cb, td.firstChild); } });
    if (own && !PICK) [].forEach.call(table.querySelectorAll('.zid-sel'), function (cb) { cb.remove(); });
    var bar = table.parentNode.querySelector(':scope > .zid-bar') || (table.previousElementSibling && table.previousElementSibling.classList.contains('zid-bar') ? table.previousElementSibling : null);
    var n = selected().length;
    var html = own
      ? (PICK ? '<span>Selected for delete: <b>' + n + '</b></span><button type="button" class="zid-btn ghost" data-zid="all">Select all shown</button><button type="button" class="zid-btn ghost" data-zid="none">Clear</button><button type="button" class="zid-btn" data-zid="bulk"' + (n ? '' : ' disabled') + '>🗑 Delete selected</button><button type="button" class="zid-btn ghost" data-zid="pick">Done</button>' : '<button type="button" class="zid-btn" data-zid="pick">🗑 Select assets to delete</button>')
      : '<button type="button" class="zid-btn" data-zid="bulk"' + (n ? '' : ' disabled') + '>🗑 Delete selected (' + n + ')</button>';
    if (!bar) { bar = document.createElement('div'); bar.className = 'zid-bar'; table.parentNode.insertBefore(bar, table); }
    if (bar.getAttribute('data-h') !== html) { bar.innerHTML = html; bar.setAttribute('data-h', html); }
  }

  function dialog(ids) {
    if (!ids.length || document.querySelector('.zid-ov')) return;
    var one = ids.length === 1;
    var list = ids.slice(0, 12).map(function (id) { return '<li>' + E(rowName(id)) + '</li>'; }).join('') + (ids.length > 12 ? '<li>… and ' + (ids.length - 12) + ' more</li>' : '');
    var ov = document.createElement('div'); ov.className = 'zid-ov';
    ov.innerHTML = '<div class="zid-dlg" role="dialog" aria-modal="true" aria-labelledby="zid-h"><h3 id="zid-h">🗑 Delete ' + (one ? 'this asset' : ids.length + ' assets') + '</h3><ul>' + list + '</ul>'
      + '<div class="m">The record, its relationships and its history are removed from the inventory. The audit log keeps who deleted what, when and why. To keep the history, use Retire or Dispose instead.</div>'
      + '<div class="m">If an asset sends logs to the SIEM, its log source is stopped first.</div>'
      + '<label style="display:block;margin-top:10px;font-size:12.5px">Reason (required)<input type="text" id="zid-reason" maxlength="500" placeholder="e.g. duplicate record, test entry, device removed" autocomplete="off"></label>'
      + '<div style="margin-top:10px;font-size:12.5px">If discovery finds it again:</div>'
      + '<label class="r"><input type="radio" name="zid-mode" value="review" checked> show it in Discovery results for review again</label>'
      + '<label class="r"><input type="radio" name="zid-mode" value="ignore"> ignore it — keep it out of the inventory</label>'
      + '<div class="zid-err" id="zid-err"></div><div class="acts"><button type="button" class="zid-btn ghost" data-zid="cancel">Cancel</button><button type="button" class="zid-go" data-zid="go">Delete permanently</button></div></div>';
    ov.zidIds = ids; document.body.appendChild(ov);
    setTimeout(function () { var i = document.getElementById('zid-reason'); if (i) i.focus(); }, 0);
  }
  function close() { var o = document.querySelector('.zid-ov'); if (o) o.remove(); }

  /* ---- Connect to SIEM: show which SIEM before connecting ---- */
  function getJ(url) { return new Promise(function (ok) { var x = new XMLHttpRequest(); x.open('GET', url); x.withCredentials = true; x.timeout = 8000; x.onload = function () { var j = null; try { j = JSON.parse(x.responseText); } catch (e) { /* not JSON: treated as no data */ } ok(x.status >= 200 && x.status < 300 ? j : null); }; x.onerror = x.ontimeout = function () { ok(null); }; x.send(); }); }
  function kv(rows) { return '<table style="width:100%;border-collapse:collapse;font-size:12.5px;margin:4px 0 2px">' + rows.filter(function (r) { return r[1] != null && r[1] !== ''; }).map(function (r) { return '<tr><td style="color:#9aa4b2;padding:3px 10px 3px 0;white-space:nowrap;vertical-align:top;width:110px">' + E(r[0]) + '</td><td style="padding:3px 0">' + r[1] + '</td></tr>'; }).join('') + '</table>'; }
  function connectDialog(btn) {
    if (document.querySelector('.zid-ov')) return;
    var id = btn.getAttribute('data-dsc-connect'), tr = btn.closest('tr'), c = cells(tr), sel = document.getElementById('dsc_cn_kind');
    var kind = btn.getAttribute('data-kind') || (sel && sel.value) || '', kindTxt = kind || 'Automatic (mapping table)';
    var ov = document.createElement('div'); ov.className = 'zid-ov'; ov.zidConnect = { id: id, kind: kind };
    ov.innerHTML = '<div class="zid-dlg" role="dialog" aria-modal="true" aria-labelledby="zid-ch" style="border-color:rgba(63,185,80,.5)"><h3 id="zid-ch" style="color:#56d364">🔗 Connect to SIEM</h3>'
      + '<div class="m" style="margin-top:0">This device will be registered as a log source and will send its logs to:</div><div id="zid-siem"><div class="m">Checking the SIEM…</div></div>'
      + '<div style="margin-top:10px;font-weight:700">Device</div><div id="zid-dev">' + kv([['Name', E(c[0] || id)], ['IP address', E(c[1] && c[1] !== '—' ? c[1] : '')], ['Type', E(c[2] || '')], ['Connector', E(kindTxt)]]) + '</div>'
      + '<div class="zid-err" id="zid-err"></div><div class="acts"><button type="button" class="zid-btn ghost" data-zid="cancel">Cancel</button><button type="button" class="zid-go" data-zid="cgo" style="background:#238636;border-color:#238636">Connect to this SIEM</button></div></div>';
    document.body.appendChild(ov);
    setTimeout(function () { var g = ov.querySelector('[data-zid="cgo"]'); if (g) g.focus(); }, 0);
    req('GET', '/assets/' + encodeURIComponent(id)).then(function (x) {
      var a = x.ok && x.j && (x.j.asset || x.j); if (!a || !document.body.contains(ov)) return;
      document.getElementById('zid-dev').innerHTML = kv([['Name', E(a.name || c[0] || id)], ['IP address', E(a.mgmt_ip || '')], ['Type', E(a.type || c[2] || '')], ['OS', E(a.os || '')], ['Site', E(a.site || '')], ['Connector', E(kindTxt)]]);
    });
    Promise.all([getJ('/api/soc/health'), getJ('/dashboards/sysinfo.json'), getJ('/api/soc/sources')]).then(function (r) {
      var h = r[0], x = r[1], src = r[2], box = document.getElementById('zid-siem'); if (!box) return;
      if (!h) { box.innerHTML = kv([['SIEM', (ZYB_ORG.short + ' SIEM (sentra-siem)')], ['Server', E((x && x.host) || '')], ['Portal', E(location.host)], ['Status', '<span style="color:#ff8a95">not answering — the connection will probably fail</span>']]); return; }
      var en = h.engine || {}, ok = h.status === 'ok';
      var cols = (h.collectors || []).filter(function (k) { return k.enabled; }).map(function (k) { return E(k.name) + ' ' + E(k.port || '') + (k.ok === false ? ' <span style="color:#ff8a95">(not listening)</span>' : ''); }).join(', ');
      var n = src && src.sources ? src.sources.length : null;
      box.innerHTML = kv([['SIEM', ('<b>' + ZYB_ORG.short + ' SIEM (sentra-siem)</b>') + (en.node_name ? ' · node <b>' + E(en.node_name) + '</b>' : '')],
        ['Server', E((x && x.host) || '')], ['Portal', E(location.host)], ['Version', E(en.version || '')],
        ['Status', ok ? '<span style="color:#56d364">● running</span>' : '<span style="color:#e3b341">● ' + E(h.status || 'unknown') + '</span>'],
        ['Collectors', cols], ['Logs now', h.eps && h.eps.m1 != null ? E(Math.round(h.eps.m1)) + ' events/s' : ''], ['Log sources', n != null ? E(n) + ' connected' : '']]);
    });
  }
  function connectGo() {
    var ov = document.querySelector('.zid-ov'); if (!ov || !ov.zidConnect) return;
    var c = ov.zidConnect, b = document.querySelector('[data-dsc-connect="' + cssId(c.id) + '"]');
    close();
    if (!b) { toast('The Connect button is no longer on the page - refresh and try again'); return; }
    var sel = document.getElementById('dsc_cn_kind'); if (sel && !b.getAttribute('data-kind') && c.kind) sel.value = c.kind;
    b.__zidOk = true; try { b.click(); } finally { b.__zidOk = false; }
  }
  function run(force) {
    var ov = document.querySelector('.zid-ov'); if (!ov || BUSY) return;
    var ids = ov.zidIds, reason = (document.getElementById('zid-reason').value || '').trim(), m = document.querySelector('input[name="zid-mode"]:checked'), err = document.getElementById('zid-err'), go = ov.querySelector('.zid-go');
    if (reason.length < 3) { err.textContent = 'Enter a reason (at least 3 characters).'; document.getElementById('zid-reason').focus(); return; }
    var body = { reason: reason, discovery: m && m.value === 'ignore' ? 'ignore' : 'review', force: !!force }, one = ids.length === 1;
    if (!one) body.ids = ids;
    BUSY = true; go.disabled = true; go.textContent = 'Deleting…'; err.textContent = '';
    req('POST', one ? '/assets/' + encodeURIComponent(ids[0]) + '/delete' : '/bulk/assets/delete', body).then(function (x) {
      BUSY = false; go.disabled = false; go.textContent = force ? 'Delete anyway' : 'Delete permanently';
      if (x.status === 403) { err.textContent = 'Only an administrator can delete assets.'; return; }
      if (x.status === 404 && !(x.j && x.j.error === 'asset not found')) { err.textContent = 'Delete is not installed on the server yet (install/add-asset-delete.sh).'; return; }
      var done = one ? (x.ok ? [ids[0]] : []) : ((x.j && x.j.results) || []).filter(function (r) { return r.ok; }).map(function (r) { return r.asset_id; });
      var siemFail = one ? (x.j && x.j.code === 'siem_stop_failed' ? [ids[0]] : []) : ((x.j && x.j.results) || []).filter(function (r) { return !r.ok && r.code === 'siem_stop_failed'; }).map(function (r) { return r.asset_id; });
      var other = one ? (!x.ok && !siemFail.length ? [(x.j && x.j.error) || 'HTTP ' + x.status] : []) : ((x.j && x.j.results) || []).filter(function (r) { return !r.ok && r.code !== 'siem_stop_failed'; }).map(function (r) { return rowName(r.asset_id) + ': ' + r.error; });
      if (!one && !x.ok) other = [(x.j && x.j.error) || 'HTTP ' + x.status];
      done.forEach(function (id) { GONE[id] = true; delete SEL[id]; var cb = root() && root().querySelector('[data-itam-lcsel="' + id + '"]'); if (cb && cb.checked) cb.click(); });
      if (done.length) toast('Deleted ' + done.length + (one ? ' asset' : ' of ' + ids.length + ' assets'));
      if (siemFail.length && !force) { ov.zidIds = siemFail; err.textContent = 'The SIEM could not be reached to stop the log source of ' + siemFail.length + ' asset(s). Try again later, or click "Delete anyway" — then remove the source in the SIEM by hand.'; go.textContent = 'Delete anyway'; go.setAttribute('data-zid', 'force'); paint(); return; }
      if (other.length) { ov.zidIds = ids.filter(function (id) { return done.indexOf(id) < 0; }); err.textContent = other.slice(0, 3).join(' · '); paint(); return; }
      close(); if (!one) { PICK = false; SEL = {}; } paint();
    });
  }

  document.addEventListener('click', function (e) {
    var t = e.target; if (!t || !t.closest) return;
    if (t.classList && t.classList.contains('zid-sel')) { e.stopPropagation(); SEL[t.getAttribute('data-id')] = t.checked; paint(); return; }
    var ch = t.closest('[data-zchip]'); if (ch) { e.preventDefault(); e.stopPropagation(); CHIP = ch.getAttribute('data-zchip'); paint(); return; }
    var sv = t.closest('[data-itam="saveasset"]'); if (sv && document.getElementById('zia_cat')) {
      if (!ADD.cat) { e.preventDefault(); e.stopPropagation(); toast('Choose a category first: Servers, Cloud, Network devices, End-user devices or Other'); var cs = document.getElementById('zia_cat'); if (cs) { cs.focus(); cs.style.outline = '2px solid #ff8a95'; } return; }
      if (ADD.cat === 'network' && !ADD.role) { e.preventDefault(); e.stopPropagation(); toast('Choose the network device role (firewall, switch, router ...)'); var rs = document.getElementById('zia_role'); if (rs) { rs.focus(); rs.style.outline = '2px solid #ff8a95'; } return; }
    }
    var zi = t.closest('[data-zia]'); if (zi && zi.zia) { e.preventDefault(); e.stopPropagation(); zi.zia(); return; }
    var cn = t.closest('[data-dsc-connect]'); if (cn && !cn.__zidOk && !cn.disabled) { e.preventDefault(); e.stopPropagation(); connectDialog(cn); return; }
    var b = t.closest('[data-zid]'); if (!b) { if (t.classList && t.classList.contains('zid-ov')) close(); return; }
    e.preventDefault(); e.stopPropagation();
    var a = b.getAttribute('data-zid');
    if (a === 'one') dialog([b.getAttribute('data-id')]);
    else if (a === 'bulk') dialog(selected());
    else if (a === 'pick') { PICK = !PICK; if (!PICK) SEL = {}; paint(); }
    else if (a === 'all') { rows().forEach(function (tr) { if (tr.style.display !== 'none') SEL[tr.getAttribute('data-itam-asset')] = true; }); [].forEach.call(document.querySelectorAll('.zid-sel'), function (cb) { cb.checked = !!SEL[cb.getAttribute('data-id')]; }); paint(); }
    else if (a === 'none') { SEL = {}; [].forEach.call(document.querySelectorAll('.zid-sel'), function (cb) { cb.checked = false; }); paint(); }
    else if (a === 'cancel') close();
    else if (a === 'go') run(false);
    else if (a === 'force') run(true);
    else if (a === 'cgo') connectGo();
  }, true);
  document.addEventListener('keydown', function (e) { if ((e.key === 'Enter' || e.key === ' ') && e.target && e.target.zia && !document.querySelector('.zid-ov')) { e.preventDefault(); e.target.zia(); return; } if (!document.querySelector('.zid-ov')) return; if (e.key === 'Escape') { e.stopPropagation(); close(); } else if (e.key === 'Enter' && e.target && e.target.tagName === 'INPUT' && e.target.closest('.zid-ov')) { e.preventDefault(); run(false); } }, true);
  document.addEventListener('change', function (e) {
    var t = e.target;
    if (t && t.id === 'zia_cat') { e.stopPropagation(); ADD.cat = t.value; t.style.outline = ''; var ty = document.getElementById('itam_add_type'), c0 = CATS.filter(function (x) { return x.k === ADD.cat; })[0]; if (ty && c0) ty.value = c0.types[0]; narrowTypes(); return; }
    if (t && t.id === 'zia_role') { e.stopPropagation(); ADD.role = t.value; t.style.outline = ''; return; }
    if (nativeSel()) setTimeout(paint, 0);
  }, true);

  function whoami() { if (ADMIN !== null || Date.now() - ASKED < 60000) return; ASKED = Date.now(); req('GET', '/status').then(function (x) { ADMIN = x.ok ? !!(x.j && x.j.me && x.j.me.role === 'admin') : null; paint(); }); }
  function boot() {
    var t = null;
    new MutationObserver(function (ms) {
      for (var i = 0; i < ms.length; i++) { var n = ms[i].target; if (n.closest && n.closest('.zid-bar,.zid-drawer,.zid-ov')) continue; if (!page()) return; if (ADMIN === null) whoami(); if (!t) t = setTimeout(function () { t = null; paint(); }, 150); return; }
    }).observe(document.body, { childList: true, subtree: true });
    if (page()) whoami();
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot); else boot();
})();
