// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
/* zyb-assetreg.js - IT Asset Register (portal page fed by /api/db, SQLite): the six summary tiles open the assets
 * behind them - registered, very high / criticality 4, production, DR site, by location, by layer - in a searchable list
 * with CSV export. Uses the register's own loaded data (window.AS_DATA.assetInventory); nothing is changed.
 * Loaded by zyb-menu.js. */
(function () {
  'use strict';
  if (window.__zybAssetReg) return; window.__zybAssetReg = true;
  function E(v) { return String(v == null ? '' : v).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); }
  function inv() { try { return (window.AS_DATA && Array.isArray(window.AS_DATA.assetInventory)) ? window.AS_DATA.assetInventory : []; } catch (e) { return []; } }
  function crit(a) { return Math.max(a.C || 0, a.I || 0, a.A || 0); }
  var TILES = [
    ['All registered assets', function () { return true; }],
    ['Very high / criticality 4', function (a) { return a.risk === 'Very High' || crit(a) === 4; }],
    ['Production', function (a) { return /prod/i.test(a.env || ''); }],
    ['DR-site assets', function (a) { return /DR/.test(a.env || '') || /DR/.test(a.loc || ''); }],
    ['Locations', null, 'loc'],
    ['Asset layers', null, 'layer']];

  function stats() {
    var r = document.querySelector('[data-areload]'); if (!r) return null;
    var n = r; while (n && n.parentNode && !(n.nextElementSibling && n.nextElementSibling.classList && n.nextElementSibling.classList.contains('noc-stats'))) n = n.parentNode;
    return n && n.nextElementSibling;
  }
  function decorate() {
    var s = stats(); if (!s || s.getAttribute('data-zybar')) return;
    s.setAttribute('data-zybar', '1');
    [].forEach.call(s.children, function (el, i) {
      if (!TILES[i]) return;
      el.setAttribute('data-zybar-t', String(i)); el.setAttribute('role', 'button'); el.setAttribute('tabindex', '0');
      el.style.cursor = 'pointer'; el.title = 'Show ' + TILES[i][0].toLowerCase();
    });
  }

  var CSS = '#zar-ov{position:fixed;inset:0;background:rgba(0,0,0,.55);z-index:100000;display:flex;align-items:flex-start;justify-content:center;padding:40px 16px;overflow:auto}'
    + '#zar-ov .d{background:var(--panel,#13151B);color:var(--txt,#ECEEF2);border:1px solid var(--line,#2E3440);border-radius:12px;width:min(1200px,100%);padding:16px;box-shadow:0 20px 60px rgba(0,0,0,.5)}'
    + '#zar-ov h3{margin:0 0 10px;font-size:16px;display:flex;gap:8px;align-items:center}#zar-ov h3 span{color:var(--muted,#8C93A1);font-weight:400;font-size:12px}'
    + '#zar-ov table{width:100%;border-collapse:collapse;font-size:12px}#zar-ov th{text-align:left;color:var(--muted,#8C93A1);font-weight:500;padding:6px;border-bottom:1px solid var(--line,#2E3440)}'
    + '#zar-ov td{padding:6px;border-bottom:1px solid rgba(255,255,255,.05);vertical-align:top}#zar-ov tr[data-g]{cursor:pointer}#zar-ov tr[data-g]:hover td{background:rgba(255,255,255,.04)}'
    + '#zar-ov input{padding:6px 10px;border:1px solid var(--line,#2E3440);border-radius:7px;background:transparent;color:inherit;font-size:12px;width:240px}'
    + '#zar-ov button{border:1px solid var(--line,#2E3440);background:transparent;color:inherit;border-radius:7px;padding:5px 11px;cursor:pointer;font-size:12px}'
    + '#zar-ov .m{color:var(--muted,#8C93A1);font-size:10.5px}#zar-ov .p{display:inline-block;font-size:10px;font-weight:700;padding:1px 7px;border-radius:8px;background:rgba(255,255,255,.08)}#zar-ov .p.vh{background:rgba(232,85,107,.18);color:#ff8a95}';
  var CUR = { title: '', list: [], q: '' };
  function overlay() {
    var o = document.getElementById('zar-ov'); if (o) return o;
    if (!document.getElementById('zar-css')) { var st = document.createElement('style'); st.id = 'zar-css'; st.textContent = CSS; document.head.appendChild(st); }
    o = document.createElement('div'); o.id = 'zar-ov'; o.setAttribute('role', 'dialog'); o.setAttribute('aria-modal', 'true');
    o.addEventListener('click', function (e) { if (e.target === o || e.target.closest('[data-zar="x"]')) close(); });
    document.body.appendChild(o); return o;
  }
  function close() { var o = document.getElementById('zar-ov'); if (o) o.remove(); }
  function showList(title, list) {
    CUR = { title: title, list: list, q: '' };
    var o = overlay();
    o.innerHTML = '<div class="d"><h3>' + E(title) + ' <span id="zar-n"></span><span style="flex:1"></span><input id="zar-q" type="search" placeholder="Search device, IP, purpose, site…" aria-label="Search"> <button type="button" data-zar="csv">⬇ CSV</button> <button type="button" data-zar="x" aria-label="Close">✕</button></h3><div style="max-height:70vh;overflow:auto" id="zar-b"></div></div>';
    var q = document.getElementById('zar-q'); q.addEventListener('input', function () { CUR.q = q.value.toLowerCase(); body(); }); q.focus();
    body();
  }
  function rowsNow() { var q = CUR.q; return CUR.list.filter(function (a) { return !q || [a.dev, a.ip, a.type, a.layer, a.purpose, a.bg, a.env, a.loc, a.city, a.mfr, a.model, a.owner, a.risk].join(' ').toLowerCase().indexOf(q) >= 0; }); }
  function body() {
    var L = rowsNow().slice().sort(function (a, b) { return crit(b) - crit(a) || String(a.dev).localeCompare(String(b.dev)); });
    document.getElementById('zar-n').textContent = L.length + ' assets';
    document.getElementById('zar-b').innerHTML = L.length ? '<table><thead><tr><th>Device</th><th>Type · layer</th><th>Purpose</th><th>Owner</th><th>Environment</th><th>Location</th><th>C · I · A</th><th>Risk</th><th>Vendor</th></tr></thead><tbody>'
      + L.slice(0, 1000).map(function (a) { return '<tr><td><b>' + E(a.dev || '—') + '</b>' + (a.ip ? '<div class="m">' + E(a.ip) + '</div>' : '') + '</td><td>' + E(a.type) + '<div class="m">' + E(a.layer) + '</div></td><td>' + E(a.purpose || '—') + (a.bg ? '<div class="m">' + E(a.bg) + '</div>' : '') + '</td><td>' + E(a.owner || '') + '<div class="m">' + E(a.cust || '') + '</div></td><td>' + E(a.env || '') + '</td><td>' + E(a.loc || '') + '<div class="m">' + E(a.city || '') + '</div></td><td>' + [a.C, a.I, a.A].map(function (x) { return x || '–'; }).join(' · ') + '</td><td><span class="p' + (a.risk === 'Very High' || crit(a) === 4 ? ' vh' : '') + '">' + E(a.risk || '—') + '</span></td><td>' + E(a.mfr || '—') + (a.model ? '<div class="m">' + E(a.model) + '</div>' : '') + '</td></tr>'; }).join('')
      + '</tbody></table>' + (L.length > 1000 ? '<p class="m">First 1000 shown — narrow with the search box or export CSV.</p>' : '') : '<p class="m">No assets match.</p>';
  }
  function showGroups(title, key) {
    var all = inv(), g = {};
    all.forEach(function (a) { var k = a[key] || '(not set)'; (g[k] = g[k] || []).push(a); });
    var keys = Object.keys(g).sort(function (a, b) { return g[b].length - g[a].length; });
    var o = overlay();
    o.innerHTML = '<div class="d"><h3>' + E(title) + ' <span>' + keys.length + ' · click one to see its assets</span><span style="flex:1"></span><button type="button" data-zar="x" aria-label="Close">✕</button></h3><table><thead><tr><th>' + (key === 'loc' ? 'Location' : 'Layer') + '</th><th>Assets</th><th>Very high / crit. 4</th><th>Production</th><th>DR</th></tr></thead><tbody>'
      + keys.map(function (k) { var L = g[k]; return '<tr data-g="' + E(k) + '" data-key="' + key + '" tabindex="0"><td><b>' + E(k) + '</b>' + (key === 'loc' && L[0] && L[0].city ? '<div class="m">' + E(L[0].city) + '</div>' : '') + '</td><td>' + L.length + '</td><td>' + L.filter(TILES[1][1]).length + '</td><td>' + L.filter(TILES[2][1]).length + '</td><td>' + L.filter(TILES[3][1]).length + '</td></tr>'; }).join('') + '</tbody></table></div>';
  }
  /* ---- Locations (= sites): shared list in IT Asset Management (/api/itam/locations) + the register's own locations.
     Edit renames the location on every register asset (/api/db) and every inventory asset; Add creates one with no assets yet. */
  var LOCS = null, KINDS = ['main', 'dr', 'branch', 'cloud', 'other'], KL = { main: 'Main site', dr: 'DR site', branch: 'Branch', cloud: 'Cloud', other: 'Other' };
  function admin() { try { return typeof _role === 'function' && _role() === 'admin'; } catch (e) { return false; } }   // eslint-disable-line no-undef
  function api(m, u, b) { return fetch(u, { method: m, credentials: 'same-origin', cache: 'no-store', headers: { 'Content-Type': 'application/json' }, body: b ? JSON.stringify(b) : undefined }).then(function (r) { return r.json().catch(function () { return {}; }).then(function (j) { if (!r.ok) throw Object.assign(new Error(j.error || (j.errors && j.errors[0]) || ('HTTP ' + r.status)), { status: r.status }); return j; }); }); }
  function lk(n) { return String(n || '').trim().toLowerCase(); }
  function merged() {
    var m = {}, add = function (name) { var k = lk(name); if (!k) return null; return m[k] || (m[k] = { name: String(name).trim(), city: '', kind: '', reg: 0, inv: 0, id: null, saved: false, address: '', notes: '' }); };
    inv().forEach(function (a) { var x = add(a.loc); if (x) { x.reg++; if (!x.city && a.city) x.city = a.city; } });
    ((LOCS && LOCS.locations) || []).forEach(function (l) { var x = add(l.name); if (!x) return; x.inv = l.assets || 0; x.saved = !!l.saved; x.id = l.id; if (l.city) x.city = l.city; x.kind = l.kind || ''; x.address = l.address || ''; x.notes = l.notes || ''; });
    return Object.keys(m).map(function (k) { return m[k]; }).sort(function (a, b) { return (b.reg + b.inv) - (a.reg + a.inv) || a.name.localeCompare(b.name); });
  }
  function loadLocs() { return api('GET', '/api/itam/locations').then(function (j) { LOCS = j; }).catch(function (e) { LOCS = { error: e.status === 403 ? 'IT Asset Management: operators and administrators only' : e.status === 404 ? 'IT Asset Management on the server does not have the locations list yet - run the update' : e.message }; }); }
  function showLocations() {
    var o = overlay(); o.innerHTML = '<div class="d"><h3>Locations &amp; sites <span>loading…</span><span style="flex:1"></span><button type="button" data-zar="x" aria-label="Close">✕</button></h3></div>';
    loadLocs().then(drawLocations);
  }
  function drawLocations(msg) {
    var L = merged(), A = admin() && LOCS && !LOCS.error, o = overlay();
    o.innerHTML = '<div class="d"><h3>Locations &amp; sites <span>' + L.length + ' · click one to see its assets</span><span style="flex:1"></span>' + (A ? '<button type="button" data-zloc="new">➕ Add location</button> ' : '') + '<button type="button" data-zar="x" aria-label="Close">✕</button></h3>'
      + (LOCS && LOCS.error ? '<p class="m" style="color:#e3b341">' + E(LOCS.error) + ' — editing is off.</p>' : '') + (msg ? '<p class="m" style="color:#56d364">' + E(msg) + '</p>' : '')
      + '<div id="zloc-f"></div><table><thead><tr><th>Location / site</th><th>City</th><th>Kind</th><th>Register assets</th><th>Inventory assets</th><th>Very high</th><th>DR</th>' + (A ? '<th></th>' : '') + '</tr></thead><tbody>'
      + L.map(function (x, i) { var R = inv().filter(function (a) { return lk(a.loc) === lk(x.name); });
        return '<tr data-g="' + E(x.name) + '" data-key="loc" tabindex="0"><td><b>' + E(x.name) + '</b>' + (x.address ? '<div class="m">' + E(x.address) + '</div>' : '') + '</td><td>' + E(x.city || '–') + '</td><td>' + E(KL[x.kind] || '–') + '</td><td>' + x.reg + '</td><td>' + x.inv + '</td><td>' + R.filter(TILES[1][1]).length + '</td><td>' + R.filter(TILES[3][1]).length + '</td>'
          + (A ? '<td style="white-space:nowrap"><button type="button" data-zloc="edit" data-i="' + i + '">✎ Edit</button>' + (x.saved && !x.reg && !x.inv ? ' <button type="button" data-zloc="del" data-i="' + i + '">🗑</button>' : '') + '</td>' : '') + '</tr>'; }).join('')
      + '</tbody></table><p class="m">Locations and sites are one list: editing a name renames it on every IT Asset Register asset and every IT Asset Management asset that uses it. Every change is in the audit log.</p></div>';
    o._locs = L;
  }
  function locForm(x) {
    var f = document.getElementById('zloc-f'); if (!f) return; x = x || { name: '', city: '', kind: '', address: '', notes: '' };
    var I = 'style="padding:6px 9px;border:1px solid var(--line,#2E3440);border-radius:7px;background:transparent;color:inherit;font-size:12px;width:100%"';
    f.innerHTML = '<div style="border:1px dashed var(--line,#2E3440);border-radius:9px;padding:12px;margin:0 0 12px;display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:10px;align-items:end">'
      + '<label class="m">Name<input id="zl-n" ' + I + ' value="' + E(x.name) + '" placeholder="Jeddah DR"></label><label class="m">City<input id="zl-c" ' + I + ' value="' + E(x.city) + '" placeholder="Jeddah"></label>'
      + '<label class="m">Kind<select id="zl-k" ' + I + '><option value="">–</option>' + KINDS.map(function (k) { return '<option value="' + k + '"' + (x.kind === k ? ' selected' : '') + '>' + KL[k] + '</option>'; }).join('') + '</select></label>'
      + '<label class="m">Address<input id="zl-a" ' + I + ' value="' + E(x.address) + '"></label><label class="m">Notes<input id="zl-o" ' + I + ' value="' + E(x.notes) + '"></label>'
      + '<div style="display:flex;gap:8px"><button type="button" data-zloc="save" style="background:#238636;border-color:#238636;color:#fff">' + (x.orig ? 'Save' : 'Add') + '</button><button type="button" data-zloc="cancel">Cancel</button></div>'
      + (x.orig && x.reg ? '<div class="m" style="grid-column:1/-1">Renaming or changing the city updates ' + x.reg + ' register assets' + (x.inv ? ' and ' + x.inv + ' inventory assets' : '') + '.</div>' : '') + '</div>';
    f._x = x; document.getElementById('zl-n').focus();
  }
  function regBody(a, loc, city) { return { dev: a.dev || '', type: a.type || '', layer: a.layer || '', env: a.env || '', purpose: a.purpose || '', bg: a.bg || '', owner: a.owner || '', cust: a.cust || '', loc: loc, city: city, mfr: a.mfr || '', model: a.model || '', ip: a.ip || '', c: a.C, i: a.I, a: a.A, risk: a.risk || '' }; }
  function saveLoc(btn) {
    var f = document.getElementById('zloc-f'), x = f && f._x; if (!x) return;
    var v = function (id) { return document.getElementById(id).value.trim(); };
    var b = { name: v('zl-n'), city: v('zl-c'), kind: v('zl-k'), address: v('zl-a'), notes: v('zl-o') };
    if (!b.name) { alert('Enter a location name'); return; }
    var dup = merged().filter(function (y) { return lk(y.name) === lk(b.name) && (!x.orig || lk(y.name) !== lk(x.orig)); })[0];
    if (dup) { alert('"' + b.name + '" already exists'); return; }
    btn.disabled = true; btn.textContent = 'Saving…';
    var itam = !x.orig ? api('POST', '/api/itam/locations', b) : x.id ? api('POST', '/api/itam/locations/' + encodeURIComponent(x.id), b) : x.inv ? api('POST', '/api/itam/locations/' + encodeURIComponent('site:' + x.orig), b) : api('POST', '/api/itam/locations', b);
    itam.then(function (r) {
      var regs = x.orig && (b.name !== x.orig || b.city !== x.city) ? inv().filter(function (a) { return lk(a.loc) === lk(x.orig) && a.id; }) : [];
      var done = 0, fail = 0, i = 0;
      var next = function () {
        if (i >= regs.length) return Promise.resolve();
        var a = regs[i++];
        return api('PATCH', '/api/db/assets/' + a.id, regBody(a, b.name, b.city || a.city || '')).then(function () { done++; }, function () { fail++; }).then(next);
      };
      return next().then(function () {
        try { var rl = document.querySelector('[data-areload]'); if (rl && regs.length) rl.click(); } catch (e) { /* register reloads later */ }
        return loadLocs().then(function () { drawLocations((x.orig ? 'Saved "' + b.name + '"' : 'Added "' + b.name + '"') + (regs.length ? ' · ' + done + ' register assets updated' + (fail ? ', ' + fail + ' failed' : '') : '') + (r && r.renamed ? ' · ' + r.renamed + ' inventory assets renamed' : '')); });
      });
    }).catch(function (e) { btn.disabled = false; btn.textContent = 'Save'; alert('Not saved: ' + e.message); });
  }
  document.addEventListener('click', function (e) {
    var z = e.target && e.target.closest && e.target.closest('#zar-ov [data-zloc]'); if (!z) return;
    e.stopPropagation(); var a = z.getAttribute('data-zloc'), o = document.getElementById('zar-ov'), L = (o && o._locs) || [];
    if (a === 'new') locForm(null);
    else if (a === 'edit') { var x = L[+z.getAttribute('data-i')]; locForm(Object.assign({ orig: x.name }, x)); }
    else if (a === 'cancel') document.getElementById('zloc-f').innerHTML = '';
    else if (a === 'save') saveLoc(z);
    else if (a === 'del') { var d = L[+z.getAttribute('data-i')]; if (!confirm('Delete the location "' + d.name + '"? No asset uses it.')) return; api('POST', '/api/itam/locations/' + encodeURIComponent(d.id) + '/delete').then(function () { return loadLocs(); }).then(function () { drawLocations('Deleted "' + d.name + '"'); }).catch(function (er) { alert(er.message); }); }
  }, true);
  /* the register's Add / Edit asset form: suggest the known locations, fill the city */
  function formHelp() {
    var f = document.querySelector('[data-af="loc"]'); if (!f || f.getAttribute('list') === 'zar-locs') return;
    var dl = document.getElementById('zar-locs'); if (!dl) { dl = document.createElement('datalist'); dl.id = 'zar-locs'; document.body.appendChild(dl); }
    var paint = function () { var L = merged(); dl.innerHTML = L.map(function (x) { return '<option value="' + E(x.name) + '">' + E(x.city || '') + '</option>'; }).join(''); f._L = L; };
    paint(); if (!LOCS) loadLocs().then(paint);
    f.setAttribute('list', 'zar-locs'); f.setAttribute('autocomplete', 'off');
    f.addEventListener('change', function () { var c = document.querySelector('[data-af="city"]'), x = (f._L || []).filter(function (y) { return lk(y.name) === lk(f.value); })[0]; if (c && x && x.city && !c.value.trim()) c.value = x.city; });
  }
  setInterval(formHelp, 1500);

  function csv() {
    var L = rowsNow(), cols = ['dev', 'ip', 'type', 'layer', 'purpose', 'bg', 'owner', 'cust', 'env', 'loc', 'city', 'C', 'I', 'A', 'risk', 'mfr', 'model'];
    var q = function (v) { v = String(v == null ? '' : v); if (/^[=+\-@\t\r]/.test(v)) v = "'" + v; return '"' + v.replace(/"/g, '""') + '"'; };
    var txt = cols.join(',') + '\n' + L.map(function (a) { return cols.map(function (c) { return q(a[c]); }).join(','); }).join('\n');
    var u = URL.createObjectURL(new Blob(['﻿' + txt], { type: 'text/csv' })), l = document.createElement('a');
    l.href = u; l.download = CUR.title.replace(/[^\w]+/g, '-').toLowerCase() + '.csv'; document.body.appendChild(l); l.click(); l.remove(); setTimeout(function () { URL.revokeObjectURL(u); }, 1000);
  }
  function open(i) {
    var t = TILES[i]; if (!t) return;
    if (t[2] === 'loc') showLocations(); else if (t[2]) showGroups(t[0], t[2]); else showList(t[0], inv().filter(t[1]));
  }
  document.addEventListener('click', function (e) {
    var t = e.target && e.target.closest && e.target.closest('[data-zybar-t]'); if (t) { open(+t.getAttribute('data-zybar-t')); return; }
    var g = e.target && e.target.closest && e.target.closest('#zar-ov tr[data-g]'); if (g) { var k = g.getAttribute('data-key'), v = g.getAttribute('data-g'); showList((k === 'loc' ? 'Location: ' : 'Layer: ') + v, inv().filter(function (a) { return (a[k] || '(not set)') === v; })); return; }
    var c = e.target && e.target.closest && e.target.closest('#zar-ov [data-zar="csv"]'); if (c) csv();
  });
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape' && document.getElementById('zar-ov')) { close(); return; }
    if ((e.key === 'Enter' || e.key === ' ') && e.target && e.target.getAttribute) { if (e.target.getAttribute('data-zybar-t')) { e.preventDefault(); open(+e.target.getAttribute('data-zybar-t')); } else if (e.target.getAttribute('data-g')) { e.preventDefault(); e.target.click(); } }
  });
  setInterval(decorate, 1200);
})();
