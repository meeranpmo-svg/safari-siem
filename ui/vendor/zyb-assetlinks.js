// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
/* zyb-assetlinks.js - "Web addresses" in the IT Asset Management asset drawer: the applications a server hosts and its
 * management consoles (ILOM / iLO / iDRAC / vCenter / Prism), APIs and documentation, each with a reachability and HTTPS
 * certificate check. Everyone sees them; operators and admins add, edit, remove and check. Data: engine/asset-links.js
 *   GET /api/itam/asset-links/:id   POST /api/itam/asset-links/:id {links}   POST /api/itam/asset-links/:id/check
 * Works over the existing ITAM page without changing it (the drawer is found by .itam-drawer and the asset id by
 * data-itam-id / the clicked row). Loaded by zyb-menu.js; does nothing when the engine add-on is not installed. */
(function () {
  'use strict';
  if (window.__zybAssetLinks || /^\/dashboards\//.test(location.pathname)) return; window.__zybAssetLinks = true;
  var API = '/api/itam', ROLE = null, LAST = null, MISSING = false, CACHE = {};
  var KL = { app: 'Application', mgmt: 'Management console', api: 'API', docs: 'Documentation', other: 'Other' };
  function E(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); }
  function req(m, p, b) { return new Promise(function (ok) { var x = new XMLHttpRequest(); x.open(m, API + p); x.withCredentials = true; x.timeout = 60000; if (b) x.setRequestHeader('Content-Type', 'application/json'); x.onload = function () { var j = null; try { j = JSON.parse(x.responseText); } catch (e) { /* not JSON: treated as no data */ } ok({ ok: x.status >= 200 && x.status < 300, status: x.status, j: j }); }; x.onerror = x.ontimeout = function () { ok({ ok: false, status: 0, j: null }); }; x.send(b ? JSON.stringify(b) : null); }); }
  function toast(t) { try { if (typeof infoToast === 'function') { infoToast(t); return; } } catch (e) { /* portal function not available on this page: carry on without it */ } }
  function canEdit() { return ROLE === 'admin' || ROLE === 'operator'; }
  var CSS = '.zal-box{margin-top:16px;border-top:1px solid rgba(255,255,255,.1);padding-top:12px;font-size:12.5px}.zal-box h4{margin:0 0 8px;font-size:13.5px;color:#fff;display:flex;gap:8px;align-items:center}'
    + '.zal-box h4 .sp{flex:1}.zal-l{display:grid;grid-template-columns:150px 1fr;gap:5px 10px}.zal-l a{color:#79b8ff;word-break:break-all}.zal-k{color:#9cc3e6;font-size:11px}'
    + '.zal-p{display:inline-block;font-size:10.5px;font-weight:600;padding:1px 7px;border-radius:9px;margin-inline-start:6px}.zal-ok{background:rgba(63,185,80,.16);color:#56d364}.zal-bad{background:rgba(248,81,73,.18);color:#ff7b72}.zal-warn{background:rgba(227,179,65,.16);color:#e3b341}'
    + '.zal-b{font:600 11.5px system-ui,sans-serif;padding:3px 9px;border-radius:7px;border:1px solid rgba(79,195,247,.45);background:rgba(79,195,247,.08);color:#9fd8ff;cursor:pointer}'
    + '.zal-ed{display:grid;grid-template-columns:1fr 2fr 1fr auto;gap:6px;margin-bottom:6px}.zal-ed input,.zal-ed select{font:12px system-ui,sans-serif;background:#0b1520;color:#e6e9ef;border:1px solid rgba(255,255,255,.18);border-radius:6px;padding:5px 7px;min-width:0}'
    + '.zal-m{color:#9aa4b2;font-size:11.5px;margin-top:6px}';
  function css() { if (document.getElementById('zal-css')) return; var s = document.createElement('style'); s.id = 'zal-css'; s.textContent = CSS; document.head.appendChild(s); }

  function drawer() { var r = document.getElementById('itam-root'); return r ? r.querySelector('.itam-drawer') : null; }
  function assetId(dr) { var b = dr.querySelector('[data-itam-id]'); return b ? b.getAttribute('data-itam-id') : LAST; }

  function view(box, id, r) {
    var L = r.links || [], C = r.checked || {};
    var rows = L.map(function (l) {
      var c = C[l.url], st = '';
      if (c) st = c.ok ? '<span class="zal-p zal-ok">' + E(c.status || 'ok') + (c.ms != null ? ' · ' + c.ms + ' ms' : '') + '</span>' : '<span class="zal-p zal-bad">' + E(c.error || ('HTTP ' + c.status)) + '</span>';
      if (c && c.tls) st += '<span class="zal-p ' + (c.tls.days_left < 30 || !c.tls.trusted ? 'zal-warn' : 'zal-ok') + '">cert ' + (c.tls.trusted ? '' : 'not trusted, ') + 'until ' + E(c.tls.valid_to) + '</span>';
      return '<span>' + E(l.label) + '<div class="zal-k">' + E(KL[l.kind] || l.kind) + '</div></span><span><a href="' + E(l.url) + '" target="_blank" rel="noopener noreferrer">' + E(l.url) + '</a>' + st + '</span>';
    }).join('');
    box.innerHTML = '<h4>🌐 Web addresses <span class="sp"></span>' + (canEdit() && L.length ? '<button type="button" class="zal-b" data-zal="check">Check</button>' : '') + (canEdit() ? '<button type="button" class="zal-b" data-zal="edit">' + (L.length ? 'Edit' : '+ Add') + '</button>' : '') + '</h4>'
      + (L.length ? '<div class="zal-l">' + rows + '</div>' : '<div class="zal-m">No web addresses recorded for this asset' + (canEdit() ? ' - add the applications it hosts and its management console (ILOM / iLO / iDRAC).' : '.') + '</div>');
    box.setAttribute('data-id', id);
  }
  function editor(box, id, r) {
    var L = (r.links || []).slice(); if (!L.length) L.push({ kind: 'app' });
    function row(l) { return '<div class="zal-ed"><input class="zl" placeholder="Label (ERP, ILOM)" value="' + E(l.label || '') + '"><input class="zu" dir="ltr" placeholder="https://..." value="' + E(l.url || '') + '"><select class="zk">' + Object.keys(KL).map(function (k) { return '<option value="' + k + '"' + (k === (l.kind || 'app') ? ' selected' : '') + '>' + KL[k] + '</option>'; }).join('') + '</select><button type="button" class="zal-b" data-zal="rm">✕</button></div>'; }
    box.innerHTML = '<h4>🌐 Web addresses</h4><div class="zal-rows">' + L.map(row).join('') + '</div>'
      + '<div style="display:flex;gap:6px;margin-top:6px"><button type="button" class="zal-b" data-zal="add">+ Address</button><span style="flex:1"></span><button type="button" class="zal-b" data-zal="cancel">Cancel</button><button type="button" class="zal-b" data-zal="save">Save</button></div>'
      + '<div class="zal-m">No user names or passwords in the address - only where to reach it.</div>';
    box.__row = row;
  }
  function load(box, id) {
    req('GET', '/asset-links/' + encodeURIComponent(id)).then(function (x) {
      if (x.status === 404 && x.j && x.j.error === 'not found') { MISSING = true; box.remove(); return; }   // engine add-on not installed
      if (!x.ok) { box.innerHTML = '<h4>🌐 Web addresses</h4><div class="zal-m">' + E((x.j && x.j.error) || 'could not load') + '</div>'; return; }
      CACHE[id] = x.j; view(box, id, x.j);
    });
  }
  function paint() {
    if (MISSING) return;
    var dr = drawer(); if (!dr) return;
    var id = assetId(dr); if (!id) return;
    var box = dr.querySelector('.zal-box');
    if (box && box.getAttribute('data-id') === id) return;
    css();
    if (!box) { box = document.createElement('div'); box.className = 'zal-box'; dr.appendChild(box); }
    box.setAttribute('data-id', id); box.innerHTML = '<h4>🌐 Web addresses</h4><div class="zal-m">Loading…</div>';
    load(box, id);
  }
  document.addEventListener('click', function (ev) {
    var t = ev.target; if (!t || !t.closest) return;
    var tr = t.closest('[data-itam-asset]'); if (tr) LAST = tr.getAttribute('data-itam-asset');
    var b = t.closest('[data-zal]'); if (!b) return;
    var box = b.closest('.zal-box'), id = box && box.getAttribute('data-id'); if (!id) return;
    var a = b.getAttribute('data-zal');
    if (a === 'edit') editor(box, id, CACHE[id] || {});
    else if (a === 'cancel') view(box, id, CACHE[id] || {});
    else if (a === 'add') box.querySelector('.zal-rows').insertAdjacentHTML('beforeend', box.__row({ kind: 'app' }));
    else if (a === 'rm') b.closest('.zal-ed').remove();
    else if (a === 'save') {
      var links = [].map.call(box.querySelectorAll('.zal-ed'), function (r) { return { label: r.querySelector('.zl').value.trim(), url: r.querySelector('.zu').value.trim(), kind: r.querySelector('.zk').value }; }).filter(function (l) { return l.url; });
      b.disabled = true;
      req('POST', '/asset-links/' + encodeURIComponent(id), { links: links }).then(function (x) { if (x.ok) { CACHE[id] = x.j; view(box, id, x.j); toast('Web addresses saved'); } else { b.disabled = false; toast((x.j && x.j.error) || 'Could not save'); } });
    } else if (a === 'check') {
      b.disabled = true; b.textContent = 'Checking…';
      req('POST', '/asset-links/' + encodeURIComponent(id) + '/check', {}).then(function (x) { if (x.ok) { CACHE[id] = x.j; view(box, id, x.j); } else { b.disabled = false; b.textContent = 'Check'; toast((x.j && x.j.error) || 'Could not check'); } });
    }
  }, true);
  function boot() {
    req('GET', '/status').then(function (x) { ROLE = x.ok && x.j && x.j.me ? String(x.j.me.role || '') : 'viewer'; paint(); });
    var t = null;
    new MutationObserver(function (ms) {
      for (var i = 0; i < ms.length; i++) { var n = ms[i].target; if (n.closest && n.closest('.zal-box')) continue; if (!t) t = setTimeout(function () { t = null; paint(); }, 250); return; }
    }).observe(document.body, { childList: true, subtree: true });
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot); else boot();
})();
