// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
/* zyb-poc.js - POC mode for presentations: loaded by zyb-dash.js ONLY while the "POC data" switch in the menu is on (stored in this
 * browser: localStorage zyb-poc = 1) or the address has ?poc=1. Then:
 *   - a GET to /api/... that the illustrative data covers (vendor/zyb-poc-data.js, window.ZYB_POC) is answered from it, never from
 *     the server - the page draws exactly as it would with real data
 *   - every change (POST / PUT / DELETE / PATCH) to /api/... is refused here: nothing is changed in POC mode
 *   - a page that has illustrative data carries the POC ribbon on every corner and a banner; a page without it says that POC data
 *     is on but this page shows live data, so the two are never mistaken for each other
 * The illustrative data is synthetic: invented host names, addresses from documentation ranges, no person's data. */
(function () {
  'use strict';
  if (window.zybPoc) return;
  var hits = 0, pass = 0, refused = [];
  function find(method, url) {
    var u; try { u = new URL(url, location.href); } catch (e) { return null; }
    if (u.pathname.indexOf('/api/') !== 0) return null;
    if (String(method || 'GET').toUpperCase() !== 'GET') return { status: 403, body: { error: 'POC mode: nothing is changed - switch POC data off in the menu to work on live data' } };
    var L = window.ZYB_POC || [];
    for (var i = 0; i < L.length; i++) { if (L[i].re.test(u.pathname)) { var d = typeof L[i].data === 'function' ? L[i].data(u) : L[i].data; hits++; mark(); return { status: 200, body: JSON.parse(JSON.stringify(d)) }; } }
    var R = window.ZYB_POC_REC; if (R && (R.common || []).indexOf(u.pathname) >= 0) return null;   // a platform call every page makes: live
    if (R && R.map && Object.prototype.hasOwnProperty.call(R.map, u.pathname)) { hits++; mark(); return { status: 200, body: shift(JSON.parse(JSON.stringify(R.map[u.pathname])), R.recorded_at) }; }
    // a page that draws from illustrative data never mixes in live answers: what the data does not cover is refused, said plainly
    if (pocPage()) { refused.push(u.pathname); return { status: 503, body: { error: 'POC: no illustrative data for this part of the page' } }; }
    pass++; return null;
  }
  function pocPage() {
    var pg = location.pathname.split('/').pop() || 'index.html', R = window.ZYB_POC_REC;
    if (R && R.pages && R.pages[pg]) return true;
    return (window.ZYB_POC || []).some(function (e) { return (e.pages || []).indexOf(pg) >= 0; });
  }
  // recorded answers carry the dates of the day they were recorded: moved forward by the same amount so the pages look current
  var ISO = /^(\d{4}-\d{2}-\d{2})(T\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+-]\d{2}:?\d{2})?)?$/;
  function shift(v, at) {
    var d = Date.now() - Date.parse(at || ''); if (!(d > 86400000)) return v;
    var walk = function (x) {
      if (typeof x === 'string') { var m = ISO.exec(x); if (!m) return x; var t = Date.parse(m[2] ? x : m[1] + 'T00:00:00Z'); if (isNaN(t)) return x; var n = new Date(t + d).toISOString(); return m[2] ? n : n.slice(0, 10); }
      if (Array.isArray(x)) return x.map(walk);
      if (x && typeof x === 'object') { for (var k in x) if (Object.prototype.hasOwnProperty.call(x, k)) x[k] = walk(x[k]); return x; }
      return x;
    };
    return walk(v);
  }
  // XMLHttpRequest: answered from the illustrative data without a network call
  var open0 = XMLHttpRequest.prototype.open, send0 = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.open = function (m, u) { this.__zybPoc = { m: m, u: u }; return open0.apply(this, arguments); };
  XMLHttpRequest.prototype.send = function () {
    var x = this, r = x.__zybPoc && find(x.__zybPoc.m, x.__zybPoc.u); if (!r) return send0.apply(this, arguments);
    var text = JSON.stringify(r.body), def = function (k, v) { try { Object.defineProperty(x, k, { value: v, configurable: true }); } catch (e) { /* a read-only property on this browser: the handlers still run */ } };
    setTimeout(function () {
      def('readyState', 4); def('status', r.status); def('statusText', r.status === 200 ? 'OK' : 'Forbidden'); def('responseText', text); def('response', x.responseType === 'json' ? r.body : text);
      def('getResponseHeader', function (h) { return /content-type/i.test(h) ? 'application/json' : null; });
      try { if (x.onreadystatechange) x.onreadystatechange(); } catch (e) { setTimeout(function () { throw e; }); }
      try { if (x.onload) x.onload({ target: x }); } catch (e) { setTimeout(function () { throw e; }); }
      try { x.dispatchEvent(new Event('load')); x.dispatchEvent(new Event('loadend')); if (x.onloadend) x.onloadend({ target: x }); } catch (e) { setTimeout(function () { throw e; }); }
    }, 90);
  };
  if (window.fetch) { var f0 = window.fetch; window.fetch = function (input, init) { var u = typeof input === 'string' ? input : (input && input.url) || '', m = (init && init.method) || (input && input.method) || 'GET', r = find(m, u);
    return r ? new Promise(function (ok) { setTimeout(function () { ok(new Response(JSON.stringify(r.body), { status: r.status, headers: { 'Content-Type': 'application/json' } })); }, 90); }) : f0.apply(this, arguments); }; }

  var marked = false;
  function mark() {
    if (marked) return; marked = true;
    var go = function () {
      var st = document.createElement('style'); st.setAttribute('data-zyb-theme', 'skip');
      st.textContent = '.zyb-poc-r{position:fixed;z-index:99999;pointer-events:none;width:230px;padding:7px 0;text-align:center;font:800 14px/1 "Segoe UI",system-ui,sans-serif;letter-spacing:.35em;color:#fff;background:linear-gradient(90deg,#e8590c,#f59f00);box-shadow:0 3px 12px rgba(0,0,0,.45)}'
        + '.zyb-poc-r.tl{top:26px;left:-58px;transform:rotate(-45deg)}.zyb-poc-r.tr{top:26px;right:-58px;transform:rotate(45deg)}.zyb-poc-r.bl{bottom:26px;left:-58px;transform:rotate(45deg)}.zyb-poc-r.br{bottom:26px;right:-58px;transform:rotate(-45deg)}'
        + '.zyb-poc-b{border:2px dashed #f59f00;background:rgba(245,159,0,.1);border-radius:10px;padding:8px 14px;margin:0 0 12px;font-size:13px}.zyb-poc-b b{color:#f59f00;letter-spacing:.1em}';
      document.head.appendChild(st);
      ['tl', 'tr', 'bl', 'br'].forEach(function (c) { var d = document.createElement('div'); d.className = 'zyb-poc-r ' + c; d.setAttribute('aria-hidden', 'true'); d.textContent = 'POC'; document.body.appendChild(d); });
      var b = document.createElement('div'); b.className = 'zyb-poc-b'; b.setAttribute('role', 'note'); b.id = 'zyb-poc-banner';
      b.innerHTML = '<b>POC</b> &nbsp;Illustrative data for presentation - not live, not ' + ((window.ZYB_ORG && window.ZYB_ORG.short) || 'the organisation') + '\'s systems. Nothing can be changed. Switch "POC data" off in the menu for live data.';
      var main = document.querySelector('main'); if (main) main.insertBefore(b, main.firstChild); else document.body.insertBefore(b, document.body.firstChild);
      [].forEach.call(document.querySelectorAll('.live, [id=live], .badge-live'), function (x) { if (/live/i.test(x.textContent)) { x.textContent = 'POC DATA'; x.hidden = false; x.style.background = '#f59f00'; x.style.color = '#111'; } });
      document.title = document.title.replace(/( \(POC\))?$/, ' (POC)');
    };
    if (document.body) go(); else document.addEventListener('DOMContentLoaded', go);
  }
  // a page with no illustrative data says so, once it has loaded
  if (pocPage()) mark();
  window.addEventListener('load', function () { setTimeout(function () { if (hits || document.getElementById('zyb-poc-nodata')) return; var main = document.querySelector('main'); if (!main) return;
    var n = document.createElement('div'); n.id = 'zyb-poc-nodata'; n.className = 'zyb-poc-b'; n.style.cssText = 'border:1px dashed #8b93a4;background:transparent;border-radius:10px;padding:6px 12px;margin:0 0 12px;font-size:12px;color:#8b93a4';
    n.textContent = 'POC data is on, but this page has no illustrative data - it shows LIVE data.'; main.insertBefore(n, main.firstChild); }, 2500); });
  window.zybPoc = { on: true, hits: function () { return hits; }, live: function () { return pass; }, refused: function () { return refused.slice(); } };
})();
