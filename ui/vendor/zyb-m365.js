// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
/* zyb-m365.js - the portal's Microsoft 365, User Management (sign-ins), Intune and M365 Security pages read /api/m365
 * (the older m365-sync service). When that service has no credentials ("configured": false) or is not there, the same
 * data comes from the SIEM's Microsoft Graph sync instead (/api/soc/m365/graph, configured on /dashboards/m365.html),
 * so one Microsoft 365 connection feeds every page. Nothing is written; the portal's own pullM365() does the drawing.
 * Loaded by zyb-menu.js. */
(function () {
  'use strict';
  if (window.__zybM365 || typeof window.fetch !== 'function') return; window.__zybM365 = true;
  var orig = window.fetch.bind(window);
  function isM365(input, init) {
    var u = typeof input === 'string' ? input : input && input.url; if (!u) return false;
    var m = (init && init.method) || (input && input.method) || 'GET';
    try { u = new URL(u, location.href); } catch (e) { return false; }
    return u.origin === location.origin && u.pathname === '/api/m365' && String(m).toUpperCase() === 'GET';
  }
  function siem() {
    return orig('/api/soc/m365/graph', { credentials: 'include', cache: 'no-store' }).then(function (r) { return r.ok ? r.json() : null; }).catch(function () { return null; });
  }
  window.fetch = function (input, init) {
    if (!isM365(input, init)) return orig(input, init);
    return orig(input, init).then(function (r) {
      if (!r.ok) return siem().then(function (j) { return j && j.configured ? new Response(JSON.stringify(j), { status: 200, headers: { 'Content-Type': 'application/json' } }) : r; });
      return r.clone().json().then(function (h) {
        if (h && h.configured) return r;   // the older sync is connected: leave it alone
        return siem().then(function (j) {
          if (!j || !j.configured) return r;
          if (h && Array.isArray(h.assets) && !j.assets) j.assets = h.assets;   // contract renewals still come from the hub file
          return new Response(JSON.stringify(j), { status: 200, headers: { 'Content-Type': 'application/json' } });
        });
      }).catch(function () { return r; });
    });
  };
  // the portal's own "Not connected" line says the credentials are missing but not where they go: add the way there
  function hint() {
    var els = document.querySelectorAll('div,p,span'); 
    for (var i = 0; i < els.length; i++) {
      var el = els[i];
      if (el.children.length > 2 || el.getAttribute('data-zm365') || !/auto-sync credentials are not configured/i.test(el.textContent || '')) continue;
      if ([].some.call(el.querySelectorAll('div,p,span'), function (c) { return /auto-sync credentials are not configured/i.test(c.textContent || ''); })) continue;   // the innermost element only
      el.setAttribute('data-zm365', '1');
      var a = document.createElement('a'); a.href = '/dashboards/m365.html#config'; a.textContent = 'Set up the Microsoft 365 connection →';
      a.style.cssText = 'margin-inline-start:10px;color:#79b8ff;font-weight:600;white-space:nowrap';
      el.appendChild(a);
    }
  }
  setInterval(hint, 1500);
  function pull() { try { if (typeof pullM365 === 'function') pullM365(); } catch (e) { /* portal not ready */ } }   // eslint-disable-line no-undef
  setTimeout(pull, 1500);
  setInterval(function () { if (!document.hidden) pull(); }, 5 * 60000);
})();
