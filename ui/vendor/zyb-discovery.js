// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
/* zyb-discovery.js - keeps the portal's Asset Discovery pages current without rebuilding the portal: loads the newest
 * Asset Discovery module (/dashboards/vendor/discovery-module.js, a copy of repos/sentra-itam/ui/discovery-module.js) and
 * its Arabic dictionary over the copy built into the portal. The module takes over the discovery pages only when it is
 * newer than the built-in one (window.__asDscVersion), so after the next portal rebuild this loader does nothing.
 * Version 2 added Nutanix Prism; version 3 adds database listeners, Solaris / Unix and storage arrays; version 4 makes the dashboard status and type counts open Results; version 13 links the Scopes page to Scope Studio. Loaded by zyb-menu.js. */
(function () {
  'use strict';
  if (window.__zybDiscovery || /^\/dashboards\//.test(location.pathname)) return; window.__zybDiscovery = true;
  var WANT = 13;
  function go() {
    if (typeof viewHTML !== 'function') { if ((go.n = (go.n || 0) + 1) < 40) setTimeout(go, 500); return; }   // eslint-disable-line no-undef
    if ((window.__asDscVersion || 0) >= WANT) return;
    fetch('/dashboards/vendor/discovery.ar.json?v=' + WANT, { credentials: 'include' }).then(function (r) { return r.ok ? r.json() : {}; }).catch(function () { return {}; }).then(function (d) {
      var X = window.X_AR = window.X_AR || {}, F = function (t) { return window.zybOrgFill ? window.zybOrgFill(String(t)) : t; };   /* the dictionary names the company as {{org.*}} tokens */  for (var k in d) if (Object.prototype.hasOwnProperty.call(d, k) && !Object.prototype.hasOwnProperty.call(X, F(k))) X[F(k)] = F(d[k]);
      var s = document.createElement('script'); s.src = '/dashboards/vendor/discovery-module.js?v=' + WANT; document.head.appendChild(s);
    });
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', go); else go();
})();
