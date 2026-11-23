// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
/* zyb-update.js - a new version shows by itself, in every browser, with no Ctrl+F5.
 * Every update writes /dashboards/build.json ({"build": "<stamp>"}, install-dashboards.sh). Each page (dashboards through
 * zyb-dash.js, the portal through zyb-menu.js) reads it as soon as it opens, every minute, whenever the tab comes back into
 * view or the window gets focus, and when the browser shows a page from its back/forward cache (pageshow persisted) - so a
 * page the browser kept from before an update is noticed within seconds, not minutes. When the
 * build has changed: /dashboards/clear-cache answers with Clear-Site-Data "cache" (add-dashboards-nginx.sh), so the browser
 * drops every file it cached for this site - saved settings, storage and the sign-in are kept - then the page reloads.
 * Someone typing, or with a form / drawer open, is never interrupted: a bar offers "Reload now" instead.
 * One reload per build per tab (sessionStorage), so a page can never reload in a loop. Values shown come only from this
 * file; nothing from the server reaches innerHTML. */
(function () {
  'use strict';
  if (window.__zybUpdate) return; window.__zybUpdate = true;
  var BUILD_URL = '/dashboards/build.json', CLEAR_URL = '/dashboards/clear-cache', EVERY = 60000, FIRST = 1500, GAP = 5000;
  var mine = /^\d{8,}$/.test(String(window.ZYB_BUILD || '')) ? String(window.ZYB_BUILD) : null;   // the build this page was served from, when known
  var typed = false, busy = false, bar = null;
  document.addEventListener('input', function () { typed = true; }, true);

  function editing() {
    var a = document.activeElement;
    if (typed) return true;
    if (a && (/^(TEXTAREA|SELECT)$/.test(a.tagName) || (a.tagName === 'INPUT' && !/^(button|submit|checkbox|radio|reset)$/i.test(a.type || '')) || a.isContentEditable)) return true;
    // a drawer or dialog the person has open (zyb-detail drawer #zd, Bootstrap / Tabler modals, native dialogs)
    var zd = document.getElementById('zd');
    return !!((zd && !zd.hidden && zd.offsetParent !== null) || document.querySelector('.modal.show, dialog[open], [role="dialog"]:not([hidden])[aria-modal="true"]'));
  }
  function seen(b) { try { return sessionStorage.getItem('zyb-updated-' + b) === '1'; } catch (e) { return false; /* no session storage: rely on the build check */ } }
  function mark(b) { try { sessionStorage.setItem('zyb-updated-' + b, '1'); } catch (e) { /* no session storage: the build check alone prevents a second reload */ } }
  function reloadFor(b) {
    mark(b);
    // the cache clear is best effort: a browser without Clear-Site-Data, or a server not yet updated, still reloads
    fetch(CLEAR_URL, { cache: 'no-store', credentials: 'same-origin', zybQuiet: true })
      .catch(function () { /* clear-cache not reachable: the reload below still re-checks every file (no-cache headers) */ })
      .then(function () { location.reload(); });
  }
  function offer(b) {
    if (bar) return;
    bar = document.createElement('div'); bar.id = 'zyb-update'; bar.setAttribute('role', 'status');
    bar.style.cssText = 'position:fixed;left:50%;bottom:18px;transform:translateX(-50%);z-index:2147483000;display:flex;align-items:center;gap:12px;padding:10px 14px;border-radius:10px;background:#0F2C5B;color:#fff;font:14px/1.4 "IBM Plex Sans","Segoe UI",system-ui,sans-serif;box-shadow:0 8px 24px rgba(0,0,0,.25)';
    var t = document.createElement('span'); t.textContent = 'A new version of the platform is installed.';
    var go = document.createElement('button'); go.type = 'button'; go.textContent = 'Reload now';
    go.style.cssText = 'border:0;border-radius:6px;padding:6px 12px;background:#fff;color:#0F2C5B;font-weight:600;cursor:pointer';
    var later = document.createElement('button'); later.type = 'button'; later.textContent = 'Later'; later.setAttribute('aria-label', 'Hide this message');
    later.style.cssText = 'border:0;background:transparent;color:#D3D9E4;cursor:pointer';
    go.addEventListener('click', function () { reloadFor(b); });
    later.addEventListener('click', function () { if (bar) { bar.remove(); bar = null; } });
    bar.appendChild(t); bar.appendChild(go); bar.appendChild(later);
    (document.body || document.documentElement).appendChild(bar);
  }
  var last = 0;
  function check(soon) {
    if (busy || document.hidden) return;
    // focus / pageshow can fire together: one question to the server per few seconds is enough
    if (soon && Date.now() - last < GAP) return;
    busy = true; last = Date.now();
    fetch(BUILD_URL + '?t=' + Date.now(), { cache: 'no-store', credentials: 'same-origin', zybQuiet: true })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (j) {
        var b = j && j.build != null ? String(j.build) : '';
        if (!/^\d{8,}$/.test(b)) return;
        if (!mine) { mine = b; return; }          // first answer on a page that did not know its build: the baseline
        if (b === mine) return;
        if (seen(b) || editing()) offer(b); else reloadFor(b);
      })
      .catch(function () { /* offline, signed out or not installed yet: the next round tries again */ })
      .then(function () { busy = false; });
  }
  // a self-rescheduling loop: the next round is booked whatever this one did. The first round runs shortly after the page
  // opens (one small no-store request): a page the browser served from its cache from before an update is caught at once.
  setTimeout(function loop() { try { check(); } finally { setTimeout(loop, EVERY); } }, FIRST);
  document.addEventListener('visibilitychange', function () { if (!document.hidden) check(true); });
  window.addEventListener('focus', function () { check(true); });
  // back / forward: the browser may show the old page from memory without asking the server at all
  window.addEventListener('pageshow', function (e) { if (e && e.persisted) { last = 0; check(true); } });
  window.zybUpdate = { check: check };
})();
