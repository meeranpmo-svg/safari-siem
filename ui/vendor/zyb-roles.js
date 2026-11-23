// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
/* zyb-roles.js - applies the signed-in person's job role (Roles & Functions, /dashboards/roles.html) to the portal:
 * menu sections their role does not include are hidden and cannot be opened. The base access level (viewer / operator /
 * admin) is enforced by the sign-in service and the back ends; this narrows what each person sees on top of it.
 * Accounts without a job role keep the full menu. Administrators always keep Identity & Sign-in and Roles & Functions.
 * Also adds a "Job roles & functions" button to the Users card in Identity & Sign-in. Loaded by zyb-menu.js. */
(function () {
  'use strict';
  if (window.__zybRoles) return; window.__zybRoles = true;
  var ME = null, ALLOW = null, ROLE = null, GATE = '';
  function toast(m) { try { if (typeof infoToast === 'function') { infoToast(m); return; } } catch (e) { /* none */ } }   // eslint-disable-line no-undef
  function load() {
    Promise.all([fetch('/api/itam/roles/me', { credentials: 'include', cache: 'no-store' }).then(function (r) { return r.ok ? r.json() : null; }).catch(function () { return null; }),
      fetch('/auth/whoami', { credentials: 'include', cache: 'no-store' }).then(function (r) { return r.ok ? r.json() : {}; }).catch(function () { return {}; })]).then(function (R) {
      ME = R[0]; GATE = String((R[1] && R[1].role) || '').toLowerCase();
      if (!ME || !ME.role) { ALLOW = null; ROLE = null; show(); return; }
      ROLE = ME.role; ALLOW = { home: 1 }; var known = {};
      (ME.functions || []).forEach(function (f) { (f.views || []).forEach(function (v) { known[v] = 1; if ((ROLE.functions[f.key] || 'none') !== 'none') ALLOW[v] = 1; }); });
      if (GATE === 'admin') { ALLOW.signin = 1; ALLOW.rbac = 1; }
      ALLOW.__known = known;
      apply();
    });
  }
  function allowed(v) {
    if (!ALLOW || !v) return true;
    if (ALLOW[v]) return true;
    if (!ALLOW.__known[v]) return ROLE.base === 'admin';   // a section not in the catalogue: administrators only
    return false;
  }
  function show() { [].forEach.call(document.querySelectorAll('[data-zyb-role-hidden]'), function (el) { el.style.display = ''; el.removeAttribute('data-zyb-role-hidden'); }); }
  function hide(el) { if (el.style.display !== 'none') { el.style.display = 'none'; el.setAttribute('data-zyb-role-hidden', '1'); } }
  function apply() {
    if (!ALLOW) return;
    var nav = document.querySelector('ul.nav'); if (!nav) return;
    [].forEach.call(nav.querySelectorAll('li[data-view]'), function (li) { if (!allowed(li.getAttribute('data-view'))) hide(li); });
    // "All platform dashboards" off no longer hides every dashboard: zyb-modules.js shows the sections of the role's functions
    // group headers with nothing left under them
    [].forEach.call(nav.querySelectorAll('li.nav-group'), function (g) {
      var n = g.nextElementSibling, any = false;
      while (n && !n.classList.contains('nav-group')) { if (n.style.display !== 'none') { any = true; break; } n = n.nextElementSibling; }
      if (!any) hide(g);
    });
    try { if (typeof currentView !== 'undefined' && !allowed(currentView) && typeof window.setView === 'function') window.setView('home'); } catch (e) { /* portal not ready */ }   // eslint-disable-line no-undef
  }
  function guard() {
    if (typeof window.setView !== 'function' || window.setView.__zybRole) return;
    var sv = window.setView;
    window.setView = function (v) { if (!allowed(v)) { toast('Your role "' + (ROLE && ROLE.name) + '" does not include this section. Ask an administrator (Roles & Functions).'); return; } return sv.apply(this, arguments); };
    window.setView.__zybRole = true;
  }
  /* Identity & Sign-in → Users: a button to the Roles & Functions page */
  function usersLink() {
    var h = [].filter.call(document.querySelectorAll('.x-card h3'), function (x) { return /local accounts/i.test(x.textContent); })[0];
    if (!h || h.querySelector('[data-zyb-roleslink]')) return;
    var a = document.createElement('a'); a.href = '/dashboards/roles.html'; a.className = 'x-btn sm'; a.setAttribute('data-zyb-roleslink', '1'); a.style.marginLeft = '8px';
    a.textContent = '🧩 Job roles & functions'; a.addEventListener('click', function (e) { e.stopPropagation(); }, true);
    h.appendChild(a);
  }
  document.addEventListener('click', function (e) {   // menu clicks that bypass setView
    var li = e.target && e.target.closest && e.target.closest('ul.nav li[data-view]');
    if (li && !allowed(li.getAttribute('data-view'))) { e.preventDefault(); e.stopPropagation(); if (e.stopImmediatePropagation) e.stopImmediatePropagation(); toast('Your role does not include this section.'); }
  }, true);
  load(); setInterval(load, 5 * 60000);
  setInterval(function () { guard(); apply(); usersLink(); }, 1200);
})();
