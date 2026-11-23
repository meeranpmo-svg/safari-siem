// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
/* zyb-early.js - runs in the portal's <head>, BEFORE the portal's own code (add-dashboards-menu.sh adds the tag), so a
 * refresh never shows the old pages first:
 *   - portal pages replaced by a live page (sample telemetry, typed-in figures) are hidden from the menu at once;
 *   - the menu stays invisible until zyb-menu.js has arranged it (workspaces, order, favourites) - never longer than 5 s;
 *   - an address that names a replaced page (#sam, #infradash, a bookmark) goes straight to its live page instead of
 *     drawing the old page and redirecting; a page whose live twin is another portal page (#assetreg) opens that one.
 * The page maps here must match zyb-menu.js LIVE / COVERED / ALIAS (menu-early.test.js compares them). Nothing is sent. */
(function () {
  'use strict';
  if (window.__zybEarly) return; window.__zybEarly = true;
  // portal view -> live dashboard page (zyb-menu.js LIVE: the ones that replace a sample page)
  var LIVE = window.ZYB_EARLY_LIVE = { siemlive: 'soc-live.html', spo: 'sharepoint.html#activity', npm: 'npm-summary.html', netperf: 'branch-connectivity.html', traffic: 'netflow.html', udt: 'rogue-detection.html', wireless: 'wireless.html', adex: 'ad-exchange.html', printers: 'printers.html', 'itam-assets': 'inventory.html', 'itam-ai': 'ai-findings.html', 'itam-stocktake': 'stocktake.html', itam: 'itam-overview.html', costopt: 'cost-optimisation.html', budget: 'budget.html#exec', 'itam-settings': 'itam-settings.html', 'itam-software': 'software-studio.html', cloudsrv: 'servers.html', ups: 'facilities.html#ups', door: 'door-access.html', ipam: 'ipam.html', ncm: 'ncm.html', m365sec: 'm365-security.html', branchnet: 'branch-connectivity.html', 'dash-fac': 'facilities.html', 'intune': 'mdm.html', 'dash-soc': 'soc-overview.html', 'agents': 'ai-team.html', 'managed': 'service-agreement.html', 'infra-wanopt': 'wan-optimization.html', 'upd-overview': 'cisco-update.html', 'upd-inventory': 'cisco-update.html#view=devices', 'upd-advisories': 'cisco-update.html#view=advisories', 'upd-plans': 'cisco-update.html#view=plans', 'upd-policy': 'cisco-update.html#view=policy', 'upd-connections': 'cisco-update.html#view=connections', command: 'executive-dashboard.html', posture: 'risk-command.html', servicedesk: 'support-center.html', support: 'support-center.html', 'dash-net': 'network-dashboard.html', infradash: 'infra-manager.html', ciodash: 'cio-dashboard.html', cisodash: 'ciso-dashboard.html', ciso: 'executive-dashboard.html', status: 'live-status.html', home: 'index.html', phishsim: 'phishing-simulation.html', brandprot: 'brand-protection.html', forensics: 'dfir.html', ir: 'incident-response.html', soar: 'soar.html', tickets: 'tickets.html', cctv: 'cctv.html', appsec: 'appsec.html', apppt: 'apppt.html', crosswalk: 'crosswalk.html', gapall: 'gap-analysis.html', 'dash-grc': 'grc-dashboard.html', 'dash-vuln': 'vuln-dashboard.html', scanlive: 'live-scan.html', webapi: 'webapps.html', mobile: 'mobile-test.html', iso: 'iso-lifecycle.html', ecc: 'ecc-studio.html', roadmap: 'roadmap.html', risk: 'risk-assess.html', 'siem-sama': 'sama-siem.html', maturity: 'maturity-level.html', netcfg: 'network-config-audit.html', roles: 'roles-raci.html', ncaaudit: 'nca-it-audit.html', ndmostudio: 'ndmo-studio.html', ndmo: 'ndmo-studio.html', pdpl: 'pdpl-studio.html', chain: 'compliance-flow.html', fwlib: 'framework-library.html', aigov: 'ai-governance.html', infraai: 'infra-ai.html', bcm: 'bcm-matrix.html', grc: 'compliance-overview.html', contcomp: 'continuous-compliance.html', validation: 'control-validation.html', custody: 'evidence-custody.html', docs: 'compliance-docs.html', controls: 'security-controls.html', archer: 'grc-register.html', iafw: 'ia-resilience.html', irm: 'insider-risk.html', sama: 'sama-audit.html', 'sama-validation': 'sama-audit.html', 'discovery': 'discovery-studio.html', 'itam-discovery': 'discovery-studio.html', 'discovery-results': 'discovery-studio.html#view=res', 'discovery-runs': 'discovery-studio.html#view=runs', 'discovery-credentials': 'discovery-studio.html#view=cred', 'discovery-scopes': 'scope-studio.html', repcenter: 'report-center.html', notify: 'notify-center.html', sam: 'apm.html', npmmon: 'npm-summary.html', alarmrules: 'alarm-rules.html', 'soc-rules': 'alarm-rules.html', signin: 'identity-signin.html', users: 'user-management.html', twin: 'digital-twin.html',
    dbperf: 'db-performance.html', exchmgmt: 'exchange-admin.html', datagov: 'dlp.html', detstudio: 'detection-validation.html', node: 'server-availability.html',
    scm: 'manageengine.html', 'dash-rep': 'platform.html', 'dash-m365': 'm365-dashboard.html', portmap: 'switch-port-map.html', topology: 'network-map.html', logs: 'log-monitor.html', changelog: 'change-log.html', hunt: 'soc-hunt.html', rogue: 'rogue-detection.html', security: 'security-center.html', soc: 'security-center.html', noc: 'ops-wall.html?view=sites', aisoc: 'ai-soc-analyst.html', socops: 'soc-performance.html', msauto: 'm365-autoconfig.html', wazuh: 'soc-console.html', 'tiw-darkweb': 'dark-web-watch.html', nac: 'network-access.html', itops: 'update-studio.html', netinv: 'infra-inventory.html', 'dash-srv': 'servers-dashboard.html', wall: 'ops-wall.html', 'itam-cmdb': 'cmdb-deps.html', implplan: 'impl-plan.html', browsing: 'browsing-monitor.html', configure: 'device-config.html', aiteam: 'ai-team.html', aiops: 'aiops.html', repl: 'dr-studio.html', virtualization: 'vsphere-studio.html', 'vuln-assets': 'scanned-assets.html' };
  var ALIAS = window.ZYB_EARLY_ALIAS = { assetreg: 'itam-assets' };
  var root = document.documentElement;
  var hide = Object.keys(LIVE).concat(Object.keys(ALIAS)).concat(['db-oracle']).map(function (v) { return 'ul.nav:not(.zyb-editing) li[data-view="' + v + '"]'; }).join(',');
  var st = document.createElement('style'); st.id = 'zyb-early-css';
  st.textContent = hide + '{display:none!important}'
    // the menu appears once, already arranged; an admin editing the menu sees everything (zyb-menu marks the list)
    + 'html:not(.zyb-menu-on) aside.side ul.nav{visibility:hidden}'
    + 'html.zyb-early-dash #viewFocus{visibility:hidden}'
    // the whole portal waits for the platform look (zyb-look.js marks html.zyb-look-ready): a first sign-in on an empty cache
    // used to show the old green portal and then switch
    + 'html:not(.zyb-look-ready) body{visibility:hidden}'
    // the portal's own logo boxes stay invisible (still laid out, so zyb-menu.js can find and replace them) until the
    // compact brand header is in place - otherwise the old logos flash on every load
    + 'html:not(.zyb-brand-on) aside.side .brand,html:not(.zyb-brand-on) aside.side .as-logo,html:not(.zyb-brand-on) aside.side img[src*="logo"]{visibility:hidden}';
  (document.head || root).appendChild(st);
  var reveal = function () { root.classList.add('zyb-menu-on', 'zyb-brand-on'); root.classList.remove('zyb-early-dash'); };
  setTimeout(function () { root.classList.add('zyb-look-ready'); }, 4000);   // the look never holds the page back longer
  setTimeout(reveal, 5000);   // whatever happens, never a hidden menu or page
  window.zybEarlyReveal = reveal;
  // the address: #view -> its live page / its live twin, before the portal reads it
  try {
    var v = (location.hash || '').replace(/^#/, '').split(/[?&]/)[0];
    // the portal opened on its own address (/, no view named): it lands on the platform home, not the portal's old start page;
    // "Portal home" links carry ?zybportal=1, so the portal itself stays one click away
    if (!v && (location.pathname === '/' || location.pathname === '/index.html') && !location.search) v = 'home';
    if (ALIAS[v]) history.replaceState(history.state, '', location.pathname + location.search + '#' + ALIAS[v]);
    else if (LIVE[v] && !/[?&]zybdash=/.test(location.search) && window.innerWidth >= 901) {
      history.replaceState({ zybdash: '/dashboards/' + LIVE[v] }, '', '/?zybdash=' + encodeURIComponent(LIVE[v]));
      root.classList.add('zyb-early-dash');   // the portal draws its home underneath; zyb-menu opens the live page over it
    }
    if (/[?&]zybdash=/.test(location.search)) root.classList.add('zyb-early-dash');
  } catch (e) { /* the address stays as it is: zyb-menu still redirects, just later */ }
})();
