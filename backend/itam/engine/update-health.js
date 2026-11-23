// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const fs = require('node:fs');
/*
 * Update Health ({P} = /api/itam, Platform Admin -> Update Health): after an update, does every page actually work - and if not,
 * why? It answers from three facts, never a guess:
 *   - the running engine's own route table (srv.list()): each page's API is registered or it is not
 *   - the modules duty.js could not load (app.dutyMissing - the "module not installed" cases)
 *   - the update report the installers write (install/update-doctor.js -> update-report.json): each installer's result, the pages it
 *     found not answering and the causes the update doctor read from the service log, with the fix
 *   GET /platform/update-health   admin   {summary, pages[], missing_modules[], installers[], findings[]}
 */
const PAGES = [
  ['Email Route Map', 'email-route-map.html', 'GET', '/mail-route', 'mail-reputation'],
  ['Email route troubleshooter', 'email-route-map.html', 'POST', '/mail-route/troubleshoot', 'mail-doctor'],
  ['Servers by platform', 'vmware-servers.html', 'GET', '/servers', 'servers'],
  ['AI Auditors', 'ai-auditors.html', 'GET', '/audit-programme', 'auditors'],
  ['Continuous control monitoring', 'audit-ccm.html', 'GET', '/audit-ccm', 'audit-ccm'],
  ['Audit Command Center', 'audit-command.html', 'GET', '/audit-auto', 'audit-auto'],
  ['SAMA IT Audit', 'sama-it-audit.html', 'GET', '/sama-itaudit', 'sama-itaudit'],
  ['Audit dashboard', 'audit-dashboard.html', 'GET', '/audit-dashboard', 'audit-dashboard'],
  ['Notification & Escalation', 'notify-center.html', 'GET', '/notify', 'notify-center'],
  ['My Workspace', 'my-workspace.html', 'GET', '/workspace/org', 'team-workspace'],
  ['Virtual Network Map', 'virtual-network-map.html', 'GET', '/virt-network', 'virt-network'],
  ['Service Agreement (SLA & NDA)', 'service-agreement.html', 'GET', '/sla', 'service-agreement'],
  ['Risk Studio', 'risk-studio.html', 'GET', '/risk-studio', 'risk-studio'],
  ['IT Operations & Updates', 'update-studio.html', 'GET', '/updates', 'update-studio'],
  ['Infrastructure Inventory', 'infra-inventory.html', 'GET', '/infra-inventory', 'infra-inventory'],
  ['Servers, Cloud & Applications Dashboard', 'servers-dashboard.html', 'GET', '/servers-dashboard', 'servers-dashboard'],
  ['Operations Wall', 'ops-wall.html', 'GET', '/ops-wall', 'ops-wall'],
  ['Executive Dashboard', 'executive-dashboard.html', 'GET', '/exec-dashboard', 'exec-dashboard'],
  ['Phishing Simulation', 'phishing-simulation.html', 'GET', '/phishsim', 'phish-sim'],
  ['Brand Protection', 'brand-protection.html', 'GET', '/brand', 'brand-protect'],
  ['CMDB & Dependencies', 'cmdb-deps.html', 'GET', '/cmdb/deps', 'cmdb-deps'],
  ['Implementation Plan & Budget', 'impl-plan.html', 'GET', '/impl-plan', 'impl-plan'],
  ['Reporting Center', 'report-center.html', 'GET', '/report-center', 'report-center'],
  ['DR Studio', 'dr-studio.html', 'GET', '/dr-studio', 'dr-studio'],
  ['vSphere Studio', 'vsphere-studio.html', 'GET', '/vsphere-studio', 'vsphere-studio'],
  ['VAPT Center', 'vapt-center.html', 'GET', '/vapt-center', 'vapt-center'],
  ['VAPT Studio', 'vapt-studio.html', 'GET', '/vapt-studio', 'vapt-studio'],
  ['Discovery Studio', 'discovery-studio.html', 'GET', '/discovery-studio', 'discovery-studio'],
  ['CISO Dashboard', 'ciso-dashboard.html', 'GET', '/ciso/insights', 'ciso'],
  ['AI CISO', 'ai-ciso.html', 'GET', '/ciso/overview', 'ciso'],
  ['AI Engineering Team', 'ai-team.html', 'GET', '/duty/readiness', 'duty'],
  ['Vulnerability Scans', 'vuln-scans.html', 'GET', '/vulnscan', 'vulnscan'],
  ['Certificates', 'certificates.html', 'GET', '/certs', 'certs'],
  ['NCA ECC', 'nca-ecc.html', 'GET', '/nca-ecc', 'nca-ecc'],
  ['NDMO', 'ndmo.html', 'GET', '/ndmo', 'ndmo'],
  ['ISO 27001', 'iso27001.html', 'GET', '/iso27001', 'iso27001'],
  ['SAMA CSF + IA', 'sama-ia.html', 'GET', '/sama-ia', 'sama-ia'],
  ['SAMA CSF Audit', 'sama-audit.html', 'GET', '/sama-audit', 'sama-audit'],
  ['AppSec & Code Review', 'appsec.html', 'GET', '/appsec', 'appsec'],
  ['App Pen Testing', 'apppt.html', 'GET', '/apppt', 'apppt'],
  ['Vulnerability & Testing Dashboard', 'vuln-dashboard.html', 'GET', '/vuln-dashboard', 'vuln-dashboard'],
  ['Mobile Application Testing', 'mobile-test.html', 'GET', '/mobile-test', 'mobile-test'],
  ['ISO 27001 Lifecycle', 'iso-lifecycle.html', 'GET', '/iso-lifecycle', 'iso-lifecycle'],
  ['NCA ECC Compliance Studio', 'ecc-studio.html', 'GET', '/nca-ecc-intel', 'nca-ecc-intel'],
  ['Remediation Roadmap', 'roadmap.html', 'GET', '/roadmap', 'roadmap'],
  ['Automated Risk Assessment', 'risk-assess.html', 'GET', '/risk-assess', 'risk-assess'],
  ['Security Controls → Compliance', 'security-controls.html', 'GET', '/controls-intel', 'controls-intel'],
  ['Cybersecurity Maturity Level', 'maturity-level.html', 'GET', '/maturity-intel', 'maturity-intel'],
  ['Network Configuration Audit', 'network-config-audit.html', 'GET', '/netcfg-intel', 'netcfg-intel'],
  ['Roles & RACI', 'roles-raci.html', 'GET', '/raci-intel', 'raci-intel'],
  ['NCA IT Audit', 'nca-it-audit.html', 'GET', '/nca-itaudit-intel', 'nca-itaudit-intel'],
  ['NDMO Studio', 'ndmo-studio.html', 'GET', '/ndmo-intel', 'ndmo-intel'],
  ['Regulatory Framework Library', 'framework-library.html', 'GET', '/fwlib-intel', 'fwlib-intel'],
  ['AI Governance', 'ai-governance.html', 'GET', '/aigov-intel', 'aigov-intel'],
  ['Business Continuity & DR Matrix', 'bcm-matrix.html', 'GET', '/bcm-intel', 'bcm-intel'],
  ['Compliance Overview', 'compliance-overview.html', 'GET', '/overview-intel', 'overview-intel'],
  ['Continuous Compliance & Auto-Remediation', 'continuous-compliance.html', 'GET', '/contcomp-intel', 'contcomp-intel'],
  ['Control Validation', 'control-validation.html', 'GET', '/validation-intel', 'validation-intel'],
  ['Evidence & Chain of Custody', 'evidence-custody.html', 'GET', '/custody-intel', 'custody-intel'],
  ['Compliance Documents & Evidence', 'compliance-docs.html', 'GET', '/docs-intel', 'docs-intel'],
  ['Framework Crosswalk', 'crosswalk.html', 'GET', '/crosswalk', 'crosswalk'],
  ['Gap Analysis - All Frameworks', 'gap-analysis.html', 'GET', '/gap-analysis', 'crosswalk'],
  ['GRC Dashboard', 'grc-dashboard.html', 'GET', '/grc-dashboard', 'grc-dashboard'],
  ['GRC Register', 'grc-register.html', 'GET', '/grc-register', 'grc-register'],
  ['IA Cyber & Operational Resilience', 'ia-resilience.html', 'GET', '/ia-resilience', 'ia-resilience'],
  ['Onboarding', 'hr-onboarding.html', 'GET', '/onboarding', 'onboarding'],
  ['Offboarding', 'hr-offboarding.html', 'GET', '/offboarding', 'offboarding'],
  ['Access Reviews', 'access-reviews.html', 'GET', '/access-reviews', 'access-reviews'],
  ['Privileged Access', 'privileged-access.html', 'GET', '/pam', 'pam'],
  ['Non-human identities', 'nhi.html', 'GET', '/nhi/summary', 'nhi'],
  ['Remote Console', 'remote-console.html', 'GET', '/console', 'remote-console'],
];

function createUpdateHealth(app, opts = {}) {
  const file = opts.reportFile || ((app.config && app.config.update_report) || '/opt/sentra-itam/update-report.json');
  function readReport() {
    try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch (e) { return e.code === 'ENOENT' ? null : { error: 'the update report could not be read (' + (e.code || 'invalid JSON') + ')' }; }
  }
  function view() {
    const srv = opts.srv || app.srv, routes = srv && srv.list ? srv.list() : [];
    const has = (m, p) => routes.some((r) => r.method === m && (r.path === p || r.path.endsWith(p) && /^\/[a-z0-9_-]+(\/[a-z0-9_-]+)?$/.test(r.path.slice(0, r.path.length - p.length))));   // stored with the API prefix (/api/itam)
    const missing = [...new Set(app.dutyMissing || [])];
    const pages = PAGES.map(([name, page, method, route, module]) => {
      const mm = missing.includes(module), ok = has(method, route) && !mm;
      return { name, page, route: method + ' ' + route, module, ok, why: ok ? null : mm ? 'the module ' + module + '.js is not on the server - run the update' : 'the engine did not register ' + route + ' - see the update findings below' };
    });
    const rep = readReport();
    const installers = rep && rep.installers ? Object.entries(rep.installers).map(([k, v]) => ({ installer: k, status: v.status, at: v.at, missing: v.missing || null, reason: v.reason || null })).sort((a, b) => String(b.at).localeCompare(String(a.at))) : [];
    const findings = rep && rep.installers ? Object.values(rep.installers).flatMap((v) => (v.findings && v.findings.findings) || []) : [];
    const bad = pages.filter((p) => !p.ok);
    return { generated_at: new Date().toISOString(), summary: { pages: pages.length, working: pages.length - bad.length, not_working: bad.length, missing_modules: missing.length,
      last_update: rep && rep.updated_at || null, state: bad.length || missing.length ? 'ATTENTION' : rep ? 'HEALTHY' : 'NO REPORT YET' },
    pages, missing_modules: missing, installers, findings, report_error: rep && rep.error || null, report_file: file };
  }
  return { view, PAGES };
}

function registerUpdateHealth(srv, app, U0) {
  const U = U0 && U0.view ? U0 : createUpdateHealth(app, Object.assign({ srv }, U0 || {}));
  app.addons = app.addons || {}; app.addons.updateHealth = U;
  srv.route('GET', '/platform/update-health', (ctx) => { ctx.need('admin'); return U.view(); });
  return U;
}

module.exports = { createUpdateHealth, registerUpdateHealth, PAGES };
