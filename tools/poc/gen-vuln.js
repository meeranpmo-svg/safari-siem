#!/usr/bin/env node
// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * gen-vuln.js - writes ui/vendor/zyb-poc-vuln.js: the POC data of the Vulnerability & Testing Dashboard (vuln-dashboard.html), made by
 * the REAL engine (backend/itam/engine/vuln-dashboard.js: pillars, matrix, pipeline, learning, history, 14-day projection) over SYNTHETIC
 * sources - scanner findings that fall over 30 days as the team fixes them, application tests and code review - with one bad day.
 * Host names and findings are invented; addresses are 10.x.   node tools/poc/gen-vuln.js
 */
const fs = require('fs'), path = require('path');
const ROOT = path.resolve(__dirname, '../..'), { createVulnDashboard } = require(path.join(ROOT, 'backend/itam/engine/vuln-dashboard.js'));
let seed = 23; const rnd = () => ((seed = (seed * 1103515245 + 12345) % 2147483648) / 2147483648);
const DAY = 864e5, NOW = Date.parse('2026-11-26T08:00:00Z');
const cols = {}, col = (n) => cols[n] || (cols[n] = (() => { const m = new Map(); return { get: (k) => m.get(k), put: (x) => m.set(x.id, x), all: (f) => [...m.values()].filter(f || (() => true)), remove: (k) => m.delete(k) }; })());
const HOSTS = ['HQ-ERP-AX-POC', 'HQ-SQL-01-POC', 'HQ-FILE-01-POC', 'FGT-RUH-01-POC', 'JUB-CCTV-NVR-POC', 'HQ-WEB-PORTAL-POC', 'JED-FILE-POC', 'HQ-EXCH-RELAY-POC', 'YNB-SITE-APP-POC', 'HQ-PRINT-01-POC', 'HQ-HV-03-POC', 'DMM-APP-POC'];
const TITLES = [['critical', 'Remote code execution in the web server (CVE-2024-POC1)', 9.8, 'external'], ['critical', 'Unsupported SQL Server version', 9.1, 'internal'], ['high', 'SMB signing not required', 7.5, 'internal'], ['high', 'FortiOS SSL-VPN heap overflow (CVE-2024-POC2)', 9.6, 'external'],
  ['high', 'Default credentials on the NVR web interface', 8.8, 'internal'], ['medium', 'TLS 1.0 enabled', 5.9, 'external'], ['high', 'Outdated OpenSSL', 7.4, 'internal'], ['medium', 'SNMP community "public"', 5.3, 'internal'], ['critical', 'Print spooler remote code execution', 8.8, 'internal'], ['medium', 'Weak SSH ciphers', 5.3, 'internal']];
const st = { crit: 14, high: 31, med: 58, low: 40 };
function findings() {
  const out = []; let i = 0;
  const push = (n, sev) => { for (let k = 0; k < n; k++) { const t = TITLES.filter((x) => x[0] === sev)[k % TITLES.filter((x) => x[0] === sev).length] || TITLES[5], h = HOSTS[(i++) % HOSTS.length];
    out.push({ title: t[1], host: h, severity: sev, cvss: t[2], priority: Math.round((sev === 'critical' ? 70 : sev === 'high' ? 50 : 30) + (t[3] === 'external' ? 20 : 0) + rnd() * 9), exposure: t[3], sources: [rnd() < 0.6 ? 'greenbone' : 'tenable'], status: 'open', sla_state: k === 0 && sev === 'critical' ? 'breached' : 'ok', owner: 'owner.poc', why: [{ text: 'POC' }] }); } };
  push(st.crit, 'critical'); push(st.high, 'high'); push(Math.min(st.med, 20), 'medium');
  return out.sort((a, b) => b.priority - a.priority);
}
const addons = {
  vaptCenter: { view: () => { const f = findings(); return { findings: f, counts: { critical: st.crit, high: st.high, medium: st.med, low: st.low }, open: st.crit + st.high + st.med + st.low, sla: { breached: 3, due_14d: 7, forecast_breaches_14d: 2, fix_rate_per_day: 1.8 }, delta: { reopened: [{}, {}], new: [], fixed: [] }, paths: [{}], duplicates_merged: 12, sources: { greenbone: { ok: true }, tenable: { ok: true } } }; } },
  vulnscan: { view: () => ({ last_scan: { id: 'S-POC' }, waiting_approval: 1, scans: [{ state: 'running' }, { state: 'done' }], pending_risk: 2 }) },
  pentest: { cadence: () => ({ kpis: { in_scope: 46, out_of_policy: 6, never_tested: 2, overdue: 4 }, assets: [] }) },
  apppt: { view: () => ({ kpis: { apps: 7, tests_overdue: 1, never_tested: 1, open: 9, critical: 1, high: 3, overdue: 1, retest_waiting: 2, regressions: 0, accept_waiting: 1 }, engagements: [{ state: 'scope_requested' }, { state: 'testing' }, { state: 'reporting' }],
    findings: [{ severity: 'critical', status: 'open' }, { severity: 'high', status: 'open' }, { severity: 'high', status: 'open' }, { severity: 'high', status: 'open' }, { severity: 'medium', status: 'open' }, { severity: 'medium', status: 'open' }], attention: [{ level: 'bad', text: 'Contractor portal (POC): 1 open critical finding' }] }) },
  appsec: { view: () => ({ kpis: { apps: 5, open: 14, critical: 1, high: 4, secrets: 2, overdue: 1, gates_failing: 1, never_scanned: 0, accept_waiting: 1 }, apps: [{ open: { critical: 1, high: 4, medium: 6, low: 3 } }], attention: [{ level: 'warn', text: 'Fleet app (POC): 2 secrets in the repository' }] }) },
};
let clock = NOW - 30 * DAY;
const app = { store: { collection: col }, addons, settings: { get: () => ({}) }, audit() {}, log: { every() {}, warn() {}, info() {} } };
const D = createVulnDashboard(app, { now: () => clock, noTimer: true });
(async () => {
  for (let d = 0; d < 30; d++) {
    // the team fixes steadily; day 21 a new scan finds a batch (the unusual day), then the fixing continues
    st.crit = Math.max(2, Math.round(14 - d * 0.35 + (d >= 21 ? 4 : 0))); st.high = Math.max(8, Math.round(31 - d * 0.6 + (d >= 21 ? 6 : 0))); st.med = Math.max(20, Math.round(58 - d * 0.9));
    await D.snapshot(); clock += DAY;
  }
  clock = NOW;
  const v = await D.view({ user: 'admin.poc', role: 'admin' });
  v.ai = { enabled: false, reason: 'POC mode - the advisor answers on the live platform', model: v.ai && v.ai.model };
  const out = '// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.\n'
    + '/* zyb-poc-vuln.js - GENERATED by tools/poc/gen-vuln.js (the real Vulnerability & Testing Dashboard engine over SYNTHETIC sources) - do not edit by hand. POC mode only. */\n'
    + '(function () {\n  var V = ' + JSON.stringify(v) + ', AT = ' + JSON.stringify(new Date(NOW).toISOString()) + ';\n'
    + '  function shift(x) { var d = Date.now() - Date.parse(AT); return JSON.parse(JSON.stringify(x), function (k, s) { if (typeof s !== \'string\') return s; var m = /^\\d{4}-\\d{2}-\\d{2}(T[\\d:.]+Z)?$/.exec(s); if (!m) return s; var n = new Date(Date.parse(m[1] ? s : s + \'T00:00:00Z\') + d).toISOString(); return m[1] ? n : n.slice(0, 10); }); }\n'
    + '  window.ZYB_POC = (window.ZYB_POC || []).concat([{ re: /^\\/api\\/itam\\/vuln-dashboard$/, pages: [\'vuln-dashboard.html\'], data: function () { return shift(V); } }]);\n})();\n';
  fs.writeFileSync(path.join(ROOT, 'ui/vendor/zyb-poc-vuln.js'), out);
  console.log('wrote ui/vendor/zyb-poc-vuln.js: index ' + v.index + ', ' + v.history.length + ' days, unusual ' + v.learning.unusual.length + ', projection ' + (v.forecast.critical ? v.forecast.critical[13].value : '-') + ' criticals in 14 d');
})().catch((e) => { console.error(e); process.exit(1); });
