// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
/* zyb-poc-team.js - POC mode only: the AI team's recorded roster (vendor/zyb-poc-rec.js) with the organisation's own estate engineers
 * that joined after the recording - Azure, PAM, compliance workflow, capacity, Hyper-V network (IT Asset side), email flow and the SIEM
 * migration (SIEM side) - each with ILLUSTRATIVE patrol figures; on the team page also illustrative work items, shift reports and
 * service scores so the overview reads like a working day. The live desk lists the real engineers from both engines. */
(function () {
  'use strict';
  var NOW = Date.now(), min = 60000;
  function eng(id, name, open, crit, high, ago, extra) {
    return Object.assign({ id: id, name: name, on_duty: true, last_patrol: NOW - ago * min, last_ms: 900 + ago * 37, patrols: 96 - ago, late: false, last_error: null, last_error_at: null, not_connected: false,
      open: open, by_status: open ? { open: Math.max(0, open - 1), investigating: open ? 1 : 0 } : {}, critical: crit, high: high, resolved_24h: Math.max(0, 3 - open), ai: { enabled: true, off: false, reason: '', used_today: open, cap: 50 } }, extra || {});
  }
  var ITAM = [eng('azure', 'AI Azure Cloud Engineer', 2, 0, 1, 6), eng('pamofficer', 'AI PAM Officer', 3, 0, 2, 4), eng('compliance', 'AI Compliance Workflow Officer (remediation actions and control activities)', 4, 0, 1, 9),
    eng('capacity', 'AI Capacity Planner (Hyper-V, servers, Azure)', 2, 0, 1, 3), eng('hvnet', 'AI Virtual Network Engineer (Hyper-V)', 3, 0, 1, 5)];
  var SOC = [eng('mailflow', 'AI Email Flow Analyst (Exchange Online)', 2, 0, 1, 7), eng('cutover', 'AI SIEM Migration Engineer (NewEvol cutover)', 5, 0, 3, 11)];
  function plus(path, add) {
    return function () { var R = window.ZYB_POC_REC, base = R && R.map && R.map[path]; var x = base ? JSON.parse(JSON.stringify(base)) : { engineers: [], policy: {} };
      var have = {}; (x.engineers || []).forEach(function (e) { have[e.id] = 1; }); x.engineers = (x.engineers || []).concat(add.filter(function (e) { return !have[e.id]; })); return x; };
  }
  // the overview's work items, shift reports and service scores - ILLUSTRATIVE, every name invented, answered on the team page only
  var H = 3600000, page = function (p) { return { test: function (x) { return x === p && /ai-team\.html$/.test(location.pathname); } }; };
  function it(id, eng, name, sev, status, title, h) { return { id: id, engineer: eng, engineer_name: name, severity: sev, status: status, title: title + ' (POC)', first_seen: NOW - h * H, last_seen: NOW - 600000 }; }
  var SOCI = [it('DW-POC-101', 'network', 'AI Network Engineer', 'critical', 'awaiting-approval', 'HQ-CORE-SW01: uplink to Jeddah dropping packets - change plan to reset the LACP member', 3),
    it('DW-POC-102', 'network', 'AI Network Engineer', 'medium', 'investigating', 'JUB-SITE-SW02: port Gi1/0/14 flapping', 5),
    it('DW-POC-103', 'security', 'AI Security Engineer', 'high', 'awaiting-approval', 'Block outbound SMB from the project-site VLAN at Yanbu', 7),
    it('DW-POC-104', 'security', 'AI Security Engineer', 'high', 'diagnosed', 'Admin sign-ins from a new country on the VPN portal', 10),
    it('DW-POC-105', 'cutover', 'AI SIEM Migration Engineer (NewEvol cutover)', 'high', 'needs-human', 'Gate 3 open: 4 log sources still only in NewEvol', 26),
    it('DW-POC-106', 'mailflow', 'AI Email Flow Analyst (Exchange Online)', 'medium', 'approved', 'Mail to a supplier domain queued for 40 minutes - connector fix approved, apply it', 2),
    it('DW-POC-107', 'windows', 'AI Windows Admin', 'medium', 'fix-applied', 'HQ-FS01: D: at 91% - old shadow copies removed, verifying', 4)];
  var ITAMI = [it('DW-POC-201', 'pdpl', 'AI PDPL Consultant', 'critical', 'needs-human', 'Records of processing missing for the HR payroll process', 50),
    it('DW-POC-202', 'pdpl', 'AI PDPL Consultant', 'critical', 'investigating', 'Personal data found on an open file share at Dammam', 8),
    it('DW-POC-203', 'pamofficer', 'AI PAM Officer', 'high', 'awaiting-approval', 'Rotate the shared local admin password on 6 site servers', 12),
    it('DW-POC-204', 'compliance', 'AI Compliance Workflow Officer (remediation actions and control activities)', 'medium', 'awaiting-approval', 'NCA ECC 2-3-1: evidence for quarterly access review overdue', 30),
    it('DW-POC-205', 'capacity', 'AI Capacity Planner (Hyper-V, servers, Azure)', 'high', 'diagnosed', 'HQPSUPERM04 memory at 83% - move one VM within the HQ cluster', 6),
    it('DW-POC-206', 'hvnet', 'AI Virtual Network Engineer (Hyper-V)', 'medium', 'open', 'VLAN 40 on the Hyper-V switch has no uplink trunk at Jeddah', 3),
    it('DW-POC-207', 'azure', 'AI Azure Cloud Engineer', 'medium', 'approved', 'Storage account allows public blob access - restriction approved, apply it', 9)];
  var REP = function (list) { var seen = {}; return list.filter(function (x) { if (seen[x.engineer]) return false; seen[x.engineer] = 1; return true; }).map(function (x) {
    var n = list.filter(function (y) { return y.engineer === x.engineer; }).length; return { engineer: x.engineer, engineer_name: x.engineer_name, at: NOW - 2 * H, day: new Date(NOW).toISOString().slice(0, 10),
      summary: 'Shift report (POC)\n' + n + ' open item(s); top: ' + x.title + '\nPatrols on time overnight; nothing changed on any system without approval.' }; }); };
  function kp(eng, name, score, sla, patrol) { var k = function (id, v, t, u, dir) { var ok = dir === 'min' ? v >= t : v <= t; return { id: id, value: v, target: t, unit: u, dir: dir, status: ok ? 'ok' : (dir === 'min' ? v >= t * 0.85 : v <= t * 1.3) ? 'warn' : 'bad' }; };
    return { engineer: eng, name: name, score: score, kpis: [k('sla_pct', sla, 90, '%', 'min'), k('patrol_pct', patrol, 98, '%', 'min'), k('approval_h', Math.round((100 - score) / 6 * 10) / 10, 8, 'h', 'max')], domain: [] }; }
  var SOCK = [kp('network', 'AI Network Engineer', 78, 86, 99), kp('security', 'AI Security Engineer', 88, 93, 100), kp('windows', 'AI Windows Admin', 62, 74, 91), kp('cutover', 'AI SIEM Migration Engineer', 71, 80, 100), kp('mailflow', 'AI Email Flow Analyst', 92, 96, 100)];
  var ITAMK = [kp('pdpl', 'AI PDPL Consultant', 55, 61, 100), kp('pamofficer', 'AI PAM Officer', 83, 90, 100), kp('compliance', 'AI Compliance Workflow Officer', 74, 82, 99), kp('capacity', 'AI Capacity Planner', 95, 100, 100), kp('azure', 'AI Azure Cloud Engineer', 90, 94, 100), kp('desktop', 'AI Desktop Support Engineer', 81, 88, 97)];
  window.ZYB_POC = (window.ZYB_POC || []).concat([{ re: page('/api/soc/duty/items'), pages: ['ai-team.html'], data: { items: SOCI } }, { re: page('/api/itam/duty/items'), pages: ['ai-team.html'], data: { items: ITAMI } },
    { re: page('/api/soc/duty/reports'), pages: ['ai-team.html'], data: { reports: REP(SOCI) } }, { re: page('/api/itam/duty/reports'), pages: ['ai-team.html'], data: { reports: REP(ITAMI) } },
    { re: page('/api/soc/duty/kpis'), pages: ['ai-team.html'], data: { engineers: SOCK } }, { re: page('/api/itam/duty/kpis'), pages: ['ai-team.html'], data: { engineers: ITAMK } }]);
  window.ZYB_POC = (window.ZYB_POC || []).concat([{ re: /^\/api\/itam\/duty\/engineers$/, data: plus('/api/itam/duty/engineers', ITAM) }, { re: /^\/api\/soc\/duty\/engineers$/, data: plus('/api/soc/duty/engineers', SOC) }]);
})();
