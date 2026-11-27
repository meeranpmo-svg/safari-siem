// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
/* zyb-poc-team.js - POC mode only: the AI team's recorded roster (vendor/zyb-poc-rec.js) with the organisation's own estate engineers
 * that joined after the recording - Azure, PAM, compliance workflow, capacity, Hyper-V network (IT Asset side), email flow and the SIEM
 * migration (SIEM side) - each with ILLUSTRATIVE patrol figures. The live desk lists the real engineers from both engines. */
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
  window.ZYB_POC = (window.ZYB_POC || []).concat([{ re: /^\/api\/itam\/duty\/engineers$/, data: plus('/api/itam/duty/engineers', ITAM) }, { re: /^\/api\/soc\/duty\/engineers$/, data: plus('/api/soc/duty/engineers', SOC) }]);
})();
