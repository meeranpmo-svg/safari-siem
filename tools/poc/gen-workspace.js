#!/usr/bin/env node
// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * gen-workspace.js - writes ui/vendor/zyb-poc-workspace.js: the POC data of the Agent Workspace (agent-workspace.html), made by the REAL
 * engine (backend/siem/engine/soc/workspace.js) on a throw-away state store over SYNTHETIC alerts and rule counters, with an
 * ILLUSTRATIVE agent text in place of a model: the three templates (one published and run, one waiting for a person, one draft) and
 * a custom workflow. Every name is invented.   node tools/poc/gen-workspace.js
 */
const fs = require('fs'), os = require('os'), path = require('path');
const ROOT = path.resolve(__dirname, '../..'), E = path.join(ROOT, 'backend/siem/engine');
const W = require(path.join(E, 'soc/workspace.js')), { createState } = require(path.join(E, 'soc/state.js'));
const NOW = Date.parse('2026-11-27T09:00:00Z'), H = 36e5;
(async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'poc-ws-'));
  try {
    const state = await createState({ dir, log: { info() {}, warn() {}, error() {} } });
    let now = NOW - 30 * H; const clock = () => now;
    const R = ['Brute force on domain controller (POC)', 'FortiGate: admin login from a new country (POC)', 'H3C: port security violation (POC)', 'Mimecast: impersonation held (POC)', 'Windows: new service installed (POC)'];
    const alerts = Array.from({ length: 46 }, (_, i) => ({ id: 'ALR-POC-' + (100 + i), created: NOW - (i * 37 % 1400) * 60000, severity: i % 9 === 0 ? 4 : i % 4 === 0 ? 3 : i % 3 === 0 ? 2 : 1, rule_name: R[i % R.length], summary: R[i % R.length] + ' on host POC-' + (i % 7), status: i % 5 === 0 ? 'closed-false-positive' : 'new' }));
    const TEXT = { triage: '1. Two of the critical alerts look real: repeated failed logons on POC-DC01 from one workstation, then a success - check that account first.\n2. The FortiGate admin login came from a known travel country for this administrator - confirm with them.\n3. The H3C port-security alerts repeat every hour on the same access port: likely a docking station, a tuning candidate.\n(Illustrative POC text - in production the AI triage agent writes this.)',
      tuning: '1. "H3C: port security violation" - 88% of matches are duplicates on 3 ports; group by port for 1 hour (saves about 40 alerts a day; risk: a second device on the same port within the hour is not alerted separately).\n2. "Windows: new service installed" - exclude the patch agent\'s signed services (risk: a malicious service signed with the same certificate would be missed).\n(Illustrative POC text.)',
      summary: 'Shift summary: 46 alerts, 5 critical. Open: the domain controller brute force (case opened after approval). Needs a person: one triage run waits for an operator. Quiet: Mimecast impersonation held 3 messages, all released after checks.\n(Illustrative POC text.)' };
    const model = async ({ system }) => ({ text: /triage/.test(system) ? TEXT.triage : /detection engineer/.test(system) ? TEXT.tuning : TEXT.summary });
    const deps = { state, now: clock, noTimer: true, model, log: { info() {}, warn() {}, error() {}, every() {} },
      alerts: { all: (f) => alerts.filter((a) => !f || f(a)), get: (id) => alerts.find((a) => a.id === id), note() {} },
      cases: { create: (i) => ({ id: 'CASE-POC-0042' }) },
      detector: { stats: () => ({ rules: R.map((n, i) => ({ id: 'r' + i, name: n, matches: [4200, 380, 9100, 120, 860][i], suppressed: [3900, 300, 8050, 40, 610][i], alerts: [18, 6, 31, 3, 9][i] })) }) } };
    const X = W.createWorkspace(deps), ctx = (user, role) => ({ user, role, audit() {} });
    const pub = async (wf) => { X.submit(wf.id, ctx('nora.poc', 'operator')); return X.decide(wf.id, { decision: 'publish', comment: 'reviewed (POC)' }, ctx('syed.poc', 'admin')); };
    const tun = X.create({ template: 'tuning' }, ctx('nora.poc', 'operator')); await pub(tun);
    now = NOW - 26 * H; await X.runNow(tun.id, {}, ctx('omar.poc', 'operator'));
    const shift = X.create({ template: 'shift' }, ctx('nora.poc', 'operator')); await pub(shift);
    now = NOW - 4 * H; await X.runNow(shift.id, {}, ctx('omar.poc', 'operator'));
    const tri = X.create({ name: 'Critical alert triage (POC)', description: 'Critical alerts of the last 24 h: the AI triage agent reads them, a person approves, a case is opened.', trigger: { type: 'manual' },
      steps: [{ type: 'alerts', window_h: 24, min_severity: 4, status: 'open' }, { type: 'condition', field: 'count', op: '>', value: 0 }, { type: 'agent', agent: 'triage', instructions: 'Name the alert to look at first.' }, { type: 'approval', role: 'operator', note: 'Check the triage before a case is opened' }, { type: 'action', action: 'create_case', title: 'Critical alerts - triaged by the AI agent (POC)' }] }, ctx('nora.poc', 'operator'));
    await pub(tri);
    now = NOW - 6 * H; const r1 = await X.runNow(tri.id, {}, ctx('omar.poc', 'operator')); await X.decideRun(r1.id, { decision: 'approve', comment: 'agreed (POC)' }, ctx('syed.poc', 'admin'));
    now = NOW - 40 * 60000; await X.runNow(tri.id, {}, ctx('omar.poc', 'operator'));
    X.create({ template: 'triage' }, ctx('lina.poc', 'operator'));
    now = NOW;
    const view = X.view(), runs = {}; for (const r of view.runs) runs[r.id] = X.getRun(r.id);
    view.ai = { enabled: true, model: 'POC' }; view.note = 'POC: illustrative workflows and runs. ' + view.note;
    const out = '// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.\n'
      + '/* zyb-poc-workspace.js - GENERATED by tools/poc/gen-workspace.js (the real Agent Workspace engine over SYNTHETIC alerts) - do not edit by hand. POC mode only. */\n'
      + '(function () {\n  var V = ' + JSON.stringify(view) + ', R = ' + JSON.stringify(runs) + ', AT = ' + JSON.stringify(new Date(NOW).toISOString()) + ';\n'
      + '  function shift(x) { var d = Date.now() - Date.parse(AT); return JSON.parse(JSON.stringify(x), function (k, s) { if (typeof s !== \'string\' || !/^\\d{4}-\\d{2}-\\d{2}T[\\d:.]+Z$/.test(s)) return s; return new Date(Date.parse(s) + d).toISOString(); }); }\n'
      + '  window.ZYB_POC = (window.ZYB_POC || []).concat([{ re: /^\\/api\\/soc\\/workspace$/, pages: [\'agent-workspace.html\'], data: function () { return shift(V); } },\n'
      + '    { re: /^\\/api\\/soc\\/workspace\\/runs\\/WSR-\\d+$/, pages: [\'agent-workspace.html\'], data: function (u) { var id = String(u.pathname).split(\'/\').pop(); return shift(R[id] || {}); } }]);\n})();\n';
    fs.writeFileSync(path.join(ROOT, 'ui/vendor/zyb-poc-workspace.js'), out);
    console.log('wrote ui/vendor/zyb-poc-workspace.js: ' + view.workflows.length + ' workflows, ' + view.runs.length + ' runs (' + view.runs.map((r) => r.status).join(', ') + ')');
    state.close && state.close();
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
})().catch((e) => { console.error(e); process.exit(1); });
