// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * The AI engineers of the organisation's own estate on the duty desk (engine/duty-core.js), for the modules registered after the
 * desk: they are read when the patrol runs (app.addons), so an engineer whose module is missing or not set up answers null
 * ("source not connected" - nothing is opened or closed). Each finding becomes one work item the desk investigates, escalates and
 * clears like any other; nothing here changes a system (a change is the module's own four-eyes plan).
 *   AI Voice Engineer (Cisco CUCM)      engine/cucm-manager.js     pool drops, flapping, trunks down, failed calls, stale phones
 *   AI Hyper-V Administrator            engine/hyperv-manager.js   capacity, right-sizing, heartbeat, replication, checkpoints
 *   AI Aramco CCC Officer               engine/aramco-ccc.js       overdue actions, evidence missing, N/A waiting, certificate expiry
 *   AI Azure Cloud Engineer             engine/azure-cloud.js      high-risk VMs with their reasons, stopped-but-billed VMs
 *   AI PAM Officer                      engine/pam-center.js       rotations overdue, high-risk privileged accounts, checkouts waiting
 *   AI Compliance Workflow Officer      engine/compliance-copilot.js  remediation overdue, control activities overdue or never done
 *   AI Capacity Planner                 engine/capacity-plan.js    a host group without N+1, memory or a volume full within 30 days
 *   AI Virtual Network Engineer         engine/hyperv-netmap.js    uplinks down, switches missing against the group, duplicates
 */
const SEV = (s) => (['critical', 'high', 'medium', 'low'].includes(s) ? s : 'medium');
const investigateFrom = (it, summary) => ({ summary: summary || it.title, checks: (it.evidence || []).map((e) => ({ name: 'Evidence', status: 'info', detail: String(e) })), causes: [{ cause: it.title, confidence: 'high', fix: it.recommendation }] });

function adapters(app) {
  const A = () => app.addons || {};
  const verifyBy = (find) => async (it) => { const f = await find(); if (f === null) return { present: true, note: 'source not readable now - kept open' }; return { present: f.some((x) => x.key === it.key), note: 'checked against the latest data' }; };

  const cucmFind = async () => {
    const X = A().cucm; if (!X) return null; const v = X.view(); if (!v.polled) return null;
    return v.findings.map((f) => ({ key: 'cucm:' + f.code + ':' + (f.target || 'all'), severity: SEV(f.severity), kind: f.code, title: f.title, evidence: ['Call Manager read at ' + v.at], recommendation: f.fix, target: { type: f.code === 'trunk-down' ? 'trunk' : f.code === 'pool-drop' ? 'device-pool' : 'phone', id: f.target || 'cucm', name: f.target || 'CUCM' }, site: '' }));
  };
  const hvFind = async () => {
    const X = A().hypervManager; if (!X) return null; const v = X.view(); if (!v.hosts.length) return null;
    return v.findings.map((f) => ({ key: 'hyperv:' + f.host + ':' + f.code + ':' + (f.target || ''), severity: SEV(f.severity), kind: f.code, title: f.host + ' - ' + f.title, evidence: ['host report of ' + f.host], recommendation: f.fix, target: { type: /^capacity|volume|overcommit/.test(f.code) ? 'host' : 'vm', id: f.target || f.host, name: f.target || f.host }, site: '' }))
      .concat(v.hosts.filter((h) => h.stale).map((h) => ({ key: 'hyperv:' + h.name + ':stale', severity: 'high', kind: 'not-reporting', title: h.name + ' has not reported since ' + h.at, evidence: ['last report ' + h.at], recommendation: 'Check the scheduled task "Sentra Hyper-V report" on the host and its outbound HTTPS to the portal', target: { type: 'host', id: h.name, name: h.name }, site: '' })));
  };
  const accFind = async () => {
    const X = A().aramcoCcc; if (!X) return null; const v = X.view({ user: 'system', role: 'viewer' }); if (!v.controls_total && !v.contracts.length) return null;
    const out = [], add = (key, sev, title, fix, target) => out.push({ key: 'accc:' + key, severity: sev, kind: key.split(':')[0], title, evidence: ['Aramco CCC register'], recommendation: fix, target: { type: 'ccc', id: target || 'ccc', name: target || 'Aramco CCC' }, site: '' });
    const today = new Date().toISOString().slice(0, 10);
    for (const a of v.actions.filter((x) => x.status !== 'done' && x.due && x.due < today)) add('action:' + a.id, 'medium', 'Remediation ' + a.id + ' for ' + a.control + ' is overdue (due ' + a.due + ', owner ' + a.owner + ')', 'Close it or agree a new date with the CCC owner', a.control);
    if (v.evidence_missing.length) add('evidence', 'medium', v.evidence_missing.length + ' implemented control(s) have no evidence', 'Record where the evidence is kept (Aramco CCC → Controls)', '');
    if (v.na_pending.length) add('na', 'low', v.na_pending.length + ' "not applicable" waiting for a second person', 'The CCC owner or an administrator accepts or refuses each', '');
    if (v.certificate && v.days_left != null && v.days_left < 0) add('cert-expired', 'critical', 'Aramco CCC ' + v.certificate.number + ' expired on ' + v.certificate.expires, 'Re-certify now: Aramco contracts need a valid certificate', v.certificate.number);
    else if (v.certificate && v.days_left != null && v.days_left <= 90) add('cert-renew', v.days_left <= 30 ? 'high' : 'medium', 'Aramco CCC ' + v.certificate.number + ' expires in ' + v.days_left + ' day(s)', 'Start the renewal: re-assess and book the audit firm', v.certificate.number);
    if (v.uncovered.length) add('uncovered', 'high', 'Contracts not covered by the certificate: ' + v.uncovered.join(', '), 'Extend the certificate to their service types', '');
    if (v.projection && v.projection.on_track === false) add('pace', 'medium', 'Readiness pace: ' + v.projection.why, 'Add owners and dates to the open gaps', '');
    return out;
  };
  // the platforms and programmes of the organisation's own estate (Azure, PAM, compliance, capacity, Hyper-V network)
  const azFind = async () => {
    const X = A().azureCloud; if (!X || typeof X.view !== 'function') return null; const v = X.view('operator'); if (!v || !Array.isArray(v.vms) || !v.vms.length) return null;
    return v.vms.filter((m) => m.risk >= 50 || m.power === 'stopped').map((m) => ({ key: 'azure:' + m.name + ':' + (m.power === 'stopped' && m.risk < 50 ? 'billed' : 'risk'), severity: m.risk >= 75 ? 'high' : 'medium', kind: m.risk >= 50 ? 'risk' : 'stopped-billed',
      title: m.name + (m.risk >= 50 ? ' - risk ' + m.risk + ': ' + (m.reasons || []).slice(0, 2).join('; ') : ' - stopped but not deallocated (compute still billed)'), evidence: ['Azure Resource Graph read'], recommendation: m.risk >= 50 ? 'Close the reasons listed on Azure Cloud Servers' : 'Deallocate it on Azure Cloud Servers (four-eyes)', target: { type: 'azure-vm', id: m.name, name: m.name } }));
  };
  const pamFind = async () => {
    const X = A().pamCenter; if (!X || typeof X.view !== 'function') return null; const v = await X.view({ user: 'system:ai-pam-officer', role: 'operator' }); if (!v || (!v.identities.length && !v.safe.length)) return null;
    return v.safe.filter((e) => e.overdue).map((e) => ({ key: 'pam:rotate:' + e.id, severity: 'high', kind: 'rotation-overdue', title: 'Password of ' + e.account + ' on ' + e.system + ' is overdue for rotation', evidence: ['PAM safe entry ' + e.id], recommendation: 'Rotate it on PAM Center (the owner; the old password is refused)', target: { type: 'pam-entry', id: e.id, name: e.system } }))
      .concat(v.identities.filter((x) => x.risk >= 70).slice(0, 30).map((x) => ({ key: 'pam:id:' + x.name, severity: x.risk >= 85 ? 'high' : 'medium', kind: 'privileged-risk', title: 'Privileged ' + (x.kind || 'account') + ' ' + x.name + ' - risk ' + x.risk, evidence: (x.reasons || []).slice(0, 4), recommendation: 'Review the account on PAM Center: remove the standing privilege, vault it or require MFA', target: { type: 'identity', id: x.name, name: x.name } })))
      .concat(v.checkouts.filter((c) => c.state === 'pending').length ? [{ key: 'pam:waiting', severity: 'low', kind: 'checkout-waiting', title: v.checkouts.filter((c) => c.state === 'pending').length + ' password checkout(s) waiting for an approver', evidence: ['PAM Center checkouts'], recommendation: 'An administrator who did not ask decides each', target: { type: 'pam', id: 'checkouts', name: 'checkouts' } }] : []);
  };
  const ccpFind = async () => {
    const X = A().complianceCopilot; if (!X || typeof X.overview !== 'function') return null; let v; try { v = await X.overview(undefined, 'operator'); } catch (e) { return null; /* no company registered yet: not connected */ }
    if (!v || (!v.duties.length && !v.actions.length && !v.total_open)) return null;
    return v.actions.filter((a) => a.overdue).map((a) => ({ key: 'ccp:action:' + a.id, severity: 'high', kind: 'action-overdue', title: 'Remediation ' + a.id + ' (' + String(a.fw || '').toUpperCase() + ' ' + (a.req_id || '') + ') overdue since ' + a.due, evidence: [a.title], recommendation: 'Escalate to the owner or agree a new date on Compliance AI Assistant', target: { type: 'action', id: a.id, name: a.title } }))
      .concat(v.duties.filter((d) => d.status === 'overdue' || d.status === 'never done').slice(0, 40).map((d) => ({ key: 'ccp:duty:' + (d.id || d.title), severity: 'medium', kind: 'activity-overdue', title: 'Control activity ' + (d.status === 'never done' ? 'never done: ' : 'overdue: ') + d.title, evidence: [(d.department || d.owner || '') + ' ' + (d.frequency || '')], recommendation: 'The owner records it done; another person verifies', target: { type: 'duty', id: d.id || d.title, name: d.title } })));
  };
  const capFind = async () => {
    const X = A().capacityPlan; if (!X) return null; const v = X.view('viewer'), out = [];
    if (v.hyperv.available) for (const g of v.hyperv.groups) {
      if (g.n1_ok === false) out.push({ key: 'cap:n1:' + g.group, severity: 'high', kind: 'no-n-plus-1', title: 'Hyper-V ' + g.group + ': ' + g.why, evidence: [g.mem_used_gb + ' of ' + g.mem_total_gb + ' GB in use'], recommendation: 'Reclaim memory from oversized VMs (' + g.reclaim_gb + ' GB) or add a host', target: { type: 'hyperv-group', id: g.group, name: g.group } });
      if (g.mem_days != null && g.mem_days <= 30) out.push({ key: 'cap:mem:' + g.group, severity: g.mem_days <= 7 ? 'high' : 'medium', kind: 'memory-full', title: 'Hyper-V ' + g.group + ': memory full in about ' + g.mem_days + ' day(s)', evidence: ['daily trend of the host reports'], recommendation: 'Plan memory or move VMs before then', target: { type: 'hyperv-group', id: g.group, name: g.group } });
      for (const x of g.volumes_soon.filter((y) => y.days <= 30)) out.push({ key: 'cap:vol:' + x.host + ':' + x.volume, severity: x.days <= 7 ? 'high' : 'medium', kind: 'volume-full', title: x.host + ' ' + x.volume + ' full in about ' + x.days + ' day(s)', evidence: ['daily trend of the host reports'], recommendation: 'Merge old checkpoints, move VHDs or extend the volume', target: { type: 'volume', id: x.host + ':' + x.volume, name: x.volume } });
    }
    if (v.azure.available) for (const x of v.azure.rightsize.filter((y) => y.savings >= 50).slice(0, 10)) out.push({ key: 'cap:az:' + x.vm, severity: 'low', kind: 'rightsize', title: 'Azure ' + x.vm + ': Advisor suggests ' + (x.target || 'resizing') + (x.savings ? ' (' + x.savings + ' ' + (x.currency || '') + ' a month)' : ''), evidence: [x.problem || 'Azure Advisor'], recommendation: 'Resize in a change window after the owner agrees', target: { type: 'azure-vm', id: x.vm, name: x.vm } });
    return v.hyperv.available || v.azure.available ? out : null;
  };
  const netFind = async () => {
    const X = A().hypervNetmap; if (!X) return null; const v = X.view(); if (!v.hosts.length) return null;
    return v.findings.filter((f) => f.severity !== 'low').map((f) => ({ key: 'hvnet:' + f.host + ':' + f.code + ':' + f.target, severity: SEV(f.severity), kind: f.code, title: f.host + ' - ' + f.title, evidence: ['virtual network report of ' + f.host], recommendation: f.fix, target: { type: 'hyperv-network', id: f.host + ':' + f.target, name: f.target } }));
  };
  return [
    { id: 'voice', name: 'AI Voice Engineer (Cisco CUCM)', findings: cucmFind, investigate: (it) => investigateFrom(it, 'Cisco Unified CM: ' + it.title), verify: verifyBy(cucmFind) },
    { id: 'hyperv', name: 'AI Hyper-V Administrator', findings: hvFind, investigate: (it) => investigateFrom(it, 'Hyper-V: ' + it.title), verify: verifyBy(hvFind) },
    { id: 'aramco', name: 'AI Aramco CCC Officer', findings: accFind, investigate: (it) => investigateFrom(it, 'Aramco CCC: ' + it.title), verify: verifyBy(accFind) },
    { id: 'azure', name: 'AI Azure Cloud Engineer', findings: azFind, investigate: (it) => investigateFrom(it, 'Azure: ' + it.title), verify: verifyBy(azFind) },
    { id: 'pamofficer', name: 'AI PAM Officer', findings: pamFind, investigate: (it) => investigateFrom(it, 'PAM: ' + it.title), verify: verifyBy(pamFind) },
    { id: 'compliance', name: 'AI Compliance Workflow Officer (remediation actions and control activities)', findings: ccpFind, investigate: (it) => investigateFrom(it, 'Compliance: ' + it.title), verify: verifyBy(ccpFind) },
    { id: 'capacity', name: 'AI Capacity Planner (Hyper-V, servers, Azure)', findings: capFind, investigate: (it) => investigateFrom(it, 'Capacity: ' + it.title), verify: verifyBy(capFind) },
    { id: 'hvnet', name: 'AI Virtual Network Engineer (Hyper-V)', findings: netFind, investigate: (it) => investigateFrom(it, 'Hyper-V network: ' + it.title), verify: verifyBy(netFind) },
  ];
}

module.exports = { adapters };
