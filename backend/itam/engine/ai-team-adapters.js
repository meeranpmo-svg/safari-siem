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
  return [
    { id: 'voice', name: 'AI Voice Engineer (Cisco CUCM)', findings: cucmFind, investigate: (it) => investigateFrom(it, 'Cisco Unified CM: ' + it.title), verify: verifyBy(cucmFind) },
    { id: 'hyperv', name: 'AI Hyper-V Administrator', findings: hvFind, investigate: (it) => investigateFrom(it, 'Hyper-V: ' + it.title), verify: verifyBy(hvFind) },
    { id: 'aramco', name: 'AI Aramco CCC Officer', findings: accFind, investigate: (it) => investigateFrom(it, 'Aramco CCC: ' + it.title), verify: verifyBy(accFind) },
  ];
}

module.exports = { adapters };
