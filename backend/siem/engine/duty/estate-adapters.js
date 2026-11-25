// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * The AI engineers of the organisation's own estate on the SIEM duty desk (duty/duty-core.js), for modules registered after the
 * desk: each reads its module when the patrol runs, so an engineer whose module is missing or not set up answers null ("source
 * not connected" - nothing is opened or closed). Every finding is one work item the desk investigates, escalates, tickets and
 * clears like any other; nothing here changes a device (a change stays the module's own four-eyes plan).
 *   AI Firewall Engineer (FortiGate)   netops/fmg.js            offline, drift, conserve mode, HA, tunnels, SD-WAN SLA, licences, firmware
 *   AI Network Access Engineer         netops/fmg-nac.js        endpoints at risk (identity change, cloned MAC, shared port, flapping)
 *   AI NDR Analyst                     soc/ndr.js               beaconing, unusual outbound volume, lateral movement
 *   AI Email Security Engineer         collect/mimecast*.js     the Mimecast collector failing or not polling
 */
const SEV = (s) => (['critical', 'high', 'medium', 'low'].includes(s) ? s : 'medium');
const inv = (it, prefix) => ({ summary: prefix + it.title, checks: (it.evidence || []).map((e) => ({ name: 'Evidence', status: 'info', detail: String(e) })), causes: [{ cause: it.title, confidence: 'high', fix: it.recommendation }] });

function estateAdapters(deps) {
  const verifyBy = (find) => async (it) => { const f = await find(); if (f === null) return { present: true, note: 'source not readable now - kept open' }; return { present: f.some((x) => x.key === it.key), note: 'checked against the latest data' }; };
  const fwFind = async () => {
    const F = deps.fmgApi; if (!F) return null; const st = F.status(); if (!st.configured || !st.last_poll_at) return null;
    return F.fleet().findings.map((f) => ({ key: 'fgt:' + (f.serial || f.device) + ':' + f.code, severity: SEV(f.severity), kind: f.code, title: f.device + ': ' + f.title,
      evidence: ['FortiGate fleet poll ' + st.last_poll_at], recommendation: f.fix, target: { type: 'firewall', id: f.serial || f.device, name: f.device }, site: '' }));
  };
  const nacFind = async () => {
    const N = deps.nacApi; if (!N) return null; const v = N.view(); if (!v.connected || !v.total || v.learning) return null;
    return v.endpoints.filter((e) => e.risk >= 30 && !e.quarantine && !e.authorised).slice(0, 200).map((e) => ({ key: 'nac:' + e.mac, severity: e.risk >= 60 ? 'high' : 'medium', kind: 'endpoint-risk',
      title: (e.host || e.mac) + ' - risk ' + e.risk + (e.sw ? ' on ' + e.sw.switch + ' ' + e.sw.port : e.site ? ' at ' + e.site : ''), evidence: e.reasons.map((r) => '+' + r.points + ' ' + r.why),
      recommendation: 'Confirm who owns it; authorise it, or propose a quarantine (Network Access Control)', target: { type: 'endpoint', id: e.mac, name: e.host || e.mac }, site: e.site || '' }));
  };
  const ndrFind = async () => {
    if (!deps.state) return null; const r = deps.state.collection('ndr_run').get('last'); if (!r) return null;
    return (r.detections || []).filter((d) => d.severity !== 'low').map((d) => ({ key: 'ndr:' + d.kind + ':' + d.host + ':' + (d.dst || ''), severity: SEV(d.severity), kind: d.kind, title: d.host + ': ' + d.why,
      evidence: ['NDR run ' + r.at], recommendation: d.kind === 'beacon' ? 'Find the process on the host making the connections (EDR), block the destination if it is not known-good' : d.kind === 'exfil' ? 'Ask the owner what was sent; check the destination; contain the host if it is not expected' : 'Check who logged on to the host and why it reached those machines; isolate it if it is not an admin task',
      target: { type: 'host', id: d.host, name: d.host }, site: '' }));
  };
  const mcFind = async () => {
    const st = deps.mimecastStats ? deps.mimecastStats() : null; const c = (deps.config && deps.config.mimecast) || {}; if (!st || !c.enabled) return null;
    const out = [], now = (deps.now || Date.now)();
    if (st.last_error) out.push({ key: 'mimecast:error', severity: 'high', kind: 'collector', title: 'Mimecast collector: ' + String(st.last_error).slice(0, 200), evidence: ['collector status'], recommendation: 'Integration Hub → Mimecast → Test shows the failing step', target: { type: 'collector', id: 'mimecast', name: 'Mimecast' }, site: '' });
    if (st.last_poll_at && now - Date.parse(st.last_poll_at) > 2 * 3600000) out.push({ key: 'mimecast:stale', severity: 'medium', kind: 'collector', title: 'Mimecast has not been polled since ' + st.last_poll_at, evidence: ['collector status'], recommendation: 'Check the SIEM service and outbound HTTPS to the Mimecast API', target: { type: 'collector', id: 'mimecast', name: 'Mimecast' }, site: '' });
    return out;
  };
  return [
    { id: 'fortigate', name: 'AI Firewall Engineer (FortiGate)', findings: fwFind, investigate: (it) => inv(it, 'FortiGate fleet: '), verify: verifyBy(fwFind) },
    { id: 'nac', name: 'AI Network Access Engineer', findings: nacFind, investigate: (it) => inv(it, 'Network Access Control: '), verify: verifyBy(nacFind) },
    { id: 'ndr', name: 'AI NDR Analyst', findings: ndrFind, investigate: (it) => inv(it, 'NDR: '), verify: verifyBy(ndrFind) },
    { id: 'mimecast', name: 'AI Email Security Engineer (Mimecast)', findings: mcFind, investigate: (it) => inv(it, 'Mimecast: '), verify: verifyBy(mcFind) },
  ];
}

module.exports = { estateAdapters };
