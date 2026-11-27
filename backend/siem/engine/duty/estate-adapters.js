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
 *   AI Email Flow Analyst              collect/m365-mailtrace.js  Exchange Online mail: a sender far above their own usual, mail to
 *                                                               personal webmail, a phishing wave, the mail trace collector failing
 *   AI SIEM Migration Engineer         soc/cutover.js           NewEvol cutover blockers (sources missing or silent, detections missed)
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
  const mailFind = async () => {
    const MT = deps.m365Mail; if (!MT || !MT.status().ready || !deps.search || typeof deps.search.fetchEvents !== 'function') return null;
    const st = MT.status(), now = (deps.now || Date.now)(), out = [];
    if (st.last_error) out.push({ key: 'mail:collector', severity: 'high', kind: 'collector', title: 'Mail trace collector: ' + String(st.last_error).slice(0, 200), evidence: ['collector status'], recommendation: 'Grant ExchangeMessageTrace.Read.All to the Microsoft 365 app registration (admin consent)', target: { type: 'collector', id: 'm365-mailtrace', name: 'Mail trace' } });
    const evs = await deps.search.fetchEvents({ q: 'src_type:m365 AND host:exchange-mailflow', from: now - 15 * 86400000, to: now, limit: 150000 });
    const r = require('../collect/m365-mailtrace').analyse(evs, now, { days: 1, internal: ((deps.config || {}).m365 || {}).internal_domains });
    for (const x of r.spikes) out.push({ key: 'mail:spike:' + x.user + ':' + x.day, severity: 'high', kind: 'outbound-spike', title: x.user + ': ' + x.why, evidence: [x.domains + ' domain(s), ' + x.mb + ' MB'], recommendation: 'Check what was sent (indicator, not proof) - a person reviews before any step', target: { type: 'mailbox', id: x.user, name: x.user } });
    for (const p of r.personal) out.push({ key: 'mail:personal:' + p.user, severity: 'medium', kind: 'personal-webmail', title: p.user + ' mailed personal webmail ' + p.messages + ' time(s)', evidence: [p.domains.join(', ')], recommendation: 'Confirm with the line manager whether company data left (PDPL / NDMO)', target: { type: 'mailbox', id: p.user, name: p.user } });
    if (r.kpis.blocked >= 50) out.push({ key: 'mail:phish:' + new Date(now).toISOString().slice(0, 10), severity: 'medium', kind: 'phishing-wave', title: r.kpis.blocked + ' inbound messages blocked in a day' + (r.blocked_domains[0] ? ', most from ' + r.blocked_domains[0].domain : ''), evidence: ['Exchange Online message trace'], recommendation: 'Warn the users targeted and block the sender domain on the gateway', target: { type: 'domain', id: r.blocked_domains[0] ? r.blocked_domains[0].domain : 'inbound', name: 'inbound mail' } });
    return out;
  };
  const cutFind = async () => {
    if (!deps.state) return null; const C = require('../soc/cutover'); if (!deps.state.collection('cutover').get('sources')) return null;   // nothing imported: not connected
    const X = C.createCutover({ state: deps.state, alerts: deps.alerts, rules: () => (deps.detector && typeof deps.detector.rules === 'function' ? deps.detector.rules() : []), volumes: C.ourVolumes(deps.ch, deps.config), now: deps.now || Date.now });
    const v = await X.view(14);
    return v.blockers.filter((b) => b.level !== 'info').map((b) => ({ key: 'cutover:' + b.what, severity: b.level === 'crit' ? 'high' : 'medium', kind: 'cutover-blocker', title: b.what, evidence: [b.why, 'readiness ' + v.score + '/100'], recommendation: 'Close it before the NewEvol cutover, or accept it in writing on SIEM Cutover', target: { type: 'cutover', id: b.what.slice(0, 120), name: 'NewEvol cutover' } }));
  };
  return [
    { id: 'fortigate', name: 'AI Firewall Engineer (FortiGate)', findings: fwFind, investigate: (it) => inv(it, 'FortiGate fleet: '), verify: verifyBy(fwFind) },
    { id: 'nac', name: 'AI Network Access Engineer', findings: nacFind, investigate: (it) => inv(it, 'Network Access Control: '), verify: verifyBy(nacFind) },
    { id: 'ndr', name: 'AI NDR Analyst', findings: ndrFind, investigate: (it) => inv(it, 'NDR: '), verify: verifyBy(ndrFind) },
    { id: 'mimecast', name: 'AI Email Security Engineer (Mimecast)', findings: mcFind, investigate: (it) => inv(it, 'Mimecast: '), verify: verifyBy(mcFind) },
    { id: 'mailflow', name: 'AI Email Flow Analyst (Exchange Online)', findings: mailFind, investigate: (it) => inv(it, 'Email logs: '), verify: verifyBy(mailFind) },
    { id: 'cutover', name: 'AI SIEM Migration Engineer (NewEvol cutover)', findings: cutFind, investigate: (it) => inv(it, 'SIEM cutover: '), verify: verifyBy(cutFind) },
  ];
}

module.exports = { estateAdapters };
