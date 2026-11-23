// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Somansa DLP — Privacy-i (endpoint DLP, the customer's product), Mail-i (network / email DLP) and Server-i
 * (server DLP) export incidents to SIEM over syslog (type `somansa`; aliases `privacy-i`, `somansa-dlp`).
 *
 * FORMAT (// VERIFY in customer environment): the Somansa policy server's SIEM/syslog export is customer-editable.
 * The documented default we onboard with is a Somansa key=value line (a product token followed by key=value /
 * key="quoted value" pairs); if the customer configures the CEF export instead, cef.js + the `somansa` hook in
 * cef-vendors.js produce the SAME normalised fields. Only the field NAMES below are assumed — the parser reads any of
 * the documented aliases and never invents a value that is not in the line.
 *   Privacy-i: policy="Confidential-USB" action=Block channel=USB file="payroll.xlsx" user=jdoe pc=FIN-PC07
 *     classification="National ID" severity=High incidentid=100245 dst="E:\" matchcount=37
 *
 * Normalised to the SAME DLP fields as the dlp() normaliser (cef-vendors.js): action dlp-incident, outcome, severity,
 * fields.dlp_vendor=somansa, dlp_action (blocked|quarantined|permitted|…), dlp_policy, dlp_channel (usb|print|upload|
 * network|clipboard|…), dlp_classification, dlp_severity, dlp_incident_id, dlp_file, dlp_destination, dlp_match_count,
 * user, host. Agent/protection-disabled events -> action agent-tamper (tags dlp, agent-tamper, T1685). Unrecognised
 * lines from a somansa source become a generic policy/log event (never dropped, never thrown).
 */
const { split, clean, parseKV, sevFromName, sevFromSyslog, splitUser, ipOrEmpty } = require('./util');
const { dlpAction } = require('./cef-vendors'); // shared DLP action vocabulary (no cycle: cef-vendors does not require this)

const MARK = /\b(?:somansa|privacy-?i|mail-?i|server-?i)\b/i;
const APP_MARK = /^(?:somansa|privacy-?i|mail-?i|server-?i)/i;
const TAMPER = /\bagent\b.*\b(?:stop|stopped|disabled|off|uninstall(?:ed)?|terminated|removed|killed)\b|\bprotection\b.*\b(?:off|disabled|stopped|bypass)\b|\bservice\b.*\bstopped\b|\btamper\b|real-?time protection disabled/i;

function pick(kv, ...keys) { for (const k of keys) { const v = clean(kv[k]); if (v) return v; } return ''; }

function parse(line, meta = {}) {
  const { hdr, body } = split(line, meta);
  const text = String(body || '').trim();
  if (!text) return null;
  const app = (hdr && hdr.app ? hdr.app : '').replace(/\[\d+\]$/, '').toLowerCase();
  const product = /privacy-?i/i.test(text + ' ' + app) ? 'Privacy-i' : /mail-?i/i.test(text + ' ' + app) ? 'Mail-i' : /server-?i/i.test(text + ' ' + app) ? 'Server-i' : 'Somansa';
  const ev = {
    src_type: 'somansa', category: 'policy', action: 'log', outcome: 'unknown',
    severity: hdr && hdr.sev >= 0 ? sevFromSyslog(hdr.sev) : 0, process: app || 'somansa',
    message: text.slice(0, 1000), tags: [], fields: {},
  };
  const kv = parseKV(text, { lowerKeys: true });

  // ---- agent / protection disabled (tamper) ----
  if (TAMPER.test(text)) {
    Object.assign(ev, { category: 'policy', action: 'agent-tamper', outcome: 'failure', severity: Math.max(ev.severity, 3) });
    const u = pick(kv, 'user', 'username', 'employee', 'userid');
    if (u) { const w = splitUser(u); ev.user = w.user; if (w.domain) ev.domain = w.domain; }
    const host = pick(kv, 'pc', 'host', 'hostname', 'computer', 'computername', 'endpoint', 'device', 'agent');
    if (host) ev.host = host.toLowerCase();
    Object.assign(ev.fields, { vendor_class: 'dlp', dlp_vendor: 'somansa', dlp_product: product });
    ev.tags.push('dlp', 'agent-tamper', 'T1685');
    return ev;
  }

  // ---- DLP incident (key=value) ----
  const actionRaw = pick(kv, 'action', 'result', 'control', 'block', 'status', 'response');
  const hasDlp = actionRaw || pick(kv, 'policy', 'rule', 'channel', 'classification', 'incidentid', 'file');
  if (hasDlp) {
    const action = dlpAction(actionRaw);
    Object.assign(ev, { category: 'policy', action: 'dlp-incident' });
    ev.outcome = action === 'blocked' || action === 'quarantined' ? 'failure' : action === 'permitted' || action === 'released' ? 'success' : 'unknown';
    const sevName = pick(kv, 'severity', 'risk', 'risklevel', 'grade');
    const user = pick(kv, 'user', 'username', 'employee', 'userid', 'sender');
    const host = pick(kv, 'pc', 'host', 'hostname', 'computer', 'computername', 'endpoint', 'device');
    const channel = pick(kv, 'channel', 'agenttype', 'media', 'path', 'protocol', 'transfer', 'route', 'type');
    Object.assign(ev.fields, {
      vendor_class: 'dlp', dlp_vendor: 'somansa', dlp_product: product,
      dlp_action: action || undefined, dlp_action_raw: clean(actionRaw) || undefined,
      dlp_policy: pick(kv, 'policy', 'rule', 'rulename', 'template') || undefined,
      dlp_channel: channel || undefined,
      dlp_classification: pick(kv, 'classification', 'pattern', 'datatype', 'content', 'keyword', 'category') || undefined,
      dlp_severity: sevName || undefined,
      dlp_incident_id: pick(kv, 'incidentid', 'incident', 'logid', 'id', 'detectid') || undefined,
      dlp_file: pick(kv, 'file', 'filename', 'document', 'attach', 'attachment') || undefined,
      dlp_destination: pick(kv, 'dst', 'destination', 'target', 'recipient', 'destpath', 'upload', 'url') || undefined,
      dlp_match_count: pick(kv, 'matchcount', 'match', 'count', 'detectcount', 'hit') || undefined,
    });
    if (user) { const w = splitUser(user); ev.user = w.user; if (w.domain) ev.domain = w.domain; }
    if (host) ev.host = host.toLowerCase();
    const sip = ipOrEmpty(pick(kv, 'src', 'srcip', 'sourceip', 'clientip', 'ip'));
    if (sip) ev.src_ip = sip;
    if (sevName) ev.severity = Math.max(ev.severity, sevFromName(sevName, 0));
    ev.severity = Math.max(ev.severity, 1);
    ev.tags.push('dlp');
    ev.message = `Somansa ${product} DLP ${action || 'incident'}: ${ev.fields.dlp_policy || ''}${channel ? ' via ' + channel : ''}${ev.user ? ' by ' + ev.user : ''}`.trim().slice(0, 1000);
    return ev;
  }

  // ---- anything else from a somansa source: generic policy/log event ----
  ev.fields.dlp_vendor = 'somansa';
  ev.fields.dlp_product = product;
  return ev;
}

module.exports = {
  name: 'somansa',
  sniff(line, meta = {}) {
    const { hdr, body } = split(line, meta);
    if (hdr && APP_MARK.test(hdr.app || '')) return true;
    return MARK.test(String(body || ''));
  },
  parse,
};
