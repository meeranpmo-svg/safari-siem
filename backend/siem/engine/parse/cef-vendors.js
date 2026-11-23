// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Vendor-aware post-mappers for CEF (cef.js) and LEEF (leef.js) events. Keyed on the CEF/LEEF header vendor/product
 * (and the LEEF "product" attribute for Check Point Log Exporter). Each hook reads the already-parsed extension
 * attributes (x) plus the labelled custom strings cef.js copied into ev.fields[<label>] and lands the vendor's data on
 * the normalised fields consistently:
 *
 *   DLP  (Forcepoint DLP, Symantec DLP, Trend Micro DLP)     → category policy, action dlp-incident, tags [dlp],
 *        fields.dlp_action blocked|quarantined|permitted|encrypted|released, dlp_policy, dlp_channel, dlp_classification,
 *        dlp_severity, dlp_incident_id, dlp_destination; outcome failure = blocked/quarantined, success = permitted.
 *   EDR  (CrowdStrike Falcon, SentinelOne, Trend Micro Apex One / Apex Central / Deep Security)
 *        → category malware, action edr-detection (av-detection for pure antivirus verdicts), tags [edr],
 *        fields.remediated true|false, disposition, threat_name, mitre_tactic / mitre_technique, confidence;
 *        outcome success = remediated/blocked, failure = detection only. Agent uninstall / tamper → action agent-tamper.
 *   Check Point (Log Exporter CEF or LEEF)                   → firewall allowed/blocked, IPS ips-detection, Anti-Virus /
 *        Anti-Bot / Threat Emulation av-detection, URL Filtering / Application Control web, Identity Awareness logon,
 *        SmartConsole/Security Management audit config-change (user = administrator, src_ip = client_ip).
 *
 * The CEF/LEEF message templates of DLP products are customer-editable ("verify" in docs/PARSERS.md): hooks therefore
 * look for the documented label names (Policy, Channel, Action, Classification, Incident ID…) and the standard keys
 * (act, suser, duser, fname, request, externalId) and never invent a value that is not in the message.
 */
const { clean, ipOrEmpty, splitUser, sevFromName } = require('./util');
const { normalizeMail } = require('./mailnorm');

const lc = (v) => String(v === undefined || v === null ? '' : v).toLowerCase();
function first(...vals) { for (const v of vals) { const c = clean(v); if (c) return c; } return ''; }
// first ev.fields value whose KEY matches re
function byLabel(ev, re) {
  for (const [k, v] of Object.entries(ev.fields || {})) if (re.test(k) && clean(v)) return clean(v);
  return '';
}
function setUser(ev, u) { if (!u) return; const w = splitUser(u); ev.user = w.user; if (w.domain) ev.domain = w.domain; }
function setHost(ev, h) { if (h && !ev.host) ev.host = clean(h).toLowerCase(); }

// ---------------------------------------------------------------- DLP
const DLP_ACTION = [
  [/quarant/, 'quarantined'], [/encrypt/, 'encrypted'], [/releas/, 'released'],
  [/block|drop|den|reject|remov|delet|prevent|discard|^yes$|^true$|^1$/, 'blocked'],
  [/permit|allow|audit|monitor|notif|log|pass|none|confirm|^no$|^false$|^0$|not blocked/, 'permitted'],
];
function dlpAction(v) { const s = lc(v); if (!s) return ''; for (const [re, a] of DLP_ACTION) if (re.test(s)) return a; return s.replace(/\s+/g, '-'); }

function dlp(ev, x, d) {
  const action = dlpAction(d.action);
  Object.assign(ev, { category: 'policy', action: 'dlp-incident' });
  ev.outcome = action === 'blocked' || action === 'quarantined' ? 'failure' : action === 'permitted' || action === 'released' ? 'success' : 'unknown';
  Object.assign(ev.fields, {
    vendor_class: 'dlp', dlp_vendor: d.vendor, dlp_action: action || undefined, dlp_action_raw: clean(d.action) || undefined,
    dlp_policy: clean(d.policy) || undefined, dlp_channel: clean(d.channel) || undefined, dlp_classification: clean(d.classification) || undefined,
    dlp_severity: clean(d.severity) || undefined, dlp_incident_id: clean(d.incident_id) || undefined, dlp_destination: clean(d.destination) || undefined,
    dlp_file: clean(d.file) || undefined, dlp_match_count: clean(d.match_count) || undefined,
  });
  if (d.user) setUser(ev, d.user);
  if (d.host) setHost(ev, d.host);
  if (d.severity) ev.severity = Math.max(ev.severity, sevFromName(d.severity, 0));
  ev.severity = Math.max(ev.severity, 1);
  ev.tags.push('dlp');
  if (!ev.message || ev.message === d.name) ev.message = `DLP ${action || 'incident'}: ${d.policy || d.name || ''}${d.channel ? ' via ' + d.channel : ''}${ev.user ? ' by ' + ev.user : ''}`.slice(0, 1000);
}

function forcepointDlp(ev, x, h) {
  dlp(ev, x, {
    vendor: 'forcepoint', name: h.name,
    policy: first(byLabel(ev, /^polic(y|ies)|policy ?name|rule ?name/i), h.name),
    action: first(x.act, byLabel(ev, /^action$|action ?taken|^act$/i), x.outcome),
    channel: first(byLabel(ev, /channel/i), x.cat, x.app),
    classification: first(byLabel(ev, /classif|data ?type|content ?classif|category|detected ?values?/i)),
    severity: first(byLabel(ev, /^severity$|^incident severity$/i), x.cat && /^(low|medium|high|critical)$/i.test(x.cat) ? x.cat : ''),
    incident_id: first(x.externalId, byLabel(ev, /incident ?id|^id$|event ?id/i)),
    destination: first(x.duser, x.destinationUserName, x.dhost, x.request, byLabel(ev, /destination/i)),
    file: first(x.fname, x.fileName, byLabel(ev, /file ?name|attachment/i)), match_count: first(x.cnt, byLabel(ev, /match|number of/i)),
    user: first(x.suser, x.sourceUserName, byLabel(ev, /^source$|source ?user|^user$|sender/i)), host: first(x.shost, x.dvchost, byLabel(ev, /endpoint|machine|hostname/i)),
  });
}

function symantecDlp(ev, x, h) {
  const blocked = byLabel(ev, /^blocked$|block/i);
  dlp(ev, x, {
    vendor: 'symantec', name: h.name,
    policy: first(byLabel(ev, /^polic(y|ies)|policy ?name|^rules?$/i), h.name),
    action: first(blocked, x.act, byLabel(ev, /^action|response|status/i)),
    channel: first(byLabel(ev, /protocol|channel/i), x.app, x.cat),
    classification: first(byLabel(ev, /classif|data ?identifier|data ?owner ?name|^rules?$|content/i)),
    severity: first(byLabel(ev, /^severity$/i), /^(info|low|medium|high|critical)$/i.test(h.sev) ? h.sev : ''),
    incident_id: first(x.externalId, byLabel(ev, /incident ?id|^id$/i), h.sigId !== '' && /^\d+$/.test(h.sigId) ? h.sigId : ''),
    destination: first(x.duser, byLabel(ev, /recipient|destination/i), x.dhost, x.request),
    file: first(x.fname, byLabel(ev, /attachment|file ?name/i)), match_count: first(x.cnt, byLabel(ev, /match ?count/i)),
    user: first(x.suser, byLabel(ev, /sender|endpoint ?user|^user$/i)), host: first(x.shost, byLabel(ev, /endpoint ?machine|machine|hostname/i)),
  });
  if (x.msg && !ev.fields.dlp_subject) ev.fields.dlp_subject = clean(x.msg).slice(0, 500);
}

// ---------------------------------------------------------------- EDR
const REMEDIATED = /blocked|quarantin|killed|prevented|cleaned|deleted|removed|mitigated|resolved|remediated|rolled ?back|rollback|terminated|denied|contained|isolat|success/;
const NOT_REMEDIATED = /detect(?:ion)? only|would have been|not mitigated|unresolved|^active$|unmitigated|failed|unable|pass(?:ed)?$|^log(?:ged)? only|^detected$|^monitor|^alert(?:ed)?$|not ?blocked|allowed|^none$/;
function remediatedOf(...vals) {
  const s = vals.map(lc).filter(Boolean).join(' | ');
  if (!s) return '';
  if (NOT_REMEDIATED.test(s)) return 'false';
  if (REMEDIATED.test(s)) return 'true';
  return '';
}

function edr(ev, x, d) {
  Object.assign(ev, { category: 'malware', action: d.action || 'edr-detection' });
  const rem = d.remediated;
  ev.outcome = rem === 'true' ? 'success' : rem === 'false' ? 'failure' : 'unknown';
  Object.assign(ev.fields, {
    vendor_class: 'edr', edr_vendor: d.vendor, remediated: rem || undefined, disposition: clean(d.disposition) || undefined,
    threat_name: clean(d.threat) || undefined, threat_classification: clean(d.classification) || undefined, confidence: clean(d.confidence) || undefined,
    mitre_tactic: clean(d.tactic) || undefined, mitre_technique: clean(d.technique) || undefined, detection_id: clean(d.detection_id) || undefined,
    file_path: clean(d.file) || undefined, console_url: clean(d.link) || undefined,
  });
  if (d.user) setUser(ev, d.user);
  if (d.host) setHost(ev, d.host);
  if (d.hash) ev.hash = clean(d.hash).toLowerCase();
  if (d.process && !ev.process) ev.process = clean(d.process);
  if (d.cmdline) ev.cmdline = clean(d.cmdline).slice(0, 8000);
  if (d.technique) { const t = /\bT\d{4}(?:\.\d{3})?\b/.exec(d.technique); if (t) ev.tags.push(t[0]); }
  ev.severity = Math.max(ev.severity, rem === 'false' ? 2 : 1);
  ev.tags.push('edr');
  if (!ev.message || ev.message === d.name) ev.message = `${d.vendor} ${d.action === 'agent-tamper' ? 'agent tamper' : 'detection'}: ${d.threat || d.name || ''}${d.disposition ? ' (' + d.disposition + ')' : ''}${ev.host ? ' on ' + ev.host : ''}`.slice(0, 1000);
}

const TAMPER_RE = /uninstall|tamper|maintenance token|sensor (?:removed|disabled|uninstalled)|agent (?:removed|disabled|uninstalled|decommission)|protection (?:disabled|turned off)|anti-?tamper|real-?time protection disabled|unload(?:ed)? (?:the )?(?:agent|sensor)/i;

function crowdstrike(ev, x, h) {
  const sig = lc(h.sigId);
  const text = `${h.name} ${x.cat || ''} ${x.act || ''} ${x.msg || ''} ${byLabel(ev, /operation|activity/i)}`;
  if (TAMPER_RE.test(text) || (/useractivityaudit/.test(sig) && /uninstall|maintenance/i.test(text))) {
    edr(ev, x, { vendor: 'crowdstrike', name: h.name, action: 'agent-tamper', remediated: '', disposition: first(x.act, byLabel(ev, /operation/i)), user: first(x.suser, x.duser), host: first(x.shost, x.dhost) });
    ev.severity = Math.max(ev.severity, 3);
    ev.tags.push('T1685');
    return;
  }
  if (/authactivityaudit/.test(sig) || /\b(?:log ?on|log ?in|authentication)\b/i.test(h.name) && !/detect/i.test(h.name)) {
    const failed = /fail|denied|invalid/i.test(text);
    Object.assign(ev, { category: 'authentication', action: failed ? 'logon-failed' : /log ?out|log ?off/i.test(text) ? 'logoff' : 'logon', outcome: failed ? 'failure' : 'success' });
    setUser(ev, first(x.suser, x.duser));
    ev.fields.vendor_class = 'edr'; ev.tags.push('edr', 'console-audit');
    return;
  }
  if (/useractivityaudit|remoteresponse|audit/.test(sig)) {
    Object.assign(ev, { category: 'system', action: /remoteresponse/.test(sig) ? 'event' : 'config-change', outcome: 'success' });
    setUser(ev, first(x.suser, x.duser));
    ev.fields.vendor_class = 'edr'; ev.fields.operation = first(x.act, byLabel(ev, /operation/i)) || undefined; ev.tags.push('edr', 'console-audit');
    return;
  }
  // DetectionSummaryEvent / EppDetectionSummaryEvent / IncidentSummaryEvent
  const disposition = first(x.act, byLabel(ev, /disposition/i));
  edr(ev, x, {
    vendor: 'crowdstrike', name: h.name, threat: first(x.cat, byLabel(ev, /detect ?name|^name$|detection/i), h.name),
    disposition, remediated: remediatedOf(disposition, x.outcome),
    classification: first(byLabel(ev, /objective/i)), tactic: first(byLabel(ev, /tactic/i)), technique: first(byLabel(ev, /technique/i)),
    confidence: first(byLabel(ev, /confidence|severity ?name/i)), detection_id: first(x.externalId, byLabel(ev, /detect ?id|composite ?id/i)),
    user: first(x.suser, x.duser), host: first(x.shost, x.dhost, x.dvchost, byLabel(ev, /computer ?name|hostname/i)),
    hash: first(x.fileHash, byLabel(ev, /sha256|sha-256|md5|hash/i)), process: first(x.sproc, x.deviceProcessName, x.fname, x.filePath, byLabel(ev, /file ?path|file ?name|image/i)),
    cmdline: first(byLabel(ev, /command ?line|cmdline/i), x.deviceCustomString5 && /command/i.test(x.cs5Label || '') ? x.cs5 : ''), link: first(byLabel(ev, /link|url/i)),
  });
}

function sentinelone(ev, x, h) {
  const text = `${h.name} ${x.cat || ''} ${x.act || ''} ${x.activityType || ''} ${x.msg || ''}`;
  const mitig = first(x.mitigationStatus, x.incidentStatus, x.threatStatus, byLabel(ev, /mitigation|incident ?status|threat ?status/i), x.act, x.outcome);
  if (TAMPER_RE.test(text)) {
    edr(ev, x, { vendor: 'sentinelone', name: h.name, action: 'agent-tamper', disposition: first(x.activityType, x.act), user: first(x.suser, x.accountName && /@/.test(x.accountName) ? x.accountName : '', x.user), host: first(x.shost, x.computerName, x.dhost) });
    ev.severity = Math.max(ev.severity, 3);
    ev.tags.push('T1685');
    return;
  }
  if (/threat|malicious|suspicious|detect|mitigat|quarantin|killed|rollback|remediat|blocked|infected/i.test(text) || x.threatClassification || x.fileHash) {
    edr(ev, x, {
      vendor: 'sentinelone', name: h.name, threat: first(x.threatName, x.fname, x.filePath && x.filePath.split(/[\\/]/).pop(), h.name),
      disposition: mitig, remediated: remediatedOf(mitig, x.analystVerdict && /false ?positive|benign/i.test(x.analystVerdict) ? 'resolved' : ''),
      classification: first(x.threatClassification, x.classification), confidence: first(x.confidenceLevel, x.detectionType, x.engines),
      detection_id: first(x.threatId, x.externalId, x.activityID), user: first(x.suser, x.sourceUserName, x.user, x.loggedInUser),
      host: first(x.shost, x.computerName, x.dhost, x.agentComputerName), hash: first(x.fileHash, x.sha1, x.sha256, x.md5),
      process: first(x.filePath, x.sourceProcessName, x.sproc, x.fname), cmdline: first(x.commandLine, x.sourceProcessCommandLine), link: first(x.threatUrl, x.url),
    });
    if (x.osFamily) ev.fields.os_family = x.osFamily;
    if (x.siteName) ev.fields.site = x.siteName;
    if (x.groupName) ev.fields.agent_group = x.groupName;
    return;
  }
  // management-console activity (user login, policy change, agent actions)
  const failed = /fail|denied|invalid/i.test(text);
  if (/log ?in|log ?on|authentic/i.test(text)) Object.assign(ev, { category: 'authentication', action: failed ? 'logon-failed' : /log ?out/i.test(text) ? 'logoff' : 'logon', outcome: failed ? 'failure' : 'success' });
  else Object.assign(ev, { category: 'system', action: /polic|setting|config|exclusion|changed|modified|created|deleted/i.test(text) ? 'config-change' : 'event', outcome: 'success' });
  setUser(ev, first(x.suser, x.accountName && /@/.test(x.accountName) ? x.accountName : '', x.user));
  ev.fields.vendor_class = 'edr'; ev.tags.push('edr', 'console-audit');
  if (x.activityType) ev.fields.activity_type = x.activityType;
}

const TREND_TYPE = [
  [/virus|malware|spyware|grayware|predictive machine learning|ransomware|anti-?malware/i, 'av'],
  [/c&c|c2|callback|command.{0,3}control/i, 'c2'],
  [/web (?:security|reputation)|url/i, 'web'],
  [/behavior monitoring|behaviour|attack discovery|suspicious object|endpoint sensor|xdr/i, 'edr'],
  [/data loss|dlp/i, 'dlp'],
  [/intrusion|ips|network security/i, 'ips'],
  [/device (?:access )?control|device control/i, 'device'],
  [/application control/i, 'appctl'],
  [/integrity monitoring|log inspection/i, 'file'],
];
function trendmicro(ev, x, h) {
  const text = `${h.name} ${h.sigId} ${x.cat || ''}`;
  let kind = '';
  for (const [re, k] of TREND_TYPE) if (re.test(text)) { kind = k; break; }
  const act = first(x.act, byLabel(ev, /^action|result|first ?action|second ?action/i));
  const host = first(x.dhost, x.shost, x.dvchost, byLabel(ev, /endpoint|host ?name|computer/i));
  const user = first(x.duser, x.suser, byLabel(ev, /user/i));
  const threat = first(byLabel(ev, /virus|malware|threat ?name|spyware|rule ?name|signature/i), x.cs1 && !x.cs1Label ? x.cs1 : '', x.cat, h.name);
  if (TAMPER_RE.test(`${h.name} ${act} ${x.msg || ''}`)) {
    edr(ev, x, { vendor: 'trendmicro', name: h.name, action: 'agent-tamper', disposition: act, user, host });
    ev.severity = Math.max(ev.severity, 3); ev.tags.push('T1685');
    return;
  }
  switch (kind) {
    case 'av':
      edr(ev, x, { vendor: 'trendmicro', name: h.name, action: 'av-detection', threat, disposition: act, remediated: remediatedOf(act, x.outcome), user, host, hash: first(x.fileHash, byLabel(ev, /sha|md5|hash/i)), process: first(x.fname, x.filePath, byLabel(ev, /file ?path|file ?name|infected/i)), link: '' });
      ev.severity = Math.max(ev.severity, 3);
      break;
    case 'edr':
      edr(ev, x, { vendor: 'trendmicro', name: h.name, threat, disposition: act, remediated: remediatedOf(act, x.outcome), user, host, hash: first(x.fileHash), process: first(x.sproc, x.dproc, x.fname, x.filePath), cmdline: first(byLabel(ev, /command/i)) });
      break;
    case 'c2':
      Object.assign(ev, { category: 'network', action: 'ips-detection', outcome: /block|den|drop|quarant|clean/i.test(act) ? 'failure' : act ? 'success' : 'unknown', severity: Math.max(ev.severity, 3) });
      ev.fields.vendor_class = 'edr'; ev.fields.threat_name = threat || undefined; ev.tags.push('edr', 'c2', 'T1071');
      if (x.request) ev.url = x.request;
      setHost(ev, host); setUser(ev, user);
      break;
    case 'ips':
      Object.assign(ev, { category: 'network', action: 'ips-detection', outcome: /block|den|drop|reset|prevent/i.test(act) ? 'failure' : act ? 'success' : 'unknown', severity: Math.max(ev.severity, 2) });
      ev.fields.threat_name = threat || undefined; setHost(ev, host);
      break;
    case 'web':
      Object.assign(ev, { category: 'web', action: /block|den/i.test(act) ? 'blocked' : 'allowed', outcome: /block|den/i.test(act) ? 'failure' : 'success' });
      if (!ev.url) ev.url = first(x.request, byLabel(ev, /url/i));
      setHost(ev, host); setUser(ev, user);
      break;
    case 'dlp':
      dlp(ev, x, { vendor: 'trendmicro', name: h.name, policy: first(byLabel(ev, /polic|template|rule/i), h.name), action: act, channel: first(byLabel(ev, /channel|protocol|process/i), x.app),
        classification: first(byLabel(ev, /template|classif|data ?identifier|category/i)), severity: '', incident_id: first(x.externalId, x.deviceExternalId), destination: first(x.duser, x.dhost, x.request), file: first(x.fname, x.filePath), user, host });
      break;
    case 'appctl':
      Object.assign(ev, { category: 'process', action: /block|den/i.test(act) ? 'blocked' : 'allowed', outcome: /block|den/i.test(act) ? 'failure' : 'success' });
      ev.process = first(x.fname, x.filePath, x.sproc) || ev.process; setHost(ev, host); setUser(ev, user);
      break;
    case 'device':
      Object.assign(ev, { category: 'policy', action: /block|den/i.test(act) ? 'blocked' : 'allowed', outcome: /block|den/i.test(act) ? 'failure' : 'success' });
      setHost(ev, host); setUser(ev, user); ev.tags.push('device-control');
      break;
    case 'file':
      Object.assign(ev, { category: 'file', action: 'event', outcome: 'unknown' }); setHost(ev, host);
      break;
    default:
      setHost(ev, host); setUser(ev, user);
      return;
  }
  ev.fields.trend_log_type = h.name;
  if (act) ev.fields.action_taken = act;
}

// ---------------------------------------------------------------- Check Point (Log Exporter)
const CP_BLOCK = /^(drop|reject|block|prevent|deny|quarantine|detect and prevent)$/i;
const CP_ALLOW = /^(accept|allow|permit|bypass|pass|inform|ask|detect|monitor|log)$/i;
function checkpoint(ev, x, h) {
  // "VPN-1 & FireWall-1" is the classic firewall blade name, not the VPN blade
  const product = lc(first(x.product, h.product)).replace(/vpn-1\s*&\s*firewall-1/, 'firewall');
  const act = first(x.act, h.format === 'leef' ? h.sigId : '', x.action);
  const blocked = CP_BLOCK.test(act);
  const allowed = CP_ALLOW.test(act);
  const sev = first(x.severity, byLabel(ev, /^severity$/i));
  if (sev) ev.severity = Math.max(ev.severity, sevFromName(sev, 0));
  ev.fields.cp_product = product || undefined;
  if (act) ev.fields.cp_action = act;
  const ruleName = first(byLabel(ev, /rule ?name|^rule$/i), x.rule_name, x.rule);
  if (ruleName) ev.fields.rule_name = ruleName;
  const user = first(x.suser, x.src_user_name, x.user, byLabel(ev, /^user ?name$|^user$/i));
  if (user) setUser(ev, user);
  if (x.resource && !ev.url) ev.url = x.resource;
  if (x.app_name && !ev.fields.app_name) ev.fields.app_name = x.app_name;
  if (/smartconsole|smartdashboard|security management|smartcenter|audit|management/.test(product) || x.administrator || x.operation) {
    const op = lc(first(x.operation, x.Operation, byLabel(ev, /^operation$/i), h.name));
    setUser(ev, first(x.administrator, x.Administrator, user));
    ev.src_ip = ipOrEmpty(x.client_ip) || ev.src_ip;
    if (/log ?in|log ?on/.test(op)) Object.assign(ev, { category: 'authentication', action: /fail/.test(op + ' ' + lc(x.audit_status)) ? 'logon-failed' : 'logon', outcome: /fail/.test(op + ' ' + lc(x.audit_status)) ? 'failure' : 'success' });
    else if (/log ?out/.test(op)) Object.assign(ev, { category: 'authentication', action: 'logoff', outcome: 'success' });
    else if (/install policy|publish|modify|create|delete|rename|clone|add|remove|set|revert/.test(op)) Object.assign(ev, { category: 'policy', action: 'config-change', outcome: /fail/.test(lc(x.audit_status)) ? 'failure' : 'success', severity: Math.max(ev.severity, 1) });
    else Object.assign(ev, { category: 'system', action: 'event', outcome: 'unknown' });
    Object.assign(ev.fields, { operation: first(x.operation, x.Operation) || undefined, object_name: first(x.objectname, x.ObjectName) || undefined, object_type: first(x.objecttype, x.ObjectType) || undefined, subject: first(x.subject) || undefined });
    ev.tags.push('admin', 'audit');
    return;
  }
  const malwareBlade = /anti.?malware|anti.?virus|anti.?bot|threat emulation|threat extraction|sandblast|zero phishing/.test(product);
  if (!malwareBlade && (/ips|smartdefense|threat prevention/.test(product) || x.protection_name || x.attack)) {
    Object.assign(ev, { category: 'network', action: 'ips-detection', outcome: blocked ? 'failure' : allowed ? 'success' : 'unknown', severity: Math.max(ev.severity, 2) });
    ev.fields.threat_name = first(x.protection_name, byLabel(ev, /protection ?name|attack ?name/i), x.attack) || undefined;
    if (x.attack_info) ev.fields.attack_info = x.attack_info;
    if (x.confidence_level) ev.fields.confidence = x.confidence_level;
    ev.tags.push('ips');
    return;
  }
  if (/anti.?malware|anti.?virus|anti.?bot|threat emulation|threat extraction|sandblast|zero phishing/.test(product)) {
    const detectOnly = /^detect$/i.test(act);
    Object.assign(ev, { category: 'malware', action: 'av-detection', outcome: blocked ? 'failure' : detectOnly || allowed ? 'success' : 'unknown', severity: Math.max(ev.severity, 3) });
    ev.fields.remediated = blocked ? 'true' : detectOnly ? 'false' : undefined;
    ev.fields.threat_name = first(x.protection_name, byLabel(ev, /protection ?name|malware ?name|virus ?name/i), x.malware_family) || undefined;
    if (x.malware_action) ev.fields.malware_action = x.malware_action;
    if (x.file_md5 || x.file_sha256 || x.file_sha1) ev.hash = lc(first(x.file_sha256, x.file_sha1, x.file_md5));
    if (x.file_name) ev.fields.file_name = x.file_name;
    if (/anti.?bot/.test(product)) ev.tags.push('c2', 'T1071');
    if (x.dst_country) ev.fields.dst_country = x.dst_country;
    return;
  }
  if (/url filtering|application control|https inspection|content awareness/.test(product)) {
    Object.assign(ev, { category: 'web', action: blocked ? 'blocked' : 'allowed', outcome: blocked ? 'failure' : 'success' });
    if (!ev.url) ev.url = first(x.resource, x.request, byLabel(ev, /url|resource/i));
    if (x.app_category || x.matched_category) ev.fields.category = first(x.app_category, x.matched_category);
    return;
  }
  if (/identity awareness|identity logging/.test(product) || /login|logon/i.test(h.name) && user) {
    const failed = /fail|reject|denied/i.test(`${h.name} ${act} ${x.auth_status || ''}`);
    Object.assign(ev, { category: 'authentication', action: failed ? 'logon-failed' : /log ?out|logoff/i.test(h.name) ? 'logoff' : 'logon', outcome: failed ? 'failure' : 'success' });
    if (x.auth_method) ev.fields.auth_method = x.auth_method;
    if (x.identity_src) ev.fields.identity_source = x.identity_src;
    return;
  }
  if (/vpn|mobile access|remote access/.test(product) || x.vpn_feature_name || x.scheme) {
    const failed = /fail|reject|denied|encryption fail/i.test(`${h.name} ${act} ${x.encryption_failure || ''} ${x.reason || ''}`);
    const login = /log ?in|log ?on|auth|key install|connect/i.test(`${h.name} ${act} ${x.vpn_feature_name || ''}`);
    if (login) Object.assign(ev, { category: 'authentication', action: failed ? 'logon-failed' : 'logon', outcome: failed ? 'failure' : 'success' });
    else Object.assign(ev, { category: 'network', action: blocked ? 'blocked' : 'vpn-event', outcome: failed || blocked ? 'failure' : 'success' });
    ev.tags.push('vpn');
    if (failed && login) ev.tags.push('T1110');
    return;
  }
  // firewall / connection logs (VPN-1 & FireWall-1, Firewall, Security Gateway)
  if (blocked) Object.assign(ev, { category: 'network', action: 'blocked', outcome: 'failure' });
  else if (allowed) Object.assign(ev, { category: 'network', action: 'allowed', outcome: 'success' });
  else if (ev.src_ip && ev.dst_ip) Object.assign(ev, { category: 'network', action: 'connection', outcome: 'unknown' });
  if (x.src_country) ev.fields.src_country = x.src_country;
}

// ---------------------------------------------------------------- Palo Alto Networks (PAN-OS CEF format)
// Header: CEF:0|Palo Alto Networks|PAN-OS|<ver>|<subtype>|<log type>|<1-10>|… (PAN-OS "CEF Configuration Guide").
// Labelled customs per the guide: Rule, Virtual System, Source/Destination Zone, URL Category, Result, Configuration
// Path, Before/After Change Detail; msg = SYSTEM description; cat = SYSTEM event id / THREAT category. ["verify" per release]
function paloalto(ev, x, h) {
  const pa = require('./paloalto');
  const type = String(h.name || '').toUpperCase();
  const sub = lc(h.sigId);
  const act = lc(x.act);
  const vd = pa.verdict(act);
  Object.assign(ev.fields, { pan_type: type, subtype: sub || undefined, pan_action: act || undefined });
  const rule = byLabel(ev, /^rule(?: name)?$/i); if (rule) ev.fields.rule = rule;
  const sevName = first(byLabel(ev, /^severity$/i), /^(informational|low|medium|high|critical)$/i.test(x.cat || '') ? x.cat : '');
  if (sevName) { ev.fields.pan_severity = lc(sevName); ev.severity = Math.max(ev.severity, sevFromName(sevName, 0)); }
  ev.event_code = `${type}${sub ? ':' + sub : ''}`;
  let m;
  if (type === 'TRAFFIC' || type === 'DECRYPTION') {
    const v = vd || 'allowed';
    Object.assign(ev, { category: 'network', action: v, outcome: v === 'blocked' ? 'failure' : 'success' });
    if (x.reason) ev.fields.session_end_reason = x.reason;
  } else if (type === 'THREAT') {
    const threat = first(byLabel(ev, /threat ?name|threat ?id|threat\/content/i), sub !== 'url' && !/^(informational|low|medium|high|critical)$/i.test(x.cat || '') ? x.cat : '');
    if (threat) { ev.fields.threat_name = threat; const t = /\((\d+)\)\s*$/.exec(threat); if (t) ev.fields.threat_id = t[1]; }
    ev.outcome = vd === 'blocked' ? 'failure' : vd === 'allowed' ? 'success' : 'unknown';
    if (sub === 'url') { Object.assign(ev, { category: 'web', action: vd || 'allowed' }); }
    else if (sub === 'virus' || sub === 'wildfire-virus') { Object.assign(ev, { category: 'malware', action: 'av-detection', severity: Math.max(ev.severity, 3) }); }
    else if (/^(vulnerability|spyware|scan|flood|packet)$/.test(sub)) { Object.assign(ev, { category: 'network', action: 'ips-detection', severity: Math.max(ev.severity, /scan|flood/.test(sub) ? 1 : 2) }); }
    else if (/^(file|data|wildfire)$/.test(sub)) { Object.assign(ev, { category: 'file', action: vd || 'allowed' }); }
    else { Object.assign(ev, { category: 'network', action: vd || 'event' }); }
    const cat = byLabel(ev, /url ?category/i); if (cat) ev.fields.category = cat;
  } else if (type === 'SYSTEM') {
    const eid = lc(first(x.cat, byLabel(ev, /event ?id/i)));
    const desc = clean(x.msg);
    ev.event_code = `SYSTEM:${eid || sub}`;
    ev.category = 'system';
    if (eid === 'auth-fail' || /authentication failed|failed authentication/i.test(desc)) { Object.assign(ev, { category: 'authentication', action: 'logon-failed', outcome: 'failure', severity: Math.max(ev.severity, 2) }); ev.tags.push('admin', 'T1110'); }
    else if (eid === 'auth-success' || /logged in via/i.test(desc)) { Object.assign(ev, { category: 'authentication', action: 'logon', outcome: 'success' }); ev.tags.push('admin'); }
    else if (/logged out/i.test(desc)) { Object.assign(ev, { category: 'authentication', action: 'logoff', outcome: 'success' }); ev.tags.push('admin'); }
    else if (sub === 'globalprotect' || /gateway-auth|portal-auth|^globalprotect/.test(eid)) { const f = /fail|denied|invalid/i.test(eid + ' ' + desc); Object.assign(ev, { category: 'authentication', action: f ? 'logon-failed' : /logout|disconnect/i.test(eid + ' ' + desc) ? 'logoff' : 'logon', outcome: f ? 'failure' : 'success' }); ev.tags.push('vpn'); if (f) ev.tags.push('T1110'); }
    else if (/^commit/.test(eid) || /^config/.test(sub)) { Object.assign(ev, { action: 'config-change', outcome: /fail/i.test(desc) ? 'failure' : 'success' }); ev.tags.push('admin'); }
    else ev.action = 'event';
    if (!ev.user && (m = /user '?([^' ]+)'?/i.exec(desc))) setUser(ev, m[1]);
    if (!ev.src_ip && (m = /(?:from|From):?\s*(\d{1,3}(?:\.\d{1,3}){3})/.exec(desc))) ev.src_ip = ipOrEmpty(m[1]);
    if ((m = /Reason:\s*([^.]+)/.exec(desc))) ev.fields.reason = m[1].trim();
  } else if (type === 'CONFIG') {
    const path = first(byLabel(ev, /configuration ?path|^path$/i));
    const result = first(byLabel(ev, /^result$/i));
    const after = first(byLabel(ev, /after ?change/i));
    Object.assign(ev, { category: /rulebase|security|nat|policy/i.test(path) ? 'policy' : 'system', action: 'config-change', outcome: /^succ/i.test(result) ? 'success' : /fail/i.test(result) ? 'failure' : 'unknown', severity: Math.max(ev.severity, 1) });
    setUser(ev, first(x.duser, x.suser));
    if (!ev.src_ip) ev.src_ip = ipOrEmpty(x.shost);
    ev.cmdline = [act, path].filter(Boolean).join(' ').slice(0, 2000);
    ev.event_code = `CONFIG:${act}`;
    Object.assign(ev.fields, { command: act || undefined, path: path || undefined, result: result || undefined, client: first(x.destinationServiceName, byLabel(ev, /^client$/i)) || undefined });
    ev.tags.push('admin');
    if (pa.anyAnyAllow(path, after)) { ev.fields.rule_any_any = 'true'; ev.severity = 3; ev.tags.push('any-any-rule'); }
  } else if (type === 'USERID') {
    const eid = lc(first(x.cat, byLabel(ev, /event ?id/i)));
    ev.event_code = `USERID:${eid || sub}`;
    Object.assign(ev, { category: 'authentication', action: /logout|timeout|delete/.test(eid) ? 'logoff' : /login|logon|add/.test(eid) ? 'logon' : 'event' });
    ev.outcome = ev.action === 'event' ? 'unknown' : 'success';
  } else if (type === 'GLOBALPROTECT') {
    const eid = lc(first(x.cat, byLabel(ev, /event ?id/i)));
    const status = lc(first(byLabel(ev, /^status$/i), x.outcome));
    const failed = status === 'failure' || /fail|denied/.test(eid);
    ev.event_code = `GLOBALPROTECT:${eid}`;
    ev.tags.push('vpn');
    if (/auth|login|connect|tunnel/.test(eid) && failed) { Object.assign(ev, { category: 'authentication', action: 'logon-failed', outcome: 'failure', severity: Math.max(ev.severity, 1) }); ev.tags.push('T1110'); }
    else if (/logout|disconnect/.test(eid)) Object.assign(ev, { category: 'authentication', action: 'logoff', outcome: 'success' });
    else if (/auth|login|connect/.test(eid)) Object.assign(ev, { category: 'authentication', action: 'logon', outcome: 'success' });
    else Object.assign(ev, { category: 'network', action: 'vpn-event' });
    const region = byLabel(ev, /source ?region|src ?region/i); if (region) ev.fields.src_country = region;
  }
  if (x.PanOSSrcLoc || x.PanOSSourceLocation) ev.fields.src_country = x.PanOSSrcLoc || x.PanOSSourceLocation;
  if (!ev.host && x.dvchost) ev.host = clean(x.dvchost);
  ev.fields.vendor_class = 'firewall';
}

// ---------------------------------------------------------------- Secure Email Gateways (CEF)
// Libraesva ESG (primary; usually its own dedicated parser, this is the CEF fallback), Proofpoint, Mimecast, Cisco ESA /
// IronPort, Forcepoint Email Security, Trend Micro / Symantec Messaging Gateway. CEF templates are vendor-specific and in
// several cases customer-editable — the hook reads the standard keys plus the documented labelled customs. // VERIFY the
// label names against the customer's gateway export. Microsoft Defender for Office 365 rides the M365 connector, not here.
function mailGateway(ev, x, h) {
  normalizeMail(ev, {
    vendor: clean(h.vendor) || clean(h.product),
    from: first(x.suser, x.sourceUserName, byLabel(ev, /^sender$|envelope.?from|mail.?from|msg.?from|^from$|sender ?address/i)),
    to: first(x.duser, x.destinationUserName, byLabel(ev, /recipient|^rcpt|mail.?to|envelope.?to|^to$/i)),
    subject: first(byLabel(ev, /subject/i)),
    action: first(x.act, byLabel(ev, /final.?action|message.?action|^action$|disposition|delivery.?status|^result$/i), x.outcome),
    verdict: first(byLabel(ev, /threat.?type|threat.?class|classification|detection.?type|spam.?class|filter.?action|^category$|module/i), x.cat, h.sigId, h.name),
    spam: first(byLabel(ev, /spam.?score|^score$|sbrs|risk.?score|spamscore|probability/i)),
    direction: first(byLabel(ev, /^direction$|directionality/i)),
    threat: first(byLabel(ev, /virus|malware|threat.?name|signature|rule.?name|spam.?name/i)),
    attachment: first(byLabel(ev, /attachment.?(?:verdict|status|disposition|result)|quicksand|file.?(?:verdict|disposition|result)|sandbox.?(?:file|attachment)/i)),
    url: first(byLabel(ev, /url.?(?:verdict|category|disposition|reputation|defense)|urlsand|link.?(?:verdict|protection)|click/i)),
    msgid: first(byLabel(ev, /message.?id|^mid$|msg.?id/i), x.externalId),
    src: first(ev.src_ip, x.src, x.sourceAddress, byLabel(ev, /sender.?ip|client.?ip|source.?ip/i)),
    severity: first(byLabel(ev, /^severity$/i), /^(info|low|medium|high|critical)$/i.test(h.sev) ? h.sev : ''),
  });
  ev.fields.email_product = clean(h.product) || undefined;
}
function mailTest(v, p, h) {
  v = String(v || '').toLowerCase();
  const vp = `${v} ${p}`.toLowerCase();
  const pl = String(p || '').toLowerCase();
  const nm = `${p} ${h && h.name ? h.name : ''}`.toLowerCase();
  if (/libraesva/.test(vp)) return true;
  if (/proofpoint|mimecast/.test(v)) return true;
  if (/iron ?port|email security appliance|\besa\b|messaging gateway|brightmail|imsva|interscan messaging|secure email|email security gateway|email protection/.test(pl)) return true;
  if (/cisco/.test(v) && /email|iron ?port|\besa\b/.test(nm)) return true;
  if (/forcepoint|websense/.test(v) && /email security|email protection|secure email/.test(pl)) return true;
  if (/trend ?micro/.test(v) && /messaging|imsva|interscan|email security/.test(nm)) return true;
  if (/symantec|broadcom/.test(v) && /messaging gateway|brightmail/.test(pl)) return true;
  return false;
}

// ---------------------------------------------------------------- Zscaler Internet Access (ZIA) via on-prem NSS (CEF)
// NSS (Nanolog Streaming Service) feeds are FULLY TEMPLATED in the ZIA Admin Portal, so the CEF label names depend on the
// feed the customer built. // VERIFY the feed output format; the hook reads the common labels plus the standard keys.
// Web proxy log (NSSWeblog) -> category web; firewall log (NSSFWlog) -> category network.
const ZS_RISKY_CAT = /anonymiz|proxy avoid|open proxies|malicious|malware|phish|botnet|spyware|command.?and.?control|\bc2\b|crypto ?min|coin ?min|newly ?(?:registered|seen)|peer.?to.?peer|\bp2p\b|remote access|dns.?(?:over|tunnel)|adware|suspicious|questionable|spam ?url|typosquat|parked|dynamic dns|miscellaneous or unknown|other adult/i;
function zscaler(ev, x, h) {
  const product = lc(first(h.product, h.name));
  const fw = /fw|firewall/.test(product) || /nssfwlog|fwlog/.test(product) || /nssfwlog|fwlog/.test(lc(byLabel(ev, /feed/i)));
  const act = first(x.act, byLabel(ev, /^action$|policy ?action|rule ?action/i), x.action);
  const blocked = /block|deny|den\b|drop|quarant|redirect|caution|isolate/i.test(lc(act));
  const user = first(x.suser, x.sourceUserName, byLabel(ev, /^user$|login ?name|^login$/i));
  if (user) setUser(ev, user);
  const urlcat = first(byLabel(ev, /url ?categor|url ?class|url ?super ?categor|app ?class|app ?categor|^category$/i), x.cat);
  const threat = first(byLabel(ev, /threat ?name|threat ?categor|malware ?class|malware ?categor|^virus$|threat$/i));
  const app = first(byLabel(ev, /^app$|cloud ?app|application ?name|^appname$/i), x.app);
  const dept = first(byLabel(ev, /department|^dept$/i));
  const policy = first(byLabel(ev, /rule ?label|policy ?name|rule ?name|^rule$|^reason$/i));
  const dlpEng = first(byLabel(ev, /dlp ?engine|dlp ?dictionar|dlp ?rule|dlp ?name/i));
  const bytesOut = first(x.out, byLabel(ev, /bytes ?out|request ?size|req ?size|^out$/i));
  const bytesIn = first(x.in, byLabel(ev, /bytes ?in|response ?size|resp ?size|^in$/i));
  if (!ev.url) ev.url = first(x.request, byLabel(ev, /^url$|request ?url/i));
  Object.assign(ev.fields, {
    vendor_class: fw ? 'firewall' : 'proxy', zscaler_product: product || undefined, zscaler_action: clean(act) || undefined,
    url_category: urlcat || undefined, app: app || undefined, department: dept || undefined, policy: policy || undefined,
    threat_name: threat || undefined, zscaler_dlp: dlpEng || undefined, bytes_out: bytesOut || undefined, bytes_in: bytesIn || undefined,
  });
  Object.assign(ev, { category: fw ? 'network' : 'web', action: blocked ? 'blocked' : 'allowed', outcome: blocked ? 'failure' : 'success' });
  if (threat) { ev.tags.push('threat'); ev.severity = Math.max(ev.severity, blocked ? 2 : 3); }
  if (dlpEng) ev.tags.push('dlp');
  ev.tags.push('zscaler');
}

// ---------------------------------------------------------------- Somansa Privacy-i / Mail-i / Server-i DLP (CEF variant)
// The customer's endpoint DLP. Its native syslog is handled by engine/parse/somansa.js; this hook covers the case where
// the Somansa policy server is configured to export CEF. // VERIFY the label names on the customer's Somansa release.
const SOMANSA_TAMPER = /agent ?(?:stop|stopped|disabled|off|uninstall|terminated|removed)|protection ?(?:off|disabled|stopped)|service ?stopped|tamper|real-?time protection disabled/i;
function somansaCef(ev, x, h) {
  const text = `${h.name} ${h.product} ${x.act || ''} ${x.msg || ''} ${byLabel(ev, /event|operation|status/i)}`;
  if (SOMANSA_TAMPER.test(text)) {
    Object.assign(ev, { category: 'policy', action: 'agent-tamper', outcome: 'failure', severity: Math.max(ev.severity, 3) });
    setUser(ev, first(x.suser, byLabel(ev, /user|employee/i)));
    setHost(ev, first(x.shost, x.dvchost, byLabel(ev, /^pc$|host|computer|endpoint|device/i)));
    Object.assign(ev.fields, { vendor_class: 'dlp', dlp_vendor: 'somansa', dlp_product: clean(h.product) || undefined });
    ev.tags.push('dlp', 'agent-tamper', 'T1685');
    return;
  }
  dlp(ev, x, {
    vendor: 'somansa', name: h.name,
    policy: first(byLabel(ev, /polic|rule ?name|template/i), h.name),
    action: first(x.act, byLabel(ev, /^action$|result|^block$|status|control/i)),
    channel: first(byLabel(ev, /channel|agent ?type|media|^path$|protocol|transfer|route/i), x.app),
    classification: first(byLabel(ev, /classif|pattern|data ?type|content|keyword|detect ?rule/i)),
    severity: first(byLabel(ev, /^severity$|risk ?level|^grade$/i), /^(low|medium|high|critical)$/i.test(x.cat || '') ? x.cat : ''),
    incident_id: first(x.externalId, byLabel(ev, /incident|log ?id|^id$|detect ?id/i)),
    destination: first(x.duser, x.dhost, x.request, byLabel(ev, /destination|target|recipient|dest ?path|upload/i)),
    file: first(x.fname, x.fileName, byLabel(ev, /file ?name|^file$|attach|document/i)),
    match_count: first(x.cnt, byLabel(ev, /match ?count|^count$|detect ?count/i)),
    user: first(x.suser, x.sourceUserName, byLabel(ev, /user|employee|sender/i)),
    host: first(x.shost, x.dvchost, byLabel(ev, /^pc$|host|computer|endpoint|device/i)),
  });
  ev.fields.dlp_product = clean(h.product) || undefined;
}

// ---------------------------------------------------------------- registry
const HOOKS = [
  { id: 'email-security', test: mailTest, apply: mailGateway },
  { id: 'zscaler', test: (v, p) => /zscaler/i.test(`${v} ${p}`) || /nssweblog|nssfwlog/i.test(p), apply: zscaler },
  { id: 'somansa', test: (v, p, h) => /somansa/i.test(v) || /privacy-?i|mail-?i|server-?i/i.test(`${p} ${h && h.name ? h.name : ''}`), apply: somansaCef },
  { id: 'paloalto', test: (v) => /palo ?alto/i.test(v), apply: paloalto },
  { id: 'forcepoint-dlp', test: (v, p, h) => /forcepoint|websense/i.test(v) && /dlp|data|triton|ap-data/i.test(p + ' ' + h.name) || /forcepoint dlp/i.test(v), apply: forcepointDlp },
  { id: 'symantec-dlp', test: (v, p) => /symantec|broadcom/i.test(v) && /dlp|data loss|vontu|enforce/i.test(p), apply: symantecDlp },
  { id: 'crowdstrike', test: (v) => /crowdstrike/i.test(v), apply: crowdstrike },
  { id: 'sentinelone', test: (v) => /sentinel ?one/i.test(v), apply: sentinelone },
  { id: 'trendmicro', test: (v) => /trend ?micro/i.test(v), apply: trendmicro },
  { id: 'checkpoint', test: (v) => /check ?point/i.test(v), apply: checkpoint },
];

/**
 * apply(ev, x, hdr) — hdr = { vendor, product, name, sigId, sev, format: 'cef'|'leef' }. Mutates ev; returns the hook id
 * (also written to ev.fields.vendor_hook) or null when no vendor hook matched.
 */
function apply(ev, x, hdr) {
  const v = String(hdr.vendor || ''), p = String(hdr.product || '');
  for (const hk of HOOKS) {
    let ok = false;
    try { ok = hk.test(v, p, hdr, x); } catch { ok = false; }
    if (!ok) continue;
    if (!ev.tags) ev.tags = [];
    if (!ev.fields) ev.fields = {};
    hk.apply(ev, x || {}, hdr);
    ev.fields.vendor_hook = hk.id;
    return hk.id;
  }
  return null;
}

module.exports = { apply, HOOKS, dlpAction, remediatedOf, byLabel };
