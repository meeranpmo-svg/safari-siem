// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Built-in response playbooks (templates). A playbook is an ordered task list; each task is either
 *   kind 'manual'       — an analyst does it and ticks it off, or
 *   kind 'automatable'  — has an action_id from ACTIONS. The engine NEVER executes actions: for automatable tasks it only
 *                         produces a recommendation + approval request object (see recommendations()). Execution is
 *                         done by a human or an external, separately approved tool after the request is approved.
 *
 *   list() → [playbook]              get(id) → playbook | null
 *   suggest(alerts[]) → playbook id  (by rule id / MITRE technique / tactic)
 *   instantiate(id) → tasks[{id,title,phase,kind,action_id,done,by,at}]
 *   entitiesFrom(alerts[]) → { ips_external[], ips_internal[], users[], hosts[], hashes[], domains[], urls[] }
 *   recommendations(tasks, entities) → [{ task_id, action_id, title, target_type, targets[], params, rationale }]
 */
const { isPrivate, parseIP } = require('../detect/ip');

const ACTIONS = {
  'fw.block_ip':            { title: 'Block external IP on FortiGate (address group deny policy)', target: 'ips_external' },
  'fw.quarantine_host':     { title: 'Quarantine internal host (FortiGate/FortiClient EMS)', target: 'ips_internal' },
  'waf.block_ip':           { title: 'Block client IP on the WAF / reverse proxy', target: 'ips_external' },
  'ad.disable_user':        { title: 'Disable Active Directory account', target: 'users' },
  'ad.reset_password':      { title: 'Force password reset at next logon', target: 'users' },
  'm365.revoke_sessions':   { title: 'Revoke Entra ID sessions / refresh tokens', target: 'users' },
  'm365.reset_mfa':         { title: 'Require MFA re-registration', target: 'users' },
  'm365.remove_inbox_rule': { title: 'Remove malicious inbox / forwarding rule', target: 'users' },
  'mail.purge_message':     { title: 'Purge the phishing message from all mailboxes', target: 'urls' },
  'mail.block_sender':      { title: 'Block sender / sender domain on the mail gateway', target: 'domains' },
  'dns.sinkhole_domain':    { title: 'Sinkhole domain on internal DNS', target: 'domains' },
  'proxy.block_domain':     { title: 'Block domain / URL on the web filter', target: 'domains' },
  'edr.isolate_host':       { title: 'Network-isolate the endpoint (EDR)', target: 'hosts' },
  'edr.scan_host':          { title: 'Run a full AV/EDR scan on the endpoint', target: 'hosts' },
  'av.block_hash':          { title: 'Add file hash to the AV/EDR block list', target: 'hashes' },
};

const PLAYBOOKS = [
  {
    id: 'PB-BRUTE-FORCE', name: 'Brute force / password spraying',
    description: 'Repeated authentication failures against one or many accounts.',
    match: { rules: ['SENTRA-AUTH-001', 'SENTRA-AUTH-002', 'SENTRA-AUTH-003', 'SENTRA-AUTH-005', 'SENTRA-LNX-001', 'SENTRA-FGT-005', 'SENTRA-SCH-001'], mitre: ['T1110'] },
    tasks: [
      { title: 'Identify targeted accounts and source IPs; confirm whether any logon succeeded', phase: 'triage', kind: 'manual' },
      { title: 'Check source IP reputation / geo and whether it is a known scanner or VPN egress', phase: 'triage', kind: 'manual' },
      { title: 'Block the external source IP(s) on the FortiGate', phase: 'containment', kind: 'automatable', action_id: 'fw.block_ip' },
      { title: 'Force password reset for accounts with a successful logon after failures', phase: 'containment', kind: 'automatable', action_id: 'ad.reset_password' },
      { title: 'Verify MFA is enforced for the targeted accounts / service', phase: 'eradication', kind: 'manual' },
      { title: 'Review account lockout policy and exposed services (RDP/SSH/VPN)', phase: 'recovery', kind: 'manual' },
      { title: 'Document findings and close the case with a resolution', phase: 'lessons', kind: 'manual' },
    ],
  },
  {
    id: 'PB-MALWARE', name: 'Malware on an endpoint',
    description: 'AV/IPS detection, known-bad hash, credential dumping or suspicious execution on a host.',
    match: { rules: ['SENTRA-FGT-002', 'SENTRA-INTEL-003', 'SENTRA-EXEC-001', 'SENTRA-EXEC-002', 'SENTRA-EXEC-003', 'SENTRA-CRED-001', 'SENTRA-CRED-002', 'SENTRA-CRED-003', 'SENTRA-SYS-003'], tactics: ['execution', 'stealth', 'defense-impairment', 'defense-evasion'] },
    tasks: [
      { title: 'Confirm the detection (file path, hash, parent process, user) and scope affected hosts', phase: 'triage', kind: 'manual' },
      { title: 'Network-isolate the affected endpoint', phase: 'containment', kind: 'automatable', action_id: 'edr.isolate_host' },
      { title: 'Block the file hash on AV/EDR', phase: 'containment', kind: 'automatable', action_id: 'av.block_hash' },
      { title: 'Block contacted C2 IPs / domains', phase: 'containment', kind: 'automatable', action_id: 'fw.block_ip' },
      { title: 'Reset credentials of users logged on to the host (credential theft assumed)', phase: 'eradication', kind: 'automatable', action_id: 'ad.reset_password' },
      { title: 'Full scan / reimage the endpoint; remove persistence (services, tasks, run keys)', phase: 'eradication', kind: 'automatable', action_id: 'edr.scan_host' },
      { title: 'Restore from clean state, monitor the host for 7 days', phase: 'recovery', kind: 'manual' },
      { title: 'Lessons learned: initial vector, detection gaps', phase: 'lessons', kind: 'manual' },
    ],
  },
  {
    id: 'PB-PHISHING', name: 'Phishing',
    description: 'Reported or detected phishing email, malicious link or attachment.',
    match: { rules: [], mitre: ['T1566'], tactics: [] },
    tasks: [
      { title: 'Collect the original message (headers, sender, URLs, attachments hashes)', phase: 'triage', kind: 'manual' },
      { title: 'Find all recipients and who clicked / opened (mail + proxy logs)', phase: 'triage', kind: 'manual' },
      { title: 'Purge the message from all mailboxes', phase: 'containment', kind: 'automatable', action_id: 'mail.purge_message' },
      { title: 'Block sender / sender domain', phase: 'containment', kind: 'automatable', action_id: 'mail.block_sender' },
      { title: 'Block phishing URLs / domains on the web filter', phase: 'containment', kind: 'automatable', action_id: 'proxy.block_domain' },
      { title: 'Reset passwords and revoke sessions for users who submitted credentials', phase: 'eradication', kind: 'automatable', action_id: 'm365.revoke_sessions' },
      { title: 'Notify users; update awareness material', phase: 'lessons', kind: 'manual' },
    ],
  },
  {
    id: 'PB-ACCOUNT-COMPROMISE', name: 'Account compromise',
    description: 'Risky sign-in, MFA fatigue, privileged group change, Kerberoasting, suspicious admin logon or mailbox rule.',
    match: { rules: ['SENTRA-M365-001', 'SENTRA-M365-002', 'SENTRA-M365-004', 'SENTRA-EXO-001', 'SENTRA-EXO-002', 'SENTRA-EXO-003', 'SENTRA-EXO-004', 'SENTRA-EXO-005', 'SENTRA-EXO-006', 'SENTRA-EXO-007', 'SENTRA-EXO-008', 'SENTRA-EXO-017', 'SENTRA-IAM-001', 'SENTRA-IAM-003', 'SENTRA-AUTH-004', 'SENTRA-AUTH-006', 'SENTRA-AUTH-007', 'SENTRA-CRED-004', 'SENTRA-CRED-005', 'SENTRA-CRED-006', 'SENTRA-FGT-006', 'SENTRA-LNX-002', 'SENTRA-LNX-003'], mitre: ['T1078', 'T1098', 'T1558', 'T1621', 'T1114'], tactics: ['initial-access', 'persistence', 'privilege-escalation'] },
    tasks: [
      { title: 'Confirm with the user / owner whether the activity was legitimate', phase: 'triage', kind: 'manual' },
      { title: 'Review the account activity timeline (logons, sources, changes) for the last 30 days', phase: 'triage', kind: 'manual' },
      { title: 'Revoke active sessions and tokens', phase: 'containment', kind: 'automatable', action_id: 'm365.revoke_sessions' },
      { title: 'Disable the account pending investigation', phase: 'containment', kind: 'automatable', action_id: 'ad.disable_user' },
      { title: 'Reset password and require MFA re-registration', phase: 'eradication', kind: 'automatable', action_id: 'm365.reset_mfa' },
      { title: 'Remove unauthorised group memberships, inbox rules, app consents', phase: 'eradication', kind: 'automatable', action_id: 'm365.remove_inbox_rule' },
      { title: 'Re-enable the account with the owner; monitor for 14 days', phase: 'recovery', kind: 'manual' },
      { title: 'Document root cause (phish, reuse, spray) and close', phase: 'lessons', kind: 'manual' },
    ],
  },
  {
    id: 'PB-WEB-ATTACK', name: 'Web application attack',
    description: 'Scanning, injection or traversal attempts against a web application; IPS hits on web services.',
    match: { rules: ['SENTRA-WEB-001', 'SENTRA-WEB-002', 'SENTRA-WEB-003', 'SENTRA-WEB-004', 'SENTRA-WEB-005', 'SENTRA-FGT-001', 'SENTRA-EXO-012', 'SENTRA-EXO-013', 'SENTRA-EXO-014', 'SENTRA-EXO-015'], mitre: ['T1190', 'T1595'], tactics: ['reconnaissance'] },
    tasks: [
      { title: 'Review the requests (URL, parameters, response codes/sizes) — did any return 200 with data?', phase: 'triage', kind: 'manual' },
      { title: 'Check application / database logs for successful exploitation', phase: 'triage', kind: 'manual' },
      { title: 'Block the attacking IP on the WAF / reverse proxy', phase: 'containment', kind: 'automatable', action_id: 'waf.block_ip' },
      { title: 'Block the attacking IP on the FortiGate', phase: 'containment', kind: 'automatable', action_id: 'fw.block_ip' },
      { title: 'Patch / fix the vulnerable endpoint; enable virtual patching (IPS/WAF signature)', phase: 'eradication', kind: 'manual' },
      { title: 'Verify integrity of the web server (webshells, new files)', phase: 'recovery', kind: 'manual' },
      { title: 'Lessons learned and close', phase: 'lessons', kind: 'manual' },
    ],
  },
  {
    id: 'PB-DATA-EXFIL', name: 'Data exfiltration',
    description: 'Unusually large outbound transfer, traffic to IOC destinations, suspicious DNS.',
    match: { rules: ['SENTRA-EXFIL-001', 'SENTRA-INTEL-001', 'SENTRA-INTEL-002', 'SENTRA-INTEL-004', 'SENTRA-FGT-003', 'SENTRA-FGT-004', 'SENTRA-EXO-009', 'SENTRA-EXO-010', 'SENTRA-EXO-011', 'SENTRA-EXO-016'], mitre: ['T1048', 'T1041', 'T1071'], tactics: ['exfiltration', 'command-and-control'] },
    tasks: [
      { title: 'Identify the internal host, user and process responsible; size and destination of the transfer', phase: 'triage', kind: 'manual' },
      { title: 'Determine whether the destination is a sanctioned service (backup, cloud sync)', phase: 'triage', kind: 'manual' },
      { title: 'Block the external destination on the FortiGate', phase: 'containment', kind: 'automatable', action_id: 'fw.block_ip' },
      { title: 'Quarantine the internal host', phase: 'containment', kind: 'automatable', action_id: 'fw.quarantine_host' },
      { title: 'Sinkhole related domains', phase: 'containment', kind: 'automatable', action_id: 'dns.sinkhole_domain' },
      { title: 'Assess what data left (classification, PDPL / regulator notification decision)', phase: 'eradication', kind: 'manual' },
      { title: 'Recover: re-image host, rotate credentials, monitor egress', phase: 'recovery', kind: 'manual' },
      { title: 'Lessons learned, DLP/egress control improvements', phase: 'lessons', kind: 'manual' },
    ],
  },
];

function list() { return PLAYBOOKS.map((p) => ({ id: p.id, name: p.name, description: p.description, tasks: p.tasks.length })); }
function get(id) { return PLAYBOOKS.find((p) => p.id === id) || null; }

function suggest(alerts) {
  const score = new Map();
  for (const a of alerts || []) {
    for (const pb of PLAYBOOKS) {
      let s = 0;
      if (pb.match.rules.includes(a.rule_id)) s += 10;
      for (const m of a.mitre || []) if ((pb.match.mitre || []).some((x) => m === x || m.startsWith(x + '.'))) s += 3;
      if (a.tactic && (pb.match.tactics || []).includes(a.tactic)) s += 1;
      if (s) score.set(pb.id, (score.get(pb.id) || 0) + s * (1 + (a.severity || 0) / 4));
    }
  }
  let best = null; let bs = 0;
  for (const [id, s] of score) if (s > bs) { best = id; bs = s; }
  return best;
}

function instantiate(id) {
  const pb = get(id);
  if (!pb) throw new Error(`unknown playbook ${id}`);
  return pb.tasks.map((t, i) => ({
    id: `T${i + 1}`, title: t.title, phase: t.phase, kind: t.kind, action_id: t.action_id || '',
    done: false, by: '', at: 0, playbook_id: pb.id,
  }));
}

const DOMAIN_RE = /^(?=.{1,253}$)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$/i;
function entitiesFrom(alerts) {
  const e = { ips_external: new Set(), ips_internal: new Set(), users: new Set(), hosts: new Set(), hashes: new Set(), domains: new Set(), urls: new Set() };
  const addIp = (v) => { if (!v || !parseIP(v)) return; (isPrivate(v) ? e.ips_internal : e.ips_external).add(v); };
  for (const a of alerts || []) {
    const bag = Object.assign({}, a.fields || {}, a.group || {});
    if (a.host) bag.host = bag.host || a.host;
    for (const [k, v0] of Object.entries(bag)) {
      const v = String(v0 || '').trim();
      if (!v) continue;
      if (/(^|\.)(src_ip|dst_ip|ip|ipaddress)$/i.test(k)) addIp(v);
      else if (/^(user|target_user)$/.test(k)) { if (!v.endsWith('$')) e.users.add(v); }
      else if (k === 'host') e.hosts.add(v);
      else if (k === 'hash') for (const h of v.match(/[0-9a-f]{32,64}/gi) || []) e.hashes.add(h.toLowerCase());
      else if (k === 'dns_query' || k === 'fields.hostname') { if (DOMAIN_RE.test(v)) e.domains.add(v.toLowerCase()); }
      else if (k === 'url') e.urls.add(v);
    }
  }
  const out = {};
  for (const k of Object.keys(e)) out[k] = [...e[k]].slice(0, 100);
  return out;
}

function recommendations(tasks, entities) {
  const out = [];
  for (const t of tasks || []) {
    if (t.kind !== 'automatable' || !t.action_id) continue;
    const act = ACTIONS[t.action_id];
    if (!act) continue;
    const targets = (entities && entities[act.target]) || [];
    out.push({
      task_id: t.id, action_id: t.action_id, title: act.title, target_type: act.target, targets,
      params: { targets },
      rationale: targets.length ? `${t.title} — ${targets.length} target(s) derived from the linked alerts`
        : `${t.title} — no ${act.target.replace('_', ' ')} found in the linked alerts; analyst must supply targets`,
    });
  }
  return out;
}

module.exports = { PLAYBOOKS, ACTIONS, list, get, suggest, instantiate, entitiesFrom, recommendations };
