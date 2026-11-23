// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Rule set = built-in pack (engine/detect/rules/*.json, read-only, shipped with the engine)
 *          + admin changes stored in the state collection "rules".
 *
 * State collection "rules" documents are complete rule definitions plus metadata:
 *   { ...rule, origin: 'builtin' | 'custom' | 'sigma', updated, updated_by }
 *   - origin 'builtin'  → an override of a shipped rule (e.g. enabled:false, tuned thresholds). Removing it resets the rule.
 *   - origin 'custom'/'sigma' → rules created through the API / imported from Sigma.
 *
 * Event fields the built-in pack relies on = what the core parsers emit (engine/parse/*.js; verified end-to-end by
 * tests/detect-e2e-parse.test.js). Raw vendor names are accepted as fallbacks where cheap.
 *   Windows: event_code = EventID; 4624/4625 user = TargetUserName, fields.logon_type, fields.status / sub_status /
 *     failure_reason; 4728/4732/4756 action group-member-added, user = actor, target_user = member, fields.group = group name
 *     (+ raw fields.TargetSid); 4720/4722 action user-created/user-enabled, target_user; 4740 target_user; 4768 action
 *     kerberos-tgt, fields.preauth_type / ticket_encryption; 4769 action kerberos-service-ticket, fields.service_name /
 *     ticket_encryption (failure → outcome failure); 1102 action audit-log-cleared; 7045/4697 action service-installed,
 *     cmdline = ImagePath/ServiceFileName, fields.service_name; 4698 action scheduled-task-created, fields.task_name;
 *     4104 action script-block with the script text in cmdline; 4688/Sysmon 1 action process-start, process, cmdline, hash;
 *     Sysmon 10 raw fields.SourceImage / TargetImage / GrantedAccess; Sysmon 22 dns_query.
 *   Linux: sshd → process 'sshd', fields.service 'ssh', action logon / logon-failed; sudo → action 'sudo', cmdline = COMMAND,
 *     target_user = USER, outcome failure on "incorrect password attempts"; useradd → user-created; usermod/gpasswd → group-member-added.
 *   FortiGate: event_code = logid; fields.* = raw key=value pairs (subtype, action, severity, crlevel, attack, sentbyte,
 *     logdesc, hostname, status, ui…); traffic deny → action 'blocked'; IPS → 'ips-detection'; AV → 'av-detection';
 *     VPN failure → action logon-failed (+ fields.action ssl-login-fail); admin login → action logon, fields.subtype system.
 *   Web (nginx/apache): category 'web', url (path+query, undecoded), http_status, user_agent.
 *   M365: src_type 'm365'; sign-ins: event_code = error code (500121 = MFA denied), fields.risk_level / risk_state;
 *     unified audit: event_code = Operation (New-InboxRule, Set-Mailbox…), fields.Parameters (JSON string).
 */
const fs = require('fs');
const path = require('path');

const RULES_DIR = path.join(__dirname, 'rules');
const META_KEYS = ['origin', 'updated', 'updated_by'];

function loadBuiltinRules(dir = RULES_DIR) {
  const out = [];
  const seen = new Set();
  for (const f of fs.readdirSync(dir).filter((n) => n.endsWith('.json')).sort()) {
    const arr = JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8'));
    for (const r of Array.isArray(arr) ? arr : [arr]) {
      if (seen.has(r.id)) throw new Error(`duplicate built-in rule id ${r.id} (${f})`);
      seen.add(r.id);
      out.push(Object.assign({}, r, { builtin: true, pack_file: f }));
    }
  }
  return out;
}

function stripMeta(doc) {
  const r = Object.assign({}, doc);
  for (const k of META_KEYS) delete r[k];
  return r;
}

/** Effective rules (built-ins with overrides applied + custom rules). */
function effectiveRules(state, builtins) {
  const base = builtins || loadBuiltinRules();
  const byId = new Map(base.map((r) => [r.id, r]));
  const stored = state ? state.collection('rules').all() : [];
  for (const doc of stored) {
    if (doc.origin === 'builtin' && byId.has(doc.id)) byId.set(doc.id, Object.assign({}, stripMeta(doc), { builtin: true, overridden: true }));
    else if (doc.origin !== 'builtin') byId.set(doc.id, Object.assign({}, stripMeta(doc), { builtin: false, origin: doc.origin }));
  }
  return [...byId.values()].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
}

module.exports = { loadBuiltinRules, effectiveRules, RULES_DIR };
