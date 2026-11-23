// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * AD change auditing (AD Audit page: AD changes, Lockout analyzer, Policy changes) - over the Windows Security events the
 * SIEM already stores (parse/windows.js 5136-5141 / 4662 / 4739 / 4719 / 4740 / 4625 / 4771 / 4776).
 *
 *   pairChanges(events)            5136 "Value Deleted" (old) + "Value Added" (new) of one LDAP operation (OpCorrelationID,
 *                                  object, attribute) → ONE change {old_values, new_values}; 5137/5138/5139/5141 as they are
 *   describe(change)               the kind-specific reading: ACL (SDDL old/new, ACEs added / removed), GPO (attribute, version
 *                                  split, client-side extensions, links), DNS (record old / new data), schema, userAccountControl
 *   parseSddl / diffSddl           deterministic SDDL parsing (owner, group, DACL ACEs) and the added / removed ACEs
 *   analyzeLockouts(locks, fails)  each 4740 joined with the 4625 / 4771 / 4776 failures of the same account in the window
 *                                  before it → the likely source computer / process / IP with the evidence counts
 *   rankLockouts(analyses)         per account: lockouts, repeat ranking, the recurring source
 *   flattenGpoReport(xml)          Get-GPOReport -ReportType Xml → { name, guid, settings{path: value} } (setting level)
 *   diffGpoSettings(a, b)          two snapshots → [{setting, change: added|removed|changed, old, new}]
 *   createAdChanges({ ch, state, config, log, sysadmin, now })   the ClickHouse / state half (see the routes module)
 *
 * PDPL: changes name the people who made them (that is the audit); values of personal-data attributes (phone, address,
 * employee number, photo …) are not returned - only that they changed. Lockouts return account, computer, IP and process only.
 */
const W = require('../parse/windows');

const MAX_ROWS = 20000;
const PERSONAL_ATTR = new Set(['telephonenumber', 'mobile', 'homephone', 'pager', 'facsimiletelephonenumber', 'ipphone', 'othertelephone', 'othermobile', 'otherhomephone',
  'streetaddress', 'postaladdress', 'postalcode', 'postofficebox', 'homepostaladdress', 'l', 'st', 'c', 'co', 'employeeid', 'employeenumber', 'thumbnailphoto', 'jpegphoto',
  'photo', 'info', 'comment', 'personaltitle', 'birthdate', 'dateofbirth', 'extensionattribute1', 'extensionattribute2', 'extensionattribute3', 'extensionattribute4',
  'extensionattribute5', 'extensionattribute6', 'extensionattribute7', 'extensionattribute8', 'extensionattribute9', 'extensionattribute10', 'extensionattribute11',
  'extensionattribute12', 'extensionattribute13', 'extensionattribute14', 'extensionattribute15', 'unicodepwd', 'userpassword', 'dbcspwd', 'ntpwdhistory', 'lmpwdhistory',
  'supplementalcredentials', 'mslaps-password', 'ms-mcs-admpwd', 'mslaps-encryptedpassword']);
const UAC_FLAGS = [[0x2, 'ACCOUNTDISABLE'], [0x10, 'LOCKOUT'], [0x20, 'PASSWD_NOTREQD'], [0x80, 'ENCRYPTED_TEXT_PWD_ALLOWED'], [0x200, 'NORMAL_ACCOUNT'], [0x1000, 'WORKSTATION_TRUST_ACCOUNT'],
  [0x2000, 'SERVER_TRUST_ACCOUNT'], [0x10000, 'DONT_EXPIRE_PASSWORD'], [0x40000, 'SMARTCARD_REQUIRED'], [0x80000, 'TRUSTED_FOR_DELEGATION'], [0x100000, 'NOT_DELEGATED'],
  [0x200000, 'USE_DES_KEY_ONLY'], [0x400000, 'DONT_REQ_PREAUTH'], [0x800000, 'PASSWORD_EXPIRED'], [0x1000000, 'TRUSTED_TO_AUTH_FOR_DELEGATION']];
const UAC_RISKY = new Set(['PASSWD_NOTREQD', 'ENCRYPTED_TEXT_PWD_ALLOWED', 'DONT_EXPIRE_PASSWORD', 'TRUSTED_FOR_DELEGATION', 'USE_DES_KEY_ONLY', 'DONT_REQ_PREAUTH', 'TRUSTED_TO_AUTH_FOR_DELEGATION']);
// client-side extensions in gPCMachineExtensionNames / gPCUserExtensionNames (only the ones we are sure of)
const CSE = { '827D319E-6EAC-11D2-A4EA-00C04F79F83A': 'Security', '35378EAC-683F-11D2-A89A-00C04FBBCFA2': 'Administrative Templates (Registry)', '42B5FAAE-6536-11D2-AE5A-0000F87571E3': 'Scripts',
  'C6DC5466-785A-11D2-84D0-00C04FB169F7': 'Software Installation', '25537BA6-77A8-11D2-9B6C-0000F8080861': 'Folder Redirection', 'F3CCC681-B74C-4060-9F26-CD84525DCA2A': 'Advanced Audit Policy' };
const GPLINK_FLAG = { 0: 'enabled', 1: 'link disabled', 2: 'enforced', 3: 'enforced, link disabled' };

// ---------------------------------------------------------------- SDDL
const SDDL_SID = { AO: 'Account Operators', BA: 'Administrators', BG: 'Guests', BO: 'Backup Operators', BU: 'Users', CA: 'Cert Publishers', CG: 'Creator Group', CO: 'Creator Owner',
  DA: 'Domain Admins', DC: 'Domain Computers', DD: 'Domain Controllers', DG: 'Domain Guests', DU: 'Domain Users', EA: 'Enterprise Admins', ED: 'Enterprise Domain Controllers',
  WD: 'Everyone', PA: 'Group Policy Creator Owners', IU: 'Interactive', LA: 'Administrator', LG: 'Guest', LS: 'Local Service', SY: 'SYSTEM', NU: 'Network', NO: 'Network Configuration Operators',
  NS: 'Network Service', PO: 'Print Operators', PS: 'SELF', PU: 'Power Users', RS: 'RAS Servers', RD: 'Remote Desktop Users', RE: 'Replicator', RC: 'Restricted', SA: 'Schema Admins',
  SO: 'Server Operators', SU: 'Service', AU: 'Authenticated Users', ER: 'Event Log Readers', CN: 'Cloneable Domain Controllers', RO: 'Enterprise Read-only Domain Controllers', AN: 'Anonymous' };
const WELL_KNOWN_SID = { 'S-1-1-0': 'Everyone', 'S-1-5-11': 'Authenticated Users', 'S-1-5-18': 'SYSTEM', 'S-1-5-10': 'SELF', 'S-1-3-0': 'Creator Owner', 'S-1-5-7': 'Anonymous',
  'S-1-5-32-544': 'Administrators', 'S-1-5-32-545': 'Users', 'S-1-5-32-548': 'Account Operators', 'S-1-5-32-549': 'Server Operators', 'S-1-5-32-550': 'Print Operators',
  'S-1-5-32-551': 'Backup Operators', 'S-1-5-9': 'Enterprise Domain Controllers', 'S-1-5-32-554': 'Pre-Windows 2000 Compatible Access' };
const RID_NAME = { 500: 'Administrator', 502: 'krbtgt', 512: 'Domain Admins', 513: 'Domain Users', 515: 'Domain Computers', 516: 'Domain Controllers', 518: 'Schema Admins',
  519: 'Enterprise Admins', 520: 'Group Policy Creator Owners', 521: 'Read-only Domain Controllers', 526: 'Key Admins', 527: 'Enterprise Key Admins', 498: 'Enterprise Read-only Domain Controllers' };
const ADMIN_TRUSTEE = new Set(['Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators', 'SYSTEM', 'Domain Controllers', 'Enterprise Domain Controllers', 'Administrator',
  'Key Admins', 'Enterprise Key Admins', 'Creator Owner', 'SELF', 'Enterprise Read-only Domain Controllers', 'Read-only Domain Controllers']);
const ACE_TYPE = { A: 'Allow', D: 'Deny', OA: 'Allow (object)', OD: 'Deny (object)', AU: 'Audit', OU: 'Audit (object)', AL: 'Alarm', ML: 'Mandatory label', XA: 'Allow (callback)', XD: 'Deny (callback)' };
const RIGHTS = { GA: 'Full control', GR: 'Read', GW: 'Write', GX: 'Execute', RC: 'Read permissions', SD: 'Delete', WD: 'Change permissions', WO: 'Take ownership', RP: 'Read property',
  WP: 'Write property', CC: 'Create child', DC: 'Delete child', LC: 'List children', SW: 'Validated write', LO: 'List object', DT: 'Delete tree', CR: 'Extended right' };
const DANGEROUS_RIGHTS = new Set(['GA', 'GW', 'WD', 'WO']);
// schemaIDGUID / rightsGUID names (the ones attackers use, and the common ones) - others stay as the GUID
const OBJ_GUID = { '00299570-246d-11d0-a768-00aa006e0529': 'Reset password', '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2': 'Replicating Directory Changes',
  '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2': 'Replicating Directory Changes All', '89e95b76-444d-4c62-991a-0facbeda640c': 'Replicating Directory Changes In Filtered Set',
  'bf9679c0-0de6-11d0-a285-00aa003049e2': 'member', 'f3a64788-5306-11d1-a9c5-0000f80367c1': 'servicePrincipalName', '5b47d60f-6090-40b2-9f37-2a4de88f3063': 'msDS-KeyCredentialLink',
  '3f78c3e5-f79a-46bd-a0b8-9d18116ddc79': 'msDS-AllowedToActOnBehalfOfOtherIdentity', 'f30e3bbe-9ff0-11d1-b603-0000f80367c1': 'gPLink', 'bf967aba-0de6-11d0-a285-00aa003049e2': 'user objects',
  'bf967a86-0de6-11d0-a285-00aa003049e2': 'computer objects', 'bf967a9c-0de6-11d0-a285-00aa003049e2': 'group objects', 'bf967a68-0de6-11d0-a285-00aa003049e2': 'userAccountControl',
  '4c164200-20c0-11d0-a768-00aa006e0529': 'User-Account-Restrictions', 'ab721a53-1e2f-11d0-9819-00aa0040529b': 'Change password', 'bf967950-0de6-11d0-a285-00aa003049e2': 'description' };
const RISKY_OBJ = new Set(['00299570-246d-11d0-a768-00aa006e0529', '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2', '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2', '89e95b76-444d-4c62-991a-0facbeda640c',
  'bf9679c0-0de6-11d0-a285-00aa003049e2', 'f3a64788-5306-11d1-a9c5-0000f80367c1', '5b47d60f-6090-40b2-9f37-2a4de88f3063', '3f78c3e5-f79a-46bd-a0b8-9d18116ddc79', 'f30e3bbe-9ff0-11d1-b603-0000f80367c1']);

function sidName(sid) {
  const v = String(sid || '').trim();
  if (SDDL_SID[v.toUpperCase()]) return SDDL_SID[v.toUpperCase()];
  if (WELL_KNOWN_SID[v.toUpperCase()]) return WELL_KNOWN_SID[v.toUpperCase()];
  const m = /^S-1-5-21-\d+-\d+-\d+-(\d+)$/i.exec(v);
  if (m && RID_NAME[m[1]]) return RID_NAME[m[1]];
  return v;
}
function rightsOf(r) {
  const t = String(r || '').trim();
  if (/^0x[0-9a-f]+$/i.test(t)) return { codes: [t.toLowerCase()], text: 'access mask ' + t.toLowerCase() };
  const codes = t.match(/[A-Z]{2}/g) || [];
  return { codes, text: codes.map((c) => RIGHTS[c] || c).join(', ') };
}
// "O:DAG:DAD:PAI(A;;RP;;;AU)(OA;CI;CR;guid;;S-1-…)S:AI(…)" → {owner, group, dacl_flags, dacl[], sacl_flags, sacl[]}
function parseSddl(text) {
  const t = String(text || '').trim(), out = { owner: '', group: '', dacl_flags: '', dacl: [], sacl_flags: '', sacl: [], valid: false };
  if (!/^(O:|G:|D:|S:)/.test(t)) return out;
  const sec = []; let depth = 0, cur = null;
  for (let i = 0; i < t.length; i++) {
    const c = t[i];
    if (c === '(') depth++;
    else if (c === ')') depth--;
    // a new section starts at "O:" / "G:" / "D:" / "S:" outside parentheses (SIDs, aliases and flags never contain ':')
    if (!depth && t[i + 1] === ':' && /[OGDS]/.test(c)) { cur = { k: c, v: '' }; sec.push(cur); i++; continue; }
    if (cur) cur.v += c;
  }
  for (const x of sec) {
    if (x.k === 'O') out.owner = x.v.trim();
    else if (x.k === 'G') out.group = x.v.trim();
    else {
      const flags = /^[^(]*/.exec(x.v)[0];
      const aces = [...x.v.matchAll(/\(([^()]*)\)/g)].map((m) => m[1]);
      if (x.k === 'D') { out.dacl_flags = flags; out.dacl = aces; } else { out.sacl_flags = flags; out.sacl = aces; }
    }
  }
  out.valid = !!(out.owner || out.group || out.dacl.length || out.sacl.length);
  return out;
}
function describeAce(ace) {
  const p = String(ace).split(';');
  const type = (p[0] || '').toUpperCase(), r = rightsOf(p[2]), obj = (p[3] || '').toLowerCase(), inh = (p[4] || '').toLowerCase(), who = sidName(p[5]);
  const flags = (p[1] || '').toUpperCase();
  const scope = /IO/.test(flags) ? ' (inherited by child objects only)' : /CI/.test(flags) ? ' (this object and children)' : '';
  const on = obj ? ' - ' + (OBJ_GUID[obj] || obj) : '';
  const forCls = inh ? ' on ' + (OBJ_GUID[inh] || inh) : '';
  const allow = type === 'A' || type === 'OA' || type === 'XA';
  const risky = allow && !ADMIN_TRUSTEE.has(who) && (r.codes.some((c) => DANGEROUS_RIGHTS.has(c)) || (obj && RISKY_OBJ.has(obj) && r.codes.some((c) => c === 'CR' || c === 'WP' || c === 'SW')) || (r.codes.includes('WP') && !obj));
  return { ace: String(ace), type: ACE_TYPE[type] || type, trustee: who, sid: p[5] || '', rights: r.text, object: obj ? (OBJ_GUID[obj] || obj) : '', inherited: /ID/.test(flags), risky,
    text: `${ACE_TYPE[type] || type} ${who}: ${r.text || '?'}${on}${forCls}${scope}` };
}
function multiset(list) { const m = new Map(); for (const x of list) m.set(x.toUpperCase(), (m.get(x.toUpperCase()) || 0) + 1); return m; }
function diffSddl(oldText, newText) {
  const a = parseSddl(oldText), b = parseSddl(newText);
  const ma = multiset(a.dacl), mb = multiset(b.dacl), added = [], removed = [];
  for (const ace of b.dacl) { const k = ace.toUpperCase(); if ((ma.get(k) || 0) > 0) ma.set(k, ma.get(k) - 1); else added.push(describeAce(ace)); }
  for (const ace of a.dacl) { const k = ace.toUpperCase(); if ((mb.get(k) || 0) > 0) mb.set(k, mb.get(k) - 1); else removed.push(describeAce(ace)); }
  const out = { parsed: a.valid && b.valid, owner_old: sidName(a.owner), owner_new: sidName(b.owner), owner_changed: !!(a.owner && b.owner && a.owner !== b.owner),
    inheritance_old: /P/.test(a.dacl_flags) ? 'blocked' : 'inherits', inheritance_new: /P/.test(b.dacl_flags) ? 'blocked' : 'inherits',
    added: added.filter((x) => !x.inherited), removed: removed.filter((x) => !x.inherited), inherited_changes: added.filter((x) => x.inherited).length + removed.filter((x) => x.inherited).length };
  out.inheritance_changed = a.valid && b.valid && out.inheritance_old !== out.inheritance_new;
  out.risky = out.added.filter((x) => x.risky).map((x) => x.text);
  return out;
}

// ---------------------------------------------------------------- pairing + description
const lc = (v) => String(v == null ? '' : v).toLowerCase();
function evTs(e) { const t = e.ts; if (typeof t === 'number') return t; const n = Date.parse(String(t).replace(' ', 'T') + (/[zZ]|[+-]\d\d:?\d\d$/.test(String(t)) ? '' : 'Z')); return Number.isFinite(n) ? n : 0; }
const OPS = { 5137: 'created', 5138: 'undeleted', 5139: 'moved', 5141: 'deleted', 4662: 'access' };
function pairChanges(events) {
  const groups = new Map(), out = [], seen = new Set();
  for (const e of events || []) {
    const f = e.fields || {}, code = String(e.event_code || '');
    const rid = f.record_id ? e.host + '|' + f.record_id : '';
    if (rid) { if (seen.has(rid)) continue; seen.add(rid); }   // the same record collected twice (agent + WEF)
    const ts = evTs(e);
    if (code === '5136') {
      const obj = f.ad_object_guid || lc(f.ad_object_dn), corr = f.ad_correlation_id && !/^0{8}-/.test(f.ad_correlation_id) ? f.ad_correlation_id : 't' + Math.floor(ts / 1000);
      const key = [lc(e.host), corr, obj, lc(f.ad_attribute)].join('|');
      let g = groups.get(key);
      if (!g) { g = { events: [], ts: 0, first: Infinity }; groups.set(key, g); }
      g.events.push(e); g.ts = Math.max(g.ts, ts); g.first = Math.min(g.first, ts);
    } else if (OPS[code]) {
      if (code === '4662' && !(f.ad_kind === 'acl' || f.ad_dcsync === '1')) continue;
      out.push(base(e, ts, OPS[code]));
    }
  }
  for (const g of groups.values()) {
    const add = g.events.find((x) => (x.fields || {}).ad_op !== 'value-deleted') || g.events[0];
    const c = base(add, g.ts, 'modified');
    const seenV = new Set();
    for (const x of g.events) {
      const v = String((x.fields || {}).ad_value || ''), op = (x.fields || {}).ad_op === 'value-deleted' ? 'old' : 'new';
      if (seenV.has(op + v)) continue; seenV.add(op + v);
      (op === 'old' ? c.old_values : c.new_values).push(v);
      if (op === 'old' && (x.fields || {}).dns_record_type) c.dns_old.push({ type: x.fields.dns_record_type, data: x.fields.dns_record_data || '', ttl: x.fields.dns_ttl || '' });
      if (op === 'new' && (x.fields || {}).dns_record_type) c.dns_new.push({ type: x.fields.dns_record_type, data: x.fields.dns_record_data || '', ttl: x.fields.dns_ttl || '' });
    }
    c.severity = Math.max(...g.events.map((x) => Number(x.severity) || 0));
    c.event_ids = g.events.map((x) => x.id).filter(Boolean).slice(0, 20);
    out.push(c);
  }
  out.sort((a, b) => b.ts - a.ts);
  return out.map(describe);
}
function base(e, ts, op) {
  const f = e.fields || {};
  return { id: e.id || '', ts, at: new Date(ts).toISOString(), dc: e.host || '', event_code: String(e.event_code || ''), op, kind: f.ad_kind || (op === 'access' ? 'access' : 'object'),
    object_class: f.ad_object_class || '', object_type: f.ad_object_type || '', object_dn: f.ad_object_dn || f.ad_new_dn || '', object_name: f.ad_object_name || '', object_guid: f.ad_object_guid || '',
    attribute: f.ad_attribute || '', who: e.user || '', who_domain: e.domain || '', correlation_id: f.ad_correlation_id || '', privileged_object: f.ad_privileged_object === '1',
    old_dn: f.ad_old_dn || '', new_dn: f.ad_new_dn || '', tree_delete: f.ad_tree_delete === '1', gpo_guid: f.gpo_guid || '', dns_zone: f.dns_zone || '', dns_record: f.dns_record || '',
    access: f.ad_access || '', dcsync: f.ad_dcsync === '1', old_values: [], new_values: [], dns_old: [], dns_new: [], severity: Number(e.severity) || 0, event_ids: e.id ? [e.id] : [] };
}
function uacFlags(v) { const n = Number(v); return Number.isFinite(n) ? UAC_FLAGS.filter(([b]) => (n & b) === b).map(([, k]) => k) : []; }
function cseNames(v) { return [...new Set((String(v || '').match(/\{[0-9A-F-]{36}\}/gi) || []).map((g) => g.slice(1, -1).toUpperCase()))].map((g) => CSE[g] || g); }
const trim = (v, n) => { const t = String(v == null ? '' : v); return t.length > n ? t.slice(0, n) + '…' : t; };
function describe(c) {
  const a = lc(c.attribute), personal = PERSONAL_ATTR.has(a);
  const out = Object.assign({}, c, { old: personal ? '' : c.old_values.join('; '), new: personal ? '' : c.new_values.join('; '), masked: personal, detail: null });
  if (personal) { out.old_values = c.old_values.length ? ['(personal data - value not shown)'] : []; out.new_values = c.new_values.length ? ['(personal data - value not shown)'] : []; }
  const nm = c.object_name || c.object_dn || c.object_guid || '?';
  if (c.op === 'access') {
    out.summary = c.dcsync ? `${c.who} used directory replication rights (DCSync) on ${c.object_class || 'the domain'}` : `${c.who}: ${c.access} on ${c.object_class || 'object'} ${c.object_guid}`;
    out.detail = { access: c.access };
  } else if (c.op !== 'modified') {
    const verb = { created: 'created', undeleted: 'restored from the recycle bin', moved: 'moved', deleted: c.tree_delete ? 'deleted (with everything under it)' : 'deleted' }[c.op];
    out.summary = `${c.object_type || 'object'} ${nm} ${verb}${c.op === 'moved' ? ': ' + c.old_dn + ' → ' + c.new_dn : ''}`;
    if (c.kind === 'gpo') out.detail = { gpo: { guid: c.gpo_guid, setting_level: 'Setting-level contents come from the GPO report snapshots (Policy changes).' } };
  } else if (c.kind === 'acl') {
    const d = diffSddl(c.old_values[0] || '', c.new_values[0] || '');
    out.detail = { acl: Object.assign({ sddl_old: c.old_values[0] || '', sddl_new: c.new_values[0] || '' }, d) };
    if (!c.old_values.length) out.detail.acl.note = 'Only the new descriptor was logged (no "Value Deleted" half in the period): ACEs listed as added are the whole new DACL.';
    out.summary = `Permissions on ${nm}: ${d.added.length} entr${d.added.length === 1 ? 'y' : 'ies'} added, ${d.removed.length} removed${d.owner_changed ? ', owner ' + d.owner_old + ' → ' + d.owner_new : ''}${d.inheritance_changed ? ', inheritance ' + d.inheritance_new : ''}${d.risky.length ? ' - RISKY: ' + d.risky.join('; ') : ''}`;
    if (d.risky.length) out.severity = Math.max(out.severity, 3);
    out.old = trim(out.old, 4000); out.new = trim(out.new, 4000);
  } else if (c.kind === 'gpo-link') {
    const o = new Map(W.parseGpLink(c.old_values.join('')).map((l) => [l.guid, l.flag])), n = new Map(W.parseGpLink(c.new_values.join('')).map((l) => [l.guid, l.flag]));
    const linked = [...n.keys()].filter((g) => !o.has(g)), unlinked = [...o.keys()].filter((g) => !n.has(g)), changed = [...n.keys()].filter((g) => o.has(g) && o.get(g) !== n.get(g)).map((g) => ({ guid: g, old: GPLINK_FLAG[o.get(g)] || String(o.get(g)), new: GPLINK_FLAG[n.get(g)] || String(n.get(g)) }));
    out.detail = { gpo_link: { linked: linked.map((g) => ({ guid: g, state: GPLINK_FLAG[n.get(g)] || String(n.get(g)) })), unlinked, changed, target: c.object_dn } };
    out.summary = `GPO links on ${nm}: ${[linked.length ? linked.length + ' linked' : '', unlinked.length ? unlinked.length + ' unlinked' : '', changed.length ? changed.map((x) => x.guid + ' ' + x.old + ' → ' + x.new).join(', ') : ''].filter(Boolean).join(', ') || 'order or options changed'}`;
  } else if (c.kind === 'gpo') {
    const g = { guid: c.gpo_guid, attribute: c.attribute, setting_level: 'This is the GPO object in AD. Which SETTING changed (old → new) needs the GPO report: see Policy changes → GPO setting changes.' };
    if (a === 'versionnumber') { const v = (x) => { const n = Number(x); return Number.isFinite(n) ? { user: n >>> 16, computer: n & 0xffff } : null; }; g.version_old = v(c.old_values[0]); g.version_new = v(c.new_values[0]);
      g.changed_side = g.version_old && g.version_new ? [g.version_new.computer !== g.version_old.computer ? 'computer' : '', g.version_new.user !== g.version_old.user ? 'user' : ''].filter(Boolean).join(' + ') || 'none' : ''; }
    if (/^gpc(machine|user)extensionnames$/.test(a)) { const o = cseNames(c.old_values.join('')), n = cseNames(c.new_values.join('')); g.extensions_added = n.filter((x) => !o.includes(x)); g.extensions_removed = o.filter((x) => !n.includes(x)); }
    out.detail = { gpo: g };
    out.summary = `GPO ${c.gpo_guid || nm}: ${c.attribute}${g.changed_side ? ' (' + g.changed_side + ' settings edited)' : ''}${g.extensions_added && g.extensions_added.length ? ' +' + g.extensions_added.join(', ') : ''}${g.extensions_removed && g.extensions_removed.length ? ' -' + g.extensions_removed.join(', ') : ''}`;
  } else if (c.kind === 'dns') {
    out.detail = { dns: { zone: c.dns_zone, record: c.dns_record, old: c.dns_old, new: c.dns_new } };
    const fmt = (l) => l.map((r) => r.type + ' ' + r.data).join(', ');
    out.summary = `DNS ${c.dns_record ? c.dns_record + '.' : ''}${c.dns_zone}: ${a === 'dnsrecord' ? (fmt(c.dns_old) || '(none)') + ' → ' + (fmt(c.dns_new) || '(removed)') : c.attribute + ' changed'}`;
  } else if (c.kind === 'schema') {
    out.summary = `Schema ${c.object_type} ${nm}: ${c.attribute} ${trim(out.old, 120) || '(empty)'} → ${trim(out.new, 120) || '(empty)'}`;
  } else {
    if (a === 'useraccountcontrol') {
      const o = uacFlags(c.old_values[0]), n = uacFlags(c.new_values[0]), set = n.filter((x) => !o.includes(x)), cleared = o.filter((x) => !n.includes(x));
      out.detail = { uac: { set, cleared, risky_set: set.filter((x) => UAC_RISKY.has(x)) } };
      if (out.detail.uac.risky_set.length) out.severity = Math.max(out.severity, 2);
      out.summary = `${c.object_type} ${nm}: userAccountControl ${set.length ? '+' + set.join(' +') : ''}${cleared.length ? ' -' + cleared.join(' -') : ''}`.trim();
    } else out.summary = personal ? `${c.object_type} ${nm}: ${c.attribute} changed (personal data - value not shown)` : `${c.object_type} ${nm}: ${c.attribute} ${trim(out.old, 120) || '(empty)'} → ${trim(out.new, 120) || '(empty)'}`;
  }
  out.old = trim(out.old, 8000); out.new = trim(out.new, 8000);
  delete out.dns_old; delete out.dns_new;
  return out;
}

// ---------------------------------------------------------------- lockout analyzer
const acct = (v) => lc(v).replace(/^.*\\/, '').replace(/@.*$/, '').trim();
const comp = (v) => String(v || '').trim().replace(/^\\\\/, '').replace(/\..*$/, '').toUpperCase();
function top(map) { return [...map.entries()].map(([name, count]) => ({ name, count })).sort((a, b) => b.count - a.count || (a.name < b.name ? -1 : 1)); }
function inc(m, k) { if (k) m.set(k, (m.get(k) || 0) + 1); }
/* locks: 4740 events {ts, host, target_user, fields.caller_computer}; fails: 4625 / 4771 / 4776 failure events.
   Each lockout looks back windowMs (default 30 min) and 1 minute after (clock skew between DCs) for the same account. */
function analyzeLockouts(locks, fails, { windowMs = 30 * 60000 } = {}) {
  const byAcct = new Map();
  for (const f of fails || []) { const k = acct(f.user); if (!k) continue; if (!byAcct.has(k)) byAcct.set(k, []); byAcct.get(k).push(Object.assign({}, f, { _ts: evTs(f) })); }
  return (locks || []).map((l) => {
    const ts = evTs(l), account = acct(l.target_user || (l.fields || {}).TargetUserName), caller = comp((l.fields || {}).caller_computer);
    const ev = (byAcct.get(account) || []).filter((f) => f._ts >= ts - windowMs && f._ts <= ts + 60000);
    const counts = { '4625': 0, '4771': 0, '4776': 0 }, computers = new Map(), ips = new Map(), procs = new Map(), types = new Map(), servers = new Map(), reasons = new Map();
    for (const f of ev) {
      const x = f.fields || {}, code = String(f.event_code);
      if (counts[code] !== undefined) counts[code]++;
      if (code === '4625' || code === '4776') inc(computers, comp(x.workstation));
      if (code === '4625' || code === '4771') inc(ips, f.src_ip && f.src_ip !== '::1' && f.src_ip !== '127.0.0.1' ? f.src_ip : '');
      if (code === '4625') { inc(procs, String(f.process || '').split('\\').pop().toLowerCase()); inc(types, x.logon_type_name || (x.logon_type ? 'type ' + x.logon_type : '')); inc(servers, String(f.host || '').toLowerCase()); }
      inc(reasons, x.failure_reason);
    }
    const C = top(computers), I = top(ips), P = top(procs), T = top(types), S = top(servers), total = ev.length;
    let computer = caller || (C[0] && C[0].name) || '', basis = caller ? 'caller computer in the 4740 event' : C[0] ? 'most failed sign-ins named this workstation' : '';
    if (!computer && S[0] && P[0]) { computer = S[0].name.toUpperCase().split('.')[0]; basis = 'the failures were on this server (' + P[0].name + ')'; }
    const corroborated = !!(caller && C.some((c) => c.name === caller));
    let confidence = 'none';
    if (total) confidence = corroborated || (C[0] && C[0].count >= 3 && C[0].count / Math.max(1, C.reduce((s, c) => s + c.count, 0)) >= 0.7) || (caller && I.length === 1) ? 'high' : (caller || C[0] || I[0]) ? 'medium' : 'low';
    else if (caller) confidence = 'low';
    const hints = [];
    if (!total) hints.push('No failed sign-in for this account in the window: is the Security log of every domain controller (and the server named by the caller) collected?');
    if (P.some((p) => /^(w3wp|msexchange|lsass)/.test(p.name)) && S.length) hints.push('Failures on an IIS / Exchange server: often a phone or mail client with an old password (ActiveSync / OWA / EWS).');
    if (T.some((t) => t.name === 'service' || t.name === 'batch')) hints.push('Service / batch logon: a Windows service or scheduled task still uses the old password.');
    if (!caller && counts['4771'] && !counts['4625']) hints.push('Only Kerberos pre-authentication failures: a device with a cached old password (mapped drive, VPN, Wi-Fi profile) - look at the client IP.');
    if (caller && /^(OWA|EXCH|MAIL|CAS|ADFS|RDG|RDS)/.test(caller)) hints.push('The caller is a front-end server: the real client is behind it - see the source IPs.');
    return { ts, at: new Date(ts).toISOString(), account, dc: l.host || '', caller_computer: caller, event_id: l.id || '',
      likely: { computer, ip: (I[0] && I[0].name) || '', process: (P[0] && P[0].name) || '', logon_type: (T[0] && T[0].name) || '', basis, confidence, corroborated },
      evidence: { failures: total, counts, computers: C.slice(0, 10), ips: I.slice(0, 10), processes: P.slice(0, 10), logon_types: T.slice(0, 6), servers: S.slice(0, 10), reasons: top(reasons).slice(0, 6) },
      window_min: Math.round(windowMs / 60000), hints };
  }).sort((a, b) => b.ts - a.ts);
}
function rankLockouts(analyses) {
  const m = new Map();
  for (const a of analyses) {
    const x = m.get(a.account) || { account: a.account, lockouts: 0, first: a.at, last: a.at, sources: new Map(), ips: new Map(), dcs: new Set() };
    x.lockouts++; if (a.at < x.first) x.first = a.at; if (a.at > x.last) x.last = a.at;
    inc(x.sources, a.likely.computer); inc(x.ips, a.likely.ip); if (a.dc) x.dcs.add(a.dc);
    m.set(a.account, x);
  }
  return [...m.values()].map((x) => { const S = top(x.sources), I = top(x.ips); return { account: x.account, lockouts: x.lockouts, repeat: x.lockouts >= 2, first: x.first, last: x.last,
    top_source: S[0] ? S[0].name : '', top_source_count: S[0] ? S[0].count : 0, recurring_source: !!(S[0] && S[0].count >= 2), sources: S.slice(0, 5), ips: I.slice(0, 5), dcs: [...x.dcs].slice(0, 5) }; })
    .sort((a, b) => b.lockouts - a.lockouts || (a.last < b.last ? 1 : -1));
}

// ---------------------------------------------------------------- domain / audit policy
function policyChanges(events) {
  const rows = (events || []).map((e) => ({ e, ts: evTs(e) })).sort((a, b) => a.ts - b.ts), last = new Map(), out = [];
  for (const { e, ts } of rows) {
    const f = e.fields || {}, code = String(e.event_code);
    if (code === '4739') {
      const settings = String(f.policy_changed_settings || '').split(',').filter(Boolean).map((k) => {
        const key = lc(e.host).split('.').slice(1).join('.') + '|' + (f.domain_name || '') + '|' + k, nv = f['policy.' + k] || '', prev = last.get(key);
        last.set(key, nv);
        return { setting: k, old: prev === undefined ? null : prev, new: nv };
      });
      out.push({ ts, at: new Date(ts).toISOString(), type: 'domain-policy', event_code: code, dc: e.host || '', who: e.user || '', policy: f.domain_policy_changed || '', domain: f.domain_name || '', settings,
        note: settings.some((x) => x.old === null) ? '4739 carries only the new value; "old" is the previous 4739 for the same setting in the period, when there is one.' : '', severity: Number(e.severity) || 0 });
    } else if (code === '4719') {
      out.push({ ts, at: new Date(ts).toISOString(), type: 'audit-policy', event_code: code, dc: e.host || '', who: e.user || '', category: f.audit_category || '', subcategory: f.audit_subcategory || '',
        changes: f.audit_changes || '', removed: f.audit_removed === '1', applied_by_gpo: f.applied_by_gpo === '1', severity: Number(e.severity) || 0 });
    }
  }
  return out.sort((a, b) => b.ts - a.ts);
}

// ---------------------------------------------------------------- GPO report (Get-GPOReport -ReportType Xml) → settings
const ENT = { lt: '<', gt: '>', amp: '&', quot: '"', apos: '\'' };
const unEnt = (t) => t.replace(/&(#x[0-9a-f]+|#\d+|lt|gt|amp|quot|apos);/gi, (m, e) => (e[0] === '#' ? String.fromCodePoint(e[1] === 'x' || e[1] === 'X' ? parseInt(e.slice(2), 16) : Number(e.slice(1))) : ENT[e.toLowerCase()]));
// a small, non-validating XML reader (elements + text; namespaces prefixes dropped). Never evaluates entities beyond the five + numeric.
function parseXml(xml) {
  const src = String(xml || '').replace(/^﻿/, ''), root = { name: '#root', children: [], text: '' }, stack = [root];
  const re = /<!--[\s\S]*?-->|<!\[CDATA\[([\s\S]*?)\]\]>|<\?[\s\S]*?\?>|<!DOCTYPE[^>]*>|<\/\s*([^\s>]+)\s*>|<\s*([^\s/>]+)((?:\s+[^\s=/>]+\s*=\s*(?:"[^"]*"|'[^']*'))*)\s*(\/?)>|([^<]+)/gy;
  let m, guard = 0;
  while ((m = re.exec(src)) && ++guard < 2e6) {
    const top = stack[stack.length - 1];
    if (m[1] !== undefined) top.text += m[1];
    else if (m[2]) { const n = m[2].replace(/^.*:/, ''); for (let i = stack.length - 1; i > 0; i--) if (stack[i].name === n) { stack.length = i; break; } }
    else if (m[3]) { const el = { name: m[3].replace(/^.*:/, ''), children: [], text: '' }; top.children.push(el); if (!m[5]) stack.push(el); }
    else if (m[6] !== undefined) top.text += unEnt(m[6]);
  }
  return root.children[0] || null;
}
const kid = (el, n) => (el && el.children.find((c) => c.name === n)) || null;
const txt = (el) => (el ? el.text.trim() : '');
const KEY_CHILDREN = ['Name', 'KeyName', 'ValueName', 'Path', 'Trustee', 'Category', 'SOMPath', 'Key', 'Command', 'Target'];
const NOISE = new Set(['Explain', 'Supported', 'SecurityDescriptor', 'SDDL', 'GPOSettingOrder', 'Filters']);
function leaves(el, prefix, out) {
  for (const c of el.children) {
    if (NOISE.has(c.name)) continue;
    const p = prefix ? prefix + '.' + c.name : c.name;
    if (c.children.length) leaves(c, p, out); else if (txt(c)) out.push(p + '=' + txt(c));
  }
  return out;
}
function settingKey(el) {
  const parts = [];
  for (const k of KEY_CHILDREN) { const c = kid(el, k); if (!c) continue; const v = c.children.length ? leaves(c, '', []).join(',') : txt(c); if (v) parts.push(v); if (parts.length >= 2) break; }
  return parts.join(' / ');
}
function flattenGpoReport(xml) {
  const r = parseXml(xml);
  if (!r || r.name !== 'GPO') return { ok: false, error: 'not a GPO report (Get-GPOReport -ReportType Xml)', settings: {} };
  const settings = {};
  const put = (k, v) => { let key = k, i = 2; while (settings[key] !== undefined && settings[key] !== v) key = k + ' #' + i++; settings[key] = v; };
  put('GPO / Name', txt(kid(r, 'Name')));
  for (const side of ['Computer', 'User']) {
    const s = kid(r, side); if (!s) continue;
    put(side + ' / Enabled', txt(kid(s, 'Enabled')));
    for (const ed of s.children.filter((c) => c.name === 'ExtensionData')) {
      const ext = kid(ed, 'Extension'), extName = txt(kid(ed, 'Name')) || 'Extension';
      if (!ext) continue;
      for (const st of ext.children) {
        const k = settingKey(st), vals = leaves(st, '', []).filter((l) => !KEY_CHILDREN.some((kc) => l.startsWith(kc + '=') && k.includes(l.slice(kc.length + 1))));
        put(`${side} / ${extName} / ${st.name}${k ? ' [' + k + ']' : ''}`, (st.children.length ? vals.join('; ') : txt(st)).slice(0, 4000));
      }
    }
  }
  for (const l of r.children.filter((c) => c.name === 'LinksTo')) put(`Links / ${txt(kid(l, 'SOMPath')) || txt(kid(l, 'SOMName'))}`, `Enabled=${txt(kid(l, 'Enabled'))}; NoOverride=${txt(kid(l, 'NoOverride'))}`);
  const sd = kid(r, 'SecurityDescriptor'), perms = sd && kid(sd, 'Permissions');
  if (perms) for (const tp of perms.children.filter((c) => c.name === 'TrusteePermissions')) put(`Delegation / ${leaves(kid(tp, 'Trustee') || { children: [] }, '', []).filter((x) => /Name=/.test(x)).map((x) => x.split('=').slice(1).join('=')).join(',') || '?'}`, leaves(tp, '', []).filter((x) => !/^Trustee\./.test(x)).join('; ').slice(0, 2000));
  const id = kid(r, 'Identifier');
  return { ok: true, name: txt(kid(r, 'Name')), guid: W.gpoGuidOf(id ? leaves(id, '', []).join(' ') : ''), modified: txt(kid(r, 'ModifiedTime')), settings };
}
function diffGpoSettings(a, b) {
  const A = (a && a.settings) || {}, B = (b && b.settings) || {}, out = [];
  for (const k of Object.keys(B)) if (!(k in A)) out.push({ setting: k, change: 'added', old: null, new: B[k] }); else if (A[k] !== B[k]) out.push({ setting: k, change: 'changed', old: A[k], new: B[k] });
  for (const k of Object.keys(A)) if (!(k in B)) out.push({ setting: k, change: 'removed', old: A[k], new: null });
  return out.sort((x, y) => (x.setting < y.setting ? -1 : 1));
}

// ---------------------------------------------------------------- the store half
function createAdChanges({ ch, state, config, log, sysadmin, now = Date.now, table = 'siem.events' } = {}) {
  const L = log || { info() {}, warn() {}, every() {} };
  const ok = () => ch && typeof ch.query === 'function';
  const cfg = () => (config && config.ad_changes) || {};
  const snaps = state ? state.collection('ad_gpo_snapshots') : null;
  const meta = state ? state.collection('ad_changes_meta') : null;
  const NA = { available: false, reason: 'the event store (ClickHouse) is not available' };
  const range = (q) => { const h = Math.min(24 * 90, Math.max(1, Number(q.hours) || 168)); return { h }; };
  const q2 = (sql, params, ms) => ch.query(sql, params, { readonly: true, timeout_ms: ms || 30000 });

  async function rawChanges(h) {
    const r = await q2(`/* adchanges:rows */ SELECT id, ts, host, event_code, user, domain, target_user, severity, fields FROM ${table}
      WHERE src_type = 'windows' AND event_code IN ('5136','5137','5138','5139','5141','4662') AND ts >= now() - INTERVAL {h:UInt32} HOUR
        AND (event_code != '4662' OR fields['ad_kind'] = 'acl' OR fields['ad_dcsync'] = '1')
      ORDER BY ts DESC LIMIT ${MAX_ROWS + 1}`, { h: { type: 'UInt32', value: h } });
    return { rows: r.slice(0, MAX_ROWS), capped: r.length > MAX_ROWS };
  }
  function gpoNames(list) {
    const m = new Map();
    for (const s of snaps ? snaps.all() : []) if (s.name && (!m.has(s.guid) || m.get(s.guid).at < s.at)) m.set(s.guid, { name: s.name, at: s.at });
    for (const c of list) if (c.kind === 'gpo' && lc(c.attribute) === 'displayname' && c.new_values[0] && c.gpo_guid) m.set(c.gpo_guid, { name: c.new_values[0], at: c.at });
    return m;
  }
  async function changes(q = {}) {
    if (!ok()) return Object.assign({ items: [] }, NA);
    const { h } = range(q), { rows, capped } = await rawChanges(h);
    let list = pairChanges(rows);
    const names = gpoNames(list);
    for (const c of list) if (c.gpo_guid && names.has(c.gpo_guid)) c.gpo_name = names.get(c.gpo_guid).name;
    const counts = { total: list.length, acl: 0, gpo: 0, 'gpo-link': 0, dns: 0, schema: 0, attribute: 0, object: 0, access: 0, privileged: 0, risky: 0 };
    for (const c of list) { counts[c.kind] = (counts[c.kind] || 0) + 1; if (c.privileged_object) counts.privileged++; if (c.detail && ((c.detail.acl && c.detail.acl.risky.length) || (c.detail.uac && c.detail.uac.risky_set.length))) counts.risky++; }
    const classes = top(list.reduce((m, c) => { inc(m, c.object_class); return m; }, new Map())).slice(0, 40);
    if (q.kind) list = list.filter((c) => (q.kind === 'gpo' ? c.kind === 'gpo' || c.kind === 'gpo-link' : c.kind === q.kind));
    if (q.object_class) list = list.filter((c) => lc(c.object_class) === lc(q.object_class) || lc(c.object_type) === lc(q.object_class));
    if (q.who) list = list.filter((c) => lc(c.who).includes(lc(q.who)));
    if (q.privileged) list = list.filter((c) => c.privileged_object);
    if (q.risky) list = list.filter((c) => c.detail && ((c.detail.acl && c.detail.acl.risky.length) || (c.detail.uac && c.detail.uac.risky_set.length)));
    if (q.q) { const t = lc(q.q); list = list.filter((c) => [c.object_dn, c.object_name, c.attribute, c.summary, c.old, c.new, c.gpo_name || '', c.who].join(' ').toLowerCase().includes(t)); }
    const lim = Math.min(5000, Math.max(1, Number(q.limit) || 500));
    return { available: true, hours: h, capped, counts, classes, total: list.length, items: list.slice(0, lim),
      note: 'Needs "Audit Directory Service Changes" on the domain controllers and auditing entries (SACL) on the objects / DNS partitions to watch; 4662 is not in the default WEF subscription.' };
  }
  async function lockouts(q = {}) {
    if (!ok()) return Object.assign({ items: [], ranking: [] }, NA);
    const { h } = range(q), win = Math.min(240, Math.max(5, Number(q.window_min) || 30)), account = acct(q.account || '');
    const locks = await q2(`/* adchanges:lockouts */ SELECT id, ts, host, target_user, fields FROM ${table}
      WHERE src_type = 'windows' AND event_code = '4740' AND ts >= now() - INTERVAL {h:UInt32} HOUR AND (empty({a:String}) OR lower(target_user) = {a:String})
      ORDER BY ts DESC LIMIT 5000`, { h: { type: 'UInt32', value: h }, a: { type: 'String', value: account } });
    const users = [...new Set(locks.map((l) => acct(l.target_user)).filter(Boolean))];
    const fails = users.length ? await q2(`/* adchanges:failures */ SELECT ts, host, event_code, user, src_ip, process, fields FROM ${table}
      WHERE src_type = 'windows' AND event_code IN ('4625','4771','4776') AND outcome = 'failure' AND ts >= now() - INTERVAL {hw:UInt32} MINUTE
        AND has({u:Array(String)}, lower(user))
      LIMIT 200000`, { hw: { type: 'UInt32', value: h * 60 + win }, u: { type: 'Array(String)', value: users } }, 60000) : [];
    const items = analyzeLockouts(locks, fails, { windowMs: win * 60000 });
    return { available: true, hours: h, window_min: win, account: account || null, total: items.length, capped: locks.length >= 5000, items: items.slice(0, account ? 500 : 1000), ranking: rankLockouts(items) };
  }
  async function policy(q = {}) {
    if (!ok()) return Object.assign({ items: [], gpo_changes: [], gpo_snapshots: [] }, NA);
    const { h } = range(q);
    const ev = await q2(`/* adchanges:policy */ SELECT ts, host, event_code, user, severity, fields FROM ${table}
      WHERE src_type = 'windows' AND event_code IN ('4739','4719') AND ts >= now() - INTERVAL {h:UInt32} HOUR ORDER BY ts DESC LIMIT 5000`, { h: { type: 'UInt32', value: h } });
    const ch2 = await changes({ hours: h, kind: 'gpo', limit: 2000 });
    const since = now() - h * 3600000;
    return { available: true, hours: h, items: policyChanges(ev), gpo_changes: ch2.items || [], gpo_snapshots: listSnapshots().filter((s) => Date.parse(s.at) >= since || s.diff_count === null).slice(0, 300),
      snapshot: status() };
  }

  // GPO setting-level snapshots (read-only Get-GPOReport through the AI Server Administrators' WinRM runner, check gpo_report)
  function server() { const S = typeof sysadmin === 'function' ? sysadmin() : sysadmin; return S && S.runner ? S : null; }
  function status() {
    const S = server(), srv = cfg().gpo_server || '';
    return { enabled: cfg().gpo_snapshots !== false, server: srv || null, runner: !!S,
      reason: !S ? 'the Windows server checks (AI Server Administrators) are not running' : !srv ? 'no GPO report server set: an administrator sets ad_changes.gpo_server to a domain controller from the Windows server list' : '' };
  }
  function listSnapshots(guid) {
    const all = snaps ? snaps.all((s) => !guid || s.guid === W.gpoGuidOf(guid)) : [];
    return all.sort((a, b) => (b.seq || 0) - (a.seq || 0) || (a.at < b.at ? 1 : -1)).map((s) => ({ id: s.id, seq: s.seq || 0, guid: s.guid, name: s.name, at: s.at, by: s.by, via: s.via, settings: Object.keys(s.settings || {}).length, previous: s.previous || null, diff_count: s.diff ? s.diff.length : null }));
  }
  function getSnapshot(id) { return snaps ? snaps.get(id) : null; }
  function store(guid, rep, by, via) {
    const flat = flattenGpoReport(rep.xml);
    if (!flat.ok) throw Object.assign(new Error(`GPO ${guid}: ${flat.error}`), { code: 502 });
    const g = W.gpoGuidOf(guid || flat.guid || rep.guid);
    const prev = listSnapshots(g)[0], prevDoc = prev ? getSnapshot(prev.id) : null;
    const diff = prevDoc ? diffGpoSettings(prevDoc, flat) : null;
    if (prevDoc && !diff.length) return { id: prevDoc.id, guid: g, name: flat.name, unchanged: true, at: prevDoc.at, diff: [] };
    const seq = (prev ? prev.seq : 0) + 1;
    const doc = { id: 'gpo-' + g.toLowerCase() + '-' + seq, seq, guid: g, name: flat.name || rep.name || '', at: new Date(now()).toISOString(), modified: rep.modified || flat.modified || '',
      by: by || '', via: via || 'manual', settings: flat.settings, previous: prevDoc ? prevDoc.id : null, diff };
    snaps.put(doc);
    const mine = snaps.all((s) => s.guid === g).sort((a, b) => (b.seq || 0) - (a.seq || 0));
    for (const old of mine.slice(cfg().gpo_keep || 20)) snaps.remove(old.id);
    return { id: doc.id, guid: g, name: doc.name, at: doc.at, previous: doc.previous, diff: diff || [], first: !prevDoc };
  }
  async function snapshot(guid, { by, via, serverRef } = {}) {
    const S = server(), ref = serverRef || cfg().gpo_server;
    if (!S) throw Object.assign(new Error('the Windows server checks are not running on this SIEM'), { code: 503 });
    if (!ref) throw Object.assign(new Error('no GPO report server: choose a domain controller (server) or set ad_changes.gpo_server'), { code: 409 });
    if (!snaps) throw Object.assign(new Error('state store not available'), { code: 503 });
    const r = await S.runner.run(ref, 'gpo_report', { guid: guid || '', hours: 24 }, { by, via: via || 'portal' });
    const d = r.data || {};
    if (d.available === false) throw Object.assign(new Error(d.reason || 'Get-GPOReport is not available on ' + r.server), { code: 409 });
    const reps = Array.isArray(d.reports) ? d.reports : d.reports ? [d.reports] : [];
    if (!reps.length) throw Object.assign(new Error(guid ? `GPO ${guid} not found on ${r.server}` : 'no GPO changed in the last 24 hours'), { code: 404 });
    return { server: r.server, snapshots: reps.slice(0, 25).map((x) => store(x.guid || guid, x, by, via)) };
  }
  // background: snapshot each GPO whose AD object changed since the last round (opt-in through gpo_server)
  async function autoRound() {
    const st = status();
    if (!st.enabled || st.reason || !ok()) return { skipped: st.reason || 'off' };
    const m = (meta && meta.get('cursor')) || { id: 'cursor', ts: now() - 3600000 };
    const rows = await q2(`/* adchanges:gpo-cursor */ SELECT fields['gpo_guid'] AS g, max(ts) AS t FROM ${table}
      WHERE src_type = 'windows' AND event_code IN ('5136','5137') AND fields['ad_kind'] = 'gpo' AND fields['gpo_guid'] != '' AND ts > fromUnixTimestamp64Milli({c:Int64})
      GROUP BY g ORDER BY t LIMIT 10`, { c: { type: 'Int64', value: m.ts } });
    const done = [];
    for (const r of rows) {
      try { const x = await snapshot(r.g, { by: 'ad-changes (automatic)', via: 'auto' }); done.push({ guid: r.g, ok: true, changes: x.snapshots.reduce((s, y) => s + (y.diff || []).length, 0) }); }
      catch (e) { done.push({ guid: r.g, ok: false, error: e.message }); L.every('adchanges-gpo-' + r.g, 3600000, 'warn', 'GPO report snapshot failed', { guid: r.g, err: e.message }); }
    }
    const last = rows.length ? Math.max(...rows.map((r) => evTs({ ts: r.t }))) : m.ts;
    if (meta) meta.put({ id: 'cursor', ts: Math.max(m.ts, last), at: new Date(now()).toISOString(), last_round: done });
    return { done };
  }
  return { changes, lockouts, policy, snapshot, listSnapshots, getSnapshot, status, autoRound, diffSnapshots: (a, b) => diffGpoSettings(getSnapshot(a), getSnapshot(b)) };
}

module.exports = { pairChanges, describe, parseSddl, diffSddl, describeAce, analyzeLockouts, rankLockouts, policyChanges, parseXml, flattenGpoReport, diffGpoSettings, createAdChanges, PERSONAL_ATTR, MAX_ROWS };
