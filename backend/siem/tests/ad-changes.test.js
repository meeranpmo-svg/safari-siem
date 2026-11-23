// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// AD change auditing: Windows 5136-5141 / 4662 / 4739 / 4719 as the agent sends them (SYNTHETIC domain synthetic.test) ->
// parser fields -> one change per LDAP operation (old + new paired by OpCorrelationID) with the kind-specific reading (ACL
// ACEs added / removed, GPO version / extensions / links, DNS record old -> new, schema, userAccountControl), personal-data
// attributes masked; the ad-changes rule pack fires on its positives and not its negatives; the GPO report snapshots
// (read-only check gpo_report) give setting-level old / new; the routes: roles (viewer refused), validation, audit records.
const test = require('node:test');
const assert = require('node:assert/strict');
const W = require('../engine/parse/windows');
const A = require('../engine/soc/adchanges');
const { createDetector, compileRule } = require('../engine/detect/engine');

const T0 = Date.UTC(2026, 10, 10, 9, 0, 0);
let rec = 1000;
const ev = (id, ed, extra) => Object.assign(W.parse(JSON.stringify(Object.assign({ Channel: 'Security', EventID: id, TimeCreated: new Date(T0 + rec * 10).toISOString(), Computer: 'DC01.synthetic.test', RecordId: rec++, EventData: ed }, extra || {}))), { id: 'e' + rec });
const SUBJ = { SubjectUserName: 'adm.syn', SubjectDomainName: 'SYN', SubjectUserSid: 'S-1-5-21-1-2-3-1105' };
const mod = (corr, dn, cls, attr, val, op) => ev(5136, Object.assign({}, SUBJ, { OpCorrelationID: '{' + corr + '}', ObjectDN: dn, ObjectGUID: '{0b0b0b0b-1111-2222-3333-' + corr.slice(-12) + '}', ObjectClass: cls, AttributeLDAPDisplayName: attr, AttributeValue: val, OperationType: op === 'old' ? '%%14675' : '%%14674', DSName: 'synthetic.test' }));
const C = (n) => '00000000-0000-0000-0000-' + String(n).padStart(12, '0');
const DOM = 'DC=synthetic,DC=test';
const GPO = '6AC1786C-016F-11D2-945F-00C04FB984F9';
const dnsHex = (ip) => '0400' + '0100' + '05f0' + '0000' + '01000000' + '00000e10' + '00000000' + '00000000' + ip.split('.').map((x) => Number(x).toString(16).padStart(2, '0')).join('');

const SD_OLD = 'O:DAG:DAD:PAI(A;;GA;;;DA)(A;;RP;;;AU)';
const SD_NEW = 'O:DAG:DAD:PAI(A;;GA;;;DA)(A;;RP;;;AU)(A;;GA;;;S-1-5-21-1-2-3-4242)';
const events = [
  mod(C(1), 'CN=AdminSDHolder,CN=System,' + DOM, 'container', 'nTSecurityDescriptor', SD_OLD, 'old'),
  mod(C(1), 'CN=AdminSDHolder,CN=System,' + DOM, 'container', 'nTSecurityDescriptor', SD_NEW, 'new'),
  mod(C(2), 'CN={' + GPO + '},CN=Policies,CN=System,' + DOM, 'groupPolicyContainer', 'versionNumber', String((3 << 16) | 7), 'old'),
  mod(C(2), 'CN={' + GPO + '},CN=Policies,CN=System,' + DOM, 'groupPolicyContainer', 'versionNumber', String((3 << 16) | 8), 'new'),
  mod(C(3), 'CN={' + GPO + '},CN=Policies,CN=System,' + DOM, 'groupPolicyContainer', 'gPCMachineExtensionNames', '[{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{D02B1F72-3407-48AE-BA88-E8213C6761F1}]', 'old'),
  mod(C(3), 'CN={' + GPO + '},CN=Policies,CN=System,' + DOM, 'groupPolicyContainer', 'gPCMachineExtensionNames', '[{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{D02B1F72-3407-48AE-BA88-E8213C6761F1}][{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]', 'new'),
  mod(C(4), 'OU=Servers,' + DOM, 'organizationalUnit', 'gPLink', '', 'old'),
  mod(C(4), 'OU=Servers,' + DOM, 'organizationalUnit', 'gPLink', '[LDAP://cn={' + GPO + '},cn=policies,cn=system,' + DOM + ';2]', 'new'),
  mod(C(5), 'DC=app01,DC=synthetic.test,CN=MicrosoftDNS,DC=DomainDnsZones,' + DOM, 'dnsNode', 'dnsRecord', dnsHex('10.10.1.20'), 'old'),
  mod(C(5), 'DC=app01,DC=synthetic.test,CN=MicrosoftDNS,DC=DomainDnsZones,' + DOM, 'dnsNode', 'dnsRecord', dnsHex('203.0.113.9'), 'new'),
  mod(C(6), 'CN=ms-Syn-Test-Attr,CN=Schema,CN=Configuration,' + DOM, 'attributeSchema', 'isMemberOfPartialAttributeSet', 'FALSE', 'old'),
  mod(C(6), 'CN=ms-Syn-Test-Attr,CN=Schema,CN=Configuration,' + DOM, 'attributeSchema', 'isMemberOfPartialAttributeSet', 'TRUE', 'new'),
  mod(C(7), 'CN=Finance Synthetic,OU=Staff,' + DOM, 'user', 'userAccountControl', '512', 'old'),
  mod(C(7), 'CN=Finance Synthetic,OU=Staff,' + DOM, 'user', 'userAccountControl', String(512 | 0x400000), 'new'),
  mod(C(8), 'CN=Finance Synthetic,OU=Staff,' + DOM, 'user', 'mobile', '+966500000001', 'old'),
  mod(C(8), 'CN=Finance Synthetic,OU=Staff,' + DOM, 'user', 'mobile', '+966500000002', 'new'),
  mod(C(9), 'CN=Finance Synthetic,OU=Staff,' + DOM, 'user', 'title', 'Analyst', 'old'),
  mod(C(9), 'CN=Finance Synthetic,OU=Staff,' + DOM, 'user', 'title', 'Senior Analyst', 'new'),
  ev(5137, Object.assign({}, SUBJ, { ObjectDN: 'CN={0D0D0D0D-AAAA-BBBB-CCCC-DDDDDDDDDDDD},CN=Policies,CN=System,' + DOM, ObjectClass: 'groupPolicyContainer', ObjectGUID: '{12121212-1111-2222-3333-444444444444}' })),
  ev(5139, Object.assign({}, SUBJ, { OldObjectDN: 'CN=Ops Synthetic,OU=Staff,' + DOM, NewObjectDN: 'CN=Ops Synthetic,OU=Admins,' + DOM, ObjectClass: 'user' })),
  ev(5141, Object.assign({}, SUBJ, { ObjectDN: 'DC=old01,DC=synthetic.test,CN=MicrosoftDNS,DC=DomainDnsZones,' + DOM, ObjectClass: 'dnsNode', TreeDelete: '%%14679' })),
  ev(4662, Object.assign({}, SUBJ, { ObjectServer: 'DS', ObjectType: '%{19195a5b-6da0-11d0-afd3-00c04fd930c9}', ObjectName: '%{9a9a9a9a-1111-2222-3333-444444444444}', AccessList: '%%7688', AccessMask: '0x100', Properties: '%%7688 {1131f6ad-9c07-11d1-f79f-00c04fc2dcd2} {19195a5b-6da0-11d0-afd3-00c04fd930c9}' })),
];

test('parser: 5136/5137/5139/5141/4662 classified (acl, gpo, gpo-link, dns, schema, attribute), DNS record decoded, privileged objects flagged', () => {
  const [acl0, acl1] = events;
  assert.equal(acl1.action, 'ad-object-modified'); assert.equal(acl1.user, 'adm.syn');
  assert.equal(acl1.fields.ad_kind, 'acl'); assert.equal(acl1.fields.ad_op, 'value-added'); assert.equal(acl0.fields.ad_op, 'value-deleted');
  assert.equal(acl1.fields.ad_privileged_object, '1'); assert.equal(acl1.severity, 3); assert.ok(acl1.tags.includes('acl-change') && acl1.tags.includes('T1098'));
  assert.equal(acl1.fields.ad_correlation_id, C(1));
  assert.equal(events[3].fields.ad_kind, 'gpo'); assert.equal(events[3].fields.gpo_guid, GPO);
  assert.equal(events[7].fields.ad_kind, 'gpo-link'); assert.equal(events[7].fields.gpo_links, GPO + ':2');
  assert.equal(events[9].fields.ad_kind, 'dns'); assert.equal(events[9].fields.dns_record, 'app01'); assert.equal(events[9].fields.dns_zone, 'synthetic.test');
  assert.equal(events[9].fields.dns_record_type, 'A'); assert.equal(events[9].fields.dns_record_data, '203.0.113.9'); assert.equal(events[8].fields.dns_record_data, '10.10.1.20');
  assert.equal(events[11].fields.ad_kind, 'schema'); assert.equal(events[11].fields.schema_object, 'ms-Syn-Test-Attr');
  assert.equal(events[13].fields.ad_kind, 'attribute'); assert.equal(events[13].target_user, 'finance synthetic');
  assert.equal(events[18].action, 'ad-object-created'); assert.equal(events[18].fields.ad_kind, 'gpo');
  assert.equal(events[19].action, 'ad-object-moved'); assert.equal(events[19].fields.ad_new_dn, 'CN=Ops Synthetic,OU=Admins,' + DOM);
  assert.equal(events[20].action, 'ad-object-deleted'); assert.equal(events[20].fields.ad_tree_delete, '0'); assert.equal(events[20].fields.dns_record, 'old01');
  assert.equal(events[21].fields.ad_dcsync, '1'); assert.ok(events[21].tags.includes('dcsync')); assert.equal(events[21].fields.ad_object_class, 'domainDNS');
  // a host updating its own DNS record is marked (the DNS rule skips it)
  const self = W.parse(JSON.stringify({ Channel: 'Security', EventID: 5136, Computer: 'DC01', EventData: { SubjectUserName: 'APP01$', ObjectDN: 'DC=app01,DC=synthetic.test,CN=MicrosoftDNS,DC=DomainDnsZones,' + DOM, ObjectClass: 'dnsNode', AttributeLDAPDisplayName: 'dnsRecord', AttributeValue: dnsHex('10.0.0.1'), OperationType: '%%14675' } }));
  assert.equal(self.fields.dns_self_update, '1');
  // 4739 / 4719
  const dp = ev(4739, Object.assign({}, SUBJ, { DomainPolicyChanged: 'Lockout Policy', DomainName: 'SYN', LockoutThreshold: '3', LockoutDuration: '-', MinPasswordLength: '-' }));
  assert.equal(dp.fields.policy_changed_settings, 'LockoutThreshold'); assert.equal(dp.fields['policy.LockoutThreshold'], '3'); assert.ok(dp.tags.includes('domain-policy'));
  const ap = ev(4719, { SubjectUserName: 'DC01$', SubjectDomainName: 'SYN', CategoryId: '%%8279', SubcategoryGuid: '{0CCE923C-69AE-11D9-BED3-505054503030}', AuditPolicyChanges: '%%8448' });
  assert.equal(ap.fields.audit_subcategory, 'Directory Service Changes'); assert.equal(ap.fields.audit_changes, 'Success removed'); assert.equal(ap.fields.audit_removed, '1'); assert.equal(ap.fields.applied_by_gpo, '1');
  // an unrelated event is untouched
  assert.equal(W.parse(JSON.stringify({ Channel: 'Security', EventID: 4624, Computer: 'x', EventData: { TargetUserName: 'a' } })).fields.ad_kind, undefined);
});

test('pairing: one change per operation with old -> new; ACL ACEs added / removed; GPO, link, DNS, schema, UAC readings; personal data masked', () => {
  const list = A.pairChanges(events.concat([events[1]]));   // the same record twice (agent + WEF) counts once
  const by = (k, attr) => list.find((c) => c.kind === k && (!attr || c.attribute === attr));
  const acl = by('acl');
  assert.equal(list.filter((c) => c.kind === 'acl').length, 1, 'old + new of one operation = one change');
  assert.deepEqual(acl.old_values, [SD_OLD]); assert.deepEqual(acl.new_values, [SD_NEW]);
  assert.equal(acl.detail.acl.added.length, 1); assert.equal(acl.detail.acl.removed.length, 0);
  assert.match(acl.detail.acl.added[0].text, /^Allow S-1-5-21-1-2-3-4242: Full control/); assert.equal(acl.detail.acl.added[0].risky, true);
  assert.match(acl.summary, /Permissions on AdminSDHolder: 1 entry added, 0 removed - RISKY/); assert.equal(acl.severity, 3); assert.equal(acl.privileged_object, true);
  const ver = by('gpo', 'versionNumber');
  assert.equal(ver.detail.gpo.changed_side, 'computer'); assert.deepEqual(ver.detail.gpo.version_new, { user: 3, computer: 8 }); assert.match(ver.detail.gpo.setting_level, /GPO report/);
  const cse = by('gpo', 'gPCMachineExtensionNames');
  assert.deepEqual(cse.detail.gpo.extensions_added, ['Security', '803E14A0-B4FB-11D0-A0D0-00A0C90F574B']);
  const link = by('gpo-link');
  assert.deepEqual(link.detail.gpo_link.linked, [{ guid: GPO, state: 'enforced' }]); assert.match(link.summary, /1 linked/);
  const dns = by('dns', 'dnsRecord');
  assert.equal(dns.summary, 'DNS app01.synthetic.test: A 10.10.1.20 → A 203.0.113.9');
  const sch = by('schema');
  assert.match(sch.summary, /^Schema schema-attribute ms-Syn-Test-Attr: isMemberOfPartialAttributeSet FALSE → TRUE/);
  const uac = by('attribute', 'userAccountControl');
  assert.deepEqual(uac.detail.uac.set, ['DONT_REQ_PREAUTH']); assert.deepEqual(uac.detail.uac.risky_set, ['DONT_REQ_PREAUTH']); assert.equal(uac.severity, 2);
  const mob = by('attribute', 'mobile');
  assert.equal(mob.masked, true); assert.equal(mob.old, ''); assert.equal(mob.new, ''); assert.ok(!JSON.stringify(mob).includes('+9665'), 'a phone number never leaves the view (PDPL)');
  assert.equal(by('attribute', 'title').summary, 'user Finance Synthetic: title Analyst → Senior Analyst');
  assert.ok(list.some((c) => c.op === 'created' && c.kind === 'gpo'));
  assert.ok(list.some((c) => c.op === 'moved' && /OU=Staff.*→.*OU=Admins/.test(c.summary)));
  assert.ok(list.some((c) => c.op === 'access' && c.dcsync && /DCSync/.test(c.summary)));
  // only the new half logged: still one change, with the honest note
  const only = A.pairChanges([events[1]])[0];
  assert.equal(only.old_values.length, 0); assert.match(only.detail.acl.note, /Only the new descriptor/);
});

test('SDDL: owner / inheritance changes, removed ACEs, well-known SIDs and rights named, admins are not "risky"', () => {
  const d = A.diffSddl('O:DAG:DAD:PAI(A;;GA;;;DA)(OA;;CR;00299570-246d-11d0-a768-00aa006e0529;;S-1-5-21-1-2-3-513)', 'O:S-1-5-21-1-2-3-4242G:DAD:AI(A;;GA;;;DA)(A;;GA;;;EA)');
  assert.equal(d.owner_old, 'Domain Admins'); assert.equal(d.owner_changed, true); assert.equal(d.inheritance_changed, true);
  assert.equal(d.removed[0].text, 'Allow (object) Domain Users: Extended right - Reset password');
  assert.equal(d.added[0].trustee, 'Enterprise Admins'); assert.equal(d.added[0].risky, false);
  assert.equal(A.parseSddl('not sddl').valid, false);
});

test('rule pack ad-changes.json: real-time rules compile; positives fire through the detector, negatives do not', () => {
  const rules = require('../engine/detect/rules/ad-changes.json');
  assert.equal(rules.length, 8);
  for (const r of rules) { assert.match(r.id, /^SENTRA-ADC-\d{3}$/); compileRule(r); assert.ok(r.mitre.length && r.sama.length && r.description.length > 40); }
  const dp = ev(4739, Object.assign({}, SUBJ, { DomainPolicyChanged: 'Password Policy', MinPasswordLength: '6' }));
  const apOff = ev(4719, Object.assign({}, SUBJ, { SubcategoryGuid: '{0CCE9215-69AE-11D9-BED3-505054503030}', AuditPolicyChanges: '%%8450' }));
  const apOn = ev(4719, Object.assign({}, SUBJ, { SubcategoryGuid: '{0CCE9215-69AE-11D9-BED3-505054503030}', AuditPolicyChanges: '%%8449' }));
  const dnsSelf = W.parse(JSON.stringify({ Channel: 'Security', EventID: 5136, Computer: 'DC01', TimeCreated: new Date(T0).toISOString(), EventData: { SubjectUserName: 'APP01$', ObjectDN: 'DC=app01,DC=synthetic.test,CN=MicrosoftDNS,DC=DomainDnsZones,' + DOM, ObjectClass: 'dnsNode', AttributeLDAPDisplayName: 'dnsRecord', AttributeValue: dnsHex('10.0.0.1'), OperationType: '%%14675' } }));
  const dcsyncByDc = ev(4662, Object.assign({}, SUBJ, { SubjectUserName: 'DC02$', AccessList: '%%7688', Properties: '{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}' }));
  const aclPlain = mod(C(50), 'CN=Some Group,OU=Groups,' + DOM, 'group', 'nTSecurityDescriptor', SD_NEW, 'new');
  const all = events.concat([dp, apOff, apOn, dnsSelf, dcsyncByDc, aclPlain]);
  const R = Object.fromEntries(rules.map((r) => [r.id, r]));
  // each rule alone over every event: which events it alerts on (group key lists them; suppression is per group)
  const fire = (rule, list) => { const out = []; const det = createDetector({ rules: [rule], onAlert: (a) => { if (!a.update) out.push(a); }, now: () => T0 }); for (const e of list) det.onEvent(e); assert.equal(det.stats().errors, 0); return out; };
  const g = (id) => fire(R[id], all).map((a) => Object.values(a.group).join('|'));
  assert.deepEqual(g('SENTRA-ADC-001'), ['adm.syn|CN=AdminSDHolder,CN=System,' + DOM], 'privileged ACL only (not the plain group, not the old half)');
  assert.deepEqual(g('SENTRA-ADC-002'), ['adm.syn|OU=Servers,' + DOM]);
  assert.deepEqual(g('SENTRA-ADC-003').sort(), ['adm.syn|0D0D0D0D-AAAA-BBBB-CCCC-DDDDDDDDDDDD', 'adm.syn|' + GPO], 'one alert per GPO and editor');
  assert.equal(fire(R['SENTRA-ADC-004'], all).length, 1);
  assert.deepEqual(g('SENTRA-ADC-005').sort(), ['synthetic.test|app01', 'synthetic.test|old01'], 'record value replaced + record deleted');
  assert.equal(fire(R['SENTRA-ADC-005'], [dnsSelf]).length, 0, 'the host updating its own record does not alert');
  assert.equal(fire(R['SENTRA-ADC-006'], [apOn]).length, 0); assert.equal(fire(R['SENTRA-ADC-006'], [apOff]).length, 1);
  assert.equal(fire(R['SENTRA-ADC-007'], all).length, 1);
  assert.deepEqual(g('SENTRA-ADC-008'), ['adm.syn']); assert.equal(fire(R['SENTRA-ADC-008'], [dcsyncByDc]).length, 0, 'a DC replicating is not DCSync');
  // negatives: an ordinary attribute change and a plain group ACL fire nothing in the whole pack
  const quiet = [events[16], events[17], aclPlain, apOn];
  for (const r of rules) assert.equal(fire(r, quiet).length, 0, r.id + ' fired on an ordinary change');
});

test('SAMA map: gpo_changes and audit_policy name the new rules', () => {
  const m = require('../engine/compliance/sama-map.json');
  const t = m.controls['3.3.7'].checks.find((c) => c.id === 'c337-topics').params.topics;
  assert.deepEqual(t.gpo_changes.rules, ['SENTRA-ADC-002', 'SENTRA-ADC-003']); assert.deepEqual(t.audit_policy.rules, ['SENTRA-ADC-006']);
  const sama = require('../engine/compliance/sama'); assert.ok(sama.loadMap(), 'the map still validates against the catalogue');
});

const GPO_XML = (minLen, lockout) => `<?xml version="1.0" encoding="utf-16"?><GPO xmlns="http://www.microsoft.com/GroupPolicy/Settings"><Identifier><Identifier xmlns="http://www.microsoft.com/GroupPolicy/Types">{${GPO}}</Identifier></Identifier><Name>Synthetic Servers Policy</Name>
<Computer><VersionDirectory>8</VersionDirectory><Enabled>true</Enabled><ExtensionData><Extension xmlns:q1="http://www.microsoft.com/GroupPolicy/Settings/Security" xsi:type="q1:SecuritySettings"><q1:Account><q1:Name>MinimumPasswordLength</q1:Name><q1:SettingNumber>${minLen}</q1:SettingNumber><q1:Type>Password</q1:Type></q1:Account>${lockout ? '<q1:Account><q1:Name>LockoutBadCount</q1:Name><q1:SettingNumber>5</q1:SettingNumber><q1:Type>Account Lockout</q1:Type></q1:Account>' : ''}</Extension><Name>Security</Name></ExtensionData>
<ExtensionData><Extension xmlns:q2="http://www.microsoft.com/GroupPolicy/Settings/Registry" xsi:type="q2:RegistrySettings"><q2:Policy><q2:Name>Turn off Autoplay</q2:Name><q2:State>Enabled</q2:State><q2:Explain>long text &amp; more</q2:Explain><q2:Category>Windows Components/AutoPlay Policies</q2:Category></q2:Policy></Extension><Name>Registry</Name></ExtensionData></Computer>
<LinksTo><SOMName>Servers</SOMName><SOMPath>synthetic.test/Servers</SOMPath><Enabled>true</Enabled><NoOverride>true</NoOverride></LinksTo></GPO>`;

test('GPO report: flattened to settings, two snapshots diffed into setting-level old / new', () => {
  const a = A.flattenGpoReport(GPO_XML(8, true)), b = A.flattenGpoReport(GPO_XML(14, false));
  assert.equal(a.ok, true); assert.equal(a.name, 'Synthetic Servers Policy'); assert.equal(a.guid, GPO);
  assert.equal(a.settings['Computer / Security / Account [MinimumPasswordLength]'], 'SettingNumber=8; Type=Password');
  assert.equal(a.settings['Computer / Registry / Policy [Turn off Autoplay / Windows Components/AutoPlay Policies]'], 'State=Enabled', 'the Explain text is not a setting');
  assert.equal(a.settings['Links / synthetic.test/Servers'], 'Enabled=true; NoOverride=true');
  assert.deepEqual(A.diffGpoSettings(a, b), [
    { setting: 'Computer / Security / Account [LockoutBadCount]', change: 'removed', old: 'SettingNumber=5; Type=Account Lockout', new: null },
    { setting: 'Computer / Security / Account [MinimumPasswordLength]', change: 'changed', old: 'SettingNumber=8; Type=Password', new: 'SettingNumber=14; Type=Password' }]);
  assert.equal(A.flattenGpoReport('<html/>').ok, false);
});

// ---------------------------------------------------------------- routes
function memState() {
  const cols = {};
  return { collection: (n) => { const m = cols[n] || (cols[n] = new Map()); return { get: (id) => m.get(id) || null, put: (o) => { m.set(o.id, JSON.parse(JSON.stringify(o))); return o; }, all: (f) => [...m.values()].filter((x) => !f || f(x)), remove: (id) => m.delete(id), size: () => m.size }; } };
}
const ROWS = events.map((e) => Object.assign({}, e, { ts: new Date(e.ts).toISOString().replace('T', ' ').replace('Z', '') }));
function setup(extra) {
  const routes = require('../engine/soc/adchanges-routes'), R = {}, seen = [];
  const ch = { query: async (sql, params) => { seen.push({ sql, params }); if (/adchanges:rows/.test(sql)) return ROWS; if (/adchanges:gpo-cursor/.test(sql)) return [{ g: GPO, t: '2026-11-10 09:00:00.000' }]; return []; } };
  const runs = [];
  let xml = GPO_XML(8, true);
  const sysadminInstance = { runner: { run: async (ref, check, params, o) => { runs.push({ ref, check, params, o }); return { server: 'dc01', data: { available: true, reports: [{ guid: GPO, name: 'Synthetic Servers Policy', modified: '2026-11-10T09:00:00Z', xml }] } }; } } };
  const deps = Object.assign({ ch, state: memState(), config: { ad_changes: { gpo_server: 'dc01' } }, log: { info() {}, warn() {}, error() {}, every() {}, child() { return this; } }, noTimers: true, sysadminInstance }, extra || {});
  routes.register({ route: (m, p, h) => { R[m + ' ' + p] = h; } }, deps);
  const call = async (m, p, role, { query, body, params } = {}) => {
    const c = { role, user: role + '.syn', query: query || {}, body, params: params || {}, code: 200, aud: [], audit(a, t, d) { c.aud.push([a, t, d]); },
      need(r) { const K = { viewer: 0, analyst: 1, operator: 2, admin: 3 }; if (K[role] < K[r]) { c.code = 403; return false; } return true; }, ok: (x) => { c.res = x; return x; }, fail(code, msg) { c.code = code; c.msg = msg; return { error: msg }; } };
    await R[m + ' /api/soc' + p](c); return c;
  };
  return { R, call, seen, runs, deps, setXml: (x) => { xml = x; } };
}

test('routes: AD changes - viewer refused, analyst reads with filters, validation names the field, every read audited', async () => {
  const { call, seen } = setup();
  let c = await call('GET', '/ad/changes', 'viewer'); assert.equal(c.code, 403, 'viewer refused (names people)');
  c = await call('GET', '/ad/changes', 'analyst', { query: { hours: '24' } }); assert.equal(c.code, 200);
  assert.equal(seen[0].params.h.value, 24); assert.match(seen[0].sql, /event_code IN \('5136'/);
  assert.equal(c.res.counts.acl, 1); assert.ok(c.res.counts.gpo >= 3); assert.equal(c.res.counts.risky, 2);
  assert.deepEqual(c.aud[0].slice(0, 2), ['ad.changes.view', 'all']);
  c = await call('GET', '/ad/changes', 'analyst', { query: { kind: 'gpo' } });
  assert.ok(c.res.items.length >= 3 && c.res.items.every((x) => x.kind === 'gpo' || x.kind === 'gpo-link')); assert.equal(c.aud[0][2].filter.kind, 'gpo');
  c = await call('GET', '/ad/changes', 'analyst', { query: { kind: 'dns' } }); assert.ok(c.res.items.some((x) => /203\.0\.113\.9/.test(x.summary)));
  c = await call('GET', '/ad/changes', 'analyst', { query: { object_class: 'user', q: 'senior' } }); assert.equal(c.res.items.length, 1);
  c = await call('GET', '/ad/changes', 'analyst', { query: { risky: '1' } }); assert.deepEqual(c.res.items.map((x) => x.kind).sort(), ['acl', 'attribute'], 'risky ACE + risky UAC flag');
  c = await call('GET', '/ad/changes', 'analyst', { query: { privileged: '1' } }); assert.ok(c.res.items.length >= 1 && c.res.items.every((x) => x.privileged_object));
  c = await call('GET', '/ad/changes', 'analyst', { query: { kind: 'everything' } }); assert.equal(c.code, 400); assert.match(c.msg, /kind must be one of/);
  c = await call('GET', '/ad/changes', 'analyst', { query: { hours: '9999' } }); assert.equal(c.code, 400); assert.match(c.msg, /hours must be at most/);
  c = await call('GET', '/ad/changes', 'analyst', { query: { object_class: "user' OR 1=1" } }); assert.equal(c.code, 400); assert.match(c.msg, /object_class/);
  assert.equal(c.aud.length, 0, 'a refused request writes no read record');
});

test('routes: GPO snapshots - operator takes one (read-only check gpo_report, audited), the next one diffs at setting level; viewer / analyst refused; validation', async () => {
  const S = setup();
  let c = await S.call('POST', '/ad/gpo/snapshot', 'analyst', { body: { guid: GPO } }); assert.equal(c.code, 403, 'running a check on a DC: operator');
  c = await S.call('POST', '/ad/gpo/snapshot', 'operator', { body: { guid: 'not-a-guid' } }); assert.equal(c.code, 400); assert.match(c.msg, /guid must be a GPO GUID/);
  c = await S.call('POST', '/ad/gpo/snapshot', 'operator', { body: { guid: GPO, server: 'DC 01!' } }); assert.equal(c.code, 400); assert.match(c.msg, /server/);
  c = await S.call('POST', '/ad/gpo/snapshot', 'operator', { body: { guid: GPO } }); assert.equal(c.code, 200);
  assert.deepEqual(S.runs[0], { ref: 'dc01', check: 'gpo_report', params: { guid: GPO, hours: 24 }, o: { by: 'operator.syn', via: 'portal' } });
  assert.equal(c.res.snapshots[0].first, true);
  assert.equal(c.aud[0][0], 'ad.gpo.snapshot'); assert.equal(c.aud[0][1], GPO); assert.equal(c.aud[0][2].server, 'dc01');
  S.setXml(GPO_XML(14, true));
  c = await S.call('POST', '/ad/gpo/snapshot', 'operator', { body: { guid: GPO } });
  const id = c.res.snapshots[0].id;
  assert.deepEqual(c.res.snapshots[0].diff.map((d) => [d.change, d.old, d.new]), [['changed', 'SettingNumber=8; Type=Password', 'SettingNumber=14; Type=Password']]);
  c = await S.call('GET', '/ad/gpo/snapshots', 'analyst', { query: { guid: GPO } }); assert.equal(c.res.items.length, 2); assert.equal(c.res.items[0].diff_count, 1);
  c = await S.call('GET', '/ad/gpo/snapshots/:id', 'analyst', { params: { id } }); assert.equal(c.res.diff.length, 1); assert.equal(c.aud[0][0], 'ad.gpo.snapshot.view');
  c = await S.call('GET', '/ad/gpo/snapshots/:id', 'analyst', { params: { id: 'nope' } }); assert.equal(c.code, 404);
  c = await S.call('GET', '/ad/gpo/snapshots/:id', 'analyst', { params: { id: '../etc' } }); assert.equal(c.code, 400);
  // an unchanged report stores nothing new
  c = await S.call('POST', '/ad/gpo/snapshot', 'operator', { body: { guid: GPO } }); assert.equal(c.res.snapshots[0].unchanged, true);
  // a failure is audited with ok:false and passed on
  const F = setup({ sysadminInstance: { runner: { run: async () => { throw Object.assign(new Error('access denied on dc01'), { code: 403 }); } } } });
  c = await F.call('POST', '/ad/gpo/snapshot', 'operator', { body: { guid: GPO } }); assert.equal(c.code, 403); assert.equal(c.aud[0][2].ok, false);
  // no server set and none given: says what to do
  const N = setup({ config: { ad_changes: {} } });
  c = await N.call('POST', '/ad/gpo/snapshot', 'operator', { body: {} }); assert.equal(c.code, 409); assert.match(c.msg, /gpo_server/);
});

test('policy changes: 4739 settings with the previous value, 4719 audit removals, GPO changes and the automatic snapshot round', async () => {
  const p1 = ev(4739, Object.assign({}, SUBJ, { DomainPolicyChanged: 'Lockout Policy', DomainName: 'SYN', LockoutThreshold: '5' }));
  const p2 = ev(4739, Object.assign({}, SUBJ, { DomainPolicyChanged: 'Lockout Policy', DomainName: 'SYN', LockoutThreshold: '0' }));
  const ap = ev(4719, Object.assign({}, SUBJ, { SubcategoryGuid: '{0CCE9215-69AE-11D9-BED3-505054503030}', AuditPolicyChanges: '%%8448, %%8450' }));
  const items = A.policyChanges([p2, ap, p1]);
  const last = items.find((x) => x.type === 'domain-policy' && x.settings[0].new === '0');
  assert.deepEqual(last.settings, [{ setting: 'LockoutThreshold', old: '5', new: '0' }]);
  assert.equal(items.find((x) => x.type === 'domain-policy' && x.settings[0].new === '5').settings[0].old, null, 'no earlier event: old is unknown, not invented');
  const a = items.find((x) => x.type === 'audit-policy'); assert.equal(a.subcategory, 'Logon'); assert.equal(a.removed, true);
  const S = setup();
  const c = await S.call('GET', '/ad/policy-changes', 'analyst', { query: { hours: '48' } });
  assert.equal(c.code, 200); assert.ok(c.res.gpo_changes.length >= 3); assert.equal(c.res.snapshot.server, 'dc01'); assert.equal(c.aud[0][0], 'ad.policy.view');
  assert.equal((await S.call('GET', '/ad/policy-changes', 'viewer')).code, 403);
  const r = await S.deps.adChanges.autoRound();
  assert.deepEqual(r.done.map((x) => [x.guid, x.ok]), [[GPO, true]]); assert.equal(S.runs[0].o.via, 'auto');
  assert.ok(S.deps.state.collection('ad_changes_meta').get('cursor').ts >= Date.UTC(2026, 10, 10, 9), 'the cursor moves on');
  const off = setup({ config: { ad_changes: {} } }); assert.match((await off.deps.adChanges.autoRound()).skipped, /gpo_server/);
  const none = await A.createAdChanges({}).changes({}); assert.equal(none.available, false);
});

test('read-only GPO report check: allow-listed, renders with a quoted GUID, refuses anything else, no write verb', () => {
  const { CHECKS } = require('../engine/sysadmin/runner');
  const c = CHECKS.find((x) => x.id === 'gpo_report');
  assert.ok(c && c.scope === 'windows' && c.personal === true);
  assert.ok(!/\b(Set|New|Remove|Restore|Backup|Import-GPO|Copy|Rename|Invoke)-GP/i.test(c.script), 'no GPO write cmdlet');
  const { spawnSync } = require('node:child_process'), path = require('node:path');
  const py = (req) => JSON.parse(spawnSync('python3', [path.join(__dirname, '../engine/sysadmin/ps-helper.py')], { input: JSON.stringify(req), encoding: 'utf8' }).stdout);
  const r = py({ op: 'render', check: 'gpo_report', params: { guid: GPO } }); assert.equal(r.ok, true); assert.ok(r.script.includes(`$g='${GPO}'`));
  assert.equal(py({ op: 'render', check: 'gpo_report', params: { guid: "x'; Remove-GPO -All" } }).ok, false);
  assert.equal(py({ op: 'render', check: 'gpo_report', params: { hours: 999 } }).ok, false);
});
