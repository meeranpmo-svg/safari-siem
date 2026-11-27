// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Firewall & Security Device Audit - a configuration audit of every FortiGate (through FortiManager, read-only) and every H3C /
 * Cisco switch whose configuration the daily capture holds, against a FIXED audit programme: what an auditor checks on a firewall
 * review, each test mapped to NCA ECC, ISO/IEC 27001:2022, Aramco CCC (SACS-002 topics) and the CIS benchmark topic.
 *   FortiGate    rule base (any-any, internet inbound, no logging, no security profile, shadowed, unused by hit counts, disabled
 *                clutter), administrator access (trusted hosts, two-factor, default "admin", idle timeout, lockout, password
 *                policy, management on internet interfaces, HTTP / Telnet), crypto (strong-crypto, admin TLS, IPsec proposals and
 *                DH groups, IKE aggressive mode, SSL-VPN TLS), logging & time (FortiAnalyzer / syslog, implicit deny logged, NTP),
 *                monitoring (SNMP v1 / v2c, SNMPv3 without privacy), resilience (HA, FortiGuard updates) and the fleet's own
 *                assessment (firmware behind the target, support / FortiGuard expired, configuration changed outside FortiManager)
 *   switches     H3C Comware / Cisco IOS configuration text: Telnet, SSH v2, SNMP v1 / v2c, central logging, NTP, AAA / local
 *                accounts with a plain-text password, password recovery, login banner, idle timeout
 * Every test answers PASS, FAIL (with the evidence: the policy ids, the interfaces, the accounts) or NOT CHECKED (the section could
 * not be read - never a pass). A score per device weights the tests by severity over the tests that could be checked; coverage
 * says how much was checked. Each failure carries the FortiOS / Comware fix as text for the network engineer - nothing here
 * changes a device: a fix goes through the FortiManager four-eyes change or the network team's change process.
 * Risk acceptance: a person with the firewall approval scope accepts a failed test on a device with a reason and an end date
 * (at most a year); it is shown as accepted, not passed. Sign-off: a run is signed off by a named person who did not start it.
 * Every run keeps a SHA-256 of its evidence, so the report can show it was not changed afterwards.
 *   GET  {P}/netops/fw-audit                 analyst            the last run (devices, tests, findings, rule base), runs
 *   POST {P}/netops/fw-audit/run             operator           read the devices and test them now
 *   POST {P}/netops/fw-audit/accept          approve:eng:security  {device, test, reason, until}
 *   POST {P}/netops/fw-audit/accept/remove   approve:eng:security  {device, test}
 *   POST {P}/netops/fw-audit/signoff         approve:eng:security  {run, note}   a different person from the one who ran it
 *   GET  {P}/netops/fw-audit/export          analyst            CSV of the findings of the last run
 */
const crypto = require('node:crypto');
const { body } = require('../util/check');
const { HttpError, wrap, audit, prefixOf } = require('../soc/routeutil');
const { guard } = require('../util/errors');

const W = { critical: 10, high: 6, medium: 3, low: 1 };
const DAY = 86400000;
const arr = (v) => (Array.isArray(v) ? v : []);
const names = (v) => arr(v).map((x) => String(x && typeof x === 'object' ? x.name || x.q_origin_key || '' : x)).filter(Boolean);
const ALL = (L) => L.some((x) => /^(all|any)$/i.test(x));
const SVC_ALL = (L) => L.some((x) => /^(ALL|any)$/i.test(x));
const R = (nca, iso, aramco, cis) => ({ nca, iso, aramco, cis });

// ---------- FortiGate: the rule base ----------
function wanSet(S) {
  const I = arr(S.interfaces), wan = new Set(I.filter((i) => i.role === 'wan').map((i) => i.name));
  for (const i of I) if (/^(wan\d*|internet.*|virtual-wan-link|sd-?wan)$/i.test(i.name)) wan.add(i.name);
  wan.add('virtual-wan-link'); wan.add('sdwan');
  return wan;
}
function rules(S) {
  const hits = new Map(arr(S.hits).map((h) => [Number(h.policyid), h]));
  return arr(S.policies).map((p, i) => {
    const h = hits.get(Number(p.policyid));
    return { id: Number(p.policyid), seq: i, name: String(p.name || ''), enabled: p.status !== 'disable', action: String(p.action || 'deny'), srcintf: names(p.srcintf), dstintf: names(p.dstintf),
      srcaddr: names(p.srcaddr), dstaddr: names(p.dstaddr), service: names(p.service), schedule: names(p.schedule).concat(typeof p.schedule === 'string' ? [p.schedule] : [])[0] || 'always',
      log: String(p.logtraffic || ''), utm: p['utm-status'] === 'enable' || !!(p['av-profile'] || p['ips-sensor'] || p['webfilter-profile'] || p['application-list']),
      ips: !!p['ips-sensor'], comments: String(p.comments || ''), hits: h ? Number(h.hit_count || 0) : null, last_used: h && Number(h.last_used) ? Number(h.last_used) * 1000 : null };
  });
}
const covers = (a, b) => ALL(a) || b.every((x) => a.includes(x));
function shadowed(RL) {
  const on = RL.filter((r) => r.enabled), out = [];
  for (let j = 1; j < on.length; j++) {
    const B = on[j];
    for (let i = 0; i < j; i++) { const A = on[i];
      if (A.schedule !== 'always' && A.schedule !== B.schedule) continue;
      if (covers(A.srcintf, B.srcintf) && covers(A.dstintf, B.dstintf) && covers(A.srcaddr, B.srcaddr) && covers(A.dstaddr, B.dstaddr) && (SVC_ALL(A.service) || B.service.every((s) => A.service.includes(s)))) {
        out.push({ id: B.id, by: A.id, conflict: A.action !== B.action }); break; }
    }
  }
  return out;
}

// ---------- FortiGate: the audit programme ----------
const FG_TESTS = [
  { id: 'FW-01', area: 'Rule base', sev: 'critical', title: 'No any-to-any accept rule', need: ['policies'], refs: R('2-5-3', '8.20', 'Network security', 'Firewall policy'),
    run: (S, X) => { const f = X.rules.filter((r) => r.enabled && r.action === 'accept' && ALL(r.srcaddr) && ALL(r.dstaddr) && SVC_ALL(r.service)); return f.length ? fail(f.map((r) => 'policy ' + r.id + (r.name ? ' "' + r.name + '"' : '') + ': all → all, service ALL')) : pass(); },
    fix: 'Replace each with rules naming the source, destination and services the business needs; place an explicit deny with logging at the end.' },
  { id: 'FW-02', area: 'Rule base', sev: 'critical', title: 'No broad accept from the internet', need: ['policies', 'interfaces'], refs: R('2-5-3', '8.20 / 8.22', 'Network security', 'Firewall policy'),
    run: (S, X) => { const f = X.rules.filter((r) => r.enabled && r.action === 'accept' && r.srcintf.some((i) => X.wan.has(i)) && (ALL(r.srcaddr) && (ALL(r.dstaddr) || SVC_ALL(r.service)))); return f.length ? fail(f.map((r) => 'policy ' + r.id + ': from ' + r.srcintf.join(',') + ' (any source) to ' + r.dstaddr.join(',') + ' service ' + r.service.join(','))) : pass(); },
    fix: 'Publish only the named server (VIP) and the named ports; restrict the source where the partner is known; add an IPS sensor.' },
  { id: 'FW-03', area: 'Rule base', sev: 'high', title: 'Every accept rule logs its traffic', need: ['policies'], refs: R('2-12-1', '8.15', 'Logging and monitoring', 'Logging'),
    run: (S, X) => { const f = X.rules.filter((r) => r.enabled && r.action === 'accept' && (r.log === 'disable' || r.log === '')); return f.length ? fail(f.map((r) => 'policy ' + r.id + ': logtraffic ' + (r.log || 'not set'))) : pass(); },
    fix: 'config firewall policy / edit <id> / set logtraffic all / next / end' },
  { id: 'FW-04', area: 'Rule base', sev: 'high', title: 'Internet-facing rules inspect traffic (IPS / antivirus / web filter)', need: ['policies', 'interfaces'], refs: R('2-5-3', '8.20 / 8.7', 'Network security', 'Security profiles'),
    run: (S, X) => { const f = X.rules.filter((r) => r.enabled && r.action === 'accept' && (r.srcintf.some((i) => X.wan.has(i)) || r.dstintf.some((i) => X.wan.has(i))) && !r.utm); return f.length ? fail(f.map((r) => 'policy ' + r.id + ' (' + r.srcintf.join(',') + ' → ' + r.dstintf.join(',') + '): no security profile')) : pass(); },
    fix: 'config firewall policy / edit <id> / set utm-status enable / set ips-sensor default / set av-profile default / set ssl-ssh-profile certificate-inspection / next / end' },
  { id: 'FW-05', area: 'Rule base', sev: 'medium', title: 'No shadowed or conflicting rules', need: ['policies'], refs: R('2-5-3', '8.20', 'Network security', 'Firewall policy review'),
    run: (S, X) => { const f = shadowed(X.rules); return f.length ? fail(f.map((s) => 'policy ' + s.id + ' never matches: policy ' + s.by + ' above it covers it' + (s.conflict ? ' with the OPPOSITE action' : ''))) : pass(); },
    fix: 'Remove the shadowed rule, or move it above the broader one if it was meant to apply. Compared by object name - address groups are not expanded.' },
  { id: 'FW-06', area: 'Rule base', sev: 'medium', title: 'No unused accept rules (no hits)', need: ['policies', 'hits'], refs: R('2-5-3', '8.20', 'Network security', 'Firewall policy review'),
    run: (S, X) => { const old = X.now - 90 * DAY, f = X.rules.filter((r) => r.enabled && r.action === 'accept' && r.hits !== null && (r.hits === 0 || (r.last_used && r.last_used < old))); return f.length ? fail(f.map((r) => 'policy ' + r.id + (r.name ? ' "' + r.name + '"' : '') + ': ' + (r.hits === 0 ? 'no hits since the counters were last reset' : 'last used ' + new Date(r.last_used).toISOString().slice(0, 10)))) : pass(); },
    fix: 'Confirm with the rule owner, disable for 30 days, then delete. Hit counters reset on reboot - check the uptime before deciding.' },
  { id: 'FW-07', area: 'Rule base', sev: 'low', title: 'Disabled rules are cleaned up and rules are documented', need: ['policies'], refs: R('2-5-3', '8.9', 'Configuration management', 'Firewall policy review'),
    run: (S, X) => { const d = X.rules.filter((r) => !r.enabled), u = X.rules.filter((r) => r.enabled && r.action === 'accept' && !r.name && !r.comments); const ev = d.map((r) => 'policy ' + r.id + ': disabled').concat(u.length ? [u.length + ' accept rule(s) with no name or comment: ' + u.slice(0, 15).map((r) => r.id).join(', ')] : []); return ev.length ? fail(ev) : pass(); },
    fix: 'Delete rules disabled for more than 90 days; give every rule a name and a comment with the change reference and owner.' },
  { id: 'FW-10', area: 'Administrator access', sev: 'critical', title: 'Administrator accounts are limited to trusted hosts', need: ['admins'], refs: R('2-2-3', '8.5', 'Access control', 'Trusted hosts'),
    run: (S) => { const f = arr(S.admins).filter((a) => { const t = Object.keys(a).filter((k) => /^trusthost\d+$/.test(k)).map((k) => String(a[k])); return !t.some((x) => x && !/^0\.0\.0\.0 0\.0\.0\.0$/.test(x.trim())); }); return f.length ? fail(f.map((a) => 'admin "' + a.name + '" (' + (a.accprofile || '') + '): can sign in from anywhere')) : pass(); },
    fix: 'config system admin / edit <name> / set trusthost1 <management-subnet> 255.255.255.0 / next / end' },
  { id: 'FW-11', area: 'Administrator access', sev: 'high', title: 'Administrators use two-factor authentication', need: ['admins'], refs: R('2-2-3', '8.5', 'Access control (MFA)', 'Two-factor'),
    run: (S) => { const f = arr(S.admins).filter((a) => (!a['two-factor'] || a['two-factor'] === 'disable') && a['remote-auth'] !== 'enable'); return f.length ? fail(f.map((a) => 'admin "' + a.name + '": no two-factor')) : pass(); },
    fix: 'config system admin / edit <name> / set two-factor fortitoken / set fortitoken <serial> / next / end  (or remote authentication through RADIUS with MFA)' },
  { id: 'FW-12', area: 'Administrator access', sev: 'medium', title: 'The default "admin" account is renamed or removed', need: ['admins'], refs: R('2-2-3', '8.2', 'Access control', 'Default accounts'),
    run: (S) => (arr(S.admins).some((a) => a.name === 'admin') ? fail(['account "admin" exists']) : pass()), fix: 'Create a named super_admin account, sign in with it, then delete "admin".' },
  { id: 'FW-13', area: 'Administrator access', sev: 'medium', title: 'Idle administrator sessions time out (≤ 10 minutes)', need: ['global'], refs: R('2-2-3', '8.5', 'Access control', 'Idle timeout'),
    run: (S) => { const t = Number(S.global && S.global.admintimeout); return !t ? nc('idle timeout not reported') : t <= 10 ? pass(['admintimeout ' + t + ' min']) : fail(['admintimeout ' + t + ' min']); }, fix: 'config system global / set admintimeout 10 / end' },
  { id: 'FW-14', area: 'Administrator access', sev: 'medium', title: 'Sign-in lockout after failed attempts', need: ['global'], refs: R('2-2-3', '8.5', 'Access control', 'Lockout'),
    run: (S) => { const g = S.global || {}, th = Number(g['admin-lockout-threshold']), du = Number(g['admin-lockout-duration']); return th && th <= 5 && du >= 300 ? pass(['threshold ' + th + ', duration ' + du + ' s']) : fail(['threshold ' + (th || 'not set') + ', duration ' + (du || 'not set') + ' s']); },
    fix: 'config system global / set admin-lockout-threshold 3 / set admin-lockout-duration 900 / end' },
  { id: 'FW-15', area: 'Administrator access', sev: 'medium', title: 'Password policy for local accounts (12+ characters, complexity, expiry)', need: ['password_policy'], refs: R('2-2-3', '5.17', 'Access control', 'Password policy'),
    run: (S) => { const p = S.password_policy || {}; if (p.status !== 'enable') return fail(['password policy disabled']); const ev = []; if (Number(p['minimum-length']) < 12) ev.push('minimum length ' + p['minimum-length']); if (!(Number(p['min-number']) >= 1 && Number(p['min-non-alphanumeric']) >= 1)) ev.push('no digit / symbol required'); if (p['expire-status'] !== 'enable') ev.push('no expiry'); return ev.length ? fail(ev) : pass(); },
    fix: 'config system password-policy / set status enable / set minimum-length 12 / set min-number 1 / set min-non-alphanumeric 1 / set expire-status enable / set expire-day 90 / end' },
  { id: 'FW-16', area: 'Administrator access', sev: 'critical', title: 'No HTTP or Telnet administration on any interface', need: ['interfaces'], refs: R('2-8-1', '8.20 / 8.24', 'Cryptography', 'Management protocols'),
    run: (S) => { const f = arr(S.interfaces).filter((i) => /\b(http|telnet)\b/.test(String(i.allowaccess || ''))); return f.length ? fail(f.map((i) => i.name + ': ' + i.allowaccess)) : pass(); }, fix: 'config system interface / edit <port> / unselect allowaccess http telnet / next / end' },
  { id: 'FW-17', area: 'Administrator access', sev: 'critical', title: 'No administration (HTTPS / SSH / SNMP) on internet interfaces', need: ['interfaces'], refs: R('2-5-3', '8.20', 'Network security', 'Management interfaces'),
    run: (S, X) => { const f = arr(S.interfaces).filter((i) => X.wan.has(i.name) && /\b(https|ssh|snmp|http|telnet)\b/.test(String(i.allowaccess || ''))); return f.length ? fail(f.map((i) => i.name + ' (internet): ' + i.allowaccess)) : pass(); },
    fix: 'config system interface / edit <wan> / set allowaccess ping fgfm   (manage over the VPN or a dedicated management interface)' },
  { id: 'FW-18', area: 'Administrator access', sev: 'low', title: 'A pre-login warning banner is shown', need: ['global'], refs: R('2-2-3', '5.10', 'Access control', 'Login banner'),
    run: (S) => ((S.global || {})['pre-login-banner'] === 'enable' ? pass() : fail(['pre-login-banner disabled'])), fix: 'config system global / set pre-login-banner enable / end  (then the text under config system replacemsg admin pre_admin-disclaimer-text)' },
  { id: 'FW-19', area: 'Administrator access', sev: 'medium', title: 'Maintainer account and USB auto-install are off', need: ['global'], refs: R('2-3-1', '8.9', 'Hardening', 'Physical access'),
    run: (S) => { const g = S.global || {}, ev = []; if (g['admin-maintainer'] === 'enable') ev.push('maintainer account enabled'); if (g['auto-install-config'] === 'enable') ev.push('USB auto-install config'); if (g['auto-install-image'] === 'enable') ev.push('USB auto-install image'); return ev.length ? fail(ev) : pass(); },
    fix: 'config system global / set admin-maintainer disable / set auto-install-config disable / set auto-install-image disable / end' },
  { id: 'FW-20', area: 'Cryptography', sev: 'high', title: 'Strong cryptography and TLS 1.2+ for administration', need: ['global'], refs: R('2-8-1', '8.24', 'Cryptography', 'Strong crypto'),
    run: (S) => { const g = S.global || {}, ev = []; if (g['strong-crypto'] !== 'enable') ev.push('strong-crypto ' + (g['strong-crypto'] || 'not set')); if (/tlsv1-0|tlsv1-1/.test(String(g['admin-https-ssl-versions'] || ''))) ev.push('admin HTTPS allows ' + g['admin-https-ssl-versions']); return ev.length ? fail(ev) : pass(); },
    fix: 'config system global / set strong-crypto enable / set admin-https-ssl-versions tlsv1-2 tlsv1-3 / end' },
  { id: 'FW-21', area: 'Cryptography', sev: 'high', title: 'IPsec VPNs use strong proposals (no DES / 3DES / MD5 / SHA-1, DH group 14+, IKEv2 or main mode)', need: ['phase1'], refs: R('2-8-1', '8.24', 'Cryptography', 'VPN crypto'),
    run: (S) => { const ev = []; for (const p of arr(S.phase1)) { const w = []; if (/\b(des|3des)-|md5|-sha1\b/.test(String(p.proposal || ''))) w.push('proposal ' + p.proposal); const g = String(p.dhgrp || '').split(/\s+/).filter(Boolean).map(Number); if (g.some((x) => [1, 2, 5].includes(x))) w.push('DH group ' + p.dhgrp); if (p.mode === 'aggressive' && String(p['ike-version'] || '1') === '1') w.push('IKEv1 aggressive mode'); if (w.length) ev.push(p.name + ': ' + w.join('; ')); } return ev.length ? fail(ev) : pass([arr(S.phase1).length + ' tunnel(s) checked']); },
    fix: 'config vpn ipsec phase1-interface / edit <tunnel> / set ike-version 2 / set proposal aes256gcm-prfsha384 aes256-sha256 / set dhgrp 20 19 14 / next / end  (agree the change with the far end)' },
  { id: 'FW-22', area: 'Cryptography', sev: 'medium', title: 'SSL-VPN requires TLS 1.2 or newer', need: ['sslvpn'], refs: R('2-8-1', '8.24', 'Cryptography', 'SSL-VPN'),
    run: (S) => { const v = S.sslvpn || {}; if (v.status === 'disable' || !arr(v['source-interface']).length) return na('SSL-VPN not in use'); return /tls1-[23]/.test(String(v['ssl-min-proto-ver'] || '')) ? pass(['minimum ' + v['ssl-min-proto-ver']]) : fail(['minimum ' + (v['ssl-min-proto-ver'] || 'not set')]); },
    fix: 'config vpn ssl settings / set ssl-min-proto-ver tls1-2 / end' },
  { id: 'FW-30', area: 'Logging & time', sev: 'critical', title: 'Logs go to FortiAnalyzer or the SIEM (syslog)', need: ['faz', 'syslog'], refs: R('2-12-1', '8.15', 'Logging and monitoring', 'Remote logging'),
    run: (S) => { const a = (S.faz || {}).status === 'enable', b = (S.syslog || {}).status === 'enable'; return a || b ? pass([a ? 'FortiAnalyzer ' + ((S.faz || {}).server || '') : '', b ? 'syslog ' + ((S.syslog || {}).server || '') : ''].filter(Boolean)) : fail(['no FortiAnalyzer and no syslog']); },
    fix: 'config log syslogd setting / set status enable / set server <SIEM collector> / set mode reliable / end' },
  { id: 'FW-31', area: 'Logging & time', sev: 'medium', title: 'Denied traffic (implicit deny) is logged', need: ['log_setting'], refs: R('2-12-1', '8.15', 'Logging and monitoring', 'Deny logging'),
    run: (S) => ((S.log_setting || {})['fwpolicy-implicit-log'] === 'enable' ? pass() : fail(['fwpolicy-implicit-log ' + ((S.log_setting || {})['fwpolicy-implicit-log'] || 'disable')])), fix: 'config log setting / set fwpolicy-implicit-log enable / end' },
  { id: 'FW-32', area: 'Logging & time', sev: 'medium', title: 'Clock synchronised by NTP', need: ['ntp'], refs: R('2-12-1', '8.17', 'Logging and monitoring', 'Time synchronisation'),
    run: (S) => ((S.ntp || {}).ntpsync === 'enable' ? pass([(S.ntp || {}).type === 'custom' ? 'custom servers: ' + arr((S.ntp || {}).ntpserver).map((x) => x.server).join(', ') : 'FortiGuard NTP']) : fail(['ntpsync disabled'])), fix: 'config system ntp / set ntpsync enable / set type custom / config ntpserver / edit 1 / set server <internal NTP> / end / end' },
  { id: 'FW-33', area: 'Monitoring', sev: 'high', title: 'No SNMP v1 / v2c; SNMPv3 with authentication and privacy', need: ['snmp_community', 'snmp_user'], refs: R('2-8-1', '8.20', 'Network security', 'SNMP'),
    run: (S) => { const ev = []; for (const c of arr(S.snmp_community)) if (c.status !== 'disable' && (c['query-v1-status'] !== 'disable' || c['query-v2c-status'] !== 'disable')) ev.push('community ' + c.id + ': SNMP v1/v2c (clear-text), ' + c.hosts + ' host(s)'); for (const u of arr(S.snmp_user)) if (u['security-level'] !== 'auth-priv') ev.push('SNMPv3 user "' + u.name + '": ' + u['security-level']); return ev.length ? fail(ev) : pass(); },
    fix: 'config system snmp community / delete <id> / end ; config system snmp user / edit <name> / set security-level auth-priv / set auth-proto sha256 / set priv-proto aes256 / next / end' },
  { id: 'FW-40', area: 'Resilience', sev: 'low', title: 'High availability configured', need: ['ha'], refs: R('2-9-1', '8.14', 'Business continuity', 'HA'),
    run: (S, X) => { const m = (S.ha || {}).mode || 'standalone'; return m !== 'standalone' ? pass(['HA ' + m]) : X.small ? na('branch / site unit - HA not expected') : fail(['standalone']); }, fix: 'Add a second unit of the same model and configure active-passive HA with session pickup.' },
  { id: 'FW-41', area: 'Resilience', sev: 'medium', title: 'FortiGuard signatures update automatically', need: ['autoupdate'], refs: R('2-10-1', '8.7', 'Malware protection', 'Updates'),
    run: (S) => ((S.autoupdate || {}).status === 'enable' ? pass(['every ' + ((S.autoupdate || {}).frequency || '')]) : fail(['scheduled updates disabled'])), fix: 'config system autoupdate schedule / set status enable / set frequency automatic / end' },
  { id: 'FW-50', area: 'Lifecycle', sev: 'high', title: 'Firmware at the approved target for the model', need: [], refs: R('2-10-3', '8.8', 'Vulnerability management', 'Firmware'),
    run: (S, X) => (X.fleet ? (X.fleet.findings || []).some((f) => f.code === 'firmware') ? fail(['FortiOS ' + (X.fleet.firmware || '?') + ' is behind the target for ' + (X.fleet.model || 'the model')]) : pass(['FortiOS ' + (X.fleet.firmware || '?')]) : nc('not in the FortiManager fleet')), fix: 'Plan a firmware upgrade in FortiManager (Network Estate → Propose change → Firmware upgrade, four-eyes).' },
  { id: 'FW-51', area: 'Lifecycle', sev: 'high', title: 'Support and FortiGuard subscriptions are current', need: [], refs: R('2-10-1', '5.22', 'Third-party / support', 'Licensing'),
    run: (S, X) => { if (!X.fleet) return nc('not in the FortiManager fleet'); const ex = arr(X.fleet.licences).filter((l) => l.expires && Date.parse(l.expires) < X.now); return ex.length ? fail(ex.map((l) => l.name + ' expired ' + String(l.expires).slice(0, 10))) : pass([arr(X.fleet.licences).length + ' licence(s) current']); },
    fix: 'Renew through the Fortinet partner; see Network Estate → licences for the co-term dates.' },
  { id: 'FW-52', area: 'Lifecycle', sev: 'high', title: 'Configuration managed by FortiManager (no change outside it)', need: [], refs: R('2-3-1', '8.9 / 8.32', 'Change management', 'Configuration management'),
    run: (S, X) => (X.fleet ? X.fleet.conf === 'modified' ? fail(['the device configuration differs from FortiManager - a change was made directly on the FortiGate']) : pass(['in sync with FortiManager']) : nc('not in the FortiManager fleet')), fix: 'Retrieve the configuration in FortiManager, review the difference with the change register, then re-install from FortiManager.' },
];
function pass(ev) { return { result: 'pass', evidence: ev || [] }; }
function fail(ev) { return { result: 'fail', evidence: ev || [] }; }
function na(why) { return { result: 'na', evidence: [why] }; }
function nc(why) { return { result: 'not_checked', evidence: [why] }; }

function auditFortigate(d, now) {
  const S = d.sections || {}, unread = d.unread || {}, dev = d.dev || {}, fleet = d.fleet || null;
  const X = { now, wan: wanSet(S), rules: rules(S), fleet, small: /FortiGate-(30|40|50|60|70|80|90|100)[A-Z]/i.test(String(dev.model || (fleet && fleet.model) || '')) };
  const tests = FG_TESTS.map((t) => {
    const miss = t.need.filter((k) => S[k] === undefined);
    let r;
    if (miss.length && !(t.id === 'FW-30' && (S.faz !== undefined || S.syslog !== undefined))) r = nc('not read: ' + miss.map((k) => k + (unread[k] ? ' (' + String(unread[k]).slice(0, 80) + ')' : '')).join('; '));
    else { try { r = t.run(S, X); } catch (e) { r = nc('could not be evaluated: ' + e.message); } }
    return { id: t.id, area: t.area, severity: t.sev, title: t.title, result: r.result, evidence: r.evidence.slice(0, 40), more: Math.max(0, r.evidence.length - 40), fix: r.result === 'fail' ? t.fix : '', refs: t.refs };
  });
  const RL = X.rules, sh = shadowed(RL);
  const rulebase = { total: RL.length, enabled: RL.filter((r) => r.enabled).length, accept: RL.filter((r) => r.enabled && r.action === 'accept').length, any_any: tests.find((t) => t.id === 'FW-01').result === 'fail' ? tests.find((t) => t.id === 'FW-01').evidence.length : 0,
    no_log: RL.filter((r) => r.enabled && r.action === 'accept' && (r.log === 'disable' || r.log === '')).length, unused: RL.filter((r) => r.enabled && r.action === 'accept' && r.hits === 0).length, shadowed: sh.length, disabled: RL.filter((r) => !r.enabled).length, hits_known: RL.some((r) => r.hits !== null) };
  return Object.assign({ id: String(dev.id || dev.name), name: String(dev.name || ''), kind: 'firewall', vendor: 'fortigate', model: dev.model || (fleet && fleet.model) || '', site: dev.site || (fleet && fleet.site) || '', firmware: dev.firmware || (fleet && fleet.firmware) || '', rulebase }, score(tests));
}

// ---------- switches: H3C Comware / Cisco IOS configuration text ----------
const SW_TESTS = [
  { id: 'SW-01', area: 'Administrator access', sev: 'critical', title: 'Telnet is off; management over SSH', refs: R('2-8-1', '8.20 / 8.24', 'Cryptography', 'Management protocols'),
    cw: (t) => (/^\s*telnet server enable/m.test(t) ? fail(['telnet server enable']) : pass()), ios: (t) => (/transport input (telnet|all)/m.test(t) ? fail(['line vty allows telnet']) : pass()),
    fix: { cw: 'undo telnet server enable ; ssh server enable ; line vty 0 63 / protocol inbound ssh', ios: 'line vty 0 15 / transport input ssh' } },
  { id: 'SW-02', area: 'Monitoring', sev: 'high', title: 'No SNMP v1 / v2c community', refs: R('2-8-1', '8.20', 'Network security', 'SNMP'),
    cw: (t) => { const m = t.match(/^\s*snmp-agent community .*/gm) || [], v = /snmp-agent sys-info version (all|v1|v2c)/.test(t); return m.length || v ? fail([m.length + ' community line(s)', v ? 'SNMP v1/v2c enabled' : ''].filter(Boolean)) : pass(); },
    ios: (t) => { const m = t.match(/^\s*snmp-server community .*/gm) || []; return m.length ? fail([m.length + ' community line(s)']) : pass(); },
    fix: { cw: 'undo snmp-agent community <name> ; snmp-agent sys-info version v3 ; snmp-agent usm-user v3 <user> <group> simple authentication-mode sha <..> privacy-mode aes128 <..>', ios: 'no snmp-server community <name> ; snmp-server group <g> v3 priv ; snmp-server user <u> <g> v3 auth sha <..> priv aes 128 <..>' } },
  { id: 'SW-03', area: 'Logging & time', sev: 'high', title: 'Logs sent to the SIEM', refs: R('2-12-1', '8.15', 'Logging and monitoring', 'Remote logging'),
    cw: (t) => (/^\s*info-center loghost /m.test(t) ? pass() : fail(['no info-center loghost'])), ios: (t) => (/^\s*logging (host )?\d/m.test(t) ? pass() : fail(['no logging host'])),
    fix: { cw: 'info-center enable ; info-center loghost <SIEM collector> facility local7', ios: 'logging host <SIEM collector> ; logging trap informational' } },
  { id: 'SW-04', area: 'Logging & time', sev: 'medium', title: 'Clock synchronised by NTP', refs: R('2-12-1', '8.17', 'Logging and monitoring', 'Time synchronisation'),
    cw: (t) => (/^\s*ntp-service (unicast-server|enable)|^\s*clock protocol ntp/m.test(t) ? pass() : fail(['no NTP server'])), ios: (t) => (/^\s*ntp server /m.test(t) ? pass() : fail(['no ntp server'])),
    fix: { cw: 'ntp-service enable ; ntp-service unicast-server <internal NTP> ; clock protocol ntp', ios: 'ntp server <internal NTP>' } },
  { id: 'SW-05', area: 'Administrator access', sev: 'critical', title: 'No local account with a plain-text password', refs: R('2-2-3', '8.5 / 8.24', 'Access control', 'Password storage'),
    cw: (t) => { const m = t.match(/^\s*password simple .*/gm) || []; return m.length ? fail([m.length + ' plain-text password line(s)']) : pass(); }, ios: (t) => (/^\s*(username \S+ password 0|enable password )/m.test(t) || !/service password-encryption/.test(t) ? fail(['plain or type-7 password storage']) : pass()),
    fix: { cw: 'local-user <name> class manage / password hash <..>  (re-enter with "password" interactively)', ios: 'username <u> secret <..> ; service password-encryption' } },
  { id: 'SW-06', area: 'Administrator access', sev: 'medium', title: 'Central authentication (RADIUS / TACACS+) for administrators', refs: R('2-2-3', '8.5', 'Access control', 'AAA'),
    cw: (t) => (/^\s*(radius|hwtacacs) scheme /m.test(t) ? pass() : fail(['local accounts only'])), ios: (t) => (/^\s*aaa new-model/m.test(t) && /(radius|tacacs)/.test(t) ? pass() : fail(['no AAA with RADIUS / TACACS+'])),
    fix: { cw: 'hwtacacs scheme <s> / primary authentication <server> ; domain <d> / authentication login hwtacacs-scheme <s> local', ios: 'aaa new-model ; aaa authentication login default group tacacs+ local' } },
  { id: 'SW-07', area: 'Administrator access', sev: 'medium', title: 'Idle sessions time out (≤ 10 minutes)', refs: R('2-2-3', '8.5', 'Access control', 'Idle timeout'),
    cw: (t) => { const m = [...t.matchAll(/idle-timeout (\d+)(?: (\d+))?/g)].map((x) => Number(x[1]) + Number(x[2] || 0) / 60); return !m.length ? fail(['default idle timeout (10 min) not set explicitly - check the VTY lines']) : m.some((x) => x === 0 || x > 10) ? fail(['idle-timeout ' + m.join(', ') + ' min']) : pass(); },
    ios: (t) => { const m = [...t.matchAll(/exec-timeout (\d+)(?: (\d+))?/g)].map((x) => Number(x[1])); return m.some((x) => x === 0 || x > 10) ? fail(['exec-timeout ' + m.join(', ')]) : pass(); },
    fix: { cw: 'line vty 0 63 / idle-timeout 10 0', ios: 'line vty 0 15 / exec-timeout 10 0' } },
  { id: 'SW-08', area: 'Hardening', sev: 'medium', title: 'Password recovery from the console is disabled', refs: R('2-3-1', '7.8', 'Hardening', 'Physical access'),
    cw: (t) => (/^\s*undo password-recovery enable/m.test(t) ? pass() : fail(['password recovery is on (default)'])), ios: () => na('Cisco: check "no service password-recovery" on the platform'),
    fix: { cw: 'undo password-recovery enable', ios: 'no service password-recovery' } },
  { id: 'SW-09', area: 'Administrator access', sev: 'low', title: 'A login warning banner is shown', refs: R('2-2-3', '5.10', 'Access control', 'Login banner'),
    cw: (t) => (/^\s*header (login|motd|shell)/m.test(t) ? pass() : fail(['no header'])), ios: (t) => (/^\s*banner (login|motd)/m.test(t) ? pass() : fail(['no banner'])), fix: { cw: 'header login % Authorised use only. %', ios: 'banner login ^Authorised use only.^' } },
];
function auditSwitch(c) {
  const kind = c.vendor === 'h3c-comware' ? 'cw' : 'ios', t = String(c.text || '');
  const tests = SW_TESTS.map((x) => { let r; if (!t) r = nc(c.error || 'configuration not captured yet'); else { try { r = x[kind](t); } catch (e) { r = nc('could not be evaluated'); } }
    return { id: x.id, area: x.area, severity: x.sev, title: x.title, result: r.result, evidence: r.evidence, more: 0, fix: r.result === 'fail' ? x.fix[kind] : '', refs: x.refs }; });
  return Object.assign({ id: String(c.id), name: String(c.name || c.id), kind: 'switch', vendor: c.vendor, model: '', site: c.site || '', firmware: '', read_at: c.at || null }, score(tests));
}

function score(tests) {
  const chk = tests.filter((t) => t.result === 'pass' || t.result === 'fail'), w = (t) => W[t.severity] || 1;
  const tot = chk.reduce((s, t) => s + w(t), 0), ok = chk.filter((t) => t.result === 'pass').reduce((s, t) => s + w(t), 0);
  const applicable = tests.filter((t) => t.result !== 'na').length;
  return { tests, score: tot ? Math.round(100 * ok / tot) : null, coverage: applicable ? Math.round(100 * chk.length / applicable) : 0,
    fails: { critical: 0, high: 0, medium: 0, low: 0, ...tests.filter((t) => t.result === 'fail').reduce((m, t) => { m[t.severity] = (m[t.severity] || 0) + 1; return m; }, {}) } };
}

// ---------- the audit: runs, acceptance, sign-off ----------
function createFwAudit({ fmg, configAudit, state, now }) {
  const NOW = now || Date.now, runs = state.collection('netops_fw_audit_runs'), acc = state.collection('netops_fw_audit_accept');
  const iso = () => new Date(NOW()).toISOString();
  async function run(by) {
    const F = typeof fmg === 'function' ? fmg() : fmg, at = iso(), devices = [], sources = {};
    if (F && typeof F.readAudit === 'function') {
      let fleet = []; try { fleet = (F.fleet() || {}).devices || []; } catch (e) { fleet = []; /* the fleet view is optional: lifecycle tests then say not checked */ }
      const byName = new Map(fleet.map((d) => [d.name, d]));
      try { const R0 = await F.readAudit(); sources.fortimanager = { ok: true, devices: R0.length }; for (const d of R0) devices.push(auditFortigate(Object.assign({}, d, { fleet: byName.get(d.dev && d.dev.name) || null }), NOW())); }
      catch (e) { sources.fortimanager = { ok: false, error: String(e.message || e).slice(0, 200) }; }
    } else sources.fortimanager = { ok: false, error: 'FortiManager not connected' };
    const caps = configAudit && typeof configAudit.list === 'function' ? configAudit.list().filter((c) => ['h3c-comware', 'cisco-ios'].includes(c.vendor)) : [];
    sources.switches = { ok: true, devices: caps.length };
    for (const c of caps) devices.push(auditSwitch(c));
    const evidence = crypto.createHash('sha256').update(JSON.stringify(devices)).digest('hex');
    const rec = { id: 'fwa-' + at.replace(/[^0-9]/g, '').slice(0, 14), at, by, sources, devices, sha256: evidence, signed_by: null, signed_at: null, note: '' };
    runs.put(rec);
    const all = runs.all().sort((a, b) => (a.at < b.at ? 1 : -1)); for (const old of all.slice(12)) runs.remove(old.id);
    return view();
  }
  function accepted() { const t = NOW(); return acc.all().filter((a) => Date.parse(a.until) >= t); }
  function decorate(r) {
    const A = new Map(accepted().map((a) => [a.device + '|' + a.test, a]));
    const devices = r.devices.map((d) => Object.assign({}, d, { tests: d.tests.map((t) => { const a = t.result === 'fail' && A.get(d.id + '|' + t.id); return a ? Object.assign({}, t, { accepted: { by: a.by, reason: a.reason, until: a.until } }) : t; }) }));
    const F = []; for (const d of devices) for (const t of d.tests) if (t.result === 'fail') F.push({ device: d.name, device_id: d.id, kind: d.kind, site: d.site, test: t.id, area: t.area, severity: t.severity, title: t.title, evidence: t.evidence, fix: t.fix, refs: t.refs, accepted: t.accepted || null });
    const sevRank = { critical: 0, high: 1, medium: 2, low: 3 }; F.sort((a, b) => sevRank[a.severity] - sevRank[b.severity] || a.device.localeCompare(b.device));
    const open = F.filter((f) => !f.accepted), scored = devices.filter((d) => d.score !== null);
    const byArea = {}; for (const d of devices) for (const t of d.tests) { const x = byArea[t.area] = byArea[t.area] || { area: t.area, pass: 0, fail: 0, not_checked: 0 }; if (t.result === 'pass') x.pass++; else if (t.result === 'fail') x.fail++; else if (t.result === 'not_checked') x.not_checked++; }
    const byTest = {}; for (const f of open) byTest[f.test] = byTest[f.test] || { test: f.test, title: f.title, severity: f.severity, devices: 0 }, byTest[f.test].devices++;
    return Object.assign({}, r, { devices, findings: F,
      kpis: { devices: devices.length, firewalls: devices.filter((d) => d.kind === 'firewall').length, switches: devices.filter((d) => d.kind === 'switch').length,
        score: scored.length ? Math.round(scored.reduce((s, d) => s + d.score, 0) / scored.length) : null, coverage: devices.length ? Math.round(devices.reduce((s, d) => s + d.coverage, 0) / devices.length) : 0,
        open: open.length, critical: open.filter((f) => f.severity === 'critical').length, high: open.filter((f) => f.severity === 'high').length, accepted: F.length - open.length,
        rules: devices.reduce((s, d) => s + (d.rulebase ? d.rulebase.total : 0), 0), any_any: devices.reduce((s, d) => s + (d.rulebase ? d.rulebase.any_any : 0), 0), unused: devices.reduce((s, d) => s + (d.rulebase ? d.rulebase.unused : 0), 0), shadowed: devices.reduce((s, d) => s + (d.rulebase ? d.rulebase.shadowed : 0), 0) },
      by_area: Object.values(byArea), top_failures: Object.values(byTest).sort((a, b) => b.devices - a.devices || sevRank[a.severity] - sevRank[b.severity]).slice(0, 10), insights: insights(devices, open) });
  }
  function insights(devices, open) {
    const out = [], p = (level, title, detail) => out.push({ level, title, detail });
    const crit = open.filter((f) => f.severity === 'critical'); if (crit.length) p('crit', crit.length + ' critical finding(s) on ' + new Set(crit.map((f) => f.device)).size + ' device(s)', 'Start with: ' + [...new Set(crit.map((f) => f.title))].slice(0, 3).join('; ') + '.');
    const same = {}; for (const f of open) (same[f.test] = same[f.test] || []).push(f.device);
    const fleetWide = Object.entries(same).filter(([, d]) => d.length >= 3 && d.length >= devices.length / 2); for (const [t, d] of fleetWide.slice(0, 3)) { const f = open.find((x) => x.test === t); p('warn', '"' + f.title + '" fails on ' + d.length + ' devices', 'One standard fixes them together: push it as a FortiManager template / CLI script or a switch baseline, then re-run the audit.'); }
    const low = devices.filter((d) => d.coverage < 70); if (low.length) p('info', low.length + ' device(s) only partly checked', 'Not checked is not a pass: ' + low.slice(0, 5).map((d) => d.name + ' ' + d.coverage + '%').join(', ') + ' - give the FortiManager API profile read access to System / Log / VPN, or capture the switch configuration.');
    const un = devices.filter((d) => d.rulebase && d.rulebase.unused >= 10); if (un.length) p('info', 'Rule-base clean-up', un.map((d) => d.name + ': ' + d.rulebase.unused + ' accept rules without hits').slice(0, 4).join('; ') + '. Fewer rules are easier to review and harder to misconfigure.');
    const worst = devices.filter((d) => d.score !== null).sort((a, b) => a.score - b.score)[0]; if (worst && worst.score < 60) p('warn', worst.name + ' scores ' + worst.score + '%', 'The weakest device - review it first.');
    return out;
  }
  function last() { return runs.all().sort((a, b) => (a.at < b.at ? 1 : -1))[0] || null; }
  function view() {
    const r = last(), F = typeof fmg === 'function' ? fmg() : fmg;
    const base = { connected: !!(F && typeof F.readAudit === 'function'), runs: runs.all().sort((a, b) => (a.at < b.at ? 1 : -1)).map((x) => ({ id: x.id, at: x.at, by: x.by, devices: x.devices.length, signed_by: x.signed_by, signed_at: x.signed_at, sha256: x.sha256 })), accepted: accepted() };
    if (!r) return Object.assign(base, { last: null, note: 'No audit run yet. Run the audit: every FortiGate in FortiManager and every switch whose configuration is captured are tested.' });
    return Object.assign(base, { last: decorate(r) });
  }
  function accept(b, who) {
    const r = last(); if (!r) throw new HttpError(409, 'run the audit first');
    const d = r.devices.find((x) => x.id === b.device || x.name === b.device); if (!d) throw new HttpError(400, 'device: not in the last audit');
    const t = d.tests.find((x) => x.id === b.test); if (!t) throw new HttpError(400, 'test: not an audit test'); if (t.result !== 'fail') throw new HttpError(409, t.id + ' did not fail on ' + d.name + ' - nothing to accept');
    const until = Date.parse(b.until); if (!(until > NOW())) throw new HttpError(400, 'until: a future date'); if (until > NOW() + 366 * DAY) throw new HttpError(400, 'until: at most one year - risk is reviewed again');
    if (t.severity === 'critical' && until > NOW() + 92 * DAY) throw new HttpError(400, 'until: a critical finding is accepted for at most three months');
    const rec = { id: (d.id + '|' + t.id).replace(/[^A-Za-z0-9_.:|-]/g, '_').slice(0, 120), device: d.id, device_name: d.name, test: t.id, severity: t.severity, reason: b.reason, until: new Date(until).toISOString().slice(0, 10), by: who, at: iso() };
    acc.put(rec); return rec;
  }
  function unaccept(b) { const id = (String(b.device) + '|' + String(b.test)).replace(/[^A-Za-z0-9_.:|-]/g, '_').slice(0, 120); const x = acc.get(id); if (!x) throw new HttpError(404, 'no acceptance for ' + b.device + ' ' + b.test); acc.remove(id); return x; }
  function signoff(b, who) {
    const r = runs.get(b.run); if (!r) throw new HttpError(404, 'run ' + b.run + ' not found');
    if (r.signed_by) throw new HttpError(409, 'run ' + r.id + ' is already signed off by ' + r.signed_by);
    if (String(r.by).toLowerCase() === String(who).toLowerCase()) throw new HttpError(403, 'four-eyes: ' + who + ' ran this audit - another person signs it off');
    if (crypto.createHash('sha256').update(JSON.stringify(r.devices)).digest('hex') !== r.sha256) throw new HttpError(409, 'the evidence of run ' + r.id + ' changed after it was taken - run the audit again');
    runs.patch(r.id, (o) => Object.assign(o, { signed_by: who, signed_at: iso(), note: b.note || '' })); return runs.get(r.id);
  }
  function csv() {
    const r = last(); if (!r) throw new HttpError(409, 'run the audit first');
    const v = decorate(r), q = (s) => '"' + String(s == null ? '' : s).replace(/"/g, '""').replace(/^([=+\-@])/, "'$1") + '"';
    const rows = [['run', 'device', 'site', 'test', 'severity', 'area', 'title', 'evidence', 'fix', 'NCA ECC', 'ISO 27001', 'Aramco CCC', 'CIS topic', 'accepted until', 'accepted by', 'reason'].map(q).join(',')];
    for (const f of v.findings) rows.push([r.id, f.device, f.site, f.test, f.severity, f.area, f.title, f.evidence.join(' | '), f.fix, f.refs.nca, f.refs.iso, f.refs.aramco, f.refs.cis, f.accepted ? f.accepted.until : '', f.accepted ? f.accepted.by : '', f.accepted ? f.accepted.reason : ''].map(q).join(','));
    return rows.join('\r\n') + '\r\n';
  }
  return { run, view, accept, unaccept, signoff, csv, last };
}

function register(api, deps) {
  const P = prefixOf(deps), N = deps.netopsInstance || {};
  const A = createFwAudit({ fmg: () => deps.fmgApi || null, configAudit: N.configAudit || null, state: deps.state, now: deps.now });
  deps.fwAudit = A;
  api.route('GET', `${P}/netops/fw-audit`, wrap(deps, 'analyst', () => A.view()));
  api.route('POST', `${P}/netops/fw-audit/run`, wrap(deps, 'operator', async (ctx) => { body(ctx.body || {}).done(); const v = await A.run(ctx.user); const r = v.last;
    audit(ctx, 'netops.fw_audit.run', r.id, { devices: r.devices.length, open: r.kpis.open, critical: r.kpis.critical, score: r.kpis.score, sha256: r.sha256 }); return v; }));
  api.route('POST', `${P}/netops/fw-audit/accept`, wrap(deps, 'approve:eng:security', (ctx) => {
    const b = body(ctx.body || {}).str('device', { required: true, max: 120 }).str('test', { required: true, max: 8, re: /^(FW|SW)-\d{2}$/, msg: 'test: an audit test id such as FW-03' }).str('reason', { required: true, min: 10, max: 400 }).str('until', { required: true, re: /^\d{4}-\d{2}-\d{2}$/, msg: 'until: YYYY-MM-DD' }).done();
    const a = A.accept(b, ctx.user); audit(ctx, 'netops.fw_audit.accept', a.id, { device: a.device_name, test: a.test, severity: a.severity, until: a.until, reason: a.reason }); return A.view(); }));
  api.route('POST', `${P}/netops/fw-audit/accept/remove`, wrap(deps, 'approve:eng:security', (ctx) => {
    const b = body(ctx.body || {}).str('device', { required: true, max: 120 }).str('test', { required: true, max: 8, re: /^(FW|SW)-\d{2}$/, msg: 'test: an audit test id' }).done();
    const a = A.unaccept(b); audit(ctx, 'netops.fw_audit.accept_remove', a.id, { device: a.device_name, test: a.test }); return A.view(); }));
  api.route('POST', `${P}/netops/fw-audit/signoff`, wrap(deps, 'approve:eng:security', (ctx) => {
    const b = body(ctx.body || {}).str('run', { required: true, max: 40, re: /^fwa-\d{14}$/, msg: 'run: an audit run id' }).str('note', { max: 600 }).done();
    const r = A.signoff(b, ctx.user); audit(ctx, 'netops.fw_audit.signoff', r.id, { ran_by: r.by, sha256: r.sha256, note: r.note || null }); return A.view(); }));
  api.route('GET', `${P}/netops/fw-audit/export`, wrap(deps, 'analyst', (ctx) => { const t = A.csv(); audit(ctx, 'netops.fw_audit.export', 'csv', { bytes: t.length }); return { csv: t, filename: 'firewall-audit-' + new Date().toISOString().slice(0, 10) + '.csv' }; }));
  // weekly, so the audit stays current between the auditors' runs; a failure is recorded by guard() and the next week tries again
  if (!deps.noTimers && !deps.noTimer && deps.config && (deps.config.netops || {}).fw_audit !== false) { const job = guard('netops.fw_audit.weekly', () => A.run('system:fw-audit')), t = setInterval(job, 7 * DAY); if (t.unref) t.unref(); }
  return A;
}

module.exports = { register, createFwAudit, auditFortigate, auditSwitch, shadowed, rules, FG_TESTS, SW_TESTS };
