// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('../util/brand');
/*
 * the organisation SIEM — SAFE synthetic detection-validation scenarios (DEFENSIVE).
 *
 * Each scenario is a small set of SYNTHETIC, clearly-benign log lines in the realistic field shape of the relevant
 * parser, mapped to the ATT&CK technique(s) and the rule it SHOULD trigger. The lines describe an attack pattern as
 * telemetry only — there is NO code here (or anywhere in this module) that performs a real attack, scan, exploit,
 * payload delivery or endpoint action. Nothing is sent on the network. The runner feeds these lines through a fresh
 * parser + an isolated detector to confirm the real rules fire.
 *
 * All indicators are obviously fake (sim.* users, 10.x "SIM-" hosts, *.test / *-sim domains, SIM- threat names).
 *
 *   scenario.build({ run_id, now }) → [{ line, meta }]   meta = { src_type, src_id }
 */

function iso(ms) { return new Date(ms).toISOString(); }
function winLine(now, i, eid, computer, provider, data) {
  return JSON.stringify(Object.assign({
    Channel: provider === 'Service Control Manager' ? 'System' : 'Security',
    EventID: eid, Computer: computer, ProviderName: provider || 'Microsoft-Windows-Security-Auditing',
    TimeCreated: iso(now + i * 1000),
  }, { EventData: data }));
}

// A descriptive, clearly-synthetic prefix for every scenario.
const SYN = 'SYNTHETIC — detection test, no real attack';

const SCENARIOS = [
  {
    id: 'win-bruteforce',
    name: 'Windows account brute force (4625 burst)',
    technique: 'T1110.001', techniques: ['T1110.001', 'T1110'],
    expect_rule: 'SENTRA-AUTH-001', source_class: 'windows', src_type: 'windows', severity: 3,
    description: 'A burst of 12 Windows 4625 failed-logon events for one account from one workstation — should trip the brute-force rule.',
    build({ now }) {
      const out = [];
      for (let i = 0; i < 12; i++) out.push({
        line: winLine(now, i, 4625, 'SIM-DC01', 'Microsoft-Windows-Security-Auditing', {
          TargetUserName: 'sim.bruteforce', TargetDomainName: 'SIMCORP', IpAddress: '10.80.80.80', IpPort: String(50000 + i),
          LogonType: 3, Status: '0xC000006D', SubStatus: '0xC000006A', WorkstationName: 'SIM-WS01',
        }),
        meta: { src_type: 'windows', src_id: 'bas-sim' },
      });
      return out;
    },
  },
  {
    id: 'win-password-spray',
    name: 'Windows password spraying (one source, many accounts)',
    technique: 'T1110.003', techniques: ['T1110.003', 'T1110'],
    expect_rule: 'SENTRA-AUTH-002', source_class: 'windows', src_type: 'windows', severity: 3,
    description: 'One source IP fails logon against 12 different synthetic accounts — should trip the password-spray rule.',
    build({ now }) {
      const out = [];
      for (let i = 0; i < 12; i++) out.push({
        line: winLine(now, i, 4625, 'SIM-DC01', 'Microsoft-Windows-Security-Auditing', {
          TargetUserName: 'sim.spray' + i, TargetDomainName: 'SIMCORP', IpAddress: '10.80.80.81', IpPort: String(51000 + i),
          LogonType: 3, Status: '0xC000006D', SubStatus: '0xC0000064', WorkstationName: 'SIM-WS02',
        }),
        meta: { src_type: 'windows', src_id: 'bas-sim' },
      });
      return out;
    },
  },
  {
    id: 'win-audit-log-cleared',
    name: 'Windows Security audit log cleared (1102)',
    technique: 'T1685.005', techniques: ['T1685.005'],
    expect_rule: 'SENTRA-SYS-001', source_class: 'windows', src_type: 'windows', severity: 4,
    description: 'A single synthetic Windows 1102 event (security audit log cleared) — should trip the log-clearing rule.',
    build({ now }) {
      return [{
        line: winLine(now, 0, 1102, 'SIM-DC01', 'Microsoft-Windows-Eventlog', { SubjectUserName: 'sim.admin', SubjectDomainName: 'DER3' }),
        meta: { src_type: 'windows', src_id: 'bas-sim' },
      }];
    },
  },
  {
    id: 'win-suspicious-service',
    name: 'Windows service installed from a suspicious path (7045)',
    technique: 'T1543.003', techniques: ['T1543.003', 'T1569.002'],
    expect_rule: 'SENTRA-SYS-003', source_class: 'windows', src_type: 'windows', severity: 4,
    description: 'A synthetic 7045 service install whose image path is under \\Windows\\Temp — should trip the suspicious-service rule (and the general service-installed rule).',
    build({ now }) {
      return [{
        line: winLine(now, 0, 7045, 'SIM-SVR01', 'Service Control Manager', {
          ServiceName: 'SimTestSvc', ImagePath: 'C:\\Windows\\Temp\\sim\\runner.exe -c powershell -nop',
          AccountName: 'LocalSystem', ServiceType: 'user mode service', StartType: 'auto start',
        }),
        meta: { src_type: 'windows', src_id: 'bas-sim' },
      }];
    },
  },
  {
    id: 'win-kerberoast',
    name: 'Kerberoasting — RC4 service tickets for many SPNs (4769)',
    technique: 'T1558.003', techniques: ['T1558.003'],
    expect_rule: 'SENTRA-CRED-005', source_class: 'windows', src_type: 'windows', severity: 4,
    description: 'One synthetic account requests RC4 (0x17) service tickets for 6 different SPNs — should trip the Kerberoasting rule (and the single RC4-ticket rule).',
    build({ now }) {
      const spns = [('MSSQLSvc/sim-db01.' + ZYB_ORG.domain + ':1433'), ('HTTP/sim-web01.' + ZYB_ORG.domain), ('CIFS/sim-fs01.' + ZYB_ORG.domain),
        ('LDAP/sim-dc02.' + ZYB_ORG.domain), ('HOST/sim-app01.' + ZYB_ORG.domain), ('MSSQLSvc/sim-db02.' + ZYB_ORG.domain + ':1433')];
      return spns.map((svc, i) => ({
        line: winLine(now, i, 4769, 'SIM-DC01', 'Microsoft-Windows-Security-Auditing', {
          TargetUserName: 'sim.svcacct@SIMCORP.EXAMPLE', TargetDomainName: 'SIMCORP', ServiceName: svc,
          TicketEncryptionType: '0x17', Status: '0x0', IpAddress: '10.50.50.50',
        }),
        meta: { src_type: 'windows', src_id: 'bas-sim' },
      }));
    },
  },
  {
    id: 'zscaler-malware-block',
    name: 'Zscaler blocked malware download (CEF)',
    technique: 'T1189', techniques: ['T1189', 'T1204.001'],
    expect_rule: 'SENTRA-ZSC-001', source_class: 'proxy', src_type: 'cef', severity: 3,
    description: 'A single synthetic Zscaler ZIA CEF line: a blocked web request carrying a (fake) threat — should trip the blocked-malware rule.',
    build() {
      return [{
        line: 'CEF:0|Zscaler|NSSWeblog|6.1|BLOCK|Malware Blocked|7|src=10.70.70.70 suser=sim.user act=Blocked '
          + 'request=http://sim-malware.test/payload.exe cs1Label=URL Category cs1=Malware '
          + 'cs2Label=Threat Name cs2=SIM-EICAR-Test-Signature cs3Label=Rule Label cs3=Block-Malware',
        meta: { src_type: 'cef', src_id: 'bas-sim' },
      }];
    },
  },
  {
    id: 'somansa-dlp-usb',
    name: 'Somansa DLP — repeated USB exfiltration on one host',
    technique: 'T1048', techniques: ['T1048', 'T1567', 'T1052'],
    expect_rule: 'SENTRA-SOM-001', source_class: 'dlp', src_type: 'somansa', severity: 3,
    description: '5 synthetic Somansa Privacy-i DLP incidents (USB channel, Block) on one endpoint within the hour — should trip the repeated-DLP rule.',
    build({ now }) {
      const out = [];
      for (let i = 0; i < 5; i++) out.push({
        line: `<134>Oct  8 10:0${i}:00 SIM-FIN07 Privacy-i: policy="Confidential-USB" action=Block channel=USB `
          + `file="sim-payroll${i}.xlsx" user=sim.dlp pc=SIM-FIN07 classification="National ID" severity=High incidentid=90000${i}`,
        meta: { src_type: 'somansa', src_id: 'bas-sim', rts: now + i * 1000 },
      });
      return out;
    },
  },
  {
    id: 'linux-ssh-bruteforce',
    name: 'Linux SSH brute force from one source',
    technique: 'T1110.001', techniques: ['T1110.001', 'T1021.004'],
    expect_rule: 'SENTRA-LNX-001', source_class: 'linux', src_type: 'linux', severity: 3,
    description: '21 synthetic sshd "Failed password" lines from one source IP within 5 minutes — should trip the SSH brute-force rule.',
    build({ now }) {
      const out = [];
      for (let i = 0; i < 21; i++) out.push({
        line: `<38>Oct  8 10:00:${String(i % 60).padStart(2, '0')} sim-web01 sshd[${1200 + i}]: Failed password for invalid user sim.ssh from 10.90.90.90 port ${50000 + i} ssh2`,
        meta: { src_type: 'linux', src_id: 'bas-sim', rts: now + i * 1000 },
      });
      return out;
    },
  },
  {
    id: 'control-no-rule',
    name: 'Control — benign event with no mapped rule (expect MISSED)',
    technique: 'T1200', techniques: ['T1200'],
    expect_rule: null, source_class: 'windows', src_type: 'windows', severity: 0, control: true,
    description: 'A benign synthetic Windows 4634 logoff. No detection rule matches it, so the expected result is MISSED — this validates that the runner reports MISSED (and never fabricates a detection).',
    build({ now }) {
      return [{
        line: winLine(now, 0, 4634, 'SIM-WS09', 'Microsoft-Windows-Security-Auditing', { TargetUserName: 'sim.user', TargetDomainName: 'SIMCORP', LogonType: 3 }),
        meta: { src_type: 'windows', src_id: 'bas-sim' },
      }];
    },
  },
];

const BY_ID = new Map(SCENARIOS.map((s) => [s.id, s]));

function meta(s) {
  return {
    id: s.id, name: s.name, synthetic: true, label: SYN,
    technique: s.technique, techniques: s.techniques.slice(),
    expect_rule: s.expect_rule, source_class: s.source_class, src_type: s.src_type,
    severity: s.severity, description: s.description, control: !!s.control,
  };
}

function list() { return SCENARIOS.map(meta); }
function get(id) { return BY_ID.get(id) || null; }

/** Scenarios whose techniques intersect the requested technique ids. */
function forTechniques(ids) {
  const want = new Set((ids || []).map(String));
  return SCENARIOS.filter((s) => s.techniques.some((t) => want.has(t)));
}

module.exports = { SCENARIOS, list, get, forTechniques, meta, SYN };
