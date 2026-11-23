// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// End-to-end field alignment: raw synthetic log lines → core parser router (engine/parse) → detector with the built-in
// rule pack. Proves the rule pack matches what the core parsers actually emit. Skipped when the core parser is absent.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { createDetector } = require('../engine/detect/engine');
const { loadBuiltinRules } = require('../engine/detect/ruleset');

const parserPath = path.join(__dirname, '..', 'engine', 'parse', 'index.js');
const haveParser = fs.existsSync(parserPath);

function run(lines, meta) {
  const { parse } = require(parserPath);
  const out = [];
  const d = createDetector({ rules: loadBuiltinRules(), onAlert: (a) => out.push(a) });
  let i = 0;
  for (const line of lines) {
    const m = Object.assign({ collector: 'syslog-udp', src_id: 'synthetic', peer_ip: '10.0.0.2', rts: Date.UTC(2026, 8, 29, 10, 0, 0) + i++ }, meta || {});
    const ev = parse(line, m);
    if (!ev.id) ev.id = `line-${i}`;
    d.onEvent(ev);
  }
  assert.equal(d.stats().errors, 0);
  return new Set(out.map((a) => a.rule_id));
}

test('linux sshd / sudo lines', { skip: !haveParser && 'core parser not present' }, () => {
  const lines = [];
  for (let i = 0; i < 20; i++) lines.push(`<38>Sep 29 13:00:${String(i).padStart(2, '0')} web01 sshd[${1000 + i}]: Failed password for invalid user test${i} from 198.51.100.7 port ${40000 + i} ssh2`);
  lines.push('<86>Sep 29 13:01:00 web01 sshd[2000]: Accepted publickey for root from 10.0.0.9 port 50000 ssh2');
  lines.push('<85>Sep 29 13:02:00 web01 sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/bash');
  for (let i = 0; i < 3; i++) lines.push(`<85>Sep 29 13:03:0${i} web01 sudo:    bob : 3 incorrect password attempts ; TTY=pts/1 ; PWD=/home/bob ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow`);
  lines.push('<86>Sep 29 13:04:00 web01 useradd[3000]: new user: name=backdoor, UID=1337, GID=1337, home=/home/backdoor, shell=/bin/bash');
  const fired = run(lines, { src_type: 'linux' });
  for (const id of ['SENTRA-LNX-001', 'SENTRA-AUTH-002', 'SENTRA-LNX-002', 'SENTRA-LNX-003', 'SENTRA-LNX-004', 'SENTRA-IAM-004']) assert.ok(fired.has(id), `${id} not fired (fired: ${[...fired].join(', ')})`);
});

test('FortiGate key=value lines', { skip: !haveParser && 'core parser not present' }, () => {
  const lines = [];
  for (let i = 0; i < 10; i++) lines.push(`<189>date=2026-09-29 time=13:00:0${i} devname="fw-hq-01" devid="FG100F" logid="0101039426" type="event" subtype="vpn" level="alert" vd="root" eventtime=${1790676000 + i} logdesc="SSL VPN login fail" action="ssl-login-fail" tunneltype="ssl-web" remip=203.0.113.99 user="vpn${i}" reason="sslvpn_login_permission_denied" msg="SSL user failed to logged in"`);
  lines.push('<185>date=2026-09-29 time=13:01:00 devname="fw-hq-01" devid="FG100F" logid="0419016384" type="utm" subtype="ips" eventtype="signature" level="alert" vd="root" severity="critical" srcip=203.0.113.77 dstip=10.0.5.10 srcport=4444 dstport=443 proto=6 action="dropped" attack="Apache.Log4j.Error.Log.Remote.Code.Execution" crlevel="critical"');
  for (let i = 0; i < 3; i++) lines.push(`<189>date=2026-09-29 time=13:0${i}:30 devname="fw-hq-01" devid="FG100F" logid="0000000013" type="traffic" subtype="forward" level="notice" srcip=10.1.2.3 dstip=198.51.100.200 srcport=5000${i} dstport=443 proto=6 action="close" policyid=12 sentbyte=${400 * 1024 * 1024} rcvdbyte=1000`);
  const fired = run(lines, { src_type: 'fortigate' });
  for (const id of ['SENTRA-FGT-005', 'SENTRA-FGT-001', 'SENTRA-EXFIL-001', 'SENTRA-AUTH-002']) assert.ok(fired.has(id), `${id} not fired (fired: ${[...fired].join(', ')})`);
});

test('Windows agent JSON events', { skip: !haveParser && 'core parser not present' }, () => {
  const w = (id, ed, extra) => JSON.stringify(Object.assign({ Channel: 'Security', ProviderName: 'Microsoft-Windows-Security-Auditing', EventID: id, Computer: 'DC01.corp.local', TimeCreated: '2026-09-29T10:00:00Z', EventData: ed }, extra || {}));
  const lines = [
    w(4625, { TargetUserName: 'olduser', TargetDomainName: 'CORP', LogonType: '3', IpAddress: '10.1.1.5', Status: '0xC000006E', SubStatus: '0xC0000072' }),
    w(4624, { TargetUserName: 'administrator', TargetDomainName: 'CORP', LogonType: '10', IpAddress: '198.51.100.20' }),
    w(4732, { SubjectUserName: 'helpdesk1', SubjectDomainName: 'CORP', MemberName: 'CN=Mallory,OU=Users,DC=corp,DC=local', MemberSid: 'S-1-5-21-1-2-3-1111', TargetUserName: 'Administrators', TargetDomainName: 'Builtin', TargetSid: 'S-1-5-32-544' }),
    w(1102, { SubjectUserName: 'mallory', SubjectDomainName: 'CORP' }),
    w(7045, { ServiceName: 'UpdSvc', ImagePath: 'C:\\Users\\Public\\upd.exe', ServiceType: 'user mode service', StartType: 'auto start', AccountName: 'LocalSystem' }, { Channel: 'System', ProviderName: 'Service Control Manager' }),
    w(4698, { SubjectUserName: 'bob', SubjectDomainName: 'CORP', TaskName: '\\Updater', TaskContent: '<Task><Actions><Exec><Command>C:\\Users\\Public\\u.exe</Command></Exec></Actions></Task>' }),
    w(4768, { TargetUserName: 'svc-legacy', TargetDomainName: 'CORP', IpAddress: '::ffff:10.1.1.9', Status: '0x0', PreAuthType: '0', TicketEncryptionType: '0x17' }),
    ...Array.from({ length: 5 }, (_, i) => w(4769, { TargetUserName: 'alice@CORP.LOCAL', ServiceName: `svc-sql${i}`, IpAddress: '::ffff:10.1.1.8', Status: '0x0', TicketEncryptionType: '0x17' })),
    w(4720, { SubjectUserName: 'admin1', SubjectDomainName: 'CORP', TargetUserName: 'svc-new', TargetDomainName: 'CORP', TargetSid: 'S-1-5-21-1-2-3-2222' }),
    w(4722, { SubjectUserName: 'admin1', SubjectDomainName: 'CORP', TargetUserName: 'svc-new', TargetDomainName: 'CORP', TargetSid: 'S-1-5-21-1-2-3-2222' }),
  ];
  const fired = run(lines, { src_type: 'windows', collector: 'agent' });
  for (const id of ['SENTRA-AUTH-004', 'SENTRA-AUTH-006', 'SENTRA-IAM-001', 'SENTRA-IAM-002', 'SENTRA-SYS-001', 'SENTRA-SYS-002', 'SENTRA-SYS-003', 'SENTRA-SYS-004', 'SENTRA-CRED-006', 'SENTRA-CRED-004', 'SENTRA-CRED-005', 'SENTRA-IAM-003', 'SENTRA-IAM-004']) {
    assert.ok(fired.has(id), `${id} not fired (fired: ${[...fired].join(', ')})`);
  }
});

test('nginx access lines', { skip: !haveParser && 'core parser not present' }, () => {
  const l = (ip, url, status, ua) => `${ip} - - [29/Sep/2026:13:00:00 +0300] "GET ${url} HTTP/1.1" ${status} 512 "-" "${ua || 'Mozilla/5.0'}"`;
  const lines = [l('203.0.113.52', '/login?user=admin%27--', 200), l('203.0.113.53', '/download?file=../../../../etc/passwd', 200), l('203.0.113.55', '/', 200, 'sqlmap/1.7.2#stable (https://sqlmap.org)')];
  for (let i = 0; i < 50; i++) lines.push(l('203.0.113.50', `/admin${i}.php`, 404));
  const fired = run(lines, { src_type: 'nginx' });
  for (const id of ['SENTRA-WEB-001', 'SENTRA-WEB-002', 'SENTRA-WEB-003', 'SENTRA-WEB-005']) assert.ok(fired.has(id), `${id} not fired (fired: ${[...fired].join(', ')})`);
});
