// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Windows events as sent by our Windows agent (JSON):
//   {Channel, EventID, TimeCreated, Computer, RecordId, Level, ProviderName, EventData:{…}, Message?}
// EventData may also arrive as [{Name, Value}] (Get-WinEvent XML conversion). TimeCreated may be ISO or "/Date(ms)/".
const { parseTime, toInt, ipOrEmpty, splitUser, clean, firstLine, safeJson, protoName } = require('./util');
const exchange = require('./exchange');

const LOGON_TYPES = { 2: 'interactive', 3: 'network', 4: 'batch', 5: 'service', 7: 'unlock', 8: 'network-cleartext', 9: 'new-credentials', 10: 'remote-interactive', 11: 'cached-interactive', 12: 'cached-remote-interactive', 13: 'cached-unlock' };
const NTSTATUS = {
  '0xc000006a': 'bad password', '0xc0000064': 'no such user', '0xc000006d': 'bad username or password', '0xc0000234': 'account locked',
  '0xc0000072': 'account disabled', '0xc000006f': 'outside logon hours', '0xc0000070': 'workstation restriction', '0xc0000071': 'password expired',
  '0xc0000193': 'account expired', '0xc0000224': 'password must change', '0xc0000133': 'clock skew', '0xc000015b': 'logon type not granted',
  '0x6': 'unknown principal', '0x12': 'account disabled/expired/locked', '0x17': 'password expired', '0x18': 'bad password (pre-auth)', '0x25': 'clock skew',
};
const ADMIN_GROUP_RE = /(^|\\)(administrators|domain admins|enterprise admins|schema admins|account operators|backup operators|server operators|print operators|dnsadmins|group policy creator owners|remote desktop users|key admins|enterprise key admins)$/i;
const LEVEL_SEV = { 1: 4, 2: 3, 3: 2 };
const LEVEL_NAMES = { critical: 1, error: 2, warning: 3, information: 4, verbose: 5 };

function eventData(o) {
  let ed = o.EventData ?? o.eventData ?? o.Properties ?? o.UserData;
  if (typeof ed === 'string') ed = safeJson(ed) || {};
  if (Array.isArray(ed)) {
    const out = {};
    for (const it of ed) if (it && it.Name !== undefined) out[it.Name] = it.Value ?? it['#text'] ?? '';
    return out;
  }
  if (ed && typeof ed === 'object') {
    // UserData (e.g. 1102 LogFileCleared) nests one level
    const keys = Object.keys(ed);
    if (keys.length === 1 && ed[keys[0]] && typeof ed[keys[0]] === 'object' && !Array.isArray(ed[keys[0]])) return { ...ed[keys[0]] };
    return { ...ed };
  }
  return {};
}

const s = (v) => clean(v);
const low = (v) => clean(v).toLowerCase();
const exe = (p) => { const m = /^"([^"]+)"|^(\S+)/.exec(clean(p)); return m ? (m[1] || m[2]) : ''; };
const statusStr = (v) => { const x = clean(v).toLowerCase(); return x.startsWith('0x') ? x : (x ? '0x' + Number(x).toString(16) : ''); };
const isOk = (st) => !st || st === '0x0' || st === '0x00000000';

function hashes(h) {
  const out = {};
  for (const part of clean(h).split(',')) { const [k, v] = part.split('='); if (k && v) out[k.trim().toLowerCase()] = v.trim().toLowerCase(); }
  return out;
}

// Command-line / image heuristics → MITRE technique tags
function procTags(image, cmd) {
  const t = [];
  const img = String(image || '').toLowerCase();
  const c = String(cmd || '').toLowerCase();
  const base = img.split('\\').pop();
  if ((base === 'powershell.exe' || base === 'pwsh.exe') && /\s-(e|en|enc|enco|encodedcommand)\s/.test(c + ' ')) t.push('T1059.001', 'encoded-command');
  if (base === 'certutil.exe' && /(urlcache|-decode|verifyctl)/.test(c)) t.push('T1105');
  if (/vssadmin(\.exe)?\s+delete\s+shadows|wmic(\.exe)?\s+shadowcopy\s+delete|bcdedit.*recoveryenabled\s+no|wbadmin\s+delete\s+catalog/.test(c)) t.push('T1490');
  if (base === 'mshta.exe') t.push('T1218.005');
  if (base === 'regsvr32.exe' && /\/i:|scrobj/.test(c)) t.push('T1218.010');
  if (base === 'rundll32.exe' && /comsvcs(\.dll)?.*minidump/.test(c)) t.push('T1003.001');
  else if (base === 'rundll32.exe') t.push('T1218.011');
  if (/procdump.*lsass|sekurlsa|mimikatz/.test(c)) t.push('T1003.001');
  if (base === 'wevtutil.exe' && /\s(cl|clear-log)\s/.test(c + ' ')) t.push('T1685.005');
  if (base === 'schtasks.exe' && /\/create/.test(c)) t.push('T1053.005');
  if (/reg(\.exe)?\s+add\s+.*\\currentversion\\run/.test(c)) t.push('T1547.001');
  if ((base === 'net.exe' || base === 'net1.exe') && /\s(user|group|localgroup)\b/.test(c)) t.push('T1087');
  if (base === 'whoami.exe') t.push('T1033');
  return t;
}

function userInto(ev, key, u, d) {
  const x = splitUser(u, d);
  ev[key] = x.user;
  if (key === 'user' && x.domain) ev.domain = x.domain;
  return x;
}

function logonCommon(ev, ed) {
  userInto(ev, 'user', ed.TargetUserName, ed.TargetDomainName);
  ev.src_ip = ipOrEmpty(ed.IpAddress);
  ev.src_port = toInt(ed.IpPort);
  ev.process = s(ed.ProcessName);
  const lt = toInt(ed.LogonType);
  if (lt) { ev.fields.logon_type = String(lt); ev.fields.logon_type_name = LOGON_TYPES[lt] || ''; }
  if (lt === 10) ev.tags.push('rdp');
  if (s(ed.WorkstationName)) ev.fields.workstation = s(ed.WorkstationName);
  if (s(ed.SubjectUserName)) ev.fields.subject_user = low(ed.SubjectUserName);
  if (s(ed.AuthenticationPackageName)) ev.fields.auth_package = s(ed.AuthenticationPackageName);
  return lt;
}

function groupAdd(ev, ed) {
  Object.assign(ev, { category: 'iam', action: 'group-member-added', outcome: 'success', severity: 2 });
  userInto(ev, 'user', ed.SubjectUserName, ed.SubjectDomainName);
  const dn = s(ed.MemberName);
  const cn = /^CN=((?:\\,|[^,])+)/i.exec(dn);
  ev.target_user = (cn ? cn[1].replace(/\\,/g, ',') : dn || s(ed.MemberSid)).toLowerCase();
  const group = s(ed.TargetUserName);
  ev.fields.group = group;
  ev.fields.group_domain = s(ed.TargetDomainName);
  ev.fields.member_sid = s(ed.MemberSid);
  ev.tags.push('T1098');
  if (ADMIN_GROUP_RE.test(group)) { ev.severity = 3; ev.tags.push('admin'); }
  ev.message = `${ev.target_user} added to group ${group} by ${ev.user}`;
}

function kerbFail(ev, st) {
  ev.fields.status = st;
  if (NTSTATUS[st]) ev.fields.failure_reason = NTSTATUS[st];
}

const SEC = {
  4624(ev, ed) {
    Object.assign(ev, { category: 'authentication', action: 'logon', outcome: 'success' });
    const lt = logonCommon(ev, ed);
    if (s(ed.ElevatedToken) === '%%1842' || s(ed.ElevatedToken).toLowerCase() === 'yes') ev.fields.elevated = 'true';
    ev.message = `Logon ${ev.user}${ev.src_ip ? ' from ' + ev.src_ip : ''} (type ${lt || '?'})`;
  },
  4625(ev, ed) {
    Object.assign(ev, { category: 'authentication', action: 'logon-failed', outcome: 'failure', severity: 1 });
    const lt = logonCommon(ev, ed);
    const st = statusStr(ed.SubStatus) && !isOk(statusStr(ed.SubStatus)) ? statusStr(ed.SubStatus) : statusStr(ed.Status);
    ev.fields.status = statusStr(ed.Status);
    ev.fields.sub_status = statusStr(ed.SubStatus);
    ev.fields.failure_reason = NTSTATUS[st] || s(ed.FailureReason);
    ev.tags.push('T1110');
    ev.message = `Logon failed for ${ev.user}${ev.src_ip ? ' from ' + ev.src_ip : ''} (type ${lt || '?'}${ev.fields.failure_reason ? ', ' + ev.fields.failure_reason : ''})`;
  },
  4634(ev, ed) { Object.assign(ev, { category: 'authentication', action: 'logoff', outcome: 'success' }); logonCommon(ev, ed); },
  4647(ev, ed) { Object.assign(ev, { category: 'authentication', action: 'logoff', outcome: 'success' }); logonCommon(ev, ed); ev.fields.user_initiated = 'true'; },
  4648(ev, ed) {
    Object.assign(ev, { category: 'authentication', action: 'logon-explicit', outcome: 'success' });
    userInto(ev, 'user', ed.SubjectUserName, ed.SubjectDomainName);
    ev.target_user = splitUser(ed.TargetUserName, ed.TargetDomainName).user;
    ev.src_ip = ipOrEmpty(ed.IpAddress);
    ev.src_port = toInt(ed.IpPort);
    ev.process = s(ed.ProcessName);
    ev.fields.target_server = s(ed.TargetServerName);
    ev.message = `${ev.user} used explicit credentials of ${ev.target_user}${ev.fields.target_server ? ' for ' + ev.fields.target_server : ''}`;
  },
  4672(ev, ed) {
    Object.assign(ev, { category: 'authentication', action: 'privileges-assigned', outcome: 'success' });
    userInto(ev, 'user', ed.SubjectUserName, ed.SubjectDomainName);
    ev.fields.privileges = s(ed.PrivilegeList).replace(/\s+/g, ' ');
    ev.tags.push('admin');
  },
  4688(ev, ed) {
    Object.assign(ev, { category: 'process', action: 'process-start', outcome: 'success' });
    userInto(ev, 'user', ed.SubjectUserName, ed.SubjectDomainName);
    const tu = splitUser(ed.TargetUserName, ed.TargetDomainName).user;
    if (tu) ev.target_user = tu;
    ev.process = s(ed.NewProcessName);
    ev.parent_process = s(ed.ParentProcessName);
    ev.cmdline = s(ed.CommandLine);
    ev.fields.process_id = s(ed.NewProcessId);
    ev.fields.parent_process_id = s(ed.ProcessId);
    ev.fields.token_elevation = s(ed.TokenElevationType);
    ev.fields.mandatory_label = s(ed.MandatoryLabel);
    ev.tags.push(...procTags(ev.process, ev.cmdline));
    ev.message = `Process ${ev.process.split('\\').pop()} started by ${ev.user}`;
  },
  4697(ev, ed) {
    Object.assign(ev, { category: 'system', action: 'service-installed', outcome: 'success', severity: 2 });
    userInto(ev, 'user', ed.SubjectUserName, ed.SubjectDomainName);
    ev.cmdline = s(ed.ServiceFileName);
    ev.process = exe(ed.ServiceFileName);
    ev.fields.service_name = s(ed.ServiceName);
    ev.fields.service_account = s(ed.ServiceAccount);
    ev.fields.start_type = s(ed.ServiceStartType);
    ev.tags.push('T1543.003');
    ev.message = `Service installed: ${ev.fields.service_name} (${ev.cmdline})`.slice(0, 300);
  },
  4698(ev, ed) {
    Object.assign(ev, { category: 'system', action: 'scheduled-task-created', outcome: 'success', severity: 2 });
    userInto(ev, 'user', ed.SubjectUserName, ed.SubjectDomainName);
    ev.fields.task_name = s(ed.TaskName);
    const xml = s(ed.TaskContent);
    ev.fields.task_content = xml.slice(0, 4000);
    const cmd = /<Command>([^<]*)<\/Command>/i.exec(xml);
    const args = /<Arguments>([^<]*)<\/Arguments>/i.exec(xml);
    if (cmd) { ev.process = cmd[1].trim(); ev.cmdline = (cmd[1] + (args ? ' ' + args[1] : '')).trim(); }
    ev.tags.push('T1053.005', ...procTags(ev.process, ev.cmdline));
    ev.message = `Scheduled task created: ${ev.fields.task_name} by ${ev.user}`;
  },
  4720(ev, ed) { iam(ev, ed, 'user-created', 2, ['T1136']); },
  4722(ev, ed) { iam(ev, ed, 'user-enabled', 1); },
  4723(ev, ed) { iam(ev, ed, 'password-change', 0); },
  4724(ev, ed) { iam(ev, ed, 'password-reset', 1, ['T1098']); },
  4725(ev, ed) { iam(ev, ed, 'user-disabled', 1); },
  4726(ev, ed) { iam(ev, ed, 'user-deleted', 2); },
  4728: groupAdd, 4732: groupAdd, 4756: groupAdd,
  4740(ev, ed) {
    Object.assign(ev, { category: 'iam', action: 'account-locked', outcome: 'success', severity: 2 });
    ev.target_user = low(ed.TargetUserName);
    userInto(ev, 'user', ed.SubjectUserName, ed.SubjectDomainName);
    ev.fields.caller_computer = s(ed.TargetDomainName);
    ev.tags.push('T1110');
    ev.message = `Account locked out: ${ev.target_user}${ev.fields.caller_computer ? ' (caller ' + ev.fields.caller_computer + ')' : ''}`;
  },
  4768(ev, ed) {
    const st = statusStr(ed.Status);
    const ok = isOk(st);
    Object.assign(ev, { category: 'authentication', action: ok ? 'kerberos-tgt' : 'logon-failed', outcome: ok ? 'success' : 'failure' });
    userInto(ev, 'user', ed.TargetUserName, ed.TargetDomainName);
    ev.src_ip = ipOrEmpty(ed.IpAddress);
    ev.src_port = toInt(ed.IpPort);
    ev.fields.auth_protocol = 'kerberos';
    ev.fields.ticket_encryption = s(ed.TicketEncryptionType);
    ev.fields.preauth_type = s(ed.PreAuthType);
    if (!ok) { kerbFail(ev, st); ev.severity = 1; ev.tags.push('T1110'); }
    if (ok && s(ed.PreAuthType) === '0') { ev.tags.push('T1558.004'); ev.severity = 2; }
  },
  4769(ev, ed) {
    const st = statusStr(ed.Status);
    const ok = isOk(st);
    Object.assign(ev, { category: 'authentication', action: 'kerberos-service-ticket', outcome: ok ? 'success' : 'failure' });
    const x = splitUser(ed.TargetUserName, ed.TargetDomainName);
    ev.user = x.user.replace(/@.*$/, '');
    ev.domain = x.domain;
    ev.src_ip = ipOrEmpty(ed.IpAddress);
    ev.src_port = toInt(ed.IpPort);
    const svc = s(ed.ServiceName);
    const enc = s(ed.TicketEncryptionType).toLowerCase();
    Object.assign(ev.fields, { service_name: svc, ticket_encryption: enc, auth_protocol: 'kerberos' });
    if (!ok) kerbFail(ev, st);
    if (ok && (enc === '0x17' || enc === '0x18') && svc && !svc.endsWith('$') && svc.toLowerCase() !== 'krbtgt') { ev.tags.push('T1558.003'); ev.severity = 2; }
  },
  4771(ev, ed) {
    Object.assign(ev, { category: 'authentication', action: 'logon-failed', outcome: 'failure', severity: 1 });
    userInto(ev, 'user', ed.TargetUserName, ed.TargetDomainName);
    ev.src_ip = ipOrEmpty(ed.IpAddress);
    ev.src_port = toInt(ed.IpPort);
    ev.fields.auth_protocol = 'kerberos';
    kerbFail(ev, statusStr(ed.Status));
    ev.tags.push('T1110');
  },
  4776(ev, ed) {
    const st = statusStr(ed.Status);
    const ok = isOk(st);
    Object.assign(ev, { category: 'authentication', action: ok ? 'credential-validated' : 'logon-failed', outcome: ok ? 'success' : 'failure', severity: ok ? 0 : 1 });
    ev.user = low(ed.TargetUserName);
    ev.fields.workstation = s(ed.Workstation);
    ev.fields.auth_protocol = 'ntlm';
    if (!ok) { kerbFail(ev, st); ev.tags.push('T1110'); }
  },
  1102(ev, ed) {
    Object.assign(ev, { category: 'system', action: 'audit-log-cleared', outcome: 'success', severity: 3 });
    userInto(ev, 'user', ed.SubjectUserName, ed.SubjectDomainName);
    ev.tags.push('T1685.005');
    ev.message = `Security audit log cleared by ${ev.user || 'unknown'}`;
  },
  7045(ev, ed) {
    Object.assign(ev, { category: 'system', action: 'service-installed', outcome: 'success', severity: 2 });
    ev.cmdline = s(ed.ImagePath);
    ev.process = exe(ed.ImagePath);
    ev.fields.service_name = s(ed.ServiceName);
    ev.fields.service_account = s(ed.AccountName);
    ev.fields.service_type = s(ed.ServiceType);
    ev.fields.start_type = s(ed.StartType);
    ev.tags.push('T1543.003', ...procTags(ev.process, ev.cmdline));
    ev.message = `Service installed: ${ev.fields.service_name} (${ev.cmdline})`.slice(0, 300);
  },
  4104(ev, ed) {
    Object.assign(ev, { category: 'process', action: 'script-block', outcome: 'success' });
    const text = s(ed.ScriptBlockText);
    ev.cmdline = text.slice(0, 32768);
    ev.process = 'powershell';
    ev.fields.script_block_id = s(ed.ScriptBlockId);
    ev.fields.script_path = s(ed.Path);
    ev.fields.message_number = s(ed.MessageNumber);
    ev.fields.message_total = s(ed.MessageTotal);
    ev.tags.push('T1059.001');
    if (/invoke-mimikatz|sekurlsa|amsiutils|amsiinitfailed|invoke-shellcode|invoke-reflectivepeinjection|virtualalloc.*createthread/i.test(text)) { ev.severity = 3; ev.tags.push('suspicious-script'); }
    else if (/downloadstring|downloadfile|invoke-webrequest|net\.webclient|frombase64string|\biex\b|invoke-expression|-bxor|reflection\.assembly/i.test(text)) { ev.severity = 2; ev.tags.push('suspicious-script'); }
    ev.message = `PowerShell script block${ev.fields.script_path ? ' ' + ev.fields.script_path : ''}: ${firstLine(text, 150)}`;
  },
  // Network Policy Server (RADIUS) — Security log, "Audit Network Policy Server" subcategory:
  // 6272 granted access, 6273 denied access, 6274 request discarded, 6275 discarded accounting, 6276 quarantined,
  // 6277 probation, 6278 full access, 6279 locked out, 6280 unlocked. EventData names per the NPS event schema.
  6272(ev, ed) { nps(ev, ed, 'logon', 'success', 0); ev.message = `RADIUS access granted to ${ev.user}${ev.fields.calling_station ? ' (' + ev.fields.calling_station + ')' : ''} via ${ev.fields.nas_identifier || ev.fields.nas_ip || '?'}`; },
  6273(ev, ed) {
    nps(ev, ed, 'logon-failed', 'failure', 1);
    ev.tags.push('T1110');
    ev.message = `RADIUS access denied to ${ev.user}${ev.fields.calling_station ? ' (' + ev.fields.calling_station + ')' : ''} via ${ev.fields.nas_identifier || ev.fields.nas_ip || '?'}${ev.fields.reason ? ': ' + ev.fields.reason : ''}`;
  },
  6274(ev, ed) { nps(ev, ed, 'event', 'failure', 1); ev.fields.radius_result = 'discarded'; ev.message = `RADIUS request discarded for ${ev.user || '?'} via ${ev.fields.nas_identifier || ev.fields.nas_ip || '?'}${ev.fields.reason ? ': ' + ev.fields.reason : ''}`; },
  6275(ev, ed) { nps(ev, ed, 'event', 'failure', 0); ev.fields.radius_result = 'accounting-discarded'; },
  6276(ev, ed) { nps(ev, ed, 'logon', 'success', 1); ev.fields.radius_result = 'quarantined'; },
  6277(ev, ed) { nps(ev, ed, 'logon', 'success', 1); ev.fields.radius_result = 'probation'; },
  6278(ev, ed) { nps(ev, ed, 'logon', 'success', 0); ev.fields.radius_result = 'full-access'; },
  6279(ev, ed) { nps(ev, ed, 'account-locked', 'failure', 2); ev.category = 'iam'; ev.tags.push('T1110'); ev.message = `NPS locked out ${ev.user}`; },
  6280(ev, ed) { nps(ev, ed, 'user-modified', 'success', 1); ev.category = 'iam'; ev.fields.radius_result = 'unlocked'; },
};

// NPS/RADIUS common EventData: SubjectUserName/Domain = the authenticating account, ClientIPAddress/ClientName = the
// RADIUS client (NAS) as registered on the NPS, NASIPv4Address/NASIdentifier = as reported by the NAS, CallingStationID = the
// end device (MAC for 802.1X / Wi-Fi, IP for VPN), CalledStationID = the SSID / NAS port, Reason/ReasonCode on 6273.
function nps(ev, ed, action, outcome, sev) {
  Object.assign(ev, { category: 'authentication', action, outcome, severity: Math.max(ev.severity, sev) });
  userInto(ev, 'user', ed.SubjectUserName, ed.SubjectDomainName);
  if (!ev.user && s(ed.FullyQualifiedSubjectUserName)) userInto(ev, 'user', ed.FullyQualifiedSubjectUserName);
  ev.src_ip = ipOrEmpty(ed.ClientIPAddress) || ipOrEmpty(ed.NASIPv4Address) || ipOrEmpty(ed.NASIPv6Address);
  const calling = s(ed.CallingStationID);
  Object.assign(ev.fields, {
    auth_protocol: 'radius', nas_ip: s(ed.NASIPv4Address) || s(ed.NASIPv6Address), nas_identifier: s(ed.NASIdentifier), nas_port_type: s(ed.NASPortType), nas_port: s(ed.NASPort),
    radius_client: s(ed.ClientName), radius_client_ip: s(ed.ClientIPAddress), calling_station: calling, called_station: s(ed.CalledStationID),
    network_policy: s(ed.NetworkPolicyName), connection_request_policy: s(ed.ProxyPolicyName), auth_type: s(ed.AuthenticationType), eap_type: s(ed.EAPType),
    auth_provider: s(ed.AuthenticationProvider), auth_server: s(ed.AuthenticationServer), reason_code: s(ed.ReasonCode), reason: s(ed.Reason),
    subject_machine: s(ed.SubjectMachineName) || s(ed.FullyQualifiedSubjectMachineName), logging_result: s(ed.LoggingResult),
  });
  if (!ev.src_ip && /^\d{1,3}(?:\.\d{1,3}){3}$/.test(calling)) ev.src_ip = ipOrEmpty(calling); // VPN NAS report the client IP as Calling-Station-Id
  ev.tags.push('radius', 'nps');
}

function iam(ev, ed, action, sev, tags = []) {
  Object.assign(ev, { category: 'iam', action, outcome: 'success', severity: sev });
  userInto(ev, 'user', ed.SubjectUserName, ed.SubjectDomainName);
  ev.target_user = splitUser(ed.TargetUserName, ed.TargetDomainName).user;
  ev.fields.target_domain = low(ed.TargetDomainName);
  ev.fields.target_sid = s(ed.TargetSid);
  ev.tags.push(...tags);
  ev.message = `${action.replace(/-/g, ' ')}: ${ev.target_user} by ${ev.user}`;
}

function sysmonProc(ev, ed) {
  ev.process = s(ed.Image);
  if (ed.User) userInto(ev, 'user', ed.User);
  ev.fields.process_id = s(ed.ProcessId);
  ev.fields.process_guid = s(ed.ProcessGuid);
}

const SYSMON = {
  1(ev, ed) {
    Object.assign(ev, { category: 'process', action: 'process-start', outcome: 'success' });
    sysmonProc(ev, ed);
    ev.parent_process = s(ed.ParentImage);
    ev.cmdline = s(ed.CommandLine);
    const h = hashes(ed.Hashes);
    ev.hash = h.sha256 || h.md5 || h.sha1 || h.imphash || '';
    Object.assign(ev.fields, {
      hashes: s(ed.Hashes), parent_cmdline: s(ed.ParentCommandLine), current_directory: s(ed.CurrentDirectory),
      integrity_level: s(ed.IntegrityLevel), original_file_name: s(ed.OriginalFileName), parent_process_id: s(ed.ParentProcessId),
      company: s(ed.Company), description: s(ed.Description),
    });
    if (ed.ParentUser) ev.fields.parent_user = low(ed.ParentUser);
    ev.tags.push(...procTags(ev.process, ev.cmdline));
    ev.message = `Process ${ev.process.split('\\').pop()} started by ${ev.user} (parent ${ev.parent_process.split('\\').pop()})`;
  },
  3(ev, ed) {
    Object.assign(ev, { category: 'network', action: 'connection', outcome: 'success' });
    sysmonProc(ev, ed);
    ev.src_ip = ipOrEmpty(ed.SourceIp);
    ev.dst_ip = ipOrEmpty(ed.DestinationIp);
    ev.src_port = toInt(ed.SourcePort);
    ev.dst_port = toInt(ed.DestinationPort);
    ev.proto = protoName(ed.Protocol);
    Object.assign(ev.fields, { dst_hostname: s(ed.DestinationHostname), src_hostname: s(ed.SourceHostname), initiated: s(ed.Initiated), dst_port_name: s(ed.DestinationPortName) });
    ev.message = `${ev.process.split('\\').pop()} → ${ev.dst_ip}:${ev.dst_port}${ev.fields.dst_hostname ? ' (' + ev.fields.dst_hostname + ')' : ''}`;
  },
  11(ev, ed) {
    Object.assign(ev, { category: 'file', action: 'file-created', outcome: 'success' });
    sysmonProc(ev, ed);
    const f = s(ed.TargetFilename);
    ev.fields.target_filename = f;
    if (/\\start menu\\programs\\startup\\/i.test(f)) { ev.tags.push('T1547.001'); ev.severity = 2; }
    ev.message = `File created: ${f}`.slice(0, 300);
  },
  13(ev, ed) {
    Object.assign(ev, { category: 'registry', action: 'registry-set', outcome: 'success' });
    sysmonProc(ev, ed);
    const k = s(ed.TargetObject);
    Object.assign(ev.fields, { target_object: k, details: s(ed.Details), event_type: s(ed.EventType) });
    if (/\\currentversion\\(run|runonce|runservices)(once)?\\/i.test(k) || /\\winlogon\\(userinit|shell)$/i.test(k)) { ev.tags.push('T1547.001'); ev.severity = 2; }
    ev.message = `Registry value set: ${k}`.slice(0, 300);
  },
  10(ev, ed) {
    Object.assign(ev, { category: 'process', action: 'process-access', outcome: 'success' });
    ev.process = s(ed.SourceImage);
    if (ed.SourceUser) userInto(ev, 'user', ed.SourceUser);
    Object.assign(ev.fields, { target_image: s(ed.TargetImage), granted_access: s(ed.GrantedAccess).toLowerCase() });
    if (/\\lsass\.exe$/i.test(s(ed.TargetImage))) { ev.tags.push('T1003.001'); ev.severity = 2; }
    ev.message = `${ev.process.split('\\').pop()} accessed ${s(ed.TargetImage).split('\\').pop()} (${ev.fields.granted_access})`;
  },
  22(ev, ed) {
    Object.assign(ev, { category: 'dns', action: 'dns-query', outcome: s(ed.QueryStatus) && s(ed.QueryStatus) !== '0' ? 'failure' : 'success' });
    sysmonProc(ev, ed);
    ev.dns_query = low(ed.QueryName);
    Object.assign(ev.fields, { query_results: s(ed.QueryResults).slice(0, 2000), query_status: s(ed.QueryStatus) });
    ev.message = `DNS query ${ev.dns_query} by ${ev.process.split('\\').pop()}`;
  },
};

// Exchange on-prem admin audit: channel "MSExchange Management", provider "MSExchange CmdletLogs",
// EventID 1 = cmdlet succeeded, 6 = cmdlet failed. EventData (unnamed) Data0 = cmdlet, Data1 = parameters, Data2 = caller;
// the rendered Message ("Cmdlet suceeded. Cmdlet Set-Mailbox, parameters -Identity …") is the fallback.
// → action "exchange-cmdlet"; fields.cmdlet / fields.parameters / fields.params.<Name> / fields.exchange_action
// (classification shared with Exchange Online, parse/exchange.js). fields.Operation / fields.Parameters mirror the
// Exchange Online record names so the same detection rules match both.
function exchangeMgmt(ev, ed, o, eid) {
  let cmdlet = s(ed.Data0);
  let params = s(ed.Data1);
  const caller = s(ed.Data2);
  if (!cmdlet || !/^[A-Za-z]+-[A-Za-z]/.test(cmdlet)) {
    const m = /Cmdlet\s+(?:suc+e+ded|failed)\.?\s*Cmdlet\s+([\w-]+),\s*parameters\s*([\s\S]*?)\.?\s*$/i.exec(String(o.Message || ''));
    if (m) { cmdlet = m[1]; params = m[2]; }
  }
  const pm = exchange.parseCmdletParams(params);
  const c = exchange.classifyCmdlet(cmdlet, pm);
  const failed = eid === 6;
  Object.assign(ev, { category: c.category, action: 'exchange-cmdlet', outcome: failed ? 'failure' : 'success', severity: c.severity });
  ev.tags.push(...c.tags, 'exchange', 'exchange-onprem');
  const who = caller.includes('/') ? splitUser(caller.split('/').pop()) : splitUser(caller);
  ev.user = who.user;
  if (who.domain) ev.domain = who.domain;
  ev.target_user = c.target;
  Object.assign(ev.fields, { cmdlet, parameters: params.slice(0, 8000), exchange_action: c.action, caller, Operation: cmdlet, Parameters: params.slice(0, 8000) });
  for (const [k, v] of Object.entries(pm)) ev.fields['params.' + k] = String(v).slice(0, 2000);
  ev.message = `Exchange cmdlet ${cmdlet} ${failed ? 'failed' : 'run'} by ${ev.user || caller || '?'}${c.target ? ' on ' + c.target : ''}`.slice(0, 300);
}

// The agent's daily baseline-hardening snapshot (agent 1.2+, EventID 1, EventData.type "hardening", settings = compact JSON
// of read-only facts: secedit policy, auditpol, fixed registry values, services, firewall, BitLocker, Defender). Tagged
// "heartbeat" too so detection skips it; hardening/store.js keeps the latest one per host for the baseline scan.
function hardeningSnapshot(ev, ed) {
  Object.assign(ev, { category: 'configuration', action: 'agent-hardening', outcome: 'success', severity: 0, process: 'sentra-agent' });
  ev.tags.push('heartbeat', 'hardening');
  ev.message = `Agent hardening snapshot v${s(ed.agent_version) || '?'}`;
}

// Our Windows agent's own heartbeat (Channel/ProviderName "SentraAgent", EventID 0): tagged "heartbeat" so the
// detection stage skips it; it still updates the source's last_seen and is stored.
// The agent's weekly file-share personal-data scan (agent 1.5, EventData.type "pii"): counts per file only, never a value.
function piiSnapshot(ev, ed) {
  Object.assign(ev, { category: 'configuration', action: 'agent-pii', outcome: 'success', severity: 0, process: 'sentra-agent' });
  ev.tags.push('heartbeat', 'pii');
  ev.message = `Agent file-share personal-data scan v${s(ed.agent_version) || '?'}`;
}

function heartbeat(ev, ed) {
  if (s(ed.type) === 'hardening') return hardeningSnapshot(ev, ed);
  if (s(ed.type) === 'pii') return piiSnapshot(ev, ed);
  Object.assign(ev, { category: 'system', action: 'agent-heartbeat', outcome: 'success', severity: 0, process: 'sentra-agent' });
  ev.tags.push('heartbeat');
  const qf = toInt(ed.queue_files);
  const dropped = toInt(ed.dropped_batches_total);
  if (s(ed.queue_full_since) || dropped > 0) { ev.severity = 1; ev.tags.push('agent-degraded'); }
  ev.message = `Agent heartbeat v${s(ed.agent_version) || '?'} (queue ${qf} files${dropped ? ', ' + dropped + ' batches dropped' : ''})`;
  // the SOC Console (soc/console.js) reads the agent version and its queue per host from the heartbeat
  if (s(ed.agent_version)) ev.fields.agent_version = s(ed.agent_version).slice(0, 20);
  ev.fields.queue_files = String(qf); if (dropped) ev.fields.dropped_batches = String(dropped);
  // agent 1.1+: resource usage (Server Availability reads the latest values per host)
  const cpu = Number(ed.cpu_pct), mt = Number(ed.mem_total_mb), mf = Number(ed.mem_free_mb);
  if (Number.isFinite(cpu) && s(ed.cpu_pct) !== '') ev.fields.cpu_pct = String(Math.max(0, Math.min(100, Math.round(cpu))));
  if (mt > 0 && Number.isFinite(mf)) { ev.fields.mem_pct = String(Math.round((1 - mf / mt) * 1000) / 10); ev.fields.mem_total_gb = String(Math.round(mt / 102.4) / 10); }
  const disks = s(ed.disks).split(';').map((d) => d.split('|')).filter((d) => d.length === 3 && Number(d[1]) > 0).slice(0, 26)
    .map(([dev, size, free]) => ({ dev: s(dev).slice(0, 8), size: Number(size), free: Number(free) }));
  if (disks.length) {
    ev.fields.disks = disks.map((d) => `${d.dev}|${d.size}|${d.free}`).join(';');
    ev.fields.disk_max_pct = String(Math.max(...disks.map((d) => Math.round((1 - d.free / d.size) * 1000) / 10)));
  }
}

// ---------------------------------------------------------------- Active Directory change auditing (DS Changes / DS Access)
// 5136 attribute modified (one event per value: "Value Deleted" = old value, "Value Added" = new value; the two halves of one
// LDAP operation share OpCorrelationID - soc/adchanges.js pairs them into one change), 5137 created, 5138 undeleted,
// 5139 moved, 5141 deleted, 4662 an operation on an object (DS Access; only write-DACL / write-owner / replication rights
// are classified). Needs "Audit Directory Service Changes" (and the SACLs it relies on) on the domain controllers.
// fields.ad_kind: acl | gpo | gpo-link | dns | schema | attribute | object ; fields.ad_op: value-added | value-deleted |
// created | undeleted | moved | deleted | access. Values are kept as logged (≤ 8000 chars, schema cap); the view masks
// personal-data attributes (PDPL).
const AD_OPS = { '%%14674': 'value-added', '%%14675': 'value-deleted', 'value added': 'value-added', 'value deleted': 'value-deleted' };
const AD_PRIV_DN = [/^CN=AdminSDHolder,CN=System,/i, /^DC=[^,]+(?:,DC=[^,]+)*$/i, /^OU=Domain Controllers,/i, /^CN=(?:Schema|Configuration),DC=/i,
  /^CN=(?:Domain Admins|Enterprise Admins|Schema Admins|Administrators|Account Operators|Backup Operators|Server Operators|Print Operators|DnsAdmins|Group Policy Creator Owners|Key Admins|Enterprise Key Admins|Domain Controllers|Read-only Domain Controllers|Cert Publishers|krbtgt|Administrator|Protected Users),/i];
const AD_TYPE = { user: 'user', inetorgperson: 'user', group: 'group', computer: 'computer', organizationalunit: 'ou', grouppolicycontainer: 'gpo', dnsnode: 'dns-record',
  dnszone: 'dns-zone', attributeschema: 'schema-attribute', classschema: 'schema-class', domaindns: 'domain', container: 'container', msds_groupmanagedserviceaccount: 'service-account',
  'msds-groupmanagedserviceaccount': 'service-account', 'msds-managedserviceaccount': 'service-account', contact: 'contact', trusteddomain: 'trust', site: 'site', subnet: 'subnet' };
// well-known schemaIDGUIDs of the classes 4662 names (ObjectType); only those we are sure of - others stay as the GUID
const CLASS_GUID = { 'bf967aba-0de6-11d0-a285-00aa003049e2': 'user', 'bf967a9c-0de6-11d0-a285-00aa003049e2': 'group', 'bf967a86-0de6-11d0-a285-00aa003049e2': 'computer',
  '19195a5b-6da0-11d0-afd3-00c04fd930c9': 'domainDNS', 'bf967aa5-0de6-11d0-a285-00aa003049e2': 'organizationalUnit', 'f30e3bc2-9ff0-11d1-b603-0000f80367c1': 'groupPolicyContainer',
  'e0fa1e8c-9b45-11d0-afdd-00c04fd930c9': 'dnsNode', 'e0fa1e8b-9b45-11d0-afdd-00c04fd930c9': 'dnsZone' };
// replication extended rights: "Replicating Directory Changes" (+ All, + In Filtered Set) - DCSync when used by a non-DC
const DCSYNC_GUIDS = ['1131f6aa-9c07-11d1-f79f-00c04fc2dcd2', '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2', '89e95b76-444d-4c62-991a-0facbeda640c'];
const DS_ACCESS = { '%%7680': 'Create Child', '%%7681': 'Delete Child', '%%7682': 'List Contents', '%%7683': 'Write Self', '%%7684': 'Read Property', '%%7685': 'Write Property',
  '%%7686': 'Delete Tree', '%%7687': 'List Object', '%%7688': 'Control Access', '%%1537': 'DELETE', '%%1538': 'READ_CONTROL', '%%1539': 'WRITE_DAC', '%%1540': 'WRITE_OWNER' };

// DN → its RDN parts (commas escaped with a backslash stay inside a part)
function dnParts(dn) {
  const out = []; let cur = '';
  const t = String(dn || '');
  for (let i = 0; i < t.length; i++) {
    const c = t[i];
    if (c === '\\' && i + 1 < t.length) { cur += c + t[i + 1]; i++; continue; }
    if (c === ',') { out.push(cur.trim()); cur = ''; continue; }
    cur += c;
  }
  if (cur.trim()) out.push(cur.trim());
  return out.map((p) => { const k = p.indexOf('='); return { type: k > 0 ? p.slice(0, k).toUpperCase() : '', value: (k > 0 ? p.slice(k + 1) : p).replace(/\\(.)/g, '$1') }; });
}
const rdnValue = (dn) => { const p = dnParts(dn)[0]; return p ? p.value : ''; };
function gpoGuidOf(text) { const m = /\{?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\}?/i.exec(String(text || '')); return m ? m[1].toUpperCase() : ''; }
// gPLink "[LDAP://cn={GUID},cn=policies,cn=system,DC=…;0][…;2]" → [{guid, flag}] (0 enabled, 1 link disabled, 2 enforced, 3 both)
function parseGpLink(v) {
  const out = [];
  for (const m of String(v || '').matchAll(/\[LDAP:\/\/([^;\]]+);(\d+)\]/gi)) out.push({ guid: gpoGuidOf(m[1]), dn: m[1], flag: Number(m[2]) });
  return out;
}
// MS-DNSP DNS_RPC / dnsRecord attribute value (the octet string 5136 logs, as hex) → {type, ttl, data}; null when not hex
const DNS_TYPES = { 0: 'TOMBSTONE', 1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR', 15: 'MX', 16: 'TXT', 28: 'AAAA', 33: 'SRV' };
function decodeDnsRecord(v) {
  const hex = String(v || '').replace(/^0x/i, '').replace(/[\s:-]/g, '');
  if (!/^[0-9a-f]+$/i.test(hex) || hex.length % 2 || hex.length < 48) return null;
  const b = Buffer.from(hex, 'hex');
  const len = b.readUInt16LE(0), typeN = b.readUInt16LE(2), ttl = b.readUInt32BE(12), d = b.slice(24, 24 + len);
  const type = DNS_TYPES[typeN] || 'type ' + typeN;
  const name = (buf, off) => { const labels = []; let i = off + 2; const n = buf[off + 1] || 0; for (let k = 0; k < n && i < buf.length; k++) { const l = buf[i]; if (!l) break; labels.push(buf.slice(i + 1, i + 1 + l).toString('latin1')); i += 1 + l; } return labels.join('.'); };
  let data = '';
  try {
    if (typeN === 1 && d.length >= 4) data = [...d.slice(0, 4)].join('.');
    else if (typeN === 28 && d.length >= 16) data = Array.from({ length: 8 }, (_, i) => d.readUInt16BE(i * 2).toString(16)).join(':').replace(/(^|:)0(:0)+(:|$)/, '::');
    else if ((typeN === 2 || typeN === 5 || typeN === 12) && d.length >= 2) data = name(d, 0);
    else if (typeN === 15 && d.length >= 4) data = d.readUInt16BE(0) + ' ' + name(d, 2);
    else if (typeN === 33 && d.length >= 8) data = `${d.readUInt16BE(0)} ${d.readUInt16BE(2)} ${d.readUInt16BE(4)} ${name(d, 6)}`;
    else if (typeN === 16) { const parts = []; let i = 0; while (i < d.length) { const l = d[i]; parts.push(d.slice(i + 1, i + 1 + l).toString('utf8')); i += 1 + l; } data = parts.join(' '); }
    else if (typeN === 0) data = 'record deleted (tombstone)';
    else data = `${d.length} bytes`;
  } catch (e) { data = `${d.length} bytes (not decoded)`; /* a truncated value: show the size, never guess */ }
  return { type, ttl, data };
}
// what an AD change is about, from the object class, DN and attribute
function adClassify(objClass, dn, attr) {
  const cls = low(objClass), a = low(attr), parts = dnParts(dn), up = String(dn || '').toUpperCase();
  const object_type = AD_TYPE[cls] || (cls || 'object');
  let kind = '';
  if (a === 'ntsecuritydescriptor') kind = 'acl';
  else if (/,CN=SCHEMA,CN=CONFIGURATION,/.test(up) || cls === 'attributeschema' || cls === 'classschema') kind = 'schema';
  else if (a === 'gplink' || a === 'gpoptions') kind = 'gpo-link';
  else if (cls === 'grouppolicycontainer' || /,CN=POLICIES,CN=SYSTEM,/.test(up)) kind = 'gpo';
  else if (cls === 'dnsnode' || cls === 'dnszone' || /,CN=MICROSOFTDNS,/.test(up)) kind = 'dns';
  else kind = attr ? 'attribute' : 'object';
  const out = { kind, object_type };
  if (kind === 'dns' || /,CN=MICROSOFTDNS,/.test(up)) {
    const i = parts.findIndex((p) => p.type === 'CN' && /^microsoftdns$/i.test(p.value));
    if (cls === 'dnszone' || i === 1) { out.dns_zone = (parts[0] || {}).value || ''; }
    else if (i >= 2) { out.dns_record = (parts[0] || {}).value || ''; out.dns_zone = (parts[1] || {}).value || ''; }
    const part = parts.slice(i + 1).map((p) => p.value).find((v) => /^(domaindnszones|forestdnszones|system)$/i.test(v));
    out.dns_partition = part ? part.toLowerCase() : '';
  }
  if (kind === 'gpo' || cls === 'grouppolicycontainer') out.gpo_guid = gpoGuidOf((parts[0] || {}).value || dn);
  if (kind === 'schema') out.schema_object = rdnValue(dn);
  out.privileged = AD_PRIV_DN.some((re) => re.test(String(dn || '').trim()));
  return out;
}
function adCommon(ev, ed, dn, cls, attr) {
  userInto(ev, 'user', ed.SubjectUserName, ed.SubjectDomainName);
  const c = adClassify(cls, dn, attr);
  const name = rdnValue(dn);
  Object.assign(ev.fields, {
    ad_kind: c.kind, ad_object_class: s(cls), ad_object_type: c.object_type, ad_object_dn: s(dn).slice(0, 2000), ad_object_name: name.slice(0, 300),
    ad_object_guid: gpoGuidOf(ed.ObjectGUID).toLowerCase(), ad_partition: s(ed.DSName), ad_correlation_id: gpoGuidOf(ed.OpCorrelationID).toLowerCase(),
    ad_app_correlation_id: gpoGuidOf(ed.AppCorrelationID).toLowerCase(),
  });
  if (c.privileged) ev.fields.ad_privileged_object = '1';
  if (c.gpo_guid) ev.fields.gpo_guid = c.gpo_guid;
  if (c.schema_object) ev.fields.schema_object = c.schema_object;
  if (c.dns_zone !== undefined) Object.assign(ev.fields, { dns_zone: c.dns_zone.toLowerCase(), dns_record: (c.dns_record || '').toLowerCase(), dns_partition: c.dns_partition });
  if (c.dns_record && ev.user && ev.user.replace(/\$$/, '') === c.dns_record.toLowerCase().split('.')[0]) ev.fields.dns_self_update = '1';   // a host updating its own record
  if (['user', 'computer', 'group', 'service-account'].includes(c.object_type) && name) ev.target_user = name.toLowerCase();
  ev.tags.push('ad-change');
  if (c.kind === 'acl') ev.tags.push('acl-change');
  else if (c.kind === 'gpo' || c.kind === 'gpo-link') ev.tags.push('gpo-change', 'T1484');
  else if (c.kind === 'dns') ev.tags.push('dns-change');
  else if (c.kind === 'schema') ev.tags.push('schema-change');
  return c;
}
function adSeverity(ev, c, op) {
  let sev = 1;
  if (c.kind === 'acl') sev = c.privileged ? 3 : 2;
  else if (c.kind === 'schema' || c.kind === 'gpo-link') sev = 2;
  else if (c.kind === 'gpo') sev = 2;
  else if (c.privileged) sev = 2;
  if (op === 'value-deleted') sev = Math.min(sev, 1);   // the old half of a modification: the new half carries the severity
  ev.severity = Math.max(ev.severity, sev);
  if (c.kind === 'acl' && c.privileged) ev.tags.push('T1098');
}
const AD_VERB = { 'value-added': 'changed', 'value-deleted': 'changed (old value)', created: 'created', undeleted: 'restored', moved: 'moved', deleted: 'deleted' };
function adModified(ev, ed) {
  Object.assign(ev, { category: 'iam', action: 'ad-object-modified', outcome: 'success' });
  const attr = s(ed.AttributeLDAPDisplayName);
  const op = AD_OPS[s(ed.OperationType).toLowerCase()] || AD_OPS[s(ed.OperationType)] || (s(ed.OperationType) ? low(ed.OperationType) : 'value-added');
  const c = adCommon(ev, ed, ed.ObjectDN, ed.ObjectClass, attr);
  const val = s(ed.AttributeValue);
  Object.assign(ev.fields, { ad_op: op, ad_attribute: attr, ad_attribute_syntax: s(ed.AttributeSyntaxOID), ad_value: val.slice(0, 8000) });
  if (c.kind === 'dns' && /^dnsrecord$/i.test(attr)) { const r = decodeDnsRecord(val); if (r) Object.assign(ev.fields, { dns_record_type: r.type, dns_record_data: r.data.slice(0, 1000), dns_ttl: String(r.ttl) }); }
  if (c.kind === 'gpo-link') { const l = parseGpLink(val); ev.fields.gpo_links = l.map((x) => x.guid + ':' + x.flag).join(';'); if (l.length === 1) ev.fields.gpo_guid = l[0].guid; }
  adSeverity(ev, c, op);
  ev.message = `AD ${c.object_type} ${rdnValue(ed.ObjectDN) || s(ed.ObjectDN)}: ${attr} ${op === 'value-deleted' ? 'old value removed' : 'value set'} by ${ev.user || '?'}`.slice(0, 300);
}
function adObject(op) {
  return (ev, ed) => {
    Object.assign(ev, { category: 'iam', action: 'ad-object-' + op, outcome: 'success' });
    const dn = op === 'moved' || op === 'undeleted' ? s(ed.NewObjectDN) || s(ed.ObjectDN) : s(ed.ObjectDN);
    const c = adCommon(ev, ed, dn, ed.ObjectClass, '');
    ev.fields.ad_op = op;
    if (op === 'moved' || op === 'undeleted') Object.assign(ev.fields, { ad_old_dn: s(ed.OldObjectDN).slice(0, 2000), ad_new_dn: s(ed.NewObjectDN).slice(0, 2000) });
    if (op === 'deleted') ev.fields.ad_tree_delete = /^(%%14680|yes)$/i.test(s(ed.TreeDelete)) ? '1' : '0';
    adSeverity(ev, c, op);
    if (op === 'deleted' && (c.kind === 'gpo' || c.privileged)) ev.severity = Math.max(ev.severity, 3);
    ev.message = `AD ${c.object_type} ${rdnValue(dn) || dn} ${AD_VERB[op]} by ${ev.user || '?'}`.slice(0, 300);
  };
}
// 4662 "An operation was performed on an object": only what changes security or reads secrets is classified
function adAccess(ev, ed) {
  Object.assign(ev, { category: 'iam', action: 'ad-object-access', outcome: ev.outcome === 'failure' ? 'failure' : 'success' });
  userInto(ev, 'user', ed.SubjectUserName, ed.SubjectDomainName);
  const type = gpoGuidOf(ed.ObjectType).toLowerCase(), access = s(ed.AccessList).split(/\s+/).filter(Boolean).map((x) => DS_ACCESS[x] || x);
  const props = s(ed.Properties).toLowerCase();
  Object.assign(ev.fields, { ad_op: 'access', ad_object_guid: gpoGuidOf(ed.ObjectName).toLowerCase(), ad_object_class: CLASS_GUID[type] || type, ad_access: [...new Set(access)].join(', '), ad_access_mask: s(ed.AccessMask), ad_properties: props.slice(0, 2000) });
  if (access.includes('WRITE_DAC') || access.includes('WRITE_OWNER')) { ev.fields.ad_kind = 'acl'; ev.tags.push('ad-change', 'acl-change'); ev.severity = Math.max(ev.severity, 2); }
  if (access.includes('Control Access') && DCSYNC_GUIDS.some((g) => props.includes(g))) {
    ev.fields.ad_dcsync = '1';
    if (!/\$$/.test(ev.user)) { ev.severity = 3; ev.tags.push('T1003.006', 'dcsync'); }
  }
  ev.message = `AD object ${ev.fields.ad_object_class || '?'} ${ev.fields.ad_object_guid}: ${ev.fields.ad_access || 'access'} by ${ev.user || '?'}${ev.fields.ad_dcsync ? ' (directory replication rights)' : ''}`.slice(0, 300);
}
// 4739 Domain Policy changed: the event carries only the NEW value of each changed setting ("-" = unchanged)
const DOMAIN_POLICY_KEYS = ['MinPasswordAge', 'MaxPasswordAge', 'ForceLogoff', 'LockoutThreshold', 'LockoutObservationWindow', 'LockoutDuration', 'PasswordProperties',
  'MinPasswordLength', 'PasswordHistoryLength', 'MachineAccountQuota', 'MixedDomainMode', 'DomainBehaviorVersion', 'OemInformation'];
function domainPolicy(ev, ed) {
  Object.assign(ev, { category: 'policy', action: 'config-change', outcome: 'success', severity: 2 });
  userInto(ev, 'user', ed.SubjectUserName, ed.SubjectDomainName);
  const changed = DOMAIN_POLICY_KEYS.filter((k) => s(ed[k]) && s(ed[k]) !== '-');
  Object.assign(ev.fields, { domain_policy_changed: s(ed.DomainPolicyChanged), domain_name: s(ed.DomainName), domain_sid: s(ed.DomainSid), policy_changed_settings: changed.join(',') });
  for (const k of changed) ev.fields['policy.' + k] = s(ed[k]).slice(0, 500);
  ev.tags.push('domain-policy', 'T1484');
  ev.message = `Domain policy changed${ev.fields.domain_policy_changed ? ' (' + ev.fields.domain_policy_changed + ')' : ''} by ${ev.user || '?'}: ${changed.map((k) => k + '=' + s(ed[k])).join(', ') || 'no setting named'}`.slice(0, 300);
}
// 4719 System audit policy changed. %%8448 success removed, %%8449 success added, %%8450 failure removed, %%8451 failure added
const AUDIT_CHANGE = { '%%8448': 'Success removed', '%%8449': 'Success added', '%%8450': 'Failure removed', '%%8451': 'Failure added' };
const AUDIT_CATEGORY = { '%%8272': 'System', '%%8273': 'Logon/Logoff', '%%8274': 'Object Access', '%%8275': 'Privilege Use', '%%8276': 'Detailed Tracking', '%%8277': 'Policy Change',
  '%%8278': 'Account Management', '%%8279': 'DS Access', '%%8280': 'Account Logon' };
const AUDIT_SUB = { '0cce9210': 'Security State Change', '0cce9211': 'Security System Extension', '0cce9212': 'System Integrity', '0cce9213': 'IPsec Driver', '0cce9214': 'Other System Events',
  '0cce9215': 'Logon', '0cce9216': 'Logoff', '0cce9217': 'Account Lockout', '0cce921b': 'Special Logon', '0cce921c': 'Other Logon/Logoff Events', '0cce9243': 'Network Policy Server',
  '0cce9249': 'Group Membership', '0cce921d': 'File System', '0cce921e': 'Registry', '0cce921f': 'Kernel Object', '0cce9220': 'SAM', '0cce9221': 'Certification Services',
  '0cce9224': 'File Share', '0cce9227': 'Other Object Access Events', '0cce9244': 'Detailed File Share', '0cce9245': 'Removable Storage', '0cce9228': 'Sensitive Privilege Use',
  '0cce922b': 'Process Creation', '0cce922c': 'Process Termination', '0cce922f': 'Audit Policy Change', '0cce9230': 'Authentication Policy Change', '0cce9231': 'Authorization Policy Change',
  '0cce9232': 'MPSSVC Rule-Level Policy Change', '0cce9235': 'User Account Management', '0cce9236': 'Computer Account Management', '0cce9237': 'Security Group Management',
  '0cce9238': 'Distribution Group Management', '0cce9239': 'Application Group Management', '0cce923a': 'Other Account Management Events', '0cce923b': 'Directory Service Access',
  '0cce923c': 'Directory Service Changes', '0cce923d': 'Directory Service Replication', '0cce923f': 'Credential Validation', '0cce9240': 'Kerberos Service Ticket Operations',
  '0cce9242': 'Kerberos Authentication Service' };
function auditPolicy(ev, ed) {
  Object.assign(ev, { category: 'policy', action: 'config-change', outcome: 'success', severity: 1 });
  userInto(ev, 'user', ed.SubjectUserName, ed.SubjectDomainName);
  const changes = s(ed.AuditPolicyChanges).split(/[\s,]+/).filter(Boolean).map((x) => AUDIT_CHANGE[x] || x);
  const sg = gpoGuidOf(ed.SubcategoryGuid).toLowerCase();
  const sub = AUDIT_SUB[sg.slice(0, 8)] || (/^%%/.test(s(ed.SubcategoryId)) ? '' : s(ed.SubcategoryId)) || sg;
  Object.assign(ev.fields, { audit_category: AUDIT_CATEGORY[s(ed.CategoryId)] || s(ed.CategoryId), audit_subcategory: sub, audit_subcategory_guid: sg, audit_changes: changes.join(', ') });
  if (changes.some((c) => /removed/i.test(c))) { ev.fields.audit_removed = '1'; ev.severity = 3; ev.tags.push('T1685.001'); }
  if (/\$$/.test(ev.user)) ev.fields.applied_by_gpo = '1';   // the computer account applies the audit policy a GPO sets
  ev.tags.push('audit-policy', 'audit-change');
  ev.message = `Audit policy changed: ${sub || '?'} - ${changes.join(', ') || '?'} by ${ev.user || '?'}${ev.fields.applied_by_gpo ? ' (applied by Group Policy)' : ''}`.slice(0, 300);
}
Object.assign(SEC, { 5136: adModified, 5137: adObject('created'), 5138: adObject('undeleted'), 5139: adObject('moved'), 5141: adObject('deleted'), 4662: adAccess, 4739: domainPolicy, 4719: auditPolicy });

// SQL Server Audit written to the Application log (provider MSSQLSERVER / MSSQL$<instance>), event 33205. The single
// unnamed Data element (agent: Data0) / the rendered message hold "key:value" lines: action_id, succeeded,
// server_principal_name, database_name, object_name, statement, client_ip, application_name, … Only known key names
// split the text, so a statement containing "x:" is not cut. Collected agentlessly via the SENTRA-WEF-SQL subscription.
const SQL_KEYS = new Set(['audit_schema_version', 'event_time', 'sequence_number', 'action_id', 'succeeded', 'is_column_permission',
  'session_id', 'server_principal_id', 'database_principal_id', 'target_server_principal_id', 'target_database_principal_id',
  'object_id', 'user_defined_event_id', 'transaction_id', 'class_type', 'permission_bitmask', 'sequence_group_id',
  'session_server_principal_name', 'server_principal_name', 'server_principal_sid', 'database_principal_name',
  'target_server_principal_name', 'target_server_principal_sid', 'target_database_principal_name', 'server_instance_name',
  'database_name', 'schema_name', 'object_name', 'statement', 'additional_information', 'user_defined_information',
  'application_name', 'connection_id', 'data_sensitivity_information', 'host_name', 'session_context', 'client_ip',
  'external_policy_permissions_checked', 'duration_milliseconds', 'response_rows', 'affected_rows', 'client_tls_version',
  'database_transaction_id', 'ledger_start_sequence_number', 'is_local_secondary_replica', 'obo_middle_tier_app_id']);
function sqlAuditFields(text) {
  const out = {};
  const re = /(?:^|\s)([a-z_]{2,40}):/g;
  const hits = [];
  let m;
  while ((m = re.exec(text))) if (SQL_KEYS.has(m[1])) hits.push({ key: m[1], start: m.index + m[0].length, from: m.index });
  for (let i = 0; i < hits.length; i++) out[hits[i].key] = text.slice(hits[i].start, i + 1 < hits.length ? hits[i + 1].from : text.length).trim();
  return out;
}
const SQL_ACTIONS = {
  LGIS: ['authentication', 'logon', 0], LGIF: ['authentication', 'logon-failed', 1], LGO: ['authentication', 'logoff', 0],
  APRL: ['iam', 'group-member-added', 2], DPRL: ['iam', 'group-member-removed', 1],
  CR: ['policy', 'config-change', 1], AL: ['policy', 'config-change', 1], DR: ['policy', 'config-change', 1],
  AUSC: ['policy', 'config-change', 2], AUSF: ['policy', 'config-change', 2],
};
function sqlAudit(ev, ed, o) {
  const text = [ed.Data0, ed.Data, ...Object.values(ed), o.Message].map((v) => (typeof v === 'string' ? v : '')).find((v) => /action_id:/.test(v)) || '';
  const a = sqlAuditFields(text);
  const act = (a.action_id || '').trim().toUpperCase();
  const [category, action, sev] = SQL_ACTIONS[act] || ['other', 'db-audit', 0];
  const ok = !/^(false|0)$/i.test(a.succeeded || 'true');
  Object.assign(ev, { category, action, outcome: a.succeeded ? (ok ? 'success' : 'failure') : 'unknown', severity: sev });
  if (act === 'LGIF') ev.tags.push('T1110');
  if (act === 'AUSC' || act === 'AUSF') ev.tags.push('audit-change');
  ev.tags.push('mssql');
  userInto(ev, 'user', a.server_principal_name || a.session_server_principal_name);
  ev.target_user = low(a.target_server_principal_name || a.target_database_principal_name);
  ev.src_ip = /^local machine$/i.test(a.client_ip || '') ? '' : ipOrEmpty(a.client_ip);
  ev.cmdline = s(a.statement).slice(0, 8000);
  const obj = [a.schema_name, a.object_name].filter(Boolean).join('.');
  Object.assign(ev.fields, {
    sql_action_id: act, sql_class_type: s(a.class_type), database: s(a.database_name), object: obj,
    sql_instance: s(a.server_instance_name), application: s(a.application_name), client_host: s(a.host_name),
    database_principal: s(a.database_principal_name), additional_information: s(a.additional_information).slice(0, 2000),
  });
  ev.message = `SQL audit ${act || '?'}${ok ? '' : ' (failed)'} by ${ev.user || '?'}${a.database_name ? ' on ' + a.database_name + (obj ? '.' + obj : '') : ''}`.slice(0, 300);
}
// SQL Server error-log login events mirrored to the Application log: 18456 failed, 18453/18454 succeeded.
// Data0 = login name, Data2 = "[CLIENT: <ip>]" (fallback: the rendered message).
function sqlLogin(ev, ed, o, eid) {
  const ok = eid !== 18456;
  Object.assign(ev, { category: 'authentication', action: ok ? 'logon' : 'logon-failed', outcome: ok ? 'success' : 'failure', severity: ok ? 0 : 1 });
  const msg = String(o.Message || '');
  const name = s(ed.Data0) || ((/login (?:failed|succeeded) for user '([^']*)'/i.exec(msg) || [])[1] || '');
  userInto(ev, 'user', name);
  const cl = /\[CLIENT:\s*([^\]\s]+)\s*\]/i.exec([ed.Data2, ed.Data1, msg].map((v) => String(v || '')).join(' '));
  if (cl) ev.src_ip = /^<local machine>$/i.test(cl[1]) ? '' : ipOrEmpty(cl[1]);
  if (!ok) { ev.tags.push('T1110'); const r = /Reason:\s*([^[]+)/i.exec(msg) || /Reason:\s*([^[]+)/i.exec(String(ed.Data1 || '')); if (r) ev.fields.failure_reason = r[1].trim().replace(/\.$/, ''); }
  ev.tags.push('mssql');
  ev.fields.auth_protocol = 'mssql';
  ev.message = `SQL Server login ${ok ? 'succeeded' : 'failed'} for ${ev.user || '?'}${ev.src_ip ? ' from ' + ev.src_ip : ''}`;
}

function levelNum(l) {
  if (typeof l === 'number') return l;
  const n = Number(l);
  if (Number.isFinite(n)) return n;
  return LEVEL_NAMES[String(l || '').toLowerCase()] || 0;
}

function parse(line, meta = {}) {
  const o = meta.obj || safeJson(line);
  if (!o || Array.isArray(o)) return null;
  const eidRaw = o.EventID ?? o.EventId ?? o.Id ?? o.event_id;
  if (eidRaw === undefined || eidRaw === null || eidRaw === '') return null;
  const eid = Number(typeof eidRaw === 'object' ? eidRaw.Value ?? eidRaw['#text'] : eidRaw);
  if (!Number.isFinite(eid)) return null;
  if (o.Channel === undefined && o.ProviderName === undefined && o.Computer === undefined && o.LogName === undefined) return null;
  const ed = eventData(o);
  const channel = String(o.Channel ?? o.LogName ?? '');
  const provider = String(o.ProviderName ?? o.Provider ?? '');
  const sysmon = /sysmon/i.test(channel) || /sysmon/i.test(provider);
  const lvl = levelNum(o.Level);
  const ev = {
    src_type: 'windows', ts: parseTime(o.TimeCreated ?? o.TimeGenerated ?? o.timestamp, 0),
    host: String(o.Computer || o.MachineName || '').toLowerCase(), event_code: String(eid),
    category: 'system', action: 'event', outcome: 'unknown', severity: LEVEL_SEV[lvl] || 0,
    message: firstLine(o.Message, 300) || `${provider || channel} event ${eid}`,
    tags: [], fields: { channel, provider, record_id: o.RecordId ?? o.RecordNumber, level: lvl ? String(lvl) : undefined, task: o.TaskDisplayName, opcode: o.OpcodeDisplayName },
  };
  const kw = String(o.KeywordsDisplayNames || o.Keywords || '');
  if (/audit failure/i.test(kw)) ev.outcome = 'failure';
  else if (/audit success/i.test(kw)) ev.outcome = 'success';
  // Windows Event Forwarding: the agent on the WEC marks forwarded records (Forwarded:true, Wec, Collector "wef:<wec>").
  // host is ALWAYS the event's own Computer (the source server), never the collector/relay; host_ip is the source's
  // DNS address when the agent resolved it (ComputerIp), otherwise the router's peer address (= the forwarder), which
  // is also kept in fields.forwarder_ip.
  const forwarded = o.Forwarded === true || /^true$/i.test(String(o.Forwarded ?? '')) || /^wef:/i.test(String(o.Collector ?? ''));
  if (forwarded) {
    ev.host = String(o.Computer || '').toLowerCase();
    const wec = String(o.Wec || String(o.Collector || '').replace(/^wef:/i, '')).toLowerCase();
    Object.assign(ev.fields, { forwarded: 'true', wec, collector_via: 'wef:' + wec, forwarded_channel: o.ForwardedChannel ? String(o.ForwardedChannel) : undefined });
    if (meta.peer_ip) ev.fields.forwarder_ip = String(meta.peer_ip);
    const hip = ipOrEmpty(o.ComputerIp);
    if (hip) ev.host_ip = hip;
    ev.tags.push('wef');
  }
  const mssql = /^mssql/i.test(provider);
  const handler = channel === 'SentraAgent' || provider === 'SentraAgent' ? heartbeat
    : (channel === 'MSExchange Management' && (eid === 1 || eid === 6)) ? exchangeMgmt
      : (eid === 33205 && (mssql || /action_id:/.test(String(ed.Data0 || o.Message || '')))) ? sqlAudit
        : (mssql && (eid === 18456 || eid === 18453 || eid === 18454)) ? sqlLogin
          : sysmon ? SYSMON[eid] : SEC[eid];
  if (handler) handler(ev, ed, o, eid);
  else if (sysmon) {
    ev.category = 'process';
    sysmonProc(ev, ed);
  }
  // every raw EventData value is also kept under its original name (detection rules may use fields.<EventDataName>)
  for (const [k, v] of Object.entries(ed)) {
    if (v === null || v === undefined || v === '' || v === '-') continue;
    const key = k.length > 64 ? k.slice(0, 64) : k;
    if (ev.fields[key] === undefined) ev.fields[key] = typeof v === 'object' ? JSON.stringify(v) : String(v);
  }
  if (!ev.tags.length) delete ev.tags;
  return ev;
}

module.exports = {
  name: 'windows',
  sniff(line, meta = {}) {
    const o = meta.obj || (line && line.charCodeAt(0) === 123 ? safeJson(line) : null);
    return !!o && (o.EventID !== undefined || o.EventId !== undefined) && (o.Channel !== undefined || o.ProviderName !== undefined || o.Computer !== undefined);
  },
  parse,
  procTags,
  // AD change auditing helpers (soc/adchanges.js)
  dnParts, adClassify, parseGpLink, decodeDnsRecord, gpoGuidOf,
};
