// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Device classification for discovery results — deterministic, explainable (every decision lists its reasons).
//   classify(dev) → {type, vendor, os, confidence (0-99), reasons[]}
//     type ∈ server | workstation | switch | router | firewall | ap | printer | phone | vm | cloud | unknown
//   ouiVendor(mac) → vendor | null          enterpriseVendor(sysObjectID) → vendor | null
// Inputs come from the merged device record: sys_descr / sys_object_id (SNMP), os, open_ports (TCP sweep), methods
// (which sources saw it), hostname, mac(s) and the per-source extras (ad, vcenter, hyperv, cucm, cloud).
//
// The OUI and enterprise-number tables are deliberately SMALL (common vendors seen in Saudi enterprise networks) and
// marked "verify" — the authoritative lists are the IEEE MA-L registry and IANA Private Enterprise Numbers. An unknown
// prefix simply yields no vendor; it never fails a classification.
const TYPES = ['server', 'workstation', 'switch', 'router', 'firewall', 'ap', 'printer', 'phone', 'vm', 'cloud', 'storage', 'unknown'];

const OUI = {
  // virtualisation / cloud
  '005056': 'VMware', '000c29': 'VMware', '000569': 'VMware', '001c14': 'VMware', '00155d': 'Microsoft (Hyper-V)',
  '000d3a': 'Microsoft (Azure)', '080027': 'Oracle VirtualBox', '525400': 'QEMU/KVM',
  // security appliances
  '00090f': 'Fortinet', '906cac': 'Fortinet', '704ca5': 'Fortinet', '085b0e': 'Fortinet', '001b17': 'Palo Alto Networks',
  '00869c': 'Palo Alto Networks', '001c7f': 'Check Point', '0017c5': 'SonicWall', 'c0eae4': 'SonicWall', '001a8c': 'Sophos',
  '7c5a1c': 'Sophos', '0001d7': 'F5 Networks', '0023e9': 'F5 Networks',
  // network
  '00000c': 'Cisco', '00180a': 'Cisco Meraki', '000b86': 'Aruba (HPE)', '24dec6': 'Aruba (HPE)', '94b40f': 'Aruba (HPE)',
  '204c03': 'Aruba (HPE)', '000585': 'Juniper Networks', '001c73': 'Arista Networks', '444ca8': 'Arista Networks',
  '000496': 'Extreme Networks', '00e02b': 'Extreme Networks', '00e0fc': 'Huawei', '24a43c': 'Ubiquiti', '44d9e7': 'Ubiquiti',
  '802aa8': 'Ubiquiti', 'f09fc2': 'Ubiquiti', '0418d6': 'Ubiquiti', '4c5e0c': 'MikroTik', '6c3b6b': 'MikroTik', 'cc2de0': 'MikroTik',
  '50c7bf': 'TP-Link', 'f4f26d': 'TP-Link', '14cc20': 'TP-Link',
  // servers / PCs
  '001422': 'Dell', 'f8b156': 'Dell', 'b8ac6f': 'Dell', '1866da': 'Dell', 'd4bed9': 'Dell', '3cd92b': 'HP', '0025b3': 'HP',
  '9457a5': 'HP', '002590': 'Supermicro', 'ac1f6b': 'Supermicro', '001b21': 'Intel', '3cfdfe': 'Intel', 'a0369f': 'Intel',
  '000393': 'Apple', '3c0754': 'Apple', 'a45e60': 'Apple', 'f01898': 'Apple', 'b827eb': 'Raspberry Pi', 'dca632': 'Raspberry Pi',
  'e45f01': 'Raspberry Pi',
  // storage / power
  '001132': 'Synology', '245ebe': 'QNAP', '00089b': 'QNAP', '00c0b7': 'APC (Schneider Electric)',
  // phones
  '0004f2': 'Polycom', '001565': 'Yealink', '805ec0': 'Yealink', '000b82': 'Grandstream',
  // printers
  '000085': 'Canon', '001e8f': 'Canon', '001ba9': 'Brother', '30055c': 'Brother', '002673': 'Ricoh', '000074': 'Ricoh',
  '0000aa': 'Xerox', '9c934e': 'Xerox', '000400': 'Lexmark', '0021b7': 'Lexmark', '00c0ee': 'Kyocera', '00206b': 'Konica Minolta',
  '64eb8c': 'Epson',
  // cameras
  '4419b6': 'Hikvision', 'c056e3': 'Hikvision', 'bcad28': 'Hikvision', '3cef8c': 'Dahua', '9002a9': 'Dahua', '00408c': 'Axis', 'accc8e': 'Axis',
};
const OUI_ROLE = {
  'VMware': 'vm', 'Microsoft (Hyper-V)': 'vm', 'Microsoft (Azure)': 'cloud', 'QEMU/KVM': 'vm', 'Oracle VirtualBox': 'vm',
  'Fortinet': 'firewall', 'Palo Alto Networks': 'firewall', 'Check Point': 'firewall', 'SonicWall': 'firewall', 'Sophos': 'firewall',
  'Polycom': 'phone', 'Yealink': 'phone', 'Grandstream': 'phone',
  'Canon': 'printer', 'Brother': 'printer', 'Ricoh': 'printer', 'Xerox': 'printer', 'Lexmark': 'printer', 'Kyocera': 'printer', 'Konica Minolta': 'printer', 'Epson': 'printer',
};
// IANA Private Enterprise Numbers (sysObjectID 1.3.6.1.4.1.<n>…) — verify
const ENTERPRISE = {
  116: 'Hitachi', 1139: 'Dell EMC', 12740: 'Dell EqualLogic', 34774: 'Huawei Storage', 37447: 'HPE Nimble Storage', 40482: 'Pure Storage',
  9: 'Cisco', 11: 'HP', 43: '3Com', 171: 'D-Link', 207: 'Allied Telesis', 232: 'HP (Compaq)', 253: 'Xerox', 311: 'Microsoft',
  318: 'APC (Schneider Electric)', 367: 'Ricoh', 641: 'Lexmark', 674: 'Dell', 789: 'NetApp', 1347: 'Kyocera', 1602: 'Canon',
  1916: 'Extreme Networks', 2011: 'Huawei', 2021: 'Net-SNMP (Linux)', 2435: 'Brother', 2620: 'Check Point', 2636: 'Juniper Networks',
  3375: 'F5 Networks', 4526: 'Netgear', 5951: 'Citrix', 6486: 'Alcatel-Lucent', 6574: 'Synology', 6876: 'VMware', 8072: 'Net-SNMP (Linux)',
  8741: 'SonicWall', 11863: 'TP-Link', 12356: 'Fortinet', 14179: 'Cisco (WLC)', 14823: 'Aruba (HPE)', 14988: 'MikroTik',
  18334: 'Konica Minolta', 24681: 'QNAP', 25461: 'Palo Alto Networks', 25506: 'H3C', 29671: 'Cisco Meraki', 30065: 'Arista Networks', 41112: 'Ubiquiti',
};

function hex12(m) { const h = String(m || '').toLowerCase().replace(/[^0-9a-f]/g, ''); return h.length === 12 ? h : null; }
function ouiVendor(mac) { const h = hex12(mac); return h ? OUI[h.slice(0, 6)] || null : null; }
function enterpriseVendor(oid) { const m = /^\.?1\.3\.6\.1\.4\.1\.(\d+)/.exec(String(oid || '')); return m ? ENTERPRISE[Number(m[1])] || null : null; }

const DESCR_RULES = [
  [/FortiGate|FortiOS/i, 'firewall', 90, 'Fortinet'],
  [/PAN-OS|Palo Alto Networks/i, 'firewall', 90, 'Palo Alto Networks'],
  [/Adaptive Security Appliance|Cisco ASA|Firepower/i, 'firewall', 90, 'Cisco'],
  [/Check ?Point|Gaia/i, 'firewall', 80, 'Check Point'],
  [/SonicWall|SonicOS/i, 'firewall', 85, 'SonicWall'],
  [/Sophos (XG|UTM|Firewall)|SFOS/i, 'firewall', 85, 'Sophos'],
  [/JUNOS.*SRX|SRX\d{3,4}/i, 'firewall', 85, 'Juniper Networks'],
  [/AireOS|Cisco Controller|Aruba Instant|Instant On|\bAP\d{2,3}\b|access point|UniFi.*AP|Ruckus|Meraki MR/i, 'ap', 80, null],
  [/Catalyst|C9[23]00|C29[67]0|C3[68]50|NX-OS|Nexus|ArubaOS-CX|ProCurve|Aruba.*Switch|JUNOS.*\bEX\d|Comware|\bswitch\b|GWN78/i, 'switch', 75, null],
  [/Cisco IOS.*(ISR|ASR|C8[0-9]{2}|C19|C29[0-9]1|C39[0-9]{2}|C4[34]\d{2})|IOS-XR|RouterOS|EdgeOS|JUNOS.*\bMX\d|\brouter\b/i, 'router', 70, null],
  [/LaserJet|JetDirect|OfficeJet|Ricoh|Xerox|Kyocera|ECOSYS|TASKalfa|Lexmark|Brother NC|bizhub|Konica|Epson|imageRUNNER|\bprinter\b|\bMFP\b/i, 'printer', 85, null],
  // storage arrays and NAS (before the generic Linux / Windows rules: many run on them)
  [/NetApp|Data ONTAP|\bONTAP\b/i, 'storage', 90, 'NetApp'],
  [/PowerStore|Unity\s*(XT|\d)|VNX|Isilon|OneFS|PowerScale|Data ?Domain|DDOS|PowerVault|Compellent|SC Series|EqualLogic|PowerMax|VMAX/i, 'storage', 88, 'Dell EMC'],
  [/3PAR|Primera|Alletra|Nimble|StoreOnce|StoreEasy|StoreVirtual|MSA \d{4}|StorageWorks/i, 'storage', 88, 'HPE'],
  [/Pure Storage|Purity|FlashArray|FlashBlade/i, 'storage', 90, 'Pure Storage'],
  [/Hitachi (VSP|Virtual Storage)|\bVSP\s*[EGF]\d/i, 'storage', 88, 'Hitachi'],
  [/OceanStor|Dorado/i, 'storage', 88, 'Huawei'],
  [/Synology|DiskStation|\bDSM\b/i, 'storage', 85, 'Synology'],
  [/QNAP|\bQTS\b|QuTS/i, 'storage', 85, 'QNAP'],
  [/VMware ESXi/i, 'server', 85, 'VMware'],
  [/Windows.*Server|Server 20(08|12|16|19|22|25)/i, 'server', 70, 'Microsoft'],
  [/Windows/i, 'workstation', 45, 'Microsoft'],
  [/SunOS|Solaris/i, 'server', 75, 'Oracle'],
  [/AIX|HP-UX/i, 'server', 70, null],
  [/Linux|Ubuntu|Red Hat|CentOS|Debian|SUSE/i, 'server', 45, null],
];
const NAME_RULES = [
  [/^(fw|fgt|pa|asa|ngfw)[-_.\d]/i, 'firewall'], [/^(sw|core|dist|acc|tor)[-_.\d]/i, 'switch'], [/^(rtr|router|gw|wan)[-_.\d]/i, 'router'],
  [/^ap[-_.\d]/i, 'ap'], [/^(prn|print|mfp|copier)/i, 'printer'], [/^sep[0-9a-f]{12}$/i, 'phone'],
  [/^(srv|svr|dc\d|sql|app|web|db|esx|hv|exch|file)[-_.\d]/i, 'server'], [/^(pc|ws|lt|lap|desk|nb)[-_.\d]/i, 'workstation'],
];

// "SunOS host 5.11 11.4.42.111.0 sun4v" → "Oracle Solaris 11.4 (SPARC)"; "SunOS host 5.10 Generic_150400-59 i86pc" → "Oracle Solaris 10 (x86)"
function solaris(d) {
  const m = /SunOS\s+\S+\s+5\.(\d+)(?:\s+(11\.\d+))?[^\n]*?\b(sun4\w*|i86pc)?\s*$/i.exec(d) || /SunOS[^\n]*?5\.(\d+)(?:\s+(11\.\d+))?/i.exec(d);
  if (!m) return /Solaris\s*\d+(\.\d+)?/i.test(d) ? 'Oracle ' + /Solaris\s*\d+(\.\d+)?/i.exec(d)[0] : null;
  const major = Number(m[1]), rel = major >= 11 ? (m[2] || (/\b11\.(\d)\b/.exec(d) || [])[0] || '11') : String(major);
  const arch = /sun4/i.test(d) ? ' (SPARC)' : /i86pc/i.test(d) ? ' (x86)' : '';
  return 'Oracle Solaris ' + rel + arch;
}

function osFrom(dev) {
  if (dev.os) return dev.os;
  const d = String(dev.sys_descr || '');
  if (/SunOS|Solaris/i.test(d)) return solaris(d);
  let m = /(Windows[^,;]*)/i.exec(d); if (m) return m[1].trim().slice(0, 80);
  m = /(FortiOS[^,;]*|PAN-OS[^,;]*|NX-OS|Cisco IOS[^,;]*|ArubaOS-CX[^,;]*|JUNOS [^,;]*|VMware ESXi[^,;]*|RouterOS[^,;]*)/i.exec(d); if (m) return m[1].trim().slice(0, 80);
  if (/Linux/i.test(d)) return 'Linux';
  return null;
}

function classify(dev) {
  const score = {}; const reasons = [];
  const add = (t, s, why) => { if (!s) return; score[t] = Math.max(score[t] || 0, s) + (score[t] ? 5 : 0); reasons.push(`${why} → ${t}`); };
  const x = dev.extra || {};
  const methods = new Set(dev.methods ? Object.keys(dev.methods) : []);
  let vendor = null;

  if (x.cloud) add('cloud', 95, `${x.cloud.provider} instance`);
  if (x.vcenter && x.vcenter.kind === 'vm') add('vm', 92, 'vCenter virtual machine');
  if (x.vcenter && x.vcenter.kind === 'host') add('server', 90, 'vCenter ESXi host');
  if (x.nutanix && x.nutanix.kind === 'vm') add('vm', 92, 'Nutanix virtual machine');
  if (x.nutanix && x.nutanix.kind === 'host') { add('server', 90, 'Nutanix host'); vendor = vendor || 'Nutanix'; }
  if (x.db && x.db.length) add('server', 70, 'database listener (' + x.db.map((d) => d.label + ' ' + d.port).join(', ') + ')');
  if (x.unix && x.unix.os) { add('server', x.unix.confidence || 60, (x.unix.label || 'Unix server') + (x.unix.ssh_banner ? ' (' + x.unix.ssh_banner + ')' : '')); if (x.unix.os === 'solaris') vendor = vendor || 'Oracle'; }
  if (x.storage && x.storage.protocols && x.storage.protocols.length) { const p = x.storage.protocols; add('storage', p.includes('ndmp') ? 75 : p.includes('iscsi') ? 65 : 30, 'storage protocols open (' + p.join(', ') + ')'); }
  // read-only logins (methods/login.js): what the system itself said after a successful login
  if (x.storage_login && x.storage_login.platform) { add('storage', 95, (x.storage_login.platform === 'ontap' ? 'NetApp ONTAP' : 'HPE MSA') + ' API login'); vendor = vendor || (x.storage_login.platform === 'ontap' ? 'NetApp' : 'HPE'); }
  if (x.unix_login && x.unix_login.os) { add('server', 88, 'SSH login: ' + x.unix_login.os); if (/solaris/i.test(x.unix_login.os)) vendor = vendor || 'Oracle'; }
  if (x.db_login && Object.keys(x.db_login).length) add('server', 85, 'database login (' + Object.keys(x.db_login).join(', ') + ')');
  if (x.hyperv && x.hyperv.kind === 'vm') add('vm', 90, 'Hyper-V virtual machine');
  if (x.hyperv && x.hyperv.kind === 'host') add('server', 85, 'Hyper-V host');
  if (x.cucm) { add('phone', 95, 'registered in CUCM'); vendor = vendor || 'Cisco'; }
  if (x.ad) {
    if (x.ad.is_dc) add('server', 90, 'AD domain controller');
    else if (/server/i.test(x.ad.os || '')) add('server', 80, 'AD computer with a server OS');
    else if (x.ad.os) add('workstation', 75, 'AD computer with a client OS');
  }
  const d = String(dev.sys_descr || '');
  for (const [re, t, s, v] of DESCR_RULES) if (d && re.test(d)) { add(t, s, `sysDescr matches ${re.source.split('|')[0].replace(/\\b/g, '')}`); if (v && !vendor) vendor = v; break; }
  const ent = enterpriseVendor(dev.sys_object_id);
  if (ent) { vendor = vendor || ent; reasons.push(`sysObjectID enterprise → ${ent}`); if (/^\.?1\.3\.6\.1\.4\.1\.12356\.101\b/.test(dev.sys_object_id || '')) add('firewall', 85, 'FortiGate sysObjectID'); if (ent === 'Palo Alto Networks') add('firewall', 85, 'Palo Alto sysObjectID'); if (/NetApp|Dell EMC|EqualLogic|Huawei Storage|Nimble|Pure Storage|Synology|QNAP/.test(ent)) add('storage', 80, `${ent} sysObjectID`); }
  const ports = new Set(dev.open_ports || []);
  if (ports.has(3389) || ports.has(135) || ports.has(445) || ports.has(5985)) add(/server/i.test(dev.os || '') ? 'server' : 'workstation', 40, 'Windows service ports open');
  if (ports.has(22) && !ports.has(3389) && !ports.has(445)) add('server', 35, 'SSH open (no Windows ports)');
  if (ports.has(9100) || ports.has(631) || ports.has(515)) add('printer', 70, 'printing ports open');
  for (const m of [dev.mac].concat(dev.macs || [])) {
    const ov = ouiVendor(m);
    if (!ov) continue;
    vendor = vendor || ov;
    reasons.push(`MAC OUI → ${ov}`);
    if (OUI_ROLE[ov]) add(OUI_ROLE[ov], OUI_ROLE[ov] === 'vm' || OUI_ROLE[ov] === 'cloud' ? 65 : 55, `MAC vendor ${ov}`);
    break;
  }
  const host = String(dev.hostname || '').split('.')[0];
  for (const [re, t] of NAME_RULES) if (host && re.test(host)) { add(t, 25, `host name pattern "${host}"`); break; }
  if (methods.has('arp') && methods.size === 1 && !Object.keys(score).length) reasons.push('seen only in the ARP table');

  let best = 'unknown'; let bs = 0;
  for (const t of Object.keys(score)) if (score[t] > bs) { best = t; bs = score[t]; }
  if (bs < 30) { best = 'unknown'; }
  // a VM / cloud verdict from a system of record outranks port/OUI hints for "server"/"workstation"
  return { type: best, vendor: vendor || null, os: osFrom(dev), confidence: Math.min(99, bs), reasons: reasons.slice(0, 12) };
}

// discovery class → ITAM asset type
const ITAM_TYPE = { storage: 'storage', server: 'server', workstation: 'workstation', switch: 'network', router: 'network', firewall: 'network', ap: 'network', printer: 'printer', phone: 'phone', vm: 'vm', cloud: 'vm', unknown: 'other' };

module.exports = { classify, ouiVendor, enterpriseVendor, osFrom, OUI, ENTERPRISE, TYPES, ITAM_TYPE, hex12 };
