// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Application and protocol mapping for flow records, in this order (the first that answers wins):
 *   1. the custom application table an administrator keeps (Exporters & settings → Applications): a name for a protocol +
 *      ports / port ranges and / or address ranges (CIDR) - e.g. "Core insurance system" = TCP 8443 to 10.20.0.0/24
 *   2. the application the exporter itself named: NBAR2 / IPFIX applicationName (96), or applicationId (95) resolved through
 *      the exporter's own options data; an id the exporter never named stays "app <engine>:<selector>"
 *   3. well-known ports (IANA) and IP protocols (ICMP, ESP, GRE, OSPF ...)
 *   4. otherwise '' - the page shows "unclassified" with the protocol / port, never a guess
 *   createAppMapper(custom[]) → { classify(rec) → name, service(rec) → { sport, dport } }
 * service(): the side that is the service is kept, the ephemeral client port is set to 0 - otherwise every client port
 * would be its own row and the one-minute rollups would grow without bound.
 */
const { createCidrSet } = require('../detect/ip');

const PROTO = { 1: 'ICMP', 2: 'IGMP', 6: 'TCP', 17: 'UDP', 47: 'GRE', 50: 'ESP', 51: 'AH', 58: 'ICMPv6', 88: 'EIGRP', 89: 'OSPF', 103: 'PIM', 112: 'VRRP', 132: 'SCTP' };
const BY_PROTO = { 1: 'ICMP', 58: 'ICMPv6', 47: 'GRE', 50: 'IPsec ESP', 51: 'IPsec AH', 89: 'OSPF', 88: 'EIGRP', 112: 'VRRP', 2: 'IGMP', 103: 'PIM' };
const TCP = { 20: 'FTP data', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 80: 'HTTP', 88: 'Kerberos', 110: 'POP3', 111: 'RPC portmap', 135: 'MS RPC', 139: 'NetBIOS session',
  143: 'IMAP', 179: 'BGP', 389: 'LDAP', 443: 'HTTPS', 445: 'SMB', 464: 'Kerberos password', 465: 'SMTPS', 587: 'SMTP submission', 636: 'LDAPS', 873: 'rsync', 993: 'IMAPS', 995: 'POP3S',
  1433: 'MS SQL', 1521: 'Oracle', 1723: 'PPTP', 2049: 'NFS', 2484: 'Oracle TLS', 3268: 'AD Global Catalog', 3269: 'AD Global Catalog TLS', 3306: 'MySQL', 3389: 'RDP', 5060: 'SIP', 5061: 'SIP TLS',
  5432: 'PostgreSQL', 5900: 'VNC', 5985: 'WinRM', 5986: 'WinRM TLS', 6379: 'Redis', 8080: 'HTTP alt', 8443: 'HTTPS alt', 9100: 'Printing (raw)', 9200: 'Elasticsearch', 27017: 'MongoDB' };
const UDP = { 53: 'DNS', 67: 'DHCP', 68: 'DHCP', 69: 'TFTP', 88: 'Kerberos', 123: 'NTP', 137: 'NetBIOS name', 138: 'NetBIOS datagram', 161: 'SNMP', 162: 'SNMP trap', 443: 'QUIC', 500: 'IPsec IKE',
  514: 'Syslog', 1194: 'OpenVPN', 1812: 'RADIUS', 1813: 'RADIUS accounting', 2055: 'NetFlow', 3478: 'STUN', 4500: 'IPsec NAT-T', 4739: 'IPFIX', 5060: 'SIP', 6343: 'sFlow' };
function wellKnown(proto, port) { return proto === 6 ? TCP[port] : proto === 17 ? UDP[port] : undefined; }
function protoName(p) { return PROTO[p] || 'IP ' + p; }

function createAppMapper(custom) {
  const list = (custom || []).map((a) => ({ name: a.name, proto: a.proto === 'tcp' ? 6 : a.proto === 'udp' ? 17 : 0,
    ports: (a.ports || []).map((r) => (Array.isArray(r) ? r : [r, r])), cidrs: a.cidrs && a.cidrs.length ? createCidrSet(a.cidrs) : null }));
  const inPorts = (ports, p) => ports.some((r) => p >= r[0] && p <= r[1]);
  function custom1(rec) {
    for (const a of list) {
      if (a.proto && a.proto !== rec.proto) continue;
      let side = null;
      if (a.ports.length) { if (inPorts(a.ports, rec.dport)) side = 'd'; else if (inPorts(a.ports, rec.sport)) side = 's'; else continue; }
      if (a.cidrs && !a.cidrs.has(rec.src) && !a.cidrs.has(rec.dst)) continue;
      return { name: a.name, side };
    }
    return null;
  }
  function classify(rec) {
    const c = custom1(rec); if (c) return c.name;
    if (rec.app_name) return rec.app_name;
    if (rec.app_id) return 'app ' + rec.app_id;
    if (BY_PROTO[rec.proto]) return BY_PROTO[rec.proto];
    const d = wellKnown(rec.proto, rec.dport), s = wellKnown(rec.proto, rec.sport);
    if (d && s) return rec.dport <= rec.sport ? d : s;
    return d || s || '';
  }
  function service(rec) {
    if (rec.proto !== 6 && rec.proto !== 17 && rec.proto !== 132) return { sport: 0, dport: 0 };
    const c = custom1(rec);
    if (c && c.side === 's') return { sport: rec.sport, dport: 0 };
    if (c && c.side === 'd') return { sport: 0, dport: rec.dport };
    const dk = !!wellKnown(rec.proto, rec.dport) || rec.dport < 1024, sk = !!wellKnown(rec.proto, rec.sport) || rec.sport < 1024;
    if (sk && !dk) return { sport: rec.sport, dport: 0 };   // a reply from the service
    return { sport: 0, dport: rec.dport };
  }
  return { classify, service };
}

module.exports = { createAppMapper, wellKnown, protoName, PROTO };
