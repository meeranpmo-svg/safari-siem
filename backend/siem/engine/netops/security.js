// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Network security checks (read-only), run every `security_interval_s` (default 6 h) per device by poller.js.
 *   check(dev, cred, opts) → { at, items:[{kind, severity, key, title, evidence[], rec}], errors[] }
 * Checks:
 *   - management exposure: Telnet (23) open; HTTP (80) open without redirecting to HTTPS          (one TCP connect each)
 *   - management certificate: expired / expiring within 30 days                                  (TLS handshake only)
 *   - monitoring hygiene: SNMP v2c (clear-text community), SNMPv3 without privacy, certificate not verified
 *   - FortiGate configuration (REST cmdb, GET): any-any accept policies, internet-to-any accept, accept policies with
 *     logging off, Telnet/HTTP admin access on interfaces, HTTPS/SSH admin on WAN interfaces, administrators without
 *     trusted hosts
 *   - Palo Alto configuration (XML API type=config action=get — needs "Configuration" read in the API role; skipped
 *     quietly when not allowed): any/any/any allow rules, allow rules without end-of-session logging, management
 *     profiles with Telnet/HTTP
 * Also reads the firewall configuration FACTS (fwfacts.js) for the PAN-OS baseline hardening and the connectivity
 * troubleshooter, kept as `facts` beside the findings.
 * Nothing is changed on a device; results become findings ("sec-…") with a recommendation.
 */
const net = require('node:net');
const tls = require('node:tls');
const http = require('node:http');
const { getJSON, getRaw, normFp } = require('./http');
const X = require('./xml');
const FACTS = require('./fwfacts');

function tcpOpen(ip, port, timeoutMs = 2500) {
  return new Promise((resolve) => {
    const s = net.connect({ host: ip, port, timeout: timeoutMs });
    const done = (v) => { s.destroy(); resolve(v); };
    s.once('connect', () => done(true)); s.once('timeout', () => done(false)); s.once('error', () => done(false));
  });
}
function httpRedirectsToHttps(ip, port, timeoutMs = 3000) {
  return new Promise((resolve) => {
    const req = http.get({ host: ip, port, path: '/', timeout: timeoutMs, headers: { 'User-Agent': 'sentra-siem-netops/1' } }, (res) => {
      const loc = String(res.headers.location || ''); res.resume(); resolve(res.statusCode >= 300 && res.statusCode < 400 && /^https:/i.test(loc));
    });
    req.on('timeout', () => { req.destroy(); resolve(null); }); req.on('error', () => resolve(null));
  });
}
function certInfo(host, port, timeoutMs = 4000) {
  return new Promise((resolve) => {
    const s = tls.connect({ host, port, servername: net.isIP(host) ? undefined : host, rejectUnauthorized: false, timeout: timeoutMs }, () => {
      const c = s.getPeerCertificate(); s.end();
      resolve(c && c.valid_to ? { valid_to: Date.parse(c.valid_to), subject: (c.subject && c.subject.CN) || '', issuer: (c.issuer && c.issuer.CN) || '', fingerprint256: c.fingerprint256 } : null);
    });
    s.on('timeout', () => { s.destroy(); resolve(null); }); s.on('error', () => resolve(null));
  });
}

const names = (a) => (Array.isArray(a) ? a.map((x) => String(x && (x.name || x.q_origin_key) || x)) : []);
const WANRE = /^(wan|internet|isp|outside|untrust|stc|mobily|zain|dia|mpls-?wan)/i;

async function fortigateConfig(dev, cred, add, errors) {
  const base = `https://${dev.api_host || dev.ip}:${cred.port || 443}`, o = { headers: { Authorization: 'Bearer ' + cred.token }, tls: cred.tls, timeoutMs: 12000 };
  const vd = cred.vdom ? '?vdom=' + encodeURIComponent(cred.vdom) : '';
  const get = async (p) => (await getJSON(base + p + vd, o)).results || [];
  let ifs = [], wanSet = new Set();
  try {
    ifs = await get('/api/v2/cmdb/system/interface');
    const wanNames = new Set(ifs.filter((i) => i.role === 'wan' || WANRE.test(i.name) || WANRE.test(i.alias || '')).map((i) => i.name));
    for (const i of ifs) {
      const acc = String(i.allowaccess || '').split(/\s+/).filter(Boolean), wan = wanNames.has(i.name);
      if (acc.includes('telnet')) add('high', 'mgmt-telnet', i.name, `Telnet administration enabled on ${i.name}`, [`allowaccess: ${acc.join(' ')}`], `Remove telnet: config system interface → edit ${i.name} → unselect allowaccess telnet.`);
      if (acc.includes('http')) add(wan ? 'high' : 'medium', 'mgmt-http', i.name, `HTTP (unencrypted) administration enabled on ${i.name}`, [`allowaccess: ${acc.join(' ')}`], `Remove http from allowaccess on ${i.name}; use HTTPS only.`);
      if (wan && (acc.includes('https') || acc.includes('ssh'))) add('medium', 'mgmt-wan', i.name, `Administration (${acc.filter((a) => a === 'https' || a === 'ssh').join('/')}) reachable on internet-facing interface ${i.name}`, [`allowaccess: ${acc.join(' ')}`], 'Allow administration only on an internal management interface, or restrict administrators with trusted hosts.');
    }
    wanSet = wanNames;
  } catch (e) { errors.push('interfaces: ' + e.message); }
  try {
    const pol = await get('/api/v2/cmdb/firewall/policy');
    for (const p of pol) {
      if (p.status === 'disable' || p.action !== 'accept') continue;
      const src = names(p.srcaddr), dst = names(p.dstaddr), svc = names(p.service), sif = names(p.srcintf), id = `${p.policyid}${p.name ? ' (' + p.name + ')' : ''}`;
      const anySrc = src.includes('all'), anyDst = dst.includes('all'), anySvc = svc.includes('ALL');
      const fromWan = sif.some((n) => wanSet.has(n) || WANRE.test(n));
      if (anySrc && anyDst && anySvc) add('high', 'fw-any-any', String(p.policyid), `Policy ${id} allows any source to any destination on any service`, [`${sif.join(',')} → ${names(p.dstintf).join(',')}`], 'Replace with specific addresses and services, or set it to deny; review its hit count first.');
      else if (fromWan && anyDst && anySvc) add('high', 'fw-internet-any', String(p.policyid), `Policy ${id} allows the internet to reach any internal address on any service`, [`from ${sif.join(',')}, source ${src.join(',')}`], 'Limit the destination to published servers and the service to the ports they need.');
      if (p.logtraffic === 'disable') add('medium', 'fw-nolog', String(p.policyid), `Policy ${id} accepts traffic without logging`, [], 'Set logtraffic to "all" (or at least "utm") so the SIEM sees this traffic.');
    }
  } catch (e) { errors.push('policies: ' + e.message); }
  try {
    const adm = await get('/api/v2/cmdb/system/admin');
    for (const a of adm) {
      const th = Object.keys(a).filter((k) => /^trusthost\d+$/.test(k)).map((k) => String(a[k]).trim());
      const open = !th.length || th.every((t) => /^0\.0\.0\.0[ /]0\.0\.0\.0$|^0\.0\.0\.0\/0$/.test(t));
      if (open) add('medium', 'fw-admin-anywhere', a.name, `Administrator "${a.name}" can log in from any address`, [`profile ${a.accprofile || ''}`], 'Set trusted hosts for every administrator (management subnet / jump host only).');
    }
    if (adm.some((a) => a.name === 'admin')) add('low', 'fw-default-admin', 'admin', 'The default "admin" account exists', [], 'Create named administrators and disable or rename "admin".');
  } catch (e) { errors.push('admins: ' + e.message); }
}

async function paloaltoConfig(dev, cred, add, errors) {
  const base = `https://${dev.api_host || dev.ip}:${cred.port || 443}/api/`, o = { headers: { 'X-PAN-KEY': cred.token }, tls: cred.tls, timeoutMs: 15000 };
  const get = async (xpath) => {
    const r = await getRaw(base + '?type=config&action=get&xpath=' + encodeURIComponent(xpath), o);
    if (r.status === 403 || r.status === 401) throw Object.assign(new Error('not allowed'), { denied: true });
    const d = X.parse(r.text); if (d.attrs.status !== 'success') throw Object.assign(new Error(X.txt(d, 'msg/line') || X.txt(d, 'msg') || 'API error'), { denied: /not authorized|access denied|Unauthorized/i.test(r.text) });
    return d;
  };
  const mem = (e, p) => X.all(e, p + '/member').map((m) => m.text.trim());
  try {
    const d = await get("/config/devices/entry/vsys/entry/rulebase/security/rules");
    for (const e of X.all(d, 'result/rules/entry')) {
      if (X.txt(e, 'disabled') === 'yes' || X.txt(e, 'action') !== 'allow') continue;
      const n = e.attrs.name, any = (p) => mem(e, p).includes('any');
      if (any('source') && any('destination') && any('application'))
        add('high', 'pa-any-any', n, `Security rule "${n}" allows any source to any destination for any application`, [`from ${mem(e, 'from').join(',')} to ${mem(e, 'to').join(',')}`], 'Restrict sources, destinations and applications; check the rule\'s hit count before changing it.');
      if (X.txt(e, 'log-end') === 'no') add('medium', 'pa-nolog', n, `Security rule "${n}" allows traffic without end-of-session logging`, [], 'Enable "Log at Session End" and forward the logs to the SIEM.');
    }
  } catch (e) { if (e.denied) errors.push('configuration read not allowed for this API key (optional: add Configuration read to its admin role)'); else errors.push('rules: ' + e.message); return; }
  try {
    const d = await get('/config/devices/entry/network/profiles/interface-management-profile');
    for (const e of X.all(d, 'result/interface-management-profile/entry')) {
      for (const p of ['telnet', 'http']) if (X.txt(e, p) === 'yes') add(p === 'telnet' ? 'high' : 'medium', 'pa-mgmt-' + p, e.attrs.name + p, `Management profile "${e.attrs.name}" allows ${p.toUpperCase()}`, [], `Disable ${p} in the interface management profile; use HTTPS/SSH from the management network only.`);
    }
  } catch (e) { errors.push('management profiles: ' + e.message); }
}

async function check(dev, cred = {}, opts = {}) {
  const items = [], errors = [], now = opts.now || Date.now();
  const add = (severity, kind, key, title, evidence, rec) => items.push({ kind, severity, key: String(key || ''), title, evidence: (evidence || []).filter(Boolean), rec });
  const ports = opts.ports || { telnet: 23, http: 80 };
  if ((dev.poll && dev.poll.ping !== false) || opts.probe) {
    if (await tcpOpen(dev.ip, ports.telnet)) add('high', 'telnet-open', 'telnet', `Telnet is open on ${dev.name} (${dev.ip})`, [`TCP ${ports.telnet} accepts connections`], 'Disable Telnet and use SSH; Telnet sends passwords in clear text.');
    if (await tcpOpen(dev.ip, ports.http)) { const red = await httpRedirectsToHttps(dev.ip, ports.http); if (red === false) add('medium', 'http-open', 'http', `Unencrypted HTTP management answers on ${dev.name} (${dev.ip})`, [`TCP ${ports.http} serves pages without redirecting to HTTPS`], 'Disable HTTP management or force a redirect to HTTPS.'); }
  }
  if (cred.api) {
    const ci = await certInfo(dev.api_host || dev.ip, cred.api.port || (dev.vendor === 'genian' ? 8443 : 443));
    if (ci && ci.valid_to) {
      const days = Math.floor((ci.valid_to - now) / 86400000);
      if (days < 0) add('high', 'cert-expired', 'cert', `Management certificate on ${dev.name} expired ${-days} days ago`, [`subject ${ci.subject}, issuer ${ci.issuer}`], 'Renew the device certificate (and update the pinned fingerprint in the credentials).');
      else if (days <= 30) add('medium', 'cert-expiring', 'cert', `Management certificate on ${dev.name} expires in ${days} days`, [`subject ${ci.subject}, valid to ${new Date(ci.valid_to).toISOString().slice(0, 10)}`], 'Renew it before it expires; afterwards update the pinned fingerprint.');
      const pin = cred.api.tls && cred.api.tls.fingerprint256; if (pin && normFp(ci.fingerprint256) !== normFp(pin)) add('medium', 'cert-changed', 'pin', `Certificate on ${dev.name} no longer matches the pinned fingerprint`, [], 'If the certificate was renewed on purpose, update the fingerprint; otherwise investigate (possible interception).');
    }
    if (cred.api.tls && cred.api.tls.insecure) add('medium', 'mon-insecure-tls', 'tls', `${dev.name}: monitoring connection does not verify the device certificate`, [], 'Pin the certificate fingerprint in Devices → Credentials.');
  }
  if (cred.snmp && cred.snmp.version === '2c') add('medium', 'snmp-v2c', 'snmp', `${dev.name} is monitored with SNMP v2c (community string in clear text)`, [], 'Configure an SNMPv3 user with SHA authentication and AES privacy, then switch the credentials to v3.');
  if (cred.snmp && cred.snmp.version === '3' && !cred.snmp.privKey) add('low', 'snmp-nopriv', 'snmp', `${dev.name}: SNMPv3 without privacy (data not encrypted)`, [], 'Add an AES privacy password to the SNMPv3 user.');
  if (cred.api && cred.api.token && dev.poll && dev.poll.api) {
    try {
      if (dev.vendor === 'fortigate') await fortigateConfig(dev, cred.api, add, errors);
      else if (dev.vendor === 'paloalto') await paloaltoConfig(dev, cred.api, add, errors);
    } catch (e) { errors.push(e.message); }
  }
  // configuration facts for the Palo Alto baseline hardening and the connectivity troubleshooter (fwfacts.js, read-only)
  let facts = null;
  if (cred.api && cred.api.token && dev.poll && dev.poll.api && (dev.vendor === 'paloalto' || dev.vendor === 'fortigate') && opts.facts !== false) {
    try { facts = await (opts.factsFn || FACTS[dev.vendor])(dev, cred.api, { now: () => now }); } catch (e) { errors.push('configuration facts: ' + e.message); }
  }
  return { at: now, items, errors, facts };
}

module.exports = { check, tcpOpen, certInfo, httpRedirectsToHttps };
