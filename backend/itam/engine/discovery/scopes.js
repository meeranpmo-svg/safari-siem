// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Discovery scopes: what to scan, when, how fast, with which methods — plus the mandatory SAFETY GATE.
//   normScope(body, {cur, sites, maxHosts, credentials}) → clean scope fields (throws 400 with a precise message)
//   normChecklist(body) → checklist                        gateOpen(scope) → bool (checklist complete AND still valid)
//   allowedMethods(scope, globalMethods) → {run:[...], blocked:[{method, reason}]}
//   targetsFingerprint(scope) → sha256 of the targets + exclusions (a checklist is bound to it)
//
// ACTIVE methods send packets to the scope's addresses (ICMP/TCP sweep, SNMP). They are blocked until an admin has
// completed the pre-scan checklist for that exact set of targets. PASSIVE methods only read systems of record
// (AD, vCenter, Hyper-V reports, CUCM, Azure, AWS) or this server's own ARP cache, and may always run.
const crypto = require('node:crypto');
const ip4 = require('./ipv4');
const sched = require('./schedule');

const ACTIVE = ['sweep', 'snmp', 'db', 'unix', 'storage'];   // db: database listener ports; unix: SSH banner + Solaris service ports
const PASSIVE = ['arp', 'ad', 'vcenter', 'nutanix', 'hyperv', 'cucm', 'azure', 'aws'];
const METHODS = ACTIVE.concat(PASSIVE);
const DEFAULT_TCP_PORTS = [22, 25, 80, 135, 443, 444, 445, 2525, 3389, 5985];   // 25 / 444 / 2525: Exchange (exchange-evidence.js)
// which credential kinds a method may use
// db / unix / storage probe without logging in; a credential only ADDS a read-only login (methods/login.js)
const OPTIONAL_CRED = ['db', 'unix', 'storage'];
const METHOD_CRED = { snmp: ['snmp_v2c', 'snmp_v3'], db: ['db_login'], unix: ['ssh'], storage: ['storage_api'], ad: ['ldap'], vcenter: ['vcenter'], nutanix: ['nutanix'], cucm: ['cucm_axl'], azure: ['azure'], aws: ['aws'] };

const bad = (msg) => Object.assign(new Error(msg), { status: 400 });
const str = (v, max) => String(v == null ? '' : v).replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, max);
const isObj = (v) => v && typeof v === 'object' && !Array.isArray(v);

function intIn(v, lo, hi, what, dflt) {
  if (v === undefined || v === null || v === '') return dflt;
  const n = Number(v);
  if (!Number.isInteger(n) || n < lo || n > hi) throw bad(`${what} must be an integer ${lo}-${hi}`);
  return n;
}
function bool(v, what, dflt) {
  if (v === undefined) return dflt;
  if (typeof v !== 'boolean') throw bad(`${what} must be true or false`);
  return v;
}

// a target is "public" unless it lies entirely inside one RFC 1918 block
function isPublicTarget(t) {
  if (!ip4.isPrivate(t.first) || !ip4.isPrivate(t.last)) return true;
  const blocks = [[0x0a000000, 8], [0xac100000, 12], [0xc0a80000, 16]];
  return !blocks.some(([b, l]) => ip4.inCidr(t.first, b, l) && ip4.inCidr(t.last, b, l));
}

function normTargets(list, what, { allowPublic, max }) {
  if (!Array.isArray(list)) throw bad(`${what} must be a list`);
  if (list.length > 256) throw bad(`${what}: at most 256 entries`);
  const out = []; let total = 0;
  for (const raw of list) {
    const t = ip4.parseTarget(raw);
    if (ip4.isSpecial(t.first) || ip4.isSpecial(t.last)) throw bad(`${what}: ${t.text} is a loopback, link-local, multicast or reserved address`);
    if (what === 'targets' && !allowPublic && isPublicTarget(t)) throw bad(`targets: ${t.text} is not private (RFC 1918). Public ranges need allow_public=true and must be ranges you own`);
    if (!out.some((x) => x.text === t.text)) { out.push(t); total += t.count; }
  }
  if (what === 'targets' && total > max) throw bad(`targets cover ${total} addresses; the limit per scope is ${max}`);
  return out;
}

function normMethods(raw, cur, credentials) {
  const m = isObj(raw) ? raw : {};
  const prev = (cur && cur.methods) || {};
  const out = {};
  for (const k of Object.keys(m)) if (!METHODS.includes(k)) throw bad(`unknown method "${k}" (allowed: ${METHODS.join(', ')})`);
  for (const k of METHODS) {
    const p = Object.assign({ enabled: false }, prev[k] || {});
    const b = isObj(m[k]) ? m[k] : (typeof m[k] === 'boolean' ? { enabled: m[k] } : {});
    const o = { enabled: bool(b.enabled, `methods.${k}.enabled`, !!p.enabled) };
    if (k === 'sweep') {
      o.icmp = bool(b.icmp, 'methods.sweep.icmp', p.icmp !== false);
      const ports = b.tcp_ports !== undefined ? b.tcp_ports : (p.tcp_ports || DEFAULT_TCP_PORTS);
      if (!Array.isArray(ports) || ports.length > 32) throw bad('methods.sweep.tcp_ports must be a list of up to 32 ports');
      o.tcp_ports = [...new Set(ports.map((x) => intIn(x, 1, 65535, 'methods.sweep.tcp_ports[]')))].sort((a, b2) => a - b2);
      if (o.tcp_ports.includes(161)) throw bad('UDP 161 is not a TCP port — enable the SNMP method instead (it sends an SNMP get of sysDescr)');
    }
    if (k === 'db') {
      const DBE = ['oracle', 'mssql', 'mysql', 'postgres', 'db2', 'mongodb', 'hana'];
      const e = b.engines !== undefined ? b.engines : (p.engines || DBE);
      if (!Array.isArray(e) || !e.length) throw bad('methods.db.engines must be a non-empty list');
      for (const x of e) if (!DBE.includes(String(x))) throw bad(`methods.db.engines: unknown engine "${x}" (allowed: ${DBE.join(', ')})`);
      o.engines = [...new Set(e.map(String))];
      // non-standard listener ports per engine, probed besides the well-known ones (a database login's own port is added at scan time)
      const pin = b.ports !== undefined ? b.ports : (p.ports || {});
      if (!isObj(pin)) throw bad('methods.db.ports must be an object such as {"oracle": [1600], "mssql": [51433]}');
      o.ports = {};
      for (const [eng, raw] of Object.entries(pin)) {
        if (!DBE.includes(eng)) throw bad(`methods.db.ports: unknown engine "${eng}" (allowed: ${DBE.join(', ')})`);
        const arr = Array.isArray(raw) ? raw : [raw];
        if (arr.length > 16) throw bad(`methods.db.ports.${eng}: at most 16 ports`);
        const v = [...new Set(arr.map((x) => intIn(x, 1, 65535, `methods.db.ports.${eng}[]`)))].sort((a, b2) => a - b2);
        if (v.length) o.ports[eng] = v;
      }
    }
    if (k === 'snmp' || k === 'db') {   // several: SNMP tries each, a database credential is per engine
      const ids = b.credential_ids !== undefined ? b.credential_ids : (p.credential_ids || []);
      if (!Array.isArray(ids) || ids.length > 8) throw bad(`methods.${k}.credential_ids must be a list (max 8)`);
      o.credential_ids = ids.map((x) => str(x, 64)).filter(Boolean);
    } else if (METHOD_CRED[k]) {
      o.credential_id = b.credential_id !== undefined ? (str(b.credential_id, 64) || null) : (p.credential_id || null);
    }
    // credential references must exist and be of the right kind
    const refs = k === 'snmp' || k === 'db' ? o.credential_ids : (o.credential_id ? [o.credential_id] : []);
    if (credentials) for (const id of refs) {
      const c = credentials(id);
      if (!c) throw bad(`methods.${k}: credential ${id} not found`);
      if (!METHOD_CRED[k].includes(c.kind)) throw bad(`methods.${k}: credential ${id} is ${c.kind}, expected ${METHOD_CRED[k].join(' or ')}`);
    }
    if (o.enabled && METHOD_CRED[k] && !OPTIONAL_CRED.includes(k) && !refs.length) throw bad(`methods.${k}: choose a credential before enabling it`);
    out[k] = o;
  }
  return out;
}

// full validation of a create (cur = null) or update (cur = existing scope; missing fields keep their value)
function normScope(body, { cur = null, sites = [], maxHosts = 4096, credentials = null } = {}) {
  const b = isObj(body) ? body : {};
  const pick = (k) => (b[k] !== undefined ? b[k] : cur ? cur[k] : undefined);
  const name = str(pick('name'), 120);
  if (!name) throw bad('name is required');
  const site = str(pick('site'), 80);
  if (!site) throw bad('site is required');
  if (sites.length && !sites.includes(site)) throw bad(`site must be one of: ${sites.join(', ')}`);
  const allowPublic = bool(b.allow_public, 'allow_public', cur ? !!cur.allow_public : false);
  const targetsIn = b.targets !== undefined ? b.targets : (cur ? cur.targets : []);
  const targets = normTargets(targetsIn, 'targets', { allowPublic, max: maxHosts });
  const exclusions = normTargets(b.exclusions !== undefined ? b.exclusions : (cur ? cur.exclusions : []), 'exclusions', { allowPublic: true, max: Infinity });
  const vlanRaw = pick('vlan');
  const vlan = vlanRaw === null || vlanRaw === undefined || vlanRaw === '' ? null : intIn(vlanRaw, 1, 4094, 'vlan');
  const rateIn = isObj(b.rate) ? b.rate : {};
  const rateCur = (cur && cur.rate) || {};
  const rate = {
    max_hosts_per_sec: intIn(rateIn.max_hosts_per_sec, 1, 500, 'rate.max_hosts_per_sec', rateCur.max_hosts_per_sec || 20),
    concurrency: intIn(rateIn.concurrency, 1, 64, 'rate.concurrency', rateCur.concurrency || 8),
  };
  const schedule = sched.normSchedule(b.schedule !== undefined ? b.schedule : (cur ? cur.schedule : { type: 'manual' }));
  const window = b.window !== undefined ? sched.normWindow(b.window) : (cur ? cur.window || null : null);
  const methods = normMethods(b.methods, cur, credentials);
  const infra = bool(b.infra, 'infra', cur ? !!cur.infra : false);
  const label = str(pick('label'), 200);
  if (!targets.length && (methods.sweep.enabled || methods.snmp.enabled || methods.db.enabled || methods.unix.enabled || methods.storage.enabled || methods.arp.enabled)) throw bad('targets are required for sweep, SNMP, database / Unix probes and ARP');
  return {
    name, label, site, vlan, allow_public: allowPublic, infra,
    targets: targets.map((t) => t.text), exclusions: exclusions.map((t) => t.text),
    host_count: targets.reduce((n, t) => n + t.count, 0),
    rate, schedule, window, methods,
  };
}

function targetsFingerprint(scope) {
  return crypto.createHash('sha256').update(JSON.stringify([scope.targets || [], scope.exclusions || [], !!scope.allow_public])).digest('hex');
}

// pre-scan checklist (all three parts are mandatory)
function normChecklist(body) {
  const b = isObj(body) ? body : {};
  const fw = isObj(b.firewall) ? b.firewall : b;
  const need = ['snmp_161', 'ssh_22', 'winrm_5985_5986', 'icmp'];
  for (const k of need) if (fw[k] !== true) throw bad(`checklist: confirm the firewall allows ${k.replace(/_/g, ' ')} from the platform server to this scope (firewall.${k} = true)`);
  const socName = str(b.soc_notified_name, 120);
  if (!socName) throw bad('checklist: name the security team / SOC contact who was notified of the scan window (soc_notified_name)');
  const d = str(b.soc_notified_date, 10);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(d) || !Number.isFinite(Date.parse(d + 'T00:00:00Z'))) throw bad('checklist: soc_notified_date must be YYYY-MM-DD');
  const approvedBy = str(b.approved_by, 120);
  if (!approvedBy) throw bad('checklist: approved_by (name of the approver) is required');
  return { firewall: { snmp_161: true, ssh_22: true, winrm_5985_5986: true, icmp: true }, soc_notified_name: socName, soc_notified_date: d, approved_by: approvedBy, note: str(b.note, 500) };
}

function gateOpen(scope) {
  const c = scope && scope.checklist;
  return !!(c && c.completed_at && c.targets_fp === targetsFingerprint(scope));
}

function allowedMethods(scope, globalMethods) {
  const run = []; const blocked = [];
  const g = globalMethods || {};
  for (const k of METHODS) {
    const m = scope.methods && scope.methods[k];
    if (!m || !m.enabled) continue;
    if (g[k] === false) { blocked.push({ method: k, reason: 'disabled globally' }); continue; }
    if (ACTIVE.includes(k) && !gateOpen(scope)) { blocked.push({ method: k, reason: 'safety gate: pre-scan checklist not completed for these targets' }); continue; }
    run.push(k);
  }
  return { run, blocked };
}

module.exports = { OPTIONAL_CRED, normScope, normChecklist, gateOpen, allowedMethods, targetsFingerprint, isPublicTarget, ACTIVE, PASSIVE, METHODS, METHOD_CRED, DEFAULT_TCP_PORTS };
