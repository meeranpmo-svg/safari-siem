// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Network inventory for the AI Network Engineer.
 *   createInventory({ state, config, log, paths? })
 *     .list() .get(id) .put(input, by) .remove(id, by) .sites()
 *     .setCredentials(id, {snmp?, api?, ssh?}, by)   → stored in secrets.json "netops.devices.<id>" (mode 600, atomic, .bak kept)
 *     .credentials(id) → {snmp, api} (engine-internal only; never returned by the API)   .credentialSummary(id) → what is set
 *     .setFacts(id, facts) → model / serial / IOS read over SSH (cli.js), kept on the device as cli_facts
 *     .seedFromSources(by) → adds devices for the SIEM's onboarded network log sources (vendor + IP) that are not in the list
 * Devices live in the state collection "netops_devices". A device: { id, name, vendor, ip, api_host, site, role,
 * criticality: 1-3, poll: {ping, snmp, api}, notes, created, updated, updated_by }.
 */
const SF = require('../secretfile');   // secrets.json sealed at rest
const fs = require('node:fs');
const net = require('node:net');
const { writeJsonAtomic } = require('../onboard/store');

const VENDORS = ['cisco-ios', 'cisco-asa', 'fortigate', 'paloalto', 'genian', 'edgeconnect', 'cisco-ucs', 'other'];
const ROLES = ['core', 'distribution', 'access', 'wan-edge', 'firewall', 'branch-router', 'nac', 'sdwan-orchestrator', 'sdwan-appliance', 'router', 'compute', 'ups', 'wlc', 'fc_switch', 'other'];   // wlc: wireless LAN controller (wlc.js, SNMP) · fc_switch: Fibre Channel SAN switch
const ID_RE = /^[a-z0-9][a-z0-9-]{1,39}$/;
const TYPE_TO_VENDOR = { cisco: 'cisco-ios', 'cisco-ios': 'cisco-ios', 'cisco-asa-ftd': 'cisco-asa', ciscoasa: 'cisco-asa', fortigate: 'fortigate', 'palo-alto': 'paloalto', paloalto: 'paloalto', 'genian-nac': 'genian', genian: 'genian', silverpeak: 'edgeconnect', edgeconnect: 'edgeconnect', 'cisco-ucs': 'cisco-ucs', ucs: 'cisco-ucs' };

class InvError extends Error { constructor(code, msg) { super(msg); this.code = code; this.errors = [msg]; } }

function clean(s, max) { return String(s == null ? '' : s).replace(/[\u0000-\u001f<>]/g, '').trim().slice(0, max); }

function validate(input, existing) {
  const d = Object.assign({}, existing || {});
  if (!existing) { d.id = clean(input.id, 40).toLowerCase(); if (!ID_RE.test(d.id)) throw new InvError(400, 'device id: 2-40 lowercase letters, digits and dashes'); }
  if (input.name !== undefined || !existing) d.name = clean(input.name || d.id, 80);
  if (input.vendor !== undefined || !existing) { d.vendor = String(input.vendor || ''); if (!VENDORS.includes(d.vendor)) throw new InvError(400, 'vendor must be one of ' + VENDORS.join(', ')); }
  if (input.ip !== undefined || !existing) { d.ip = clean(input.ip, 45); if (!net.isIP(d.ip)) throw new InvError(400, 'management IP address required'); }
  if (input.api_host !== undefined) { d.api_host = clean(input.api_host, 253); if (d.api_host && !net.isIP(d.api_host) && !/^[a-z0-9.-]+$/i.test(d.api_host)) throw new InvError(400, 'api_host must be an IP or host name'); }
  if (input.site !== undefined || !existing) d.site = clean(input.site || 'Unassigned', 60);
  if (input.role !== undefined || !existing) { d.role = String(input.role || 'other'); if (!ROLES.includes(d.role)) throw new InvError(400, 'role must be one of ' + ROLES.join(', ')); }
  if (input.criticality !== undefined || !existing) { const c = Number(input.criticality || 2); d.criticality = c >= 1 && c <= 3 ? Math.round(c) : 2; }
  if (input.poll !== undefined || !existing) { const p = input.poll || {}; d.poll = { ping: p.ping !== false, snmp: !!p.snmp, api: !!p.api }; }
  if (input.uplinks !== undefined) d.uplinks = (Array.isArray(input.uplinks) ? input.uplinks : []).slice(0, 20).map((s) => clean(s, 64)).filter(Boolean);
  if (input.notes !== undefined) d.notes = clean(input.notes, 500);
  return d;
}

function validateCreds(c) {
  const out = {};
  if (c.snmp) {
    const s = c.snmp, v = String(s.version || '3');
    if (v === '2c') { if (!s.community) throw new InvError(400, 'SNMP v2c needs a community'); out.snmp = { version: '2c', community: String(s.community).slice(0, 64), port: +s.port || 161 }; }
    else if (v === '3') {
      if (!s.user) throw new InvError(400, 'SNMPv3 needs a user');
      for (const k of ['authKey', 'privKey']) if (s[k] && String(s[k]).length < 8) throw new InvError(400, 'SNMPv3 passwords must be at least 8 characters');
      const ap = String(s.authProto || 'sha').toLowerCase(); if (!['sha', 'sha256'].includes(ap)) throw new InvError(400, 'SNMPv3 authentication must be sha or sha256 (MD5 is not accepted)');
      if (s.privKey && !s.authKey) throw new InvError(400, 'SNMPv3 privacy needs authentication');
      out.snmp = { version: '3', user: String(s.user).slice(0, 64), authProto: ap, authKey: s.authKey ? String(s.authKey) : '', privProto: 'aes', privKey: s.privKey ? String(s.privKey) : '', port: +s.port || 161 };
    } else throw new InvError(400, 'SNMP version must be 2c or 3');
  }
  if (c.api) {
    // a token / API key, or (Cisco UCS Manager XML API, which has no keys) a read-only username and password
    const a = c.api, up = !a.token && a.username && a.password;
    if (!a.token && !up) throw new InvError(400, 'API token / key required (Cisco UCS: a read-only username and password)');
    if (up && !/^[A-Za-z0-9._@\\-]{1,64}$/.test(String(a.username))) throw new InvError(400, 'API username: letters, digits . _ @ \\ -');
    const tls = {}; if (a.fingerprint256) { const f = String(a.fingerprint256).replace(/[^0-9a-f]/gi, ''); if (f.length !== 64) throw new InvError(400, 'certificate fingerprint must be a SHA-256 fingerprint'); tls.fingerprint256 = f; }
    if (a.insecure) tls.insecure = true;
    out.api = { token: up ? undefined : String(a.token).slice(0, 512), username: up ? String(a.username) : undefined, password: up ? String(a.password).slice(0, 256) : undefined, port: +a.port || undefined, vdom: a.vdom ? clean(a.vdom, 31) : undefined, tls, nodes_path: a.nodes_path ? clean(a.nodes_path, 200) : undefined };
  }
  for (const kind of ['ssh', 'ssh_write']) {   // ssh: read-only CLI login (show commands, cli.js) · ssh_write: approved tasks only (tasks.js)
    if (!c[kind]) continue;
    if (kind === 'ssh_write' && c[kind].pam !== undefined) {   // the write account lives in the PAM: only its reference is stored
      const ref = String(c[kind].pam || '').trim(), port = c[kind].port === undefined || c[kind].port === '' ? 22 : +c[kind].port;
      if (!/^[A-Za-z0-9 _.:\/@\\-]{1,200}$/.test(ref)) throw new InvError(400, 'PAM account reference: letters, digits, space _ . : / @ \\ - (max 200)');
      if (!Number.isInteger(port) || port < 1 || port > 65535) throw new InvError(400, 'SSH port must be 1-65535');
      out.ssh_write = { pam: ref, port }; continue;
    }
    const h = c[kind], what = kind === 'ssh' ? 'SSH' : 'SSH write login'; if (!h.username || !h.password) throw new InvError(400, what + ' needs a username and a password');
    if (!/^[A-Za-z0-9._@\\-]{1,64}$/.test(String(h.username))) throw new InvError(400, what + ' username: letters, digits . _ @ \\ -');
    const port = h.port === undefined || h.port === '' ? 22 : +h.port; if (!Number.isInteger(port) || port < 1 || port > 65535) throw new InvError(400, what + ' port must be 1-65535');
    out[kind] = { username: String(h.username), password: String(h.password).slice(0, 256), secret: h.secret ? String(h.secret).slice(0, 256) : '', port };
  }
  return out;
}

function createInventory({ state, config, log, paths } = {}) {
  if (!state) throw new Error('inventory needs state');
  const col = state.collection('netops_devices');
  const secPath = (paths && paths.secrets) || (config && config._paths && config._paths.secrets);
  const L = log || { info() {}, warn() {} };
  function secretsAll() { return (config && config.secrets && config.secrets.netops && config.secrets.netops.devices) || {}; }

  return {
    VENDORS, ROLES,
    list: () => col.all().sort((a, b) => (a.site + a.name).localeCompare(b.site + b.name)),
    get: (id) => col.get(id) || null,
    put(input, by) {
      const ex = input && input.id ? col.get(String(input.id).toLowerCase()) : null;
      const d = validate(input || {}, ex);
      d.updated = Date.now(); d.updated_by = by || ''; if (!ex) d.created = d.updated;
      col.put(d); return d;
    },
    remove(id, by) {
      if (!col.get(id)) throw new InvError(404, 'device not found');
      col.remove(id); L.info('netops device removed', { id, by });
      if (secretsAll()[id]) this.setCredentials(id, null, by);
      return { removed: id };
    },
    sites() { const m = {}; for (const d of col.all()) (m[d.site] = m[d.site] || []).push(d.id); return m; },
    credentials: (id) => secretsAll()[id] || {},
    credentialSummary(id) { const c = secretsAll()[id] || {}; return { snmp: c.snmp ? 'v' + c.snmp.version + (c.snmp.version === '3' ? ' ' + (c.snmp.privKey ? 'authPriv' : c.snmp.authKey ? 'authNoPriv' : 'noAuth') : '') : null, api: c.api ? 'token set' + (c.api.tls && c.api.tls.fingerprint256 ? ', certificate pinned' : c.api.tls && c.api.tls.insecure ? ', certificate NOT verified' : '') : null,
      ssh: c.ssh ? 'user ' + c.ssh.username + (c.ssh.secret ? ' + enable' : '') + (c.ssh.port && c.ssh.port !== 22 ? ', port ' + c.ssh.port : '') : null,
      ssh_write: c.ssh_write ? (c.ssh_write.pam ? 'from PAM: ' + c.ssh_write.pam + ' (checked out per approved task)' : 'user ' + c.ssh_write.username + (c.ssh_write.secret ? ' + enable' : '') + ' (approved tasks only, stored)') : null }; },
    setFacts(id, facts) { const d = col.get(id); if (!d) throw new InvError(404, 'device not found'); d.cli_facts = facts; col.put(d); return d; },
    setCredentials(id, creds, by) {
      if (!secPath) throw new InvError(500, 'secrets path unknown');
      if (creds && !col.get(id)) throw new InvError(404, 'device not found');
      let sec = {}; try { sec = SF.read(secPath) || {}; } catch (e) { if (e.code !== 'ENOENT') throw e; }
      sec.netops = sec.netops || {}; sec.netops.devices = sec.netops.devices || {};
      if (creds) sec.netops.devices[id] = Object.assign({}, sec.netops.devices[id] || {}, validateCreds(creds)); else delete sec.netops.devices[id];
      writeJsonAtomic(secPath, sec);
      if (config && config.secrets) { config.secrets.netops = config.secrets.netops || {}; config.secrets.netops.devices = sec.netops.devices; }
      L.info('netops credentials changed', { id, by, set: creds ? Object.keys(creds) : 'removed' });
      return this.credentialSummary(id);
    },
    seedFromSources(by) {
      const added = [];
      for (const s of (config && config.sources) || []) {
        const vendor = TYPE_TO_VENDOR[String(s.type || '').toLowerCase()] || TYPE_TO_VENDOR[String(s.kind || '').toLowerCase()];
        const ip = s.match_ip && net.isIP(s.match_ip) ? s.match_ip : null;
        if (!vendor || !ip || col.all().some((d) => d.ip === ip)) continue;
        const id = String(s.id).toLowerCase().replace(/[^a-z0-9-]/g, '-').slice(0, 40);
        if (!ID_RE.test(id) || col.get(id)) continue;
        try { added.push(this.put({ id, name: s.label || s.id, vendor, ip, site: s.site || 'Unassigned', role: vendor === 'genian' ? 'nac' : vendor === 'edgeconnect' ? 'sdwan-appliance' : /fortigate|paloalto|asa/.test(vendor) ? 'firewall' : 'other', poll: { ping: true } }, by).id); } catch (e) { /* skip invalid */ }
      }
      return { added };
    },
  };
}

module.exports = { createInventory, validate, validateCreds, VENDORS, ROLES, InvError };
