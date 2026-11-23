// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Normalised event schema (ARCH.md "Normalised event"). Shared by parsers, writer, query compiler and tail filters.
const crypto = require('node:crypto');
const net = require('node:net');

// field -> kind. kinds: time, uuid, str (exact-match string), text (long free text: substring match),
// ip, num (with max), tags (Array), map (Map(String,String))
const FIELDS = {
  ts: { kind: 'time', ch: "DateTime64(3, 'UTC')" },
  rts: { kind: 'time', ch: "DateTime64(3, 'UTC')" },
  id: { kind: 'uuid', ch: 'UUID' },
  src_type: { kind: 'str', lower: true, ch: 'LowCardinality(String)' },
  src_id: { kind: 'str', ch: 'LowCardinality(String)' },
  collector: { kind: 'str', lower: true, ch: 'LowCardinality(String)' },
  host: { kind: 'str', ch: 'String' },
  host_ip: { kind: 'ip', ch: 'String' },
  category: { kind: 'str', lower: true, ch: 'LowCardinality(String)' },
  action: { kind: 'str', lower: true, ch: 'LowCardinality(String)' },
  outcome: { kind: 'str', lower: true, ch: 'LowCardinality(String)' },
  severity: { kind: 'num', max: 4, ch: 'UInt8' },
  user: { kind: 'str', lower: true, ch: 'String' },
  target_user: { kind: 'str', lower: true, ch: 'String' },
  domain: { kind: 'str', lower: true, ch: 'String' },
  src_ip: { kind: 'ip', ch: 'String' },
  dst_ip: { kind: 'ip', ch: 'String' },
  src_port: { kind: 'num', max: 65535, ch: 'UInt16' },
  dst_port: { kind: 'num', max: 65535, ch: 'UInt16' },
  proto: { kind: 'str', lower: true, ch: 'LowCardinality(String)' },
  process: { kind: 'str', ch: 'String' },
  parent_process: { kind: 'str', ch: 'String' },
  cmdline: { kind: 'text', ch: 'String' },
  hash: { kind: 'str', lower: true, ch: 'String' },
  url: { kind: 'text', ch: 'String' },
  http_method: { kind: 'str', upper: true, ch: 'String' },
  http_status: { kind: 'num', max: 999, ch: 'UInt16' },
  user_agent: { kind: 'text', ch: 'String' },
  dns_query: { kind: 'str', lower: true, ch: 'String' },
  event_code: { kind: 'str', ch: 'String' },
  message: { kind: 'text', ch: 'String' },
  tags: { kind: 'tags', ch: 'Array(LowCardinality(String))' },
  fields: { kind: 'map', ch: 'Map(String, String)' },
  raw: { kind: 'text', ch: 'String CODEC(ZSTD(3))' },
};
const FIELD_NAMES = Object.keys(FIELDS);

const SRC_TYPES = ['linux', 'nginx', 'fortigate', 'windows', 'cef', 'leef', 'json', 'm365', 'cisco', 'syslog', 'exchange', 'iis', 'ad',
  // device classes (engine/parse/{paloalto,ciscoasa,ciscoucs,f5,netscaler,esxi}.js; dlp-cef/edr-cef = cef.js + cef-vendors.js hooks)
  'paloalto', 'cisco-asa', 'cisco-ucs', 'f5', 'netscaler', 'esxi', 'dlp-cef', 'edr-cef',
  'silverpeak', // Silver Peak / HPE Aruba EdgeConnect WAN optimisation (engine/parse/silverpeak.js)
  'somansa', 'libraesva', 'cloudflare']; // Somansa DLP (engine/parse/somansa.js); Libraesva Email Security Gateway (engine/parse/libraesva.js). Zscaler ZIA/NSS and the other email gateways ride 'cef'.
const COLLECTORS = ['syslog-udp', 'syslog-tcp', 'syslog-tls', 'http', 'agent', 'm365', 'lr', 'ad-sync', 'cloudflare'];
const CATEGORIES = ['authentication', 'network', 'web', 'process', 'iam', 'malware', 'file', 'registry', 'dns',
  'system', 'policy', 'email', 'cloud', 'database', 'other']; // database: engine/db-audit (Oracle health + audit trail)
const OUTCOMES = ['success', 'failure', 'unknown'];
// Action vocabulary used by the bundled parsers. The ARCH list plus the few extra verbs the parsers need.
const ACTIONS = [
  'logon', 'logon-failed', 'logoff', 'logon-explicit', 'privileges-assigned', 'credential-validated', 'session-opened', 'session-closed',
  'kerberos-tgt', 'kerberos-service-ticket',
  'user-created', 'user-deleted', 'user-enabled', 'user-disabled', 'user-modified', 'password-change', 'password-reset',
  'account-locked', 'group-member-added', 'group-member-removed', 'role-assigned',
  'process-start', 'process-access', 'script-block', 'service-installed', 'scheduled-task-created', 'audit-log-cleared',
  'connection', 'blocked', 'allowed', 'http-request', 'dns-query', 'ips-detection', 'av-detection',
  'file-created', 'registry-set', 'sudo', 'su', 'config-change', 'service-started', 'service-stopped', 'service-failed',
  'vpn-event', 'cron', 'agent-heartbeat', 'log', 'event', 'unparsed',
  // Exchange / Exchange Online (parse/exchange.js, parse/m365.js, parse/windows.js)
  'exchange-cmdlet', 'inbox-rule-created', 'inbox-rule-modified', 'inbox-rule-removed', 'mail-forwarding-set', 'mail-forwarding-removed',
  'mailbox-modified', 'mailbox-permission-added', 'mailbox-permission-removed', 'mailbox-folder-permission-added',
  'sendas-permission-added', 'sendas-permission-removed', 'transport-rule-created', 'transport-rule-modified', 'transport-rule-removed',
  'mailbox-export', 'mailbox-search', 'mail-connector-changed', 'org-relationship-changed', 'hybrid-config-changed',
  'mail-domain-changed', 'journal-rule-changed', 'audit-disabled', 'config-read',
  'mail-items-accessed', 'send', 'send-as', 'send-on-behalf', 'mail-deleted', 'mail-moved', 'mail-item-created', 'mail-item-updated',
  'mail-folder-accessed', 'mailbox-activity',
  'receive', 'deliver', 'fail', 'submit', 'defer', 'dsn', 'drop', 'expand', 'redirect', 'resolve', 'transfer', 'transport',
  // device classes (parse/f5.js, netscaler.js, esxi.js, cef-vendors.js, windows.js MSSQL)
  'waf-detection', 'dlp-incident', 'edr-detection', 'agent-tamper', 'db-audit',
  'vm-power-on', 'vm-power-off', 'vm-created', 'vm-deleted', 'vm-reconfigured', 'maintenance-mode',
];
const CAT_SET = new Set(CATEGORIES);
const OUT_SET = new Set(OUTCOMES);

const MAX_FIELDS_KEYS = 200;
const MAX_FIELD_VALUE = 8192;
// the Windows agent's daily hardening snapshot is one compact JSON value that hardening/store.js must parse whole: a cut
// copy is not JSON and the host would never be scanned (agent 1.3 adds IIS and Hyper-V, typically 10-60 KB)
const MAX_SNAPSHOT_VALUE = 256 * 1024;
const MAX_MESSAGE = 4096;
const MIN_TS = Date.UTC(2000, 0, 1);

function blankEvent() {
  return {
    ts: 0, rts: 0, id: '', src_type: '', src_id: '', collector: '', host: '', host_ip: '',
    category: 'other', action: '', outcome: 'unknown', severity: 0,
    user: '', target_user: '', domain: '', src_ip: '', dst_ip: '', src_port: 0, dst_port: 0, proto: '',
    process: '', parent_process: '', cmdline: '', hash: '', url: '', http_method: '', http_status: 0, user_agent: '',
    dns_query: '', event_code: '', message: '', tags: [], fields: {}, raw: '',
  };
}

function cleanIp(v) {
  if (v === undefined || v === null) return '';
  let s = String(v).trim();
  if (!s || s === '-') return '';
  if (s[0] === '[') { const e = s.indexOf(']'); if (e > 0) s = s.slice(1, e); }
  const pct = s.indexOf('%'); if (pct > 0) s = s.slice(0, pct);
  if (s.startsWith('::ffff:') && net.isIPv4(s.slice(7))) s = s.slice(7);
  return net.isIP(s) ? s.toLowerCase() : null; // null = present but invalid
}

function str(v) {
  if (v === undefined || v === null) return '';
  if (typeof v === 'string') return v;
  if (typeof v === 'object') { try { return JSON.stringify(v); } catch { return String(v); } }
  return String(v);
}

function int(v, max) {
  const n = typeof v === 'number' ? v : parseInt(v, 10);
  if (!Number.isFinite(n) || n < 0) return 0;
  return n > max ? max : Math.trunc(n);
}

// Coerce a parser/router output into a complete, schema-valid event (in place; returns it).
function finalise(ev, meta = {}) {
  const now = meta.rts || Date.now();
  if (!ev.fields || typeof ev.fields !== 'object' || Array.isArray(ev.fields)) ev.fields = {};
  const f = ev.fields;
  for (const name of FIELD_NAMES) {
    const d = FIELDS[name];
    const v = ev[name];
    switch (d.kind) {
      case 'time': {
        let n = typeof v === 'number' ? v : (v instanceof Date ? v.getTime() : (v ? Date.parse(v) : 0));
        if (name === 'rts') { if (!(n > MIN_TS)) n = now; }
        else if (!(n > MIN_TS) || n > (ev.rts || now) + 86400000) { if (n) f.ts_invalid = str(v); n = ev.rts || now; }
        ev[name] = Math.trunc(n);
        break;
      }
      case 'uuid': if (typeof v !== 'string' || v.length !== 36) ev[name] = crypto.randomUUID(); break;
      case 'num': ev[name] = int(v, d.max); break;
      case 'ip': {
        const c = cleanIp(v);
        if (c === null) { f[name + '_raw'] = str(v).slice(0, 256); ev[name] = ''; } else ev[name] = c;
        break;
      }
      case 'tags': {
        if (!Array.isArray(v)) ev.tags = v ? [str(v)] : [];
        else if (v.length) ev.tags = [...new Set(v.filter(Boolean).map(str))].slice(0, 64);
        break;
      }
      case 'map': break;
      default: {
        let s = str(v);
        if (d.lower) s = s.toLowerCase();
        else if (d.upper) s = s.toUpperCase();
        if (name === 'message' && s.length > MAX_MESSAGE) s = s.slice(0, MAX_MESSAGE);
        ev[name] = s;
      }
    }
  }
  if (!CAT_SET.has(ev.category)) { if (ev.category) f.category_raw = ev.category; ev.category = 'other'; }
  if (!OUT_SET.has(ev.outcome)) { if (ev.outcome) f.outcome_raw = ev.outcome; ev.outcome = 'unknown'; }
  if (ev.action) ev.action = ev.action.replace(/\s+/g, '-');
  // fields: flat string map, bounded
  let n = 0;
  for (const k of Object.keys(f)) {
    const v = f[k];
    if (v === undefined || v === null || v === '' || ++n > MAX_FIELDS_KEYS || k.length > 128) { delete f[k]; continue; }
    if (typeof v !== 'string') f[k] = str(v);
    const cap = k === 'settings' && (ev.action === 'agent-hardening' || ev.action === 'agent-pii') ? MAX_SNAPSHOT_VALUE : MAX_FIELD_VALUE;
    if (f[k].length > cap) f[k] = f[k].slice(0, cap);
  }
  return ev;
}

module.exports = {
  FIELDS, FIELD_NAMES, SRC_TYPES, COLLECTORS, CATEGORIES, OUTCOMES, ACTIONS,
  blankEvent, finalise, cleanIp, str,
};
