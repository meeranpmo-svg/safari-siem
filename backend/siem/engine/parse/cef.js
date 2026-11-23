// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// ArcSight CEF: CEF:Version|Vendor|Product|DeviceVersion|SignatureID|Name|Severity|Extension
const { split, parseTime, toInt, ipOrEmpty, protoName, splitUser, clean } = require('./util');

function splitHeader(s, count) {
  const parts = [];
  let cur = '';
  let i = 0;
  for (; i < s.length && parts.length < count; i++) {
    const c = s[i];
    if (c === '\\' && (s[i + 1] === '|' || s[i + 1] === '\\')) { cur += s[i + 1]; i++; continue; }
    if (c === '|') { parts.push(cur); cur = ''; continue; }
    cur += c;
  }
  if (parts.length < count) return null;
  return { parts, rest: s.slice(i) };
}

const unescExt = (v) => v.replace(/\\([=\\|])/g, '$1').replace(/\\n/g, '\n').replace(/\\r/g, '\r');

// Extension: space separated key=value, values may contain spaces; '=' inside values is escaped as '\='.
function parseExt(s) {
  const out = {};
  const re = /(?:^|\s)([A-Za-z0-9_.[\]-]+)=/g;
  const hits = [];
  let m;
  while ((m = re.exec(s))) {
    if (m.index > 0 && s[m.index] !== ' ' && s[m.index] !== '\t') continue;
    hits.push({ key: m[1], vstart: re.lastIndex, kstart: m.index });
  }
  for (let i = 0; i < hits.length; i++) {
    const end = i + 1 < hits.length ? hits[i + 1].kstart : s.length;
    out[hits[i].key] = unescExt(s.slice(hits[i].vstart, end).trim());
  }
  return out;
}

function sevOf(v) {
  if (v === undefined || v === '') return 0;
  const n = Number(v);
  if (Number.isFinite(n)) return n <= 0 ? 0 : n <= 3 ? 1 : n <= 6 ? 2 : n <= 8 ? 3 : 4;
  const s = String(v).toLowerCase();
  return { low: 1, medium: 2, high: 3, 'very-high': 4, 'very high': 4, unknown: 0 }[s] || 0;
}

// Shared category/action heuristics for CEF & LEEF
function classify(ev, text, act, outcomeHint) {
  const t = text.toLowerCase();
  const a = String(act || '').toLowerCase();
  const failed = /fail|denied|reject|invalid/.test(String(outcomeHint || '').toLowerCase()) || /fail/.test(t);
  if (/virus|malware|trojan|ransom|worm|spyware/.test(t)) { ev.category = 'malware'; ev.action = 'av-detection'; }
  else if (/\bips\b|\bids\b|intrusion|exploit|attack|signature/.test(t)) { ev.category = 'network'; ev.action = 'ips-detection'; }
  else if (/log ?on|log ?in|authenticat|sign-?in/.test(t)) { ev.category = 'authentication'; ev.action = failed ? 'logon-failed' : 'logon'; ev.outcome = failed ? 'failure' : 'success'; }
  else if (/block|deny|denied|drop|reject/.test(a)) { ev.category = 'network'; ev.action = 'blocked'; ev.outcome = 'failure'; }
  else if (/allow|accept|permit|pass/.test(a)) { ev.category = 'network'; ev.action = 'allowed'; ev.outcome = 'success'; }
  else if (ev.url) { ev.category = 'web'; ev.action = 'http-request'; }
  else if (ev.src_ip && ev.dst_ip) { ev.category = 'network'; ev.action = 'connection'; }
  if (outcomeHint && ev.outcome === 'unknown') {
    const o = String(outcomeHint).toLowerCase().replace(/^\//, '');
    if (/success|succeeded|allow/.test(o)) ev.outcome = 'success';
    else if (/fail|deny|block/.test(o)) ev.outcome = 'failure';
  }
}

const MAPPED = new Set(['src', 'sourceAddress', 'dst', 'destinationAddress', 'spt', 'sourcePort', 'dpt', 'destinationPort', 'proto',
  'transportProtocol', 'suser', 'sourceUserName', 'duser', 'destinationUserName', 'dvchost', 'deviceHostName', 'request',
  'requestMethod', 'requestClientApplication', 'fileHash', 'msg', 'message', 'rt', 'end', 'sproc', 'sourceProcessName', 'dproc', 'destinationProcessName',
  'deviceProcessName', 'act', 'outcome', 'shost', 'dhost', 'sntdom', 'dntdom']);

function parse(line, meta = {}) {
  const { body } = split(line, meta);
  const at = body.indexOf('CEF:');
  if (at < 0) return null;
  const h = splitHeader(body.slice(at + 4), 7);
  if (!h) return null;
  const [ver, vendor, product, devVer, sigId, name, sev] = h.parts;
  const x = parseExt(h.rest);
  const who = splitUser(x.suser || x.sourceUserName || '', x.sntdom);
  const target = splitUser(x.duser || x.destinationUserName || '');
  const ev = {
    src_type: 'cef', ts: parseTime(x.rt || x.end || '', meta.tz_offset_min || 0),
    host: clean(x.dvchost || x.deviceHostName), src_ip: ipOrEmpty(x.src || x.sourceAddress), dst_ip: ipOrEmpty(x.dst || x.destinationAddress),
    src_port: toInt(x.spt || x.sourcePort), dst_port: toInt(x.dpt || x.destinationPort), proto: protoName(x.proto || x.transportProtocol),
    user: who.user, domain: who.domain, target_user: target.user, url: x.request || '', http_method: x.requestMethod || '',
    user_agent: x.requestClientApplication || '', hash: clean(x.fileHash),
    process: x.sproc || x.sourceProcessName || x.deviceProcessName || '', event_code: sigId,
    severity: sevOf(sev), category: 'other', action: 'event', outcome: 'unknown',
    message: (name + (x.msg ? ': ' + x.msg : '')).slice(0, 1000),
    fields: { cef_version: ver, cef_vendor: vendor, cef_product: product, cef_device_version: devVer, cef_name: name, act: x.act, cef_outcome: x.outcome },
  };
  if (x.shost) ev.fields.src_host = x.shost;
  if (x.dhost) ev.fields.dst_host = x.dhost;
  if (x.dproc || x.destinationProcessName) ev.fields.dst_process = x.dproc || x.destinationProcessName;
  // custom string/number labels: cs1=value cs1Label=name → fields[name]
  const labelled = new Set();
  for (const k of Object.keys(x)) {
    const lm = /^(c[sn]\d|c6a\d|cfp\d|deviceCustomString\d|deviceCustomNumber\d)Label$/.exec(k);
    if (lm && x[lm[1]] !== undefined) { ev.fields[x[k]] = x[lm[1]]; labelled.add(k); labelled.add(lm[1]); }
  }
  for (const [k, v] of Object.entries(x)) if (!MAPPED.has(k) && !labelled.has(k)) ev.fields[k] = v;
  classify(ev, `${vendor} ${product} ${name} ${x.cat || ''}`, x.act, x.outcome);
  // vendor-aware post-mapping (DLP / EDR / Check Point): cef-vendors.js, keyed on deviceVendor / deviceProduct
  ev.tags = [];
  vendors().apply(ev, x, { vendor, product, name, sigId, sev, format: 'cef' });
  if (!ev.tags.length) delete ev.tags;
  return ev;
}

let vendorsMod = null;
function vendors() { if (!vendorsMod) vendorsMod = require('./cef-vendors'); return vendorsMod; } // lazy: cef-vendors ↔ cef

module.exports = {
  name: 'cef',
  sniff(line, meta = {}) { const { body } = split(line, meta); return /(?:^|\s|:)CEF:\d+\|/.test(body); },
  parse,
  parseExt,
  splitHeader,
  sevOf,
  classify,
  vendors,
};
