// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// FortiGate (FortiOS 6.x/7.x) key=value logs: traffic, utm (ips / virus / webfilter / app-ctrl / dns / anomaly),
// event (vpn, system admin login/logout, config changes, user auth).
const { split, parseKV, parseTime, epochToMs, sevFromName, toInt, ipOrEmpty, protoName, splitUser, clean } = require('./util');

const START_RE = /(?:^|\s)(?:date|logver|devname|logid|eventtime)=/;
const CONSUMED = new Set(['date', 'time', 'eventtime', 'tz', 'devname', 'logid', 'level', 'srcip', 'dstip', 'srcport', 'dstport',
  'proto', 'user', 'msg']);
const BLOCK_WORDS = new Set(['deny', 'denied', 'block', 'blocked', 'drop', 'dropped', 'reject', 'reset', 'clear_session', 'drop_session', 'close_session', 'server-rst-blocked']);
const ALLOW_WORDS = new Set(['accept', 'allow', 'allowed', 'pass', 'passthrough', 'permit', 'close', 'timeout', 'client-rst', 'server-rst', 'start', 'ip-conn', 'monitored', 'detected']);

function tsOf(kv, offDefault) {
  if (kv.eventtime && /^\d+$/.test(kv.eventtime)) return epochToMs(Number(kv.eventtime));
  if (kv.date && kv.time) {
    const off = kv.tz ? kv.tz : null;
    const s = `${kv.date}T${kv.time}${off && /^[+-]\d{2}:?\d{2}$/.test(off) ? off : ''}`;
    return parseTime(s, offDefault);
  }
  return 0;
}

function verdict(a) {
  const v = String(a || '').toLowerCase();
  if (BLOCK_WORDS.has(v)) return 'blocked';
  if (ALLOW_WORDS.has(v)) return 'allowed';
  return '';
}

function parse(line, meta = {}) {
  const { body } = split(line, meta);
  const at = body.search(START_RE);
  if (at < 0) return null;
  const kv = parseKV(body.slice(at));
  if (!kv.logid && !kv.devid && !kv.devname) return null;
  if (!kv.type && !kv.subtype) return null;
  const type = String(kv.type || '').toLowerCase();
  const sub = String(kv.subtype || '').toLowerCase();
  const act = String(kv.action || '').toLowerCase();
  const who = splitUser(kv.user || kv.srcuser || kv.unauthuser || '');
  const ev = {
    src_type: 'fortigate', ts: tsOf(kv, meta.tz_offset_min || 0), host: clean(kv.devname),
    src_ip: ipOrEmpty(kv.srcip), dst_ip: ipOrEmpty(kv.dstip), src_port: toInt(kv.srcport), dst_port: toInt(kv.dstport),
    proto: protoName(kv.proto), user: who.user, domain: who.domain, event_code: kv.logid || '',
    severity: sevFromName(kv.level, 0), category: 'network', action: 'event', outcome: 'unknown',
    message: kv.msg || kv.logdesc || `${type}/${sub} ${act}`.trim(), tags: [], fields: {},
  };
  for (const [k, v] of Object.entries(kv)) if (!CONSUMED.has(k) && v !== '' && v !== 'N/A') ev.fields[k] = v;
  if (kv.level) ev.fields.fg_level = kv.level;

  if (type === 'traffic') {
    const vd = verdict(act) || (kv.policyid === '0' ? 'blocked' : 'allowed');
    ev.action = vd;
    ev.outcome = vd === 'blocked' ? 'failure' : 'success';
    if (!kv.msg && !kv.logdesc) ev.message = `${sub} ${act || vd} ${kv.srcip || ''}:${kv.srcport || ''} → ${kv.dstip || ''}:${kv.dstport || ''} ${kv.service || ''}`.trim();
  } else if (type === 'utm') {
    const vd = verdict(act);
    if (vd) ev.outcome = vd === 'blocked' ? 'failure' : 'success';
    if (kv.crlevel) ev.severity = Math.max(ev.severity, sevFromName(kv.crlevel, 0));
    if (sub === 'ips' || sub === 'anomaly') {
      ev.action = 'ips-detection';
      ev.severity = Math.max(ev.severity, sevFromName(kv.severity, 2));
      ev.message = kv.attack ? `IPS: ${kv.attack}` : ev.message;
    } else if (sub === 'virus' || sub === 'av') {
      ev.category = 'malware';
      ev.action = 'av-detection';
      ev.severity = Math.max(ev.severity, 3);
      ev.hash = clean(kv.filehash || kv.analyticscksum);
      if (kv.url) ev.url = (kv.hostname || '') + kv.url;
      ev.message = kv.virus ? `AV: ${kv.virus} in ${kv.filename || kv.url || ''}`.trim() : ev.message;
    } else if (sub === 'webfilter') {
      ev.category = 'web';
      ev.action = vd || 'allowed';
      ev.url = (kv.hostname || '') + (kv.url || '');
      if (kv.method) ev.http_method = kv.method.toUpperCase();
    } else if (sub === 'dns') {
      ev.category = 'dns';
      ev.action = vd === 'blocked' ? 'blocked' : 'dns-query';
      ev.dns_query = clean(kv.qname).toLowerCase();
    } else if (sub === 'app-ctrl' || sub === 'application') {
      ev.action = vd || 'allowed';
    } else {
      ev.action = vd || 'event';
    }
  } else if (type === 'event') {
    ev.category = 'system';
    const status = String(kv.status || '').toLowerCase();
    const failed = /fail/.test(status) || /fail/.test(act) || /fail/i.test(kv.logdesc || '');
    if (sub === 'vpn') {
      ev.tags.push('vpn');
      if (/login-fail|auth-fail|ssl-login-fail/.test(act) || (act.includes('login') && failed)) {
        Object.assign(ev, { category: 'authentication', action: 'logon-failed', outcome: 'failure', severity: Math.max(ev.severity, 1) });
        ev.tags.push('T1110');
      } else if (act === 'tunnel-up' || act === 'ssl-login' || act === 'login') {
        Object.assign(ev, { category: 'authentication', action: 'logon', outcome: 'success' });
      } else if (act === 'tunnel-down' || act === 'logout') {
        Object.assign(ev, { category: 'authentication', action: 'logoff', outcome: 'success' });
      } else {
        Object.assign(ev, { category: 'network', action: 'vpn-event' });
      }
      if (kv.remip) ev.src_ip = ipOrEmpty(kv.remip) || ev.src_ip;
      if (kv.tunnelip && !ev.dst_ip) ev.fields.tunnel_ip = kv.tunnelip;
    } else if (act === 'login' || act === 'logout' || /admin login|admin logout/i.test(kv.logdesc || '')) {
      ev.tags.push('admin');
      ev.category = 'authentication';
      if (act === 'logout') { ev.action = 'logoff'; ev.outcome = 'success'; } else if (failed) { ev.action = 'logon-failed'; ev.outcome = 'failure'; ev.severity = Math.max(ev.severity, 2); ev.tags.push('T1110'); } else { ev.action = 'logon'; ev.outcome = 'success'; }
      if (!ev.src_ip && kv.ui) { const m = /\(([^)]+)\)/.exec(kv.ui); if (m) ev.src_ip = ipOrEmpty(m[1]); }
    } else if (kv.cfgpath || /^(edit|add|delete|set|unset|move|config)$/.test(act) || /configured|config/i.test(kv.logdesc || '')) {
      ev.category = String(kv.cfgpath || '').startsWith('firewall') ? 'policy' : 'system';
      ev.action = 'config-change';
      ev.outcome = 'success';
      ev.severity = Math.max(ev.severity, 1);
      ev.tags.push('admin');
    } else if (sub === 'user' || act === 'authentication') {
      ev.category = 'authentication';
      ev.action = failed ? 'logon-failed' : 'logon';
      ev.outcome = failed ? 'failure' : 'success';
    } else {
      ev.action = act || 'event';
    }
  } else {
    ev.action = verdict(act) || 'event';
  }
  return ev;
}

module.exports = {
  name: 'fortigate',
  sniff(line, meta = {}) {
    const { body } = split(line, meta);
    return START_RE.test(body) && /\blogid="?\d+/.test(body) && /\btype="?\w+/.test(body);
  },
  parse,
};
