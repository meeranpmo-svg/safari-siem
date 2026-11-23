// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// IBM LEEF 1.0 / 2.0: LEEF:1.0|Vendor|Product|Version|EventID|k=v<TAB>k=v…
//                      LEEF:2.0|Vendor|Product|Version|EventID|<delim>|k=v<delim>k=v…  (delim char, or hex like x5E / 0x09)
const { split, parseTime, toInt, ipOrEmpty, protoName, splitUser, clean } = require('./util');
const { splitHeader, parseExt, sevOf, classify } = require('./cef');

function delimOf(d) {
  if (!d) return '\t';
  const m = /^(?:0?x)([0-9a-fA-F]{1,4})$/.exec(d);
  if (m) return String.fromCharCode(parseInt(m[1], 16));
  return d[0];
}

function attrs(s, delim) {
  if (s.includes(delim)) {
    const out = {};
    for (const part of s.split(delim)) {
      const eq = part.indexOf('=');
      if (eq > 0) out[part.slice(0, eq).trim()] = part.slice(eq + 1);
    }
    return out;
  }
  return parseExt(s); // senders that replaced tabs by spaces
}

const MAPPED = new Set(['src', 'dst', 'srcPort', 'dstPort', 'proto', 'usrName', 'sev', 'devTime', 'devTimeFormat', 'url', 'srcMAC', 'identHostName', 'accountName', 'domain']);

function parse(line, meta = {}) {
  const { body } = split(line, meta);
  const at = body.indexOf('LEEF:');
  if (at < 0) return null;
  const s = body.slice(at + 5);
  const v2 = s.startsWith('2');
  const h = splitHeader(s, v2 ? 6 : 5);
  if (!h) return null;
  const [ver, vendor, product, devVer, eventId, delimSpec] = h.parts;
  const a = attrs(h.rest, v2 ? delimOf(delimSpec) : '\t');
  const who = splitUser(a.usrName || a.accountName || '', a.domain);
  const ev = {
    src_type: 'leef', ts: parseTime(a.devTime || '', meta.tz_offset_min || 0),
    host: clean(a.identHostName), src_ip: ipOrEmpty(a.src), dst_ip: ipOrEmpty(a.dst), src_port: toInt(a.srcPort), dst_port: toInt(a.dstPort),
    proto: protoName(a.proto), user: who.user, domain: who.domain, url: a.url || '', event_code: eventId,
    severity: sevOf(a.sev), category: 'other', action: 'event', outcome: 'unknown',
    message: `${vendor} ${product} ${eventId}${a.cat ? ' (' + a.cat + ')' : ''}`,
    fields: { leef_version: ver, leef_vendor: vendor, leef_product: product, leef_device_version: devVer },
  };
  for (const [k, v] of Object.entries(a)) if (!MAPPED.has(k)) ev.fields[k] = v;
  classify(ev, `${vendor} ${product} ${eventId} ${a.cat || ''}`, a.action || a.act, a.outcome || a.result);
  // vendor-aware post-mapping (Check Point Log Exporter LEEF etc.): cef-vendors.js
  ev.tags = [];
  require('./cef').vendors().apply(ev, a, { vendor, product, name: eventId, sigId: eventId, sev: a.sev, format: 'leef' });
  if (!ev.tags.length) delete ev.tags;
  return ev;
}

module.exports = {
  name: 'leef',
  sniff(line, meta = {}) { const { body } = split(line, meta); return /(?:^|\s)LEEF:[12]\.0\|/.test(body); },
  parse,
};
