// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// IIS W3C extended logs — in particular the Exchange front end / back end web sites
// (C:\inetpub\logs\LogFiles\W3SVC1\u_exYYMMDD.log = Default Web Site, W3SVC2 = Exchange Back End).
// Space-separated fields, spaces inside values encoded as '+', '-' = empty, times in UTC. Field order comes from the
// '#Fields:' header line (remembered per source/host/tag); without a header the IIS default field set is assumed:
//   date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) cs(Referer) sc-status
//   sc-substatus sc-win32-status time-taken
// (W3C extended format: https://learn.microsoft.com/en-us/windows/win32/http/w3c-logging)
// Accepted shapes: raw lines (rsyslog imfile / any forwarder) and JSON objects keyed by the W3C field names.
// Requests to Exchange virtual directories (OWA, ECP, EWS, Autodiscover, MAPI, PowerShell, ActiveSync, OAB, RPC)
// are tagged "exchange" (+ "exchange-<vdir>"); ProxyShell-style Autodiscover abuse is tagged T1190.
// ActiveSync requests also carry fields.eas_cmd / eas_device_id / eas_device_type from the query string (Exchange Reports:
// OWA & ActiveSync, engine/soc/exchange-reports.js).
const { split, parseTime, ipOrEmpty, toInt, clean, splitUser, safeJson } = require('./util');
const ex = require('./exchange');

const DEFAULT_FIELDS = ['date', 'time', 's-ip', 'cs-method', 'cs-uri-stem', 'cs-uri-query', 's-port', 'cs-username', 'c-ip',
  'cs(user-agent)', 'cs(referer)', 'sc-status', 'sc-substatus', 'sc-win32-status', 'time-taken'];
const LINE_RE = /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} \S+ /;
const HEADER_RE = /^#(Software: Microsoft Internet Information Services|Fields: date time |Fields: date\s)/i;
const EXCHANGE_VDIRS = new Set(['owa', 'ecp', 'ews', 'autodiscover', 'mapi', 'powershell', 'microsoft-server-activesync', 'oab', 'rpc', 'rpcwithcert', 'exchange', 'exchweb', 'public']);
const dash = (v) => (v === undefined || v === '-' ? '' : v);
const plus = (v) => dash(v).replace(/\+/g, ' ');

function fromMap(m, host) {
  const stem = dash(m['cs-uri-stem']);
  const query = dash(m['cs-uri-query']);
  const status = toInt(m['sc-status']);
  const vdir = (/^\/([^/?]+)/.exec(stem) || [])[1] || '';
  const who = splitUser(dash(m['cs-username']));
  const tags = [];
  const vd = vdir.toLowerCase();
  if (EXCHANGE_VDIRS.has(vd)) tags.push('exchange', 'exchange-' + vd);
  let severity = status >= 500 ? 1 : 0;
  const url = stem + (query ? '?' + query : '');
  // ProxyShell (CVE-2021-34473 …): Autodiscover path confusion reaching PowerShell/MAPI back end
  if (/\/autodiscover\/autodiscover\.json/i.test(url) && /(powershell|mapi\/nspi|\/ews\/)/i.test(url) && /@/.test(url)) { tags.push('T1190', 'proxyshell'); severity = 3; }
  const eas = vd === 'microsoft-server-activesync' ? easQuery(query) : null;
  const ev = {
    src_type: 'iis', category: 'web', action: 'http-request', outcome: status && status < 400 ? 'success' : 'failure',
    ts: parseTime(`${m.date}T${m.time}Z`, 0), host: host || clean(m['s-computername']).toLowerCase(),
    src_ip: ipOrEmpty(dash(m['x-forwarded-for']).split(',')[0]) || ipOrEmpty(m['c-ip']), dst_ip: ipOrEmpty(m['s-ip']), dst_port: toInt(m['s-port']),
    user: who.user, domain: who.domain, http_method: dash(m['cs-method']), url, http_status: status,
    user_agent: plus(m['cs(user-agent)']), severity, tags,
    message: `${dash(m['cs-method'])} ${stem} ${status}`.slice(0, 300),
    fields: {
      vdir, substatus: dash(m['sc-substatus']), win32_status: dash(m['sc-win32-status']), time_taken_ms: dash(m['time-taken']),
      referer: plus(m['cs(referer)']), c_ip: dash(m['c-ip']), x_forwarded_for: dash(m['x-forwarded-for']), site: dash(m['s-sitename']),
      cs_host: dash(m['cs-host']), sc_bytes: dash(m['sc-bytes']), cs_bytes: dash(m['cs-bytes']),
    },
  };
  if (eas) Object.assign(ev.fields, eas);
  return ev;
}

// Exchange ActiveSync request: ?Cmd=Sync&User=CORP%5Cuser&DeviceId=…&DeviceType=iPhone (plain form; the base64-encoded
// form some clients send carries no readable pairs and is left alone). Only well-formed identifiers are kept - the
// device's phone number / IMEI are never in the query and nothing else from it is stored here.
const EAS_OK = { Cmd: /^[A-Za-z]{1,30}$/, DeviceId: /^[A-Za-z0-9]{1,64}$/, DeviceType: /^[A-Za-z0-9_.-]{1,40}$/ };
const EAS_KEY = { Cmd: 'eas_cmd', DeviceId: 'eas_device_id', DeviceType: 'eas_device_type' };
function easQuery(q) {
  if (!q || q.indexOf('=') < 0) return null;
  const out = {};
  for (const part of q.split('&')) {
    const i = part.indexOf('='); if (i <= 0) continue;
    const k = part.slice(0, i); let v = part.slice(i + 1);
    if (!EAS_OK[k]) continue;
    try { v = decodeURIComponent(v.replace(/\+/g, ' ')); } catch (e) { continue; /* malformed escape: not an identifier we keep */ }
    if (EAS_OK[k].test(v)) out[EAS_KEY[k]] = v;
  }
  return Object.keys(out).length ? out : null;
}

function parse(line, meta = {}) {
  const { hdr, body } = split(line, meta);
  const host = ex.hostFromTag(hdr) || (hdr && hdr.host) || '';
  const obj = meta.obj || (body.charCodeAt(0) === 123 ? safeJson(body) : null);
  if (obj && !Array.isArray(obj)) {
    if (obj['cs-uri-stem'] === undefined) return null;
    const m = {};
    for (const [k, v] of Object.entries(obj)) m[k.toLowerCase()] = v === null || v === undefined ? '-' : String(v);
    return fromMap(m, clean(obj.server || obj.host || '').toLowerCase() || host);
  }
  if (body[0] === '#') {
    if (!HEADER_RE.test(body) && !/^#(Version|Date):/.test(body)) return null;
    const fm = /^#Fields:\s*(.+)$/i.exec(body);
    if (fm) ex.rememberFields(ex.cacheKey(meta, hdr, 'iis'), fm[1].trim().split(/\s+/).map((x) => x.toLowerCase()));
    return ex.headerEvent(meta.src_type && meta.src_type !== 'syslog' ? meta.src_type : 'iis', body, host);
  }
  if (!LINE_RE.test(body)) return null;
  const names = ex.headerCache.get(ex.cacheKey(meta, hdr, 'iis')) || DEFAULT_FIELDS;
  const vals = body.split(' ');
  if (vals.length < Math.min(names.length, 10)) return null;
  const m = {};
  names.forEach((n, i) => { m[n] = vals[i]; });
  if (!/^[A-Z]{3,12}$/.test(m['cs-method'] || '') || !(m['cs-uri-stem'] || '').startsWith('/')) return null;
  return fromMap(m, host);
}

module.exports = {
  name: 'iis',
  sniff(line, meta = {}) {
    if (meta.obj) return meta.obj['cs-uri-stem'] !== undefined;
    const { body } = split(line, meta);
    return LINE_RE.test(body) || HEADER_RE.test(body);
  },
  parse,
  DEFAULT_FIELDS,
};
