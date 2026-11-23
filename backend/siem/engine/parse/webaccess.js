// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// nginx / Apache access logs: common + combined format, with optional virtual-host prefix
// ("vhost client ident user [...]" or Apache vhost_combined "vhost:port client ident user [...]")
// and trailing extra fields (request time, X-Forwarded-For, …). Syslog-wrapped lines (tag nginx:/httpd:) are fine.
const { split, parseTime, toInt, ipOrEmpty, clean } = require('./util');

const TAIL_RE = /^\[([^\]]+)\] "((?:[^"\\]|\\.)*)" (\d{3}) (\d+|-)(?: "((?:[^"\\]|\\.)*)" "((?:[^"\\]|\\.)*)")?(.*)$/;
const SNIFF_RE = /^(?:\S+ ){2,4}\[\d{1,2}\/[A-Za-z]{3}\/\d{4}:\d{2}:\d{2}:\d{2}[^\]]*\] "/;
const unesc = (s) => (s ? s.replace(/\\(["\\])/g, '$1').replace(/\\x([0-9a-fA-F]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16))) : '');

function parse(line, meta = {}) {
  const { hdr, body } = split(line, meta);
  const b = body.indexOf(' [');
  if (b < 0) return null;
  const pre = body.slice(0, b).trim().split(/\s+/);
  if (pre.length < 3 || pre.length > 5) return null;
  const m = TAIL_RE.exec(body.slice(b + 1));
  if (!m) return null;
  let vhost = '';
  let vport = '';
  let client;
  let ident;
  let user;
  if (pre.length === 3) [client, ident, user] = pre;
  else {
    [vhost, client, ident] = pre;
    user = pre.slice(3).join(' ');
    const c = vhost.lastIndexOf(':');
    if (c > 0 && /^\d+$/.test(vhost.slice(c + 1)) && !vhost.includes(']')) { vport = vhost.slice(c + 1); vhost = vhost.slice(0, c); }
  }
  const req = unesc(m[2]);
  const rm = /^([A-Z]{3,10}) (\S+)(?: (HTTP\/[\d.]+))?$/.exec(req);
  const status = toInt(m[3]);
  const extra = m[7] ? m[7].trim() : '';
  const fields = {
    vhost: vhost || undefined, vhost_port: vport || undefined, ident: clean(ident) || undefined,
    referer: clean(unesc(m[5])) || undefined, bytes: m[4] === '-' ? '0' : m[4], protocol: rm ? rm[3] : undefined,
    request: rm ? undefined : req.slice(0, 2048), extra: extra || undefined,
  };
  const xff = /"(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-f:]+)(?:, [^"]*)?"/i.exec(extra);
  if (xff) fields.x_forwarded_for = xff[1];
  const srcIp = ipOrEmpty(client);
  if (!srcIp) fields.client = client;
  return {
    src_type: 'nginx', category: 'web', action: 'http-request', outcome: status && status < 400 ? 'success' : 'failure',
    ts: parseTime(m[1], meta.tz_offset_min || 0),
    host: (hdr && hdr.host) || vhost, src_ip: srcIp, user: clean(user).toLowerCase(),
    http_method: rm ? rm[1] : '', url: rm ? rm[2] : '', http_status: status, user_agent: clean(unesc(m[6])),
    severity: status >= 500 ? 1 : 0, fields,
    message: `${rm ? rm[1] + ' ' + rm[2] : req.slice(0, 100)} ${status}`.slice(0, 300),
  };
}

module.exports = {
  name: 'webaccess',
  sniff(line, meta = {}) { const { body } = split(line, meta); return SNIFF_RE.test(body); },
  parse,
};
