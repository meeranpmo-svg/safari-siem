// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// RFC 5424 syslog: <PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [SD] MSG
const { parseTime, sevFromSyslog, firstLine } = require('./util');

const HDR_RE = /^<(\d{1,3})>1 (\S+) (\S+) (\S+) (\S+) (\S+) /;
const nil = (s) => (s === '-' ? '' : s);

function parseSD(line, i, sd) {
  // returns index after SD, or -1 if malformed
  while (line[i] === '[') {
    i++;
    let id = '';
    while (i < line.length && line[i] !== ' ' && line[i] !== ']') id += line[i++];
    const params = {};
    while (line[i] === ' ') {
      i++;
      let name = '';
      while (i < line.length && line[i] !== '=' && line[i] !== ']') name += line[i++];
      if (line[i] !== '=' || line[i + 1] !== '"') return -1;
      i += 2;
      let val = '';
      while (i < line.length && line[i] !== '"') {
        if (line[i] === '\\' && i + 1 < line.length && '"\\]'.includes(line[i + 1])) { val += line[i + 1]; i += 2; continue; }
        val += line[i++];
      }
      if (line[i] !== '"') return -1;
      i++;
      params[name] = val;
    }
    if (line[i] !== ']') return -1;
    i++;
    sd[id] = params;
  }
  return i;
}

function parseHeader(line) {
  if (line.charCodeAt(0) !== 60) return null;
  const m = HDR_RE.exec(line);
  if (!m) return null;
  const pri = Number(m[1]);
  if (pri > 191) return null;
  let i = m[0].length;
  const sd = {};
  if (line[i] === '-') i++;
  else if (line[i] === '[') { i = parseSD(line, i, sd); if (i < 0) return null; }
  else return null;
  let msg = line[i] === ' ' ? line.slice(i + 1) : line.slice(i);
  if (msg.charCodeAt(0) === 0xfeff) msg = msg.slice(1);
  return {
    format: 'rfc5424', pri, facility: pri >> 3, sev: pri & 7,
    ts: m[2] === '-' ? 0 : parseTime(m[2], 0),
    host: nil(m[3]), app: nil(m[4]), pid: nil(m[5]), msgid: nil(m[6]), sd, msg,
  };
}

// Generic event from any syslog header (also used by the router as the fallback for unknown content).
function eventFromHeader(hdr) {
  const fields = {};
  if (hdr.facility !== undefined) fields.facility = String(hdr.facility);
  if (hdr.app) fields.app = hdr.app;
  if (hdr.pid) fields.pid = hdr.pid;
  if (hdr.msgid) fields.msgid = hdr.msgid;
  for (const [id, params] of Object.entries(hdr.sd || {})) for (const [k, v] of Object.entries(params)) fields[`sd.${id}.${k}`] = v;
  return {
    ts: hdr.ts, host: hdr.host, category: 'system', action: 'log', outcome: 'unknown',
    severity: sevFromSyslog(hdr.sev), process: hdr.app || '', message: firstLine(hdr.msg, 1000), fields,
  };
}

module.exports = {
  name: 'rfc5424',
  sniff: (line) => HDR_RE.test(line),
  parse(line) { const h = parseHeader(line); return h ? { src_type: 'syslog', ...eventFromHeader(h) } : null; },
  parseHeader,
  eventFromHeader,
};
