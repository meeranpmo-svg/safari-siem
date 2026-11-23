// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// RFC 3164 (BSD) syslog: <PRI>Mmm dd hh:mm:ss HOST TAG[PID]: MSG
// Variants handled: missing PRI, ISO-8601 timestamp (rsyslog), year in timestamp (Cisco ASA), missing host,
// PRI with no timestamp at all (FortiGate, CEF senders, ASA without timestamps).
const { MONTHS, inferYear, parseTime, wallToMs } = require('./util');
const { eventFromHeader } = require('./rfc5424');

const PRI_RE = /^<(\d{1,3})>/;
const BSD_TS = /([A-Z][a-z]{2})\s{1,2}(\d{1,2})(?:\s+(\d{4}))?\s+(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))?(?=\s|:)/y;
const ISO_TS = /(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:?\d{2})?)(?=\s)/y;
const TAG_RE = /^([A-Za-z0-9_.\/()-]{1,64})(?:\[([^\]\s]{0,32})\])?: ?/;
const HOST_RE = /^[A-Za-z0-9_.:%-]{1,255}$/;
const PAYLOAD_RE = /^(?:CEF:\d|LEEF:\d|%[A-Z])/; // payload markers that must not be taken for a host or tag

function parseHeader(line, offMin = 0, refMs = Date.now()) {
  let i = 0;
  let pri = -1;
  const pm = PRI_RE.exec(line);
  if (pm) { pri = Number(pm[1]); if (pri > 191) return null; i = pm[0].length; }
  let ts = 0;
  let hasTs = false;
  BSD_TS.lastIndex = i;
  let m = BSD_TS.exec(line);
  if (m && MONTHS[m[1].toLowerCase()] !== undefined) {
    const mo = MONTHS[m[1].toLowerCase()];
    const ms = m[7] ? Number((m[7] + '00').slice(0, 3)) : 0;
    ts = m[3] ? wallToMs(+m[3], mo, +m[2], +m[4], +m[5], +m[6], ms, offMin) : inferYear(mo, +m[2], +m[4], +m[5], +m[6], ms, offMin, refMs);
    i = BSD_TS.lastIndex;
    hasTs = true;
  } else {
    ISO_TS.lastIndex = i;
    m = ISO_TS.exec(line);
    if (m) { ts = parseTime(m[1], offMin); i = ISO_TS.lastIndex; hasTs = true; }
  }
  if (pri < 0 && !hasTs) return null;
  let host = '';
  let app = '';
  let pid = '';
  let rest = line.slice(i).replace(/^\s+/, '');
  if (hasTs) {
    const sp = rest.indexOf(' ');
    const cand = sp < 0 ? rest : rest.slice(0, sp);
    if (cand && sp > 0 && !cand.endsWith(':') && HOST_RE.test(cand) && !PAYLOAD_RE.test(cand)) { host = cand; rest = rest.slice(sp + 1); }
    const t = PAYLOAD_RE.test(rest) ? null : TAG_RE.exec(rest);
    if (t) { app = t[1]; pid = t[2] || ''; rest = rest.slice(t[0].length); }
    else if (rest.startsWith(': ')) rest = rest.slice(2);
  }
  return {
    format: 'rfc3164', pri, facility: pri >= 0 ? pri >> 3 : undefined, sev: pri >= 0 ? pri & 7 : -1,
    ts, host, app, pid, msgid: '', sd: null, msg: rest,
  };
}

module.exports = {
  name: 'rfc3164',
  sniff: (line) => PRI_RE.test(line) || /^[A-Z][a-z]{2}\s{1,2}\d{1,2} \d{2}:/.test(line),
  parse(line, meta = {}) {
    const h = parseHeader(line, meta.tz_offset_min || 0, meta.rts || Date.now());
    return h ? { src_type: 'syslog', ...eventFromHeader(h) } : null;
  },
  parseHeader,
};
