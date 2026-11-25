// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Parser router. Picks the parser by the source's configured type, falls back to content sniffing, then to a
// generic syslog event, and finally to an `unparsed` event. Never drops a line and never throws.
//   createParser({log, config}) → { parse(line, meta) → event, stats(), parsers }
//   config.exchange.store_subjects (default false): mail subjects are stored only as SHA-256 (fields + raw).
// A parser may return `raw_body` (e.g. the line with the mail subject replaced by its hash); the router then stores
// <syslog header prefix> + raw_body as `raw` instead of the original line.
//   meta = { collector, src_id, src_type?, peer_ip, rts, tz_offset_min?, obj? (already-parsed JSON object),
//            stream? (file identity "<host>|<path>" for relay-tailed files: learned #Fields headers are kept per stream) }
const { finalise, blankEvent } = require('../schema');
const { syslogHeader, sevFromSyslog } = require('./util');
const rfc5424 = require('./rfc5424');

const P = {
  windows: require('./windows'),
  m365: require('./m365'),
  cloudflare: require('./cloudflare'),
  json: require('./json'),
  cef: require('./cef'),
  leef: require('./leef'),
  fortigate: require('./fortigate'),
  cisco: require('./cisco'),
  h3c: require('./h3c'),                 // H3C / HPE Comware switches and routers (%%10MODULE/level/MNEMONIC)
  webaccess: require('./webaccess'),
  linux: require('./linux'),
  exchange: require('./exchange'),
  iis: require('./iis'),
  // device classes (engine/parse/<file>.js, docs/PARSERS.md)
  paloalto: require('./paloalto'),
  ciscoasa: require('./ciscoasa'),
  ciscoucs: require('./ciscoucs'),
  f5: require('./f5'),
  netscaler: require('./netscaler'),
  esxi: require('./esxi'),
  silverpeak: require('./silverpeak'),   // Silver Peak / HPE Aruba EdgeConnect WAN optimisation (docs/PARSERS.md)
  somansa: require('./somansa'),         // Somansa Privacy-i / Mail-i / Server-i DLP (native key=value syslog)
  libraesva: require('./libraesva'),     // Libraesva Email Security Gateway (Postfix/Amavis mail-log syslog)
  rfc5424,
  rfc3164: require('./rfc3164'),
};

// source type → preferred parser
const BY_TYPE = {
  windows: P.windows, m365: P.m365, cloudflare: P.cloudflare, json: P.json, cef: P.cef, leef: P.leef, fortigate: P.fortigate, cisco: P.cisco,
  h3c: P.h3c, comware: P.h3c, 'h3c-comware': P.h3c,
  nginx: P.webaccess, apache: P.webaccess, web: P.webaccess, webaccess: P.webaccess, linux: P.linux,
  exchange: P.exchange, msgtrk: P.exchange, iis: P.iis,
  paloalto: P.paloalto, 'pan-os': P.paloalto, panos: P.paloalto,
  'cisco-asa': P.ciscoasa, 'cisco-ftd': P.ciscoasa, asa: P.ciscoasa, ftd: P.ciscoasa,
  'cisco-ucs': P.ciscoucs, ucs: P.ciscoucs,
  f5: P.f5, bigip: P.f5, 'f5-bigip': P.f5,
  netscaler: P.netscaler, 'citrix-adc': P.netscaler, adc: P.netscaler,
  esxi: P.esxi, vmware: P.esxi,
  silverpeak: P.silverpeak, 'silver-peak': P.silverpeak, edgeconnect: P.silverpeak,
  somansa: P.somansa, 'privacy-i': P.somansa, 'somansa-dlp': P.somansa,
  libraesva: P.libraesva, 'libraesva-esg': P.libraesva,
  // CEF/LEEF feeds from DLP / EDR / Check Point / Zscaler NSS / email gateways: the generic parsers plus the vendor hooks in cef-vendors.js
  'dlp-cef': P.cef, 'edr-cef': P.cef, 'checkpoint-cef': P.cef, 'checkpoint-leef': P.leef,
};
// sniff order for unknown/"syslog" sources: most specific first. PAN CSV, NetScaler and UCSM carry unmistakable
// markers; cisco-asa must precede cisco (same %TAG), ciscoucs too (%UCSM-n-X would match the IOS pattern); F5 and ESXi
// are keyed on message ids / Originator tags and go before the generic exchange/iis/web/linux text parsers. Silver Peak is
// sniffed only on vendor words (Silver Peak / EdgeConnect / ECOS / VXOA or a vendor tag) and sits before linux.js so its
// sshd lines are not taken for a Linux host; sources registered with type silverpeak skip sniffing entirely.
const JSON_ORDER = [P.windows, P.m365, P.cloudflare, P.exchange, P.iis, P.json];
const TEXT_ORDER = [P.cef, P.leef, P.paloalto, P.netscaler, P.ciscoucs, P.ciscoasa, P.fortigate, P.cisco, P.h3c, P.f5, P.esxi, P.silverpeak, P.somansa, P.libraesva, P.exchange, P.iis, P.webaccess, P.linux];

function createParser({ log, config } = {}) {
  if (config) P.exchange.configure(config.exchange || {});
  const perSource = new Map(); // src_id → {events, errors, by_parser:{}}
  const byParser = {};

  function count(srcId, parserName, err) {
    let s = perSource.get(srcId);
    if (!s) { s = { events: 0, parse_errors: 0, by_parser: {} }; if (perSource.size < 5000) perSource.set(srcId, s); }
    s.events++;
    if (err) s.parse_errors++;
    s.by_parser[parserName] = (s.by_parser[parserName] || 0) + 1;
    byParser[parserName] = (byParser[parserName] || 0) + 1;
  }

  function tryParser(p, body, m, errs) {
    try {
      return p.parse(body, m) || null;
    } catch (e) {
      errs.push(p.name + ': ' + e.message);
      if (log) log.every('parser-throw-' + p.name, 30000, 'warn', 'parser threw', { parser: p.name, src_id: m.src_id, err: e.message });
      return null;
    }
  }

  function parse(line, meta = {}) {
    if (Buffer.isBuffer(line)) line = line.toString('utf8');
    if (typeof line !== 'string') line = line === undefined || line === null ? '' : String(line);
    const rts = meta.rts || Date.now();
    const srcType = meta.src_type || 'syslog';
    let ev = null;
    let parserName = 'none';
    let hdr = null;
    let body = line;
    const errs = [];
    try {
      let obj = meta.obj && typeof meta.obj === 'object' && !Array.isArray(meta.obj) ? meta.obj : null;
      if (!obj) {
        hdr = syslogHeader(line, { tz_offset_min: meta.tz_offset_min || 0, rts });
        if (hdr) body = hdr.msg;
        if (body.charCodeAt(0) === 123) { try { const o = JSON.parse(body); if (o && typeof o === 'object' && !Array.isArray(o)) obj = o; } catch { /* not JSON */ } }
      }
      const m = { collector: meta.collector, src_id: meta.src_id, src_type: srcType, peer_ip: meta.peer_ip, rts, tz_offset_min: meta.tz_offset_min || 0, syslog: hdr, obj };
      if (meta.stream) m.stream = meta.stream; // file identity (relay file sources): keys the learned #Fields header per file
      const preferred = BY_TYPE[srcType];
      if (preferred) { ev = tryParser(preferred, body, m, errs); if (ev) parserName = preferred.name; }
      if (!ev) {
        for (const p of obj ? JSON_ORDER : TEXT_ORDER) {
          if (p === preferred) continue;
          let ok = false;
          try { ok = p.sniff(body, m); } catch { ok = false; }
          if (!ok) continue;
          ev = tryParser(p, body, m, errs);
          if (ev) { parserName = p.name; break; }
        }
      }
      if (!ev && hdr) { ev = rfc5424.eventFromHeader(hdr); ev.src_type = srcType === 'syslog' || !srcType ? 'syslog' : srcType; parserName = hdr.format; }
      if (ev && hdr) {
        if (!ev.ts) ev.ts = hdr.ts;
        if (!ev.host) ev.host = hdr.host;
        if (ev.severity === undefined) ev.severity = sevFromSyslog(hdr.sev);
        if (!ev.fields) ev.fields = {};
        if (hdr.app && ev.fields.app === undefined) ev.fields.app = hdr.app;
        if (hdr.pid && ev.fields.pid === undefined) ev.fields.pid = hdr.pid;
        if (hdr.facility !== undefined && ev.fields.facility === undefined) ev.fields.facility = String(hdr.facility);
      }
    } catch (e) {
      errs.push('router: ' + e.message);
      ev = null;
    }
    const perr = !ev;
    if (!ev) ev = { action: 'unparsed', category: 'other', src_type: srcType, message: line.slice(0, 300), fields: {} };
    if (!ev.src_type) ev.src_type = srcType;
    if (errs.length) { if (!ev.fields) ev.fields = {}; ev.fields.parse_error = errs.join('; ').slice(0, 500); }
    const out = Object.assign(blankEvent(), ev);
    out.rts = rts;
    out.src_id = meta.src_id || '';
    out.collector = meta.collector || '';
    if (!out.host_ip) out.host_ip = meta.peer_ip || '';
    out.raw = typeof out.raw_body === 'string' ? line.slice(0, line.length - body.length) + out.raw_body : line;
    delete out.raw_body;
    if (!out.fields) out.fields = {};
    if (!out.tags) out.tags = [];
    // Site enrichment hook: the collector resolves the site from the source registry (onboarding hub keeps site per
    // source, keyed by src_id) and passes it as meta.site; the parser only stamps it. Nothing is looked up here.
    if (meta.site && out.fields.site === undefined) out.fields.site = String(meta.site).slice(0, 64);
    try { finalise(out, { rts }); } catch (e) { out.fields.finalise_error = e.message; }
    if (perr || errs.length) Object.defineProperty(out, '_perr', { value: 1, enumerable: false, writable: true });
    count(out.src_id, parserName, perr || errs.length > 0);
    return out;
  }

  function stats() {
    const sources = {};
    for (const [k, v] of perSource) sources[k] = v;
    return { by_parser: { ...byParser }, sources };
  }

  return { parse, stats, parsers: P };
}

const defaultParser = createParser();
module.exports = { createParser, parse: defaultParser.parse, parsers: P, BY_TYPE };
