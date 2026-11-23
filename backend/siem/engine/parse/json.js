// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Generic JSON: accepts our own schema field names directly, ECS-style nested objects, and common aliases.
// Everything not mapped goes to `fields` (flattened, dotted keys).
const { parseTime, ipOrEmpty, safeJson, flatten, toInt, sevFromName, splitUser, clean, protoName, firstLine } = require('./util');
const { CATEGORIES, OUTCOMES } = require('../schema');

const ALIASES = {
  ts: ['ts', '@timestamp', 'timestamp', 'time', 'eventTime', 'event.created', 'datetime', 'date'],
  host: ['host', 'hostname', 'host.name', 'host.hostname', 'computer', 'device', 'observer.hostname'],
  message: ['message', 'msg', 'event.original', 'log', 'text', 'summary'],
  user: ['user', 'username', 'user.name', 'userName', 'account', 'login', 'actor'],
  target_user: ['target_user', 'user.target.name', 'targetUser'],
  domain: ['domain', 'user.domain'],
  src_ip: ['src_ip', 'source.ip', 'client.ip', 'client_ip', 'srcip', 'src', 'remote_addr', 'ip', 'sourceIPAddress'],
  dst_ip: ['dst_ip', 'destination.ip', 'server.ip', 'dstip', 'dst'],
  src_port: ['src_port', 'source.port', 'client.port', 'srcport', 'spt'],
  dst_port: ['dst_port', 'destination.port', 'server.port', 'dstport', 'dpt'],
  proto: ['proto', 'network.transport', 'protocol'],
  process: ['process', 'process.executable', 'process.name', 'image'],
  parent_process: ['parent_process', 'process.parent.executable', 'process.parent.name'],
  cmdline: ['cmdline', 'process.command_line', 'command_line', 'command'],
  hash: ['hash', 'process.hash.sha256', 'file.hash.sha256', 'sha256', 'md5'],
  url: ['url', 'url.original', 'url.full', 'request_uri', 'uri', 'path'],
  http_method: ['http_method', 'http.request.method', 'method'],
  http_status: ['http_status', 'http.response.status_code', 'status', 'status_code'],
  user_agent: ['user_agent', 'user_agent.original', 'userAgent', 'http_user_agent'],
  dns_query: ['dns_query', 'dns.question.name', 'query'],
  event_code: ['event_code', 'event.code', 'event_id', 'eventId', 'code'],
  action: ['action', 'event.action'],
  outcome: ['outcome', 'event.outcome', 'result'],
  category: ['category', 'event.category'],
  severity: ['severity', 'level', 'log.level', 'event.severity', 'priority'],
  tags: ['tags'],
};
const NUMERIC = new Set(['src_port', 'dst_port', 'http_status']);

function pick(flat, names) {
  for (const n of names) if (flat[n] !== undefined && flat[n] !== '') { const v = flat[n]; delete flat[n]; return v; }
  return undefined;
}

function parse(line, meta = {}) {
  const o = meta.obj || safeJson(line);
  if (!o || Array.isArray(o)) return null;
  const flat = flatten(o);
  // pre-structured `fields` object from senders that already speak our schema
  const preFields = o.fields && typeof o.fields === 'object' && !Array.isArray(o.fields) ? o.fields : null;
  if (preFields) for (const k of Object.keys(flat)) if (k.startsWith('fields.')) delete flat[k];
  const ev = { src_type: 'json', fields: {} };
  for (const [field, names] of Object.entries(ALIASES)) {
    const v = pick(flat, names);
    if (v === undefined) continue;
    if (field === 'ts') ev.ts = parseTime(v, meta.tz_offset_min || 0);
    else if (NUMERIC.has(field)) ev[field] = toInt(v);
    else if (field === 'severity') ev.severity = /^\d+$/.test(v) ? Math.min(4, toInt(v)) : sevFromName(v, 0);
    else if (field === 'src_ip' || field === 'dst_ip') { ev[field] = ipOrEmpty(v); if (!ev[field]) ev.fields[field + '_raw'] = v; }
    else if (field === 'user' || field === 'target_user') { const x = splitUser(v); ev[field] = x.user; if (field === 'user' && x.domain && !ev.domain) ev.domain = x.domain; }
    else if (field === 'tags') { try { const t = JSON.parse(v); ev.tags = Array.isArray(t) ? t.map(String) : [String(v)]; } catch { ev.tags = String(v).split(',').map((x) => x.trim()).filter(Boolean); } }
    else if (field === 'proto') ev.proto = protoName(v);
    else if (field === 'category') { const c = String(v).toLowerCase(); if (CATEGORIES.includes(c)) ev.category = c; else ev.fields.category_raw = v; }
    else if (field === 'outcome') { const c = String(v).toLowerCase(); ev.outcome = OUTCOMES.includes(c) ? c : (/^(ok|succe)/.test(c) ? 'success' : /^(fail|den|err)/.test(c) ? 'failure' : 'unknown'); }
    else if (field === 'message') ev.message = firstLine(v, 4000);
    else ev[field] = clean(v);
  }
  if (preFields) for (const [k, v] of Object.entries(preFields)) ev.fields[k] = typeof v === 'object' ? JSON.stringify(v) : String(v);
  for (const [k, v] of Object.entries(flat)) {
    if (k === 'src_type' || k === 'src_id' || k === 'collector' || k === 'id' || k === 'rts' || k === 'raw' || k === 'host_ip') continue;
    ev.fields[k] = v;
  }
  if (!ev.action) ev.action = 'event';
  return ev;
}

module.exports = {
  name: 'json',
  sniff(line, meta = {}) { return !!(meta.obj || safeJson(line)); },
  parse,
};
