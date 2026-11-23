// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * ZKTeco ZKBioSecurity / ZKBio CVSecurity - read-only client for door access health.
 *   GET https://<server>:<port><path>?access_token=<token>&pageNo=1&pageSize=<n>   (token from System -> API Authorization)
 * Only GET, and only the three paths an admin saved (devices, doors, events) - never a remote door open, a person, a card or a level.
 * The path names differ between ZKBio releases, so they are settings (DEFAULT_PATHS below) and the answers are read by field
 * pattern, not by one fixed layout. A field the server does not send stays null ("not reported"), never a guess.
 * PDPL: an access event names a person; this client keeps the event type, the door and the time ONLY - pin, name, card and photo
 * are dropped here, before anything is stored.
 */
const { request } = require('../secops/https');

const DEFAULT_PATHS = { devices: '/api/device/list', doors: '/api/door/list', events: '/api/transaction/list' };
const PATH_RE = /^\/api\/[A-Za-z0-9_/.-]{1,120}$/;
const okPath = (p) => PATH_RE.test(p) && !p.includes('..');

// the list inside whichever envelope this release uses
function rows(j) {
  if (Array.isArray(j)) return j;
  if (!j || typeof j !== 'object') return null;
  for (const k of ['data', 'rows', 'list', 'records', 'items', 'result']) {
    const v = j[k];
    if (Array.isArray(v)) return v;
    if (v && typeof v === 'object') { const r = rows(v); if (r) return r; }
  }
  return null;
}
const pick = (o, keys) => { for (const k of keys) if (o[k] !== undefined && o[k] !== null && o[k] !== '') return o[k]; return null; };
const txt = (v, max = 120) => (v == null ? null : String(v).replace(/[\u0000-\u001f]/g, ' ').trim().slice(0, max) || null);
function onlineOf(o) {
  const v = pick(o, ['connectState', 'connStatus', 'commStatus', 'onlineStatus', 'online', 'isOnline', 'status', 'state']);
  if (v == null) return null;
  const s = String(v).trim().toLowerCase();
  if (['1', 'true', 'online', 'connected', 'normal'].includes(s)) return true;
  if (['0', 'false', 'offline', 'disconnected', 'abnormal'].includes(s)) return false;
  return null;                                           // any other code is not something we can read as up or down
}
function device(o) {
  return { name: txt(pick(o, ['devName', 'deviceName', 'alias', 'name'])), sn: txt(pick(o, ['sn', 'devSn', 'deviceSn', 'serialNumber']), 60),
    ip: txt(pick(o, ['ipAddress', 'ip', 'devIp']), 45), area: txt(pick(o, ['areaName', 'area', 'authAreaName']), 80),
    model: txt(pick(o, ['deviceType', 'devType', 'model', 'machineType']), 60), firmware: txt(pick(o, ['fwVersion', 'firmware', 'firmwareVersion']), 60), online: onlineOf(o) };
}
function door(o) {
  const en = pick(o, ['enabled', 'enable', 'isEnable']);
  return { name: txt(pick(o, ['doorName', 'name', 'alias'])), device: txt(pick(o, ['devName', 'deviceName', 'devAlias'])), sn: txt(pick(o, ['devSn', 'sn', 'deviceSn']), 60),
    enabled: en == null ? null : ['1', 'true'].includes(String(en).toLowerCase()), state: txt(pick(o, ['doorState', 'doorStatus', 'sensorState', 'relayState']), 40) };
}
const KINDS = [['duress', /duress/i], ['forced', /forc(ed|ibly)|break.?in|opened (abnormally|without)/i], ['tamper', /tamper|dismantl/i],
  ['held-open', /held open|open(ed)? (too long|timeout)|door left open|open overtime/i], ['alarm', /alarm|anti-?pass/i],
  ['denied', /denied|invalid|illegal|not registered|unregistered|failed|expired|no access/i]];
function eventKind(name) { const s = String(name || ''); for (const [k, re] of KINDS) if (re.test(s)) return k; return 'normal'; }
// an access event, with the person removed (PDPL)
function event(o) {
  const name = txt(pick(o, ['eventName', 'eventTypeName', 'eventDesc', 'event', 'description']), 120);
  const t = pick(o, ['eventTime', 'time', 'createTime', 'dateTime']);
  return { kind: eventKind(name), event: name, door: txt(pick(o, ['eventPointName', 'doorName', 'pointName']), 120), device: txt(pick(o, ['devAlias', 'devName', 'deviceName']), 120),
    at: t == null ? null : (Number.isFinite(Number(t)) && String(t).length >= 12 ? Number(t) : Date.parse(String(t).replace(' ', 'T') + (/[zZ]|[+-]\d\d:?\d\d$/.test(String(t)) ? '' : '+03:00'))) || null };
}
const riyadh = (ms) => new Date(ms + 3 * 3600000).toISOString().replace('T', ' ').slice(0, 19);

function createClient(cfg) {
  const paths = Object.assign({}, DEFAULT_PATHS, cfg.paths || {});
  async function get(which, extra = {}) {
    const p = paths[which]; if (!okPath(p)) throw new Error(which + ' path is not allowed: ' + p);
    const u = new URL('https://' + cfg.host + ':' + (cfg.port || 8098) + p);
    if (cfg.allowHttp) u.protocol = 'http:';
    u.searchParams.set('access_token', cfg.token); u.searchParams.set('pageNo', '1'); u.searchParams.set('pageSize', String(cfg.pageSize || 1000));
    for (const [k, v] of Object.entries(extra)) u.searchParams.set(k, v);
    const r = await request({ url: u.toString(), method: 'GET', tls: cfg.tls || {}, timeoutMs: cfg.timeoutMs || 15000, allow_http: !!cfg.allowHttp });
    if (r.status === 401 || r.status === 403) throw new Error(which + ': HTTP ' + r.status + ' - the API token is not accepted (System -> API Authorization)');
    if (r.status === 404) throw new Error(which + ': HTTP 404 - this ZKBio release has no ' + p + '; set the right path in the connection');
    if (r.status < 200 || r.status >= 300) throw new Error(which + ': HTTP ' + r.status);
    if (!r.json) throw new Error(which + ': the answer is not JSON (is this the ZKBio API port?)');
    const code = r.json.code != null ? String(r.json.code) : null;
    if (code && !['0', '200', '00'].includes(code)) throw new Error(which + ': ZKBio refused (code ' + code + (r.json.message || r.json.msg ? ' - ' + txt(r.json.message || r.json.msg) : '') + ')');
    const L = rows(r.json); if (!L) throw new Error(which + ': no list in the answer');
    return L;
  }
  async function snapshot(now = Date.now()) {
    const out = { at: now, devices: null, doors: null, events: null, errors: [] };
    try { out.devices = (await get('devices')).map(device); } catch (e) { out.errors.push(e.message); }
    try { out.doors = (await get('doors')).map(door); } catch (e) { out.errors.push(e.message); }
    try { out.events = (await get('events', { startDate: riyadh(now - 86400000), endDate: riyadh(now) })).map(event).filter((e) => e.kind !== 'normal'); } catch (e) { out.errors.push(e.message); }
    if (out.devices == null && out.doors == null && out.events == null) throw new Error(out.errors[0] || 'nothing read');
    return out;
  }
  return { get, snapshot };
}

module.exports = { createClient, rows, device, door, event, eventKind, onlineOf, okPath, DEFAULT_PATHS };
