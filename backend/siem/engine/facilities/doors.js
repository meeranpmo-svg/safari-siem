// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Door access - ZKTeco ZKBioSecurity servers (one per site or one for all), read only (zkbio.js).
 *   connections   state collection "zkbio_servers"; the API token in secrets.json "zkbio.servers.<id>" (sealed, write-only)
 *   poll          every poll_min (default 10) through guard('facilities.zkbio.poll'), rescheduled in finally
 *   view          controllers online / offline / not reported, doors, and the last 24 h of door ALARMS (forced open, held open,
 *                 duress, tamper, alarm) and denied attempts - counted per door, with no person in them (PDPL)
 *   actions       ranked: duress, forced open, tamper, controllers offline, held open, repeated denials at one door, server unread
 * A server not read for 3 polls is stale and its controllers read "not reported", never online.
 */
const SF = require('../secretfile');
const { writeJsonAtomic } = require('../onboard/store');
const { body: check } = require('../util/check');
const { guard: guardJob } = require('../util/errors');
const Z = require('./zkbio');

const ID_RE = /^[a-z0-9][a-z0-9-]{1,39}$/;
const bad = (status, msg) => Object.assign(new Error(msg), { status, code: status });

function analyse({ servers = [], snapshot = () => null, pollMin = 10, now = Date.now(), deniedRepeat = 10 }) {
  const controllers = [], doors = [], alarms = [], srv = [];
  for (const s of servers) {
    const snap = snapshot(s.id), stale = !snap || now - snap.at > 3 * pollMin * 60000;
    srv.push({ id: s.id, label: s.label, site: s.site, enabled: s.enabled, token: s.token, last: snap ? snap.at : null, stale, errors: snap ? snap.errors || [] : [], error: snap && snap.error ? snap.error : null });
    if (!s.enabled || !snap || snap.error) continue;
    for (const d of snap.devices || []) controllers.push(Object.assign({}, d, { server: s.id, site: d.area || s.site, online: stale ? null : d.online }));
    for (const d of snap.doors || []) doors.push(Object.assign({}, d, { server: s.id, site: s.site }));
    for (const e of snap.events || []) if (e.at == null || now - e.at <= 86400000) alarms.push(Object.assign({}, e, { server: s.id, site: s.site }));
  }
  const RANK = { false: 0, null: 1, true: 2 };
  controllers.sort((a, b) => RANK[a.online] - RANK[b.online] || String(a.name).localeCompare(String(b.name)));
  const by = {}; for (const e of alarms) { const k = (e.door || e.device || '(door not named)') + '|' + e.site; const r = by[k] || (by[k] = { door: e.door || e.device || '(door not named)', site: e.site, counts: {}, last: null }); r.counts[e.kind] = (r.counts[e.kind] || 0) + 1; if (e.at && (!r.last || e.at > r.last)) r.last = e.at; }
  const perDoor = Object.values(by).sort((a, b) => Object.values(b.counts).reduce((x, y) => x + y, 0) - Object.values(a.counts).reduce((x, y) => x + y, 0));
  const kc = (k) => alarms.filter((e) => e.kind === k).length;
  const kpis = { servers: servers.length, controllers: controllers.length, online: controllers.filter((c) => c.online === true).length, offline: controllers.filter((c) => c.online === false).length,
    not_reported: controllers.filter((c) => c.online === null).length, doors: doors.length, forced: kc('forced'), held_open: kc('held-open'), duress: kc('duress'), tamper: kc('tamper'), alarm: kc('alarm'), denied: kc('denied'),
    unread: srv.filter((s) => s.enabled && (s.stale || s.error)).length };
  const actions = [], A = (p, n, t, d) => { if (n) actions.push({ priority: p, title: n + ' ' + t, detail: d }); };
  const doorsWith = (k) => perDoor.filter((r) => r.counts[k]).slice(0, 4).map((r) => r.door + (r.site ? ' (' + r.site + ')' : '') + ' ×' + r.counts[k]).join(', ');
  A(100, kpis.duress, 'duress alarm(s) in 24 h', doorsWith('duress') + ' - a person opened a door under threat; call security now.');
  A(95, kpis.forced, 'door(s) forced open in 24 h', doorsWith('forced') + ' - check the CCTV for that door and time, and the door itself.');
  A(90, kpis.tamper, 'tamper alarm(s) in 24 h', doorsWith('tamper') + ' - someone opened or removed a reader / controller.');
  A(80, kpis.offline, 'door controller(s) offline', controllers.filter((c) => c.online === false).slice(0, 5).map((c) => (c.name || c.sn || c.ip) + (c.site ? ' (' + c.site + ')' : '')).join(', ') + ' - its doors run on the last rules it received and send no events; check power and network.');
  A(60, kpis.held_open, 'door(s) held open in 24 h', doorsWith('held-open') + ' - propped doors; check the closer and remind the site.');
  const rep = perDoor.filter((r) => (r.counts.denied || 0) >= deniedRepeat);
  A(50, rep.length, 'door(s) with ' + deniedRepeat + '+ denied attempts in 24 h', rep.slice(0, 4).map((r) => r.door + ' ×' + r.counts.denied).join(', ') + ' - an expired card used again and again, or someone trying cards; review in ZKBio.');
  A(40, kpis.unread, 'ZKBio server(s) not read', srv.filter((s) => s.enabled && (s.stale || s.error)).map((s) => s.label + ': ' + (s.error || 'not read for 3 polls')).join(' · '));
  actions.sort((a, b) => b.priority - a.priority);
  return { configured: servers.length > 0, reason: servers.length ? null : 'No door access system is connected. Add the ZKBioSecurity server (address, port and an API token from System -> API Authorization) under Door access -> Connection.',
    at: now, kpis, servers: srv, controllers, doors, per_door: perDoor, actions,
    note: 'Read from ZKBioSecurity through its API, GET only - no door is opened or changed. Events keep the type, door and time; who badged is not read into the platform.' };
}

function createDoors({ state, config, log, now, allowHttp } = {}) {
  if (!state) throw new Error('doors needs state');
  const NOW = now || Date.now, col = state.collection('zkbio_servers'), snaps = new Map(), L = log || { info() {}, warn() {} };
  const secPath = (config && config._paths && config._paths.secrets) || null;
  const pollMin = (config && config.facilities && config.facilities.poll_min) || 10;
  const secrets = () => (config && config.secrets && config.secrets.zkbio && config.secrets.zkbio.servers) || {};
  const pub = (s) => { const sec = secrets()[s.id] || {}; return Object.assign({}, s, { token: sec.token ? 'token set' + (sec.tls && sec.tls.insecure ? ' (TLS NOT verified)' : sec.tls && sec.tls.fingerprint256 ? ' (certificate pinned)' : '') : null }); };

  function put(input, by) {
    const b = check(input).str('id', { max: 40 }).str('label', { max: 80 }).str('site', { max: 60 }).str('host', { host: true, max: 253 }).int('port', { min: 1, max: 65535 }).bool('enabled')
      .str('path_devices', { max: 124 }).str('path_doors', { max: 124 }).str('path_events', { max: 124 }).done();
    const id = String(b.id || '').toLowerCase(); if (!ID_RE.test(id)) throw bad(400, 'id: 2-40 lowercase letters, digits and dashes');
    const ex = col.get(id), s = Object.assign({ id, enabled: true, port: 8098, site: 'Unassigned', paths: {} }, ex || {});
    if (b.label !== undefined || !ex) s.label = b.label || id;
    if (b.site !== undefined) s.site = b.site;
    if (b.host !== undefined) s.host = b.host; if (!s.host) throw bad(400, 'host is required');
    if (b.port !== undefined) s.port = b.port;
    if (b.enabled !== undefined) s.enabled = b.enabled;
    s.paths = Object.assign({}, s.paths);
    for (const k of ['devices', 'doors', 'events']) { const v = b['path_' + k]; if (v !== undefined) { if (!Z.okPath(v)) throw bad(400, 'path_' + k + ': a path under /api/ (letters, digits, / . _ -)'); s.paths[k] = v; } }
    s.updated = NOW(); s.updated_by = by; col.put(s); return pub(s);
  }
  function remove(id, by) { if (!col.get(id)) throw bad(404, 'server not found'); col.remove(id); snaps.delete(id); if (secrets()[id]) setToken(id, null, by); return { removed: id }; }
  function setToken(id, input, by) {
    if (!secPath) throw bad(500, 'secrets path unknown');
    if (input && !col.get(id)) throw bad(404, 'server not found');
    let b = null;
    if (input) { b = check(input).str('token', { required: true, max: 512 }).str('fingerprint256', { max: 100 }).bool('insecure').done();
      if (b.fingerprint256 && b.fingerprint256.replace(/[^0-9a-f]/gi, '').length !== 64) throw bad(400, 'fingerprint256 must be a SHA-256 certificate fingerprint'); }
    let sec = {}; try { sec = SF.read(secPath) || {}; } catch (e) { if (e.code !== 'ENOENT') throw e; }
    sec.zkbio = sec.zkbio || {}; sec.zkbio.servers = sec.zkbio.servers || {};
    if (b) sec.zkbio.servers[id] = { token: b.token, tls: Object.assign({}, b.fingerprint256 ? { fingerprint256: b.fingerprint256.replace(/[^0-9a-f]/gi, '') } : {}, b.insecure ? { insecure: true } : {}) };
    else delete sec.zkbio.servers[id];
    writeJsonAtomic(secPath, sec);
    if (config && config.secrets) { config.secrets.zkbio = config.secrets.zkbio || {}; config.secrets.zkbio.servers = sec.zkbio.servers; }
    L.info('zkbio token changed', { id, by, set: !!b });
    return pub(col.get(id) || { id });
  }
  const cfgOf = (s) => { const sec = secrets()[s.id] || {}; return { host: s.host, port: s.port, token: sec.token, tls: sec.tls || {}, paths: s.paths, allowHttp }; };
  async function pollOne(id) {
    const s = col.get(id); if (!s) throw bad(404, 'server not found');
    const sec = secrets()[id] || {}; let out;
    if (!sec.token) out = { at: NOW(), error: 'API token not set' };
    else { try { out = await Z.createClient(cfgOf(s)).snapshot(NOW()); } catch (e) { out = { at: NOW(), error: e.message }; L.warn('zkbio read failed', { id, err: e.message }); } }
    snaps.set(id, out); return out;
  }
  async function pollAll() { for (const s of col.all()) if (s.enabled) await pollOne(s.id); }
  const view = () => analyse({ servers: col.all().map(pub), snapshot: (id) => snaps.get(id) || null, pollMin, now: NOW() });
  let timer = null;
  function start({ firstMs = 30000 } = {}) {
    stop(); const run = guardJob('facilities.zkbio.poll', pollAll);
    const loop = async () => { try { await run(); } finally { timer = setTimeout(loop, Math.max(2, pollMin) * 60000); if (timer.unref) timer.unref(); } };
    timer = setTimeout(loop, firstMs); if (timer.unref) timer.unref();
  }
  function stop() { if (timer) clearTimeout(timer); timer = null; }
  return { list: () => col.all().map(pub), get: (id) => { const s = col.get(id); return s ? pub(s) : null; }, put, remove, setToken, sync: pollOne, pollAll, view, start, stop };
}

module.exports = { createDoors, analyse };
