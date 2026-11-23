// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * CCTV / NVR - recorder and camera health, read only (isapi.js: Hikvision ISAPI, four GET paths).
 *   recorders    state collection "nvr_recorders"; user + password in secrets.json "cctv.recorders.<id>" (sealed, write-only)
 *   poll         every poll_min (default 5) through guard('facilities.cctv.poll'), rescheduled in finally
 *   history      per camera, its online state at each poll for 7 days (state collection "cctv_hist") - what the ML reads
 *   view         recorders (model, firmware, reachable / stale), disks (status, used %), cameras online / offline / not reported
 *   ML           availability per camera over 7 days; flapping (4+ changes in 24 h); a GROUP OUTAGE - 3+ cameras on one recorder
 *                going offline within 10 minutes - points to one shared cause (PoE switch, uplink, power) instead of N camera
 *                faults; a camera offline since it was first seen; recording at risk = disk error, or no disk
 *   actions      ranked: disk failed, recorder unreachable, group outage, cameras offline, flapping, recorder stale
 * A recorder not read for 3 polls is stale and its cameras read "not reported", never online. No video or image is read.
 */
const SF = require('../secretfile');
const { writeJsonAtomic } = require('../onboard/store');
const { body: check } = require('../util/check');
const { guard: guardJob } = require('../util/errors');
const I = require('./isapi');

const ID_RE = /^[a-z0-9][a-z0-9-]{1,39}$/;
const bad = (status, msg) => Object.assign(new Error(msg), { status, code: status });
const DAY = 86400000, KEEP = 7 * DAY;

// cameras of one snapshot: channels joined to their status by channel id
function camerasOf(rec, snap, stale) {
  const st = new Map((snap.status || []).map((x) => [x.id, x])), out = [];
  const ids = new Set([...(snap.channels || []).map((c) => c.id), ...(snap.status || []).map((c) => c.id)]);
  for (const id of ids) { const c = (snap.channels || []).find((x) => x.id === id) || {}, s = st.get(id) || {};
    out.push({ key: rec.id + ':' + id, recorder: rec.id, recorder_label: rec.label, site: rec.site, channel: id, name: c.name || null, ip: c.ip || s.ip || null, online: stale || snap.status == null ? null : s.online == null ? null : s.online }); }
  return out.sort((a, b) => Number(a.channel) - Number(b.channel));
}
function analyse({ recorders = [], snapshot = () => null, history = () => ({}), pollMin = 5, now = Date.now() }) {
  const recs = [], cams = [], disks = [], outages = [];
  for (const r of recorders) {
    const snap = snapshot(r.id), stale = !snap || now - snap.at > 3 * pollMin * 60000;
    recs.push({ id: r.id, label: r.label, site: r.site, host: r.host, enabled: r.enabled, credential: r.credential, last: snap ? snap.at : null, stale, error: snap && snap.error ? snap.error : null, errors: snap ? snap.errors || [] : [], info: snap && snap.info ? snap.info : null,
      cameras: snap && !snap.error ? camerasOf(r, snap, stale).length : null });
    if (!r.enabled || !snap || snap.error) continue;
    const H = history(r.id) || {};
    for (const c of camerasOf(r, snap, stale)) {
      const h = (H[c.channel] || []).filter((p) => now - p[0] <= KEEP), up = h.filter((p) => p[1] === 1).length, d24 = h.filter((p) => now - p[0] <= DAY);
      let changes = 0; for (let i = 1; i < d24.length; i++) if (d24[i][1] !== d24[i - 1][1]) changes++;
      let downSince = null; if (c.online === false) { downSince = now; for (let i = h.length - 1; i >= 0 && h[i][1] === 0; i--) downSince = h[i][0]; }
      cams.push(Object.assign(c, { availability_7d: h.length >= 12 ? Math.round(1000 * up / h.length) / 10 : null, samples: h.length, flaps_24h: changes, flapping: changes >= 4, down_since: downSince, never_seen_up: h.length >= 12 && up === 0 }));
    }
    for (const d of snap.disks || []) disks.push(Object.assign({}, d, { recorder: r.id, recorder_label: r.label, used_pct: d.capacity_gb ? Math.round(100 * (d.capacity_gb - (d.free_gb || 0)) / d.capacity_gb) : null, failed: !!(d.status && !/^ok$|^normal$|^idle$/i.test(d.status)) }));
    // group outage: cameras of this recorder that went down within 10 minutes of each other
    const down = cams.filter((c) => c.recorder === r.id && c.online === false && c.down_since).sort((a, b) => a.down_since - b.down_since);
    let grp = []; const flush = () => { if (grp.length >= 3) outages.push({ recorder: r.id, recorder_label: r.label, site: r.site, cameras: grp.map((c) => c.name || 'channel ' + c.channel), since: grp[0].down_since, why: grp.length + ' cameras on ' + r.label + ' went offline within 10 minutes of each other - one shared cause is likely (the PoE switch or its uplink, a power circuit), not ' + grp.length + ' camera faults' }); grp = []; };
    for (const c of down) { if (grp.length && c.down_since - grp[0].down_since > 600000) flush(); grp.push(c); } flush();
  }
  const noDisk = recs.filter((r) => r.enabled && !r.stale && !r.error && !disks.some((d) => d.recorder === r.id));
  const kpis = { recorders: recorders.length, reachable: recs.filter((r) => r.enabled && !r.stale && !r.error).length, unreachable: recs.filter((r) => r.enabled && (r.stale || r.error)).length,
    cameras: cams.length, online: cams.filter((c) => c.online === true).length, offline: cams.filter((c) => c.online === false).length, not_reported: cams.filter((c) => c.online === null).length,
    flapping: cams.filter((c) => c.flapping).length, disks: disks.length, disks_failed: disks.filter((d) => d.failed).length, group_outages: outages.length };
  const avail = cams.filter((c) => c.availability_7d != null); kpis.availability_7d = avail.length ? Math.round(10 * avail.reduce((s, c) => s + c.availability_7d, 0) / avail.length) / 10 : null;
  const actions = [], A = (p, n, t, d) => { if (n) actions.push({ priority: p, title: n + ' ' + t, detail: d }); };
  A(100, kpis.disks_failed, 'recorder disk(s) not healthy', disks.filter((d) => d.failed).map((d) => d.recorder_label + ' disk ' + (d.id || '') + ': ' + d.status).join(' · ') + ' - recording on that disk is at risk; replace it and check the recorder\'s RAID / disk group.');
  A(95, noDisk.length, 'recorder(s) report no disk', noDisk.map((r) => r.label).join(', ') + ' - a recorder without a disk records nothing.');
  A(90, kpis.unreachable, 'recorder(s) not reachable', recs.filter((r) => r.enabled && (r.stale || r.error)).map((r) => r.label + ': ' + (r.error || 'not read for 3 polls')).join(' · '));
  for (const o of outages) A(85, o.cameras.length, 'cameras down together on ' + o.recorder_label, o.why + '.');
  const lone = cams.filter((c) => c.online === false && !outages.some((o) => o.recorder === c.recorder && o.cameras.includes(c.name || 'channel ' + c.channel)));
  A(70, lone.length, 'camera(s) offline', lone.slice(0, 6).map((c) => (c.name || 'channel ' + c.channel) + ' (' + c.recorder_label + ')').join(', ') + ' - check the camera\'s cable / PoE port and that its IP did not change.');
  A(50, kpis.flapping, 'camera(s) going on and off', cams.filter((c) => c.flapping).slice(0, 6).map((c) => (c.name || 'channel ' + c.channel) + ' ×' + c.flaps_24h).join(', ') + ' - usually a failing cable, PoE budget on the switch, or a camera rebooting.');
  actions.sort((a, b) => b.priority - a.priority);
  return { configured: recorders.length > 0, reason: recorders.length ? null : 'No recorder is connected. Add each NVR (address, a read-only user) under Recorders: the platform reads camera status and disk health from it, never video.',
    at: now, kpis, recorders: recs, cameras: cams, disks, outages, actions,
    note: 'Read from the recorders through ISAPI, GET only - no video, no image, no setting is read or changed. Availability is this platform\'s own measurement, one sample per poll.' };
}

function createCctv({ state, config, log, now, client } = {}) {
  if (!state) throw new Error('cctv needs state');
  const NOW = now || Date.now, col = state.collection('nvr_recorders'), hist = state.collection('cctv_hist'), snaps = new Map(), L = log || { info() {}, warn() {} };
  const secPath = (config && config._paths && config._paths.secrets) || null;
  const pollMin = (config && config.facilities && config.facilities.cctv_poll_min) || 5;
  const secrets = () => (config && config.secrets && config.secrets.cctv && config.secrets.cctv.recorders) || {};
  const pub = (r) => { const s = secrets()[r.id] || {}; return Object.assign({}, r, { credential: s.user ? 'user ' + s.user + ' (password set)' + (r.https === false ? ' · HTTP, not encrypted' : s.tls && s.tls.fingerprint256 ? ' · certificate pinned' : s.tls && s.tls.insecure ? ' · TLS NOT verified' : '') : null }); };
  function put(input, by) {
    const b = check(input).str('id', { max: 40 }).str('label', { max: 80 }).str('site', { max: 60 }).str('host', { host: true, max: 253 }).int('port', { min: 1, max: 65535 }).bool('https').bool('enabled').str('vendor', { max: 20 }).done();
    const id = String(b.id || '').toLowerCase(); if (!ID_RE.test(id)) throw bad(400, 'id: 2-40 lowercase letters, digits and dashes');
    if (b.vendor && b.vendor !== 'hikvision') throw bad(400, 'vendor: only hikvision (ISAPI) is read today');
    const ex = col.get(id), r = Object.assign({ id, enabled: true, https: true, port: 443, site: 'Unassigned', vendor: 'hikvision' }, ex || {});
    for (const k of ['label', 'site', 'host', 'port', 'https', 'enabled']) if (b[k] !== undefined) r[k] = b[k];
    if (!r.label) r.label = id; if (!r.host) throw bad(400, 'host is required');
    if (b.https === false && b.port === undefined && !ex) r.port = 80;
    r.updated = NOW(); r.updated_by = by; col.put(r); return pub(r);
  }
  function remove(id, by) { if (!col.get(id)) throw bad(404, 'recorder not found'); col.remove(id); hist.remove(id); snaps.delete(id); if (secrets()[id]) setCredential(id, null, by); return { removed: id }; }
  function setCredential(id, input, by) {
    if (!secPath) throw bad(500, 'secrets path unknown');
    if (input && !col.get(id)) throw bad(404, 'recorder not found');
    let b = null;
    if (input) { b = check(input).str('user', { required: true, max: 64 }).str('password', { required: true, max: 128 }).str('fingerprint256', { max: 100 }).bool('insecure').done();
      if (b.fingerprint256 && b.fingerprint256.replace(/[^0-9a-f]/gi, '').length !== 64) throw bad(400, 'fingerprint256 must be a SHA-256 certificate fingerprint');
      if (/^admin$/i.test(b.user)) throw bad(400, 'user: use a read-only operator account, not admin - the platform only reads'); }
    let sec = {}; try { sec = SF.read(secPath) || {}; } catch (e) { if (e.code !== 'ENOENT') throw e; }
    sec.cctv = sec.cctv || {}; sec.cctv.recorders = sec.cctv.recorders || {};
    if (b) sec.cctv.recorders[id] = { user: b.user, pass: b.password, tls: Object.assign({}, b.fingerprint256 ? { fingerprint256: b.fingerprint256.replace(/[^0-9a-f]/gi, '') } : {}, b.insecure ? { insecure: true } : {}) };
    else delete sec.cctv.recorders[id];
    writeJsonAtomic(secPath, sec);
    if (config && config.secrets) { config.secrets.cctv = config.secrets.cctv || {}; config.secrets.cctv.recorders = sec.cctv.recorders; }
    L.info('cctv credential changed', { id, by, set: !!b });
    return pub(col.get(id) || { id });
  }
  function record(id, snap) { if (snap.error || !snap.status) return; const h = hist.get(id) || { id, ch: {} }, t = snap.at;
    for (const s of snap.status) { if (s.online == null) continue; const a = (h.ch[s.id] || []).filter((p) => t - p[0] <= KEEP); a.push([t, s.online ? 1 : 0]); h.ch[s.id] = a.slice(-2100); }
    hist.put(h); }
  async function pollOne(id) {
    const r = col.get(id); if (!r) throw bad(404, 'recorder not found');
    const s = secrets()[id] || {}; let out;
    if (!s.user) out = { at: NOW(), error: 'user and password not set' };
    else { try { out = await (client || I.createClient)({ host: r.host, port: r.port, https: r.https !== false, user: s.user, pass: s.pass, tls: s.tls || {} }).snapshot(NOW()); }
      catch (e) { out = { at: NOW(), error: e.message }; L.warn('cctv read failed', { id, err: e.message }); } }
    snaps.set(id, out); record(id, out); return out;
  }
  async function pollAll() { for (const r of col.all()) if (r.enabled) await pollOne(r.id); }
  const view = () => analyse({ recorders: col.all().map(pub), snapshot: (id) => snaps.get(id) || null, history: (id) => (hist.get(id) || {}).ch || {}, pollMin, now: NOW() });
  let timer = null;
  function start({ firstMs = 45000 } = {}) {
    stop(); const run = guardJob('facilities.cctv.poll', pollAll);
    const loop = async () => { try { await run(); } finally { timer = setTimeout(loop, Math.max(2, pollMin) * 60000); if (timer.unref) timer.unref(); } };
    timer = setTimeout(loop, firstMs); if (timer.unref) timer.unref();
  }
  function stop() { if (timer) clearTimeout(timer); timer = null; }
  return { list: () => col.all().map(pub), get: (id) => { const r = col.get(id); return r ? pub(r) : null; }, put, remove, setCredential, sync: pollOne, pollAll, view, start, stop };
}

module.exports = { createCctv, analyse };
