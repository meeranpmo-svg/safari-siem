// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const { guardOf } = require('./errors');
// Storage arrays: NetApp ONTAP and HPE MSA read-only (engine/storage-sources.js), linked to the IT Asset Management
// storage assets. Per array: health, controllers / nodes, pools / aggregates with capacity, volumes, failed disks and recent
// error events; findings with plain thresholds; arrays that are not in the inventory are said so.
//   GET  /storage                      {settings, kinds, platforms[], summary, arrays[], findings[]}             operator
//   GET  /storage/platforms/:id        one array in full (every volume and disk finding)                          operator
//   POST /storage/platforms            {id?, kind: ontap|msa|synology, label, base_url, username, password, ca_file?, interval_min?}  admin
//   POST /storage/platforms/:id/test | /pin {fingerprint} | /sync | /delete                                         admin
//   PUT  /storage/settings             {pool_warn_pct, pool_crit_pct, volume_warn_pct}                            admin
// Credentials are sealed (AES-256-GCM, discovery vault key) and never returned, logged or audited. Changing the address
// or CA file needs the password again. Self-contained; added with one registration line (install/add-storage.sh).
const crypto = require('node:crypto');
const { createSealer } = require('./discovery/vault');

const KINDS = { ontap: 'NetApp ONTAP', msa: 'HPE MSA (2060 / 2062 / 2050 / 2052 / 2040 / 1060 / 1050 / 1040 / P2000 G3)', synology: 'Synology (SA3600 / SA3400 / FS / RS / DS, DSM 7)' };
const SYS = { user: 'system:storage-sync', role: 'system', ip: '' };
const CLOSED = { retired: 1, disposed: 1, lost: 1 };
const s = (v, max) => String(v == null ? '' : v).replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, max || 200);
const bad = (msg, status = 400) => Object.assign(new Error(msg), { status });
const low = (v) => String(v || '').trim().toLowerCase();
const SEV = { critical: 4, high: 3, medium: 2, low: 1 };

function createStorage(app, opts = {}) {
  const { store } = app;
  const plat = store.collection('storage_platforms'), snap = store.collection('storage_snapshots'), conf = store.collection('storage_settings'), assets = store.collection('assets');
  const dc = (app.config && app.config.discovery) || {};
  const sealer = opts.sealer || createSealer({ keyFile: dc.vault_key_file, createKey: dc.vault_create_key !== false, purpose: 'sentra-itam-storage-platforms' });
  // the arrays are read by the Python module (pyengine/storage_sources.py, docs/PYTHON-MIGRATION.md); config
  // storage.engine = "node" keeps the Node.js reader; without Python the bridge falls back to it by itself
  const src = opts.sources || (((app.config && app.config.storage) || {}).engine === 'node' ? require('./storage-sources') : require('./storage-sources-py').createStorageSourcesPy({ python: dc.python_bin || '/opt/sentra-siem/pyenv/bin/python3' }));
  const audit = (e) => { if (app.audit) app.audit(e); };
  const now = opts.now || Date.now;
  const running = new Map();

  function settings() { return Object.assign({ pool_warn_pct: 85, pool_crit_pct: 95, volume_warn_pct: 90 }, (conf.get('settings') || {}).values || {}); }
  function putSettings(b, who) {
    const v = settings();
    for (const k of ['pool_warn_pct', 'pool_crit_pct', 'volume_warn_pct']) if (k in b) { const n = Number(b[k]); if (!Number.isFinite(n) || n < 50 || n > 100) throw bad(k + ' must be 50 to 100'); v[k] = Math.round(n); }
    if (v.pool_warn_pct >= v.pool_crit_pct) throw bad('the warning level must be below the critical level');
    conf.put({ id: 'settings', values: v, updated_by: who.user, updated_at: new Date(now()).toISOString() });
    audit({ by: who.user, role: who.role, ip: who.ip, action: 'storage.settings', target: 'settings', detail: v });
    return view();
  }
  function pview(p) { const { enc, presented, ...pub } = p; return Object.assign(pub, { credentials_set: !!enc, presented: presented || null }); } // eslint-disable-line no-unused-vars
  function cred(p) { if (!p.enc) throw bad('credentials not set', 409); return { target: { base_url: p.base_url, ca_file: p.ca_file || undefined, tls_fingerprint: p.tls_fingerprint || undefined }, secret: JSON.parse(sealer.unseal(p.id, p.enc)) }; }
  const wipe = (c) => { if (c && c.secret) for (const k of Object.keys(c.secret)) c.secret[k] = null; };

  function save(b, who) {
    const cur = b.id ? plat.get(String(b.id)) : null;
    if (b.id && !cur) throw bad('array not found', 404);
    const kind = cur ? cur.kind : s(b.kind, 20);
    if (!KINDS[kind]) throw bad('kind must be ontap, msa or synology');
    const o = Object.assign({}, cur || { id: 'sp_' + crypto.randomBytes(5).toString('hex'), kind, created_by: who.user, created_at: new Date(now()).toISOString(), interval_min: 30 });
    if ('label' in b || !cur) o.label = s(b.label, 80) || s(b.base_url, 80) || KINDS[kind];
    let moved = false;
    if ('base_url' in b) {
      const u = s(b.base_url, 300).replace(/\/+$/, '');
      try { src.baseOf(u); } catch (e) { throw bad(e.message); }
      if (cur && u !== cur.base_url) { moved = true; o.tls_fingerprint = ''; o.presented = null; }
      o.base_url = u;
    }
    if (!o.base_url) throw bad('the management address is required');
    if ('ca_file' in b) { const f = s(b.ca_file, 250); if (f && !/^\/[A-Za-z0-9._/-]+$/.test(f)) throw bad('ca_file must be an absolute path'); if (cur && f !== (cur.ca_file || '')) moved = true; o.ca_file = f; }
    if ('site' in b) o.site = s(b.site, 80);
    if ('interval_min' in b) { const m = Number(b.interval_min); if (!Number.isFinite(m) || m < 10 || m > 1440) throw bad('interval must be 10 to 1440 minutes'); o.interval_min = Math.round(m); }
    const user = s(b.username, 200), pass = b.password == null ? '' : String(b.password).slice(0, 256);
    let secret = null;
    if (user || pass) { if (!user || !pass) throw bad('enter both the user name and the password'); secret = { username: user, password: pass }; }
    if (secret) {
      if (!sealer.available()) throw bad('credential vault unavailable: ' + sealer.unavailableReason(), 503);
      o.enc = sealer.seal(o.id, JSON.stringify(secret)); o.credentials_at = new Date(now()).toISOString(); o.credentials_by = who.user;
    } else if (!cur) throw bad('enter the user name and password of a read-only (monitor) account');
    else if (moved) throw bad('the address or CA file changed: enter the password again');
    o.updated_by = who.user; o.updated_at = new Date(now()).toISOString();
    plat.put(o);
    audit({ by: who.user, role: who.role, ip: who.ip, action: cur ? 'storage.platform.update' : 'storage.platform.create', target: o.id, detail: { kind, label: o.label, base_url: o.base_url, credentials_changed: !!secret } });
    return Object.assign(view(), { platform: pview(o) });
  }
  async function test(id, who) {
    const p = plat.get(String(id)); if (!p) throw bad('array not found', 404);
    const c = cred(p); let r;
    try { r = await src.test(p.kind, c); } finally { wipe(c); }
    plat.patch(p.id, (x) => { x.last_test = { at: new Date(now()).toISOString(), ok: !!r.ok, error_class: r.error_class || null, message: r.message || r.error || '' }; x.presented = r.presented || null; });
    audit({ by: who.user, role: who.role, ip: who.ip, action: 'storage.platform.test', target: p.id, detail: { ok: !!r.ok, error_class: r.error_class || null } });
    return { result: r, platform: pview(plat.get(p.id)) };
  }
  function pin(id, b, who) {
    const p = plat.get(String(id)); if (!p) throw bad('array not found', 404);
    const fp = s(b.fingerprint, 120).replace(/:/g, '').toLowerCase(), seen = p.presented && String(p.presented.fingerprint256 || '').replace(/:/g, '').toLowerCase();
    if (!fp || fp !== seen) throw bad('pin only the certificate shown by the last test (run Test again)', 409);
    plat.patch(p.id, (x) => { x.tls_fingerprint = fp; x.presented = null; x.pinned_by = who.user; x.pinned_at = new Date(now()).toISOString(); });
    audit({ by: who.user, role: who.role, ip: who.ip, action: 'storage.platform.pin', target: p.id, detail: { fingerprint256: fp } });
    return Object.assign(view(), { platform: pview(plat.get(p.id)) });
  }
  function remove(id, who) {
    const p = plat.get(String(id)); if (!p) throw bad('array not found', 404);
    snap.remove(p.id); plat.remove(p.id);
    audit({ by: who.user, role: who.role, ip: who.ip, action: 'storage.platform.delete', target: p.id, detail: { kind: p.kind, label: p.label } });
    return view();
  }
  async function sync(id, who = SYS) {
    const p = plat.get(String(id)); if (!p) throw bad('array not found', 404);
    if (running.has(p.id)) return running.get(p.id);
    const job = (async () => {
      const at = new Date(now()).toISOString(), out = { at, ok: true };
      try {
        const c = cred(p); let r;
        try { r = await src[p.kind](c, {}); } finally { wipe(c); }
        if (!r.ok) throw Object.assign(new Error(r.error || r.error_class), { cls: r.error_class });
        const { ok, ...data } = r; // eslint-disable-line no-unused-vars
        snap.put(Object.assign({ id: p.id, at }, data));
        Object.assign(out, { pools: r.pools.length, volumes: r.volumes.length, disks: r.disks.total, failed_disks: r.disks.failed.length, ms: r.ms, engine: r.engine || 'node' });
      } catch (e) { out.ok = false; out.error = e.cls ? `${e.cls}: ${e.message}` : e.message; }
      plat.patch(p.id, (x) => { x.last_sync = out; });
      if (who !== SYS || !out.ok) audit({ by: who.user, role: who.role, ip: who.ip, action: 'storage.platform.sync', target: p.id, detail: { ok: out.ok, error: out.error || null } });
      running.delete(p.id);
      return out;
    })();
    running.set(p.id, job);
    return job;
  }
  function tick() {
    const t = now();
    for (const p of plat.all()) { if (!p.enc || running.has(p.id)) continue; const last = p.last_sync ? Date.parse(p.last_sync.at) : 0; if (t - last >= (p.interval_min || 30) * 60000) guardOf(app, 'storage.sync.' + p.id, sync)(p.id); }
  }

  function hostOf(u) { try { return new URL(u).hostname.toLowerCase(); } catch { return ''; } }
  function assetFor(p, d) {
    const serials = new Set([d && d.system && d.system.serial].concat(((d && d.controllers) || []).map((c) => c.serial)).filter(Boolean).map(low));
    const host = hostOf(p.base_url), name = low(d && d.system && d.system.name);
    return assets.all((a) => !CLOSED[a.status] && ((a.serial && serials.has(low(a.serial))) || (host && low(a.mgmt_ip) === host) || (name && low(a.name).split('.')[0] === name.split('.')[0] && a.type === 'storage')))[0] || null;
  }
  function findings(p, d, st, t) {
    const out = [], add = (severity, kind, title, rec, evidence) => out.push({ array: p.label, array_id: p.id, severity, kind, title, recommendation: rec, evidence: evidence || [] });
    if (p.last_sync && !p.last_sync.ok) add('medium', 'cannot-read', `${p.label}: could not be read`, 'Check the address, the read-only account and the certificate (Test).', [p.last_sync.error]);
    if (!d) return out;
    const age = t - Date.parse(d.at);
    if (age > Math.max(3, (p.interval_min || 30) * 3 / 60) * 3600000) add('low', 'stale', `${p.label}: data is ${Math.round(age / 3600000)} h old`, 'The array has not been read recently; check the connection.');
    if (d.system && d.system.health && d.system.health !== 'ok') add(d.system.health === 'fault' ? 'critical' : 'high', 'health', `${p.label}: array health ${d.system.health}`, 'Open the array management console and check the health details / event log.');
    for (const c of d.controllers || []) if (c.health && c.health !== 'ok') add('high', 'controller', `${p.label}: ${c.name} ${c.state || c.health}`, 'A controller / node is not healthy: check it in the array console; I/O may be running on the partner only.');
    for (const x of d.disks.failed || []) add('critical', 'disk', `${p.label}: disk ${x.name || x.serial || ''} ${x.state || 'failed'}`, 'Replace the failed drive (check that a spare took over and the rebuild completed).', [x.model, x.serial ? 'S/N ' + x.serial : ''].filter(Boolean));
    for (const pl of d.pools || []) {
      if (pl.health && pl.health !== 'ok') add('high', 'pool', `${p.label}: pool ${pl.name} ${pl.state || pl.health}`, 'Check the pool / aggregate state in the array console.');
      if (pl.used_pct != null && pl.used_pct >= st.pool_crit_pct) add('critical', 'capacity', `${p.label}: pool ${pl.name} ${pl.used_pct} % full`, 'Free space or add capacity now - thin volumes and snapshots stop when a pool fills.');
      else if (pl.used_pct != null && pl.used_pct >= st.pool_warn_pct) add('medium', 'capacity', `${p.label}: pool ${pl.name} ${pl.used_pct} % full`, 'Plan capacity: delete old snapshots / move volumes, or add drives.');
    }
    const full = (d.volumes || []).filter((v) => v.used_pct != null && v.used_pct >= st.volume_warn_pct);
    if (full.length) add('medium', 'volume', `${p.label}: ${full.length} volume(s) above ${st.volume_warn_pct} %`, 'Grow the volumes or clean them up before applications run out of space.', full.slice(0, 6).map((v) => `${v.name} ${v.used_pct} %`));
    const recent = (d.events || []).filter((e) => e.at && t - Date.parse(e.at) < 86400000 && /error|critical|alert|emergency/.test(e.severity));
    if (recent.length) add('medium', 'events', `${p.label}: ${recent.length} error event(s) in 24 h`, 'Review the events on the array.', recent.slice(0, 4).map((e) => `${e.severity}: ${e.message}`));
    return out;
  }
  function view() {
    const st = settings(), t = now(), arrays = [], all = [];
    for (const p of plat.all().sort((x, y) => (x.label < y.label ? -1 : 1))) {
      const d = snap.get(p.id), a = assetFor(p, d), f = findings(p, d, st, t);
      if (d && !a) f.push({ array: p.label, array_id: p.id, severity: 'low', kind: 'inventory', title: `${p.label}: not in IT Asset Management`, recommendation: 'Approve it from Asset Discovery (storage method) or add it as a storage asset, so ownership, warranty and end of life are tracked.', evidence: [d.system && d.system.serial ? 'S/N ' + d.system.serial : ''].filter(Boolean) });
      all.push(...f);
      const cap = (d && d.pools || []).reduce((m, x) => { m.size += x.size_bytes || 0; m.used += x.used_bytes || 0; m.free += x.free_bytes || 0; return m; }, { size: 0, used: 0, free: 0 });
      arrays.push({ platform: pview(p), at: d ? d.at : null, system: d ? d.system : null, controllers: d ? d.controllers : [], pools: d ? d.pools : [],
        volumes_total: d ? d.volumes.length : 0, volumes_fullest: d ? d.volumes.filter((v) => v.used_pct != null).sort((x, y) => y.used_pct - x.used_pct).slice(0, 15) : [],
        disks: d ? { total: d.disks.total, spares: d.disks.spares, failed: d.disks.failed.length } : null, events: d ? (d.events || []).slice(0, 10) : [],
        capacity: { size_bytes: cap.size, used_bytes: cap.used, free_bytes: cap.free, used_pct: cap.size ? Math.round(cap.used / cap.size * 1000) / 10 : null },
        asset: a ? { id: a.id, name: a.name, asset_tag: a.asset_tag || null } : null, worst: f.sort((x, y) => SEV[y.severity] - SEV[x.severity])[0] ? f[0].severity : null });
    }
    all.sort((x, y) => SEV[y.severity] - SEV[x.severity]);
    const tot = arrays.reduce((m, x) => { m.size += x.capacity.size_bytes; m.used += x.capacity.used_bytes; return m; }, { size: 0, used: 0 });
    return { settings: st, kinds: KINDS, platforms: plat.all().map(pview), arrays, findings: all,
      summary: { arrays: arrays.length, read: arrays.filter((x) => x.at).length, size_bytes: tot.size, used_bytes: tot.used, used_pct: tot.size ? Math.round(tot.used / tot.size * 1000) / 10 : null,
        failed_disks: arrays.reduce((n, x) => n + ((x.disks && x.disks.failed) || 0), 0), critical: all.filter((x) => x.severity === 'critical').length, high: all.filter((x) => x.severity === 'high').length,
        storage_assets: assets.all((a) => !CLOSED[a.status] && a.type === 'storage').length, not_in_inventory: all.filter((x) => x.kind === 'inventory').length } };
  }
  function detail(id) {
    const p = plat.get(String(id)); if (!p) throw bad('array not found', 404);
    const d = snap.get(p.id) || null;
    return { platform: pview(p), data: d, findings: findings(p, d, settings(), now()), asset: (() => { const a = assetFor(p, d); return a ? { id: a.id, name: a.name } : null; })() };
  }
  return { view, detail, save, test, pin, remove, sync, tick, putSettings, KINDS };
}

function registerStorage(srv, app) {
  const S = createStorage(app);
  srv.route('GET', '/storage', (ctx) => { ctx.need('operator'); return S.view(); });
  srv.route('GET', '/storage/platforms/:id', (ctx) => { ctx.need('operator'); return S.detail(ctx.params.id); });
  srv.route('POST', '/storage/platforms', (ctx) => { ctx.need('admin'); return S.save(ctx.body || {}, ctx.who); });
  srv.route('POST', '/storage/platforms/:id/test', async (ctx) => { ctx.need('admin'); return S.test(ctx.params.id, ctx.who); });
  srv.route('POST', '/storage/platforms/:id/pin', (ctx) => { ctx.need('admin'); return S.pin(ctx.params.id, ctx.body || {}, ctx.who); });
  srv.route('POST', '/storage/platforms/:id/sync', async (ctx) => { ctx.need('admin'); return { sync: await S.sync(ctx.params.id, ctx.who) }; });
  srv.route('POST', '/storage/platforms/:id/delete', (ctx) => { ctx.need('admin'); return S.remove(ctx.params.id, ctx.who); });
  srv.route('PUT', '/storage/settings', (ctx) => { ctx.need('admin'); return S.putSettings(ctx.body || {}, ctx.who); });
  const t1 = setTimeout(guardOf(app, 'storage.tick', S.tick), 100000), t2 = setInterval(guardOf(app, 'storage.tick', S.tick), 60000);
  if (t1.unref) t1.unref(); if (t2.unref) t2.unref();
  (app.addons = app.addons || {}).storage = S;   // reachable from Sync all now (engine/reconcile.js)
  return S;
}

module.exports = { createStorage, registerStorage, KINDS };
