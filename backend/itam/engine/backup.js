// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const { guardOf } = require('./errors');
// Backup coverage: NetBackup, Veeam and Cohesity read-only (engine/backup-sources.js), matched to the IT Asset
// Management servers and VMs. For every server / VM: the newest good backup across all platforms, the newest attempt
// and its result, and a verdict - protected (good backup within target_hours, default 26), stale, failed, or none.
// Backups of things that are not in the inventory are listed too, and assets can be exempted with a reason.
//   GET  /backup                       {settings, platforms[], summary, assets[], unmatched[], failed_jobs[]}     operator
//   POST /backup/platforms             {id?, kind: netbackup|veeam|cohesity, label, base_url, api_key | username + password,
//                                       api_version?, domain?, interval_min?}                                     admin
//   POST /backup/platforms/:id/test | /pin {fingerprint} | /sync | /delete                                         admin
//   PUT  /backup/settings              {target_hours, window_days}                                               admin
//   POST /backup/exempt                {asset_id, reason} | {asset_id, remove: true}                              admin
// Credentials are sealed (AES-256-GCM, discovery vault key) and never returned, logged or audited. Changing the address
// or CA file needs the secret again. Self-contained; added with one registration line (install/add-backup.sh).
const crypto = require('node:crypto');
const { createSealer } = require('./discovery/vault');

const KINDS = { netbackup: 'Veritas NetBackup', veeam: 'Veeam Backup & Replication', cohesity: 'Cohesity' };
const SYS = { user: 'system:backup-sync', role: 'system', ip: '' };
const CLOSED = { retired: 1, disposed: 1, lost: 1 };
const HOUR = 3600000;
const s = (v, max) => String(v == null ? '' : v).replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, max || 200);
const bad = (msg, status = 400) => Object.assign(new Error(msg), { status });
const low = (v) => String(v || '').trim().toLowerCase();
const short = (v) => low(v).split('.')[0];

function createBackup(app, opts = {}) {
  const { store } = app;
  const plat = store.collection('backup_platforms'), objs = store.collection('backup_objects'), conf = store.collection('backup_settings'), exempt = store.collection('backup_exempt'), assets = store.collection('assets');
  const dc = (app.config && app.config.discovery) || {};
  const sealer = opts.sealer || createSealer({ keyFile: dc.vault_key_file, createKey: dc.vault_create_key !== false, purpose: 'sentra-itam-backup-platforms' });
  // read by the Python module (pyengine/backup_sources.py, docs/PYTHON-MIGRATION.md); config backup.engine = "node" keeps
  // the Node.js reader; without Python the bridge falls back to it by itself
  const src = opts.sources || (((app.config && app.config.backup) || {}).engine === 'node' ? require('./backup-sources') : require('./backup-sources-py').createBackupSourcesPy({ python: ((app.config && app.config.discovery) || {}).python_bin || '/opt/sentra-siem/pyenv/bin/python3' }));
  const audit = (e) => { if (app.audit) app.audit(e); };
  const now = opts.now || Date.now;
  const running = new Map();

  function settings() { return Object.assign({ target_hours: 26, window_days: 7 }, (conf.get('settings') || {}).values || {}); }
  function putSettings(b, who) {
    const v = settings();
    if ('target_hours' in b) { const n = Number(b.target_hours); if (!Number.isFinite(n) || n < 1 || n > 24 * 31) throw bad('target_hours must be 1 to 744'); v.target_hours = Math.round(n); }
    if ('window_days' in b) { const n = Number(b.window_days); if (!Number.isFinite(n) || n < 1 || n > 31) throw bad('window_days must be 1 to 31'); v.window_days = Math.round(n); }
    conf.put({ id: 'settings', values: v, updated_by: who.user, updated_at: new Date(now()).toISOString() });
    audit({ by: who.user, role: who.role, ip: who.ip, action: 'backup.settings', target: 'settings', detail: v });
    return view();
  }
  function pview(p) { const { enc, presented, ...pub } = p; return Object.assign(pub, { credentials_set: !!enc, presented: presented || null }); } // eslint-disable-line no-unused-vars
  function cred(p) {
    if (!p.enc) throw bad('credentials not set', 409);
    return { target: { base_url: p.base_url, ca_file: p.ca_file || undefined, tls_fingerprint: p.tls_fingerprint || undefined, api_version: p.api_version || undefined, domain: p.domain || undefined }, secret: JSON.parse(sealer.unseal(p.id, p.enc)) };
  }
  const wipe = (c) => { if (c && c.secret) for (const k of Object.keys(c.secret)) c.secret[k] = null; };

  function save(b, who) {
    const cur = b.id ? plat.get(String(b.id)) : null;
    if (b.id && !cur) throw bad('platform not found', 404);
    // the type can be corrected on an existing system (a NetBackup primary saved as Cohesity): a new type needs its own secret
    const kind = cur && !b.kind ? cur.kind : s(b.kind, 20), retyped = !!(cur && kind !== cur.kind);
    if (!KINDS[kind]) throw bad('kind must be netbackup, veeam or cohesity');
    const o = Object.assign({}, cur || { id: 'bp_' + crypto.randomBytes(5).toString('hex'), kind, created_by: who.user, created_at: new Date(now()).toISOString(), interval_min: 60 });
    if ('label' in b || !cur) o.label = s(b.label, 80) || s(b.base_url, 80) || KINDS[kind];
    let moved = false;
    if (retyped) { o.kind = kind; o.tls_fingerprint = ''; o.presented = null; o.last_sync = null; o.api_version = ''; moved = true; }
    if ('base_url' in b) {
      // the NetBackup web console address (…/webui) is what people copy; its API is on the same host, port 1556, at /netbackup
      const u = (kind === 'netbackup' ? s(b.base_url, 300).replace(/\/webui\b.*$/i, '') : s(b.base_url, 300)).replace(/\/+$/, '');
      try { src.baseOf(u, 443); } catch (e) { throw bad(e.message); }
      if (cur && u !== cur.base_url) { moved = true; o.tls_fingerprint = ''; o.presented = null; }
      o.base_url = u;
    }
    if (!o.base_url) throw bad('the address is required');
    if ('ca_file' in b) { const f = s(b.ca_file, 250); if (f && !/^\/[A-Za-z0-9._/-]+$/.test(f)) throw bad('ca_file must be an absolute path'); if (cur && f !== (cur.ca_file || '')) moved = true; o.ca_file = f; }
    if ('api_version' in b) { const v = s(b.api_version, 20); if (v && !/^[0-9A-Za-z.-]+$/.test(v)) throw bad('invalid API version'); o.api_version = v; }
    if ('domain' in b) o.domain = s(b.domain, 120);
    if ('interval_min' in b) { const m = Number(b.interval_min); if (!Number.isFinite(m) || m < 15 || m > 1440) throw bad('interval must be 15 to 1440 minutes'); o.interval_min = Math.round(m); }
    const key = b.api_key == null ? '' : String(b.api_key).slice(0, 2000), user = s(b.username, 200), pass = b.password == null ? '' : String(b.password).slice(0, 256);
    let secret = null;
    if (key) secret = { api_key: key };
    else if (user || pass) { if (!user || !pass) throw bad('enter both the user name and the password'); secret = { username: user, password: pass }; }
    if (secret) {
      if (kind === 'netbackup' && !secret.api_key) throw bad('NetBackup uses an API key (NetBackup web UI > your user > API keys)');
      if (kind === 'veeam' && !secret.username) throw bad('Veeam uses a user name and password');
      if (!sealer.available()) throw bad('credential vault unavailable: ' + sealer.unavailableReason(), 503);
      o.enc = sealer.seal(o.id, JSON.stringify(secret)); o.credentials_at = new Date(now()).toISOString(); o.credentials_by = who.user;
    } else if (!cur) throw bad(kind === 'netbackup' ? 'enter the API key' : kind === 'veeam' ? 'enter the user name and password' : 'enter an API key, or a user name and password');
    else if (moved) throw bad(retyped ? 'the type changed to ' + KINDS[kind] + ': enter its ' + (kind === 'netbackup' ? 'API key' : kind === 'veeam' ? 'user name and password' : 'API key, or user name and password') : 'the address or CA file changed: enter the secret again');
    if (retyped) for (const x of objs.all((y) => y.platform_id === o.id)) objs.remove(x.id);   // read by the old type: not this system's data
    o.updated_by = who.user; o.updated_at = new Date(now()).toISOString();
    plat.put(o);
    audit({ by: who.user, role: who.role, ip: who.ip, action: cur ? 'backup.platform.update' : 'backup.platform.create', target: o.id, detail: { kind, kind_before: retyped ? cur.kind : undefined, label: o.label, base_url: o.base_url, credentials_changed: !!secret } });
    return Object.assign(view(), { platform: pview(o) });
  }
  async function test(id, who) {
    const p = plat.get(String(id)); if (!p) throw bad('platform not found', 404);
    const c = cred(p); let r;
    try { r = await src.test(p.kind, c); } finally { wipe(c); }
    plat.patch(p.id, (x) => { x.last_test = { at: new Date(now()).toISOString(), ok: !!r.ok, error_class: r.error_class || null, message: r.message || r.error || '' }; x.presented = r.presented || null; });
    audit({ by: who.user, role: who.role, ip: who.ip, action: 'backup.platform.test', target: p.id, detail: { ok: !!r.ok, error_class: r.error_class || null } });
    return { result: r, platform: pview(plat.get(p.id)) };
  }
  function pin(id, b, who) {
    const p = plat.get(String(id)); if (!p) throw bad('platform not found', 404);
    const fp = s(b.fingerprint, 120).replace(/:/g, '').toLowerCase(), seen = p.presented && String(p.presented.fingerprint256 || '').replace(/:/g, '').toLowerCase();
    if (!fp || fp !== seen) throw bad('pin only the certificate shown by the last test (run Test again)', 409);
    plat.patch(p.id, (x) => { x.tls_fingerprint = fp; x.presented = null; x.pinned_by = who.user; x.pinned_at = new Date(now()).toISOString(); });
    audit({ by: who.user, role: who.role, ip: who.ip, action: 'backup.platform.pin', target: p.id, detail: { fingerprint256: fp } });
    return Object.assign(view(), { platform: pview(plat.get(p.id)) });
  }
  function remove(id, who) {
    const p = plat.get(String(id)); if (!p) throw bad('platform not found', 404);
    for (const o of objs.all((x) => x.platform_id === p.id)) objs.remove(o.id);
    plat.remove(p.id);
    audit({ by: who.user, role: who.role, ip: who.ip, action: 'backup.platform.delete', target: p.id, detail: { kind: p.kind, label: p.label } });
    return view();
  }
  async function sync(id, who = SYS) {
    const p = plat.get(String(id)); if (!p) throw bad('platform not found', 404);
    if (running.has(p.id)) return running.get(p.id);
    const job = (async () => {
      const at = new Date(now()).toISOString(), out = { at, ok: true };
      try {
        const c = cred(p); let r;
        try { r = await src[p.kind](c, { days: settings().window_days, now: now() }); } finally { wipe(c); }
        if (!r.ok) throw Object.assign(new Error(r.error || r.error_class), { cls: r.error_class });
        for (const o of objs.all((x) => x.platform_id === p.id)) objs.remove(o.id);
        for (const o of r.objects) objs.put(Object.assign({ id: `${p.id}:${low(o.name)}`, platform_id: p.id, platform_kind: p.kind, platform_label: p.label }, o));
        const dayAgo = new Date(now() - 24 * HOUR).toISOString();
        const failed = r.jobs.filter((j) => j.status === 'failed' && (j.end || j.start || '') >= dayAgo);
        Object.assign(out, { objects: r.objects.length, jobs: r.jobs.length, failed_24h: failed.length, failed_jobs: failed.slice(0, 200), api_version: r.api_version || null, ms: r.ms });
      } catch (e) { out.ok = false; out.error = e.cls ? `${e.cls}: ${e.message}` : e.message; }
      plat.patch(p.id, (x) => { x.last_sync = out; });
      if (who !== SYS || !out.ok) audit({ by: who.user, role: who.role, ip: who.ip, action: 'backup.platform.sync', target: p.id, detail: { ok: out.ok, objects: out.objects, failed_24h: out.failed_24h, error: out.error || null } });
      running.delete(p.id);
      return out;
    })();
    running.set(p.id, job);
    return job;
  }
  function tick() {
    const t = now();
    for (const p of plat.all()) { if (!p.enc || running.has(p.id)) continue; const last = p.last_sync ? Date.parse(p.last_sync.at) : 0; if (t - last >= (p.interval_min || 60) * 60000) guardOf(app, 'backup.sync.' + p.id, sync)(p.id); }
  }
  function setExempt(b, who) {
    const a = assets.get(String(b.asset_id || '')); if (!a) throw bad('asset not found', 404);
    if (b.remove === true) exempt.remove(a.id);
    else { const reason = s(b.reason, 300); if (reason.length < 3) throw bad('give a reason (for example: stateless web node, rebuilt from template)'); exempt.put({ id: a.id, reason, by: who.user, at: new Date(now()).toISOString() }); }
    audit({ by: who.user, role: who.role, ip: who.ip, action: b.remove ? 'backup.exempt.remove' : 'backup.exempt', target: a.id, detail: { name: a.name, reason: b.reason || null } });
    return view();
  }

  // coverage: inventory servers / VMs against every backup object
  // A VM-level backup (NetBackup's Nutanix AHV / VMware policies) names the VM by its UUID - "0579b919-…_NTX-ASI-CLS-HO-01"
  // is VM uuid + "_" + cluster. The UUID is resolved through what the platform already read: the VM list of Capacity Planning
  // (virt_capacity: Nutanix / vCenter, name + uuid) and Asset Discovery's links (disc_devices uids ntnx:<id> / vc:<uuid>
  // -> asset). A linked asset matches directly; otherwise the VM's name is matched like any other name.
  const UUID_RE = /^([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:[_ ](.{1,120}))?$/i;
  function vmIndex() {
    const vms = new Map(), linked = new Map();
    try { for (const d of store.collection('virt_capacity').all()) for (const v of d.vms || []) for (const u of [v.uuid, v.id]) if (u && UUID_RE.test(String(u))) vms.set(low(u), { name: v.name || '', platform: d.label || '', kind: d.kind || '' }); } catch (e) { /* Capacity Planning not installed */ }
    try { for (const d of store.collection('disc_devices').all((x) => x.asset_id)) for (const u of d.uids || []) { const m = /^(?:ntnx|vc):(.+)$/i.exec(u); if (m && UUID_RE.test(m[1])) linked.set(low(m[1]), d.asset_id); } } catch (e) { /* no discovery */ }
    return { vms, linked };
  }
  function resolveObj(o, VI) {
    const m = UUID_RE.exec(String(o.name || '').trim()); if (!m) return null;
    const u = low(m[1]), vm = VI.vms.get(u);
    return { uuid: u, cluster: m[2] || '', vm_name: (vm && vm.name) || o.display_name || '', vm_platform: vm ? vm.platform : '', asset_id: VI.linked.get(u) || null };
  }
  function view() {
    const st = settings(), t = now(), target = st.target_hours * HOUR;
    const VI = vmIndex(), all = objs.all().map((o) => { const r = resolveObj(o, VI); return r ? Object.assign({}, o, { vm: r }) : o; }), byName = new Map(), byAsset = new Map();
    const addKey = (k, o) => { if (!k) return; if (!byName.has(k)) byName.set(k, []); byName.get(k).push(o); };
    for (const o of all) {
      for (const k of new Set([low(o.name), short(o.name)])) addKey(k, o);
      if (o.display_name) for (const k of new Set([low(o.display_name), short(o.display_name)])) addKey(k, o);
      if (o.vm && o.vm.vm_name) for (const k of new Set([low(o.vm.vm_name), short(o.vm.vm_name)])) addKey(k, o);
      if (o.vm && o.vm.asset_id) { if (!byAsset.has(o.vm.asset_id)) byAsset.set(o.vm.asset_id, []); byAsset.get(o.vm.asset_id).push(o); }
    }
    const used = new Set();
    const rows = assets.all((a) => !CLOSED[a.status] && (a.type === 'server' || a.type === 'vm')).map((a) => {
      const keys = new Set([low(a.name), short(a.name), low(a.hostname), short(a.hostname), low(a.asset_tag), low(a.mgmt_ip)].filter(Boolean));
      const found = new Map(); for (const k of keys) for (const o of byName.get(k) || []) found.set(o.id, o);
      for (const o of byAsset.get(a.id) || []) found.set(o.id, o);
      const list = [...found.values()]; list.forEach((o) => used.add(o.id));
      const good = list.map((o) => o.last_success).filter(Boolean).sort().pop() || null;
      const lastAttempt = list.filter((o) => o.last_attempt).sort((x, y) => String(y.last_attempt).localeCompare(String(x.last_attempt)))[0] || null;
      const ex = exempt.get(a.id);
      let status;
      if (ex) status = 'exempt';
      else if (!list.length) status = 'none';
      else if (good && t - Date.parse(good) <= target) status = 'protected';
      else if (lastAttempt && lastAttempt.last_status === 'failed') status = 'failed';
      else status = 'stale';
      return { asset_id: a.id, name: a.name || a.id, type: a.type, os: a.os || '', site: a.site || '', mgmt_ip: a.mgmt_ip || '', status, last_success: good, age_hours: good ? Math.round((t - Date.parse(good)) / HOUR) : null,
        last_attempt: lastAttempt ? lastAttempt.last_attempt : null, last_result: lastAttempt ? lastAttempt.last_status : null,
        platforms: [...new Set(list.map((o) => KINDS[o.platform_kind] || o.platform_kind))], jobs: [...new Set(list.map((o) => o.job || o.policy).filter(Boolean))].slice(0, 5), exempt: ex ? { reason: ex.reason, by: ex.by, at: ex.at } : null };
    });
    const order = { failed: 0, none: 1, stale: 2, protected: 3, exempt: 4 };
    rows.sort((x, y) => order[x.status] - order[y.status] || String(x.name).localeCompare(String(y.name)));
    const count = (k) => rows.filter((r) => r.status === k).length;
    const platforms = plat.all().map(pview).sort((x, y) => (x.label < y.label ? -1 : 1));
    const failed = [];
    for (const p of platforms) for (const j of (p.last_sync && p.last_sync.failed_jobs) || []) failed.push(Object.assign({ platform: p.label, kind: p.kind }, j));
    failed.sort((x, y) => String(y.end || y.start).localeCompare(String(x.end || x.start)));
    return {
      settings: st, kinds: KINDS, platforms,
      summary: { assets: rows.length, protected: count('protected'), stale: count('stale'), failed: count('failed'), none: count('none'), exempt: count('exempt'),
        coverage_pct: rows.length - count('exempt') ? Math.round(count('protected') * 100 / (rows.length - count('exempt'))) : null, objects: all.length, failed_jobs_24h: failed.length, platforms_failing: platforms.filter((p) => p.last_sync && !p.last_sync.ok).length },
      assets: rows,
      vm_names: { by_uuid: all.filter((o) => o.vm).length, resolved: all.filter((o) => o.vm && o.vm.vm_name).length },
      unmatched: all.filter((o) => !used.has(o.id)).map((o) => ({ name: o.name, vm_name: o.vm ? o.vm.vm_name || null : null, vm_uuid: o.vm ? o.vm.uuid : null, vm_cluster: o.vm ? o.vm.cluster : null, vm_platform: o.vm ? o.vm.vm_platform : null, platform: o.platform_label, kind: o.platform_kind, job: o.job || o.policy || '', last_success: o.last_success, last_status: o.last_status })).sort((x, y) => String(x.vm_name || x.name).localeCompare(String(y.vm_name || y.name))).slice(0, 5000),
      failed_jobs: failed.slice(0, 500),
    };
  }
  return { view, save, test, pin, remove, sync, tick, putSettings, setExempt, KINDS };
}

function registerBackup(srv, app) {
  const B = createBackup(app);
  srv.route('GET', '/backup', (ctx) => { ctx.need('operator'); return B.view(); });
  srv.route('POST', '/backup/platforms', (ctx) => { ctx.need('admin'); return B.save(ctx.body || {}, ctx.who); });
  srv.route('POST', '/backup/platforms/:id/test', async (ctx) => { ctx.need('admin'); return B.test(ctx.params.id, ctx.who); });
  srv.route('POST', '/backup/platforms/:id/pin', (ctx) => { ctx.need('admin'); return B.pin(ctx.params.id, ctx.body || {}, ctx.who); });
  srv.route('POST', '/backup/platforms/:id/sync', async (ctx) => { ctx.need('admin'); return { sync: await B.sync(ctx.params.id, ctx.who) }; });
  srv.route('POST', '/backup/platforms/:id/delete', (ctx) => { ctx.need('admin'); return B.remove(ctx.params.id, ctx.who); });
  srv.route('PUT', '/backup/settings', (ctx) => { ctx.need('admin'); return B.putSettings(ctx.body || {}, ctx.who); });
  srv.route('POST', '/backup/exempt', (ctx) => { ctx.need('admin'); return B.setExempt(ctx.body || {}, ctx.who); });
  const t1 = setTimeout(guardOf(app, 'backup.tick', B.tick), 120000), t2 = setInterval(guardOf(app, 'backup.tick', B.tick), 60000);
  if (t1.unref) t1.unref(); if (t2.unref) t2.unref();
  (app.addons = app.addons || {}).backup = B;   // reachable from Sync all now (engine/reconcile.js)
  return B;
}

module.exports = { createBackup, registerBackup, KINDS };
