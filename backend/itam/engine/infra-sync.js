// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const fs = require('node:fs');
const { guardOf } = require('./errors');
const { body } = require('./check');
// IT Asset Management <-> Infrastructure Automation (sentra-infra, 127.0.0.1:9160 /api/infra): the two inventories stay one.
//   to sentra-infra   network devices (Cisco IOS / NX-OS, FortiGate, Aruba) and Linux servers of the asset register with an IP,
//                  and the PostgreSQL / MySQL instances the service map confirmed on them, become sentra-infra targets
//                  (system health, config backup, DB health) on the configured probe. A target already there (same
//                  address and kind) is not added twice; when its name, site or owner changes here, those three fields
//                  follow. A target removed in sentra-infra on purpose is not sent again.
//   to ITAM        every sentra-infra target is a sighting in Asset Discovery (method "infra"): linked to the asset with the
//                  same IP, or added to the register straight away (a person registered it there) unless an administrator
//                  turned auto_add off.
// Credentials are NEVER copied between services: sentra-infra targets are created without a credential reference (the
// probe's own SSH key, or an administrator enters the login in Infrastructure Automation -> Settings, write-only).
//   GET  /infra-sync            {settings, last, pending[], skipped[], sent[]}   operator
//   POST /infra-sync/run        sync now                                         operator
//   PUT  /infra-sync/settings   {auto, pull, auto_add, probe_id, include{network, linux, db}}   admin
// Link: config.infra {base_url, prefix, secret_file} (install/add-infra-sync.sh copies sentra-infra's proxy secret to
// /etc/sentra-itam/infra-proxy-secret, 640 root:sentra-itam). Runs every 10 minutes through the job register.
const CLOSED = { retired: 1, disposed: 1 };
const SYS = { user: 'system:itam-infra-sync', role: 'admin', ip: '' };
const low = (v) => String(v == null ? '' : v).toLowerCase();
const bad = (msg, status = 400) => Object.assign(new Error(msg), { status });
const LINUX = /linux|ubuntu|debian|red ?hat|rhel|centos|rocky|alma|oracle linux|suse|sles|fedora|amazon linux/i;

// which sentra-infra profile fits a network asset (vendor, model, OS, the discovery link); null = no read-only profile exists
function deviceProfile(a) {
  const t = low([a.vendor, a.model, a.os, a.discovery && a.discovery.vendor, a.discovery && a.discovery.os].filter(Boolean).join(' '));
  if (/forti/.test(t)) return 'fortigate';
  if (/aruba|arubaos/.test(t)) return 'aruba';
  if (/nx-?os|nexus|\bn\d{1,2}k\b/.test(t)) return 'cisco-nxos';
  if (/cisco|catalyst|ios/.test(t) && !/\basa\d*\b|firepower|ftd/.test(t)) return 'cisco-ios';   // ASA / Firepower: no read-only profile there
  return null;
}

function createInfraSync(app, opts = {}) {
  const { store } = app;
  const col = store.collection('infra_sync'), conf = store.collection('infra_sync_settings'), assets = store.collection('assets'), devs = store.collection('disc_devices');
  const ic = (app.config && app.config.infra) || {};
  const base = String(ic.base_url || 'http://127.0.0.1:9160').replace(/\/+$/, ''), prefix = ic.prefix || '/api/infra';
  const secretFile = ic.secret_file || '/etc/sentra-itam/infra-proxy-secret';
  const request = opts.request || require('./discovery/httpc').request;
  const read = opts.readFile || ((p) => fs.readFileSync(p, 'utf8'));
  const audit = (e) => { if (app.audit) app.audit(e); };
  const now = opts.now || Date.now;
  let last = null, running = null;

  function settings() {
    const v = Object.assign({ auto: true, pull: true, auto_add: true, probe_id: '', include: { network: true, linux: true, db: true } }, (conf.get('settings') || {}).values || {});
    v.include = Object.assign({ network: true, linux: true, db: true }, v.include || {});
    return v;
  }
  function secret() {
    let v; try { v = String(read(secretFile)).trim(); } catch (e) { throw bad(`Infrastructure Automation link not set up: ${secretFile} not readable (${e.code || 'error'}) - run install/add-infra-sync.sh`, 503); }
    if (v.startsWith('{')) { try { v = String(JSON.parse(v).proxy_secret || ''); } catch { v = ''; } }
    if (v.length < 16) throw bad('Infrastructure Automation proxy secret missing', 503);
    return v;
  }
  async function call(method, path, who, b) {
    const headers = { 'X-Sentra-Proxy-Secret': secret(), 'X-Auth-User': String(who.user).slice(0, 200), 'X-Auth-Role': 'operator', Accept: 'application/json' };
    if (b) headers['Content-Type'] = 'application/json';
    let r; try { r = await request(base + prefix + path, { method, headers, body: b ? JSON.stringify(b) : null, timeoutMs: 20000 }); } catch (e) { throw bad(`Infrastructure Automation not reachable (${e.code || e.message || 'error'}) - is sentra-infra running?`, 502); }
    if (r.status === 401 || r.status === 403) throw bad('Infrastructure Automation refused the platform credentials (check the proxy secret file)', 502);
    if (r.status === 200 && (!r.json || typeof r.json !== 'object')) throw bad('Infrastructure Automation did not answer with data', 502);
    return r;
  }
  const errOf = (r) => (r.json && (r.json.error || (r.json.errors || []).join('; '))) || `HTTP ${r.status}`;
  function ipOf(a) { if (a.mgmt_ip) return a.mgmt_ip; const d = devs.all((x) => x.asset_id === a.id && x.ip)[0]; return d ? d.ip : ''; }

  /* what IT Asset Management offers: {key, kind, profile, name, address, site, owner, asset_id} - and why others are not */
  function offer() {
    const inc = settings().include, out = [], skipped = [];
    let svc = null; try { svc = app.addons && app.addons.serviceMap ? app.addons.serviceMap.view('operator').servers : null; } catch (e) { svc = null; }   // the service map is optional: no DB targets without it
    const osByIp = new Map((svc || []).filter((r) => r.os).map((r) => [r.ip, r.os]));
    for (const a of assets.all((x) => !CLOSED[x.status])) {
      const ip = ipOf(a), base0 = { asset_id: a.id, name: String(a.name || ip).slice(0, 120), site: String(a.site || '').slice(0, 120), owner: String(a.owner || '').slice(0, 120) };
      if (a.type === 'network' && inc.network) {
        const p = deviceProfile(a);
        if (!ip) skipped.push({ asset_id: a.id, name: a.name, why: 'no IP address - add the management IP' });
        else if (!p) skipped.push({ asset_id: a.id, name: a.name, why: `no read-only profile for ${a.vendor || 'this vendor'} in Infrastructure Automation (Cisco IOS / NX-OS, FortiGate, Aruba)` });
        else out.push(Object.assign({ key: `device:${ip}`, kind: 'device', profile: p, address: ip }, base0));
      } else if ((a.type === 'server' || a.type === 'vm') && inc.linux) {
        const os = a.os || (a.discovery && a.discovery.os) || osByIp.get(ip) || '';
        if (!LINUX.test(os)) continue;                       // Windows / Solaris / unknown: no agentless Linux profile
        if (!ip) skipped.push({ asset_id: a.id, name: a.name, why: 'Linux server without an IP address' });
        else out.push(Object.assign({ key: `host:${ip}`, kind: 'host', profile: 'linux', address: ip }, base0));
      }
    }
    if (inc.db && svc) for (const r of svc) for (const s of r.services || []) {
      if (s.confidence !== 'confirmed' || (s.id !== 'postgres' && s.id !== 'mysql')) continue;
      out.push({ key: `db:${r.ip}:${s.id}`, kind: 'db', profile: s.id, address: r.ip, name: `${r.host || r.ip} ${s.id === 'postgres' ? 'PostgreSQL' : 'MySQL'}`.slice(0, 120), site: '', owner: (r.asset && r.asset.owner) || '', asset_id: r.asset ? r.asset.id : null });
    }
    return { out, skipped };
  }

  async function probeId(who) {
    const s = settings(); if (s.probe_id) return s.probe_id;
    const r = await call('GET', '/probes', who); const list = (r.json && r.json.probes) || [];
    if (list.length === 1) return list[0].id;
    throw bad(list.length ? `${list.length} probes are configured - choose which one runs the synced targets (Settings: probe_id)` : 'no Infrastructure Automation probe is configured yet - install a probe first', 409);
  }

  async function run(who = SYS) {
    if (running) return running;
    running = (async () => {
      const at = new Date(now()).toISOString(), out = { at, by: who.user, ok: true, added: [], updated: [], already: 0, skipped_removed: 0, failed: [] };
      try {
        const r = await call('GET', '/targets', who);
        if (r.status !== 200) throw bad(`Infrastructure Automation: ${errOf(r)}`, 502);
        const list = (r.json && r.json.targets) || [];
        const byKey = new Map(list.map((t) => [t.kind === 'db' ? `db:${t.address}:${t.profile}` : `${t.kind}:${t.address}`, t]));
        const { out: offered } = offer();
        let probe = null;
        for (const o of offered) {
          const rec = col.get(o.key), t = byKey.get(o.key);
          if (t) {
            out.already++;
            if (!rec) col.put({ id: o.key, target_id: t.id, asset_id: o.asset_id, state: 'present', at });
            // name / site / owner edited in IT Asset Management -> the same three fields in sentra-infra (nothing else)
            const upd = {}; for (const k of ['name', 'site', 'owner']) if (o[k] && t[k] !== o[k]) upd[k] = o[k];
            if (Object.keys(upd).length) {
              const p = await call('POST', '/targets/' + encodeURIComponent(t.id), who, upd);
              if (p.status >= 300) out.failed.push({ key: o.key, name: o.name, error: 'update: ' + errOf(p) }); else out.updated.push({ key: o.key, target_id: t.id, changed: Object.keys(upd) });
            }
            continue;
          }
          if (rec && rec.state === 'sent') { out.skipped_removed++; continue; }   // removed in Infrastructure Automation on purpose
          if (!probe) probe = await probeId(who);
          const b = { kind: o.kind, profile: o.profile, name: o.name, address: o.address, site: o.site, owner: o.owner, probe_id: probe, enabled: true };
          const p = await call('POST', '/targets', who, b);
          if (p.status >= 300) { out.failed.push({ key: o.key, name: o.name, error: errOf(p) }); continue; }
          const tid = p.json && p.json.target && p.json.target.id;
          col.put({ id: o.key, target_id: tid || null, asset_id: o.asset_id, state: 'sent', at });
          out.added.push({ key: o.key, target_id: tid || null, name: o.name, kind: o.kind, profile: o.profile, address: o.address });
          byKey.set(o.key, Object.assign({ id: tid }, b));
        }
        if (settings().pull) out.pulled = pull(list, at);
      } catch (e) { out.ok = false; out.error = e.message; }
      if (out.added.length || out.updated.length || out.failed.length || who !== SYS) audit({ by: who.user, role: who.role, ip: who.ip, action: 'infra_sync.run', target: 'infra', detail: { added: out.added.length, updated: out.updated.length, failed: out.failed.length, pulled: out.pulled || null, error: out.error || null } });
      last = out; running = null;
      return out;
    })();
    return running;
  }

  /* sentra-infra targets -> Asset Discovery -> assets */
  function pull(list, at) {
    const D = app.discovery, res = { seen: 0, linked: 0, added: 0, waiting: 0, errors: 0 };
    if (!D || !D.devices) return res;
    const TYPE = { host: 'server', device: 'switch' }, VENDOR = { 'cisco-ios': 'Cisco', 'cisco-nxos': 'Cisco', fortigate: 'Fortinet', aruba: 'HPE Aruba' };
    for (const t of list) {
      if (!t || !t.address || t.kind === 'db' || !/^[0-9a-fA-F.:]+$/.test(t.address)) continue;   // DB instances live on a host already counted; names (not IPs) are left to discovery
      try {
        const d = D.devices.observe({ method: 'infra', hostname: low(t.name || ''), ips: [t.address], vendor: VENDOR[t.profile] || undefined, os: t.profile === 'linux' ? 'Linux' : undefined, uid: 'infra:' + t.id,
          extra: { infra: { target_id: t.id, kind: t.kind, profile: t.profile, status: t.status || null, last_seen: t.last_seen || null } } }, { site: t.site || undefined, at });
        if (!d) continue;
        res.seen++;
        const want = t.profile === 'fortigate' ? 'firewall' : TYPE[t.kind];
        devs.patch(d.id, (x) => { if (want && (!x.type || x.type === 'unknown')) x.type = want; x.confidence = Math.max(x.confidence || 0, 85); const why = 'Infrastructure Automation target (' + t.profile + ')'; x.reasons = [why].concat((x.reasons || []).filter((r) => r !== why)).slice(0, 12); return x; });
        const cur = devs.get(d.id);
        if (cur.asset_id) continue;
        const same = assets.all((a) => !CLOSED[a.status] && a.mgmt_ip === t.address);
        if (same.length === 1) { D.merge(cur.id, same[0].id, SYS); res.linked++; continue; }
        if (settings().auto_add && !same.length && cur.status === 'new') { D.approve(cur.id, SYS); res.added++; continue; }
        res.waiting++;
      } catch (e) { res.errors++; }
    }
    return res;
  }

  function view() {
    const { out, skipped } = offer(), sent = col.all(), seen = new Set(sent.map((s) => s.id));
    return { settings: settings(), link: { base_url: base + prefix, secret_file: secretFile }, last, sent, pending: out.filter((o) => !seen.has(o.key)), skipped };
  }
  function putSettings(b, who) {
    const cur = settings(), v = Object.assign({}, cur);
    for (const k of ['auto', 'pull', 'auto_add']) if (k in b) v[k] = b[k];
    if ('probe_id' in b) v.probe_id = b.probe_id;
    if (b.include) v.include = Object.assign({}, cur.include, b.include);
    conf.put({ id: 'settings', values: v, updated_by: who.user, updated_at: new Date(now()).toISOString() });
    audit({ by: who.user, role: who.role, ip: who.ip, action: 'infra_sync.settings', target: 'settings', detail: v });
    return view();
  }
  function tick() { return settings().auto ? run() : undefined; }
  // read-only access for Infrastructure Automation intelligence (engine/infra-intel.js): GET only, as the asking person with role operator
  const get = async (path, who) => { if (!/^\/[A-Za-z0-9/_.?=&%-]{1,300}$/.test(String(path)) || String(path).includes('..')) throw bad('bad Infrastructure Automation path', 400); return call('GET', path, who || { user: 'system:infra-intel' }); };
  return { run, view, putSettings, offer, get, tick: guardOf(app, 'infra-sync.tick', tick), deviceProfile };
}

function registerInfraSync(srv, app, opts = {}) {
  const N = createInfraSync(app, opts);
  srv.route('GET', '/infra-sync', (ctx) => { ctx.need('operator'); return N.view(); });
  srv.route('POST', '/infra-sync/run', async (ctx) => { ctx.need('operator'); return N.run(ctx.who); });
  srv.route('PUT', '/infra-sync/settings', (ctx) => {
    ctx.need('admin');
    const b = body(ctx.body).bool('auto').bool('pull').bool('auto_add').str('probe_id', { max: 64, re: /^[A-Za-z0-9_.-]{0,64}$/, msg: 'probe_id: letters, digits, . _ -' }).done();
    const inc = ctx.body && ctx.body.include;
    if (inc !== undefined) { if (!inc || typeof inc !== 'object' || Array.isArray(inc)) throw bad('include must be an object {network, linux, db}'); b.include = body(inc).bool('network').bool('linux').bool('db').done(); }
    return N.putSettings(b, ctx.who);
  });
  if (!opts.noTimer) { const t1 = setTimeout(guardOf(app, 'infra-sync.tick', N.tick), 90000), t2 = setInterval(guardOf(app, 'infra-sync.tick', N.tick), 10 * 60000); if (t1.unref) t1.unref(); if (t2.unref) t2.unref(); }
  (app.addons = app.addons || {}).infraSync = N;   // reachable from Sync all now (engine/reconcile.js)
  return N;
}

module.exports = { createInfraSync, registerInfraSync, deviceProfile };
