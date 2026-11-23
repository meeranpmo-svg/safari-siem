// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const fs = require('node:fs');
const { guardOf } = require('./errors');
const { body } = require('./check');
/*
 * Servers by platform (Servers & Virtualization -> VMware / Windows / Exchange / Solaris / Oracle Linux, {P} = /api/itam).
 * Every server and VM in the asset register, with what the platform already holds about each one - nothing is guessed:
 *   asset record (OS, vendor, model, serial, warranty, owner, site), the Asset Discovery device (OS it saw, SSH login it
 *   proved), vCenter / Prism facts (IP, host, VM name, power), Backup Status, End of Life, Endpoint Central patches, and for
 *   Solaris / Linux the operating system read over SSH (inv-helper.py op ssh_health: file systems, inodes, memory, swap, load,
 *   failed services / SMF maintenance, NTP, last OS update, uptime).
 * Which platform a server is, its findings and the fix for each are decided in Python (pyengine/server_rules.py).
 *
 * SSH: the same trust rule as Asset Discovery and Database Servers - the host key must be one an administrator trusted
 * (disc_trust), checked BEFORE the password is sent; the login is the one Asset Discovery proved on that server or one an
 * administrator chose here (read-only account). A fresh Database Servers reading of the same IP is used instead of a second
 * login. Every config.servers.interval_min (default 15).
 *
 * Routes: GET /servers?platform= (operator - names servers, IPs, owners) · GET /servers/:id (operator)
 *         POST /servers/run (operator, audited - reads Unix servers now) · POST /servers/ssh {asset_id, cred_id|null} (admin, audited)
 */
const CLOSED = { retired: 1, disposed: 1, lost: 1 };
const PLATFORMS = ['vmware', 'windows', 'exchange', 'solaris', 'oracle_linux', 'linux', 'nutanix', 'unknown'];
const UNIX = new Set(['solaris', 'oracle_linux', 'linux']);
const ID = /^[A-Za-z0-9_.:-]{1,80}$/;
const s = (v, n = 160) => (v == null ? null : String(v).slice(0, n));
const ts = (v) => { const n = typeof v === 'number' ? v : Date.parse(v || ''); return Number.isFinite(n) ? n : 0; };

function pythonBin(app, opts) {
  const c = opts.python || ((app.config && app.config.discovery) || {}).python_bin;
  return [c, '/opt/sentra-siem/pyenv/bin/python3'].filter(Boolean).find((p) => fs.existsSync(p)) || 'python3';
}

function createServers(app, opts = {}) {
  const store = app.store, now = opts.now || Date.now;
  const assets = store.collection('assets'), devs = store.collection('disc_devices'), trustCol = store.collection('disc_trust');
  const snaps = store.collection('server_os_health'), links = store.collection('server_links'), dbSnaps = store.collection('db_server_health');
  const py = opts.py || require('./pyengine').createPyEngine({ python: pythonBin(app, opts), timeoutMs: 30000, resident: false });
  const dc = (app.config && app.config.discovery) || {};
  const cfg = () => Object.assign({ enabled: true, interval_min: 15 }, (app.config && app.config.servers) || {});
  const D = () => opts.discovery || app.discovery || null;
  const A = () => app.addons || {};
  const runHelper = opts.invRun || require('./discovery/methods/login').realRunner(dc.python_bin || '/opt/sentra-siem/pyenv/bin/python3');
  const lg = app.log || { info() {}, warn() {} };
  const bad = (m, status = 400) => Object.assign(new Error(m), { status });
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: (who && who.user) || 'system:itam-servers', role: (who && who.role) || 'system', ip: (who && who.ip) || '', action, target, detail }); };
  const every = (key, msg, extra) => { try { if (lg.every) lg.every('servers:' + key, 600000, 'warn', msg, extra); else lg.warn(msg, extra); } catch (e) { /* logging never stops the answer */ } };
  let timer = null, running = null;

  function vaultSsh() { try { const V = D() && D().vault; return V ? (V.list() || []).filter((c) => c.kind === 'ssh') : []; } catch (e) { every('vault', 'servers: the credential vault could not be listed', { err: e.message }); return []; } }
  // what each add-on knows, read once per answer; an add-on that is missing or fails is "not connected", never "all fine"
  function sources() {
    const out = { backup: null, lifecycle: null, patch: null, facts: null };
    try { const B = A().backup; if (B) { const v = B.view(); if ((v.platforms || []).length) out.backup = new Map((v.assets || []).map((x) => [x.asset_id, x])); } } catch (e) { every('backup', 'servers: Backup Status could not be read', { err: e.message }); }
    try { const L = A().lifecycle; if (L) out.lifecycle = new Map(((L.view({}) || {}).items || []).filter((i) => String(i.key || '').startsWith('asset:')).map((i) => [String(i.key).slice(6), i])); } catch (e) { every('lifecycle', 'servers: End of Life could not be read', { err: e.message }); }
    try { const M = A().manageengine; if (M) { const c = (M.computers() || {}).computers || []; if (c.length) out.patch = new Map(c.filter((x) => x.asset_id).map((x) => [x.asset_id, x])); } } catch (e) { every('patch', 'servers: Endpoint Central could not be read', { err: e.message }); }
    try { const F = A().inventoryFacts || require('./inventory-facts').createInventoryFacts(app); out.facts = (F.all() || {}).assets || {}; } catch (e) { every('facts', 'servers: inventory facts could not be read', { err: e.message }); }
    return out;
  }
  function sshFor(a, ip, dev) {
    const L = links.get(a.id) || {}, creds = vaultSsh();
    let cred = L.ssh_cred_id ? creds.find((c) => c.id === L.ssh_cred_id) : null, via = cred ? 'chosen here' : '';
    const proven = dev && dev.extra && dev.extra.unix_login && dev.extra.unix_login.credential;
    if (!cred && proven) { cred = creds.find((c) => c.label === proven) || null; via = cred ? 'proven by Asset Discovery' : ''; }
    const port = (cred && cred.target && cred.target.port) || 22, tr = ip ? trustCol.get(`ssh:${ip}:${port}`) : null;
    return { cred, via, port, trust: tr || null };
  }
  // the OS reading: our own, or Database Servers' when it is newer (the same server, one SSH login fewer)
  function reading(id, ip) {
    const mine = snaps.get(id) || null, theirs = ip ? dbSnaps.get(ip) : null;
    if (theirs && theirs.server && (!mine || !mine.server || ts(theirs.at) > ts(mine.at))) return Object.assign({}, theirs, { via: 'Database Servers' });
    return mine;
  }
  function gather() {
    const S = sources(), byAsset = new Map(), EX = require('./exchange-evidence').exchangeHints(app);
    // every Asset Discovery record of the asset: the newest one leads, but an OS or address another source reported (vCenter's
    // guest OS beside an nmap sweep that guessed nothing) still counts - one server is seen by several sources
    const allOf = new Map();
    for (const d of devs.all((x) => x.asset_id)) { const o = byAsset.get(d.asset_id); if (!o || ts(d.last_seen) > ts(o.last_seen)) byAsset.set(d.asset_id, d); (allOf.get(d.asset_id) || allOf.set(d.asset_id, []).get(d.asset_id)).push(d); }
    const osOf = (id) => [...new Set((allOf.get(id) || []).map((d) => String(d.os || d.os_version || '').trim()).filter(Boolean))].join(' / ');
    const ipOf = (id) => { for (const d of allOf.get(id) || []) { const i = d.ip || (d.ips || [])[0]; if (i) return i; } return null; };
    // EVERY address a source reported for the server, with the source - a second NIC, a cluster or a replication address shows,
    // not only the first one found. vCenter / Prism / Hyper-V VM records carry what VMware Tools / NGT / the guest reported.
    const IP4 = /^(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
    const ipsOf = (a, f, dev) => {
      const m = new Map(), put = (ip, src) => { const t = String(ip || '').trim(); if (IP4.test(t) && !/^(127\.|169\.254\.|0\.)/.test(t) && !m.has(t)) m.set(t, src); };
      put(f.ip, 'inventory'); put(a.mgmt_ip, 'asset register'); if (dev) put(dev.ip, dev.method || dev.source || 'discovery');
      for (const d of allOf.get(a.id) || []) { const src = d.method || d.source || 'discovery'; put(d.ip, src); for (const i of d.ips || []) put(i, src); }
      return [...m].slice(0, 32).map(([ip, src]) => ({ ip, src: s(src, 40) }));
    };
    const list = assets.all((a) => !CLOSED[a.status] && (a.type === 'server' || a.type === 'vm')).slice(0, 5000).map((a) => {
      const dev = byAsset.get(a.id) || null, x = (dev && dev.extra) || {}, f = (S.facts && S.facts[a.id]) || {};
      const ip = f.ip || a.mgmt_ip || (dev && dev.ip) || ipOf(a.id) || null, ssh = sshFor(a, ip, dev), r = reading(a.id, ip);
      const bk = S.backup && S.backup.get(a.id), lc = S.lifecycle && S.lifecycle.get(a.id), pt = S.patch && S.patch.get(a.id);
      return {
        id: a.id, name: s(a.name || a.asset_tag || a.id, 120), type: a.type, os: s(a.os, 120), vendor: s(a.vendor, 80), model: s(a.model, 120), serial: s(a.serial, 80),
        warranty_end: (a.warranty && a.warranty.end) || null, owner: s(a.owner || a.assigned_to, 80), site: s(a.site || a.location, 80), ip, ips: ipsOf(a, f, dev),
        tags: (a.tags || []).slice(0, 20).map((t) => s(t, 40)), software: (a.software || []).slice(0, 60).map((w) => s(w && (w.name || w), 100)), notes: s(a.notes, 300),
        exchange_hint: s(EX.forAsset(a, [ip, dev && dev.ip]), 200) || null,
        device_os: s(osOf(a.id) || (dev && (dev.os || dev.os_version)), 200), unix_os: s((x.unix_login && x.unix_login.os) || (x.unix && x.unix.label), 120), read_os: s(r && r.server && r.server.os, 120),
        hypervisor: x.vcenter && x.vcenter.kind === 'vm' ? 'vcenter' : x.nutanix && x.nutanix.kind === 'vm' ? 'nutanix' : (f.platform && /vcenter|vmware/i.test(f.platform) ? 'vcenter' : f.platform && /nutanix|prism/i.test(f.platform) ? 'nutanix' : null),
        host_name: f.host_name || null, vm_name: f.vm_name || null, power: f.power || null, power_at: f.power_at || null, last_seen: dev ? dev.last_seen || null : null,
        backup: bk ? { status: bk.status, last_success: bk.last_success, age_hours: bk.age_hours, last_attempt: bk.last_attempt } : null,
        lifecycle: lc ? { status: lc.status, eol: lc.eol || null, days: lc.days == null ? null : lc.days, product: s(lc.product, 80) } : null,
        patch: pt ? { missing: pt.missing, critical: pt.critical, health: s(pt.health, 40) } : null,
        os_read: r ? { at: r.at, error: s(r.error, 300), error_class: r.error_class || null, skipped: r.skipped || null, server: r.server || null, via: r.via || null } : null,
        ssh: { credential: ssh.cred ? ssh.cred.label : null, via: ssh.via || null, port: ssh.port, host_key: ssh.trust ? ssh.trust.state : 'not seen' },
      };
    });
    return { list, src: { backup: !!S.backup, lifecycle: !!S.lifecycle, patch: !!S.patch, facts: !!S.facts } };
  }
  async function assess(platform) {
    const g = gather();
    const r = await py.call('servers.assess', { servers: g.list, platform: platform || '', settings: cfg(), sources: g.src, now: now() });
    if (!r || r.ok === false || !Array.isArray(r.servers)) {
      every('py', 'servers: the server rules (Python) did not answer', { cls: r && r.error_class, err: String((r && r.error) || '').slice(0, 200) });
      throw bad('The server rules run in Python and Python did not answer (' + ((r && r.error_class) || 'error') + ') - run the update so pyengine is installed', 409);
    }
    const st = (snaps.get('last') || {}).value || null;
    return Object.assign(r, { generated_at: new Date(now()).toISOString(), sources: g.src, last_pass: st, ssh_logins: vaultSsh().map((c) => ({ id: c.id, label: c.label })) });
  }
  async function view(platform) {
    if (platform && PLATFORMS.indexOf(platform) < 0) throw bad('platform must be one of ' + PLATFORMS.join(', '));
    return assess(platform);
  }
  async function one(id) {
    const all = await assess('');
    const x = all.servers.find((v) => v.id === id); if (!x) throw bad('server not found in the asset register', 404);
    return { server: x, findings: all.findings.filter((f) => f.asset_id === id), settings: all.settings, ssh_logins: all.ssh_logins };
  }

  async function readOne(x) {
    const at = new Date(now()).toISOString(), a = assets.get(x.id), dev = devs.all((d) => d.asset_id === x.id)[0] || null, S = sshFor(a, x.ip, dev);
    const theirs = x.ip ? dbSnaps.get(x.ip) : null;
    if (theirs && theirs.server && now() - ts(theirs.at) < Math.max(5, Number(cfg().interval_min) || 15) * 60000) return 'shared';
    if (!x.ip || !S.cred || !S.trust || S.trust.state !== 'trusted') { snaps.put({ id: x.id, at, error: null, server: (snaps.get(x.id) || {}).server || null, skipped: !x.ip ? 'no-ip' : !S.cred ? 'no-login' : 'host-key' }); return 'skipped'; }
    const c = D().vault.open(S.cred.id);
    let r;
    try { r = await runHelper({ op: 'ssh_health', host: x.ip, port: S.port, username: c.secret.username, password: c.secret.password, private_key: c.secret.private_key, fp: S.trust.fp }); }
    finally { c.release(); }
    if (!r || !r.ok) {
      if (r && r.error_class === 'hostkey_changed' && D().trust) D().trust.see('ssh', x.ip, S.port, r.fp, {});   // shown to an administrator to decide; never auto-accepted
      snaps.put({ id: x.id, at, error: s((r && r.error) || 'no answer', 300), error_class: (r && r.error_class) || 'error', server: null });
      return 'failed';
    }
    snaps.put({ id: x.id, at, server: r.server, error: null });
    return 'read';
  }
  async function pass(who) {
    if (running) return running;
    running = (async () => {
      const res = { at: new Date(now()).toISOString(), unix: 0, read: 0, shared: 0, skipped: 0, failed: 0 };
      if (!cfg().enabled) return Object.assign(res, { note: 'switched off (config servers.enabled)' });
      const all = await assess('');
      for (const x of all.servers.filter((v) => v.platforms.some((p) => UNIX.has(p)))) {
        res.unix++;
        try { res[await readOne(x)]++; }
        catch (e) { res.failed++; snaps.put({ id: x.id, at: res.at, error: s(e.message, 300), error_class: 'error', server: null }); }
      }
      snaps.put({ id: 'last', value: res });
      if (res.failed) every('pass', 'servers: some Unix servers could not be read', res);
      if (who) audit(who, 'servers.read', 'unix', res);
      return res;
    })().finally(() => { running = null; });
    return running;
  }
  function setSsh(b, who) {
    const v = body(b).str('asset_id', { required: true, id: true }).str('cred_id', { max: 80, id: true }).done();
    const a = assets.get(v.asset_id); if (!a || CLOSED[a.status] || (a.type !== 'server' && a.type !== 'vm')) throw bad('server not found in the asset register', 404);
    const id = v.cred_id || null;
    if (id && !vaultSsh().some((c) => c.id === id)) throw bad('cred_id: choose a saved SSH login (Asset Discovery → Credentials, kind ssh)');
    const cur = links.get(a.id) || { id: a.id };
    links.put(Object.assign(cur, { ssh_cred_id: id, by: (who && who.user) || '', at: new Date(now()).toISOString() }));
    audit(who, 'servers.ssh', a.id, { cred_id: id, name: a.name || a.id });
    return { asset_id: a.id, cred_id: id };
  }
  function start() { if (timer) return; timer = setInterval(guardOf(app, 'servers.pass', () => pass()), Math.max(5, Number(cfg().interval_min) || 15) * 60000); if (timer.unref) timer.unref(); }
  function stop() { if (timer) clearInterval(timer); timer = null; }
  return { view, one, pass, setSsh, start, stop, gather, PLATFORMS };
}

function registerServerRoutes(srv, app, S) {
  if (!S || typeof S.view !== 'function') S = createServers(app, S || {});
  srv.route('GET', '/servers', async (ctx) => {
    ctx.need('operator');
    const p = String((ctx.query || {}).platform || '').trim();
    if (p && S.PLATFORMS.indexOf(p) < 0) throw Object.assign(new Error('platform must be one of ' + S.PLATFORMS.join(', ')), { status: 400 });
    return S.view(p);
  });
  srv.route('GET', '/servers/:id', async (ctx) => {
    ctx.need('operator');
    const id = String(ctx.params.id || ''); if (!ID.test(id)) throw Object.assign(new Error('id is not a valid asset id'), { status: 400 });
    return S.one(id);
  });
  srv.route('POST', '/servers/run', async (ctx) => { ctx.need('operator'); return S.pass(ctx.who); });
  srv.route('POST', '/servers/ssh', (ctx) => { ctx.need('admin'); return S.setSsh(ctx.body || {}, ctx.who); });
  (app.addons = app.addons || {}).servers = S;
  return S;
}

module.exports = { createServers, registerServerRoutes };
