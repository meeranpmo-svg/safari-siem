// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const { guardOf } = require('./errors');
// Virtualization platforms for Asset Discovery: any number of VMware vCenter and Nutanix Prism (Central or Element)
// connections (and Proxmox VE with a read-only API token). Each sync reads hosts and VMs (read-only) and feeds them to Asset Discovery as sightings, so they show in
// Discovery > Results like every other source; with "approve automatically" (default on) new hosts and VMs go straight
// into IT Asset Management, which is what the server dashboards read. VMs are linked to their host (runs_on) and, for
// Nutanix, each host's sockets / cores / cluster are filled into the core-based licence audit (unless entered by hand).
//   GET  /virt                     {platforms[], kinds, sites}                                   operator
//   GET  /virt/inventory           hosts + VMs from every source (this page, Discovery scopes, the inventory)   operator
//   POST /virt                     {id?, kind: vcenter|esxi|nutanix, label, base_url, username, password, site,
//                                   ca_file?, interval_min?, auto_approve?}                     admin
//   POST /virt/:id/test            connection test; an untrusted certificate is shown for Trust & pin   admin
//   POST /virt/:id/pin             {fingerprint} pin the certificate seen by the last test       admin
//   POST /virt/:id/sync            sync now                                                       admin
//   POST /virt/:id/delete                                                                         admin
//   POST /virt/hosts/fill-ips      fill missing ESXi / Nutanix host addresses now (also hourly)     operator
// The user name and password are sealed (AES-256-GCM, discovery vault key) and never returned, logged or audited.
// Changing the URL, CA file or pin needs the password again (the saved password is never sent to a new address).
// Self-contained (stored collections), added to an existing install with one registration line (install/add-virt.sh).
const crypto = require('node:crypto');
const { createSealer } = require('./discovery/vault');

const KINDS = { vcenter: 'VMware vCenter', esxi: 'VMware ESXi (standalone host)', nutanix: 'Nutanix Prism', proxmox: 'Proxmox VE (API token)' };
const SYS = { user: 'system:virt-sync', role: 'admin', ip: '' };
const s = (v, max) => String(v == null ? '' : v).replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, max || 200);
const bad = (msg, status = 400) => Object.assign(new Error(msg), { status });
const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;

function createVirt(app, opts = {}) {
  const { store } = app;
  const col = store.collection('virt_platforms'), devs = store.collection('disc_devices'), facts = store.collection('core_lic_facts');
  const dc = (app.config && app.config.discovery) || {};
  const sealer = opts.sealer || createSealer({ keyFile: dc.vault_key_file, createKey: dc.vault_create_key !== false, purpose: 'sentra-itam-virt-platforms' });
  const PM = (() => { try { return require('./discovery/py-methods'); } catch (e) { return { wrap: (n, m) => m, configure() {} }; } })();   // answered by Python (step 5a); a missing bridge never stops the engine
  if (!app.discovery) PM.configure({ python: dc.python_bin, engine: dc.engine });
  const methods = opts.methods || { vcenter: PM.wrap('vcenter', require('./discovery/methods/vcenter')), esxi: PM.wrap('esxi', require('./discovery/methods/esxi')), nutanix: PM.wrap('nutanix', require('./discovery/methods/nutanix')), proxmox: require('./discovery/methods/proxmox') };
  const audit = (e) => { if (app.audit) app.audit(e); };
  const now = opts.now || Date.now;
  const running = new Map();
  const disc = () => app.discovery || null;
  // vCenter's host list gives only the name the host was added with (usually a DNS name), and some Prism versions leave
  // the hypervisor address out: the host's own name is then resolved in DNS (the same lookup vCenter uses to reach it)
  const lookup = opts.resolve || ((name) => require('node:dns').promises.lookup(name, { family: 4 }).then((r) => r.address));
  async function ipOfName(name, cache) {
    const n = String(name || '').trim().toLowerCase();
    if (!n || IPV4.test(n) || !/^[a-z0-9][a-z0-9.-]{0,252}$/.test(n)) return null;
    if (!cache.has(n)) cache.set(n, Promise.race([lookup(n), new Promise((r) => setTimeout(() => r(null), 3000))]).then((ip) => (IPV4.test(String(ip || '')) ? ip : null)).catch(() => null));
    return cache.get(n);
  }
  // a host approved earlier without an address gets it now - only filled when empty, never overwritten
  function fillIp(assetId, ip, source, out) {
    if (!assetId || !ip) return;
    const assets = store.collection('assets'), a = assets.get(assetId);
    if (!a || a.mgmt_ip) return;
    assets.patch(assetId, (x) => { x.mgmt_ip = ip; x.networked = true; x.prov = Object.assign({}, x.prov, { mgmt_ip: source }); x.updated_at = new Date(now()).toISOString(); return x; });
    out.ips_filled = (out.ips_filled || 0) + 1;
  }

  function view(p) {
    const { enc, presented, ...pub } = p; // eslint-disable-line no-unused-vars
    return Object.assign(pub, { credentials_set: !!enc, presented: presented || null });
  }
  function list() { return { platforms: col.all().map(view).sort((a, b) => (a.label < b.label ? -1 : 1)), kinds: KINDS, sites: disc() && disc().sites ? disc().sites() : [] }; }
  function cred(p) {
    if (!p.enc) throw bad('user name and password not set', 409);
    const sec = JSON.parse(sealer.unseal(p.id, p.enc));
    return { target: { base_url: p.base_url, ca_file: p.ca_file || undefined, tls_fingerprint: p.tls_fingerprint || undefined }, secret: sec };
  }

  function save(b, who) {
    const kind = s(b.kind, 20);
    const cur = b.id ? col.get(String(b.id)) : null;
    if (b.id && !cur) throw bad('platform not found', 404);
    const k = cur ? cur.kind : kind;
    if (!KINDS[k]) throw bad('kind must be vcenter, esxi, nutanix or proxmox');
    const o = Object.assign({}, cur || { id: 'vp_' + crypto.randomBytes(5).toString('hex'), kind: k, created_by: who.user, created_at: new Date(now()).toISOString(), auto_approve: true, interval_min: 60 });
    if ('label' in b || !cur) o.label = s(b.label, 80) || s(b.base_url, 80);
    let moved = false;
    if ('base_url' in b) {
      const u = s(b.base_url, 300).replace(/\/+$/, '');
      if (!/^https:\/\/[A-Za-z0-9.-]+(:\d{1,5})?(\/[^\s]*)?$/.test(u)) throw bad('the address must be https://<host or IP>[:port]');
      if (cur && u !== cur.base_url) { moved = true; o.tls_fingerprint = ''; o.presented = null; }
      o.base_url = u;
    }
    if (!o.base_url) throw bad('the address is required');
    if ('ca_file' in b) { const f = s(b.ca_file, 250); if (f && !/^\/[A-Za-z0-9._/-]+$/.test(f)) throw bad('ca_file must be an absolute path'); if (cur && f !== (cur.ca_file || '')) moved = true; o.ca_file = f; }
    if ('site' in b) o.site = s(b.site, 80);
    if ('interval_min' in b) { const m = Number(b.interval_min); if (!Number.isFinite(m) || m < 15 || m > 1440) throw bad('interval must be 15 to 1440 minutes'); o.interval_min = Math.round(m); }
    if ('auto_approve' in b) o.auto_approve = b.auto_approve === true;
    const user = s(b.username, 128), pass = b.password == null ? '' : String(b.password).slice(0, 256);
    if (user || pass) {
      if (!user || !pass) throw bad('enter both the user name and the password');
      if (!sealer.available()) throw bad('credential vault unavailable: ' + sealer.unavailableReason(), 503);
      o.enc = sealer.seal(o.id, JSON.stringify({ username: user, password: pass }));
      o.credentials_at = new Date(now()).toISOString(); o.credentials_by = who.user;
    } else if (!cur) throw bad('enter the user name and password');
    else if (moved) throw bad('the address or CA file changed: enter the password again');
    o.updated_by = who.user; o.updated_at = new Date(now()).toISOString();
    col.put(o);
    audit({ by: who.user, role: who.role, ip: who.ip, action: cur ? 'virt.update' : 'virt.create', target: o.id, detail: { kind: o.kind, label: o.label, base_url: o.base_url, site: o.site || '', credentials_changed: !!(user && pass) } });
    return Object.assign(list(), { platform: view(o) });
  }

  async function test(id, who) {
    const p = col.get(String(id)); if (!p) throw bad('platform not found', 404);
    const c = cred(p);
    let r;
    try { r = await methods[p.kind].test(c); } finally { for (const x of Object.keys(c.secret)) c.secret[x] = null; }
    const presented = r && r.tls && r.tls.presented ? r.tls.presented : null;
    col.patch(p.id, (x) => { x.last_test = { at: new Date(now()).toISOString(), ok: !!r.ok, error_class: r.error_class || null, message: r.message || '' }; x.presented = presented; });
    audit({ by: who.user, role: who.role, ip: who.ip, action: 'virt.test', target: p.id, detail: { ok: !!r.ok, error_class: r.error_class || null } });
    return { result: r, platform: view(col.get(p.id)) };
  }
  function pin(id, b, who) {
    const p = col.get(String(id)); if (!p) throw bad('platform not found', 404);
    const fp = s(b.fingerprint, 120).replace(/:/g, '').toLowerCase();
    const seen = p.presented && String(p.presented.fingerprint256 || '').replace(/:/g, '').toLowerCase();
    if (!fp || fp !== seen) throw bad('pin only the certificate shown by the last test (run Test again)', 409);
    col.patch(p.id, (x) => { x.tls_fingerprint = fp; x.presented = null; x.pinned_by = who.user; x.pinned_at = new Date(now()).toISOString(); });
    audit({ by: who.user, role: who.role, ip: who.ip, action: 'virt.pin', target: p.id, detail: { fingerprint256: fp } });
    return Object.assign(list(), { platform: view(col.get(p.id)) });
  }
  function remove(id, who) {
    const p = col.get(String(id)); if (!p) throw bad('platform not found', 404);
    col.remove(p.id);
    audit({ by: who.user, role: who.role, ip: who.ip, action: 'virt.delete', target: p.id, detail: { kind: p.kind, label: p.label } });
    return list();
  }

  // one sighting into Asset Discovery; Nutanix gets its type set here (the classifier knows vCenter, not Nutanix)
  function observe(o, ctx, fix) {
    const D = disc(); if (!D || !D.devices) throw bad('Asset Discovery is not available in this engine', 503);
    const d = D.devices.observe(o, ctx);
    if (d && fix) devs.patch(d.id, (x) => { x.type = fix.type; if (fix.vendor) x.vendor = fix.vendor; x.confidence = Math.max(x.confidence || 0, 90); x.reasons = [fix.why].concat((x.reasons || []).filter((r) => r !== fix.why)).slice(0, 12); });
    return d ? devs.get(d.id) || d : null;
  }
  function approveIfNew(d, p, out) {
    if (!d || !p.auto_approve) return d && d.asset_id ? d.asset_id : null;
    if (d.status === 'new') { try { const r = disc().approve(d.id, SYS); out.approved++; return r.asset_id; } catch (e) { out.approve_errors++; return null; } }
    return d.asset_id || null;
  }
  function vendorOfCpu(m) { return /amd|epyc/i.test(m || '') ? 'amd' : /intel|xeon/i.test(m || '') ? 'intel' : /power/i.test(m || '') ? 'ibm power' : ''; }

  async function sync(id, who = SYS) {
    const p = col.get(String(id)); if (!p) throw bad('platform not found', 404);
    if (running.has(p.id)) return running.get(p.id);
    const job = (async () => {
      const t0 = now(), out = { at: new Date(t0).toISOString(), ok: true, hosts: 0, vms: 0, clusters: 0, approved: 0, approve_errors: 0, linked: 0, cores_filled: 0 };
      const ctx = { site: p.site || null, scope_id: null, at: out.at };
      try {
        const c = cred(p);
        let r;
        try { r = await methods[p.kind].collect(c); } finally { for (const x of Object.keys(c.secret)) c.secret[x] = null; }
        if (!r.ok) throw Object.assign(new Error(r.error || r.error_class || 'collect failed'), { cls: r.error_class });
        const hostAsset = new Map(), vmAsset = [], dnsCache = new Map();
        if (p.kind === 'vcenter' || p.kind === 'esxi') {   // a standalone ESXi host gives the same hosts / VMs shape
          for (const h of r.hosts) {
            // the management address vCenter / the host reported (vmk), else the name when it is an address, else DNS
            const named = IPV4.test(h.name || '') ? h.name : null, rep = IPV4.test(h.ip || '') ? h.ip : null, ip = rep || named || await ipOfName(h.name, dnsCache);
            const d = observe({ method: 'vcenter', hostname: named ? '' : h.name, ip, uid: `vc-host:${p.id}:${h.id}`, os: 'VMware ESXi', extra: { vcenter: { kind: 'host', state: h.state, platform: p.label, vmk: h.vmk || null, ip_from: rep || named ? 'vcenter' : ip ? 'dns' : null } } }, ctx);
            const a = approveIfNew(d, p, out); if (a) { hostAsset.set(h.id, a); fillIp(a, ip, 'vcenter', out); }
            if (!ip) out.hosts_without_ip = (out.hosts_without_ip || 0) + 1;
          }
          for (const v of r.vms) {
            const d = observe({ method: 'vcenter', hostname: v.hostname || v.name, ips: v.ips, macs: v.macs, os: v.guest_os, uid: `vc:${v.uuid || p.id + ':' + v.id}`, extra: { vcenter: { kind: 'vm', host: v.host_name, power_state: v.power_state, uuid: v.uuid, name: v.name, platform: p.label } } }, ctx);
            const a = approveIfNew(d, p, out); if (a) vmAsset.push([a, v.host_id]);
          }
        } else if (p.kind === 'proxmox') {   // Proxmox VE nodes and their VMs / containers
          for (const h of r.hosts) {
            const ip = h.ip || await ipOfName(h.name, dnsCache);
            if (!ip) out.hosts_without_ip = (out.hosts_without_ip || 0) + 1;
            const d = observe({ method: 'proxmox', hostname: h.name, ip, os: 'Proxmox VE', vendor: 'Proxmox', uid: `pve-node:${p.id}:${h.id}`, extra: { proxmox: { kind: 'host', state: h.state, platform: p.label, ip_from: h.ip ? 'proxmox' : ip ? 'dns' : null } } }, ctx, { type: 'server', vendor: 'Proxmox', why: 'Proxmox VE node -> server' });
            const a = approveIfNew(d, p, out); if (a) { hostAsset.set(h.id, a); fillIp(a, ip, 'import', out); }
          }
          for (const v of r.vms) {
            const d = observe({ method: 'proxmox', hostname: v.name, uid: `pve:${p.id}:${v.id}`, extra: { proxmox: { kind: 'vm', host: v.host_name, power_state: v.power_state, vcpus: v.vcpus, memory_mb: v.memory_mb, name: v.name, platform: p.label, container: v.kind === 'container' } } }, ctx, { type: 'vm', why: 'Proxmox VE guest -> vm' });
            const a = approveIfNew(d, p, out); if (a) vmAsset.push([a, v.host_id]);
          }
        } else {
          for (const h of r.hosts) {
            if (!h.ip) { h.ip = await ipOfName(h.name, dnsCache); if (!h.ip) out.hosts_without_ip = (out.hosts_without_ip || 0) + 1; }
            const d = observe({ method: 'nutanix', hostname: h.name, ip: h.ip, serial: h.serial, model: h.model, vendor: 'Nutanix', os: h.hypervisor || 'Nutanix AHV', uid: `ntnx-host:${h.id}`,
              extra: { nutanix: { kind: 'host', cluster: h.cluster, cvm_ip: h.cvm_ip, ipmi_ip: h.ipmi_ip, sockets: h.sockets, cores: h.cores, cpu_model: h.cpu_model, platform: p.label } } }, ctx, { type: 'server', vendor: 'Nutanix', why: 'Nutanix Prism host → server' });
            const a = approveIfNew(d, p, out);
            if (a) {
              hostAsset.set(h.id, a); fillIp(a, h.ip, 'import', out);
              const f = facts.get(a);
              if (h.sockets && h.cores_per_socket && (!f || f.source === 'nutanix' || (!f.sockets && !f.cores_per_socket))) {
                facts.put(Object.assign({}, f || { id: a }, { sockets: h.sockets, cores_per_socket: h.cores_per_socket, cluster: (f && f.source !== 'nutanix' && f.cluster) || h.cluster || '', cpu_vendor: (f && f.cpu_vendor) || vendorOfCpu(h.cpu_model), source: 'nutanix', updated_by: SYS.user, updated_at: out.at }));
                out.cores_filled++;
              }
            }
          }
          for (const v of r.vms) {
            const d = observe({ method: 'nutanix', hostname: v.name, ips: v.ips, macs: v.macs, uid: `ntnx:${v.id}`,
              extra: { nutanix: { kind: 'vm', host: v.host_name, cluster: v.cluster, power_state: v.power_state, vcpus: v.vcpus, memory_mb: v.memory_mb, name: v.name, platform: p.label } } }, ctx, { type: 'vm', why: 'Nutanix Prism VM → vm' });
            const a = approveIfNew(d, p, out); if (a) vmAsset.push([a, v.host_id]);
          }
          out.clusters = (r.clusters || []).length;
        }
        out.hosts = r.hosts.length; out.vms = r.vms.length; out.api = r.api || null;
        // VM → host (runs_on), for the inventory, the CMDB map and the core licence audit
        if (app.assets && app.assets.addRelationship) {
          const have = new Set((app.assets.allRelationships ? app.assets.allRelationships() : []).filter((x) => x.type === 'runs_on').map((x) => x.from + '>' + x.to));
          for (const [vm, hid] of vmAsset) {
            const host = hostAsset.get(hid); if (!host || have.has(vm + '>' + host)) continue;
            try { app.assets.addRelationship({ from: vm, to: host, type: 'runs_on', rationale: `${KINDS[p.kind]} ${p.label}: VM placed on host` }, { user: SYS.user, role: 'system' }, { source: p.kind === 'vcenter' || p.kind === 'esxi' ? 'vcenter' : 'import', autoConfirm: true }); out.linked++; } catch { /* endpoint missing */ }
          }
        }
      } catch (e) { out.ok = false; out.error = e.cls ? `${e.cls}: ${e.message}` : e.message; }
      out.ms = now() - t0;
      // the dashboards that read the capacity collection (Nutanix VMs, Capacity, Power Control, the server pages) follow at once,
      // not at the next hourly collection
      const CAP = app.addons && app.addons.virtCapacity;
      if (out.ok && p.kind !== 'proxmox' && CAP && typeof CAP.collectPlatform === 'function') {   // capacity reads vCenter / ESXi / Nutanix
        out.capacity = 'collecting';
        Promise.resolve().then(() => CAP.collectPlatform(p.id, who)).catch((e) => { try { if (app.log) app.log.warn('virt: capacity collection after the sync failed', { platform: p.id, err: String(e.message || e).slice(0, 200) }); } catch (x) { /* logging never stops the sync */ } });
      }
      col.patch(p.id, (x) => { x.last_sync = out; });
      if (who !== SYS || !out.ok || out.approved) audit({ by: who.user, role: who.role, ip: who.ip, action: 'virt.sync', target: p.id, detail: out });
      running.delete(p.id);
      return out;
    })();
    running.set(p.id, job);
    return job;
  }
  // ESXi / Nutanix hosts recorded without an address (a Discovery scope run before host addresses were read, a host vCenter
  // knows only by a name): filled from what another source already knows - the asset's management IP, another sighting of
  // the same host name, the capacity read's VMkernel address - and last from DNS. Only an empty address is filled.
  let filling = null, lastFill = 0;
  function knownIps() {
    const m = new Map(), put = (n, ip, from) => { const k = String(n || '').trim().toLowerCase(); if (k && IPV4.test(String(ip || '')) && !m.has(k)) { m.set(k, { ip, from }); m.set(k.split('.')[0], m.get(k.split('.')[0]) || { ip, from }); } };
    for (const d of devs.all((x) => x.ip)) { put(d.hostname, d.ip, 'another sighting'); put(d.fqdn, d.ip, 'another sighting'); }
    try { for (const p of store.collection('virt_capacity').all()) for (const h of p.hosts || []) put(h.name, h.mgmt_ip || h.ip, 'vCenter / Prism capacity read'); } catch (e) { /* capacity not collected yet */ }
    return m;
  }
  async function fillHostIps(force) {
    if (filling) return filling;
    if (!force && now() - lastFill < 3600000) return null;
    filling = (async () => {
      lastFill = now();
      const out = { at: new Date(now()).toISOString(), checked: 0, filled: 0, from: {} }, cache = new Map(), known = knownIps(), assets = store.collection('assets');
      for (const d of devs.all((x) => !x.ip && ((x.extra && ((x.extra.vcenter && x.extra.vcenter.kind === 'host') || (x.extra.nutanix && x.extra.nutanix.kind === 'host') || (x.extra.proxmox && x.extra.proxmox.kind === 'host'))) || /esxi|ahv|proxmox/i.test(x.os || '')))) {
        out.checked++;
        const name = d.hostname || d.fqdn || (d.extra && ((d.extra.vcenter || {}).name || (d.extra.nutanix || {}).name)) || '';
        const a = d.asset_id ? assets.get(d.asset_id) : null;
        let ip = a && IPV4.test(a.mgmt_ip || '') ? a.mgmt_ip : null, from = ip ? 'asset' : null;
        if (!ip) { const k = known.get(String(name).toLowerCase()) || known.get(String(name).toLowerCase().split('.')[0]); if (k) { ip = k.ip; from = k.from; } }
        if (!ip) { ip = await ipOfName(name, cache); if (ip) from = 'dns'; }
        if (!ip) continue;
        devs.patch(d.id, (x) => { if (!x.ip) { x.ip = ip; const src = x.extra && (x.extra.vcenter || x.extra.nutanix); if (src) src.ip_from = from; } return x; });
        fillIp(d.asset_id, ip, from === 'dns' ? 'dns' : 'vcenter', out);
        out.filled++; out.from[from] = (out.from[from] || 0) + 1;
      }
      if (out.filled && app.log) app.log.info('virt: host addresses filled', out);
      return out;
    })().finally(() => { filling = null; });
    return filling;
  }
  function tick() {
    guardOf(app, 'virt.fill-host-ips', fillHostIps)(false);
    const t = now();
    for (const p of col.all()) {
      if (!p.enc || running.has(p.id)) continue;
      const last = p.last_sync ? Date.parse(p.last_sync.at) : 0;
      if (t - last >= (p.interval_min || 60) * 60000) guardOf(app, 'virt.sync.' + p.id, sync)(p.id);
    }
  }
  // Hosts and VMs from EVERY source, not only the platforms on this page: vCenter / Nutanix scopes in Asset Discovery,
  // Hyper-V reports, and inventory records that are hypervisors or VMs (entered by hand, imported, or merged earlier).
  const HV = /\b(esxi|vmware esx|ahv|nutanix|hyper-v|proxmox|xenserver|xcp-ng)\b/i;
  function inventory() {
    const scopes = store.collection('disc_scopes').all(), runs = store.collection('disc_runs').all();
    const scopeName = new Map(scopes.map((x) => [x.id, x.label || x.name || x.id]));
    const items = [], seenAsset = new Set(), known = knownIps(), assetIp = new Map(store.collection('assets').all((a) => IPV4.test(a.mgmt_ip || '')).map((a) => [a.id, a.mgmt_ip]));
    for (const d of devs.all()) {
      const ex = d.extra || {}, src = ['vcenter', 'nutanix', 'hyperv'].find((m) => ex[m] || (d.methods && d.methods[m]));
      if (!src) continue;
      const e = ex[src] || {}, kind = e.kind === 'host' ? 'host' : e.kind === 'vm' ? 'vm' : (/esxi|ahv|hyper-v|proxmox/i.test(d.os || '') ? 'host' : 'vm');
      if (d.asset_id) seenAsset.add(d.asset_id);
      const aIp = d.asset_id ? (assetIp.get(d.asset_id) || null) : null, kn = !d.ip && !aIp && kind === 'host' ? (known.get(String(d.hostname || d.fqdn || e.name || '').toLowerCase()) || null) : null;
      items.push({ kind, name: e.name || d.hostname || d.fqdn || d.ip || d.id, ip: d.ip || aIp || (kn && kn.ip) || null, ip_from: d.ip ? (e.ip_from || null) : aIp ? 'asset' : kn ? kn.from : null, os: d.os || null, power_state: e.power_state || e.state || null,
        host: e.host || null, cluster: e.cluster || null, vcpus: e.vcpus || e.cores || null, memory_mb: e.memory_mb || null, source: src,
        platform: e.platform || (d.scope_id ? 'Discovery scope: ' + (scopeName.get(d.scope_id) || d.scope_id) : KINDS[src] || src), site: d.site || null,
        last_seen: d.last_seen || null, status: d.status || null, asset_id: d.asset_id || null, device_id: d.id });
    }
    for (const a of store.collection('assets').all()) {
      if (seenAsset.has(a.id) || a.status === 'retired' || a.status === 'disposed') continue;
      const host = HV.test(a.os || '') || (a.vendor && /nutanix/i.test(a.vendor) && a.type === 'server'), vm = a.type === 'vm';
      if (!host && !vm) continue;
      items.push({ kind: host ? 'host' : 'vm', name: a.name, ip: a.mgmt_ip || null, os: a.os || null, power_state: null, host: null, cluster: null, vcpus: null, memory_mb: a.mem_gb ? a.mem_gb * 1024 : null,
        source: 'inventory', platform: 'IT Asset Management', site: a.site || null, last_seen: a.updated_at || null, status: a.status || null, asset_id: a.id, device_id: null });
    }
    items.sort((a, b) => (a.kind === b.kind ? String(a.name).localeCompare(String(b.name)) : a.kind === 'host' ? -1 : 1));
    // Discovery scopes that read a virtualization platform, with the result of their last run for those methods
    const dscopes = scopes.filter((x) => x.methods && ['vcenter', 'nutanix', 'hyperv'].some((m) => x.methods[m] && x.methods[m].enabled)).map((x) => {
      const last = runs.filter((r) => r.scope_id === x.id && r.stats).sort((a, b) => (a.started_at < b.started_at ? 1 : -1))[0];
      const ms = ['vcenter', 'nutanix', 'hyperv'].filter((m) => x.methods[m] && x.methods[m].enabled);
      // a method with no result in the last run says why: blocked (and the reason), the run still going, stopped or failed
      const why = (m) => {
        const b = (last.methods_blocked || []).find((y) => y.method === m);
        if (b) return 'blocked: ' + b.reason;
        if (last.status === 'running') return 'the run is still going';
        const ST = { cancelled: 'was cancelled', stopped_window: 'stopped at the end of its scan window', interrupted: 'was interrupted (the engine restarted)', failed: 'failed' };
        if (ST[last.status]) return 'the run ' + ST[last.status] + (last.error ? ': ' + String(last.error).slice(0, 120) : ' before reaching it');
        if ((last.methods_run || []).length && !(last.methods_run || []).includes(m)) return 'not part of that run (started with: ' + last.methods_run.join(', ') + ')';
        return 'no result recorded';
      };
      return { id: x.id, label: x.label || x.name || x.id, site: x.site || null, methods: ms, last_run: last ? last.started_at : null, last_status: last ? last.status || null : null,
        results: last ? ms.map((m) => Object.assign({ method: m }, last.stats[m] || { ok: null, note: why(m) })) : [] };
    });
    const c = (k, f) => items.filter((i) => i.kind === k && (!f || f(i))).length;
    return { items: items.slice(0, 5000), total: items.length, scopes: dscopes,
      summary: { hosts: c('host'), vms: c('vm'), vms_on: c('vm', (i) => /on|running/i.test(i.power_state || '')), vms_off: c('vm', (i) => /off|stopped|suspend/i.test(i.power_state || '')), in_inventory: items.filter((i) => i.asset_id).length,
        by_source: items.reduce((o, i) => { o[i.source] = (o[i.source] || 0) + 1; return o; }, {}) } };
  }

  return { list, save, test, pin, remove, sync, tick, inventory, fillHostIps, KINDS };
}

function registerVirt(srv, app) {
  const V = createVirt(app);
  srv.route('GET', '/virt', (ctx) => { ctx.need('operator'); return V.list(); });
  srv.route('GET', '/virt/inventory', (ctx) => { ctx.need('operator'); return V.inventory(); });
  srv.route('POST', '/virt', (ctx) => { ctx.need('admin'); return V.save(ctx.body || {}, ctx.who); });
  srv.route('POST', '/virt/:id/test', async (ctx) => { ctx.need('admin'); return V.test(ctx.params.id, ctx.who); });
  srv.route('POST', '/virt/:id/pin', (ctx) => { ctx.need('admin'); return V.pin(ctx.params.id, ctx.body || {}, ctx.who); });
  srv.route('POST', '/virt/:id/sync', async (ctx) => { ctx.need('admin'); return { sync: await V.sync(ctx.params.id, ctx.who) }; });
  srv.route('POST', '/virt/hosts/fill-ips', async (ctx) => {
    ctx.need('operator');
    const r = await V.fillHostIps(true);
    if (app.audit) app.audit({ by: ctx.who.user, role: ctx.who.role, ip: ctx.who.ip, action: 'virt.hosts.fill_ips', target: 'virtualization', detail: r });
    return Object.assign({ fill: r }, V.inventory());
  });
  srv.route('POST', '/virt/:id/delete', (ctx) => { ctx.need('admin'); return V.remove(ctx.params.id, ctx.who); });
  const t1 = setTimeout(guardOf(app, 'virt.tick', V.tick), 90000), t2 = setInterval(guardOf(app, 'virt.tick', V.tick), 60000);
  if (t1.unref) t1.unref(); if (t2.unref) t2.unref();
  (app.addons = app.addons || {}).virt = V;   // reachable from Sync all now (engine/reconcile.js)
  return V;
}

module.exports = { createVirt, registerVirt, KINDS };
