// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Core-based licence audit: Oracle Database (processor / socket metrics), Microsoft Windows Server (per core) and VMware
// vSphere / VVF / VCF (per core) - what the estate needs from the physical servers, the ESXi hosts and the VMs on them,
// against what the organisation owns (entitlements).
//   GET  /core-licensing                       {settings, summary, products{}, hosts[], deployments[], entitlements[]}  operator
//   POST /core-licensing/hosts                 {items:[{id|name|ip, sockets, cores_per_socket, cpu_vendor, cluster,
//                                                oracle: ee|se2|none|auto, odi: yes|none|auto, windows: std|dc|auto, notes}]}   facts per server / VM  operator
//   POST /core-licensing/entitlements          {id?, product, quantity, expiry?, contract?, notes?}             admin
//   POST /core-licensing/entitlements/:id/delete                                                                 admin
//   PUT  /core-licensing/settings              {oracle_scope, core_factor, win_dc_ratio, vmware_min_per_cpu, vmware_min_order} admin
// Rules (vendor licensing terms; the settings let an administrator match their own contract):
//   Oracle EE (Processor): physical cores x core factor (Intel / AMD 0.5, IBM POWER 1.0), rounded up per server. VMware is
//     soft partitioning to Oracle: a VM is licensed on every physical host it can run on - oracle_scope "cluster" (the
//     host's cluster) or "vcenter" (every ESXi host; Oracle's strictest reading). "host" only with hard partitioning.
//     Named User Plus minimum: 25 per processor.
//   Oracle Data Integrator EE: Processor metric like Database EE (cores x core factor, same VMware scope, NUP min 25).
//   Oracle SE2: 1 licence per occupied socket, servers of at most 2 sockets; same VMware scope. NUP minimum 10 per server.
//   Windows Server (Standard / Datacenter): every physical core of the host, at least 8 per processor and 16 per server, sold
//     in 2-core packs. Datacenter: unlimited Windows VMs on the host. Standard: each full licensing of the host's cores
//     covers 2 Windows VMs (OSEs). The cheaper edition is suggested from win_dc_ratio (Datacenter price / Standard price).
//   VMware (Broadcom subscription): every physical core of each ESXi host, at least vmware_min_per_cpu (16) per CPU, and
//     at least vmware_min_order (72) cores per order.
// Core counts: the facts entered here (bulk paste from the page) or read from vCenter / Nutanix Prism by the capacity
// collection (virt-capacity.js: sockets and cores per socket per ESXi / AHV host), else read from the asset's CPU text when
// it carries them ("2 x 16 cores", "32 cores"). Hosts with no core count are listed as "cores unknown" - nothing is guessed.
// Self-contained (stored collections), added to an existing install with one registration line (install/add-core-licensing.sh).
const crypto = require('node:crypto');

const DAY = 86400000;
const CLOSED = { retired: 1, disposed: 1 };
const PRODUCTS = {
  oracle_ee: { name: 'Oracle Database Enterprise Edition', unit: 'processor licences' },
  oracle_se2: { name: 'Oracle Database Standard Edition 2', unit: 'processor licences (sockets)' },
  oracle_odi: { name: 'Oracle Data Integrator Enterprise Edition (ODI)', unit: 'processor licences' },
  windows_std: { name: 'Windows Server Standard', unit: 'cores' },
  windows_dc: { name: 'Windows Server Datacenter', unit: 'cores' },
  vmware: { name: 'VMware vSphere / VVF / VCF', unit: 'cores' },
};
const DEFAULTS = { oracle_scope: 'cluster', core_factor: 0.5, win_dc_ratio: 5.8, vmware_min_per_cpu: 16, vmware_min_order: 72 };
const SCOPES = ['host', 'cluster', 'vcenter'];
const s = (v, max) => String(v == null ? '' : v).replace(/[\u0000-\u001f\u007f]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, max || 120);
const bad = (msg, status = 400) => Object.assign(new Error(msg), { status });
const int = (v) => { const n = parseInt(v, 10); return Number.isFinite(n) && n > 0 && n < 100000 ? n : null; };
const tags = (a) => (Array.isArray(a.tags) ? a.tags : []).map((t) => String(t).toLowerCase());

const WIN_SERVER = /win[a-z_ ]*\d*[ _]*(server|srv)/i;
function isVm(a) { return a.type === 'vm' || tags(a).includes('vm'); }
function isEsxi(a) { return tags(a).includes('esxi-host') || /esxi|vmware\s*esx/i.test(a.os || ''); }
function factorFor(vendor, def) { const v = String(vendor || '').toLowerCase(); return /power|ibm/.test(v) ? 1 : /intel|amd|xeon|epyc|sparc/.test(v) ? 0.5 : def; }
function vendorOf(cpu) { const c = String(cpu || ''); return /amd|epyc|opteron/i.test(c) ? 'amd' : /intel|xeon/i.test(c) ? 'intel' : /power/i.test(c) ? 'ibm power' : /sparc/i.test(c) ? 'sparc' : ''; }
// "2 x Intel Xeon Gold 6338 32-Core" / "2 sockets, 16 cores each" / "32 cores" / "2 CPU 16 cores per socket"
function parseCores(cpu) {
  const c = String(cpu || '');
  let m = /(\d+)\s*(?:x|×|\*)\s*[^,;]*?(\d+)[\s-]*cores?/i.exec(c);
  if (m) return { sockets: int(m[1]), cores_per_socket: int(m[2]), from: 'cpu text' };
  const so = /(\d+)\s*(?:sockets?|cpus?|processors?)\b/i.exec(c), co = /(\d+)\s*[\s-]*cores?\s*(per|each|\/)?/i.exec(c);
  if (so && co) return co[2] ? { sockets: int(so[1]), cores_per_socket: int(co[1]), from: 'cpu text' } : { sockets: int(so[1]), cores_per_socket: Math.ceil(int(co[1]) / int(so[1])) || null, from: 'cpu text' };
  if (co) return { sockets: 1, cores_per_socket: int(co[1]), from: 'cpu text', total_only: true };
  return null;
}
// Oracle Data Integrator (ODI agent / studio / standalone agent) - processor metric like Database EE
function odiOf(a, fact) {
  const o = fact && fact.odi;
  if (o === 'yes' || o === 'none') return o === 'yes';
  return (a.software || []).some((x) => /oracle\s*data\s*integrator|\bodi\b[^\n]*(agent|studio|12c|11g)|odi[_ -]?(agent|studio)/i.test(`${x.publisher || ''} ${x.name || ''}`));
}
const cfOf = (f) => { const n = f && f.core_factor != null && f.core_factor !== '' ? Number(f.core_factor) : NaN; return Number.isFinite(n) && n > 0 && n <= 1 ? n : null; };
function oracleOf(a, fact) {
  const o = fact && fact.oracle;
  if (o === 'ee' || o === 'se2' || o === 'none') return o === 'none' ? null : o;
  const sw = (a.software || []).find((x) => /oracle.*database|oracle\s*db|oracle\s*\d+[cgi]\b/i.test(`${x.publisher || ''} ${x.name || ''}`));
  // a database the platform monitors reported its edition itself (V$VERSION banner, written by oracle-licences.js)
  if (!sw) return fact && (fact.oracle_detected === 'ee' || fact.oracle_detected === 'se2') ? fact.oracle_detected : null;
  return /standard\s*edition|\bse2?\b/i.test(sw.name || '') ? 'se2' : 'ee';
}

function createCoreLicensing(app, opts = {}) {
  const { store } = app;
  const facts = store.collection('core_lic_facts'), ents = store.collection('core_lic_entitlements'), conf = store.collection('core_lic_settings');
  const assets = store.collection('assets'), rels = store.collection('relationships');
  const audit = (e) => { if (app.audit) app.audit(e); };
  const now = opts.now || Date.now;

  function settings() { return Object.assign({}, DEFAULTS, (conf.get('settings') || {}).values || {}); }
  function putSettings(b, who) {
    const cur = settings(), o = {};
    if ('oracle_scope' in b) { if (!SCOPES.includes(b.oracle_scope)) throw bad('oracle_scope must be one of ' + SCOPES.join(', ')); o.oracle_scope = b.oracle_scope; }
    const numIn = (k, lo, hi) => { if (k in b) { const n = Number(b[k]); if (!Number.isFinite(n) || n < lo || n > hi) throw bad(`${k} must be between ${lo} and ${hi}`); o[k] = n; } };
    numIn('core_factor', 0.25, 1); numIn('win_dc_ratio', 1, 50); numIn('vmware_min_per_cpu', 0, 128); numIn('vmware_min_order', 0, 10000);
    const values = Object.assign({}, cur, o);
    conf.put({ id: 'settings', values, updated_by: who.user, updated_at: new Date(now()).toISOString() });
    audit({ by: who.user, role: who.role, ip: who.ip, action: 'core_licensing.settings', target: 'settings', detail: o });
    return view();
  }

  function hostOf(vmId, byId) {
    for (const r of rels.all((x) => x.type === 'runs_on' && x.from === vmId)) { const h = byId.get(r.to); if (h && !CLOSED[h.status]) return h; }
    return null;
  }

  function view() {
    const st = settings(), t = now();
    const live = assets.all((a) => !CLOSED[a.status] && (a.type === 'server' || isVm(a) || isEsxi(a)));
    const byId = new Map(live.map((a) => [a.id, a]));
    const factOf = (id) => facts.get(id) || null;

    // physical servers (anything not a VM)
    const hosts = live.filter((a) => !isVm(a)).map((a) => {
      const f = factOf(a.id) || {}, p = parseCores(a.cpu) || {};
      const sockets = int(f.sockets) || p.sockets || null, cps = int(f.cores_per_socket) || p.cores_per_socket || null;
      const vendor = f.cpu_vendor || vendorOf(a.cpu);
      const esxi = isEsxi(a);
      return { id: a.id, name: a.name || a.asset_tag || a.id, site: a.site || '', os: a.os || '', cpu: a.cpu || '', esxi,
        cluster: f.cluster || (esxi ? '' : ''), sockets, cores_per_socket: cps, cores: sockets && cps ? sockets * cps : null,
        // where the count came from: typed in here, read from vCenter / Prism (capacity collection), or the CPU text
        cores_from: int(f.sockets) && int(f.cores_per_socket) ? (f.source === 'vcenter' ? 'vCenter' : f.source === 'nutanix' ? 'Nutanix Prism' : 'entered') : p.from || null, total_only: !int(f.sockets) && !!p.total_only,
        // the Oracle core factor: a person's entry, else the Oracle Processor Core Factor Table row matched to the CPU model
        // (oracle-licences.js writes it), else the vendor rule below; with none of those the default is ASSUMED and says so
        cpu_vendor: vendor, factor: cfOf(f) != null ? cfOf(f) : factorFor(vendor, st.core_factor), factor_assumed: cfOf(f) == null && !vendor,
        factor_source: cfOf(f) != null ? (f.core_factor_src === 'entered' ? 'entered' : 'table') : vendor ? 'vendor' : 'default', factor_row: cfOf(f) != null ? (f.core_factor_row || '') : '',
        windows_host: WIN_SERVER.test(a.os || ''), windows_edition: f.windows || 'auto', notes: f.notes || '', vms: [] };
    });
    // why an ESXi / AHV host still has no core count, and what fills it (never a guess)
    const cap = app.addons && app.addons.virtCapacity ? (() => { try { return app.addons.virtCapacity.report(); } catch (e) { return null; } })() : null;
    const capHint = !cap ? 'install the capacity collection (add-virt-capacity.sh) - it reads sockets and cores from vCenter / Prism - or type the counts in here'
      : !cap.platforms.length ? 'connect vCenter / Prism on the Virtualization page - the capacity collection then reads the cores'
      : cap.platforms.some((p) => p.error) ? 'the last capacity collection failed (' + cap.platforms.filter((p) => p.error).map((p) => p.label + ': ' + p.error).join('; ') + ') - fix it on Virtualization → Capacity, or type the counts in here'
      : 'not read yet: Virtualization → Capacity → Collect now (the host must be in the inventory from the vCenter / Prism sync), or type the counts in here';
    for (const h of hosts) if (!h.cores && (h.esxi || /nutanix|ahv/i.test(h.os))) h.cores_hint = capHint;
    const hostById = new Map(hosts.map((h) => [h.id, h]));
    const clusterKey = (h) => (h.esxi ? 'esxi:' + (h.cluster || '(cluster not set)') : 'host:' + h.id);

    // VMs on their hosts
    const vms = live.filter(isVm).map((a) => {
      const f = factOf(a.id) || {}, h = hostOf(a.id, byId);
      return { id: a.id, name: a.name || a.id, os: a.os || '', host_id: h ? h.id : null, windows: WIN_SERVER.test(a.os || ''), oracle: oracleOf(a, f), odi: odiOf(a, f) };
    });
    for (const v of vms) { const h = v.host_id && hostById.get(v.host_id); if (h) h.vms.push({ id: v.id, name: v.name, windows: v.windows, oracle: v.oracle, odi: v.odi }); }

    // Oracle deployments → physical hosts to license
    const deployments = [];
    for (const a of live.filter((x) => !isVm(x))) {
      const o = oracleOf(a, factOf(a.id)); if (o) deployments.push({ id: a.id, name: a.name || a.id, edition: o, vm: false, host_id: a.id });
      if (odiOf(a, factOf(a.id))) deployments.push({ id: a.id, name: a.name || a.id, edition: 'odi', vm: false, host_id: a.id });
    }
    for (const v of vms) {
      if (v.oracle) deployments.push({ id: v.id, name: v.name, edition: v.oracle, vm: true, host_id: v.host_id });
      if (v.odi) deployments.push({ id: v.id, name: v.name, edition: 'odi', vm: true, host_id: v.host_id });
    }
    const allEsxi = hosts.filter((h) => h.esxi);
    function scopeHosts(d) {
      const h = d.host_id && hostById.get(d.host_id);
      if (!h) return null;
      if (!d.vm || st.oracle_scope === 'host') return [h];
      if (st.oracle_scope === 'vcenter') return h.esxi ? allEsxi : [h];
      const k = clusterKey(h); return hosts.filter((x) => clusterKey(x) === k);
    }
    const oracle = { ee: new Map(), se2: new Map(), odi: new Map() };
    for (const d of deployments) {
      const sc = scopeHosts(d);
      d.scope = sc ? sc.map((h) => h.name) : null;
      if (!sc) { d.problem = 'the physical host of this VM is not known - link the VM to its host (vCenter sync or CMDB)'; continue; }
      for (const h of sc) oracle[d.edition].set(h.id, h);
    }
    const unknown = [];
    function oracleNeed(edition) {
      let req = 0, nup = 0, missing = []; const rows = [];
      for (const h of oracle[edition].values()) {
        if (edition === 'ee' || edition === 'odi') {
          if (!h.cores) { missing.push(h.name); continue; }
          const n = Math.ceil(h.cores * h.factor); req += n; nup += n * 25;
          rows.push({ host: h.name, cores: h.cores, factor: h.factor, licences: n });
        } else {
          if (!h.sockets) { missing.push(h.name); continue; }
          req += h.sockets; nup += 10;
          rows.push({ host: h.name, sockets: h.sockets, licences: h.sockets, problem: h.sockets > 2 ? 'SE2 is allowed only on servers with at most 2 sockets' : null });
        }
      }
      missing.forEach((n) => unknown.push({ host: n, product: 'oracle_' + edition }));
      return { required: req, nup_minimum: nup, hosts: rows, cores_unknown: missing };
    }
    const prod = { oracle_ee: oracleNeed('ee'), oracle_se2: oracleNeed('se2'), oracle_odi: oracleNeed('odi') };

    // Windows Server per physical host
    const win = { std: 0, dc: 0, rows: [], cores_unknown: [] };
    for (const h of hosts) {
      const winVms = h.vms.filter((v) => v.windows).length;
      const oses = winVms > 0 ? winVms : (h.windows_host ? 1 : 0);
      if (!oses) continue;
      if (!h.sockets || !h.cores_per_socket) { win.cores_unknown.push(h.name); unknown.push({ host: h.name, product: 'windows' }); continue; }
      const coreReq = Math.max(16, h.sockets * Math.max(8, h.cores_per_socket));
      const stdCores = coreReq * Math.ceil(oses / 2), dcCores = coreReq;
      const suggest = Math.ceil(oses / 2) > st.win_dc_ratio ? 'dc' : 'std';
      const edition = h.windows_edition === 'std' || h.windows_edition === 'dc' ? h.windows_edition : suggest;
      if (edition === 'dc') win.dc += dcCores; else win.std += stdCores;
      win.rows.push({ host: h.name, cores: h.cores, licensed_cores: coreReq, windows_oses: oses, standard_cores: stdCores, datacenter_cores: dcCores, edition, suggested: suggest, packs: (edition === 'dc' ? dcCores : stdCores) / 2 });
    }
    prod.windows_std = { required: win.std, hosts: win.rows.filter((r) => r.edition === 'std'), cores_unknown: win.cores_unknown };
    prod.windows_dc = { required: win.dc, hosts: win.rows.filter((r) => r.edition === 'dc'), cores_unknown: win.cores_unknown };

    // VMware per ESXi host
    let vm = 0; const vrows = [], vmiss = [];
    for (const h of allEsxi) {
      if (!h.sockets || !h.cores_per_socket) { vmiss.push(h.name); unknown.push({ host: h.name, product: 'vmware' }); continue; }
      const c = h.sockets * Math.max(st.vmware_min_per_cpu, h.cores_per_socket); vm += c;
      vrows.push({ host: h.name, cluster: h.cluster || '', cores: h.cores, licensed_cores: c, vms: h.vms.length });
    }
    prod.vmware = { required: vm && vm < st.vmware_min_order ? st.vmware_min_order : vm, physical_licensed: vm, minimum_order_applied: !!(vm && vm < st.vmware_min_order), hosts: vrows, cores_unknown: vmiss };

    // against what is owned
    const entitlements = ents.all().map((e) => Object.assign({}, e, { days_left: e.expiry ? Math.round((Date.parse(e.expiry) - t) / DAY) : null }));
    const summary = [];
    for (const k of Object.keys(PRODUCTS)) {
      const mine = entitlements.filter((e) => e.product === k && !(e.days_left !== null && e.days_left < 0));
      const owned = mine.reduce((n, e) => n + (Number(e.quantity) || 0), 0), p = prod[k];
      const status = owned < p.required ? 'shortfall' : p.cores_unknown.length ? 'incomplete' : !p.required && !owned ? 'not_used' : 'compliant';
      const expiring = mine.filter((e) => e.days_left !== null && e.days_left <= 90).map((e) => ({ id: e.id, contract: e.contract || '', expiry: e.expiry, days_left: e.days_left }));
      summary.push({ product: k, name: PRODUCTS[k].name, unit: PRODUCTS[k].unit, required: p.required, owned, delta: owned - p.required, status, cores_unknown: p.cores_unknown.length, expiring });
    }
    return { settings: st, products_catalogue: PRODUCTS, scopes: SCOPES, summary, products: prod, deployments, hosts, unknown, entitlements,
      counts: { physical: hosts.length, esxi: allEsxi.length, vms: vms.length, vms_without_host: vms.filter((v) => !v.host_id).length, cores_unknown: hosts.filter((h) => !h.cores).length } };
  }

  function findAsset(it) {
    if (it.id && assets.get(String(it.id))) return assets.get(String(it.id));
    const n = s(it.name || it.host).toLowerCase(), short = n.split('.')[0], ip = s(it.ip);
    if (!n && !ip) return null;
    const hit = (x) => { const v = String(x || '').toLowerCase(); return v && (v === n || v.split('.')[0] === short); };
    return assets.all((a) => !CLOSED[a.status] && ((n && [a.name, a.asset_tag, a.hostname].some(hit)) || (ip && a.mgmt_ip === ip)))[0] || null;
  }
  function putFacts(b, who) {
    const items = Array.isArray(b.items) ? b.items.slice(0, 5000) : [];
    if (!items.length) throw bad('no rows');
    const saved = [], notFound = [];
    for (const it of items) {
      const a = findAsset(it || {});
      if (!a) { notFound.push(s(it && (it.name || it.host || it.ip || it.id), 80)); continue; }
      const cur = facts.get(a.id) || { id: a.id };
      const o = Object.assign({}, cur);
      if ('sockets' in it) o.sockets = int(it.sockets);
      if ('cores_per_socket' in it) o.cores_per_socket = int(it.cores_per_socket);
      // a count typed in here is the person's: the vCenter / Prism reading no longer replaces it (empty both = hand back)
      if ('sockets' in it || 'cores_per_socket' in it) { if (o.sockets || o.cores_per_socket) o.source = 'entered'; else delete o.source; }
      if ('cpu_vendor' in it) o.cpu_vendor = s(it.cpu_vendor, 40).toLowerCase();
      if ('cluster' in it) o.cluster = s(it.cluster, 80);
      if ('oracle' in it) { const v = s(it.oracle, 10).toLowerCase(); if (v && !['ee', 'se2', 'none', 'auto'].includes(v)) throw bad('oracle must be ee, se2, none or auto'); o.oracle = v === 'auto' ? '' : v; }
      if ('odi' in it) { const v = s(it.odi, 10).toLowerCase(); if (v && !['yes', 'none', 'auto'].includes(v)) throw bad('odi must be yes, none or auto'); o.odi = v === 'auto' ? '' : v; }
      if ('windows' in it) { const v = s(it.windows, 10).toLowerCase(); if (v && !['std', 'dc', 'auto'].includes(v)) throw bad('windows must be std, dc or auto'); o.windows = v === 'auto' ? '' : v; }
      if ('notes' in it) o.notes = s(it.notes, 300);
      o.updated_by = who.user; o.updated_at = new Date(now()).toISOString();
      facts.put(o); saved.push(a.name || a.id);
    }
    audit({ by: who.user, role: who.role, ip: who.ip, action: 'core_licensing.facts', target: 'hosts', detail: { saved: saved.length, not_found: notFound.length } });
    return Object.assign(view(), { saved: saved.length, not_found: notFound });
  }
  function putEnt(b, who) {
    const product = s(b.product, 20);
    if (!PRODUCTS[product]) throw bad('product must be one of ' + Object.keys(PRODUCTS).join(', '));
    const q = Number(b.quantity); if (!Number.isFinite(q) || q < 0 || q > 1e6) throw bad('quantity must be a number');
    const expiry = s(b.expiry, 10); if (expiry && !/^\d{4}-\d{2}-\d{2}$/.test(expiry)) throw bad('expiry must be YYYY-MM-DD');
    const cur = b.id ? ents.get(String(b.id)) : null;
    const o = Object.assign({}, cur || { id: 'cle_' + crypto.randomBytes(5).toString('hex'), created_by: who.user, created_at: new Date(now()).toISOString() },
      { product, quantity: Math.round(q), expiry: expiry || null, contract: s(b.contract, 120), notes: s(b.notes, 300), updated_by: who.user, updated_at: new Date(now()).toISOString() });
    ents.put(o);
    audit({ by: who.user, role: who.role, ip: who.ip, action: cur ? 'core_licensing.entitlement.update' : 'core_licensing.entitlement.create', target: o.id, detail: { product, quantity: o.quantity, expiry: o.expiry } });
    return Object.assign(view(), { entitlement: o });
  }
  function delEnt(id, who) {
    const cur = ents.get(String(id || '')); if (!cur) throw bad('entitlement not found', 404);
    ents.remove(cur.id);
    audit({ by: who.user, role: who.role, ip: who.ip, action: 'core_licensing.entitlement.delete', target: cur.id, detail: { product: cur.product, quantity: cur.quantity } });
    return view();
  }
  // the page's view with the rules run in Python (pyengine/core_licensing_rules.py, step 6e): the same inputs view() reads,
  // only the fields the rules use. A missing or failing Python, or core_licensing.engine = "node" → view() above.
  const py = ((app.config && app.config.core_licensing) || {}).engine === 'node' ? null
    : (() => { try { return require('./pyengine').createPyEngine({ python: ((app.config && app.config.discovery) || {}).python_bin || undefined, timeoutMs: 120000 }); } catch (e) { return null; } })();
  const pick = (o, ks) => { const r = {}; for (const k of ks) if (o[k] !== undefined) r[k] = o[k]; return r; };
  function inputs() {
    const cap = app.addons && app.addons.virtCapacity ? (() => { try { return app.addons.virtCapacity.report(); } catch (e) { return null; } })() : null;
    return {
      settings: settings(), now: now(),
      assets: assets.all((a) => !CLOSED[a.status]).map((a) => Object.assign(pick(a, ['id', 'name', 'asset_tag', 'site', 'os', 'cpu', 'type', 'tags', 'status']),
        Array.isArray(a.software) ? { software: a.software.map((x) => (x && typeof x === 'object' ? pick(x, ['publisher', 'name']) : x)) } : {})),
      facts: facts.all(), runs_on: rels.all((x) => x.type === 'runs_on').map((r) => ({ from: r.from, to: r.to })), entitlements: ents.all(),
      capacity: cap ? { platforms: (cap.platforms || []).map((p) => ({ label: p.label, error: p.error })) } : null,
    };
  }
  async function viewAuto() {
    if (py) {
      const r = await py.call('rules.core_licensing', inputs());
      if (r && Array.isArray(r.summary)) return r;
    }
    return view();
  }
  return { view, viewAuto, inputs, putFacts, putEnt, delEnt, putSettings, settings };
}

function registerCoreLicensing(srv, app, opts) {
  const C = createCoreLicensing(app);
  (app.addons = app.addons || {}).coreLicensing = C;
  srv.route('GET', '/core-licensing', (ctx) => { ctx.need('operator'); return C.viewAuto(); });
  srv.route('POST', '/core-licensing/hosts', (ctx) => { ctx.need('operator'); return C.putFacts(ctx.body || {}, ctx.who); });
  srv.route('POST', '/core-licensing/entitlements/:id/delete', (ctx) => { ctx.need('admin'); return C.delEnt(ctx.params.id, ctx.who); });
  srv.route('POST', '/core-licensing/entitlements', (ctx) => { ctx.need('admin'); return C.putEnt(ctx.body || {}, ctx.who); });
  srv.route('PUT', '/core-licensing/settings', (ctx) => { ctx.need('admin'); return C.putSettings(ctx.body || {}, ctx.who); });
  // Databases -> Oracle Licence Inventory: core factor table matching + the monitored databases' editions (same install unit)
  try { require('./oracle-licences').registerOracleLicences(srv, app, { coreLicensing: C, noTimer: opts && opts.noTimer }); }
  catch (e) { if (e.code !== 'MODULE_NOT_FOUND') throw e; (app.log || { warn() {} }).warn('core-licensing: oracle-licences.js not installed - Oracle Licence Inventory unavailable'); }
  return C;
}

module.exports = { createCoreLicensing, registerCoreLicensing, parseCores, WIN_SERVER, DEFAULTS, PRODUCTS };
