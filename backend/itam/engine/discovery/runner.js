// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Executes ONE discovery run for one scope. Passive methods first (systems of record + this server's ARP cache), then
// the active sweep / SNMP — only when the safety gate is open and the scope's scan window allows it — under the
// scope's rate limit (hosts per second, token bucket) and concurrency limit. A run can be cancelled at any time; the
// flag is checked between hosts and between methods.
//   execute({run, scope, allowed, ctx}) → updates run.stats / run.progress in place; resolves when done.
//   ctx = {vault, devices, deps, settings, log, isCancelled(), onProgress()}
const dns = require('node:dns');
const ip4 = require('./ipv4');
const sched = require('./schedule');
const sweep = require('./methods/sweep');
const svcM = require('./methods/services');
const loginM = require('./methods/login');
const PM = (() => { try { return require('./py-methods'); } catch (e) { return { wrap: (n, m) => m, configure() {} }; } })();   // inventory sources answered by Python (docs/PYTHON-MIGRATION.md step 5a); a missing bridge never stops the engine
const snmpM = PM.wrapSnmp ? PM.wrapSnmp(require('./methods/snmp')) : require('./methods/snmp');
const adM = PM.wrap('ad', require('./methods/ad'));
const vcM = PM.wrap('vcenter', require('./methods/vcenter'));
const ntxM = PM.wrap('nutanix', require('./methods/nutanix'));
const cucmM = PM.wrap('cucm', require('./methods/cucm'));
const azM = PM.wrap('azure', require('./methods/azure'));
const awsM = PM.wrap('aws', require('./methods/aws'));

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function tokenBucket(perSec) {
  const interval = 1000 / Math.max(1, perSec);
  let next = 0;
  return async function take() {
    const now = Date.now();
    const at = Math.max(now, next);
    next = at + interval;
    if (at > now) await sleep(at - now);
  };
}
async function pool(items, n, fn, stop) {
  let i = 0;
  const workers = Array.from({ length: Math.max(1, Math.min(n, items.length)) }, async () => {
    while (i < items.length && !stop()) { const it = items[i++]; await fn(it); }
  });
  await Promise.all(workers);
}

async function withCred(vault, id, fn) {
  const c = vault.open(id);
  try { return await fn(c); } finally { c.release(); }
}

// Names from AD / vCenter → IPv4: the server's own resolver first, then the configured DNS servers
// (discovery.dns_servers) or else the domain controllers of the AD credential, which are the domain's DNS servers.
function makeResolver(ctx, extra) {
  const cfg = (ctx.config && ctx.config.discovery) || {};
  if (cfg.ad_resolve_dns === false) return null;
  const servers = [...new Set([].concat(cfg.dns_servers || [], extra || []).filter((x) => ip4.parseIp(String(x || '')) !== null))];
  let r2 = null;
  if (servers.length) { try { r2 = new dns.promises.Resolver({ timeout: 3000, tries: 1 }); r2.setServers(servers); } catch { r2 = null; } }
  const cache = new Map();
  return async (h) => {
    if (cache.has(h)) { const v = cache.get(h); if (!v) throw new Error('unresolved'); return v; }
    let ip = null;
    try { ip = (await dns.promises.lookup(h, { family: 4 })).address; } catch { ip = null; }
    if (!ip && r2) { try { ip = (await r2.resolve4(h))[0] || null; } catch { ip = null; } }
    cache.set(h, ip);
    if (!ip) throw new Error('unresolved');
    return ip;
  };
}
function credDnsServers(c) {
  const t = (c && c.target) || {}, out = [];
  if (t.ip) out.push(t.ip);
  for (const u of [].concat(t.servers || [])) { const m = /^ldaps?:\/\/([^:/]+)/i.exec(String(u)); if (m && ip4.parseIp(m[1]) !== null) out.push(m[1]); }
  return out;
}

async function execute({ run, scope, allowed, ctx }) {
  const { vault, devices, deps = {}, settings, log } = ctx;
  const stop = () => ctx.isCancelled();
  const base = { scope_id: scope.id, site: scope.site, vlan: scope.vlan, run_id: run.id };
  const obs = (o) => { const d = devices.observe(o, Object.assign({ at: new Date().toISOString() }, base)); if (d) run.seen.add(d.id); return d; };
  const stat = (m, s) => { run.stats[m] = Object.assign(run.stats[m] || {}, s); ctx.onProgress(); };
  const m = scope.methods;
  const cloudOpt = (k) => Object.assign({}, (ctx.config.discovery || {})[k] || {}, deps.request ? { request: deps.request } : {});

  // ---------------- passive ----------------
  for (const method of ['ad', 'vcenter', 'nutanix', 'cucm', 'azure', 'aws', 'arp', 'hyperv']) {
    if (stop() || !allowed.includes(method)) continue;
    const t0 = Date.now();
    try {
      if (method === 'ad') {
        let dcs = [];
        const r = await withCred(vault, m.ad.credential_id, (c) => { dcs = credDnsServers(c); return adM.collect(c, { ca: deps.ldapCa }); });
        if (!r.ok) { stat('ad', { ok: false, error_class: r.error_class }); continue; }
        const resolve = deps.resolve || makeResolver(ctx, dcs);
        if (!ctx.resolve && resolve) ctx.resolve = resolve;   // reused for vCenter host names in this run
        let n = 0, resolved = 0;
        for (const c of r.computers) {
          if (stop()) break;
          let ip = null;
          if (resolve && c.fqdn && c.enabled) { try { ip = await resolve(c.fqdn); resolved++; } catch { ip = null; } }
          // user PCs and servers usually sit outside the scanned ranges: keep their address (marked) instead of dropping it
          const outside = !!(ip && scope.targets.length && !ip4.contains(scope.targets, ip));
          if (ip && ip4.contains(scope.exclusions || [], ip)) ip = null;
          obs({ method: 'ad', hostname: c.name, fqdn: c.fqdn, ip, os: [c.os, c.os_version].filter(Boolean).join(' '), uid: `ad:${c.dn}`, extra: { ad: { ou: c.ou, enabled: c.enabled, last_logon: c.last_logon, is_dc: c.is_dc, os: c.os, ip_outside_scope: outside || undefined } } });
          n++;
        }
        stat('ad', { ok: true, seen: n, resolved, ms: Date.now() - t0 });
      } else if (method === 'vcenter') {
        const r = await withCred(vault, m.vcenter.credential_id, (c) => vcM.collect(c, { request: deps.request }));
        if (!r.ok) { stat('vcenter', { ok: false, error_class: r.error_class }); continue; }
        const vres = deps.resolve || ctx.resolve || makeResolver(ctx, []);
        for (const h of r.hosts) {   // physical ESXi hosts: vCenter knows them by name - resolve it to an address
          // the management VMkernel address vCenter reported; else the name when it is an address; else DNS
          let ip = h.ip && ip4.parseIp(h.ip) !== null ? h.ip : ip4.parseIp(h.name) !== null ? h.name : null, from = ip ? 'vcenter' : null;
          if (!ip && vres && /\./.test(h.name)) { try { ip = await vres(h.name); if (ip) from = 'dns'; } catch { ip = null; } }
          obs({ method: 'vcenter', hostname: ip4.parseIp(h.name) === null ? h.name : '', ip, uid: `vc-host:${h.id}`, os: 'VMware ESXi', extra: { vcenter: { kind: 'host', state: h.state, vmk: h.vmk || null, ip_from: from } } });
        }
        for (const v of r.vms) obs({ method: 'vcenter', hostname: v.hostname || v.name, ips: v.ips, macs: v.macs, os: v.guest_os, uid: `vc:${v.uuid || v.id}`, extra: { vcenter: { kind: 'vm', host: v.host_name, power_state: v.power_state, uuid: v.uuid, name: v.name } } });
        stat('vcenter', { ok: true, seen: r.hosts.length + r.vms.length, hosts: r.hosts.length, vms: r.vms.length, ms: Date.now() - t0 });
      } else if (method === 'nutanix') {
        const r = await withCred(vault, m.nutanix.credential_id, (c) => ntxM.collect(c, { request: deps.request }));
        if (!r.ok) { stat('nutanix', { ok: false, error_class: r.error_class }); continue; }
        for (const h of r.hosts) obs({ method: 'nutanix', hostname: h.name, ip: h.ip, serial: h.serial, model: h.model, vendor: 'Nutanix', os: h.hypervisor || 'Nutanix AHV', uid: `ntnx-host:${h.id}`, extra: { nutanix: { kind: 'host', cluster: h.cluster, cvm_ip: h.cvm_ip, ipmi_ip: h.ipmi_ip, sockets: h.sockets, cores: h.cores, cores_per_socket: h.cores_per_socket, cpu_model: h.cpu_model } } });
        for (const v of r.vms) obs({ method: 'nutanix', hostname: v.name, ips: v.ips, macs: v.macs, uid: `ntnx:${v.id}`, extra: { nutanix: { kind: 'vm', host: v.host_name, cluster: v.cluster, power_state: v.power_state, vcpus: v.vcpus, memory_mb: v.memory_mb, name: v.name } } });
        stat('nutanix', { ok: true, seen: r.hosts.length + r.vms.length, hosts: r.hosts.length, vms: r.vms.length, clusters: (r.clusters || []).length, api: r.api, ms: Date.now() - t0 });
      } else if (method === 'cucm') {
        const r = await withCred(vault, m.cucm.credential_id, (c) => cucmM.collect(c, { request: deps.request }));
        if (!r.ok) { stat('cucm', { ok: false, error_class: r.error_class }); continue; }
        for (const p of r.phones) obs({ method: 'cucm', mac: p.mac, ip: p.ip, hostname: p.name.toLowerCase(), model: p.model, vendor: 'Cisco', uid: `cucm:${p.name.toLowerCase()}`, extra: { cucm: { name: p.name, model: p.model, device_pool: p.device_pool, status: p.status, description: p.description, protocol: p.protocol } } });
        stat('cucm', { ok: true, seen: r.phones.length, registered: r.phones.filter((p) => p.status === 'Registered').length, ms: Date.now() - t0 });
      } else if (method === 'azure') {
        const r = await withCred(vault, m.azure.credential_id, (c) => azM.collect(c, cloudOpt('azure')));
        if (!r.ok) { stat('azure', { ok: false, error_class: r.error_class }); continue; }
        for (const v of r.vms) obs({ method: 'azure', ips: v.ips, macs: v.macs, hostname: v.name, os: v.os_type, uid: `azure:${v.id}`, extra: { cloud: { provider: 'Azure', name: v.name, location: v.location, resource_group: v.resource_group, subscription: v.subscription, size: v.size, power: v.power } } });
        stat('azure', { ok: true, seen: r.vms.length, ms: Date.now() - t0 });
      } else if (method === 'aws') {
        const r = await withCred(vault, m.aws.credential_id, (c) => awsM.collect(c, cloudOpt('aws')));
        if (!r.ok) { stat('aws', { ok: false, error_class: r.error_class }); continue; }
        for (const i of r.instances) obs({ method: 'aws', ip: i.private_ip, macs: i.macs, hostname: i.name || (i.private_dns || '').split('.')[0], os: i.platform, uid: `aws:${i.id}`, extra: { cloud: { provider: 'AWS', name: i.name, instance_id: i.id, type: i.type, state: i.state, region: i.region, az: i.az, account: i.account, public_ip: i.public_ip } } });
        stat('aws', { ok: true, seen: r.instances.length, ms: Date.now() - t0 });
      } else if (method === 'arp') {
        const rows = sweep.arp({ readFile: deps.readFile, arp_path: ctx.config.discovery && ctx.config.discovery.arp_path });
        let n = 0;
        for (const r of rows) if (ip4.contains(scope.targets, r.ip) && !ip4.contains(scope.exclusions, r.ip)) { obs({ method: 'arp', ip: r.ip, mac: r.mac }); n++; }
        stat('arp', { ok: true, seen: n, ms: Date.now() - t0 });
      } else if (method === 'hyperv') {
        stat('hyperv', { ok: true, push_only: true, note: 'Hyper-V inventory arrives as reports from the Windows agent / relay' });
      }
    } catch (e) {
      stat(method, { ok: false, error_class: e.code === 'arp_unavailable' ? 'unavailable' : (e.status === 503 ? 'vault' : 'error') });
      log.warn('discovery: method failed', { run: run.id, method, err: e.message });
    }
  }

  // ---------------- active (safety gate already checked by the caller) ----------------
  const active = allowed.filter((x) => x === 'sweep' || x === 'snmp' || x === 'db' || x === 'unix' || x === 'storage');
  if (!active.length || stop()) return;
  const hosts = ip4.expand(scope.targets, scope.exclusions, { max: (ctx.config.discovery && ctx.config.discovery.max_hosts_per_scope) || 4096 }).map(ip4.ipStr);
  run.progress = { hosts_total: hosts.length, hosts_done: 0, alive: 0, phase: 'ping', started_at: new Date().toISOString() };
  const take = tokenBucket(scope.rate.max_hosts_per_sec);
  const windowOk = () => sched.inWindow(scope.window, Date.now());
  const st = settings();
  const alive = new Map(); // ip → {open:[], snmp: credId|null}
  const arpSeen = new Map(); // ip → mac, from SNMP ARP tables
  // 1) ICMP batch
  if (allowed.includes('sweep') && m.sweep.icmp) {
    const t0 = Date.now();
    try {
      const chunk = Math.max(1, Math.min(64, scope.rate.max_hosts_per_sec));
      let up = 0;
      for (let i = 0; i < hosts.length && !stop(); i += chunk) {
        if (!windowOk()) { ctx.stopWindow(); break; }
        for (let k = 0; k < Math.min(chunk, hosts.length - i); k++) await take();
        const r = await sweep.icmp(hosts.slice(i, i + chunk), { mode: st.icmp_mode, fping_bin: ctx.config.discovery.fping_bin, ping_bin: ctx.config.discovery.ping_bin, timeout_ms: ctx.config.discovery.icmp_timeout_ms, exec: deps.exec });
        for (const ip of r) { alive.set(ip, alive.get(ip) || { open: [], snmp: null }); up++; }
      }
      stat('icmp', { ok: true, alive: up, ms: Date.now() - t0 }); run.progress.alive = up;
    } catch (e) { stat('icmp', { ok: false, error_class: e.code === 'icmp_unavailable' ? 'unavailable' : 'error' }); log.warn('discovery: ICMP unavailable', { run: run.id, err: e.message }); }
  }
  // 2) per host: TCP connect probes + SNMP sysDescr probe (UDP 161), concurrency-limited and rate-limited
  const snmpCreds = allowed.includes('snmp') ? (m.snmp.credential_ids || []) : [];
  const opened = new Map();
  try {
    for (const id of snmpCreds) opened.set(id, vault.open(id));
    const t0 = Date.now();
    let tcpUp = 0; let snmpUp = 0; let dbHosts = 0; let dbListeners = 0; let unixHosts = 0; let storHosts = 0;
    const loginTargets = new Map();   // ip → {db:[{engine,port}], ssh: port|null, storage} for the read-only login phase
    const lt = (ip) => { if (!loginTargets.has(ip)) loginTargets.set(ip, { ip, db: [], ssh: null, storage: false }); return loginTargets.get(ip); };
    const useDb = allowed.includes('db'), useUnix = allowed.includes('unix'), useStor = allowed.includes('storage'), probeOpt = { connect: deps.connect, banner: deps.banner, timeout_ms: ctx.config.discovery.tcp_timeout_ms };
    // database listeners on non-standard ports: the scope's list + the port written on each database login (so a login for
    // Oracle on 1600 is enough for discovery to find that listener)
    const dbExtraPorts = {};
    if (useDb) {
      const addPort = (e, port) => { const n = Number(port); if (!e || !Number.isInteger(n) || n < 1 || n > 65535) return; (dbExtraPorts[e] = dbExtraPorts[e] || []); if (!dbExtraPorts[e].includes(n)) dbExtraPorts[e].push(n); };
      for (const [e, list] of Object.entries((m.db && m.db.ports) || {})) for (const port of list || []) addPort(e, port);
      for (const id of (m.db && m.db.credential_ids) || []) { try { const c = vault && vault.get ? vault.get(id) : null; if (c && c.target) addPort(c.target.engine, c.target.port); } catch { /* unusable credential */ } }
    }
    run.progress.phase = 'probe';
    // per host the TCP ports and the SNMP probe run at the same time (not one after another): a silent address costs one
    // timeout (~0.8-1.5 s) instead of the sum of all of them (~7 s), so a /24 takes about a minute instead of several
    await pool(hosts, scope.rate.concurrency, async (ip) => {
      if (!windowOk()) { ctx.stopWindow(); return; }
      await take();
      if (stop()) return;
      const rec = alive.get(ip) || { open: [], snmp: null };
      let isUp = alive.has(ip);
      const tcpP = allowed.includes('sweep') && m.sweep.tcp_ports.length
        ? Promise.all(m.sweep.tcp_ports.map((port) => sweep.tcp(ip, [port], { connect: deps.connect, timeout_ms: ctx.config.discovery.tcp_timeout_ms })))
          .then((rs) => ({ alive: rs.some((r) => r.alive), open: [].concat(...rs.map((r) => r.open)).sort((a, b) => a - b) }))
        : Promise.resolve(null);
      const snmpP = (async () => {
        for (const id of snmpCreds) {
          const p = await snmpM.probe(ip, opened.get(id), { createSession: deps.createSession, timeout: ctx.config.discovery.snmp_timeout_ms });
          if (p.ok) return id;
        }
        return null;
      })();
      const dbP = useDb ? svcM.db(ip, m.db.engines, Object.assign({}, probeOpt, { extra_ports: dbExtraPorts })).catch(() => null) : Promise.resolve(null);
      const unixP = useUnix ? svcM.unix(ip, probeOpt).catch(() => null) : Promise.resolve(null);
      const storP = useStor ? svcM.storage(ip, probeOpt).catch(() => null) : Promise.resolve(null);
      const [r, sid, dr, ur, sr] = await Promise.all([tcpP, snmpP, dbP, unixP, storP]);
      if (sr && sr.alive) isUp = true;
      if (r && r.alive) { isUp = true; tcpUp++; rec.open = r.open; }
      if (sid) { rec.snmp = sid; isUp = true; snmpUp++; }
      if (dr && dr.alive) isUp = true;
      if (ur && ur.alive) isUp = true;
      if (isUp) {
        if (!alive.has(ip)) run.progress.alive++; alive.set(ip, rec);
        obs({ method: allowed.includes('sweep') ? 'sweep' : allowed.includes('snmp') ? 'snmp' : useDb ? 'db' : useUnix ? 'unix' : 'storage', ip, open_ports: rec.open });
        if (sr && sr.protocols.length) { if (sr.protocols.some((p) => p !== 'nfs')) storHosts++; obs({ method: 'storage', ip, open_ports: sr.open, extra: { storage: { protocols: sr.protocols } } }); }
        if (dr && dr.found.length) { dbHosts++; dbListeners += dr.found.length; obs({ method: 'db', ip, open_ports: dr.open, extra: { db: dr.found } }); }
        if (dr && dr.found.length) lt(ip).db = dr.found.map((f) => ({ engine: f.engine, port: f.port }));
        if (ur && ur.open.includes(22)) lt(ip).ssh = 22;
        if (sr && sr.protocols.some((p) => p !== 'nfs')) lt(ip).storage = true;
        if (ur && (ur.open.length || ur.ssh_banner)) { if (ur.hint) unixHosts++; obs({ method: 'unix', ip, open_ports: ur.open, os: ur.hint ? ur.hint.label : '', extra: { unix: { ssh_banner: ur.ssh_banner, ports: ur.open, os: ur.hint ? ur.hint.os : null, label: ur.hint ? ur.hint.label : null, confidence: ur.hint ? ur.hint.confidence : null } } }); }
      }
      run.progress.hosts_done++;
      if (run.progress.hosts_done % 8 === 0) ctx.onProgress();
    }, stop);
    if (allowed.includes('sweep')) stat('sweep', { ok: true, alive: alive.size, tcp_alive: tcpUp, hosts: hosts.length, ms: Date.now() - t0 });
    if (useDb) stat('db', { ok: true, seen: dbHosts, listeners: dbListeners, ms: Date.now() - t0 });
    if (useUnix) stat('unix', { ok: true, seen: unixHosts, ms: Date.now() - t0 });
    if (useStor) stat('storage', { ok: true, seen: storHosts, ms: Date.now() - t0 });
    // 2b) read-only logins with the scope's credentials (only where the probes found something; trusted keys only)
    const wantLogin = (useDb && (m.db.credential_ids || []).length) || (useUnix && m.unix.credential_id) || (useStor && m.storage.credential_id);
    if (wantLogin && loginTargets.size && !stop() && ctx.trust && ctx.invRun) {
      run.progress.phase = 'login'; ctx.onProgress();
      const mm = { db: useDb ? m.db : null, unix: useUnix ? m.unix : null, storage: useStor ? m.storage : null };
      await loginM.loginPhase({ targets: [...loginTargets.values()], m: mm, vault, trust: ctx.trust, run: ctx.invRun, request: deps.request, obs, stat, take, stop, pool, concurrency: scope.rate.concurrency, log });
    }
    // 3) SNMP collection on responders (system, interfaces, entity serial, LLDP / CDP neighbours)
    if (snmpCreds.length && !stop()) {
      const responders = [...alive.entries()].filter(([, r]) => r.snmp);
      run.progress.phase = 'snmp'; run.progress.snmp_total = responders.length; run.progress.snmp_done = 0; ctx.onProgress();
      let ok = 0;
      await pool(responders, Math.min(scope.rate.concurrency, 8), async ([ip, r]) => {
        if (!windowOk()) { ctx.stopWindow(); return; }
        await take();
        const c = await snmpM.collect(ip, opened.get(r.snmp), { createSession: deps.createSession, timeout: ctx.config.discovery.snmp_timeout_ms });
        run.progress.snmp_done++; ctx.onProgress();
        if (!c.ok) return;
        ok++;
        obs({ method: 'snmp', ip, mac: c.mac, macs: c.macs, serial: c.serial, model: c.model, sys: c.sys, neighbours: c.neighbours });
        for (const a of c.arp || []) arpSeen.set(a.ip, a.mac);
      }, stop);
      stat('snmp', { ok: true, responders: snmpUp, collected: ok, ms: Date.now() - t0 });
      // 4) MAC addresses from the routers' / switches' ARP tables: for every address in the scope and every device
      //    already known in it (e.g. AD computers on user subnets) that has no MAC yet
      if (arpSeen.size && !stop()) {
        const known = new Set();
        for (const d of (ctx.devices && ctx.devices.list ? ctx.devices.list((x) => x.scope_id === scope.id) : [])) for (const x of d.ips || []) known.add(x);
        let n = 0;
        for (const [aip, mac] of arpSeen) {
          if (ip4.contains(scope.exclusions || [], aip)) continue;
          if (!known.has(aip) && !ip4.contains(scope.targets, aip)) continue;
          obs({ method: 'arp', ip: aip, mac }); n++;
        }
        stat('arp_snmp', { ok: true, entries: arpSeen.size, matched: n, ms: Date.now() - t0 });
      }
    }
  } finally { for (const c of opened.values()) c.release(); }
}

module.exports = { execute, tokenBucket, pool };
