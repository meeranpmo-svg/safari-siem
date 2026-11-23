// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const { guardOf } = require('./errors');
// Approved switches, routers and firewalls → the AI Network Engineer (SIEM netops inventory). Once a network device is
// in IT Asset Management (approved from Asset Discovery or added by hand) it is added to the AI Network Engineer's
// device list with its vendor family, management IP, site and role, so reachability (ping) monitoring starts right away.
//   GET  /netops-sync          {settings, last, pending[], sent[]}       operator
//   POST /netops-sync/run      send now                                   admin
//   PUT  /netops-sync/settings {auto: true|false}                         admin
// Runs every 5 minutes when auto is on (default). A device already in the AI Network Engineer (same IP) is not added
// twice; when its name or site is changed here, that change is sent (only those two fields - the network team's vendor,
// role, polling and credentials stay as they set them). A device the network team removed there is not sent again.
// Which network devices are sent: type "network" with an IP (the management IP, else the address discovery saw), unless
// discovery classed it as something that is not a network device (printer, phone, server …); a discovery class of
// "unknown" does not block it. A network-looking asset that is NOT sent is listed with the reason (GET → skipped[]). Only inventory facts are sent - SNMP / API credentials are
// never copied between services (they stay write-only): set them once in AI Network Engineer > device > Credentials
// (SNMP polling then adds CPU, memory, interfaces, neighbours). Uses the same SIEM link as Connect to SIEM
// (config discovery.siem: base_url, prefix, secret_file).
// The other way (same run): every device in the AI Network Engineer is reported to Asset Discovery as a sighting (method
// "netops": name, IP, vendor, and the model / serial / IOS version the device itself reported over its API or "show
// version / show inventory"). A device already linked to an asset fills that asset's facts through the normal merge rules
// (a field edited by hand is locked and stays); an unlinked device with the same IP as exactly one active asset is linked
// to it; any other device is added to IT Asset Management straight away (auto_add, default on; an administrator can turn it
// off, then such devices wait in Asset Discovery for approval).
// Self-contained (stored collections), added to an existing install with one registration line (install/add-netops-sync.sh).
const fs = require('node:fs');

const CLOSED = { retired: 1, disposed: 1 };
const bad = (msg, status = 400) => Object.assign(new Error(msg), { status });
const low = (v) => String(v || '').toLowerCase();
const SYS = { user: 'system:itam-netops-sync', role: 'admin' };

const NOT_NET_CLASS = ['printer', 'phone', 'workstation', 'server', 'vm', 'cloud', 'storage'];
const NET_MODEL = /^(WS-C|C9\d{3}|C8\d{3}|C1\d{3}|ISR|ASR|N\dK|N\d{2}K|ASA|FPR|AIR-|C9800|CBS\d|SG\d{3}|IE-\d|FG-|FortiGate|PA-\d|FortiSwitch|FS-\d)/i;
/* why a network-looking asset is (not) sent: {ok, why}. ipOf: management IP, else the linked discovery device's IP */
function netCheck(a, ipOf) {
  if (!a || CLOSED[a.status]) return { ok: false, why: 'retired' };
  const t = (a.tags || []).map(low), cls = low(a.discovery && a.discovery.class);
  const looks = a.type === 'network' || NET_MODEL.test(a.model || '') || t.some((x) => ['switch', 'router', 'firewall'].includes(x));
  if (!looks) return { ok: false, why: 'not a network device' };
  if (a.type !== 'network') return { ok: false, why: `type is "${a.type}" - set the type to Network to monitor it in the AI Network Engineer` };
  if (cls && NOT_NET_CLASS.includes(cls) && !t.some((x) => ['switch', 'router', 'firewall', 'core', 'distribution', 'access'].includes(x))) return { ok: false, why: `discovery classed it as ${cls} - add a tag switch / router / firewall if it is one` };
  if (!(ipOf ? ipOf(a) : a.mgmt_ip)) return { ok: false, why: 'no IP address - add the management IP' };
  return { ok: true };
}
function isNetDevice(a) { return netCheck(a).ok; }
function vendorOf(a) {
  const t = low([a.vendor, a.model, a.os, a.discovery && a.discovery.vendor, a.discovery && a.discovery.os].join(' ')), fw = (a.tags || []).map(low).includes('firewall') || low(a.discovery && a.discovery.class) === 'firewall';
  if (/forti/.test(t)) return 'fortigate';
  if (/palo ?alto|pan-os/.test(t)) return 'paloalto';
  if (/cisco/.test(t)) return fw || /\basa\b|firepower|ftd/.test(t) ? 'cisco-asa' : 'cisco-ios';
  return 'other';
}
function roleOf(a, vendor) {
  const t = (a.tags || []).map(low), cls = low(a.discovery && a.discovery.class);
  for (const r of ['core', 'distribution', 'access']) if (t.includes(r)) return r;
  if (t.includes('firewall') || cls === 'firewall' || /fortigate|paloalto|asa/.test(vendor)) return 'firewall';
  if (t.includes('router') || cls === 'router') return 'branch-router';
  return 'other';
}
const VENDOR_NAME = { 'cisco-ios': 'Cisco', 'cisco-asa': 'Cisco', fortigate: 'Fortinet', paloalto: 'Palo Alto Networks', genian: 'Genians', edgeconnect: 'HPE Aruba' };
function discType(nd) {
  if (/fortigate|paloalto|cisco-asa/.test(nd.vendor) || nd.role === 'firewall') return 'firewall';
  if (/router|wan-edge|sdwan/.test(nd.role || '') || nd.vendor === 'edgeconnect') return 'router';
  if (/core|distribution|access|switch/.test(nd.role || '') || nd.vendor === 'cisco-ios') return 'switch';
  return '';
}
function idOf(a, taken) {
  let base = low(a.name || a.mgmt_ip).split('.')[0].replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 34);
  if (base.length < 2) base = 'dev-' + low(a.mgmt_ip).replace(/[^0-9]+/g, '-');
  if (!/^[a-z0-9]/.test(base)) base = 'd' + base;
  let id = base.slice(0, 40), n = 2;
  while (taken.has(id)) id = `${base.slice(0, 36)}-${n++}`;
  return id;
}

function createNetopsSync(app, opts = {}) {
  const { store } = app;
  const col = store.collection('netops_sync'), conf = store.collection('netops_sync_settings'), assets = store.collection('assets');
  const sc = ((app.config && app.config.discovery) || {}).siem || {};
  const base = String(sc.base_url || 'http://127.0.0.1:9120').replace(/\/+$/, ''), prefix = sc.prefix || '/api/soc';
  const request = opts.request || require('./discovery/httpc').request;
  const read = opts.readFile || ((p) => fs.readFileSync(p, 'utf8'));
  const audit = (e) => { if (app.audit) app.audit(e); };
  const now = opts.now || Date.now;
  let last = null, running = null;

  // auto_add (default on): a device the network team registered in the AI Network Engineer was already added by a person, so
  // it goes straight into the register (and from there to Cisco coverage, monitoring, log collection) instead of waiting
  // for a second approval. Only an explicit choice by a person turns it off: a stored "false" without auto_add_by is the
  // old default that every settings save used to write, and no longer counts.
  function settings() {
    const v = Object.assign({ auto: true, pull: true, auto_add: true }, (conf.get('settings') || {}).values || {});
    if (v.auto_add === false && !v.auto_add_by) v.auto_add = true;
    return v;
  }
  function secret() {
    if (!sc.secret_file) throw bad('SIEM link not configured (discovery.siem.secret_file)', 503);
    let v; try { v = String(read(sc.secret_file)).trim(); } catch (e) { throw bad(`SIEM proxy secret file not readable (${e.code || 'error'})`, 503); }
    if (v.startsWith('{')) { try { v = String(JSON.parse(v).proxy_secret || ''); } catch { v = ''; } }
    if (v.length < 16) throw bad('SIEM proxy secret missing', 503);
    return v;
  }
  async function call(method, path, who, body) {
    const headers = { 'X-Sentra-Proxy-Secret': secret(), 'X-Auth-User': String(who.user).slice(0, 200), 'X-Auth-Role': 'admin', Accept: 'application/json' };
    if (body) headers['Content-Type'] = 'application/json';
    let r; try { r = await request(base + prefix + path, { method, headers, body: body ? JSON.stringify(body) : null, timeoutMs: 20000 }); } catch (e) { throw bad(`SIEM not reachable (${e.code || e.message || 'error'})`, 502); }
    if (r.status === 401 || r.status === 403) throw bad('the SIEM refused the platform credentials (check the proxy secret file)', 502);
    return r;
  }
  const devs = store.collection('disc_devices');
  function ipOf(a) { if (a.mgmt_ip) return a.mgmt_ip; const d = devs.all((x) => x.asset_id === a.id && x.ip)[0]; return d ? d.ip : ''; }
  function candidates() { return assets.all((a) => netCheck(a, ipOf).ok).map((a) => Object.assign({}, a, { mgmt_ip: ipOf(a) })); }
  function skipped() { return assets.all((a) => !CLOSED[a.status]).map((a) => ({ a, r: netCheck(a, ipOf) })).filter((x) => !x.r.ok && x.r.why !== 'not a network device').map((x) => ({ asset_id: x.a.id, name: x.a.name, type: x.a.type, vendor: x.a.vendor || '', model: x.a.model || '', why: x.r.why })); }

  async function run(who = SYS) {
    if (running) return running;
    running = (async () => {
      const at = new Date(now()).toISOString(), out = { at, by: who.user, ok: true, added: [], updated: [], already: 0, skipped_removed: 0, failed: [] };
      try {
        const r = await call('GET', '/netops/devices', who);
        if (r.status !== 200) throw bad(`SIEM: HTTP ${r.status}`, 502);
        const list = (r.json && (r.json.items || r.json.devices)) || [];
        const byIp = new Map(list.map((d) => [d.ip, d])), taken = new Set(list.map((d) => d.id));
        for (const a of candidates()) {
          const rec = col.get(a.id);
          if (byIp.has(a.mgmt_ip)) {
            out.already++; const d = byIp.get(a.mgmt_ip);
            if (!rec) col.put({ id: a.id, device_id: d.id, ip: a.mgmt_ip, state: 'present', at });
            // name / site edited in IT Asset Management → the same two fields in the AI Network Engineer (nothing else)
            const name = String(a.name || a.mgmt_ip).slice(0, 80), site = a.site || '';
            const upd = {}; if (d.id && a.name && d.name !== name) upd.name = name; if (d.id && site && d.site !== site) upd.site = site.slice(0, 60);
            if (Object.keys(upd).length) {
              const p = await call('POST', '/netops/devices', who, Object.assign({ id: d.id }, upd));
              if (p.status >= 300) out.failed.push({ asset_id: a.id, name: a.name, ip: a.mgmt_ip, error: 'update: ' + ((p.json && (p.json.error || (p.json.errors || []).join('; '))) || `HTTP ${p.status}`) });
              else { out.updated.push({ asset_id: a.id, device_id: d.id, changed: upd }); Object.assign(d, upd); }
            }
            continue;
          }
          if (rec && rec.state === 'sent') { out.skipped_removed++; continue; }   // removed in the AI Network Engineer on purpose
          const vendor = vendorOf(a), id = idOf(a, taken);
          const body = { id, name: String(a.name || a.mgmt_ip).slice(0, 80), vendor, ip: a.mgmt_ip, site: a.site || 'Unassigned', role: roleOf(a, vendor), criticality: 2, poll: { ping: true, snmp: false, api: false },
            notes: `from IT Asset Management ${a.id}${a.model ? ' · ' + a.model : ''}`.slice(0, 500) };
          const p = await call('POST', '/netops/devices', who, body);
          if (p.status >= 300) { out.failed.push({ asset_id: a.id, name: a.name, ip: a.mgmt_ip, error: (p.json && (p.json.error || (p.json.errors || []).join('; '))) || `HTTP ${p.status}` }); continue; }
          taken.add(id); byIp.set(a.mgmt_ip, body);
          col.put({ id: a.id, device_id: id, ip: a.mgmt_ip, vendor, state: 'sent', at });
          out.added.push({ asset_id: a.id, device_id: id, name: body.name, ip: a.mgmt_ip, vendor, role: body.role });
        }
        if (settings().pull) out.pulled = pull(list, at);
      } catch (e) { out.ok = false; out.error = e.message; }
      if (out.added.length || out.updated.length || out.failed.length || who !== SYS) audit({ by: who.user, role: who.role, ip: who.ip, action: 'netops_sync.run', target: 'netops', detail: { added: out.added.length, updated: out.updated.length, failed: out.failed.length, error: out.error || null } });
      last = out; running = null;
      return out;
    })();
    return running;
  }
  /* AI Network Engineer → Asset Discovery → assets (facts the devices reported) */
  function pull(list, at) {
    const D = app.discovery, res = { seen: 0, facts_updated: 0, linked: 0, added: 0, waiting: 0, errors: 0 };
    if (!D || !D.devices) return res;
    for (const nd of list) {
      if (!nd || !nd.ip) continue;
      const sys = (nd.last && nd.last.system) || {}, cf = nd.cli_facts || {};
      const serial = (Array.isArray(cf.serials) && cf.serials[0]) || sys.serial || '', model = cf.model || sys.model || '';
      const ver = cf.version || sys.version || '', vname = VENDOR_NAME[nd.vendor] || '';
      const os = ver ? ((/cisco/.test(nd.vendor) ? (nd.vendor === 'cisco-asa' ? 'Cisco ASA ' : 'Cisco IOS ') : nd.vendor === 'fortigate' ? 'FortiOS ' : nd.vendor === 'paloalto' ? 'PAN-OS ' : '') + ver).trim() : '';
      try {
        const d = D.devices.observe({ method: 'netops', hostname: low(cf.hostname || sys.name || nd.name || ''), ips: [nd.ip], serial: serial || undefined, model: model || undefined, os: os || undefined, vendor: vname || undefined, uid: 'netops:' + nd.id,
          extra: { netops: { device_id: nd.id, vendor: nd.vendor, role: nd.role || '', site: nd.site || '', serials: Array.isArray(cf.serials) ? cf.serials.slice(0, 12) : [], facts_at: cf.at || null } } }, { site: nd.site && nd.site !== 'Unassigned' ? nd.site : null, scope_id: null, at });
        if (!d) continue;
        res.seen++;
        const t = discType(nd), why = 'AI Network Engineer device (' + nd.vendor + ')';
        devs.patch(d.id, (x) => {
          // what the device reports about itself outranks scans (snmp 6, sweep 3); only vCenter / Nutanix / CUCM (9) rank higher
          x.rank = x.rank || {};
          for (const [k, v] of [['serial', serial], ['model', model], ['os', os]]) if (v && (!x[k] || (x.rank[k] || 0) <= 8)) { x[k] = v; x.rank[k] = 8; }
          if (t && (!x.type || x.type === 'unknown')) x.type = t; if (vname && !x.vendor) x.vendor = vname; x.confidence = Math.max(x.confidence || 0, 90); x.reasons = [why].concat((x.reasons || []).filter((r) => r !== why)).slice(0, 12); return x; });
        const cur = devs.get(d.id);
        if (cur.asset_id) {
          const f = {}; if (serial) f.serial = serial; if (model) f.model = model; if (os) f.os = os; if (vname) f.vendor = vname;
          if (Object.keys(f).length) { const r = app.assets.upsert(f, 'discovery', { source_id: cur.id, at }, { forceAssetId: cur.asset_id }); if (r && r.changed && r.changed.length) res.facts_updated++; }
          continue;
        }
        const same = assets.all((a) => !CLOSED[a.status] && a.mgmt_ip === nd.ip);
        if (same.length === 1) { D.merge(cur.id, same[0].id, SYS); res.linked++; continue; }
        if (settings().auto_add && !same.length && cur.status === 'new') { D.approve(cur.id, SYS); res.added++; continue; }
        res.waiting++;
      } catch (e) { res.errors++; }
    }
    return res;
  }
  function view() {
    const sent = col.all(), seen = new Set(sent.map((s) => s.id));
    return { settings: settings(), last, sent, pending: candidates().filter((a) => !seen.has(a.id)).map((a) => ({ asset_id: a.id, name: a.name, ip: a.mgmt_ip, vendor: vendorOf(a), site: a.site || '' })), skipped: skipped() };
  }
  function putSettings(b, who) {
    const v = Object.assign(settings(), 'auto' in b ? { auto: b.auto === true } : {}, 'pull' in b ? { pull: b.pull === true } : {}, 'auto_add' in b ? { auto_add: b.auto_add === true, auto_add_by: who.user, auto_add_at: new Date(now()).toISOString() } : {});
    conf.put({ id: 'settings', values: v, updated_by: who.user, updated_at: new Date(now()).toISOString() });
    audit({ by: who.user, role: who.role, ip: who.ip, action: 'netops_sync.settings', target: 'settings', detail: v });
    return view();
  }
  function tick() { return settings().auto ? run() : undefined; }   // a failure reaches the job register (engine/errors.js)
  return { run, view, putSettings, tick: guardOf(app, 'netops-sync.tick', tick),  /* a direct call (Sync now, tests) can never reject unhandled */ vendorOf, roleOf, idOf, candidates, skipped, ipOf };
}

function registerNetopsSync(srv, app) {
  const N = createNetopsSync(app);
  srv.route('GET', '/netops-sync', (ctx) => { ctx.need('operator'); return N.view(); });
  srv.route('POST', '/netops-sync/run', async (ctx) => { ctx.need('admin'); return N.run(ctx.who); });
  srv.route('PUT', '/netops-sync/settings', (ctx) => { ctx.need('admin'); return N.putSettings(ctx.body || {}, ctx.who); });
  const t1 = setTimeout(guardOf(app, 'netops-sync.tick', N.tick), 60000), t2 = setInterval(guardOf(app, 'netops-sync.tick', N.tick), 5 * 60000);
  if (t1.unref) t1.unref(); if (t2.unref) t2.unref();
  (app.addons = app.addons || {}).netopsSync = N;   // reachable from Sync all now (engine/reconcile.js)
  return N;
}

module.exports = { createNetopsSync, registerNetopsSync, isNetDevice, netCheck };
