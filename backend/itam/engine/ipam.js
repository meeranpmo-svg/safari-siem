// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
const ZYB_ORG = require('./brand');
const { body } = require('./check');
const { createIntelKit, trend, robustZ } = require('./intel-kit');
const ip4 = require('./discovery/ipv4');
/*
 * IP Address Management ({P} = /api/itam; Network -> IP Address Management). The address plan people keep, checked against the
 * addresses the platform actually sees - nothing invented:
 *   subnets        registered by a person (CIDR, name, site, VLAN, gateway, DHCP range, purpose, owner). Observed addresses that
 *                  fall in no registered subnet are grouped by /24 and PROPOSED - a person registers them.
 *   observed       every address the platform holds: asset register management addresses, Asset Discovery devices (IP, MAC,
 *                  host name, last seen) - each with its sources
 *   reservations   an address held for a named purpose (and an optional end date); only a free address inside a registered
 *                  subnet, never in the DHCP range; released with a reason
 *   per subnet     usable size, used (observed or reserved, not double-counted), free, utilisation, DHCP range share, the next free
 *                  address (skipping network, broadcast, gateway, DHCP range, reserved and observed)
 *   findings       one address with two MACs (conflict), two assets on one address, an asset address not seen by discovery for
 *                  30 days (stale), an address seen but in no asset record (unknown device), a reservation seen in use by a
 *                  different host name, a reservation past its end date, a subnet at 80 % / 90 % - each with what to do
 *   learning       one snapshot a day of every subnet's used count: least-squares growth and days until full (5+ snapshots), and
 *                  a day whose new addresses are far from the usual (robust z on median / MAD, 7+ snapshots)
 *   GET  /ipam                         viewer    counts and subnet utilisation (+ addresses, findings, reservations for operators)
 *   POST /ipam/subnets                 operator  {id?, cidr, name, site?, vlan?, gateway?, dhcp_start?, dhcp_end?, purpose?, owner?}   audited
 *   POST /ipam/subnets/:id/retire      operator  {reason}                                                                          audited
 *   POST /ipam/reserve                 operator  {ip, name, purpose?, until?}                                                       audited
 *   POST /ipam/reservations/:id/release operator {reason}                                                                          audited
 *   POST /ipam/ask                     operator  read-only AI address-plan advisor (kit)
 */
const DAY = 86400000, STALE_DAYS = 30;
const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 };
const s = (v, n = 200) => String(v == null ? '' : v).replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, n);

function parseCidr(c) {
  const m = /^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/.exec(String(c || '').trim()); if (!m) return null;
  const base = ip4.parseIp(m[1]), bits = Number(m[2]); if (base === null || bits < 8 || bits > 30) return null;
  const net = (base & ip4.maskOf(bits)) >>> 0, size = 2 ** (32 - bits);
  return { cidr: ip4.ipStr(net) + '/' + bits, net, bits, first: net + 1, last: net + size - 2, broadcast: net + size - 1, usable: size - 2 };
}

function createIpam(app, opts = {}) {
  const store = app.store;
  const SUB = () => store.collection('ipam_subnets'), RES = () => store.collection('ipam_reservations');
  let K;
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role || '', ip: who.ip || '', action: 'ipam.' + action, target, detail }); };
  const nid = (col, pre) => { let n = col().all().length + 1, id; do { id = pre + String(n++).padStart(4, '0'); } while (col().get(id)); return id; };
  // every address the platform holds, with its sources
  function observed() {
    const M = new Map(), at = (ip) => { let r = M.get(ip); if (!r) { r = { ip, n: ip4.parseIp(ip), macs: new Set(), hosts: new Set(), assets: [], sources: new Set(), last_seen: null }; M.set(ip, r); } return r; };
    for (const a of store.collection('assets').all((x) => x.mgmt_ip && !['disposed', 'retired', 'lost', 'stolen'].includes(x.status))) {
      const r = at(String(a.mgmt_ip).trim()); r.assets.push({ id: a.id, name: a.name || a.asset_tag || a.id }); r.sources.add('asset register'); if (a.name) r.hosts.add(String(a.name).toLowerCase());
    }
    for (const d of store.collection('disc_devices').all((x) => x.status !== 'ignored')) for (const ip of d.ips || []) {
      const r = at(ip); r.sources.add('discovery'); for (const m of d.macs || []) r.macs.add(String(m).toLowerCase()); if (d.hostname) r.hosts.add(d.hostname);
      const t = Date.parse(d.last_seen); if (isFinite(t) && (!r.last_seen || t > r.last_seen)) r.last_seen = t;
    }
    return [...M.values()].filter((r) => r.n !== null).map((r) => Object.assign(r, { macs: [...r.macs], hosts: [...r.hosts], sources: [...r.sources] }));
  }
  function subnets() { return SUB().all((x) => !x.retired).map((x) => Object.assign({}, x, parseCidr(x.cidr))).filter((x) => x.net !== undefined); }
  function analyse() {
    const t = K.now(), S = subnets(), O = observed(), R = RES().all((x) => !x.released);
    const inSub = (n) => S.find((x) => n >= x.net && n <= x.broadcast) || null;
    const findings = [], F = (sev, kind, ref, title, fix) => findings.push({ severity: sev, kind, ref, title, fix });
    const rows = S.map((x) => {
      const ds = x.dhcp_start ? ip4.parseIp(x.dhcp_start) : null, de = x.dhcp_end ? ip4.parseIp(x.dhcp_end) : null, gw = x.gateway ? ip4.parseIp(x.gateway) : null;
      const used = new Set(), obs = O.filter((o) => o.n >= x.first && o.n <= x.last), res = R.filter((r) => { const n = ip4.parseIp(r.ip); return n >= x.first && n <= x.last; });
      for (const o of obs) used.add(o.n); for (const r of res) used.add(ip4.parseIp(r.ip)); if (gw) used.add(gw);
      const dhcp = ds !== null && de !== null ? de - ds + 1 : 0, dhcpUsed = ds !== null ? obs.filter((o) => o.n >= ds && o.n <= de).length : 0;
      let next = null; for (let n = x.first; n <= x.last && next === null; n++) if (!used.has(n) && !(ds !== null && n >= ds && n <= de)) next = ip4.ipStr(n);
      const pct = Math.round(used.size / x.usable * 1000) / 10;
      if (pct >= 90) F('high', 'full', x.id, x.name + ' (' + x.cidr + ') is ' + pct + ' % used', 'Plan a larger subnet or move devices; ' + (x.usable - used.size) + ' addresses left.');
      else if (pct >= 80) F('medium', 'full', x.id, x.name + ' (' + x.cidr + ') is ' + pct + ' % used', 'Review the addresses in use and reclaim stale ones before it fills.');
      if (dhcp && dhcpUsed / dhcp >= 0.9) F('medium', 'dhcp', x.id, x.name + ': the DHCP range is ' + Math.round(dhcpUsed / dhcp * 100) + ' % used', 'Widen the DHCP range or shorten the lease time.');
      return { id: x.id, cidr: x.cidr, name: x.name, site: x.site || '', vlan: x.vlan || null, gateway: x.gateway || '', purpose: x.purpose || '', owner: x.owner || '', dhcp_start: x.dhcp_start || '', dhcp_end: x.dhcp_end || '',
        usable: x.usable, used: used.size, free: x.usable - used.size, pct, observed: obs.length, reserved: res.length, dhcp_size: dhcp, dhcp_used: dhcpUsed, next_free: next };
    });
    const addrs = O.map((o) => {
      const sub = inSub(o.n), rv = R.find((r) => r.ip === o.ip) || null;
      if (o.macs.length > 1) F('high', 'conflict', o.ip, o.ip + ' is used by ' + o.macs.length + ' devices (' + o.macs.join(', ') + ')', 'An address conflict: give one device another address or a DHCP reservation, then rescan.');
      if (o.assets.length > 1) F('medium', 'duplicate', o.ip, o.ip + ' is the management address of ' + o.assets.length + ' assets (' + o.assets.map((a) => a.name).join(', ') + ')', 'Correct the asset records - one address, one asset.');
      if (o.assets.length && !o.sources.includes('discovery')) F('low', 'stale', o.ip, o.ip + ' (' + o.assets[0].name + ') is in the asset register but discovery never saw it', 'Check the asset still uses this address, or include its network in an Asset Discovery scope.');
      else if (o.assets.length && o.last_seen && t - o.last_seen > STALE_DAYS * DAY) F('low', 'stale', o.ip, o.ip + ' (' + o.assets[0].name + ') not seen for ' + Math.round((t - o.last_seen) / DAY) + ' days', 'Reclaim the address if the device is gone; update or retire the asset.');
      if (!o.assets.length && o.sources.includes('discovery')) F('low', 'unknown', o.ip, o.ip + (o.hosts[0] ? ' (' + o.hosts[0] + ')' : '') + ' is in use but in no asset record', 'Approve it in Asset Discovery so it has an owner, or find out what it is.');
      if (rv && o.hosts.length && rv.name && !o.hosts.includes(String(rv.name).toLowerCase())) F('medium', 'reservation', o.ip, o.ip + ' is reserved for ' + rv.name + ' but seen as ' + o.hosts.join(', '), 'Something else took the reserved address - find it, or release the reservation.');
      return { ip: o.ip, subnet: sub ? sub.id : null, macs: o.macs, hosts: o.hosts, assets: o.assets, sources: o.sources, last_seen: o.last_seen ? new Date(o.last_seen).toISOString() : null, reserved: rv ? rv.id : null };
    }).sort((a, b) => ip4.parseIp(a.ip) - ip4.parseIp(b.ip));
    for (const r of R) if (r.until && Date.parse(r.until) < t) F('low', 'expired', r.id, r.ip + ' reserved for ' + r.name + ' until ' + r.until + ' - the date has passed', 'Release it or extend the reservation.');
    // proposals: observed addresses in no registered subnet, grouped by /24
    const P = {}; for (const a of addrs) if (!a.subnet) { const k = a.ip.split('.').slice(0, 3).join('.') + '.0/24'; (P[k] = P[k] || { cidr: k, addresses: 0, sample: [] }).addresses++; if (P[k].sample.length < 4) P[k].sample.push(a.ip); }
    const proposals = Object.values(P).sort((a, b) => b.addresses - a.addresses);
    if (proposals.length) F('medium', 'unplanned', proposals[0].cidr, proposals.length + ' network(s) in use are not in the address plan (largest ' + proposals[0].cidr + ', ' + proposals[0].addresses + ' addresses)', 'Register them as subnets with their site, VLAN and owner.');
    const SEV = { high: 0, medium: 1, low: 2 }; findings.sort((a, b) => SEV[a.severity] - SEV[b.severity]);
    return { rows, addrs, findings, proposals, reservations: R };
  }
  function learning(rows) {
    const H = K.history(120), out = {};
    for (const r of rows) {
      const pts = H.filter((h) => h.subs && h.subs[r.id] != null).map((h) => ({ t: Date.parse(h.id + 'T00:00:00Z') / DAY, y: h.subs[r.id] }));
      const tr = pts.length >= 5 ? trend(pts, { now: K.now() }) : null, slope = tr && typeof tr.slope_per_week === 'number' ? tr.slope_per_week / 7 : null;
      out[r.id] = { samples: pts.length, growth_per_day: slope != null ? Math.round(slope * 100) / 100 : null,
        days_to_full: slope > 0 ? Math.round(r.free / slope) : null, why: pts.length < 5 ? 'needs 5 daily samples (' + pts.length + ' so far)' : slope > 0 ? 'least squares over ' + pts.length + ' days' : 'not growing' };
    }
    const tot = H.map((h) => h.total).filter((v) => typeof v === 'number'), diffs = tot.slice(1).map((v, i) => v - tot[i]);
    let unusual = null; if (diffs.length >= 7) { const z = robustZ(diffs.slice(0, -1), diffs[diffs.length - 1]); if (z != null && Math.abs(z) >= 3.5) unusual = { change: diffs[diffs.length - 1], z: Math.round(z * 10) / 10, why: 'today\'s change in addresses in use is far from the usual daily change (robust z ' + Math.round(z * 10) / 10 + ')' }; }
    return { subnets: out, unusual, snapshots: H.length };
  }
  function view(who) {
    const A = analyse(), L = learning(A.rows), op = (RANK[who && who.role] || 0) >= RANK.operator;
    for (const r of A.rows) r.learning = L.subnets[r.id];
    const kpis = { subnets: A.rows.length, addresses: A.addrs.length, in_plan: A.addrs.filter((a) => a.subnet).length, reserved: A.reservations.length, conflicts: A.findings.filter((f) => f.kind === 'conflict').length,
      unknown: A.findings.filter((f) => f.kind === 'unknown').length, stale: A.findings.filter((f) => f.kind === 'stale').length, unplanned: A.proposals.length, nearly_full: A.rows.filter((r) => r.pct >= 80).length };
    const out = { generated_at: K.iso(), ai: K.aiStatus(), kpis, subnets: A.rows, learning: { unusual: L.unusual, snapshots: L.snapshots }, can_details: op,
      note: 'Addresses come from the asset register and Asset Discovery. The plan (subnets, reservations) is kept by people; nothing here changes a device, a DHCP server or DNS.' };
    if (op) Object.assign(out, { addresses: A.addrs.slice(0, 5000), findings: A.findings.slice(0, 300), proposals: A.proposals.slice(0, 50), reservations: A.reservations });
    return out;
  }
  function putSubnet(b0, who) {
    K.person(who, 'change the address plan');
    const b = body(b0 || {}).str('id', { max: 12, re: /^SN-\d{4,}$/, msg: 'id must be a subnet id (SN-nnnn)' }).str('cidr', { required: true, max: 18 }).str('name', { required: true, max: 80 })
      .str('site', { max: 80 }).int('vlan', { min: 1, max: 4094 }).str('gateway', { max: 15 }).str('dhcp_start', { max: 15 }).str('dhcp_end', { max: 15 }).str('purpose', { max: 200 }).str('owner', { max: 80 }).done();
    const c = parseCidr(b.cidr); if (!c) throw httpErr(400, 'cidr must be an IPv4 network with a prefix from /8 to /30, e.g. 10.20.5.0/24');
    const inside = (k) => { if (!b[k]) return null; const n = ip4.parseIp(b[k]); if (n === null || n < c.first || n > c.last) throw httpErr(400, k + ' must be an address inside ' + c.cidr); return n; };
    const gw = inside('gateway'), ds = inside('dhcp_start'), de = inside('dhcp_end');
    if ((ds === null) !== (de === null)) throw httpErr(400, 'dhcp_start and dhcp_end go together');
    if (ds !== null && ds > de) throw httpErr(400, 'dhcp_start must not be after dhcp_end');
    if (gw !== null && ds !== null && gw >= ds && gw <= de) throw httpErr(400, 'gateway must be outside the DHCP range');
    const clash = subnets().find((x) => x.id !== b.id && c.net <= x.broadcast && x.net <= c.broadcast);
    if (clash) throw httpErr(409, c.cidr + ' overlaps ' + clash.cidr + ' (' + clash.name + ')');
    let rec; if (b.id) { const cur = SUB().get(b.id); if (!cur || cur.retired) throw httpErr(404, 'no subnet ' + b.id); rec = Object.assign({}, cur, b); }
    else rec = Object.assign({ id: nid(SUB, 'SN-'), created_by: who.user, created_at: K.iso() }, b);
    rec.cidr = c.cidr; rec.updated_by = who.user; rec.updated_at = K.iso(); SUB().put(rec);
    audit(who, b.id ? 'subnet.update' : 'subnet.add', rec.id, { cidr: rec.cidr, name: rec.name, fields: Object.keys(b).sort() });
    return rec;
  }
  function retireSubnet(id, b0, who) {
    K.person(who, 'change the address plan');
    const b = body(b0 || {}).str('reason', { required: true, max: 300 }).done(), cur = SUB().get(id);
    if (!cur || cur.retired) throw httpErr(404, 'no subnet ' + id);
    cur.retired = { by: who.user, at: K.iso(), reason: b.reason }; SUB().put(cur); audit(who, 'subnet.retire', id, { cidr: cur.cidr, reason: b.reason }); return cur;
  }
  function reserve(b0, who) {
    K.person(who, 'reserve an address');
    const b = body(b0 || {}).str('ip', { required: true, max: 15 }).str('name', { required: true, max: 80 }).str('purpose', { max: 200 }).date('until').done();
    const n = ip4.parseIp(b.ip); if (n === null) throw httpErr(400, 'ip must be an IPv4 address');
    const sub = subnets().find((x) => n >= x.first && n <= x.last); if (!sub) throw httpErr(409, b.ip + ' is in no registered subnet - register the subnet first');
    if (sub.gateway && ip4.parseIp(sub.gateway) === n) throw httpErr(409, b.ip + ' is the gateway of ' + sub.cidr);
    if (sub.dhcp_start && n >= ip4.parseIp(sub.dhcp_start) && n <= ip4.parseIp(sub.dhcp_end)) throw httpErr(409, b.ip + ' is inside the DHCP range ' + sub.dhcp_start + ' - ' + sub.dhcp_end + ' - reserve it on the DHCP server instead');
    if (RES().all((r) => !r.released && r.ip === b.ip).length) throw httpErr(409, b.ip + ' is already reserved');
    const seen = observed().find((o) => o.ip === b.ip); if (seen) throw httpErr(409, b.ip + ' is in use (' + (seen.hosts[0] || seen.sources.join(', ')) + ') - choose a free address');
    const rec = { id: nid(RES, 'IR-'), ip: b.ip, subnet: sub.id, name: b.name, purpose: b.purpose || '', until: b.until || null, by: who.user, at: K.iso() };
    RES().put(rec); audit(who, 'reserve', rec.id, { ip: rec.ip, name: rec.name, until: rec.until }); return rec;
  }
  function release(id, b0, who) {
    K.person(who, 'release a reservation');
    const b = body(b0 || {}).str('reason', { required: true, max: 300 }).done(), cur = RES().get(id);
    if (!cur || cur.released) throw httpErr(404, 'no reservation ' + id);
    cur.released = { by: who.user, at: K.iso(), reason: b.reason }; RES().put(cur); audit(who, 'release', id, { ip: cur.ip, reason: b.reason }); return cur;
  }
  async function snapshot() { return K.snapshot(async () => { const A = analyse(); if (!A.rows.length && !A.addrs.length) return null; const subs = {}; for (const r of A.rows) subs[r.id] = r.used; return { total: A.addrs.length, subs }; }); }
  K = createIntelKit(app, { key: 'ipam', feature: 'itam.ipam-advisor', now: opts.now, sdk: opts.sdk, getKey: opts.getKey, noTimer: opts.noTimer,
    system: ('You are the IP address-plan advisor for the network team of ' + ZYB_ORG.name + '. You read the registered subnets with their utilisation and growth, the addresses the platform observes, the reservations and the findings (conflicts, duplicates, stale, unknown devices, networks not in the plan). Recommend what to fix first and how to keep the plan ahead of growth. Base every statement on the tool output, cite subnets and addresses, never invent one. You cannot change anything: people change the plan, the DHCP server and the devices.'),
    tools: [{ name: 'ipam_overview', description: 'KPIs, subnets with utilisation, next free address and growth, findings with fixes, proposed subnets, reservations.', run: async () => { const v = view({ role: 'operator' }); return { kpis: v.kpis, subnets: v.subnets, findings: v.findings, proposals: v.proposals, reservations: v.reservations }; } }] });
  return { view, putSubnet, retireSubnet, reserve, release, snapshot, ask: K.ask, start: () => K.start(snapshot), stop: K.stop, parseCidr };
}
function registerIpam(srv, app, X) {
  app.addons = app.addons || {}; app.addons.ipam = X;   // read by the scan-target planner (engine/scan-targets.js)
  const ID = (re, what) => (ctx) => { const v = String((ctx.params && ctx.params.id) || ''); if (!re.test(v)) throw httpErr(400, 'id must be ' + what); return v; };
  const sn = ID(/^SN-\d{4,}$/, 'a subnet id (SN-nnnn)'), ir = ID(/^IR-\d{4,}$/, 'a reservation id (IR-nnnn)');
  srv.route('GET', '/ipam', (ctx) => { ctx.need('viewer'); return X.view(ctx.who); });
  srv.route('POST', '/ipam/subnets', (ctx) => { ctx.need('operator'); return X.putSubnet(ctx.body, ctx.who); }, { maxBody: 4096 });
  srv.route('POST', '/ipam/subnets/:id/retire', (ctx) => { ctx.need('operator'); return X.retireSubnet(sn(ctx), ctx.body, ctx.who); });
  srv.route('POST', '/ipam/reserve', (ctx) => { ctx.need('operator'); return X.reserve(ctx.body, ctx.who); }, { maxBody: 2048 });
  srv.route('POST', '/ipam/reservations/:id/release', (ctx) => { ctx.need('operator'); return X.release(ir(ctx), ctx.body, ctx.who); });
  srv.route('POST', '/ipam/ask', (ctx) => { ctx.need('operator'); return X.ask(ctx.body, ctx.who); }, { maxBody: 8192 });
}
module.exports = { createIpam, registerIpam, parseCidr };
