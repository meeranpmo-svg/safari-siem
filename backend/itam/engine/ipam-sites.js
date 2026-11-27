// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * IP Address Management by site ({P} = /api/itam; Network -> IP Address Management -> Sites) - the address plan of the head office,
 * the branches and the project sites as one plan, on top of the subnet register (engine/ipam.js), which stays the place subnets live.
 *   sites      register of sites: name, kind (head office, data centre, branch, office, project site, cloud), city, address block
 *              (one CIDR per site, never overlapping another site's block or a subnet outside it), status (active / closed), a project
 *              site's end date and contact. Sites found in the subnet register or the asset register but not in this register are
 *              listed to be added.
 *   templates  the standard VLAN / subnet layout per kind - users, servers, voice, staff and guest Wi-Fi, CCTV, printers, time
 *              clocks, management - each with its VLAN, prefix length and whether it has DHCP. An administrator changes them.
 *   open       a new site is PROPOSED by an operator (name, kind, city, contact, optional end date); the engine picks the next free block
 *              of the size for that kind inside the organisation's private range and lays out the template's subnets (gateway = first
 *              address, DHCP = the second half for client subnets). A DIFFERENT person, an administrator, approves: the subnets are then
 *              created in the subnet register (validated there, overlaps refused) and the site becomes active. Never an AI identity.
 *   close      a project site that ends is proposed for closure with a reason; on approval by another administrator its subnets are
 *              retired and its block is kept out of reuse for 90 days (a device still configured with an old address stays traceable).
 *   per site   subnets, usable / used / free addresses, the fullest subnet, conflicts and unknown devices at the site, utilisation;
 *              what the AI noticed (a subnet over 80 %, a project site ending within 30 days, sites not in the register, blocks used
 *              outside their site); CSV of a site's address plan for the network engineer.
 * Nothing here changes a switch, a firewall, a DHCP server or DNS - the plan is applied on the devices through their own change process.
 *   GET  /ipam/sites                     viewer    the sites, templates, KPIs, insights, open proposals
 *   PUT  /ipam/sites/:id                 admin     register / edit a site that already exists (its block is checked)
 *   PUT  /ipam/templates/:kind           admin     the standard layout of a kind
 *   POST /ipam/sites/propose             operator  {name, kind, city, contact?, ends?}   a new site: block and subnets laid out
 *   POST /ipam/sites/:id/close           operator  {reason}                              propose closing a site
 *   POST /ipam/site-proposals/:id/decide admin     {decision: approve | reject, note?}   another person; approve applies it
 *   GET  /ipam/sites/:id/plan            operator  the site's address plan (CSV)
 */
const ip4 = require('./discovery/ipv4');
const { body, param } = require('./check');
const { isHuman } = require('./approve-scopes');

const bad = (msg, status = 400) => Object.assign(new Error(msg), { status });
const KINDS = { head_office: 'Head office', data_centre: 'Data centre', branch: 'Branch', office: 'Office', project_site: 'Project site', cloud: 'Cloud' };
const BLOCK = { head_office: 16, data_centre: 16, branch: 18, office: 20, project_site: 20, cloud: 20 };
const QUARANTINE_DAYS = 90, DAY = 86400000;
// the standard layout per kind: [name, vlan, prefix, dhcp]
const TEMPLATE = {
  head_office: [['Users', 10, 22, true], ['Servers', 20, 24, false], ['Voice', 30, 24, true], ['Wi-Fi staff', 40, 23, true], ['Wi-Fi guest', 50, 24, true], ['CCTV', 60, 24, false], ['Printers', 70, 25, false], ['Time clocks / IoT', 80, 26, false], ['Management', 99, 26, false]],
  data_centre: [['Servers', 20, 22, false], ['Storage', 25, 24, false], ['Hyper-V hosts', 26, 26, false], ['Backup', 27, 25, false], ['Management', 99, 25, false]],
  branch: [['Users', 10, 23, true], ['Voice', 30, 25, true], ['Wi-Fi staff', 40, 24, true], ['Wi-Fi guest', 50, 25, true], ['CCTV', 60, 25, false], ['Printers', 70, 26, false], ['Management', 99, 27, false]],
  office: [['Users', 10, 24, true], ['Wi-Fi', 40, 25, true], ['CCTV', 60, 26, false], ['Printers', 70, 27, false], ['Management', 99, 27, false]],
  project_site: [['Site users', 10, 24, true], ['Site Wi-Fi', 40, 24, true], ['CCTV / NVR', 60, 25, false], ['Time clocks / IoT', 80, 26, false], ['Printers', 70, 27, false], ['Management', 99, 27, false]],
  cloud: [['Workloads', 20, 22, false], ['Gateway', 99, 27, false]],
};
const low = (v) => String(v == null ? '' : v).trim().toLowerCase();
const slug = (v) => low(v).replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 40) || 'site';
function cidrOf(c) { const m = /^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/.exec(String(c || '').trim()); if (!m) return null; const base = ip4.parseIp(m[1]), bits = Number(m[2]); if (base === null || bits < 8 || bits > 30) return null; const net = (base & ip4.maskOf(bits)) >>> 0, size = 2 ** (32 - bits); return { cidr: ip4.ipStr(net) + '/' + bits, net, bits, end: net + size - 1, size }; }
const overlaps = (a, b) => a.net <= b.end && b.net <= a.end;

function createIpamSites(app, opts = {}) {
  const now = opts.now || Date.now, iso = () => new Date(now()).toISOString();
  const SITES = () => app.store.collection('ipam_sites'), PROPS = () => app.store.collection('ipam_site_proposals'), TPL = () => app.store.collection('ipam_templates');
  const ipam = () => (app.addons && app.addons.ipam) || null;
  const cfg = () => (app.config && app.config.ipam) || {};
  const SUPERNET = () => cidrOf(cfg().supernet || '10.0.0.0/8');
  const audit = (who, action, target, detail) => { if (app.audit) app.audit({ by: who.user, role: who.role || '', ip: who.ip || '', action: 'ipam.site.' + action, target, detail }); };
  const person = (who, what) => { if (!isHuman(who.user)) throw bad('a person ' + what + '; an AI or service identity never does', 403); };
  const template = (kind) => { const t = TPL().get(kind); return (t && t.rows) || TEMPLATE[kind].map(([name, vlan, prefix, dhcp]) => ({ name, vlan, prefix, dhcp })); };

  function blocksInUse() {   // every block a site holds (closed ones while in quarantine) and every subnet outside a site block
    const L = [], t = now();
    for (const s of SITES().all()) { const c = cidrOf(s.block); if (!c) continue; if (s.status === 'closed' && s.closed_at && t - Date.parse(s.closed_at) > QUARANTINE_DAYS * DAY) continue; L.push(Object.assign({ owner: 'site ' + s.name }, c)); }
    for (const p of PROPS().all((x) => x.state === 'pending' && x.kind === 'open')) { const c = cidrOf(p.block); if (c) L.push(Object.assign({ owner: 'proposal ' + p.id }, c)); }
    const I = ipam(); if (I) for (const x of I.view({ role: 'admin' }).subnets || []) { const c = cidrOf(x.cidr); if (c) L.push(Object.assign({ owner: 'subnet ' + x.cidr }, c)); }
    return L;
  }
  function nextBlock(bits, used) {   // first free block of that size inside the organisation's range, aligned
    const S = SUPERNET(), size = 2 ** (32 - bits);
    for (let n = S.net; n + size - 1 <= S.end; n += size) { const c = { net: n, end: n + size - 1 }; if (!used.some((u) => overlaps(u, c))) return ip4.ipStr(n) + '/' + bits; }
    return null;
  }
  function layout(block, kind) {   // the template's subnets packed into the block, largest first, aligned
    const B = cidrOf(block), rows = template(kind).slice().sort((a, b) => a.prefix - b.prefix), out = []; let cur = B.net;
    for (const r of rows) {
      const size = 2 ** (32 - r.prefix); cur = Math.ceil(cur / size) * size; if (cur + size - 1 > B.end) throw bad('the ' + KINDS[kind] + ' template does not fit in ' + block + ' - change the template or the block size');
      const first = cur + 1, last = cur + size - 2, half = cur + Math.floor(size / 2);
      out.push({ name: r.name, vlan: r.vlan, cidr: ip4.ipStr(cur) + '/' + r.prefix, gateway: ip4.ipStr(first), dhcp_start: r.dhcp ? ip4.ipStr(half) : '', dhcp_end: r.dhcp ? ip4.ipStr(last) : '', usable: size - 2, purpose: r.name.toLowerCase() });
      cur += size;
    }
    return out.sort((a, b) => a.vlan - b.vlan);
  }

  // ---------- the view ----------
  function view(who) {
    const I = ipam(), V = I ? I.view(Object.assign({}, who, { role: who.role === 'viewer' ? 'viewer' : 'operator' })) : { subnets: [], findings: [] };
    const subs = V.subnets || [], F = V.findings || [], reg = SITES().all(), t = now();
    const bySite = {}; for (const x of subs) (bySite[low(x.site)] = bySite[low(x.site)] || []).push(x);
    const sites = reg.map((s) => {
      const S0 = bySite[low(s.name)] || [], usable = S0.reduce((n, x) => n + (x.usable || 0), 0), used = S0.reduce((n, x) => n + (x.used || 0), 0), B = cidrOf(s.block);
      const outside = B ? S0.filter((x) => { const c = cidrOf(x.cidr); return c && !(c.net >= B.net && c.end <= B.end); }).map((x) => x.cidr) : [];
      const ids = new Set(S0.map((x) => x.id)), fs = F.filter((f) => ids.has(f.subnet) || (f.ip && B && (() => { const n = ip4.parseIp(f.ip); return n !== null && n >= B.net && n <= B.end; })()));
      const fullest = S0.slice().sort((a, b) => (b.pct || 0) - (a.pct || 0))[0] || null, days = s.ends ? Math.floor((Date.parse(s.ends) - t) / DAY) : null;
      return Object.assign({}, s, { kind_label: KINDS[s.kind] || s.kind, subnets: S0.length, usable, used, free: usable - used, pct: usable ? Math.round(100 * used / usable) : null, fullest: fullest ? { cidr: fullest.cidr, name: fullest.name, pct: fullest.pct } : null,
        conflicts: fs.filter((f) => f.kind === 'conflict').length, unknown: fs.filter((f) => f.kind === 'unknown').length, outside_block: outside, ends_in_days: days, block_size: B ? B.size : null });
    }).sort((a, b) => ['head_office', 'data_centre', 'branch', 'office', 'project_site', 'cloud'].indexOf(a.kind) - ['head_office', 'data_centre', 'branch', 'office', 'project_site', 'cloud'].indexOf(b.kind) || a.name.localeCompare(b.name));
    const known = new Set(reg.map((s) => low(s.name)));
    const assetSites = {}; for (const a of app.store.collection('assets').all((x) => x.site && x.status !== 'deleted')) assetSites[a.site] = (assetSites[a.site] || 0) + 1;
    const missing = [...new Set(subs.map((x) => x.site).filter(Boolean).concat(Object.keys(assetSites)))].filter((n) => !known.has(low(n)) && !/^azure|^aws|^oci/i.test(n)).map((n) => ({ name: n, subnets: (bySite[low(n)] || []).length, assets: assetSites[n] || 0 }));
    const active = sites.filter((s) => s.status !== 'closed');
    const kpis = { sites: active.length, head_office: active.filter((s) => s.kind === 'head_office').length, branches: active.filter((s) => s.kind === 'branch' || s.kind === 'office').length, project_sites: active.filter((s) => s.kind === 'project_site').length,
      subnets: active.reduce((n, s) => n + s.subnets, 0), usable: active.reduce((n, s) => n + s.usable, 0), used: active.reduce((n, s) => n + s.used, 0), conflicts: active.reduce((n, s) => n + s.conflicts, 0),
      proposals: PROPS().all((x) => x.state === 'pending').length, not_registered: missing.length };
    kpis.pct = kpis.usable ? Math.round(100 * kpis.used / kpis.usable) : null;
    return { generated_at: iso(), kinds: KINDS, supernet: SUPERNET().cidr, sites, kpis, missing, insights: insights(active, missing, subs),
      templates: Object.fromEntries(Object.keys(KINDS).map((k) => [k, template(k)])), block_bits: BLOCK,
      proposals: PROPS().all().sort((a, b) => (a.at < b.at ? 1 : -1)).slice(0, 50), can_manage: who.role === 'admin', can_propose: ['operator', 'admin'].includes(who.role),
      note: 'The plan is kept here; nothing changes a switch, firewall, DHCP server or DNS. Apply an approved site plan on the devices through their own change process.' };
  }
  function insights(sites, missing, subs) {
    const out = [], p = (lvl, t, d) => out.push({ level: lvl, title: t, detail: d });
    const hot = subs.filter((x) => (x.pct || 0) >= 80); if (hot.length) p('crit', hot.length + ' subnet(s) 80% full or more', hot.slice(0, 5).map((x) => x.cidr + ' ' + x.name + (x.site ? ' (' + x.site + ')' : '') + ' ' + x.pct + '%').join('; ') + '. Widen the scope or add a subnet from the site block before DHCP runs out.');
    const ending = sites.filter((s) => s.kind === 'project_site' && s.ends_in_days !== null && s.ends_in_days <= 30); if (ending.length) p('warn', ending.length + ' project site(s) end within 30 days', ending.map((s) => s.name + ' (' + s.ends + ')').join(', ') + '. Propose the closure so the subnets are retired and the block is freed after 90 days.');
    const conf = sites.filter((s) => s.conflicts); if (conf.length) p('crit', 'Address conflicts at ' + conf.map((s) => s.name + ' (' + s.conflicts + ')').join(', '), 'Two devices answer on one address - users there lose connection at random.');
    const out0 = sites.filter((s) => s.outside_block.length); if (out0.length) p('warn', out0.length + ' site(s) use subnets outside their block', out0.map((s) => s.name + ': ' + s.outside_block.join(', ')).join('; ') + '. Move them into the site block or widen the block - routing summaries depend on it.');
    if (missing.length) p('info', missing.length + ' site name(s) in use but not in the site register', missing.slice(0, 6).map((m) => m.name).join(', ') + '. Register them so their addresses are planned and they appear on the map.');
    const noPlan = sites.filter((s) => !s.subnets); if (noPlan.length) p('info', noPlan.length + ' site(s) with no subnet yet', noPlan.map((s) => s.name).join(', ') + '.');
    return out;
  }

  // ---------- register, templates ----------
  function putSite(id0, b0, who) {
    person(who, 'changes the site register');
    const id = param(id0, 'id'); if (!/^[a-z0-9][a-z0-9-]{1,39}$/.test(id)) throw bad('id: 2-40 lower-case letters, digits or -');
    const b = body(b0 || {}).str('name', { required: true, min: 2, max: 80 }).oneOf('kind', Object.keys(KINDS), { required: true }).str('city', { max: 60 }).str('block', { required: true, max: 18 })
      .str('contact', { max: 80 }).date('ends', {}).oneOf('status', ['active', 'closed'], { def: 'active' }).done();
    const c = cidrOf(b.block); if (!c) throw bad('block: an IPv4 network such as 10.40.0.0/20');
    const S = SUPERNET(); if (!(c.net >= S.net && c.end <= S.end)) throw bad('block: inside the organisation range ' + S.cidr);
    for (const s of SITES().all((x) => x.id !== id && x.status !== 'closed')) { const o = cidrOf(s.block); if (o && overlaps(o, c)) throw bad('block: ' + c.cidr + ' overlaps the block of ' + s.name + ' (' + s.block + ')', 409); }
    if (SITES().all((x) => x.id !== id && low(x.name) === low(b.name)).length) throw bad('name: already a site', 409);
    const prev = SITES().get(id), rec = Object.assign({}, prev || {}, b, { id, block: c.cidr, updated_by: who.user, updated_at: iso() }, prev ? {} : { created_by: who.user, created_at: iso() });
    SITES().put(rec); audit(who, prev ? 'update' : 'register', id, { name: b.name, kind: b.kind, block: c.cidr, renamed_from: prev && prev.name !== b.name ? prev.name : undefined });
    return view(who);
  }
  function putTemplate(kind0, b0, who) {
    person(who, 'changes a site template');
    if (!KINDS[kind0]) throw bad('kind: one of ' + Object.keys(KINDS).join(', '));
    const rows = (b0 && b0.rows); if (!Array.isArray(rows) || !rows.length || rows.length > 20) throw bad('rows: 1-20 subnets');
    const R = rows.map((r, i) => { try { return body(r || {}).str('name', { required: true, min: 2, max: 40 }).int('vlan', { required: true, min: 1, max: 4094 }).int('prefix', { required: true, min: 20, max: 29 }).bool('dhcp', { def: false }).done(); } catch (e) { throw bad('rows[' + i + '].' + e.message); } });
    if (new Set(R.map((r) => r.vlan)).size !== R.length) throw bad('rows: each VLAN once');
    const need = R.reduce((n, r) => n + 2 ** (32 - r.prefix), 0), cap = 2 ** (32 - BLOCK[kind0]); if (need > cap) throw bad('rows: ' + need + ' addresses do not fit in a /' + BLOCK[kind0] + ' (' + cap + ')');
    TPL().put({ id: kind0, rows: R, by: who.user, at: iso() }); audit(who, 'template', kind0, { rows: R.length, addresses: need });
    return view(who);
  }

  // ---------- open / close with four-eyes ----------
  function propose(b0, who) {
    person(who, 'proposes a new site');
    const b = body(b0 || {}).str('name', { required: true, min: 2, max: 80 }).oneOf('kind', Object.keys(KINDS), { required: true }).str('city', { required: true, max: 60 }).str('contact', { max: 80 }).date('ends', {}).str('reason', { max: 300 }).done();
    if (SITES().all((x) => low(x.name) === low(b.name) && x.status !== 'closed').length || PROPS().all((x) => x.state === 'pending' && low(x.name) === low(b.name)).length) throw bad('name: already a site or waiting for approval', 409);
    if (b.kind === 'project_site' && b.ends && b.ends < iso().slice(0, 10)) throw bad('ends: today or later');
    const block = nextBlock(BLOCK[b.kind], blocksInUse()); if (!block) throw bad('no free /' + BLOCK[b.kind] + ' left in ' + SUPERNET().cidr + ' - an administrator widens the range (ipam.supernet)', 409);
    const subnets = layout(block, b.kind);
    const rec = Object.assign({ id: 'SP-' + String(PROPS().all().length + 1).padStart(4, '0'), kind: 'open', state: 'pending', site_id: slug(b.name), block, subnets, proposed_by: who.user, at: iso() }, b, { site_kind: b.kind });
    rec.kind = 'open'; PROPS().put(rec);
    audit(who, 'propose', rec.id, { name: b.name, kind: b.kind, block, subnets: subnets.length });
    return rec;
  }
  function proposeClose(id0, b0, who) {
    person(who, 'proposes closing a site');
    const s = SITES().get(param(id0, 'id')); if (!s || s.status === 'closed') throw bad('site not found or already closed', 404);
    const b = body(b0 || {}).str('reason', { required: true, min: 5, max: 300 }).done();
    if (PROPS().all((x) => x.state === 'pending' && x.site_id === s.id).length) throw bad('a change for ' + s.name + ' is already waiting', 409);
    const rec = { id: 'SP-' + String(PROPS().all().length + 1).padStart(4, '0'), kind: 'close', state: 'pending', site_id: s.id, name: s.name, block: s.block, reason: b.reason, proposed_by: who.user, at: iso() };
    PROPS().put(rec); audit(who, 'propose_close', rec.id, { site: s.name, reason: b.reason }); return rec;
  }
  function decide(id0, b0, who) {
    person(who, 'decides a site change');
    const p = PROPS().get(param(id0, 'id')); if (!p) throw bad('proposal not found', 404);
    if (p.state !== 'pending') throw bad('proposal is ' + p.state, 409);
    if (low(p.proposed_by) === low(who.user)) throw bad('four-eyes: ' + who.user + ' proposed this - another person decides', 403);
    const b = body(b0 || {}).oneOf('decision', ['approve', 'reject'], { required: true }).str('note', { max: 300 }).done();
    if (b.decision === 'reject') { PROPS().patch(p.id, (o) => Object.assign(o, { state: 'rejected', decided_by: who.user, decided_at: iso(), note: b.note || '' })); audit(who, 'reject', p.id, { name: p.name }); return PROPS().get(p.id); }
    const I = ipam(); if (!I) throw bad('the subnet register (IP Address Management) is not installed', 409);
    const made = [];
    if (p.kind === 'open') {
      if (blocksInUse().filter((u) => !/^proposal /.test(u.owner)).some((u) => overlaps(u, cidrOf(p.block)))) throw bad('the block ' + p.block + ' was taken since the proposal - propose again', 409);
      SITES().put({ id: p.site_id, name: p.name, kind: p.site_kind, city: p.city, block: p.block, contact: p.contact || '', ends: p.ends || null, status: 'active', created_by: p.proposed_by, approved_by: who.user, created_at: iso() });
      for (const x of p.subnets) { const r = I.putSubnet({ cidr: x.cidr, name: p.name + ' ' + x.name, site: p.name, vlan: x.vlan, gateway: x.gateway, dhcp_start: x.dhcp_start || undefined, dhcp_end: x.dhcp_end || undefined, purpose: x.purpose, owner: p.contact || undefined }, who); made.push(r && r.id ? r.id : x.cidr); }
    } else {
      const s = SITES().get(p.site_id), V = I.view({ role: 'admin' });
      for (const x of (V.subnets || []).filter((y) => low(y.site) === low(s.name))) { I.retireSubnet(x.id, { reason: 'site closed: ' + p.reason }, who); made.push(x.id); }
      SITES().patch(s.id, (o) => Object.assign(o, { status: 'closed', closed_at: iso(), closed_by: who.user }));
    }
    PROPS().patch(p.id, (o) => Object.assign(o, { state: 'applied', decided_by: who.user, decided_at: iso(), note: b.note || '', subnets_changed: made.length }));
    audit(who, p.kind === 'open' ? 'open' : 'close', p.id, { name: p.name, block: p.block, subnets: made.length, proposed_by: p.proposed_by });
    return PROPS().get(p.id);
  }
  function planCsv(id0) {
    const s = SITES().get(param(id0, 'id')); if (!s) throw bad('site not found', 404);
    const I = ipam(), subs = I ? (I.view({ role: 'admin' }).subnets || []).filter((x) => low(x.site) === low(s.name)) : [];
    const q = (v) => '"' + String(v == null ? '' : v).replace(/"/g, '""').replace(/^([=+\-@])/, "'$1") + '"';
    return [['site', 'kind', 'block', 'vlan', 'subnet', 'name', 'gateway', 'dhcp start', 'dhcp end', 'usable', 'used', 'free', 'utilisation %'].map(q).join(',')]
      .concat(subs.sort((a, b) => (a.vlan || 0) - (b.vlan || 0)).map((x) => [s.name, KINDS[s.kind], s.block, x.vlan, x.cidr, x.name, x.gateway, x.dhcp_start, x.dhcp_end, x.usable, x.used, x.free, x.pct].map(q).join(','))).join('\r\n') + '\r\n';
  }
  return { view, putSite, putTemplate, propose, proposeClose, decide, planCsv, layout, nextBlock, KINDS, TEMPLATE };
}

function registerIpamSites(srv, app, X) {
  const id = (ctx) => param(String((ctx.params && ctx.params.id) || ''), 'id');
  srv.route('GET', '/ipam/sites', (ctx) => { ctx.need('viewer'); return X.view(ctx.who); });
  srv.route('PUT', '/ipam/sites/:id', (ctx) => { ctx.need('admin'); return X.putSite(ctx.params.id, ctx.body, ctx.who); }, { maxBody: 2048 });
  srv.route('PUT', '/ipam/templates/:kind', (ctx) => { ctx.need('admin'); return X.putTemplate(String(ctx.params.kind || ''), ctx.body, ctx.who); }, { maxBody: 8192 });
  srv.route('POST', '/ipam/sites/propose', (ctx) => { ctx.need('operator'); return X.propose(ctx.body, ctx.who); }, { maxBody: 2048 });
  srv.route('POST', '/ipam/sites/:id/close', (ctx) => { ctx.need('operator'); return X.proposeClose(ctx.params.id, ctx.body, ctx.who); }, { maxBody: 2048 });
  srv.route('POST', '/ipam/site-proposals/:id/decide', (ctx) => { ctx.need('admin'); return X.decide(ctx.params.id, ctx.body, ctx.who); }, { maxBody: 2048 });
  srv.route('GET', '/ipam/sites/:id/plan', (ctx) => { ctx.need('operator'); return { csv: X.planCsv(id(ctx)) }; });
  (app.addons = app.addons || {}).ipamSites = X;
  return X;
}

module.exports = { createIpamSites, registerIpamSites, TEMPLATE, KINDS };
