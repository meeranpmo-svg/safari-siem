// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Network Access Control without a NAC product: one endpoint per MAC across every site, joined from what the platform already reads
 *   - the FortiGates' device detection (through FortiManager or directly, netops/fmg.js): IP, host name, OS, user, site
 *   - the switch port map (netops/portmap.js, Cisco IOS and H3C Comware, read-only SSH): switch, port, VLAN, port description, moves
 * Nothing new is polled and nothing is changed on a device.
 * ML, explainable - every point itemised, learning before judging:
 *   new endpoint     first seen in the last 24 h, once the fleet has 7 days of history ("learning" before that)       +25
 *   identity change  the same MAC reported as another OS / host name (spoofing or a re-imaged device)                  +30
 *   two sites        the same MAC at two FortiGates within 30 minutes (a cloned MAC)                                   +35
 *   rare at site     its OS is under 3 % of the site's endpoints (sites with 30+ endpoints)                               +15
 *   unauthorised     seen for more than 7 days and never authorised                                                    +10
 *   shared port      2+ MACs active on one access port (an unmanaged switch or hub behind it)                          +20
 *   flapping / move  3+ port moves in 24 h (a loop or spoofing) +25; moved to another port +10
 *   random MAC       a locally administered (privacy) MAC - said, not scored
 *   not via FortiGate on a switch port but never seen by a FortiGate (a static address, or traffic that stays local) - said
 * Decisions are four-eyes: an operator proposes "authorise" (owner, purpose) or "quarantine" (why); a different person with the
 * firewall approver scope approves. A quarantine is carried out in FortiManager / on the FortiGate by a person (add the MAC to the
 * quarantine address group or the NAC policy) and marked done here - the platform never blocks on its own.
 *   GET  {P}/nac/endpoints                       analyst (names devices and users)
 *   POST {P}/nac/decisions                       operator  {mac, action: authorise | quarantine, owner?, reason, expires? (authorise, <= 90 days)}
 *   POST {P}/nac/decisions/:id/decide            approve:eng:security  {decision, comment}
 *   POST {P}/nac/decisions/:id/done              operator  {note}   (quarantine carried out)
 */
const { body, param } = require('../util/check');
const { HttpError, wrap, audit, prefixOf } = require('../soc/routeutil');

const MAC = /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/;
const DAY = 86400000;
const family = (os) => { const o = String(os || '').toLowerCase(); return /windows/.test(o) ? 'windows' : /mac ?os|ios|ipados|apple/.test(o) ? 'apple' : /android/.test(o) ? 'android' : /linux|ubuntu|debian|red ?hat|centos/.test(o) ? 'linux' : o ? o.split(/\s+/)[0] : ''; };
const randomMac = (m) => /^.[26ae]/.test(m);

function assess(list, decisions, now) {
  const oldest = list.reduce((a, e) => Math.min(a, Date.parse(e.first_seen) || now), now), learning = now - oldest < 7 * DAY;
  // an authorisation may carry an end date (a contractor at a project site): after it the device is not authorised any more
  const today = new Date(now + 3 * 3600000).toISOString().slice(0, 10), okAuth = decisions.filter((d) => d.action === 'authorise' && d.status === 'approved');
  const auth = new Set(okAuth.filter((d) => !d.expires || d.expires >= today).map((d) => d.mac)), until = new Map(okAuth.map((d) => [d.mac, d.expires || null]));
  const quar = new Map(decisions.filter((d) => d.action === 'quarantine' && ['approved', 'done'].includes(d.status)).map((d) => [d.mac, d.status]));
  const bySite = new Map(); for (const e of list) { const s = bySite.get(e.site) || { n: 0, os: {} }; s.n++; const f = family(e.os) || '?'; s.os[f] = (s.os[f] || 0) + 1; bySite.set(e.site, s); }
  return list.map((e) => {
    const r = [], add = (pts, code, why) => r.push({ points: pts, code, why });
    const first = Date.parse(e.first_seen) || now;
    if (!learning && now - first < DAY && !auth.has(e.mac)) add(25, 'new', 'first seen ' + Math.round((now - first) / 3600000) + ' h ago');
    const fams = [...new Set((e.idents || []).map((x) => family(x.split('|')[0])).filter(Boolean))];
    if (fams.length > 1) add(30, 'identity', 'reported as ' + fams.join(' and then ') + ' under one MAC');
    const recent = (e.sightings || []).filter((x) => now - Date.parse(x.at) < 2 * 3600000);
    for (let i = 0; i < recent.length; i++) for (let j = i + 1; j < recent.length; j++) if (recent[i].fortigate !== recent[j].fortigate && Math.abs(Date.parse(recent[i].at) - Date.parse(recent[j].at)) <= 30 * 60000) { if (!r.some((x) => x.code === 'two-sites')) add(35, 'two-sites', 'at ' + recent[i].fortigate + ' and ' + recent[j].fortigate + ' within 30 min'); }
    const s = bySite.get(e.site), f = family(e.os) || '?';
    if (s && s.n >= 30 && s.os[f] / s.n < 0.03) add(15, 'rare', (f === '?' ? 'unknown OS' : f) + ' is ' + Math.round(s.os[f] / s.n * 1000) / 10 + ' % of ' + s.n + ' endpoints at ' + e.site);
    if (!auth.has(e.mac) && now - first > 7 * DAY) add(10, 'unauthorised', 'seen for ' + Math.floor((now - first) / DAY) + ' days, never authorised');
    const sw = e.sw;
    if (sw && sw.shared >= 2) add(20, 'shared-port', sw.shared + ' MACs on access port ' + sw.port + ' of ' + sw.switch + ' - an unmanaged switch or hub behind it');
    if (sw && sw.moves24 >= 3) add(25, 'flapping', sw.moves24 + ' port moves in 24 h - a loop or a spoofed MAC'); else if (sw && sw.moves24 >= 1) add(10, 'moved', 'moved to ' + sw.switch + ' ' + sw.port + ' in the last 24 h');
    const notes = randomMac(e.mac) ? ['privacy (random) MAC - the same device may appear under another MAC'] : [];
    if (sw && !e.fortigate) notes.push('on a switch port but never seen by a FortiGate - a static address, or its traffic stays local');
    return Object.assign({}, e, { risk: Math.min(100, r.reduce((a, x) => a + x.points, 0)), reasons: r, notes, authorised: auth.has(e.mac), auth_expires: until.get(e.mac) || null, auth_expired: until.has(e.mac) && !auth.has(e.mac), quarantine: quar.get(e.mac) || null });
  }).concat([]).sort((a, b) => b.risk - a.risk || String(b.last_seen).localeCompare(String(a.last_seen)));
}

function register(api, deps) {
  if (!deps.state) throw new Error('nac needs deps.state');
  const P = prefixOf(deps), eps = deps.state.collection('fmg_endpoints'), dec = deps.state.collection('nac_decisions'), NOW = deps.now || Date.now;
  const nextId = () => { let m = 0; for (const d of dec.all()) { const n = Number(String(d.id).slice(4)); if (n > m) m = n; } return 'NAC-' + String(m + 1).padStart(5, '0'); };
  // the switch side (port map): latest read per switch → ports (VLAN, description) and ARP; portmap_macs → where each MAC is now
  const pm = { macs: deps.state.collection('portmap_macs'), reads: deps.state.collection('portmap_reads') };
  const inv = () => (deps.netopsInstance && deps.netopsInstance.inventory) || null;
  const devName = (id) => { const I = inv(); const d = I && (I.get ? I.get(id) : null); return (d && d.name) || id; };
  const colon = (h) => (h.length === 12 ? h.match(/../g).join(':') : h);
  function merge(fg, now) {
    const latest = new Map(); for (const r of pm.reads.all()) latest.set(r.id, r);   // one read record per switch (its device id)
    const arp = new Map(), portInfo = new Map(), trunk = new Set();
    for (const [dev, r] of latest) { for (const a of r.arp || []) arp.set(a.mac, a.ip); for (const x of r.ports || []) portInfo.set(dev + '|' + String(x.port).toLowerCase(), x); for (const t of r.trunks || []) trunk.add(dev + '|' + t); }
    const active = pm.macs.all((m) => now - m.last < DAY && !trunk.has(m.device + '|' + m.port)), perPort = new Map();
    for (const m of active) perPort.set(m.device + '|' + m.port, (perPort.get(m.device + '|' + m.port) || 0) + 1);
    const by = new Map(fg.map((e) => [e.mac, Object.assign({}, e)]));
    for (const m of active) {
      const mac = colon(m.id), pi = portInfo.get(m.device + '|' + m.port) || {}, moves24 = (m.moves || []).filter((x) => now - (x.t || x.at || 0) < DAY).length;
      const sw = { switch: devName(m.device), device: m.device, port: pi.port || m.port, vlan: pi.vlan || '', desc: pi.name || '', vendor: (latest.get(m.device) || {}).vendor || 'cisco-ios', shared: perPort.get(m.device + '|' + m.port) || 1, moves24 };
      const cur = by.get(mac);
      if (cur) cur.sw = sw;
      else by.set(mac, { id: mac, mac, ip: arp.get(m.id) || '', host: '', os: '', site: '', fortigate: '', first_seen: new Date(m.first).toISOString(), last_seen: new Date(m.last).toISOString(), idents: [], sightings: [], sw });
    }
    return [...by.values()];
  }
  // what a person runs to quarantine at the switch port (shown, never pushed): the organisation's quarantine VLAN, else shutdown
  function steps(e) {
    const q = ((deps.config.netops || {}).nac || {}).quarantine_vlan, sw = e.sw, cw = sw.vendor === 'h3c-comware';
    const lines = cw ? ['system-view', 'interface ' + sw.port, q ? 'port access vlan ' + q : 'shutdown', 'quit', 'save'] : ['configure terminal', 'interface ' + sw.port, q ? 'switchport access vlan ' + q : 'shutdown', 'end', 'write memory'];
    return { switch: sw.switch, port: sw.port, vendor: cw ? 'H3C Comware' : 'Cisco IOS', lines, note: q ? 'moves the port to quarantine VLAN ' + q : 'no quarantine VLAN set (netops.nac.quarantine_vlan): the port is shut down' };
  }
  // the duty desk's AI Network Access Engineer reads the same view (duty/estate-adapters.js)
  deps.nacApi = { view: () => nacView() };
  function nacView() {
    const now = NOW(), all = merge(eps.all(), now), list = assess(all, dec.all(), now).map((e) => Object.assign(e, { quarantine_steps: e.sw ? steps(e) : null })), oldest = all.reduce((a, e) => Math.min(a, Date.parse(e.first_seen) || now), now);
    const sites = {}; for (const e of list) { const s = sites[e.site] = sites[e.site] || { site: e.site, endpoints: 0, risky: 0 }; s.endpoints++; if (e.risk >= 30) s.risky++; }
    return { connected: !!deps.fmgApi || pm.reads.size() > 0, sources: { fortigate: eps.size(), switch_ports: pm.macs.size(), switches: pm.reads.size() }, learning: now - oldest < 7 * 86400000, learning_until: new Date(oldest + 7 * 86400000).toISOString().slice(0, 10), endpoints: list.slice(0, 3000), total: list.length,
      sites: Object.values(sites).map((s) => Object.assign(s, { exposure: s.endpoints ? Math.round(100 * s.risky / s.endpoints) : 0 })).sort((a, b) => b.exposure - a.exposure),
      decisions: dec.all().sort((a, b) => String(b.id).localeCompare(String(a.id))).slice(0, 300) };
  }
  api.route('GET', `${P}/nac/endpoints`, wrap(deps, 'analyst', () => nacView()));
  api.route('POST', `${P}/nac/decisions`, wrap(deps, 'operator', async (ctx) => {
    const b = body(ctx.body).str('mac', { required: true, max: 17 }).oneOf('action', ['authorise', 'quarantine'], { required: true }).str('owner', { max: 120 }).str('reason', { required: true, max: 400 }).date('expires', {}).done();
    const mac = b.mac.toLowerCase(); if (!MAC.test(mac)) throw new HttpError(400, 'mac: aa:bb:cc:dd:ee:ff');
    if (!eps.get(mac)) throw new HttpError(404, 'mac: not seen by any FortiGate');
    if (b.reason.length < 10) throw new HttpError(400, 'reason: say why, in at least 10 characters');
    if (b.action === 'authorise' && !b.owner) throw new HttpError(400, 'owner: who the device belongs to');
    if (b.expires) {   // time-limited access (contractors, visitors at a project site): within 90 days, only for an authorisation
      if (b.action !== 'authorise') throw new HttpError(400, 'expires: only an authorisation ends on a date');
      const t = Date.parse(b.expires + 'T23:59:59Z'), n0 = NOW(); if (!(t > n0)) throw new HttpError(400, 'expires: a date in the future'); if (t - n0 > 90 * DAY) throw new HttpError(400, 'expires: at most 90 days ahead');
    }
    if (dec.all((d) => d.mac === mac && d.action === b.action && d.status === 'proposed').length) throw new HttpError(409, 'a ' + b.action + ' for ' + mac + ' is already waiting for approval');
    const d = dec.put({ id: nextId(), mac, action: b.action, owner: b.owner || '', reason: b.reason, expires: b.expires || null, status: 'proposed', proposed_by: ctx.user, proposed_at: new Date(NOW()).toISOString() });
    audit(ctx, 'nac.decision.propose', d.id, { mac, action: d.action }); return d;
  }));
  api.route('POST', `${P}/nac/decisions/:id/decide`, wrap(deps, 'approve:eng:security', async (ctx) => {
    const b = body(ctx.body).oneOf('decision', ['approved', 'rejected'], { required: true }).str('comment', { max: 400 }).done();
    const id = param(String(ctx.params.id || ''), 'id'), d = dec.get(id); if (!d) throw new HttpError(404, 'decision not found');
    if (d.status !== 'proposed') throw new HttpError(409, 'only a proposed decision is decided');
    if (String(d.proposed_by).toLowerCase() === String(ctx.user).toLowerCase()) throw new HttpError(403, 'four-eyes: the person who proposed it does not approve it');
    if (b.decision === 'rejected' && !(b.comment && b.comment.length >= 5)) throw new HttpError(400, 'comment: say why it is rejected');
    const n = dec.patch(id, (x) => { x.status = b.decision; x.decided_by = ctx.user; x.decided_at = new Date(NOW()).toISOString(); x.comment = b.comment || ''; return x; });
    audit(ctx, 'nac.decision.' + (b.decision === 'approved' ? 'approve' : 'reject'), id, { mac: d.mac, action: d.action, proposed_by: d.proposed_by }); return n;
  }));
  api.route('POST', `${P}/nac/decisions/:id/done`, wrap(deps, 'operator', async (ctx) => {
    const b = body(ctx.body).str('note', { required: true, max: 400 }).done();
    const id = param(String(ctx.params.id || ''), 'id'), d = dec.get(id); if (!d) throw new HttpError(404, 'decision not found');
    if (d.action !== 'quarantine' || d.status !== 'approved') throw new HttpError(409, 'only an approved quarantine is marked done');
    const n = dec.patch(id, (x) => { x.status = 'done'; x.done_by = ctx.user; x.done_at = new Date(NOW()).toISOString(); x.note = b.note; return x; });
    audit(ctx, 'nac.decision.done', id, { mac: d.mac }); return n;
  }));
}

module.exports = { register, assess, family };
