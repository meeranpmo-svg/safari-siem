// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Network Access Control from the FortiGates' own device detection (read through FortiManager by netops/fmg.js - nothing new is
 * polled, nothing is changed on a device). One endpoint per MAC across every site, with where, when and as what it was seen.
 * ML, explainable - every point itemised, learning before judging:
 *   new endpoint     first seen in the last 24 h, once the fleet has 7 days of history ("learning" before that)       +25
 *   identity change  the same MAC reported as another OS / host name (spoofing or a re-imaged device)                  +30
 *   two sites        the same MAC at two FortiGates within 30 minutes (a cloned MAC)                                   +35
 *   rare at site     its OS is under 3 % of the site's endpoints (sites with 30+ endpoints)                               +15
 *   unauthorised     seen for more than 7 days and never authorised                                                    +10
 *   random MAC       a locally administered (privacy) MAC - said, not scored
 * Decisions are four-eyes: an operator proposes "authorise" (owner, purpose) or "quarantine" (why); a different person with the
 * firewall approver scope approves. A quarantine is carried out in FortiManager / on the FortiGate by a person (add the MAC to the
 * quarantine address group or the NAC policy) and marked done here - the platform never blocks on its own.
 *   GET  {P}/nac/endpoints                       analyst (names devices and users)
 *   POST {P}/nac/decisions                       operator  {mac, action: authorise | quarantine, owner?, reason}
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
  const auth = new Set(decisions.filter((d) => d.action === 'authorise' && d.status === 'approved').map((d) => d.mac));
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
    const notes = randomMac(e.mac) ? ['privacy (random) MAC - the same device may appear under another MAC'] : [];
    return Object.assign({}, e, { risk: Math.min(100, r.reduce((a, x) => a + x.points, 0)), reasons: r, notes, authorised: auth.has(e.mac), quarantine: quar.get(e.mac) || null });
  }).concat([]).sort((a, b) => b.risk - a.risk || String(b.last_seen).localeCompare(String(a.last_seen)));
}

function register(api, deps) {
  if (!deps.state) throw new Error('nac needs deps.state');
  const P = prefixOf(deps), eps = deps.state.collection('fmg_endpoints'), dec = deps.state.collection('nac_decisions'), NOW = deps.now || Date.now;
  const nextId = () => { let m = 0; for (const d of dec.all()) { const n = Number(String(d.id).slice(4)); if (n > m) m = n; } return 'NAC-' + String(m + 1).padStart(5, '0'); };
  api.route('GET', `${P}/nac/endpoints`, wrap(deps, 'analyst', () => {
    const all = eps.all(), now = NOW(), list = assess(all, dec.all(), now), oldest = all.reduce((a, e) => Math.min(a, Date.parse(e.first_seen) || now), now);
    const sites = {}; for (const e of list) { const s = sites[e.site] = sites[e.site] || { site: e.site, endpoints: 0, risky: 0 }; s.endpoints++; if (e.risk >= 30) s.risky++; }
    return { connected: !!deps.fmgApi, learning: now - oldest < 7 * 86400000, learning_until: new Date(oldest + 7 * 86400000).toISOString().slice(0, 10), endpoints: list.slice(0, 3000), total: list.length,
      sites: Object.values(sites).map((s) => Object.assign(s, { exposure: s.endpoints ? Math.round(100 * s.risky / s.endpoints) : 0 })).sort((a, b) => b.exposure - a.exposure),
      decisions: dec.all().sort((a, b) => String(b.id).localeCompare(String(a.id))).slice(0, 300) };
  }));
  api.route('POST', `${P}/nac/decisions`, wrap(deps, 'operator', async (ctx) => {
    const b = body(ctx.body).str('mac', { required: true, max: 17 }).oneOf('action', ['authorise', 'quarantine'], { required: true }).str('owner', { max: 120 }).str('reason', { required: true, max: 400 }).done();
    const mac = b.mac.toLowerCase(); if (!MAC.test(mac)) throw new HttpError(400, 'mac: aa:bb:cc:dd:ee:ff');
    if (!eps.get(mac)) throw new HttpError(404, 'mac: not seen by any FortiGate');
    if (b.reason.length < 10) throw new HttpError(400, 'reason: say why, in at least 10 characters');
    if (b.action === 'authorise' && !b.owner) throw new HttpError(400, 'owner: who the device belongs to');
    if (dec.all((d) => d.mac === mac && d.action === b.action && d.status === 'proposed').length) throw new HttpError(409, 'a ' + b.action + ' for ' + mac + ' is already waiting for approval');
    const d = dec.put({ id: nextId(), mac, action: b.action, owner: b.owner || '', reason: b.reason, status: 'proposed', proposed_by: ctx.user, proposed_at: new Date(NOW()).toISOString() });
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
