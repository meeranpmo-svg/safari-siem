// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Network Map - the organisation's offices on a map of Saudi Arabia with their firewalls and the connectivity between them, live.
 * Every figure comes from the FortiGate fleet (netops/fmg.js through FortiManager and the standalone FortiGates): each firewall's
 * site (its FortiManager description / location), whether it is online, and its IPsec tunnels. An office is placed on the map by a
 * Saudi city found in its site name, or by coordinates an administrator sets; one that cannot be placed is listed to the side,
 * never guessed onto the map. Connectivity is each office's VPN link back to the hub (Head Office / Data Centre): up when the
 * office firewall is online with a tunnel up, degraded when it is online but its tunnels are down, down when it is offline.
 *
 * Machine learning (no model call, each office against its own history): FLAPPING - an office whose firewall or tunnels changed
 * state many times in 24 h; UNUSUAL OUTAGE - an office down now that is up almost all of the time. Indicators from the records,
 * not proof; nothing is changed automatically. A change to a firewall stays the FortiGate fleet's own four-eyes plan.
 *
 *   GET /netops/geomap                 any signed-in   offices (placed + unplaced), links, KPIs, anomalies, the map outline
 *   PUT /netops/geomap/site/:id        admin           {lat, lng}  place an office the city match did not find (or move it)
 */
const ZYB_ORG = require('../util/brand');
const { body, param } = require('../util/check');
const { HttpError, wrap, audit } = require('../soc/routeutil');
const { guard } = require('../util/errors');

const MIN = 60000, H = 3600000, DAY = 86400000;
const low = (s) => String(s == null ? '' : s).toLowerCase();
const slug = (s) => low(s).replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '') || 'site';
// Saudi Arabia: major cities and project areas, latitude / longitude. An office's site name is matched against these (longest
// name first, so "Khamis Mushait" wins over "Khamis"); an administrator can set coordinates for anything not matched.
const CITIES = [
  ['Khamis Mushait', 18.31, 42.73], ['King Abdullah Economic City', 22.42, 39.10], ['Hafar Al-Batin', 28.43, 45.97], ['Hafar Albatin', 28.43, 45.97],
  ['Al-Ahsa', 25.38, 49.59], ['Al Ahsa', 25.38, 49.59], ['Al Kharj', 24.15, 47.30], ['Al Bahah', 20.01, 41.47], ['Al Baha', 20.01, 41.47],
  ['Riyadh', 24.71, 46.68], ['Jeddah', 21.49, 39.19], ['Makkah', 21.39, 39.86], ['Mecca', 21.39, 39.86], ['Madinah', 24.52, 39.57], ['Medina', 24.52, 39.57],
  ['Dammam', 26.43, 50.10], ['Khobar', 26.28, 50.21], ['Dhahran', 26.29, 50.15], ['Jubail', 27.00, 49.66], ['Hofuf', 25.38, 49.59], ['Buraidah', 26.36, 43.98],
  ['Unaizah', 26.08, 43.99], ['Qassim', 26.21, 43.50], ['Hail', 27.52, 41.69], ['Tabuk', 28.38, 36.57], ['Abha', 18.22, 42.51], ['Jizan', 16.89, 42.57],
  ['Jazan', 16.89, 42.57], ['Najran', 17.49, 44.13], ['Taif', 21.44, 40.51], ['Yanbu', 24.09, 38.06], ['Arar', 30.98, 41.04], ['Sakaka', 29.97, 40.21],
  ['Qurayyat', 31.33, 37.34], ['Rafha', 29.63, 43.50], ['NEOM', 27.90, 35.20], ['Umluj', 25.02, 37.27], ['Rabigh', 22.80, 39.03], ['Duba', 27.35, 35.69],
  ['Sharurah', 17.47, 47.11], ['Wadi Dawasir', 20.47, 44.80], ['Al Qatif', 26.52, 49.99], ['Qatif', 26.52, 49.99], ['Hafr', 28.43, 45.97], ['Baha', 20.01, 41.47],
].sort((a, b) => b[0].length - a[0].length);
// a simplified outline of Saudi Arabia (longitude, latitude) for the page to draw; the offices are projected the same way, so
// they sit in the right place on it. A schematic map, not a survey.
const OUTLINE = [
  [34.6, 28.1], [36.0, 29.2], [37.5, 31.0], [38.9, 31.8], [40.0, 31.9], [42.1, 31.1], [44.7, 29.2], [46.4, 29.1], [47.5, 28.9], [48.5, 28.5],
  [49.0, 28.1], [48.8, 27.6], [49.6, 27.0], [50.2, 26.5], [50.1, 25.6], [50.8, 25.0], [51.6, 24.8], [52.6, 23.0], [55.2, 22.6], [55.7, 20.0],
  [52.0, 19.0], [49.1, 18.6], [47.5, 17.4], [45.2, 17.3], [43.4, 17.5], [42.6, 16.4], [41.8, 16.9], [41.2, 18.7], [40.1, 20.3], [39.0, 21.5],
  [38.9, 23.0], [37.2, 24.3], [36.5, 25.5], [35.2, 26.6], [34.6, 28.1],
].map(([lng, lat]) => ({ lng, lat }));

function createGeomap(deps) {
  const now = deps.now || Date.now, state = deps.state, log = deps.log || { info() {}, warn() {} };
  const coords = () => state.collection('geomap_coords'), hist = () => state.collection('geomap_hist');
  const cfgSites = ((deps.config && deps.config.netops && deps.config.netops.geomap) || {}).sites || {};

  // where an office sits: an administrator's saved coordinates, then the brand / config coordinates, then a Saudi city in its name
  function locate(siteName) {
    const key = slug(siteName), lk = low(siteName).trim();
    const saved = coords().get(key); if (saved && isFinite(saved.lat) && isFinite(saved.lng)) return { lat: saved.lat, lng: saved.lng, by: 'set' };
    const c = cfgSites[siteName] || cfgSites[lk]; if (c && isFinite(c.lat) && isFinite(c.lng)) return { lat: Number(c.lat), lng: Number(c.lng), by: 'config' };
    for (const [name, lat, lng] of CITIES) if (lk.includes(low(name))) return { lat, lng, city: name, by: 'city' };
    return null;
  }
  const isHub = (name) => /head ?office|\bhq\b|data ?cent|\bdc\b|core|main office/i.test(name);

  // one office from its firewalls: worst health, online count, tunnels; its link to the hub
  function siteFrom(name, devs) {
    const online = devs.filter((d) => d.conn !== 'down').length, offline = devs.length - online;
    const tun = { up: 0, down: 0 }; for (const d of devs) for (const t of d.tunnels || []) tun[t.up ? 'up' : 'down']++;
    const order = { down: 0, attention: 1, watch: 2, ok: 3 };
    const health = devs.map((d) => d.health).sort((a, b) => order[a] - order[b])[0] || 'ok';
    const state = offline === devs.length && devs.length ? 'down' : online && tun.up ? 'up' : online && (tun.up + tun.down) ? 'degraded' : online ? 'online' : 'unknown';
    return { name, firewalls: devs.length, online, offline, health, tunnels_up: tun.up, tunnels_down: tun.down, state,
      devices: devs.slice(0, 40).map((d) => ({ name: d.name, model: d.model, health: d.health, online: d.conn !== 'down' })) };
  }

  function build() {
    const F = deps.fmgApi; const connected = !!(F && F.status && F.status().configured && F.status().last_poll_at);
    const bySite = {};
    if (connected) for (const d of F.fleet().devices) { const s = (d.site || '').trim() || 'Unassigned'; (bySite[s] = bySite[s] || []).push(d); }
    const all = Object.entries(bySite).map(([name, devs]) => { const loc = locate(name), base = siteFrom(name, devs);
      return Object.assign(base, { id: slug(name), hub: isHub(name), lat: loc ? loc.lat : null, lng: loc ? loc.lng : null, placed: !!loc, located_by: loc ? loc.by : null, city: loc ? loc.city || null : null }); });
    all.sort((a, b) => ({ down: 0, degraded: 1, online: 2, unknown: 3, up: 4 }[a.state] - { down: 0, degraded: 1, online: 2, unknown: 3, up: 4 }[b.state]) || a.name.localeCompare(b.name));
    return { connected, sites: all };
  }

  // one reading per office for the learning (online firewall, tunnels up); 8 days kept
  function sample() {
    const { connected, sites } = build(); if (!connected) return { sampled: 0 };
    const t = now(); for (const s of sites) hist().put({ id: s.id + '|' + t, site: s.id, t, online: s.online > 0, up: s.state === 'up', tun: s.tunnels_up });
    for (const o of hist().all((x) => t - x.t > 8 * DAY)) hist().remove(o.id);
    return { sampled: sites.length };
  }

  // flapping and unusual outage, each office against its own 7-day history
  function anomalies(sites, t) {
    const out = [];
    for (const s of sites) {
      const h = hist().all((x) => x.site === s.id && t - x.t <= 7 * DAY).sort((a, b) => a.t - b.t);
      const day = h.filter((x) => t - x.t <= DAY);
      let flips = 0; for (let i = 1; i < day.length; i++) if (day[i].online !== day[i - 1].online || day[i].up !== day[i - 1].up) flips++;
      if (day.length >= 8 && flips >= 6) out.push({ site: s.id, name: s.name, kind: 'flapping', severity: 'high', why: s.name + ': the link changed state ' + flips + ' times in 24 h (' + day.length + ' readings) - usually steady' });
      else if (s.state === 'down' && h.length >= 12) { const days = new Set(h.map((x) => Math.floor(x.t / DAY))).size, up = h.filter((x) => x.online).length / h.length;
        if (days >= 2 && up >= 0.9) out.push({ site: s.id, name: s.name, kind: 'outage', severity: 'high', why: s.name + ' is down now - up ' + Math.round(up * 100) + ' % of the last ' + days + ' day(s) (' + h.length + ' readings)' }); }
    }
    return out.sort((a, b) => (b.severity === 'high') - (a.severity === 'high'));
  }

  function view() {
    const { connected, sites } = build(), t = now();
    const placed = sites.filter((s) => s.placed), hub = placed.find((s) => s.hub) || placed.slice().sort((a, b) => b.firewalls - a.firewalls)[0] || null;
    const links = hub ? placed.filter((s) => s.id !== hub.id).map((s) => ({ from: s.id, to: hub.id, state: s.state,
      reason: s.state === 'up' ? 'firewall online, VPN up' : s.state === 'degraded' ? 'firewall online, VPN tunnels down' : s.state === 'online' ? 'firewall online, no VPN tunnel seen' : s.state === 'down' ? 'firewall offline' : 'no firewall data' })) : [];
    const kpis = { offices: sites.length, placed: placed.length, unplaced: sites.length - placed.length, firewalls: sites.reduce((n, s) => n + s.firewalls, 0),
      up: sites.filter((s) => s.state === 'up').length, degraded: sites.filter((s) => s.state === 'degraded').length, down: sites.filter((s) => s.state === 'down').length };
    return { connected, at: new Date(t).toISOString(), hub: hub ? hub.id : null, sites, links, kpis, anomalies: connected ? anomalies(sites, t) : [], outline: OUTLINE, cities: CITIES.map(([name, lat, lng]) => ({ name, lat, lng })),
      note: connected ? '' : 'No FortiGate is connected yet - connect FortiManager or a standalone FortiGate in the Integration Hub. Name each firewall\'s location with its Saudi city so its office appears on the map.' };
  }

  function setSite(id, b0, who) {
    const key = slug(param(id, 'id')); if (key === 'site') throw new HttpError(400, 'id: not a site');
    const b = body(b0).num('lat', { required: true, min: 16, max: 33 }).num('lng', { required: true, min: 34, max: 56 }).done();
    coords().put({ id: key, lat: b.lat, lng: b.lng, by: who.user, at: new Date(now()).toISOString() });
    return { id: key, lat: b.lat, lng: b.lng };
  }

  if (!(deps.noTimer)) { const tm = setInterval(guard('netops.geomap.sample', () => sample()), 10 * MIN); if (tm.unref) tm.unref(); }
  return { view, sample, setSite, locate };
}

function register(api, deps) {
  if (!deps.state) return;
  const P = deps.prefix || '/api/soc', G = createGeomap(deps);
  deps.geomapApi = G;
  api.route('GET', `${P}/netops/geomap`, wrap(deps, null, () => G.view()));
  api.route('PUT', `${P}/netops/geomap/site/:id`, wrap(deps, 'admin', (ctx) => { const r = G.setSite(ctx.params.id, ctx.body, ctx); audit(ctx, 'geomap.site.set', r.id, { lat: r.lat, lng: r.lng }); return r; }), { maxBody: 512 });
}

module.exports = { createGeomap, register, CITIES, OUTLINE };
