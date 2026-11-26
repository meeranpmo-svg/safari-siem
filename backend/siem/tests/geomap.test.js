// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Network Map (engine/netops/geomap.js), SYNTHETIC firewalls: offices from the FortiGate fleet grouped by site, placed on the map
// of Saudi Arabia by a city in the site name (never guessed when unknown), connectivity to the hub (up / degraded / down / online),
// KPIs; an administrator places an unmatched office (validated, in Saudi bounds); the ML flags flapping and an unusual outage from
// each office's own history; nothing connected says so; the map outline and city list are returned for the page.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs'), os = require('node:os'), path = require('node:path');
const { createState } = require('../engine/soc/state');
const G = require('../engine/netops/geomap');

const dev = (name, site, conn, tunnels, health) => ({ name, site, conn, health: health || (conn === 'down' ? 'down' : 'ok'), model: 'FortiGate-60F', tunnels: tunnels || [] });
function fakeFmg(devices) { let polled = true; return { status: () => ({ configured: true, last_poll_at: polled ? '2026-11-26T06:00:00Z' : null }), fleet: () => ({ devices }), _off: () => { polled = false; } }; }
function mk(devices, extra) {
  const state = createState({ dir: fs.mkdtempSync(path.join(os.tmpdir(), 'geo-')) });
  let t = Date.parse('2026-11-26T09:00:00Z');
  const deps = Object.assign({ state, fmgApi: fakeFmg(devices), now: () => t, noTimer: true, config: {}, prefix: '/api/soc' }, extra || {});
  return { g: G.createGeomap(deps), state, setT: (x) => { t = x; }, deps };
}

test('offices placed by city, connectivity to the hub, KPIs, the map outline', () => {
  const { g } = mk([
    dev('FGT-HQ-01', 'Riyadh Head Office', 'up', [{ up: true }]),
    dev('FGT-JED-01', 'Jeddah Project Office', 'up', [{ up: true }]),
    dev('FGT-DMM-01', 'Dammam Site', 'up', [{ up: false }]),        // online, VPN down -> degraded
    dev('FGT-ABH-01', 'Abha Camp', 'down', []),                      // offline -> down
    dev('FGT-XX-01', 'Mystery Compound', 'up', [{ up: true }]),      // no city -> unplaced
  ]);
  const v = g.view();
  assert.equal(v.connected, true); assert.equal(v.kpis.offices, 5); assert.equal(v.kpis.placed, 4); assert.equal(v.kpis.unplaced, 1);
  const hq = v.sites.find((s) => s.name === 'Riyadh Head Office'); assert.ok(hq.hub && hq.placed && Math.round(hq.lat) === 25 && Math.round(hq.lng) === 47, JSON.stringify(hq));
  assert.equal(v.hub, hq.id);
  const jed = v.sites.find((s) => /Jeddah/.test(s.name)); assert.equal(jed.state, 'up'); assert.ok(jed.placed && jed.lng < 40, 'Jeddah on the west coast');
  assert.equal(v.sites.find((s) => /Dammam/.test(s.name)).state, 'degraded');
  assert.equal(v.sites.find((s) => /Abha/.test(s.name)).state, 'down');
  const un = v.sites.find((s) => /Mystery/.test(s.name)); assert.equal(un.placed, false); assert.equal(un.lat, null);
  // links: every placed office except the hub links to the hub, with a reason
  assert.equal(v.links.length, 3); const lj = v.links.find((l) => l.from === jed.id); assert.equal(lj.to === hq.id && lj.state === 'up', true); assert.match(v.links.find((l) => l.from === v.sites.find((s) => /Dammam/.test(s.name)).id).reason, /VPN tunnels down/);
  assert.equal(v.kpis.up + v.kpis.degraded + v.kpis.down >= 3, true);
  assert.ok(Array.isArray(v.outline) && v.outline.length > 10 && v.outline.every((p) => p.lat >= 16 && p.lat <= 33 && p.lng >= 34 && p.lng <= 56), 'a Saudi Arabia outline for the page');
  assert.ok(v.cities.some((c) => c.name === 'Riyadh'));
});

test('an administrator places an office the city match did not find; validated; in Saudi bounds; audited', () => {
  const { g, state } = mk([dev('FGT-XX-01', 'Mystery Compound', 'up', [{ up: true }])]);
  const ADM = { user: 'admin.syn', role: 'admin' };
  assert.throws(() => g.setSite('mystery-compound', { lat: 99, lng: 46 }, ADM), /lat must be at most 33/);
  assert.throws(() => g.setSite('mystery-compound', { lat: 24 }, ADM), /lng is required/);
  const r = g.setSite('mystery-compound', { lat: 24.6, lng: 46.7 }, ADM); assert.equal(r.lat, 24.6);
  const v = g.view(); const m = v.sites.find((s) => /Mystery/.test(s.name)); assert.equal(m.placed, true); assert.equal(m.located_by, 'set'); assert.equal(m.lat, 24.6);
  assert.ok(state.collection('geomap_coords').get('mystery-compound'));
});

test('ML: flapping and an unusual outage from each office own history; nothing fabricated', () => {
  const online = [dev('FGT-A', 'Riyadh Office', 'up', [{ up: true }])];
  const { g, setT } = mk(online);
  const DAY = 86400000, start = Date.parse('2026-11-19T09:00:00Z');
  // 7 steady days for a Jeddah office that is up, then it is down now (unusual outage); a Riyadh office that flaps today
  for (let d = 0; d < 7; d++) { setT(start + d * DAY); online.length = 0; online.push(dev('FGT-A', 'Riyadh Office', 'up', [{ up: true }]), dev('FGT-B', 'Jeddah Office', 'up', [{ up: true }])); g.sample(); }
  // today: 10 readings, Riyadh flipping online/offline; Jeddah goes offline
  const today = Date.parse('2026-11-26T00:00:00Z');
  for (let i = 0; i < 12; i++) { setT(today + i * 3600000); online.length = 0; online.push(dev('FGT-A', 'Riyadh Office', i % 2 ? 'up' : 'down', i % 2 ? [{ up: true }] : []), dev('FGT-B', 'Jeddah Office', 'up', [{ up: true }])); g.sample(); }
  setT(today + 13 * 3600000); online.length = 0; online.push(dev('FGT-A', 'Riyadh Office', 'up', [{ up: true }]), dev('FGT-B', 'Jeddah Office', 'down', []));
  const v = g.view();
  assert.ok(v.anomalies.some((a) => a.kind === 'flapping' && /Riyadh/.test(a.name)), 'flapping flagged: ' + JSON.stringify(v.anomalies));
  assert.ok(v.anomalies.some((a) => a.kind === 'outage' && /Jeddah/.test(a.name) && /up 100 %|up 9[0-9] %/.test(a.why)), 'unusual outage flagged: ' + JSON.stringify(v.anomalies));
});

test('nothing connected: says so, no fabricated office', () => {
  const { g } = mk([]); const F = g.view;
  const { g: g2 } = mk([dev('X', 'Riyadh', 'up', [])]); g2.view(); // sanity
  const empty = mk([]); empty.deps.fmgApi._off();
  const v = empty.g.view(); assert.equal(v.connected, false); assert.equal(v.sites.length, 0); assert.match(v.note, /No FortiGate is connected/); assert.deepEqual(v.anomalies, []);
  assert.ok(v.outline.length > 10, 'the map outline is still returned');
});
