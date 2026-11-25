// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// The route map with FortiGates managed by FortiManager: the proposal adds one node per managed FortiGate at its site, an IPsec
// link where a tunnel's peer is another managed FortiGate's address, one SD-WAN link per member to the Internet (distinct ids);
// a saved map measures those nodes and links from the FortiManager poll (down tunnel, SD-WAN member out of SLA / down, a
// FortiGate FortiManager cannot reach). Without FortiManager nothing changes. SYNTHETIC network.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createState } = require('../engine/soc/state');
const { createRouteMap } = require('../engine/netops/routemap');

const G = (name, o) => Object.assign({ name, serial: 'SN-' + name, adom: 'Sites', site: '', ip: '', conn: 'up', health: 'ok', metrics: { cpu: 5, mem: 30 }, tunnels: [], links: [], findings: [] }, o);
function fleet(state) {
  return [
    G('FGT-HQ', { site: 'HQ', ip: '198.51.100.1', tunnels: [{ name: 'to-site7', peer: '198.51.100.7', up: state.tunnel }, { name: 'to-unknown', peer: '192.0.2.99', up: true }] }),
    G('FGT-S7', { site: 'Site 7', ip: '198.51.100.7', tunnels: [{ name: 'to-hq', peer: '198.51.100.1', up: state.tunnel }],
      links: [{ check: 'hc', member: 'wan1', state: 'up', latency: 20, jitter: 2, loss: 0, sla_ok: true }, { check: 'hc', member: 'wan2', state: state.wan2, latency: 300, jitter: 40, loss: 8, sla_ok: false }] }),
    G('FGT-S9', { site: 'Site 9', ip: '198.51.100.9', conn: state.s9 }),
  ];
}
function mk(withFmg = true) {
  const st = { tunnel: true, wan2: 'up', s9: 'up' };
  const F = { fleet: () => ({ devices: fleet(st) }), device: (n) => { const d = fleet(st).find((x) => x.name === n); if (!d) throw new Error('not found'); return d; } };
  const state = createState({ dir: fs.mkdtempSync(path.join(os.tmpdir(), 'rmf-')) });
  const RM = createRouteMap({ inventory: { list: () => [], get: () => null }, poller: { snapshot: () => null, snapshots: () => ({}) }, state, log: { info() {}, warn() {} }, config: {}, now: () => Date.parse('2026-11-25T10:00:00Z'), fmg: () => (withFmg ? F : null) });
  return { RM, st };
}

test('proposal from FortiManager: nodes per FortiGate, IPsec where the peer is managed, one SD-WAN link per member', () => {
  const { RM } = mk();
  const p = RM.propose(), m = p.map || p;
  const fg = m.nodes.filter((n) => n.fortigate);
  assert.deepEqual(fg.map((n) => n.fortigate).sort(), ['FGT-HQ', 'FGT-S7', 'FGT-S9']);
  assert.ok(fg.every((n) => n.kind === 'firewall' && n.site), 'at their sites');
  const ipsec = m.links.filter((l) => l.kind === 'ipsec'); assert.equal(ipsec.length, 1, 'HQ ↔ Site 7 once (both ends name it)');
  const sd = m.links.filter((l) => l.kind === 'sdwan'); assert.equal(sd.length, 2); assert.notEqual(sd[0].id, sd[1].id, 'distinct ids per member');
  assert.ok(m.nodes.some((n) => n.id === 'internet'));
  assert.ok(JSON.stringify(p).includes('192.0.2.99'), 'a tunnel to an unmanaged peer is said');
  assert.equal(mk(false).RM.propose().map ? mk(false).RM.propose().map.nodes.filter((n) => n.fortigate).length : 0, 0, 'no FortiManager, no FortiGate nodes');
});

test('a saved map is measured from the FortiManager poll', () => {
  const { RM, st } = mk();
  const p = RM.propose(), m = p.map || p;
  RM.save(m, 'admin.syn');
  let v = RM.evaluate({});
  const link = (kind, pred) => v.links.find((l) => l.kind === kind && (!pred || pred(l)));
  assert.equal(link('ipsec').state, 'up');
  st.tunnel = false; st.wan2 = 'down'; st.s9 = 'down';
  v = RM.evaluate({});
  assert.equal(link('ipsec').state, 'down'); assert.match(JSON.stringify(link('ipsec')), /to-(site7|hq)/);
  assert.ok(v.links.some((l) => l.kind === 'sdwan' && l.state === 'down'), 'SD-WAN member down');
  assert.ok(v.nodes.some((n) => n.label === 'FGT-S9' && n.state === 'down'), 'a FortiGate FortiManager cannot reach is down');
});
