// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Port map on H3C / HPE Comware 7: interface brief (link, speed, duplex, access / trunk / hybrid, PVID, description, route-mode
// section ignored), MAC table, LLDP verbose, ARP and VLANs; port names in the short Comware form so the tables join; the read
// uses only display commands. Output is SYNTHETIC in the Comware 7 layout.
const test = require('node:test');
const assert = require('node:assert/strict');
const PM = require('../engine/netops/portmap');

const BRIEF = `Brief information on interfaces in route mode:
Link: ADM - administratively down; Stby - standby
Interface            Link Protocol Primary IP      Description
Vlan10               UP   UP       10.7.10.1
Brief information on interfaces in bridge mode:
Link: ADM - administratively down; Stby - standby
Speed: (a) - auto
Duplex: (a)/A - auto; H - half; F - full
Type: A - access; T - trunk; H - hybrid
Interface            Link Speed   Duplex Type PVID Description
GE1/0/1              UP   1G(a)   F(a)   A    10   PC-RECEPTION
GE1/0/2              DOWN auto    A      A    1
GE1/0/3              ADM  auto    A      A    10
GE1/0/4              UP   100M(a) H(a)   A    20   PRINTER 2F
XGE1/0/49            UP   10G     F      T    1    uplink to core
BAGG1                UP   20G     F      T    1
`;
const MACS = `MAC Address      VLAN ID    State            Port/NICKNAME            Aging
0011-2233-4401   10         Learned          GE1/0/1                  Y
0011-2233-4402   10         Learned          GE1/0/1                  Y
0011-2233-4404   20         Learned          GE1/0/4                  Y
00aa-bbcc-dd01   1          Learned          XGE1/0/49                Y
--- 4 MAC address(es) found ---
`;
const LLDP = `LLDP neighbor-information of port 49[Ten-GigabitEthernet1/0/49]:
LLDP agent nearest-bridge:
 LLDP neighbor index : 1
 ChassisID/subtype   : 00aa-bbcc-dd01/MAC address
 PortID/subtype      : Ten-GigabitEthernet1/0/1/Interface name
 Port description    : to access 2F
 System name         : CORE-SYN
 System description  : H3C Comware Platform Software
 System capabilities supported : Bridge,Router
 System capabilities enabled   : Bridge,Router
 Management address type : IPv4
 Management address  : 10.7.0.2
`;
const ARP = `  Type: S-Static   D-Dynamic   O-Openflow   R-Rule   M-Multiport  I-Invalid
IP address      MAC address    VLAN/VSI name Interface                Aging Type
10.7.10.21      0011-2233-4401 10            GE1/0/1                  20    D
10.7.20.30      0011-2233-4404 20            GE1/0/4                  18    D
`;
const VLANS = `Brief information about all VLANs:
Supported Minimum VLAN ID: 1
VLAN ID   Name                            Port
1         VLAN 0001                       GE1/0/2
10        Users                           GE1/0/1 GE1/0/3
20        Printers                        GE1/0/4
`;

test('Comware parsers: ports, trunks, MAC table, LLDP, ARP, VLANs', () => {
  const st = PM.cwStatus(BRIEF);
  assert.deepEqual(st.ports.map((p) => p.port), ['GE1/0/1', 'GE1/0/2', 'GE1/0/3', 'GE1/0/4', 'XGE1/0/49', 'BAGG1'], 'route-mode section ignored');
  assert.deepEqual([st.ports[0].status, st.ports[0].vlan, st.ports[0].duplex, st.ports[0].speed, st.ports[0].name], ['connected', '10', 'full', '1g(a)'.replace(/[()]/g, ''), 'PC-RECEPTION']);
  assert.equal(st.ports[1].status, 'notconnect'); assert.equal(st.ports[2].status, 'disabled'); assert.equal(st.ports[3].duplex, 'half'); assert.equal(st.ports[4].vlan, 'trunk');
  assert.ok(st.trunks.has('xge1/0/49') && st.trunks.has('bagg1') && !st.trunks.has('ge1/0/1'));
  const m = PM.cwMacs(MACS); assert.equal(m.length, 4); assert.deepEqual(m[0], { vlan: 10, mac: '001122334401', type: 'learned', port: 'GE1/0/1' });
  const l = PM.cwLldp(LLDP)[0]; assert.deepEqual([l.local, l.name, l.ip, l.caps.join(',')], ['XGE1/0/49', 'CORE-SYN', '10.7.0.2', 'Bridge,Router'], 'long names map to the short form the other tables use');
  assert.deepEqual(PM.cwArp(ARP), [{ ip: '10.7.10.21', mac: '001122334401' }, { ip: '10.7.20.30', mac: '001122334404' }]);
  assert.deepEqual(PM.cwVlans(VLANS), { 1: 'VLAN 0001', 10: 'Users', 20: 'Printers' });
  assert.equal(PM.cwIf('Ten-GigabitEthernet1/0/49'), 'XGE1/0/49'); assert.equal(PM.cwIf('GigabitEthernet 1/0/1'), 'GE1/0/1'); assert.equal(PM.cwIf('Bridge-Aggregation1'), 'BAGG1');
});

test('reading an H3C switch: display commands only, ports and MACs stored, trunk MACs not counted as endpoints', async () => {
  const fs = require('node:fs'), os = require('node:os'), path = require('node:path');
  const { createState } = require('../engine/soc/state');
  const state = createState({ dir: fs.mkdtempSync(path.join(os.tmpdir(), 'pmh3c-')) });
  const OUT = { 'display interface brief': BRIEF, 'display mac-address': MACS, 'display lldp neighbor-information verbose': LLDP, 'display arp': ARP, 'display vlan brief': VLANS };
  const sent = [];
  const dev = { id: 'sw-2f', name: 'SW-2F-SYN', vendor: 'h3c-comware', ip: '10.7.0.3', role: 'access' };
  const cli = { supported: () => true, hostKey: () => 'SHA256:syn', run: async (id, cmds) => { sent.push(...cmds); return { results: cmds.map((c) => ({ output: OUT[c] || '' })) }; } };
  const P = PM.createPortMap({ inventory: { list: () => [dev], get: (id) => (id === dev.id ? dev : null), credentialSummary: () => ({ ssh: true }) }, poller: { snapshot: () => null }, cli, tasks: null, state, config: {}, log: { info() {}, warn() {} }, now: () => Date.parse('2026-11-25T10:00:00Z') });
  const r = await P.read('sw-2f', 'op.syn');
  assert.equal(r.ports, 6); assert.equal(r.macs, 4); assert.deepEqual(r.errors, []);
  assert.ok(sent.length && sent.every((c) => /^display /.test(c)), 'read-only display commands: ' + sent);
  const macs = state.collection('portmap_macs').all();
  assert.ok(macs.some((m) => m.id === '001122334401' && m.port === 'ge1/0/1'));
  assert.ok(!macs.some((m) => m.id === '00aabbccdd01'), 'a MAC learned on the trunk uplink is not an endpoint');
  const rec = state.collection('portmap_reads').get('sw-2f'); assert.equal(rec.vendor, 'h3c-comware'); assert.ok(rec.trunks.includes('xge1/0/49'));
});
