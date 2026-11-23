// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// One-way audio troubleshooter (netops/voice.js) and the voice facts added to fwfacts.js: RTP per direction from the firewall
// logs (denied, no reply, NAT, which firewall saw which direction), SIP ALG on FortiGate / PAN-OS, policies that allow the
// voice range one way only, SCCP phones not blamed on the SIP ALG, WAN events, the phone / call manager checks. Route: analyst
// runs it, operator for a live re-read, viewer refused, validation names the field, the run is audited. SYNTHETIC data only.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs'), os = require('node:os'), path = require('node:path');
const FACTS = require('../engine/netops/fwfacts');
const { diagnose, coversRtp, oneDirection } = require('../engine/netops/voice');
const routes = require('../engine/netops/routes');
const { createState } = require('../engine/soc/state');

const FG = { id: 'fg-br', name: 'FG-BRANCH-SYN', vendor: 'fortigate', ip: '10.30.0.1' }, PA = { id: 'pa-dc', name: 'PA-DC-SYN', vendor: 'paloalto', ip: '10.0.0.1' };
const A = '10.30.1.25', B = '10.0.20.40';
const fgFacts = (o = {}) => Object.assign({ vendor: 'fortigate', at: 1, settings: { asymroute: 'disable', default_voip_alg_mode: 'proxy-based' }, session_helper: [{ id: 13, name: 'sip', protocol: 17, port: 5060 }, { id: 1, name: 'pptp', protocol: 6, port: 1723 }],
  services: [{ name: 'CISCO-RTP', udp: '16384-32767' }, { name: 'DNS', udp: '53' }],
  policies: [{ id: 21, name: 'voice-out', status: 'enable', action: 'accept', srcintf: ['voice'], dstintf: ['to-DC'], service: ['CISCO-RTP'], voip_profile: 'default' }, { id: 22, name: 'dns', status: 'enable', action: 'accept', srcintf: ['to-DC'], dstintf: ['voice'], service: ['DNS'] }] }, o);
const paFacts = (o = {}) => Object.assign({ vendor: 'paloalto', at: 1, alg: [], rules: { items: [{ name: 'voice', action: 'allow', from: ['dc'], to: ['vpn'], application: ['rtp', 'rtcp'], service: ['any'] }, { name: 'voice-back', action: 'allow', from: ['vpn'], to: ['dc'], application: ['rtp'], service: ['any'] }] } }, o);
const row = (o) => Object.assign({ vendor: 'fortigate', firewall: 'FG-BRANCH-SYN', firewall_ip: FG.ip, kind: 'rtp', action: 'accept', sessions: 10, oneway: 0, nat_ip: '', peer: B, sample: `${A}:20480 → ${B}:24576` }, o);
function deps(F, rows, o = {}) {
  return { inventory: { list: () => o.devs || [FG, PA] }, poller: { snapshot: (id) => ({ security: { facts: F[id] }, system: (o.system || {})[id] || { cpu_pct: 20, mem_pct: 40 } }) },
    evidence: { voiceFlows: async (q) => { deps.last = q; return rows; }, deviceEvents: async ({ host }) => (o.events || []).filter((e) => !e.host || e.host === host) } };
}

test('helpers: RTP range coverage (ALL, ALL_UDP, a custom range) and one-way pairs', () => {
  assert.equal(coversRtp(['ALL'], []), true); assert.equal(coversRtp(['ALL_UDP'], []), true);
  assert.equal(coversRtp(['CISCO-RTP'], [{ name: 'CISCO-RTP', udp: '16384-32767:1024-65535' }]), true);
  assert.equal(coversRtp(['PART'], [{ name: 'PART', udp: '16384-20000' }]), false);
  assert.equal(coversRtp(['HTTPS'], [{ name: 'HTTPS', tcp: '443' }]), false);
  assert.deepEqual(oneDirection([{ from: 'voice', to: 'wan' }, { from: 'lan', to: 'dmz' }, { from: 'dmz', to: 'lan' }]).map((p) => p.from + '>' + p.to), ['voice>wan']);
});

test('facts: FortiGate VoIP ALG mode, SIP session helper, service ranges, VoIP profile per policy; PAN-OS ALG overrides', async () => {
  const FGJ = { '/api/v2/cmdb/system/settings': { asymroute: 'disable', 'default-voip-alg-mode': 'kernel-helper-based' }, '/api/v2/cmdb/system/session-helper': [{ id: 13, name: 'sip', protocol: 17, port: 5060 }],
    '/api/v2/cmdb/firewall.service/custom': [{ name: 'CISCO-RTP', protocol: 'TCP/UDP/SCTP', 'udp-portrange': '16384-32767' }], '/api/v2/cmdb/firewall/policy': [{ policyid: 5, action: 'accept', srcintf: [], dstintf: [], service: [], 'voip-profile': { name: 'strict' } }] };
  const f = await FACTS.fortigate(FG, { token: 'synthetic-token' }, { get: async (u) => { const p = new URL(u).pathname; return p in FGJ ? { status: 200, json: { results: FGJ[p] } } : { status: 403 }; } });
  assert.equal(f.settings.default_voip_alg_mode, 'kernel-helper-based');
  assert.deepEqual(f.session_helper, [{ id: 13, name: 'sip', protocol: 17, port: 5060 }]);
  assert.equal(f.services[0].udp, '16384-32767'); assert.equal(f.policies[0].voip_profile, 'strict');
  assert.ok(f.unread.some((u) => u.section === 'ssl_profiles'), 'a refused section is unread, never a pass');
  assert.ok(!JSON.stringify(f).includes('synthetic-token'));
  const p = await FACTS.paloalto(PA, { token: 'k' }, { get: async (u) => { const q = new URL(u).searchParams; if (q.get('type') === 'op') return { status: 200, text: '<response status="success"><result/></response>' };
    return { status: 200, text: '<response status="success"><result>' + (q.get('xpath') === FACTS.PA_XPATH.alg ? '<application><entry name="sip"><alg-disabled>yes</alg-disabled></entry></application>' : '') + '</result></response>' }; } });
  assert.deepEqual(p.alg, [{ name: 'sip', disabled: true }]);
});

test('a denied direction: the firewall that blocks it, which side hears nothing, both-direction fix with rollback', async () => {
  const rows = [row({ direction: 'a_to_b' }), row({ direction: 'b_to_a', action: 'deny', sessions: 7, sample: `${B}:24576 → ${A}:20480` })];
  const r = await diagnose(deps({ 'fg-br': fgFacts({ settings: { default_voip_alg_mode: 'kernel-helper-based' }, session_helper: [] }), 'pa-dc': paFacts({ alg: [{ name: 'sip', disabled: true }] }) }, rows), { a: A, b: B, hear: 'a_cannot_hear_b' });
  assert.equal(r.causes[0].id, 'rtp-deny'); assert.match(r.causes[0].title, /FG-BRANCH-SYN blocks the voice from 10\.0\.20\.40 to 10\.30\.1\.25/);
  assert.match(r.summary, /audio 10\.0\.20\.40 → 10\.30\.1\.25 is lost/);
  const s = r.causes[0].steps[0]; assert.ok(s.commands.some((c) => /udp-portrange 16384-32767/.test(c)) && s.commands.filter((c) => /set name "SENTRA-VOICE-RTP/.test(c)).length === 2 && s.rollback.length);
  assert.equal(deps.last.a, A); assert.equal(r.manual.length, 4);
});

test('SIP ALG on with one-way audio is a high-confidence cause; the fix turns the ALG off and removes the helper, with rollback', async () => {
  const rows = [row({ direction: 'a_to_b', sessions: 12, oneway: 9 }), row({ direction: 'a_signalling', kind: 'sip', peer: '10.0.5.10', sample: `${A}:5060 → 10.0.5.10:5060` })];
  const r = await diagnose(deps({ 'fg-br': fgFacts(), 'pa-dc': paFacts() }, rows), { a: A, b: B, hear: 'a_cannot_hear_b' });
  const c = r.causes.find((x) => x.id === 'sip-alg'); assert.ok(c); assert.equal(c.confidence, 'high'); assert.equal(r.causes[0].id, 'sip-alg');
  const st = c.steps.find((x) => x.vendor === 'fortigate');
  assert.ok(st.commands.includes('    set default-voip-alg-mode kernel-helper-based') && st.commands.includes('    delete 13') && st.commands.includes('        unset voip-profile'));
  assert.ok(st.rollback.includes('    set default-voip-alg-mode proxy-based') && st.rollback.includes('        set port 5060'));
  assert.ok(!st.commands.includes('    delete 1'), 'only the SIP helper is removed, not pptp');
  assert.ok(r.checks.some((k) => /SIP ALG on the firewalls/.test(k.name) && k.status === 'warn'));
});

test('an SCCP phone is not blamed on the SIP ALG', async () => {
  const rows = [row({ direction: 'a_to_b' }), row({ direction: 'b_to_a' }), row({ direction: 'a_signalling', kind: 'sccp', peer: '10.0.5.10' })];
  const r = await diagnose(deps({ 'fg-br': fgFacts(), 'pa-dc': paFacts() }, rows), { a: A, b: B, hear: 'b_cannot_hear_a' });
  assert.ok(!r.causes.some((c) => c.id === 'sip-alg'));
  assert.ok(r.checks.some((k) => /SCCP/.test(k.detail || '')));
  assert.ok(r.checks.some((k) => /reported direction/.test(k.name)), 'the logs passed the reported direction: said');
});

test('asymmetric path, NAT on the voice, a policy one way only, WAN flaps and a firewall under pressure', async () => {
  let r = await diagnose(deps({ 'fg-br': fgFacts({ settings: { default_voip_alg_mode: 'kernel-helper-based' }, session_helper: [] }), 'pa-dc': paFacts({ alg: [{ name: 'sip', disabled: true }] }) },
    [row({ direction: 'a_to_b', oneway: 10 }), row({ direction: 'b_to_a', vendor: 'paloalto', firewall: 'PA-DC-SYN', firewall_ip: PA.ip, oneway: 10 })]), { a: A, b: B, hear: 'both' });
  assert.equal(r.causes[0].id, 'asymmetric'); assert.match(r.causes[0].explanation, /FG-BRANCH-SYN.*PA-DC-SYN/s);
  r = await diagnose(deps({ 'fg-br': fgFacts({ settings: { default_voip_alg_mode: 'kernel-helper-based' }, session_helper: [], policies: [] }), 'pa-dc': paFacts({ alg: [{ name: 'sip', disabled: true }] }) },
    [row({ direction: 'a_to_b', oneway: 8, nat_ip: '172.16.0.9' })]), { a: A, b: B, hear: 'a_cannot_hear_b' });
  assert.ok(r.causes.some((c) => c.id === 'nat' && c.confidence === 'high'));
  r = await diagnose(deps({ 'fg-br': fgFacts({ settings: { default_voip_alg_mode: 'kernel-helper-based' }, session_helper: [] }), 'pa-dc': paFacts({ alg: [{ name: 'sip', disabled: true }] }) },
    [row({ direction: 'a_to_b', oneway: 8 })], { system: { 'fg-br': { cpu_pct: 97, mem_pct: 60 } }, events: [{ ts: 't1', host: 'FG-BRANCH-SYN', message: 'IPsec tunnel to-DC down' }, { ts: 't2', host: 'FG-BRANCH-SYN', message: 'IPsec tunnel to-DC up' }] }), { a: A, b: B, hear: 'a_cannot_hear_b' });
  const ids = r.causes.map((c) => c.id);
  for (const id of ['policy-one-way', 'wan-flap', 'resources']) assert.ok(ids.includes(id), id + ' in ' + ids);
  assert.match(r.causes.find((c) => c.id === 'policy-one-way').title, /voice → to-DC but not back/);
});

test('nothing logged, and no firewalls at all: said plainly, the phone and call manager checks remain', async () => {
  let r = await diagnose(deps({}, []), { a: A, b: B });
  assert.ok(r.causes.some((c) => c.id === 'no-logs')); assert.match(r.summary, /Most likely|No voice/);
  r = await diagnose({ inventory: { list: () => [] }, poller: { snapshot: () => null }, evidence: null }, { a: A, b: B });
  assert.match(r.summary, /Add the firewalls/); assert.equal(r.manual.length, 4);
});

test('route: analyst runs it, live re-read needs operator, viewer refused, validation names the field, audited', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentra-voice-')), state = await createState({ dir: path.join(dir, 'state') });
  const config = { netops: { enabled: false } }; Object.defineProperty(config, 'secrets', { value: {}, enumerable: false, writable: true });
  const F = { 'fg-br': fgFacts(), 'pa-dc': paFacts() }; let live = 0;
  const poller = { snapshot: (id) => ({ security: { facts: F[id] } }), snapshots: () => ({}), stats: () => ({}), forget() {}, start() {} };
  const N = routes.createNetops({ state, config, log: { info() {}, warn() {}, error() {} }, poller, factsFor: async (d) => { live++; return F[d.id]; } });
  for (const d of [FG, PA]) N.inventory.put(Object.assign({ site: 'Riyadh HQ', poll: {} }, d), 'syed');
  const R = {}; routes.register({ route: (m, p, h) => { R[m + ' ' + p] = h; } }, { state, config, log: { error() {}, info() {} }, netops: N });
  const RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 }, audits = [];
  async function call(role, body) {
    const out = {}; const ctx = { role, user: 'omar.syn', body, params: {}, query: {}, need(r) { if (RANK[role] < RANK[r]) { out.status = 403; return false; } return true; }, audit: (a, t, d) => audits.push({ a, t, d }), ok(b) { out.status = 200; out.body = b; }, fail(c, msg) { out.status = c; out.error = msg; } };
    try { const rv = await R['POST /api/soc/netops/voice'](ctx); if (rv !== undefined && !out.status) { out.status = 200; out.body = rv; } } catch (e) { out.status = e.status || e.code; out.error = e.message; }
    return out;
  }
  assert.equal((await call('viewer', { a: A, b: B })).status, 403);
  let r = await call('analyst', { a: A, b: B, hear: 'a_cannot_hear_b', extra: 'dropped' });
  assert.equal(r.status, 200, r.error); assert.equal(r.body.lost, 'b_to_a'); assert.equal(live, 0);
  assert.ok(r.body.checks.some((c) => /Voice sessions/.test(c.name) && c.status === 'skip'), 'no log database here: said, not hidden');
  assert.equal((await call('analyst', { a: A, b: B, refresh: true })).status, 403);
  assert.equal((await call('operator', { a: A, b: B, refresh: true })).status, 200); assert.equal(live, 2);
  for (const [b, re] of [[{ b: B }, /a is required/], [{ a: 'phone1', b: B }, /a must be/], [{ a: A, b: '10.0.0.0/40' }, /b must be/], [{ a: A, b: A }, /differ/], [{ a: A, b: B, hear: 'loud' }, /hear/], [{ a: A, b: B, minutes: 5 }, /minutes/]]) {
    const x = await call('analyst', b); assert.equal(x.status, 400, JSON.stringify(b)); assert.match(x.error || '', re);
  }
  const au = audits.filter((x) => x.a === 'netops.voice.diagnose');
  assert.ok(au.length >= 2 && au[0].d.a === A && au[0].d.hear === 'a_cannot_hear_b');
});

test('evidence.voiceFlows: both directions and side a signalling, values as bound parameters, bad input refused', async () => {
  const { createEvidence } = require('../engine/netops/evidence');
  let got = null; const E = createEvidence({ ch: { query: async (sql, params) => { got = { sql, params }; return []; } }, config: {} });
  await E.voiceFlows({ a: '10.30.1.0/24', b: B, minutes: 60 });
  assert.match(got.sql, /isIPAddressInRange\(src_ip, \{a:String\}\)/); assert.match(got.sql, /dst_ip = \{b:String\}/); assert.match(got.sql, /'a_to_b'.*'b_to_a'.*'a_signalling'/s);
  assert.ok(!got.sql.includes('10.30.1.0') && !got.sql.includes(B), 'addresses never in the SQL text');
  assert.deepEqual([got.params.a.value, got.params.b.value, got.params.m.value], ['10.30.1.0/24', B, 60]);
  await assert.rejects(E.voiceFlows({ a: "10.0.0.1' OR 1=1", b: B }), /a must be an IP address or subnet/);
});
