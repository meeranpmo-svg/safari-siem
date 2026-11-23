// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Baseline-hardening snapshots: the Windows agent's daily snapshot event (parse/windows.js → action agent-hardening, skipped
// by detection), the latest-per-host store (hardening/store.js: persisted, size-capped, bad JSON refused), and
// GET /hardening/snapshots (analyst and above, viewer refused, read audited, unknown host 404, query validated). Synthetic data.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs'), os = require('node:os'), path = require('node:path');
const { createParser } = require('../engine/parse');
const { createHardeningStore } = require('../engine/hardening/store');
const routes = require('../engine/hardening/routes');

const SNAP = { os: { caption: 'Microsoft Windows Server 2022 Standard', product_type: 3 }, secpol: { MinimumPasswordLength: 8 }, reg: { SMB1: 0 } };
const line = (host, settings) => JSON.stringify({ Channel: 'SentraAgent', EventID: 1, TimeCreated: '2026-10-25T03:00:00.000Z', Computer: host, RecordId: 0, Level: 4, ProviderName: 'SentraAgent',
  EventData: { type: 'hardening', agent_version: '1.2.0', settings: typeof settings === 'string' ? settings : JSON.stringify(settings) }, Message: 'SentraAgent hardening snapshot' });

function ctxOf(user, role, query) {
  const out = { status: 200, body: null }, audits = [];
  const RANK = { viewer: 0, analyst: 1, operator: 2, admin: 3 };
  return { user, role, query: query || {}, params: {}, out, audits,
    need: (r) => { if ((RANK[role] || 0) < RANK[r]) { out.status = 403; return false; } return true; },
    ok: (j) => { out.body = j; return j; }, fail: (code, msg) => { out.status = code; out.body = { error: msg }; return out.body; },
    audit: (action, target, detail) => audits.push({ action, target, detail }) };
}
function routeOf(H) { const R = {}; routes.register({ route: (m, p, h) => { R[m + ' ' + p] = h; } }, { hardening: H, config: {} }); return R['GET /api/soc/hardening/snapshots']; }
async function call(h, ctx) { const r = await h(ctx); if (ctx.out.body === null && r !== undefined) ctx.out.body = r; return ctx; }

test('parser: the agent snapshot is action agent-hardening, tagged heartbeat (detection skips it), settings kept', () => {
  const ev = createParser().parse(line('WS-SYN-01.corp.test', SNAP), { collector: 'agent', src_id: 'win', src_type: 'windows', rts: Date.now() });
  assert.equal(ev.action, 'agent-hardening'); assert.ok(ev.tags.includes('heartbeat') && ev.tags.includes('hardening'));
  assert.deepEqual(JSON.parse(ev.fields.settings), SNAP);
  const hb = createParser().parse(line('WS-SYN-01', SNAP).replace('"type":"hardening"', '"type":"heartbeat"'), { collector: 'agent', src_id: 'win', src_type: 'windows', rts: Date.now() });
  assert.equal(hb.action, 'agent-heartbeat', 'a plain heartbeat is unchanged');
});

test('store: latest per host, persisted, bad JSON and oversize refused, host cap', () => {
  const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'sentra-hard-')), 'state', 'h.json');
  let t = Date.parse('2026-10-25T03:00:00Z');
  const S = createHardeningStore({ file, now: () => t, maxHosts: 2 });
  const P = createParser(), meta = { collector: 'agent', src_id: 'win', src_type: 'windows', rts: t };
  S.stage(P.parse(line('SRV-SYN-1', SNAP), meta));
  S.stage(P.parse(line('SRV-SYN-1', Object.assign({}, SNAP, { reg: { SMB1: 1 } })), meta));
  assert.equal(S.list().length, 1); assert.equal(S.get('srv-syn-1').settings.reg.SMB1, 1, 'the newest snapshot wins');
  S.stage(P.parse(line('SRV-SYN-2', '{not json'), meta));
  S.stage(P.parse(line('SRV-SYN-3', { big: 'x'.repeat(270000) }), meta));
  assert.equal(S.stats().rejected, 2); assert.equal(S.list().length, 1);
  // agent 1.3: a Hyper-V host with 200 VMs and IIS sites is far above the 8 KB field cap and the old 64 KB - kept whole
  // (before the fix the parser cut it at 8 KB, the copy was not JSON and the host was never scanned)
  const hv = { hyperv: { migration_enabled: true, vms: Array.from({ length: 200 }, (_, i) => ({ name: 'VM-SYNTHETIC-' + i, generation: 2, state: 'Running', secure_boot: true, tpm: false, mac_spoofing: false, dhcp_guard: true, router_guard: true, guest_service: false, pad: 'p'.repeat(250) })) }, iis: { sites: [{ name: 'Portal-SYN', protocols: ['https'] }] } };
  S.stage(P.parse(line('HV-SYN-1', hv), meta));
  assert.ok(JSON.stringify(hv).length > 65536); assert.equal(S.get('hv-syn-1').settings.hyperv.vms.length, 200); assert.equal(S.get('hv-syn-1').settings.iis.sites[0].name, 'Portal-SYN');
  S.stage({ action: 'agent-heartbeat', fields: {} }); assert.equal(S.stats().rejected, 2, 'other events ignored');
  S.put('srv-syn-4', { settings: {} }); S.put('srv-syn-5', { settings: {} });
  assert.deepEqual(S.list().map((h) => h.host), ['srv-syn-4', 'srv-syn-5'], 'oldest dropped above the cap');
  assert.equal(S.put('bad host!', { settings: {} }), false);
  S.flush();
  const again = createHardeningStore({ file, now: () => t });
  assert.equal(again.list().length, 2, 'reloaded from disk');
});

test('route: analyst reads (audited), viewer refused, unknown host 404, bad query 400, store absent says so', async () => {
  const S = createHardeningStore({}); S.put('srv-syn-1', { settings: SNAP });
  const h = routeOf(S);
  const v = await call(h, ctxOf('v.syn', 'viewer')); assert.equal(v.out.status, 403); assert.equal(v.audits.length, 0);
  const a = await call(h, ctxOf('a.syn', 'analyst'));
  assert.equal(a.out.status, 200); assert.equal(a.out.body.hosts.length, 1);
  assert.deepEqual(a.audits[0], { action: 'hardening.snapshots.read', target: 'all', detail: { hosts: 1 } });
  const one = await call(h, ctxOf('a.syn', 'analyst', { host: 'SRV-SYN-1' })); assert.equal(one.out.body.hosts[0].host, 'srv-syn-1');
  const nf = await call(h, ctxOf('a.syn', 'analyst', { host: 'nope' })); assert.equal(nf.out.status, 404);
  const bad = await call(h, ctxOf('a.syn', 'analyst', { host: 'x'.repeat(300) })); assert.equal(bad.out.status, 400); assert.match(bad.out.body.error, /host/);
  const none = await call(routeOf(null), ctxOf('a.syn', 'analyst')); assert.equal(none.out.body.available, false);
});
