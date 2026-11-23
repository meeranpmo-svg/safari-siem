// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// AI Virtualization Administrator with Claude (engine/virt-ai.js): off until external AI is allowed AND a key is stored
// (status names which); a duty-desk "Investigate with AI" runs read-only tools over the collected vCenter data and records
// the standard change plan through the four-eyes store (nothing executed); a free question gets no plan tools and is
// operator-only; tool inputs are schema-checked. The SDK is a fake: no network, no key.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');
const { createVirtCapacity } = require('../engine/virt-capacity');
const { createSealer } = require('../engine/discovery/vault');
const { fakeVc } = require('./fixtures-vcenter-soap');

const ADM = { user: 'syed', role: 'admin', ip: '' };

// scripted Claude: each call pops the next turn; a turn is a function of the request (so it can read tool results)
function fakeSdk(turns, seen) {
  const create = async (params) => {
    seen.push(JSON.parse(JSON.stringify(params)));
    const t = turns.shift(); if (!t) throw new Error('no more scripted turns');
    return Object.assign({ model: params.model, usage: { input_tokens: 10, output_tokens: 5 } }, t(params));
  };
  return class { constructor(o) { this.opts = o; this.messages = { create }; this.beta = { messages: { create } }; } };
}
const toolUse = (id, name, input) => ({ stop_reason: 'tool_use', content: [{ type: 'tool_use', id, name, input }] });
const text = (s) => ({ stop_reason: 'end_turn', content: [{ type: 'text', text: s }] });

async function setup(t, { key = 'sk-ant-test', allow = true, turns = [], seen = [] } = {}) {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  let clock = Date.parse('2026-08-01T08:00:00Z'); const now = () => clock;
  const sealer = createSealer({ keyFile: e.app.config.discovery.vault_key_file, createKey: true, purpose: 'sentra-itam-virt-platforms' });
  e.app.store.collection('virt_platforms').put({ id: 'vp_1', kind: 'vcenter', label: 'VC-RUH', base_url: 'https://vc1.corp.local', site: 'Riyadh HQ', enc: sealer.seal('vp_1', JSON.stringify({ username: 'svc@vsphere.local', password: 'Vc-pass-1' })) });
  const C = createVirtCapacity(e.app, { request: fakeVc([]), now, sealer });
  e.app.addons = e.app.addons || {}; e.app.addons.virtCapacity = C;
  if (allow) e.app.settings.update({ external_ai_allowed: true }, ADM);
  const D = registerDuty(e.app.srv, e.app, { noTimer: true, now, virtAi: { sdk: fakeSdk(turns, seen), getKey: () => key, now } });
  await C.run(ADM); await D.patrol('virt');
  return { e, D, seen };
}

test('virt AI: off until allowed and keyed; readiness says which', async (t) => {
  const a = await setup(t, { allow: false });
  let s = (await a.e.req('GET', '/virt/ai/status', { role: 'viewer' })).json;
  assert.equal(s.enabled, false); assert.match(s.reason, /external AI is not allowed/);
  const r = (await a.e.req('GET', '/duty/readiness', { role: 'viewer' })).json.engineers.find((x) => x.id === 'virt');
  assert.ok(r.to_fix.some((f) => /zyb-virt-ai --allow-external/.test(f.fix)));
  const b = await setup(t, { key: '' });
  s = (await b.e.req('GET', '/virt/ai/status', { role: 'viewer' })).json;
  assert.equal(s.enabled, false); assert.match(s.reason, /no Anthropic API key/);
  const it = b.D.list({ engineer: 'virt' }).items[0];
  assert.equal((await b.e.req('POST', `/duty/items/${it.id}/investigate`, { role: 'operator', body: { ai: true } })).json.ai || null, null, 'no AI ran');
});

test('virt AI: Investigate with AI uses read-only tools and records the standard plan for approval', async (t) => {
  const turns = [
    () => ({ stop_reason: 'tool_use', content: [{ type: 'thinking', thinking: 'x', signature: 's' }, { type: 'tool_use', id: 't1', name: 'overview', input: {} }, { type: 'tool_use', id: 't2', name: 'list_vms', input: { name: 'APP-1' } }] }),
    (p) => {
      const res = p.messages[p.messages.length - 1].content;
      assert.equal(res.length, 2); assert.ok(!res[0].is_error, res[0].content); assert.match(res[0].content, /VC-RUH/); assert.match(res[1].content, /APP-1/);
      return toolUse('t3', 'propose_standard_plan', {});
    },
    (p) => { const r = p.messages[p.messages.length - 1].content[0]; assert.match(r.content, /"recorded":"VCH-/); return text('Summary: APP-1 carries a 60-day snapshot.'); },
  ];
  const { e, D, seen } = await setup(t, { turns });
  const snap = D.list({ engineer: 'virt' }).items.find((x) => x.kind === 'snapshot-old');
  // the rule-based plan was already written on patrol: the AI's call links it instead of duplicating it
  const before = D.get(snap.id).changes.slice();
  const r = await e.req('POST', `/duty/items/${snap.id}/investigate`, { user: 'ali', role: 'operator', body: { ai: true } });
  assert.equal(r.status, 200, r.text);
  const it = D.get(snap.id);
  assert.match(it.ai.answer, /60-day snapshot/); assert.equal(it.ai.steps, 3); assert.deepEqual(it.changes, before);
  assert.equal(seen[0].model, 'claude-opus-5-5'); assert.deepEqual(seen[0].thinking, { type: 'adaptive' });
  assert.ok(seen[0].tools.some((x) => x.name === 'propose_custom_plan'));
  assert.equal(seen[1].messages[1].content[0].type, 'thinking', 'assistant turn sent back unchanged');
  // a viewer sees that an analysis exists, not its text
  assert.equal((await e.req('GET', '/duty/items/' + snap.id, { role: 'viewer' })).json.ai, null);
});

test('virt AI: a custom plan is recorded as AI-written and still needs four eyes; bad tool input is refused', async (t) => {
  const turns = [
    () => toolUse('t1', 'list_vms', { limit: 5000 }),
    (p) => { assert.match(p.messages[p.messages.length - 1].content[0].content, /invalid input/); return toolUse('t2', 'propose_custom_plan', { title: 'Reboot esx02 after hardware check', reason: 'sensor red', steps: ['Enter maintenance mode', 'Reboot'], commands: [{ lang: 'powercli', text: "Get-VMHost -Id 'HostSystem-host-12' | Set-VMHost -State Maintenance" }], rollback: 'Exit maintenance mode', risk: 'medium' }); },
    () => text('Recorded a plan.'),
  ];
  const { e, D } = await setup(t, { turns });
  const red = D.list({ engineer: 'virt' }).items.find((x) => x.kind === 'host-health');
  await e.req('POST', `/duty/items/${red.id}/investigate`, { user: 'ali', role: 'operator', body: { ai: true } });
  const it = D.get(red.id); assert.equal(it.status, 'awaiting-approval'); assert.equal(it.changes.length, 1);
  const plan = (await e.req('GET', '/virt/changes/' + it.changes[0], { role: 'viewer' })).json;
  assert.equal(plan.source, 'ai'); assert.equal(plan.state, 'proposed'); assert.equal(plan.requested_by, 'duty:virt');
  assert.match(plan.prechecks[0], /AI-written/); assert.equal(plan.commands[0].lang, 'powercli');
  assert.equal((await e.req('POST', `/virt/changes/${plan.id}/approve`, { role: 'operator', body: {} })).status, 403, 'operators cannot approve');
});

test('virt AI: a free question is operator-only, offers no plan tools, and is audited', async (t) => {
  const seen = [];
  const { e } = await setup(t, { seen, turns: [() => text('Cluster RUH-PROD cannot survive one host failure.')] });
  assert.equal((await e.req('POST', '/virt/ai/ask', { role: 'viewer', body: { question: 'N+1?' } })).status, 403);
  const r = await e.req('POST', '/virt/ai/ask', { user: 'ali', role: 'operator', body: { question: 'Can RUH-PROD survive a host failure?' } });
  assert.equal(r.status, 200, r.text); assert.match(r.json.answer, /cannot survive/);
  assert.ok(!seen[0].tools.some((x) => /^propose_/.test(x.name)), 'no plan tools without a work item');
  assert.equal((await e.req('POST', '/virt/ai/ask', { role: 'operator', body: { question: '' } })).status, 400);
  const audit = (await e.req('GET', '/audit?limit=100', { role: 'admin' })).json.audit;
  assert.ok(audit.some((x) => x.action === 'virt.ai.ask' && x.by === 'ali'));
});

test('virt AI: switched off per engineer in the duty policy - no Ask, no Investigate with AI, status says why; back on works', async (t) => {
  const seen = [];
  const { e, D } = await setup(t, { seen, turns: [() => text('ok after switching back on')] });
  assert.equal((await e.req('PUT', '/duty/policy', { role: 'operator', body: { ai_off: ['virt'] } })).status, 403, 'admins only');
  assert.equal((await e.req('PUT', '/duty/policy', { role: 'admin', body: { ai_off: ['nope'] } })).status, 400, 'unknown engineer refused');
  assert.equal((await e.req('PUT', '/duty/policy', { role: 'admin', body: { ai_off: ['virt'] } })).status, 200);
  const st = (await e.req('GET', '/virt/ai/status', { role: 'viewer' })).json; assert.equal(st.enabled, false); assert.match(st.reason, /switched off for this engineer/);
  assert.equal((await e.req('POST', '/virt/ai/ask', { role: 'operator', body: { question: 'N+1?' } })).status, 503);
  const eng = D.engineers().find((x) => x.id === 'virt'); assert.equal(eng.ai.enabled, false); assert.equal(eng.ai.off, true);
  const it = D.list({ engineer: 'virt' }).items[0];
  await e.req('POST', `/duty/items/${it.id}/investigate`, { role: 'operator', body: { ai: true } });
  assert.equal(seen.length, 0, 'nothing sent to Claude while switched off');
  await e.req('PUT', '/duty/policy', { role: 'admin', body: { ai_off: [] } });
  const r = await e.req('POST', '/virt/ai/ask', { user: 'ali', role: 'operator', body: { question: 'N+1?' } });
  assert.equal(r.status, 200, r.text); assert.equal(seen.length, 1);
});
