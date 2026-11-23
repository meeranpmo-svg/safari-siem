// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Standalone ESXi host (kind esxi): read over the same read-only vSphere SOAP API as vCenter (no Automation REST on
// ESXi) - inventory method, capacity collection and the AI Virtualization Administrator all work without a vCenter; only
// the SOAP_OK read-only calls are ever sent; the platform API accepts kind esxi.
const test = require('node:test');
const assert = require('node:assert/strict');
const { startApp } = require('./helpers');
const esxi = require('../engine/discovery/methods/esxi');
const { createVirtCapacity, SOAP_OK } = require('../engine/virt-capacity');
const { registerDuty } = require('../engine/duty');
const { createSealer } = require('../engine/discovery/vault');
const { fakeVc } = require('./fixtures-vcenter-soap');

const ADM = { user: 'syed', role: 'admin', ip: '' };
const cred = { target: { base_url: 'https://10.100.5.21' }, secret: { username: 'svc@vsphere.local', password: 'Vc-pass-1' } };

test('esxi method: hosts and VMs over read-only SOAP, nothing else sent', async () => {
  const calls = [];
  const r = await esxi.collect(cred, { request: fakeVc(calls) });
  assert.equal(r.ok, true, r.error);
  assert.ok(r.hosts.length >= 1 && r.vms.length >= 1);
  assert.ok(r.vms.every((v) => v.host_id !== undefined && 'power_state' in v));
  assert.ok(calls.every((c) => SOAP_OK.has(c.m)), 'only read-only SOAP methods: ' + [...new Set(calls.map((c) => c.m))].join(','));
  assert.ok(calls.every((c) => /^https:\/\/10\.100\.5\.21\/sdk$/.test(c.url)));
  const t = await esxi.test(cred, { request: fakeVc([]) });
  assert.equal(t.ok, true); assert.ok(t.discovered.hosts >= 1);
  const bad = await esxi.collect({ target: cred.target, secret: { username: 'x', password: 'wrong' } }, { request: async () => ({ status: 500, headers: {}, text: '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"><soapenv:Body><soapenv:Fault><faultstring>Cannot complete login due to an incorrect user name or password.</faultstring><detail><InvalidLoginFault/></detail></soapenv:Fault></soapenv:Body></soapenv:Envelope>' }) });
  assert.equal(bad.ok, false); assert.equal(bad.error_class, 'auth');
});

test('esxi platform: capacity collection and the AI Virtualization Administrator work without a vCenter', async (t) => {
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  // the Virtualization page accepts kind esxi
  const add = await e.req('POST', '/virt', { role: 'admin', body: { kind: 'esxi', label: 'ESX-DMZ-01', base_url: 'https://10.100.5.21', username: 'svc@vsphere.local', password: 'Vc-pass-1' } });
  assert.equal(add.status, 200, add.text); assert.equal(add.json.platform.kind, 'esxi'); assert.match(add.json.kinds.esxi, /ESXi/);
  const now = () => Date.parse('2026-08-01T08:00:00Z');
  const sealer = createSealer({ keyFile: e.app.config.discovery.vault_key_file, createKey: true, purpose: 'sentra-itam-virt-platforms' });
  const C = createVirtCapacity(e.app, { request: fakeVc([]), now, sealer });
  e.app.addons = e.app.addons || {}; e.app.addons.virtCapacity = C;
  await C.run(ADM);
  const rep = C.report(), p = rep.platforms.find((x) => x.kind === 'esxi');
  assert.ok(p && p.collected && !p.error, JSON.stringify(p));
  assert.ok(rep.hosts.some((h) => h.platform === 'ESX-DMZ-01'));
  const D = registerDuty(e.app.srv, e.app, { noTimer: true, now });
  await D.patrol('virt');
  const snap = D.list({ engineer: 'virt' }).items.find((x) => x.kind === 'snapshot-old');
  assert.ok(snap, 'old snapshots found on the standalone host');
  const plan = (await e.req('GET', '/virt/changes/' + D.get(snap.id).changes[0], { role: 'viewer' })).json;
  assert.equal(plan.commands[0].lang, 'powercli', 'vSphere plan (PowerCLI works against ESXi too)');
});
