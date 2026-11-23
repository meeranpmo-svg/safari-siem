// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// AI Engineering Team intelligence (engine/duty-intel.js, identical to the SIEM's engine/duty/duty-intel.js) over SYNTHETIC work items:
// precision withheld below 3 closures and Beta-shrunk above; verified-fix rate; MTTR now vs before; past-SLA; backlog projection; a
// stopped patrol; trust itemised; needs-you ranked with the reason; noisy checks; one target in two queues; recurring; the route
// (viewer reads); the two copies are byte-identical.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs'), path = require('node:path');
const { startApp } = require('./helpers');
const DI = require('../engine/duty-intel');
const NOW = Date.parse('2026-11-19T09:00:00Z'), H = 3600000, D = 86400000;
function items() {
  const L = [];
  // pentest: 4 false positives of 5 closures (noisy kind), 2 re-opened, backlog rising, one item needs a person past SLA
  for (let k = 0; k < 5; k++) L.push({ id: 'P' + k, engineer: 'pentest', kind: 'tls', severity: 'medium', status: 'closed', close_code: k < 4 ? 'false-positive' : 'fixed', detected_at: NOW - (20 + k) * D, resolved_at: NOW - (19 + k) * D, last_seen: NOW - H, target: { id: 'a1', name: 'web-syn-01' } });
  for (let k = 0; k < 10; k++) L.push({ id: 'Q' + k, engineer: 'pentest', kind: 'port', severity: 'high', status: 'open', detected_at: NOW - k * 2 * D - H, last_seen: NOW - H, target: { id: 'a' + (k + 2), name: 'srv-syn-' + k }, reopened: k === 0 ? 2 : 0 });
  L.push({ id: 'Q99', engineer: 'pentest', kind: 'port', severity: 'critical', status: 'needs-human', detected_at: NOW - 3 * D, last_seen: NOW - H, target: { id: 'a1', name: 'web-syn-01' }, reopened: 1, title: 'SMB open to the internet' });
  // desktop: good - fixes verified, fast
  for (let k = 0; k < 4; k++) L.push({ id: 'D' + k, engineer: 'desktop', kind: 'patch', severity: 'high', status: 'resolved', resolution: 'verified-fixed', changes: ['C' + k], detected_at: NOW - (k + 1) * D, resolved_at: NOW - (k + 1) * D + 6 * H, last_seen: NOW - H });
  L.push({ id: 'D9', engineer: 'desktop', kind: 'patch', severity: 'medium', status: 'resolved', resolution: 'cleared', detected_at: NOW - 40 * D, resolved_at: NOW - 40 * D + 20 * H, last_seen: NOW - 39 * D });
  L.push({ id: 'D8', engineer: 'desktop', kind: 'offline', severity: 'medium', status: 'open', detected_at: NOW - 2 * H, last_seen: NOW - H, target: { id: 'a1', name: 'web-syn-01' }, title: 'agent not reporting' });
  return L;
}
test('per engineer, trust, needs you, noisy, overlaps and recurring - each with its reason', () => {
  const v = DI.analyse({ items: items(), engineers: [{ id: 'pentest', name: 'AI Pentester (syn)' }, { id: 'desktop', name: 'AI Desktop (syn)' }, { id: 'virt', name: 'AI Virt (syn)' }], now: NOW, source: 'itam' });
  const p = v.engineers.find((e) => e.id === 'pentest'), d = v.engineers.find((e) => e.id === 'desktop'), vr = v.engineers.find((e) => e.id === 'virt');
  assert.equal(p.precision, 29, 'Beta(1,1): 1 - 5/7'); assert.ok(p.trust < d.trust); assert.match(p.why, /false positives \(precision 29 %\)/);
  assert.ok(p.trust_items.some((i) => /past their SLA/.test(i.label)));
  assert.equal(d.precision, null, 'withheld below 3 closures'); assert.equal(d.verified_pct, 100); assert.equal(d.mttr_h, 6); assert.equal(d.mttr_prev_h, 20);
  assert.equal(vr.trust, null); assert.match(vr.why, /not measured/);
  assert.ok(p.backlog.length === 30 && p.backlog_slope > 0 && p.backlog_7d >= p.backlog[29].value, 'backlog projection');
  assert.equal(v.engineers[0].id, 'pentest', 'least trusted first');
  assert.equal(v.needs[0].id, 'Q99'); assert.match(v.needs[0].why, /needs a person · critical · past its 24 h SLA by 48 h · re-opened 1x/);
  assert.ok(v.noisy.some((g) => g.kind === 'tls' && g.fp === 4));
  const ov = v.overlaps.find((o) => o.target === 'web-syn-01'); assert.ok(ov && ov.engineers.length === 2); assert.match(ov.why, /agree one owner/);
  assert.equal(v.recurring[0].id, 'Q0');
  assert.equal(v.team.engineers, 3); assert.ok(v.team.trust > 0 && v.team.trust < 100);
  const stopped = DI.analyse({ items: [{ id: 'X', engineer: 'e', severity: 'low', status: 'open', detected_at: NOW - 9 * D, last_seen: NOW - 5 * D }], now: NOW });
  assert.match(stopped.engineers[0].why, /is the patrol running/);
});
test('the route, and the copies are identical', async (t) => {
  const siem = [path.join(__dirname, '../../siem/engine/duty/duty-intel.js'), '/home/user/sentra-siem/engine/duty/duty-intel.js'].find((f) => fs.existsSync(f));
  if (siem) assert.equal(fs.readFileSync(path.join(__dirname, '../engine/duty-intel.js'), 'utf8'), fs.readFileSync(siem, 'utf8'), 'ITAM and SIEM duty-intel.js differ');
  const e = await startApp({ noAi: true }); t.after(() => e.close());
  require('../engine/duty').registerDuty(e.app.srv, e.app, { noTimer: true, now: () => NOW, python: process.env.PYTHON || 'python3' });
  const col = e.app.store.collection('duty_items'); for (const it of items()) col.put(it);
  const r = await e.req('GET', '/duty/intel', { user: 'vera.syn', role: 'viewer' }); assert.equal(r.status, 200, r.text);
  assert.equal(r.json.source, 'itam'); assert.ok(r.json.engineers.some((x) => x.id === 'pentest' && x.precision === 29)); assert.equal(r.json.needs[0].id, 'Q99');
});
