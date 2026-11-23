// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Migration step 9i (sentra-itam docs/PYTHON-MIGRATION.md): the duty desk's human writes - assign, note, snooze, close and
// the duty policy - decided by engine/duty/duty_rules.py on the record Node.js holds, committed by duty-core.js, must do
// exactly what the Node.js functions do: same answers, same refusals, same work items, policy record and audit entries,
// with odd values (hours '1.5' / 0 / 'x', blank reasons, an unknown close code, a closed item, policy numbers as text,
// unknown engineers / KPIs, a KPI target cleared with ''). A record that changes while Python decides is never
// overwritten: Node.js decides on what it holds. The same file runs in IT Asset Management (sentra-itam engine/).
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { createState } = require('../engine/soc/state');
const { createDuty } = require('../engine/duty/duty-core');

const PY = process.env.PYTHON || 'python3';
const hasPy = spawnSync(PY, ['--version']).status === 0;
const store = () => createState({ dir: path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'sentra-dutyw-')), 'state') });
const plain = (v) => JSON.parse(JSON.stringify(v));
const F = (key, over) => Object.assign({ key, severity: 'high', kind: 'wan-down', title: 'Down: ' + key, evidence: ['x'], recommendation: 'Check ' + key, target: { type: 'device', id: key, name: key }, site: 'Riyadh' }, over || {});

test('duty writes: Python decides exactly like Node.js', { skip: !hasPy && 'python3 not available' }, async () => {
  const t = Date.UTC(2026, 9, 19, 6, 0);
  const list = [F('a'), F('b', { severity: 'critical' }), F('c'), F('d', { severity: 'low' })];
  const eng = (id) => ({ id, name: 'AI ' + id, findings: () => list.map((f) => Object.assign({}, f)) });
  const mk = (python) => {
    const audits = [];
    const D = createDuty({ store: store(), now: () => t, python, audit: (action, target, detail) => audits.push({ action, target, detail }), engineers: [eng('network'), eng('windows')], policyDefaults: { ai_min_severity: 'off' } });
    return { D, audits };
  };
  const N = mk(null), P = mk(PY);
  for (const x of [N, P]) await x.D.patrol('network');
  const ids = N.D.list({}).items.map((x) => x.id).sort();
  assert.deepEqual(P.D.list({}).items.map((x) => x.id).sort(), ids);
  const [a, b, c, d] = ids;
  const run = async (fn) => {
    const out = [];
    for (const x of [N, P]) { try { out.push({ ok: plain(await fn(x.D)) }); } catch (e) { out.push({ status: e.status, error: e.message }); } }
    assert.deepEqual(out[1], out[0], fn.toString());
  };
  await run((D) => D.assignAuto(a, ' Siva ', 'syed'));
  await run((D) => D.assignAuto(b, '', 'syed'));
  await run((D) => D.assignAuto('DW-999999', 'x', 'syed'));
  await run((D) => D.noteAuto(a, '  checked the WAN link \n', 'siva'));
  await run((D) => D.noteAuto(a, '   ', 'siva'));
  await run((D) => D.noteAuto('nope', 'x', 'siva'));
  await run((D) => D.snoozeAuto(b, '1.5', ' waiting for the ISP ', 'siva'));
  await run((D) => D.snoozeAuto(c, 0, 'x', 'siva'));
  await run((D) => D.snoozeAuto(c, 'x', 'x', 'siva'));
  await run((D) => D.snoozeAuto(c, 24, '  ', 'siva'));
  await run((D) => D.closeAuto(c, 'accepted-risk', ' approved by the CISO ', 'siva'));
  await run((D) => D.closeAuto(c, 'fixed', 'again', 'siva'));
  await run((D) => D.snoozeAuto(c, 24, 'x', 'siva'));
  await run((D) => D.closeAuto(d, 'oops', 'x', 'siva'));
  await run((D) => D.closeAuto(d, 'duplicate', '', 'siva'));
  await run((D) => D.closeAuto(d, 'toString', 'x', 'siva'));               // CLOSE_CODES['toString'] in JS: Node.js decides
  await run((D) => D.closeAuto(d, 'fixed', 'patched by hand', undefined));
  await run((D) => D.setPolicyAuto({ patrol_min: '15', enabled: 0, ai_off: ['windows', 'windows'], kpi_targets: { network: { sla_pct: '95', fix_h: '' } }, ticket_min_severity: 'high' }, 'syed'));
  await run((D) => D.setPolicyAuto({ patrol_min: 1 }, 'syed'));
  await run((D) => D.setPolicyAuto({ ai_off: ['nobody'] }, 'syed'));
  await run((D) => D.setPolicyAuto({ kpi_targets: { network: { speed: 1 } } }, 'syed'));
  await run((D) => D.setPolicyAuto({ kpi_targets: [] }, 'syed'));
  await run((D) => D.setPolicyAuto({ ai_min_severity: 'severe' }, 'syed'));
  await run((D) => D.setPolicyAuto({ report_hour: '6.5', verify_every_min: 15, foo: 1 }, 'syed'));
  for (const id of ids) assert.deepEqual(plain(P.D.get(id)), plain(N.D.get(id)), id);
  assert.deepEqual(plain(P.D.policy()), plain(N.D.policy()), 'the same policy');
  assert.deepEqual(plain(P.audits), plain(N.audits), 'the same audit entries');
  const st = P.D.writeStats();
  assert.deepEqual(st, { python: 23, node: 1, changed_meanwhile: 0 }, 'Python decided all but the one handed back: ' + JSON.stringify(st));
  assert.equal(N.D.writeStats().python, 0);

  // a work item changed while Python decides is not overwritten: Node.js decides on what it holds
  const p2 = P.D.noteAuto(a, 'late note', 'siva');
  P.D.assign(a, 'Rasheed', 'admin');                    // lands before the Python answer
  await p2;
  const it = P.D.get(a);
  assert.equal(it.owner, 'Rasheed'); assert.equal(it.history[it.history.length - 1].note, 'late note', 'both changes kept');
  assert.equal(P.D.writeStats().changed_meanwhile, 1);
});
