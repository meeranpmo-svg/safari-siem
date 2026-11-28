// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// How to fix a Hyper-V Optimization finding (engine/hyperv-fix.js) over SYNTHETIC recommendations: every kind has checks, a change
// and a confirmation; the commands carry the VM, the disk and the volume from the report; the new disk size is 25 % above the
// maximum (at least 20 GB more, rounded up to 10 GB); a hostile VM name or path stays inside its single-quoted literal (a quote is
// doubled, a line break dropped) so it cannot add a command; every recommendation from the real analysis carries its plan.
const test = require('node:test');
const assert = require('node:assert/strict');
const { fixOf, q } = require('../engine/hyperv-fix');
const O = require('../engine/hyperv-optimize');

const KINDS = ['vhd-full', 'volume-full', 'volume-trend', 'overcommit', 'memory-down', 'memory-up', 'vcpu-down', 'vcpu-up', 'idle', 'checkpoint', 'nic-busy', 'balance'];

test('every kind: checks first, a change, a confirmation, and the risk', () => {
  for (const kind of KINDS) {
    const f = fixOf({ kind, target: 'VM-SYN', host: 'HV-SYN-01', detail: { vm: 'VM-SYN', host: 'HV-SYN-01', volume: 'D:\\', path: 'D:\\VMs\\VM-SYN\\d.vhdx', max_gb: 100, to_mb: 16384, to: 4, from: 'HV-SYN-01', nic: 'NIC1' } });
    const K = f.steps.map((s) => s.kind);
    assert.ok(f.summary && f.risk, kind + ': summary and risk'); assert.equal(K[0], 'check', kind + ': checks first'); assert.ok(K.includes('change') && K[K.length - 1] === 'verify', kind + ': ' + K.join(','));
  }
});

test('the disk plan: the real path, checkpoints first, the new size, both ways (compact or extend)', () => {
  const f = fixOf({ kind: 'vhd-full', target: 'HQVLOGCOLLECTOR-SYN', host: 'HV-SYN-01', detail: { vm: 'HQVLOGCOLLECTOR-SYN', host: 'HV-SYN-01', path: 'D:\\VMs\\HQVLOGCOLLECTOR-SYN.vhdx', size_gb: 98, max_gb: 100 } });
  const all = f.steps.map((s) => s.cmd || '').join('\n');
  assert.match(all, /Get-VHD -Path 'D:\\VMs\\HQVLOGCOLLECTOR-SYN\.vhdx'/); assert.match(all, /Get-VMSnapshot -VMName 'HQVLOGCOLLECTOR-SYN'/);
  assert.match(all, /Resize-VHD -Path 'D:\\VMs\\HQVLOGCOLLECTOR-SYN\.vhdx' -SizeBytes 130GB/, '100 GB × 1.25 = 125, rounded up to 130');
  assert.match(all, /Optimize-VHD/); assert.match(f.steps.find((s) => /clean and compact/.test(s.title)).text, /retention/, 'a log collector: set a retention');
});

test('a hostile name cannot add a command', () => {
  assert.equal(q("x'; Remove-Item C:\\ -Recurse; '"), "'x''; Remove-Item C:\\ -Recurse; '''");
  assert.equal(q('a\nRemove-Item x'), "'aRemove-Item x'");
  const f = fixOf({ kind: 'checkpoint', target: "evil'; Stop-Computer; '", host: 'HV', detail: { vm: "evil'; Stop-Computer; '\nRestart-Computer" } });
  const cmd = f.steps[0].cmd;
  assert.ok(!/\n/.test(cmd.split('Get-VMSnapshot')[1].split('|')[0]), 'no line break inside the value');
  assert.match(cmd, /-VMName 'evil''; Stop-Computer; ''Restart-Computer'/, 'the whole name stays one quoted literal');
});

test('every recommendation of the real analysis carries its plan', () => {
  const GB = 1024, NOW = Date.parse('2026-11-27T09:00:00Z');
  const rep = { at: new Date(NOW).toISOString(), host: { name: 'HV-SYN-01', cores: 32, cpu_pct: 40, mem_total_mb: 256 * GB, mem_free_mb: 20 * GB, volumes: [{ name: 'D:\\', size_gb: 1000, free_gb: 60 }], nics: [] },
    vms: [{ name: 'VM-SYN', state: 'running', vcpus: 2, mem_assigned_mb: 8 * GB, vhds: [{ path: 'D:\\VM-SYN\\d.vhdx', size_gb: 99, max_gb: 100 }], checkpoints: [] }] };
  const r = O.analyse({ latest: [rep], now: NOW });
  const v = r.recommendations.find((x) => x.kind === 'vhd-full'), w = r.recommendations.find((x) => x.kind === 'volume-full');
  assert.ok(v && w); assert.equal(v.detail.path, 'D:\\VM-SYN\\d.vhdx'); assert.ok(r.recommendations.every((x) => x.fix && x.fix.steps.length >= 3));
  assert.match(w.fix.steps[0].cmd, /Get-ChildItem -Path 'D:\\'/);
});
