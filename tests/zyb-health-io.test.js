// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Disk speed of the platform server (ui/zyb-health-io.js, used by zyb-health): /proc/diskstats parsing, latency / MB/s /
// busy maths, iowait, and the problems raised - a slow virtual disk like the one seen on a Hyper-V VM with a checkpoint
// (~1 s per write) is critical; an idle disk or a handful of requests raises nothing. Synthetic counters only.
const { test } = require('node:test');
const assert = require('node:assert');
const IO = require('../ui/zyb-health-io.js');

const line = (name, f) => '   8       0 ' + name + ' ' + f.join(' ');
// reads rmerged rsect rms writes wmerged wsect wms inflight io_ms weighted
const T0 = [line('sda', [1000, 0, 80000, 2000, 5000, 0, 400000, 10000, 0, 9000, 12000, 0, 0, 0, 0]),
  line('sda1', [900, 0, 70000, 1800, 4000, 0, 300000, 9000, 0, 8000, 11000, 0, 0, 0, 0]),
  line('loop0', [5, 0, 10, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0]),
  line('nvme0n1', [10, 0, 80, 5, 10, 0, 80, 5, 0, 10, 10, 0, 0, 0, 0]), line('nvme0n1p1', [1, 0, 8, 1, 1, 0, 8, 1, 0, 1, 1, 0, 0, 0, 0]), 'garbage'].join('\n');
// 60 s later: sda did 600 writes taking 600 000 ms in total (1 s each), 60 reads at 5 ms; busy 57 s of 60
const T1 = [line('sda', [1060, 0, 80000 + 60 * 8, 2300, 5600, 0, 400000 + 2048 * 60, 610000, 3, 66000, 99000, 0, 0, 0, 0]),
  line('nvme0n1', [12, 0, 96, 6, 12, 0, 96, 6, 0, 12, 12, 0, 0, 0, 0])].join('\n');

test('parse: whole disks only, partitions / loop / garbage dropped', () => {
  const d = IO.parseDiskstats(T0);
  assert.deepStrictEqual(Object.keys(d).sort(), ['nvme0n1', 'sda']);
  assert.strictEqual(d.sda.writes, 5000); assert.strictEqual(d.sda.wms, 10000); assert.strictEqual(d.sda.io_ms, 9000);
  assert.deepStrictEqual(IO.parseDiskstats(''), {}); assert.deepStrictEqual(IO.parseDiskstats(null), {});
});

test('rates: latency per request, MB/s, busy %, queue', () => {
  const r = IO.ioRates(IO.parseDiskstats(T0), IO.parseDiskstats(T1), 60000);
  const sda = r.find((x) => x.dev === 'sda');
  assert.strictEqual(sda.write_ms, 1000); assert.strictEqual(sda.read_ms, 5);
  assert.strictEqual(sda.write_iops, 10); assert.strictEqual(sda.read_iops, 1);
  assert.strictEqual(sda.write_mbs, 1); assert.strictEqual(sda.busy_pct, 95); assert.strictEqual(sda.queued, 3); assert.strictEqual(sda.ops, 660);
  const nv = r.find((x) => x.dev === 'nvme0n1'); assert.strictEqual(nv.ops, 4);
  assert.deepStrictEqual(IO.ioRates(null, IO.parseDiskstats(T1), 0), [], 'no window, no figures');
});

test('rates: counters that went backwards (a reboot) give no reading; a disk with no requests has no latency', () => {
  assert.deepStrictEqual(IO.ioRates(IO.parseDiskstats(T1), IO.parseDiskstats(T0), 60000).filter((x) => x.dev === 'sda'), []);
  const same = IO.ioRates(IO.parseDiskstats(T1), IO.parseDiskstats(T1), 1000)[0];
  assert.strictEqual(same.write_ms, null); assert.strictEqual(same.read_ms, null); assert.strictEqual(same.busy_pct, 0);
});

test('iowait from two /proc/stat lines', () => {
  assert.strictEqual(IO.iowaitPct('cpu 100 0 100 700 100 0 0', 'cpu 110 0 110 720 160 0 0'), 60);
  assert.strictEqual(IO.iowaitPct('cpu 1', 'cpu 2'), null); assert.strictEqual(IO.iowaitPct('cpu 1 1 1 1 1', 'cpu 1 1 1 1 1'), null);
});

test('issues: ~1 s per write is critical with the Hyper-V fix; idle / few requests raise nothing; iowait thresholds', () => {
  const r = IO.ioRates(IO.parseDiskstats(T0), IO.parseDiskstats(T1), 60000);
  const iss = IO.ioIssues(r, 71);
  const w = iss.find((i) => i.key === 'io-write-sda');
  assert.strictEqual(w.sev, 'crit'); assert.match(w.text, /1000 ms per write/); assert.match(w.fix, /checkpoint/i); assert.match(w.fix, /Move-VMStorage/);
  assert.ok(!iss.some((i) => i.key === 'io-read-sda'), '5 ms reads are healthy');
  assert.strictEqual(iss.find((i) => i.key === 'io-busy-sda').sev, 'warn');
  assert.strictEqual(iss.find((i) => i.key === 'iowait').sev, 'crit');
  assert.ok(!iss.some((i) => /nvme0n1/.test(i.key)), '4 requests are too few to judge');
  assert.strictEqual(IO.ioIssues(r, 25).find((i) => i.key === 'iowait').sev, 'warn');
  assert.ok(!IO.ioIssues([], 3).length, 'a quiet, fast server raises nothing');
  const slow = [{ dev: 'vda', ops: 50, write_ms: 80, read_ms: 300, busy_pct: 10 }];
  const s2 = IO.ioIssues(slow, null);
  assert.strictEqual(s2.find((i) => i.key === 'io-write-vda').sev, 'warn'); assert.strictEqual(s2.find((i) => i.key === 'io-read-vda').sev, 'crit');
  assert.ok(!IO.ioIssues(slow, null, { io_write_warn_ms: 100, io_read_crit_ms: 500, io_read_warn_ms: 400 }).length, 'thresholds come from /etc/zyb-health.conf');
});

test('zyb-health wires disk speed in and the installer copies the module next to it', () => {
  const fs = require('node:fs'), path = require('node:path'), ui = path.join(__dirname, '../ui');
  const h = fs.readFileSync(path.join(ui, 'zyb-health.js'), 'utf8'), inst = fs.readFileSync(path.join(ui, 'install-platform.sh'), 'utf8');
  assert.match(h, /require\(path\.join\(__dirname, 'zyb-health-io\.js'\)\)/); assert.match(h, /storage: fsl, diskio,/); assert.match(h, /'sentra-auth'/);
  assert.match(inst, /install -m 644 "\$HERE\/zyb-health-io\.js" \/usr\/local\/lib\/zyb\/zyb-health-io\.js/);
});
