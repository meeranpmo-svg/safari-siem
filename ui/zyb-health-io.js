// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// zyb-health-io - disk speed of the server that hosts the platform, for zyb-health (Platform Health page).
// Reads /proc/diskstats twice and works out, per disk: reads / writes per second, MB/s, read and write latency (ms per
// request, the "await" of iostat), how busy the disk was (%), and the CPU time spent waiting for the disk (iowait).
// A slow disk is the most common reason an install stalls or a page times out on a virtual machine (a Hyper-V checkpoint,
// a dynamically expanding disk on a busy HDD datastore), so a slow disk is reported with what to check on the host.
// Pure functions only - no file access here - so the tests can feed synthetic counters.

const SKIP = /^(loop|ram|zram|sr|fd|dm-|md)\d*/;

// /proc/diskstats: major minor name reads rmerged rsectors rms writes wmerged wsectors wms inflight io_ms weighted ...
function parseDiskstats(text) {
  const out = {};
  for (const l of String(text || '').split('\n')) {
    const p = l.trim().split(/\s+/); if (p.length < 14) continue;
    const name = p[2]; if (SKIP.test(name)) continue;
    // whole disks only (sda, vda, xvda, nvme0n1), not partitions (sda1, nvme0n1p1)
    if (/^(sd|vd|xvd|hd)[a-z]+\d+$/.test(name) || /^nvme\d+n\d+p\d+$/.test(name) || /^mmcblk\d+p\d+$/.test(name)) continue;
    const n = p.slice(3, 14).map(Number); if (n.some((v) => !Number.isFinite(v))) continue;
    out[name] = { reads: n[0], rsect: n[2], rms: n[3], writes: n[4], wsect: n[6], wms: n[7], inflight: n[8], io_ms: n[9] };
  }
  return out;
}

// iowait share of CPU time between two /proc/stat first lines ("cpu user nice system idle iowait ...")
function iowaitPct(stat1, stat2) {
  const f = (t) => String(t || '').split('\n')[0].trim().split(/\s+/).slice(1).map(Number);
  const a = f(stat1), b = f(stat2); if (a.length < 5 || b.length < 5) return null;
  const tot = b.reduce((x, y) => x + y, 0) - a.reduce((x, y) => x + y, 0); if (!(tot > 0)) return null;
  return Math.round(((b[4] - a[4]) / tot) * 1000) / 10;
}

const r1 = (v) => Math.round(v * 10) / 10;
// rates between two parsed snapshots taken ms apart. Counters that went backwards (a reboot) give no reading.
function ioRates(prev, cur, ms) {
  const out = [];
  if (!(ms > 0)) return out;
  for (const name of Object.keys(cur || {}).sort()) {
    const a = (prev || {})[name], b = cur[name]; if (!a) continue;
    const d = (k) => b[k] - a[k];
    if (['reads', 'writes', 'rms', 'wms', 'io_ms', 'rsect', 'wsect'].some((k) => d(k) < 0)) continue;
    const s = ms / 1000;
    out.push({ dev: name, seconds: r1(s),
      read_iops: r1(d('reads') / s), write_iops: r1(d('writes') / s),
      read_mbs: r1((d('rsect') * 512) / 1048576 / s), write_mbs: r1((d('wsect') * 512) / 1048576 / s),
      read_ms: d('reads') ? r1(d('rms') / d('reads')) : null, write_ms: d('writes') ? r1(d('wms') / d('writes')) : null,
      busy_pct: Math.min(100, r1((d('io_ms') / ms) * 100)), queued: b.inflight, ops: d('reads') + d('writes') });
  }
  return out;
}

const HOST_FIX = 'On the Hyper-V host: remove old checkpoints (Get-VMSnapshot / Remove-VMSnapshot) so the disk is not a differencing .avhdx, '
  + 'and put the virtual disk on SSD storage (Move-VMStorage). On this server: iostat -x 5 shows the same numbers.';
// problems to raise. A latency figure needs enough requests behind it to mean something (min_ops in the window).
function ioIssues(rates, iowait, C) {
  const c = Object.assign({ io_write_warn_ms: 50, io_write_crit_ms: 200, io_read_warn_ms: 50, io_read_crit_ms: 200, io_busy_warn: 90, iowait_warn: 20, iowait_crit: 40, io_min_ops: 10 }, C || {});
  const out = [];
  for (const r of rates || []) {
    if (r.ops < c.io_min_ops) continue;
    for (const [k, label] of [['write_ms', 'write'], ['read_ms', 'read']]) {
      const v = r[k]; if (v == null) continue;
      const crit = c['io_' + label + '_crit_ms'], warn = c['io_' + label + '_warn_ms'];
      if (v >= crit) out.push({ sev: 'crit', area: 'storage', key: 'io-' + label + '-' + r.dev, text: `Disk ${r.dev} is very slow: ${v} ms per ${label} (healthy is under 20 ms)`, fix: HOST_FIX });
      else if (v >= warn) out.push({ sev: 'warn', area: 'storage', key: 'io-' + label + '-' + r.dev, text: `Disk ${r.dev} is slow: ${v} ms per ${label} (healthy is under 20 ms)`, fix: HOST_FIX });
    }
    if (r.busy_pct >= c.io_busy_warn) out.push({ sev: 'warn', area: 'storage', key: 'io-busy-' + r.dev, text: `Disk ${r.dev} is ${r.busy_pct}% busy`, fix: 'Something is writing heavily (iotop shows what); if it stays busy, move the disk to faster storage.' });
  }
  if (iowait != null) {
    if (iowait >= c.iowait_crit) out.push({ sev: 'crit', area: 'system', key: 'iowait', text: `The CPU spends ${iowait}% of its time waiting for the disk`, fix: HOST_FIX });
    else if (iowait >= c.iowait_warn) out.push({ sev: 'warn', area: 'system', key: 'iowait', text: `The CPU spends ${iowait}% of its time waiting for the disk`, fix: HOST_FIX });
  }
  return out;
}

module.exports = { parseDiskstats, iowaitPct, ioRates, ioIssues };
