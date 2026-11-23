// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Linux collector: reads /proc, /sys and DMI for hardware, and dpkg or rpm for installed packages. Runs unprivileged;
// DMI serials under /sys/class/dmi/id are usually world-readable, but if not, serial simply stays null (degrade).
const fs = require('node:fs');

function readFile(p) { try { return fs.readFileSync(p, 'utf8').trim(); } catch { return null; } }

async function collect(sh) {
  const detail = {}; let software = [];

  detail.serial = readFile('/sys/class/dmi/id/product_serial') || readFile('/sys/class/dmi/id/board_serial') || null;
  detail.manufacturer = readFile('/sys/class/dmi/id/sys_vendor') || null;
  detail.model = readFile('/sys/class/dmi/id/product_name') || null;
  detail.uuid = readFile('/sys/class/dmi/id/product_uuid') || null;
  const chassis = readFile('/sys/class/dmi/id/chassis_type');
  if (chassis) { const laptop = new Set(['8', '9', '10', '11', '14', '31']); detail.chassis = laptop.has(chassis) ? 'laptop' : 'desktop'; }

  // pretty OS name
  const osrel = readFile('/etc/os-release');
  if (osrel) { const m = /PRETTY_NAME="?([^"\n]+)"?/.exec(osrel); if (m) detail.os = m[1]; }

  // memory (kB → GB)
  const meminfo = readFile('/proc/meminfo');
  if (meminfo) { const m = /MemTotal:\s+(\d+)\skB/.exec(meminfo); if (m) detail.mem_gb = Math.round(Number(m[1]) / (1024 * 1024)); }

  // packages: dpkg first, then rpm
  const dpkg = await sh('dpkg-query', ['-W', '-f=${Package}\t${Version}\n']);
  if (dpkg.ok && dpkg.out.trim()) {
    software = dpkg.out.split('\n').map((l) => l.split('\t')).filter((p) => p[0]).map((p) => ({ name: p[0], version: (p[1] || '').trim() || null, publisher: null })).slice(0, 5000);
  } else {
    const rpm = await sh('rpm', ['-qa', '--qf', '%{NAME}\t%{VERSION}-%{RELEASE}\t%{VENDOR}\n']);
    if (rpm.ok && rpm.out.trim()) software = rpm.out.split('\n').map((l) => l.split('\t')).filter((p) => p[0]).map((p) => ({ name: p[0], version: (p[1] || '').trim() || null, publisher: (p[2] || '').trim() || null })).slice(0, 5000);
  }

  // last applied package (best-effort patch level)
  const lastUpdate = readFile('/var/log/dpkg.log') ? null : null; // avoid reading large logs; left null by design
  if (lastUpdate) detail.patch_level = lastUpdate;

  return { detail, software };
}

module.exports = { collect };
