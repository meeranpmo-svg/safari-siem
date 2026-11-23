// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// macOS collector: system_profiler (JSON) for hardware, and a scan of /Applications bundles for installed apps.
// Runs as the user/daemon; all probes degrade to null/[] on failure.
async function collect(sh) {
  const detail = {}; let software = [];

  const hw = await sh('system_profiler', ['SPHardwareDataType', '-json'], { timeout: 20000 });
  if (hw.ok && hw.out.trim().startsWith('{')) {
    try {
      const j = JSON.parse(hw.out); const h = (j.SPHardwareDataType || [])[0] || {};
      detail.manufacturer = 'Apple'; detail.model = h.machine_name || h.machine_model || null;
      detail.serial = h.serial_number || null; detail.uuid = h.platform_UUID || null;
      detail.cpu = h.chip_type || h.cpu_type || null;
      if (h.physical_memory) { const m = /(\d+)\s*GB/i.exec(h.physical_memory); if (m) detail.mem_gb = Number(m[1]); }
      detail.chassis = /book/i.test(detail.model || '') ? 'laptop' : 'desktop';
    } catch { /* ignore */ }
  }

  const sw = await sh('system_profiler', ['SPApplicationsDataType', '-json'], { timeout: 30000 });
  if (sw.ok && sw.out.trim().startsWith('{')) {
    try {
      const j = JSON.parse(sw.out); const apps = j.SPApplicationsDataType || [];
      software = apps.filter((a) => a && a._name).map((a) => ({ name: a._name, version: a.version || null, publisher: a.obtained_from || null })).slice(0, 5000);
    } catch { /* ignore */ }
  }

  const ver = await sh('sw_vers', ['-productVersion']);
  if (ver.ok && ver.out.trim()) detail.os = `macOS ${ver.out.trim()}`;

  return { detail, software };
}

module.exports = { collect };
