// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Windows collector: prefers PowerShell CIM (modern) and falls back to wmic (older boxes). Read-only queries only.
// Degrades to {} / [] if neither is available. Runs as a least-privilege service account (LocalService is enough
// for these read-only CIM/registry queries; no admin rights required).
function firstLine(s) { return String(s || '').split(/\r?\n/).map((x) => x.trim()).filter(Boolean)[0] || null; }

async function collect(sh) {
  const detail = {}; let software = [];

  // identity + chassis via CIM
  const ps = await sh('powershell', ['-NoProfile', '-NonInteractive', '-Command',
    '$ErrorActionPreference="SilentlyContinue";' +
    '$cs=Get-CimInstance Win32_ComputerSystem; $bi=Get-CimInstance Win32_BIOS; $os=Get-CimInstance Win32_OperatingSystem; $en=Get-CimInstance Win32_SystemEnclosure;' +
    '[pscustomobject]@{manufacturer=$cs.Manufacturer;model=$cs.Model;serial=$bi.SerialNumber;os=$os.Caption+" "+$os.Version;chassis=($en.ChassisTypes -join ",");uuid=(Get-CimInstance Win32_ComputerSystemProduct).UUID} | ConvertTo-Json -Compress']);
  if (ps.ok && ps.out.trim().startsWith('{')) {
    try {
      const j = JSON.parse(ps.out);
      detail.manufacturer = j.manufacturer || null; detail.model = j.model || null; detail.serial = j.serial || null;
      if (j.os) detail.os = j.os; detail.uuid = j.uuid || null;
      const laptopChassis = new Set(['8', '9', '10', '11', '12', '14', '18', '21', '31']);
      detail.chassis = String(j.chassis || '').split(',').some((c) => laptopChassis.has(c.trim())) ? 'laptop' : 'desktop';
    } catch { /* ignore */ }
  } else {
    // wmic fallback
    const serial = await sh('wmic', ['bios', 'get', 'serialnumber']);
    const model = await sh('wmic', ['computersystem', 'get', 'model']);
    const mfr = await sh('wmic', ['computersystem', 'get', 'manufacturer']);
    detail.serial = firstLine(serial.out.replace(/SerialNumber/i, '')); detail.model = firstLine(model.out.replace(/Model/i, '')); detail.manufacturer = firstLine(mfr.out.replace(/Manufacturer/i, ''));
  }

  // installed software from the uninstall registry keys (no admin needed)
  const swps = await sh('powershell', ['-NoProfile', '-NonInteractive', '-Command',
    '$ErrorActionPreference="SilentlyContinue";' +
    '$p="HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*","HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*";' +
    'Get-ItemProperty $p | Where-Object {$_.DisplayName} | Select-Object @{n="name";e={$_.DisplayName}},@{n="version";e={$_.DisplayVersion}},@{n="publisher";e={$_.Publisher}} | ConvertTo-Json -Compress']);
  if (swps.ok && swps.out.trim()) {
    try { const arr = JSON.parse(swps.out.trim().startsWith('[') ? swps.out : `[${swps.out}]`); software = arr.filter((x) => x && x.name).map((x) => ({ name: x.name, version: x.version || null, publisher: x.publisher || null })); } catch { /* ignore */ }
  }

  // last patch (most recent hotfix install date)
  const qfe = await sh('powershell', ['-NoProfile', '-NonInteractive', '-Command', '$ErrorActionPreference="SilentlyContinue";(Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1).HotFixID']);
  if (qfe.ok && firstLine(qfe.out)) detail.patch_level = firstLine(qfe.out);

  return { detail, software };
}

module.exports = { collect };
