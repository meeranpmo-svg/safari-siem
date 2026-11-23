#!/bin/bash
# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
# add-exo-runtime.sh - the runtime the leaver steps need on the platform server (engine/exo.js runs engine/exo/exo-run.ps1
#   and engine/exo/spo-run.ps1): PowerShell 7 (pwsh), the ExchangeOnlineManagement module (3.x) and, for the OneDrive
#   hand-over, PnP.PowerShell (2.x, needs PowerShell 7.4 or later) - installed for all users.
#   Nothing else is changed. The Exchange Online settings (tenant, app id, certificate) are entered on the HR Offboarding page.
#   sudo bash add-exo-runtime.sh          check, and install the module if pwsh is present
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
if ! command -v pwsh >/dev/null 2>&1; then
  echo "PowerShell 7 (pwsh) is not installed. Install it from Microsoft's package repository, then run this again:"
  echo "  Ubuntu / Debian : https://learn.microsoft.com/powershell/scripting/install/install-ubuntu"
  echo "  RHEL / Oracle Linux : https://learn.microsoft.com/powershell/scripting/install/install-rhel"
  exit 2
fi
echo "pwsh: $(pwsh -NoLogo -NoProfile -Command '$PSVersionTable.PSVersion.ToString()')"
pwsh -NoLogo -NoProfile -NonInteractive -Command '
  $m = Get-Module -ListAvailable ExchangeOnlineManagement | Sort-Object Version -Descending | Select-Object -First 1
  if ($m -and $m.Version -ge [version]"3.0.0") { "ExchangeOnlineManagement $($m.Version) is installed"; exit 0 }
  Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
  Install-Module ExchangeOnlineManagement -Scope AllUsers -MinimumVersion 3.0.0 -Force -AllowClobber
  $m = Get-Module -ListAvailable ExchangeOnlineManagement | Sort-Object Version -Descending | Select-Object -First 1
  "ExchangeOnlineManagement $($m.Version) installed"'
pwsh -NoLogo -NoProfile -NonInteractive -Command '
  if ($PSVersionTable.PSVersion -lt [version]"7.4") { "PnP.PowerShell needs PowerShell 7.4 or later (this is $($PSVersionTable.PSVersion)) - update pwsh to use the OneDrive hand-over"; exit 0 }
  $m = Get-Module -ListAvailable PnP.PowerShell | Sort-Object Version -Descending | Select-Object -First 1
  if ($m -and $m.Version -ge [version]"2.0.0") { "PnP.PowerShell $($m.Version) is installed"; exit 0 }
  Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
  Install-Module PnP.PowerShell -Scope AllUsers -MinimumVersion 2.0.0 -Force -AllowClobber
  $m = Get-Module -ListAvailable PnP.PowerShell | Sort-Object Version -Descending | Select-Object -First 1
  "PnP.PowerShell $($m.Version) installed"'
echo "Done. Put the app certificate (.pfx) where only the platform can read it, e.g. /etc/sentra/exo-app.pfx, readable only by the account the platform runs as (chmod 600),"
echo "then HR Offboarding -> Exchange Online -> Save and Test (add the SharePoint admin address there for the OneDrive hand-over)."
