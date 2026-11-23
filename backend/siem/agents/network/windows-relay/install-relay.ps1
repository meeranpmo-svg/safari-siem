# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
<#
  install-relay.ps1 - installs sentra-syslog-relay on a Windows host.

  Creates the program + data folders, writes config.json (ACL'd, it holds the ingest token), adds a
  firewall rule limited to the sending devices, and registers a scheduled task that starts at boot as SYSTEM.

  Capture only (see the logs locally, forward nothing):
    .\install-relay.ps1 -AllowFrom 192.168.1.2

  Capture + forward to the SIEM (the token is read from -TokenFile or prompted for, never passed on the command
  line, where it would land in PowerShell history and 4104/4688 events):
    .\install-relay.ps1 -AllowFrom 192.168.1.2 -CollectorUrl https://siem.example.local -SrcId fw-hq-01 -TokenFile \\deploy\sentra\fw-hq-01.token
  Optional: -PinnedThumbprint <SHA-1 or SHA-256 of the collector certificate>

  Uninstall:
    .\install-relay.ps1 -Uninstall
#>
[CmdletBinding()]
param(
  [string[]] $AllowFrom = @(),
  [int]      $Port = 5514,
  [string]   $ListenIp = '0.0.0.0',
  [string]   $CollectorUrl,
  [string]   $SrcId = 'fw-hq-01',
  [string]   $TokenFile,
  [string]   $PinnedThumbprint = '',
  [int]      $KeepDays = 14,
  [switch]   $NoFirewallRule,
  [switch]   $Uninstall
)

$ErrorActionPreference = 'Stop'

$TaskName   = 'SentraSyslogRelay'
$InstallDir = Join-Path $env:ProgramFiles 'SentraSyslogRelay'
$DataDir    = Join-Path $env:ProgramData  'SentraSyslogRelay'
$ConfigPath = Join-Path $DataDir 'config.json'
$ScriptDest = Join-Path $InstallDir 'sentra-syslog-relay.ps1'
$RuleName   = 'Ash syslog relay (device syslog)'

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
          ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw 'Run this from an elevated PowerShell (Run as Administrator).'
}

if ($Uninstall) {
  schtasks.exe /Delete /TN $TaskName /F 2>$null | Out-Null
  netsh.exe advfirewall firewall delete rule name="$RuleName" 2>$null | Out-Null
  if (Test-Path -LiteralPath $InstallDir) { Remove-Item -LiteralPath $InstallDir -Recurse -Force }
  # the config holds the ingest token: remove it (revoke it on the collector too: sudo sentra-siem-token revoke <src_id>)
  if (Test-Path -LiteralPath $ConfigPath) { Remove-Item -LiteralPath $ConfigPath -Force }
  Write-Host "Removed task, firewall rule, $InstallDir and the config (token)."
  Write-Host "Kept $DataDir\logs and \queue (captured logs) - delete them by hand if you want them gone."
  Write-Host 'Revoke the source token on the collector: sudo sentra-siem-token revoke <src_id>'
  return
}

$SidSystem = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
$SidAdmins = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
$SidUsers  = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-545')
function Set-RestrictedAcl {
  # Protected ACL (no inheritance): SYSTEM + Administrators full control; optional Users read/execute. Owner = Administrators.
  param([string]$Path, [bool]$IsDirectory, [bool]$UsersRead = $false)
  $acl = if ($IsDirectory) { New-Object System.Security.AccessControl.DirectorySecurity } else { New-Object System.Security.AccessControl.FileSecurity }
  $acl.SetAccessRuleProtection($true, $false)
  $acl.SetOwner($SidAdmins)
  $inh = if ($IsDirectory) { [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit' } else { [System.Security.AccessControl.InheritanceFlags]::None }
  $prop = [System.Security.AccessControl.PropagationFlags]::None
  $allow = [System.Security.AccessControl.AccessControlType]::Allow
  foreach ($sid in @($SidSystem, $SidAdmins)) {
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($sid, [System.Security.AccessControl.FileSystemRights]::FullControl, $inh, $prop, $allow)))
  }
  if ($UsersRead) {
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($SidUsers, [System.Security.AccessControl.FileSystemRights]::ReadAndExecute, $inh, $prop, $allow)))
  }
  Set-Acl -LiteralPath $Path -AclObject $acl
}
function Assert-SafeExisting([string]$Path) {
  # a folder pre-created by an unprivileged user (anyone may create folders under ProgramData) is not trusted
  if (-not (Test-Path -LiteralPath $Path)) { return }
  $item = Get-Item -LiteralPath $Path -Force
  if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "$Path is a reparse point (junction/symlink) - refusing to install into it" }
  $owner = (Get-Acl -LiteralPath $Path).GetOwner([System.Security.Principal.SecurityIdentifier])
  if ($owner -ne $SidSystem -and $owner -ne $SidAdmins) { throw "$Path exists and is owned by $owner, not SYSTEM/Administrators - remove it and re-run" }
}

if ($CollectorUrl -and -not $CollectorUrl.StartsWith('https://', [StringComparison]::OrdinalIgnoreCase)) { throw '-CollectorUrl must start with https://' }
$PinnedThumbprint = ($PinnedThumbprint -replace '[\s:]', '').ToUpperInvariant()
if ($PinnedThumbprint -and $PinnedThumbprint -notmatch '^([0-9A-F]{40}|[0-9A-F]{64})$') { throw '-PinnedThumbprint must be 40 (SHA-1) or 64 (SHA-256) hex characters' }
$Token = ''
if ($TokenFile) {
  if (-not (Test-Path -LiteralPath $TokenFile)) { throw "token file not found: $TokenFile" }
  $Token = ([System.IO.File]::ReadAllText($TokenFile)).Trim()
} elseif ($CollectorUrl -and (Test-Path -LiteralPath $ConfigPath)) {
  try { $Token = [string]((Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json).token) } catch { $Token = '' }
  if ($Token) { Write-Host 'Keeping the existing token (pass -TokenFile to replace it).' }
}
if ($CollectorUrl -and -not $Token) {
  $ss = Read-Host -AsSecureString -Prompt "Ingest token for source '$SrcId' (input hidden; sudo sentra-siem-token add $SrcId on the collector)"
  $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($ss)
  try { $Token = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
  if (-not $Token) { throw 'A -CollectorUrl needs an ingest token.' }
}
if ($AllowFrom.Count -eq 0) {
  Write-Warning 'No -AllowFrom given: the relay will accept syslog from ANY host. UDP source IPs are trivially'
  Write-Warning 'spoofable, so pass the sending devices explicitly, e.g. -AllowFrom 192.168.1.2'
}

# ---------- folders ----------
# Program folder: Users may read/execute (the task runs the script as SYSTEM, so it must not be writable by them).
# Data folder (captured logs, queue, config with the token): SYSTEM + Administrators only, set BEFORE anything is
# written - otherwise local users could read firewall logs or drop forged batches that SYSTEM forwards.
Assert-SafeExisting $InstallDir
Assert-SafeExisting $DataDir
foreach ($d in @($InstallDir, $DataDir)) { if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Force -Path $d | Out-Null } }
Set-RestrictedAcl -Path $InstallDir -IsDirectory $true -UsersRead $true
Set-RestrictedAcl -Path $DataDir -IsDirectory $true
foreach ($d in @((Join-Path $DataDir 'logs'), (Join-Path $DataDir 'queue'))) {
  if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Force -Path $d | Out-Null }
  Set-RestrictedAcl -Path $d -IsDirectory $true
}

# ---------- script ----------
$src = Join-Path $PSScriptRoot 'sentra-syslog-relay.ps1'
if (-not (Test-Path -LiteralPath $src)) { throw "sentra-syslog-relay.ps1 not found next to this installer ($PSScriptRoot)." }
Copy-Item -LiteralPath $src -Destination $ScriptDest -Force

# ---------- config ----------
$cfg = [ordered]@{
  listen_ip     = $ListenIp
  port          = $Port
  allow_from    = @($AllowFrom)
  log_dir       = (Join-Path $DataDir 'logs')
  queue_dir     = (Join-Path $DataDir 'queue')
  keep_days     = $KeepDays
  forward       = [bool]$CollectorUrl
  collector_url = if ($CollectorUrl) { $CollectorUrl } else { '' }
  src_id        = $SrcId
  token         = if ($Token) { $Token } else { '' }
  pinned_thumbprint = $PinnedThumbprint
}
$cfg | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $ConfigPath -Encoding utf8

# config holds the ingest token: written into the already-restricted folder, then given its own protected ACL
Set-RestrictedAcl -Path $ConfigPath -IsDirectory $false

# ---------- firewall ----------
if (-not $NoFirewallRule) {
  netsh.exe advfirewall firewall delete rule name="$RuleName" 2>$null | Out-Null
  $scope = 'any'
  if ($AllowFrom.Count -gt 0) { $scope = ($AllowFrom -join ',') }
  foreach ($proto in @('TCP', 'UDP')) {
    netsh.exe advfirewall firewall add rule name="$RuleName" dir=in action=allow `
      protocol=$proto localport=$Port remoteip=$scope profile=any | Out-Null
  }
  Write-Host "Firewall: allowed $Port/TCP and $Port/UDP inbound from $scope."
}

# ---------- scheduled task ----------
$cmd = "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$ScriptDest`""
schtasks.exe /Delete /TN $TaskName /F 2>$null | Out-Null
schtasks.exe /Create /TN $TaskName /TR $cmd /SC ONSTART /RU SYSTEM /RL HIGHEST /F | Out-Null
schtasks.exe /Run /TN $TaskName | Out-Null

Write-Host ''
Write-Host "Installed. Task '$TaskName' runs at boot as SYSTEM and is now started."
Write-Host "  script  $ScriptDest"
Write-Host "  config  $ConfigPath"
Write-Host "  logs    $(Join-Path $DataDir 'logs')"
if ($CollectorUrl) { Write-Host "  forward $CollectorUrl/ingest/$SrcId" } else { Write-Host '  forward off (capture only)' }
Write-Host ''
Write-Host 'Verify:'
Write-Host "  Get-ChildItem '$(Join-Path $DataDir 'logs')'"
Write-Host "  Get-Content '$(Join-Path $DataDir 'logs')\syslog-$(Get-Date -Format 'yyyyMMdd').log' -Tail 20 -Wait"
Write-Host ''
Write-Host 'To watch lines arrive interactively instead, stop the task and run in the foreground:'
Write-Host "  schtasks /End /TN $TaskName"
Write-Host "  & '$ScriptDest' -Tail"
