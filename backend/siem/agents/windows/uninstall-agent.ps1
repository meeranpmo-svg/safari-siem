# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
<#
.SYNOPSIS
  Removes the Sentra SIEM Windows agent (SentraAgent). Run from an elevated PowerShell prompt.

.DESCRIPTION
  Stops and deletes the scheduled task, waits for a running pass to finish, removes C:\Program Files\SentraAgent and
  (unless -KeepData) C:\ProgramData\SentraAgent (config, token, bookmarks, logs, queue).
  If the local queue still holds unsent batches, the data folder is kept unless -Force is given.
  Remember to revoke the source's token on the SIEM (sentra-siem-token revoke <src>) when a whole source is retired.
#>
[CmdletBinding()]
param(
  [string]$InstallDir = (Join-Path $env:ProgramFiles 'SentraAgent'),
  [string]$DataDir = (Join-Path $env:ProgramData 'SentraAgent'),
  [switch]$KeepData,
  [switch]$Force
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$TaskName = 'SentraAgent'

$principal = New-Object System.Security.Principal.WindowsPrincipal([System.Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run this script from an elevated (Administrator) PowerShell prompt.' }

# 1. task
$eapSaved = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
$null = & schtasks.exe /Query /TN $TaskName 2>&1
if ($LASTEXITCODE -eq 0) {
  $null = & schtasks.exe /End /TN $TaskName 2>&1
  & schtasks.exe /Delete /TN $TaskName /F | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "could not delete scheduled task $TaskName" }
  Write-Host "Scheduled task \$TaskName removed."
} else { Write-Host "Scheduled task \$TaskName not present." }
$ErrorActionPreference = $eapSaved

# 2. wait for an in-flight pass (the agent holds this mutex while it runs)
$m = New-Object System.Threading.Mutex($false, 'Global\SentraAgentForwarder')
$got = $false
try {
  try { $got = $m.WaitOne(90000) } catch [System.Threading.AbandonedMutexException] { $got = $true }
  if (-not $got) { Write-Warning 'an agent pass is still running after 90 s; continuing anyway' }
} finally { if ($got) { $m.ReleaseMutex() }; $m.Dispose() }

# 3. program files
if (Test-Path -LiteralPath $InstallDir) { Remove-Item -LiteralPath $InstallDir -Recurse -Force; Write-Host "Removed $InstallDir" }

# 4. data
if ($KeepData) { Write-Host "Kept $DataDir (-KeepData)"; return }
if (Test-Path -LiteralPath $DataDir) {
  $pending = @(Get-ChildItem -LiteralPath (Join-Path $DataDir 'queue') -Filter '*.ndjson.gz' -File -ErrorAction SilentlyContinue)
  if ($pending.Count -gt 0 -and -not $Force) {
    Write-Warning ("{0} unsent batch(es) remain in {1}\queue - data folder kept. Re-run with -Force to delete it anyway." -f $pending.Count, $DataDir)
    return
  }
  Remove-Item -LiteralPath $DataDir -Recurse -Force
  Write-Host "Removed $DataDir (config, token, bookmarks, logs, queue)"
}
Write-Host 'SentraAgent uninstalled.'
