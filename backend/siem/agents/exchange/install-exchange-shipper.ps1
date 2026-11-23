# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
<#
.SYNOPSIS
  Installs the Sentra SIEM Exchange file shipper (SentraExchangeShipper) on this Exchange server.
  Run from an elevated Windows PowerShell 5.1 prompt on EACH Exchange server.

.DESCRIPTION
  - copies sentra-exchange-shipper.ps1 to  C:\Program Files\SentraExchangeShipper\   (writable by Administrators/SYSTEM only)
  - creates                             C:\ProgramData\SentraExchangeShipper\{queue,logs} - ACL: SYSTEM + Administrators only
  - writes config.json (defaults from sentra-exchange-shipper.ps1 -PrintDefaultConfig + collector URL / source id / pin)
  - writes token.txt (ingest token for the source) - ACL SYSTEM + Administrators only, never echoed
  - registers the scheduled task "\SentraExchangeShipper" running as SYSTEM every minute (or -Loop: continuous with restart)
  - shows which message tracking / IIS log files were discovered (dry run of the shipper)

  The token is read from -TokenFile (e.g. a file on a secured deployment share, deleted afterwards) or prompted for
  as a SecureString. It is never accepted as a plain command-line argument (it would land in logs / 4104 events).
  The same token as the Windows agent's source "win-exchange" can be used (one source for both feeds).

.EXAMPLE
  .\install-exchange-shipper.ps1 -CollectorUrl https://soc.example.com
.EXAMPLE
  .\install-exchange-shipper.ps1 -CollectorUrl https://soc.example.com -SourceId win-exchange -TokenFile \\deploy\sentra\win-exchange.token
.EXAMPLE
  .\install-exchange-shipper.ps1 -ExportTaskXml C:\temp\SentraExchangeShipper.xml     # only writes the task definition, no admin needed
#>
[CmdletBinding(DefaultParameterSetName = 'Install')]
param(
  [Parameter(Mandatory = $true, ParameterSetName = 'Install')][string]$CollectorUrl,
  [Parameter(ParameterSetName = 'Install')][string]$SourceId = 'win-exchange',
  [Parameter(ParameterSetName = 'Install')][string]$TokenFile = '',
  [Parameter(ParameterSetName = 'Install')][string]$PinnedThumbprint = '',
  [Parameter(ParameterSetName = 'Install')][string]$ExchangeInstallPath = '',
  [Parameter(ParameterSetName = 'Install')][string]$ServerName = '',
  [Parameter(ParameterSetName = 'Install')][switch]$ResetConfig,
  [Parameter(ParameterSetName = 'Install')][switch]$NoStart,
  [Parameter(ParameterSetName = 'Export', Mandatory = $true)][string]$ExportTaskXml,
  [string]$InstallDir = (Join-Path $env:ProgramFiles 'SentraExchangeShipper'),
  [string]$DataDir = (Join-Path $env:ProgramData 'SentraExchangeShipper'),
  [switch]$Loop,
  [switch]$Realtime,                               # = -Loop -LoopSeconds 5: message tracking / IIS lines within ~5 s
  [ValidateRange(5, 300)][int]$LoopSeconds = 60    # loop mode: seconds between passes
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$TaskName = 'SentraExchangeShipper'
$ScriptName = 'sentra-exchange-shipper.ps1'
$SidSystem = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
$SidAdmins = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
$SidUsers  = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-545')
$Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
if ($Realtime) { $Loop = [switch]$true; if (-not $PSBoundParameters.ContainsKey('LoopSeconds')) { $LoopSeconds = 5 } }

function Get-TaskXml {
  param([string]$ScriptPath, [bool]$LoopMode, [int]$Seconds = 60)
  $ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
  $arguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$ScriptPath`""
  if ($LoopMode) { $arguments += " -Loop -LoopSeconds $Seconds" }
  $start = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ss')
  # per-minute mode: a pass every minute, each bounded to 30 min, overlapping starts ignored (the shipper also holds a mutex)
  # loop mode: started at boot and re-triggered every 5 minutes (IgnoreNew keeps a single instance), restarted on failure
  $interval = if ($LoopMode) { 'PT5M' } else { 'PT1M' }
  $limit = if ($LoopMode) { 'PT0S' } else { 'PT30M' }
  $restart = if ($LoopMode) { '<RestartOnFailure><Interval>PT1M</Interval><Count>999</Count></RestartOnFailure>' } else { '' }
  $esc = [System.Security.SecurityElement]
@"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Author>Sentra SOC</Author>
    <Description>Sentra SIEM - Exchange file shipper (SentraExchangeShipper). Ships message tracking and IIS logs to the SIEM collector over HTTPS.</Description>
    <URI>\$TaskName</URI>
  </RegistrationInfo>
  <Triggers>
    <BootTrigger><Enabled>true</Enabled><Delay>PT2M</Delay></BootTrigger>
    <TimeTrigger>
      <Repetition><Interval>$interval</Interval><StopAtDurationEnd>false</StopAtDurationEnd></Repetition>
      <StartBoundary>$start</StartBoundary>
      <Enabled>true</Enabled>
    </TimeTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings><StopOnIdleEnd>false</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>$limit</ExecutionTimeLimit>
    <Priority>7</Priority>
    $restart
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>$($esc::Escape($ps))</Command>
      <Arguments>$($esc::Escape($arguments))</Arguments>
    </Exec>
  </Actions>
</Task>
"@
}

function Set-RestrictedAcl {
  # Protected ACL (no inheritance from the parent): SYSTEM + Administrators full control; optional Users read/execute.
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
  # anyone may create folders under ProgramData: a pre-created folder (or a junction) is not trusted
  if (-not (Test-Path -LiteralPath $Path)) { return }
  $item = Get-Item -LiteralPath $Path -Force
  if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "$Path is a reparse point (junction/symlink) - refusing to install into it" }
  $owner = (Get-Acl -LiteralPath $Path).GetOwner([System.Security.Principal.SecurityIdentifier])
  if ($owner -ne $SidSystem -and $owner -ne $SidAdmins) { throw "$Path exists and is owned by $owner, not SYSTEM/Administrators - remove it and re-run" }
}

function Read-TokenSecure {
  $ss = Read-Host -AsSecureString -Prompt "Ingest token for source '$SourceId' (input hidden)"
  $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($ss)
  try { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}

function Invoke-Native {
  # Runs a native command with ErrorActionPreference 'Continue' (Windows PowerShell 5.1 turns a redirected stderr line
  # into a terminating error under 'Stop') and returns @{ Code; Output }. Success is judged by the exit code only.
  param([string]$Exe, [string[]]$Arguments)
  $eapSaved = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
  try {
    $out = @(& $Exe @Arguments 2>&1 | ForEach-Object { "$_" })
    return @{ Code = $LASTEXITCODE; Output = $out }
  } finally { $ErrorActionPreference = $eapSaved }
}

# ---------------------------------------------------------------------------------------------------------------
if ($PSCmdlet.ParameterSetName -eq 'Export') {
  $xml = Get-TaskXml -ScriptPath (Join-Path $InstallDir $ScriptName) -LoopMode ([bool]$Loop) -Seconds $LoopSeconds
  [void]([xml]$xml)   # well-formed check
  [System.IO.File]::WriteAllText($ExportTaskXml, $xml, [System.Text.Encoding]::Unicode)
  Write-Host "Task definition written to $ExportTaskXml (import with: schtasks /Create /XML `"$ExportTaskXml`" /TN $TaskName)"
  return
}

$principal = New-Object System.Security.Principal.WindowsPrincipal([System.Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run this script from an elevated (Administrator) PowerShell prompt.' }
if ($PSVersionTable.PSVersion.Major -lt 5) { Write-Warning "PowerShell $($PSVersionTable.PSVersion) detected; the shipper is tested on Windows PowerShell 5.1 (WMF 5.1)." }
if (-not $CollectorUrl.StartsWith('https://', [StringComparison]::OrdinalIgnoreCase)) { throw 'CollectorUrl must start with https://' }
if ($SourceId -notmatch '^[A-Za-z0-9._-]{1,64}$') { throw 'SourceId must match [A-Za-z0-9._-]{1,64}' }
$PinnedThumbprint = ($PinnedThumbprint -replace '[\s:]', '').ToUpperInvariant()
if ($PinnedThumbprint -and $PinnedThumbprint -notmatch '^([0-9A-F]{40}|[0-9A-F]{64})$') { throw 'PinnedThumbprint must be 40 (SHA-1) or 64 (SHA-256) hex characters' }
if ($ExchangeInstallPath -and -not (Test-Path -LiteralPath $ExchangeInstallPath)) { throw "ExchangeInstallPath not found: $ExchangeInstallPath" }

$src = Join-Path $PSScriptRoot $ScriptName
if (-not (Test-Path -LiteralPath $src)) { throw "$ScriptName not found next to this script ($src)" }

# 1. program files
Write-Host "[1/5] Installing shipper to $InstallDir"
Assert-SafeExisting $InstallDir
Assert-SafeExisting $DataDir
if (-not (Test-Path -LiteralPath $InstallDir)) { [void](New-Item -ItemType Directory -Path $InstallDir) }
Set-RestrictedAcl -Path $InstallDir -IsDirectory $true -UsersRead $true
$shipperPath = Join-Path $InstallDir $ScriptName
Copy-Item -LiteralPath $src -Destination $shipperPath -Force
try { Unblock-File -LiteralPath $shipperPath } catch { }

# 2. data directory, locked down
Write-Host "[2/5] Preparing $DataDir (ACL: SYSTEM + Administrators only)"
foreach ($d in @($DataDir, (Join-Path $DataDir 'queue'), (Join-Path $DataDir 'queue\rejected'), (Join-Path $DataDir 'logs'))) {
  if (-not (Test-Path -LiteralPath $d)) { [void](New-Item -ItemType Directory -Path $d) }
}
Set-RestrictedAcl -Path $DataDir -IsDirectory $true
# make every existing child inherit the protected ACL
foreach ($item in @(Get-ChildItem -LiteralPath $DataDir -Recurse -Force -Attributes !ReparsePoint)) {
  $a = Get-Acl -LiteralPath $item.FullName
  $a.SetOwner($SidAdmins)   # a non-admin owner would keep WRITE_DAC on config.json
  $a.SetAccessRuleProtection($false, $false)
  foreach ($r in @($a.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier]))) { [void]$a.RemoveAccessRuleSpecific($r) }
  Set-Acl -LiteralPath $item.FullName -AclObject $a
}

# 3. configuration
Write-Host '[3/5] Writing config.json'
$cfgPath = Join-Path $DataDir 'config.json'
$cfg = $null
if ((Test-Path -LiteralPath $cfgPath) -and -not $ResetConfig) {
  $cfg = [System.IO.File]::ReadAllText($cfgPath) | ConvertFrom-Json
  Write-Host '      existing config kept (collector, source id and pin updated; use -ResetConfig to start from defaults)'
} else {
  $cfg = (& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $shipperPath -PrintDefaultConfig | Out-String) | ConvertFrom-Json
}
$cfg | Add-Member -NotePropertyName CollectorUrl -NotePropertyValue $CollectorUrl.TrimEnd('/') -Force
$cfg | Add-Member -NotePropertyName SourceId -NotePropertyValue $SourceId -Force
$cfg | Add-Member -NotePropertyName PinnedThumbprint -NotePropertyValue $PinnedThumbprint -Force
$cfg | Add-Member -NotePropertyName TestPlainHttp -NotePropertyValue $false -Force
if ($ExchangeInstallPath) { $cfg | Add-Member -NotePropertyName ExchangeInstallPath -NotePropertyValue $ExchangeInstallPath -Force }
if ($ServerName) { $cfg | Add-Member -NotePropertyName ServerName -NotePropertyValue $ServerName -Force }
[System.IO.File]::WriteAllText($cfgPath, ($cfg | ConvertTo-Json -Depth 6), $Utf8NoBom)

# 4. token
$tokPath = Join-Path $DataDir 'token.txt'
if ($TokenFile) {
  if (-not (Test-Path -LiteralPath $TokenFile)) { throw "token file not found: $TokenFile" }
  $token = ([System.IO.File]::ReadAllText($TokenFile)).Trim()
} elseif (Test-Path -LiteralPath $tokPath) {
  $token = ([System.IO.File]::ReadAllText($tokPath)).Trim()
  Write-Host '[4/5] Keeping the existing token (pass -TokenFile to replace it)'
} else {
  $token = Read-TokenSecure
}
if ([string]::IsNullOrWhiteSpace($token) -or $token.Length -lt 16) { throw 'the ingest token is empty or too short' }
if ($TokenFile -or -not (Test-Path -LiteralPath $tokPath)) {
  Write-Host '[4/5] Storing the ingest token (ACL: SYSTEM + Administrators only)'
  [System.IO.File]::WriteAllText($tokPath, $token, $Utf8NoBom)
}
Set-RestrictedAcl -Path $tokPath -IsDirectory $false
$token = $null

# 5. scheduled task
Write-Host "[5/5] Registering scheduled task \$TaskName (SYSTEM, $(if ($Loop) { 'continuous loop' } else { 'every minute' }))"
$xmlPath = Join-Path $env:TEMP ("ashexshipper-task-{0}.xml" -f [guid]::NewGuid().ToString('N'))
try {
  [System.IO.File]::WriteAllText($xmlPath, (Get-TaskXml -ScriptPath $shipperPath -LoopMode ([bool]$Loop) -Seconds $LoopSeconds), [System.Text.Encoding]::Unicode)
  $r = Invoke-Native -Exe 'schtasks.exe' -Arguments @('/Create', '/TN', $TaskName, '/XML', $xmlPath, '/F')
  if ($r.Code -ne 0) { throw "schtasks /Create failed with exit code $($r.Code): $($r.Output -join ' ')" }
} finally { Remove-Item -LiteralPath $xmlPath -Force -ErrorAction SilentlyContinue }

# Which log files were found? (dry run of the shipper: reads config.json, sends nothing)
Write-Host ''
Write-Host 'Log files discovered (dry run):'
$dr = Invoke-Native -Exe 'powershell.exe' -Arguments @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $shipperPath, '-DataDir', $DataDir, '-DryRun', '-Count', '0')
foreach ($l in $dr.Output) { if ($l -match '^# dry-run: source|ExchangeInstallPath') { Write-Host ('      ' + ($l -replace '^# dry-run: ', '')) } }
if (($dr.Output -join "`n") -match 'no files found|ExchangeInstallPath not found') {
  Write-Warning 'some log paths were not found - check "Sources[].Paths" / "ExchangeInstallPath" in config.json (IIS logging must be enabled with W3C format)'
}

# Informative reachability check (TCP only; TLS/token are verified by the first pass - see logs\shipper.log)
try {
  $u = [Uri]$CollectorUrl
  $tcp = New-Object System.Net.Sockets.TcpClient
  $ar = $tcp.BeginConnect($u.Host, $u.Port, $null, $null)
  if ($ar.AsyncWaitHandle.WaitOne(3000) -and $tcp.Connected) { Write-Host "      collector $($u.Host):$($u.Port) reachable (TCP)" } else { Write-Warning "collector $($u.Host):$($u.Port) not reachable over TCP right now - lines will queue locally" }
  $tcp.Close()
} catch { Write-Warning "reachability check failed: $($_.Exception.Message)" }

if (-not $NoStart) { $r = Invoke-Native -Exe 'schtasks.exe' -Arguments @('/Run', '/TN', $TaskName); if ($r.Code -ne 0) { Write-Warning "could not start the task now (exit $($r.Code)); it runs at the next minute" } }
Write-Host ''
Write-Host 'SentraExchangeShipper installed.'
Write-Host "  logs      : $(Join-Path $DataDir 'logs\shipper.log')"
Write-Host "  queue     : $(Join-Path $DataDir 'queue')"
Write-Host "  bookmarks : $(Join-Path $DataDir 'bookmarks.json')"
Write-Host "  verify    : Get-Content '$(Join-Path $DataDir 'logs\shipper.log')' -Tail 5   (one 'pass done' line per minute)"
Write-Host "              SIEM portal -> Sources -> '$SourceId' shows host $(if ($ServerName) { $ServerName } else { $env:COMPUTERNAME }) with message tracking / IIS events"
