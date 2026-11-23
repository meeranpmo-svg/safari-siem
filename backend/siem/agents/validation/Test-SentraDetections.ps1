# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
<#
.SYNOPSIS
  End-to-end detection test for the Sentra SIEM on a Windows TEST machine: performs real but harmless actions
  that the SIEM must detect, cleans everything up, and prints the command that checks the alerts on the SIEM server.

.DESCRIPTION
  Run as Administrator on a TEST machine (or a test server) whose logs reach the SIEM through the SentraAgent.
  Get a change/test approval first and tell the SOC team: real alerts will be raised.

      powershell -ExecutionPolicy Bypass -File .\Test-SentraDetections.ps1

  What it does (each step is undone at the end, even if a step fails):
    1. creates a local test user  ashval-<random>                        -> SENTRA-IAM-003, SENTRA-IAM-004
    2. 12 failed logons for that user (wrong password, network logon)    -> SENTRA-AUTH-001 (+ SENTRA-AUTH-005 if a lockout policy applies)
    3. adds the test user to the local Administrators group             -> SENTRA-IAM-001
    4. installs a service pointing to C:\Users\Public\ashval-<id>.exe   -> SENTRA-SYS-002, SENTRA-SYS-003  (never started; the file does not exist)
    5. creates a scheduled task (disabled, never runs)                  -> SENTRA-SYS-004
    6. runs PowerShell with an encoded command that only prints text    -> SENTRA-EXEC-001
    7. runs a download cradle against 127.0.0.1:9 (nothing listens)     -> SENTRA-EXEC-002
  It does NOT clear logs, touch LSASS or run attack tools (use a lab VM and Atomic Red Team for those).

  Needed audit settings (the script checks and can enable them with -EnableAuditing):
    Logon, Account Lockout, User Account Management, Security Group Management, Process Creation (+ command line),
    Other Object Access Events (scheduled tasks), PowerShell script block logging.

.PARAMETER EnableAuditing  Turn the needed audit settings on before testing (they stay on).
.PARAMETER Yes             Do not ask for confirmation.
#>
[CmdletBinding()]
param([switch]$EnableAuditing, [switch]$Yes)

$ErrorActionPreference = 'Stop'
function Say($m)  { Write-Host "==> $m" -ForegroundColor Cyan }
function Ok($m)   { Write-Host "    $m" -ForegroundColor Green }
function Warn($m) { Write-Host "warning: $m" -ForegroundColor Yellow }

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { Write-Host 'error: run PowerShell as Administrator' -ForegroundColor Red; exit 1 }

$id = -join ((48..57) + (97..122) | Get-Random -Count 6 | ForEach-Object { [char]$_ })
$TestUser = "ashval-$id"
$Service = "ashval-$id-svc"
$Task = "ashval-$id-task"
$Computer = $env:COMPUTERNAME.ToLower()

Write-Host ''
Write-Host "Sentra SIEM - endpoint detection test on $Computer (run $id)" -ForegroundColor White
Write-Host 'This makes REAL changes that the SOC will see as alerts: a test user (added to Administrators), failed logons,'
Write-Host 'a service and a scheduled task (never started), and two harmless PowerShell commands. Everything is removed at the end.'
if (-not $Yes) { $a = Read-Host 'Is this a test machine and is the test approved? (yes/no)'; if ($a -ne 'yes') { Write-Host 'cancelled'; exit 1 } }

# ---- audit policy
$need = @('Logon', 'Account Lockout', 'User Account Management', 'Security Group Management', 'Process Creation', 'Other Object Access Events')
if ($EnableAuditing) {
  Say 'enabling the needed audit settings'
  foreach ($s in $need) { auditpol /set /subcategory:"$s" /success:enable /failure:enable | Out-Null }
  reg add 'HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit' /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f | Out-Null
  reg add 'HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f | Out-Null
} else {
  $ap = (auditpol /get /category:* 2>$null) -join "`n"
  foreach ($s in $need) { if ($ap -match "(?m)^\s+$([regex]::Escape($s))\s+No Auditing") { Warn "audit '$s' is off - its detections cannot fire (run with -EnableAuditing)" } }
}

$start = [DateTime]::UtcNow.AddSeconds(-5).ToString('yyyy-MM-ddTHH:mm:ssZ')
$expect = New-Object System.Collections.ArrayList
$pw = 'Tv!' + [Guid]::NewGuid().ToString('N').Substring(0, 16) + 'a1'
try {
  Say "1. creating test user $TestUser"
  net user $TestUser $pw /add /comment:"sentra-siem validation test $id - delete if found" | Out-Null
  [void]$expect.AddRange(@('SENTRA-IAM-003', 'SENTRA-IAM-004'))

  Say '2. 12 failed logons for the test user (wrong password)'
  Add-Type -AssemblyName System.DirectoryServices.AccountManagement
  $ctx = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Machine)
  for ($i = 1; $i -le 12; $i++) { try { [void]$ctx.ValidateCredentials($TestUser, "wrong-$i") } catch { } ; Start-Sleep -Milliseconds 300 }
  [void]$expect.Add('SENTRA-AUTH-001')

  Say '3. adding the test user to the local Administrators group'
  $admins = (New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')).Translate([Security.Principal.NTAccount]).Value.Split('\')[-1]
  net localgroup "$admins" $TestUser /add | Out-Null
  [void]$expect.Add('SENTRA-IAM-001')

  Say "4. installing service $Service (never started)"
  sc.exe create $Service binPath= "C:\Users\Public\ashval-$id.exe" start= demand DisplayName= "sentra-siem validation $id" | Out-Null
  [void]$expect.AddRange(@('SENTRA-SYS-002', 'SENTRA-SYS-003'))

  Say "5. creating scheduled task $Task (disabled, never runs)"
  $act = New-ScheduledTaskAction -Execute 'C:\Windows\System32\cmd.exe' -Argument "/c echo sentra-siem validation $id"
  Register-ScheduledTask -TaskName $Task -Action $act -Description "sentra-siem validation test $id" -Force | Out-Null
  Disable-ScheduledTask -TaskName $Task | Out-Null
  [void]$expect.Add('SENTRA-SYS-004')

  Say '6. PowerShell encoded command (prints a line of text)'
  $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("Write-Output 'sentra-siem validation test $id'"))
  & powershell.exe -NoProfile -NonInteractive -EncodedCommand $enc | Out-Null
  [void]$expect.Add('SENTRA-EXEC-001')

  Say '7. PowerShell download cradle against 127.0.0.1:9 (fails, nothing is downloaded)'
  & powershell.exe -NoProfile -NonInteractive -Command "try { IEX (New-Object Net.WebClient).DownloadString('http://127.0.0.1:9/ashval-$id') } catch { 'no listener - expected' }" | Out-Null
  [void]$expect.Add('SENTRA-EXEC-002')
} catch {
  Warn "step failed: $($_.Exception.Message)"
} finally {
  Say 'cleaning up'
  try { Unregister-ScheduledTask -TaskName $Task -Confirm:$false -ErrorAction SilentlyContinue } catch { }
  sc.exe delete $Service 2>$null | Out-Null
  net user $TestUser /delete 2>$null | Out-Null
  Ok 'test user, service and task removed'
}

Write-Host ''
Write-Host 'Wait 2-3 minutes for the agent to ship the events, then run this ON THE SIEM SERVER:' -ForegroundColor White
Write-Host ''
Write-Host "  sudo sentra-siem-validate check --host $Computer --since $start --expect $($expect -join ',')" -ForegroundColor Green
Write-Host ''
Write-Host 'PASS = the SIEM raised that alert. FAIL = check the audit settings above, the agent (Get-Service SentraAgent) and the agent log.'
