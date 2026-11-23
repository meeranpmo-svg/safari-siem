# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
# itam-agent installer for Windows. Installs the agent, enrols it with a one-time token, and registers a Scheduled
# Task that runs it periodically.
#
#   powershell -ExecutionPolicy Bypass -File install.ps1 -Server https://<portal>/agent [-TokenFile C:\path\token.txt] `
#              [-NodeBin "C:\Program Files\nodejs\node.exe"] [-IntervalMinutes 60]
#   Without -TokenFile the token is prompted for (no echo). The token is handed to the agent on STDIN, never on a command
#   line (visible to other processes); a -TokenFile is deleted after enrolment. -Token is accepted for compatibility but
#   warns. The server must be https://.
#
# LEAST PRIVILEGE:
#   - The agent only READS local inventory (Win32_* CIM classes + the Uninstall registry keys) and makes OUTBOUND
#     HTTPS to the ITAM gateway. It never listens and needs no inbound firewall rule.
#   - Install/enrol must be run once elevated (to create the service dir + scheduled task). The scheduled task runs as
#     the built-in LOCAL SERVICE account - NOT an administrator. LocalService can read the CIM data and HKLM Uninstall
#     keys used here; no admin rights are required at run time. Any probe that is denied degrades to null, never fails.
#   - State (including the per-agent key) lives in %ProgramData%\sentra-itam-agent with inherited ACLs restricted to
#     SYSTEM/Administrators/LocalService.
param(
  [Parameter(Mandatory=$true)][string]$Server,
  [string]$Token = "",
  [string]$TokenFile = "",
  [string]$NodeBin = "$env:ProgramFiles\nodejs\node.exe",
  [int]$IntervalMinutes = 60
)
$ErrorActionPreference = "Stop"
if (-not (Test-Path $NodeBin)) { throw "node not found at $NodeBin (pass -NodeBin)" }
if ($Server -notmatch '^https://') { throw "-Server must be an https:// URL" }
if ($Token) { Write-Warning "-Token exposes the token in the process list; prefer -TokenFile or the prompt" }
elseif ($TokenFile) { $Token = (Get-Content -LiteralPath $TokenFile -TotalCount 1).Trim() }
else {
  $sec = Read-Host -AsSecureString "one-time enrolment token"
  $Token = [Runtime.InteropServices.Marshal]::PtrToStringBSTR([Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec))
}
if (-not $Token) { throw "no enrolment token" }

$here = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)   # agent\ dir
$app  = "$env:ProgramFiles\itam-agent"
$data = "$env:ProgramData\sentra-itam-agent"
New-Item -ItemType Directory -Force -Path $app, $data | Out-Null
Copy-Item "$here\*.js" $app -Force
Copy-Item "$here\collect" $app -Recurse -Force

# restrict the state dir (holds the agent key): SYSTEM + Administrators + LocalService only
icacls $data /inheritance:r /grant "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" "LOCAL SERVICE:(OI)(CI)M" | Out-Null

Write-Host "enrolling ..."
$env:ITAM_AGENT_DIR = $data
# token on STDIN (not argv): piping a string to a native exe writes it to the process's standard input
$Token | & $NodeBin "$app\agent.js" enrol --server $Server --token-stdin --dir $data
$rc = $LASTEXITCODE
$Token = $null
if ($rc -ne 0) { throw "enrolment failed" }
if ($TokenFile) { Remove-Item -LiteralPath $TokenFile -Force }   # single-use token file removed after enrolment

# scheduled task running as LOCAL SERVICE (least privilege), repeating on the interval
$action  = New-ScheduledTaskAction -Execute $NodeBin -Argument "`"$app\agent.js`" once --dir `"$data`""
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(2) -RepetitionInterval (New-TimeSpan -Minutes $IntervalMinutes)
$principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\LOCAL SERVICE" -LogonType ServiceAccount -RunLevel Limited
Register-ScheduledTask -TaskName "ITAM Endpoint Agent" -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null
Write-Host "installed: scheduled task 'ITAM Endpoint Agent' (every $IntervalMinutes min, as LOCAL SERVICE)"
