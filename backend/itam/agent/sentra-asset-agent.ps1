# Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
# sentra-asset-agent.ps1 - IT asset agent for Windows in plain PowerShell 5.1: nothing to install (no Node.js, no modules).
# For computers at project sites that are not on the company network: it only makes OUTBOUND HTTPS to the portal, so it works
# over the internet or a VPN, never listens on a port and needs no inbound firewall rule.
#
#   Install (once, PowerShell as Administrator):
#     powershell -ExecutionPolicy Bypass -File sentra-asset-agent.ps1 -Server https://<portal>/agent -Install
#       -> asks for the one-time enrolment key (no echo), enrols, saves the agent key and creates a scheduled task
#          (every -IntervalHours, default 6, and at start-up) that sends the inventory
#   Run once by hand:      sentra-asset-agent.ps1 -Server https://<portal>/agent
#   Remove:                sentra-asset-agent.ps1 -Uninstall
#
# What it sends (read-only, nothing is changed on the computer): computer name, manufacturer, model, serial number, UUID,
# chassis (laptop / desktop / server), OS and version, CPU, memory, disk size, MAC and IP addresses, the installed software
# from the Uninstall registry keys and the date of the newest Windows update. No files, no user content, no passwords.
# Every report carries a rising sequence number, a fresh nonce and the time, so the server refuses a replayed report.
# If the portal cannot be reached the run simply ends; the next run sends a fresh, complete inventory.
[CmdletBinding()]
param(
  [ValidatePattern('^https://[A-Za-z0-9.-]+(:\d+)?/agent$')][string]$Server,
  [string]$EnrolToken = '',
  [string]$TokenFile = '',
  [string]$DataDir = "$env:ProgramData\SentraAssetAgent",
  [ValidateRange(1, 48)][int]$IntervalHours = 6,
  [switch]$Install,
  [switch]$Uninstall
)
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$TaskName = 'Sentra Asset Agent'
$KeyFile = Join-Path $DataDir 'agent.key'
$StateFile = Join-Path $DataDir 'state.json'
$LogFile = Join-Path $DataDir 'agent.log'

function Write-AgentLog([string]$Text) {
  try { if (-not (Test-Path $DataDir)) { New-Item -ItemType Directory -Force $DataDir | Out-Null }
    Add-Content -Path $LogFile -Value ((Get-Date).ToUniversalTime().ToString('s') + 'Z ' + $Text)
    if ((Get-Item $LogFile).Length -gt 1MB) { Move-Item -Force $LogFile ($LogFile + '.1') } } catch { Write-Verbose 'the log could not be written - the run continues' }
}
function Protect-Dir([string]$Path) {
  # only SYSTEM and Administrators may read the agent key
  $acl = New-Object System.Security.AccessControl.DirectorySecurity
  $acl.SetAccessRuleProtection($true, $false)
  foreach ($sid in 'S-1-5-18', 'S-1-5-32-544') {
    $id = (New-Object System.Security.Principal.SecurityIdentifier($sid)).Translate([System.Security.Principal.NTAccount])
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($id, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
  }
  Set-Acl -Path $Path -AclObject $acl
}

if ($Uninstall) {
  Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
  if (Test-Path $DataDir) { Remove-Item -Recurse -Force $DataDir }
  Write-Output 'Sentra Asset Agent removed (the computer stays in IT Asset Management until an administrator retires it).'
  return
}
if (-not $Server) { throw 'Give -Server https://<portal>/agent' }

# ---- enrol once: the one-time key buys a per-agent key, kept readable by SYSTEM and Administrators only
if (-not (Test-Path $KeyFile)) {
  if ($TokenFile) { $EnrolToken = (Get-Content -Raw $TokenFile).Trim(); Remove-Item -Force $TokenFile }
  if (-not $EnrolToken) { $s = Read-Host -AsSecureString 'One-time enrolment key'; $EnrolToken = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($s)) }
  if (-not $EnrolToken) { throw 'No enrolment key - an administrator creates one on the platform (Agents & Downloads)' }
  New-Item -ItemType Directory -Force $DataDir | Out-Null; Protect-Dir $DataDir
  $enr = Invoke-RestMethod -Method Post -Uri "$Server/enrol" -ContentType 'application/json' -Body (@{ token = $EnrolToken; hostname = $env:COMPUTERNAME; platform = 'windows' } | ConvertTo-Json -Compress) -TimeoutSec 60
  if (-not $enr.agent_key) { throw 'The portal did not return an agent key' }
  Set-Content -Path $KeyFile -Value $enr.agent_key -NoNewline
  @{ seq = 0; agent_id = $enr.agent_id; server = $Server } | ConvertTo-Json | Set-Content $StateFile
  Write-AgentLog ('enrolled as ' + $enr.agent_id)
}

if ($Install) {
  $dest = Join-Path $DataDir 'sentra-asset-agent.ps1'
  if ($PSCommandPath -and ($PSCommandPath -ne $dest)) { Copy-Item -Force $PSCommandPath $dest }
  $arg = "-NoProfile -ExecutionPolicy Bypass -File `"$dest`" -Server $Server"
  $act = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $arg
  $trg = @((New-ScheduledTaskTrigger -AtStartup), (New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(2) -RepetitionInterval (New-TimeSpan -Hours $IntervalHours)))
  $set = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 30) -MultipleInstances IgnoreNew
  Register-ScheduledTask -TaskName $TaskName -Action $act -Trigger $trg -Settings $set -User 'SYSTEM' -RunLevel Highest -Force | Out-Null
  Write-Output "Installed: '$TaskName' sends the inventory every $IntervalHours hour(s) and at start-up. Sending the first one now..."
}

# ---- collect (read-only CIM / registry); each part that fails is left out, the rest is still sent
function Try-Get([scriptblock]$Block) { try { & $Block } catch { Write-AgentLog ('read failed: ' + $_.Exception.Message); $null } }
$cs = Try-Get { Get-CimInstance Win32_ComputerSystem }
$bios = Try-Get { Get-CimInstance Win32_BIOS }
$prod = Try-Get { Get-CimInstance Win32_ComputerSystemProduct }
$os = Try-Get { Get-CimInstance Win32_OperatingSystem }
$cpu = Try-Get { Get-CimInstance Win32_Processor | Select-Object -First 1 }
$disk = Try-Get { (Get-CimInstance Win32_DiskDrive | Measure-Object -Property Size -Sum).Sum }
$nics = @(Try-Get { Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled = True' })
$hot = Try-Get { Get-HotFix | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 1 }
$chassis = if ($cs -and $cs.PCSystemType -eq 2) { 'laptop' } elseif ($os -and $os.ProductType -ne 1) { 'server' } else { 'desktop' }
$ips = @($nics | ForEach-Object { $_.IPAddress } | Where-Object { $_ -and $_ -match '^\d+\.\d+\.\d+\.\d+$' -and $_ -notmatch '^(127|169\.254)\.' })
$macs = @($nics | ForEach-Object { $_.MACAddress } | Where-Object { $_ })
$sw = @()
foreach ($k in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*') {
  $sw += @(Try-Get { Get-ItemProperty $k -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -and -not $_.SystemComponent } | ForEach-Object { @{ name = [string]$_.DisplayName; publisher = [string]$_.Publisher; version = [string]$_.DisplayVersion } } })
}
$sw = @($sw | Where-Object { $_ } | Sort-Object { $_.name } -Unique | Select-Object -First 5000)
$hostFacts = @{
  hostname = $env:COMPUTERNAME
  manufacturer = if ($cs) { [string]$cs.Manufacturer } else { '' }
  model = if ($cs) { [string]$cs.Model } else { '' }
  serial = if ($bios) { [string]$bios.SerialNumber } else { '' }
  uuid = if ($prod) { [string]$prod.UUID } else { '' }
  chassis = $chassis
  type = if ($chassis -eq 'server') { 'server' } elseif ($chassis -eq 'laptop') { 'laptop' } else { 'workstation' }
  os = if ($os) { ([string]$os.Caption).Trim() + ' ' + [string]$os.Version } else { '' }
  cpu = if ($cpu) { ([string]$cpu.Name).Trim() } else { '' }
  mem_gb = if ($cs) { [math]::Round($cs.TotalPhysicalMemory / 1GB, 1) } else { $null }
  disk_gb = if ($disk) { [math]::Round($disk / 1GB) } else { $null }
  ip = if ($ips.Count) { $ips[0] } else { '' }
  mac = if ($macs.Count) { $macs[0] } else { '' }
  macs = $macs
  patch_level = if ($hot) { 'newest update ' + $hot.HotFixID + ' on ' + $hot.InstalledOn.ToString('yyyy-MM-dd') } else { '' }
}

# ---- report: a rising sequence number, a nonce and the time (the server refuses replays and stale reports)
$state = if (Test-Path $StateFile) { Get-Content -Raw $StateFile | ConvertFrom-Json } else { [pscustomobject]@{ seq = 0 } }
$seq = [int]$state.seq + 1
$report = @{ seq = $seq; nonce = [guid]::NewGuid().ToString(); ts = (Get-Date).ToUniversalTime().ToString('o'); host = $hostFacts; software = $sw }
$key = (Get-Content -Raw $KeyFile).Trim()
try {
  $r = Invoke-RestMethod -Method Post -Uri "$Server/report" -Headers @{ Authorization = "Bearer $key" } -ContentType 'application/json' -Body ($report | ConvertTo-Json -Depth 5 -Compress) -TimeoutSec 120
  $state | Add-Member -Force -NotePropertyName seq -NotePropertyValue $seq
  $state | Add-Member -Force -NotePropertyName last_ok -NotePropertyValue $report.ts
  $state | ConvertTo-Json | Set-Content $StateFile
  Write-AgentLog ("report $seq sent: " + $sw.Count + ' software entries')
  Write-Output ("Inventory sent (" + $sw.Count + " software entries).")
} catch {
  # not silent: logged with the reason; the next scheduled run sends a fresh full inventory
  Write-AgentLog ('report failed: ' + $_.Exception.Message)
  throw ('The portal could not be reached or refused the report: ' + $_.Exception.Message + ' - check that https://' + ([uri]$Server).Host + ' is reachable from this computer (internet / VPN) and its certificate is trusted.')
}
