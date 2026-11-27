# Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
# hyperv-report.ps1 - run ON each Hyper-V host (scheduled task as SYSTEM, every 15 minutes). Two things, nothing else:
#   1 READ-ONLY report: host CPU / memory / volumes, network speed per NIC (link and rate), disk latency and every VM (incl. its network rate) (state, uptime, vCPUs, CPU, memory assigned / demand, heartbeat,
#     virtual disks, checkpoints, replication, IPs, MACs) -> POST <server>/agent/hyperv with this host's agent key
#   2 APPROVED actions only: GET <server>/agent/hyperv/actions?host=<this host> returns what a person proposed and a DIFFERENT
#     administrator approved for a VM on THIS host; only start / shutdown / turn-off / restart / checkpoint are run, each result is
#     reported back. The platform never connects into the host; -NoActions turns part 2 off entirely.
# Easiest: Hyper-V Servers page -> "+ Add Hyper-V hosts" gives one command per host that does all of the below.
# First run on a host:  .\hyperv-report.ps1 -Server https://<portal host>/agent -EnrolToken <token from Settings → Agent tokens>
#   enrols the host and keeps its agent key in C:\ProgramData\Sentra\agent.key (readable by SYSTEM and Administrators only).
# Scheduled task (run once as an administrator):
#   schtasks /Create /TN "Sentra Hyper-V report" /SC MINUTE /MO 15 /RU SYSTEM /RL HIGHEST /TR "powershell -NoProfile -ExecutionPolicy Bypass -File C:\ProgramData\Sentra\hyperv-report.ps1 -Server https://<portal host>/agent"
# The portal's certificate must be trusted by the host (the organisation's CA, or import the portal certificate).
param(
  [Parameter(Mandatory = $true)][ValidatePattern('^https://[A-Za-z0-9.-]+(:\d+)?/agent$')][string]$Server,
  [string]$KeyFile = 'C:\ProgramData\Sentra\agent.key',
  [string]$EnrolToken = '',
  [switch]$NoActions
)
$ErrorActionPreference = 'Stop'
# Windows PowerShell 5.1 on older Windows Server offers only TLS 1.0 / 1.1 by default; the portal needs TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
# what went wrong, in words an administrator can act on (the full error follows it)
function Explain($err) {
  $m = "$err"
  if ($m -match 'trust relationship|SSL/TLS secure channel|certificate') { return "the host does not trust the portal's certificate - import the organisation's CA (or the portal certificate) into Local Machine > Trusted Root Certification Authorities, then run the command again" }
  if ($m -match 'could not be resolved|No such host|remote name') { return "the host cannot resolve the portal's name - check DNS on the host, or create the commands from the portal opened by an address the host can reach" }
  if ($m -match 'Unable to connect|actively refused|timed out|timeout|connection was closed|underlying connection') { return "the host cannot reach the portal on HTTPS (443) - check the firewall between the host and the portal and any proxy (Test-NetConnection <portal> -Port 443)" }
  if ($m -match '\(401\)|\(403\)|Unauthorized|Forbidden|token') { return "the one-time key was refused - it is used, expired or removed: remove the host on the Hyper-V Servers page and create its command again" }
  return "see the error below"
}

if (-not (Test-Path $KeyFile)) {
  if (-not $EnrolToken) { throw "no agent key at $KeyFile - run once with -EnrolToken <token>" }
  $dir = Split-Path $KeyFile; New-Item -ItemType Directory -Force -Path $dir | Out-Null
  Write-Host "Enrolling $env:COMPUTERNAME with $Server ..."
  try {
  $enr = Invoke-RestMethod -Method Post -Uri "$Server/enrol" -ContentType 'application/json' -Body (@{ token = $EnrolToken; hostname = $env:COMPUTERNAME; platform = 'windows' } | ConvertTo-Json -Compress)
  } catch { Write-Host ('NOT ENROLLED: ' + (Explain $_)) -ForegroundColor Red; throw }
  Set-Content -Path $KeyFile -Value $enr.agent_key -NoNewline
  $acl = New-Object System.Security.AccessControl.FileSecurity; $acl.SetAccessRuleProtection($true, $false)
  foreach ($who in @('NT AUTHORITY\SYSTEM', 'BUILTIN\Administrators')) { $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($who, 'FullControl', 'Allow'))) }
  Set-Acl -Path $KeyFile -AclObject $acl
}
$headers = @{ Authorization = 'Bearer ' + (Get-Content -Raw $KeyFile).Trim() }
if (-not (Get-Module -ListAvailable -Name Hyper-V)) { Write-Host 'Enrolled, but the Hyper-V PowerShell module is missing on this host: run  Install-WindowsFeature Hyper-V-PowerShell  (or add "Hyper-V Module for Windows PowerShell" in Server Manager) - the report starts on the next run' -ForegroundColor Yellow; exit 2 }
Import-Module Hyper-V -ErrorAction Stop

# ---- 1 the report (read-only)
$cs = Get-CimInstance Win32_ComputerSystem; $os = Get-CimInstance Win32_OperatingSystem
$cpu = (Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average
$vols = @(Get-CimInstance Win32_Volume -Filter 'DriveType=3' | Where-Object { $_.Capacity -gt 0 -and $_.Name -notlike '\\?\*' } | ForEach-Object {
  @{ name = $_.Name.TrimEnd('\'); size_gb = [math]::Round($_.Capacity / 1GB, 1); free_gb = [math]::Round($_.FreeSpace / 1GB, 1); csv = ($_.Name -like '*ClusterStorage*') } })
$ip = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notlike '169.254.*' -and $_.IPAddress -ne '127.0.0.1' } | Select-Object -First 1).IPAddress
# network speed and disk: one 2-second sample of the performance counters (read-only). A counter the host does not have leaves
# the value empty - never a 0 that reads as "idle", never a failed report.
$nics = @(); $disk = $null; $vmNet = @{}
try {
  $paths = @('\Network Adapter(*)\Bytes Received/sec', '\Network Adapter(*)\Bytes Sent/sec', '\PhysicalDisk(_Total)\Avg. Disk sec/Transfer',
             '\PhysicalDisk(_Total)\Disk Read Bytes/sec', '\PhysicalDisk(_Total)\Disk Write Bytes/sec',
             '\Hyper-V Virtual Network Adapter(*)\Bytes Received/sec', '\Hyper-V Virtual Network Adapter(*)\Bytes Sent/sec')
  $cs2 = (Get-Counter -Counter $paths -SampleInterval 2 -MaxSamples 1 -ErrorAction SilentlyContinue).CounterSamples
  $val = { param($set, $inst, $cn) ($cs2 | Where-Object { $_.Path -like "*\$set(*)\$cn" -and $_.InstanceName -eq $inst } | Select-Object -First 1).CookedValue }
  foreach ($a in @(Get-NetAdapter -Physical | Where-Object { $_.Status -eq 'Up' })) {
    $inst = ($a.InterfaceDescription -replace '\(', '[' -replace '\)', ']' -replace '#', '_' -replace '/', '_').ToLower()
    $rx = & $val 'network adapter' $inst 'bytes received/sec'; $tx = & $val 'network adapter' $inst 'bytes sent/sec'
    $nics += @{ name = $a.Name; link_mbps = [math]::Round($a.ReceiveLinkSpeed / 1e6); rx_bps = $(if ($null -ne $rx) { [math]::Round($rx * 8) } else { $null }); tx_bps = $(if ($null -ne $tx) { [math]::Round($tx * 8) } else { $null }) }
  }
  $lat = & $val 'physicaldisk' '_total' 'avg. disk sec/transfer'
  if ($null -ne $lat) { $disk = @{ latency_ms = [math]::Round($lat * 1000, 1); read_bps = [math]::Round((& $val 'physicaldisk' '_total' 'disk read bytes/sec')); write_bps = [math]::Round((& $val 'physicaldisk' '_total' 'disk write bytes/sec')) } }
  foreach ($c in @($cs2 | Where-Object { $_.Path -like '*\hyper-v virtual network adapter(*' })) {
    $vmn = $c.InstanceName -replace '_network adapter.*$', '';   # "<vm name>_network adapter_<ids>" - a VM name may itself hold '_'
    if (-not $vmNet.ContainsKey($vmn)) { $vmNet[$vmn] = @{ rx = 0.0; tx = 0.0 } }
    if ($c.Path -like '*bytes received/sec') { $vmNet[$vmn].rx += $c.CookedValue * 8 } else { $vmNet[$vmn].tx += $c.CookedValue * 8 }
  }
} catch { Write-Warning ('performance counters not read: ' + $_.Exception.Message) }   # the report still goes, without network / disk figures

$vms = @(Get-VM | ForEach-Object {
  $vm = $_
  $na = @(Get-VMNetworkAdapter -VM $vm)
  $hb = (Get-VMIntegrationService -VM $vm | Where-Object { $_.Name -eq 'Heartbeat' } | Select-Object -First 1).PrimaryStatusDescription
  $disks = @(Get-VMHardDiskDrive -VM $vm | ForEach-Object { $p = $_.Path; try { $v = Get-VHD -Path $p; @{ path = $p; size_gb = [math]::Round($v.FileSize / 1GB, 1); max_gb = [math]::Round($v.Size / 1GB, 1) } } catch { @{ path = $p } } })
  $cps = @(Get-VMSnapshot -VM $vm | ForEach-Object { @{ name = $_.Name; created = $_.CreationTime.ToUniversalTime().ToString('o') } })
  @{ vm_id = $vm.VMId.Guid; name = $vm.Name; state = "$($vm.State)"; generation = $vm.Generation; uptime_s = [int]$vm.Uptime.TotalSeconds; vcpus = $vm.ProcessorCount; cpu_pct = $vm.CPUUsage
     mem_assigned_mb = [int]($vm.MemoryAssigned / 1MB); mem_demand_mb = [int]($vm.MemoryDemand / 1MB); dynamic_memory = $vm.DynamicMemoryEnabled; heartbeat = "$hb"
     ips = @($na.IPAddresses | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' }); macs = @($na.MacAddress); vhds = $disks; checkpoints = $cps
     replication_state = "$($vm.ReplicationState)"; replication_health = "$($vm.ReplicationHealth)"
     net_rx_bps = $(if ($vmNet.ContainsKey($vm.Name.ToLower())) { [math]::Round($vmNet[$vm.Name.ToLower()].rx) } else { $null }); net_tx_bps = $(if ($vmNet.ContainsKey($vm.Name.ToLower())) { [math]::Round($vmNet[$vm.Name.ToLower()].tx) } else { $null }) }
})
# virtual networking (read-only): virtual switches and their uplinks (SET or NIC team), the physical NICs, every VM and
# management-OS network adapter with its VLAN - for the Virtual Network Map. A host without these cmdlets still sends the rest.
$net = $null
try {
  $phy = @(Get-NetAdapter -Physical | ForEach-Object { @{ name = $_.Name; desc = $_.InterfaceDescription; status = "$($_.Status)"; link_mbps = [math]::Round($_.ReceiveLinkSpeed / 1e6); mac = "$($_.MacAddress)" } })
  $sw = @(Get-VMSwitch | ForEach-Object {
    $x = $_; $up = @()
    try { $t = Get-VMSwitchTeam -Name $x.Name -ErrorAction Stop; $up = @($t.NetAdapterInterfaceDescription) } catch { $up = @($x.NetAdapterInterfaceDescription | Where-Object { $_ }) }   # not a SET switch: its one uplink
    @{ name = $x.Name; type = "$($x.SwitchType)"; mgmt_os = [bool]$x.AllowManagementOS; set = [bool]$x.EmbeddedTeamingEnabled; uplinks = $up } })
  $ad = @(Get-VMNetworkAdapter -All | ForEach-Object {
    $a = $_; $vl = $null; try { $vl = Get-VMNetworkAdapterVlan -VMNetworkAdapter $a } catch { $vl = $null }   # no VLAN setting readable: shown as untagged
    @{ vm = $(if ($a.IsManagementOs) { '' } else { "$($a.VMName)" }); mgmt_os = [bool]$a.IsManagementOs; name = "$($a.Name)"; switch = "$($a.SwitchName)"; mac = "$($a.MacAddress)"; status = "$($a.Status)"
       ips = @($a.IPAddresses | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' }); vlan_mode = $(if ($vl) { "$($vl.OperationMode)" } else { '' })
       vlan = $(if ($vl -and $vl.AccessVlanId) { [int]$vl.AccessVlanId } else { $null }); allowed = $(if ($vl) { "$($vl.AllowedVlanIdListString)" } else { '' }); native = $(if ($vl -and $vl.NativeVlanId) { [int]$vl.NativeVlanId } else { $null }) } })
  $net = @{ switches = $sw; physical = $phy; adapters = $ad }
} catch { Write-Warning ('virtual network not read: ' + $_.Exception.Message) }   # the report still goes, without the network map

$report = @{ collected_at = (Get-Date).ToUniversalTime().ToString('o'); vms = $vms
  host = @{ name = $env:COMPUTERNAME; fqdn = "$($cs.DNSHostName).$($cs.Domain)".ToLower(); ip = $ip; os = $os.Caption; logical_processors = $cs.NumberOfLogicalProcessors; cpu_pct = $cpu
            mem_total_mb = [int]($os.TotalVisibleMemorySize / 1KB); mem_free_mb = [int]($os.FreePhysicalMemory / 1KB); volumes = $vols; nics = $nics; disk = $disk; network = $net } }
Invoke-RestMethod -Method Post -Uri "$Server/hyperv" -Headers $headers -ContentType 'application/json' -Body ($report | ConvertTo-Json -Depth 8 -Compress) | Out-Null

# ---- 2 approved actions for THIS host only, from a fixed list
if ($NoActions) { return }
$todo = Invoke-RestMethod -Method Get -Uri ("$Server/hyperv/actions?host=" + [uri]::EscapeDataString($env:COMPUTERNAME)) -Headers $headers
foreach ($a in @($todo.actions)) {
  $ok = $true; $msg = ''
  try {
    $vm = Get-VM -Name $a.vm -ErrorAction Stop
    switch ($a.action) {
      'start'      { Start-VM -VM $vm }
      'shutdown'   { Stop-VM -VM $vm -Force }                 # guest shutdown through integration services
      'turn-off'   { Stop-VM -VM $vm -TurnOff -Force }
      'restart'    { Restart-VM -VM $vm -Force }
      'checkpoint' { Checkpoint-VM -VM $vm -SnapshotName ('approved ' + $a.id) }
      default      { throw "not an allowed action: $($a.action)" }
    }
    $msg = "$($a.action) done on $($vm.Name)"
  } catch { $ok = $false; $msg = $_.Exception.Message }
  if ($msg.Length -gt 390) { $msg = $msg.Substring(0, 390) }
  Invoke-RestMethod -Method Post -Uri "$Server/hyperv/actions/$($a.id)/result" -Headers $headers -ContentType 'application/json' -Body (@{ ok = $ok; message = $msg } | ConvertTo-Json -Compress) | Out-Null
}
