# Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
# hyperv-report.ps1 - run ON each Hyper-V host (scheduled task as SYSTEM, every 15 minutes). Two things, nothing else:
#   1 READ-ONLY report: host CPU / memory / volumes and every VM (state, uptime, vCPUs, CPU, memory assigned / demand, heartbeat,
#     virtual disks, checkpoints, replication, IPs, MACs) -> POST <server>/agent/hyperv with this host's agent key
#   2 APPROVED actions only: GET <server>/agent/hyperv/actions?host=<this host> returns what a person proposed and a DIFFERENT
#     administrator approved for a VM on THIS host; only start / shutdown / turn-off / restart / checkpoint are run, each result is
#     reported back. The platform never connects into the host; -NoActions turns part 2 off entirely.
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
Import-Module Hyper-V -ErrorAction Stop

if (-not (Test-Path $KeyFile)) {
  if (-not $EnrolToken) { throw "no agent key at $KeyFile - run once with -EnrolToken <token>" }
  $dir = Split-Path $KeyFile; New-Item -ItemType Directory -Force -Path $dir | Out-Null
  $enr = Invoke-RestMethod -Method Post -Uri "$Server/enrol" -ContentType 'application/json' -Body (@{ token = $EnrolToken; hostname = $env:COMPUTERNAME; platform = 'windows' } | ConvertTo-Json -Compress)
  Set-Content -Path $KeyFile -Value $enr.agent_key -NoNewline
  $acl = New-Object System.Security.AccessControl.FileSecurity; $acl.SetAccessRuleProtection($true, $false)
  foreach ($who in @('NT AUTHORITY\SYSTEM', 'BUILTIN\Administrators')) { $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($who, 'FullControl', 'Allow'))) }
  Set-Acl -Path $KeyFile -AclObject $acl
}
$headers = @{ Authorization = 'Bearer ' + (Get-Content -Raw $KeyFile).Trim() }

# ---- 1 the report (read-only)
$cs = Get-CimInstance Win32_ComputerSystem; $os = Get-CimInstance Win32_OperatingSystem
$cpu = (Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average
$vols = @(Get-CimInstance Win32_Volume -Filter 'DriveType=3' | Where-Object { $_.Capacity -gt 0 -and $_.Name -notlike '\\?\*' } | ForEach-Object {
  @{ name = $_.Name.TrimEnd('\'); size_gb = [math]::Round($_.Capacity / 1GB, 1); free_gb = [math]::Round($_.FreeSpace / 1GB, 1); csv = ($_.Name -like '*ClusterStorage*') } })
$ip = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notlike '169.254.*' -and $_.IPAddress -ne '127.0.0.1' } | Select-Object -First 1).IPAddress
$vms = @(Get-VM | ForEach-Object {
  $vm = $_
  $na = @(Get-VMNetworkAdapter -VM $vm)
  $hb = (Get-VMIntegrationService -VM $vm | Where-Object { $_.Name -eq 'Heartbeat' } | Select-Object -First 1).PrimaryStatusDescription
  $disks = @(Get-VMHardDiskDrive -VM $vm | ForEach-Object { $p = $_.Path; try { $v = Get-VHD -Path $p; @{ path = $p; size_gb = [math]::Round($v.FileSize / 1GB, 1); max_gb = [math]::Round($v.Size / 1GB, 1) } } catch { @{ path = $p } } })
  $cps = @(Get-VMSnapshot -VM $vm | ForEach-Object { @{ name = $_.Name; created = $_.CreationTime.ToUniversalTime().ToString('o') } })
  @{ vm_id = $vm.VMId.Guid; name = $vm.Name; state = "$($vm.State)"; generation = $vm.Generation; uptime_s = [int]$vm.Uptime.TotalSeconds; vcpus = $vm.ProcessorCount; cpu_pct = $vm.CPUUsage
     mem_assigned_mb = [int]($vm.MemoryAssigned / 1MB); mem_demand_mb = [int]($vm.MemoryDemand / 1MB); dynamic_memory = $vm.DynamicMemoryEnabled; heartbeat = "$hb"
     ips = @($na.IPAddresses | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' }); macs = @($na.MacAddress); vhds = $disks; checkpoints = $cps
     replication_state = "$($vm.ReplicationState)"; replication_health = "$($vm.ReplicationHealth)" }
})
$report = @{ collected_at = (Get-Date).ToUniversalTime().ToString('o'); vms = $vms
  host = @{ name = $env:COMPUTERNAME; fqdn = "$($cs.DNSHostName).$($cs.Domain)".ToLower(); ip = $ip; os = $os.Caption; logical_processors = $cs.NumberOfLogicalProcessors; cpu_pct = $cpu
            mem_total_mb = [int]($os.TotalVisibleMemorySize / 1KB); mem_free_mb = [int]($os.FreePhysicalMemory / 1KB); volumes = $vols } }
Invoke-RestMethod -Method Post -Uri "$Server/hyperv" -Headers $headers -ContentType 'application/json' -Body ($report | ConvertTo-Json -Depth 6 -Compress) | Out-Null

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
