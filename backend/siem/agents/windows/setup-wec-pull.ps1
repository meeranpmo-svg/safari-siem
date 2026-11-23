# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
<#
.SYNOPSIS
  PULL Windows event logs from many servers into the SIEM with NOTHING installed on those servers: one Windows Event
  Collector (WEC) pulls their logs over WinRM (Kerberos, the collector's computer account), and the SIEM agent on that
  collector ships them. Run elevated, as a domain admin, on any domain-joined machine:
    - ON the collector itself, or
    - on a domain controller / admin server with -Collector <collector>: the collector is set up remotely over WinRM.

.DESCRIPTION
  1. turns on the Windows Event Collector service on the collector (wecutil qc) and enlarges the ForwardedEvents log
  2. creates a COLLECTOR-INITIATED subscription "SentraSIEM-Pull": the collector connects to each listed server and pulls
     Security (the account / logon / privilege / policy events the SIEM's rules use), System (service installs, crashes,
     time changes, Netlogon), Application errors, PowerShell script blocks, Sysmon and Microsoft Defender detections
  3. -GrantReaders: puts the collector's computer account in "Event Log Readers" on each server (domain controllers: the
     domain's builtin "Event Log Readers" group, once) - the only right it needs; it cannot change anything. This step runs
     from the machine you start the script on (no second WinRM hop).
  4. adds the ForwardedEvents channel to the SIEM agent on the collector (install the agent there first:
     install-agent.ps1 -CollectorUrl https://<siem> -SourceId win-servers-trial -Realtime)
  Each event keeps its own server name: the SIEM shows every server separately (and IT Asset Management marks each one
  connected) although only one agent sends. Active Directory is read over ADSI (built into Windows; no RSAT needed).

  On the servers nothing is installed; they need WinRM listening (default on Windows Server 2012 and later; else
  "winrm quickconfig" or the GPO) and TCP 5985 open from the collector. -Collector needs WinRM on the collector too.

.EXAMPLE
  .\setup-wec-pull.ps1 -FromAD -GrantReaders -Collector lr01.corp-hq.com    # from a domain controller
.EXAMPLE
  .\setup-wec-pull.ps1 -FromAD -GrantReaders            # on the collector itself
.EXAMPLE
  .\setup-wec-pull.ps1 -Servers srv-dc1.corp.local,srv-exch1.corp.local -GrantReaders -Collector 192.168.1.122
.EXAMPLE
  .\setup-wec-pull.ps1 -Status [-Collector lr01.corp-hq.com]   # which servers are being pulled, and errors per server
.EXAMPLE
  .\setup-wec-pull.ps1 -ExportXml C:\temp\sub.xml -Servers a,b   # only writes the subscription XML (review / change control)
.EXAMPLE
  .\setup-wec-pull.ps1 -Remove [-Collector ...]         # deletes the subscription (the agent channel stays, harmless)
#>
[CmdletBinding()]
param(
  [string[]]$Servers = @(), [string]$ServerFile = '', [switch]$FromAD, [string]$Collector = '',
  [string]$SubscriptionName = 'SentraSIEM-Pull', [switch]$GrantReaders, [switch]$IncludeHistory,
  [ValidateRange(64, 16384)][int]$ForwardedLogMB = 2048,
  [switch]$Status, [switch]$Remove, [string]$ExportXml = ''
)
$ErrorActionPreference = 'Stop'
$script:failed = $false
function Say($m, $c = 'Gray') { if ($c -eq 'Fail') { $script:failed = $true; $c = 'Red' }; Write-Host $m -ForegroundColor $c }
# a native tool's stderr must not become a terminating error under ErrorActionPreference Stop (Windows PowerShell 5.1):
# run it with Continue, return its output lines as text; the exit code stays in $LASTEXITCODE
function Native([scriptblock]$cmd) { $eap = $ErrorActionPreference; $ErrorActionPreference = 'Continue'; try { & $cmd 2>&1 | ForEach-Object { "$_" } } finally { $ErrorActionPreference = $eap } }
$isAdmin = $false; try { $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) } catch { }

# ---- everything that happens ON the collector: self-contained, so it runs locally or through Invoke-Command unchanged.
# Returns "<colour>|<text>" lines (colour Fail = an error), or the collector's identity for op 'whoami'.
$CollectorSide = {
  param([string]$op, [string]$sub, [string]$xml, [int]$logMB)
  $ErrorActionPreference = 'Stop'
  $o = New-Object System.Collections.ArrayList
  function Out($c, $m) { [void]$o.Add("$c|$m") }
  function Native([scriptblock]$cmd) { $eap = $ErrorActionPreference; $ErrorActionPreference = 'Continue'; try { & $cmd 2>&1 | ForEach-Object { "$_" } } finally { $ErrorActionPreference = $eap } }
  $cfgFile = 'C:\ProgramData\SentraAgent\config.json'
  if ($op -eq 'whoami') {
    $cs = Get-CimInstance Win32_ComputerSystem
    $fq = $env:COMPUTERNAME; try { $fq = [System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName } catch { }
    return [pscustomobject]@{ name = $env:COMPUTERNAME; fqdn = $fq.ToLower(); domain = $cs.Domain; joined = [bool]$cs.PartOfDomain; agent = (Test-Path $cfgFile) }
  }
  if ($op -eq 'status') {
    $svc = Get-Service Wecsvc -ErrorAction SilentlyContinue
    if (-not $svc) { Out 'Fail' 'the Windows Event Collector service (Wecsvc) is not on this machine'; return $o }
    if ($svc.Status -ne 'Running') {
      Out 'Fail' "the Windows Event Collector service (Wecsvc) is $($svc.Status) (startup: $($svc.StartType)) - nothing is being pulled"
      Out 'Yellow' '   start it (Start-Service Wecsvc) or run the setup again'
      return $o
    }
    $out = Native { wecutil gr $sub }
    if ($LASTEXITCODE) {
      if ("$out" -match '0x6ba|0x6d9') { Out 'Fail' 'the Windows Event Collector service is not answering - restart it:  Restart-Service Wecsvc' }
      elseif ("$out" -match '0x5\b|Access is denied') { Out 'Fail' 'access denied - run from an elevated PowerShell (Run as administrator), as a domain admin' }
      else { Out 'Fail' "subscription '$sub' not found - run the setup first"; Out 'Gray' "   wecutil: $out" }
      return $o
    }
    foreach ($l in $out) { if ($l -match 'RunTimeStatus: *Active') { Out 'Green' $l } elseif ($l -match 'RunTimeStatus|ErrorMessage|LastError') { Out 'Yellow' $l } else { Out 'Gray' $l } }
    $fe = Get-WinEvent -ListLog ForwardedEvents -ErrorAction SilentlyContinue
    if ($fe) { Out 'Cyan' ("ForwardedEvents: {0:N0} events, {1:N0} MB of {2:N0} MB" -f $fe.RecordCount, ($fe.FileSize / 1MB), ($fe.MaximumSizeInBytes / 1MB)) }
    return $o
  }
  if ($op -eq 'remove') { Native { wecutil ds $sub } | Out-Null; Out 'Green' "subscription '$sub' removed (servers keep their logs; nothing was installed on them)"; return $o }
  if ($op -eq 'setup') {
    Out 'Cyan' "==> Windows Event Collector service on $env:COMPUTERNAME"
    Native { wecutil qc /q } | Out-Null
    Set-Service Wecsvc -StartupType Automatic; Start-Service Wecsvc
    Native { wevtutil sl ForwardedEvents /ms:$([int64]$logMB * 1MB) /rt:false } | Out-Null
    Out 'Gray' "   running; ForwardedEvents log $logMB MB"
    Out 'Cyan' "==> subscription $sub"
    $tmp = Join-Path $env:TEMP ("sentra-wec-{0}.xml" -f ([guid]::NewGuid().ToString('N').Substring(0, 8)))
    [IO.File]::WriteAllText($tmp, $xml, (New-Object Text.UTF8Encoding($false)))
    try {
      Native { wecutil ds $sub } | Out-Null
      $r = Native { wecutil cs $tmp }
      if ($LASTEXITCODE) { Out 'Fail' "   wecutil could not create the subscription: $r"; return $o }
    } finally { Remove-Item $tmp -ErrorAction SilentlyContinue }
    Out 'Green' '   created (collector-initiated: the collector pulls; nothing changes on the servers)'
    return $o
  }
  if ($op -eq 'finish') {
    # the computer account must present a fresh Kerberos ticket that carries a new group membership (domain controllers)
    Native { klist -li 0x3e7 purge } | Out-Null
    if (Test-Path $cfgFile) {
      $cfg = Get-Content $cfgFile -Raw | ConvertFrom-Json
      $chs = @($cfg.Channels)
      if (-not ($chs | Where-Object { $_.Name -eq 'ForwardedEvents' })) {
        $chs += [pscustomobject]@{ Name = 'ForwardedEvents'; Enabled = $true; IncludeMessage = $true; Levels = @(); ExcludeEventIds = @(); EventIds = @() }
        $cfg.Channels = $chs
        $bak = "$cfgFile.bak-$(Get-Date -Format yyyyMMddHHmmss)"; Copy-Item $cfgFile $bak
        ($cfg | ConvertTo-Json -Depth 8) | Set-Content -Encoding UTF8 $cfgFile
        Out 'Green' "==> SIEM agent on $($env:COMPUTERNAME): ForwardedEvents channel added (backup $bak)"
      } else { Out 'Gray' "==> SIEM agent on $($env:COMPUTERNAME): already reads ForwardedEvents" }
    } else {
      Out 'Yellow' "==> the SIEM agent is not installed on $($env:COMPUTERNAME) yet - install it there, then run this script again:"
      Out 'Gray' '      .\install-agent.ps1 -CollectorUrl https://<siem> -SourceId win-servers-trial -Realtime'
    }
    return $o
  }
}

# ---- where the collector is: this machine, or -Collector (name or IP; an IP is turned into its DNS name for Kerberos)
$localNames = @(); $ln = if ($env:COMPUTERNAME) { $env:COMPUTERNAME } else { [Environment]::MachineName }; $localNames += $ln.ToLower()
try { $localNames += ([System.Net.Dns]::GetHostEntry($ln)).HostName.ToLower() } catch { }
$remote = $false; $C = ''
if ($Collector) {
  $C = $Collector.Trim().ToLower()
  if ($C -match '^\d{1,3}(\.\d{1,3}){3}$') {
    try { $C = ([System.Net.Dns]::GetHostEntry($C)).HostName.ToLower() } catch { Say "cannot find the DNS name of $Collector (reverse lookup failed) - give the collector's full name, e.g. -Collector lr01.corp-hq.com" 'Red'; exit 1 }
    if ($C -match '^\d') { Say "no DNS name for $Collector - give the collector's full name" 'Red'; exit 1 }
  }
  if ($C -notmatch '^[a-z0-9][a-z0-9.-]{0,252}$') { Say "not a host name: $Collector" 'Red'; exit 1 }
  $remote = -not ($localNames -contains $C -or $localNames -contains ($C -split '\.')[0])
}
function OnCollector([string]$op, [string]$xml = '') {
  if ($remote) { Invoke-Command -ComputerName $C -ErrorAction Stop -ScriptBlock $CollectorSide -ArgumentList $op, $SubscriptionName, $xml, $ForwardedLogMB }
  else { & $CollectorSide $op $SubscriptionName $xml $ForwardedLogMB }
}
function Show($lines) { foreach ($l in @($lines)) { if ($l -is [string] -and $l -match '^(\w+)\|(.*)$') { Say $Matches[2] $Matches[1] } } }
function Reach() {
  if (-not $remote) { return }
  try { [void](Test-WSMan -ComputerName $C -Authentication Kerberos -ErrorAction Stop) }
  catch { Say "cannot reach the collector $C over WinRM ($((($_.Exception.Message) -split "`n")[0]))" 'Red'; Say '   on the collector: winrm quickconfig  (or the WinRM GPO); TCP 5985 open from this machine; use its full DNS name' 'Yellow'; exit 1 }
}

if ($Status) {
  Reach
  try { Show (OnCollector 'status') } catch { Say "could not read the collector: $((($_.Exception.Message) -split "`n")[0])" 'Red'; exit 1 }
  if ($script:failed) { exit 1 } else { exit 0 }
}
if (-not $isAdmin -and -not $ExportXml) { Say 'run from an elevated PowerShell (Run as administrator), as a domain admin' 'Red'; exit 1 }
# the subscription pulls over Kerberos: the collector and the machine running this must both be in the domain
if (-not $ExportXml) {
  $cs = $null; try { $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop } catch { }
  if ($cs -and -not $cs.PartOfDomain) {
    Say "this machine ($($cs.Name)) is not joined to the domain - run this script on the collector, or on a domain controller with -Collector <collector name>" 'Red'
    Say '   servers only send their logs to a domain member over Kerberos, and this machine cannot reach Active Directory' 'Yellow'
    exit 1
  }
}
Reach
if ($Remove) { try { Show (OnCollector 'remove') } catch { Say "could not reach the collector: $($_.Exception.Message)" 'Red'; exit 1 }; exit 0 }
$col = $null
if (-not $ExportXml) {
  try { $col = OnCollector 'whoami' } catch { Say "could not reach the collector $C ($((($_.Exception.Message) -split "`n")[0]))" 'Red'; exit 1 }
  if (-not $col.joined) { Say "the collector $($col.name) is not joined to the domain - servers will not send to it" 'Red'; exit 1 }
  Say ("==> collector: {0} ({1}){2}" -f $col.name, $col.fqdn, $(if ($remote) { ' - set up remotely over WinRM' } else { ' - this machine' })) 'Cyan'
  if (-not $col.agent) { Say "   note: the SIEM agent is not installed on $($col.name) (C:\ProgramData\SentraAgent) - the pulled events only reach the SIEM from a machine where it is" 'Yellow' }
}

# ---- the server list
if ($ServerFile) { $Servers += Get-Content $ServerFile | Where-Object { $_ -and $_ -notmatch '^\s*#' } | ForEach-Object { $_.Trim() } }
# Active Directory over ADSI (built into Windows) - no RSAT / ActiveDirectory module needed
function Find-AD([string]$filter, [string[]]$props) {
  $ds = New-Object System.DirectoryServices.DirectorySearcher([ADSI]'', $filter)
  $ds.PageSize = 1000; foreach ($p in $props) { [void]$ds.PropertiesToLoad.Add($p) }
  try { $ds.FindAll() } finally { $ds.Dispose() }
}
if ($FromAD) {
  try {
    # enabled computer objects whose operating system says Server (userAccountControl bit 2 = disabled)
    $found = @(Find-AD '(&(objectCategory=computer)(operatingSystem=*Server*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' @('dnshostname') |
      ForEach-Object { [string]($_.Properties['dnshostname'] | Select-Object -First 1) } | Where-Object { $_ })
  } catch { Say "could not read Active Directory ($($_.Exception.Message)) - run this as a domain user on a domain-joined machine, or give -Servers" 'Red'; exit 1 }
  Say "==> Active Directory: $($found.Count) enabled Windows Server computer objects" 'Cyan'
  $Servers += $found
}
# the collector itself is read by its own agent, not pulled
$skip = @(); if ($col) { $skip = @($col.name.ToLower(), $col.fqdn) } elseif (-not $remote) { $skip = $localNames }
$Servers = @($Servers | ForEach-Object { $_ -split '[,; ]+' } | Where-Object { $_ } | ForEach-Object { $_.Trim().ToLower() } | Where-Object { $skip -notcontains $_ } | Select-Object -Unique)
if (-not $Servers.Count) { Say 'give servers: -Servers a,b  or -ServerFile list.txt  or -FromAD   (the collector itself is read by its own agent)' 'Yellow'; exit 1 }
foreach ($s in $Servers) { if ($s -notmatch '^[a-z0-9][a-z0-9.-]{0,252}$') { Say "not a host name: $s" 'Red'; exit 1 } }

# ---- the query: the same events the SIEM agent ships by default (agents/windows/sentra-agent.ps1), max 20 ids per Select
$sec = @(1100,1102,1104,4608,4616,4618,4624,4625,4634,4647,4648,4649,4657,4670,4672,4675,4688,4697,4698,4699,4700,4701,4702,
         4704,4705,4713,4716,4717,4718,4719,4720,4722,4723,4724,4725,4726,4727,4728,4729,4730,4731,4732,4733,4734,4735,4737,4738,
         4739,4740,4741,4742,4743,4744,4746,4747,4748,4749,4750,4751,4752,4753,4754,4755,4756,4757,4758,4759,4760,4761,4762,4763,4764,
         4765,4766,4767,4768,4769,4770,4771,4772,4773,4774,4775,4776,4777,4778,4779,4780,4781,4782,4793,4794,4797,4798,4799,
         4817,4826,4865,4866,4867,4886,4887,4888,4890,4891,4898,4899,4900,4904,4905,4906,4907,4908,4912,4946,4947,4948,4950,4954,4956,4964,
         5024,5025,5027,5030,5033,5034,5035,5037,5038,5136,5137,5138,5139,5141,5376,5377,5378,5632,5633,
         6144,6145,6272,6273,6274,6275,6276,6277,6278,6279,6280,6281,6416,6419,6420,6421,6422,6423,6424)
$sys = @(1,12,13,41,104,1074,1076,6005,6006,6008,6009,6013,7000,7009,7022,7023,7024,7026,7030,7031,7032,7034,7040,7045,
         5719,5722,5723,5805,5807,5823,5824,5825,5826,5827,5828,5829,5830,5831,1116,1117,3033,3063,20001,24577,24579)
$sel = New-Object System.Collections.ArrayList
function Add-Sel($path, $ids) { for ($k = 0; $k -lt $ids.Count; $k += 20) { $chunk = $ids[$k..([Math]::Min($k + 19, $ids.Count - 1))]; [void]$sel.Add("<Select Path=`"$path`">*[System[(" + (($chunk | ForEach-Object { "EventID=$_" }) -join ' or ') + ")]]</Select>") } }
Add-Sel 'Security' $sec
Add-Sel 'System' $sys
[void]$sel.Add('<Select Path="Application">*[System[(Level=1 or Level=2)]]</Select>')
[void]$sel.Add('<Select Path="Microsoft-Windows-PowerShell/Operational">*[System[(EventID=4103 or EventID=4104)]]</Select>')
[void]$sel.Add('<Select Path="Microsoft-Windows-Sysmon/Operational">*</Select>')
[void]$sel.Add('<Select Path="Microsoft-Windows-Windows Defender/Operational">*[System[(EventID=1006 or EventID=1007 or EventID=1008 or EventID=1015 or EventID=1116 or EventID=1117 or EventID=1118 or EventID=1119 or EventID=5001 or EventID=5004 or EventID=5007 or EventID=5010 or EventID=5012)]]</Select>')
$query = "<QueryList><Query Id=`"0`">" + ($sel -join '') + "</Query></QueryList>"
$esc = [Security.SecurityElement]::Escape($query)
$sources = ($Servers | ForEach-Object { "<EventSource Enabled=`"true`"><Address>$_</Address></EventSource>" }) -join "`r`n      "
$xml = @"
<Subscription xmlns="http://schemas.microsoft.com/2006/03/windows/events/subscription">
  <SubscriptionId>$SubscriptionName</SubscriptionId>
  <SubscriptionType>CollectorInitiated</SubscriptionType>
  <Description>Sentra SIEM - pull Windows event logs from $($Servers.Count) server(s); shipped by the SIEM agent on the collector (ForwardedEvents)</Description>
  <Enabled>true</Enabled>
  <Uri>http://schemas.microsoft.com/wbem/wsman/1/windows/EventLog</Uri>
  <ConfigurationMode>MinLatency</ConfigurationMode>
  <Query>$esc</Query>
  <ReadExistingEvents>$(if ($IncludeHistory) { 'true' } else { 'false' })</ReadExistingEvents>
  <TransportName>HTTP</TransportName>
  <ContentFormat>RenderedText</ContentFormat>
  <Locale Language="en-US"/>
  <LogFile>ForwardedEvents</LogFile>
  <CredentialsType>Default</CredentialsType>
  <EventSources>
      $sources
  </EventSources>
</Subscription>
"@
if ($ExportXml) { [IO.File]::WriteAllText($ExportXml, $xml, (New-Object Text.UTF8Encoding($false))); Say "subscription XML written to $ExportXml ($($Servers.Count) servers, $($sel.Count) query parts)" 'Green'; exit 0 }

# ---- 1 + 2. collector service, log size, subscription (on the collector)
try { Show (OnCollector 'setup' $xml) } catch { Say "setting up the collector failed: $((($_.Exception.Message) -split "`n")[0])" 'Red'; exit 1 }
if ($script:failed) { exit 1 }
Say "   $($Servers.Count) servers in the subscription"

# ---- 3. the collector's read right on each server (from THIS machine: one WinRM hop to each server)
if ($GrantReaders) {
  $acct = "$env:USERDOMAIN\$($col.name)`$"
  Say "==> giving $acct read access to the event logs (Event Log Readers)" 'Cyan'
  $dcDone = $false
  foreach ($s in $Servers) {
    try {
      $r = Invoke-Command -ComputerName $s -ErrorAction Stop -ArgumentList $acct -ScriptBlock {
        param($a)
        $dc = (Get-CimInstance Win32_ComputerSystem).DomainRole -ge 4
        if ($dc) { return 'dc' }
        try { Add-LocalGroupMember -SID 'S-1-5-32-573' -Member $a -ErrorAction Stop; 'added' } catch { if ($_.Exception.Message -match 'already a member') { 'already' } else { 'error: ' + $_.Exception.Message } }
      }
      if ($r -eq 'dc') {
        if (-not $dcDone) {
          try {
            # the domain's builtin Event Log Readers group (well-known SID) + the collector's computer object, over ADSI
            $obj = Find-AD "(&(objectCategory=computer)(sAMAccountName=$($col.name)`$))" @('distinguishedname') | Select-Object -First 1
            if (-not $obj) { throw "computer object $($col.name) not found in AD" }
            $grp = [ADSI]'LDAP://<SID=S-1-5-32-573>'
            $grp.Add('LDAP://' + [string]$obj.Properties['distinguishedname'][0])
            Say "   domain controllers: added to the domain's Event Log Readers group" 'Green'
          }
          catch { if ($_.Exception.Message -match 'already') { Say '   domain controllers: already in Event Log Readers' } else { Say "   domain controllers: add $acct to the builtin 'Event Log Readers' group in AD Users and Computers ($($_.Exception.Message))" 'Yellow' } }
          $dcDone = $true
        }
      } else { Say ("   {0}: {1}" -f $s, $r) $(if ($r -like 'error*') { 'Yellow' } else { 'Gray' }) }
    } catch { Say "   ${s}: not reachable over WinRM ($((($_.Exception.Message) -split "`n")[0])) - enable WinRM there or set the group by GPO" 'Yellow' }
  }
}

# ---- 4. refresh the collector's tickets, and the SIEM agent there reads ForwardedEvents
try { Show (OnCollector 'finish') } catch { Say "finishing on the collector failed: $((($_.Exception.Message) -split "`n")[0])" 'Yellow' }
$st = if ($remote) { " -Collector $C" } else { '' }
Say ''
Say "Done. In 2-5 minutes check:  .\setup-wec-pull.ps1 -Status$st   (every server should read Active)" 'Green'
Say 'Then in the portal: Log Sources > win-servers-trial shows each server as its own host; Asset Discovery turns them to Receiving.'
