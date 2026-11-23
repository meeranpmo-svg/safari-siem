# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
<#
.SYNOPSIS
  Sentra SIEM - Windows event forwarder (SentraAgent).

.DESCRIPTION
  Reads Windows event log channels, filters by a per-channel allow list, converts each event to JSON and ships
  NDJSON batches (gzip) over HTTPS to  https://<collector>/ingest/<src_id>  with header X-Sentra-Token.

  - PowerShell 5.1 compatible, no external modules (uses .NET System.Diagnostics.Eventing.Reader).
  - Per-channel bookmarks (last EventRecordID) in <DataDir>\bookmarks.json; a bookmark only advances after the
    events it covers were accepted by the collector (HTTP 2xx) or written to the local disk queue.
  - Local disk queue (<DataDir>\queue, bounded - default 200 MB) while the collector is unreachable; replayed
    oldest-first. When the queue is full the agent stops reading (policy "pause"): events stay in the Windows
    event log, nothing is dropped unless the event log itself wraps. Policy "drop-oldest" is available.
  - TLS 1.2+ only, certificate validation always ON; optional pinned certificate thumbprint (SHA-1 or SHA-256).
  - Retry with back-off (in-run retries + persisted back-off between runs).
  - Heartbeat event every HeartbeatMinutes (default 5).
  - Baseline-hardening snapshot every HardeningHours (default 24): READ-ONLY security settings (secedit export of the
    security policy, auditpol, a fixed list of registry values, services, firewall profiles, BitLocker, Defender) for
    the platform's CIS / SAMA baseline scan; on IIS and Hyper-V hosts their settings too (1.3); on a domain controller
    the domain's security settings and on an Exchange server the organisation's (1.4); the certificates in the machine
    stores (My, WebHosting, Remote Desktop) and, on an AD CS certification authority, the machine certificates it issued
    that are still valid or expired in the last 60 days (1.6) - dates, names, key and template only, never a private key.
    Nothing is changed.
  - File-share personal-data scan every FileScanHours (default 168) - OFF until FileScanPaths lists folders or 'auto'
    (every non-administrative SMB share on this server) (1.5). Runs as its own low-priority process (-FileScan) so event
    forwarding never waits; files are opened read-only; matches are COUNTED here (national ID, Iqama, mobile, e-mail,
    IBAN, card, health terms - the same rules and thresholds as the SIEM's pii/classify.js) and only counts per file,
    file names and folders, and whether Everyone / Authenticated Users / Domain Users can read the file leave the server.
  - Runs as SYSTEM from a scheduled task every minute (single pass, guarded by a global mutex), or -Loop.

  Event JSON:
    {Channel, EventID, TimeCreated (ISO-8601 UTC), Computer, RecordId, Level, ProviderName,
     EventData:{name:value,...}, Message (first 2 KB)}

.PARAMETER DryRun
  Read the last -Count events of -Channel (no bookmarks, no allow list, nothing written, nothing sent) and print
  the JSON lines to stdout. A summary (NDJSON / gzip sizes) goes to the host. Needs no config and no token.

.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File sentra-agent.ps1 -DryRun -Channel System -Count 5
.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File sentra-agent.ps1 -PrintDefaultConfig
.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File sentra-agent.ps1            # one pass (what the scheduled task runs)
#>
[CmdletBinding()]
param(
  [string]$DataDir = (Join-Path $env:ProgramData 'SentraAgent'),
  [string]$ConfigPath = '',
  [switch]$DryRun,
  [string]$Channel = 'System',
  [int]$Count = 5,
  [switch]$PrintDefaultConfig,
  [switch]$Loop,
  [switch]$FileScan,
  [int]$LoopSeconds = 30
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$AgentVersion = '1.7.0'

# ----------------------------------------------------------------------------------------------------------------
# Defaults (single source of truth; install-agent.ps1 writes these into config.json via -PrintDefaultConfig)
# ----------------------------------------------------------------------------------------------------------------
function Get-DefaultConfig {
  [ordered]@{
    CollectorUrl             = 'https://siem.example.local'   # https only; path /ingest/<SourceId> is appended
    SourceId                 = 'win-servers'                  # must exist in the engine (token issued for it)
    TokenFile                = ''                             # default <DataDir>\token.txt
    PinnedThumbprint         = ''                             # optional: SHA-1 (40 hex) or SHA-256 (64 hex) of the collector cert
    Proxy                    = ''                             # optional http://proxy:port ; empty = direct connection
    BatchMaxEvents           = 2000
    BatchMaxBytes            = 1048576                        # uncompressed NDJSON bytes per POST
    MaxEventsPerChannelRun   = 20000                          # bound one pass; the rest is read next pass
    MaxFieldChars            = 32768                          # cap per EventData value (e.g. 4104 script blocks)
    MessageMaxBytes          = 2048
    QueueMaxMB               = 200
    QueueFullPolicy          = 'pause'                        # pause | drop-oldest
    HeartbeatMinutes         = 5
    HardeningHours           = 24                             # baseline-hardening snapshot (read-only settings) every N hours; 0 = off
    FileScanPaths            = @()                            # file-share personal-data scan: folders (D:\Shares) or 'auto' (every SMB share); empty = off
    FileScanHours            = 168                            # how often the file-share scan runs
    FileScanMaxFiles         = 50000                          # files looked at per scan (names); the rest next time
    FileScanMaxMB            = 5                              # larger files are classified by name only
    FileScanMinutes          = 60                             # time budget of one scan
    FirstRunLookbackMinutes  = 60                             # on first start of a channel, how far back to read
    HttpTimeoutSeconds       = 30
    RetriesPerRun            = 3
    MaxBackoffMinutes        = 15
    LogMaxMB                 = 5
    SkipOwnScriptBlocks      = $true                          # drop 4104 events whose Path is this agent script (else it logs itself every run)
    Channels = @(
      [ordered]@{ Name = 'Security'; Enabled = $true; IncludeMessage = $true; Levels = @(); ExcludeEventIds = @();
        EventIds = @(1100,1102,1104,1108,
                     4608,4610,4611,4614,4616,4618,4621,4622,
                     4624,4625,4647,4648,4649,4657,4670,4672,4675,
                     4688,4692,4693,4694,4695,4697,4698,4699,4700,4701,4702,
                     4704,4705,4706,4707,4713,4714,4715,4716,4717,4718,4719,
                     4720,4722,4723,4724,4725,4726,4727,4728,4729,4730,4731,4732,4733,4734,4735,4737,4738,
                     4739,4740,4741,4742,4743,4744,4745,4746,4747,4748,4749,4750,4751,4752,4753,
                     4754,4755,4756,4757,4758,4759,4760,4761,4762,4763,4764,4765,4766,4767,
                     4768,4769,4770,4771,4772,4773,4774,4775,4776,4777,4778,4779,4780,4781,4782,4793,4794,4797,4798,4799,
                     4817,4826,4865,4866,4867,4886,4887,4888,4890,4891,4898,4899,4900,
                     4904,4905,4906,4907,4908,4912,4946,4947,4948,4950,4954,4956,4964,
                     5024,5025,5027,5030,5033,5034,5035,5037,5038,
                     5136,5137,5138,5139,5141,5376,5377,5378,5632,5633,
                     6144,6145,6272,6273,6274,6275,6276,6277,6278,6279,6280,6281,6400,6401,6402,6403,6404,6405,6406,6407,6408,6409,6410,6416,6419,6420,6421,6422,6423,6424) }
      [ordered]@{ Name = 'System'; Enabled = $true; IncludeMessage = $true; Levels = @(); ExcludeEventIds = @();
        EventIds = @(1,12,13,41,104,1074,1076,6005,6006,6008,6009,6013,
                     7000,7009,7022,7023,7024,7026,7030,7031,7032,7034,7040,7045,
                     5719,5722,5723,5805,5807,5823,5824,5825,5826,5827,5828,5829,5830,5831,
                     1116,1117,3033,3063,20001,24577,24579) }
      [ordered]@{ Name = 'Application'; Enabled = $true; IncludeMessage = $true; Levels = @(1,2); ExcludeEventIds = @();
        EventIds = @() }                                      # errors only (Critical=1, Error=2), all event ids
      [ordered]@{ Name = 'Microsoft-Windows-Sysmon/Operational'; Enabled = $true; IncludeMessage = $false; Levels = @(); ExcludeEventIds = @();
        EventIds = @() }                                      # all - filtering is done by the Sysmon config
      [ordered]@{ Name = 'Microsoft-Windows-PowerShell/Operational'; Enabled = $true; IncludeMessage = $false; Levels = @(); ExcludeEventIds = @();
        EventIds = @(4104) }
      [ordered]@{ Name = 'MSExchange Management'; Enabled = $true; IncludeMessage = $true; Levels = @(); ExcludeEventIds = @();
        EventIds = @(1,6) }                                   # Exchange on-prem admin audit (1 = cmdlet succeeded, 6 = failed); skipped where the channel does not exist
      [ordered]@{ Name = 'Microsoft-Windows-Windows Defender/Operational'; Enabled = $true; IncludeMessage = $true; Levels = @(); ExcludeEventIds = @();
        EventIds = @(1005,1006,1007,1008,1009,1010,1011,1012,1013,1015,1116,1117,1118,1119,1120,1121,1122,1125,1126,
                     2001,2003,2004,2006,3002,3007,5001,5004,5007,5008,5009,5010,5011,5012,5013,5100,5101) }
    )
  }
}

if ($PrintDefaultConfig) {
  Get-DefaultConfig | ConvertTo-Json -Depth 6
  return
}

# ----------------------------------------------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------------------------------------------
$Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
$script:LogFile = $null
$script:LogMaxBytes = 5MB

function Write-AgentLog {
  param([string]$Level, [string]$Text)
  $line = '{0} [{1}] {2}' -f ([DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')), $Level, $Text
  if ($script:LogFile) {
    try {
      if ((Test-Path -LiteralPath $script:LogFile) -and ((Get-Item -LiteralPath $script:LogFile).Length -gt $script:LogMaxBytes)) {
        for ($i = 2; $i -ge 1; $i--) {
          $src = "$($script:LogFile).$i"; $dst = "$($script:LogFile).$($i + 1)"
          if (Test-Path -LiteralPath $src) { Move-Item -LiteralPath $src -Destination $dst -Force }
        }
        Move-Item -LiteralPath $script:LogFile -Destination "$($script:LogFile).1" -Force
      }
      [System.IO.File]::AppendAllText($script:LogFile, $line + "`r`n", $Utf8NoBom)
    } catch { }
  }
  if ($DryRun -or $Level -eq 'ERROR') { [Console]::Error.WriteLine($line) }
}

function Limit-Utf8 {
  # Truncate a string so that its UTF-8 encoding is at most $MaxBytes bytes.
  param([string]$Text, [int]$MaxBytes)
  if ([string]::IsNullOrEmpty($Text)) { return '' }
  if ($Text.Length -gt $MaxBytes) { $Text = $Text.Substring(0, $MaxBytes) }
  while ($Utf8NoBom.GetByteCount($Text) -gt $MaxBytes) {
    $cut = [Math]::Max(1, [int](($Utf8NoBom.GetByteCount($Text) - $MaxBytes) / 3))
    $Text = $Text.Substring(0, $Text.Length - $cut)
  }
  # do not end on a lone high surrogate
  if ($Text.Length -gt 0 -and [char]::IsHighSurrogate($Text[$Text.Length - 1])) { $Text = $Text.Substring(0, $Text.Length - 1) }
  return $Text
}

function Write-FileAtomic {
  param([string]$Path, [string]$Content)
  $tmp = "$Path.tmp"
  [System.IO.File]::WriteAllText($tmp, $Content, $Utf8NoBom)
  if (Test-Path -LiteralPath $Path) { [System.IO.File]::Replace($tmp, $Path, [NullString]::Value) } else { [System.IO.File]::Move($tmp, $Path) }
}

function Read-JsonFile {
  param([string]$Path)
  if (-not (Test-Path -LiteralPath $Path)) { return $null }
  $txt = [System.IO.File]::ReadAllText($Path, $Utf8NoBom)
  if ([string]::IsNullOrWhiteSpace($txt)) { return $null }
  return ($txt | ConvertFrom-Json)
}

function Get-Prop {
  # Read a property from a PSCustomObject (from ConvertFrom-Json) with a default.
  param($Object, [string]$Name, $Default)
  if ($null -eq $Object) { return $Default }
  $p = $Object.PSObject.Properties[$Name]
  if ($null -eq $p -or $null -eq $p.Value) { return $Default }
  return $p.Value
}

function ConvertTo-UtcDate {
  # State timestamps are ISO-8601 strings; PowerShell 7's ConvertFrom-Json may already hand back a DateTime.
  param($Value)
  if ($null -eq $Value -or [string]::IsNullOrEmpty([string]$Value)) { return $null }
  if ($Value -is [DateTime]) { return $Value.ToUniversalTime() }
  return [DateTime]::Parse([string]$Value, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime()
}

function Get-InnerException {
  # .NET method calls surface as MethodInvocationException; walk the chain to the requested type.
  param([Exception]$Exception, [type]$Type)
  $e = $Exception
  while ($null -ne $e) { if ($Type.IsInstanceOfType($e)) { return $e }; $e = $e.InnerException }
  return $null
}

function ConvertTo-GzipBytes {
  param([byte[]]$Bytes)
  $ms = New-Object System.IO.MemoryStream
  $gz = New-Object System.IO.Compression.GZipStream($ms, [System.IO.Compression.CompressionMode]::Compress)
  $gz.Write($Bytes, 0, $Bytes.Length)
  $gz.Close()
  return ,$ms.ToArray()
}

# ----------------------------------------------------------------------------------------------------------------
# Event conversion
# ----------------------------------------------------------------------------------------------------------------
function Get-PerfSample {
  # CPU %, memory and fixed-disk usage via CIM (language-independent, no performance-counter names). Never throws.
  $o = [ordered]@{}
  try { $c = Get-CimInstance -ClassName Win32_PerfFormattedData_PerfOS_Processor -Filter "Name='_Total'" -ErrorAction Stop; $o.cpu_pct = [string][int]$c.PercentProcessorTime } catch { }
  try { $m = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $o.mem_total_mb = [string][math]::Round($m.TotalVisibleMemorySize / 1024); $o.mem_free_mb = [string][math]::Round($m.FreePhysicalMemory / 1024) } catch { }
  try { $d = @(Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction Stop | Where-Object { $_.Size -gt 0 })
        $o.disks = (($d | ForEach-Object { '{0}|{1}|{2}' -f $_.DeviceID, [math]::Round($_.Size / 1GB, 1), [math]::Round($_.FreeSpace / 1GB, 1) }) -join ';') } catch { }
  return $o
}

function Get-EventDataMap {
  param([System.Diagnostics.Eventing.Reader.EventRecord]$Record, [int]$MaxFieldChars)
  $map = [ordered]@{}
  try {
    [xml]$x = $Record.ToXml()
    $root = $x.DocumentElement
    $ed = $null; $ud = $null
    foreach ($n in $root.ChildNodes) {
      if ($n.LocalName -eq 'EventData') { $ed = $n }
      elseif ($n.LocalName -eq 'UserData') { $ud = $n }
    }
    if ($null -ne $ed) {
      $i = 0
      foreach ($d in $ed.ChildNodes) {
        if ($d.NodeType -ne [System.Xml.XmlNodeType]::Element) { continue }
        $name = $d.GetAttribute('Name')
        if ([string]::IsNullOrEmpty($name)) { $name = if ($d.LocalName -eq 'Data') { "Data$i" } else { $d.LocalName } }
        $val = $d.InnerText
        if ($null -ne $val -and $val.Length -gt $MaxFieldChars) { $val = $val.Substring(0, $MaxFieldChars) }
        if ($map.Contains($name)) { $name = "$name$i" }
        $map[$name] = $val
        $i++
      }
    }
    if ($null -ne $ud) {
      # UserData: <UserData><SomeElement xmlns=...><Field>value</Field>...</SomeElement></UserData> - flatten one level
      foreach ($top in $ud.ChildNodes) {
        if ($top.NodeType -ne [System.Xml.XmlNodeType]::Element) { continue }
        foreach ($f in $top.ChildNodes) {
          if ($f.NodeType -ne [System.Xml.XmlNodeType]::Element) { continue }
          $val = $f.InnerText
          if ($null -ne $val -and $val.Length -gt $MaxFieldChars) { $val = $val.Substring(0, $MaxFieldChars) }
          $map[$f.LocalName] = $val
        }
      }
    }
  } catch {
    $map['_agent_error'] = 'eventdata: ' + $_.Exception.Message
  }
  return $map
}

function ConvertTo-SentraEvent {
  param([System.Diagnostics.Eventing.Reader.EventRecord]$Record, [string]$ChannelName, [bool]$IncludeMessage, $Cfg)
  $msg = ''
  if ($IncludeMessage) {
    try { $msg = $Record.FormatDescription() } catch { $msg = '' }
    if ($null -eq $msg) { $msg = '' }
    $msg = Limit-Utf8 -Text $msg -MaxBytes $Cfg.MessageMaxBytes
  }
  $tc = ''
  # Nullable<DateTime> arrives unwrapped in PowerShell; the cast works for both shapes.
  if ($null -ne $Record.TimeCreated) { $tc = ([DateTime]$Record.TimeCreated).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ') }
  $lvl = 0
  if ($null -ne $Record.Level) { $lvl = [int]$Record.Level }
  return [ordered]@{
    Channel      = $ChannelName
    EventID      = [int]$Record.Id
    TimeCreated  = $tc
    Computer     = $Record.MachineName
    RecordId     = [long]$Record.RecordId
    Level        = $lvl
    ProviderName = $Record.ProviderName
    EventData    = (Get-EventDataMap -Record $Record -MaxFieldChars $Cfg.MaxFieldChars)
    Message      = $msg
  }
}

function ConvertTo-JsonLine {
  param($Object)
  # -Compress keeps one event per line (NDJSON). Newlines inside strings are escaped by ConvertTo-Json.
  return ($Object | ConvertTo-Json -Depth 5 -Compress)
}

# ----------------------------------------------------------------------------------------------------------------
# Event log reading
# ----------------------------------------------------------------------------------------------------------------
function New-EventReader {
  param([string]$ChannelName, [string]$XPath, [bool]$Reverse)
  $q = New-Object System.Diagnostics.Eventing.Reader.EventLogQuery($ChannelName, [System.Diagnostics.Eventing.Reader.PathType]::LogName, $XPath)
  $q.ReverseDirection = $Reverse
  return (New-Object System.Diagnostics.Eventing.Reader.EventLogReader($q))
}

function Get-NewestRecordId {
  param([string]$ChannelName)
  $r = New-EventReader -ChannelName $ChannelName -XPath '*' -Reverse $true
  try {
    $e = $r.ReadEvent()
    if ($null -eq $e) { return [long]0 }
    try { return [long]$e.RecordId } finally { $e.Dispose() }
  } finally { $r.Dispose() }
}

function Get-ChannelXPath {
  param($Ch, [long]$Bookmark, [int]$LookbackMinutes)
  $conds = New-Object System.Collections.Generic.List[string]
  if ($Bookmark -gt 0) { $conds.Add("EventRecordID > $Bookmark") }
  elseif ($LookbackMinutes -gt 0) { $conds.Add("TimeCreated[timediff(@SystemTime) <= $([long]$LookbackMinutes * 60000)]") }
  $levels = @(Get-Prop $Ch 'Levels' @())
  if ($levels.Count -gt 0) { $conds.Add('(' + (($levels | ForEach-Object { "Level=$([int]$_)" }) -join ' or ') + ')') }
  # Small allow lists go into the query (less data read); large ones are filtered client-side only, because the
  # event log query engine rejects very long XPath expressions.
  $ids = @(Get-Prop $Ch 'EventIds' @())
  if ($ids.Count -gt 0 -and $ids.Count -le 20) { $conds.Add('(' + (($ids | ForEach-Object { "EventID=$([int]$_)" }) -join ' or ') + ')') }
  if ($conds.Count -eq 0) { return '*' }
  return '*[System[' + ($conds -join ' and ') + ']]'
}

# ----------------------------------------------------------------------------------------------------------------
# Dry run: print the last N events of a channel, send nothing, write nothing
# ----------------------------------------------------------------------------------------------------------------
if ($DryRun) {
  $cfg = [pscustomobject](Get-DefaultConfig)
  $lines = New-Object System.Collections.Generic.List[string]
  try { $r = New-EventReader -ChannelName $Channel -XPath '*' -Reverse $true }
  catch {
    $inner = $_.Exception; while ($null -ne $inner.InnerException) { $inner = $inner.InnerException }
    [Console]::Error.WriteLine("# dry-run: cannot read channel '$Channel': $($inner.Message) (Security needs an elevated prompt; Sysmon must be installed)")
    exit 1
  }
  try {
    for ($i = 0; $i -lt $Count; $i++) {
      $e = $r.ReadEvent()
      if ($null -eq $e) { break }
      try { $lines.Add((ConvertTo-JsonLine (ConvertTo-SentraEvent -Record $e -ChannelName $Channel -IncludeMessage $true -Cfg $cfg))) }
      finally { $e.Dispose() }
    }
  } finally { $r.Dispose() }
  $lines.Reverse()   # oldest first, like the real pipeline
  foreach ($l in $lines) { Write-Output $l }
  $body = ($lines -join "`n") + "`n"
  $raw = $Utf8NoBom.GetBytes($body)
  $gz = ConvertTo-GzipBytes -Bytes $raw
  $summary = "# dry-run: channel '{0}', {1} event(s), NDJSON {2} bytes, gzip {3} bytes - nothing was sent" -f $Channel, $lines.Count, $raw.Length, $gz.Length
  [Console]::Error.WriteLine($summary)
  return
}

# ----------------------------------------------------------------------------------------------------------------
# Real run: configuration, state, transport
# ----------------------------------------------------------------------------------------------------------------
if (-not $ConfigPath) { $ConfigPath = Join-Path $DataDir 'config.json' }
$QueueDir     = Join-Path $DataDir 'queue'
$RejectDir    = Join-Path $QueueDir 'rejected'
$LogDir       = Join-Path $DataDir 'logs'
$BookmarkPath = Join-Path $DataDir 'bookmarks.json'
$StatePath    = Join-Path $DataDir 'state.json'
foreach ($d in @($DataDir, $QueueDir, $RejectDir, $LogDir)) { if (-not (Test-Path -LiteralPath $d)) { [void](New-Item -ItemType Directory -Path $d -Force) } }
$script:LogFile = Join-Path $LogDir 'agent.log'

function Get-EffectiveConfig {
  $defaults = Get-DefaultConfig
  $file = Read-JsonFile -Path $ConfigPath
  if ($null -eq $file) { throw "config not found or empty: $ConfigPath (run install-agent.ps1)" }
  $cfg = [ordered]@{}
  foreach ($k in $defaults.Keys) { $cfg[$k] = Get-Prop $file $k $defaults[$k] }
  if ([string]::IsNullOrWhiteSpace($cfg.TokenFile)) { $cfg.TokenFile = Join-Path $DataDir 'token.txt' }
  $u = [string]$cfg.CollectorUrl
  if (-not $u.StartsWith('https://', [StringComparison]::OrdinalIgnoreCase)) { throw 'CollectorUrl must start with https://' }
  if ($cfg.SourceId -notmatch '^[A-Za-z0-9._-]{1,64}$') { throw 'SourceId must match [A-Za-z0-9._-]{1,64}' }
  $tp = ([string]$cfg.PinnedThumbprint) -replace '[\s:]', ''
  if ($tp -and $tp -notmatch '^([0-9A-Fa-f]{40}|[0-9A-Fa-f]{64})$') { throw 'PinnedThumbprint must be 40 (SHA-1) or 64 (SHA-256) hex characters' }
  $cfg.PinnedThumbprint = $tp.ToUpperInvariant()
  if (@('pause', 'drop-oldest') -notcontains $cfg.QueueFullPolicy) { $cfg.QueueFullPolicy = 'pause' }
  $cfg.BatchMaxEvents = [Math]::Min([Math]::Max([int]$cfg.BatchMaxEvents, 1), 2000)
  $cfg.BatchMaxBytes  = [Math]::Min([Math]::Max([int]$cfg.BatchMaxBytes, 65536), 1048576)
  $cfg.MessageMaxBytes = [Math]::Min([Math]::Max([int]$cfg.MessageMaxBytes, 0), 2048)
  $cfg.IngestUrl = $u.TrimEnd('/') + '/ingest/' + [Uri]::EscapeDataString($cfg.SourceId)
  return [pscustomobject]$cfg
}

function Initialize-Transport {
  param($Cfg)
  # TLS 1.2+ only. TLS 1.3 is added where the OS supports it (Windows Server 2022 / Windows 11, build >= 20348).
  $proto = [Net.SecurityProtocolType]::Tls12
  $build = [Environment]::OSVersion.Version.Build
  if (([enum]::GetNames([Net.SecurityProtocolType]) -contains 'Tls13') -and $build -ge 20348) { $proto = $proto -bor [Net.SecurityProtocolType]'Tls13' }
  [Net.ServicePointManager]::SecurityProtocol = $proto
  [Net.ServicePointManager]::Expect100Continue = $false
  if ($Cfg.PinnedThumbprint) {
    if (-not ('SentraAgent.CertPin' -as [type])) {
      Add-Type -TypeDefinition @'
using System;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
namespace SentraAgent {
  public static class CertPin {
    public static string Expected = "";
    public static string LastSeen = "";
    // Normal chain + name validation must pass AND the leaf certificate must match the pinned thumbprint.
    public static bool Validate(object sender, X509Certificate cert, X509Chain chain, SslPolicyErrors errors) {
      if (errors != SslPolicyErrors.None || cert == null) { LastSeen = "policy:" + errors.ToString(); return false; }
      string sha1 = cert.GetCertHashString().ToUpperInvariant();
      string sha256;
      using (SHA256 h = SHA256.Create()) { sha256 = BitConverter.ToString(h.ComputeHash(cert.GetRawCertData())).Replace("-", ""); }
      LastSeen = sha256;
      return String.Equals(Expected, sha1, StringComparison.OrdinalIgnoreCase) || String.Equals(Expected, sha256, StringComparison.OrdinalIgnoreCase);
    }
    public static RemoteCertificateValidationCallback Callback() { return new RemoteCertificateValidationCallback(Validate); }
  }
}
'@
    }
    [SentraAgent.CertPin]::Expected = $Cfg.PinnedThumbprint
  }
}


function Send-Batch {
  # Returns: 'ok' | 'retry' (network / 5xx / 429 / 401 / 403 - keep and back off) | 'reject' (other 4xx - poison batch)
  param([byte[]]$GzBody, [string]$BatchId)
  $cfg = $script:Cfg
  $script:Attempted = $true
  try {
    $req = [Net.HttpWebRequest]::Create($cfg.IngestUrl)
    $req.Method = 'POST'
    $req.ContentType = 'application/x-ndjson'
    $req.UserAgent = "SentraAgent/$AgentVersion"
    $req.Timeout = [int]$cfg.HttpTimeoutSeconds * 1000
    $req.ReadWriteTimeout = [int]$cfg.HttpTimeoutSeconds * 1000
    $req.KeepAlive = $true
    $req.AllowAutoRedirect = $false
    $req.Headers.Add('Content-Encoding', 'gzip')
    $req.Headers.Add('X-Sentra-Token', $script:Token)
    $req.Headers.Add('X-Sentra-Batch-Id', $BatchId)
    $req.Headers.Add('X-Sentra-Agent', "$AgentVersion;$env:COMPUTERNAME")
    if ($cfg.Proxy) { $req.Proxy = New-Object System.Net.WebProxy([string]$cfg.Proxy, $true) } else { $req.Proxy = $null }
    if ($cfg.PinnedThumbprint) { $req.ServerCertificateValidationCallback = [SentraAgent.CertPin]::Callback() }
    $req.ContentLength = $GzBody.Length
    $s = $req.GetRequestStream()
    try { $s.Write($GzBody, 0, $GzBody.Length) } finally { $s.Close() }
    $resp = $req.GetResponse()
    $code = [int]$resp.StatusCode
    $resp.Close()
    if ($code -ge 200 -and $code -lt 300) { return 'ok' }
    Write-AgentLog 'WARN' "collector answered HTTP $code"
    return 'retry'
  } catch {
    $we = Get-InnerException -Exception $_.Exception -Type ([System.Net.WebException])
    if ($null -eq $we) { Write-AgentLog 'WARN' "send failed: $($_.Exception.Message)"; return 'retry' }
    if ($null -ne $we.Response) {
      $code = [int]$we.Response.StatusCode
      $we.Response.Close()
      if ($code -eq 401 -or $code -eq 403) { Write-AgentLog 'ERROR' "collector rejected the token for source '$($cfg.SourceId)' (HTTP $code) - data kept in the queue"; return 'retry' }
      if ($code -eq 408 -or $code -eq 429 -or $code -ge 500 -or ($code -ge 300 -and $code -lt 400)) { Write-AgentLog 'WARN' "collector busy/unavailable (HTTP $code)"; return 'retry' }
      Write-AgentLog 'ERROR' "collector rejected batch $BatchId (HTTP $code) - moved to queue\rejected"
      return 'reject'
    }
    $detail = $we.Status.ToString() + ': ' + $we.Message
    if ($cfg.PinnedThumbprint -and $we.Status -eq [System.Net.WebExceptionStatus]::TrustFailure) { $detail += " (pinned=$($cfg.PinnedThumbprint) seen=$([SentraAgent.CertPin]::LastSeen))" }
    Write-AgentLog 'WARN' "collector unreachable: $detail"
    return 'retry'
  }
}

function Send-WithRetry {
  param([byte[]]$GzBody, [string]$BatchId)
  $delay = 2
  $tries = [Math]::Max(1, [int]$script:Cfg.RetriesPerRun)
  for ($a = 1; $a -le $tries; $a++) {
    $r = Send-Batch -GzBody $GzBody -BatchId $BatchId
    if ($r -ne 'retry') { return $r }
    if ($a -lt $tries) { Start-Sleep -Seconds $delay; $delay = [Math]::Min($delay * 2, 30) }
  }
  return 'retry'
}

# --- disk queue -------------------------------------------------------------------------------------------------
function Get-QueueFiles { return @(Get-ChildItem -LiteralPath $QueueDir -Filter '*.ndjson.gz' -File -ErrorAction SilentlyContinue | Sort-Object Name) }
function Get-QueueBytes {
  $sum = [long]0
  foreach ($f in @(Get-ChildItem -LiteralPath $QueueDir -Recurse -File -ErrorAction SilentlyContinue)) { $sum += $f.Length }
  return $sum
}
function New-QueueName { param([string]$BatchId) return ('{0:D19}-{1}.ndjson.gz' -f [DateTime]::UtcNow.Ticks, $BatchId) }

function Add-ToQueue {
  # Returns $true when the batch is durably on disk.
  param([byte[]]$GzBody, [string]$BatchId)
  $cfg = $script:Cfg
  $max = [long]$cfg.QueueMaxMB * 1MB
  $used = Get-QueueBytes
  if ($used + $GzBody.Length -gt $max) {
    if ($cfg.QueueFullPolicy -eq 'drop-oldest') {
      foreach ($f in (Get-QueueFiles)) {
        if ($used + $GzBody.Length -le $max) { break }
        $used -= $f.Length
        Remove-Item -LiteralPath $f.FullName -Force
        $script:State.dropped_batches = [long]$script:State.dropped_batches + 1
        Write-AgentLog 'WARN' "queue full - dropped oldest batch $($f.Name)"
      }
    }
    if ($used + $GzBody.Length -gt $max) {
      $script:QueueFull = $true
      Write-AgentLog 'WARN' 'queue full - pausing collection (events remain in the Windows event log)'
      return $false
    }
  }
  $path = Join-Path $QueueDir (New-QueueName -BatchId $BatchId)
  try {
    [System.IO.File]::WriteAllBytes("$path.part", $GzBody)
    [System.IO.File]::Move("$path.part", $path)
    return $true
  } catch {
    Write-AgentLog 'ERROR' "cannot write queue file: $($_.Exception.Message)"
    return $false
  }
}

function Clear-Queue {
  # Replay queued batches oldest-first. Returns $true when the queue is empty afterwards.
  foreach ($f in (Get-QueueFiles)) {
    $bytes = [System.IO.File]::ReadAllBytes($f.FullName)
    $batchId = ($f.Name -replace '\.ndjson\.gz$', '') -replace '^\d+-', ''
    $r = Send-WithRetry -GzBody $bytes -BatchId $batchId
    if ($r -eq 'ok') { Remove-Item -LiteralPath $f.FullName -Force; $script:State.sent_batches = [long]$script:State.sent_batches + 1; continue }
    if ($r -eq 'reject') { Move-Item -LiteralPath $f.FullName -Destination (Join-Path $RejectDir $f.Name) -Force; continue }
    return $false
  }
  return $true
}

function Remove-OldRejects {
  $limit = [DateTime]::UtcNow.AddDays(-7)
  foreach ($f in @(Get-ChildItem -LiteralPath $RejectDir -File -ErrorAction SilentlyContinue)) {
    if ($f.LastWriteTimeUtc -lt $limit) { Remove-Item -LiteralPath $f.FullName -Force -ErrorAction SilentlyContinue }
  }
}

# --- state ------------------------------------------------------------------------------------------------------
function Get-State {
  $s = Read-JsonFile -Path $StatePath
  $h = [ordered]@{ last_heartbeat = ''; last_success = ''; next_attempt = ''; backoff_minutes = 0
                   sent_batches = 0; sent_events = 0; dropped_batches = 0; queue_full_since = ''; last_hardening = ''; last_filescan = '' }
  foreach ($k in @($h.Keys)) { $h[$k] = Get-Prop $s $k $h[$k] }
  foreach ($k in @('last_heartbeat', 'last_success', 'next_attempt', 'queue_full_since', 'last_hardening', 'last_filescan')) {
    $d = ConvertTo-UtcDate $h[$k]
    if ($null -eq $d) { $h[$k] = '' } else { $h[$k] = $d.ToString('o') }
  }
  return $h
}
function Save-State { Write-FileAtomic -Path $StatePath -Content ($script:State | ConvertTo-Json -Depth 3) }

function Get-Bookmarks {
  $b = Read-JsonFile -Path $BookmarkPath
  $h = @{}
  if ($null -ne $b) { foreach ($p in $b.PSObject.Properties) { $h[$p.Name] = [long]$p.Value } }
  return $h
}
function Save-Bookmarks { Write-FileAtomic -Path $BookmarkPath -Content (([pscustomobject]$script:Bm) | ConvertTo-Json) }

# --- batch ------------------------------------------------------------------------------------------------------
function Invoke-Flush {
  # Make the current batch durable (send; else queue), then commit bookmarks up to everything read so far.
  # Returns $false when the batch could be neither sent nor queued (bookmarks are then NOT advanced).
  if ($script:Batch.Count -gt 0) {
    $bodyBytes = $Utf8NoBom.GetBytes(($script:Batch -join "`n") + "`n")
    $gz = ConvertTo-GzipBytes -Bytes $bodyBytes
    $id = [guid]::NewGuid().ToString('N')
    $ok = $false
    if ($script:CollectorUp) {
      $r = Send-WithRetry -GzBody $gz -BatchId $id
      if ($r -eq 'ok') {
        $ok = $true
        $script:State.sent_batches = [long]$script:State.sent_batches + 1
        $script:State.sent_events = [long]$script:State.sent_events + $script:Batch.Count
      } elseif ($r -eq 'reject') {
        [System.IO.File]::WriteAllBytes((Join-Path $RejectDir (New-QueueName -BatchId $id)), $gz); $ok = $true
      } else { $script:CollectorUp = $false }
    }
    if (-not $ok) { $ok = Add-ToQueue -GzBody $gz -BatchId $id }
    if (-not $ok) { return $false }
    $script:PassEvents += $script:Batch.Count
    $script:Batch.Clear()
    $script:BatchBytes = 0
  }
  foreach ($k in @($script:LastRead.Keys)) { $script:Bm[$k] = $script:LastRead[$k] }
  Save-Bookmarks
  return $true
}

function Add-BatchLine {
  param([string]$Line)
  $n = $Utf8NoBom.GetByteCount($Line) + 1
  if ($script:Batch.Count -gt 0 -and (($script:BatchBytes + $n) -gt $script:Cfg.BatchMaxBytes -or $script:Batch.Count -ge $script:Cfg.BatchMaxEvents)) {
    if (-not (Invoke-Flush)) { return $false }
  }
  $script:Batch.Add($Line)
  $script:BatchBytes += $n
  return $true
}

function Get-RegValue {
  param([string]$Path, [string]$Name)
  try { $v = Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop; return $v.$Name } catch { return $null }
}

function Get-HardeningSnapshot {
  # READ-ONLY. Every section is read on its own; one that cannot be read is null (the scan says "not checked", never
  # "pass"). secedit writes its export to a temporary file in the data directory, deleted straight after.
  $o = [ordered]@{ collected_at = [DateTime]::UtcNow.ToString('o') }
  try { $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        $o.os = [ordered]@{ caption = [string]$os.Caption; version = [string]$os.Version; build = [string]$os.BuildNumber; product_type = [int]$os.ProductType
                            domain_role = [int]$cs.DomainRole; part_of_domain = [bool]$cs.PartOfDomain; last_boot = ([DateTime]$os.LastBootUpTime).ToUniversalTime().ToString('o') } } catch { $o.os = $null }
  try { $hf = @(Get-CimInstance -ClassName Win32_QuickFixEngineering -ErrorAction Stop | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending)
        $o.last_hotfix = if ($hf.Count) { ([DateTime]$hf[0].InstalledOn).ToString('yyyy-MM-dd') } else { $null } } catch { $o.last_hotfix = $null }
  $tmp = Join-Path $DataDir ('secpol-' + [guid]::NewGuid().ToString('N') + '.inf')
  try {
    $null = & secedit.exe /export /cfg $tmp /areas SECURITYPOLICY USER_RIGHTS /quiet
    $sec = [ordered]@{}; $section = ''
    foreach ($l in (Get-Content -LiteralPath $tmp -ErrorAction Stop)) {
      if ($l -match '^\[(.+)\]$') { $section = $Matches[1]; continue }
      if ($section -notin @('System Access', 'Event Audit', 'Privilege Rights') -and $l -notmatch '^MACHINE\\') { continue }
      if ($l -match '^\s*([^=]+?)\s*=\s*(.*)$') {
        $k = $Matches[1]; $v = $Matches[2].Trim().Trim('"')
        if ($section -eq 'System Access' -and $k -in @('NewAdministratorName', 'NewGuestName')) { $sec[$k] = $v; continue }
        $sec[$k] = $v
      }
    }
    $o.secpol = $sec
  } catch { $o.secpol = $null } finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
  try { $ap = [ordered]@{}
        foreach ($r in (& auditpol.exe /get /category:* /r | ConvertFrom-Csv)) { if ($r.Subcategory) { $ap[[string]$r.'Subcategory GUID'] = [string]$r.'Inclusion Setting' } }
        $o.auditpol = $ap } catch { $o.auditpol = $null }
  $lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; $pol = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows'
  $sys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; $sch = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'
  $o.reg = [ordered]@{
    LmCompatibilityLevel = Get-RegValue $lsa 'LmCompatibilityLevel'; NoLMHash = Get-RegValue $lsa 'NoLMHash'
    RestrictAnonymous = Get-RegValue $lsa 'RestrictAnonymous'; RestrictAnonymousSAM = Get-RegValue $lsa 'RestrictAnonymousSAM'
    RunAsPPL = Get-RegValue $lsa 'RunAsPPL'; LsaCfgFlags = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' 'LsaCfgFlags'
    WDigestUseLogonCredential = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential'
    EnableLUA = Get-RegValue $sys 'EnableLUA'; ConsentPromptBehaviorAdmin = Get-RegValue $sys 'ConsentPromptBehaviorAdmin'
    InactivityTimeoutSecs = Get-RegValue $sys 'InactivityTimeoutSecs'; LegalNoticeText = [bool](Get-RegValue $sys 'LegalNoticeText')
    SmbServerSigning = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'RequireSecuritySignature'
    SmbClientSigning = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' 'RequireSecuritySignature'
    SMB1Server = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'SMB1'
    RdpDeny = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections'
    RdpNla = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication'
    RdpMinEncryption = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'MinEncryptionLevel'
    LlmnrOff = Get-RegValue "$pol NT\DNSClient" 'EnableMulticast'
    NoAutorun = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun'
    ScriptBlockLogging = Get-RegValue "$pol\PowerShell\ScriptBlockLogging" 'EnableScriptBlockLogging'
    Tls10Server = Get-RegValue "$sch\TLS 1.0\Server" 'Enabled'; Tls11Server = Get-RegValue "$sch\TLS 1.1\Server" 'Enabled'
    Ssl3Server = Get-RegValue "$sch\SSL 3.0\Server" 'Enabled'
    SecurityLogMaxKB = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security' 'MaxSize'
    WinRMAllowUnencrypted = Get-RegValue "$pol\WinRM\Service" 'AllowUnencryptedTraffic'
  }
  try { $sm = Get-SmbServerConfiguration -ErrorAction Stop; $o.smb = [ordered]@{ smb1 = [bool]$sm.EnableSMB1Protocol; signing_required = [bool]$sm.RequireSecuritySignature; encrypt = [bool]$sm.EncryptData } } catch { $o.smb = $null }
  try { $o.firewall = @(Get-NetFirewallProfile -ErrorAction Stop | ForEach-Object { [ordered]@{ name = [string]$_.Name; enabled = [bool]$_.Enabled; inbound = [string]$_.DefaultInboundAction; log_blocked = [string]$_.LogBlocked } }) } catch { $o.firewall = $null }
  try { $o.bitlocker = @(Get-CimInstance -Namespace 'root\cimv2\Security\MicrosoftVolumeEncryption' -ClassName Win32_EncryptableVolume -ErrorAction Stop |
          Where-Object { $_.DriveLetter } | ForEach-Object { [ordered]@{ drive = [string]$_.DriveLetter; protection = [int]$_.ProtectionStatus } }) } catch { $o.bitlocker = $null }
  try { $mp = Get-MpComputerStatus -ErrorAction Stop
        $o.defender = [ordered]@{ realtime = [bool]$mp.RealTimeProtectionEnabled; antivirus = [bool]$mp.AntivirusEnabled; signature_age_days = [int]$mp.AntivirusSignatureAge; tamper = [bool]$mp.IsTamperProtected } } catch { $o.defender = $null }
  $o.services = [ordered]@{}
  foreach ($n in @('Spooler', 'RemoteRegistry', 'TlntSvr', 'SNMP', 'FTPSVC', 'W3SVC', 'WinRM', 'SSDPSRV', 'upnphost', 'XblGameSave', 'TermService', 'EventLog', 'MpsSvc', 'WinDefend', 'W32Time')) {
    try { $svc = Get-CimInstance -ClassName Win32_Service -Filter "Name='$n'" -ErrorAction Stop
          if ($svc) { $o.services[$n] = [ordered]@{ start = [string]$svc.StartMode; state = [string]$svc.State } } } catch { }
  }
  try { $o.local_admins = @(Get-CimInstance -ClassName Win32_Group -Filter "LocalAccount=True AND SID='S-1-5-32-544'" -ErrorAction Stop | Get-CimAssociatedInstance -ResultClassName Win32_UserAccount -ErrorAction Stop).Count } catch { $o.local_admins = $null }
  try { $g = Get-CimInstance -ClassName Win32_UserAccount -Filter "LocalAccount=True AND SID LIKE '%-501'" -ErrorAction Stop; $o.guest_enabled = if ($g) { -not [bool]$g.Disabled } else { $null } } catch { $o.guest_enabled = $null }
  # IIS (only where the Web Server role is installed): sites, bindings, directory browsing, detailed errors, logging, the
  # Server / X-Powered-By headers, app pool identities, WebDAV - read with Get-WebConfigurationProperty, nothing set
  $o.iis = $null
  if (Get-Module -ListAvailable -Name WebAdministration -ErrorAction SilentlyContinue) {
    try {
      Import-Module WebAdministration -ErrorAction Stop
      $iis = [ordered]@{ sites = @(); pools = @() }
      foreach ($site in @(Get-Website -ErrorAction Stop | Select-Object -First 50)) {
        $p = 'IIS:\Sites\' + $site.Name
        $db = $null; $log = $null
        try { $db = [bool](Get-WebConfigurationProperty -PSPath $p -Filter 'system.webServer/directoryBrowse' -Name enabled -ErrorAction Stop).Value } catch { }
        try { $log = [bool]$site.logFile.enabled } catch { }
        $iis.sites += [ordered]@{ name = [string]$site.Name; state = [string]$site.State; protocols = @($site.Bindings.Collection | ForEach-Object { [string]$_.protocol } | Select-Object -Unique); directory_browse = $db; logging = $log }
      }
      try { $iis.error_mode = [string](Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.webServer/httpErrors' -Name errorMode -ErrorAction Stop) } catch { $iis.error_mode = $null }
      try { $iis.remove_server_header = [bool](Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.webServer/security/requestFiltering' -Name removeServerHeader -ErrorAction Stop).Value } catch { $iis.remove_server_header = $null }
      try { $iis.powered_by = [bool](@(Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.webServer/httpProtocol/customHeaders/add' -Name name -ErrorAction Stop | Where-Object { $_.Value -eq 'X-Powered-By' }).Count) } catch { $iis.powered_by = $null }
      try { $iis.webdav = [bool](Get-WebGlobalModule -Name WebDAVModule -ErrorAction SilentlyContinue) } catch { $iis.webdav = $null }
      try { $iis.pools = @(Get-ChildItem IIS:\AppPools -ErrorAction Stop | Select-Object -First 100 | ForEach-Object { [ordered]@{ name = [string]$_.Name; identity = [string]$_.processModel.identityType } }) } catch { }
      $o.iis = $iis
    } catch { $o.iis = [ordered]@{ error = [string]$_.Exception.Message } }
  }
  # Hyper-V (only where the role is installed): live migration authentication and networks, enhanced session mode, and per VM
  # Secure Boot, vTPM, MAC spoofing / DHCP guard / router guard and the Guest Service Interface - counts and VM names only
  $o.hyperv = $null
  if (Get-Command Get-VMHost -ErrorAction SilentlyContinue) {
    try {
      $vh = Get-VMHost -ErrorAction Stop
      $hv = [ordered]@{ migration_enabled = [bool]$vh.VirtualMachineMigrationEnabled; migration_auth = [string]$vh.VirtualMachineMigrationAuthenticationType
                        migration_any_network = [bool]$vh.UseAnyNetworkForMigration; enhanced_session = [bool]$vh.EnableEnhancedSessionMode; vms = @() }
      foreach ($vm in @(Get-VM -ErrorAction Stop | Select-Object -First 200)) {
        $r = [ordered]@{ name = [string]$vm.Name; generation = [int]$vm.Generation; state = [string]$vm.State }
        if ($vm.Generation -eq 2) { try { $r.secure_boot = ([string](Get-VMFirmware -VM $vm -ErrorAction Stop).SecureBoot) -eq 'On' } catch { } ; try { $r.tpm = [bool](Get-VMSecurity -VM $vm -ErrorAction Stop).TpmEnabled } catch { } }
        try { $na = @(Get-VMNetworkAdapter -VM $vm -ErrorAction Stop); $r.mac_spoofing = [bool]@($na | Where-Object { [string]$_.MacAddressSpoofing -eq 'On' }).Count
              $r.dhcp_guard = -not [bool]@($na | Where-Object { [string]$_.DhcpGuard -ne 'On' }).Count; $r.router_guard = -not [bool]@($na | Where-Object { [string]$_.RouterGuard -ne 'On' }).Count } catch { }
        try { $r.guest_service = [bool](Get-VMIntegrationService -VM $vm -ErrorAction Stop | Where-Object { $_.Id -match '6C09BB55-D683-4DA0-8931-C9BF705F6480' }).Enabled } catch { }
        $hv.vms += $r
      }
      $o.hyperv = $hv
    } catch { $o.hyperv = [ordered]@{ error = [string]$_.Exception.Message } }
  }
  # Active Directory (only on a domain controller with the ActiveDirectory module): the domain's password and lockout policy,
  # functional levels, Recycle Bin, krbtgt password age, privileged group sizes, and COUNTS of risky accounts (password never
  # expires / not required, no Kerberos pre-authentication, admins with an SPN, stale, unconstrained delegation) with at most
  # 20 account names each as evidence. LDAP queries with fixed filters, read as the DC's own computer account.
  $o.ad = $null
  if ($o.os -and [int]$o.os.domain_role -ge 4 -and (Get-Module -ListAvailable -Name ActiveDirectory -ErrorAction SilentlyContinue)) {
    try {
      Import-Module ActiveDirectory -ErrorAction Stop
      $dom = Get-ADDomain -ErrorAction Stop
      $ad = [ordered]@{ domain = [string]$dom.DNSRoot; domain_mode = [string]$dom.DomainMode }
      try { $ad.forest_mode = [string](Get-ADForest -ErrorAction Stop).ForestMode } catch { $ad.forest_mode = $null }
      try { $pp = Get-ADDefaultDomainPasswordPolicy -ErrorAction Stop
            $ad.pwd = [ordered]@{ min_length = [int]$pp.MinPasswordLength; complexity = [bool]$pp.ComplexityEnabled; history = [int]$pp.PasswordHistoryCount
                                  max_age_days = [int]$pp.MaxPasswordAge.TotalDays; lockout_threshold = [int]$pp.LockoutThreshold; reversible = [bool]$pp.ReversibleEncryptionEnabled } } catch { $ad.pwd = $null }
      try { $ad.recycle_bin = [bool]@((Get-ADOptionalFeature -Filter "Name -eq 'Recycle Bin Feature'" -ErrorAction Stop).EnabledScopes).Count } catch { $ad.recycle_bin = $null }
      try { $kt = Get-ADUser krbtgt -Properties PasswordLastSet -ErrorAction Stop; $ad.krbtgt_age_days = [int]([DateTime]::UtcNow - ([DateTime]$kt.PasswordLastSet).ToUniversalTime()).TotalDays } catch { $ad.krbtgt_age_days = $null }
      $ad.groups = [ordered]@{}
      $rootSid = [string]$dom.DomainSID
      try { $rootSid = [string](Get-ADDomain -Identity (Get-ADForest -ErrorAction Stop).RootDomain -ErrorAction Stop).DomainSID } catch { }   # single-domain forest or root not reachable: this domain
      $grp = [ordered]@{ domain_admins = "$($dom.DomainSID)-512"; enterprise_admins = "$rootSid-519"; schema_admins = "$rootSid-518"; administrators = 'S-1-5-32-544'; protected_users = "$($dom.DomainSID)-525" }
      foreach ($k in $grp.Keys) {
        try { $m = @(Get-ADGroupMember -Identity $grp[$k] -Recursive -ErrorAction Stop | Where-Object { $_.objectClass -eq 'user' })
              $ad.groups[$k] = [ordered]@{ count = $m.Count; names = @($m | Select-Object -First 20 | ForEach-Object { [string]$_.SamAccountName }) } }
        catch { $ad.groups[$k] = $null }   # a group in another domain of the forest may not be readable from here: not checked
      }
      $off = '(!(userAccountControl:1.2.840.113556.1.4.803:=2))'
      $stale = [DateTime]::UtcNow.AddDays(-90).ToFileTimeUtc()
      $q = [ordered]@{
        pwd_never_expires = "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536)$off)"
        pwd_not_required  = "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32)$off)"
        no_preauth        = "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304)$off)"
        admin_spn         = "(&(objectCategory=person)(objectClass=user)(adminCount=1)(servicePrincipalName=*)(!(sAMAccountName=krbtgt))$off)"
        stale_users       = "(&(objectCategory=person)(objectClass=user)(lastLogonTimestamp<=$stale)$off)"
        unconstrained     = "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(primaryGroupID=516))$off)"
      }
      $ad.accounts = [ordered]@{}
      foreach ($k in $q.Keys) {
        try { $r = @(Get-ADObject -LDAPFilter $q[$k] -Properties sAMAccountName -ResultSetSize 5000 -ErrorAction Stop)
              $ad.accounts[$k] = [ordered]@{ count = $r.Count; names = @($r | Select-Object -First 20 | ForEach-Object { [string]$_.sAMAccountName }) } } catch { $ad.accounts[$k] = $null }
      }
      try { $ad.computers = @(Get-ADObject -LDAPFilter "(&(objectCategory=computer)$off)" -ResultSetSize 50000 -ErrorAction Stop).Count } catch { $ad.computers = $null }
      try { $lc = @(Get-ADObject -LDAPFilter "(&(objectCategory=computer)$off(|(msLAPS-PasswordExpirationTime=*)(ms-Mcs-AdmPwdExpirationTime=*)))" -ResultSetSize 50000 -ErrorAction Stop).Count; $ad.laps_computers = $lc } catch { $ad.laps_computers = $null }
      $np = 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'
      try { $ad.ldap_signing = [int](Get-ItemProperty -Path $np -Name LDAPServerIntegrity -ErrorAction Stop).LDAPServerIntegrity } catch { $ad.ldap_signing = $null }
      try { $ad.ldap_channel_binding = [int](Get-ItemProperty -Path $np -Name LdapEnforceChannelBinding -ErrorAction Stop).LdapEnforceChannelBinding } catch { $ad.ldap_channel_binding = 0 }
      $o.ad = $ad
    } catch { $o.ad = [ordered]@{ error = [string]$_.Exception.Message } }
  }
  # Exchange Server (only where the Exchange management snap-in is installed): build, organisation and server settings the
  # CIS Exchange benchmark asks about - modern auth, audit logging, mailbox audit, external auto-forwarding, anonymous relay on
  # receive connectors, OWA / ECP exposure, Extended Protection, anti-malware bypass, TLS 1.0 / 1.1. Get-* cmdlets only.
  $o.exchange = $null
  $exSnap = Get-PSSnapin -Registered -Name 'Microsoft.Exchange.Management.PowerShell.SnapIn' -ErrorAction SilentlyContinue
  if ($exSnap) {
    try {
      if (-not (Get-PSSnapin -Name 'Microsoft.Exchange.Management.PowerShell.SnapIn' -ErrorAction SilentlyContinue)) { Add-PSSnapin 'Microsoft.Exchange.Management.PowerShell.SnapIn' -ErrorAction Stop }
      $ex = [ordered]@{}
      try { $ex.build = [string](Get-Command ExSetup.exe -ErrorAction Stop).FileVersionInfo.ProductVersion } catch { try { $ex.build = [string](Get-ExchangeServer -Identity $env:COMPUTERNAME -ErrorAction Stop).AdminDisplayVersion } catch { $ex.build = $null } }
      try { $oc = Get-OrganizationConfig -ErrorAction Stop; $ex.modern_auth = [bool]$oc.OAuth2ClientProfileEnabled; $ex.mailbox_audit_off = [bool]$oc.AuditDisabled; $ex.mapi_http = [bool]$oc.MapiHttpEnabled } catch { }
      try { $ex.admin_audit = [bool](Get-AdminAuditLogConfig -ErrorAction Stop).AdminAuditLogEnabled } catch { $ex.admin_audit = $null }
      try { $ex.auto_forward = [bool](Get-RemoteDomain -Identity Default -ErrorAction Stop).AutoForwardEnabled } catch { $ex.auto_forward = $null }
      try {
        $ex.receive = @(Get-ReceiveConnector -Server $env:COMPUTERNAME -ErrorAction Stop | Select-Object -First 50 | ForEach-Object {
          $rc = $_; $anon = [string]$rc.PermissionGroups -match 'AnonymousUsers'; $relay = $false
          if ($anon) { try { $relay = [bool]@(Get-ADPermission -Identity $rc.Identity -ErrorAction Stop | Where-Object { [string]$_.User -match 'ANONYMOUS' -and [string]$_.ExtendedRights -match 'Accept-Any-Recipient' -and -not $_.Deny }).Count } catch { $relay = $null } }
          [ordered]@{ name = [string]$rc.Name; anonymous = [bool]$anon; open_relay = $relay; tls = [string]$rc.AuthMechanism -match 'Tls'; enabled = [bool]$rc.Enabled } })
      } catch { $ex.receive = $null }
      try { $ow = Get-OwaVirtualDirectory -Server $env:COMPUTERNAME -ADPropertiesOnly -ErrorAction Stop | Select-Object -First 1; $ex.owa_basic = [bool]$ow.BasicAuthentication; $ex.owa_external = [bool][string]$ow.ExternalUrl } catch { }
      try { $ec = Get-EcpVirtualDirectory -Server $env:COMPUTERNAME -ADPropertiesOnly -ErrorAction Stop | Select-Object -First 1; $ex.ecp_external = [bool][string]$ec.ExternalUrl -and [bool]$ec.AdminEnabled } catch { }
      try { $ex.ep_ews = [string](Get-WebServicesVirtualDirectory -Server $env:COMPUTERNAME -ADPropertiesOnly -ErrorAction Stop | Select-Object -First 1).ExtendedProtectionTokenChecking } catch { $ex.ep_ews = $null }
      try { $ex.malware_bypass = [bool](Get-MalwareFilteringServer -Identity $env:COMPUTERNAME -ErrorAction Stop).BypassFiltering } catch { $ex.malware_bypass = $null }
      foreach ($t in @(@('tls10', 'TLS 1.0'), @('tls11', 'TLS 1.1'))) {
        try { $ex[$t[0] + '_server'] = [int](Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$($t[1])\Server" -Name Enabled -ErrorAction Stop).Enabled } catch { $ex[$t[0] + '_server'] = $null }
      }
      $o.exchange = $ex
    } catch { $o.exchange = [ordered]@{ error = [string]$_.Exception.Message } }
  }
  # Certificates in the machine stores ("keystores"): what is installed on the server, not only what a port presents. The
  # Cert: drive is read; the private key is never touched (has_key only says one exists). At most 300 certificates.
  $o.certs = $null
  try {
    $list = New-Object System.Collections.ArrayList
    foreach ($st in @('My', 'WebHosting', 'Remote Desktop')) {
      foreach ($c in @(Get-ChildItem -Path ('Cert:\LocalMachine\' + $st) -ErrorAction SilentlyContinue | Select-Object -First 200)) {
        if ($list.Count -ge 300) { break }
        $bits = $null; try { $bits = [int]$c.PublicKey.Key.KeySize } catch { try { $bits = [int]$c.PublicKey.EncodedKeyValue.RawData.Length * 8 } catch { $bits = $null } }
        $sans = @(); try { $sans = @($c.DnsNameList | Select-Object -First 10 | ForEach-Object { [string]$_.Unicode }) } catch { }
        [void]$list.Add([ordered]@{ store = $st; subject = [string]$c.GetNameInfo('SimpleName', $false); issuer = [string]$c.GetNameInfo('SimpleName', $true)
          thumbprint = [string]$c.Thumbprint; serial = [string]$c.SerialNumber; not_before = $c.NotBefore.ToUniversalTime().ToString('o'); not_after = $c.NotAfter.ToUniversalTime().ToString('o')
          has_key = [bool]$c.HasPrivateKey; key_alg = [string]$c.PublicKey.Oid.FriendlyName; key_bits = $bits; sig_alg = [string]$c.SignatureAlgorithm.FriendlyName
          self_signed = ([string]$c.Subject -eq [string]$c.Issuer); sans = $sans; eku = @($c.EnhancedKeyUsageList | Select-Object -First 5 | ForEach-Object { [string]$_.FriendlyName }) })
      }
    }
    $o.certs = @($list)
  } catch { $o.certs = [ordered]@{ error = [string]$_.Exception.Message } }
  # On an AD CS certification authority: the machine certificates it issued that are still valid or expired in the last 60
  # days (certutil -view, read-only), soonest expiry first, at most 500. User / smart-card / e-mail / EFS templates are left
  # out: those are people's credentials, not this platform's inventory. Requester names are not read.
  $o.ca_issued = $null
  if (Get-Service -Name CertSvc -ErrorAction SilentlyContinue) {
    try {
      $since = (Get-Date).AddDays(-60).ToString('d')
      $raw = & certutil.exe -view -restrict ("Disposition=20,NotAfter>=" + $since) -out 'RequestID,CommonName,NotAfter,CertificateTemplate,SerialNumber' csv 2>$null
      if ($LASTEXITCODE -ne 0) { throw ('certutil exit ' + $LASTEXITCODE) }
      $rows = @($raw | Select-Object -Skip 1 | ConvertFrom-Csv -Header 'id', 'cn', 'not_after', 'template', 'serial')
      $o.ca_issued = @($rows | Where-Object { [string]$_.template -notmatch '(?i)user|smart ?card|e-?mail|efs' } | ForEach-Object {
          $na = $null; try { $na = ([datetime]::Parse([string]$_.not_after)).ToUniversalTime().ToString('o') } catch { $na = $null }
          [ordered]@{ request_id = [string]$_.id; cn = [string]$_.cn; not_after = $na; template = ([string]$_.template -replace '^[0-9.]+ ', ''); serial = [string]$_.serial } } |
        Where-Object { $_.not_after } | Sort-Object { $_.not_after } | Select-Object -First 500)
    } catch { $o.ca_issued = [ordered]@{ error = [string]$_.Exception.Message } }
  }
  return $o
}

function Get-HostFqdn {
  try { return [System.Net.Dns]::GetHostEntry('').HostName } catch { return $env:COMPUTERNAME }
}

# ----------------------------------------------------------------------------------------------------------------
# One pass
# ----------------------------------------------------------------------------------------------------------------
function Invoke-AgentPass {
  $script:Cfg = Get-EffectiveConfig
  $cfg = $script:Cfg
  $script:LogMaxBytes = [long]$cfg.LogMaxMB * 1MB
  if (-not (Test-Path -LiteralPath $cfg.TokenFile)) { throw "token file not found: $($cfg.TokenFile)" }
  $script:Token = ([System.IO.File]::ReadAllText($cfg.TokenFile)).Trim()
  if (-not $script:Token) { throw 'token file is empty' }
  Initialize-Transport -Cfg $cfg
  Remove-OldRejects

  $script:State = Get-State
  $script:QueueFull = $false
  $script:Attempted = $false
  $script:Batch = New-Object System.Collections.Generic.List[string]
  $script:BatchBytes = 0
  $script:PassEvents = 0
  $script:LastRead = @{}          # channel -> highest RecordId read (sent, queued or filtered out)
  $script:Bm = Get-Bookmarks
  $now = [DateTime]::UtcNow

  # Persisted back-off: after a failure, the collector is only contacted again once next_attempt has passed.
  $script:CollectorUp = $true
  $na = ConvertTo-UtcDate $script:State.next_attempt
  if ($null -ne $na -and $now -lt $na) { $script:CollectorUp = $false }
  if ($script:CollectorUp) { $script:CollectorUp = Clear-Queue }

  # Heartbeat (carries CPU / memory / disk usage for the Server Availability page)
  $lh = ConvertTo-UtcDate $script:State.last_heartbeat
  if ($null -eq $lh -or ($now - $lh).TotalMinutes -ge [double]$cfg.HeartbeatMinutes) {
    $hb = [ordered]@{
      Channel = 'SentraAgent'; EventID = 0; TimeCreated = $now.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
      Computer = (Get-HostFqdn); RecordId = 0; Level = 4; ProviderName = 'SentraAgent'
      EventData = [ordered]@{
        type = 'heartbeat'; agent_version = $AgentVersion; source_id = $cfg.SourceId
        os = [Environment]::OSVersion.VersionString; ps_version = $PSVersionTable.PSVersion.ToString()
        queue_files = [string]@(Get-QueueFiles).Count; queue_bytes = [string](Get-QueueBytes)
        queue_full_since = [string]$script:State.queue_full_since
        last_success = [string]$script:State.last_success; sent_events_total = [string]$script:State.sent_events
        dropped_batches_total = [string]$script:State.dropped_batches
        bookmarks = (($script:Bm.Keys | Sort-Object | ForEach-Object { "$_=$($script:Bm[$_])" }) -join '; ')
      }
      Message = 'SentraAgent heartbeat'
    }
    foreach ($kv in (Get-PerfSample).GetEnumerator()) { $hb.EventData[$kv.Key] = $kv.Value }
    [void](Add-BatchLine (ConvertTo-JsonLine $hb))
    $script:State.last_heartbeat = $now.ToString('o')
  }

  # Baseline-hardening snapshot (read-only settings), queued like any event so it survives a collector outage
  $hh = [double](Get-Prop $cfg 'HardeningHours' 24)
  $lhd = ConvertTo-UtcDate $script:State.last_hardening
  if ($hh -gt 0 -and ($null -eq $lhd -or ($now - $lhd).TotalHours -ge $hh)) {
    try {
      $snap = Get-HardeningSnapshot
      $hev = [ordered]@{
        Channel = 'SentraAgent'; EventID = 1; TimeCreated = $now.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
        Computer = (Get-HostFqdn); RecordId = 0; Level = 4; ProviderName = 'SentraAgent'
        EventData = [ordered]@{ type = 'hardening'; agent_version = $AgentVersion; source_id = $cfg.SourceId; settings = ($snap | ConvertTo-Json -Depth 5 -Compress) }
        Message = 'SentraAgent hardening snapshot'
      }
      [void](Add-BatchLine (ConvertTo-JsonLine $hev))
    } catch { Write-AgentLog 'WARN' "hardening snapshot not taken: $($_.Exception.Message)" }
    $script:State.last_hardening = $now.ToString('o')
  }

  # File-share personal-data scan (1.5): a finished scan is queued like any event; a due one is started as its own
  # low-priority process (-FileScan) so this pass - and event forwarding - never waits for it
  $fsFile = Join-Path $DataDir 'filescan.json'
  if (Test-Path -LiteralPath $fsFile) {
    try {
      $raw = [IO.File]::ReadAllText($fsFile)
      if ($raw.Length -le 250000) {
        $pev = [ordered]@{
          Channel = 'SentraAgent'; EventID = 1; TimeCreated = $now.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
          Computer = (Get-HostFqdn); RecordId = 0; Level = 4; ProviderName = 'SentraAgent'
          EventData = [ordered]@{ type = 'pii'; agent_version = $AgentVersion; source_id = $cfg.SourceId; settings = $raw }
          Message = 'SentraAgent file-share personal-data scan'
        }
        [void](Add-BatchLine (ConvertTo-JsonLine $pev))
      } else { Write-AgentLog 'WARN' 'file scan result too large to send - lower FileScanMaxFiles or scan fewer folders' }
      Remove-Item -LiteralPath $fsFile -Force
    } catch { Write-AgentLog 'WARN' "file scan result not queued: $($_.Exception.Message)" }
  }
  $fsh = [double](Get-Prop $cfg 'FileScanHours' 168); $lfs = ConvertTo-UtcDate $script:State.last_filescan
  if (@($cfg.FileScanPaths | Where-Object { $_ }).Count -gt 0 -and $fsh -gt 0 -and ($null -eq $lfs -or ($now - $lfs).TotalHours -ge $fsh)) {
    try {
      $pp = Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"' + $PSCommandPath + '"'), '-FileScan', '-DataDir', ('"' + $DataDir + '"')) -WindowStyle Hidden -PassThru
      try { $pp.PriorityClass = 'BelowNormal' } catch { Write-AgentLog 'DEBUG' 'file scan priority not lowered' }
      Write-AgentLog 'INFO' 'file-share personal-data scan started'
    } catch { Write-AgentLog 'WARN' "file scan not started: $($_.Exception.Message)" }
    $script:State.last_filescan = $now.ToString('o')
  }

  $aborted = $false
  # Collector down and queue (nearly) full: pause - do not read, bookmarks stay, events remain in the event log.
  if (-not $script:CollectorUp -and $cfg.QueueFullPolicy -eq 'pause' -and ((Get-QueueBytes) -ge ([long]$cfg.QueueMaxMB * 1MB - $cfg.BatchMaxBytes))) {
    Write-AgentLog 'WARN' 'collector unreachable and queue full - collection paused this pass'
    $script:QueueFull = $true
    $aborted = $true
  }

  if (-not $aborted) {
    foreach ($ch in @($cfg.Channels)) {
      if (-not (Get-Prop $ch 'Enabled' $true)) { continue }
      $name = [string]$ch.Name
      $allow = @{};  foreach ($i in @(Get-Prop $ch 'EventIds' @()))        { $allow[[int]$i] = $true }
      $deny = @{};   foreach ($i in @(Get-Prop $ch 'ExcludeEventIds' @())) { $deny[[int]$i] = $true }
      $levels = @{}; foreach ($i in @(Get-Prop $ch 'Levels' @()))          { $levels[[int]$i] = $true }
      $incMsg = [bool](Get-Prop $ch 'IncludeMessage' $true)
      $skipSelf = [bool]$cfg.SkipOwnScriptBlocks -and $name -eq 'Microsoft-Windows-PowerShell/Operational'
      $known = $script:Bm.ContainsKey($name)
      $b = [long]0; if ($known) { $b = [long]$script:Bm[$name] }

      try {
        $newest = Get-NewestRecordId -ChannelName $name
      } catch {
        if (Get-InnerException -Exception $_.Exception -Type ([System.Diagnostics.Eventing.Reader.EventLogNotFoundException])) { Write-AgentLog 'DEBUG' "channel not present: $name" }
        elseif (Get-InnerException -Exception $_.Exception -Type ([System.UnauthorizedAccessException])) { Write-AgentLog 'WARN' "no access to channel: $name" }
        else { Write-AgentLog 'WARN' "channel $name unavailable: $($_.Exception.Message)" }
        continue
      }

      if ($known -and $b -gt 0 -and $newest -lt $b) {
        Write-AgentLog 'WARN' "channel $name was cleared or reset (newest RecordId $newest < bookmark $b) - re-reading from the start"
        $b = 0
      }
      if (-not $known) {
        # First time this channel is seen: read only the look-back window, not the whole log.
        if ([int]$cfg.FirstRunLookbackMinutes -le 0) { $script:LastRead[$name] = $newest; continue }
        $xp = Get-ChannelXPath -Ch $ch -Bookmark 0 -LookbackMinutes ([int]$cfg.FirstRunLookbackMinutes)
      } else {
        if ($b -gt 0 -and $newest -le $b) { continue }
        $xp = Get-ChannelXPath -Ch $ch -Bookmark $b -LookbackMinutes 0
      }

      $reader = $null
      $maxId = $b
      $read = 0
      try {
        $reader = New-EventReader -ChannelName $name -XPath $xp -Reverse $false
        while ($read -lt [int]$cfg.MaxEventsPerChannelRun) {
          $e = $reader.ReadEvent()
          if ($null -eq $e) { break }
          $read++
          try {
            $id = [int]$e.Id
            $keep = ($allow.Count -eq 0 -or $allow.ContainsKey($id)) -and -not $deny.ContainsKey($id)
            if ($keep -and $levels.Count -gt 0) { $keep = ($null -ne $e.Level) -and $levels.ContainsKey([int]$e.Level) }
            if ($keep) {
              $obj = ConvertTo-SentraEvent -Record $e -ChannelName $name -IncludeMessage $incMsg -Cfg $cfg
              if ($skipSelf -and $id -eq 4104 -and $obj.EventData.Contains('Path') -and [string]::Equals([string]$obj.EventData['Path'], $PSCommandPath, [StringComparison]::OrdinalIgnoreCase)) { $keep = $false }
            }
            if ($keep) {
              if (-not (Add-BatchLine (ConvertTo-JsonLine $obj))) { $aborted = $true; break }
            }
            if ($null -ne $e.RecordId -and [long]$e.RecordId -gt $maxId) { $maxId = [long]$e.RecordId; $script:LastRead[$name] = $maxId }
          } finally { $e.Dispose() }
        }
        # Nothing matched: everything up to the newest record seen before the query has been considered.
        if (-not $aborted -and -not $script:LastRead.ContainsKey($name)) { $script:LastRead[$name] = [Math]::Max($maxId, $newest) }
        if ($read -ge [int]$cfg.MaxEventsPerChannelRun) { Write-AgentLog 'INFO' "channel ${name}: read limit reached, continuing next pass"; $script:Backlog = $true }
      } catch {
        Write-AgentLog 'WARN' "reading $name failed: $($_.Exception.Message)"
      } finally {
        if ($null -ne $reader) { $reader.Dispose() }
      }
      if ($aborted) { break }
    }
  }

  if (-not $aborted) { $aborted = -not (Invoke-Flush) }
  if ($aborted -and $script:Batch.Count -gt 0) { Write-AgentLog 'WARN' "pass stopped with $($script:Batch.Count) event(s) not yet durable; they are re-read next pass" }

  # back-off bookkeeping: grow only after a real failed attempt; reset after success
  if ($script:CollectorUp -and $script:Attempted) {
    $script:State.last_success = [DateTime]::UtcNow.ToString('o'); $script:State.next_attempt = ''; $script:State.backoff_minutes = 0
  } elseif (-not $script:CollectorUp -and $script:Attempted) {
    $bo = [int]$script:State.backoff_minutes
    if ($bo -le 0) { $bo = 1 } else { $bo = [Math]::Min($bo * 2, [int]$cfg.MaxBackoffMinutes) }
    $script:State.backoff_minutes = $bo
    $script:State.next_attempt = [DateTime]::UtcNow.AddMinutes($bo).ToString('o')
  }
  if ($script:QueueFull) { if (-not $script:State.queue_full_since) { $script:State.queue_full_since = $now.ToString('o') } } else { $script:State.queue_full_since = '' }
  Save-State
  $cs = 'up'; if (-not $script:CollectorUp) { $cs = 'unreachable/back-off' }
  Write-AgentLog 'INFO' ("pass done: {0} event(s) shipped or queued, collector {1}, queue {2} file(s)" -f $script:PassEvents, $cs, @(Get-QueueFiles).Count)
}

# ----------------------------------------------------------------------------------------------------------------
# File-share personal-data scan (1.5) - read-only; counts per file only (rules = SIEM engine/pii/classify.js)
# Credentials in files (private keys, API keys, password = ...; credential file names) are counted the same way: that a
# file holds one and how many - never the value, never a snippet.
# ----------------------------------------------------------------------------------------------------------------
$script:PiiRules = @(
  @{ k = 'national_id'; re = '(?<![\d])1\d{9}(?![\d])'; min = 3 },
  @{ k = 'iqama'; re = '(?<![\d])2\d{9}(?![\d])'; min = 3 },
  @{ k = 'mobile'; re = '(?<![\d+])(?:\+?966|00966|0)5\d{8}(?![\d])'; min = 3 },
  @{ k = 'email'; re = '[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]+\.[A-Za-z]{2,}'; min = 10 },
  @{ k = 'iban'; re = '\bSA\d{2}[ ]?(?:\d{4}[ ]?){5}\b'; min = 1 },
  @{ k = 'card'; re = '(?<![\d])(?:\d[ -]?){13,19}(?![\d])'; min = 1; luhn = $true },
  @{ k = 'health'; re = '\b(?:diagnosis|ICD-?10|medical report|prescription|chronic disease|lab result)\b|\u062A\u0634\u062E\u064A\u0635|\u062A\u0642\u0631\u064A\u0631 \u0637\u0628\u064A|\u0648\u0635\u0641\u0629 \u0637\u0628\u064A\u0629|\u0645\u0631\u0636 \u0645\u0632\u0645\u0646'; min = 2; ci = $true },
  @{ k = 'private_key'; re = '-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----'; min = 1 },
  @{ k = 'api_key'; re = '\b(?:AKIA[0-9A-Z]{16}|sk-(?:ant-|proj-)?[A-Za-z0-9_-]{24,}|gh[pousr]_[A-Za-z0-9]{36}|xox[abprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{35})\b'; min = 1 },
  @{ k = 'password'; re = '\b(?:password|passwd|pwd)\s*[:=]\s*\S{4,}|\u0643\u0644\u0645\u0629 (?:\u0627\u0644\u0645\u0631\u0648\u0631|\u0627\u0644\u0633\u0631)\s*[:=]\s*\S{4,}'; min = 1; ci = $true }
)
$script:PiiNames = @(
  @{ k = 'passport'; re = 'passport|\u062C\u0648\u0627\u0632' },
  @{ k = 'iqama'; re = 'iqama|\u0625\u0642\u0627\u0645\u0629|\u0627\u0642\u0627\u0645\u0629' },
  @{ k = 'national_id'; re = 'national[ _-]?id|\u0647\u0648\u064A\u0629' },
  @{ k = 'health'; re = 'medical|diagnos|prescription|lab[ _-]?result|\u062A\u0642\u0631\u064A\u0631[ _]\u0637\u0628\u064A|\u0637\u0628\u064A' },
  @{ k = 'salary'; re = 'payroll|salary|payslip|\u0631\u0648\u0627\u062A\u0628|\u0631\u0627\u062A\u0628' },
  @{ k = 'iban'; re = '\biban\b|bank[ _-]?(details|account)|\u062D\u0633\u0627\u0628[ _]\u0628\u0646\u0643\u064A' },
  @{ k = 'cv'; re = '\b(cv|resume|curriculum)\b|\u0633\u064A\u0631\u0629[ _]\u0630\u0627\u062A\u064A\u0629' },
  @{ k = 'secret_file'; re = '^id_(?:rsa|dsa|ecdsa|ed25519)$|\.(?:pem|key|pfx|p12|ppk|jks|keystore|kdbx)$|^\.env(?:\.[a-z]+)?$|(?:^|[^a-z])(?:credentials?|secrets?|passwords?)(?:[^a-z]|$)|\u0643\u0644\u0645\u0627\u062A[ _]\u0627\u0644\u0645\u0631\u0648\u0631' }
)
function Test-Luhn { param([string]$D) $t = 0; for ($i = 0; $i -lt $D.Length; $i++) { $n = [int][string]$D[$D.Length - 1 - $i]; if ($i % 2) { $n *= 2; if ($n -gt 9) { $n -= 9 } }; $t += $n }; return ($t % 10 -eq 0) }
function Get-PiiCounts {
  param([string]$Text)
  $out = [ordered]@{}
  $noIban = [regex]::Replace($Text, $script:PiiRules[4].re, ' ')
  foreach ($r in $script:PiiRules) {
    $src = $Text; if ($r.ContainsKey('luhn')) { $src = $noIban }
    $opt = [Text.RegularExpressions.RegexOptions]::None; if ($r.ContainsKey('ci')) { $opt = [Text.RegularExpressions.RegexOptions]::IgnoreCase }   # as in classify.js (flag i): only the words ignore case
    $n = 0
    foreach ($m in [regex]::Matches($src, $r.re, $opt)) { if ($r.ContainsKey('luhn')) { $d = $m.Value -replace '\D', ''; if ($d.Length -lt 13 -or -not (Test-Luhn $d)) { continue } }; $n++ }
    if ($n -ge $r.min) { $out[$r.k] = $n }
  }
  return $out
}
function Get-PiiText {
  param([string]$Path)
  $max = 2MB
  if ($Path -match '\.(txt|csv|log|json|xml|html?|tsv|pem|key|env|ini|conf|cfg|ya?ml|config|properties|ps1|sh|py)$') {
    $fs = [IO.File]::Open($Path, 'Open', 'Read', 'ReadWrite')
    try { $sr = New-Object IO.StreamReader($fs, $true); $buf = New-Object char[] $max; $n = $sr.ReadBlock($buf, 0, $max); return (New-Object string($buf, 0, $n)) } finally { $fs.Dispose() }
  }
  if ($Path -match '\.(docx|xlsx|pptx)$') {
    $want = '^ppt/slides/slide\d+\.xml$'
    if ($Path -match '\.docx$') { $want = '^word/(document|header\d*|footer\d*)\.xml$' } elseif ($Path -match '\.xlsx$') { $want = '^xl/(sharedStrings|worksheets/sheet\d+)\.xml$' }
    $fs = [IO.File]::Open($Path, 'Open', 'Read', 'ReadWrite')
    try {
      $zip = New-Object IO.Compression.ZipArchive($fs, [IO.Compression.ZipArchiveMode]::Read)
      $sb = New-Object Text.StringBuilder
      foreach ($e in $zip.Entries) {
        if ($e.FullName -notmatch $want) { continue }
        $sr = New-Object IO.StreamReader($e.Open()); try { [void]$sb.Append(' ').Append(($sr.ReadToEnd() -replace '<[^>]+>', ' ')) } finally { $sr.Dispose() }
        if ($sb.Length -gt $max) { break }
      }
      $zip.Dispose(); return $sb.ToString()
    } finally { $fs.Dispose() }
  }
  return $null
}
function Test-OpenAcl {
  param([string]$Path)
  try {
    foreach ($a in (Get-Acl -LiteralPath $Path).Access) {
      if ($a.AccessControlType -ne 'Allow') { continue }
      if ([string]$a.IdentityReference -match '(^|\\)(Everyone|Authenticated Users|Domain Users|Users)$' -and (($a.FileSystemRights -band [Security.AccessControl.FileSystemRights]::ReadData) -ne 0)) { return $true }
    }
    return $false
  } catch { return $null }   # ACL not readable: unknown, never "closed"
}
function Invoke-FileScan {
  param($Cfg)
  Add-Type -AssemblyName System.IO.Compression
  $t0 = Get-Date; $deadline = $t0.AddMinutes([Math]::Max([int]$Cfg.FileScanMinutes, 5))
  $maxFiles = [Math]::Max([int]$Cfg.FileScanMaxFiles, 100); $maxBytes = [long]([Math]::Max([int]$Cfg.FileScanMaxMB, 1)) * 1MB
  $roots = @()
  foreach ($p in @($Cfg.FileScanPaths)) {
    if ([string]$p -eq 'auto') { try { foreach ($sh in (Get-SmbShare -ErrorAction Stop | Where-Object { -not $_.Special -and $_.Path -and $_.Name -notmatch '\$$' })) { $roots += [pscustomobject]@{ path = $sh.Path; share = $sh.Name } } } catch { Write-AgentLog 'WARN' "file scan: SMB shares not listed: $($_.Exception.Message)" } }
    elseif ($p) { $roots += [pscustomobject]@{ path = [string]$p; share = '' } }
  }
  $seen = 0; $hitsTotal = 0; $out = @()
  foreach ($r in $roots) {
    $res = [ordered]@{ path = $r.path; share = $r.share; files_seen = 0; files_read = 0; files_skipped = 0; files_unreadable = 0; dirs_denied = 0; truncated = $false; hits = @() }
    $stack = New-Object System.Collections.Stack; $stack.Push($r.path)
    while ($stack.Count -gt 0) {
      if ((Get-Date) -gt $deadline -or $seen -ge $maxFiles) { $res.truncated = $true; break }
      $dir = $stack.Pop()
      try { foreach ($d in [IO.Directory]::EnumerateDirectories($dir)) { if (-not ((Get-Item -LiteralPath $d -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) { $stack.Push($d) } } } catch { $res.dirs_denied++ }
      try { $files = @([IO.Directory]::EnumerateFiles($dir)) } catch { $res.dirs_denied++; continue }
      foreach ($f in $files) {
        if ($seen -ge $maxFiles) { $res.truncated = $true; break }
        $seen++; $res.files_seen++
        $name = [IO.Path]::GetFileName($f)
        $nk = @($script:PiiNames | Where-Object { $name -match $_.re } | ForEach-Object { $_.k })
        $kinds = [ordered]@{}; $by = $null; if ($nk.Count) { $by = 'name' }
        $fi = $null; try { $fi = New-Object IO.FileInfo($f) } catch { $fi = $null }
        if ($f -match '\.(txt|csv|log|json|xml|html?|tsv|pem|key|env|ini|conf|cfg|ya?ml|config|properties|ps1|sh|py)$' -or $f -match '\.(docx|xlsx|pptx)$') {
          if ($fi -and $fi.Length -le $maxBytes) {
            try { $txt = Get-PiiText -Path $f; if ($null -ne $txt) { $res.files_read++; $kinds = Get-PiiCounts -Text $txt; if ($kinds.Count) { $by = 'content' } } else { $res.files_unreadable++ } } catch { $res.files_unreadable++ }
            $txt = $null
          } else { $res.files_skipped++ }
        }
        if (-not $by) { continue }
        if ($hitsTotal -ge 800) { $res.truncated = $true; continue }
        $hitsTotal++
        $rel = $f.Substring([Math]::Min($r.path.Length, $f.Length)).TrimStart('\')
        $res.hits += [ordered]@{ p = $rel; size = $(if ($fi) { $fi.Length } else { 0 }); modified = $(if ($fi) { $fi.LastWriteTimeUtc.ToString('o') } else { '' }); kinds = $kinds; name_kinds = $nk; by = $by; open = (Test-OpenAcl -Path $f) }
      }
    }
    $out += $res
  }
  return [ordered]@{ at = (Get-Date).ToUniversalTime().ToString('o'); agent_version = $AgentVersion; seconds = [int]((Get-Date) - $t0).TotalSeconds; max_files = $maxFiles; roots = $out }
}

if ($FileScan) {
  $fsMutex = New-Object System.Threading.Mutex($false, 'Global\SentraAgentFileScan'); $fsOwned = $false
  try {
    try { $fsOwned = $fsMutex.WaitOne(0) } catch { $fsOwned = $true }
    if (-not $fsOwned) { return }
    try { $cfg = Get-EffectiveConfig; $snap = Invoke-FileScan -Cfg $cfg; Write-FileAtomic -Path (Join-Path $DataDir 'filescan.json') -Content ($snap | ConvertTo-Json -Depth 6 -Compress); Write-AgentLog 'INFO' ("file scan done: {0} root(s) in {1} s" -f @($snap.roots).Count, $snap.seconds) }
    catch { Write-AgentLog 'ERROR' "file scan failed: $($_.Exception.Message)" }
  } finally { if ($fsOwned) { $fsMutex.ReleaseMutex() }; $fsMutex.Dispose() }
  return
}

# ----------------------------------------------------------------------------------------------------------------
# Main: single instance via a global mutex
# ----------------------------------------------------------------------------------------------------------------
$mutex = New-Object System.Threading.Mutex($false, 'Global\SentraAgentForwarder')
$owned = $false
try {
  try { $owned = $mutex.WaitOne(0) } catch { if (Get-InnerException -Exception $_.Exception -Type ([System.Threading.AbandonedMutexException])) { $owned = $true } else { throw } }
  if (-not $owned) { Write-AgentLog 'DEBUG' 'another instance is running - exiting'; return }
  do {
    $script:Backlog = $false
    try { Invoke-AgentPass }
    catch { Write-AgentLog 'ERROR' ("pass failed: {0} (line {1})" -f $_.Exception.Message, $_.InvocationInfo.ScriptLineNumber) }
    if ($Loop -and -not $script:Backlog) { Start-Sleep -Seconds ([Math]::Max($LoopSeconds, 5)) }
  } while ($Loop)
} finally {
  if ($owned) { $mutex.ReleaseMutex() }
  $mutex.Dispose()
}
