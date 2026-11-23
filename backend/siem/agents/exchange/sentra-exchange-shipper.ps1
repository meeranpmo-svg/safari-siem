# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
<#
.SYNOPSIS
  Sentra SIEM - Exchange file shipper (SentraExchangeShipper): message tracking + IIS logs over HTTPS.

.DESCRIPTION
  Tails the Exchange message tracking logs (MSGTRK*.log) and the IIS logs of the Exchange web sites (W3SVC1 /
  W3SVC2 u_ex*.log) by byte offset and ships the RAW lines as NDJSON batches (gzip) to
  https://<collector>/ingest/<src_id> with header X-Sentra-Token - the same transport contract as the Windows event
  agent (agents/windows/sentra-agent.ps1): X-Sentra-Batch-Id stable across retries, TLS 1.2+, certificate validation on,
  disk queue (<= 200 MB, oldest first) while the collector is unreachable, back-off, heartbeat, mutex single instance.

  Every data line is prefixed with an RFC 5424 syslog header that carries the Exchange server name as host and the
  stream tag  exmsgtrk-<SERVER>  /  exiis-<SERVER>  as app-name, exactly like the rsyslog imfile option in
  agents/exchange/README.md:
      <174>1 2026-10-07T10:00:00Z EX01 exmsgtrk-EX01 - - - 2026-10-07T09:59:58.123Z,10.20.0.15,...
  The engine takes host from that tag and remembers the '#Fields:' header per source + host + tag, so the current
  header of each file is re-sent ahead of the data lines whenever it changes (and, by default, once per batch).

  - PowerShell 5.1 compatible, no external modules, no binaries.
  - Per-file bookmarks (<DataDir>\bookmarks.json: byte offset + current #Fields header). A bookmark only advances
    after the lines it covers were accepted by the collector (HTTP 2xx) or written to the local disk queue.
  - Rotation: a new file (new hour/day) starts at offset 0; a file that became shorter than its bookmark
    (truncated / rolled in place) restarts at 0; files that disappear are forgotten.
  - First run: files written within FirstRunLookbackMinutes are read from the start, older files start at the end.
  - Runs as SYSTEM from a scheduled task every minute (single pass), or -Loop.

.PARAMETER DryRun
  Print the last -Count data lines of the newest file of every source, prefixed exactly as they would be sent, and a
  summary (files found, sizes) on stderr. Reads config.json if present (else defaults), touches no bookmarks, writes
  and sends nothing, needs no token. -Count 0 prints only the summary (used by the installer to show the paths).

.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File sentra-exchange-shipper.ps1 -DryRun -Count 5
.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File sentra-exchange-shipper.ps1 -PrintDefaultConfig
.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File sentra-exchange-shipper.ps1          # one pass (what the task runs)
#>
[CmdletBinding()]
param(
  [string]$DataDir = (Join-Path $env:ProgramData 'SentraExchangeShipper'),
  [string]$ConfigPath = '',
  [switch]$DryRun,
  [int]$Count = 5,
  [switch]$PrintDefaultConfig,
  [switch]$Loop,
  [int]$LoopSeconds = 60
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$ShipperVersion = '1.0.0'

# ----------------------------------------------------------------------------------------------------------------
# Defaults (single source of truth; install-exchange-shipper.ps1 writes these into config.json via -PrintDefaultConfig)
# ----------------------------------------------------------------------------------------------------------------
function Get-DefaultConfig {
  [ordered]@{
    CollectorUrl             = 'https://siem.example.local'   # https only; path /ingest/<SourceId> is appended
    SourceId                 = 'win-exchange'                 # must exist in the engine with type "exchange" (token issued for it)
    TokenFile                = ''                             # default <DataDir>\token.txt
    PinnedThumbprint         = ''                             # optional: SHA-1 (40 hex) or SHA-256 (64 hex) of the collector cert
    Proxy                    = ''                             # optional http://proxy:port ; empty = direct connection
    ServerName               = ''                             # host name sent with every line; empty = this computer's name
    ExchangeInstallPath      = ''                             # empty = $env:ExchangeInstallPath / registry (HKLM\SOFTWARE\Microsoft\ExchangeServer\v15\Setup)
    BatchMaxLines            = 2000
    BatchMaxBytes            = 1048576                        # uncompressed NDJSON bytes per POST
    MaxLinesPerPass          = 50000                          # bound one pass; the rest is read next pass
    MaxReadBytesPerFile      = 8388608                        # bytes read from one file per pass
    MaxLineBytes             = 65536                          # longer lines are skipped
    MaxFileAgeHours          = 48                             # files not written for longer are not looked at
    FirstRunLookbackMinutes  = 60                             # first start: files written within this window are read from the start
    HeaderEveryBatch         = $true                          # re-send the #Fields header in every batch (cheap; survives engine restarts)
    QueueMaxMB               = 200
    QueueFullPolicy          = 'pause'                        # pause | drop-oldest
    HeartbeatMinutes         = 5
    HttpTimeoutSeconds       = 30
    RetriesPerRun            = 3
    MaxBackoffMinutes        = 15
    LogMaxMB                 = 5
    TestPlainHttp            = $false                         # tests only: allow http:// to 127.0.0.1 / localhost
    Sources = @(
      [ordered]@{ Name = 'msgtrk'; Enabled = $true; Tag = 'exmsgtrk'
        Paths = @('%ExchangeInstallPath%TransportRoles\Logs\MessageTracking\MSGTRK*.log',
                  '%ExchangeInstallPath%TransportRoles\Logs\MessageTracking\MSGTRKMD*.log',
                  '%ExchangeInstallPath%TransportRoles\Logs\MessageTracking\MSGTRKMS*.log') }
      [ordered]@{ Name = 'iis'; Enabled = $true; Tag = 'exiis'
        Paths = @('%SystemDrive%\inetpub\logs\LogFiles\W3SVC1\u_ex*.log',
                  '%SystemDrive%\inetpub\logs\LogFiles\W3SVC2\u_ex*.log') }
    )
  }
}

if ($PrintDefaultConfig) {
  Get-DefaultConfig | ConvertTo-Json -Depth 6
  return
}

# ----------------------------------------------------------------------------------------------------------------
# Helpers (shared with sentra-agent.ps1)
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
  # Read a property from a PSCustomObject (from ConvertFrom-Json) or a hashtable with a default.
  param($Object, [string]$Name, $Default)
  if ($null -eq $Object) { return $Default }
  if ($Object -is [System.Collections.IDictionary]) {
    if ($Object.Contains($Name) -and $null -ne $Object[$Name]) { return $Object[$Name] }
    return $Default
  }
  $p = $Object.PSObject.Properties[$Name]
  if ($null -eq $p -or $null -eq $p.Value) { return $Default }
  return $p.Value
}

function ConvertTo-UtcDate {
  param($Value)
  if ($null -eq $Value -or [string]::IsNullOrEmpty([string]$Value)) { return $null }
  if ($Value -is [DateTime]) { return $Value.ToUniversalTime() }
  return [DateTime]::Parse([string]$Value, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime()
}

function Get-InnerException {
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

function ConvertTo-JsonLine {
  param($Object)
  return ($Object | ConvertTo-Json -Depth 5 -Compress)
}

function Get-HostFqdn {
  try { return [System.Net.Dns]::GetHostEntry('').HostName } catch { return $env:COMPUTERNAME }
}

# ----------------------------------------------------------------------------------------------------------------
# Paths and files
# ----------------------------------------------------------------------------------------------------------------
function Get-ExchangeInstallPath {
  param([string]$Configured)
  if ($Configured) { return $Configured }
  if ($env:ExchangeInstallPath) { return $env:ExchangeInstallPath }
  foreach ($k in @('HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15\Setup', 'HKLM:\SOFTWARE\Microsoft\ExchangeServer\v14\Setup')) {
    try {
      $v = (Get-ItemProperty -LiteralPath $k -Name MsiInstallPath -ErrorAction Stop).MsiInstallPath
      if ($v) { return [string]$v }
    } catch { }
  }
  return ''
}

function Expand-LogPath {
  # %ExchangeInstallPath% plus the usual environment variables. Returns '' when the Exchange path is needed but unknown.
  param([string]$Pattern, [string]$ExchangePath)
  $p = [string]$Pattern
  $marker = '%ExchangeInstallPath%'
  $idx = $p.IndexOf($marker, [StringComparison]::OrdinalIgnoreCase)
  if ($idx -ge 0) {
    if (-not $ExchangePath) { return '' }
    $base = $ExchangePath.TrimEnd('\') + '\'
    $p = $p.Substring(0, $idx) + $base + $p.Substring($idx + $marker.Length).TrimStart('\')
  }
  return [Environment]::ExpandEnvironmentVariables($p)
}

function Get-SourceFiles {
  # All files matching the source's patterns (deduplicated by path, case-insensitive), oldest LastWriteTime first.
  param($Source, [string]$ExchangePath, [int]$MaxAgeHours)
  $seen = @{}
  $list = New-Object System.Collections.Generic.List[object]
  $limit = [DateTime]::UtcNow.AddHours(-1 * [Math]::Max($MaxAgeHours, 1))
  foreach ($pat in @(Get-Prop $Source 'Paths' @())) {
    $full = Expand-LogPath -Pattern ([string]$pat) -ExchangePath $ExchangePath
    if (-not $full) { $script:MissingExchangePath = $true; continue }
    $dir = Split-Path -Path $full -Parent
    $leaf = Split-Path -Path $full -Leaf
    if (-not $dir -or -not (Test-Path -LiteralPath $dir)) { continue }
    foreach ($f in @(Get-ChildItem -LiteralPath $dir -Filter $leaf -File -ErrorAction SilentlyContinue)) {
      $key = $f.FullName.ToLowerInvariant()
      if ($seen.ContainsKey($key)) { continue }
      $seen[$key] = $true
      if ($MaxAgeHours -gt 0 -and $f.LastWriteTimeUtc -lt $limit) { continue }
      $list.Add($f)
    }
  }
  return @($list | Sort-Object LastWriteTimeUtc, Name)
}

function Get-FileHeader {
  # The last '#Fields:' line within the first 16 KB of a file (headers are written at the top). '' when none.
  param([string]$Path)
  try {
    $fs = New-Object System.IO.FileStream($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, ([System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete))
    try {
      $want = [int][Math]::Min(16384, $fs.Length)
      if ($want -le 0) { return '' }
      $buf = New-Object byte[] $want
      $n = 0
      while ($n -lt $want) { $r = $fs.Read($buf, $n, $want - $n); if ($r -le 0) { break }; $n += $r }
      $txt = $Utf8NoBom.GetString($buf, 0, $n)
      if ($txt.Length -gt 0 -and [int]$txt[0] -eq 0xFEFF) { $txt = $txt.Substring(1) }
      $hdr = ''
      foreach ($l in $txt.Split("`n")) {
        $t = $l.TrimEnd("`r")
        if ($t.StartsWith('#Fields:', [StringComparison]::OrdinalIgnoreCase)) { $hdr = $t }
      }
      return $hdr
    } finally { $fs.Dispose() }
  } catch { return '' }
}

function Read-FileLines {
  # Read complete lines from $Offset. Returns a hashtable:
  #   Lines   = list of @{ Text = <line without CR/LF>; End = <byte offset just after the line's LF> }
  #   Length  = current file length; Truncated = $true when the file is shorter than $Offset; Skipped = bytes dropped
  param([string]$Path, [long]$Offset, [int]$MaxBytes, [int]$MaxLineBytes)
  $res = @{ Lines = (New-Object System.Collections.Generic.List[object]); Length = [long]0; Truncated = $false; Skipped = [long]0; Offset = $Offset }
  $fs = New-Object System.IO.FileStream($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, ([System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete))
  try {
    $len = $fs.Length
    $res.Length = $len
    if ($len -lt $Offset) { $res.Truncated = $true; return $res }
    if ($Offset -eq 0 -and $len -ge 3) {
      $bom = New-Object byte[] 3
      [void]$fs.Read($bom, 0, 3)
      if ($bom[0] -eq 0xEF -and $bom[1] -eq 0xBB -and $bom[2] -eq 0xBF) { $Offset = 3; $res.Offset = 3 }
    }
    $want = [int][Math]::Min([long]$MaxBytes, $len - $Offset)
    if ($want -le 0) { return $res }
    $fs.Position = $Offset
    $buf = New-Object byte[] $want
    $n = 0
    while ($n -lt $want) { $r = $fs.Read($buf, $n, $want - $n); if ($r -le 0) { break }; $n += $r }
    if ($n -le 0) { return $res }
    $last = [Array]::LastIndexOf($buf, [byte]10, $n - 1)
    if ($last -lt 0) {
      # no complete line in the window: either a partial line still being written (wait) or a runaway line (skip)
      if ($n -ge $MaxLineBytes) { $res.Skipped = $n; $res.Offset = $Offset + $n }
      return $res
    }
    $txt = $Utf8NoBom.GetString($buf, 0, $last)      # everything up to (excluding) the last LF
    $pos = $Offset
    foreach ($seg in $txt.Split("`n")) {
      $pos += $Utf8NoBom.GetByteCount($seg) + 1
      $t = $seg.TrimEnd("`r")
      if ($t.Length -eq 0) { continue }
      if ($Utf8NoBom.GetByteCount($t) -gt $MaxLineBytes) { $res.Skipped += $t.Length; continue }
      $res.Lines.Add(@{ Text = $t; End = $pos })
    }
    $res.Offset = $Offset + $last + 1
    return $res
  } finally { $fs.Dispose() }
}

function Get-LinePrefix {
  # RFC 5424 header: facility local5 (21), severity info (6) -> PRI 174; host = Exchange server; app = <tag>-<server>
  param([string]$Tag, [string]$Server)
  return ('<174>1 {0} {1} {2}-{1} - - - ' -f ([DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')), $Server, $Tag)
}

function Get-ServerName {
  param($Cfg)
  $s = [string](Get-Prop $Cfg 'ServerName' '')
  if (-not $s) { $s = $env:COMPUTERNAME }
  return ($s -replace '[^A-Za-z0-9._-]', '')
}

# ----------------------------------------------------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------------------------------------------------
if (-not $ConfigPath) { $ConfigPath = Join-Path $DataDir 'config.json' }

function Get-EffectiveConfig {
  param([bool]$AllowMissing = $false)
  $defaults = Get-DefaultConfig
  $file = Read-JsonFile -Path $ConfigPath
  if ($null -eq $file -and -not $AllowMissing) { throw "config not found or empty: $ConfigPath (run install-exchange-shipper.ps1)" }
  $cfg = [ordered]@{}
  foreach ($k in $defaults.Keys) { $cfg[$k] = Get-Prop $file $k $defaults[$k] }
  if ([string]::IsNullOrWhiteSpace($cfg.TokenFile)) { $cfg.TokenFile = Join-Path $DataDir 'token.txt' }
  $u = [string]$cfg.CollectorUrl
  if (-not $u.StartsWith('https://', [StringComparison]::OrdinalIgnoreCase)) {
    $plainOk = $false
    if ([bool]$cfg.TestPlainHttp -and $u.StartsWith('http://', [StringComparison]::OrdinalIgnoreCase)) {
      try { $h = ([Uri]$u).Host; $plainOk = @('127.0.0.1', 'localhost', '::1', '[::1]') -contains $h.ToLowerInvariant() } catch { $plainOk = $false }
    }
    if (-not $plainOk) { throw 'CollectorUrl must start with https:// (plain http is allowed only to 127.0.0.1/localhost with TestPlainHttp=true)' }
  }
  if ($cfg.SourceId -notmatch '^[A-Za-z0-9._-]{1,64}$') { throw 'SourceId must match [A-Za-z0-9._-]{1,64}' }
  $tp = ([string]$cfg.PinnedThumbprint) -replace '[\s:]', ''
  if ($tp -and $tp -notmatch '^([0-9A-Fa-f]{40}|[0-9A-Fa-f]{64})$') { throw 'PinnedThumbprint must be 40 (SHA-1) or 64 (SHA-256) hex characters' }
  $cfg.PinnedThumbprint = $tp.ToUpperInvariant()
  if (@('pause', 'drop-oldest') -notcontains $cfg.QueueFullPolicy) { $cfg.QueueFullPolicy = 'pause' }
  $cfg.BatchMaxLines       = [Math]::Min([Math]::Max([int]$cfg.BatchMaxLines, 1), 2000)
  $cfg.BatchMaxBytes       = [Math]::Min([Math]::Max([int]$cfg.BatchMaxBytes, 65536), 1048576)
  $cfg.MaxLineBytes        = [Math]::Min([Math]::Max([int]$cfg.MaxLineBytes, 1024), 1048576)
  $cfg.MaxReadBytesPerFile = [Math]::Max([int]$cfg.MaxReadBytesPerFile, [int]$cfg.MaxLineBytes * 2)
  $cfg.ExchangeInstallPath = Get-ExchangeInstallPath -Configured ([string]$cfg.ExchangeInstallPath)
  $cfg.Sources = @($cfg.Sources)
  $cfg.IngestUrl = $u.TrimEnd('/') + '/ingest/' + [Uri]::EscapeDataString($cfg.SourceId)
  return [pscustomobject]$cfg
}

# ----------------------------------------------------------------------------------------------------------------
# Dry run: print what would be sent for the newest file of every source; write nothing, send nothing
# ----------------------------------------------------------------------------------------------------------------
if ($DryRun) {
  $cfg = Get-EffectiveConfig -AllowMissing $true
  $server = Get-ServerName -Cfg $cfg
  $script:MissingExchangePath = $false
  $printed = 0
  $summary = New-Object System.Collections.Generic.List[string]
  foreach ($src in @($cfg.Sources)) {
    if (-not (Get-Prop $src 'Enabled' $true)) { continue }
    $name = [string](Get-Prop $src 'Name' 'source'); $tag = [string](Get-Prop $src 'Tag' $name)
    $files = @(Get-SourceFiles -Source $src -ExchangePath $cfg.ExchangeInstallPath -MaxAgeHours 0)
    $patterns = @(@(Get-Prop $src 'Paths' @()) | ForEach-Object { $x = Expand-LogPath -Pattern ([string]$_) -ExchangePath $cfg.ExchangeInstallPath; if ($x) { $x } else { "$_ (ExchangeInstallPath unknown)" } })
    if ($files.Count -eq 0) { $summary.Add("# dry-run: source '$name' ($tag-$server): no files found for " + ($patterns -join ' | ')); continue }
    $newest = $files | Sort-Object LastWriteTimeUtc | Select-Object -Last 1
    $total = [long]0; foreach ($f in $files) { $total += $f.Length }
    $summary.Add(("# dry-run: source '{0}' ({1}-{2}): {3} file(s), {4} KB, newest {5}" -f $name, $tag, $server, $files.Count, [Math]::Round($total / 1KB), $newest.FullName))
    if ($Count -le 0) { continue }
    $prefix = Get-LinePrefix -Tag $tag -Server $server
    $hdr = Get-FileHeader -Path $newest.FullName
    $start = [Math]::Max([long]0, $newest.Length - 1048576)
    $r = Read-FileLines -Path $newest.FullName -Offset $start -MaxBytes 1048576 -MaxLineBytes ([int]$cfg.MaxLineBytes)
    $data = New-Object System.Collections.Generic.List[string]
    foreach ($l in $r.Lines) {
      $t = [string]$l.Text
      if ($t.StartsWith('#')) { if ($t.StartsWith('#Fields:', [StringComparison]::OrdinalIgnoreCase)) { $hdr = $t }; continue }
      $data.Add($t)
    }
    if ($start -gt 0 -and $data.Count -gt 0) { $data.RemoveAt(0) }   # the first line of a window that starts mid-file is partial
    $skip = [Math]::Max(0, $data.Count - $Count)
    if ($hdr) { Write-Output ($prefix + $hdr); $printed++ }
    for ($i = $skip; $i -lt $data.Count; $i++) { Write-Output ($prefix + $data[$i]); $printed++ }
  }
  if ($script:MissingExchangePath) { $summary.Add('# dry-run: ExchangeInstallPath not found (env var / registry) - set "ExchangeInstallPath" in config.json') }
  foreach ($s in $summary) { [Console]::Error.WriteLine($s) }
  [Console]::Error.WriteLine("# dry-run: $printed line(s) printed (header + last $Count data lines per source) - nothing was sent, no bookmarks touched")
  return
}

# ----------------------------------------------------------------------------------------------------------------
# Real run: state, transport
# ----------------------------------------------------------------------------------------------------------------
$QueueDir     = Join-Path $DataDir 'queue'
$RejectDir    = Join-Path $QueueDir 'rejected'
$LogDir       = Join-Path $DataDir 'logs'
$BookmarkPath = Join-Path $DataDir 'bookmarks.json'
$StatePath    = Join-Path $DataDir 'state.json'
foreach ($d in @($DataDir, $QueueDir, $RejectDir, $LogDir)) { if (-not (Test-Path -LiteralPath $d)) { [void](New-Item -ItemType Directory -Path $d -Force) } }
$script:LogFile = Join-Path $LogDir 'shipper.log'

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
    $req.UserAgent = "SentraExchangeShipper/$ShipperVersion"
    $req.Timeout = [int]$cfg.HttpTimeoutSeconds * 1000
    $req.ReadWriteTimeout = [int]$cfg.HttpTimeoutSeconds * 1000
    $req.KeepAlive = $true
    $req.AllowAutoRedirect = $false
    $req.Headers.Add('Content-Encoding', 'gzip')
    $req.Headers.Add('X-Sentra-Token', $script:Token)
    $req.Headers.Add('X-Sentra-Batch-Id', $BatchId)
    $req.Headers.Add('X-Sentra-Agent', "exchange-shipper/$ShipperVersion;$env:COMPUTERNAME")
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
      Write-AgentLog 'WARN' 'queue full - pausing collection (lines remain in the log files)'
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
                   sent_batches = 0; sent_lines = 0; dropped_batches = 0; queue_full_since = ''; sent_headers = $null }
  foreach ($k in @($h.Keys)) { $h[$k] = Get-Prop $s $k $h[$k] }
  foreach ($k in @('last_heartbeat', 'last_success', 'next_attempt', 'queue_full_since')) {
    $d = ConvertTo-UtcDate $h[$k]
    if ($null -eq $d) { $h[$k] = '' } else { $h[$k] = $d.ToString('o') }
  }
  # sent_headers: tag -> last #Fields line sent (only meaningful when HeaderEveryBatch is off)
  $sh = [ordered]@{}
  $raw = $h['sent_headers']
  if ($null -ne $raw) { foreach ($p in $raw.PSObject.Properties) { $sh[$p.Name] = [string]$p.Value } }
  $h['sent_headers'] = $sh
  return $h
}
function Save-State { Write-FileAtomic -Path $StatePath -Content ($script:State | ConvertTo-Json -Depth 4) }

function Get-Bookmarks {
  # path (lower case) -> [ordered]@{ offset = <long>; header = <#Fields line or ''> }
  $b = Read-JsonFile -Path $BookmarkPath
  $h = @{}
  if ($null -ne $b) {
    foreach ($p in $b.PSObject.Properties) {
      $h[$p.Name] = [ordered]@{ offset = [long](Get-Prop $p.Value 'offset' 0); header = [string](Get-Prop $p.Value 'header' '') }
    }
  }
  return $h
}
function Save-Bookmarks {
  $o = [ordered]@{}
  foreach ($k in @($script:Bm.Keys | Sort-Object)) { $o[$k] = $script:Bm[$k] }
  Write-FileAtomic -Path $BookmarkPath -Content (([pscustomobject]$o) | ConvertTo-Json -Depth 3)
}

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
        $script:State.sent_lines = [long]$script:State.sent_lines + $script:Batch.Count
      } elseif ($r -eq 'reject') {
        [System.IO.File]::WriteAllBytes((Join-Path $RejectDir (New-QueueName -BatchId $id)), $gz); $ok = $true
      } else { $script:CollectorUp = $false }
    }
    if (-not $ok) { $ok = Add-ToQueue -GzBody $gz -BatchId $id }
    if (-not $ok) { return $false }
    $script:PassLines += $script:Batch.Count
    $script:Batch.Clear()
    $script:BatchBytes = 0
    # next batch starts with the headers again (engine restarts lose the header memory; the cost is one short line)
    if ([bool]$script:Cfg.HeaderEveryBatch) { $script:StreamHeader = @{} }
  }
  foreach ($k in @($script:LastRead.Keys)) { $script:Bm[$k] = $script:LastRead[$k] }
  Save-Bookmarks
  if (-not [bool]$script:Cfg.HeaderEveryBatch) {
    $sh = [ordered]@{}
    foreach ($k in @($script:StreamHeader.Keys | Sort-Object)) { $sh[$k] = $script:StreamHeader[$k] }
    $script:State.sent_headers = $sh
    Save-State
  }
  return $true
}

function Add-BatchLine {
  param([string]$Line)
  $n = $Utf8NoBom.GetByteCount($Line) + 1
  if ($script:Batch.Count -gt 0 -and (($script:BatchBytes + $n) -gt $script:Cfg.BatchMaxBytes -or $script:Batch.Count -ge $script:Cfg.BatchMaxLines)) {
    if (-not (Invoke-Flush)) { return $false }
  }
  $script:Batch.Add($Line)
  $script:BatchBytes += $n
  return $true
}

function Add-DataLine {
  # A data line of stream $Tag whose file currently has header $Header: the header goes first whenever it differs
  # from the last one sent on that stream (and once per batch by default). Header + line never straddle a batch.
  param([string]$Tag, [string]$Header, [string]$Prefix, [string]$Line)
  $needHdr = ($Header -ne '') -and (-not $script:StreamHeader.ContainsKey($Tag) -or $script:StreamHeader[$Tag] -ne $Header)
  $n = $Utf8NoBom.GetByteCount($Prefix + $Line) + 1; $cnt = 1
  if ($needHdr) { $n += $Utf8NoBom.GetByteCount($Prefix + $Header) + 1; $cnt = 2 }
  if ($script:Batch.Count -gt 0 -and (($script:BatchBytes + $n) -gt $script:Cfg.BatchMaxBytes -or ($script:Batch.Count + $cnt) -gt $script:Cfg.BatchMaxLines)) {
    # flush here (not inside Add-BatchLine) so that the header decision is taken for the batch the line lands in
    if (-not (Invoke-Flush)) { return $false }
    $needHdr = ($Header -ne '') -and (-not $script:StreamHeader.ContainsKey($Tag) -or $script:StreamHeader[$Tag] -ne $Header)
  }
  if ($needHdr) {
    if (-not (Add-BatchLine ($Prefix + $Header))) { return $false }
    $script:StreamHeader[$Tag] = $Header
  }
  return (Add-BatchLine ($Prefix + $Line))
}

# ----------------------------------------------------------------------------------------------------------------
# One pass
# ----------------------------------------------------------------------------------------------------------------
function Invoke-ShipperPass {
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
  $script:MissingExchangePath = $false
  $script:Batch = New-Object System.Collections.Generic.List[string]
  $script:BatchBytes = 0
  $script:PassLines = 0
  $script:LastRead = @{}          # file key -> @{offset; header} covering everything read so far (sent or queued on flush)
  $script:StreamHeader = @{}      # tag -> header last emitted
  if (-not [bool]$cfg.HeaderEveryBatch) { foreach ($k in @($script:State.sent_headers.Keys)) { $script:StreamHeader[$k] = [string]$script:State.sent_headers[$k] } }
  $firstRun = -not (Test-Path -LiteralPath $BookmarkPath)
  $script:Bm = Get-Bookmarks
  $server = Get-ServerName -Cfg $cfg
  $now = [DateTime]::UtcNow

  # Persisted back-off: after a failure, the collector is only contacted again once next_attempt has passed.
  $script:CollectorUp = $true
  $na = ConvertTo-UtcDate $script:State.next_attempt
  if ($null -ne $na -and $now -lt $na) { $script:CollectorUp = $false }
  if ($script:CollectorUp) { $script:CollectorUp = Clear-Queue }

  # Heartbeat (same JSON shape as the Windows agent's heartbeat; parsed by the engine's windows parser)
  $lh = ConvertTo-UtcDate $script:State.last_heartbeat
  if ($null -eq $lh -or ($now - $lh).TotalMinutes -ge [double]$cfg.HeartbeatMinutes) {
    $hb = [ordered]@{
      Channel = 'SentraExchangeShipper'; EventID = 0; TimeCreated = $now.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
      Computer = (Get-HostFqdn); RecordId = 0; Level = 4; ProviderName = 'SentraExchangeShipper'
      EventData = [ordered]@{
        type = 'heartbeat'; agent_version = $ShipperVersion; source_id = $cfg.SourceId; server = $server
        os = [Environment]::OSVersion.VersionString; ps_version = $PSVersionTable.PSVersion.ToString()
        queue_files = [string]@(Get-QueueFiles).Count; queue_bytes = [string](Get-QueueBytes)
        queue_full_since = [string]$script:State.queue_full_since
        last_success = [string]$script:State.last_success; sent_lines_total = [string]$script:State.sent_lines
        dropped_batches_total = [string]$script:State.dropped_batches
        files_tracked = [string]$script:Bm.Count
      }
      Message = 'SentraExchangeShipper heartbeat'
    }
    [void](Add-BatchLine (ConvertTo-JsonLine $hb))
    $script:State.last_heartbeat = $now.ToString('o')
  }

  $aborted = $false
  if (-not $script:CollectorUp -and $cfg.QueueFullPolicy -eq 'pause' -and ((Get-QueueBytes) -ge ([long]$cfg.QueueMaxMB * 1MB - $cfg.BatchMaxBytes))) {
    Write-AgentLog 'WARN' 'collector unreachable and queue full - collection paused this pass (lines stay in the log files)'
    $script:QueueFull = $true
    $aborted = $true
  }

  $seenKeys = @{}
  $dataLines = 0
  if (-not $aborted) {
    foreach ($src in @($cfg.Sources)) {
      if (-not (Get-Prop $src 'Enabled' $true)) { continue }
      $name = [string](Get-Prop $src 'Name' 'source')
      $tag = [string](Get-Prop $src 'Tag' $name)
      $prefix = Get-LinePrefix -Tag $tag -Server $server
      $files = @(Get-SourceFiles -Source $src -ExchangePath $cfg.ExchangeInstallPath -MaxAgeHours ([int]$cfg.MaxFileAgeHours))
      foreach ($f in $files) {
        $key = $f.FullName.ToLowerInvariant()
        $seenKeys[$key] = $true
        $offset = [long]0; $header = ''
        if ($script:Bm.ContainsKey($key)) {
          $offset = [long]$script:Bm[$key].offset; $header = [string]$script:Bm[$key].header
        } elseif ($firstRun -and [int]$cfg.FirstRunLookbackMinutes -gt 0 -and $f.LastWriteTimeUtc -lt $now.AddMinutes(-1 * [int]$cfg.FirstRunLookbackMinutes)) {
          # first start: an old file is not replayed - remember its end and its header
          $script:LastRead[$key] = [ordered]@{ offset = [long]$f.Length; header = (Get-FileHeader -Path $f.FullName) }
          Write-AgentLog 'INFO' "first run: starting at the end of $($f.FullName) ($($f.Length) bytes)"
          continue
        } else {
          Write-AgentLog 'INFO' "new file: $($f.FullName)"
        }
        if (-not $header -and $offset -gt 0) { $header = Get-FileHeader -Path $f.FullName }

        try {
          $r = Read-FileLines -Path $f.FullName -Offset $offset -MaxBytes ([int]$cfg.MaxReadBytesPerFile) -MaxLineBytes ([int]$cfg.MaxLineBytes)
          if ($r.Truncated) {
            Write-AgentLog 'WARN' "file $($f.Name) is shorter than its bookmark ($($r.Length) < $offset) - truncated or rolled in place, re-reading from the start"
            $offset = 0; $header = ''
            $script:LastRead[$key] = [ordered]@{ offset = [long]0; header = '' }
            $r = Read-FileLines -Path $f.FullName -Offset 0 -MaxBytes ([int]$cfg.MaxReadBytesPerFile) -MaxLineBytes ([int]$cfg.MaxLineBytes)
          }
          if ($r.Skipped -gt 0) { Write-AgentLog 'WARN' "file $($f.Name): skipped $($r.Skipped) byte(s) of over-long line(s)" }
          if ($r.Offset -ne $offset -and $r.Lines.Count -eq 0) { $script:LastRead[$key] = [ordered]@{ offset = [long]$r.Offset; header = $header } }
          foreach ($l in $r.Lines) {
            $t = [string]$l.Text
            if ($t[0] -eq '#') {
              if ($t.StartsWith('#Fields:', [StringComparison]::OrdinalIgnoreCase)) {
                if ($t -ne $header) { Write-AgentLog 'INFO' "file $($f.Name): header is now '$t'" }
                $header = $t
              }
              $script:LastRead[$key] = [ordered]@{ offset = [long]$l.End; header = $header }
              continue
            }
            if (-not (Add-DataLine -Tag $tag -Header $header -Prefix $prefix -Line $t)) { $aborted = $true; break }
            $script:LastRead[$key] = [ordered]@{ offset = [long]$l.End; header = $header }
            $dataLines++
            if ($dataLines -ge [int]$cfg.MaxLinesPerPass) { break }
          }
          if ($r.Offset -lt $r.Length -and -not $aborted) { $script:Backlog = $true }
        } catch {
          Write-AgentLog 'WARN' "reading $($f.FullName) failed: $($_.Exception.Message)"
        }
        if ($aborted) { break }
        if ($dataLines -ge [int]$cfg.MaxLinesPerPass) { Write-AgentLog 'INFO' 'line limit for this pass reached, continuing next pass'; $script:Backlog = $true; break }
      }
      if ($aborted -or $dataLines -ge [int]$cfg.MaxLinesPerPass) { break }
    }
  }
  if ($script:MissingExchangePath) { Write-AgentLog 'WARN' 'ExchangeInstallPath not found (env var / registry) - message tracking paths skipped; set "ExchangeInstallPath" in config.json' }

  if (-not $aborted) { $aborted = -not (Invoke-Flush) }
  if ($aborted -and $script:Batch.Count -gt 0) { Write-AgentLog 'WARN' "pass stopped with $($script:Batch.Count) line(s) not yet durable; they are re-read next pass" }

  # forget bookmarks of files that are gone (rotation cleanup) - only after a successful commit
  if (-not $aborted) {
    $gone = @()
    foreach ($k in @($script:Bm.Keys)) { if (-not $seenKeys.ContainsKey($k) -and -not (Test-Path -LiteralPath $k)) { $gone += $k } }
    if ($gone.Count -gt 0) { foreach ($k in $gone) { $script:Bm.Remove($k) }; Save-Bookmarks; Write-AgentLog 'INFO' "forgot $($gone.Count) bookmark(s) of deleted file(s)" }
  }

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
  Write-AgentLog 'INFO' ("pass done: {0} line(s) shipped or queued, collector {1}, queue {2} file(s), {3} file(s) tracked" -f $script:PassLines, $cs, @(Get-QueueFiles).Count, $script:Bm.Count)
}

# ----------------------------------------------------------------------------------------------------------------
# Main: single instance via a global mutex
# ----------------------------------------------------------------------------------------------------------------
$mutex = New-Object System.Threading.Mutex($false, 'Global\SentraExchangeShipper')
$owned = $false
try {
  try { $owned = $mutex.WaitOne(0) } catch { if (Get-InnerException -Exception $_.Exception -Type ([System.Threading.AbandonedMutexException])) { $owned = $true } else { throw } }
  if (-not $owned) { Write-AgentLog 'DEBUG' 'another instance is running - exiting'; return }
  do {
    $script:Backlog = $false
    try { Invoke-ShipperPass }
    catch { Write-AgentLog 'ERROR' ("pass failed: {0} (line {1})" -f $_.Exception.Message, $_.InvocationInfo.ScriptLineNumber) }
    if ($Loop -and -not $script:Backlog) { Start-Sleep -Seconds ([Math]::Max($LoopSeconds, 5)) }
  } while ($Loop)
} finally {
  if ($owned) { $mutex.ReleaseMutex() }
  $mutex.Dispose()
}
