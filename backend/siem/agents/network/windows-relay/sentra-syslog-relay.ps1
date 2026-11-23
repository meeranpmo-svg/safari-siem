# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
<#
  sentra-syslog-relay.ps1 - syslog collector + forwarder for Windows.

  Receives syslog from network devices (FortiGate, Cisco, ...) on the LAN and
    1. appends every line to a rotating daily file   (so logs are visible on the spot), and
    2. optionally forwards them to the SIEM over HTTPS, reusing the SentraAgent contract:
       gzip NDJSON -> POST https://<collector>/ingest/<src_id>, X-Sentra-Token, X-Sentra-Batch-Id, disk queue + back-off.

  Raw syslog lines are what the engine wants: http-ingest passes each line to parser.parse() with the
  src_type of the registered source, so a source registered as {"type":"fortigate"} is parsed by the
  FortiGate parser. No engine change needed.

  Plain PowerShell 5.1 + .NET. No modules, no binaries.

  TCP framing matches engine/collect/syslog.js createFramer: mode is decided on the first frame of a
  connection - "octet" (RFC 6587, what FortiOS 'set mode reliable' sends) if it starts with <digits><space><,
  otherwise LF.
#>
[CmdletBinding()]
param(
  [string]   $ConfigPath = "$env:ProgramData\SentraSyslogRelay\config.json",
  [string]   $ListenIp,
  [int]      $Port,
  [string[]] $AllowFrom,                 # source IPs allowed to send; empty = accept any (not recommended)
  [switch]   $Tail,                      # also echo every line to the console (live view)
  [switch]   $NoForward,                 # capture to file only
  [switch]   $PrintDefaultConfig
)

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$DEFAULTS = [ordered]@{
  listen_ip       = '0.0.0.0'
  port            = 5514
  allow_from      = @()
  log_dir         = "$env:ProgramData\SentraSyslogRelay\logs"
  queue_dir       = "$env:ProgramData\SentraSyslogRelay\queue"
  keep_days       = 14
  max_line        = 16384
  forward         = $false
  collector_url   = 'https://siem.example.local'
  src_id          = 'fw-hq-01'
  token           = ''
  max_batch       = 2000
  max_batch_bytes = 1048576
  flush_seconds   = 5
  queue_max_mb    = 200
  pinned_thumbprint = ''   # optional SHA-1 (40 hex) or SHA-256 (64 hex) of the collector certificate
}

if ($PrintDefaultConfig) { ($DEFAULTS | ConvertTo-Json -Depth 4); return }

# ---------- config ----------
$cfg = $DEFAULTS.Clone()
if (Test-Path -LiteralPath $ConfigPath) {
  $onDisk = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
  foreach ($k in @($cfg.Keys)) { if ($null -ne $onDisk.$k) { $cfg[$k] = $onDisk.$k } }
}
if ($PSBoundParameters.ContainsKey('ListenIp'))  { $cfg.listen_ip  = $ListenIp }
if ($PSBoundParameters.ContainsKey('Port'))      { $cfg.port       = $Port }
if ($PSBoundParameters.ContainsKey('AllowFrom')) { $cfg.allow_from = $AllowFrom }
if ($NoForward) { $cfg.forward = $false }

foreach ($d in @($cfg.log_dir, $cfg.queue_dir)) {
  if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Force -Path $d | Out-Null }
}

$allow = @{}
foreach ($a in @($cfg.allow_from)) { if ($a) { $allow[[string]$a] = $true } }
$allowAll = ($allow.Count -eq 0)
if ($cfg.forward -and -not $cfg.token) { throw 'forward is enabled but no token is set (see install-relay.ps1 -TokenFile)' }
if ($cfg.forward -and -not ([string]$cfg.collector_url).StartsWith('https://', [StringComparison]::OrdinalIgnoreCase)) { throw 'collector_url must start with https://' }
$pin = ([string]$cfg.pinned_thumbprint) -replace '[\s:]', ''
if ($pin -and $pin -notmatch '^([0-9A-Fa-f]{40}|[0-9A-Fa-f]{64})$') { throw 'pinned_thumbprint must be 40 (SHA-1) or 64 (SHA-256) hex characters' }
# TLS certificate validation is always on; an optional pin additionally requires the collector's exact certificate
if ($pin) {
  Add-Type -TypeDefinition @'
using System;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
namespace SentraRelay {
  public static class CertPin {
    public static string Expected = "";
    public static bool Validate(object sender, X509Certificate cert, X509Chain chain, SslPolicyErrors errors) {
      if (errors != SslPolicyErrors.None || cert == null) return false;
      string sha1 = cert.GetCertHashString();
      string sha256;
      using (SHA256 h = SHA256.Create()) { sha256 = BitConverter.ToString(h.ComputeHash(cert.GetRawCertData())).Replace("-", ""); }
      return String.Equals(Expected, sha1, StringComparison.OrdinalIgnoreCase) || String.Equals(Expected, sha256, StringComparison.OrdinalIgnoreCase);
    }
    public static RemoteCertificateValidationCallback Callback() { return new RemoteCertificateValidationCallback(Validate); }
  }
}
'@
  [SentraRelay.CertPin]::Expected = $pin.ToUpperInvariant()
}

function Write-Note($msg) { Write-Host ("[{0}] {1}" -f (Get-Date -Format 'HH:mm:ss'), $msg) }

# ---------- TCP framer (mirrors engine/collect/syslog.js createFramer) ----------
function New-Framer {
  param([int]$MaxLine)
  [pscustomobject]@{ Buf = [byte[]]@(); Mode = $null; MaxLine = $MaxLine }
}

function Read-Frames {
  param($Framer, [byte[]]$Chunk)
  $out = New-Object System.Collections.Generic.List[string]
  # cast is deliberate: in PowerShell byte[] + byte[] yields Object[], which does not bind cleanly
  # to Encoding.GetString(byte[], int, int).
  $Framer.Buf = [byte[]]($Framer.Buf + $Chunk)
  while ($true) {
    $b = $Framer.Buf
    if ($b.Length -eq 0) { break }

    if ($null -eq $Framer.Mode) {
      $i = 0
      while ($i -lt $b.Length -and $b[$i] -ge 0x30 -and $b[$i] -le 0x39) { $i++ }
      if ($i -gt 0 -and $i -lt $b.Length -and $b[$i] -eq 0x20) {
        if ($i + 1 -ge $b.Length) { break }                       # need one more byte to decide
        if ($b[$i + 1] -eq 0x3c) { $Framer.Mode = 'octet' } else { $Framer.Mode = 'lf' }
      }
      elseif ($i -ge $b.Length) { break }                         # all digits so far, undecided
      else { $Framer.Mode = 'lf' }
    }

    if ($Framer.Mode -eq 'octet') {
      $i = 0
      while ($i -lt $b.Length -and $b[$i] -ge 0x30 -and $b[$i] -le 0x39) { $i++ }
      if ($i -eq 0) { $Framer.Mode = 'lf'; continue }              # not octet after all
      if ($i -ge $b.Length -or $b[$i] -ne 0x20) { break }          # length prefix incomplete
      $len = [int]([System.Text.Encoding]::ASCII.GetString($b, 0, $i))
      if ($len -le 0 -or $len -gt $Framer.MaxLine) { $Framer.Mode = 'lf'; continue }
      $start = $i + 1
      if ($b.Length - $start -lt $len) { break }                   # frame incomplete
      $out.Add([System.Text.Encoding]::UTF8.GetString($b, $start, $len))
      $rest = $start + $len
      if ($rest -lt $b.Length) { $Framer.Buf = $b[$rest..($b.Length - 1)] } else { $Framer.Buf = [byte[]]@() }
    }
    else {
      $nl = [Array]::IndexOf($b, [byte]0x0A)
      if ($nl -lt 0) {
        if ($b.Length -gt $Framer.MaxLine * 2) { $Framer.Buf = [byte[]]@() }   # runaway line, drop
        break
      }
      $end = $nl
      if ($end -gt 0 -and $b[$end - 1] -eq 0x0D) { $end-- }
      if ($end -gt 0) { $out.Add([System.Text.Encoding]::UTF8.GetString($b, 0, [Math]::Min($end, $Framer.MaxLine))) }
      if (($nl + 1) -lt $b.Length) { $Framer.Buf = $b[($nl + 1)..($b.Length - 1)] } else { $Framer.Buf = [byte[]]@() }
    }
  }
  return $out
}

# ---------- sinks ----------
function Add-ToDailyFile {
  param([string[]]$Lines)
  $path = Join-Path $cfg.log_dir ("syslog-{0}.log" -f (Get-Date -Format 'yyyyMMdd'))
  [System.IO.File]::AppendAllLines($path, [string[]]$Lines, [System.Text.Encoding]::UTF8)
}

function Remove-OldFiles {
  $cut = (Get-Date).AddDays(-[int]$cfg.keep_days)
  Get-ChildItem -LiteralPath $cfg.log_dir -Filter 'syslog-*.log' -ErrorAction SilentlyContinue |
    Where-Object { $_.LastWriteTime -lt $cut } |
    Remove-Item -Force -ErrorAction SilentlyContinue
}

function Compress-Bytes {
  param([byte[]]$Raw)
  $ms = New-Object System.IO.MemoryStream
  $gz = New-Object System.IO.Compression.GZipStream($ms, [System.IO.Compression.CompressionMode]::Compress, $true)
  $gz.Write($Raw, 0, $Raw.Length)
  $gz.Dispose()
  $bytes = $ms.ToArray()
  $ms.Dispose()
  return $bytes
}

function Send-Batch {
  param([byte[]]$Gzip, [string]$BatchId)
  $url = ($cfg.collector_url.TrimEnd('/')) + '/ingest/' + $cfg.src_id
  $req = [System.Net.HttpWebRequest]::Create($url)
  $req.Method           = 'POST'
  $req.ContentType      = 'application/x-ndjson'
  $req.Timeout          = 30000
  $req.ReadWriteTimeout = 30000
  $req.Headers.Add('Content-Encoding', 'gzip')
  $req.Headers.Add('X-Sentra-Token', [string]$cfg.token)
  $req.Headers.Add('X-Sentra-Batch-Id', $BatchId)
  $req.AllowAutoRedirect = $false
  if ($pin) { $req.ServerCertificateValidationCallback = [SentraRelay.CertPin]::Callback() }
  $s = $req.GetRequestStream()
  $s.Write($Gzip, 0, $Gzip.Length)
  $s.Dispose()
  $resp = $req.GetResponse()
  $code = [int]$resp.StatusCode
  $resp.Dispose()
  return $code
}

function Save-ToQueue {
  param([byte[]]$Gzip, [string]$BatchId)
  $used = (Get-ChildItem -LiteralPath $cfg.queue_dir -Filter '*.ndjson.gz' -ErrorAction SilentlyContinue |
            Measure-Object -Property Length -Sum).Sum
  if ($used -ge ([int]$cfg.queue_max_mb * 1MB)) { Write-Note 'queue full - batch dropped'; return }
  $name = '{0:yyyyMMddHHmmssfff}-{1}.ndjson.gz' -f (Get-Date), $BatchId
  [System.IO.File]::WriteAllBytes((Join-Path $cfg.queue_dir $name), $Gzip)
}

function Resume-Queue {
  $files = Get-ChildItem -LiteralPath $cfg.queue_dir -Filter '*.ndjson.gz' -ErrorAction SilentlyContinue |
             Sort-Object Name | Select-Object -First 20
  foreach ($f in $files) {
    $id = ($f.BaseName -split '-', 2)[1]
    if (-not $id) { $id = [guid]::NewGuid().ToString('N') }
    try {
      Send-Batch -Gzip ([System.IO.File]::ReadAllBytes($f.FullName)) -BatchId $id | Out-Null
      Remove-Item -LiteralPath $f.FullName -Force
    }
    catch { return $false }
  }
  return $true
}

# ---------- listeners ----------
$udp = New-Object System.Net.Sockets.UdpClient
$udp.Client.ExclusiveAddressUse = $false
$udp.Client.ReceiveBufferSize = 8MB
$udp.Client.Bind((New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Parse($cfg.listen_ip), [int]$cfg.port)))

$tcp = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Parse($cfg.listen_ip), [int]$cfg.port)
$tcp.Start()

$target = 'off'
if ($cfg.forward) { $target = ($cfg.collector_url.TrimEnd('/')) + '/ingest/' + $cfg.src_id }
Write-Note ("listening on {0}:{1} (UDP+TCP) - files {2} - forward {3}" -f $cfg.listen_ip, $cfg.port, $cfg.log_dir, $target)
if (-not $allowAll) { Write-Note ("accepting only from: " + ($allow.Keys -join ', ')) }

$clients   = New-Object System.Collections.ArrayList
$batch     = New-Object System.Collections.Generic.List[string]
$bytes     = 0
$lastFlush = Get-Date
$lastPrune = Get-Date
$nextTry   = Get-Date
$backoff   = 0
$total     = 0
$anyEP     = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)

function Flush-Batch {
  if ($batch.Count -eq 0) { return }
  $lines = $batch.ToArray()
  $batch.Clear()
  $script:bytes = 0
  $script:lastFlush = Get-Date

  try { Add-ToDailyFile -Lines $lines } catch { Write-Note ("file sink failed: " + $_.Exception.Message) }
  if (-not $cfg.forward) { return }

  $gz = Compress-Bytes ([System.Text.Encoding]::UTF8.GetBytes(($lines -join "`n") + "`n"))
  $id = [guid]::NewGuid().ToString('N')
  if ((Get-Date) -lt $script:nextTry) { Save-ToQueue -Gzip $gz -BatchId $id; return }
  try {
    Send-Batch -Gzip $gz -BatchId $id | Out-Null
    $script:backoff = 0
    Resume-Queue | Out-Null
  }
  catch {
    if ($script:backoff -eq 0) { $script:backoff = 60 } else { $script:backoff = [Math]::Min($script:backoff * 2, 900) }
    $script:nextTry = (Get-Date).AddSeconds($script:backoff)
    Write-Note ("forward failed ({0}) - queueing, retry in {1}s" -f $_.Exception.Message, $script:backoff)
    Save-ToQueue -Gzip $gz -BatchId $id
  }
}

function Add-Lines {
  param([string[]]$Lines, [string]$PeerIp)
  foreach ($l in $Lines) {
    if (-not $l) { continue }
    $script:total++
    $batch.Add($l) | Out-Null
    $script:bytes += $l.Length
    if ($Tail) { Write-Host ("{0,-15} {1}" -f $PeerIp, $l) }
  }
}

try {
  while ($true) {
    $did = $false

    while ($udp.Available -gt 0) {
      $data = $udp.Receive([ref]$anyEP)
      $peer = $anyEP.Address.ToString()
      if ($allowAll -or $allow.ContainsKey($peer)) {
        $txt = [System.Text.Encoding]::UTF8.GetString($data)
        Add-Lines -Lines ($txt -split "`n" | ForEach-Object { $_.TrimEnd("`r") }) -PeerIp $peer
      }
      $did = $true
    }

    while ($tcp.Pending()) {
      $c = $tcp.AcceptTcpClient()
      $peer = ([System.Net.IPEndPoint]$c.Client.RemoteEndPoint).Address.ToString()
      if (-not ($allowAll -or $allow.ContainsKey($peer))) { $c.Close(); continue }
      $c.ReceiveBufferSize = 1MB
      $clients.Add([pscustomobject]@{
        Client = $c; Stream = $c.GetStream(); Peer = $peer
        Framer = (New-Framer -MaxLine ([int]$cfg.max_line))
      }) | Out-Null
      Write-Note "tcp connect from $peer"
      $did = $true
    }

    foreach ($e in @($clients)) {
      try {
        if (-not $e.Client.Connected) { throw 'closed' }
        $avail = $e.Client.Available
        if ($avail -gt 0) {
          $buf = New-Object byte[] $avail
          $n = $e.Stream.Read($buf, 0, $avail)
          if ($n -le 0) { throw 'eof' }
          if ($n -lt $avail) { $buf = $buf[0..($n - 1)] }
          Add-Lines -Lines (Read-Frames -Framer $e.Framer -Chunk $buf) -PeerIp $e.Peer
          $did = $true
        }
      }
      catch {
        try { $e.Stream.Dispose(); $e.Client.Close() } catch {}
        $clients.Remove($e)
        Write-Note ("tcp disconnect " + $e.Peer)
      }
    }

    if ($batch.Count -ge [int]$cfg.max_batch -or
        $bytes -ge [int]$cfg.max_batch_bytes -or
        ((Get-Date) - $lastFlush).TotalSeconds -ge [int]$cfg.flush_seconds) { Flush-Batch }

    if (((Get-Date) - $lastPrune).TotalHours -ge 6) { Remove-OldFiles; $lastPrune = Get-Date }
    if (-not $did) { Start-Sleep -Milliseconds 50 }
  }
}
finally {
  Flush-Batch
  foreach ($e in @($clients)) { try { $e.Client.Close() } catch {} }
  try { $tcp.Stop(); $udp.Close() } catch {}
  Write-Note ("stopped - {0} lines handled" -f $total)
}
