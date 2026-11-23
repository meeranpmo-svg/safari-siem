# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
# Helpers for run-tests.ps1 (dot-sourced): assertions, loopback HTTP listener, shipper runner, fixture writers.
# Windows PowerShell 5.1, no modules.

$script:Pass = 0; $script:Fail = 0; $script:Failures = New-Object System.Collections.Generic.List[string]
$Utf8NoBom = New-Object System.Text.UTF8Encoding($false)

function Assert-True { param([bool]$Cond, [string]$What)
  if ($Cond) { $script:Pass++; Write-Host "  ok    $What" }
  else { $script:Fail++; $script:Failures.Add($What); Write-Host "  FAIL  $What" -ForegroundColor Red }
}
function Assert-Eq { param($Actual, $Expected, [string]$What)
  $ok = ("$Actual" -eq "$Expected")
  $txt = $What; if (-not $ok) { $txt = "$What (expected '$Expected', got '$Actual')" }
  Assert-True -Cond $ok -What $txt
}

# ---------------------------------------------------------------------------------------------------- listener
# System.Net.HttpListener on 127.0.0.1:<free port>. Requests are pumped from the test thread while the shipper
# (a child process) runs. Each received batch: @{ Id; Token; Agent; Encoding; Lines }.
$script:Listener = $null; $script:Pending = $null; $script:Port = 0
$script:Received = New-Object System.Collections.Generic.List[object]
$script:Mode = 'ok'            # ok | 401 | 503

function Get-FreePort {
  $l = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 0)
  $l.Start(); $p = ([System.Net.IPEndPoint]$l.LocalEndpoint).Port; $l.Stop(); return $p
}
function Start-Listener {
  if ($script:Port -eq 0) { $script:Port = Get-FreePort }
  $script:Listener = New-Object System.Net.HttpListener
  $script:Listener.Prefixes.Add("http://127.0.0.1:$($script:Port)/")
  $script:Listener.Start()
  $script:Pending = $null
}
function Stop-Listener {
  if ($null -ne $script:Listener) { try { $script:Listener.Stop(); $script:Listener.Close() } catch { } }
  $script:Listener = $null; $script:Pending = $null
}
function Read-Body {
  param([System.Net.HttpListenerRequest]$Req)
  $ms = New-Object System.IO.MemoryStream
  $Req.InputStream.CopyTo($ms)
  $bytes = $ms.ToArray()
  if ($Req.Headers['Content-Encoding'] -match 'gzip') {
    $in = New-Object System.IO.MemoryStream(,$bytes)
    $gz = New-Object System.IO.Compression.GZipStream($in, [System.IO.Compression.CompressionMode]::Decompress)
    $out = New-Object System.IO.MemoryStream
    $gz.CopyTo($out); $gz.Dispose()
    $bytes = $out.ToArray()
  }
  return $Utf8NoBom.GetString($bytes)
}
function Invoke-Handle {
  param([System.Net.HttpListenerContext]$Ctx)
  $req = $Ctx.Request
  $text = Read-Body -Req $req
  $lines = @($text.Split("`n") | ForEach-Object { $_.TrimEnd("`r") } | Where-Object { $_ -ne '' })
  $script:Received.Add(@{ Id = [string]$req.Headers['X-Sentra-Batch-Id']; Token = [string]$req.Headers['X-Sentra-Token']
                          Agent = [string]$req.Headers['X-Sentra-Agent']; Encoding = [string]$req.Headers['Content-Encoding']
                          Path = $req.Url.AbsolutePath; Lines = $lines; Mode = $script:Mode })
  $resp = $Ctx.Response
  $body = '{"ok":true,"accepted":' + $lines.Count + ',"rejected":0,"errors":[]}'
  if ($script:Mode -eq '401') { $resp.StatusCode = 401; $body = '{"error":"invalid or missing X-Sentra-Token"}' }
  elseif ($script:Mode -eq '503') { $resp.StatusCode = 503; $body = '{"error":"busy"}' }
  else { $resp.StatusCode = 200 }
  $b = $Utf8NoBom.GetBytes($body)
  $resp.ContentType = 'application/json'; $resp.ContentLength64 = $b.Length
  $resp.OutputStream.Write($b, 0, $b.Length); $resp.OutputStream.Close()
}
function Pump-Listener {
  if ($null -eq $script:Listener) { return }
  try {
    if ($null -eq $script:Pending) { $script:Pending = $script:Listener.GetContextAsync() }
    if ($script:Pending.IsCompleted) {
      $t = $script:Pending; $script:Pending = $null
      if (-not $t.IsFaulted -and -not $t.IsCanceled) { Invoke-Handle -Ctx $t.Result }
    }
  } catch { $script:Pending = $null }
}

# ---------------------------------------------------------------------------------------------------- shipper
function Invoke-Shipper {
  # Runs one pass of the shipper as a child process (Windows PowerShell 5.1) while pumping the listener.
  # Returns @{ ExitCode; StdOut; StdErr }.
  param([string[]]$ExtraArgs = @())
  $out = Join-Path $script:Work ('out-{0}.txt' -f [guid]::NewGuid().ToString('N'))
  $err = Join-Path $script:Work ('err-{0}.txt' -f [guid]::NewGuid().ToString('N'))
  $args = @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $script:Shipper, '-DataDir', $script:Data) + $ExtraArgs
  $p = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -ArgumentList $args `
        -RedirectStandardOutput $out -RedirectStandardError $err -NoNewWindow -PassThru
  $null = $p.Handle    # PS 5.1: ExitCode is only populated when the handle was cached before the process exits
  while (-not $p.HasExited) { Pump-Listener; Start-Sleep -Milliseconds 20 }
  for ($i = 0; $i -lt 10; $i++) { Pump-Listener; Start-Sleep -Milliseconds 20 }
  $so = ''; $se = ''
  if (Test-Path $out) { $so = [IO.File]::ReadAllText($out) }
  if (Test-Path $err) { $se = [IO.File]::ReadAllText($err) }
  return @{ ExitCode = $p.ExitCode; StdOut = $so; StdErr = $se }
}
function Get-NewBatches {
  # Batches received since the last call.
  $n = $script:Received.Count
  $b = @(); for ($i = $script:Taken; $i -lt $n; $i++) { $b += ,$script:Received[$i] }
  $script:Taken = $n
  return ,$b
}
$script:Taken = 0

function Get-DataLines { param($Batches, [string]$Tag)
  $r = @()
  foreach ($b in @($Batches)) { foreach ($l in $b.Lines) { if ($l -match ("^<174>1 \S+ \S+ " + [regex]::Escape($Tag) + "-\S+ - - - [^#]")) { $r += $l } } }
  return ,$r
}
function Get-HeaderLines { param($Batches, [string]$Tag)
  $r = @()
  foreach ($b in @($Batches)) { foreach ($l in $b.Lines) { if ($l -match ("^<174>1 \S+ \S+ " + [regex]::Escape($Tag) + "-\S+ - - - #Fields:")) { $r += $l } } }
  return ,$r
}
function Get-Payload { param([string]$Line) return ($Line -replace '^<174>1 \S+ \S+ \S+ - - - ', '') }

# ---------------------------------------------------------------------------------------------------- files
function Add-Lines { param([string]$Path, [string[]]$Lines, [string]$Eol = "`r`n")
  $txt = ($Lines -join $Eol) + $Eol
  [IO.File]::AppendAllText($Path, $txt, $Utf8NoBom)
}
function Add-Partial { param([string]$Path, [string]$Text) [IO.File]::AppendAllText($Path, $Text, $Utf8NoBom) }
function New-MsgTrkLine { param([int]$N, [string]$EventId = 'SEND')
  return ('2026-10-07T11:{0:D2}:00.000Z,10.20.0.16,TEST-EX01,10.20.0.16,TEST-EX01,08DDSYNTH{0:D4};250 2.0.0 OK,Intra-Organization SMTP Send Connector,SMTP,{1},2000{0:D2},<append-{0:D4}@test-ex01.test.local>,bbbbcccc-0000-1111-2222-3333444400{0:D2},bob@test.local,250 2.6.0 Queued,4096,1,,,Appended line {0},alice@test.local,alice@test.local,2026-10-07T11:00:00.000Z;SRV=TEST-EX01,Originating,,10.20.0.99,,,Email,log-a{0:D4},15.02.1544.004' -f $N, $EventId)
}
function New-IisLine { param([int]$N, [string]$Extra = '')
  $l = ('2026-10-07 11:{0:D2}:00 10.20.0.16 GET /owa/appended{0} - 443 TEST\alice 203.0.113.44 Mozilla/5.0+SyntheticTest - 200 0 0 {0}' -f $N)
  if ($Extra) { $l += ' ' + $Extra }
  return $l
}
function Read-Json { param([string]$Path) return ([IO.File]::ReadAllText($Path) | ConvertFrom-Json) }
function Get-Bookmark { param([string]$Path)
  $b = Read-Json (Join-Path $script:Data 'bookmarks.json')
  $p = $b.PSObject.Properties[$Path.ToLowerInvariant()]
  if ($null -eq $p) { return $null }
  return $p.Value
}
function Set-ConfigValue { param([string]$Name, $Value)
  $c = Read-Json $script:ConfigPath
  $c | Add-Member -NotePropertyName $Name -NotePropertyValue $Value -Force
  [IO.File]::WriteAllText($script:ConfigPath, ($c | ConvertTo-Json -Depth 6), $Utf8NoBom)
}
function Clear-Backoff {
  $sp = Join-Path $script:Data 'state.json'
  if (Test-Path $sp) { $s = Read-Json $sp; $s.next_attempt = ''; [IO.File]::WriteAllText($sp, ($s | ConvertTo-Json -Depth 4), $Utf8NoBom) }
}
function Get-ShipperLog { return [IO.File]::ReadAllText((Join-Path $script:Data 'logs\shipper.log')) }
