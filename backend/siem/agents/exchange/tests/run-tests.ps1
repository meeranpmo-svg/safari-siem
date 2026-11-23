# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
<#
.SYNOPSIS
  Local tests for sentra-exchange-shipper.ps1 (Windows PowerShell 5.1, no network, no admin needed).

.DESCRIPTION
  Copies the fixtures (a message tracking file in the documented format, an IIS u_ex file) to a temp folder,
  starts a loopback HTTP listener (System.Net.HttpListener on 127.0.0.1:<free port>; plain http is accepted by the
  shipper only for loopback with TestPlainHttp=true) that gunzips every POST and records the NDJSON items, and runs
  the shipper pass by pass as a child process. Covers: first pass + raw-line shape, idle pass, append, partial line,
  truncate/roll, new file, header change (message tracking + IIS), queue-and-replay with the listener down, HTTP 401,
  HeaderEveryBatch=false, batch splitting, dry run, mutex single instance, and - when node.exe is available - the
  received lines fed through the engine parser (engine/parse).

  powershell -NoProfile -ExecutionPolicy Bypass -File tests\run-tests.ps1
#>
[CmdletBinding()]
param([switch]$KeepWork)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'test-lib.ps1')

$script:Shipper = Join-Path (Split-Path $PSScriptRoot -Parent) 'sentra-exchange-shipper.ps1'
$script:Work = Join-Path $env:TEMP ('sentra-exshipper-test-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
$script:Data = Join-Path $script:Work 'data'
$MsgDir = Join-Path $script:Work 'MessageTracking'; $IisDir1 = Join-Path $script:Work 'W3SVC1'; $IisDir2 = Join-Path $script:Work 'W3SVC2'
foreach ($d in @($script:Work, $script:Data, $MsgDir, $IisDir1, $IisDir2)) { [void](New-Item -ItemType Directory -Path $d -Force) }
Copy-Item (Join-Path $PSScriptRoot 'fixtures\MessageTracking\*') $MsgDir
Copy-Item (Join-Path $PSScriptRoot 'fixtures\W3SVC1\*') $IisDir1
# the shipper's first run only replays files written within FirstRunLookbackMinutes - make the copies "fresh"
foreach ($f in (Get-ChildItem $MsgDir, $IisDir1 -File)) { $f.LastWriteTimeUtc = [DateTime]::UtcNow }
$MsgFile = Join-Path $MsgDir 'MSGTRK2026100710-1.LOG'
$IisFile = Join-Path $IisDir1 'u_ex261007.log'
$MsgHeader = (Get-Content $MsgFile | Where-Object { $_ -like '#Fields:*' } | Select-Object -First 1)
$IisHeader = (Get-Content $IisFile | Where-Object { $_ -like '#Fields:*' } | Select-Object -First 1)
Write-Host "work dir: $($script:Work)"

Start-Listener
Write-Host "listener: http://127.0.0.1:$($script:Port)/"

# config + token (the installer normally writes these)
$script:ConfigPath = Join-Path $script:Data 'config.json'
$cfg = (& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $script:Shipper -PrintDefaultConfig | Out-String) | ConvertFrom-Json
$cfg.CollectorUrl = "http://127.0.0.1:$($script:Port)"
$cfg.SourceId = 'win-exchange-test'
$cfg.TestPlainHttp = $true
$cfg.ServerName = 'TEST-EX01'
$cfg.RetriesPerRun = 1
$cfg.HttpTimeoutSeconds = 10
$cfg.Sources[0].Paths = @((Join-Path $MsgDir 'MSGTRK*.log'), (Join-Path $MsgDir 'MSGTRKMD*.log'), (Join-Path $MsgDir 'MSGTRKMS*.log'))
$cfg.Sources[1].Paths = @((Join-Path $IisDir1 'u_ex*.log'), (Join-Path $IisDir2 'u_ex*.log'))
[IO.File]::WriteAllText($script:ConfigPath, ($cfg | ConvertTo-Json -Depth 6), $Utf8NoBom)
$Token = 'test-token-' + [guid]::NewGuid().ToString('N')
[IO.File]::WriteAllText((Join-Path $script:Data 'token.txt'), $Token, $Utf8NoBom)
$Prefix = '^<174>1 \d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z TEST-EX01 '

try {
  # ------------------------------------------------------------------------------------------------ T1 first pass
  Write-Host "`n[T1] first pass: header + 20 message tracking lines, header + 10 IIS lines, heartbeat"
  $r = Invoke-Shipper
  Assert-Eq $r.ExitCode 0 'shipper exit code 0'
  $b = Get-NewBatches
  Assert-Eq $b.Count 1 'one batch received'
  if ($b.Count -ge 1) {
    Assert-Eq $b[0].Path '/ingest/win-exchange-test' 'POST path /ingest/<src_id>'
    Assert-Eq $b[0].Token $Token 'X-Sentra-Token sent'
    Assert-True ($b[0].Id -match '^[0-9a-f]{32}$') 'X-Sentra-Batch-Id is a 32-hex id'
    Assert-Eq $b[0].Encoding 'gzip' 'Content-Encoding gzip'
    Assert-True ($b[0].Agent -like 'exchange-shipper/*') 'X-Sentra-Agent header'
    Assert-True ($b[0].Lines[0] -like '{"Channel":"SentraExchangeShipper"*"type":"heartbeat"*') 'heartbeat JSON is the first line'
    Assert-Eq $b[0].Lines.Count 33 '33 lines = heartbeat + 2 headers + 20 + 10 data lines'
    $trk = Get-DataLines $b 'exmsgtrk'; $iis = Get-DataLines $b 'exiis'
    Assert-Eq $trk.Count 20 '20 message tracking data lines'
    Assert-Eq $iis.Count 10 '10 IIS data lines'
    Assert-True ($trk[0] -match ($Prefix + 'exmsgtrk-TEST-EX01 - - - 2026-10-07T10:00:01\.123Z,10\.20\.0\.15,')) 'RFC 5424 prefix <174>1 <ts> TEST-EX01 exmsgtrk-TEST-EX01 - - - <raw csv>'
    Assert-True ($iis[0] -match ($Prefix + 'exiis-TEST-EX01 - - - 2026-10-07 10:00:00 10\.20\.0\.16 GET /owa/ ')) 'IIS lines tagged exiis-TEST-EX01'
    $hTrk = Get-HeaderLines $b 'exmsgtrk'; $hIis = Get-HeaderLines $b 'exiis'
    Assert-Eq $hTrk.Count 1 'exactly one message tracking #Fields header in the batch'
    Assert-Eq (Get-Payload $hTrk[0]) $MsgHeader 'message tracking header is the file header'
    Assert-Eq (Get-Payload $hIis[0]) $IisHeader 'IIS header is the file header'
    Assert-True ($b[0].Lines.IndexOf($hTrk[0]) -lt $b[0].Lines.IndexOf($trk[0])) 'message tracking header precedes its first data line'
    Assert-True ($b[0].Lines.IndexOf($hIis[0]) -lt $b[0].Lines.IndexOf($iis[0])) 'IIS header precedes its first data line'
    Assert-True (@($b[0].Lines | Where-Object { $_ -match '- - - #(Software|Version|Date|Log-type)' }).Count -eq 0) 'other comment lines (#Software/#Version/#Date) are not forwarded'
    Assert-True ((Get-Payload $trk[0]).Contains('"Quarterly results, ""confidential"""')) 'quoted CSV cell sent verbatim'
  }
  $bm = Get-Bookmark $MsgFile
  Assert-True ($null -ne $bm) 'bookmark exists for the message tracking file'
  if ($null -ne $bm) {
    Assert-Eq $bm.offset (Get-Item $MsgFile).Length 'bookmark offset == file length'
    Assert-Eq $bm.header $MsgHeader 'bookmark remembers the #Fields header'
  }
  Assert-Eq (Get-Bookmark $IisFile).offset (Get-Item $IisFile).Length 'IIS bookmark offset == file length'
  $st = Read-Json (Join-Path $script:Data 'state.json')
  Assert-True ($st.last_success -ne '') 'state.last_success set'
  Assert-True ((Get-ShipperLog) -notmatch [regex]::Escape($Token)) 'token never appears in the log'

  # ------------------------------------------------------------------------------------------------ T2 idle
  Write-Host "`n[T2] idle pass: nothing new -> nothing sent"
  $r = Invoke-Shipper
  $b = Get-NewBatches
  Assert-Eq $b.Count 0 'no batch sent'
  Assert-True ((Get-ShipperLog) -match 'pass done: 0 line\(s\)') 'log: pass done with 0 lines'

  # ------------------------------------------------------------------------------------------------ T3 append + partial
  Write-Host "`n[T3] append 5 lines (CRLF) + an incomplete trailing line"
  $lenBefore = (Get-Item $MsgFile).Length
  Add-Lines $MsgFile @(1..5 | ForEach-Object { New-MsgTrkLine $_ })
  $lenComplete = (Get-Item $MsgFile).Length
  $partial = (New-MsgTrkLine 6).Substring(0, 40)
  Add-Partial $MsgFile $partial
  $r = Invoke-Shipper
  $b = Get-NewBatches
  Assert-Eq $b.Count 1 'one batch'
  $trk = Get-DataLines $b 'exmsgtrk'
  Assert-Eq $trk.Count 5 '5 appended lines received'
  Assert-Eq (Get-HeaderLines $b 'exmsgtrk').Count 1 'header re-sent with the batch (HeaderEveryBatch default)'
  Assert-Eq (Get-DataLines $b 'exiis').Count 0 'no IIS lines (unchanged file)'
  Assert-Eq (Get-Payload $trk[4]) (New-MsgTrkLine 5) 'last appended line intact (CRLF stripped)'
  Assert-Eq (Get-Bookmark $MsgFile).offset $lenComplete 'bookmark stops before the incomplete line'
  Write-Host "      complete the partial line"
  Add-Partial $MsgFile ((New-MsgTrkLine 6).Substring(40) + "`r`n")
  $r = Invoke-Shipper
  $b = Get-NewBatches
  $trk = Get-DataLines $b 'exmsgtrk'
  Assert-Eq $trk.Count 1 'the completed line is sent once'
  Assert-Eq (Get-Payload $trk[0]) (New-MsgTrkLine 6) 'completed line is whole'
  Assert-Eq (Get-Bookmark $MsgFile).offset (Get-Item $MsgFile).Length 'bookmark at EOF'

  # ------------------------------------------------------------------------------------------------ T4 truncate
  Write-Host "`n[T4] file truncated and rewritten with a different #Fields header"
  $newHeader = '#Fields: date-time,client-ip,client-hostname,server-ip,server-hostname,source-context,connector-id,source,event-id,internal-message-id,message-id,network-message-id,recipient-address,recipient-status,total-bytes,recipient-count,related-recipient-address,reference,message-subject,sender-address,return-path,message-info,directionality,tenant-id,original-client-ip,original-server-ip,custom-data,transport-traffic-type,log-id,schema-version,x-custom'
  [IO.File]::WriteAllText($MsgFile, ('#Software: Microsoft Exchange Server' + "`r`n" + '#Version: 15.02.1544.004' + "`r`n" + $newHeader + "`r`n"), $Utf8NoBom)
  Add-Lines $MsgFile @(11..13 | ForEach-Object { (New-MsgTrkLine $_) + ',custom' })
  $r = Invoke-Shipper
  $b = Get-NewBatches
  $trk = Get-DataLines $b 'exmsgtrk'; $h = Get-HeaderLines $b 'exmsgtrk'
  Assert-Eq $trk.Count 3 '3 lines of the rewritten file received (restart at offset 0)'
  Assert-Eq $h.Count 1 'one header line'
  Assert-Eq (Get-Payload $h[0]) $newHeader 'the NEW header was sent'
  Assert-True ($b.Count -ge 1 -and $b[0].Lines.IndexOf($h[0]) -lt $b[0].Lines.IndexOf($trk[0])) 'new header precedes the data'
  Assert-True ((Get-ShipperLog) -match 'shorter than its bookmark') 'log notes the truncation'
  Assert-Eq (Get-Bookmark $MsgFile).header $newHeader 'bookmark header updated'
  Assert-Eq (Get-Bookmark $MsgFile).offset (Get-Item $MsgFile).Length 'bookmark at new EOF'

  # ------------------------------------------------------------------------------------------------ T5 new file
  Write-Host "`n[T5] rotation: a new MSGTRK file appears (next hour)"
  $MsgFile2 = Join-Path $MsgDir 'MSGTRK2026100711-1.LOG'
  [IO.File]::WriteAllText($MsgFile2, ('#Software: Microsoft Exchange Server' + "`r`n" + $MsgHeader + "`r`n"), $Utf8NoBom)
  Add-Lines $MsgFile2 @(21..24 | ForEach-Object { New-MsgTrkLine $_ })
  $r = Invoke-Shipper
  $b = Get-NewBatches
  $trk = Get-DataLines $b 'exmsgtrk'
  Assert-Eq $trk.Count 4 '4 lines from the new file'
  Assert-Eq (Get-Payload (Get-HeaderLines $b 'exmsgtrk')[0]) $MsgHeader 'header of the new file sent (differs from the previous file)'
  Assert-True ((Get-ShipperLog) -match [regex]::Escape('new file: ' + $MsgFile2)) 'log notes the new file'
  Assert-Eq (Get-Bookmark $MsgFile2).offset (Get-Item $MsgFile2).Length 'new file bookmarked at EOF'
  Assert-Eq (Get-Bookmark $MsgFile).offset (Get-Item $MsgFile).Length 'old file bookmark unchanged'
  Write-Host "      both files written in one pass -> header re-sent at the switch"
  Add-Lines $MsgFile @((New-MsgTrkLine 14) + ',custom')
  Start-Sleep -Milliseconds 30
  Add-Lines $MsgFile2 @(New-MsgTrkLine 25)
  $r = Invoke-Shipper
  $b = Get-NewBatches
  $lines = @($b[0].Lines | Where-Object { $_ -match 'exmsgtrk-' } | ForEach-Object { Get-Payload $_ })
  Assert-Eq $lines.Count 4 'header, line, header, line'
  Assert-True ($lines[0] -eq $newHeader -and $lines[2] -eq $MsgHeader) 'each file''s lines are preceded by that file''s header'

  # ------------------------------------------------------------------------------------------------ T6 IIS header change mid-file
  Write-Host "`n[T6] IIS: field selection changed mid-file (new #Fields with x-forwarded-for)"
  $iisHeader2 = $IisHeader + ' x-forwarded-for'
  Add-Lines $IisFile @('#Software: Microsoft Internet Information Services 10.0', '#Version: 1.0', '#Date: 2026-10-07 11:00:00', $iisHeader2, (New-IisLine 1 '198.51.100.9'), (New-IisLine 2 '198.51.100.10'))
  $r = Invoke-Shipper
  $b = Get-NewBatches
  $iis = Get-DataLines $b 'exiis'; $h = Get-HeaderLines $b 'exiis'
  Assert-Eq $iis.Count 2 '2 IIS lines'
  Assert-Eq (Get-Payload $h[0]) $iisHeader2 'new IIS header sent'
  Assert-True ($b[0].Lines.IndexOf($h[0]) -lt $b[0].Lines.IndexOf($iis[0])) 'IIS header precedes the lines'
  Assert-Eq (Get-Bookmark $IisFile).header $iisHeader2 'IIS bookmark header updated'

  # ------------------------------------------------------------------------------------------------ T7 queue + replay
  Write-Host "`n[T7] collector down: lines are queued, bookmarks advance, replayed oldest-first when it is back"
  Stop-Listener
  Add-Lines $MsgFile2 @(31..33 | ForEach-Object { New-MsgTrkLine $_ })
  $r = Invoke-Shipper
  Assert-Eq (Get-NewBatches).Count 0 'nothing received while down'
  $q = @(Get-ChildItem (Join-Path $script:Data 'queue') -Filter '*.ndjson.gz' -File | Sort-Object Name)
  Assert-Eq $q.Count 1 'one batch in the queue'
  Assert-Eq (Get-Bookmark $MsgFile2).offset (Get-Item $MsgFile2).Length 'bookmark advanced (batch is durable on disk)'
  $st = Read-Json (Join-Path $script:Data 'state.json')
  Assert-Eq $st.backoff_minutes 1 'back-off 1 minute'
  Assert-True ($st.next_attempt -ne '') 'next_attempt set'
  Assert-True ((Get-ShipperLog) -match 'collector unreachable') 'log: collector unreachable'
  Write-Host "      still in back-off: next batch goes straight to the queue without a connection attempt"
  Add-Lines $MsgFile2 @(34..35 | ForEach-Object { New-MsgTrkLine $_ })
  $r = Invoke-Shipper
  $q = @(Get-ChildItem (Join-Path $script:Data 'queue') -Filter '*.ndjson.gz' -File | Sort-Object Name)
  Assert-Eq $q.Count 2 'two batches queued'
  $qIds = @($q | ForEach-Object { ($_.Name -replace '\.ndjson\.gz$', '') -replace '^\d+-', '' })
  Write-Host "      collector back"
  Start-Listener
  Clear-Backoff
  $r = Invoke-Shipper
  $b = Get-NewBatches
  Assert-Eq $b.Count 2 'two batches replayed'
  if ($b.Count -eq 2) {
    Assert-Eq $b[0].Id $qIds[0] 'oldest batch first, X-Sentra-Batch-Id == queue file id'
    Assert-Eq $b[1].Id $qIds[1] 'second batch id == queue file id'
    Assert-Eq (Get-DataLines $b[0] 'exmsgtrk').Count 3 'first replayed batch has the 3 lines'
    Assert-Eq (Get-DataLines $b[1] 'exmsgtrk').Count 2 'second replayed batch has the 2 lines'
  }
  Assert-Eq (@(Get-ChildItem (Join-Path $script:Data 'queue') -Filter '*.ndjson.gz' -File)).Count 0 'queue empty'
  $st = Read-Json (Join-Path $script:Data 'state.json')
  Assert-Eq $st.backoff_minutes 0 'back-off reset'

  # ------------------------------------------------------------------------------------------------ T8 HTTP 401
  Write-Host "`n[T8] HTTP 401 (bad token): batch kept in the queue, not rejected"
  $script:Mode = '401'
  Add-Lines $MsgFile2 @(New-MsgTrkLine 41)
  $r = Invoke-Shipper
  [void](Get-NewBatches)
  Assert-Eq (@(Get-ChildItem (Join-Path $script:Data 'queue') -Filter '*.ndjson.gz' -File)).Count 1 'batch queued after 401'
  Assert-Eq (@(Get-ChildItem (Join-Path $script:Data 'queue\rejected') -File)).Count 0 'nothing in rejected'
  Assert-True ((Get-ShipperLog) -match 'rejected the token') 'log: token rejected'
  $script:Mode = 'ok'
  Clear-Backoff
  $r = Invoke-Shipper
  $b = Get-NewBatches
  Assert-Eq (Get-DataLines $b 'exmsgtrk').Count 1 'drained after the token is accepted again'

  # ------------------------------------------------------------------------------------------------ T9 HeaderEveryBatch off
  Write-Host "`n[T9] HeaderEveryBatch=false: header only when it changes (remembered across runs in state.json)"
  Set-ConfigValue 'HeaderEveryBatch' $false
  Add-Lines $MsgFile2 @(New-MsgTrkLine 51)
  $r = Invoke-Shipper
  $b = Get-NewBatches
  Assert-Eq (Get-HeaderLines $b 'exmsgtrk').Count 1 'first batch after the switch carries the header'
  Add-Lines $MsgFile2 @(New-MsgTrkLine 52)
  $r = Invoke-Shipper
  $b = Get-NewBatches
  Assert-Eq (Get-DataLines $b 'exmsgtrk').Count 1 'line received'
  Assert-Eq (Get-HeaderLines $b 'exmsgtrk').Count 0 'no header when unchanged'
  $st = Read-Json (Join-Path $script:Data 'state.json')
  Assert-Eq $st.sent_headers.'exmsgtrk' $MsgHeader 'state.sent_headers remembers the header per stream'
  Add-Lines $MsgFile2 @($newHeader, ((New-MsgTrkLine 53) + ',custom'))
  $r = Invoke-Shipper
  $b = Get-NewBatches
  $h = Get-HeaderLines $b 'exmsgtrk'
  Assert-Eq $h.Count 1 'header sent again when it changes'
  Assert-Eq (Get-Payload $h[0]) $newHeader 'it is the changed header'
  Set-ConfigValue 'HeaderEveryBatch' $true

  # ------------------------------------------------------------------------------------------------ T10 batch split
  Write-Host "`n[T10] batches split at BatchMaxLines, each starting with the header"
  Set-ConfigValue 'BatchMaxLines' 5
  Add-Lines $MsgFile2 @(61..72 | ForEach-Object { (New-MsgTrkLine $_) + ',custom' })
  $r = Invoke-Shipper
  $b = Get-NewBatches
  Assert-Eq $b.Count 3 '12 lines -> 3 batches of header + 4'
  $all = 0; $okHdr = $true
  foreach ($x in $b) {
    $all += (Get-DataLines $x 'exmsgtrk').Count
    $first = $x.Lines[0]; if ($first -like '{"Channel":"SentraExchangeShipper"*') { $first = $x.Lines[1] }   # a heartbeat may lead the first batch
    if ((Get-Payload $first) -ne $newHeader) { $okHdr = $false }
    if ($x.Lines.Count -gt 5) { $okHdr = $false }
  }
  Assert-Eq $all 12 'all 12 lines received'
  Assert-True $okHdr 'every batch starts with the header and has <= 5 lines'
  Assert-True (@($b | ForEach-Object { $_.Id } | Sort-Object -Unique).Count -eq 3) 'distinct batch ids'
  Set-ConfigValue 'BatchMaxLines' 2000

  # ------------------------------------------------------------------------------------------------ T11 dry run
  Write-Host "`n[T11] -DryRun -Count 3: prints, sends nothing, touches no bookmarks"
  $bmBefore = [IO.File]::ReadAllText((Join-Path $script:Data 'bookmarks.json'))
  $r = Invoke-Shipper -ExtraArgs @('-DryRun', '-Count', '3')
  $outLines = @($r.StdOut -split "`r?`n" | Where-Object { $_ -ne '' })
  Assert-Eq $r.ExitCode 0 'dry run exit code 0'
  Assert-Eq (Get-NewBatches).Count 0 'nothing sent'
  Assert-Eq $outLines.Count 8 '8 stdout lines: (header + 3) for message tracking and for IIS'
  Assert-True ($outLines[0] -match ($Prefix + 'exmsgtrk-TEST-EX01 - - - #Fields:')) 'first line is the message tracking header, prefixed like a real send'
  Assert-Eq (Get-Payload $outLines[3]) ((New-MsgTrkLine 72) + ',custom') 'last message tracking line of the newest file'
  Assert-True ($outLines[4] -match ($Prefix + 'exiis-TEST-EX01 - - - #Fields:')) 'IIS header follows'
  Assert-True ($r.StdErr -match "source 'msgtrk' \(exmsgtrk-TEST-EX01\): 2 file\(s\)") 'summary lists the files per source'
  Assert-True ($r.StdErr -match 'nothing was sent') 'summary says nothing was sent'
  Assert-Eq ([IO.File]::ReadAllText((Join-Path $script:Data 'bookmarks.json'))) $bmBefore 'bookmarks unchanged'
  $r = Invoke-Shipper -ExtraArgs @('-DryRun', '-Count', '0')
  Assert-True ($r.StdOut.Trim() -eq '' -and $r.StdErr -match '2 file\(s\)') '-Count 0 prints only the summary'

  # ------------------------------------------------------------------------------------------------ T12 mutex
  Write-Host "`n[T12] single instance: a second shipper exits while the mutex is held"
  $m = New-Object System.Threading.Mutex($false, 'Global\SentraExchangeShipper')
  [void]$m.WaitOne(0)
  Add-Lines $MsgFile2 @((New-MsgTrkLine 81) + ',custom')
  try { $r = Invoke-Shipper } finally { $m.ReleaseMutex(); $m.Dispose() }
  Assert-Eq (Get-NewBatches).Count 0 'no batch while another instance holds the mutex'
  Assert-True ((Get-ShipperLog) -match 'another instance is running') 'log: another instance is running'
  $r = Invoke-Shipper
  Assert-Eq (Get-DataLines (Get-NewBatches) 'exmsgtrk').Count 1 'line shipped once the mutex is free'

  # ------------------------------------------------------------------------------------------------ T13 https enforced
  Write-Host "`n[T13] plain http is refused without TestPlainHttp"
  Set-ConfigValue 'TestPlainHttp' $false
  Add-Lines $MsgFile2 @((New-MsgTrkLine 82) + ',custom')
  $r = Invoke-Shipper
  Assert-Eq (Get-NewBatches).Count 0 'nothing sent'
  Assert-True ((Get-ShipperLog) -match 'CollectorUrl must start with https://') 'log: CollectorUrl must start with https://'
  Set-ConfigValue 'TestPlainHttp' $true

  # ------------------------------------------------------------------------------------------------ T14 engine parser (optional)
  Write-Host "`n[T14] engine parser check (node)"
  $node = Get-Command node.exe -ErrorAction SilentlyContinue
  $engine = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) '..\engine\parse\index.js'
  if ($null -eq $node -or -not (Test-Path $engine)) { Write-Host '  skip  node.exe or engine/parse not available' }
  else {
    $nd = Join-Path $script:Work 'received.ndjson'
    $all = New-Object System.Collections.Generic.List[string]
    foreach ($x in $script:Received) { if ($x.Mode -eq 'ok') { foreach ($l in $x.Lines) { $all.Add($l) } } }
    [IO.File]::WriteAllText($nd, (($all -join "`n") + "`n"), $Utf8NoBom)
    $res = (& $node.Source (Join-Path $PSScriptRoot 'engine-check.js') $nd 'win-exchange-test' | Out-String) | ConvertFrom-Json
    Assert-Eq $res.unparsed 0 'engine: no unparsed line'
    Assert-Eq $res.hosts.'test-ex01' ($res.total - $res.heartbeat) 'engine: host = test-ex01 for every line (from the tag)'
    Assert-Eq $res.msgtrk 57 "engine: all 57 message tracking data lines sent in the suite parsed as email events"
    Assert-True ($res.iis -ge 12) "engine: IIS events parsed ($($res.iis))"
    Assert-True ($res.actions.send -ge 1 -and $res.actions.deliver -ge 1 -and $res.actions.fail -ge 1) 'engine: actions send/deliver/fail present'
    Assert-Eq $res.subject_in_clear 0 'engine: subjects hashed, never in clear'
    Assert-True ($res.xff -ge 2) 'engine: x-forwarded-for picked up after the IIS header change'
    Assert-True ($res.headers -ge 10) "engine: header lines became log_header events ($($res.headers))"
  }
} finally {
  Stop-Listener
}

Write-Host ''
Write-Host ("RESULT: {0} passed, {1} failed" -f $script:Pass, $script:Fail)
foreach ($f in $script:Failures) { Write-Host "  - $f" -ForegroundColor Red }
if ($script:Fail -eq 0 -and -not $KeepWork) { Remove-Item $script:Work -Recurse -Force -ErrorAction SilentlyContinue } else { Write-Host "work dir kept: $($script:Work)" }
exit $script:Fail
