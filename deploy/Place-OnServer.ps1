# Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
# Place-OnServer.ps1 - copy this clean tree to the server at /opt/sentra-platform (development / code analysis).
# The running platform is NOT touched: no service, no /opt/sentra-itam, /opt/sentra-siem, /var/www or /etc change.
# Same path as the updater: pack -> SHA-256 -> scp to your home folder -> ssh: check the SHA-256, then install-dev-folder.sh.
#
#   powershell -ExecutionPolicy Bypass -File .\deploy\Place-OnServer.ps1 [-Server user@host] [-Compare]
#   -Compare also runs the read-only comparison with what the server runs (deploy/compare-with-live.sh).
param(
  [string]$Server = "admin@platform-server",
  [switch]$Compare
)
$ErrorActionPreference = "Continue"   # native tar/scp/ssh results are checked with $LASTEXITCODE
function Fail($m) { Write-Host "!! $m" -ForegroundColor Red; exit 1 }
$Tree = Split-Path -Parent $PSScriptRoot
if (-not (Test-Path (Join-Path $Tree "backend")) -or -not (Test-Path (Join-Path $Tree "ui"))) { Fail "$Tree is not the platform clean tree" }

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$tgz = Join-Path $env:TEMP "sentra-platform-$stamp.tgz"
Write-Host "==> packing $Tree"
tar -czf $tgz --exclude=.git -C $Tree .
if ($LASTEXITCODE -ne 0) { Fail "could not pack the tree (tar)" }
$sha = (Get-FileHash -Algorithm SHA256 $tgz).Hash.ToLower()
Write-Host ("    {0:N1} MB, SHA-256 {1}" -f ((Get-Item $tgz).Length / 1MB), $sha)

$r = "sentra-platform-$stamp"
Write-Host "==> copying to $Server (your home folder)"
scp $tgz (Join-Path $Tree "deploy\install-dev-folder.sh") "${Server}:"
if ($LASTEXITCODE -ne 0) { Fail "copy to the server failed" }

$cmd = "cd ~ && sudo bash ~/install-dev-folder.sh ~/$r.tgz $sha"   # scp kept the local name, which is $r.tgz
if ($Compare) { $cmd += " && bash /opt/sentra-platform/deploy/compare-with-live.sh" }
Write-Host "==> installing /opt/sentra-platform on the server (sudo password if asked)"
ssh -t $Server $cmd
if ($LASTEXITCODE -ne 0) { Fail "the server reported a problem - scroll up for the message (nothing live was changed)" }
Remove-Item -Force $tgz
Write-Host "==> done: /opt/sentra-platform on $Server" -ForegroundColor Green
