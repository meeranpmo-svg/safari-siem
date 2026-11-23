# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
<#
.SYNOPSIS
  Keep the three copies of sentra-siem identical: this PC, GitHub, and the platform server.

.DESCRIPTION
  Run from the sentra-siem folder on the PC while the VPN is connected:

      powershell -ExecutionPolicy Bypass -File .\scripts\sync.ps1

  1. GitHub -> PC   pulls the latest commits (fast-forward only, never merges silently)
  2. PC -> GitHub   commits any local changes (asks for a message) and pushes
  3. tests          node --test tests/  (skipped if Node.js is not installed on the PC; -SkipTests to skip)
  4. PC -> server   packages exactly that commit, copies it over SSH and runs install/install.sh
                    (upgrade in place: config, secrets and data are kept, previous code -> /opt/sentra-siem.prev)
  5. verify         reads /opt/sentra-siem/VERSION on the server and checks it is the same commit as GitHub

  The server address and SSH user are asked once and saved in %USERPROFILE%\.sentra-siem-deploy.json
  (outside the repo). Passwords are never stored: ssh and sudo prompt for them.

.PARAMETER Status    Only show which commit the PC, GitHub and the server are on. Changes nothing.
.PARAMETER Rollback  Switch the server back to the previous version (/opt/sentra-siem.prev).
.PARAMETER SkipTests Deploy without running the test suite.
.PARAMETER InstallArgs Extra options for install.sh, e.g. "--listen-lan". Normally not needed on upgrades.
.PARAMETER Reconfigure Ask for the server address / SSH user again.
.PARAMETER AllowPassword Allow SSH password login. By default only SSH keys are used; set one up once with:
            ssh-keygen -t ed25519   then   type $env:USERPROFILE\.ssh\id_ed25519.pub | ssh user@server "mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys"
#>
[CmdletBinding()]
param(
  [switch]$Status,
  [switch]$Rollback,
  [switch]$SkipTests,
  [string]$InstallArgs = '',
  [switch]$Reconfigure,
  [switch]$AllowPassword
)

$ErrorActionPreference = 'Stop'
$ConfigFile = Join-Path $env:USERPROFILE '.sentra-siem-deploy.json'

function Say($msg)  { Write-Host "==> $msg" -ForegroundColor Cyan }
function Ok($msg)   { Write-Host "    $msg" -ForegroundColor Green }
function Warn($msg) { Write-Host "warning: $msg" -ForegroundColor Yellow }
function Die($msg)  { Write-Host "error: $msg" -ForegroundColor Red; exit 1 }

function Invoke-Native {
  # runs a native command, stops on a non-zero exit code
  param([string]$Exe, [string[]]$Arguments)
  & $Exe @Arguments
  if ($LASTEXITCODE -ne 0) { Die "$Exe $($Arguments -join ' ') failed (exit $LASTEXITCODE)" }
}

function Get-Git([string[]]$Arguments) {
  $ErrorActionPreference = 'Continue'   # Windows PowerShell 5.1 turns redirected native stderr into errors
  $out = & git @Arguments 2>$null
  if ($LASTEXITCODE -ne 0) { return '' }
  return ($out | Out-String).Trim()
}

# ---------------------------------------------------------------------------------------------------------------
# preflight
# ---------------------------------------------------------------------------------------------------------------
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root
if (-not (Test-Path (Join-Path $Root 'engine\main.js'))) { Die "run this from the sentra-siem repository (engine\main.js not found under $Root)" }
foreach ($tool in 'git', 'ssh', 'scp') {
  if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
    Die "$tool not found. Git: https://git-scm.com/download/win  -  ssh/scp: Settings > Apps > Optional features > OpenSSH Client"
  }
}

$cfg = $null
if ((Test-Path $ConfigFile) -and -not $Reconfigure) {
  $cfg = Get-Content $ConfigFile -Raw | ConvertFrom-Json
}
if (-not $cfg -or -not $cfg.Server -or -not $cfg.User) {
  Say "server settings (saved to $ConfigFile, no passwords)"
  $server = Read-Host '    platform server IP or hostname (reachable over the VPN)'
  $user   = Read-Host '    SSH user on that server (needs sudo)'
  $port   = Read-Host '    SSH port [22]'
  if (-not $port) { $port = '22' }
  if (-not $server -or -not $user) { Die 'server and user are required' }
  $cfg = [pscustomobject]@{ Server = $server.Trim(); User = $user.Trim(); Port = [int]$port }
  $cfg | ConvertTo-Json | Set-Content -Path $ConfigFile -Encoding UTF8
}
$Target  = "$($cfg.User)@$($cfg.Server)"
# The server's host key is remembered on first use and checked on every later connection; password login is off
# unless -AllowPassword is given (keys only, as the platform's SAMA hardening requires).
$auth = @('-o', 'StrictHostKeyChecking=accept-new')
if (-not $AllowPassword) { $auth += @('-o', 'PasswordAuthentication=no', '-o', 'KbdInteractiveAuthentication=no') }
$SshArgs = @('-p', "$($cfg.Port)", '-o', 'ConnectTimeout=15') + $auth
$ScpArgs = @('-P', "$($cfg.Port)", '-o', 'ConnectTimeout=15') + $auth

function Get-ServerVersion {
  $ErrorActionPreference = 'Continue'
  $v = & ssh @SshArgs $Target 'cat /opt/sentra-siem/VERSION 2>/dev/null || echo none' 2>$null
  if ($LASTEXITCODE -ne 0) { return 'unreachable (VPN connected?)' }
  return ($v | Out-String).Trim()
}

$Branch = Get-Git @('rev-parse', '--abbrev-ref', 'HEAD')
if (-not $Branch -or $Branch -eq 'HEAD') { Die 'not on a branch (detached HEAD) - run: git checkout main' }

# ---------------------------------------------------------------------------------------------------------------
# -Status: report only
# ---------------------------------------------------------------------------------------------------------------
if ($Status) {
  Invoke-Native git @('fetch', '--quiet', 'origin', $Branch)
  $pc = Get-Git @('rev-parse', '--short', 'HEAD')
  $gh = Get-Git @('rev-parse', '--short', "origin/$Branch")
  $dirty = Get-Git @('status', '--porcelain')
  Say 'where each copy is'
  Write-Host ("    PC      {0}{1}" -f $pc, $(if ($dirty) { '  + uncommitted changes' } else { '' }))
  Write-Host  "    GitHub  $gh"
  Write-Host  "    Server  $(Get-ServerVersion)"
  exit 0
}

# ---------------------------------------------------------------------------------------------------------------
# -Rollback
# ---------------------------------------------------------------------------------------------------------------
if ($Rollback) {
  Say "rolling the server back to /opt/sentra-siem.prev (sudo will ask for the password)"
  $cmd = 'set -e; test -d /opt/sentra-siem.prev || { echo "no previous version on the server"; exit 1; }; ' +
         'sudo systemctl stop sentra-siem; sudo rm -rf /opt/sentra-siem.bad; sudo mv /opt/sentra-siem /opt/sentra-siem.bad; ' +
         'sudo mv /opt/sentra-siem.prev /opt/sentra-siem; sudo systemctl start sentra-siem; sleep 3; systemctl is-active sentra-siem; ' +
         'cat /opt/sentra-siem/VERSION 2>/dev/null || true'
  Invoke-Native ssh (@('-t') + $SshArgs + @($Target, $cmd))
  Warn 'the server now runs an OLDER commit than the PC and GitHub. Fix the problem, commit, and run sync.ps1 again.'
  exit 0
}

# ---------------------------------------------------------------------------------------------------------------
# 1. GitHub -> PC
# ---------------------------------------------------------------------------------------------------------------
Say "1/5  pulling from GitHub ($Branch)"
$dirty = Get-Git @('status', '--porcelain')
if ($dirty) { Invoke-Native git @('stash', 'push', '--include-untracked', '--quiet', '-m', 'sync.ps1 auto-stash') }
& git pull --ff-only --quiet origin $Branch
$pullCode = $LASTEXITCODE
if ($dirty) {
  & git stash pop --quiet
  if ($LASTEXITCODE -ne 0) { Die 'your local changes conflict with the changes from GitHub. Resolve the conflicts (git status), then run sync.ps1 again.' }
}
if ($pullCode -ne 0) { Die 'pull failed: the PC and GitHub have different commits. Run "git pull --rebase", fix any conflicts, then run sync.ps1 again.' }
Ok "PC is at $(Get-Git @('rev-parse', '--short', 'HEAD'))"

# ---------------------------------------------------------------------------------------------------------------
# 2. PC -> GitHub
# ---------------------------------------------------------------------------------------------------------------
Say '2/5  sending local changes to GitHub'
if (Get-Git @('status', '--porcelain')) {
  Write-Host ''
  & git status --short
  Write-Host ''
  # new (untracked) files are how credential files end up on GitHub: they must be confirmed one by one
  $untracked = @((Get-Git @('ls-files', '--others', '--exclude-standard')) -split "`n" | Where-Object { $_ })
  if ($untracked.Count) {
    Warn "$($untracked.Count) NEW file(s) will be added to GitHub:"
    $untracked | ForEach-Object { Write-Host "      $_" -ForegroundColor Yellow }
    if ((Read-Host '    Type YES to add these new files') -cne 'YES') { Die 'cancelled - nothing was pushed or deployed' }
  }
  $msg = Read-Host '    Commit message (empty = cancel)'
  if (-not $msg) { Die 'cancelled - nothing was pushed or deployed' }
  Invoke-Native git @('add', '-A')
  # secret scan of what is about to be committed (file names and added lines)
  $names = @((Get-Git @('diff', '--cached', '--name-only')) -split "`n" | Where-Object { $_ })
  $badNames = $names | Where-Object { $_ -match '(?i)(password|passwd|logins|secrets?\.json|\.env$|\.pem$|\.key$|\.pfx$|\.p12$|id_rsa|id_ed25519)' -and $_ -notmatch '^tests/fixtures/synthetic-' }
  $added = (Get-Git @('diff', '--cached', '-U0')) -split "`n" | Where-Object { $_ -match '^\+' -and $_ -notmatch '^\+\+\+' }
  $badLines = $added | Where-Object { $_ -match '(?i)(BEGIN [A-Z ]*PRIVATE KEY|password\s*[:=]\s*["''][^"'']{6,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{30,}|xox[bp]-[A-Za-z0-9-]{10,})' }
  if ($badNames -or $badLines) {
    & git reset --quiet
    if ($badNames) { Warn 'files that look like credentials:'; $badNames | ForEach-Object { Write-Host "      $_" -ForegroundColor Red } }
    if ($badLines) { Warn "$(@($badLines).Count) added line(s) look like secrets (not shown)" }
    Die 'possible secrets - nothing was committed. Remove them (or add them to .gitignore) and run sync.ps1 again.'
  }
  Invoke-Native git @('commit', '--quiet', '-m', $msg)
}
$ahead = Get-Git @('rev-list', '--count', "origin/$Branch..HEAD")
if ($ahead -and [int]$ahead -gt 0) {
  Invoke-Native git @('push', '--quiet', 'origin', $Branch)
  Ok "pushed $ahead commit(s)"
} else {
  Ok 'GitHub already up to date'
}
$Sha   = Get-Git @('rev-parse', 'HEAD')
$Short = $Sha.Substring(0, 7)

# ---------------------------------------------------------------------------------------------------------------
# 3. tests
# ---------------------------------------------------------------------------------------------------------------
if ($SkipTests) {
  Warn '3/5  tests skipped (-SkipTests)'
} elseif (-not (Get-Command node -ErrorAction SilentlyContinue)) {
  Warn '3/5  Node.js is not installed on this PC - tests skipped'
} else {
  Say '3/5  running tests (node --test tests/)'
  cmd /c "node --test tests/ > `"$env:TEMP\sentra-siem-tests.txt`" 2>&1"
  if ($LASTEXITCODE -ne 0) {
    Get-Content (Join-Path $env:TEMP 'sentra-siem-tests.txt') -Tail 40
    Die "tests failed - NOT deployed. Full output: $env:TEMP\sentra-siem-tests.txt  (deploy anyway: -SkipTests)"
  }
  Ok 'all tests passed'
}

# ---------------------------------------------------------------------------------------------------------------
# 4. PC -> server
# ---------------------------------------------------------------------------------------------------------------
Say "4/5  deploying $Short to $($cfg.Server)"
$work = Join-Path $env:TEMP "sentra-siem-deploy-$Short"
if (Test-Path $work) { Remove-Item -Recurse -Force $work }
New-Item -ItemType Directory -Path $work | Out-Null
# VERSION is copied to /opt/sentra-siem by install.sh, which is how step 5 (and -Status) know what the server runs
[IO.File]::WriteAllText((Join-Path $work 'VERSION'), "$Sha`n")
$pkg = Join-Path $work "sentra-siem-$Short.tar.gz"
# exactly the committed tree (no untracked files, no .git), plus VERSION (needs Git >= 2.29)
Invoke-Native git @('archive', '--format=tar.gz', '--prefix=sentra-siem/', "--add-file=$(Join-Path $work 'VERSION')", '-o', $pkg, 'HEAD')

Ok 'copying the package'
# a private, unpredictable staging directory (mktemp -d is mode 700)
$ErrorActionPreference = 'Continue'
$remoteDir = ((& ssh @SshArgs $Target 'mktemp -d /tmp/sentra-siem-deploy.XXXXXXXX') | Out-String).Trim()
$ErrorActionPreference = 'Stop'
if ($remoteDir -notmatch '^/tmp/sentra-siem-deploy\.[A-Za-z0-9]{8}$') { Die "could not create a staging directory on the server (SSH key set up? see Get-Help .\scripts\sync.ps1 -Parameter AllowPassword)" }
Invoke-Native scp ($ScpArgs + @($pkg, "${Target}:$remoteDir/"))

Ok 'installing (sudo will ask for the password)'
$install = "set -e; cd $remoteDir; tar xzf sentra-siem-$Short.tar.gz; cd sentra-siem; " +
           "sudo bash ./install/install.sh $InstallArgs; cd /; rm -rf $remoteDir"
Invoke-Native ssh (@('-t') + $SshArgs + @($Target, $install))
Remove-Item -Recurse -Force $work

# ---------------------------------------------------------------------------------------------------------------
# 5. verify
# ---------------------------------------------------------------------------------------------------------------
Say '5/5  checking all three copies match'
$srv = Get-ServerVersion
$ErrorActionPreference = 'Continue'
$active = (& ssh @SshArgs $Target 'systemctl is-active sentra-siem' 2>$null | Out-String).Trim()
$ErrorActionPreference = 'Stop'
Write-Host "    PC      $Short"
Write-Host "    GitHub  $((Get-Git @('rev-parse', "origin/$Branch")).Substring(0, 7))"
Write-Host "    Server  $(if ($srv.Length -ge 7) { $srv.Substring(0, 7) } else { $srv })  (service: $active)"
if ($srv -ne $Sha) { Die 'the server is not on the same commit - check the install output above' }
if ($active -ne 'active') { Die 'service is not running: ssh in and run  journalctl -u sentra-siem -n 50   (undo: sync.ps1 -Rollback)' }
Ok 'PC, GitHub and the platform server are identical.'
