# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
# SharePoint Online runner for the platform (engine/exo.js) - used by HR Offboarding to give a leaver's manager access to the
# leaver's OneDrive for an approved period. A FIXED list of operations - never a free-form command. Everything comes on stdin
# as one JSON object (the certificate password included, so it never appears on a command line or in a log):
#   { org, app_id, cert_path, cert_password, admin_url, op, params }
# Sign-in: app-only with the same certificate as Exchange Online (Connect-PnPOnline -ClientId -CertificatePath -Tenant). The app
# needs the SharePoint application permission Sites.FullControl.All (SharePoint, not Graph) - adding a site collection
# administrator on someone else's OneDrive needs it. Only OneDrive sites (https://<tenant>-my.sharepoint.com/personal/...) are
# accepted, and only the administrators the platform names are added or removed - never the owner.
# Output: one JSON line on stdout {ok:true, data} | {ok:false, error}. Requires PowerShell 7.4 and PnP.PowerShell >= 2.
$ErrorActionPreference = 'Stop'
function Out-Result($obj) { [Console]::Out.WriteLine(($obj | ConvertTo-Json -Depth 6 -Compress)) }
$addr = '^[A-Za-z0-9._%+''-]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,24}$'
$site = '^https://[a-z0-9-]{1,63}-my\.sharepoint\.com/personal/[A-Za-z0-9_]{1,200}/?$'
try {
  $in = [Console]::In.ReadToEnd() | ConvertFrom-Json
  $ops = @('spo-test', 'get-onedrive', 'add-site-admin', 'remove-site-admin')
  if ($ops -notcontains $in.op) { throw "operation not allowed: $($in.op)" }
  if ($in.org -notmatch '^[A-Za-z0-9-]{1,63}(\.[A-Za-z0-9-]{1,63})+$') { throw 'org must be the tenant domain (contoso.onmicrosoft.com)' }
  if ($in.app_id -notmatch '^[0-9a-fA-F-]{36}$') { throw 'app_id must be a GUID' }
  if ($in.admin_url -notmatch '^https://[a-z0-9-]{1,63}-admin\.sharepoint\.com/?$') { throw 'admin_url must be https://<tenant>-admin.sharepoint.com' }
  if (-not (Test-Path -LiteralPath $in.cert_path -PathType Leaf)) { throw 'the certificate file is not on the server' }
  $p = $in.params
  if ($in.op -eq 'get-onedrive' -and "$($p.identity)" -notmatch $addr) { throw 'identity must be a user address' }
  if ($in.op -in @('add-site-admin', 'remove-site-admin')) {
    if ("$($p.site)" -notmatch $site) { throw 'site must be a OneDrive address (https://<tenant>-my.sharepoint.com/personal/...)' }
    if ("$($p.user)" -notmatch $addr) { throw 'user must be a user address' }
  }
  Import-Module PnP.PowerShell -MinimumVersion 2.0.0 -ErrorAction Stop
  $sec = ConvertTo-SecureString -String "$($in.cert_password)" -AsPlainText -Force
  $in.cert_password = $null
  $conn = @{ ClientId = $in.app_id; Tenant = $in.org; CertificatePath = $in.cert_path; CertificatePassword = $sec }
  function Admins() { @(Get-PnPSiteCollectionAdmin | ForEach-Object { "$($_.Email)".ToLower() } | Where-Object { $_ }) }
  switch ($in.op) {
    'spo-test' { Connect-PnPOnline -Url $in.admin_url @conn; $n = @(Get-PnPTenantSite -Template 'SPSPERS' -ErrorAction Stop | Select-Object -First 1).Count; Out-Result @{ ok = $true; data = @{ onedrive_read = ($n -ge 0) } } }
    'get-onedrive' {
      Connect-PnPOnline -Url $in.admin_url @conn
      $url = "$((Get-PnPUserProfileProperty -Account $p.identity -ErrorAction Stop).PersonalUrl)".TrimEnd('/')
      if (-not $url -or $url -notmatch $site) { Out-Result @{ ok = $true; data = @{ found = $false } }; break }
      $s = Get-PnPTenantSite -Identity $url -Detailed -ErrorAction SilentlyContinue
      if (-not $s) { Out-Result @{ ok = $true; data = @{ found = $false; url = $url } }; break }
      Connect-PnPOnline -Url $url @conn
      Out-Result @{ ok = $true; data = @{ found = $true; url = $url; storage_mb = [int64]$s.StorageUsageCurrent; last_modified = "$($s.LastContentModifiedDate.ToString('o'))"; lock = "$($s.LockState)"; owner = "$($s.Owner)".ToLower(); admins = Admins } }
    }
    'add-site-admin' { Connect-PnPOnline -Url $p.site @conn; Add-PnPSiteCollectionAdmin -Owners $p.user -ErrorAction Stop; Out-Result @{ ok = $true; data = @{ granted = ((Admins) -contains "$($p.user)".ToLower()) } } }
    'remove-site-admin' { Connect-PnPOnline -Url $p.site @conn; Remove-PnPSiteCollectionAdmin -Owners $p.user -ErrorAction Stop; Out-Result @{ ok = $true; data = @{ removed = -not ((Admins) -contains "$($p.user)".ToLower()) } } }
  }
} catch { $m = ("$($_.Exception.Message)" -replace '\s+', ' '); Out-Result @{ ok = $false; error = $m.Substring(0, [Math]::Min(300, $m.Length)) } }
finally { try { Disconnect-PnPOnline -ErrorAction SilentlyContinue } catch { $null = $_ } }   # nothing to disconnect when sign-in failed
