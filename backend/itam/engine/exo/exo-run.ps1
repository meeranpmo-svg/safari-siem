# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
# Exchange Online runner for the platform (engine/exo.js). A FIXED list of operations - never a free-form command. Everything
# comes on stdin as one JSON object (the certificate password included, so it never appears on a command line or in a log):
#   { org, app_id, cert_path, cert_password, op, params }
# Sign-in: app-only with a certificate (Connect-ExchangeOnline -AppId -CertificateFilePath -Organization). The app needs the
# Exchange.ManageAsApp permission and an Exchange role that allows Get-EXOMailbox / Set-Mailbox / Add-MailboxPermission /
# Set-MailboxAutoReplyConfiguration / Get-InboxRule / Disable-InboxRule / Get-AcceptedDomain (e.g. a custom role group with
# "Mail Recipients"), nothing more. Forwarding: inbox rules are DISABLED, never deleted (they stay as evidence).
# Output: one JSON line on stdout {ok:true, data} | {ok:false, error}. Requires PowerShell 7 and ExchangeOnlineManagement >= 3.
$ErrorActionPreference = 'Stop'
function Out-Result($obj) { [Console]::Out.WriteLine(($obj | ConvertTo-Json -Depth 6 -Compress)) }
$addr = '^[A-Za-z0-9._%+''-]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,24}$'
try {
  $in = [Console]::In.ReadToEnd() | ConvertFrom-Json
  $ops = @('test', 'get-mailbox', 'convert-shared', 'add-fullaccess', 'set-autoreply', 'get-forwarding', 'clear-forwarding', 'disable-inbox-rule')
  if ($ops -notcontains $in.op) { throw "operation not allowed: $($in.op)" }
  if ($in.org -notmatch '^[A-Za-z0-9-]{1,63}(\.[A-Za-z0-9-]{1,63})+$') { throw 'org must be the tenant domain (contoso.onmicrosoft.com)' }
  if ($in.app_id -notmatch '^[0-9a-fA-F-]{36}$') { throw 'app_id must be a GUID' }
  if (-not (Test-Path -LiteralPath $in.cert_path -PathType Leaf)) { throw 'the certificate file is not on the server' }
  $p = $in.params
  if ($in.op -ne 'test') { if ("$($p.identity)" -notmatch $addr) { throw 'identity must be a mailbox address' } }
  Import-Module ExchangeOnlineManagement -MinimumVersion 3.0.0 -ErrorAction Stop
  $sec = ConvertTo-SecureString -String "$($in.cert_password)" -AsPlainText -Force
  $in.cert_password = $null
  Connect-ExchangeOnline -AppId $in.app_id -CertificateFilePath $in.cert_path -CertificatePassword $sec -Organization $in.org -ShowBanner:$false -ErrorAction Stop | Out-Null
  try {
    switch ($in.op) {
      'test' { $o = Get-OrganizationConfig | Select-Object -First 1; Out-Result @{ ok = $true; data = @{ organization = "$($o.Name)" } } }
      'get-mailbox' {
        $m = Get-EXOMailbox -Identity $p.identity -Properties RecipientTypeDetails, LitigationHoldEnabled, ArchiveStatus, ForwardingSmtpAddress -ErrorAction SilentlyContinue
        if (-not $m) {
          $r = Get-EXORecipient -Identity $p.identity -ErrorAction SilentlyContinue
          Out-Result @{ ok = $true; data = @{ found = $false; recipient_type = $(if ($r) { "$($r.RecipientTypeDetails)" } else { $null }) } }
        } else {
          Out-Result @{ ok = $true; data = @{ found = $true; type = "$($m.RecipientTypeDetails)"; litigation_hold = [bool]$m.LitigationHoldEnabled; archive = "$($m.ArchiveStatus)"; forwarding = "$($m.ForwardingSmtpAddress)" } }
        }
      }
      'convert-shared' { Set-Mailbox -Identity $p.identity -Type Shared -ErrorAction Stop; $m = Get-EXOMailbox -Identity $p.identity -Properties RecipientTypeDetails; Out-Result @{ ok = $true; data = @{ type = "$($m.RecipientTypeDetails)" } } }
      'add-fullaccess' {
        if ("$($p.user)" -notmatch $addr) { throw 'user must be a mailbox address' }
        Add-MailboxPermission -Identity $p.identity -User $p.user -AccessRights FullAccess -InheritanceType All -AutoMapping $true -Confirm:$false -ErrorAction Stop | Out-Null
        $has = Get-EXOMailboxPermission -Identity $p.identity | Where-Object { $_.User -eq $p.user -and $_.AccessRights -contains 'FullAccess' }
        Out-Result @{ ok = $true; data = @{ granted = [bool]$has } }
      }
      'get-forwarding' {
        $m = Get-EXOMailbox -Identity $p.identity -Properties ForwardingSmtpAddress, ForwardingAddress, DeliverToMailboxAndForward -ErrorAction SilentlyContinue
        if (-not $m) {
          $r = Get-EXORecipient -Identity $p.identity -ErrorAction SilentlyContinue
          Out-Result @{ ok = $true; data = @{ found = $false; recipient_type = $(if ($r) { "$($r.RecipientTypeDetails)" } else { $null }) } }
        } else {
          $fa = ''
          if ($m.ForwardingAddress) { $fr = Get-EXORecipient -Identity "$($m.ForwardingAddress)" -ErrorAction SilentlyContinue; $fa = $(if ($fr) { "$($fr.PrimarySmtpAddress)" } else { "$($m.ForwardingAddress)" }) }
          $rules = @(Get-InboxRule -Mailbox $p.identity -ErrorAction Stop | Where-Object { $_.ForwardTo -or $_.RedirectTo -or $_.ForwardAsAttachmentTo } | Select-Object -First 50 | ForEach-Object {
            @{ id = "$($_.RuleIdentity)"; name = "$($_.Name)"; enabled = [bool]$_.Enabled; targets = @(@($_.ForwardTo) + @($_.RedirectTo) + @($_.ForwardAsAttachmentTo) | Where-Object { $_ } | ForEach-Object { "$_" }) } })
          $dom = @(Get-AcceptedDomain | ForEach-Object { "$($_.DomainName)" })
          Out-Result @{ ok = $true; data = @{ found = $true; smtp = ("$($m.ForwardingSmtpAddress)" -replace '^smtp:', ''); address = $fa; keep_copy = [bool]$m.DeliverToMailboxAndForward; rules = $rules; accepted_domains = $dom } }
        }
      }
      'clear-forwarding' {
        Set-Mailbox -Identity $p.identity -ForwardingSmtpAddress $null -ForwardingAddress $null -DeliverToMailboxAndForward $false -ErrorAction Stop
        $m = Get-EXOMailbox -Identity $p.identity -Properties ForwardingSmtpAddress, ForwardingAddress
        Out-Result @{ ok = $true; data = @{ smtp = "$($m.ForwardingSmtpAddress)"; address = "$($m.ForwardingAddress)" } }
      }
      'disable-inbox-rule' {
        if ("$($p.rule)" -notmatch '^\d{1,20}$') { throw 'rule must be the inbox rule id (digits)' }
        Disable-InboxRule -Mailbox $p.identity -Identity "$($p.rule)" -Confirm:$false -ErrorAction Stop
        $r = Get-InboxRule -Mailbox $p.identity -Identity "$($p.rule)" -ErrorAction Stop
        Out-Result @{ ok = $true; data = @{ enabled = [bool]$r.Enabled } }
      }
      'set-autoreply' {
        $msg = "$($p.message)"; if ($msg.Length -lt 5 -or $msg.Length -gt 2000) { throw 'message must be 5-2000 characters' }
        Set-MailboxAutoReplyConfiguration -Identity $p.identity -AutoReplyState Enabled -InternalMessage $msg -ExternalMessage $msg -ExternalAudience All -ErrorAction Stop
        Out-Result @{ ok = $true; data = @{ autoreply = 'enabled' } }
      }
    }
  } finally { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null }
} catch { Out-Result @{ ok = $false; error = ("$($_.Exception.Message)" -replace '\s+', ' ').Substring(0, [Math]::Min(300, ("$($_.Exception.Message)" -replace '\s+', ' ').Length)) } }
