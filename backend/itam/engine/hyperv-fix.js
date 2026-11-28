// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * How to fix a Hyper-V Optimization finding (engine/hyperv-optimize.js): for each kind of recommendation, the plan a person follows -
 * what to check first, the change, and how to confirm it worked - with the PowerShell to run on the host, filled in with the VM, the
 * virtual disk and the volume from the host's own report. The platform never runs any of it: the collectors are read-only, and a
 * change is made by a person (the four-eyes VM actions on Hyper-V Servers cover start / shut down / checkpoint).
 *   fixOf(rec) → { summary, steps: [{ kind: 'check'|'change'|'verify', title, text, cmd? }], risk, page? }
 * Names come from the host's report and may be anything: every value placed in a command is a single-quoted PowerShell literal
 * (q() doubles a quote and drops control characters), so a hostile VM name cannot break out of the command it is shown in.
 */
const q = (v) => "'" + String(v == null ? '' : v).replace(/[\u0000-\u001f\u007f]/g, '').replace(/['\u2018\u2019\u201a\u201b]/g, "''") + "'";
const gb = (n) => Math.max(1, Math.ceil(Number(n) || 0));
const up10 = (n) => Math.ceil((Number(n) || 0) / 10) * 10;

function fixOf(r) {
  const d = r.detail || {}, vm = q(d.vm || r.target), host = d.host || r.host;
  switch (r.kind) {
    case 'vhd-full': {
      const to = up10(Math.max((d.max_gb || 0) * 1.25, (d.max_gb || 0) + 20)), P = q(d.path || '');
      return { summary: 'The virtual disk is close to the largest size it may grow to. Either the guest really is full (extend the disk) or the file holds deleted data (clean and compact it). Find out which first.',
        steps: [
          { kind: 'check', title: 'How full is the guest itself?', text: 'Sign in to ' + (d.vm || r.target) + ' and look at the free space of the drive on this disk. On Windows:', cmd: 'Get-Volume | Where-Object DriveLetter | Select-Object DriveLetter, FileSystemLabel, @{n=\'FreeGB\';e={[math]::Round($_.SizeRemaining/1GB,1)}}, @{n=\'SizeGB\';e={[math]::Round($_.Size/1GB,1)}}' },
          { kind: 'check', title: 'The disk and its checkpoints (on ' + host + ')', text: 'A disk cannot be resized while the VM has checkpoints. Read-only:', cmd: 'Get-VHD -Path ' + P + ' | Select-Object Path, VhdType, @{n=\'MaxGB\';e={[math]::Round($_.Size/1GB,1)}}, @{n=\'FileGB\';e={[math]::Round($_.FileSize/1GB,1)}}\nGet-VMSnapshot -VMName ' + vm + ' | Select-Object Name, CreationTime\nGet-VMHardDiskDrive -VMName ' + vm + ' | Select-Object ControllerType, Path' },
          { kind: 'change', title: 'If the guest has plenty of free space: clean and compact', text: 'The file kept data the guest has deleted. In the guest, clear what is not needed' + (/log/i.test(d.vm || '') ? ' (old logs: set a retention period on the collector)' : '') + ', then release the space; in a maintenance window, shut the VM down and compact the file:', cmd: '# in the guest (Windows)\nOptimize-Volume -DriveLetter C -ReTrim -Verbose\n# on ' + host + ', VM shut down\nStop-VM -Name ' + vm + '\nOptimize-VHD -Path ' + P + ' -Mode Full\nStart-VM -Name ' + vm },
          { kind: 'change', title: 'If the guest really is full: extend the disk', text: 'Make sure the volume on the host has room for the extra ' + gb(to - (d.max_gb || 0)) + ' GB, remove the checkpoints first (a person decides), then extend. A VHDX on a SCSI controller extends while the VM runs (Generation 2, Windows Server 2012 R2 or later); on IDE, shut the VM down first.', cmd: 'Resize-VHD -Path ' + P + ' -SizeBytes ' + to + 'GB' },
          { kind: 'change', title: 'Then give the space to the guest', text: 'Windows guest (the partition on this disk, here C:):', cmd: 'Resize-Partition -DriveLetter C -Size (Get-PartitionSupportedSize -DriveLetter C).SizeMax\n# Linux guest: sudo growpart /dev/sda 1 ; then sudo resize2fs /dev/sda1 (ext4) or sudo xfs_growfs / (xfs)' },
          { kind: 'verify', title: 'Confirm', text: 'Get-VHD shows the new maximum and the guest shows the new free space. The host\'s next report (every 15 minutes) clears this finding.' }],
        risk: 'Extending a dynamic disk lets it take more of the volume - check the thin-provisioning figure for that volume on this page. Compacting needs the VM shut down. Take a backup first.' };
    }
    case 'volume-full': case 'volume-trend': {
      const V = String(d.volume || r.target), root = q(V.replace(/[\\/]*$/, '\\'));
      return { summary: (r.kind === 'volume-full' ? 'The host volume is nearly full. When it fills, every VM with a disk on it pauses.' : 'At its current growth the host volume fills within weeks.') + ' Free space in this order: old checkpoints, orphaned disks, moving a VM, extending the volume.',
        steps: [
          { kind: 'check', title: 'What takes the space (read-only, on ' + host + ')', text: 'The largest virtual disks and checkpoint files on ' + V + ':', cmd: 'Get-ChildItem -Path ' + root + ' -Recurse -Include *.vhdx,*.avhdx,*.vhd -ErrorAction SilentlyContinue | Sort-Object Length -Descending | Select-Object -First 20 FullName, @{n=\'GB\';e={[math]::Round($_.Length/1GB,1)}}' },
          { kind: 'check', title: 'Checkpoints and orphaned disks (read-only)', text: 'Checkpoints of every VM, and disk files on the volume that no VM uses:', cmd: 'Get-VM | Get-VMSnapshot | Select-Object VMName, Name, CreationTime\n$used = Get-VM | Get-VMHardDiskDrive | Select-Object -ExpandProperty Path\nGet-ChildItem -Path ' + root + ' -Recurse -Include *.vhdx,*.avhdx -ErrorAction SilentlyContinue | Where-Object { $used -notcontains $_.FullName } | Select-Object FullName, @{n=\'GB\';e={[math]::Round($_.Length/1GB,1)}}' },
          { kind: 'change', title: 'Delete checkpoints that are no longer needed', text: 'Hyper-V merges each checkpoint back into its disk; the merge needs some free space and takes time. A leftover backup checkpoint usually means a failed backup job - check the backup software too.', cmd: 'Remove-VMSnapshot -VMName <vm> -Name <checkpoint>' },
          { kind: 'change', title: 'Move a VM\'s storage to another volume (no downtime)', text: 'Storage live migration of one large VM to a volume with room:', cmd: 'Move-VMStorage -VMName <vm> -DestinationStoragePath <D:\\Hyper-V\\vm-name>' },
          { kind: 'change', title: 'Or extend the volume', text: 'Grow the LUN / disk on the storage first, then the partition on the host' + (d.csv ? ' (a Cluster Shared Volume: from the node that owns it)' : '') + ':', cmd: 'Update-HostStorageCache\nResize-Partition -DriveLetter <letter> -Size (Get-PartitionSupportedSize -DriveLetter <letter>).SizeMax' },
          { kind: 'verify', title: 'Confirm', text: 'Keep at least 15 % free. The next report shows the new figure; Capacity Planning shows the new fill date.' }],
        risk: 'Never delete a disk file that a VM or a backup still uses - the orphaned-disk list is a starting point, check each file before removing it. Delete checkpoints one at a time and let each merge finish.' };
    }
    case 'overcommit': return { summary: 'The dynamic disks on this volume may grow to more than the volume can hold. Nothing is wrong yet, but if they all grow, the volume fills and every VM on it stops.',
      steps: [
        { kind: 'check', title: 'Which disks can grow the most (read-only)', text: 'Maximum against current size of every dynamic disk on ' + (d.volume || r.target) + ':', cmd: 'Get-VM | Get-VMHardDiskDrive | Where-Object Path -like ' + q(String(d.volume || r.target).replace(/[\\/]*$/, '\\') + '*') + ' | ForEach-Object { Get-VHD -Path $_.Path } | Select-Object Path, VhdType, @{n=\'MaxGB\';e={[math]::Round($_.Size/1GB)}}, @{n=\'NowGB\';e={[math]::Round($_.FileSize/1GB)}}' },
        { kind: 'change', title: 'Agree a limit and keep to it', text: 'Do not extend more disks on this volume; place new VMs elsewhere; move the fastest-growing VM to another volume (Move-VMStorage), or extend the volume.' },
        { kind: 'verify', title: 'Confirm', text: 'The thin-provisioning chart on this page shows the volume under 150 %.' }],
      risk: 'Converting a dynamic disk to fixed takes the full size at once - only where the space exists.' };
    case 'memory-down': case 'memory-up': {
      const to = d.to_mb ? Math.round(d.to_mb / 1024 * 10) / 10 : null, up = r.kind === 'memory-up';
      return { summary: up ? 'The VM is short of memory and pages to disk. Give it more - check the host has it free first.' : 'The VM has much more memory than it uses. Giving some back frees the host for other VMs.',
        steps: [
          { kind: 'check', title: 'Current memory and the host\'s free memory (read-only)', text: 'On ' + host + ':', cmd: 'Get-VMMemory -VMName ' + vm + ' | Select-Object DynamicMemoryEnabled, @{n=\'StartupGB\';e={$_.Startup/1GB}}, @{n=\'MaxGB\';e={$_.Maximum/1GB}}\n(Get-Counter \'\\Memory\\Available MBytes\').CounterSamples.CookedValue' },
          { kind: 'check', title: 'Agree it with the owner', text: 'Confirm with the application owner and plan a short maintenance window: changing the memory of a VM with fixed memory needs it shut down.' },
          { kind: 'change', title: (up ? 'Give ' : 'Set ') + (d.vm || r.target) + ' ' + (to ? to + ' GB' : 'the new size'), text: 'Fixed memory - shut down, change, start:', cmd: 'Stop-VM -Name ' + vm + '\nSet-VMMemory -VMName ' + vm + ' -StartupBytes ' + (to ? Math.round(to) + 'GB' : '<size>GB') + '\nStart-VM -Name ' + vm + '\n# dynamic memory instead: change the maximum while it runs\n# Set-VMMemory -VMName ' + vm + ' -MaximumBytes ' + (to ? Math.round(to) + 'GB' : '<size>GB') },
          { kind: 'verify', title: 'Confirm', text: 'After a week of use the VM\'s memory demand should stay under 90 % of what it has. The daily snapshots on this page show it.' }],
        risk: up ? 'Do not give more than the host has free - the VM would not start.' : 'Keep the 25 % headroom this advice already includes; month-end or batch peaks may need more - check with the owner.', page: 'hyperv.html' };
    }
    case 'vcpu-down': case 'vcpu-up': return { summary: r.kind === 'vcpu-down' ? 'The VM has more virtual CPUs than it uses. Idle vCPUs still wait for free cores on a busy host and slow every VM on it.' : 'The VM is CPU-bound. More vCPUs help only if the application uses them - check first.',
      steps: [
        { kind: 'check', title: 'Current vCPUs (read-only)', text: 'On ' + host + ':', cmd: 'Get-VMProcessor -VMName ' + vm + ' | Select-Object Count, Reserve, Maximum' },
        { kind: 'change', title: 'Change the count in a maintenance window', text: 'The VM must be shut down:', cmd: 'Stop-VM -Name ' + vm + '\nSet-VMProcessor -VMName ' + vm + ' -Count ' + (d.to || '<n>') + '\nStart-VM -Name ' + vm },
        { kind: 'verify', title: 'Confirm', text: 'Watch the VM\'s CPU for a week on this page.' }],
      risk: 'Some licences count vCPUs (for example SQL Server) - check the licence before changing.', page: 'hyperv.html' };
    case 'idle': return { summary: 'The VM has been off for a long time but still holds its disks. Archive it, then delete it - after the owner agrees.',
      steps: [
        { kind: 'check', title: 'Who owns it and what is on it', text: 'Find the owner in the asset register, and confirm nothing needs it (a yearly job, a DR copy, a licence server).' },
        { kind: 'change', title: 'Export it as an archive first', text: 'To a share with room:', cmd: 'Export-VM -Name ' + vm + ' -Path <\\\\backup-server\\vm-archive>' },
        { kind: 'change', title: 'Then remove it and its disks', text: 'Remove-VM leaves the disk files; delete them after checking the paths:', cmd: '$disks = Get-VMHardDiskDrive -VMName ' + vm + ' | Select-Object -ExpandProperty Path\nRemove-VM -Name ' + vm + '\n$disks | ForEach-Object { Remove-Item -LiteralPath $_ -Confirm }' },
        { kind: 'verify', title: 'Confirm', text: 'The VM is gone from the next report and the volume shows the space back. Mark the asset retired in the asset register.' }],
      risk: 'Deleting cannot be undone - keep the export until the owner confirms.' };
    case 'checkpoint': return { summary: 'Old checkpoints slow the VM (every read walks the chain) and keep growing on disk. Delete the ones no one needs - Hyper-V merges the changes back.',
      steps: [
        { kind: 'check', title: 'The checkpoints (read-only)', text: 'On ' + host + ':', cmd: 'Get-VMSnapshot -VMName ' + vm + ' | Select-Object Name, CreationTime, SnapshotType' },
        { kind: 'change', title: 'Delete them', text: 'Ask who took them first. A "Recovery" type is left by backup software - check the backup job instead of deleting it by hand.', cmd: 'Get-VMSnapshot -VMName ' + vm + ' | Where-Object CreationTime -lt (Get-Date).AddDays(-7) | Remove-VMSnapshot' },
        { kind: 'verify', title: 'Confirm', text: 'Get-VMSnapshot returns nothing old, and the .avhdx files are gone once the merge finishes.' }],
      risk: 'The merge needs free space on the volume and takes time on large disks - do it outside busy hours.', page: 'hyperv.html' };
    case 'nic-busy': return { summary: 'A physical network card of the host is close to its link speed at peak. VMs on it slow down when it saturates.',
      steps: [
        { kind: 'check', title: 'Which VMs send the most (read-only)', text: 'On ' + host + ':', cmd: 'Get-NetAdapterStatistics -Name ' + q(d.nic || r.target) + '\nGet-VM | Get-VMNetworkAdapter | Sort-Object { $_.BandwidthPercentage } -Descending | Select-Object VMName, SwitchName, IPAddresses' },
        { kind: 'change', title: 'Add bandwidth or spread the load', text: 'Add a second card to the switch team (Switch Embedded Teaming), or move the busiest VMs to another switch / host:', cmd: 'Add-VMSwitchTeamMember -VMSwitchName <switch> -NetAdapterName <second NIC>' },
        { kind: 'verify', title: 'Confirm', text: 'The network chart on this page shows the peak under 70 %.' }],
      risk: 'Changing the team briefly interrupts traffic on that switch - do it in a maintenance window.' };
    case 'balance': return { summary: 'One host uses much more memory than another of the same site. Moving one VM evens them out, with no downtime.',
      steps: [
        { kind: 'check', title: 'Can it move? (read-only)', text: 'Checks the destination has the same switch names, the CPU is compatible and there is room:', cmd: 'Compare-VM -Name ' + vm + ' -DestinationHost ' + q(d.to || '') + ' | Select-Object -ExpandProperty Incompatibilities' },
        { kind: 'change', title: 'Live-migrate it', text: 'From ' + (d.from || host) + ' to ' + (d.to || 'the other host') + ':', cmd: 'Move-VM -Name ' + vm + ' -DestinationHost ' + q(d.to || '') },
        { kind: 'verify', title: 'Confirm', text: 'Both hosts show the new memory figures on this page after the next report.' }],
      risk: 'Live migration needs migration networks and authentication set up between the hosts - see the Virtual Network Map.', page: 'virtual-network-map.html' };
    default: return { summary: r.why || '', steps: [], risk: '' };
  }
}

module.exports = { fixOf, q };
