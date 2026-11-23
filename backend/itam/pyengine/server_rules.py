# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
"""Servers by platform (Servers & Virtualization -> VMware / Windows / Exchange / Solaris / Oracle Linux). engine/servers.js
gathers, for every server and VM in the asset register, what the platform already holds about it (asset record, Asset
Discovery device, vCenter / Prism facts, backup status, end of life, Endpoint Central patches, the operating system read
over SSH); this module decides which platform each one is, what is wrong with it and what to do. Standard library only.

  servers.assess {servers, platform, settings, sources, now}  -> {platforms, servers, findings, summary}

Platform is decided from facts only, and the reason is kept (shown on the page): the OS the asset record / Asset Discovery /
the SSH login reported, the hypervisor the VM runs on, installed software, tags, the host name pattern for Exchange.
A server whose OS nobody recorded is "unknown" - listed so it can be fixed, never guessed from its name alone.
A value no source gave is "not reported", never healthy.
"""
import re
import time

SEV = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
PLATFORMS = {
    'vmware': 'VMware ESXi hosts and the VMs on them',
    'windows': 'Windows Server',
    'exchange': 'Exchange Server',
    'solaris': 'Oracle Solaris',
    'oracle_linux': 'Oracle Linux',
    'linux': 'Other Linux (RHEL, CentOS, SUSE, Ubuntu ...)',
    'nutanix': 'Nutanix AHV hosts',
    'unknown': 'Operating system not recorded',
}
UNIX = ('solaris', 'oracle_linux', 'linux')
DEFAULTS = {'fs_warn': 85, 'fs_high': 90, 'fs_crit': 95, 'patch_days': 180, 'uptime_days': 365, 'stale_min': 60}
DAY = 86400000


def _low(v):
    return str(v or '').lower()


def _text(s):
    return ' '.join(_low(x) for x in (s.get('os'), s.get('device_os'), s.get('unix_os'), s.get('read_os'), s.get('model'), s.get('vendor')))


def exchange_why(s):
    """the same facts as engine/sysadmin-sync.js exchangeWhy (an Exchange server is a Windows server), plus what Business Services
    and the Email Route Map register found (engine/exchange-evidence.js)"""
    for sw in s.get('software') or []:
        if re.search(r'microsoft exchange server', str(sw), re.I):
            return 'software: ' + str(sw)[:80]
    if 'exchange' in [_low(t) for t in s.get('tags') or []]:
        return 'tag: exchange'
    if s.get('exchange_hint'):
        return str(s['exchange_hint'])[:200]
    if re.search(r'\bexchange\b', ' '.join(str(x or '') for x in (s.get('os'), s.get('model'), s.get('notes'))), re.I):
        return 'asset record mentions Exchange'
    host = _low(s.get('name')).split('.')[0]
    if re.search(r'^(exch|exchange|mbx|exc|ex20\d\d|ex1[369])[-_]?\d*[a-z]?$|[-_](exch|mbx|exchange)\d*$', host):
        return 'host name ' + str(s.get('name'))
    if re.search(r'(^|[-_])mail(srv|svr|server)?[-_]?\d*[a-z]?($|[-_])', host) and 'windows' in _text(s):
        return 'host name ' + str(s.get('name')) + ' (Windows mail server)'
    return ''


def classify(s):
    """-> (platforms, why). A Windows VM on vCenter is ['windows', 'vmware']: it appears on both pages."""
    t, out, why = _text(s), [], []
    if re.search(r'\besxi?\b|vmkernel|vmware esx', t):
        out.append('vmware'); why.append('OS: ESXi')
    elif re.search(r'\bahv\b|nutanix', t) and s.get('type') == 'server':
        out.append('nutanix'); why.append('OS: Nutanix AHV')
    ex = exchange_why(s)
    if 'windows' in t or ex:
        out.append('windows'); why.append('OS: Windows' if 'windows' in t else 'Exchange runs only on Windows')
        if ex:
            out.append('exchange'); why.append('Exchange - ' + ex)
    elif re.search(r'sunos|solaris', t):
        out.append('solaris'); why.append('OS: Solaris')
    elif re.search(r'oracle linux|oraclelinux|\bol ?\d|\.el\d+uek|\buek\b', t):
        out.append('oracle_linux'); why.append('OS: Oracle Linux')
    elif re.search(r'linux|red ?hat|rhel|centos|ubuntu|suse|sles|debian|rocky|alma', t):
        out.append('linux'); why.append('OS: Linux')
    if s.get('hypervisor') == 'vcenter' and 'vmware' not in out:
        out.append('vmware'); why.append('VM in vCenter')
    if s.get('hypervisor') == 'nutanix' and 'nutanix' not in out:
        out.append('nutanix'); why.append('VM in Prism')
    if not [p for p in out if p not in ('vmware', 'nutanix')] and not (s.get('type') == 'server' and out):
        out.append('unknown'); why.append('no operating system recorded by the asset record, Asset Discovery or a login')
    return out, why


def _ms(v):
    if v is None or v == '':
        return None
    if isinstance(v, (int, float)):
        return int(v)
    try:
        return int(time.mktime(time.strptime(str(v)[:10], '%Y-%m-%d')) * 1000)
    except ValueError:
        return None


def findings(s, plats, st, src, now):
    out, name = [], s.get('name') or s.get('id')

    def add(sev, kind, title, rec, evidence=None):
        out.append({'asset_id': s.get('id'), 'server': name, 'severity': sev, 'kind': kind, 'title': title, 'recommendation': rec,
                    'evidence': [e for e in (evidence or []) if e]})
    # register facts
    if s.get('warranty_end') and (_ms(s['warranty_end']) or now) < now:
        add('low', 'warranty', '%s: hardware warranty ended %s' % (name, s['warranty_end']), 'Renew support or plan the replacement (End of Life & Isolation).')
    lc = s.get('lifecycle')
    if lc and lc.get('status') == 'eol':
        add('high', 'eol', '%s: %s is past end of support%s' % (name, lc.get('product') or 'the operating system', ' (' + lc['eol'] + ')' if lc.get('eol') else ''),
            'No security fixes any more: upgrade or replace it, or isolate it and record an exception (End of Life & Isolation).')
    elif lc and lc.get('status') == 'soon':
        add('medium', 'eol', '%s: %s reaches end of support%s' % (name, lc.get('product') or 'the operating system', ' in %s days' % lc['days'] if lc.get('days') is not None else ' soon'),
            'Plan the upgrade before support ends.')
    bk = s.get('backup')
    if src.get('backup') and bk and s.get('power') != 'off':
        if bk.get('status') == 'none':
            add('high', 'backup', '%s: no backup found' % name, 'Add it to a backup job (Veeam / Nutanix / Commvault), or record why it needs none on Backup Status.')
        elif bk.get('status') == 'failed':
            add('high', 'backup', '%s: last backup failed' % name, 'Check the backup job log and run it again.', ['last attempt %s' % bk.get('last_attempt')] if bk.get('last_attempt') else [])
        elif bk.get('status') == 'stale':
            add('medium', 'backup', '%s: last good backup %s hours ago' % (name, bk.get('age_hours')), 'The backup is older than its target: check the job schedule.')
    pt = s.get('patch')
    if pt and pt.get('critical'):
        add('high', 'patch', '%s: %s critical patches missing (Endpoint Central)' % (name, pt['critical']), 'Approve and deploy them in the next patch window (ManageEngine).')
    elif pt and pt.get('missing'):
        add('medium', 'patch', '%s: %s patches missing (Endpoint Central)' % (name, pt['missing']), 'Deploy them in the next patch window (ManageEngine).')
    if 'unknown' in plats:
        add('low', 'os-unknown', '%s: operating system not recorded' % name, 'Fill in the OS on the asset, or let Asset Discovery read it (WMI / SSH login) - until then it cannot be checked as a server of its platform.')
    if s.get('power') == 'off':
        add('low', 'powered-off', '%s: VM is powered off%s' % (name, ' (as of ' + str(s.get('power_at'))[:16] + ')' if s.get('power_at') else ''),
            'If it is no longer needed, retire it in the asset register so licences and backups are released.')
    if not any(p in UNIX for p in plats):
        return out
    # operating system read over SSH (Solaris / Linux)
    r = s.get('os_read') or {}
    v = r.get('server')
    if not v:
        ssh = s.get('ssh') or {}
        why = ('no SSH login: Asset Discovery has not proven one on this server - choose a read-only login here' if not ssh.get('credential')
               else 'the SSH host key has not been seen yet - run Asset Discovery (unix method) on it' if ssh.get('host_key') in (None, 'not seen')
               else 'the SSH host key is %s - an administrator must trust it in Asset Discovery first' % ssh.get('host_key') if ssh.get('host_key') != 'trusted'
               else 'could not be read: %s' % (r.get('error_class') or r.get('error')) if r.get('error')
               else 'not read yet - it is read on the next pass')
        add('medium' if r.get('error') else 'low', 'not-read', '%s: operating system not read' % name, why)
        return out
    if r.get('at') and now - (_ms(r['at']) if not str(r['at']).isdigit() else int(r['at'])) > st['stale_min'] * 60000 * 4:
        add('low', 'stale', '%s: last OS reading is old (%s)' % (name, str(r['at'])[:16]), 'The SSH reading has not succeeded recently - check the login and the network path.')
    for f in v.get('filesystems') or []:
        p = f.get('used_pct')
        if p is None:
            continue
        sev = 'critical' if p >= st['fs_crit'] else 'high' if p >= st['fs_high'] else 'medium' if p >= st['fs_warn'] else None
        if sev:
            add(sev, 'filesystem', '%s %s %s%% full' % (name, f.get('mount'), p), 'Free space (old logs, core files, package caches) or extend the file system / ZFS dataset before applications stop writing.',
                ['%s MB free' % round((f.get('avail_kb') or 0) / 1024)])
    for i in v.get('inodes') or []:
        if (i.get('used_pct') or 0) >= 90:
            add('high', 'inodes', '%s %s: %s%% of inodes used' % (name, i.get('mount'), i['used_pct']), 'Millions of small files (spool, session or log files): find and purge them.')
    mt, ma = v.get('mem_total_mb'), v.get('mem_avail_mb')
    if mt and ma is not None:
        pc = round(ma / mt * 100)
        if pc < 10:
            add('high' if pc < 5 else 'medium', 'memory', '%s: only %s%% memory available' % (name, pc), 'Find the process using it (top / prstat) and add memory or move a workload.', ['%s MB of %s MB' % (ma, mt)])
    stt, su = v.get('swap_total_mb'), v.get('swap_used_mb')
    if stt and su is not None and su / stt > 0.5:
        add('medium', 'swap', '%s: %s%% of swap in use' % (name, round(su / stt * 100)), 'The server is short of memory: everything on it slows down. Add memory or reduce what runs on it.')
    nc, l5 = v.get('ncpu'), v.get('load5')
    if nc and l5 is not None and l5 / nc > 1.5:
        add('high' if l5 / nc > 2 else 'medium', 'load', '%s: load %s on %s CPUs (5 min)' % (name, l5, nc), 'CPU is saturated: see the top processes.',
            ['%s %s%% CPU' % (x.get('command'), x.get('cpu_pct')) for x in (v.get('top') or [])[:3]])
    for sv in v.get('failed_services') or []:
        add('high', 'service', '%s: service %s is %s' % (name, sv.get('name'), sv.get('state')),
            'svcs -xv %s (Solaris) / systemctl status %s (Linux): read why it stopped, fix it, then svcadm clear / systemctl restart.' % (sv.get('name'), sv.get('name')))
    if v.get('ntp_synced') is False:
        add('medium', 'ntp', '%s: clock not synchronised (NTP)' % name, 'Fix chrony / ntpd: authentication, logs and clusters need synchronised clocks.')
    lp = _ms(v.get('last_patch'))
    if lp and now - lp > st['patch_days'] * DAY:
        add('medium', 'os-patch', '%s: last OS update installed %s' % (name, v.get('last_patch')), 'Patch the operating system in the next maintenance window (yum / dnf update; pkg update on Solaris).')
    if v.get('uptime_s') is not None and v['uptime_s'] > st['uptime_days'] * 86400:
        add('low', 'uptime', '%s: up %s days' % (name, round(v['uptime_s'] / 86400)), 'A server not restarted for this long is not running its latest kernel patches.')
    return out


def assess(r):
    st = dict(DEFAULTS)
    st.update({k: v for k, v in (r.get('settings') or {}).items() if k in DEFAULTS and isinstance(v, (int, float))})
    src, now, want = r.get('sources') or {}, int(r.get('now') or time.time() * 1000), r.get('platform') or ''
    counts = {k: {'label': PLATFORMS[k], 'servers': 0, 'critical': 0, 'high': 0, 'read': 0} for k in PLATFORMS}
    rows, allf = [], []
    for s in r.get('servers') or []:
        plats, why = classify(s)
        F = findings(s, plats, st, src, now)
        worst = max((f['severity'] for f in F), key=lambda x: SEV[x], default=None)
        v = (s.get('os_read') or {}).get('server')
        for p in plats:
            c = counts[p]
            c['servers'] += 1
            c['critical'] += sum(1 for f in F if f['severity'] == 'critical')
            c['high'] += sum(1 for f in F if f['severity'] == 'high')
            if v:
                c['read'] += 1
        if want and want not in plats:
            continue
        fsmax = max((f for f in (v or {}).get('filesystems') or [] if f.get('used_pct') is not None), key=lambda f: f['used_pct'], default=None)
        rows.append(dict(s, platforms=plats, platform_why=why, findings=len(F), worst=worst, fs_fullest=fsmax,
                         os_shown=(v or {}).get('os') or s.get('os') or s.get('device_os') or s.get('unix_os') or None))
        allf.extend(F)
    allf.sort(key=lambda f: -SEV[f['severity']])
    rows.sort(key=lambda x: (-SEV.get(x['worst'] or '', 0), _low(x.get('name'))))
    return {'platform': want or None, 'label': PLATFORMS.get(want) if want else 'All servers', 'platforms': counts, 'servers': rows, 'findings': allf[:2000], 'settings': st,
            'summary': {'servers': len(rows), 'critical': sum(1 for f in allf if f['severity'] == 'critical'), 'high': sum(1 for f in allf if f['severity'] == 'high'),
                        'read': sum(1 for x in rows if (x.get('os_read') or {}).get('server')), 'unix': sum(1 for x in rows if any(p in UNIX for p in x['platforms'])),
                        'eol': sum(1 for x in rows if (x.get('lifecycle') or {}).get('status') == 'eol'),
                        'no_backup': sum(1 for x in rows if (x.get('backup') or {}).get('status') in ('none', 'failed')) if src.get('backup') else None,
                        'powered_off': sum(1 for x in rows if x.get('power') == 'off')}}


OPS = {'servers.assess': assess}
