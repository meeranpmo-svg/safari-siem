#!/usr/bin/env node
// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// zyb-health - health of the server that hosts the platform (hardware, storage, services, backup) for the
// "Platform Health & Backup" dashboard. Runs as root every minute (zyb-health.timer, install-platform.sh) and writes
// /var/www/sentra/dashboards/health.json (no secrets). New / cleared problems are also written to the system log
// (tag zyb-health), so the SIEM sees them when it collects this server's logs.
//   hardware   vendor / model, virtual or physical, CPU temperatures, ECC memory errors, RAID (mdraid), SMART per disk
//   storage    every real file system: used %, inodes, read-only
//   system     CPU, load, memory, swap, uptime, kernel I/O / hardware errors in 24 h, NTP sync, failed systemd units
//   services   sentra-siem, sentra-itam, clickhouse, nginx, docker + the portal sync container, with since-when
//   network    interfaces: link, speed, errors / drops
//   tls        the portal certificate expiry
//   backup     /var/lib/zyb-backup/status.json (zyb-backup)
// Settings: /etc/zyb-health.conf (JSON, optional): {"disk_warn":85,"disk_crit":95,"temp_warn":80,"services":[...],"cert":"/etc/nginx/ssl/portal.crt"}
const fs = require('node:fs');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const OUT = process.env.ZYB_HEALTH_OUT || '/var/www/sentra/dashboards/health.json';
const STATE = process.env.ZYB_HEALTH_STATE || '/var/lib/zyb-health';
const BACKUP_STATUS = process.env.ZYB_BACKUP_STATUS || '/var/lib/zyb-backup/status.json';
let C = { disk_warn: 85, disk_crit: 95, inode_warn: 85, temp_warn: 80, temp_crit: 90, cert_warn_days: 30, backup_max_h: 26,
  services: ['sentra-siem', 'sentra-itam', 'clickhouse-server', 'nginx', 'docker'], containers: ['noc-m365'], cert: '' };
try { C = Object.assign(C, JSON.parse(fs.readFileSync('/etc/zyb-health.conf', 'utf8'))); } catch { /* defaults */ }

const read = (p) => { try { return fs.readFileSync(p, 'utf8'); } catch { return ''; } };
const run = (cmd, args, t) => { try { return execFileSync(cmd, args, { encoding: 'utf8', timeout: t || 8000, stdio: ['ignore', 'pipe', 'ignore'] }); } catch (e) { return e && e.stdout ? String(e.stdout) : ''; } };
const has = (cmd) => !!run('sh', ['-c', 'command -v ' + cmd]).trim();
const num = (v) => { const n = Number(v); return Number.isFinite(n) ? n : null; };
const issues = [];
const issue = (sev, area, key, text, fix) => issues.push({ sev, area, key, text, fix: fix || '' });

// ---- system
function cpuSample() { const l = read('/proc/stat').split('\n')[0].trim().split(/\s+/).slice(1).map(Number); return { idle: l[3] + (l[4] || 0), total: l.reduce((a, b) => a + b, 0) }; }
const s1 = cpuSample(); run('sleep', ['1']); const s2 = cpuSample();
const cpuPct = s2.total > s1.total ? Math.round((1 - (s2.idle - s1.idle) / (s2.total - s1.total)) * 1000) / 10 : null;
const cores = (read('/proc/cpuinfo').match(/^processor/mg) || []).length || 1;
const load = read('/proc/loadavg').split(' ').slice(0, 3).map(Number);
const mi = {}; read('/proc/meminfo').split('\n').forEach((l) => { const m = /^(\w+):\s+(\d+)/.exec(l); if (m) mi[m[1]] = Number(m[2]) * 1024; });
const mem = { total: mi.MemTotal || 0, avail: mi.MemAvailable || 0, swap_total: mi.SwapTotal || 0, swap_free: mi.SwapFree || 0 };
mem.pct = mem.total ? Math.round((1 - mem.avail / mem.total) * 1000) / 10 : null;
mem.swap_pct = mem.swap_total ? Math.round((1 - mem.swap_free / mem.swap_total) * 1000) / 10 : 0;
if (mem.pct >= 95) issue('crit', 'system', 'mem', `Memory ${mem.pct}% used`, 'Find the process using it (top / ps), add memory or reduce the ClickHouse cache.');
else if (mem.pct >= 90) issue('warn', 'system', 'mem', `Memory ${mem.pct}% used`, 'Watch it; add memory if it stays high.');
if (mem.swap_pct >= 50) issue('warn', 'system', 'swap', `Swap ${mem.swap_pct}% used`, 'The server is short of memory - add RAM.');
if (load[1] > cores * 2) issue('warn', 'system', 'load', `Load ${load[1]} on ${cores} cores (5 min)`, 'Check what is busy (top); the SIEM may be ingesting a burst or a query is running long.');
const uptime = Math.round(num(read('/proc/uptime').split(' ')[0]) || 0);
const os = (/PRETTY_NAME="?([^"\n]+)/.exec(read('/etc/os-release')) || [])[1] || 'Linux';
const kernel = run('uname', ['-r']).trim();
const virt = run('systemd-detect-virt', []).trim() || 'none';
const dmi = (f) => read('/sys/class/dmi/id/' + f).trim();
const hw = { vendor: dmi('sys_vendor'), model: dmi('product_name'), bios: [dmi('bios_vendor'), dmi('bios_version'), dmi('bios_date')].filter(Boolean).join(' '), virtual: virt !== 'none', virt,
  cpu: (/model name\s*:\s*(.+)/.exec(read('/proc/cpuinfo')) || [])[1] || '' };

// temperatures: hwmon (coretemp / k10temp / nvme / acpitz) + thermal zones
const temps = [];
try {
  for (const h of fs.readdirSync('/sys/class/hwmon')) {
    const d = path.join('/sys/class/hwmon', h), name = read(path.join(d, 'name')).trim();
    for (const f of fs.readdirSync(d).filter((x) => /^temp\d+_input$/.test(x))) {
      const v = num(read(path.join(d, f)).trim()); if (v === null) continue;
      const label = read(path.join(d, f.replace('_input', '_label'))).trim();
      temps.push({ sensor: name + (label ? ' ' + label : ''), c: Math.round(v / 100) / 10 });
    }
  }
} catch { /* none */ }
if (!temps.length) { try { for (const z of fs.readdirSync('/sys/class/thermal').filter((x) => /^thermal_zone/.test(x))) { const v = num(read(`/sys/class/thermal/${z}/temp`).trim()); if (v !== null) temps.push({ sensor: read(`/sys/class/thermal/${z}/type`).trim() || z, c: Math.round(v / 100) / 10 }); } } catch { /* none */ } }
const tmax = temps.length ? Math.max(...temps.map((t) => t.c)) : null;
if (tmax !== null && tmax >= C.temp_crit) issue('crit', 'hardware', 'temp', `Temperature ${tmax} °C`, 'Check the server fans, airflow and the room cooling now.');
else if (tmax !== null && tmax >= C.temp_warn) issue('warn', 'hardware', 'temp', `Temperature ${tmax} °C`, 'Check fans and airflow.');

// ECC memory errors (EDAC)
const ecc = { ce: 0, ue: 0, available: false };
try { for (const m of fs.readdirSync('/sys/devices/system/edac/mc').filter((x) => /^mc\d+/.test(x))) { ecc.available = true; ecc.ce += num(read(`/sys/devices/system/edac/mc/${m}/ce_count`).trim()) || 0; ecc.ue += num(read(`/sys/devices/system/edac/mc/${m}/ue_count`).trim()) || 0; } } catch { /* no EDAC */ }
if (ecc.ue) issue('crit', 'hardware', 'ecc-ue', `${ecc.ue} uncorrectable memory (ECC) errors`, 'A memory module is failing - plan a replacement with the hardware vendor.');
else if (ecc.ce > 100) issue('warn', 'hardware', 'ecc-ce', `${ecc.ce} corrected memory (ECC) errors`, 'A memory module may be wearing out - check the server management console (iDRAC / iLO).');

// software RAID
const raid = [];
const md = read('/proc/mdstat');
for (const m of md.matchAll(/^(md\d+)\s*:\s*(\w+)\s+(\w+)[^\n]*\n\s*\d+ blocks[^[]*\[(\d+)\/(\d+)\]\s*\[([U_]+)\]/mg)) {
  const r = { dev: m[1], state: m[2], level: m[3], disks: Number(m[4]), up: Number(m[5]), map: m[6], degraded: m[6].includes('_') }; raid.push(r);
  if (r.degraded) issue('crit', 'hardware', 'raid-' + r.dev, `RAID ${r.dev} (${r.level}) is degraded: ${r.up} of ${r.disks} disks`, 'Replace the failed disk and let the array rebuild.');
}
if (/recovery|resync/.test(md)) issue('info', 'hardware', 'raid-resync', 'A RAID array is rebuilding', '');

// SMART per physical disk
const disks = [];
const blk = (() => { try { return JSON.parse(run('lsblk', ['-J', '-d', '-o', 'NAME,TYPE,SIZE,MODEL,ROTA,TRAN,SERIAL'])).blockdevices || []; } catch { return []; } })();
const smartctl = has('smartctl');
for (const d of blk.filter((b) => b.type === 'disk' && !/^(loop|zram|sr|fd)/.test(b.name))) {
  const x = { dev: d.name, size: d.size, model: (d.model || '').trim(), type: d.rota === true || d.rota === '1' ? 'HDD' : /nvme/.test(d.name) ? 'NVMe' : 'SSD', smart: null };
  if (smartctl && !hw.virtual) {
    let j = null; try { j = JSON.parse(run('smartctl', ['-H', '-A', '-j', '/dev/' + d.name], 15000)); } catch { j = null; }
    if (j && j.smart_status) {
      const attr = (id) => ((j.ata_smart_attributes && j.ata_smart_attributes.table) || []).filter((a) => a.id === id)[0];
      const nv = j.nvme_smart_health_information_log || {};
      x.smart = { passed: j.smart_status.passed !== false, temp: (j.temperature && j.temperature.current) || null, hours: (j.power_on_time && j.power_on_time.hours) || nv.power_on_hours || null,
        realloc: attr(5) ? attr(5).raw.value : null, pending: attr(197) ? attr(197).raw.value : null, wear_pct: nv.percentage_used != null ? nv.percentage_used : null, media_errors: nv.media_errors != null ? nv.media_errors : null };
      if (!x.smart.passed) issue('crit', 'hardware', 'smart-' + d.name, `Disk ${d.name} (${x.model}) SMART health check FAILED`, 'Back up now and replace the disk.');
      else if ((x.smart.realloc || 0) > 0 || (x.smart.pending || 0) > 0 || (x.smart.media_errors || 0) > 0) issue('warn', 'hardware', 'smart-' + d.name, `Disk ${d.name} has bad sectors (reallocated ${x.smart.realloc || 0}, pending ${x.smart.pending || 0})`, 'The disk is wearing out - plan a replacement.');
      if ((x.smart.wear_pct || 0) >= 90) issue('warn', 'hardware', 'wear-' + d.name, `SSD ${d.name} ${x.smart.wear_pct}% worn`, 'Plan a replacement.');
    }
  }
  disks.push(x);
}

// file systems
const fsl = [];
for (const l of run('df', ['-P', '-B1', '-x', 'tmpfs', '-x', 'devtmpfs', '-x', 'squashfs', '-x', 'overlay', '-x', 'efivarfs']).split('\n').slice(1)) {
  const p = l.trim().split(/\s+/); if (p.length < 6 || !/^\//.test(p[0]) && !/^[a-z0-9]+:/.test(p[0])) continue;
  const mnt = p.slice(5).join(' '); if (/^\/(boot\/efi|snap|run|var\/lib\/docker\/)/.test(mnt)) continue;
  const total = Number(p[1]), used = Number(p[2]), pct = total ? Math.round(used / total * 1000) / 10 : 0;
  fsl.push({ dev: p[0], mount: mnt, total, used, avail: Number(p[3]), pct });
}
const ino = {}; run('df', ['-P', '-i']).split('\n').slice(1).forEach((l) => { const p = l.trim().split(/\s+/); if (p.length >= 6) ino[p.slice(5).join(' ')] = parseInt(p[4], 10); });
const ro = new Set(read('/proc/mounts').split('\n').map((l) => l.split(' ')).filter((p) => p[3] && /(^|,)ro(,|$)/.test(p[3]) && /^\//.test(p[0])).map((p) => p[1]));
for (const f of fsl) {
  f.inode_pct = Number.isFinite(ino[f.mount]) ? ino[f.mount] : null; f.readonly = ro.has(f.mount);
  if (f.pct >= C.disk_crit) issue('crit', 'storage', 'fs-' + f.mount, `${f.mount} is ${f.pct}% full`, f.mount === '/var/lib/clickhouse' || /clickhouse/.test(f.mount) ? 'Shorten the SIEM log retention or extend the disk.' : 'Free space or extend the disk.');
  else if (f.pct >= C.disk_warn) issue('warn', 'storage', 'fs-' + f.mount, `${f.mount} is ${f.pct}% full`, 'Plan more space.');
  if (f.inode_pct >= C.inode_warn) issue('warn', 'storage', 'ino-' + f.mount, `${f.mount}: ${f.inode_pct}% of inodes used`, 'Many small files - clean up old logs / temp files.');
  if (f.readonly && f.mount === '/') issue('crit', 'storage', 'ro-root', 'The root file system is read-only', 'The kernel remounted it after disk errors - check the disk and run fsck.');
}

// kernel errors (24 h): disk I/O, machine check, file system
const klog = run('journalctl', ['-k', '-p', 'err', '--since', '-24h', '--no-pager', '-o', 'cat'], 15000).split('\n').filter(Boolean);
const kio = klog.filter((l) => /I\/O error|blk_update_request|Buffer I\/O|medium error|ata\d+.*(failed|error)|nvme.*(timeout|reset)/i.test(l));
const kmce = klog.filter((l) => /mce|machine check|hardware error|EDAC/i.test(l));
const kfs = klog.filter((l) => /EXT4-fs error|XFS.*(corrupt|error)|remount.*read-only/i.test(l));
if (kio.length) issue('crit', 'hardware', 'kio', `${kio.length} disk I/O errors in the kernel log (24 h)`, 'A disk or its controller is failing - check SMART / the storage array.');
if (kmce.length) issue('crit', 'hardware', 'kmce', `${kmce.length} hardware (machine check) errors in the kernel log (24 h)`, 'Check the server management console (iDRAC / iLO) for the failing part.');
if (kfs.length) issue('crit', 'storage', 'kfs', `${kfs.length} file system errors in the kernel log (24 h)`, 'Run a file system check in a maintenance window.');

// time sync
const ntp = /yes/i.test(run('timedatectl', ['show', '-p', 'NTPSynchronized', '--value']));
if (!ntp) issue('warn', 'system', 'ntp', 'The clock is not synchronised (NTP)', 'Log times will drift - point chrony / systemd-timesyncd at the domain controllers.');
const failedUnits = run('systemctl', ['--failed', '--no-legend', '--plain']).split('\n').map((l) => l.trim().split(/\s+/)[0]).filter(Boolean);
if (failedUnits.length) issue('warn', 'services', 'failed-units', `${failedUnits.length} failed system services: ${failedUnits.slice(0, 5).join(', ')}`, 'systemctl status <name> shows why.');

// services
const services = [];
for (const s of C.services) {
  const p = {}; run('systemctl', ['show', s, '-p', 'LoadState,ActiveState,SubState,ActiveEnterTimestamp,NRestarts']).split('\n').forEach((l) => { const i = l.indexOf('='); if (i > 0) p[l.slice(0, i)] = l.slice(i + 1); });
  if (p.LoadState === 'not-found' || !p.LoadState) continue;
  const x = { name: s, active: p.ActiveState, sub: p.SubState, since: p.ActiveEnterTimestamp || '', restarts: num(p.NRestarts) || 0 }; services.push(x);
  if (x.active !== 'active') issue('crit', 'services', 'svc-' + s, `${s} is ${x.active}`, `sudo systemctl status ${s}; sudo journalctl -u ${s} -n 50`);
  else if (x.restarts > 3) issue('warn', 'services', 'rst-' + s, `${s} restarted ${x.restarts} times`, `sudo journalctl -u ${s} -n 100 shows why it keeps restarting.`);
}
if (has('docker')) {
  for (const c of C.containers) {
    const st = run('docker', ['inspect', '-f', '{{.State.Status}}|{{.State.StartedAt}}|{{.RestartCount}}', c]).trim(); if (!st) continue;
    const [status, started, rc] = st.split('|'); services.push({ name: 'container ' + c, active: status === 'running' ? 'active' : status, sub: status, since: started, restarts: num(rc) || 0 });
    if (status !== 'running') issue('crit', 'services', 'ctr-' + c, `Container ${c} is ${status}`, `sudo docker start ${c}; sudo docker logs --tail 50 ${c}`);
  }
}

// network interfaces
const nics = [];
try {
  for (const n of fs.readdirSync('/sys/class/net').filter((x) => x !== 'lo' && !/^(veth|docker|br-|virbr)/.test(x))) {
    const g = (f) => read(`/sys/class/net/${n}/${f}`).trim(), st = (f) => num(g('statistics/' + f)) || 0;
    const x = { name: n, state: g('operstate'), speed: num(g('speed')), rx_err: st('rx_errors'), tx_err: st('tx_errors'), rx_drop: st('rx_dropped'), mac: g('address') };
    nics.push(x);
    const prev = (() => { try { return JSON.parse(read(path.join(STATE, 'nic-' + n + '.json'))); } catch { return null; } })();
    if (prev && (x.rx_err + x.tx_err) - (prev.rx_err + prev.tx_err) > 100) issue('warn', 'network', 'nic-' + n, `${n}: ${(x.rx_err + x.tx_err) - (prev.rx_err + prev.tx_err)} new interface errors since the last check`, 'Check the cable / switch port (duplex, speed).');
    try { fs.mkdirSync(STATE, { recursive: true }); fs.writeFileSync(path.join(STATE, 'nic-' + n + '.json'), JSON.stringify(x)); } catch { /* read-only */ }
  }
} catch { /* none */ }
if (nics.length && !nics.some((n) => n.state === 'up')) issue('crit', 'network', 'nic-down', 'No network interface is up', '');

// portal certificate
let tls = null;
const certFile = C.cert || (() => { const m = /ssl_certificate\s+([^;\s]+);/.exec(run('sh', ['-c', 'cat /etc/nginx/conf.d/*.conf /etc/nginx/sites-enabled/* 2>/dev/null'])); return m ? m[1] : ''; })();
if (certFile && has('openssl')) {
  const o = run('openssl', ['x509', '-in', certFile, '-noout', '-enddate', '-subject']);
  const end = (/notAfter=(.+)/.exec(o) || [])[1];
  if (end) { const days = Math.floor((Date.parse(end) - Date.now()) / 86400000); tls = { file: certFile, expires: new Date(Date.parse(end)).toISOString(), days, subject: ((/subject=\s*(.+)/.exec(o) || [])[1] || '').trim() };
    if (days < 0) issue('crit', 'tls', 'cert', `The portal certificate expired ${-days} days ago`, 'Renew the certificate and reload nginx.');
    else if (days <= C.cert_warn_days) issue('warn', 'tls', 'cert', `The portal certificate expires in ${days} days`, 'Renew it before it expires.'); }
}

// backup
let backup = null;
try { backup = JSON.parse(read(BACKUP_STATUS)); } catch { backup = null; }
if (!backup) issue('warn', 'backup', 'backup-none', 'No backup has run yet', 'Open Platform Health & Backup → Run backup now, or wait for the nightly run.');
else {
  const last = backup.last || {}; const okAt = Date.parse(backup.last_ok_at || '') || 0;
  if (last.ok === false) issue('crit', 'backup', 'backup-failed', 'The last backup FAILED: ' + (last.error || 'see the backup log'), 'sudo journalctl -u zyb-backup -n 50');
  if (okAt && Date.now() - okAt > C.backup_max_h * 3600000) issue('warn', 'backup', 'backup-old', `Last good backup is ${Math.round((Date.now() - okAt) / 3600000)} hours old`, 'Check the backup timer: systemctl status zyb-backup.timer');
  if (last.ok && last.remote === 'failed') issue('warn', 'backup', 'backup-remote', 'The backup was not copied off this server: ' + (last.remote_error || ''), 'A backup only on this server is lost with the server - fix the remote copy.');
  if (backup.config && !backup.config.remote) issue('warn', 'backup', 'backup-local', 'Backups are kept on this server only', 'Set a remote copy (network share or SFTP) in /etc/zyb-backup.conf.');
}

// write + log state changes
const sev = { crit: 3, warn: 2, info: 1 };
issues.sort((a, b) => sev[b.sev] - sev[a.sev]);
const status = issues.some((i) => i.sev === 'crit') ? 'critical' : issues.some((i) => i.sev === 'warn') ? 'warning' : 'ok';
const out = { time: Math.floor(Date.now() / 1000), host: run('hostname', []).trim(), os, kernel, uptime, status, issues,
  hardware: Object.assign(hw, { temps, temp_max: tmax, ecc, raid, disks, smart_available: smartctl && !hw.virtual }),
  system: { cpu_pct: cpuPct, cores, load, mem, ntp, failed_units: failedUnits, kernel_errors_24h: { io: kio.length, hardware: kmce.length, fs: kfs.length, sample: kio.concat(kmce, kfs).slice(0, 5) } },
  storage: fsl, services, network: nics, tls, backup };
try {
  const tmp = OUT + '.tmp'; fs.mkdirSync(path.dirname(OUT), { recursive: true }); fs.writeFileSync(tmp, JSON.stringify(out)); fs.chmodSync(tmp, 0o644); fs.renameSync(tmp, OUT);
  const pf = path.join(STATE, 'issues.json'), prev = (() => { try { return JSON.parse(read(pf)); } catch { return {}; } })(), now = {};
  for (const i of issues) { now[i.key] = i.sev; if (prev[i.key] !== i.sev) run('logger', ['-t', 'zyb-health', '-p', i.sev === 'crit' ? 'user.crit' : i.sev === 'warn' ? 'user.warning' : 'user.info', `${i.sev.toUpperCase()} ${i.area}: ${i.text}`]); }
  for (const k of Object.keys(prev)) if (!now[k]) run('logger', ['-t', 'zyb-health', '-p', 'user.notice', `CLEARED ${k}`]);
  fs.mkdirSync(STATE, { recursive: true }); fs.writeFileSync(pf, JSON.stringify(now));
} catch (e) { process.stderr.write('zyb-health: ' + e.message + '\n'); process.exit(1); }
