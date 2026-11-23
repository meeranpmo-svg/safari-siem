// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Approved network tasks for the AI Network Engineer — Cisco IOS / IOS-XE switches and routers.
 * The engineer (or a person) proposes a TASK from a fixed template; the exact commands are built HERE from validated
 * parameters (never from free text, never from the AI's own wording); an administrator who did not ask for it approves
 * the change plan; then an operator presses Run and the SIEM carries it out with the device's WRITE login:
 *   1 prechecks (read-only show commands) — the task is refused when the device is not in the state it expects
 *   2 backup: the running configuration (secrets removed) is kept on the plan
 *   3 the configuration lines are pushed (cli-helper.py op "config", which checks every line against its own allowlist)
 *   4 verification with show commands: the result must be what the task promised
 *   5 verification failed or the push failed → the computed rollback is pushed at once (op "config") and the plan says so
 *   6 verified → write memory; the plan is marked applied by "<operator> via the SIEM" and validated
 * Templates: vlan-create · port-access-vlan · trunk-vlan-add · port-description · port-shutdown · port-enable ·
 *            ios-stage (copy image, verify MD5 against the approved value, set boot, save — never reloads) · ios-reload
 *            (scheduled "reload in N", cancelled by rollback). Anything else stays a manual change plan.
 * The write account is separate from the read-only one. With PAM configured (pam.js) it is CHECKED OUT from the PAM for
 * each run (the device stores only the PAM account reference, netops.devices.<id>.ssh_write.pam) and checked in afterwards;
 * with PAM required (the default once PAM is on) a stored write password is never used. Without either, no task runs. The SSH host key must be pinned (cli.js) — no trust-on-first-use. config netops.tasks.enabled=false
 * switches execution off everywhere.
 *   createTasks({ inventory, cli, changes, config, log, runner })
 *     .catalogue()  .build(deviceId, type, params) → preview   .propose({device,type,params,reason,…}, by) → plan
 *     .execute(planId, who) → plan (with .execution)          .status(deviceId?) → {enabled, reason}
 */
const { redact, DEVICE_TYPE } = require('./cli');

class TaskError extends Error { constructor(code, msg) { super(msg); this.code = code; this.errors = [msg]; } }
const bad = (m) => new TaskError(400, m);

/* ---------- validated parameters ---------- */
const IFNAME = /^(?:GigabitEthernet|TenGigabitEthernet|TwentyFiveGigE|FortyGigabitEthernet|HundredGigE|FastEthernet|Ethernet|Gi|Te|Tw|Fo|Hu|Fa|Eth)\d{1,2}(?:\/\d{1,3}){1,3}$/i;
const PORTCH = /^(?:Port-channel|Po)\d{1,3}$/i;
function vlanId(v, what = 'VLAN') {
  const n = Number(v);
  if (!Number.isInteger(n) || n < 2 || n > 4094 || (n >= 1002 && n <= 1005)) throw bad(`${what} must be 2-4094 (not 1, not 1002-1005)`);
  return n;
}
function ifList(a, { trunk } = {}) {
  const list = (Array.isArray(a) ? a : String(a || '').split(/[\s,;]+/)).map((x) => String(x).trim()).filter(Boolean);
  if (!list.length) throw bad('at least one interface is required');
  if (list.length > 48) throw bad('at most 48 interfaces per task');
  for (const i of list) if (!IFNAME.test(i) && !(trunk && PORTCH.test(i))) throw bad(`"${i.slice(0, 40)}" is not a physical interface name (e.g. GigabitEthernet1/0/12)`);
  return [...new Set(list)];
}
function vlanList(a) {
  const list = (Array.isArray(a) ? a : String(a || '').split(/[\s,;]+/)).map((x) => String(x).trim()).filter(Boolean).map((x) => vlanId(x));
  if (!list.length) throw bad('at least one VLAN is required'); if (list.length > 32) throw bad('at most 32 VLANs per task');
  return [...new Set(list)].sort((x, y) => x - y);
}
const text = (v, re, what, max) => { const s = String(v == null ? '' : v).trim(); if (!s) return ''; if (s.length > max || !re.test(s)) throw bad(`${what}: letters, digits and ${re === DESC ? 'space _ . : / ( ) # -' : '_ . -'} only, max ${max}`); return s; };
const DESC = /^[A-Za-z0-9 _.:/()#-]+$/, VNAME = /^[A-Za-z0-9_.-]+$/;

/* ---------- parsing IOS output ---------- */
function ifConfig(out) {   // show running-config interface X
  const L = String(out || '').split('\n').map((l) => l.replace(/\r$/, ''));
  const has = (re) => L.some((l) => re.test(l)), get = (re) => { for (const l of L) { const m = re.exec(l); if (m) return m[1]; } return null; };
  return { exists: has(/^interface /i), trunk: has(/^\s*switchport mode trunk/i), access: has(/^\s*switchport mode access/i), anyMode: has(/^\s*switchport mode /i),
    accessVlan: get(/^\s*switchport access vlan (\d+)/i), description: get(/^\s*description (.+)$/i), shutdown: has(/^\s*shutdown\s*$/i),
    allowed: get(/^\s*switchport trunk allowed vlan (.+)$/i) };
}
const vlanAbsent = (out) => /not found in current VLAN database|VLAN id \d+ not found/i.test(String(out || ''));
const vlanBriefHas = (out, n, name) => String(out || '').split('\n').some((l) => new RegExp('^' + n + '\\s+' + (name ? name.replace(/[.]/g, '\\.') : '\\S+') + '\\s+').test(l));
const swAccess = (out) => { const m = /Access Mode VLAN:\s*(\d+)/i.exec(String(out || '')), a = /Administrative Mode:\s*(.+)/i.exec(String(out || '')); return { vlan: m ? Number(m[1]) : null, mode: a ? a[1].trim().toLowerCase() : '' }; };
function vtyBlocks(text) {   // "line vty 0 4" blocks with their transport input
  const out = []; let cur = null;
  for (const l of String(text || '').split(/\r?\n/)) {
    if (/^line vty \d+( \d+)?\s*$/i.test(l)) { cur = { head: l.trim(), transport: '' }; out.push(cur); continue; }
    if (/^\S/.test(l)) { cur = null; continue; }
    const m = cur && /^\s+transport input (.+?)\s*$/i.exec(l); if (m) cur.transport = m[1].toLowerCase().trim();
  }
  return out;
}
function expand(spec) {   // "1,10-12,20" → Set
  const s = new Set(); if (!spec || /^all$/i.test(spec.trim())) return null;
  for (const p of String(spec).split(',')) { const m = /^(\d+)(?:-(\d+))?$/.exec(p.trim()); if (!m) continue; const a = +m[1], b = m[2] ? +m[2] : a; for (let i = a; i <= b && i - a < 4095; i++) s.add(i); }
  return s;
}

/* ---------- templates ----------
   pre(p)               show commands read before anything changes
   plan(p, pre)         → {commands, rollback}  (throws when the device is not in the expected state)
   verify(p)            show commands read after the push      check(p, out) → {ok, detail} */
const TEMPLATES = {
  'vlan-create': {
    title: (p) => `Create VLAN ${p.vlan}${p.name ? ' (' + p.name + ')' : ''}`, risk: 'low',
    norm: (b) => ({ vlan: vlanId(b.vlan), name: text(b.name, VNAME, 'VLAN name', 32) }),
    pre: (p) => [`show vlan id ${p.vlan}`],
    plan: (p, pre) => { if (!vlanAbsent(pre[0])) throw new TaskError(409, `VLAN ${p.vlan} already exists on the device - nothing to create`); return { commands: [`vlan ${p.vlan}`].concat(p.name ? [` name ${p.name}`] : []), rollback: [`no vlan ${p.vlan}`] }; },
    verify: () => ['show vlan brief'],
    check: (p, out) => (vlanBriefHas(out[0], p.vlan, p.name || null) ? { ok: true, detail: `VLAN ${p.vlan} is in the VLAN database` } : { ok: false, detail: `VLAN ${p.vlan} is not shown by show vlan brief` }),
  },
  'port-access-vlan': {
    title: (p) => `Put ${p.interfaces.length} port(s) in VLAN ${p.vlan}`, risk: 'medium',
    norm: (b) => ({ vlan: vlanId(b.vlan), interfaces: ifList(b.interfaces), description: text(b.description, DESC, 'description', 80) }),
    pre: (p) => [`show vlan id ${p.vlan}`].concat(p.interfaces.map((i) => `show running-config interface ${i}`)),
    plan: (p, pre) => {
      if (vlanAbsent(pre[0])) throw new TaskError(409, `VLAN ${p.vlan} does not exist on the device - create it first (task vlan-create)`);
      const commands = [], rollback = [];
      p.interfaces.forEach((i, k) => {
        const c = ifConfig(pre[k + 1]);
        if (!c.exists) throw new TaskError(409, `${i} does not exist on the device`);
        if (c.trunk) throw new TaskError(409, `${i} is a trunk (an uplink) - making it an access port would cut traffic; it is refused`);
        commands.push(`interface ${i}`, ' switchport mode access', ` switchport access vlan ${p.vlan}`);
        if (p.description) commands.push(` description ${p.description}`);
        rollback.push(`interface ${i}`, c.accessVlan ? ` switchport access vlan ${c.accessVlan}` : ' no switchport access vlan');
        if (!c.access) rollback.push(' no switchport mode');
        if (p.description) rollback.push(c.description && DESC.test(c.description) && c.description.length <= 80 ? ` description ${c.description}` : ' no description');
      });
      return { commands, rollback };
    },
    verify: (p) => p.interfaces.map((i) => `show interfaces ${i} switchport`),
    check: (p, out) => { const badIf = p.interfaces.filter((i, k) => { const s = swAccess(out[k]); return s.vlan !== p.vlan || !/access/.test(s.mode); }); return badIf.length ? { ok: false, detail: `not in access VLAN ${p.vlan}: ${badIf.join(', ')}` } : { ok: true, detail: `${p.interfaces.length} port(s) in access VLAN ${p.vlan}` }; },
  },
  'trunk-vlan-add': {
    title: (p) => `Allow VLAN ${p.vlans.join(',')} on ${p.interfaces.length} trunk(s)`, risk: 'medium',
    norm: (b) => ({ vlans: vlanList(b.vlans || b.vlan), interfaces: ifList(b.interfaces, { trunk: true }) }),
    pre: (p) => p.interfaces.map((i) => `show running-config interface ${i}`),
    plan: (p, pre) => {
      const commands = [], rollback = [], v = p.vlans.join(',');
      p.interfaces.forEach((i, k) => {
        const c = ifConfig(pre[k]);
        if (!c.exists) throw new TaskError(409, `${i} does not exist on the device`);
        if (!c.trunk) throw new TaskError(409, `${i} is not a trunk - nothing to add the VLAN to`);
        const now = expand(c.allowed); if (now === null) throw new TaskError(409, `${i} already allows all VLANs`);
        const add = p.vlans.filter((x) => !now.has(x)); if (!add.length) return;
        commands.push(`interface ${i}`, ` switchport trunk allowed vlan add ${add.join(',')}`);
        rollback.push(`interface ${i}`, ` switchport trunk allowed vlan remove ${add.join(',')}`);
      });
      if (!commands.length) throw new TaskError(409, `VLAN ${v} is already allowed on every trunk listed`);
      return { commands, rollback };
    },
    verify: (p) => p.interfaces.map((i) => `show running-config interface ${i}`),
    check: (p, out) => { const miss = p.interfaces.filter((i, k) => { const a = expand(ifConfig(out[k]).allowed); return a !== null && p.vlans.some((x) => !a.has(x)); }); return miss.length ? { ok: false, detail: `VLAN not allowed yet on ${miss.join(', ')}` } : { ok: true, detail: `VLAN ${p.vlans.join(',')} allowed on the trunk(s)` }; },
  },
  'port-description': {
    title: (p) => `Describe ${p.interface} as "${p.description}"`, risk: 'low',
    norm: (b) => { const d = text(b.description, DESC, 'description', 80); if (!d) throw bad('description is required'); return { interface: ifList([b.interface], { trunk: true })[0], description: d }; },
    pre: (p) => [`show running-config interface ${p.interface}`],
    plan: (p, pre) => { const c = ifConfig(pre[0]); if (!c.exists) throw new TaskError(409, `${p.interface} does not exist on the device`); return { commands: [`interface ${p.interface}`, ` description ${p.description}`], rollback: [`interface ${p.interface}`, c.description && DESC.test(c.description) && c.description.length <= 80 ? ` description ${c.description}` : ' no description'] }; },
    verify: (p) => [`show running-config interface ${p.interface}`],
    check: (p, out) => (ifConfig(out[0]).description === p.description ? { ok: true, detail: 'description set' } : { ok: false, detail: 'description not shown in the running configuration' }),
  },
  'port-shutdown': {
    title: (p) => `Shut down ${p.interface}`, risk: 'high',
    norm: (b) => ({ interface: ifList([b.interface])[0] }),
    pre: (p) => [`show running-config interface ${p.interface}`],
    plan: (p, pre) => { const c = ifConfig(pre[0]); if (!c.exists) throw new TaskError(409, `${p.interface} does not exist`); if (c.trunk) throw new TaskError(409, `${p.interface} is a trunk (an uplink) - shutting it down from here is refused`); if (c.shutdown) throw new TaskError(409, `${p.interface} is already shut down`); return { commands: [`interface ${p.interface}`, ' shutdown'], rollback: [`interface ${p.interface}`, ' no shutdown'] }; },
    verify: (p) => [`show running-config interface ${p.interface}`],
    check: (p, out) => (ifConfig(out[0]).shutdown ? { ok: true, detail: 'port administratively down' } : { ok: false, detail: 'port is not shut down' }),
  },
  'port-enable': {
    title: (p) => `Enable ${p.interface} (no shutdown)`, risk: 'medium',
    norm: (b) => ({ interface: ifList([b.interface], { trunk: true })[0] }),
    pre: (p) => [`show running-config interface ${p.interface}`],
    plan: (p, pre) => { const c = ifConfig(pre[0]); if (!c.exists) throw new TaskError(409, `${p.interface} does not exist`); if (!c.shutdown) throw new TaskError(409, `${p.interface} is not shut down`); return { commands: [`interface ${p.interface}`, ' no shutdown'], rollback: [`interface ${p.interface}`, ' shutdown'] }; },
    verify: (p) => [`show running-config interface ${p.interface}`],
    check: (p, out) => (!ifConfig(out[0]).shutdown ? { ok: true, detail: 'port enabled' } : { ok: false, detail: 'port is still shut down' }),
  },
  // management hardening (CIS Cisco IOS 1.x / NCA ECC 2-5): proposed from the configuration architecture, run after approval
  'vty-ssh-only': {
    title: () => 'Allow only SSH on the VTY lines (no Telnet)', risk: 'medium',
    norm: () => ({}),
    pre: () => ['show ip ssh', 'show running-config | section line vty'],
    plan: (p, pre) => {
      // never cut the way in: SSH has to be running before Telnet is taken away
      if (!/SSH Enabled/i.test(pre[0])) throw new TaskError(409, 'SSH is not enabled on the device (no RSA keys / ip ssh): enabling SSH is done by a person first, then this task');
      const blocks = vtyBlocks(pre[1]); if (!blocks.length) throw new TaskError(409, 'no "line vty" section in the running configuration');
      const todo = blocks.filter((b) => b.transport !== 'ssh'); if (!todo.length) throw new TaskError(409, 'every VTY line already allows SSH only - nothing to change');
      const commands = [], rollback = [];
      for (const b of todo) { commands.push(b.head, ' transport input ssh'); rollback.push(b.head, b.transport ? ' transport input ' + b.transport : ' default transport input'); }
      return { commands, rollback };
    },
    verify: () => ['show running-config | section line vty'],
    check: (p, out) => { const b = vtyBlocks(out[0]); return b.length && b.every((x) => x.transport === 'ssh') ? { ok: true, detail: 'every VTY line: transport input ssh' } : { ok: false, detail: 'a VTY line still allows another transport: ' + b.filter((x) => x.transport !== 'ssh').map((x) => x.head.trim() + ' (' + (x.transport || 'default') + ')').join(', ') }; },
  },
  'http-server-off': {
    title: () => 'Turn off the clear-text HTTP server (keep HTTPS)', risk: 'low',
    norm: () => ({}),
    pre: () => ['show running-config | include ip http'],
    plan: (p, pre) => { if (!/^ip http server\s*$/m.test(pre[0])) throw new TaskError(409, 'the HTTP server is already off - nothing to change'); return { commands: ['no ip http server'], rollback: ['ip http server'] }; },
    verify: () => ['show running-config | include ip http'],
    check: (p, out) => (/^ip http server\s*$/m.test(out[0]) ? { ok: false, detail: 'ip http server is still configured' } : { ok: true, detail: 'ip http server removed' + (/^ip http secure-server/m.test(out[0]) ? ' (HTTPS kept)' : '') }),
  },
  'ios-stage': {
    title: (p) => `Stage IOS image ${p.image} (copy, verify MD5, set boot) - no reload`, risk: 'high', special: 'stage',
    norm: (b) => {
      const image = String(b.image || '').trim(), url = String(b.url || '').trim(), md5 = String(b.md5 || '').trim().toLowerCase();
      if (!/^[A-Za-z0-9._-]{1,120}\.bin$/.test(image)) throw bad('image must be the .bin file name, e.g. cat9k_iosxe.17.09.05.SPA.bin');
      if (!/^(?:tftp|ftp|http|https):\/\/[A-Za-z0-9.-]{1,253}(?::\d{1,5})?\/[A-Za-z0-9._/-]{1,200}$/.test(url) || !url.endsWith('/' + image)) throw bad('url must be tftp:// ftp:// http:// or https://<server>/<path>/' + (image || '<image>') + ' (no user or password in it)');
      if (!/^[0-9a-f]{32}$/.test(md5)) throw bad('md5 must be the 32-character MD5 from Cisco Software Download');
      return { image, url, md5 };
    },
    pre: () => ['show version', 'show boot'],
  },
  'ios-reload': {
    title: (p) => `Reload the device in ${p.minutes} minute(s) (scheduled)`, risk: 'high', special: 'reload',
    norm: (b) => { const m = Number(b.minutes); if (!Number.isInteger(m) || m < 5 || m > 1440) throw bad('minutes must be 5-1440 (the reload is scheduled, and cancelled by rollback)'); return { minutes: m }; },
    pre: () => ['show reload'],
  },
};

function createTasks({ inventory, cli, changes, config, log, runner, pam } = {}) {
  const L = log || { info() {}, warn() {} };
  const cfg = () => (config && config.netops && config.netops.tasks) || {};
  const exec = runner;
  const running = new Set();

  function device(id) { const d = inventory.get(id); if (!d) throw new TaskError(404, 'device not found'); return d; }
  // where the write account comes from: {pam: ref} (checked out at run time) or a stored login (only when PAM is not required)
  function writeLogin(d) {
    const w = (inventory.credentials(d.id) || {}).ssh_write, ps = pam ? pam.status() : { enabled: false };
    if (w && w.pam) return ps.enabled ? { pam: w.pam, port: w.port || 22 } : null;
    if (ps.enabled && ps.required) return null;
    return w && w.username && w.password ? Object.assign({}, w) : null;   // a copy: execute() wipes its own password after the run
  }
  function status(id) {
    if (cfg().enabled === false) return { enabled: false, reason: 'approved tasks are switched off (config netops.tasks.enabled)' };
    if (!exec) return { enabled: false, reason: 'the device CLI helper is not available' };
    if (id) {
      const d = device(id);
      if (d.vendor !== 'cisco-ios') return { enabled: false, reason: `${d.name}: approved tasks run on Cisco IOS / IOS-XE only` };
      const ps = pam ? pam.status() : { enabled: false };
      if (ps.enabled && !ps.ready) return { enabled: false, reason: 'PAM: ' + ps.reason };
      if (!writeLogin(d)) return { enabled: false, reason: ps.enabled ? `${d.name}: no PAM account set - an administrator enters the PAM account reference under the device's credentials (SSH write login → from PAM)` : `${d.name}: no write login - an administrator sets one under the device's credentials (SSH write login: a PAM account reference, or a stored login)` };
      if (!cli.hostKey(d.id)) return { enabled: false, reason: `${d.name}: the SSH host key is not trusted yet` };
    }
    return { enabled: true };
  }
  function build(id, type, params) {
    const d = device(id), T = TEMPLATES[type];
    if (!T) throw bad('unknown task type - one of: ' + Object.keys(TEMPLATES).join(', '));
    if (d.vendor !== 'cisco-ios') throw bad(`${d.name} is ${d.vendor}: approved tasks are for Cisco IOS / IOS-XE`);
    const p = T.norm(params || {});
    const preview = T.special === 'stage'
      ? [`copy ${p.url} flash:${p.image}`, `verify /md5 flash:${p.image}   (must equal ${p.md5})`, `boot system flash:${p.image}`, 'write memory   (no reload - schedule it with an ios-reload task)']
      : T.special === 'reload' ? [`reload in ${p.minutes}`] : ['(exact lines are computed from the device\'s state at run time, after the prechecks)'];
    return { device: d.id, type, params: p, title: T.title(p), risk: T.risk, prechecks: (T.pre ? T.pre(p) : []).map((c) => 'read: ' + c), preview };
  }
  function propose(b, by) {
    const x = build(b.device, b.type, b.params);
    const plan = changes.propose({ device: x.device, title: x.title, reason: b.reason || '', risk: x.risk, source: b.source, requested_by: b.requested_by, ticket: b.ticket,
      prechecks: x.prechecks, commands: x.preview, rollback: ['computed at run time from the prechecks, applied automatically if verification fails'],
      task: { type: x.type, params: x.params } }, by);
    return plan;
  }

  async function call(d, w, k, req, ms) {
    return exec(Object.assign({ host: d.ip, port: w.port || 22, device_type: DEVICE_TYPE[d.vendor], username: w.username, password: w.password, secret: w.secret || '', known_host: { type: k.type, key: k.key }, timeout: 20 }, req), ms || 180000);
  }
  async function show(d, w, k, cmds) {
    const r = await call(d, w, k, { op: 'run', commands: cmds, read_timeout: 90 });
    if (!r.ok) throw new TaskError(502, 'read failed: ' + (r.error || r.kind));
    return (r.results || []).map((x) => (x.error ? '' : String(x.output || '')));
  }

  async function execute(planId, who) {
    const plan = changes.get(planId); if (!plan) throw new TaskError(404, 'change plan not found');
    if (!plan.task || !TEMPLATES[plan.task.type]) throw new TaskError(400, 'this plan is not an approved task - it is applied by a person');
    if (plan.status !== 'approved') throw new TaskError(409, plan.status === 'proposed' ? 'the plan is not approved yet' : 'the plan is ' + plan.status);
    const st = status(plan.device); if (!st.enabled) throw new TaskError(409, st.reason);
    if (running.has(plan.device)) throw new TaskError(429, 'another task is running on this device');
    const d = device(plan.device), k = cli.hostKeyFull(d.id), T = TEMPLATES[plan.task.type];
    let w = writeLogin(d);
    const p = T.norm(plan.task.params);   // re-validated: the stored plan is never trusted blindly
    const by = (who && who.user) || '', steps = [], step = (name, ok, detail, output) => steps.push({ at: Date.now(), name, ok, detail: String(detail || '').slice(0, 600), output: output ? redact(String(output)).slice(0, 4000) : undefined });
    running.add(d.id);
    changes.recordExecution(plan.id, { status: 'executing', by, steps });
    let outcome = 'failed', rollback = null, lease = null;
    try {
      if (w.pam) {   // the write password exists only for this run: checked out now, checked in in finally
        const co = await pam.checkout({ account: w.pam, device: d.id, ip: d.ip, name: d.name, reason: plan.title, plan: plan.id, requested_by: plan.requested_by || plan.proposed_by || '', approved_by: plan.decided_by || '', run_by: by });
        lease = { account: w.pam, lease: co.lease };
        w = { username: co.username, password: co.password, secret: co.secret, port: w.port };
        step('PAM checkout', true, `checked out "${lease.account}"` + (co.lease ? ` (lease ${co.lease})` : '') + ' for this run only');
      }
      const pre = await show(d, w, k, T.pre(p)); step('prechecks', true, T.pre(p).join(' · '));
      const backup = await show(d, w, k, ['show running-config']); step('backup', true, 'running configuration saved on the plan (secrets removed)', backup[0]);
      if (T.special === 'stage') {
        if (/Installation mode is INSTALL|INSTALL mode/i.test(pre[0])) throw new TaskError(409, 'the switch boots in INSTALL mode: upgrades use "install add file … activate commit" - a person does this one');
        const oldBoot = (/BOOT variable = ([^\r\n;]+)/i.exec(pre[1]) || [])[1] || '';
        const c = await call(d, w, k, { op: 'copy', src: p.url, image: p.image, md5: p.md5 }, 3600000);
        if (!c.ok) { step('copy + verify MD5', false, c.error || c.kind); throw new TaskError(502, 'image copy / MD5 check failed: ' + (c.error || c.kind)); }
        step('copy + verify MD5', true, `flash:${p.image} MD5 ${c.md5} matches the approved value`);
        const lines = ['no boot system', `boot system flash:${p.image}`];
        rollback = oldBoot ? ['no boot system'].concat(oldBoot.split(',').map((x) => x.trim()).filter((x) => /^flash:[A-Za-z0-9._/-]+$/.test(x)).map((x) => 'boot system ' + x)) : ['no boot system'];
        const r = await call(d, w, k, { op: 'config', lines });
        if (!r.ok) { step('set boot', false, r.error); throw new TaskError(502, 'setting the boot image failed: ' + r.error); }
        step('set boot', true, lines.join(' · '));
        const v = await show(d, w, k, ['show boot']);
        if (!new RegExp('flash:' + p.image.replace(/\./g, '\\.')).test(v[0])) { step('verify', false, 'boot variable does not point at the new image', v[0]); throw Object.assign(new TaskError(502, 'verification failed'), { rollback: true }); }
        step('verify', true, 'boot variable points at the new image (the device still runs the old one until a reload)', v[0]);
      } else if (T.special === 'reload') {
        if (/Reload scheduled/i.test(pre[0])) throw new TaskError(409, 'a reload is already scheduled on the device');
        const s = await call(d, w, k, { op: 'save' }); if (!s.ok) throw new TaskError(502, 'write memory failed before the reload: ' + s.error);
        const r = await call(d, w, k, { op: 'reload', minutes: p.minutes });
        if (!r.ok) { step('schedule reload', false, r.error); throw new TaskError(502, 'scheduling the reload failed: ' + r.error); }
        const v = await show(d, w, k, ['show reload']);
        if (!/Reload scheduled/i.test(v[0])) { step('verify', false, 'no reload scheduled', v[0]); throw new TaskError(502, 'the reload is not scheduled'); }
        step('schedule reload', true, `reload in ${p.minutes} min - cancel with "reload cancel" if needed`, v[0]);
      } else {
        const x = T.plan(p, pre); rollback = x.rollback; step('plan', true, x.commands.join(' · '));
        const r = await call(d, w, k, { op: 'config', lines: x.commands });
        if (!r.ok) { step('push', false, r.error || r.kind); throw Object.assign(new TaskError(502, 'push failed: ' + (r.error || r.kind)), { rollback: true }); }
        step('push', true, `${x.commands.length} line(s) applied`, r.output);
        const v = await show(d, w, k, T.verify(p)), ck = T.check(p, v);
        step('verify', ck.ok, ck.detail, v.join('\n'));
        if (!ck.ok) throw Object.assign(new TaskError(502, 'verification failed: ' + ck.detail), { rollback: true });
      }
      if (T.special !== 'reload') { const s = await call(d, w, k, { op: 'save' }); step('write memory', !!s.ok, s.ok ? 'startup configuration saved' : s.error); }
      outcome = 'done';
    } catch (e) {
      step('stopped', false, e.message);
      if (e.rollback && rollback && rollback.length) {
        const r = await call(d, w, k, { op: 'config', lines: rollback }).catch((x) => ({ ok: false, error: x.message }));
        step('rollback', !!r.ok, r.ok ? rollback.join(' · ') : 'ROLLBACK FAILED - a person must check the device now: ' + r.error);
        outcome = r.ok ? 'rolled-back' : 'rollback-failed';
      }
    } finally {
      running.delete(d.id);
      if (lease) { const ci = await pam.checkin({ account: lease.account, lease: lease.lease, device: d.id, plan: plan.id, outcome }).catch(() => ({ ok: false })); step('PAM check-in', !!ci.ok, ci.ok ? `"${lease.account}" checked in` : `check-in of "${lease.account}" failed - check it in the PAM`); }
      if (w) { w.password = null; w.secret = null; }
    }
    L.info('netops task', { plan: plan.id, device: d.id, type: plan.task.type, by, outcome });
    return changes.recordExecution(plan.id, { status: outcome, by, steps, finished: Date.now() });
  }

  return { pamStatus: () => (pam ? pam.status() : { enabled: false }), catalogue: () => Object.keys(TEMPLATES).map((k) => ({ type: k, risk: TEMPLATES[k].risk })), build, propose, execute, status, TEMPLATES };
}

module.exports = { createTasks, TEMPLATES, TaskError, ifConfig, expand, vtyBlocks };
