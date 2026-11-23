// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * Baseline-hardening snapshots from the Windows agent (agent 1.2+, once a day; 1.3 adds IIS and Hyper-V): the LATEST snapshot per host, for the
 * baseline scan in IT Asset Management (sentra-itam engine/hardening.js reads GET {P}/hardening/snapshots and decides in
 * Python against the CIS benchmarks / SAMA CSF / NCA ECC). The SIEM only keeps and serves the facts - it judges nothing.
 *
 *   createHardeningStore({ file, now, log, maxHosts }) → { stage(ev), put(host, snap), list(), get(host), stats() }
 *   stage(ev)  pipeline stage: takes events with action 'agent-hardening' (parse/windows.js), parses fields.settings
 *   A snapshot holds settings only - no account names except the renamed built-in administrator / guest account name,
 *   which CIS asks about. Saved atomically (tmp + rename), at most every 30 s; at most maxHosts hosts (oldest dropped).
 */
const fs = require('node:fs');
const path = require('node:path');

const HOST_RE = /^[a-z0-9][a-z0-9._-]{0,252}$/;
const MAX_SNAP = 512 * 1024;   // agent 1.3 adds IIS sites and up to 200 Hyper-V VMs; 1.6 machine certificates (300) and a CA's issued list (500)

function createHardeningStore({ file, now = Date.now, log = null, maxHosts = 20000, action = 'agent-hardening', label = 'hardening' } = {}) {
  // the same latest-per-host store also keeps the agent's file-share personal-data scan (action 'agent-pii', pii/routes.js)
  const hosts = new Map();       // host → { host, ip, at, received, agent_version, settings }
  let dirty = false, lastSave = 0, rejected = 0;
  if (file) {
    try {
      const j = JSON.parse(fs.readFileSync(file, 'utf8'));
      for (const h of Array.isArray(j.hosts) ? j.hosts : []) if (h && HOST_RE.test(h.host || '')) hosts.set(h.host, h);
    } catch (e) { if (e.code !== 'ENOENT' && log) log.warn(label + ': snapshot file unreadable, starting empty', { err: e.message }); }
  }
  function save(force) {
    if (!file || !dirty || (!force && now() - lastSave < 30000)) return;
    try {
      fs.mkdirSync(path.dirname(file), { recursive: true });
      fs.writeFileSync(file + '.tmp', JSON.stringify({ at: new Date(now()).toISOString(), hosts: [...hosts.values()] }));
      fs.renameSync(file + '.tmp', file);
      dirty = false; lastSave = now();
    } catch (e) { if (log) log.every(label + '-save', 600000, 'warn', label + ': snapshots not saved', { err: e.message }); }
  }
  function put(host, snap) {
    const h = String(host || '').trim().toLowerCase();
    if (!HOST_RE.test(h) || !snap || typeof snap.settings !== 'object' || Array.isArray(snap.settings)) { rejected++; return false; }
    hosts.delete(h);
    hosts.set(h, { host: h, ip: snap.ip || '', at: snap.at || new Date(now()).toISOString(), received: new Date(now()).toISOString(), agent_version: String(snap.agent_version || '').slice(0, 20), settings: snap.settings });
    while (hosts.size > maxHosts) hosts.delete(hosts.keys().next().value);
    dirty = true; save(false);
    return true;
  }
  function stage(ev) {
    if (!ev || ev.action !== action) return;
    // only the agent itself, over the authenticated HTTPS ingest (a per-source token), may replace a host's snapshot - a syslog
    // line or an unregistered sender that merely says action=agent-hardening is refused, so compliance cannot be forged that way
    if (ev.collector !== 'agent' || ev.src_type !== 'windows') { rejected++; if (log) log.every(label + '-src', 600000, 'warn', label + ': snapshot refused - not from an agent over HTTPS ingest', { host: ev.host, collector: ev.collector }); return; }
    const raw = ev.fields && ev.fields.settings;
    if (typeof raw !== 'string' || raw.length > MAX_SNAP) { rejected++; if (log) log.every(label + '-big', 600000, 'warn', label + ': snapshot missing or too large', { host: ev.host, size: raw ? raw.length : 0 }); return; }
    let settings;
    try { settings = JSON.parse(raw); } catch (e) { rejected++; if (log) log.every(label + '-json', 600000, 'warn', label + ': snapshot is not JSON', { host: ev.host }); return; }
    put(ev.host, { ip: ev.host_ip || '', at: ev.ts ? new Date(ev.ts).toISOString() : undefined, agent_version: ev.fields.agent_version, settings });
  }
  return {
    stage, put,
    list: () => [...hosts.values()],
    get: (h) => hosts.get(String(h || '').toLowerCase()) || null,
    flush: () => save(true),
    stats: () => ({ hosts: hosts.size, rejected }),
  };
}

module.exports = { createHardeningStore };
