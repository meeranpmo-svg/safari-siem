// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// itam-agent local state: server URL, agent id + key (chmod 600), the monotonic report seq, and an offline spool.
// Least privilege: the state file holds the agent key, so it is created 0600 and lives under a service-owned dir.
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

function defaultStateDir() {
  if (process.platform === 'win32') return path.join(process.env.ProgramData || 'C:\\ProgramData', 'sentra-itam-agent');
  if (process.platform === 'darwin') return '/Library/Application Support/sentra-itam-agent';
  return '/var/lib/sentra-itam-agent';
}

function createAgentState(opts = {}) {
  const dir = opts.dir || process.env.ITAM_AGENT_DIR || defaultStateDir();
  const file = path.join(dir, 'agent.json');
  let state = { server: null, agent_id: null, agent_key: null, seq: 0, spool: [], enrolled_at: null };

  function load() {
    try { state = Object.assign(state, JSON.parse(fs.readFileSync(file, 'utf8'))); } catch (e) { if (e.code !== 'ENOENT') throw e; }
    return state;
  }
  function save() {
    fs.mkdirSync(dir, { recursive: true });
    const tmp = file + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(state), { mode: 0o600 });
    try { fs.chmodSync(tmp, 0o600); } catch { /* windows */ }
    fs.renameSync(tmp, file);
    try { fs.chmodSync(file, 0o600); } catch { /* windows */ }
  }
  return {
    get: () => state,
    load, save, file, dir,
    set(patch) { Object.assign(state, patch); save(); },
    nextSeq() { state.seq = (state.seq || 0) + 1; save(); return state.seq; },
    enrolled: () => !!(state.agent_id && state.agent_key),
    spoolPush(report) { state.spool = (state.spool || []).concat([report]).slice(-200); save(); },
    spoolTake() { const s = state.spool || []; state.spool = []; save(); return s; },
  };
}

module.exports = { createAgentState, defaultStateDir };
