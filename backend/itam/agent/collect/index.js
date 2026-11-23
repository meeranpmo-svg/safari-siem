// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Platform-detecting hardware/OS/software collector. Each platform module shells out to native tools and MUST degrade
// gracefully: any command that is missing, denied or malformed yields null/[] rather than throwing. The agent never
// crashes because a probe failed.
const os = require('node:os');
const { execFile } = require('node:child_process');

// run a command, never throw; resolve {ok, out} (out = stdout string, '' on any failure)
function sh(cmd, args, { timeout = 15000, input } = {}) {
  return new Promise((resolve) => {
    let done = false;
    const child = execFile(cmd, args, { timeout, maxBuffer: 16 * 1024 * 1024, windowsHide: true }, (err, stdout) => {
      if (done) return; done = true;
      resolve({ ok: !err, out: String(stdout || '') });
    });
    if (input) { try { child.stdin.write(input); child.stdin.end(); } catch { /* ignore */ } }
  });
}

function base() {
  const nics = [];
  const ifs = os.networkInterfaces();
  for (const name of Object.keys(ifs)) for (const ni of ifs[name] || []) {
    if (ni.internal) continue;
    if (ni.mac && ni.mac !== '00:00:00:00:00:00') nics.push({ mac: ni.mac, ip: ni.family === 'IPv4' ? ni.address : null });
  }
  const macs = [...new Set(nics.map((n) => n.mac))];
  const ip = (nics.find((n) => n.ip) || {}).ip || null;
  return {
    hostname: os.hostname(), os: `${os.type()} ${os.release()}`, arch: os.arch(),
    cpu: (os.cpus()[0] || {}).model || null, cpu_count: os.cpus().length,
    mem_gb: Math.round(os.totalmem() / (1024 ** 3)), mac: macs[0] || null, macs, ip,
    platform: process.platform === 'win32' ? 'windows' : process.platform === 'darwin' ? 'macos' : 'linux',
  };
}

async function collect() {
  const facts = base();
  let detail = {}; let software = [];
  try {
    if (process.platform === 'win32') ({ detail, software } = await require('./windows').collect(sh));
    else if (process.platform === 'darwin') ({ detail, software } = await require('./macos').collect(sh));
    else ({ detail, software } = await require('./linux').collect(sh));
  } catch { /* degrade: keep base facts only */ }
  const host = Object.assign(facts, detail || {});
  return { host, software: Array.isArray(software) ? software : [] };
}

module.exports = { collect, sh, base };
