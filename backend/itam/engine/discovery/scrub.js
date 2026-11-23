// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Log / audit / error scrubber for discovery. Two layers:
//   1. field names that look secret (password, community, secret, token, key material, bind DN …) are replaced by
//      "[redacted]" wherever they appear in a logged object;
//   2. every credential value the vault has opened in this process is registered here while it is in use, and any
//      occurrence of it inside ANY logged string (error messages from a device or library included) is replaced.
//   createScrubber() → { register(values[]), release(values[]), text(s), deep(o), wrapLogger(log), size() }
const SECRET_KEY = /(pass(word|phrase)?|secret|community|token|private_?key|auth_?password|priv_?password|access_?key|secret_?key|bind_?dn|authorization|credential_value|^value$)/i;
const MIN_LEN = 4;

function createScrubber() {
  const live = new Map(); // value → refcount

  function register(values) {
    for (const v of [].concat(values || [])) {
      const s = typeof v === 'string' ? v : '';
      if (s.length < MIN_LEN) continue;
      live.set(s, (live.get(s) || 0) + 1);
    }
  }
  function release(values) {
    for (const v of [].concat(values || [])) {
      const n = live.get(v);
      if (!n) continue;
      if (n <= 1) live.delete(v); else live.set(v, n - 1);
    }
  }
  function text(s) {
    let out = String(s);
    if (!live.size) return out;
    // longest first so a secret containing another secret is fully covered
    for (const v of [...live.keys()].sort((a, b) => b.length - a.length)) if (out.includes(v)) out = out.split(v).join('[redacted]');
    return out;
  }
  function deep(o, depth = 0) {
    if (o === null || o === undefined) return o;
    if (typeof o === 'string') return text(o);
    if (typeof o !== 'object') return o;
    if (depth > 6) return '[depth]';
    if (o instanceof Error) return { name: o.name, message: text(o.message), code: o.code };
    if (Buffer.isBuffer(o)) return '[bytes]';
    if (Array.isArray(o)) return o.slice(0, 200).map((x) => deep(x, depth + 1));
    const r = {};
    for (const k of Object.keys(o)) r[k] = SECRET_KEY.test(k) ? '[redacted]' : deep(o[k], depth + 1);
    return r;
  }
  function wrapLogger(log) {
    const l = log || {};
    const call = (lvl) => (m, f) => { if (typeof l[lvl] === 'function') l[lvl](text(m), f === undefined ? f : deep(f)); };
    return {
      debug: call('debug'), info: call('info'), warn: call('warn'), error: call('error'),
      isDebug: () => (typeof l.isDebug === 'function' ? l.isDebug() : false),
      every(key, ms, lvl, m, f) { if (typeof l.every === 'function') l.every(key, ms, lvl, text(m), f === undefined ? f : deep(f)); },
    };
  }
  return { register, release, text, deep, wrapLogger, size: () => live.size };
}

module.exports = { createScrubber, SECRET_KEY };
