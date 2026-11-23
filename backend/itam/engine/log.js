// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Levelled JSON logs to stdout (journald): one object per line {t, lvl, mod, msg, ...fields}.
// Never pass secrets (proxy secret, private token, agent keys/tokens) or raw discovery payloads to the logger.
const LEVELS = { debug: 10, info: 20, warn: 30, error: 40 };

// a library or driver error can echo a connection string, a token or a password: every string written is passed through the
// same masking the AI guard applies before a model call (password=…, Bearer …, keys, connection strings)
let RED = null;
function red(text) {
  if (!RED) { try { RED = require('./ai-guard').redactSecrets; } catch (e) { RED = (x) => x; /* the guard is missing on a very old install: log as before */ } }
  try { return RED(text); } catch (e) { return text; /* masking must never stop a log line */ }
}

function createLogger({ level = process.env.SENTRA_ITAM_LOG_LEVEL || 'info', name = 'sentra-itam', stream = process.stdout } = {}) {
  const min = LEVELS[level] || LEVELS.info;
  const throttles = new Map();
  function write(lvl, msg, fields) {
    if (LEVELS[lvl] < min) return;
    const rec = { t: new Date().toISOString(), lvl, mod: name, msg: red(String(msg || '')) };
    if (fields && typeof fields === 'object') {
      for (const k of Object.keys(fields)) {
        const v = fields[k];
        rec[k] = v instanceof Error ? { name: v.name, message: red(v.message), code: v.code } : typeof v === 'string' ? red(v) : v;
      }
    }
    let line;
    try { line = JSON.stringify(rec); } catch { line = JSON.stringify({ t: rec.t, lvl, mod: name, msg: rec.msg }); }
    try { stream.write(line + '\n'); } catch { /* stdout closed */ }
  }
  return {
    level,
    debug: (m, f) => write('debug', m, f),
    info: (m, f) => write('info', m, f),
    warn: (m, f) => write('warn', m, f),
    error: (m, f) => write('error', m, f),
    isDebug: () => min <= LEVELS.debug,
    every(key, ms, lvl, msg, fields) {
      const now = Date.now();
      const t = throttles.get(key) || { at: 0, n: 0 };
      if (now - t.at < ms) { t.n++; throttles.set(key, t); return; }
      throttles.set(key, { at: now, n: 0 });
      if (throttles.size > 500) throttles.clear();
      write(lvl, msg, Object.assign({}, fields || {}, t.n ? { suppressed: t.n } : {}));
    },
  };
}

const silent = { debug() {}, info() {}, warn() {}, error() {}, isDebug: () => false, every() {} };

module.exports = { createLogger, silent };
