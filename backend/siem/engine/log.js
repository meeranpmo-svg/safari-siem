// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Levelled JSON logs to stdout: one JSON object per line {t, lvl, mod, msg, ...fields}.
// Usage: log.info('message', {k: v}) — (fields, 'message') order is accepted too. log.child({mod: 'x'}).
const LEVELS = { debug: 10, info: 20, warn: 30, error: 40, fatal: 50 };

// a library or driver error can echo a connection string, a token or a password: every string written is passed through the
// same masking the AI guard applies before a model call (password=…, Bearer …, keys, connection strings)
let RED = null;
function red(text) {
  if (!RED) { try { RED = require('./util/ai-guard').redactSecrets; } catch (e) { RED = (x) => x; /* guard missing: log as before */ } }
  try { return RED(text); } catch (e) { return text; /* masking must never stop a log line */ }
}
function errObj(e) {
  return { name: e.name, message: red(e.message), code: e.code, stack: e.stack ? red(String(e.stack).split('\n').slice(0, 6).join('\n')) : undefined };
}

function createLogger({ level = process.env.SENTRA_SIEM_LOG_LEVEL || 'info', name = 'sentra-siem', stream = process.stdout, bindings = {} } = {}) {
  const min = LEVELS[level] || LEVELS.info;
  const throttles = new Map();

  function write(lvl, a, b) {
    if (LEVELS[lvl] < min) return;
    let msg = '';
    let fields;
    if (typeof a === 'string') { msg = a; fields = b; } else { fields = a; msg = typeof b === 'string' ? b : ''; }
    const rec = { t: new Date().toISOString(), lvl, mod: name, msg: red(msg) };
    for (const k in bindings) rec[k] = bindings[k];
    if (fields instanceof Error) rec.err = errObj(fields);
    else if (fields && typeof fields === 'object') {
      for (const k in fields) { const v = fields[k]; rec[k] = v instanceof Error ? errObj(v) : typeof v === 'string' ? red(v) : v; }
    }
    let line;
    try { line = JSON.stringify(rec); } catch { line = JSON.stringify({ t: rec.t, lvl, mod: name, msg, note: 'unserialisable log fields' }); }
    try { stream.write(line + '\n'); } catch { /* stdout closed */ }
  }

  const logger = {
    level,
    debug: (a, b) => write('debug', a, b),
    info: (a, b) => write('info', a, b),
    warn: (a, b) => write('warn', a, b),
    error: (a, b) => write('error', a, b),
    fatal: (a, b) => write('fatal', a, b),
    isDebug: () => min <= LEVELS.debug,
    child(extra = {}) {
      const { mod, ...rest } = extra;
      return createLogger({ level, name: mod || name, stream, bindings: { ...bindings, ...rest } });
    },
    // Log at most once per `ms` for `key`; suppressed count is reported with the next line.
    every(key, ms, lvl, msg, fields) {
      const now = Date.now();
      const t = throttles.get(key) || { at: 0, n: 0 };
      if (now - t.at < ms) { t.n++; throttles.set(key, t); return; }
      const extra = t.n ? { suppressed: t.n } : {};
      throttles.set(key, { at: now, n: 0 });
      if (throttles.size > 1000) throttles.clear();
      write(lvl, msg, { ...(fields || {}), ...extra });
    },
  };
  return logger;
}

const log = createLogger();
module.exports = { createLogger, log, LEVELS };
