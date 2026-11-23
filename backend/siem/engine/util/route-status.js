// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * What happened to each route module at this start, kept in <state_dir>/routes-status.json for the updater's summary
 * (shield scripts/update-server.sh). The summary used to search the journal for one "routes registered" line per module;
 * journald drops lines when a start logs a burst, so a working module could read "NOT registered", and a module that
 * failed to load said nothing useful. The file holds the reason instead of a guess.
 *
 *   createRouteStatus({ file, now }) -> { absent(rel), loadFailed(rel, err), registered(rel), registerFailed(rel, err), write() }
 *   states: registered | not_present | load_failed | register_failed. Errors are cut to their first line (300 chars) - a
 *   module path or a JavaScript error, never configuration values.
 */
const fs = require('node:fs');
const path = require('node:path');

const firstLine = (e) => String((e && (e.message || e)) || '').split('\n')[0].slice(0, 300);

function createRouteStatus({ file, now = Date.now } = {}) {
  const modules = [];
  const add = (module, state, err) => { modules.push(Object.assign({ module, state }, err ? { error: firstLine(err) } : {})); };
  return {
    absent: (rel) => add(rel, 'not_present'),
    loadFailed: (rel, err) => add(rel, 'load_failed', err),
    registered: (rel) => add(rel, 'registered'),
    registerFailed: (rel, err) => add(rel, 'register_failed', err),
    list: () => modules.slice(),
    // written atomically (tmp + rename) so the updater never reads half a file; a write failure never stops the engine
    write() {
      if (!file) return false;
      try {
        // checked first: mkdirSync(recursive) over a path whose parent is a plain file loops in some Node releases
        const dir = path.dirname(file); let st = null;
        try { st = fs.statSync(dir); } catch (e) { st = null; /* not there yet: created below */ }
        if (st && !st.isDirectory()) return false;
        if (!st) fs.mkdirSync(dir, { recursive: true });
        const tmp = file + '.tmp';
        fs.writeFileSync(tmp, JSON.stringify({ at: new Date(now()).toISOString(), pid: process.pid, modules }, null, 1));
        fs.renameSync(tmp, file);
        return true;
      } catch (e) { return false; /* the status file is a convenience for the updater; the engine runs without it */ }
    },
  };
}

module.exports = { createRouteStatus };
