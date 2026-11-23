// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// `node --test tests/` resolves the directory to this file (Node 20/22). It runs every tests/*.test.js in its OWN
// process (like `node --test` does for separate files), 4 at a time, and reports one sub-test per file with the
// file's pass/fail counts. Isolation matters: several suites start servers and use timers.
// Run a single file directly with:  node --test tests/parse.test.js
const fs = require('node:fs');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const files = fs.readdirSync(__dirname).filter((f) => f.endsWith('.test.js')).sort();

function runFile(file) {
  return new Promise((resolve) => {
    const env = { ...process.env };
    delete env.NODE_TEST_CONTEXT; // otherwise the child thinks it is already a test-runner child
    const child = spawn(process.execPath, ['--test', '--test-reporter=tap', path.join(__dirname, file)], { env, stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '';
    child.stdout.on('data', (c) => { out += c; });
    child.stderr.on('data', (c) => { out += c; });
    child.on('close', (code) => resolve({ code, out }));
  });
}

describe('sentra-siem test files (isolated processes)', { concurrency: 4 }, () => {
  for (const f of files) {
    it(f, async (t) => {
      const { code, out } = await runFile(f);
      const num = (k) => { const m = new RegExp(`^# ${k} (\\d+)`, 'm').exec(out); return m ? Number(m[1]) : 0; };
      t.diagnostic(`${f}: ${num('pass')} passed, ${num('fail')} failed`);
      if (code !== 0) {
        const failed = out.split('\n').filter((l) => /^\s*not ok /.test(l)).slice(0, 20).join('\n');
        assert.fail(`${f} exited with ${code}\n${failed}\n--- output tail ---\n${out.slice(-4000)}`);
      }
      assert.ok(num('pass') > 0, `${f}: no passing tests reported`);
    });
  }
});
