// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// install/link-siem.sh: the IT Asset Management → SIEM link that was missing on new servers ("SIEM connection not configured
// (discovery.siem.secret_file)" on SharePoint). Static checks (the script needs root and the real /etc): valid bash, the secret
// read from the sealed store and never printed or put on a command line, the file written 640 root:sentra-itam without following
// links, the setting written into discovery.siem, a 401 reported as a refusal; the server update and the fresh install run it;
// and the engine's error names what to run.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs'), path = require('path'), { execFileSync } = require('child_process');
const ROOT = path.resolve(__dirname, '../../..'), F = path.join(__dirname, '../install/link-siem.sh'), S = fs.readFileSync(F, 'utf8');

test('link-siem.sh: valid, reads the sealed secret, never prints it, writes it safely', () => {
  execFileSync('bash', ['-n', F]);
  assert.match(S, /sentra-siem-secrets get proxy_secret/);
  assert.doesNotMatch(S, /echo[^\n]*\$SECRET/, 'the secret is never echoed');
  assert.match(S, /printf '%s' "\$SECRET" \|/, 'handed over on stdin (printf is a builtin: not in the process list)');
  assert.match(S, /O_NOFOLLOW/); assert.match(S, /0o640/); assert.match(S, /unset SECRET/);
  assert.match(S, /discovery\.siem=Object\.assign/); assert.match(S, /secret_file:sf/);
  assert.match(S, /401\*\) die/);
  assert.match(S, /bak-link-siem-/, 'backup before the config is changed');
});

test('the server update and the fresh install run it', () => {
  assert.match(fs.readFileSync(path.join(ROOT, 'deploy/server/update-server.sh'), 'utf8'), /sentra-itam\/install\/link-siem\.sh/);
  assert.match(fs.readFileSync(path.join(ROOT, 'deploy/install-fresh-server.sh'), 'utf8'), /backend\/itam\/install\/link-siem\.sh/);
});

test('not configured: the error says what to run', async () => {
  const { createSiem } = require('../engine/discovery/siem');
  const L = createSiem({ config: { discovery: { siem: {} } }, assets: { raw: () => null }, log: { every() {}, warn() {}, info() {}, error() {} } });
  await assert.rejects(() => L.call('GET', '/onboard/sources', { user: 'a', role: 'viewer' }), (e) => e.status === 503 && /link-siem\.sh/.test(e.message));
});
