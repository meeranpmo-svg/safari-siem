// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Agent packages a server fetches itself (engine/agent-packages.js) from a SYNTHETIC agents folder: only a file named in the manifest
// is served, with its SHA-256 and the bytes (base64); a path, an unknown name or a missing build are refused with a reason; the route
// needs no session (agent side) through the real app.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs'), os = require('node:os'), path = require('node:path'), crypto = require('node:crypto');
const { createAgentPackages } = require('../engine/agent-packages');
const { startApp } = require('./helpers');
const { registerDuty } = require('../engine/duty');

function folder() {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'agents-')), body = Buffer.from('PK synthetic zip');
  fs.writeFileSync(path.join(d, 'sentra-siem-windows-agent.zip'), body); fs.writeFileSync(path.join(d, 'secret.zip'), 'not listed');
  fs.writeFileSync(path.join(d, 'manifest.json'), JSON.stringify({ built: 'x', items: [{ file: 'sentra-siem-windows-agent.zip', sha256: crypto.createHash('sha256').update(body).digest('hex') }] }));
  return { d, body };
}

test('packages: listed files only, with their fingerprint', () => {
  const { d, body } = folder(), P = createAgentPackages({ dir: d });
  const r = P.get('sentra-siem-windows-agent.zip'); assert.equal(Buffer.from(r.b64, 'base64').toString(), body.toString()); assert.equal(r.sha256, crypto.createHash('sha256').update(body).digest('hex'));
  assert.throws(() => P.get('secret.zip'), /no agent package named/); assert.throws(() => P.get('../manifest.json'), /not an agent package name/);
  assert.throws(() => createAgentPackages({ dir: path.join(d, 'none') }).get('sentra-siem-windows-agent.zip'), /not built on this server/);
});

test('route: no session needed (agent side)', async (t) => {
  const { d } = folder(), e = await startApp({ noAi: true }); t.after(() => e.close());
  registerDuty(e.app.srv, e.app, { noTimer: true, agentsDir: d, python: process.env.PYTHON || 'python3' });
  const r = await e.req('GET', '/agent/packages/sentra-siem-windows-agent.zip', { noAuth: true }); assert.equal(r.status, 200, r.text); assert.ok(r.json.b64 && r.json.sha256);
});
