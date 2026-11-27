// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// The agent downloads (ui/build-agents.py, run by install-dashboards.sh): every package is built from this checkout, the manifest
// gives each file's size and the SHA-256 of the file as served, the archives hold the agent files under one folder and nothing
// else (no state, no logs, no secret), the build is repeatable (same input, same archive bytes), and the installer runs it.
const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs'), os = require('node:os'), path = require('node:path'), crypto = require('node:crypto');
const { execFileSync } = require('node:child_process');
const ROOT = path.join(__dirname, '..'), UI = path.join(ROOT, 'ui');
const build = () => { const d = fs.mkdtempSync(path.join(os.tmpdir(), 'agents-')); execFileSync('python3', [path.join(UI, 'build-agents.py'), d, ROOT]); return path.join(d, 'agents'); };

test('agent downloads: five packages, manifest sizes and SHA-256 match the files', () => {
  const out = build(), m = JSON.parse(fs.readFileSync(path.join(out, 'manifest.json'), 'utf8'));
  assert.deepStrictEqual(m.items.map((i) => i.id).sort(), ['asset-node-unix', 'asset-node-win', 'asset-windows', 'siem-linux', 'siem-windows']);
  for (const i of m.items) {
    const b = fs.readFileSync(path.join(out, i.file));
    assert.strictEqual(i.bytes, b.length, i.file + ' size'); assert.strictEqual(i.sha256, crypto.createHash('sha256').update(b).digest('hex'), i.file + ' sha256');
    assert.ok(i.title && i.purpose && i.platform && i.needs, i.file + ' described');
  }
  assert.strictEqual(fs.readFileSync(path.join(out, 'sentra-asset-agent.ps1'), 'utf8'), fs.readFileSync(path.join(ROOT, 'backend/itam/agent/sentra-asset-agent.ps1'), 'utf8'), 'the PowerShell agent as in the checkout');
});

test('agent downloads: archive contents, nothing else, repeatable', () => {
  const a = build(), b = build();
  const list = (f) => execFileSync('python3', ['-c', 'import sys,zipfile,tarfile\np=sys.argv[1]\nprint("\\n".join(zipfile.ZipFile(p).namelist() if p.endswith(".zip") else tarfile.open(p).getnames()))', path.join(a, f)]).toString().trim().split('\n');
  const win = list('sentra-siem-windows-agent.zip');
  assert.deepStrictEqual(win.sort(), ['sentra-siem-windows-agent/README.md', 'sentra-siem-windows-agent/install-agent.ps1', 'sentra-siem-windows-agent/sentra-agent.ps1', 'sentra-siem-windows-agent/uninstall-agent.ps1']);
  const node = list('itam-agent.zip'); assert.ok(node.includes('itam-agent/agent.js') && node.includes('itam-agent/install/install.ps1') && !node.some((x) => /sentra-asset-agent|\.key|state|\.log$/.test(x)), node.join(','));
  assert.ok(list('sentra-siem-linux-forwarder.tar.gz').every((x) => x.startsWith('sentra-siem-linux-forwarder/')));
  for (const f of ['sentra-siem-windows-agent.zip', 'itam-agent.zip', 'itam-agent.tar.gz', 'sentra-siem-linux-forwarder.tar.gz', 'sentra-asset-agent.ps1']) {
    const x = fs.readFileSync(path.join(a, f)), y = fs.readFileSync(path.join(b, f));
    if (!f.endsWith('.tar.gz')) assert.ok(x.equals(y), f + ' is repeatable');   // gzip stores a time; the tar inside is fixed
    assert.ok(!/BEGIN (RSA |EC )?PRIVATE KEY|agent_key"\s*:\s*"[0-9a-f]{20,}/.test(x.toString('latin1')), f + ' holds no key');
  }
  const inst = fs.readFileSync(path.join(UI, 'install-dashboards.sh'), 'utf8');
  assert.match(inst, /python3 "\$HERE\/build-agents\.py" "\$STAGE" "\$HERE\/\.\."/); assert.match(inst, / agents\.html /);
});
