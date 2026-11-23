// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Agent 1.6 certificate inventory: the snapshot store accepts a full one (300 machine certificates + a CA's 500 issued
// certificates) and serves it unchanged to IT Asset Management; the agent script only READS the certificate stores and the
// CA database - no key export, no store change, no certutil write verb - and leaves people's certificates (user / smart card
// / e-mail / EFS templates) and requester names out. SYNTHETIC data.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { createHardeningStore } = require('../engine/hardening/store');

const PS = fs.readFileSync(path.join(__dirname, '..', 'agents', 'windows', 'sentra-agent.ps1'), 'utf8');

test('store: a full certificate snapshot is kept and served', () => {
  const st = createHardeningStore({});
  const certs = Array.from({ length: 300 }, (_, i) => ({ store: 'My', subject: 'srv' + i + '.corp.syn', issuer: 'Corp Issuing CA (synthetic)', thumbprint: 'A'.repeat(40), serial: String(i).padStart(32, '0'),
    not_before: '2025-01-01T00:00:00Z', not_after: '2026-12-01T00:00:00Z', has_key: true, key_alg: 'RSA', key_bits: 2048, sig_alg: 'sha256RSA', self_signed: false, sans: ['srv' + i + '.corp.syn', 'srv' + i], eku: ['Server Authentication'] }));
  const ca = Array.from({ length: 500 }, (_, i) => ({ request_id: String(i), cn: 'host' + i + '.corp.syn', not_after: '2026-11-0' + ((i % 9) + 1) + 'T00:00:00Z', template: 'WebServer', serial: String(i).padStart(32, '0') }));
  const raw = JSON.stringify({ os: { caption: 'Windows Server 2022' }, certs, ca_issued: ca });
  assert.ok(raw.length < 512 * 1024, 'fits the snapshot limit: ' + raw.length);
  st.stage({ action: 'agent-hardening', collector: 'agent', src_type: 'windows', host: 'ca01.corp.syn', ts: Date.now(), fields: { settings: raw, agent_version: '1.6.0' } });
  const h = st.get('ca01.corp.syn');
  assert.equal(h.settings.certs.length, 300); assert.equal(h.settings.ca_issued.length, 500); assert.equal(h.agent_version, '1.6.0');
});

test('agent script: read-only certificate collection, people left out', () => {
  assert.match(PS, /\$AgentVersion = '1\.7\.0'/);
  assert.match(PS, /Get-ChildItem -Path \('Cert:\\LocalMachine\\' \+ \$st\)/);
  assert.match(PS, /certutil\.exe -view -restrict/);
  for (const bad of [/Export-PfxCertificate/i, /Export-Certificate/i, /Remove-Item\s+[^\n]*Cert:/i, /Import-(Pfx)?Certificate/i, /certutil(\.exe)?\s+-(delstore|addstore|importpfx|exportpfx|repairstore|revoke|deny|resubmit|setreg)/i, /\.PrivateKey\b/, /ExportParameters|ExportCspBlob/i])
    assert.ok(!bad.test(PS), 'the agent must not ' + bad);
  assert.match(PS, /-notmatch '\(\?i\)user\|smart \?card\|e-\?mail\|efs'/, 'person certificate templates are filtered out');
  assert.ok(!/RequesterName/.test(PS), 'requester names are not read');
});
