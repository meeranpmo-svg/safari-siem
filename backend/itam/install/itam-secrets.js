#!/usr/bin/env node
// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// /etc/sentra-itam/secrets.json values sealed at rest (engine/secret-values.js). Values travel on stdin only, never argv/env.
//   node itam-secrets.js status                 which values are sealed / plaintext (never the values)
//   node itam-secrets.js seal                   seal every plaintext value (proxy_secret stays readable for nginx)
//   printf %s "$V" | node itam-secrets.js set NAME   store one value sealed (refuses to store it in clear)
// SENTRA_ITAM_SECRETS / SENTRA_ITAM_VAULT_KEY override the paths.
const path = require('node:path');
const fs = require('node:fs');
const engineDir = fs.existsSync(path.join(__dirname, '..', 'engine', 'secret-values.js')) ? path.join(__dirname, '..', 'engine') : '/opt/sentra-itam/engine';
const SV = require(path.join(engineDir, 'secret-values.js'));
const file = process.env.SENTRA_ITAM_SECRETS || '/etc/sentra-itam/secrets.json';
const keyFile = process.env.SENTRA_ITAM_VAULT_KEY || SV.DEFAULT_KEY;
const [cmd, name] = process.argv.slice(2);
try {
  if (cmd === 'status') {
    const s = SV.fileStatus(file, keyFile);
    console.log(file + (s.exists ? ' mode ' + s.mode : ' missing') + (s.error ? ' - ' + s.error : ''));
    for (const e of s.entries) console.log('  ' + e.name.padEnd(22) + ' ' + e.state + (e.why ? ' (' + e.why + ')' : ''));
    process.exit(s.entries.some((e) => e.state === 'plaintext' || e.state === 'sealed-unopenable') ? 3 : 0);
  } else if (cmd === 'seal') {
    const done = SV.sealFile(file, keyFile);
    console.log(done.length ? 'sealed: ' + done.join(', ') : 'nothing to seal (already sealed)');
  } else if (cmd === 'set' && name) {
    const v = fs.readFileSync(0, 'utf8').replace(/\r?\n$/, '');
    SV.setValue(file, keyFile, name, v);
    console.log(name + (v ? ' stored' + (SV.PLAIN_BY_DESIGN[name] ? '' : ' sealed (AES-256-GCM)') : ' removed'));
  } else { console.error('usage: itam-secrets.js status | seal | set NAME (value on stdin)'); process.exit(2); }
} catch (e) { console.error('!! ' + e.message); process.exit(1); }
