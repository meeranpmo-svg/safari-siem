#!/usr/bin/env node
// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/* Citynet's licence tool - runs OFFLINE on a Citynet machine, never on a customer server. The private key it makes must stay with
 * Citynet (never in git, never on a customer server, never pasted in chat); only the public key is installed on a server.
 *   node licence-tool.js keygen <dir>                          writes <dir>/licence-private.pem (0600) and <dir>/licence-pub.pem
 *   node licence-tool.js sign <private.pem> <request.json>     prints the signed licence to install (Platform Admin -> Modules & Solutions)
 *   node licence-tool.js verify <pub.pem> <licence.json>       checks a signed licence
 *   node licence-tool.js fingerprint                           (on a customer server) prints this server's fingerprint for "servers"
 *   node licence-tool.js set-public-key <pub.pem> [<sentra-siem>] builds the public key into the code (ITAM, and the SIEM repo when its
 *                                                              path is given) - commit and deploy: from then on the platform is ENFORCED
 *                                                              (no valid licence for the server -> 14 days' grace, then people are locked out)
 * request.json: { "licence_id": "CN-2027-001", "customer": "…", "edition": "Cyber Security", "modules": ["siem-core", …] | null,
 *   "limits": { "users": 50, "ips": 2000, "servers": 300, "network_devices": 200, "databases": 40, "log_sources": 500 } (or "unlimited"),
 *   "issued": "2026-11-03", "expires": "2027-11-03", "servers": ["ABCD-1234-…"] (optional: fingerprints), "grace_days": 14 (optional) } */
const fs = require('node:fs'), path = require('node:path'), crypto = require('node:crypto');
const { payloadOf, verify } = require(path.join(__dirname, '..', '..', 'backend', 'itam', 'engine', 'licence.js'));
const [cmd, a, b] = process.argv.slice(2);
const die = (m) => { console.error(m); process.exit(1); };
if (cmd === 'keygen') {
  if (!a) die('usage: keygen <dir>');
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
  fs.mkdirSync(a, { recursive: true });
  fs.writeFileSync(path.join(a, 'licence-private.pem'), privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
  fs.writeFileSync(path.join(a, 'licence-pub.pem'), publicKey.export({ type: 'spki', format: 'pem' }));
  console.log('written: ' + path.join(a, 'licence-private.pem') + ' (keep it with Citynet) and licence-pub.pem (install on the server as /etc/sentra-itam/licence-pub.pem)');
} else if (cmd === 'sign') {
  if (!a || !b) die('usage: sign <private.pem> <request.json>');
  const lic = JSON.parse(fs.readFileSync(b, 'utf8')); delete lic.signature;
  lic.signature = crypto.sign(null, Buffer.from(payloadOf(lic)), crypto.createPrivateKey(fs.readFileSync(a, 'utf8'))).toString('base64');
  console.log(JSON.stringify(lic, null, 2));
} else if (cmd === 'verify') {
  if (!a || !b) die('usage: verify <pub.pem> <licence.json>');
  const r = verify(JSON.parse(fs.readFileSync(b, 'utf8')), fs.readFileSync(a, 'utf8')); console.log(r.ok ? 'valid' : 'NOT valid: ' + r.why); process.exit(r.ok ? 0 : 2);
} else if (cmd === 'fingerprint') {
  const { fingerprintOf } = require(path.join(__dirname, '..', '..', 'backend', 'itam', 'engine', 'licence.js'));
  let mid = ''; for (const f of ['/etc/machine-id', '/var/lib/dbus/machine-id']) { try { mid = fs.readFileSync(f, 'utf8').trim(); if (mid) break; } catch (e) { /* not on this system: try the next file */ } }
  console.log(fingerprintOf(require('node:os').hostname(), mid));
} else if (cmd === 'set-public-key') {
  if (!a) die('usage: set-public-key <licence-pub.pem> [<path to sentra-siem>]');
  const pem = fs.readFileSync(a, 'utf8').trim();
  if (/PRIVATE KEY/.test(pem)) die('that is the PRIVATE key - give the public key (licence-pub.pem); the private key never goes into the code');
  try { if (crypto.createPublicKey(pem).asymmetricKeyType !== 'ed25519') die('not an Ed25519 public key'); } catch (e) { die('not a public key: ' + e.message); }
  const body = (rel) => "// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.\n'use strict';\n"
    + "// The licence issuer's PUBLIC key, built into the code (set by tools/licence/licence-tool.js set-public-key). Licensing is ENFORCED:\n"
    + "// the platform runs only with a licence signed by the matching private key, which stays with the issuer. Not a secret.\n"
    + 'module.exports = { PUBLIC_KEY: ' + JSON.stringify(pem + '\n') + ' };\n';
  const itam = path.join(__dirname, '..', '..', 'backend', 'itam', 'engine', 'licence-pubkey.js'); fs.writeFileSync(itam, body()); console.log('written: ' + itam);
  if (b) { const siem = path.join(b, 'engine', 'util', 'licence-pubkey.js'); if (!fs.existsSync(path.dirname(siem))) die('not an sentra-siem checkout: ' + b); fs.writeFileSync(siem, body()); console.log('written: ' + siem); }
  console.log('Commit and deploy both. Before you deploy, issue and install a licence for every server (fingerprint), or the platform locks after the grace period.');
} else die('usage: keygen <dir> | sign <private.pem> <request.json> | verify <pub.pem> <licence.json> | fingerprint | set-public-key <pub.pem> [<sentra-siem>]');
