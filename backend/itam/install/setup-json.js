// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Idempotent config/secrets writer used by install.sh. Merges new values over an existing file without clobbering
// anything already set; generates a proxy_secret on first run. Never prints secrets.
//   node setup-json.js config  <path> [--provider P] [--private-url URL] [--model NAME]
//   node setup-json.js secrets <path> [--private-token-file F]
const fs = require('node:fs');
const crypto = require('node:crypto');

function readJson(p) { try { return JSON.parse(fs.readFileSync(p, 'utf8')); } catch { return {}; } }
function writeJson(p, o, mode) { const tmp = p + '.tmp'; fs.writeFileSync(tmp, JSON.stringify(o, null, 2) + '\n', { mode: mode || 0o644 }); try { fs.chmodSync(tmp, mode || 0o644); } catch { /* */ } fs.renameSync(tmp, p); }
function arg(name) { const i = process.argv.indexOf(`--${name}`); return i > 0 ? process.argv[i + 1] : null; }

const kind = process.argv[2];
const path = process.argv[3];
if (!kind || !path) { process.stderr.write('usage: setup-json.js config|secrets <path> [options]\n'); process.exit(2); }

if (kind === 'config') {
  const cfg = readJson(path);
  cfg.api = cfg.api || {};
  if (cfg.api.port === undefined) cfg.api.port = 9150;
  cfg.ai = cfg.ai || {};
  const provider = arg('provider'); if (provider) cfg.ai.provider = provider;
  const purl = arg('private-url'); if (purl) cfg.ai.private_url = purl.replace(/\/+$/, '');
  const model = arg('model'); if (model) cfg.ai.model = model;
  if (cfg.ai.provider === undefined) cfg.ai.provider = 'private';
  cfg.netops = cfg.netops || {};
  cfg.vcenter = cfg.vcenter || {};
  writeJson(path, cfg, 0o640);
  process.stdout.write('config.json written\n');
} else if (kind === 'secrets') {
  const sec = readJson(path);
  if (!sec.proxy_secret) sec.proxy_secret = crypto.randomBytes(24).toString('hex');
  const tokenFile = arg('private-token-file');
  if (tokenFile) { try { sec.private_token = fs.readFileSync(tokenFile, 'utf8').trim(); } catch { /* keep existing */ } }
  if (sec.private_token === undefined) sec.private_token = '';
  writeJson(path, sec, 0o600);
  process.stdout.write('secrets.json written (proxy secret ' + (sec.proxy_secret ? 'present' : 'MISSING') + ')\n');
} else { process.stderr.write(`unknown kind ${kind}\n`); process.exit(2); }
