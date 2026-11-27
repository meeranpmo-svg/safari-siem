// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/*
 * The agent packages for a server to fetch itself, without a browser session (agent side, like the Hyper-V report script): the files
 * the Agents & Downloads page offers (built by build-agents.py into <dashboards>/agents with manifest.json). Only a file named in the
 * manifest is served; it carries no secret - the ingest token / enrolment key is created on the platform and handed over separately,
 * once - and the install command checks its SHA-256 against the one the page showed before running anything.
 *   GET /agent/packages/:name   (no session; JSON {name, sha256, bytes, b64})
 */
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const httpErr = (status, msg) => Object.assign(new Error(msg), { status });
const NAME = /^[a-z0-9][a-z0-9._-]{0,80}\.(zip|ps1|tar\.gz)$/;
const MAX = 8 * 1024 * 1024;

function createAgentPackages(opts = {}) {
  const dir = opts.dir || path.join(process.env.SENTRA_DASHBOARDS || '/var/www/sentra/dashboards', 'agents');
  function get(name0) {
    const name = String(name0 || '');
    if (!NAME.test(name)) throw httpErr(400, 'name: not an agent package name');
    let man; try { man = JSON.parse(fs.readFileSync(path.join(dir, 'manifest.json'), 'utf8')); } catch (e) { throw httpErr(503, 'the agent packages are not built on this server - run the platform update'); }
    const list = Array.isArray(man) ? man : (man.items || man.files || []);
    const item = list.find((x) => x && (x.file === name || x.name === name));
    if (!item) throw httpErr(404, 'no agent package named ' + name);
    const file = path.join(dir, name);
    let buf; try { buf = fs.readFileSync(file); } catch (e) { throw httpErr(503, 'the package ' + name + ' is listed but not on disk - run the platform update'); }
    if (buf.length > MAX) throw httpErr(413, 'package too large');
    return { name, sha256: crypto.createHash('sha256').update(buf).digest('hex'), bytes: buf.length, b64: buf.toString('base64') };
  }
  return { get, dir };
}

function registerAgentPackages(srv, app, X) {
  srv.route('GET', '/packages/:name', (ctx) => X.get(ctx.params.name), { agent: true });
}

module.exports = { createAgentPackages, registerAgentPackages };
