// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// A throwaway PostgreSQL cluster for tests (PostgreSQL binaries + the "postgres" OS user when running as root). Returns
// null when it cannot start - the tests that need it are skipped with that reason, never faked.
const fs = require('node:fs'), os = require('node:os'), path = require('node:path'), { spawnSync } = require('node:child_process');
const BIN = ['/usr/lib/postgresql/16/bin', '/usr/lib/postgresql/15/bin', '/usr/lib/postgresql/14/bin'].find((d) => fs.existsSync(path.join(d, 'initdb')));
function startPg() {
  if (!BIN) return { skip: 'PostgreSQL binaries not installed' };
  const root = process.getuid && process.getuid() === 0;
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'zyb-pg-')), data = path.join(dir, 'data'), port = 20000 + Math.floor(Math.random() * 20000);
  if (root) spawnSync('chown', ['-R', 'postgres:postgres', dir]);
  const run = (bin, args) => spawnSync(root ? 'runuser' : path.join(BIN, bin), root ? ['-u', 'postgres', '--', path.join(BIN, bin)].concat(args) : args, { encoding: 'utf8' });
  let r = run('initdb', ['-D', data, '-U', 'zybsu', '--auth=trust', '-E', 'UTF8', '--locale=C.UTF-8']);
  if (r.status !== 0) r = run('initdb', ['-D', data, '-U', 'zybsu', '--auth=trust', '-E', 'UTF8']);
  if (r.status !== 0) return { skip: 'initdb failed: ' + String(r.stderr).slice(0, 200) };
  fs.appendFileSync(path.join(data, 'postgresql.conf'), `\nport = ${port}\nlisten_addresses = '127.0.0.1'\nunix_socket_directories = '${dir}'\n`);
  // password logins for the engine's accounts (md5/scram), trust for the setup superuser only
  fs.writeFileSync(path.join(data, 'pg_hba.conf'), 'host all zybsu 127.0.0.1/32 trust\nhost all all 127.0.0.1/32 scram-sha-256\n');
  if (root) spawnSync('chown', ['-R', 'postgres:postgres', dir]);
  r = run('pg_ctl', ['-D', data, '-l', path.join(dir, 'log'), '-w', 'start']);
  if (r.status !== 0) return { skip: 'pg_ctl start failed: ' + String(r.stderr || r.stdout).slice(0, 200) };
  return { port, dir, stop() { run('pg_ctl', ['-D', data, '-m', 'immediate', 'stop']); try { fs.rmSync(dir, { recursive: true, force: true }); } catch (e) { /* gone */ } } };
}
module.exports = { startPg };
