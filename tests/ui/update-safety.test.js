// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// update-server.sh safety rules (no browser needed): a platform backup is taken before anything changes and a failed
// backup stops the update; the Python tools are re-installed when the package carries a different (patched) wheel
// bundle, not only when a module is missing - otherwise a security fix in the bundle never reaches the server.
// Run: node update-safety.test.js
const fs = require('fs'), path = require('path');
const ROOT = path.resolve(__dirname, '../..');
// source layout (shield + sentra-siem side by side) or the clean tree (deploy/server, backend/siem)
const first = (...c) => c.find((p) => fs.existsSync(p)) || c[0];
const srv = fs.readFileSync(first(path.join(ROOT, 'deploy/server/update-server.sh'), path.join(ROOT, 'deploy/server/update-server.sh')), 'utf8');
let bad = 0; const check = (ok, msg) => { console.log((ok ? 'ok   ' : 'FAIL ') + msg); if (!ok) bad++; };

const iBackup = srv.indexOf('/usr/local/sbin/zyb-backup;'), iStep1 = srv.indexOf('step "1/5 SIEM engine"');
check(iBackup > 0 && iBackup < iStep1, 'the platform backup runs before the first change (step 1)');
const block = srv.slice(srv.indexOf('if [ -x /usr/local/sbin/zyb-backup ]'), iStep1);
check(/else echo "!! the platform backup failed[^\n]*exit 1; fi/.test(block), 'a failed backup stops the update');
check(/ZYB_SKIP_BACKUP:-}" = 1/.test(block), 'the stop can be overridden on purpose (ZYB_SKIP_BACKUP=1)');
check(/python-wheels-linux-x86_64\.tgz\.sha256/.test(srv) && /\.bundle-sha256/.test(srv), 'the Python setup is skipped only when the venv was built from this package\'s wheel bundle');
const setup = fs.readFileSync(first(path.join(ROOT, 'backend', 'siem', 'install', 'netops-cli-setup.sh'), path.join(ROOT, 'backend', 'siem', 'install', 'netops-cli-setup.sh')), 'utf8');
check(/> "\$VENV\/\.bundle-sha256"/.test(setup), 'netops-cli-setup.sh records the bundle it installed from (sentra-siem)');
console.log(bad ? 'FAILED ' + bad : 'OK update safety'); process.exit(bad ? 1 : 0);
