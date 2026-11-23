// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// Backup platforms read by the Python module (pyengine/backup_sources.py) - migration step 2 (docs/PYTHON-MIGRATION.md).
const { createPySources } = require('./py-sources');
function createBackupSourcesPy(o = {}) { return createPySources({ module: 'backup', kinds: ['netbackup', 'veeam', 'cohesity'], node: require('./backup-sources'), python: o.python, py: o.py }); }
module.exports = { createBackupSourcesPy };
