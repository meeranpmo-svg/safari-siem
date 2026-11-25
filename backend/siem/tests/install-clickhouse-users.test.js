// Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// install.sh with ClickHouse already installed (by hand, or an earlier run that stopped) and no SIEM users file: it must create the
// users from secrets.json (ch-install.sh), otherwise the engine fails with "Authentication failed ... no user with such name".
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

test('install.sh creates the ClickHouse users when ClickHouse is there but its SIEM users file is not', () => {
  const sh = fs.readFileSync(path.join(__dirname, '..', 'install', 'install.sh'), 'utf8');
  const i = sh.indexOf('if ! command -v clickhouse-server'), block = sh.slice(i, sh.indexOf('\nfi\n', i));
  assert.match(block, /elif \[ ! -f \/etc\/clickhouse-server\/users\.d\/sentra-siem\.xml \]; then[\s\S]*?bash "\$APP\/install\/ch-install\.sh"/, 'missing users file → ch-install.sh');
  assert.match(block, /elif ! grep -q 'sentra_siem_admin'/, 'the older-version upgrade still runs');
  const ch = fs.readFileSync(path.join(__dirname, '..', 'install', 'ch-install.sh'), 'utf8');
  assert.match(ch, /users\.d\/sentra-siem\.xml/); assert.ok(!/DROP (TABLE|DATABASE)/i.test(ch), 'creating the users never drops data');
});
