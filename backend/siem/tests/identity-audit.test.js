// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// AD identity audit flags from userAccountControl, old passwords, never signed in, adminCount orphans.
const test = require('node:test');
const assert = require('node:assert/strict');
const { createIdentity } = require('../engine/ad/identity');

const DAY = 86400000, T = Date.parse('2026-10-12T00:00:00Z');
test('identity audit: flags, counts, ?flag= filter', () => {
  const id = createIdentity({ now: () => T });
  id.replace({ synced: T, users: [
    { sam: 'alice', uac: 0x200 | 0x10000, privileged: true, last_logon: T - DAY, pwd_last_set: T - 400 * DAY },
    { sam: 'bob', uac: 0x200 | 0x20 | 0x400000, last_logon: 0, pwd_last_set: T - 10 * DAY },
    { sam: 'carl', uac: 0x202 | 0x10000, disabled: true, admin_count: 1, pwd_last_set: T - 900 * DAY },
    { sam: 'svc-sql', uac: 0x200 | 0x80000, last_logon: T - DAY, pwd_last_set: T - 30 * DAY },
  ], groups: [] });
  const c = id.summary().counts;
  assert.deepEqual([c.pwd_never_expires, c.pwd_not_required, c.no_preauth, c.delegation, c.old_pwd, c.never_logon, c.privileged_pwd_never_expires, c.admin_count_orphans], [1, 1, 1, 1, 1, 1, 1, 1]);
  const names = (q) => id.list(q).items.map((r) => r.sam);
  assert.deepEqual(names({ flag: 'pwd_never_expires' }), ['alice']);          // carl is disabled
  assert.deepEqual(names({ flag: 'old_pwd' }), ['alice']);
  assert.deepEqual(names({ flag: 'old_pwd', pwd_days: 20 }), ['alice', 'svc-sql']);
  assert.deepEqual(names({ flag: 'admin_orphan' }), ['carl']);
  assert.deepEqual(names({ flag: 'no_preauth' }), ['bob']);
  const a = id.list({ q: 'alice' }).items[0];
  assert.equal(a.pwd_age_days, 400); assert.equal(a.never_logon, false); assert.equal(a.pwd_never_expires, true);
});
