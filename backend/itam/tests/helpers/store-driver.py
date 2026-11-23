# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
"""Test driver: apply a list of store operations with pyengine/store.py (argv[1] = the store folder, ops on stdin)."""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'pyengine'))
from store import Store, parse  # noqa: E402

s = Store(sys.argv[1])
for op in parse(sys.stdin.read()):
    c = s.collection(op['c']) if 'c' in op else None
    if op['op'] == 'put':
        c.put(op['o'])
    elif op['op'] == 'patch':
        c.patch(op['id'], lambda o, st=op['set']: o.update(st))
    elif op['op'] == 'remove':
        c.remove(op['id'])
    elif op['op'] == 'audit':
        s.audit(op['entry'])
    elif op['op'] == 'snapshot':
        c.snapshot()
# not closed: closing snapshots every collection, and the test compares the journals as written
print(json.dumps({'ok': True}))
