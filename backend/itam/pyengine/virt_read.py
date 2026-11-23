# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
"""Virtualization change plans - migration step 8e (docs/PYTHON-MIGRATION.md), answered from the store files (store.py,
read-only), exactly like engine/virt-admin.js: GET /virt/changes (?state=) and /virt/changes/:id. Proposing, approving,
rejecting and recording a plan as applied stay in Node.js, the only writer of the store until step 9.
Standard library only (Python 3.8+).
"""
import functools

from store import reader as store_reader


def _lt(a, b):
    """a < b as JavaScript compares two ISO strings; undefined or null on either side is false"""
    if isinstance(a, str) and isinstance(b, str):
        return a < b
    if isinstance(a, (int, float)) and isinstance(b, (int, float)) and not isinstance(a, bool) and not isinstance(b, bool):
        return a < b
    return False


def _plans(r):
    rows = store_reader(r['dir']).collection('virt_changes').all()
    # plans.all().sort((a, b) => (a.requested_at < b.requested_at ? 1 : -1)) - never "equal": V8's sort is a port of
    # CPython's TimSort, so the same comparator makes the same calls and ties land in the same order
    return sorted(rows, key=functools.cmp_to_key(lambda a, b: 1 if _lt(a.get('requested_at'), b.get('requested_at')) else -1))


def changes(r):
    st = (r.get('query') or {}).get('state')
    return {'changes': [p for p in _plans(r) if not st or p.get('state') == st]}


def change(r):
    i = r.get('id')
    p = next((x for x in _plans(r) if x.get('id') == i), None)
    return {'found': p is not None, 'change': p}


OPS = {'virtplans.changes': changes, 'virtplans.change': change}   # not 'virt.': that prefix is the vCenter / Prism readers
