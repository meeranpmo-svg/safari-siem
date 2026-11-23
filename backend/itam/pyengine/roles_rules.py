# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
"""Job roles - migration step 8b (docs/PYTHON-MIGRATION.md). The read routes of engine/roles.js, answered from the store
files themselves (store.py, read-only): GET /roles (list), /roles/me (me), /roles/approvers (approvers). The catalogue
(functions, levels, bases, approval scopes, groups, AI engineers) is code in roles.js / approve-scopes.js and comes with
the request; the roles and the assignments are read here. Saving, deleting and assigning stay in Node.js, the only
writer of the store until step 9.
Standard library only (Python 3.8+).
"""
import functools

from reconcile_rules import locale_compare
from store import reader as store_reader


def _k(u):
    return (u if isinstance(u, str) else '' if u is None else str(u)).lower() if u else ''


def _cols(r):
    s = store_reader(r['dir'])
    return s.collection('job_roles'), s.collection('role_assignments')


def _cat(r):
    return r.get('catalogue') or {}


def approver_map(r, roles=None, assign=None):
    if roles is None:
        roles, assign = _cols(r)
    out = {sc: [] for sc in (_cat(r).get('approve_scopes') or {})}
    for a in assign.all():
        ro = roles.get(a.get('role_id'))
        if not ro or ro.get('base') == 'viewer':
            continue
        for sc in ro.get('approves') or []:
            if sc in out:
                out[sc].append(_k(a.get('user')))
    for sc in out:
        out[sc].sort()
    return out


def approvers(r):
    roles, assign = _cols(r)
    cat = _cat(r)
    m = approver_map(r, roles, assign)
    eng = []
    for sc, e in (cat.get('engineers') or {}).items():
        direct, group = m.get(sc) or [], m.get(e[0]) or []
        eng.append({'scope': sc, 'group': e[0], 'engineer': e[1], 'approves': e[2], 'people': sorted(dict.fromkeys(direct + group)),
                    'direct': list(direct), 'via_group': list(group)})
    return {'scopes': cat.get('approve_scopes'), 'groups': cat.get('groups'), 'approvers': m, 'engineers': eng}


def _order(x, y):
    if bool(x.get('builtin')) == bool(y.get('builtin')) and x.get('builtin') == y.get('builtin'):
        return locale_compare(str(x.get('name')), str(y.get('name')))
    return -1 if x.get('builtin') else 1


def list_(r):
    roles, assign = _cols(r)
    cat = _cat(r)
    a = assign.all()
    rows = []
    for ro in sorted(roles.all(), key=functools.cmp_to_key(_order)):
        o = dict(ro)
        o['users'] = [x.get('user') for x in a if x.get('role_id') == ro.get('id')]
        rows.append(o)
    return {'functions': [{'key': f['key'], 'name': f['name'], 'views': f['views']} for f in cat.get('functions') or []],
            'levels': cat.get('levels'), 'bases': cat.get('bases'), 'approve_scopes': cat.get('approve_scopes'), 'roles': rows,
            'assignments': [{k: x.get(k) for k in ('user', 'role_id', 'by', 'at', 'source', 'via') if k in x} for x in a]}


def me(r):
    roles, assign = _cols(r)
    user = r.get('user')
    fns = [{'key': f['key'], 'views': f['views']} for f in _cat(r).get('functions') or []]
    a = assign.get(_k(user))
    ro = roles.get(a.get('role_id')) if a else None
    u = {'user': user} if 'user' in r else {}   # an undefined user is left out, as JSON.stringify does
    if not ro:
        return dict(u, role=None, functions=fns)
    return dict(u, role= {k: v for k, v in (('id', ro.get('id')), ('name', ro.get('name')), ('base', ro.get('base')), ('functions', ro.get('functions')),
                                                    ('approves', [] if ro.get('base') == 'viewer' else (ro.get('approves') or []))) if v is not None or k in ro},
                functions=fns)
