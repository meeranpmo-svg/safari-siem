# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
"""Job roles - the WRITES, migration step 9b (docs/PYTHON-MIGRATION.md): save, delete and assign decided here exactly
like engine/roles.js. The store keeps ONE writer, so nothing is written here: each operation reads the current roles
and assignments (store.reader) and answers the records to write ({puts, removes}) and the audit entry - or a refusal
({refuse: {status, error}}) worded exactly as Node.js words it. Node.js commits the answer only if nothing it was
decided on changed meanwhile, otherwise it decides again itself. Node.js supplies the new id and the time, so both
engines write identical records.
Standard library only (Python 3.8+).
"""
import re

from store import reader as store_reader

USER_RE = re.compile(r'^[A-Za-z0-9._@\\-]{1,100}$')
_CTRL = re.compile('[\u0000-\u001f\u007f]')
# String.prototype.trim's whitespace: not Python's (Python also strips U+0085 and keeps U+FEFF)
JS_WS = '\t\n\x0b\x0c\r \u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000\ufeff'


def _utf16(t, n):
    if len(t) <= n // 2 or all(ord(c) < 0x10000 for c in t):
        return t[:n]
    return t.encode('utf-16-le', 'surrogatepass')[:2 * n].decode('utf-16-le', 'surrogatepass')


def js_str(v):
    if v is None:
        return 'null'
    if isinstance(v, bool):
        return 'true' if v else 'false'
    if isinstance(v, float) and v.is_integer() and abs(v) < 1e21:
        return str(int(v))
    if isinstance(v, list):
        return ','.join('' if x is None else js_str(x) for x in v)
    if isinstance(v, dict):
        return '[object Object]'
    return str(v)


def s(v, mx=120):
    """s() of roles.js: control characters to spaces, trimmed, at most mx UTF-16 units"""
    return _utf16(_CTRL.sub(' ', '' if v is None else js_str(v)).strip(JS_WS), mx or 120)


def k(u):
    return js_str(u).lower() if u else ''


class Refuse(Exception):
    def __init__(self, status, error):
        super().__init__(error)
        self.status, self.error = status, error


def bad(msg, status=400):
    return Refuse(status, msg)


def _ctx(r):
    st = store_reader(r['dir'])
    return st.collection('job_roles'), st.collection('role_assignments'), r.get('catalogue') or {}, r.get('who') or {}, r.get('at')


def _all_none(cat):
    return {f['key']: 'none' for f in cat.get('functions') or []}


def _norm_functions(f, cur, cat):
    out = _all_none(cat)
    if isinstance(cur, dict):
        out.update(cur)
    levels = cat.get('levels') or []
    for fn in cat.get('functions') or []:
        if isinstance(f, dict) and fn['key'] in f:
            v = js_str(f[fn['key']]) if f[fn['key']] is not None else 'null'
            if v not in levels:
                raise bad('%s: access must be none, view or manage' % fn['name'])
            out[fn['key']] = v
    return out


def _norm_approves(v, base, cat):
    scopes = cat.get('approve_scopes') or {}
    out = list(dict.fromkeys(js_str(x) if x is not None else 'null' for x in (v if isinstance(v, list) else [])))
    for x in out:
        if x not in scopes:
            raise bad('unknown approval scope "%s" (%s)' % (s(x, 30), ', '.join(scopes.keys())))
    if out and base == 'viewer':
        raise bad('a read-only (viewer) role cannot approve - raise the base level to operator')
    return out


def _audit(who, action, target, detail):
    return {'by': who.get('user'), 'role': who.get('role'), 'ip': who.get('ip'), 'action': action, 'target': target, 'detail': detail}


def save(r):
    roles, _, cat, who, at = _ctx(r)
    b = r.get('body') if isinstance(r.get('body'), dict) else {}
    rid = s(b.get('id'), 60) if b.get('id') else ''
    cur = roles.get(rid) if rid else None
    if rid and cur is None:
        raise bad('role not found', 404)
    name = s(b['name'] if 'name' in b else (cur.get('name') if cur else None), 60)
    if not name:
        raise bad('a role name is required')
    if any(js_str(x.get('name')).lower() == name.lower() and x.get('id') != rid for x in roles.all()):
        raise bad('a role called "%s" already exists' % name, 409)
    base = js_str(b['base']) if 'base' in b else js_str((cur.get('base') if cur else None) or 'viewer')
    if base not in (cat.get('bases') or []):
        raise bad('base must be viewer, operator or admin')
    functions = _norm_functions(b.get('functions'), cur.get('functions') if cur else None, cat)
    if base == 'viewer' and 'manage' in functions.values():
        raise bad('a role with base level "viewer" cannot manage anything - raise the base level or set those functions to view')
    approves = _norm_approves(b['approves'] if 'approves' in b else (cur.get('approves') if cur else None), base, cat)
    rec = dict(cur or {})
    rec.update({'id': rid or r.get('new_id'), 'name': name, 'base': base, 'description': s(b['description'] if 'description' in b else (cur.get('description') if cur else None), 300),
                'functions': functions, 'approves': approves, 'builtin': bool(cur and cur.get('builtin')), 'updated_by': who.get('user'), 'updated_at': at})
    if cur is None:
        rec['created_by'] = who.get('user')
        rec['created_at'] = at
    return {'puts': [{'c': 'job_roles', 'o': rec}], 'removes': [], 'saved': rec,
            'audit': _audit(who, 'roles.update' if cur else 'roles.create', rec['id'], {'name': name, 'base': base, 'functions': functions, 'approves': approves})}


def remove(r):
    roles, assign, _, who, _ = _ctx(r)
    ro = roles.get(js_str(r.get('id') or ''))
    if ro is None:
        raise bad('role not found', 404)
    if ro.get('builtin'):
        raise bad('built-in roles cannot be deleted (change their functions instead)', 409)
    n = len([x for x in assign.all() if x.get('role_id') == ro.get('id')])
    if n:
        raise bad('%d users have this role - assign them another role first' % n, 409)
    return {'puts': [], 'removes': [{'c': 'job_roles', 'id': ro['id']}], 'audit': _audit(who, 'roles.delete', ro['id'], {'name': ro.get('name')})}


def assign_user(r):
    roles, assign, _, who, at = _ctx(r)
    b = r.get('body') if isinstance(r.get('body'), dict) else {}
    user = s(b.get('user'), 100)
    if not USER_RE.match(user):
        raise bad('invalid user name')
    rid = s(b.get('role_id'), 60) if b.get('role_id') else None
    before = assign.get(k(user))
    puts, removes = [], []
    if rid:
        ro = roles.get(rid)
        if ro is None:
            raise bad('role not found', 404)
        if k(user) == k(who.get('user')) and ro.get('base') != 'admin':
            raise bad('you cannot give yourself a role without administration - ask another administrator', 409)
        puts.append({'c': 'role_assignments', 'o': {'id': k(user), 'user': user, 'role_id': rid, 'by': who.get('user'), 'at': at}})
    else:
        if k(user) == k(who.get('user')):
            raise bad('you cannot remove your own role', 409)
        if before is not None:
            removes.append({'c': 'role_assignments', 'id': k(user)})
    return {'puts': puts, 'removes': removes, 'audit': _audit(who, 'roles.assign', user, {'from': before.get('role_id') if before else None, 'to': rid})}


def _guard(fn):
    def run(r):
        try:
            return fn(r)
        except Refuse as e:
            return {'refuse': {'status': e.status, 'error': e.error}}
    return run


OPS = {'roles.save': _guard(save), 'roles.remove': _guard(remove), 'roles.assign': _guard(assign_user)}
