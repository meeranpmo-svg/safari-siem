# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
"""Desk Support and Budget - the store WRITES, migration step 9h (docs/PYTHON-MIGRATION.md), decided here exactly like
engine/desksupport.js (settings, a patch request, taking over a request the AI engineer raised) and engine/budget.js
(last year's budget import, a requirement added / edited by hand, deleting one, settings). Nothing is written here; the
engine (engine/py-writer.js) commits only if every record decided on is what it holds now.
Not here, on purpose:
  - Desk Support ticket triage and patch approval: they call ServiceDesk Plus / Endpoint Central with the sealed
    ManageEngine credentials, and a credential-carrying call never goes through the shared Python service;
  - Budget decisions (approve / defer / reject a line): they are made on the GENERATED budget, which stays in JavaScript
    (the faster language for that hot path, measured 78 ms); so does every page these writes answer with - the engine
    builds it after the commit.
What Python does not read exactly like JavaScript answers {node: true}.
Standard library only (Python 3.8+).
"""
import re
from datetime import datetime, timezone

from assets_write import NodeDecides, Refuse, _str_to_num, _to_str, _trim, _utf16
from core_write import _Ctx, js_round
from jscompat import MISSING, truthy
from roles_write import JS_WS

PROTO = {'constructor', '__proto__', 'hasOwnProperty', 'isPrototypeOf', 'propertyIsEnumerable', 'toLocaleString', 'toString', 'valueOf',
         '__defineGetter__', '__defineSetter__', '__lookupGetter__', '__lookupSetter__'}
_CTRL = re.compile('[\u0000-\u001f\u007f]')


def U(v):
    return v is MISSING


def P(o, k):
    """o.k for any JSON value (a property of a non-object is undefined here)"""
    return o.get(k, MISSING) if isinstance(o, dict) else MISSING


def _string(v):
    return '' if v is None or v is MISSING else _to_str(v)


def s(v, mx=200):
    return _utf16(_trim(_CTRL.sub(' ', _string(v))), mx or 200)


def _or(*vals):
    for v in vals[:-1]:
        if not U(v) and truthy(v):
            return v
    return vals[-1]


def u16len(t):
    return len(t) + sum(1 for ch in t if ord(ch) > 0xFFFF)


def number(v):
    """Number(v) when finite, else None"""
    if U(v):
        return None
    if v is None:
        return 0
    if isinstance(v, bool):
        return 1 if v else 0
    if isinstance(v, (int, float)):
        return v if v == v and v not in (float('inf'), float('-inf')) else None
    if isinstance(v, (str, list)):
        n = _str_to_num(_to_str(v))
        return None if n is None or n in (float('inf'), float('-inf')) else n
    return None


def is_int(n):
    return n is not None and n == int(n)


def _who(r):
    w = r.get('who')
    if not isinstance(w, dict) or not all(k in w for k in ('user', 'role', 'ip')):
        raise NodeDecides()
    return w


def _audit(who, action, target, detail):
    return {'by': who['user'], 'role': who['role'], 'ip': who['ip'], 'action': action, 'target': target, 'detail': detail}


# ---- Desk Support ---------------------------------------------------------------------------------------------------
PRIORITIES = ['Low', 'Medium', 'High', 'Urgent']
MODES = ['off', 'suggest', 'auto']
DEF_PRIORITY = [
    ['Urgent', 'down|outage|cannot work|production|ransom|breach|all users|data loss|urgent|p1'],
    ['High', 'not working|error|crash|blocked|vpn|email down|cannot access|locked out|asap|important'],
    ['Low', 'how to|how do i|question|request|please install|rename|cosmetic|enhancement|when you can'],
]
DEF_GROUPS = [
    ['Network', 'network|wifi|wi-fi|vpn|internet|lan|switch|router|firewall'],
    ['Messaging', 'email|outlook|exchange|mailbox|calendar|teams|sharepoint'],
    ['Identity & Access', 'password|account|login|mfa|access|permission|locked|ad |active directory'],
    ['Desktop Support', 'laptop|desktop|pc|printer|monitor|keyboard|mouse|install|software|office|windows|slow|screen'],
]
FIRST_RESPONSE = 'Thank you for contacting IT support. Your ticket has been received and assigned; a technician will update you shortly.'
_HHMM = re.compile(r'^([01][0-9]|2[0-3]):[0-5][0-9]\Z')


def desk_config(c):
    rec = c.get('desk_config', 'cfg')
    v = _or(P(rec, 'values') if rec is not None else MISSING, {})
    if not isinstance(v, dict):
        raise NodeDecides()
    g = lambda k: v.get(k, MISSING)   # noqa: E731
    patch = {'mode': 'off', 'min_critical': 1, 'window_start': '20:00', 'window_end': '06:00', 'max_per_run': 10, 'auto_approve': False}
    pv = _or(g('patch'), {})
    if not isinstance(pv, dict):
        raise NodeDecides()   # Object.assign of a string / list copies its indices
    patch.update(pv)
    return {
        'mode': g('mode') if isinstance(g('mode'), str) and g('mode') in MODES else 'off',
        'technicians': g('technicians') if isinstance(g('technicians'), list) else [],
        'priority_rules': g('priority_rules') if isinstance(g('priority_rules'), list) and g('priority_rules') else DEF_PRIORITY,
        'groups': g('groups') if isinstance(g('groups'), list) and g('groups') else DEF_GROUPS,
        'ack_status': _or(g('ack_status'), 'In Progress'),
        'first_response': _or(g('first_response'), FIRST_RESPONSE),
        'max_per_run': _or(g('max_per_run'), 25),
        'rr_index': _or(g('rr_index'), 0),
        'patch': patch,
    }


def desk_set_config(r, c):
    who, at = _who(r), r.get('at')
    b = r.get('body') or {}
    cur = desk_config(c)
    v = {}
    m = s(b.get('mode', MISSING)).lower()
    v['mode'] = m if m in MODES else cur['mode']
    if isinstance(b.get('technicians'), list):
        techs = []
        for t in b['technicians'][:200]:
            if t is None:
                raise NodeDecides()   # null.name throws in Node.js
            sk = P(t, 'skills')
            sk = sk if isinstance(sk, list) else _string(_or(sk, '')).split(',')
            rec = {'name': s(P(t, 'name'), 120), 'email': s(P(t, 'email'), 160), 'skills': [x for x in (s(y, 40) for y in sk) if x][:20]}
            if rec['name'] or rec['email']:
                techs.append(rec)
        v['technicians'] = techs
    else:
        v['technicians'] = cur['technicians']
    pr = b.get('priority_rules')
    v['priority_rules'] = [[x[0], s(x[1] if len(x) > 1 else MISSING, 300)] for x in pr if isinstance(x, list) and len(x) > 0 and isinstance(x[0], str) and x[0] in PRIORITIES][:40] if isinstance(pr, list) else cur['priority_rules']
    gr = b.get('groups')
    v['groups'] = [[s(x[0] if len(x) > 0 else MISSING, 80), s(x[1] if len(x) > 1 else MISSING, 300)] for x in gr if isinstance(x, list)][:40] if isinstance(gr, list) else cur['groups']
    v['ack_status'] = s(b.get('ack_status', MISSING), 40) or cur['ack_status']
    v['first_response'] = s(b.get('first_response', MISSING), 1000) or cur['first_response']
    mp = b.get('max_per_run', MISSING)
    if not U(mp) and mp is not None:
        n = number(mp)
        if not is_int(n) or n < 1 or n > 200:
            raise Refuse(400, 'max_per_run must be 1-200')
        v['max_per_run'] = int(n)
    else:
        v['max_per_run'] = cur['max_per_run']
    p = b.get('patch', MISSING)
    p = p if (not U(p) and truthy(p) and isinstance(p, (dict, list))) else {}
    pg = lambda k: P(p, k)   # noqa: E731
    cp = cur['patch']
    pm = s(pg('mode')).lower()
    mc, mx = number(pg('min_critical')), number(pg('max_per_run'))
    v['patch'] = {'mode': pm if pm in ('off', 'suggest', 'auto') else cp.get('mode', MISSING),
                  'min_critical': int(mc) if is_int(mc) and mc >= 1 else cp.get('min_critical', MISSING),
                  'window_start': s(pg('window_start'), 5) or cp.get('window_start', MISSING),
                  'window_end': s(pg('window_end'), 5) or cp.get('window_end', MISSING),
                  'max_per_run': int(mx) if is_int(mx) and mx >= 1 else cp.get('max_per_run', MISSING),
                  'auto_approve': pg('auto_approve') is True}
    if any(U(x) for x in v['patch'].values()):
        raise NodeDecides()
    if v['patch']['auto_approve']:
        armed = truthy(cp.get('auto_approve')) and truthy(cp.get('armed_by'))
        v['patch']['armed_by'] = cp['armed_by'] if armed else who['user']
        v['patch']['armed_at'] = cp['armed_at'] if truthy(cp.get('auto_approve')) and truthy(cp.get('armed_at')) else at
    for k in ('window_start', 'window_end'):
        if not U(pg(k)) and not (isinstance(v['patch'][k], str) and _HHMM.match(v['patch'][k])):
            raise Refuse(400, '%s must be HH:MM (Riyadh time)' % k)
    v['rr_index'] = cur['rr_index']
    detail = {'mode': v['mode'], 'patch_mode': v['patch']['mode'], 'auto_approve': v['patch']['auto_approve'], 'technicians': len(v['technicians'])}
    a = _audit(who, 'desk.config', 'desk', detail)
    return {'puts': [{'c': 'desk_config', 'o': {'id': 'cfg', 'values': v}}], 'audit': a, 'result': {}}


def _is_system(u):
    return re.match(r'^(duty|system):', _trim(_string(_or(u, ''))), re.I | re.A) is not None


def desk_request_patch(r, c):
    who, at = _who(r), r.get('at')
    rid = s(r.get('id'), 40)
    comp = c.get('me_ec_computers', rid)
    if comp is None:
        hit = next((x for x in c.all('me_ec_computers') if x.get('resource_id', MISSING) == rid), None)
        comp = c.seen('me_ec_computers', hit) if hit is not None else None
    if comp is None:
        raise Refuse(404, 'computer not found')
    if not all(k in comp for k in ('name', 'critical', 'missing')):
        raise NodeDecides()
    rec = {'id': r.get('new_id'), 'resource_id': rid, 'name': comp['name'], 'critical': comp['critical'], 'missing': comp['missing'], 'state': 'requested',
           'requested_by': who['user'], 'requested_at': at, 'history': [{'at': at, 'by': who['user'], 'what': 'patch install requested'}]}
    return {'puts': [{'c': 'desk_patch', 'o': rec}], 'result': rec, 'audit': _audit(who, 'desk.patch.request', rid, {'critical': comp['critical']})}


def desk_endorse_patch(r, c):
    who, at = _who(r), r.get('at')
    rec = c.get('desk_patch', s(r.get('id'), 20))
    if rec is None:
        raise Refuse(404, 'patch request not found')
    st = rec.get('state', MISSING)
    if st != 'requested':
        raise Refuse(409, 'already ' + ('undefined' if U(st) else _to_str(st)))
    rb = rec.get('requested_by', MISSING)
    if not _is_system(rb):
        raise Refuse(409, 'this request was made by ' + ('undefined' if U(rb) else _to_str(rb)) + ' - nothing to take over')
    if not isinstance(rec.get('history'), list):
        raise NodeDecides()
    rec['raised_by'] = rb
    rec['requested_by'] = who['user']
    rec['history'].append({'at': at, 'by': who['user'], 'what': 'taken over from ' + _to_str(rb) + ' - a different administrator must approve'})
    return {'puts': [{'c': 'desk_patch', 'o': rec}], 'result': rec, 'audit': _audit(who, 'desk.patch.endorse', rec.get('resource_id', MISSING), {'from': rb})}


# ---- Budget ---------------------------------------------------------------------------------------------------------
KINDS = ['capex', 'opex']
PRIOS = ['must', 'should', 'could']
AREAS = {'it_ops': ['infrastructure', 'applications'], 'cyber': ['security']}
DEFAULTS = {'fy': None, 'currency': 'SAR', 'envelopes': {'it_ops': 66000000, 'cyber': 30000000},
            'unit_costs': {k: None for k in ('server', 'workstation', 'network', 'firewall', 'storage', 'printer', 'phone', 'os_upgrade', 'storage_tb', 'support_server', 'support_storage', 'support_network')},
            'support_pct': None, 'inflation_pct': 0, 'storage_target_pct': 70, 'storage_warn_pct': 85}
_WS = '[' + re.escape(JS_WS) + ']'
_MONEY_PFX = re.compile('^([sS][aA][rR]|[sS][rR]|ر\\.س)')
_DAY = re.compile(r'^[0-9]{4}-[0-9]{2}-[0-9]{2}\Z')


def money(v):
    if v is None or U(v) or v == '':
        return None
    t = re.sub('[,' + re.escape(JS_WS) + ']', '', _to_str(v))
    n = _str_to_num(_MONEY_PFX.sub('', t, count=1))
    if n is None or n in (float('inf'), float('-inf')) or n < 0:
        return None
    return js_round(n * 100) / 100


def budget_settings(c, now_ms):
    rec = c.get('budget_settings', 'settings')
    v = _or(P(rec, 'values') if rec is not None else MISSING, {})
    if not isinstance(v, dict):
        raise NodeDecides()
    o = dict(DEFAULTS)
    o.update(v)
    for k in ('envelopes', 'unit_costs'):
        x = _or(v.get(k, MISSING), {})
        if not isinstance(x, dict):
            raise NodeDecides()
        d = dict(DEFAULTS[k])
        d.update(x)
        o[k] = d
    if U(o.get('fy', MISSING)) or not truthy(o.get('fy')):
        o['fy'] = datetime.fromtimestamp(now_ms / 1000, tz=timezone.utc).year + 1
    return o


def _rx(pat, v):
    return re.search(pat, _string(v), re.I | re.A) is not None


def _norm_row(row, i):
    g = lambda k: P(row, k)   # noqa: E731
    envs = _or(g('envelope'), g('budget'), g('department'), '')
    env = 'cyber' if _rx('cyber|secur', envs) else 'it_ops' if _rx('it|oper|infra|app', envs) else None
    ar = _or(g('area'), g('category'), '')
    area = 'applications' if _rx('app', ar) else 'infrastructure' if _rx('infra|network|server|storage|data ?cent', ar) else 'security' if _rx('secur|cyber', ar) else ''
    kd = _or(g('kind'), g('type'), g('capex_opex'), '')
    kind = 'capex' if _rx('cap', kd) else 'opex' if _rx('op', kd) else None
    title = s(_or(g('title'), g('item'), g('description'), g('name')), 200)
    if not title:
        return None
    nn = lambda x: not U(x) and x is not None   # noqa: E731  x != null
    return {'key': s(_or(g('id'), g('ref'), ''), 60) or str(i + 1), 'title': title, 'envelope': env, 'area': area, 'kind': kind,
            'approved': money(g('approved') if nn(g('approved')) else g('budget_amount') if nn(g('budget_amount')) else g('amount')),
            'spent': money(g('spent') if nn(g('spent')) else g('actual')), 'status': s(g('status'), 40), 'vendor': s(_or(g('vendor'), g('supplier')), 120) or None}


def budget_import(r, c):
    who, at = _who(r), r.get('at')
    b = r.get('body') or {}
    fy = number(b.get('fy', MISSING))
    if not is_int(fy) or fy < 2000 or fy > 2100:
        raise Refuse(400, 'fy must be the year of the budget being imported, e.g. 2026')
    fy = int(fy)
    rows_in = b.get('rows')
    if not isinstance(rows_in, list) or not rows_in or len(rows_in) > 5000:
        raise Refuse(400, 'rows must be a list of 1-5000 budget lines')
    if any(x is None for x in rows_in):
        raise NodeDecides()   # null.envelope throws in Node.js
    rows = [x for x in (_norm_row(row, i) for i, row in enumerate(rows_in)) if x]
    if not rows:
        raise Refuse(400, 'no usable rows: each needs a title / item / description')
    no_kind = sum(1 for x in rows if not x['kind'])
    for x in rows:
        if not x['kind']:
            x['kind'] = 'opex'
    c.get('budget_previous', 'current')
    return {'puts': [{'c': 'budget_previous', 'o': {'id': 'current', 'fy': fy, 'rows': rows, 'by': who['user'], 'at': at}}],
            'audit': _audit(who, 'budget.import_previous', 'FY%d' % fy, {'rows': len(rows), 'skipped': len(rows_in) - len(rows), 'no_kind': no_kind}),
            'result': {'imported': len(rows), 'skipped': len(rows_in) - len(rows), 'assumed_opex': no_kind}}


def budget_save_line(r, c):
    who, at = _who(r), r.get('at')
    b = r.get('body') or {}
    st = budget_settings(c, r.get('now'))
    e = b.get('envelope', MISSING)
    key = None if U(e) or e is None else _to_str(e)   # AREAS[x] reads the key String(x): AREAS[['it_ops']] is AREAS.it_ops
    if key in PROTO or (key in AREAS and not isinstance(e, str)):
        raise NodeDecides()
    env = e if isinstance(e, str) and e in AREAS else None
    if not env:
        raise Refuse(400, 'envelope must be it_ops or cyber')
    area = b['area'] if isinstance(b.get('area'), str) and b['area'] in AREAS[env] else AREAS[env][0]
    kind = b.get('kind', MISSING)
    if not (isinstance(kind, str) and kind in KINDS):
        raise Refuse(400, 'kind must be capex or opex')
    title = s(b.get('title', MISSING), 200)
    if u16len(title) < 3:
        raise Refuse(400, 'a title is required')
    am_raw = b.get('amount', MISSING)
    amount = money(am_raw)
    if not U(am_raw) and am_raw is not None and am_raw != '' and amount is None:
        raise Refuse(400, 'amount must be a number')
    bid = b.get('id', MISSING)
    lid = _to_str(bid) if (not U(bid) and truthy(bid) and _to_str(bid).startswith('man:')) else r.get('new_id')
    cur = c.get('budget_lines', lid)
    due = b.get('due', MISSING)
    due_s = _string(_or(due, ''))
    if _DAY.match(due_s) and not isinstance(due, str):
        raise NodeDecides()   # String(['2026-01-01']) passes the test and the array would be stored
    cg = lambda k: cur.get(k, MISSING) if cur is not None else MISSING   # noqa: E731
    pr = b.get('priority', MISSING)
    rec = dict(cur or {})
    rec.update({'id': lid, 'fy': st['fy'], 'source': 'manual', 'envelope': env, 'area': area, 'kind': kind, 'title': title, 'amount': amount,
                'basis': 'price needed' if amount is None else 'entered by ' + _to_str(who['user']),
                'reason': s(b.get('justification', MISSING), 500) or 'new requirement', 'priority': pr if isinstance(pr, str) and pr in PRIOS else 'should',
                'due': due if _DAY.match(due_s) else '%s-01-01' % _to_str(st['fy']), 'status': _or(cg('status'), 'proposed'), 'ref': None,
                'created_by': _or(cg('created_by'), who['user']), 'created_at': _or(cg('created_at'), at), 'updated_by': who['user']})
    return {'puts': [{'c': 'budget_lines', 'o': rec}], 'result': {},
            'audit': _audit(who, 'budget.line_update' if cur is not None else 'budget.line_add', lid, {'title': title, 'envelope': env, 'kind': kind, 'amount': amount})}


def budget_remove(r, c):
    who = _who(r)
    cur = c.get('budget_lines', _string(_or(r.get('id', MISSING), '')))
    if cur is None or cur.get('source', MISSING) != 'manual':
        raise Refuse(400, 'only a requirement added by hand can be deleted - reject a generated line instead')
    return {'puts': [], 'removes': [{'c': 'budget_lines', 'id': cur['id']}], 'result': {},
            'audit': _audit(who, 'budget.line_delete', cur['id'], {'title': cur.get('title', MISSING), 'amount': cur.get('amount', MISSING)})}


def budget_put_settings(r, c):
    who, at = _who(r), r.get('at')
    b = r.get('body') or {}
    v = budget_settings(c, r.get('now'))
    if 'fy' in b:
        fy = number(b['fy'])
        if not is_int(fy) or fy < 2000 or fy > 2100:
            raise Refuse(400, 'fy must be a year')
        v['fy'] = int(fy)
    if 'currency' in b:
        cu = s(b['currency'], 8).upper()
        if not re.match(r'^[A-Z]{3}\Z', cu):
            raise Refuse(400, 'currency must be a 3-letter code')
        v['currency'] = cu
    for grp in ('envelopes', 'unit_costs'):
        x = b.get(grp, MISSING)
        if U(x) or not truthy(x):
            continue
        if not isinstance(x, (dict, list)):
            raise NodeDecides()   # 'k' in 'a string' throws in Node.js
        if isinstance(x, list):
            continue
        keys = list(AREAS) if grp == 'envelopes' else list(DEFAULTS['unit_costs'])
        for k in keys:
            if k not in x:
                continue
            raw = x[k]
            if grp == 'envelopes':
                n = money(raw)
                if n is None:
                    raise Refuse(400, 'envelope %s must be a number' % k)
            else:
                n = None if raw == '' or raw is None else money(raw)
                if raw != '' and raw is not None and n is None:
                    raise Refuse(400, 'standard cost %s must be a number' % k)
            v[grp][k] = n
    for k, lo, hi in (('support_pct', 0, 100), ('inflation_pct', -50, 100), ('storage_target_pct', 30, 95), ('storage_warn_pct', 50, 100)):
        if k not in b:
            continue
        if b[k] == '' or b[k] is None:
            if k == 'support_pct':
                v[k] = None
                continue
            raise Refuse(400, '%s is required' % k)
        n = number(b[k])
        if n is None or n < lo or n > hi:
            raise Refuse(400, '%s must be %d-%d' % (k, lo, hi))
        v[k] = n
    return {'puts': [{'c': 'budget_settings', 'o': {'id': 'settings', 'values': v, 'updated_by': who['user'], 'updated_at': at}}], 'result': {},
            'audit': _audit(who, 'budget.settings', 'settings', v)}


def _guard(fn):
    def run(r):
        try:
            c = _Ctx(r)
        except Exception:
            return {'ok': False, 'error_class': 'protocol', 'error': 'store not readable'}
        try:
            out = fn(r, c)
        except Refuse as e:
            out = {'refuse': {'status': e.status, 'error': e.error}}
        except NodeDecides:
            return {'node': True}
        out['based_on'] = c.based
        return out
    return run


OPS = {'desk.config': _guard(desk_set_config), 'desk.patch_request': _guard(desk_request_patch), 'desk.patch_endorse': _guard(desk_endorse_patch),
       'budget.import': _guard(budget_import), 'budget.line': _guard(budget_save_line), 'budget.remove': _guard(budget_remove), 'budget.settings': _guard(budget_put_settings)}
