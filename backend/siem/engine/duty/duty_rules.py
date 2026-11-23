# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
"""AI engineers' duty desk - the rules in Python (migration step 7, docs/PYTHON-MIGRATION.md in sentra-itam).
The SAME file sits next to duty-core.js in the SIEM (engine/duty/duty_rules.py) and in IT Asset Management
(engine/duty_rules.py); a test fails if the two copies differ. Each operation answers exactly like its Node.js twin in
duty-core.js, from the inputs Node.js read; nothing is read or written here and no engineer is called from here.
  duty.plan       planPatrol()     the patrol's open / update / re-open / clear and the snoozes that ran out
  duty.list       listCore()       the work-item list (filter, order, slim)
  duty.engineers  engineersCore()  the engineers' cards
  duty.kpis       kpisCore()       an engineer's KPIs
  duty.report     reportCore()     the shift handover
and the human WRITES (step 9i), decided on the record Node.js holds and passes in ("held"); Node.js commits the answer
only if that record did not change meanwhile, otherwise it decides itself:
  duty.assign / duty.note / duty.snooze / duty.close   assign() / note() / snooze() / close()   → {result: item, audit?}
  duty.policy                                           setPolicy()                              → {result, put, audit}
  a refusal is {refuse: {status, error}}; what is not read exactly like JavaScript is {node: true}
Run as:  python3 -I duty_rules.py   with ONE JSON request on stdin ({"op": ..., ...}), ONE JSON answer on stdout.
Standard library only (Python 3.8+).
"""
import functools
import json
import math
import re
import sys
from datetime import datetime, timedelta, timezone

U = object()   # JavaScript's undefined (a key that is not there)
SEV = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
TERMINAL = ('resolved', 'closed')
SLA_H = {'critical': 24, 'high': 72, 'medium': 168, 'low': 720}
DAY = 86400000
_CTRL = re.compile('[\u0000-\u0008\u000b-\u001f]')
_HUMAN_NOT = re.compile(r'^(system|core)[:-]')


# ---- JavaScript semantics the rules depend on ---------------------------------------------------------------------
def g(o, k):
    return o.get(k, U) if isinstance(o, dict) else U


def T(v):
    """truthiness: undefined, null, false, 0, NaN and '' are false; an empty object or list is true"""
    if v is U or v is None or v is False or v == '':
        return False
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        return v != 0 and v == v
    return True


def orv(*a):
    """a || b || ... || last"""
    for v in a[:-1]:
        if T(v):
            return v
    return a[-1]


def js_str(v):
    """String(v)"""
    if v is U:
        return 'undefined'
    if v is None:
        return 'null'
    if isinstance(v, bool):
        return 'true' if v else 'false'
    if isinstance(v, float):
        if v != v:
            return 'NaN'
        if math.isinf(v):
            return 'Infinity' if v > 0 else '-Infinity'
        if v.is_integer() and abs(v) < 1e21:
            return str(int(v))
        return repr(v)
    if isinstance(v, list):
        return ','.join('' if x is None or x is U else js_str(x) for x in v)
    if isinstance(v, dict):
        return '[object Object]'
    return str(v)


_NUM = re.compile(r'^[+-]?(\d+\.?\d*|\.\d+)([eE][+-]?\d+)?$')


def num(v):
    """Number(v) (NaN as float('nan'))"""
    if v is U:
        return float('nan')
    if v is None:
        return 0
    if isinstance(v, bool):
        return 1 if v else 0
    if isinstance(v, (int, float)):
        return v
    if isinstance(v, (list, dict)):
        if isinstance(v, list) and len(v) <= 1:
            return num(v[0]) if v and not isinstance(v[0], (list, dict)) else (0 if not v else float('nan'))
        return float('nan')
    s = str(v).strip()
    if s == '':
        return 0
    if _NUM.match(s):
        return float(s)
    m = re.match(r'^0([xob])([0-9a-f]+)$', s, re.I)
    if m:
        try:
            return int(m.group(2), {'x': 16, 'o': 8, 'b': 2}[m.group(1).lower()])
        except ValueError:
            return float('nan')
    if re.match(r'^[+-]?Infinity$', s):
        return float('-inf') if s[0] == '-' else float('inf')
    return float('nan')


def n0(v):
    """(v || 0) as a number"""
    return num(v) if T(v) else 0


def js_round(x):
    """Math.round(x)"""
    return x if isinstance(x, float) and (x != x or math.isinf(x)) else math.floor(x + 0.5)


def clip(s, n):
    """clip() of duty-core.js: control characters out, then the first n UTF-16 code units"""
    if s is None or s is U:
        return ''
    t = _CTRL.sub('', js_str(s))
    if len(t) <= n // 2 or all(ord(c) < 0x10000 for c in t):
        return t[:n]
    b = t.encode('utf-16-le', 'surrogatepass')[:2 * n]
    return b.decode('utf-16-le', 'surrogatepass')


def stringify(x):
    """JSON.stringify(x) for a value that is not a string"""
    if x is U:
        return U
    return json.dumps(clean(x), ensure_ascii=False, separators=(',', ':'), allow_nan=False)


def clean(v):
    """drop the undefined values, as JSON.stringify does"""
    if isinstance(v, dict):
        return {k: clean(x) for k, x in v.items() if x is not U}
    if isinstance(v, list):
        return [None if x is U else clean(x) for x in v]
    return v


def cmp_sort(a, fn):
    """Array.prototype.sort with a comparator (stable in both engines)"""
    def k(x, y):
        r = fn(x, y)
        return -1 if r < 0 else 1 if r > 0 else 0
    return sorted(a, key=functools.cmp_to_key(k))


def sev_of(s):
    return SEV.get(js_str(s), 0)


def hist_of(x):
    h = g(x, 'history')
    return h if isinstance(h, list) else []


def term(x):
    return g(x, 'status') in TERMINAL


def riyadh_day(t):
    return (datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(milliseconds=t + 3 * 3600000)).strftime('%Y-%m-%d')


# ---- planPatrol ----------------------------------------------------------------------------------------------------
def from_finding(f):
    t = g(f, 'target')

    def tg(k):
        return g(t, k) if T(t) else t
    ev = g(f, 'evidence')
    ev = ev if T(ev) else []
    evl = ev if isinstance(ev, list) else [ev]
    o = {
        # SEV[x] turns x into text, as JavaScript does
        'severity': f['severity'] if js_str(g(f, 'severity')) in SEV else 'medium', 'kind': clip(g(f, 'kind'), 60), 'title': clip(g(f, 'title'), 240),
        'evidence': [clip(x if isinstance(x, str) else stringify(x), 400) for x in evl][:8],
        'recommendation': clip(g(f, 'recommendation'), 2000), 'site': clip(g(f, 'site'), 80),
        'target': {'type': clip(tg('type'), 30), 'id': clip(tg('id'), 120), 'name': clip(tg('name'), 160)},
    }
    if T(g(f, 'title_ar')):   # Arabic from the PDPL consultant's rules; other engineers' items are unchanged
        o.update({'title_ar': clip(g(f, 'title_ar'), 240), 'recommendation_ar': clip(g(f, 'recommendation_ar'), 2000)})
    return o


def plan_patrol(inp):
    t0, P = inp.get('now'), inp.get('policy') or {}
    findings = inp.get('findings')
    live = isinstance(findings, list)
    n = inp.get('counter') or 0
    touched, out = {}, {'opened': 0, 'reopened': 0, 'updated': 0, 'cleared': 0}

    def save(it):
        it['updated'] = t0
        touched.setdefault(it['id'], it)

    def hist(it, by, action, note):
        it['history'] = (hist_of(it) + [{'at': t0, 'by': orv(by, 'duty'), 'action': action, 'note': clip(note, 1000)}])[-100:]

    mine, added = list(inp.get('items') or []), []
    by_key = {}
    if live:
        for f in findings:
            if T(f) and T(g(f, 'key')):
                by_key[js_str(f['key'])] = f
    active, recent = {}, {}
    for it in mine:
        k = g(it, 'key')
        if not term(it):
            active[k] = it
        else:
            prev = recent.get(k)
            if prev is None or n0(g(it, 'resolved_at')) > n0(g(prev, 'resolved_at')):
                recent[k] = it
    if live:
        for key, f in by_key.items():
            v = from_finding(f)
            it = active.get(key)
            if it is not None:
                worse = sev_of(v['severity']) > sev_of(g(it, 'severity'))
                it.update({'last_seen': t0, 'seen_count': n0(g(it, 'seen_count')) + 1, 'evidence': v['evidence'], 'title': v['title'],
                           'recommendation': orv(v['recommendation'], g(it, 'recommendation'))})
                if 'title_ar' in v:
                    it.update({'title_ar': v['title_ar'], 'recommendation_ar': v['recommendation_ar']})
                if worse:
                    hist(it, 'duty', 'escalated', '%s → %s' % (js_str(g(it, 'severity')), v['severity']))
                    it['severity'] = v['severity']
                save(it)
                out['updated'] += 1
                continue
            old = recent.get(key)
            if old is not None and g(old, 'status') == 'closed' and T(g(old, 'suppress_until')) and num(old['suppress_until']) > t0:
                old['last_seen'] = t0
                old['suppressed_seen'] = n0(g(old, 'suppressed_seen')) + 1
                save(old)
                continue
            if old is not None and (t0 - n0(g(old, 'resolved_at'))) <= num(g(P, 'reopen_window_days')) * DAY and not (g(old, 'status') == 'closed' and g(old, 'close_code') == 'duplicate'):
                cc = g(old, 'close_code')
                old.update(v)
                old.update({'status': 'open', 'last_seen': t0, 'seen_count': n0(g(old, 'seen_count')) + 1, 'reopened': n0(g(old, 'reopened')) + 1,
                            'resolved_at': None, 'resolution': None, 'investigation': None, 'verify_at': 0})
                hist(old, 'duty', 'reopened', 'the problem came back after it was ' + ('closed (' + js_str(cc) + ')' if T(cc) else 'resolved'))
                save(old)
                out['reopened'] += 1
                continue
            n += 1
            it = {'id': 'DW-' + str(n).rjust(6, '0'), 'engineer': inp.get('engineer', U), 'engineer_name': inp.get('engineer_name', U), 'key': key, 'status': 'open',
                  'first_seen': t0, 'last_seen': t0, 'seen_count': 1, 'detected_at': t0, 'investigation': None, 'ai': None, 'changes': [], 'ticket': None,
                  'owner': '', 'reopened': 0, 'history': []}
            it.update(v)
            hist(it, 'duty', 'opened', v['title'])
            save(it)
            added.append(it)
            out['opened'] += 1
        for key, it in active.items():
            if key in by_key:
                continue
            fixed = g(it, 'status') == 'fix-applied'
            it['status'] = 'resolved'
            it['resolved_at'] = t0
            it['resolution'] = 'verified-fixed' if fixed else 'cleared'
            hist(it, 'duty', it['resolution'], 'no longer detected after the change was applied' if fixed else 'no longer detected at the patrol')
            save(it)
            out['cleared'] += 1
    for it in mine + added:
        if not (g(it, 'status') == 'snoozed' and T(g(it, 'snooze_until')) and num(it['snooze_until']) <= t0):
            continue
        it['status'] = 'diagnosed' if T(g(it, 'investigation')) else 'open'
        hist(it, 'duty', 'snooze-ended', '')
        save(it)
    return {'puts': list(touched.values()), 'counter': n, 'out': out}


# ---- listCore ------------------------------------------------------------------------------------------------------
def _slice_end(v):
    """the end argument of Array.prototype.slice: ToIntegerOrInfinity"""
    if v != v:
        return 0
    if math.isinf(v):
        return None if v > 0 else 0
    return int(v)


def list_core(inp):
    f = inp.get('filter') or {}
    all_ = [x for x in (inp.get('items') or []) if not T(g(f, 'engineer')) or g(x, 'engineer') == f['engineer']]
    st = g(f, 'status')
    if st == 'open':
        all_ = [x for x in all_ if not term(x)]
    elif T(st):
        all_ = [x for x in all_ if g(x, 'status') == st]
    if T(g(f, 'since')):
        since = num(f['since'])
        all_ = [x for x in all_ if n0(g(x, 'updated')) >= since]
    all_ = cmp_sort(all_, lambda a, b: (int(term(a)) - int(term(b))) or (sev_of(g(b, 'severity')) - sev_of(g(a, 'severity'))) or (n0(g(b, 'last_seen')) - n0(g(a, 'last_seen'))))
    lim0 = num(g(f, 'limit'))
    lim = min(lim0 if T(lim0) else 300, 1000)

    def slim(x):
        o = {k: v for k, v in x.items() if k != 'history'}
        ai = g(o, 'ai')
        if T(ai):
            o['ai'] = {'at': g(ai, 'at'), 'error': g(ai, 'error'), 'proposed': g(ai, 'proposed'), 'steps': g(ai, 'steps')}
        return o
    return {'items': [slim(x) for x in all_[:_slice_end(lim)]], 'total': len(all_)}


# ---- engineersCore -------------------------------------------------------------------------------------------------
def engineers_core(inp):
    P, t, all_ = inp.get('policy') or {}, inp.get('now'), inp.get('items') or []
    res = []
    for e in inp.get('engineers') or []:
        st = g(e, 'st')
        st = st if T(st) else {}
        mine = [x for x in all_ if g(x, 'engineer') == g(e, 'id')]
        opn = [x for x in mine if not term(x)]
        by = {}
        for x in opn:
            k = js_str(g(x, 'status'))
            by[k] = by.get(k, 0) + 1
        s = g(e, 'ai')
        late = T(g(P, 'enabled')) and T(g(st, 'last_patrol')) and t - num(st['last_patrol']) > 3 * num(g(P, 'patrol_min')) * 60000
        lr = g(st, 'last_result')
        res.append({'id': g(e, 'id'), 'name': g(e, 'name'), 'on_duty': g(P, 'enabled'), 'last_patrol': orv(g(st, 'last_patrol'), None), 'last_ms': orv(g(st, 'last_ms'), None),
                    'patrols': orv(g(st, 'patrols'), 0), 'late': bool(late), 'last_error': orv(g(st, 'last_error'), None), 'last_error_at': orv(g(st, 'last_error_at'), None),
                    'not_connected': bool(T(lr) and T(g(lr, 'not_connected'))), 'open': len(opn), 'by_status': by,
                    'critical': len([x for x in opn if g(x, 'severity') == 'critical']), 'high': len([x for x in opn if g(x, 'severity') == 'high']),
                    'resolved_24h': len([x for x in mine if term(x) and t - n0(g(x, 'resolved_at')) < DAY]),
                    'ai': {'enabled': T(g(s, 'enabled')), 'off': T(g(s, 'off')), 'reason': orv(g(s, 'reason'), ''), 'used_today': g(e, 'used_today'), 'cap': g(P, 'ai_daily_cap')} if T(s) else None})
    return {'engineers': res}


# ---- kpisCore ------------------------------------------------------------------------------------------------------
def human(by):
    return T(by) and by != 'duty' and not _HUMAN_NOT.search(js_str(by))


def median(a):
    if not a:
        return None
    s = cmp_sort(a, lambda x, y: x - y)
    m = len(s) >> 1
    return s[m] if len(s) % 2 else (s[m - 1] + s[m]) / 2


def r1(v):
    return None if v is None else js_round(v * 10) / 10


def kpis_core(inp):
    eng_id, t = inp.get('engineer', U), inp.get('now')
    d0 = num(inp.get('days', U))
    days = min(90, max(1, js_round(d0 if T(d0) else 30)))
    since = t - days * DAY
    P, TG = inp.get('policy') or {}, inp.get('targets') or {}
    st = inp.get('st')
    st = st if T(st) else {}
    mine = inp.get('items') or []
    opn = [x for x in mine if not term(x)]
    resolved = [x for x in mine if term(x) and n0(g(x, 'resolved_at')) >= since]
    H = hist_of

    def det(x):
        return num(orv(g(x, 'detected_at'), g(x, 'first_seen')))
    serious = [x for x in opn if sev_of(g(x, 'severity')) >= 3 and g(x, 'status') != 'snoozed']
    sla_res = [x for x in resolved if sev_of(g(x, 'severity')) >= 3 and g(x, 'resolution') != 'closed:duplicate']
    sla_open_late = [x for x in serious if t - det(x) > SLA_H[js_str(x['severity'])] * 3600000]
    sla_ok = len([x for x in sla_res if (num(g(x, 'resolved_at')) - det(x)) <= SLA_H[js_str(x['severity'])] * 3600000])
    sla_n = len(sla_res) + len(sla_open_late)
    opened = [x for x in mine if n0(g(x, 'detected_at')) >= since]
    diag = []
    for x in opened:
        h = next((e for e in H(x) if g(e, 'action') == 'diagnosed'), None)
        if h is not None:
            diag.append((num(g(h, 'at')) - num(g(x, 'detected_at'))) / 60000)
    hum = []
    for x in opened:
        if sev_of(g(x, 'severity')) < 3:
            continue
        dx = num(g(x, 'detected_at'))
        h = next((e for e in H(x) if human(g(e, 'by')) and num(g(e, 'at')) >= dx), None)
        if h is not None:
            hum.append((num(g(h, 'at')) - dx) / 3600000)
            continue
        age = (t - dx) / 3600000
        if not term(x) and age > num(g(TG, 'human_h')):
            hum.append(age)
    appr, waiting = [], []
    for x in mine:
        h = H(x)
        for i, e in enumerate(h):
            if g(e, 'action') != 'fix-proposed':
                continue
            d = next((m for m in h[i + 1:] if g(m, 'action') in ('approved', 'fix-applied', 'needs-human', 'verified-fixed')), None)
            if d is not None:
                if num(g(d, 'at')) >= since:
                    appr.append((num(g(d, 'at')) - num(g(e, 'at'))) / 3600000)
            elif g(x, 'status') == 'awaiting-approval':
                waiting.append((t - num(g(e, 'at'))) / 3600000)
    fixed = [x for x in resolved if g(x, 'resolution') in ('verified-fixed', 'closed:fixed')]
    still_there = sum(len([e for e in H(x) if g(e, 'action') == 'still-present' and num(g(e, 'at')) >= since]) for x in mine)
    vfix = len([x for x in resolved if g(x, 'resolution') == 'verified-fixed'])
    reopened = len([x for x in mine if any(g(e, 'action') == 'reopened' and num(g(e, 'at')) >= since for e in H(x))])
    late = bool(T(g(P, 'enabled')) and T(g(st, 'last_patrol')) and t - num(st['last_patrol']) > 3 * num(g(P, 'patrol_min')) * 60000)
    patrol_pct = max(0, 100 - n0(g(st, 'errors')) / num(st['patrols']) * 100) if T(g(st, 'patrols')) else None
    lr = g(st, 'last_result')
    not_conn = bool(T(lr) and T(g(lr, 'not_connected')))

    def K(id_, label, value, unit, dir_, detail, measured=U):
        if measured is U:
            measured = value is not None
        target = g(TG, id_)
        status = 'na'
        if T(measured) and value is not None:
            if dir_ == 'max':
                status = 'ok' if value <= num(target) else 'warn' if T(target) and value <= num(target) * 1.5 else 'bad'
            else:
                status = 'ok' if value >= num(target) else 'warn' if value >= num(target) * 0.85 else 'bad'
        return {'id': id_, 'label': label, 'value': r1(value) if T(measured) else None, 'unit': unit, 'target': target, 'dir': dir_, 'status': status, 'detail': detail}

    S = js_str
    lst = [
        K('open_serious', 'Open critical / high problems', len(serious), '', 'max', '%d open in all; %d serious and unassigned' % (len(opn), len([x for x in serious if not T(g(x, 'owner'))])),
          (T(g(st, 'patrols')) and not not_conn) or len(serious) > 0),
        K('sla_pct', 'Resolved within SLA (critical 24 h, high 72 h)', sla_ok / sla_n * 100 if sla_n else None, '%', 'min',
          '%d of %d on time' % (sla_ok, sla_n) + ('; %d open and already late' % len(sla_open_late) if sla_open_late else '')),
        K('diag_min', 'Time to diagnosis (automatic, median)', median(diag), 'min', 'max', '%d problems diagnosed' % len(diag)),
        K('human_h', 'First response by a person (serious, median)', median(hum), 'h', 'max', '%d serious problems; counts assignment, notes, snooze, close by a named person' % len(hum)),
        K('approval_h', 'Human approval time for proposed fixes (median)', median(appr), 'h', 'max',
          '%d decided in the window; %d waiting now' % (len(appr), len(waiting)) + (', oldest %s h' % S(r1(max(waiting))) if waiting else '')),
        K('fix_h', 'Time to fix (median, detected → fixed)', median([(num(g(x, 'resolved_at')) - det(x)) / 3600000 for x in fixed]), 'h', 'max',
          '%d fixed (%d verified by a re-check)' % (len(fixed), vfix)),
        K('fix_success_pct', 'Applied fixes that held on re-check', vfix / (vfix + still_there) * 100 if (vfix + still_there) else None, '%', 'min',
          '%d verified, %d still present after the change' % (vfix, still_there)),
        K('reopen_pct', 'Problems that came back', reopened / len(resolved) * 100 if resolved else None, '%', 'max', '%d came back of %d resolved' % (reopened, len(resolved))),
        K('patrol_pct', 'Patrols without errors', 0 if late else patrol_pct, '%', 'min',
          ('patrol is LATE (no patrol in ' + S(3 * num(g(P, 'patrol_min'))) + ' min)') if late else
          '%s patrols, %s with errors' % (S(orv(g(st, 'patrols'), 0)), S(orv(g(st, 'errors'), 0))) + (' - source not connected' if not_conn else ''),
          late or patrol_pct is not None),
    ]
    domain = inp.get('domain')
    if not T(domain):
        by = {}
        for x in opn:
            k = js_str(orv(g(x, 'kind'), 'other'))
            by[k] = by.get(k, 0) + 1
        domain = [{'label': 'Open: ' + k, 'value': c, 'unit': '', 'target': 0, 'dir': 'max', 'status': 'bad' if c else 'ok'}
                  for k, c in cmp_sort(list(by.items()), lambda a, b: b[1] - a[1])[:8]]
    scored = [] if not_conn else [k for k in lst if k['status'] != 'na']
    score = js_round(sum(100 if k['status'] == 'ok' else 60 if k['status'] == 'warn' else 0 for k in scored) / len(scored)) if scored else None
    return {'engineer': eng_id, 'name': inp.get('name', U), 'days': days, 'at': t, 'not_connected': not_conn, 'score': score, 'measured': len(scored), 'kpis': lst,
            'domain': domain, 'counts': {'opened': len(opened), 'resolved': len(resolved), 'verified_fixed': vfix, 'open': len(opn), 'awaiting_approval': len(waiting)}}


# ---- reportCore ----------------------------------------------------------------------------------------------------
def report_core(inp):
    t = inp.get('now')
    since = inp.get('since') if T(inp.get('since')) else t - DAY
    eng_id, name = inp.get('engineer', U), inp.get('name', U)
    mine = inp.get('items') or []
    opn = [x for x in mine if not term(x)]
    st = inp.get('st')
    st = st if T(st) else {}

    def in_win(x, k):
        return n0(g(x, k)) >= since

    def ev(x, a):
        return any(g(h, 'action') == a and num(g(h, 'at')) >= since for h in hist_of(x))

    def top(arr):
        out = []
        for x in cmp_sort(arr, lambda a, b: sev_of(g(b, 'severity')) - sev_of(g(a, 'severity')))[:15]:
            tg = g(x, 'target')
            out.append({'id': g(x, 'id'), 'severity': g(x, 'severity'), 'title': g(x, 'title'), 'status': g(x, 'status'), 'target': g(tg, 'name') if T(tg) else tg,
                        'owner': g(x, 'owner'), 'changes': g(x, 'changes')})
        return out
    day = riyadh_day(t)
    c = {
        'opened': len([x for x in mine if in_win(x, 'detected_at')]), 'reopened': len([x for x in mine if ev(x, 'reopened')]),
        'cleared': len([x for x in mine if g(x, 'resolution') == 'cleared' and in_win(x, 'resolved_at')]),
        'verified_fixed': len([x for x in mine if g(x, 'resolution') == 'verified-fixed' and in_win(x, 'resolved_at')]),
        'closed': len([x for x in mine if g(x, 'status') == 'closed' and in_win(x, 'resolved_at')]),
        'ai_investigations': len([x for x in mine if T(g(x, 'ai')) and n0(g(x['ai'], 'at')) >= since]),
        'open': len(opn), 'critical_open': len([x for x in opn if g(x, 'severity') == 'critical']),
    }
    r = {'id': 'R-' + js_str(eng_id) + '-' + day + '-' + js_str(t), 'engineer': eng_id, 'engineer_name': name, 'at': t, 'since': since, 'day': day, 'counts': c,
         'awaiting_approval': top([x for x in opn if g(x, 'status') == 'awaiting-approval']),
         'approved_not_applied': top([x for x in opn if g(x, 'status') == 'approved']),
         'needs_human': top([x for x in opn if g(x, 'status') in ('needs-human', 'diagnosed')]),
         'still_unassigned': len([x for x in opn if not T(g(x, 'owner')) and sev_of(g(x, 'severity')) >= 3]),
         'patrols': {'last': orv(g(st, 'last_patrol'), None), 'total': orv(g(st, 'patrols'), 0), 'last_error': orv(g(st, 'last_error'), None)}}
    S = js_str
    lines = [
        '%s - shift handover %s' % (S(name), day),
        'New %d, came back %d; resolved %d (%d verified after a change, %d cleared, %d closed by a person).' % (c['opened'], c['reopened'], c['cleared'] + c['verified_fixed'] + c['closed'], c['verified_fixed'], c['cleared'], c['closed']),
        'Open now: %d (%d critical). Waiting for approval: %d. Approved, not yet applied: %d. Needs a person: %d. Serious and unassigned: %d.' % (
            c['open'], c['critical_open'], len(r['awaiting_approval']), len(r['approved_not_applied']), len(r['needs_human']), r['still_unassigned']),
        ('Last patrol problem: ' + S(st['last_error'])) if T(g(st, 'last_error')) else 'Patrols ran without errors.',
    ]
    r['summary'] = '\n'.join(lines)
    return r


# ---- the human writes (step 9i) ------------------------------------------------------------------------------------
JS_WS = '\t\n\x0b\x0c\r \u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000\ufeff'
CLOSE_CODES = ['fixed', 'accepted-risk', 'false-positive', 'duplicate']
PROTO = {'constructor', '__proto__', 'hasOwnProperty', 'isPrototypeOf', 'propertyIsEnumerable', 'toLocaleString', 'toString', 'valueOf',
         '__defineGetter__', '__defineSetter__', '__lookupGetter__', '__lookupSetter__'}
_INT_KEY = re.compile(r'^(0|[1-9][0-9]*)$')


class Refuse(Exception):
    def __init__(self, status, error):
        super().__init__(error)
        self.status, self.error = status, error


class NodeDecides(Exception):
    pass


def finite(v):
    return isinstance(v, (int, float)) and not isinstance(v, bool) and v == v and not math.isinf(v)


def round_exact(x):
    """Math.round(x), exactly (floor(x + 0.5) is off for 0.49999999999999994)"""
    f = math.floor(x)
    return f + 1 if x - f >= 0.5 else f


def _canon(v):
    if isinstance(v, bool) or v is None or isinstance(v, str):
        return v
    if isinstance(v, float) and v.is_integer() and abs(v) < 1e21:
        return int(v)
    if isinstance(v, dict):
        return {k: _canon(x) for k, x in v.items() if x is not U}
    if isinstance(v, list):
        return [None if x is U else _canon(x) for x in v]
    return v


def same_json(a, b):
    """JSON.stringify(a) === JSON.stringify(b) (integral floats print as integers in JavaScript)"""
    if a is U or b is U:
        return a is b
    return json.dumps(_canon(a), ensure_ascii=False, separators=(',', ':')) == json.dumps(_canon(b), ensure_ascii=False, separators=(',', ':'))


def _held(r):
    it = r.get('held')
    if it is None:
        raise Refuse(404, 'work item not found')
    h = g(it, 'history')
    if h is not U and h is not None and not isinstance(h, list) and T(h):
        raise NodeDecides()   # (it.history || []).concat(...) of a string / object
    return dict(it)


def _hist(it, by, now, action, note):
    it['history'] = (hist_of(it) + [{'at': now, 'by': orv(by, 'duty'), 'action': action, 'note': clip(note, 1000)}])[-100:]


def w_assign(r):
    by, now = g(r, 'by'), r.get('now')
    it = _held(r)
    it['owner'] = orv(clip(g(r, 'owner'), 120), by, '')
    _hist(it, by, now, 'assigned', it['owner'])
    it['updated'] = now
    return {'result': it, 'audit': ['duty.assign', r.get('id'), {'by': by, 'owner': it['owner']}]}


def w_note(r):
    by, now = g(r, 'by'), r.get('now')
    txt = clip(g(r, 'text'), 2000).strip(JS_WS)
    if not txt:
        raise Refuse(400, 'a note is required')
    it = _held(r)
    _hist(it, by, now, 'note', txt)
    it['updated'] = now
    return {'result': it}


def w_snooze(r):
    by, now = g(r, 'by'), r.get('now')
    h, rs = num(g(r, 'hours')), clip(g(r, 'reason'), 500).strip(JS_WS)
    if not finite(h) or h < 1 or h > 720:
        raise Refuse(400, 'snooze for 1-720 hours')
    if not rs:
        raise Refuse(400, 'a reason is required')
    it = _held(r)
    if term(it):
        raise Refuse(409, 'this work item is ' + js_str(g(it, 'status')))
    it['status'] = 'snoozed'
    it['snooze_until'] = now + h * 3600000
    it['snooze_reason'] = rs
    _hist(it, by, now, 'snoozed', '%s h: %s' % (js_str(h), rs))
    it['updated'] = now
    return {'result': it, 'audit': ['duty.snooze', r.get('id'), {'by': by, 'hours': h}]}


def w_close(r):
    by, now = g(r, 'by'), r.get('now')
    code = g(r, 'code')
    key = None if code is U or code is None else js_str(code)   # CLOSE_CODES[code] reads the key String(code)
    if key in PROTO or (key in CLOSE_CODES and not isinstance(code, str)):
        raise NodeDecides()
    if key not in CLOSE_CODES:
        raise Refuse(400, 'close code must be one of: ' + ', '.join(CLOSE_CODES))
    rs = clip(g(r, 'reason'), 1000).strip(JS_WS)
    if not rs:
        raise Refuse(400, 'a reason is required')
    it = _held(r)
    if term(it):
        raise Refuse(409, 'this work item is already ' + js_str(g(it, 'status')))
    it.update({'status': 'closed', 'close_code': code, 'resolved_at': now, 'resolution': 'closed:' + code, 'closed_by': orv(by, '')})
    if code in ('accepted-risk', 'false-positive'):
        it['suppress_until'] = now + 30 * DAY
    _hist(it, by, now, 'closed', code + ': ' + rs)
    it['updated'] = now
    return {'result': it, 'audit': ['duty.close', r.get('id'), {'by': by, 'code': code}]}


def w_policy(r):
    by, now = g(r, 'by'), r.get('now')
    inp = r.get('input') if isinstance(r.get('input'), dict) else {}
    cur, engs, kpis = r.get('cur') or {}, set(r.get('engineers') or []), set(r.get('kpi_keys') or [])
    if any(_INT_KEY.match(k) for k in inp):
        raise NodeDecides()   # Object.keys() puts integer-like keys first
    out = dict(cur)
    if 'enabled' in inp:
        out['enabled'] = T(inp['enabled'])
    for k, lo, hi in (('patrol_min', 2, 1440), ('max_investigations', 0, 50), ('ai_daily_cap', 0, 200), ('report_hour', 0, 23), ('reopen_window_days', 0, 90), ('verify_every_min', 5, 1440)):
        if k in inp:
            v = num(inp[k])
            if not finite(v) or v < lo or v > hi:
                raise Refuse(400, '%s must be %d-%d' % (k, lo, hi))
            out[k] = round_exact(v)
    if 'ai_off' in inp:
        lst = inp['ai_off']
        if not isinstance(lst, list):
            raise Refuse(400, 'ai_off must be a list of engineer ids')
        keys = [js_str(x) for x in lst]
        if any(k in PROTO for k in keys):
            raise NodeDecides()
        unknown = [x for x, k in zip(lst, keys) if k not in engs]
        if unknown:
            raise Refuse(400, 'unknown engineer: ' + ', '.join('' if x is None else js_str(x) for x in unknown))
        out['ai_off'] = list(dict.fromkeys(keys))
    if 'kpi_targets' in inp:
        kt = inp['kpi_targets']
        if not isinstance(kt, dict):
            raise Refuse(400, 'kpi_targets must be { engineer: { kpi: number } }')
        o = {}
        for e, m in kt.items():
            if _INT_KEY.match(e) or e in PROTO:
                raise NodeDecides()
            if e not in engs:
                raise Refuse(400, 'unknown engineer: ' + e)
            if not T(m) or not isinstance(m, (dict, list)):
                raise Refuse(400, 'kpi_targets.' + e + ' must be an object')
            pairs = [(str(i), v) for i, v in enumerate(m)] if isinstance(m, list) else list(m.items())
            if isinstance(m, dict) and any(_INT_KEY.match(k) for k in m):
                raise NodeDecides()
            o[e] = {}
            for k, v in pairs:
                if k in PROTO:
                    raise NodeDecides()   # 'constructor' in KPI_DEFAULTS is true in JavaScript
                if k not in kpis:
                    raise Refuse(400, 'unknown KPI: ' + k)
                if v is None or v == '':
                    continue
                n = num(v)
                if not finite(n) or n < 0 or n > 100000:
                    raise Refuse(400, 'kpi_targets.%s.%s must be 0-100000' % (e, k))
                o[e][k] = n
        out['kpi_targets'] = o
    for k in ('ai_min_severity', 'ticket_min_severity'):
        if k in inp:
            x = inp[k]
            key = None if x is None else js_str(x)
            if key in PROTO or (key in SEV and not isinstance(x, str)):
                raise NodeDecides()   # SEV[x] reads the key String(x)
            if x != 'off' and key not in SEV:
                raise Refuse(400, '%s must be off, low, medium, high or critical' % k)
            out[k] = x
    changed = [k for k in inp if not same_json(cur.get(k, U), out.get(k, U))]
    return {'result': out, 'put': {'id': 'policy', 'value': out, 'by': orv(by, ''), 'at': now}, 'audit': ['duty.policy', 'policy', {'by': by, 'changed': changed}]}


def _write(fn):
    def run(r):
        try:
            return fn(r)
        except Refuse as e:
            return {'refuse': {'status': e.status, 'error': e.error}}
        except NodeDecides:
            return {'node': True}
    return run


OPS = {'duty.plan': plan_patrol, 'duty.list': list_core, 'duty.engineers': engineers_core, 'duty.kpis': kpis_core, 'duty.report': report_core,
       'duty.assign': _write(w_assign), 'duty.note': _write(w_note), 'duty.snooze': _write(w_snooze), 'duty.close': _write(w_close), 'duty.policy': _write(w_policy),
       'ping': lambda r: {'ok': True, 'python': sys.version.split()[0]}}


def main():
    try:
        req = json.loads(sys.stdin.buffer.read().decode('utf-8'))
        fn = OPS.get(req.get('op'))
        ans = fn(req) if fn else {'ok': False, 'error': 'unknown op'}
        data = json.dumps(clean(ans), ensure_ascii=True, allow_nan=False)
    except Exception as e:   # answered, never a traceback on stdout: Node.js then uses its own rules
        data = json.dumps({'ok': False, 'error': '%s: %s' % (type(e).__name__, str(e)[:300])})
    sys.stdout.write(data)


if __name__ == '__main__':
    main()
