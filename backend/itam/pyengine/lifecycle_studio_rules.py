# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
"""Lifecycle Studio rules (engine/lifecycle-studio.js): when each asset should be replaced, renewed or isolated, and what the
next two years of refresh look like - learned from this register, every number explained.

op lifecycle.studio  {assets, retired, eol, uncovered, contracts, relationships, plan, now}
  lifespan   per type: the median age at retirement of assets of that type retired here (purchase or first-seen date ->
             retirement date), when 3 or more are known; otherwise a stated default (server 5 y, network 7 y, ...).
  due        the earliest of: vendor end of life, end of warranty + 1 year (hardware), purchase / first seen + lifespan.
             The driver is named.
  risk       0-100, additive and itemised: past end of life (+40, +15 with an approved exception), end of life in 180 days
             (+20), out of warranty (+15), no support contract covers it (+15), older than its lifespan (+10), other CIs run on
             or depend on it (+4 each, max 20).
  action     isolate / replace / upgrade / renew support / extend warranty / plan / ok - from the drivers, with the reason.
  cost       the median purchase cost of the same model (3+ known), else of the same type (3+ known), else "not known" -
             never a guess.
  forecast   the next 8 quarters (plus overdue): replacements due by type and the known cost; renewals: support contracts
             ending in the next 12 months by month.
"""
import datetime as _dt

ACTIVE = {'in_use', 'in_stock', 'in_repair'}
DEFAULT_LIFE = {'server': 5, 'vm': None, 'network': 7, 'storage': 5, 'workstation': 5, 'laptop': 4, 'printer': 6, 'ups': 6, 'phone': 6,
                'mobile': 3, 'peripheral': 5}
HW = {'server', 'network', 'storage', 'workstation', 'laptop', 'printer', 'ups', 'phone', 'mobile', 'peripheral'}
DAY = 86400.0
YEAR = 365.25 * DAY


def _ts(v):
    if not v:
        return None
    t = str(v)
    try:
        if 'T' in t:
            return (_dt.datetime.strptime(t[:19], '%Y-%m-%dT%H:%M:%S') - _dt.datetime(1970, 1, 1)).total_seconds()
        return (_dt.datetime.strptime(t[:10], '%Y-%m-%d') - _dt.datetime(1970, 1, 1)).total_seconds()
    except ValueError:
        return None


def _date(ts):
    return (_dt.datetime(1970, 1, 1) + _dt.timedelta(seconds=ts)).strftime('%Y-%m-%d')


def quarter(ts):
    d = _dt.datetime(1970, 1, 1) + _dt.timedelta(seconds=ts)
    return '%d-Q%d' % (d.year, (d.month - 1) // 3 + 1)


def yrs(v):
    return ('%.1f' % v).rstrip('0').rstrip('.')


def median(xs):
    xs = sorted(xs)
    n = len(xs)
    if not n:
        return None
    return xs[n // 2] if n % 2 else (xs[n // 2 - 1] + xs[n // 2]) / 2.0


def op_studio(req):
    now = float(req.get('now') or 0) / 1000.0 or (_dt.datetime.utcnow() - _dt.datetime(1970, 1, 1)).total_seconds()
    assets = [a for a in (req.get('assets') or []) if isinstance(a, dict) and a.get('id') and a.get('status', 'in_use') in ACTIVE]
    eol = req.get('eol') or {}                  # asset id -> {status, eol, product, isolation_required, exception}
    uncovered = set(req.get('uncovered') or [])  # asset ids in a support family that no active contract covers
    in_scope = set(req.get('in_scope') or [])
    planned = {}
    for p in req.get('plan') or []:
        if p.get('status') in ('proposed', 'planned'):
            planned.setdefault(p.get('asset_id'), []).append(p)

    # learned lifespan per type from retirements
    ages = {}
    for r in req.get('retired') or []:
        start, end = _ts(r.get('purchase_date') or r.get('first_seen')), _ts(r.get('retired_at'))
        if start and end and end > start:
            ages.setdefault(r.get('type') or 'other', []).append((end - start) / YEAR)
    life = {}
    for t in set(list(DEFAULT_LIFE.keys()) + list(ages.keys())):
        xs = ages.get(t, [])
        if len(xs) >= 3:
            life[t] = {'years': round(median(xs), 1), 'n': len(xs), 'source': 'learned'}
        elif DEFAULT_LIFE.get(t):
            life[t] = {'years': DEFAULT_LIFE[t], 'n': len(xs), 'source': 'default'}

    # cost: median purchase cost by model, then by type
    by_model, by_type = {}, {}
    for a in assets + (req.get('retired') or []):
        c = a.get('cost')
        if isinstance(c, (int, float)) and c > 0:
            if a.get('model'):
                by_model.setdefault((a.get('type'), a.get('model')), []).append(c)
            by_type.setdefault(a.get('type'), []).append(c)

    def cost_of(a):
        m = by_model.get((a.get('type'), a.get('model'))) if a.get('model') else None
        if m and len(m) >= 3:
            return {'value': round(median(m)), 'basis': 'median purchase cost of %d %s %s' % (len(m), a.get('model'), a.get('type'))}
        t = by_type.get(a.get('type'))
        if t and len(t) >= 3:
            return {'value': round(median(t)), 'basis': 'median purchase cost of %d %s asset(s)' % (len(t), a.get('type'))}
        return None

    dependents = {}
    for r in req.get('relationships') or []:
        if r.get('type') in ('runs_on', 'depends_on', 'installed_on'):
            dependents[r.get('to')] = dependents.get(r.get('to'), 0) + 1

    rows = []
    for a in assets:
        t = a.get('type') or 'other'
        e = eol.get(a['id']) or {}
        start = _ts(a.get('purchase_date') or a.get('first_seen'))
        age = round((now - start) / YEAR, 1) if start else None
        we = _ts(a.get('warranty_end'))
        eol_ts = _ts(e.get('eol') or a.get('eol'))
        eol_status = e.get('status') or ('eol' if eol_ts and eol_ts < now else 'soon' if eol_ts and eol_ts - now < 180 * DAY else 'supported' if eol_ts else 'unknown')
        lf = life.get(t)
        drivers = []
        if eol_ts:
            drivers.append((eol_ts, 'vendor end of life%s' % (' (' + e['product'] + ')' if e.get('product') else '')))
        elif eol_status == 'eol':
            drivers.append((now, 'vendor end of life passed%s' % (' (' + e['product'] + ')' if e.get('product') else '')))
        if we and t in HW:
            drivers.append((we + YEAR, 'one year after the warranty ended (%s)' % _date(we)))
        if start and lf:
            drivers.append((start + lf['years'] * YEAR, '%s years of life from %s (%s for %s)' % (yrs(lf['years']), 'purchase' if a.get('purchase_date') else 'first seen - no purchase date recorded', lf['source'] + (' from %d retirements' % lf['n'] if lf['source'] == 'learned' else ''), t)))
        due = min(drivers) if drivers else None

        why, risk = [], 0

        def add(p, txt):
            why.append({'points': p, 'text': txt})
            return p
        exc_ok = (e.get('exception') or {}).get('state') == 'approved'
        if eol_status == 'eol':
            risk += add(15 if exc_ok else 40, 'past vendor end of life' + (' - risk exception until ' + str(e['exception'].get('expires')) if exc_ok else ''))
        elif eol_status == 'soon':
            risk += add(20, 'vendor end of life ' + (_date(eol_ts) if eol_ts else 'within 180 days'))
        if we and we < now and t in HW:
            risk += add(15, 'out of warranty since ' + _date(we))
        if a['id'] in uncovered:
            risk += add(15, 'no active support contract covers it')
        if age is not None and lf and age > lf['years']:
            risk += add(10, '%s years old - beyond the %s-year life of a %s' % (yrs(age), yrs(lf['years']), t))
        dep = dependents.get(a['id'], 0)
        if dep:
            risk += add(min(20, 4 * dep), '%d CI(s) run on or depend on it' % dep)
        risk = min(100, risk)

        if e.get('isolation_required'):
            action, reason = 'isolate', 'past end of life and not isolated - isolate until replaced or upgraded'
        elif eol_status == 'eol':
            action, reason = ('upgrade' if t == 'vm' else 'replace'), 'past vendor end of life'
        elif due and due[0] < now:
            action, reason = 'replace', 'due since ' + _date(due[0]) + ': ' + due[1]
        elif eol_status == 'soon':
            action, reason = ('upgrade' if t == 'vm' else 'plan'), 'end of life on ' + (_date(eol_ts) if eol_ts else 'soon') + ' - plan the upgrade / replacement'
        elif a['id'] in uncovered:
            action, reason = 'renew support', 'in scope of a support family but no active contract covers it'
        elif we and we < now and t in HW and (not due or due[0] - now > YEAR):
            action, reason = 'extend warranty', 'out of warranty, more than a year of life left'
        elif due and due[0] - now < 365 * DAY:
            action, reason = 'plan', 'due ' + _date(due[0]) + ': ' + due[1]
        else:
            action, reason = 'ok', ('next milestone ' + _date(due[0]) + ': ' + due[1]) if due else 'no date known - record a purchase date, warranty or end of life'
        rows.append({'id': a['id'], 'name': a.get('name'), 'type': t, 'site': a.get('site') or '', 'model': a.get('model') or '', 'age': age,
                     'purchase_date': a.get('purchase_date'), 'warranty_end': a.get('warranty_end'), 'eol': _date(eol_ts) if eol_ts else None, 'eol_status': eol_status,
                     'product': e.get('product'), 'support': 'uncovered' if a['id'] in uncovered else 'covered' if a['id'] in in_scope else 'n/a',
                     'dependents': dep, 'risk': risk, 'why': why, 'due': _date(due[0]) if due else None, 'due_why': due[1] if due else None,
                     'quarter': ('overdue' if due[0] < now else quarter(due[0])) if due else None, 'action': action, 'reason': reason,
                     'cost': cost_of(a) if action in ('replace', 'plan', 'isolate') else None, 'planned': [{'id': p.get('id'), 'action': p.get('action'), 'quarter': p.get('quarter'), 'status': p.get('status')} for p in planned.get(a['id'], [])]})
    rows.sort(key=lambda r: (-r['risk'], r['due'] or '9999'))

    # forecast: overdue + next 8 quarters
    qs = ['overdue']
    d = _dt.datetime(1970, 1, 1) + _dt.timedelta(seconds=now)
    y, q = d.year, (d.month - 1) // 3 + 1
    for _ in range(8):
        qs.append('%d-Q%d' % (y, q))
        q += 1
        if q > 4:
            q, y = 1, y + 1
    fc = {k: {'quarter': k, 'count': 0, 'by_type': {}, 'cost': 0, 'cost_unknown': 0} for k in qs}
    for r in rows:
        if r['action'] in ('replace', 'plan', 'isolate', 'upgrade') and r['quarter'] in fc:
            f = fc[r['quarter']]
            f['count'] += 1
            f['by_type'][r['type']] = f['by_type'].get(r['type'], 0) + 1
            if r['cost']:
                f['cost'] += r['cost']['value']
            elif r['type'] != 'vm':
                f['cost_unknown'] += 1
    renew = {}
    for c in req.get('contracts') or []:
        end = _ts(c.get('end'))
        if end and now - 31 * DAY < end < now + 365 * DAY and c.get('state') != 'retired':
            m = (_dt.datetime(1970, 1, 1) + _dt.timedelta(seconds=end)).strftime('%Y-%m')
            x = renew.setdefault(m, {'month': m, 'count': 0, 'cost': 0, 'contracts': []})
            x['count'] += 1
            x['cost'] += c.get('cost') or 0
            x['contracts'].append({'id': c.get('id'), 'vendor': c.get('vendor'), 'product': c.get('product'), 'end': c.get('end'), 'cost': c.get('cost')})
    cnt = lambda fn: len([r for r in rows if fn(r)])
    supported = cnt(lambda r: r['eol_status'] in ('supported',) or (r['eol_status'] == 'unknown' and r['type'] == 'vm'))
    return {'ok': True,
            'summary': {'assets': len(rows), 'eol': cnt(lambda r: r['eol_status'] == 'eol'), 'eol_soon': cnt(lambda r: r['eol_status'] == 'soon'),
                        'isolate': cnt(lambda r: r['action'] == 'isolate'), 'out_of_warranty': cnt(lambda r: any('out of warranty' in w['text'] for w in r['why'])),
                        'uncovered': cnt(lambda r: r['support'] == 'uncovered'), 'overdue': fc['overdue']['count'],
                        'due_12m': sum(fc[k]['count'] for k in qs[1:5]), 'high_risk': cnt(lambda r: r['risk'] >= 50),
                        'no_dates': cnt(lambda r: r['due'] is None), 'planned': len([p for p in (req.get('plan') or []) if p.get('status') == 'planned']),
                        'supported_pct': int(round(100.0 * supported / len(rows))) if rows else None},
            'assets': rows[:20000], 'forecast': [fc[k] for k in qs], 'renewals': [renew[k] for k in sorted(renew)], 'lifespans': life,
            'learned': {'note': 'Lifespans learned from %d retirement(s) with dates; costs from %d recorded purchase cost(s). A type without 3 retirements uses the stated default.'
                        % (sum(len(v) for v in ages.values()), sum(len(v) for v in by_type.values()))}}


OPS = {'lifecycle.studio': op_studio}
