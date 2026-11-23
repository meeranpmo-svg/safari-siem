# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
"""Asset Studio rules (asset_studio_rules.py) (engine/asset-studio.js): the asset register read with machine learning, every number explained.

op assets.studio  {assets, blocked, ai, now}
  health      0-100 per active asset, every point taken off named: missing fields, not seen by any source for 30 days while
              in use, out of warranty, past end of life, no owner, no site.
  anomalies   stale (in use, a source saw it before, nothing for 30+ days), ghost (retired / disposed, yet a source saw it in
              the last 7 days), warranty ending in 90 days.
  suggestions a missing vendor / model / OS / site / department / type learned from peers: for each feature of the asset
              (name prefix, subnet, model, vendor) the distribution of the field among assets that have it; the purest feature
              with 3+ peers wins, confidence = Laplace (top + 1) / (n + 2), offered at 0.7 or more, with the counts as the reason.
              Nothing is applied here - a person accepts a suggestion.
"""
import re
import datetime as _dt

ACTIVE = {'in_use', 'in_stock', 'in_repair'}
CLOSED = {'retired', 'disposed'}
EXPECT = {
    'server': ['site', 'owner', 'vendor', 'model', 'serial', 'os', 'mgmt_ip'],
    'vm': ['site', 'owner', 'os', 'mgmt_ip'],
    'network': ['site', 'owner', 'vendor', 'model', 'serial', 'mgmt_ip'],
    'storage': ['site', 'owner', 'vendor', 'model', 'serial', 'mgmt_ip'],
    'workstation': ['site', 'owner', 'vendor', 'model', 'serial', 'os'],
    'laptop': ['owner', 'vendor', 'model', 'serial', 'os'],
    'printer': ['site', 'vendor', 'model', 'serial', 'mgmt_ip'],
}
DEFAULT_EXPECT = ['site', 'owner', 'vendor', 'model']
LABEL = {'site': 'site', 'owner': 'owner', 'vendor': 'vendor', 'model': 'model', 'serial': 'serial number', 'os': 'operating system',
         'mgmt_ip': 'management IP', 'department': 'department', 'type': 'type'}
LEARN = ['vendor', 'model', 'os', 'site', 'department', 'type']
HW = {'server', 'network', 'storage', 'workstation', 'laptop', 'printer', 'ups', 'phone'}
DAY = 86400.0


def _ts(v):
    if not v:
        return None
    try:
        t = str(v)[:19].replace('Z', '')
        fmt = '%Y-%m-%dT%H:%M:%S' if 'T' in t else '%Y-%m-%d'
        return (_dt.datetime.strptime(t[:19] if 'T' in t else t[:10], fmt) - _dt.datetime(1970, 1, 1)).total_seconds()
    except ValueError:
        return None


def prefix(name):
    m = re.match(r'^([A-Za-z]{2,})[-_ .]?', str(name or ''))
    return m.group(1).upper() if m else None


def net24(ip):
    p = str(ip or '').split('.')
    return '.'.join(p[:3]) if len(p) == 4 and all(x.isdigit() for x in p) else None


def features(a):
    f = []
    if prefix(a.get('name')):
        f.append(('name prefix', prefix(a.get('name')) + '-*'))
    if net24(a.get('mgmt_ip')):
        f.append(('subnet', net24(a.get('mgmt_ip')) + '.0/24'))
    if a.get('model'):
        f.append(('model', a['model']))
    if a.get('vendor'):
        f.append(('vendor', a['vendor']))
    return f


def health(a, now):
    want = EXPECT.get(a.get('type'), DEFAULT_EXPECT)
    why, score = [], 100
    miss = [k for k in want if not a.get(k)]
    if miss:
        p = min(40, 6 * len(miss))
        score -= p
        why.append({'points': -p, 'code': 'missing', 'text': 'missing ' + ', '.join(LABEL.get(m, m) for m in miss)})
    ls = _ts(a.get('last_seen'))
    if a.get('status') == 'in_use' and ls and (now - ls) > 30 * DAY:
        score -= 25
        why.append({'points': -25, 'code': 'stale', 'text': 'no source has seen it for %d days' % int((now - ls) / DAY)})
    we = _ts(a.get('warranty_end'))
    if we and a.get('type') in HW:
        if we < now:
            score -= 15
            why.append({'points': -15, 'code': 'warranty', 'text': 'out of warranty since ' + str(a.get('warranty_end'))[:10]})
        elif we - now < 90 * DAY:
            score -= 5
            why.append({'points': -5, 'code': 'warranty-soon', 'text': 'warranty ends ' + str(a.get('warranty_end'))[:10]})
    eol = _ts(a.get('eol'))
    if eol and eol < now:
        score -= 20
        why.append({'points': -20, 'code': 'eol', 'text': 'past end of life (' + str(a.get('eol'))[:10] + ')'})
    if not a.get('owner') and 'owner' not in miss:
        score -= 10
        why.append({'points': -10, 'code': 'owner', 'text': 'no owner'})
    return max(0, score), why


def op_studio(req):
    assets = [a for a in (req.get('assets') or []) if isinstance(a, dict) and a.get('id')]
    blocked = set(req.get('blocked') or [])
    now = float(req.get('now') or 0) / 1000.0 or (_dt.datetime.utcnow() - _dt.datetime(1970, 1, 1)).total_seconds()
    active = [a for a in assets if a.get('status', 'in_use') in ACTIVE]

    rows, anomalies = [], []
    for a in active:
        h, why = health(a, now)
        rows.append({'id': a['id'], 'name': a.get('name'), 'type': a.get('type') or 'other', 'status': a.get('status'), 'site': a.get('site') or '',
                     'owner': a.get('owner') or '', 'ip': a.get('mgmt_ip') or '', 'vendor': a.get('vendor') or '', 'model': a.get('model') or '',
                     'os': a.get('os') or '', 'last_seen': a.get('last_seen'), 'health': h, 'why': why, 'codes': [w['code'] for w in why]})
        if 'stale' in [w['code'] for w in why]:
            anomalies.append({'id': a['id'], 'name': a.get('name'), 'kind': 'stale', 'text': '%s is in use but %s' % (a.get('name'), [w['text'] for w in why if w['code'] == 'stale'][0])})
        if 'warranty-soon' in [w['code'] for w in why]:
            anomalies.append({'id': a['id'], 'name': a.get('name'), 'kind': 'warranty', 'text': '%s: %s' % (a.get('name'), [w['text'] for w in why if w['code'] == 'warranty-soon'][0])})
    for a in assets:
        ls = _ts(a.get('last_seen'))
        if a.get('status') in CLOSED and ls and (now - ls) < 7 * DAY:
            anomalies.append({'id': a['id'], 'name': a.get('name'), 'kind': 'ghost', 'text': '%s is %s, yet a source saw it %s - is it still on the network?' % (a.get('name'), a.get('status'), str(a.get('last_seen'))[:10])})

    # ---- learned suggestions
    sugg = []
    for field in LEARN:
        dist = {}
        for a in active:
            v = a.get(field)
            if not v or (field == 'type' and v == 'other'):
                continue
            for fk, fv in features(a):
                if fk == field:
                    continue
                d = dist.setdefault((fk, fv), {})
                d[v] = d.get(v, 0) + 1
        for a in active:
            cur = a.get(field)
            if cur and not (field == 'type' and cur == 'other'):
                continue
            best = None
            for fk, fv in features(a):
                if fk == field:
                    continue
                d = dist.get((fk, fv))
                if not d:
                    continue
                n = sum(d.values())
                top, c = max(d.items(), key=lambda kv: kv[1])
                if n < 3:
                    continue
                conf = round((c + 1.0) / (n + 2.0), 2)
                if not best or conf > best[0]:
                    best = (conf, top, c, n, fk, fv)
            if best and best[0] >= 0.7:
                conf, top, c, n, fk, fv = best
                key = '%s|%s|%s' % (field, a['id'], top)
                if key in blocked:
                    continue
                sugg.append({'key': key, 'id': a['id'], 'name': a.get('name'), 'field': field, 'label': LABEL.get(field, field), 'value': top,
                             'confidence': conf, 'kind': 'learned',
                             'why': '%d of %d assets with %s %s have %s "%s"' % (c, n, fk, fv, LABEL.get(field, field), top)})
    for p in req.get('ai') or []:
        if p.get('key') in blocked:
            continue
        sugg.append(p)
    sugg.sort(key=lambda x: -(x.get('confidence') or 0))

    def count(fn):
        return len([r for r in rows if fn(r)])
    by_type, by_site = {}, {}
    for r in rows:
        by_type[r['type']] = by_type.get(r['type'], 0) + 1
        by_site[r['site'] or '(no site)'] = by_site.get(r['site'] or '(no site)', 0) + 1
    hp = int(round(sum(r['health'] for r in rows) / float(len(rows)))) if rows else None
    return {'ok': True,
            'summary': {'assets': len(assets), 'active': len(rows), 'health_pct': hp, 'stale': count(lambda r: 'stale' in r['codes']),
                        'ghosts': len([x for x in anomalies if x['kind'] == 'ghost']), 'out_of_warranty': count(lambda r: 'warranty' in r['codes']),
                        'warranty_soon': count(lambda r: 'warranty-soon' in r['codes']), 'eol': count(lambda r: 'eol' in r['codes']),
                        'no_owner': count(lambda r: not r['owner']), 'suggestions': len(sugg), 'by_type': by_type, 'by_site': by_site},
            'assets': sorted(rows, key=lambda r: r['health'])[:20000], 'anomalies': anomalies[:300], 'suggestions': sugg[:500],
            'learned': {'note': 'Suggestions learned from %d active asset(s) in this register; %d decision(s) by people remembered.' % (len(active), len(blocked))}}


OPS = {'assets.studio': op_studio}
