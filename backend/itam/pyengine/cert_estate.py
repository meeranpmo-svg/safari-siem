# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
"""Certificate lifecycle across the estate - the four pillars of the Certificates page. Python decides, Node.js commits
(engine/certs.js): this module reads only the facts it is given and writes nothing.

  certs.estate  {endpoints, keystores, ca, renewals, requests, installs, policy, alerts, sent, now}
                -> inventory (one row per certificate, every place it was seen), expiry timeline, alerts due, compliance report

Sources:
  network   the TLS endpoints the platform reads every 6 h (the assessment in cert_rules.assess)
  keystore  the machine certificate stores of Windows servers (agent 1.6 snapshot through the SIEM): what is INSTALLED,
            including certificates no port presents yet
  ca        the machine certificates an AD CS certification authority issued (agent 1.6 on the CA server)
The same certificate seen in several places (matched on its serial number) is one row that lists every place, so a renewal
that reached the endpoint but left the old certificate in a store, or a CA certificate installed nowhere, shows. Nothing here
contacts a server; alerts are DECIDED here (which certificate crossed which threshold, once) and sent by Node.js.
Standard library only.
"""
from datetime import datetime, timezone

DAY = 86400000
SEV = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}
LEAD = {'acme': 20, 'adcs': 45, 'manual': 60, 'self': 30, 'unknown': 60}
BUCKETS = [('expired', None, -1), ('0-7', 0, 7), ('8-30', 8, 30), ('31-60', 31, 60), ('61-90', 61, 90), ('91-180', 91, 180), ('180+', 181, None)]
THRESHOLDS = [60, 30, 14, 7, 1]


def ms(v):
    if isinstance(v, (int, float)):
        return int(v)
    if not v or not isinstance(v, str):
        return None
    s = v.strip()
    try:
        d = datetime.fromisoformat(s[:-1] + '+00:00' if s.endswith('Z') else s)
        if d.tzinfo is None:
            d = d.replace(tzinfo=timezone.utc)
        return int(d.timestamp() * 1000)
    except ValueError:
        return None


def day(t):
    return datetime.fromtimestamp(t / 1000, timezone.utc).strftime('%Y-%m-%d') if t is not None else None


def ser(v):
    s = ''.join(ch for ch in str(v or '').lower() if ch in '0123456789abcdef')
    return s.lstrip('0') or None


def bucket(d):
    if d is None:
        return None
    for name, lo, hi in BUCKETS:
        if (lo is None or d >= lo) and (hi is None or d <= hi):
            return name
    return None


def _risk(r, key, sev, text, fix):
    r.append({'key': key, 'severity': sev, 'text': text, 'fix': fix})


def collect(req, now):
    """one row per certificate (by serial, else per place), each with every place it was seen"""
    rows, by_serial = [], {}

    def put(cert, place):
        s = ser(cert.get('serial'))
        if s and s in by_serial:
            row = by_serial[s]
            row['places'].append(place)
            for k in ('owner', 'issuer_kind'):
                if not row.get(k) and cert.get(k):
                    row[k] = cert[k]
            row['critical'] = row['critical'] or bool(cert.get('critical'))
            return
        row = dict(cert, places=[place])
        rows.append(row)
        if s:
            by_serial[s] = row

    for ep in req.get('endpoints') or []:
        sc = ep.get('scan') or {}
        if not sc.get('ok'):
            continue
        put({'subject': sc.get('subject'), 'names': sc.get('names') or [], 'issuer': sc.get('issuer'), 'not_after': sc.get('not_after'), 'not_before': sc.get('not_before'),
             'serial': sc.get('serial'), 'key_type': sc.get('key_type'), 'key_bits': sc.get('key_bits'), 'sig_alg': None, 'self_signed': bool(sc.get('self_signed')),
             'trusted': sc.get('trusted'), 'owner': ep.get('owner') or None, 'critical': bool(ep.get('critical')), 'issuer_kind': ep.get('issuer_kind'), 'endpoint_id': ep.get('id')},
            {'source': 'network', 'where': ep.get('label') or (str(ep.get('host')) + ':' + str(ep.get('port'))), 'endpoint_id': ep.get('id'), 'renewal': ep.get('renewal')})
    for ks in req.get('keystores') or []:
        for c in ks.get('certs') or []:
            eku = [str(x).lower() for x in c.get('eku') or []]
            put({'subject': c.get('subject'), 'names': c.get('sans') or [], 'issuer': c.get('issuer'), 'not_after': ms(c.get('not_after')), 'not_before': ms(c.get('not_before')),
                 'serial': c.get('serial'), 'key_type': str(c.get('key_alg') or '').lower().replace('rsa', 'rsa').replace('ecc', 'ec'), 'key_bits': c.get('key_bits'), 'sig_alg': c.get('sig_alg'),
                 'self_signed': bool(c.get('self_signed')), 'trusted': None, 'owner': None, 'critical': False, 'issuer_kind': 'self' if c.get('self_signed') else None,
                 'server_auth': (not eku) or any('server auth' in x for x in eku)},
                {'source': 'keystore', 'where': str(ks.get('host')) + ' · ' + str(c.get('store') or 'My'), 'host': ks.get('host'), 'has_key': bool(c.get('has_key')), 'thumbprint': c.get('thumbprint')})
    for ca in req.get('ca') or []:
        for c in ca.get('rows') or []:
            put({'subject': c.get('cn'), 'names': [c.get('cn')] if c.get('cn') else [], 'issuer': 'AD CS on ' + str(ca.get('host')), 'not_after': ms(c.get('not_after')), 'not_before': None,
                 'serial': c.get('serial'), 'key_type': None, 'key_bits': None, 'sig_alg': None, 'self_signed': False, 'trusted': None, 'owner': None, 'critical': False, 'issuer_kind': 'adcs',
                 'template': c.get('template')},
                {'source': 'ca', 'where': 'issued by ' + str(ca.get('host')) + (' (' + str(c.get('template')) + ')' if c.get('template') else ''), 'host': ca.get('host'), 'request_id': c.get('request_id')})
    return rows


def judge(row, P, now):
    r, d = [], None
    na = row.get('not_after')
    if na is not None:
        d = int((na - now) // DAY)
    kind = row.get('issuer_kind') or 'unknown'
    lead = P['lead_days'].get(kind, P['lead_days']['unknown'])
    srcs = {p['source'] for p in row['places']}
    live = 'network' in srcs
    installed = srcs & {'network', 'keystore'}
    where = ', '.join(p['where'] for p in row['places'][:3])
    if d is not None and d < 0:
        if live:
            _risk(r, 'expired', 'critical' if row.get('critical') else 'high', 'expired %d days ago and still presented on %s' % (-d, where), 'renew it and install the new certificate now (Renewal & Publishing)')
        elif installed:
            _risk(r, 'expired_installed', 'low', 'expired %d days ago and still installed in %s' % (-d, where), 'remove the expired certificate from the store once nothing uses it')
    elif d is not None and d <= lead:
        open_ren = any((p.get('renewal') or {}).get('status') for p in row['places'])
        sev = 'high' if d <= 7 else 'medium'
        if installed:
            _risk(r, 'expiring', sev if not open_ren else 'low', 'expires in %d days (renew-by lead %d days for %s)%s' % (d, lead, kind, ' - a renewal is open' if open_ren else ''),
                  'open a renewal (or let ACME / AD CS issue it) and publish it to every place listed')
        elif 'ca' in srcs:
            _risk(r, 'expiring_unplaced', 'low', 'issued by the CA, expires in %d days, and not seen installed anywhere the platform reads' % d, 'check where it is used; if nowhere, let it expire')
    if row.get('key_type') == 'rsa' and row.get('key_bits') and int(row['key_bits']) < P['min_rsa']:
        _risk(r, 'weak_key', 'high', 'RSA %d-bit key (policy %d)' % (row['key_bits'], P['min_rsa']), 'reissue with RSA %d+ or ECDSA P-256' % P['min_rsa'])
    if row.get('sig_alg') and 'sha1' in str(row['sig_alg']).lower():
        _risk(r, 'sha1', 'high', 'signed with SHA-1 (' + str(row['sig_alg']) + ')', 'reissue with SHA-256 or stronger')
    if row.get('self_signed') and live:
        _risk(r, 'self_signed', 'medium', 'self-signed certificate presented on ' + where, 'replace it with a certificate from the internal CA (AD CS) or a public CA')
    if live and row.get('trusted') is False and not row.get('self_signed'):
        _risk(r, 'untrusted', 'medium', 'the chain is not trusted by a standard client', 'install the full chain (intermediate certificates) on the server')
    if live and not row.get('owner'):
        _risk(r, 'no_owner', 'low', 'no owner recorded for the endpoint', 'record the owner on the endpoint so alerts reach a person')
    r.sort(key=lambda x: -SEV[x['severity']])
    return d, r


def estate(req):
    now = int(req.get('now') or 0)
    pol = req.get('policy') or {}
    P = {'lead_days': dict(LEAD, **{k: int(v) for k, v in (pol.get('lead_days') or {}).items() if k in LEAD}), 'min_rsa': int(pol.get('min_rsa') or 2048)}
    rows = collect(req, now)
    items = []
    for i, row in enumerate(rows):
        d, risks = judge(row, P, now)
        srcs = sorted({p['source'] for p in row['places']})
        items.append({'id': 'c' + str(i + 1), 'subject': row.get('subject') or '(no subject)', 'names': (row.get('names') or [])[:10], 'issuer': row.get('issuer') or '',
                      'issuer_kind': row.get('issuer_kind') or 'unknown', 'serial': row.get('serial') or '', 'not_after': day(row.get('not_after')), 'days_left': d, 'bucket': bucket(d),
                      'key': ((row.get('key_type') or '').upper() + ' ' + str(row.get('key_bits') or '')).strip() or None, 'sig_alg': row.get('sig_alg'), 'self_signed': bool(row.get('self_signed')),
                      'template': row.get('template'), 'owner': row.get('owner'), 'critical': bool(row.get('critical')), 'sources': srcs, 'places': row['places'],
                      'risks': risks, 'risk': risks[0]['severity'] if risks else 'none'})
    order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'none': 4}
    items.sort(key=lambda x: (order[x['risk']], x['days_left'] if x['days_left'] is not None else 99999))

    # ---- expiry timeline (installed certificates only: a CA record nobody installed is not an outage)
    inst = [x for x in items if set(x['sources']) & {'network', 'keystore'}]
    timeline = [{'bucket': b[0], 'count': sum(1 for x in inst if x['bucket'] == b[0]), 'critical': sum(1 for x in inst if x['bucket'] == b[0] and x['critical'])} for b in BUCKETS]

    # ---- alerts: each installed certificate crossing a threshold, once per (certificate, threshold); expired once
    al = req.get('alerts') or {}
    th = sorted({int(t) for t in (al.get('thresholds') or THRESHOLDS) if 0 < int(t) <= 365}, reverse=True)
    sent = set(req.get('sent') or [])
    due = []
    for x in inst:
        if x['days_left'] is None:
            continue
        hit = 'expired' if x['days_left'] < 0 else next((str(t) for t in sorted(th) if x['days_left'] <= t), None)
        if not hit:
            continue
        key = (x['serial'] or x['subject']) + '|' + hit
        if key in sent:
            continue
        due.append({'key': key, 'threshold': hit, 'subject': x['subject'], 'days_left': x['days_left'], 'not_after': x['not_after'], 'owner': x['owner'],
                    'where': [p['where'] for p in x['places']][:5], 'critical': x['critical']})

    # ---- compliance & audit report
    eps = [e for e in req.get('endpoints') or []]
    ren = req.get('renewals') or []
    t12 = now - 365 * DAY
    done12 = [r for r in ren if r.get('status') == 'verified' and (ms(r.get('verified_at') or r.get('updated_at')) or 0) >= t12]
    on_time = [r for r in done12 if r.get('old_not_after') and (ms(r.get('verified_at') or r.get('updated_at')) or 0) <= int(r['old_not_after'])]
    auto = [e for e in eps if e.get('issuer_kind') in ('acme', 'adcs')]
    within = [x for x in items if not any(r['key'] in ('expired', 'weak_key', 'sha1', 'self_signed', 'untrusted') for r in x['risks'])]
    owned = [e for e in eps if e.get('owner')]
    report = {
        'generated': day(now), 'certificates': len(items), 'installed': len(inst), 'by_source': {s: sum(1 for x in items if s in x['sources']) for s in ('network', 'keystore', 'ca')},
        'within_policy_pct': round(100 * len(within) / len(items)) if items else None,
        'endpoints_with_owner_pct': round(100 * len(owned) / len(eps)) if eps else None,
        'automatable_pct': round(100 * len(auto) / len(eps)) if eps else None,
        'renewals_verified_12m': len(done12), 'renewed_before_expiry_pct': round(100 * len(on_time) / len(done12)) if done12 else None,
        'renewals_open': sum(1 for r in ren if r.get('status') not in ('verified', 'cancelled')),
        'requests_issued': sum(1 for q in req.get('requests') or [] if q.get('status') in ('issued', 'accepted', 'installed')),
        'installs_verified': sum(1 for j in req.get('installs') or [] if j.get('status') == 'verified'),
        'by_issuer': sorted(({'issuer': k, 'count': v} for k, v in _count(x['issuer'] or 'unknown' for x in items).items()), key=lambda z: -z['count'])[:10],
        'by_key': sorted(({'key': k, 'count': v} for k, v in _count(x['key'] or 'not reported' for x in items).items()), key=lambda z: -z['count']),
        'by_risk': _count(x['risk'] for x in items),
        'controls': [
            {'ref': 'SAMA CSF 3.3.9 · NCA ECC 2-8', 'what': 'Certificates use strong keys and signatures', 'ok': not any(r['key'] in ('weak_key', 'sha1') for x in items for r in x['risks'])},
            {'ref': 'SAMA CSF 3.3.9 · NCA ECC 2-8-3', 'what': 'No expired certificate is presented by a service', 'ok': not any(r['key'] == 'expired' for x in items for r in x['risks'])},
            {'ref': 'SAMA CSF 3.3.3 · NCA ECC 2-1', 'what': 'Every certificate endpoint has an owner', 'ok': bool(eps) and len(owned) == len(eps)},
            {'ref': 'NCA ECC 2-8', 'what': 'Renewals are completed before expiry (12 months)', 'ok': (len(on_time) == len(done12)) if done12 else None},
        ],
    }
    srcs = [{'id': 'network', 'name': 'TLS endpoints', 'connected': bool(eps), 'count': report['by_source']['network'], 'reason': '' if eps else 'add endpoints or run Discover'},
            {'id': 'keystore', 'name': 'Windows certificate stores (agent 1.6)', 'connected': bool(req.get('keystores')), 'count': report['by_source']['keystore'],
             'reason': '' if req.get('keystores') else (req.get('keystore_reason') or 'install / update the Windows agent to 1.6 on the servers')},
            {'id': 'ca', 'name': 'AD CS issued certificates (agent 1.6 on the CA)', 'connected': bool(req.get('ca')), 'count': report['by_source']['ca'],
             'reason': '' if req.get('ca') else (req.get('ca_reason') or 'install / update the Windows agent to 1.6 on the certification authority server')}]
    return {'ok': True, 'items': items, 'timeline': timeline, 'alerts_due': due, 'thresholds': th, 'report': report, 'sources': srcs, 'policy': P,
            'note': 'One row per certificate, with every place it was seen (matched on the serial number). The platform reads; it never removes or installs a certificate outside an approved installation.'}


def _count(it):
    o = {}
    for k in it:
        o[k] = o.get(k, 0) + 1
    return o


OPS = {'certs.estate': estate}
