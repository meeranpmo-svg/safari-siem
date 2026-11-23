# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
"""FireCompass rules (engine/firecompass.js): external attack-surface / VAPT findings from FireCompass, mapped, normalised and
merged with the internal Greenbone scans. FireCompass publishes no public API schema, so nothing here assumes field names:

op firecompass.map        {columns, rows}            which column holds what. Each canonical field is scored per column from the
                          column NAME (synonyms, token overlap) and its VALUES (CVE pattern, IP / domain / URL, severity words,
                          0-10 numbers, dates); one column per field, best first. Confidence 0-1 per field; a field under 0.35 is
                          left unmapped - never guessed. A person confirms the mapping before anything is stored.
op firecompass.normalize  {rows, mapping, source}    findings in one shape: asset, title, severity (from the word, else CVSS),
                          cvss, cves[], status, dates, port, description, remediation, a stable id (the source id, else asset +
                          title). Rows without an asset or a title are dropped AND counted.
op firecompass.view       {fc, gb, assets, now}      the merge:
  exposure    external when the asset is a public IP, a domain name or a URL; internal when it is a private (RFC 1918) address
  overlap     a FireCompass finding and a Greenbone finding are the SAME when the asset matches (IP or host name) and they share a
              CVE; LIKELY the same when the asset matches and the titles share >= 60 % of their words (Jaccard). Never by title
              alone - two hosts with the same weakness are two findings.
  risk        0-100, every point named: severity base (critical 60 / high 45 / medium 25 / low 10, or CVSS x 6), external +15,
              exploit / KEV / ransomware words +10, the asset's criticality in IT Asset Management (critical +10, high +5),
              confirmed by both FireCompass and Greenbone +5, open more than 30 days +5 (90 days +10).
  families    findings grouped by weakness family (normalised title words) - one fix often closes a whole family.
"""

import re
import math
import hashlib
import ipaddress
import datetime as dt

CANON = {
    'id': ['id', 'finding id', 'issue id', 'risk id', 'uid', 'reference', 'ref'],
    'asset': ['asset', 'host', 'hostname', 'ip', 'ip address', 'target', 'domain', 'subdomain', 'url', 'endpoint', 'fqdn', 'affected asset', 'resource'],
    'title': ['title', 'name', 'finding', 'issue', 'vulnerability', 'risk', 'summary', 'finding name', 'risk title'],
    'severity': ['severity', 'risk level', 'priority', 'criticality', 'rating', 'impact', 'level'],
    'cvss': ['cvss', 'cvss score', 'score', 'base score', 'cvss v3', 'cvss3'],
    'cve': ['cve', 'cves', 'cve id', 'cve ids', 'vulnerability id'],
    'status': ['status', 'state', 'remediation status', 'finding status'],
    'first_seen': ['first seen', 'discovered', 'detected', 'created', 'found', 'found on', 'discovery date', 'first detected', 'date found'],
    'last_seen': ['last seen', 'updated', 'last detected', 'modified', 'last updated'],
    'port': ['port', 'service port', 'port/protocol'],
    'description': ['description', 'details', 'detail', 'observation', 'evidence'],
    'remediation': ['remediation', 'recommendation', 'solution', 'fix', 'mitigation'],
    'category': ['category', 'type', 'class', 'attack vector', 'technique'],
}
SEV_WORDS = {'critical': 'critical', 'crit': 'critical', 'p1': 'critical', 'very high': 'critical', 'high': 'high', 'p2': 'high', 'medium': 'medium', 'moderate': 'medium', 'med': 'medium', 'p3': 'medium',
             'low': 'low', 'p4': 'low', 'info': 'info', 'informational': 'info', 'none': 'info'}
CVE = re.compile(r'CVE-\d{4}-\d{4,7}', re.I)
DOM = re.compile(r'^(?=.{1,253}$)([a-z0-9-]{1,63}\.)+[a-z]{2,24}$', re.I)
STOP = set('the a an of on in to for and or is are with without by via from at be not no version versions detected found vulnerability vulnerable issue'.split())


def _tok(s):
    return [t for t in re.split(r'[^a-z0-9]+', str(s or '').lower()) if t and t not in STOP]


def _ntok(s):
    # column names keep every word ("Issue", "Vulnerability", "Found" are field names here, not filler)
    return [t for t in re.split(r'[^a-z0-9]+', str(s or '').lower()) if t]


def _name_score(col, syns):
    c = ' '.join(_ntok(col))
    if not c:
        return 0.0
    best = 0.0
    for s in syns:
        st = ' '.join(_ntok(s))
        if c == st:
            return 1.0
        a, b = set(c.split()), set(st.split())
        j = len(a & b) / float(len(a | b)) if a | b else 0
        if st and (c.startswith(st + ' ') or c.endswith(' ' + st)):
            j = max(j, 0.75)
        best = max(best, j)
    return best


def _date(v):
    s = str(v or '').strip()
    if not s:
        return None
    for fmt in ('%Y-%m-%dT%H:%M:%S', '%Y-%m-%d %H:%M:%S', '%Y-%m-%d', '%d/%m/%Y', '%m/%d/%Y', '%d-%m-%Y', '%Y/%m/%d'):
        try:
            return dt.datetime.strptime(s[:19].replace('Z', ''), fmt)
        except ValueError:
            continue
    try:
        n = float(s)
        if n > 1e12:
            n /= 1000.0
        if 1e9 < n < 4e9:
            return dt.datetime.utcfromtimestamp(n)
    except ValueError:
        pass
    return None


def _host_of(v):
    s = str(v or '').strip()
    m = re.match(r'^[a-z][a-z0-9+.-]*://([^/:?#]+)', s, re.I)
    if m:
        s = m.group(1)
    s = s.split('/')[0]
    if s.count(':') == 1 and not s.startswith('['):
        s = s.split(':')[0]
    return s.strip('[]').lower()


def _value_score(field, vals):
    vals = [str(v).strip() for v in vals if v is not None and str(v).strip() != '']
    if not vals:
        return 0.0
    n = float(len(vals))
    def share(fn):
        return sum(1 for v in vals if fn(v)) / n
    if field == 'cve':
        return share(lambda v: bool(CVE.search(v)))
    if field == 'asset':
        def isasset(v):
            h = _host_of(v)
            try:
                ipaddress.ip_address(h)
                return True
            except ValueError:
                return bool(DOM.match(h))
        return share(isasset)
    if field == 'severity':
        return share(lambda v: v.lower() in SEV_WORDS)
    if field == 'cvss':
        def isc(v):
            try:
                x = float(v)
                return 0 <= x <= 10 and ('.' in v or x <= 10)
            except ValueError:
                return False
        return share(isc) * 0.8
    if field in ('first_seen', 'last_seen'):
        return share(lambda v: _date(v) is not None) * 0.7
    if field == 'port':
        return share(lambda v: bool(re.match(r'^\d{1,5}(/(tcp|udp))?$', v, re.I))) * 0.8
    if field == 'status':
        return share(lambda v: v.lower() in ('open', 'closed', 'fixed', 'resolved', 'new', 'in progress', 'reopened', 'accepted', 'false positive', 'remediated', 'active')) * 0.9
    if field in ('title', 'description', 'remediation'):
        avg = sum(len(v) for v in vals) / n
        return 0.4 if (field == 'title' and 8 <= avg <= 160) or (field != 'title' and avg > 60) else 0.1
    if field == 'id':
        return 0.5 if len(set(vals)) == len(vals) else 0.0
    return 0.0


def op_map(req):
    cols = [str(c) for c in (req.get('columns') or [])][:200]
    rows = (req.get('rows') or [])[:200]
    scores = {}
    for f, syns in CANON.items():
        for c in cols:
            nm, vs = _name_score(c, syns), _value_score(f, [r.get(c) for r in rows if isinstance(r, dict)])
            sc = 0.65 * nm + 0.35 * vs if nm else 0.6 * vs
            if f in ('cvss', 'first_seen', 'last_seen', 'port', 'severity', 'cve') and nm >= 0.75 and vs >= 0.5:
                sc = max(sc, 0.9)
            scores[(f, c)] = sc
    mapping, conf, used = {}, {}, set()
    for (f, c), sc in sorted(scores.items(), key=lambda x: -x[1]):
        if f in mapping or c in used or sc < 0.35:
            continue
        mapping[f], conf[f] = c, round(min(1.0, sc), 2)
        used.add(c)
    return {'ok': True, 'mapping': mapping, 'confidence': conf, 'unmapped_columns': [c for c in cols if c not in used],
            'missing': [f for f in ('asset', 'title', 'severity') if f not in mapping], 'fields': list(CANON.keys())}


def _sev(v, cvss):
    w = str(v or '').strip().lower()
    if w in SEV_WORDS:
        return SEV_WORDS[w]
    try:
        n = float(w)
        if 0 <= n <= 10 and cvss is None:
            cvss = n
    except ValueError:
        pass
    if cvss is None:
        return 'unknown'
    return 'critical' if cvss >= 9 else 'high' if cvss >= 7 else 'medium' if cvss >= 4 else 'low' if cvss > 0 else 'info'


def _status(v):
    w = str(v or '').strip().lower()
    if w in ('closed', 'fixed', 'resolved', 'remediated'):
        return 'closed'
    if w in ('false positive', 'false_positive', 'fp'):
        return 'false_positive'
    if w in ('accepted', 'risk accepted', 'accepted risk'):
        return 'accepted'
    return 'open'


def op_normalize(req):
    m = req.get('mapping') or {}
    src = str(req.get('source') or 'import')
    out, dropped = [], {'no_asset': 0, 'no_title': 0}
    def g(r, f):
        c = m.get(f)
        return r.get(c) if c else None
    for r in (req.get('rows') or [])[:20000]:
        if not isinstance(r, dict):
            continue
        asset, title = str(g(r, 'asset') or '').strip()[:300], re.sub(r'\s+', ' ', str(g(r, 'title') or '')).strip()[:300]
        if not asset:
            dropped['no_asset'] += 1
            continue
        if not title:
            dropped['no_title'] += 1
            continue
        cvss = None
        try:
            c = float(g(r, 'cvss'))
            cvss = c if 0 <= c <= 10 else None
        except (TypeError, ValueError):
            cvss = None
        cves = sorted(set(x.upper() for x in CVE.findall(' '.join(str(g(r, k) or '') for k in ('cve', 'title', 'description')))))[:30]
        fs, ls = _date(g(r, 'first_seen')), _date(g(r, 'last_seen'))
        sid = str(g(r, 'id') or '').strip()[:120]
        key = 'fc:' + hashlib.sha256(((sid or (_host_of(asset) + '|' + title.lower())) ).encode('utf-8')).hexdigest()[:20]
        port = None
        try:
            port = int(re.match(r'^\s*(\d{1,5})', str(g(r, 'port') or '')).group(1)) if g(r, 'port') is not None and re.match(r'^\s*\d', str(g(r, 'port'))) else None
        except (AttributeError, ValueError):
            port = None
        out.append({'id': key, 'source_id': sid or None, 'asset': asset, 'host': _host_of(asset), 'title': title, 'severity': _sev(g(r, 'severity'), cvss), 'cvss': cvss, 'cves': cves,
                    'status_src': _status(g(r, 'status')), 'first_seen': fs.strftime('%Y-%m-%d') if fs else None, 'last_seen': ls.strftime('%Y-%m-%d') if ls else None, 'port': port,
                    'category': str(g(r, 'category') or '').strip()[:120] or None, 'description': str(g(r, 'description') or '').strip()[:4000] or None,
                    'remediation': str(g(r, 'remediation') or '').strip()[:4000] or None})
    return {'ok': True, 'findings': out, 'dropped': dropped}


def _exposure(host):
    h = str(host or '')
    try:
        ip = ipaddress.ip_address(h)
        # RFC 1918 / ULA / loopback / link-local are inside; Python's is_private also counts documentation and other reserved
        # ranges, which would hide an internet-facing address, so the ranges are named
        inside = any(ip in ipaddress.ip_network(n) for n in (('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8', '169.254.0.0/16', '100.64.0.0/10') if ip.version == 4 else ('fc00::/7', 'fe80::/10', '::1/128')))
        return 'internal' if inside else 'external'
    except ValueError:
        return 'external' if DOM.match(h) else 'unknown'


def _family(title):
    t = [x for x in _tok(title) if not re.match(r'^\d', x) and not x.startswith('cve')]
    return ' '.join(t[:2]) or 'other'


def op_view(req):
    now = (req.get('now') or 0) / 1000.0
    fc = [f for f in (req.get('fc') or [])]
    gb = req.get('gb') or []
    crit = {}
    for a in req.get('assets') or []:
        for k in ('name', 'ip', 'hostname', 'fqdn'):
            v = str(a.get(k) or '').strip().lower()
            if v:
                crit[v] = str(a.get('criticality') or '').lower()
    gb_by_host = {}
    for g in gb:
        for k in (g.get('host'), g.get('hostname')):
            k = str(k or '').strip().lower()
            if k:
                gb_by_host.setdefault(k, []).append(g)
    rows, fam = [], {}
    for f in fc:
        why = []
        base = {'critical': 60, 'high': 45, 'medium': 25, 'low': 10, 'info': 0}.get(f.get('severity'))
        if f.get('cvss') is not None:
            base = max(base or 0, int(round(f['cvss'] * 6)))
        why.append({'points': base or 0, 'text': '%s severity%s' % (f.get('severity'), ' (CVSS %.1f)' % f['cvss'] if f.get('cvss') is not None else '')})
        exp = _exposure(f.get('host'))
        if exp == 'external':
            why.append({'points': 15, 'text': 'exposed to the internet (%s)' % f.get('host')})
        text = ' '.join(str(f.get(k) or '') for k in ('title', 'description', 'category')).lower()
        if re.search(r'\b(exploit(ed|able)?|kev|known exploited|ransomware|rce|remote code execution|actively)\b', text):
            why.append({'points': 10, 'text': 'exploit / known-exploited / remote code execution named in the finding'})
        c = crit.get(str(f.get('host') or '').lower()) or crit.get(str(f.get('asset') or '').lower())
        if c == 'critical':
            why.append({'points': 10, 'text': 'the asset is business-critical in IT Asset Management (tier or tag)'})
        elif c == 'high':
            why.append({'points': 5, 'text': 'the asset is high criticality in IT Asset Management'})
        match, how = None, None
        for g in gb_by_host.get(str(f.get('host') or '').lower(), []):
            if set(f.get('cves') or []) & set(g.get('cves') or []):
                match, how = g, 'same'
                break
            a, b = set(_tok(f.get('title'))), set(_tok(g.get('name')))
            if a and b and len(a & b) / float(len(a | b)) >= 0.6:
                match, how = g, 'likely'
        if match and how == 'same':
            why.append({'points': 5, 'text': 'also reported by the Greenbone internal scan (same CVE)'})
        age = None
        if f.get('first_seen'):
            try:
                age = (now - (dt.datetime.strptime(f['first_seen'], '%Y-%m-%d') - dt.datetime(1970, 1, 1)).total_seconds()) / 86400.0
            except ValueError:
                age = None
        if age is not None and age > 90 and f.get('status') == 'open':
            why.append({'points': 10, 'text': 'open for %d days' % age})
        elif age is not None and age > 30 and f.get('status') == 'open':
            why.append({'points': 5, 'text': 'open for %d days' % age})
        risk = min(100, sum(w['points'] for w in why))
        fk = _family(f.get('title'))
        rows.append(dict(f, exposure=exp, risk=risk, why_risk=why, overlap=how, overlap_with=({'id': match.get('id'), 'host': match.get('host'), 'name': match.get('name'), 'severity': match.get('severity')} if match else None), family=fk, age_days=None if age is None else int(age), asset_criticality=c or None))
        if f.get('status') == 'open':
            fam.setdefault(fk, []).append(f.get('id'))
    rows.sort(key=lambda r: -r['risk'])
    openr = [r for r in rows if r.get('status') == 'open']
    hosts = {}
    for r in openr:
        h = hosts.setdefault(r['host'], {'host': r['host'], 'exposure': r['exposure'], 'findings': 0, 'max_risk': 0, 'worst': 'info', 'criticality': r['asset_criticality']})
        h['findings'] += 1
        h['max_risk'] = max(h['max_risk'], r['risk'])
        order = ['info', 'low', 'medium', 'high', 'critical']
        if r['severity'] in order and order.index(r['severity']) > order.index(h['worst']):
            h['worst'] = r['severity']
    matched_gb = set(r['overlap_with']['id'] for r in rows if r.get('overlap_with') and r['overlap_with'].get('id'))
    by = {}
    for r in openr:
        by[r['severity']] = by.get(r['severity'], 0) + 1
    families = sorted(({'family': k, 'findings': len(v)} for k, v in fam.items() if len(v) >= 2), key=lambda x: -x['findings'])[:12]
    score = None
    if openr:
        top = sorted((r['risk'] for r in openr), reverse=True)[:10]
        score = max(0, 100 - int(round(sum(top) / float(len(top)) * 0.8 + min(20, len(openr) / 5.0))))
    return {'ok': True, 'findings': rows, 'hosts': sorted(hosts.values(), key=lambda h: -h['max_risk'])[:200], 'families': families,
            'overlap': {'fc_only': len([r for r in openr if not r['overlap']]), 'both': len([r for r in openr if r['overlap']]), 'gb_only': max(0, len([g for g in gb]) - len(matched_gb))},
            'summary': {'open': len(openr), 'by_severity': by, 'external': len([r for r in openr if r['exposure'] == 'external']), 'internal': len([r for r in openr if r['exposure'] == 'internal']),
                        'hosts': len(hosts), 'pending_decisions': len([r for r in rows if (r.get('decision') or {}).get('state') == 'pending']), 'posture': score,
                        'high_risk': len([r for r in openr if r['risk'] >= 70]),
                        'by_vendor': {v: len([r for r in openr if (r.get('vendor') or 'firecompass') == v]) for v in ('firecompass', 'tenable')}}}


OPS = {'firecompass.map': op_map, 'firecompass.normalize': op_normalize, 'firecompass.view': op_view}
