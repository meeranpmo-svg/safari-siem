# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
"""Data catalog and identity correlation rules (engine/pdpl-catalog.js commits what these decide).

The catalog is built from the read-only discovery scans: every column that holds (or is named like) personal data, grouped
by ATTRIBUTE (national ID, mobile, diagnosis ...) and by SOURCE (database). Identifier columns are the columns a person
can be found by; an administrator confirms them (suggested: national ID / Iqama / passport / mobile / e-mail / IBAN columns
whose sampled values did not contradict the name). The identity search runs only through confirmed identifier columns.

  pdpl.catalog          {scans, identifiers, targets}  -> attributes, sources, columns, suggestions, coverage
  pdpl.catalog also takes files {sharepoint, fileshares} from the SIEM (SharePoint / OneDrive collector and the Windows
  agent's file-share scan): file sources, the files holding personal data and how exposed they are (anonymous link,
  people outside the organisation, readable by everyone) - exposure of sensitive files is a finding.
  pdpl.correlate_plan   {scans, identifiers, id_type}  -> per source, the identifier columns to search
  pdpl.correlate_result {results, scans}               -> per system: rows found, tables, errors; the systems to task
"""

# PDPL Art. 1 sensitive data. Credit data is NOT sensitive: it is its own class (Art. 24, IR Arts. 11 / 27) - explicit consent,
# the person told of every disclosure request - but no impact assessment and no 'sensitive' label because of it.
SENSITIVE = ('health', 'biometric', 'genetic', 'criminal', 'religious', 'beliefs', 'ethnic', 'parentage')
CATEGORY = {'national_id': 'identity', 'iqama': 'identity', 'passport': 'identity', 'mobile': 'contact', 'email': 'contact', 'iban': 'financial', 'card': 'financial', 'health': 'health', 'salary': 'financial', 'cv': 'employment'}
ID_TYPES = [('national_id', 'National ID'), ('iqama', 'Iqama'), ('passport', 'Passport'), ('mobile', 'Mobile number'), ('email', 'E-mail'), ('iban', 'IBAN'),
            ('customer_no', 'Customer number'), ('policy_no', 'Policy number'), ('claim_no', 'Claim number')]
SUGGEST = ('national_id', 'iqama', 'passport', 'mobile', 'email', 'iban')
LABEL = {'cv': 'CV / résumé', 'national_id': 'National ID', 'iqama': 'Iqama number', 'passport': 'Passport number', 'name': 'Person name', 'birth_date': 'Date of birth', 'gender': 'Gender',
         'nationality': 'Nationality', 'religion': 'Religion', 'mobile': 'Mobile / phone', 'email': 'E-mail address', 'address': 'Address', 'iban': 'IBAN / bank account',
         'card': 'Payment card', 'salary': 'Salary / income', 'health': 'Health / diagnosis', 'credit': 'Credit data', 'biometric': 'Biometric / photo', 'location': 'Location',
         'criminal': 'Criminal record', 'vehicle_owner': 'Vehicle (plate / VIN)'}


def cid(s, c):
    return '|'.join([str(s.get('db')), str(c.get('owner')), str(c.get('table')), str(c.get('column'))])


def catalog(req):
    scans, ids = req.get('scans') or [], {i['id']: i for i in req.get('identifiers') or []}
    attrs, sources, cols, sugg = {}, [], [], []
    for s in scans:
        live = [c for c in s.get('columns') or [] if c.get('confirmed') is not False]
        cats = sorted({c.get('category') for c in live if c.get('category')})
        sources.append({'db': s.get('db'), 'label': s.get('label'), 'engine': s.get('engine') or 'oracle', 'host': s.get('host'), 'at': s.get('at'), 'ok': bool(s.get('ok')), 'error': s.get('error') or '',
                        'columns': len(live), 'tables': len({(c.get('owner'), c.get('table')) for c in live}), 'categories': cats, 'sensitive': [c for c in cats if c in SENSITIVE],
                        'identifiers': sum(1 for c in live if cid(s, c) in ids), 'scanned_columns': s.get('scanned_columns'), 'probe_denied': s.get('probe_denied') or 0})
        for c in s.get('columns') or []:
            k = c.get('kind')
            row = {'id': cid(s, c), 'db': s.get('db'), 'source': s.get('label'), 'engine': s.get('engine') or 'oracle', 'owner': c.get('owner'), 'table': c.get('table'), 'column': c.get('column'), 'type': c.get('type'),
                   'rows': c.get('rows'), 'kind': k, 'attribute': LABEL.get(k, k), 'category': c.get('category'), 'sensitive': c.get('category') in SENSITIVE, 'by': c.get('by'),
                   'confirmed': c.get('confirmed'), 'sampled': c.get('sampled'), 'matched': c.get('matched'), 'identifier': (ids.get(cid(s, c)) or {}).get('id_type')}
            cols.append(row)
            if c.get('confirmed') is False:
                continue
            a = attrs.setdefault(k, {'kind': k, 'attribute': LABEL.get(k, k), 'category': c.get('category'), 'sensitive': c.get('category') in SENSITIVE, 'sources': set(), 'columns': 0, 'confirmed': 0, 'max_rows': 0})
            a['sources'].add(s.get('db')); a['columns'] += 1; a['confirmed'] += 1 if c.get('confirmed') else 0; a['max_rows'] = max(a['max_rows'], c.get('rows') or 0)
            if k in SUGGEST and not row['identifier']:
                sugg.append({'id': row['id'], 'source': s.get('label'), 'table': str(c.get('owner')) + '.' + str(c.get('table')), 'column': c.get('column'), 'id_type': k, 'confirmed': c.get('confirmed')})
    fsrc, frows, fstat = file_sources(req.get('files')) if req.get('files') is not None else ([], [], {'linked': False})
    for fs_ in fsrc:
        for k, n in fs_['file_kinds'].items():
            a = attrs.setdefault(k, {'kind': k, 'attribute': LABEL.get(k, k), 'category': CATEGORY.get(k, 'other'), 'sensitive': CATEGORY.get(k) in SENSITIVE, 'sources': set(), 'columns': 0, 'confirmed': 0, 'max_rows': 0})
            a['sources'].add(fs_['db']); a['files'] = a.get('files', 0) + n
    sources += [{k: v for k, v in x.items() if k != 'file_kinds'} for x in fsrc]
    out_attrs = sorted(({**a, 'sources': len(a['sources']), 'files': a.get('files', 0)} for a in attrs.values()), key=lambda a: (not a['sensitive'], -(a['columns'] + a['files'])))
    known = req.get('targets') or []
    scanned = {s.get('db') for s in scans}
    return {'attributes': out_attrs, 'sources': sources, 'columns': cols[:5000], 'columns_total': len(cols), 'suggestions': sugg[:200], 'id_types': [[k, v] for k, v in ID_TYPES],
            'identifiers': list(ids.values()),
            'coverage': {'targets': len(known), 'scanned': sum(1 for s in sources if s['ok']), 'failed': sum(1 for s in sources if not s['ok']),
                         'not_scanned': [t for t in known if t.get('key') not in scanned][:50]},
            'totals': {'sources': len(sources), 'columns': sum(1 for c in cols if c['confirmed'] is not False), 'attributes': len(out_attrs), 'sensitive_columns': sum(1 for c in cols if c['sensitive'] and c['confirmed'] is not False),
                       'files': len(frows), 'exposed_files': sum(1 for r in frows if EXPOSURE_RANK.get(r.get('exposure') or 'none', 0) >= 2)},
            'files': frows[:5000], 'files_total': len(frows), 'file_status': fstat, 'findings': file_findings(frows),
            'note': 'Built from read-only scans: each database dictionary (where the login may read a table, 50 values are tested on the platform server), SharePoint / OneDrive through Microsoft Graph and file shares through the Windows agent on the file server. Only the count of matches is kept. No personal data value is stored or shown.'}


STRONG = ('national_id', 'iqama', 'passport', 'iban', 'card', 'health', 'salary')
EXPOSURE_RANK = {'anonymous': 3, 'external': 3, 'everyone': 2, 'organization': 1, 'none': 0}


def file_sources(files):
    """SharePoint / OneDrive sources and the agent's file-share roots, in one shape: sources[] and files[]"""
    sp, fsh = (files or {}).get('sharepoint') or {}, ((files or {}).get('fileshares') or {}).get('hosts') or []
    sources, rows = [], []

    def add(src_key, label, engine, host, at, ok, err, hits, seen, read, truncated, exp_of):
        kinds, exp = {}, {'anonymous': 0, 'external': 0, 'everyone': 0, 'organization': 0}
        for h in hits:
            ks = sorted(set(list((h.get('kinds') or {}).keys()) + list(h.get('name_kinds') or [])))
            e = exp_of(h)
            if e in exp:
                exp[e] += 1
            for k in ks:
                kinds[k] = kinds.get(k, 0) + 1
            rows.append({'id': src_key + '|' + str(h.get('id') or h.get('p') or h.get('name')), 'db': src_key, 'source': label, 'engine': engine,
                         'name': h.get('name') or str(h.get('p') or '').split('\\')[-1], 'path': h.get('path') if h.get('path') is not None else '\\'.join(str(h.get('p') or '').split('\\')[:-1]),
                         'size': h.get('size'), 'modified': h.get('modified'), 'kinds': h.get('kinds') or {}, 'name_kinds': h.get('name_kinds') or [], 'by': h.get('by'),
                         'attributes': [LABEL.get(k, k) for k in ks], 'sensitive': any(CATEGORY.get(k) in SENSITIVE for k in ks), 'strong': any(k in STRONG for k in ks), 'exposure': e})
        cats = sorted({CATEGORY.get(k, 'other') for k in kinds})
        sources.append({'db': src_key, 'label': label, 'engine': engine, 'host': host, 'at': at, 'ok': ok, 'error': err or '', 'columns': 0, 'tables': 0, 'files': len(hits),
                        'files_seen': seen, 'files_read': read, 'truncated': bool(truncated), 'categories': cats, 'sensitive': [c for c in cats if c in SENSITIVE], 'identifiers': 0, 'exposure': exp,
                        'file_kinds': kinds})

    for x in sp.get('sources') or []:
        add(x.get('key'), x.get('label'), x.get('kind') or 'sharepoint', x.get('url') or '', sp.get('at'), not x.get('errors'), '; '.join(x.get('errors') or []),
            x.get('hits') or [], x.get('files_seen'), x.get('files_read'), x.get('truncated') or x.get('hits_truncated'), lambda h: h.get('shared'))
    for hst in fsh:
        st = hst.get('settings') or {}
        for r in st.get('roots') or []:
            lab = '\\\\' + str(hst.get('host')) + '\\' + r['share'] if r.get('share') else str(hst.get('host')) + ':' + str(r.get('path'))
            add('fs:' + str(hst.get('host')) + ':' + str(r.get('path')), lab, 'fileshare', hst.get('host'), st.get('at') or hst.get('at'), True,
                ('%d folder(s) could not be read' % r['dirs_denied']) if r.get('dirs_denied') else '', r.get('hits') or [], r.get('files_seen'), r.get('files_read'), r.get('truncated'),
                lambda h: 'everyone' if h.get('open') else ('none' if h.get('open') is False else None))
    status = sp.get('status') or {}
    return sources, rows, {'sharepoint': {'at': sp.get('at'), 'never': bool(sp.get('never')), 'errors': sp.get('errors') or [], 'running': bool(status.get('running')), 'progress': status.get('progress') or '',
                                          'last_error': status.get('last_error') or '', 'enabled': bool(status.get('enabled')), 'onedrive': bool(status.get('onedrive'))},
                           'file_servers': len(fsh), 'linked': files is not None}


def file_findings(rows):
    F, exposed = [], [r for r in rows if r.get('strong') and EXPOSURE_RANK.get(r.get('exposure') or 'none', 0) >= 2]
    exposed.sort(key=lambda r: -EXPOSURE_RANK.get(r['exposure'], 0))
    for r in exposed[:50]:
        how = {'anonymous': 'shared by an anonymous link (anyone with the link)', 'external': 'shared with people outside the organisation', 'everyone': 'readable by everyone on the file share'}[r['exposure']]
        F.append({'key': 'files:' + r['id'] + ':exposed', 'severity': 'high' if r['exposure'] in ('anonymous', 'external') or r.get('sensitive') else 'medium',
                  'title': '%s (%s) holds %s and is %s' % (r['name'], r['source'], ', '.join(r['attributes']) or 'personal data', how), 'evidence': [(r.get('path') or '') + ' · found by ' + str(r.get('by'))],
                  'recommendation': 'Remove the link / outside access, or restrict the folder to the people who need it (PDPL Art. 19: security of personal data); move it to the system of record if it is a copy.',
                  'requirement': 'P-13', 'target': {'type': 'file', 'id': r['id'], 'name': r['name']}})
    if len(exposed) > 50:
        F.append({'key': 'files:exposed:more', 'severity': 'high', 'title': '%d more exposed files with personal data' % (len(exposed) - 50), 'evidence': [], 'requirement': 'P-13',
                  'recommendation': 'Open the Data Catalog, filter the files by exposure and work through them.'})
    return F


def correlate_plan(req):
    scans, t = {s.get('db'): s for s in req.get('scans') or []}, req.get('id_type')
    plan = {}
    for i in req.get('identifiers') or []:
        if i.get('id_type') != t or i.get('db') not in scans:
            continue
        s = scans[i['db']]
        col = next((c for c in s.get('columns') or [] if c.get('owner') == i.get('owner') and c.get('table') == i.get('table') and c.get('column') == i.get('column')), None)
        if not col:
            continue
        p = plan.setdefault(i['db'], {'db': i['db'], 'label': s.get('label'), 'engine': s.get('engine') or 'oracle', 'columns': []})
        p['columns'].append({'owner': col.get('owner'), 'table': col.get('table'), 'column': col.get('column'), 'type': col.get('type')})
    return {'plan': list(plan.values())}


def correlate_result(req):
    out = []
    for r in req.get('results') or []:
        rows = r.get('rows') or []
        found = [x for x in rows if (x.get('count') or 0) > 0]
        out.append({'db': r.get('db'), 'system': r.get('label'), 'engine': r.get('engine'), 'ok': bool(r.get('ok')), 'error': r.get('error') or '',
                    'rows': sum(x.get('count') or 0 for x in found), 'tables': sorted({str(x.get('owner')) + '.' + str(x.get('table')) for x in found}),
                    'columns': [{'table': str(x.get('owner')) + '.' + str(x.get('table')), 'column': x.get('column'), 'count': x.get('count'), 'error': x.get('error')} for x in rows]})
    hit = [x for x in out if x['rows']]
    return {'systems': out, 'found_in': [x['system'] for x in hit], 'searched': len(out), 'failed': sum(1 for x in out if not x['ok'] or any(c.get('error') for c in x['columns']))}


OPS = {'pdpl.catalog': catalog, 'pdpl.correlate_plan': correlate_plan, 'pdpl.correlate_result': correlate_result}
