# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
"""Certificate lifecycle rules (the AI PKI Engineer). Python decides, Node.js commits (engine/certs.js): this module reads
only what it is given and writes nothing.

  certs.assess {endpoints, scans, renewals, policy, now} -> endpoints with lifecycle state, findings, renewal confirmations,
                                                           counts

Lifecycle: valid -> renew-due (inside the issuer's lead time) -> expiring (<= 14 days) -> expired. Weak keys, a name the
certificate does not cover, an untrusted chain on a public site, a self-signed certificate on a critical service and an
endpoint that could not be read are findings. A renewal is CONFIRMED only by a scan: the endpoint now presents a different
certificate that lasts longer than the one the renewal was opened for - never because someone marked it done.
Standard library only.
"""

DAY = 86400000
LEAD_DEFAULT = {'acme': 30, 'adcs': 45, 'manual': 60, 'self': 30, 'unknown': 45}
ISSUER_NAMES = {'acme': 'ACME (automatic public CA)', 'adcs': 'Microsoft AD CS (internal CA)', 'manual': 'Public CA, ordered by hand',
                'self': 'Self-signed', 'unknown': 'Unknown issuer'}
TARGET_NAMES = {'linux-nginx': 'nginx (Linux)', 'linux-apache': 'Apache (Linux)', 'iis': 'IIS (Windows)', 'exchange': 'Exchange',
                'f5': 'F5 BIG-IP', 'fortigate': 'FortiGate', 'paloalto': 'Palo Alto', 'other': 'Other / by hand', 'none': 'Not set'}
SEVN = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
ACME_ISSUERS = ("let's encrypt", 'zerossl', 'buypass', 'google trust services')


def guess_issuer(scan):
    """issuer kind from what the endpoint presented, when the operator did not set it"""
    if not scan or not scan.get('ok'):
        return 'unknown'
    iss = str(scan.get('issuer') or '').lower()
    if scan.get('self_signed'):
        return 'self'
    if any(x in iss for x in ACME_ISSUERS):
        return 'acme'
    if scan.get('trusted'):
        return 'manual'
    return 'adcs' if iss else 'unknown'


def _f(ep, key, sev, title, evidence, rec):
    return {'key': ep['id'] + ':' + key, 'severity': sev, 'kind': key, 'title': title, 'evidence': [e for e in evidence if e][:6],
            'recommendation': rec, 'target': {'type': 'certificate', 'id': ep['id'], 'name': ep.get('label') or (ep['host'] + ':' + str(ep['port']))}}


def assess(req):
    eps = [e for e in (req.get('endpoints') or []) if not e.get('retired')]
    scans = req.get('scans') or {}
    renewals = req.get('renewals') or []
    pol = req.get('policy') or {}
    lead = dict(LEAD_DEFAULT, **{k: int(v) for k, v in (pol.get('lead_days') or {}).items() if k in LEAD_DEFAULT})
    min_rsa = int(pol.get('min_rsa') or 2048)
    min_ec = int(pol.get('min_ec') or 256)
    now = int(req.get('now') or 0)
    out, F, confirm = [], [], []
    open_by_ep = {}
    for r in renewals:
        if r.get('status') not in ('verified', 'cancelled'):
            open_by_ep[r.get('endpoint_id')] = r
    for ep in eps:
        sc = scans.get(ep['id'])
        kind = ep.get('issuer_kind') or guess_issuer(sc)
        name = ep.get('label') or (ep['host'] + ':' + str(ep['port']))
        row = {'id': ep['id'], 'label': name, 'host': ep['host'], 'port': ep['port'], 'critical': bool(ep.get('critical')), 'owner': ep.get('owner') or '', 'auto_renew': bool(ep.get('auto_renew')), 'sni': ep.get('sni') or '', 'source': ep.get('source') or '',
               'issuer_kind': kind, 'issuer_kind_name': ISSUER_NAMES.get(kind, kind), 'issuer_kind_set': bool(ep.get('issuer_kind')),
               'deploy_target': ep.get('deploy_target') or 'none', 'deploy_target_name': TARGET_NAMES.get(ep.get('deploy_target') or 'none', 'Not set'),
               'scan': sc, 'state': 'unknown', 'days_left': None, 'renew_by': None, 'renewal': None}
        rn = open_by_ep.get(ep['id'])
        if rn:
            row['renewal'] = {'id': rn['id'], 'status': rn.get('status')}
        if not sc:
            row['state'] = 'not-scanned'
            out.append(row)
            continue
        if not sc.get('ok'):
            row['state'] = 'unreachable'
            F.append(_f(ep, 'unreachable', 'low', name + ': the certificate could not be read', [str(sc.get('error') or '')[:200]],
                        'Check the host and port are right and reachable from the platform, or retire the endpoint.'))
            out.append(row)
            continue
        exp = sc.get('not_after') or 0
        days = int((exp - now) // DAY) if exp else None
        renew_by = exp - lead.get(kind, 45) * DAY if exp else None
        row['days_left'], row['renew_by'] = days, renew_by
        if days is None:
            row['state'] = 'unknown'
        elif days < 0:
            row['state'] = 'expired'
        elif days <= 14:
            row['state'] = 'expiring'
        elif now >= renew_by:
            row['state'] = 'renew-due'
        else:
            row['state'] = 'valid'
        ev = ['expires ' + str(sc.get('not_after_iso') or ''), 'issuer: ' + str(sc.get('issuer') or '?'), 'serial ' + str(sc.get('serial') or '?')]
        plan = 'Renew through ' + ISSUER_NAMES.get(kind, kind) + (', install on ' + TARGET_NAMES.get(row['deploy_target'], row['deploy_target']) if row['deploy_target'] != 'none' else '') + ' and re-scan to confirm.'
        if row['state'] == 'expired':
            F.append(_f(ep, 'expired', 'critical', name + ': certificate EXPIRED ' + str(-days) + ' day(s) ago', ev, plan + ' Clients now refuse or warn on this service.'))
        elif row['state'] == 'expiring':
            F.append(_f(ep, 'expiring', 'high' if not rn else 'medium', name + ': certificate expires in ' + str(days) + ' day(s)' + (' - renewal ' + rn['id'] + ' is ' + rn.get('status', '') if rn else ''), ev, plan))
        elif row['state'] == 'renew-due' and not rn:
            F.append(_f(ep, 'renew-due', 'medium', name + ': renewal due (' + str(days) + ' days left; lead time for ' + ISSUER_NAMES.get(kind, kind) + ' is ' + str(lead.get(kind, 45)) + ' days)', ev, 'Open a renewal. ' + plan))
        kt, bits = str(sc.get('key_type') or '').lower(), int(sc.get('key_bits') or 0)
        if (kt == 'rsa' and 0 < bits < min_rsa) or (kt == 'ec' and 0 < bits < min_ec):
            F.append(_f(ep, 'weak-key', 'medium', name + ': weak key (' + kt.upper() + ' ' + str(bits) + ' bits)', ['minimum RSA ' + str(min_rsa) + ' / EC ' + str(min_ec)],
                        'Issue the next certificate with a new key of at least RSA ' + str(min_rsa) + ' or EC P-256 (do not re-use the old key).'))
        if sc.get('name_ok') is False:
            F.append(_f(ep, 'name-mismatch', 'high', name + ': the certificate does not cover ' + str(sc.get('sni') or ep['host']), ['names: ' + ', '.join((sc.get('names') or [])[:6])],
                        'Re-issue with the host name in the Subject Alternative Names, or point clients at a name the certificate covers.'))
        if kind in ('acme', 'manual') and sc.get('trusted') is False:
            F.append(_f(ep, 'untrusted', 'high', name + ': chain not trusted (' + str(sc.get('trust_error') or '') + ')', [], 'Install the full intermediate chain from the CA with the certificate.'))
        if sc.get('self_signed') and ep.get('critical'):
            F.append(_f(ep, 'self-signed', 'medium', name + ': self-signed certificate on a critical service', [], 'Replace it with a certificate from the internal CA (AD CS) or a public CA.'))
        if rn and rn.get('status') not in ('verified', 'cancelled'):
            old = rn.get('old_fingerprint') or ''
            if old and sc.get('fingerprint256') and sc['fingerprint256'] != old and exp > int(rn.get('old_not_after') or 0):
                confirm.append({'renewal_id': rn['id'], 'endpoint_id': ep['id'], 'fingerprint256': sc['fingerprint256'], 'not_after': exp,
                                'note': 'scan found the new certificate (serial ' + str(sc.get('serial') or '?') + ', expires ' + str(sc.get('not_after_iso') or '') + ')'})
        out.append(row)
    F.extend(request_findings(req.get('requests'), {e['id']: e for e in eps}, scans, now))
    F.sort(key=lambda f: -SEVN.get(f['severity'], 0))
    counts = {k: 0 for k in ('valid', 'renew-due', 'expiring', 'expired', 'unreachable', 'not-scanned', 'unknown')}
    for r in out:
        counts[r['state']] = counts.get(r['state'], 0) + 1
    return {'endpoints': out, 'findings': F, 'confirm': confirm, 'counts': counts, 'lead_days': lead, 'min_rsa': min_rsa, 'min_ec': min_ec,
            'renewals_open': len(open_by_ep), 'connected': bool(eps)}


# ---------------------------------------------------------------- phase 2: issuance decisions
import fnmatch  # noqa: E402
from datetime import datetime, timezone  # noqa: E402
import re  # noqa: E402

METHOD_OF = {'acme': 'acme', 'adcs': 'adcs', 'manual': 'manual', 'self': 'manual', 'unknown': 'manual'}
IPV4 = __import__('re').compile(r'^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$')


def plan_request(req):
    """{endpoint, scan, policy, names?, method?, key_type?, key_bits?} -> {names, method, key_type, key_bits, needs_approval,
    why[]} | {refuse}. Names the endpoint already answers for (host, SNI, the names in the certificate it presents) need no
    approval; any other name, or a wildcard, needs a second person (it widens what the certificate can impersonate)."""
    ep, sc, pol = req.get('endpoint') or {}, req.get('scan') or {}, req.get('policy') or {}
    kind = ep.get('issuer_kind') or guess_issuer(sc)
    method = req.get('method') or METHOD_OF.get(kind, 'manual')
    if method not in ('acme', 'adcs', 'manual'):
        return {'refuse': {'status': 400, 'error': 'method must be acme, adcs or manual'}}
    known = set()
    for n in [ep.get('host'), ep.get('sni')] + list((sc.get('names') or []) if sc.get('ok') else []):
        if n:
            known.add(str(n).lower())
    names = [str(n).lower() for n in (req.get('names') or [])] or sorted(n for n in known if n and (method != 'acme' or not IPV4.match(n)))
    if not names:
        return {'refuse': {'status': 409, 'error': 'no name to request: scan the endpoint or give the names'}}
    if len(names) > 50:
        return {'refuse': {'status': 400, 'error': 'at most 50 names in one certificate'}}
    if method == 'acme' and any(IPV4.match(n) for n in names):
        return {'refuse': {'status': 400, 'error': 'public ACME certificate authorities do not issue for IP addresses - use AD CS for internal addresses'}}
    allowed = [str(p).lower() for p in (pol.get('allowed_names') or [])]
    why = []
    for n in names:
        if n.startswith('*.'):
            why.append(n + ' is a wildcard')
        elif n not in known and not any(fnmatch.fnmatchcase(n, p) for p in allowed):
            why.append(n + ' is not a name this endpoint presents today')
    kt = req.get('key_type') or pol.get('key_type') or 'rsa'
    kb = int(req.get('key_bits') or (256 if kt == 'ec' else max(2048, int(pol.get('min_rsa') or 2048))))
    if kt == 'rsa' and (kb not in (2048, 3072, 4096) or kb < int(pol.get('min_rsa') or 2048)):
        return {'refuse': {'status': 400, 'error': 'RSA key must be 2048, 3072 or 4096 bits and at least the policy minimum (' + str(pol.get('min_rsa') or 2048) + ')'}}
    if kt == 'ec' and kb not in (256, 384):
        return {'refuse': {'status': 400, 'error': 'EC key must be P-256 or P-384'}}
    if kt not in ('rsa', 'ec'):
        return {'refuse': {'status': 400, 'error': 'key_type must be rsa or ec'}}
    return {'names': names, 'method': method, 'key_type': kt, 'key_bits': kb, 'needs_approval': bool(why), 'why': why}


def accept_issued(req):
    """{request: {names}, facts: inspectCert(), now, policy} -> {accept, problems[]} ('ok' is the bridge's failure flag) - a certificate is accepted only when it
    belongs to our key, covers every name asked for, is valid now and lasts long enough to be worth installing."""
    r, f, now = req.get('request') or {}, req.get('facts') or {}, int(req.get('now') or 0)
    if not f.get('ok'):
        return {'accept': False, 'problems': [str(f.get('error') or 'not a certificate')]}
    p = []
    if f.get('key_match') is not True:
        p.append('the certificate does not belong to the private key of this request')
    have = set(f.get('names') or [])
    miss = [n for n in (r.get('names') or []) if n not in have]
    if miss:
        p.append('not covered: ' + ', '.join(miss[:10]))
    if f.get('not_before') and f['not_before'] > now + 3600000:
        p.append('not valid yet')
    if not f.get('not_after') or f['not_after'] <= now + 7 * DAY:
        p.append('expires within 7 days')
    if f.get('self_signed'):
        p.append('self-signed - not issued by a certificate authority')
    return {'accept': not p, 'problems': p}


def request_findings(requests, endpoints_by_id, scans, now):
    """issuance that is stuck: failed, waiting on a person or a DNS record for long, or issued but still not installed"""
    F = []
    for q in requests or []:
        ep = endpoints_by_id.get(q.get('endpoint_id')) or {'id': q.get('endpoint_id') or '?', 'host': '?', 'port': ''}
        age = (now - int(q.get('updated_ms') or q.get('created_ms') or now)) // DAY
        st = q.get('status')
        tgt = {'id': ep['id'], 'host': ep.get('host', '?'), 'port': ep.get('port', ''), 'label': ep.get('label')}
        if st == 'failed':
            F.append(_f(tgt, 'issue-failed:' + q['id'], 'high', (ep.get('label') or ep.get('host')) + ': issuance ' + q['id'] + ' failed', [str(q.get('error') or '')[:200]], 'Read the error, fix the cause (DNS, challenge, CA permission) and start a new request.'))
        elif st in ('awaiting-dns', 'awaiting-approval', 'adcs-pending') and age >= 2:
            what = {'awaiting-dns': 'waiting for the DNS TXT record', 'awaiting-approval': 'waiting for a second person to approve the names', 'adcs-pending': 'held by the AD CS manager'}[st]
            F.append(_f(tgt, 'issue-stuck:' + q['id'], 'medium', (ep.get('label') or ep.get('host')) + ': request ' + q['id'] + ' ' + what + ' for ' + str(age) + ' days', [], 'Complete the step or cancel the request.'))
        elif st == 'issued':
            sc = scans.get(ep['id']) or {}
            if sc.get('ok') and sc.get('fingerprint256') != q.get('fingerprint256') and age >= 7:
                F.append(_f(tgt, 'not-installed:' + q['id'], 'medium', (ep.get('label') or ep.get('host')) + ': certificate ' + q['id'] + ' issued ' + str(age) + ' days ago but not installed', ['the endpoint still presents ' + str(sc.get('serial') or '?')], 'Install it (export the bundle, or the installation plan when phase 3 is in place) and re-scan.'))
    return F


# ---------------------------------------------------------------- phase 3: installation on Palo Alto / FortiGate
BINDINGS = {
    'paloalto': ['ssl-tls-profile', 'none'],
    'fortigate': ['admin-server-cert', 'ssl-vpn', 'vip', 'none'],
}
DAY = 86400000


def _covers(names, host):
    h = str(host or '').lower()
    for n in names or []:
        n = str(n).lower()
        if n == h or (n.startswith('*.') and h.count('.') == n.count('.') and h.endswith(n[1:])):
            return True
    return False


def plan_install(req):
    """{request, target, endpoint, now} -> {refuse: {status, error}} | {cert_name, steps[], warnings[]}.
    A certificate is installed only when it was issued and checked by this platform, has at least 7 days left, covers the
    name the endpoint is reached by, and the binding exists for that kind of device."""
    q, t, ep, now = req.get('request') or {}, req.get('target') or {}, req.get('endpoint'), int(req.get('now') or 0)
    def no(status, msg):
        return {'refuse': {'status': status, 'error': msg}}
    if q.get('status') != 'issued' or not q.get('fingerprint256'):
        return no(409, 'request %s is %s - only an issued certificate is installed' % (q.get('id'), q.get('status')))
    na = int(q.get('not_after') or 0)
    if na - now < 7 * DAY:
        return no(409, 'the certificate expires in less than 7 days - issue a new one')
    kind = t.get('kind')
    if kind not in BINDINGS:
        return no(400, 'installation is built for Palo Alto and FortiGate only')
    b = (t.get('binding') or {}).get('type') or 'none'
    if b not in BINDINGS[kind]:
        return no(400, 'binding %s does not exist on %s (%s)' % (b, kind, ', '.join(BINDINGS[kind])))
    if b in ('ssl-tls-profile', 'vip') and not (t.get('binding') or {}).get('name'):
        return no(400, 'the binding %s needs the name of the profile / virtual server' % b)
    warnings = []
    if ep:
        host = ep.get('sni') or ep.get('host')
        if host and not _covers(q.get('names'), host) and not str(host).replace('.', '').isdigit():
            return no(409, 'the certificate (%s) does not cover %s, the name the endpoint is reached by' % (', '.join(q.get('names') or []), host))
    else:
        warnings.append('no certificate endpoint is linked to this device: the installation cannot be verified by a scan, only by the device answer')
    if b == 'admin-server-cert':
        warnings.append('the FortiGate management certificate changes: the platform accepts the new certificate for this device during the job and keeps it pinned afterwards')
    if b == 'none':
        warnings.append('the certificate is imported only; nothing uses it until someone binds it')
    cn = re.sub(r'[^A-Za-z0-9-]+', '-', str((q.get('names') or ['cert'])[0]).replace('*', 'wildcard')).strip('-')[:20]
    day = datetime.fromtimestamp(na / 1000, tz=timezone.utc).strftime('%Y%m%d')
    name = ('zyb-%s-%s' % (cn, day))[:35]
    steps = ['read the binding in use (kept for rollback)', 'import the private key and certificate as ' + name, 'import the issuing CA chain']
    if b != 'none':
        steps.append('bind %s%s to %s' % (b, (' ' + t['binding']['name']) if (t.get('binding') or {}).get('name') else '', name))
    if kind == 'paloalto':
        steps.insert(0, 'refuse if anyone has uncommitted changes on the firewall (a commit would push them too)')
        if b != 'none':
            steps.append('commit and wait for the commit job to finish')
    steps.append('verify: the device / endpoint presents fingerprint ' + str(q.get('fingerprint256'))[:23] + '…')
    return {'cert_name': name, 'steps': steps, 'warnings': warnings, 'binding': b}
