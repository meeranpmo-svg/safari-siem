# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
"""AWS Signature Version 4 - the same algorithm and output as engine/discovery/sigv4.js (checked against the AWS test
vectors through the parity test). sign({method, url, headers, body, region, service, accessKeyId, secretAccessKey,
sessionToken?, amzDate?}) -> {headers, canonicalRequest, stringToSign, signature, signedHeaders}
Standard library only (Python 3.8+).
"""
import hashlib
import hmac as _hmac
import re
import urllib.parse
from datetime import datetime, timezone


def sha256hex(s):
    return hashlib.sha256(s.encode('utf-8') if isinstance(s, str) else s).hexdigest()


def _h(k, s):
    return _hmac.new(k.encode('utf-8') if isinstance(k, str) else k, s.encode('utf-8'), hashlib.sha256).digest()


def enc(s):
    """RFC 3986 (unreserved: A-Z a-z 0-9 - _ . ~)"""
    return urllib.parse.quote(str(s), safe='-_.~')


def canonical_query(query):
    pairs = [(enc(k), enc(v)) for k, v in urllib.parse.parse_qsl(query, keep_blank_values=True)]
    pairs.sort()
    return '&'.join('%s=%s' % p for p in pairs)


def canonical_uri(path):
    return '/'.join(enc(urllib.parse.unquote(seg)) for seg in (path or '/').split('/')) or '/'


def signing_key(secret, date, region, service):
    return _h(_h(_h(_h('AWS4' + secret, date), region), service), 'aws4_request')


def _host(u):
    """URL.host: the host plus the port unless it is the scheme's default"""
    host = u.hostname or ''
    if ':' in host:
        host = '[%s]' % host
    port = u.port
    if port is not None and port != {'https': 443, 'http': 80}.get(u.scheme):
        host += ':%d' % port
    return host


def sign(o):
    u = urllib.parse.urlsplit(o['url'])
    amz = o.get('amzDate') or datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    date = amz[:8]
    body = '' if o.get('body') is None else o['body']
    headers = {}
    for k, v in (o.get('headers') or {}).items():
        headers[k.lower()] = re.sub(r'\s+', ' ', str(v).strip())
    if not headers.get('host'):
        headers['host'] = _host(u)
    headers['x-amz-date'] = amz
    if o.get('sessionToken'):
        headers['x-amz-security-token'] = o['sessionToken']
    names = sorted(headers)
    canonical_headers = ''.join('%s:%s\n' % (n, headers[n]) for n in names)
    signed = ';'.join(names)
    creq = '\n'.join([str(o.get('method') or 'GET').upper(), canonical_uri(u.path), canonical_query(u.query), canonical_headers, signed, sha256hex(body)])
    scope = '%s/%s/%s/aws4_request' % (date, o['region'], o['service'])
    sts = '\n'.join(['AWS4-HMAC-SHA256', amz, scope, sha256hex(creq)])
    sig = _hmac.new(signing_key(o['secretAccessKey'], date, o['region'], o['service']), sts.encode('utf-8'), hashlib.sha256).hexdigest()
    out = dict(o.get('headers') or {})
    out.update({'X-Amz-Date': amz, 'Authorization': 'AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s' % (o['accessKeyId'], scope, signed, sig)})
    if o.get('sessionToken'):
        out['X-Amz-Security-Token'] = o['sessionToken']
    return {'headers': out, 'canonicalRequest': creq, 'stringToSign': sts, 'signature': sig, 'signedHeaders': signed}
