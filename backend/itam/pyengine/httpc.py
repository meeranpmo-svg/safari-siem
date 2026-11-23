# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
"""Small HTTPS client for the Python modules of IT Asset Management - the same rules as engine/discovery/httpc.js.

request(url, method='GET', headers=None, body=None, timeout_ms=30000, ca_file=None, pin=None, capture_untrusted=False)
  -> {'status', 'headers', 'text', 'json'}     raises HttpcError(code, message, presented=None)
  - https only; plain http ONLY for loopback hosts (127.0.0.1 / localhost / ::1 - local test arrays).
  - TLS verification is never switched off: the system CAs, a CA PEM file (ca_file), or an administrator-approved
    SHA-256 certificate fingerprint (pin) for appliances with self-signed certificates. With a pin the request
    (headers carrying credentials) is written only AFTER the presented certificate matched the pin.
  - capture_untrusted (Test / Trust & pin only): still FAILS CLOSED - nothing is sent to a server that did not verify -
    but the presented certificate's SHA-256 fingerprint (and subject / issuer when Python can decode them) is put on the
    error so the page can offer Trust & pin.
  - one connection per request, 16 MB response cap, TLS 1.2 or newer.
Standard library only (Python 3.8+).
"""
import hashlib
import http.client
import json
import os
import socket
import ssl
import tempfile
import urllib.parse

LOOPBACK = {'127.0.0.1', 'localhost', '::1'}
MAX_BYTES = 16 * 1024 * 1024


class HttpcError(Exception):
    def __init__(self, code, message, presented=None, http=None, pin_mismatch=False):
        super().__init__(message)
        self.code = code
        self.presented = presented
        self.http = http
        self.pin_mismatch = pin_mismatch


def _dn(parts):
    out = []
    for rdn in parts or ():
        for k, v in rdn:
            key = {'commonName': 'CN', 'organizationName': 'O', 'organizationalUnitName': 'OU', 'localityName': 'L',
                   'stateOrProvinceName': 'ST', 'countryName': 'C'}.get(k)
            if key:
                out.append('%s=%s' % (key, v))
    return ', '.join(out)


def _cert_info(der):
    """What an administrator needs to recognise the appliance - never the key or the raw certificate."""
    info = {'fingerprint256': hashlib.sha256(der).hexdigest(), 'subject': None, 'issuer': None,
            'valid_from': None, 'valid_to': None, 'serial': None, 'self_signed': None}
    try:  # CPython can decode a PEM file with this helper; when it is not there the fingerprint is still enough
        fd, path = tempfile.mkstemp(suffix='.pem')
        try:
            with os.fdopen(fd, 'w') as f:
                f.write(ssl.DER_cert_to_PEM_cert(der))
            d = ssl._ssl._test_decode_cert(path)  # noqa: SLF001
        finally:
            os.unlink(path)
        info.update(subject=_dn(d.get('subject')), issuer=_dn(d.get('issuer')), valid_from=d.get('notBefore'),
                    valid_to=d.get('notAfter'), serial=d.get('serialNumber'))
        info['self_signed'] = bool(info['subject']) and info['subject'] == info['issuer']
    except Exception:  # pragma: no cover - decoding is a convenience
        pass
    return info


def _context(verify, ca_file):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    if verify:
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        if ca_file:
            try:
                ctx.load_verify_locations(cafile=ca_file)
            except OSError as e:
                raise HttpcError('config', 'CA file not readable (%s)' % (e.strerror or e))
        else:
            ctx.load_default_certs()
    else:  # replaced by the fingerprint check (pin) or used only to capture the presented certificate
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _presented(host, port, timeout):
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            with _context(False, None).wrap_socket(s, server_hostname=host) as t:
                return _cert_info(t.getpeercert(binary_form=True))
    except Exception:
        return None


def request(url, method='GET', headers=None, body=None, timeout_ms=30000, ca_file=None, pin=None, capture_untrusted=False):
    try:
        u = urllib.parse.urlsplit(url)
    except ValueError:
        raise HttpcError('config', 'invalid URL')
    host = (u.hostname or '').strip('[]')
    is_https = u.scheme == 'https'
    if not is_https and not (u.scheme == 'http' and host in LOOPBACK):
        raise HttpcError('config', 'only https:// endpoints are allowed')
    port = u.port or (443 if is_https else 80)
    path = (u.path or '/') + ('?' + u.query if u.query else '')
    timeout = max(1.0, (timeout_ms or 30000) / 1000.0)
    pin = (pin or '').replace(':', '').lower()
    hdrs = dict(headers or {})
    data = None if body is None else (body if isinstance(body, bytes) else str(body).encode('utf-8'))
    if data is not None:
        hdrs['Content-Length'] = str(len(data))

    if is_https:
        conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=_context(not pin, ca_file))
    else:
        conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        try:
            conn.connect()
        except ssl.SSLCertVerificationError as e:
            presented = _presented(host, port, timeout) if capture_untrusted else None
            raise HttpcError('tls', 'the certificate is not trusted (%s) - nothing was sent; check it, then Trust & pin'
                             % (e.verify_message or 'verification failed'), presented=presented)
        except ssl.SSLError as e:
            raise HttpcError('tls', 'TLS failed: %s' % (e.reason or e))
        except socket.timeout:
            raise HttpcError('timeout', 'no answer from %s:%s within %ss' % (host, port, int(timeout)))
        except OSError as e:
            raise HttpcError('unreachable', '%s:%s cannot be reached (%s)' % (host, port, e.strerror or e))
        if is_https and pin:
            fp = hashlib.sha256(conn.sock.getpeercert(binary_form=True)).hexdigest()
            if fp != pin:  # nothing has been written yet
                raise HttpcError('tls', 'the certificate does not match the pinned fingerprint - nothing was sent',
                                 presented=_cert_info(conn.sock.getpeercert(binary_form=True)), pin_mismatch=True)
        try:
            conn.request(method or 'GET', path, body=data, headers=hdrs)
            r = conn.getresponse()
            raw = r.read(MAX_BYTES + 1)
        except socket.timeout:
            raise HttpcError('timeout', 'no answer from %s:%s within %ss' % (host, port, int(timeout)))
        except OSError as e:
            raise HttpcError('unreachable', 'the connection to %s:%s failed (%s)' % (host, port, e.strerror or e))
        if len(raw) > MAX_BYTES:
            raise HttpcError('protocol', 'the answer is larger than 16 MB')
        text = raw.decode('utf-8', 'replace')
        try:
            js = json.loads(text) if text.strip()[:1] in ('{', '[') else None
        except ValueError:
            js = None
        hdrs = {}
        for k, v in r.getheaders():   # Set-Cookie is a list, as Node.js gives it (a server may send several)
            if k.lower() == 'set-cookie':
                hdrs.setdefault('set-cookie', []).append(v)
            else:
                hdrs[k.lower()] = v
        return {'status': r.status, 'headers': hdrs, 'text': text, 'json': js}
    finally:
        conn.close()
