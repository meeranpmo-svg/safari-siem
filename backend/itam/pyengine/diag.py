# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
"""Connection-test diagnostics - the same rules and English texts as engine/discovery/diag.js, so the vault and the Connect
Wizard show the same classified result whichever engine ran the test.
  result(kind, latency_ms, pin, http, discovered, presented, message)   -> success result
  from_error(kind, err, latency_ms, pin)                                 -> classified failure result
  DErr(code, message, stage, http, tls_trusted)                          -> what the connectors raise
Standard library only (Python 3.8+).
"""
CLASSES = ['auth', 'authz', 'timeout', 'unreachable', 'tls', 'config', 'protocol', 'not_supported']
SYS = {'vcenter': 'vCenter', 'esxi': 'the ESXi host', 'cucm_axl': 'CUCM', 'ldap': 'the directory', 'azure': 'Azure', 'aws': 'AWS',
       'nutanix': 'Nutanix Prism'}


class DErr(Exception):
    def __init__(self, code, message=None, stage=None, http=None, tls_trusted=False, presented=None, pin_mismatch=False):
        super().__init__(message or code)
        self.code, self.stage, self.http, self.tls_trusted = code, stage, http, tls_trusted
        self.presented, self.pin_mismatch = presented, pin_mismatch
        self.not_pc = False


def class_of(code):
    return code if code in CLASSES else 'protocol'


def stage_of(code, given):
    if given:
        return given
    if code in ('tls', 'auth', 'authz'):
        return code
    if code in ('timeout', 'unreachable'):
        return 'connect'
    if code == 'not_supported':
        return 'none'
    return 'config' if code == 'config' else 'protocol'


def auth_hint(kind):
    if kind == 'vcenter':
        return 'Check: the user name is in full SSO form (for example administrator@vsphere.local, not a bare name), the account is not locked, and the password is current.'
    if kind == 'ldap':
        return 'Check: the bind DN and password are correct (LDAP result 49, invalidCredentials), the account is not locked, and the password is current.'
    if kind == 'cucm_axl':
        return 'Check: the AXL user name and password are correct, the account is not locked, and the user has the Standard AXL Read Only API Access role.'
    return 'Check the user name and password and that the account is not locked.'


def authz_hint(kind):
    return {'vcenter': 'Assign the service account a read-only role in vCenter (the built-in Read-only role is enough).',
            'ldap': 'Grant the bind account permission to read the search base.',
            'cucm_axl': 'Grant the AXL user the Standard AXL Read Only API Access role.',
            'azure': 'Assign the app registration the built-in Reader role on the subscriptions.',
            'aws': 'Grant the IAM principal ec2:DescribeInstances.'}.get(kind, 'Assign the account read-only access to the system.')


def _http(h, dflt):
    return dflt if h is None or h == 0 or h == '' else h


def texts(kind, code, stage, http):
    sys_ = SYS.get(kind, 'the system')
    if code == 'tls':
        if stage == 'pin-mismatch':
            return {'message': 'TLS: the presented certificate does not match the approved pin.',
                    'hint': 'The appliance certificate changed, or this is not the host you pinned. Confirm the new certificate is genuine before re-pinning.'}
        return {'message': 'TLS: certificate not trusted — review and pin the certificate below.',
                'hint': 'This is a TLS / certificate problem, not a login problem. Check the presented certificate (subject, issuer, validity, SHA-256 fingerprint); if it is the correct appliance certificate, pin it.'}
    if code == 'auth':
        return {'message': 'TLS OK (certificate trusted); %s rejected the credentials (HTTP %s).' % (sys_, _http(http, 401)), 'hint': auth_hint(kind)}
    if code == 'authz':
        return {'message': 'Authenticated, but the account lacks a required read privilege (HTTP %s).' % _http(http, 403), 'hint': authz_hint(kind)}
    if code == 'timeout':
        return {'message': 'Timed out waiting for %s to respond.' % sys_, 'hint': 'Check the host and port, the firewall path from the platform server, and that the service is running.'}
    if code == 'unreachable':
        return {'message': 'Could not reach %s (connection failed).' % sys_, 'hint': 'Check the host / IP and port and the network path from the platform server.'}
    if code == 'config':
        return {'message': 'Connection settings are invalid for %s.' % sys_, 'hint': 'Check the URL / host, port and CA file path.'}
    if code == 'not_supported':
        return {'message': 'This credential type is stored for future use and is not tested.', 'hint': None}
    return {'message': '%s answered, but not as expected.' % sys_,
            'hint': 'The endpoint responded but not in the expected way — verify the URL / path and the system version.'}


def result(kind, latency_ms=None, pin=False, http=None, discovered=None, presented=None, message=None):
    return {'ok': True, 'latency_ms': latency_ms, 'error_class': None, 'stage': 'read', 'http': http,
            'tls': {'trusted': True, 'pinned': bool(pin), 'presented': presented or None},
            'message': message or 'Connected to %s.' % SYS.get(kind, 'the system'), 'hint': None, 'discovered': discovered or None}


def from_error(kind, e, latency_ms=None, pin=False):
    code = class_of(getattr(e, 'code', None))
    presented = getattr(e, 'presented', None) or None
    pm = bool(getattr(e, 'pin_mismatch', False))
    stage = 'pin-mismatch' if code == 'tls' and pm else stage_of(code, getattr(e, 'stage', None))
    http = getattr(e, 'http', None)
    t = texts(kind, code, stage, http)
    trusted = True if code in ('auth', 'authz') else False if code == 'tls' else bool(getattr(e, 'tls_trusted', False))
    return {'ok': False, 'latency_ms': latency_ms, 'error_class': code, 'stage': 'tls' if stage == 'pin-mismatch' else stage, 'http': http,
            'tls': {'trusted': trusted, 'pinned': bool(pin), 'presented': presented, 'pin_mismatch': pm},
            'message': t['message'], 'hint': t['hint'], 'discovered': None}
