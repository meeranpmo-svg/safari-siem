# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
"""Read-only clients for the backup platforms - the Python version of engine/backup-sources.js (same answers, field for
field; tests/backup-python.test.js compares them).

collect(kind, cred, opts) -> {ok, platform, version?, objects: [{name, kind, job, last_attempt, last_status:
  success|warning|failed|running, last_success, size_bytes?, policy?}], jobs: [{id, job, client?, status, start, end,
  error?}]} | {ok: False, error_class, error}  covering the last `days` days (default 7). Only GET requests, plus each
platform's own sign-in POST; guard() refuses anything else before a connection is opened.
  NetBackup (Administration API): https://<primary>:1556/netbackup, API key in Authorization, media type
    application/vnd.netbackup+json;version=<api_version> (default 14.0); GET /admin/jobs, /catalog/images (JSON:API paging).
  Veeam Backup & Replication REST: https://<server>:9419, POST /api/oauth2/token (password grant), x-api-version
    (default 1.1-rev0); GET /api/v1/sessions, /api/v1/restorePoints; POST /api/oauth2/logout at the end.
  Cohesity (public API v1): https://<cluster>, header apiKey or POST /irisservices/api/v1/public/accessTokens;
    GET /irisservices/api/v1/public/protectionRuns.
cred = {target: {base_url, ca_file?, tls_fingerprint?, api_version?, domain?}, secret: {api_key? | username + password}}
"""
import json
import re
import time
import urllib.parse

import httpc
from jscompat import (MISSING, encode_uri_component, form_encode, gt, iso, iso_now_minus, js_round, js_str, low, num, truthy)

DAY = 86400000
CLASSES = ('auth', 'authz', 'timeout', 'unreachable', 'tls', 'config', 'protocol')


class BackupError(Exception):
    def __init__(self, code, message, presented=None, http=None):
        super().__init__(message)
        self.code, self.presented, self.http = code, presented, http


def _cls(e):
    c = getattr(e, 'code', None)
    return c if c in CLASSES else 'protocol'


ALLOW = {
    'netbackup': lambda m, p: m == 'GET' and re.match(r'^/netbackup/(admin/jobs|catalog/images)(\?|$)', p) is not None,
    'veeam': lambda m, p: (m == 'POST' and p in ('/api/oauth2/token', '/api/oauth2/logout')) or (m == 'GET' and re.match(r'^/api/v1/(sessions|restorePoints|serverInfo)(\?|$)', p) is not None),
    'cohesity': lambda m, p: (m == 'POST' and p == '/irisservices/api/v1/public/accessTokens') or (m == 'GET' and re.match(r'^/irisservices/api/v1/public/(protectionRuns|basicClusterInfo)(\?|$)', p) is not None),
}


def guard(kind, method, path):
    if kind in ALLOW and ALLOW[kind](method, path):
        return
    raise BackupError('config', '%s backup reading is read-only; refusing %s %s' % (kind, method, path))


def wrong_type(kind, url):
    """wrongType in engine/backup-sources.js: a 404 on the product's own API path usually means the wrong type was chosen"""
    u = str(url or '')
    if kind != 'netbackup' and re.search(r'/webui\b', u, re.I):
        return ' - this address is the NetBackup web console (/webui): the system looks like a NetBackup primary server, so choose the type NetBackup (its API answers on port 1556)'
    if kind == 'cohesity':
        return ' - the server answered but has no Cohesity API: check the type (NetBackup / Veeam / Cohesity) and that this is the Cohesity cluster address'
    if kind == 'netbackup':
        return ' - the server answered but has no NetBackup API at /netbackup: check the type and that this is the primary server (port 1556)'
    if kind == 'veeam':
        return ' - the server answered but has no Veeam REST API: check the type and that this is the Veeam Backup server (port 9419)'
    return ''


def base_of(url, port):
    b = re.sub(r'/+$', '', str(url or '').strip())
    # https; plain http only for a loopback test server (the HTTP client refuses anything else anyway)
    if not (re.match(r'^https://[A-Za-z0-9.-]+(:\d{1,5})?(/.*)?$', b) or re.match(r'^http://(127\.0\.0\.1|localhost)(:\d{1,5})?(/.*)?$', b)):
        raise BackupError('config', 'the address must be https://<host or IP>[:port]')
    u = urllib.parse.urlsplit(b)
    default = 443 if u.scheme == 'https' else 80
    p = u.port if u.port and u.port != default else None   # the URL API drops a default port, like new URL()
    return '%s://%s:%s' % (u.scheme, u.hostname, p or port)


class _Client:
    def __init__(self, kind, cred, opts, port):
        self.kind, self.t, self.o = kind, cred.get('target') or {}, opts
        self.base = base_of(self.t.get('base_url'), port)

    def call(self, method, path, headers=None, body=None):
        guard(self.kind, method, path)
        h = {'Accept': 'application/json'}
        h.update(headers or {})
        short = path.split('?')[0]
        try:
            r = httpc.request(self.base + path, method, h, body=body, ca_file=self.t.get('ca_file') or None, pin=self.t.get('tls_fingerprint') or None,
                              capture_untrusted=bool(self.o.get('captureUntrusted')), timeout_ms=self.o.get('timeoutMs') or 60000)
        except httpc.HttpcError as e:
            raise BackupError(e.code, str(e), presented=e.presented)
        s = r['status']
        if s == 401:
            raise BackupError('auth', '%s: the credentials were rejected (HTTP 401)' % self.kind, http=401)
        if s == 403:
            raise BackupError('authz', '%s: the account may not read %s (HTTP 403)' % (self.kind, short), http=403)
        if s in (406, 415):
            raise BackupError('protocol', '%s: the server refused the API version / media type (HTTP %d) - set the API version to the one your server shows' % (self.kind, s), http=s)
        if s < 200 or s >= 300:
            # the product's own reason (NetBackup: errorMessage / errorDetails, Veeam: message, Cohesity: message)
            j = r.get('json') if isinstance(r.get('json'), dict) else {}
            det = j.get('errorDetails')
            parts = [j.get('errorMessage'), j.get('message'), j.get('error') if isinstance(j.get('error'), str) else '', '; '.join(js_str(x) for x in det) if isinstance(det, list) else '']
            why = ' - '.join(js_str(x) for x in parts if truthy(x))
            why = re.sub(r'[\x00-\x1f]', ' ', why)[:240]
            raise BackupError('protocol', '%s: %s %s answered HTTP %d%s%s' % (self.kind, method, short, s, (': ' + why) if why else '', wrong_type(self.kind, self.t.get('base_url')) if s == 404 else ''), http=s)
        return r['json']


def _fail(e, t0):
    return {'ok': False, 'error_class': _cls(e), 'error': str(e), 'presented': getattr(e, 'presented', None) or None, 'ms': int((time.time() - t0) * 1000)}


def _now(opts):
    return opts.get('now') or int(time.time() * 1000)


# ---------------------------------------------------------------- NetBackup -----------------------------------------
def _nb_status(a):
    state = js_str(a.get('state') or '').upper()
    if state and state != 'DONE':
        return 'running'
    st = num(a['status']) if 'status' in a else None
    return 'success' if st == 0 else 'warning' if st == 1 else 'failed'   # NetBackup status 1 = partially successful


def netbackup(cred, opts=None):
    opts = opts or {}
    t0 = time.time()
    try:
        sec = cred.get('secret') or {}
        if not sec.get('api_key'):
            raise BackupError('config', 'NetBackup needs an API key')
        c = _Client('netbackup', cred, opts, 1556)
        ver = re.sub(r'[^0-9.]', '', js_str(c.t.get('api_version') or '14.0')) or '14.0'
        H = {'Authorization': sec['api_key'], 'Accept': 'application/vnd.netbackup+json;version=%s' % ver}
        since = iso_now_minus(_now(opts), opts.get('days') or 7)   # with milliseconds, as the NetBackup API documents

        def pages(path, flt, mx, sort=None):
            out, offset = [], 0
            for _ in range(200):
                if len(out) >= mx:
                    break
                q = (('filter=%s&' % encode_uri_component(flt)) if flt else '') + (('sort=%s&' % sort) if sort else '') + 'page%5Blimit%5D=100&page%5Boffset%5D=' + js_str(offset)
                j = c.call('GET', '/netbackup/%s?%s' % (path, q), H) or {}
                d = j.get('data') if isinstance(j, dict) and isinstance(j.get('data'), list) else []
                out.extend(d)
                pg = (j.get('meta') or {}).get('pagination') if isinstance(j, dict) and isinstance(j.get('meta'), dict) else None
                nxt = pg.get('next') if isinstance(pg, dict) else None
                if not d or (truthy(pg) and (nxt is None or not gt(nxt, offset))) or (not truthy(pg) and len(d) < 100):
                    break
                offset = nxt if truthy(pg) and nxt is not None else offset + len(d)
                if not flt and sort and d:   # newest first: stop past the window
                    last = iso(((d[-1] or {}).get('attributes') or {}).get(sort.lstrip('-')))
                    if last is not None and last < since:
                        break
            return out

        # NetBackup versions differ in the filters they accept (HTTP 400): precise filter, then time only, then newest first
        def try_pages(path, variants, mx):
            last = None
            for v in variants:
                try:
                    return pages(path, v[0], mx, v[1] if len(v) > 1 else None)
                except BackupError as e:
                    if getattr(e, 'http', None) != 400:
                        raise
                    last = e
            raise last

        def in_win(v):
            x = iso(v)
            return x is None or x >= since
        jobs_raw = [x for x in try_pages('admin/jobs', [["jobType eq 'BACKUP' and startTime ge %s" % since], ['startTime ge %s' % since], ['', '-startTime']], opts.get('maxJobs') or 20000)
                    if (not truthy((x.get('attributes') or {}).get('jobType')) or js_str((x.get('attributes') or {}).get('jobType')).upper() == 'BACKUP') and in_win((x.get('attributes') or {}).get('startTime'))]
        images = []
        try:
            images = [x for x in try_pages('catalog/images', [['backupTime ge %s' % since], ['', '-backupTime']], opts.get('maxImages') or 20000) if in_win((x.get('attributes') or {}).get('backupTime'))]
        except BackupError as e:
            if e.code != 'authz' and getattr(e, 'http', None) != 400:   # the images are a supplement to the jobs
                raise

        def job(x):
            a = x.get('attributes') or {}
            kb = a.get('kilobytesTransferred')
            return {'id': js_str(a.get('jobId') or x.get('id') or ''), 'job': a.get('policyName') or '', 'schedule': a.get('scheduleName') or '',
                    'client': a.get('clientName') or '',
                    'display_name': js_str(a.get('assetDisplayableName'))[:200] if truthy(a.get('assetDisplayableName')) and a.get('assetDisplayableName') != a.get('clientName') else '',
                    'status': _nb_status(a), 'code': num(a['status']) if a.get('status') is not None else None,
                    'start': iso(a.get('startTime')), 'end': iso(a.get('endTime')), 'size_bytes': num(kb) * 1024 if truthy(kb) and num(kb) is not None else None}
        jobs = [job(x) for x in jobs_raw]
        objs = {}

        def get(name):
            k = low(name)
            if k not in objs:
                objs[k] = {'name': name, 'kind': 'client', 'job': '', 'last_attempt': None, 'last_status': None, 'last_success': None, 'size_bytes': None, 'policy': ''}
            return objs[k]
        for j in sorted([x for x in jobs if x['client']], key=lambda x: js_str(x['start'])):
            ob = get(j['client'])
            ob['job'] = j['job']
            ob['policy'] = j['job']
            if j['display_name']:   # a VM backup's client is the VM uuid; NetBackup 9+ also sends the VM's name
                ob['display_name'] = j['display_name']
            if j['status'] != 'running':
                ob['last_attempt'] = j['end'] or j['start']
                ob['last_status'] = j['status']
            elif not ob['last_status']:
                ob['last_status'] = 'running'
            if j['status'] in ('success', 'warning') and (not ob['last_success'] or gt(j['end'], ob['last_success'])):
                ob['last_success'] = j['end'] or j['start']
                ob['size_bytes'] = j['size_bytes']
        for x in images:
            a = x.get('attributes') or {}
            if not a.get('clientName'):
                continue
            ob = get(a['clientName'])
            bt = iso(a.get('backupTime'))
            if bt and (not ob['last_success'] or gt(bt, ob['last_success'])):
                ob['last_success'] = bt
                if not ob['policy']:
                    ob['policy'] = a.get('policyName') or ''
                if truthy(a.get('kilobytes')):
                    ob['size_bytes'] = (num(a['kilobytes']) or 0) * 1024 if num(a['kilobytes']) is not None else None
            if not ob['last_status']:
                ob['last_status'] = 'success'
        return {'ok': True, 'platform': 'netbackup', 'api_version': ver, 'objects': list(objs.values()), 'jobs': jobs, 'ms': int((time.time() - t0) * 1000)}
    except Exception as e:
        return _fail(e, t0)


# ---------------------------------------------------------------- Veeam ---------------------------------------------
def _veeam_status(r):
    v = (r.get('result') or r) if isinstance(r, dict) else r
    s = low(v or '')
    if s == 'success':
        return 'success'
    if s == 'warning':
        return 'warning'
    if s == 'failed':
        return 'failed'
    return 'running' if s == 'none' or not s else s


def veeam(cred, opts=None):
    opts = opts or {}
    t0 = time.time()
    c, token = None, None
    try:
        sec = cred.get('secret') or {}
        if not sec.get('username') or not sec.get('password'):
            raise BackupError('config', 'Veeam needs a user name and password')
        c = _Client('veeam', cred, opts, 9419)
        ver = re.sub(r'[^0-9A-Za-z.-]', '', js_str(c.t.get('api_version') or '1.1-rev0'))
        form = form_encode([('grant_type', 'password'), ('username', sec['username']), ('password', sec['password'])])
        tok = c.call('POST', '/api/oauth2/token', {'x-api-version': ver, 'Content-Type': 'application/x-www-form-urlencoded'}, form)
        token = tok.get('access_token') if isinstance(tok, dict) else None
        if not token:
            raise BackupError('auth', 'Veeam returned no access token')
        H = {'x-api-version': ver, 'Authorization': 'Bearer %s' % token}
        since = iso_now_minus(_now(opts), opts.get('days') or 7)

        def pages(path, mx):
            out, skip = [], 0
            while skip < mx:
                j = c.call('GET', '%s%sskip=%d&limit=500' % (path, '&' if '?' in path else '?', skip), H) or {}
                d = j.get('data') if isinstance(j, dict) and isinstance(j.get('data'), list) else []
                out.extend(d)
                pgn = j.get('pagination') if isinstance(j, dict) else None
                total = num(pgn.get('total', MISSING) if 'total' in pgn else MISSING) if isinstance(pgn, dict) else None
                if len(d) < 500 or (total and len(out) >= total):
                    break
                skip += 500
            return out
        sess = pages('/api/v1/sessions?typeFilter=BackupJob&createdAfterFilter=%s&orderColumn=CreationTime&orderAsc=false' % encode_uri_component(since), opts.get('maxJobs') or 20000)
        rps = pages('/api/v1/restorePoints?createdAfterFilter=%s&orderColumn=CreationTime&orderAsc=false' % encode_uri_component(since), opts.get('maxImages') or 50000)
        jobs = [{'id': s.get('id'), 'job': s.get('name') or '', 'status': 'running' if s.get('state') and low(s.get('state')) != 'stopped' else _veeam_status(s.get('result')),
                 'start': iso(s.get('creationTime')), 'end': iso(s.get('endTime')),
                 'error': ((s.get('result') or {}).get('message') if isinstance(s.get('result'), dict) else None) or None} for s in sess]
        objs = {}
        for r in rps:
            k = low(r.get('name'))
            if not k:
                continue
            ct = iso(r.get('creationTime'))
            ob = objs.get(k) or {'name': r.get('name'), 'kind': 'vm' if low(r.get('platformName')) in ('vmware', 'hyperv') else 'object', 'job': '', 'last_attempt': None,
                                 'last_status': 'success', 'last_success': None, 'size_bytes': None, 'policy': ''}
            if ct and (not ob['last_success'] or gt(ct, ob['last_success'])):
                ob['last_success'] = ct
                ob['last_attempt'] = ct
            objs[k] = ob
        last_by_job = {}   # a failed run: the job's last session failed after the object's newest restore point
        for j in jobs:
            if j['status'] != 'running' and (j['job'] not in last_by_job or gt(j['start'], last_by_job[j['job']]['start'])):
                last_by_job[j['job']] = j
        return {'ok': True, 'platform': 'veeam', 'api_version': ver, 'objects': list(objs.values()), 'jobs': jobs,
                'failed_jobs': [j['job'] for j in last_by_job.values() if j['status'] == 'failed'], 'ms': int((time.time() - t0) * 1000)}
    except Exception as e:
        return _fail(e, t0)
    finally:
        if c is not None and token:
            try:
                c.call('POST', '/api/oauth2/logout', {'x-api-version': js_str(c.t.get('api_version') or '1.1-rev0'), 'Authorization': 'Bearer %s' % token}, '')
            except Exception:
                pass


# ---------------------------------------------------------------- Cohesity ------------------------------------------
def _coh_status(s):
    v = re.sub(r'^k', '', js_str(s or '')).lower()
    if v == 'success':
        return 'success'
    if v == 'warning':
        return 'warning'
    return 'failed' if re.search(r'fail|cancel', v) else 'running'


def _us(v):
    return iso(js_round(v / 1000)) if v else None


def cohesity(cred, opts=None):
    opts = opts or {}
    t0 = time.time()
    try:
        c = _Client('cohesity', cred, opts, 443)
        sec = cred.get('secret') or {}
        if sec.get('api_key'):
            H = {'apiKey': sec['api_key']}
        elif sec.get('username') and sec.get('password'):
            j = c.call('POST', '/irisservices/api/v1/public/accessTokens', {'Content-Type': 'application/json'},
                       json.dumps({'username': sec['username'], 'password': sec['password'], 'domain': c.t.get('domain') or 'LOCAL'}, separators=(',', ':'), ensure_ascii=False))
            if not isinstance(j, dict) or not j.get('accessToken'):
                raise BackupError('auth', 'Cohesity returned no access token')
            H = {'Authorization': '%s %s' % (j.get('tokenType') or 'Bearer', j['accessToken'])}
        else:
            raise BackupError('config', 'Cohesity needs an API key, or a user name and password')
        since_us = (_now(opts) - (opts.get('days') or 7) * DAY) * 1000
        runs = c.call('GET', '/irisservices/api/v1/public/protectionRuns?startTimeUsecs=%s&numRuns=%s&excludeTasks=false&excludeNonRestoreableRuns=false'
                      % (js_str(since_us), js_str(opts.get('maxJobs') or 5000)), H) or []
        jobs, objs = [], {}
        for r in runs if isinstance(runs, list) else []:
            b = r.get('backupRun') or {}
            st = b.get('stats') or {}
            start, end = _us(st.get('startTimeUsecs')), _us(st.get('endTimeUsecs'))
            jobs.append({'id': js_str(r.get('jobId') or '') + ':' + js_str(b.get('jobRunId') or ''), 'job': r.get('jobName') or '', 'status': _coh_status(b.get('status')),
                         'start': start, 'end': end, 'error': (b.get('error') or '') or None})
            for sb in b.get('sourceBackupStatus') or []:
                src = sb.get('source') or {}
                name = (src.get('displayName') or src.get('name')) or ''
                if not name:
                    continue
                k, s, sst = low(name), _coh_status(sb.get('status')), sb.get('stats') or {}
                at = _us(sst.get('endTimeUsecs')) if sst.get('endTimeUsecs') else end
                ob = objs.get(k) or {'name': name, 'kind': 'object', 'job': r.get('jobName') or '', 'last_attempt': None, 'last_status': None, 'last_success': None,
                                     'size_bytes': None, 'policy': r.get('jobName') or ''}
                if s != 'running' and (not ob['last_attempt'] or (at and gt(at, ob['last_attempt']))):
                    ob['last_attempt'] = at
                    ob['last_status'] = s
                    ob['job'] = r.get('jobName') or ob['job']
                if not ob['last_status']:
                    ob['last_status'] = s
                if s in ('success', 'warning') and at and (not ob['last_success'] or gt(at, ob['last_success'])):
                    ob['last_success'] = at
                    if sst.get('totalLogicalBackupSizeBytes'):
                        ob['size_bytes'] = num(sst['totalLogicalBackupSizeBytes'])
                objs[k] = ob
        return {'ok': True, 'platform': 'cohesity', 'objects': list(objs.values()), 'jobs': jobs, 'ms': int((time.time() - t0) * 1000)}
    except Exception as e:
        return _fail(e, t0)


def test(kind, cred, opts=None):
    fn = {'netbackup': netbackup, 'veeam': veeam, 'cohesity': cohesity}.get(kind)
    if not fn:
        return {'ok': False, 'error_class': 'config', 'error': 'unknown platform'}
    o = {'captureUntrusted': True, 'days': 1, 'maxJobs': 200, 'maxImages': 200}
    o.update({k: v for k, v in (opts or {}).items() if v is not None})
    r = fn(cred, o)
    if not r.get('ok'):
        return r
    return {'ok': True, 'message': 'Connected: %d backup runs and %d protected objects in the last 24 hours.' % (len(r['jobs']), len(r['objects']))}
