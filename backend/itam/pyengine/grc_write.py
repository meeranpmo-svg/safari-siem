# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
"""GRC - the WRITES of policy drafts and DR drills, migration step 9c (docs/PYTHON-MIGRATION.md), decided here exactly like
engine/grc.js; Node.js commits (the store keeps ONE writer - see roles_write.py for the pattern). Each answer is
{puts, removes, result} or {refuse: {status, error}, puts} - a refusal can still carry a put, because Node.js takes the next
draft / drill number BEFORE it checks the input, so a refused new record still uses a number up; the two engines must
number alike. Node.js supplies `at` (the module's clock) and `wall` (Date.now(), which the "approval withdrawn" notes use).
The four-eyes rules are here too: whoever wrote or changed a draft does not approve it; whoever ran a drill does not sign
it off; a change after approval / sign-off withdraws it.
Standard library only (Python 3.8+).
"""
import re
from datetime import datetime, timezone

from grc_read import DR_TYPES, enrich, _strip_doc
from jscompat import js_round, num
from roles_write import JS_WS, Refuse, _utf16, js_str
from store import reader as store_reader

_VER = re.compile(r'^(\d+)\.(\d+)$', re.ASCII)
_AUTHOR = re.compile(r'^(created|edited|document uploaded)')


def S(v):
    return 'undefined' if v is _U else js_str(v)


_U = object()


def g(o, k):
    return o.get(k, _U) if isinstance(o, dict) else _U


def T(v):
    if v is _U or v is None or v is False or v == '':
        return False
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        return v != 0 and v == v
    return True


def sl(v, n):
    """String(v).slice(0, n)"""
    return _utf16(S(v), n)


def trim(t):
    return t.strip(JS_WS)


def norm_user(u):
    return trim('' if u is None or u is _U else js_str(u)).lower()


def same_user(a, b):
    return bool(norm_user(a)) and norm_user(a) == norm_user(b)


def iso_ms(ms):
    t = datetime.fromtimestamp(ms / 1000, tz=timezone.utc)
    return t.strftime('%Y-%m-%dT%H:%M:%S.') + '%03dZ' % (t.microsecond // 1000)


def bump(v):
    m = _VER.match(S(v) if T(v) else '0.1')
    return '0.2' if not m else m.group(1) + '.' + str(int(m.group(2)) + 1)


def _num0(v):
    """Number(v) || 0"""
    n = num(v)
    return n if n else 0


def _clampnum(v, lo, hi):
    n = _num0(v)
    return max(lo, min(hi, n)) if hi is not None else max(lo, n)


class Ctx:
    def __init__(self, r, col):
        st = store_reader(r['dir'])
        self.col, self.counters = st.collection(col), st.collection('counters')
        self.at, self.wall = r.get('at'), r.get('wall')
        who = r.get('who') or {}
        self.user = who.get('user') or ''
        self.puts, self.removes = [], []
        self.colname = col

    def next_id(self, prefix, name):
        cur = (self.counters.get(name) or {}).get('n') or 0
        n = cur + 1
        self.puts.append({'c': 'counters', 'o': {'id': name, 'n': n}})
        return '%s-%s' % (prefix, str(n).rjust(4, '0'))

    def refuse(self, status, error):
        e = Refuse(status, error)
        e.puts = list(self.puts)
        return e

    def hist(self, rec, what, at=None):
        rec['history'] = (rec.get('history') if isinstance(rec.get('history'), list) else []) + [{'at': self.at if at is None else at, 'by': self.user, 'what': what}]


def _reopen_draft(c, rec, why):
    if rec.get('status') in ('approved', 'in-review'):
        c.hist(rec, 'back to draft - ' + why + ' after ' + rec['status'] + (' (was approved by ' + S(rec['approved_by']) + ')' if T(g(rec, 'approved_by')) else ''), c.wall)
        rec['status'] = 'draft'
        rec['approved_by'] = None
        rec['approved_at'] = None


def _reopen_drill(c, rec, why):
    so = rec.get('signoff')
    if isinstance(so, dict) and T(g(so, 'by')):
        c.hist(rec, 'sign-off by ' + S(so['by']) + ' withdrawn - ' + why + ' after sign-off', c.wall)
        rec['signoff'] = None


def _lines(v):
    """(Array.isArray(v) ? v : String(v || '').split('\\n')).map((s) => String(s).trim()).filter(Boolean)"""
    items = v if isinstance(v, list) else (S(v) if T(v) else '').split('\n')
    return [t for t in (trim(js_str(x)) for x in items) if t]


def _doc(c, inp):
    fn = sl(g(inp, 'filename') if T(g(inp, 'filename')) else '', 200)
    if not fn:
        raise c.refuse(400, 'a filename is required')
    b64 = inp.get('content_b64') if isinstance(inp.get('content_b64'), str) else ''
    inline = bool(b64) and len(b64) <= 1300000
    size = num(g(inp, 'size')) if g(inp, 'size') is not _U else None
    d = {'filename': fn, 'size': size if size else (js_round(len(b64) * 0.75) if b64 else 0), 'sha256': sl(g(inp, 'sha256') if T(g(inp, 'sha256')) else '', 64).lower(),
         'uploaded_by': c.user, 'uploaded_at': c.at, 'stored': 'inline' if inline else 'by-reference'}
    if inline:
        d['content_b64'] = b64
    return fn, d, inline


# ---- drafts ---------------------------------------------------------------------------------------------------------
def draft_put(r):
    c, inp = Ctx(r, 'grc_drafts'), r.get('body') or {}
    t = c.at
    d = c.col.get(inp['id']) if T(g(inp, 'id')) else None
    if T(g(inp, 'id')) and d is None:
        raise c.refuse(404, 'draft not found')
    new = d is None
    rec = dict(d) if d else {'id': c.next_id('DRAFT', 'grc_drafts'), 'status': 'draft', 'version': '0.1', 'created': t, 'by': c.user, 'history': [], 'document': None}
    for k in ('doc_id', 'title', 'sub_code', 'domain', 'owner', 'frameworks', 'purpose', 'body', 'control', 'supersedes'):
        if g(inp, k) is not _U:
            rec[k] = sl(inp[k], 40000)
    if g(inp, 'requirements') is not _U:
        rec['requirements'] = _lines(inp['requirements'])[:200]
    if not trim(S(rec.get('title')) if T(g(rec, 'title')) else ''):
        raise c.refuse(400, 'a policy title is required')
    rec['updated'] = t
    if not new:
        _reopen_draft(c, rec, 'edited')
    rec['version'] = '0.1' if new else bump(d.get('version', _U))
    rec['history'] = ((d.get('history') if isinstance(d.get('history'), list) else []) if d else []) + [{'at': t, 'by': c.user, 'what': 'created' if new else 'edited'}]
    c.puts.append({'c': 'grc_drafts', 'o': rec})
    return {'puts': c.puts, 'removes': [], 'result': _strip_doc(rec, 'document')}


def draft_status(r):
    c = Ctx(r, 'grc_drafts')
    d = c.col.get(r.get('id'))
    if d is None:
        raise c.refuse(404, 'draft not found')
    d = dict(d)
    status = r.get('status')
    if status not in ('draft', 'in-review', 'approved', 'rejected'):
        raise c.refuse(400, 'status must be draft, in-review, approved or rejected')
    if status == 'approved':
        authors = [d.get('by')] + [h.get('by') for h in (d.get('history') or []) if isinstance(h, dict) and _AUTHOR.match(S(h.get('what', _U)))]
        if any(same_user(a, c.user) for a in authors):
            raise c.refuse(403, 'four eyes: you wrote or changed this draft - another administrator must approve it')
    d['status'] = status
    if status == 'approved':
        d['version'] = '1.0' if re.match(r'^0\.', S(d['version']) if T(g(d, 'version')) else '') else d.get('version')
        d['approved_by'] = c.user
        d['approved_at'] = c.at
    d['updated'] = c.at
    c.hist(d, 'status → ' + status)
    c.puts.append({'c': 'grc_drafts', 'o': d})
    return {'puts': c.puts, 'removes': [], 'result': _strip_doc(d, 'document')}


def draft_upload(r):
    c, inp = Ctx(r, 'grc_drafts'), r.get('body') or {}
    d = c.col.get(r.get('id'))
    if d is None:
        raise c.refuse(404, 'draft not found')
    d = dict(d)
    fn, doc, inline = _doc(c, inp)
    d['document'] = doc
    _reopen_draft(c, d, 'document replaced')
    d['updated'] = c.at
    d['version'] = bump(d.get('version', _U))
    c.hist(d, 'document uploaded: ' + fn + (' (' + doc['sha256'][:12] + '…)' if doc['sha256'] else '') + ('' if inline else ' — by reference'))
    c.puts.append({'c': 'grc_drafts', 'o': d})
    return {'puts': c.puts, 'removes': [], 'result': _strip_doc(d, 'document')}


def draft_delete(r):
    c = Ctx(r, 'grc_drafts')
    if c.col.get(r.get('id')) is None:
        raise c.refuse(404, 'draft not found')
    return {'puts': [], 'removes': [{'c': 'grc_drafts', 'id': r.get('id')}], 'result': {'ok': True}}


# ---- drills ---------------------------------------------------------------------------------------------------------
def _null_or_min(v):
    return None if v == '' or v is None or v is _U else max(0, _num0(v))


def drill_put(r):
    c, inp = Ctx(r, 'grc_drills'), r.get('body') or {}
    t = c.at
    d = c.col.get(inp['id']) if T(g(inp, 'id')) else None
    if T(g(inp, 'id')) and d is None:
        raise c.refuse(404, 'drill not found')
    new = d is None
    rec = dict(d) if d else {'id': c.next_id('DR', 'grc_drills'), 'status': 'planned', 'result': None, 'executed': None, 'created': t, 'by': c.user, 'history': [],
                             'evidence': None, 'findings': [], 'actions': [], 'rto_target_min': None, 'rto_actual_min': None, 'rpo_target_min': None, 'rpo_actual_min': None}
    for k in ('title', 'system', 'scope_detail', 'objective', 'owner', 'participants', 'sama_ref', 'sama_area'):
        if g(inp, k) is not _U:
            rec[k] = sl(inp[k], 4000)
    if g(inp, 'type') is not _U:
        if not (isinstance(inp['type'], str) and inp['type'] in DR_TYPES):
            raise c.refuse(400, 'type must be one of: ' + ', '.join(DR_TYPES))
        rec['type'] = inp['type']
    if not T(g(rec, 'type')):
        rec['type'] = 'failover'
    if g(inp, 'scheduled') is not _U:
        rec['scheduled'] = sl(inp['scheduled'], 40)
    if g(inp, 'frequency_months') is not _U:
        rec['frequency_months'] = _clampnum(inp['frequency_months'], 0, 60)
    if rec.get('frequency_months') is None:
        rec['frequency_months'] = 12
    for k in ('rto_target_min', 'rpo_target_min'):
        if g(inp, k) is not _U:
            rec[k] = _null_or_min(inp[k])
    if not trim(S(rec['title']) if T(g(rec, 'title')) else ''):
        raise c.refuse(400, 'a drill title is required')
    if not trim(S(rec['system']) if T(g(rec, 'system')) else ''):
        raise c.refuse(400, 'the system / service in scope is required')
    if not new:
        _reopen_drill(c, rec, 'drill details edited')
    rec['updated'] = t
    rec['history'] = ((d.get('history') if isinstance(d.get('history'), list) else []) if d else []) + [{'at': t, 'by': c.user, 'what': 'planned' if new else 'edited'}]
    c.puts.append({'c': 'grc_drills', 'o': rec})
    return {'puts': c.puts, 'removes': [], 'result': enrich(rec)}


def _drill(c, r):
    d = c.col.get(r.get('id'))
    if d is None:
        raise c.refuse(404, 'drill not found')
    return dict(d)


def drill_result(r):
    c, inp = Ctx(r, 'grc_drills'), r.get('body') or {}
    d = _drill(c, r)
    result = inp.get('result')
    if result not in ('pass', 'partial', 'fail'):
        raise c.refuse(400, 'result must be pass, partial or fail')
    d['result'] = result
    d['executed'] = sl(inp['executed'] if T(g(inp, 'executed')) else '', 40) or iso_ms(c.at)[:10]
    d['status'] = 'completed'
    d['executed_by'] = c.user
    for k in ('rto_actual_min', 'rpo_actual_min'):
        if g(inp, k) is not _U:
            d[k] = _null_or_min(inp[k])
    if g(inp, 'findings') is not _U:
        d['findings'] = _lines(inp['findings'])[:100]
    if g(inp, 'actions') is not _U:
        d['actions'] = _lines(inp['actions'])[:100]
    if g(inp, 'summary') is not _U:
        d['result_summary'] = sl(inp['summary'], 8000)
    d['signoff'] = None
    d['updated'] = c.at
    c.hist(d, 'result recorded: ' + result + (' (' + S(d['executed']) + ')' if T(d.get('executed')) else ''))
    c.puts.append({'c': 'grc_drills', 'o': d})
    return {'puts': c.puts, 'removes': [], 'result': enrich(d)}


def drill_signoff(r):
    c, inp = Ctx(r, 'grc_drills'), r.get('body') or {}
    d = _drill(c, r)
    if d.get('status') != 'completed':
        raise c.refuse(400, 'only a completed drill can be signed off')
    by = c.user
    independent = (not same_user(by, d['executed_by'])) if by and T(g(d, 'executed_by')) else None
    if independent is False:
        raise c.refuse(403, 'the drill was run by ' + by + ' - another administrator must sign it off')
    d['signoff'] = {'by': by, 'at': c.at, 'note': sl(inp['note'] if T(g(inp, 'note')) else '', 2000), 'independent': independent}
    d['updated'] = c.at
    c.hist(d, 'signed off')
    c.puts.append({'c': 'grc_drills', 'o': d})
    return {'puts': c.puts, 'removes': [], 'result': enrich(d)}


def drill_cancel(r):
    c, inp = Ctx(r, 'grc_drills'), r.get('body') or {}
    d = _drill(c, r)
    d['status'] = 'cancelled'
    d['updated'] = c.at
    c.hist(d, 'cancelled' + (': ' + sl(inp['note'], 400) if T(g(inp, 'note')) else ''))
    c.puts.append({'c': 'grc_drills', 'o': d})
    return {'puts': c.puts, 'removes': [], 'result': enrich(d)}


def drill_upload(r):
    c, inp = Ctx(r, 'grc_drills'), r.get('body') or {}
    d = _drill(c, r)
    fn, ev, inline = _doc(c, inp)
    d['evidence'] = ev
    _reopen_drill(c, d, 'evidence replaced')
    d['updated'] = c.at
    c.hist(d, 'evidence attached: ' + fn + ('' if inline else ' — by reference'))
    c.puts.append({'c': 'grc_drills', 'o': d})
    return {'puts': c.puts, 'removes': [], 'result': enrich(d)}


def drill_delete(r):
    c = Ctx(r, 'grc_drills')
    if c.col.get(r.get('id')) is None:
        raise c.refuse(404, 'drill not found')
    return {'puts': [], 'removes': [{'c': 'grc_drills', 'id': r.get('id')}], 'result': {'ok': True}}


def _guard(fn):
    def run(r):
        try:
            return fn(r)
        except Refuse as e:
            return {'refuse': {'status': e.status, 'error': e.error}, 'puts': getattr(e, 'puts', []), 'removes': []}
    return run


OPS = {'grc.draft_put': _guard(draft_put), 'grc.draft_status': _guard(draft_status), 'grc.draft_upload': _guard(draft_upload), 'grc.draft_delete': _guard(draft_delete),
       'grc.drill_put': _guard(drill_put), 'grc.drill_result': _guard(drill_result), 'grc.drill_signoff': _guard(drill_signoff), 'grc.drill_cancel': _guard(drill_cancel),
       'grc.drill_upload': _guard(drill_upload), 'grc.drill_delete': _guard(drill_delete)}
