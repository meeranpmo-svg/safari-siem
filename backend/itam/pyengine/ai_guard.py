# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
"""The AI guard rails in Python - migration step 9j-a (docs/PYTHON-MIGRATION.md): engine/ai/sanitise.js (what is masked
before anything leaves for the model: e-mail, IBAN, card, KSA mobile, 10-digit IDs, the IPv4 host octet, the
administrator's redaction terms) and engine/ai/validate.js (the model's JSON parsed, coerced, and every reference the
model was not given dropped). The model call itself - it carries the API key - stays in Node.js.
  ai.sanitise_pair  {system, prompt, redact_terms}   → {system, prompt, system_sha256, prompt_sha256}
  ai.validate       {kind, text, ctx, res}           → {ai, validation}
The engine (engine/ai/guard-py.js) also runs the Node.js function and uses this answer only when the two are identical;
a difference is counted and the Node.js answer used - a privacy control is never weakened by a port. A parse error whose
wording is V8's own (JSON.parse's message) answers {node: true}.
Standard library only (Python 3.8+).
"""
import hashlib
import json
import re

from assets_write import NodeDecides, _js_number, _str_to_num, _trim, _utf16
from jscompat import truthy
from roles_write import JS_WS

# ---- sanitise ---------------------------------------------------------------------------------------------------------
# JavaScript regexes without the u flag: \b, \d and the classes are ASCII - re.A gives exactly that
RULES = [
    (re.compile(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+', re.A), '[email]'),
    (re.compile(r'\bSA\d{2}(?: ?\d{4}){5}\b', re.A | re.I), '[iban]'),
    (re.compile(r'\b\d{4}(?:[ -]\d{4}){2,3}(?:[ -]\d{1,3})?\b', re.A), '[card]'),
    (re.compile(r'\b\d{13,19}\b', re.A), '[card]'),
    (re.compile(r'(?:\+966|\b00966|\b966|\b0)[ -]?5\d(?:[ -]?\d){7}\b', re.A), '[phone]'),
    (re.compile(r'\b\d{10}\b', re.A), '[id]'),
    (re.compile(r'\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b', re.A), '\\1.\\2.\\3.•'),
]


def _u16len(t):
    return len(t) + sum(1 for ch in t if ord(ch) > 0xFFFF)


def terms_regex(terms):
    """termsRegex(): whole words (no letter, digit or _ on either side), longest first, case-insensitive (Unicode)"""
    lst = []
    for t in terms if isinstance(terms, list) else []:
        s = _trim((t if isinstance(t, str) else _to_s(t)) if truthy(t) else '')   # String(t || '').trim()
        if 2 <= _u16len(s) <= 100:
            lst.append(s)
    if not lst:
        return None
    lst = sorted(lst, key=lambda x: -_u16len(x))   # Array.prototype.sort is stable, as sorted() is
    # Python's Unicode \\w is [\\p{L}\\p{N}_] (str.isalnum: categories L* and N*), the class the JavaScript lookarounds use
    return re.compile('(?<!\\w)(?:' + '|'.join(re.escape(x) for x in lst) + ')(?!\\w)', re.I)


def _to_s(v):
    if isinstance(v, bool):
        return 'true' if v else 'false'
    if isinstance(v, (int, float)):
        return _js_number(v)
    if isinstance(v, list):
        return ','.join('' if x is None else _to_s(x) for x in v)
    if isinstance(v, dict):
        return '[object Object]'
    return str(v)


def sanitise(text, terms_re):
    s = '' if text is None else (text if isinstance(text, str) else _to_s(text))
    for rx, rep in RULES:
        s = rx.sub(rep, s)
    if terms_re is not None:
        s = terms_re.sub('[redacted]', s)
    return s


def _sha(s):
    # Node.js hashes a string as UTF-8 with each lone surrogate replaced by U+FFFD
    return hashlib.sha256(re.sub('[\ud800-\udfff]', '�', s).encode('utf-8')).hexdigest()


def sanitise_pair(r):
    tre = terms_regex(r.get('redact_terms'))
    ss, sp = sanitise(r.get('system'), tre), sanitise(r.get('prompt'), tre)
    return {'system': ss, 'prompt': sp, 'system_sha256': _sha(ss), 'prompt_sha256': _sha(sp)}


# ---- validate ---------------------------------------------------------------------------------------------------------
class _ParseError(Exception):
    pass


def _const(name):
    raise _ParseError(name)   # JSON.parse has no NaN / Infinity literals


def _int(s):
    v = int(s)
    return v if abs(v) < 2 ** 53 else float(s)   # JSON.parse reads every number as a double


def _parse(s):
    try:
        return True, json.loads(s, parse_constant=_const, parse_int=_int)
    except (ValueError, _ParseError, RecursionError):
        return False, None


_TRAIL = re.compile(',[' + re.escape(JS_WS) + ']*([}\\]])')


def try_parse(s):
    ok, v = _parse(s)
    if ok:
        return True, v
    return _parse(_TRAIL.sub('\\1', s).replace('“', '"').replace('”', '"'))


def first_balanced(s):
    start = s.find('{')
    if start < 0:
        return None
    depth, in_str, esc = 0, False, False
    for i in range(start, len(s)):
        ch = s[i]
        if in_str:
            if esc:
                esc = False
            elif ch == '\\':
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == '{':
            depth += 1
        elif ch == '}':
            depth -= 1
            if depth == 0:
                return s[start:i + 1]
    return None


_FENCE = re.compile('```(?:json|JSON)?[' + re.escape(JS_WS) + ']*\\n?([\\s\\S]*?)```')


def extract_json(text):
    s = text if isinstance(text, str) else ('' if not text else _to_s(text))
    if not _trim(s):
        return None, None, 'the model returned an empty answer'
    for m in _FENCE.finditer(s):
        body = _trim(m.group(1))
        if not body.startswith('{'):
            continue
        ok, v = try_parse(body)
        if ok and isinstance(v, dict):
            return v, 'fence', None
    b = first_balanced(s)
    if b is not None:
        ok, v = try_parse(b)
        if ok and isinstance(v, dict):
            return v, 'brace', None
        if not ok:
            raise NodeDecides()   # the error names JSON.parse's own message: V8's wording
        return None, None, 'the JSON object could not be parsed (undefined)'
    return None, None, 'no JSON object found in the answer'


TYPES = ['server', 'vm', 'workstation', 'laptop', 'network', 'printer', 'phone', 'storage', 'ups', 'mobile', 'peripheral', 'software', 'licence', 'other']
REL_TYPES = ['runs_on', 'connected_to', 'depends_on', 'member_of', 'installed_on']
_U = object()


def _g(o, k):
    return o.get(k, _U) if isinstance(o, dict) else _U


def _or(a, b):
    return a if (a is not _U and a is not None and a is not False and a != '' and not (isinstance(a, (int, float)) and not isinstance(a, bool) and (a == 0 or a != a))) else b


def arr(v):
    if v is _U or v is None or v == '':
        return []
    return v if isinstance(v, list) else [v]


def st(v, mx=4000):
    if v is _U or v is None:
        return ''
    t = v if isinstance(v, str) else _to_s(v) if isinstance(v, (bool, int, float)) else ''
    return _utf16(_trim(t), mx)


def _number(v):
    if v is _U:
        return None
    if v is None:
        return 0
    if isinstance(v, bool):
        return 1 if v else 0
    if isinstance(v, (int, float)):
        return v if v == v and v not in (float('inf'), float('-inf')) else None
    if isinstance(v, (str, list)):
        n = _str_to_num(_to_s(v))
        return None if n is None or n in (float('inf'), float('-inf')) else n
    return None


def conf(v):
    n = _number(v)
    return None if n is None else max(0, min(1, n))


def en(v, allowed, dflt):
    k = st(v).lower()
    return k if k in allowed else dflt


def v_classify(o, ctx, W):
    ids = set(x for x in (ctx.get('ids') or []) if isinstance(x, str))
    d = {'assets': [], 'merges': []}
    for a in [x for x in arr(_g(o, 'assets')) if isinstance(x, dict)]:
        ref = st(_or(_g(a, 'ref'), _g(a, 'id')), 80)
        if ref not in ids:
            W.append('classify: ref "%s" was not supplied — dropped' % _utf16(ref, 40))
            continue
        d['assets'].append({'ref': ref, 'type': en(_g(a, 'type'), TYPES, None), 'vendor': st(_g(a, 'vendor'), 200) or None, 'model': st(_g(a, 'model'), 200) or None,
                            'category': st(_g(a, 'category'), 120) or None, 'confidence': conf(_g(a, 'confidence')), 'rationale': st(_g(a, 'rationale'), 2000)})
    for mg in [x for x in arr(_g(o, 'merges')) if isinstance(x, dict)]:
        keep, dup = st(_g(mg, 'keep'), 80), st(_or(_g(mg, 'duplicate'), _g(mg, 'dup')), 80)
        if keep not in ids or dup not in ids or keep == dup:
            W.append('classify: a merge references an id that was not supplied — dropped')
            continue
        d['merges'].append({'keep': keep, 'duplicate': dup, 'confidence': conf(_g(mg, 'confidence')), 'rationale': st(_g(mg, 'rationale'), 2000)})
    return d


def v_relate(o, ctx, W):
    ids = set(x for x in (ctx.get('ids') or []) if isinstance(x, str))
    d = {'relationships': []}
    for r in [x for x in arr(_g(o, 'relationships')) if isinstance(x, dict)]:
        frm, to, typ = st(_g(r, 'from'), 80), st(_g(r, 'to'), 80), en(_g(r, 'type'), REL_TYPES, None)
        if frm not in ids or to not in ids or frm == to or not typ:
            W.append('relate: a relationship references an unknown id or type — dropped')
            continue
        d['relationships'].append({'from': frm, 'to': to, 'type': typ, 'confidence': conf(_g(r, 'confidence')), 'rationale': st(_g(r, 'rationale'), 2000)})
    return d


def v_refresh(o, ctx, W):
    ids = set(x for x in (ctx.get('ids') or []) if isinstance(x, str))
    d = {'summary': st(_g(o, 'summary'), 6000), 'items': [], 'risks': [x for x in (st(y, 1000) for y in arr(_g(o, 'risks'))) if x][:30]}
    for it in [x for x in arr(_g(o, 'items')) if isinstance(x, dict)]:
        aid = st(_g(it, 'asset_id'), 80)
        if aid not in ids:
            W.append('refresh: asset_id "%s" was not supplied — dropped' % _utf16(aid, 40))
            continue
        d['items'].append({'asset_id': aid, 'action': en(_g(it, 'action'), ['replace', 'renew', 'monitor', 'retire'], 'monitor'), 'when': st(_g(it, 'when'), 60),
                           'reason': st(_g(it, 'reason'), 2000), 'estimated_cost': _number(_g(it, 'estimated_cost'))})
    return d


V = {'classify': v_classify, 'relate': v_relate, 'refresh': v_refresh}


def validate(r):
    kind, text = r.get('kind'), r.get('text')
    ctx = r.get('ctx') if isinstance(r.get('ctx'), dict) else {}
    res = r.get('res') if isinstance(r.get('res'), dict) else {}
    if not isinstance(ctx.get('ids', []), list) or not all(isinstance(x, str) for x in ctx.get('ids') or []):
        raise NodeDecides()   # new Set(ids) of other values compares them by identity, not by text
    obj, how, error = extract_json(text)
    pre = []
    if _or(res.get('truncated', _U), False):
        pre.append('the model answer was truncated (max tokens) — content may be incomplete')
    if obj is None:
        raw = text if isinstance(text, str) else ('' if not text else _to_s(text))
        return {'ai': {'raw': _utf16(raw, 100000)}, 'validation': {'ok': False, 'parsed_by': None, 'errors': [error], 'warnings': pre}}
    if how == 'brace':
        pre.append('the JSON was not inside a ```json fence (recovered from the first {...} block)')
    fn = V.get(kind) if isinstance(kind, str) else None
    if fn is None:
        raise NodeDecides()
    W = []
    data = fn(obj, ctx, W)
    return {'ai': data, 'validation': {'ok': True, 'parsed_by': how, 'errors': [], 'warnings': pre + W}}


def _guard(fn):
    def run(r):
        try:
            return fn(r)
        except NodeDecides:
            return {'node': True}
    return run


OPS = {'ai.sanitise_pair': _guard(sanitise_pair), 'ai.validate': _guard(validate)}
