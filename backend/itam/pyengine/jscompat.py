# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
"""JavaScript rules the ported modules keep on purpose, so a Python module answers exactly like the Node.js one it
replaces (docs/PYTHON-MIGRATION.md). Each function says which JavaScript expression it stands for.
"""
import math
import re
from datetime import datetime, timedelta, timezone

MISSING = object()


def js_round(x):
    """Math.round(x): halves go up (Python's round() goes to even)."""
    return math.floor(x + 0.5)


def num(v=MISSING):
    """Number(v) when finite, else None. Number(undefined) = NaN, Number(null) = 0, Number('') = 0."""
    if v is MISSING:
        return None
    if v is None:
        return 0
    if isinstance(v, bool):
        return 1 if v else 0
    if isinstance(v, (int, float)):
        return v if math.isfinite(v) else None
    s = str(v).strip()
    if s == '':
        return 0
    try:
        n = float(s)
    except ValueError:
        return None
    if not math.isfinite(n):
        return None
    return int(n) if n.is_integer() and re.match(r'^[+-]?\d+$', s) else n


def truthy(v):
    """JavaScript truthiness: null, false, 0, NaN and '' are false - an empty object or list is TRUE (unlike Python)."""
    if v is None or v is False or v == '':
        return False
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        return v != 0 and v == v
    return True


def low(v):
    """String(v || '').trim().toLowerCase()"""
    return js_str(v).strip().lower() if v else ''


def js_str(v):
    """String(v) for the values that occur in answers (numbers print without a trailing .0)."""
    if v is None:
        return 'null'
    if isinstance(v, bool):
        return 'true' if v else 'false'
    if isinstance(v, float) and v.is_integer() and abs(v) < 1e21:
        return str(int(v))
    if isinstance(v, dict):
        return '[object Object]'
    return str(v)


def gt(a, b):
    """a > b as JavaScript compares two ISO strings, or a string with null (always false)."""
    if isinstance(a, str) and isinstance(b, str):
        return a > b
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return a > b
    return False


def encode_uri_component(s):
    """encodeURIComponent(s)"""
    out = []
    for b in str(s).encode('utf-8'):
        c = chr(b)
        out.append(c if (c.isalnum() and b < 128) or c in "-_.!~*'()" else '%%%02X' % b)
    return ''.join(out)


def form_encode(pairs):
    """new URLSearchParams(obj).toString() - application/x-www-form-urlencoded as browsers and Node write it."""
    def enc(s):
        out = []
        for b in str(s).encode('utf-8'):
            c = chr(b)
            out.append(c if (c.isalnum() and b < 128) or c in '*-._' else '+' if c == ' ' else '%%%02X' % b)
        return ''.join(out)
    return '&'.join('%s=%s' % (enc(k), enc(v)) for k, v in pairs)


_ISO = re.compile(r'^(\d{4})-(\d{2})-(\d{2})(?:[T ](\d{2}):(\d{2})(?::(\d{2})(?:[.,](\d+))?)?)?\s*(Z|[+-]\d{2}:?\d{2})?$', re.I)


def iso(v):
    """iso() of the Node.js modules: a number is epoch milliseconds, a string goes through Date.parse (a date-time without a
    zone is local time, a date alone is UTC); the answer is toISOString() (milliseconds, Z) or None."""
    if v is None or v == '':
        return None
    try:
        if isinstance(v, (int, float)) and not isinstance(v, bool):
            if not math.isfinite(v) or v <= 0:
                return None
            t = datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(milliseconds=math.floor(v))
        else:
            m = _ISO.match(str(v).strip())
            if not m:
                return None
            y, mo, d, hh, mi, ss, frac, tz = m.groups()
            ms = int((frac or '0')[:3].ljust(3, '0'))
            base = datetime(int(y), int(mo), int(d), int(hh or 0), int(mi or 0), int(ss or 0), ms * 1000)
            if tz:
                if tz.upper() == 'Z':
                    t = base.replace(tzinfo=timezone.utc)
                else:
                    sign = 1 if tz[0] == '+' else -1
                    hhmm = tz[1:].replace(':', '')
                    t = base.replace(tzinfo=timezone(sign * timedelta(hours=int(hhmm[:2]), minutes=int(hhmm[2:]))))
            elif hh is None:
                t = base.replace(tzinfo=timezone.utc)   # Date.parse('2026-10-13') is UTC midnight
            else:
                t = base.astimezone()                    # a date-time without a zone is local time
            t = t.astimezone(timezone.utc)
            if t.timestamp() <= 0:
                return None
        return t.strftime('%Y-%m-%dT%H:%M:%S.') + '%03dZ' % (t.microsecond // 1000)
    except (ValueError, OverflowError, OSError):
        return None


def iso_now_minus(now_ms, days, keep_ms=True):
    """new Date(now - days * DAY).toISOString()  (keep_ms False: .replace(/\\.\\d{3}Z$/, 'Z'))"""
    t = datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(milliseconds=now_ms - days * 86400000)
    s = t.strftime('%Y-%m-%dT%H:%M:%S.') + '%03dZ' % (t.microsecond // 1000)
    return s if keep_ms else s[:-5] + 'Z'
