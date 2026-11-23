# Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
"""org_brand - the company identity the Python readers print: the same brand setting the Node engine reads (engine/brand.js).

Read once: SENTRA_BRAND_FILE, then /etc/sentra/brand.json, then ../engine/brand.default.json. Texts carry {{org.name}},
{{org.short}}, {{org.name_ar}} ... tokens; fill() puts the values in. A missing or broken file is an error, never a guess.
"""
import json
import os
import re

_TEXT = ('name', 'short', 'name_ar', 'short_ar', 'domain', 'website', 'report_header', 'portal_host')
_BAD = re.compile(r'[<>&"\'`\r\n]')
_TOKEN = re.compile(r'\{\{org\.([a-z_]+)\}\}')


def _check(b, source):
    if not isinstance(b, dict):
        raise ValueError('brand: %s is not an object' % source)
    for k in _TEXT:
        v = b.get(k)
        if not isinstance(v, str) or not v.strip():
            raise ValueError('brand: "%s" is missing in %s' % (k, source))
        if _BAD.search(v):
            raise ValueError('brand: "%s" in %s may not contain < > & quotes or line breaks' % (k, source))
    out = dict(b)
    out['upper'] = out['short'].upper()
    out['li_ar'] = 'ل' + out['short_ar']
    out['bi_ar'] = 'ب' + out['short_ar']
    out['platform_ip'] = out.get('platform_ip') or ''
    out['platform_addr'] = out['platform_ip'] or 'the platform server'
    return out


def load(environ=None):
    environ = os.environ if environ is None else environ
    here = os.path.dirname(os.path.abspath(__file__))
    for f in (environ.get('SENTRA_BRAND_FILE'), '/etc/sentra/brand.json', os.path.join(here, '..', 'engine', 'brand.default.json')):
        if not f:
            continue
        try:
            with open(f, encoding='utf-8') as fh:
                raw = fh.read()
        except (FileNotFoundError, PermissionError):
            continue
        return _check(json.loads(raw), f)
    raise RuntimeError('brand: no brand file found (run tools/brand/apply-brand.js)')


ORG = load()


def fill(text):
    """The text with every {{org.<field>}} token replaced by the brand value (unknown tokens are left as they are)."""
    return _TOKEN.sub(lambda m: ORG[m.group(1)] if isinstance(ORG.get(m.group(1)), str) else m.group(0), text)
