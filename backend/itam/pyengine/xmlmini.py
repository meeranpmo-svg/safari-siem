# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
"""Minimal, tolerant XML reader - the same rules as engine/discovery/xml.js, so a SOAP answer reads identically in both.
No DTDs, no external entities (they are never expanded - XXE-safe by construction), namespaces reduced to local names.
  parse(text) -> root Node(name, attrs, children, text)
  find / find_all (descendants, depth first), child (direct child), text_of, child_text, esc
Standard library only (Python 3.8+).
"""
import re

ENT = {'lt': '<', 'gt': '>', 'amp': '&', 'quot': '"', 'apos': "'"}
_ENT_RX = re.compile(r'&(#x[0-9a-fA-F]+|#\d+|[a-zA-Z]+);')
_NAME_RX = re.compile(r'^([^\s/>]+)')
_ATTR_RX = re.compile(r'''([^\s=]+)\s*=\s*("([^"]*)"|'([^']*)')''')


class Node:
    __slots__ = ('name', 'attrs', 'children', 'text')

    def __init__(self, name):
        self.name, self.attrs, self.children, self.text = name, {}, [], ''


def decode(s):
    def rep(m):
        e = m.group(1)
        if e[0] == '#':
            n = int(e[2:], 16) if e[1] == 'x' else int(e[1:], 10)
            return chr(n) if 0 < n < 0x110000 else ''
        return ENT.get(e, m.group(0))
    return _ENT_RX.sub(rep, s)


def _local(n):
    i = n.find(':')
    return n[i + 1:] if i >= 0 else n


def parse(text):
    s = text or ''
    if len(s) > 32 * 1024 * 1024:
        raise ValueError('XML too large')
    root = Node('#root')
    stack = [root]
    i, n = 0, len(s)
    while i < n:
        lt = s.find('<', i)
        if lt < 0:
            stack[-1].text += decode(s[i:])
            break
        if lt > i:
            stack[-1].text += decode(s[i:lt])
        if s.startswith('<!--', lt):
            e = s.find('-->', lt + 4)
            i = n if e < 0 else e + 3
            continue
        if s.startswith('<![CDATA[', lt):
            e = s.find(']]>', lt + 9)
            stack[-1].text += s[lt + 9:n if e < 0 else e]
            i = n if e < 0 else e + 3
            continue
        if s.startswith('<?', lt) or s.startswith('<!', lt):
            e = s.find('>', lt)
            i = n if e < 0 else e + 1
            continue
        gt = s.find('>', lt)
        if gt < 0:
            raise ValueError('unterminated tag')
        tag = s[lt + 1:gt]
        i = gt + 1
        if tag[:1] == '/':
            name = _local(tag[1:].strip())
            for k in range(len(stack) - 1, 0, -1):
                if stack[k].name == name:
                    del stack[k:]
                    break
            continue
        self_close = tag.endswith('/')
        if self_close:
            tag = tag[:-1]
        m = _NAME_RX.match(tag)
        if not m:
            continue
        node = Node(_local(m.group(1)))
        for a in _ATTR_RX.finditer(tag[len(m.group(1)):]):
            node.attrs[_local(a.group(1))] = decode(a.group(3) if a.group(3) is not None else a.group(4))
        stack[-1].children.append(node)
        if not self_close:
            stack.append(node)
        if len(stack) > 200:
            raise ValueError('XML nested too deeply')
    return root


def find(node, name):
    if node is None:
        return None
    for c in node.children:
        if c.name == name:
            return c
        r = find(c, name)
        if r is not None:
            return r
    return None


def find_all(node, name, out=None):
    out = [] if out is None else out
    if node is None:
        return out
    for c in node.children:
        if c.name == name:
            out.append(c)
        find_all(c, name, out)
    return out


def child(node, name):
    if node is None:
        return None
    return next((c for c in node.children if c.name == name), None)


def text_of(node, name=None):
    n = find(node, name) if name else node
    return n.text.strip() if n is not None else ''


def child_text(node, name):
    n = child(node, name)
    return n.text.strip() if n is not None else ''


def esc(v):
    return re.sub(r'''[<>&"']''', lambda m: {'<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;', "'": '&apos;'}[m.group(0)],
                  '' if v is None else str(v))
