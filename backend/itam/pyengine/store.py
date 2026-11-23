# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
"""The state store in Python - migration step 8a (docs/PYTHON-MIGRATION.md). The same files as engine/store.js, byte for
byte: <name>.jsonl journals + <name>.snap.json snapshots per collection, and the hash-chained audit-YYYYMM.jsonl journal
(sha256(prev + "\\n" + JSON of the record without its hash)). A record written here reads back identically in Node.js and
the other way round, and each verifies the other's audit chain.

Until the Node.js process is gone (step 9) it is the ONLY writer: it keeps every collection in memory, so a record written
from here would be invisible to it and later overwritten. On the live server this module therefore opens the store
read-only (Store(dir, readonly=True)), which refuses every write and reads the files safely next to a writer:
  - a last line still being written (no newline yet) is not read, and never reported as damage
  - a snapshot that is replaced while the journal is read (compaction) makes the read start again, so no journal entry
    is lost between the old snapshot and the truncated journal
Writing (readonly=False) exists for the parity tests now and for step 9.
Standard library only (Python 3.8+).
"""
import hashlib
import json
import os
import re
import time
from datetime import datetime, timezone
from decimal import Decimal

NAME_RE = re.compile(r'^[a-z][a-z0-9_-]{0,40}$')
GENESIS = '0' * 64
RING = 5000
_INDEX = re.compile(r'^(0|[1-9][0-9]*)$')
_ESC = {'"': '\\"', '\\': '\\\\', '\b': '\\b', '\f': '\\f', '\n': '\\n', '\r': '\\r', '\t': '\\t'}


class ReadOnly(Exception):
    pass


# ---- JSON.stringify, exactly --------------------------------------------------------------------------------------
def _js_number(v):
    if isinstance(v, bool):
        return 'true' if v else 'false'
    if isinstance(v, int):
        return str(v)
    if v != v or v in (float('inf'), float('-inf')):
        return 'null'
    if v == 0:
        return '0'                               # -0 too
    if v.is_integer() and abs(v) < 1e21:
        return str(int(v))
    sign = '-' if v < 0 else ''
    d = Decimal(repr(abs(v)))                    # repr = the shortest digits that read back, like JavaScript
    _, digits, exp = d.as_tuple()
    ds = ''.join(map(str, digits)).rstrip('0') or '0'
    exp += len(digits) - len(ds)
    k = len(ds)
    n = exp + k                                  # ECMAScript Number::toString: value = 0.ds x 10^n
    if k <= n <= 21:
        s = ds + '0' * (n - k)
    elif 0 < n <= 21:
        s = ds[:n] + '.' + ds[n:]
    elif -6 < n <= 0:
        s = '0.' + '0' * (-n) + ds
    else:
        e = n - 1
        s = ds[0] + ('.' + ds[1:] if k > 1 else '') + 'e' + ('+' if e >= 0 else '-') + str(abs(e))
    return sign + s


def _js_string(s):
    out = ['"']
    for ch in s:
        c = ord(ch)
        if ch in _ESC:
            out.append(_ESC[ch])
        elif c < 0x20 or 0xD800 <= c <= 0xDFFF:   # control characters and lone surrogates: \\u00xx (well-formed JSON.stringify)
            out.append('\\u%04x' % c)
        else:
            out.append(ch)
    out.append('"')
    return ''.join(out)


def _keys(o):
    """JavaScript's own-key order: integer-like keys first, ascending, then the others in insertion order"""
    idx = sorted((k for k in o if _INDEX.match(k) and int(k) < 4294967295), key=int)
    rest = [k for k in o if not (_INDEX.match(k) and int(k) < 4294967295)]
    return idx + rest


def stringify(v):
    """JSON.stringify(v) for values read from JSON (dict, list, str, int, float, bool, None)"""
    if v is None:
        return 'null'
    if isinstance(v, str):
        return _js_string(v)
    if isinstance(v, (bool, int, float)):
        return _js_number(v)
    if isinstance(v, list):
        return '[' + ','.join(stringify(x) for x in v) + ']'
    if isinstance(v, dict):
        return '{' + ','.join(_js_string(k) + ':' + stringify(v[k]) for k in _keys(v)) + '}'
    raise TypeError('not a JSON value: %r' % type(v))


def parse(s):
    """JSON.parse. The key order JavaScript would give an object (integer-like keys first) is applied by stringify(), and
    the files were written in that order already, so the fast C reader is enough"""
    return json.loads(s)


def sha256(s):
    return hashlib.sha256(s.encode('utf-8', 'surrogatepass')).hexdigest()


def chain_hash(rec):
    rest = {k: v for k, v in rec.items() if k != 'hash'}
    p = rest['prev'] if 'prev' in rest else None
    prev = 'undefined' if 'prev' not in rest else p if isinstance(p, str) else stringify(p)   # rest.prev + "\n" in JavaScript
    return sha256(prev + '\n' + stringify(rest))


def _chain_ok(rec):
    """chain_hash(rec) == rec.hash, fast: Python's C JSON writer first. If its text hashes to the recorded hash it IS the
    text Node.js hashed (SHA-256), so Node.js accepts the record too; otherwise the exact JavaScript writer decides (a
    record with integer-like keys, -0, 1e21, lone surrogates... or a tampered one). 50,000 records: 3 s -> about 1 s."""
    h = rec.get('hash')
    rest = {k: v for k, v in rec.items() if k != 'hash'}
    p = rest.get('prev')
    if isinstance(p, str):
        try:
            fast = json.dumps(rest, ensure_ascii=False, separators=(',', ':'), allow_nan=False)
            if hashlib.sha256((p + '\n' + fast).encode('utf-8', 'surrogatepass')).hexdigest() == h:
                return True
        except (ValueError, TypeError):
            pass
    return chain_hash(rec) == h


def _copy(o):
    return parse(stringify(o))


def _now_iso():
    t = datetime.now(timezone.utc)
    return t.strftime('%Y-%m-%dT%H:%M:%S.') + '%03dZ' % (t.microsecond // 1000)


def _lines(data, complete_only):
    """the journal's lines; complete_only: a last line without its newline is still being written - not read"""
    parts = data.split('\n')
    last = parts.pop()                           # '' when the file ends with a newline
    if last and not complete_only:
        parts.append(last)
    return [p for p in parts if p]


def _read(path):
    with open(path, 'rb') as f:
        return f.read().decode('utf-8', 'surrogatepass')


def _stat(path):
    try:
        st = os.stat(path)
        return (st.st_ino, st.st_mtime_ns, st.st_size)
    except FileNotFoundError:
        return None


class Collection:
    def __init__(self, store, name):
        if not NAME_RE.match(name):
            raise ValueError('invalid collection name %s' % name)
        self.store, self.name = store, name
        self.jpath = os.path.join(store.dir, name + '.jsonl')
        self.spath = os.path.join(store.dir, name + '.snap.json')
        self.writes, self.bad = 0, 0
        self.items = self._load()
        self.fd = None if store.readonly else open(self.jpath, 'a', encoding='utf-8', errors='surrogatepass', newline='\n')

    def _apply(self, items, data, ro):
        """apply journal text to items; returns the number of unreadable lines"""
        bad = 0
        for line in _lines(data, ro):
            try:
                rec = parse(line)
            except ValueError:
                bad += 1
                continue
            if rec.get('op') == 'put' and isinstance(rec.get('o'), dict) and 'id' in rec['o']:
                items[rec['o']['id']] = rec['o']
            elif rec.get('op') == 'del':
                items.pop(rec.get('id'), None)
        return bad

    def _load(self):
        ro = self.store.readonly
        for attempt in range(50):
            before = _stat(self.spath)
            items, bad = {}, 0
            try:
                for o in parse(_read(self.spath)).get('items') or []:
                    items[o.get('id')] = o
            except FileNotFoundError:
                pass
            raw = b''
            try:
                with open(self.jpath, 'rb') as f:
                    raw = f.read()
            except FileNotFoundError:
                pass
            # read-only: only complete lines; the offset says where the next refresh() continues
            done = raw[:raw.rfind(b'\n') + 1] if ro else raw
            bad = self._apply(items, done.decode('utf-8', 'surrogatepass'), False)
            # a compaction between reading the snapshot and the journal: read both again
            if not ro or _stat(self.spath) == before:
                self.bad, self.joff, self.snap = bad, len(done), before
                return items
            time.sleep(0.005 * (1 + attempt % 4))
        raise RuntimeError('the %s collection kept changing while it was read' % self.name)

    def refresh(self):
        """read-only: bring the collection up to date with what the writer appended since the last read - only the new
        complete lines are read. A compaction (the snapshot replaced, the journal truncated) reloads it. Checked again
        AFTER reading: the writer replaces the snapshot before it truncates the journal, so a truncation that raced this
        read always shows up as a changed snapshot."""
        if not self.store.readonly:
            return False
        if _stat(self.spath) != self.snap:
            self.items = self._load()
            return True
        try:
            size = os.stat(self.jpath).st_size
        except FileNotFoundError:
            size = 0
        if size < self.joff:
            self.items = self._load()
            return True
        if size == self.joff:
            return False
        with open(self.jpath, 'rb') as f:
            f.seek(self.joff)
            chunk = f.read(size - self.joff)
        if _stat(self.spath) != self.snap:
            self.items = self._load()
            return True
        done = chunk[:chunk.rfind(b'\n') + 1]
        if done:
            self.bad += self._apply(self.items, done.decode('utf-8', 'surrogatepass'), False)
            self.joff += len(done)
        return bool(done)

    def get(self, id_):
        return self.items.get(id_)

    def all(self, flt=None):
        return [o for o in self.items.values() if flt is None or flt(o)]

    def size(self):
        return len(self.items)

    def _append(self, rec):
        if self.store.readonly:
            raise ReadOnly('the store is open read-only: the Node.js engine is the only writer until step 9')
        self.fd.write(stringify(rec) + '\n')
        self.fd.flush()
        if self.store.fsync:
            os.fsync(self.fd.fileno())
        self.writes += 1
        if self.writes >= 5000:
            self.snapshot()

    def put(self, obj):
        if not isinstance(obj, dict) or obj.get('id') in (None, ''):
            raise ValueError('put into %s needs id' % self.name)
        o = _copy(obj)
        self._append({'op': 'put', 'o': o})
        self.items[o['id']] = o
        return o

    def patch(self, id_, fn):
        cur = self.items.get(id_)
        if cur is None:
            return None
        copy = _copy(cur)
        res = fn(copy)
        nxt = res if isinstance(res, dict) else copy
        nxt['id'] = id_
        self._append({'op': 'put', 'o': nxt})
        self.items[id_] = nxt
        return nxt

    def remove(self, id_):
        if id_ not in self.items:
            return False
        self._append({'op': 'del', 'id': id_})
        del self.items[id_]
        return True

    def snapshot(self):
        if self.store.readonly:
            raise ReadOnly('the store is open read-only')
        tmp = self.spath + '.tmp'
        with open(tmp, 'w', encoding='utf-8', errors='surrogatepass', newline='\n') as f:
            f.write(stringify({'at': int(time.time() * 1000), 'items': list(self.items.values())}))
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.spath)
        self.fd.close()
        open(self.jpath, 'w').close()
        self.fd = open(self.jpath, 'a', encoding='utf-8', errors='surrogatepass', newline='\n')
        self.writes = 0


class Store:
    def __init__(self, dir_, readonly=False, fsync=False):
        if not dir_:
            raise ValueError('Store needs dir')
        self.dir, self.readonly, self.fsync = dir_, readonly, fsync
        if not readonly:
            os.makedirs(dir_, exist_ok=True)
        elif not os.path.isdir(dir_):
            raise FileNotFoundError('no store at %s' % dir_)
        self.cols = {}
        self.ring, self.last_hash, self.seq = [], GENESIS, 0
        self.audit_fd, self.audit_month = None, ''
        files = self.audit_files()
        for i, f in enumerate(files[-2:]):
            last_file = i == len(files[-2:]) - 1
            for line in _lines(_read(os.path.join(dir_, f)), readonly and last_file):
                try:
                    rec = parse(line)
                except ValueError:
                    continue
                self.ring.append(rec)
                if len(self.ring) > RING:
                    self.ring.pop(0)
                if rec.get('hash'):
                    self.last_hash = rec['hash']
                    self.seq = rec.get('seq') or self.seq

    def audit_files(self):
        return sorted(f for f in os.listdir(self.dir) if re.match(r'^audit-\d{6}\.jsonl$', f))

    def collection(self, name):
        c = self.cols.get(name)
        if c is None:
            c = self.cols[name] = Collection(self, name)
        return c

    def audit(self, entry):
        if self.readonly:
            raise ReadOnly('the store is open read-only: the Node.js engine is the only writer until step 9')
        at = entry.get('at') or _now_iso()
        rec = {'seq': self.seq + 1, 'at': at}
        rec.update(entry)
        rec.update({'seq': self.seq + 1, 'at': at, 'prev': self.last_hash})
        rec.pop('hash', None)
        rec = _copy(rec)                          # the key order JavaScript would hold
        rec['hash'] = chain_hash(rec)
        month = at[:7].replace('-', '')
        if month != self.audit_month:
            if self.audit_fd:
                self.audit_fd.close()
            self.audit_fd = open(os.path.join(self.dir, 'audit-%s.jsonl' % month), 'a', encoding='utf-8', errors='surrogatepass', newline='\n')
            self.audit_month = month
        self.audit_fd.write(stringify(rec) + '\n')
        self.audit_fd.flush()
        if self.fsync:
            os.fsync(self.audit_fd.fileno())
        self.seq, self.last_hash = rec['seq'], rec['hash']
        self.ring.append(rec)
        if len(self.ring) > RING:
            self.ring.pop(0)
        return rec

    def audit_tail(self, n=100, flt=None):
        out = []
        for rec in reversed(self.ring):
            if len(out) >= n:
                break
            if flt is None or flt(rec):
                out.append(rec)
        return out

    def verify_audit(self):
        prev, checked = GENESIS, 0
        files = self.audit_files()
        for fi, f in enumerate(files):
            data = _read(os.path.join(self.dir, f))
            lines = data.split('\n')
            for i, line in enumerate(lines):
                if not line:
                    continue
                if self.readonly and fi == len(files) - 1 and i == len(lines) - 1:
                    break                         # the writer is still writing this line: not damage, not yet a record
                try:
                    rec = parse(line)
                except ValueError:
                    return {'ok': False, 'checked': checked, 'bad_at': '%s:%d' % (f, i + 1), 'reason': 'unreadable line'}
                if rec.get('prev') != prev or not _chain_ok(rec):
                    return {'ok': False, 'checked': checked, 'bad_at': '%s:%d' % (f, i + 1), 'reason': 'hash chain broken'}
                prev = rec['hash']
                checked += 1
        return {'ok': True, 'checked': checked, 'head': prev}

    def snapshot(self):
        for c in self.cols.values():
            if c.writes:
                c.snapshot()

    def close(self):
        if self.readonly:
            return
        self.snapshot()
        for c in self.cols.values():
            c.fd.close()
        self.cols = {}
        if self.audit_fd:
            self.audit_fd.close()
            self.audit_fd, self.audit_month = None, ''


# ---- the resident service keeps read-only stores in memory and refreshes them on each use ---------------------------
_CACHE = {}


RESIDENT = False   # set by serve.py: the resident service keeps stores in memory


def reader(dir_):
    """the store for a read operation: kept in memory and refreshed in the resident service, else read fresh"""
    return cached(dir_) if RESIDENT else Store(dir_, readonly=True)


def cached(dir_):
    """Store(dir_, readonly=True), kept in memory between calls; every collection already opened is brought up to date"""
    s = _CACHE.get(dir_)
    if s is None:
        s = _CACHE[dir_] = Store(dir_, readonly=True)
    else:
        for c in list(s.cols.values()):
            c.refresh()
    return s


# ---- operations for run.py (read-only: the Node.js engine is the writer) ----------------------------------------------
def op_read(r):
    s = Store(r['dir'], readonly=True)
    c = s.collection(r['collection'])
    ids = r.get('ids')
    items = [c.get(i) for i in ids if c.get(i) is not None] if isinstance(ids, list) else c.all()
    return {'items': items, 'size': c.size()}


def op_verify(r):
    return Store(r['dir'], readonly=True).verify_audit()


def op_tail(r):
    return {'audit': Store(r['dir'], readonly=True).audit_tail(min(int(r.get('n') or 100), RING))}
