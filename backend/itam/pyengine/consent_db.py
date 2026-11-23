# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
"""Consent state in SQLite (engine/pdpl-consent.js). Standard library only.

The hash-chained journal (<store>/consent-YYYYMM.jsonl) stays the source of truth; this database is the current state
per (subject reference, purpose) and the counters per purpose, so the engine no longer holds them in memory. Every
update carries the journal sequence it applies (meta.last_seq) and is ignored when already applied - replaying the
journal after a crash or for the first migration is therefore safe.

  consent.apply   {db, events: [{seq, t, subject_ref, purpose, action, version, channel}]}  -> {applied, last_seq}
  consent.get     {db, subject_ref, purposes[]}         -> {state: {purpose: {s, v, t, ch}}}
  consent.stats   {db, purposes: {id: current_version}, since_day} -> {stats: {id: {...}}, last_seq, rows}
  consent.last    {db}                                   -> {last_seq}

Only subject references (HMAC values) reach this file - never an identifier in clear. The file is created 0600.
"""
import os
import sqlite3
import threading

_CONN = {}
_LOCK = threading.Lock()
SCHEMA = """
create table if not exists consent_state (subject_ref text not null, purpose text not null, status text not null check (status in ('g','w')),
  version integer, at integer not null, channel text, primary key (subject_ref, purpose)) without rowid;
create index if not exists consent_state_pv on consent_state (purpose, status, version);
create table if not exists consent_counter (purpose text not null, day text not null, channel text not null, action text not null, n integer not null,
  primary key (purpose, day, channel, action)) without rowid;
create table if not exists consent_meta (k text primary key, v text) without rowid;
"""


def _db(path):
    if not path or not isinstance(path, str) or not path.endswith('.sqlite'):
        raise ValueError('db must be the consent database path')
    with _LOCK:
        c = _CONN.get(path)
        if c is None:
            new = not os.path.exists(path)
            old = os.umask(0o077)
            try:
                c = sqlite3.connect(path, timeout=30, isolation_level=None, check_same_thread=False)
            finally:
                os.umask(old)
            if new:
                os.chmod(path, 0o600)
            c.execute('pragma journal_mode=wal')
            c.execute('pragma synchronous=normal')
            c.executescript(SCHEMA)
            _CONN[path] = c
        return c


def _last(c):
    r = c.execute("select v from consent_meta where k = 'last_seq'").fetchone()
    return int(r[0]) if r else 0


def last(req):
    return {'last_seq': _last(_db(req.get('db')))}


def apply(req):
    c = _db(req.get('db'))
    applied = 0
    c.execute('begin immediate')
    try:
        ls = _last(c)
        for e in sorted(req.get('events') or [], key=lambda x: int(x.get('seq') or 0)):
            seq = int(e.get('seq') or 0)
            if seq <= ls:
                continue          # already applied (replay after a crash, or the first migration)
            if e.get('action') not in ('grant', 'withdraw') or not e.get('subject_ref') or not e.get('purpose'):
                raise ValueError('event %d is not a consent event' % seq)
            st = 'g' if e['action'] == 'grant' else 'w'
            c.execute('insert into consent_state (subject_ref, purpose, status, version, at, channel) values (?,?,?,?,?,?) '
                      'on conflict (subject_ref, purpose) do update set status = excluded.status, version = excluded.version, at = excluded.at, channel = excluded.channel',
                      (e['subject_ref'], e['purpose'], st, e.get('version'), int(e.get('t') or 0), e.get('channel') or ''))
            day = _day(int(e.get('t') or 0))
            c.execute('insert into consent_counter (purpose, day, channel, action, n) values (?,?,?,?,1) on conflict (purpose, day, channel, action) do update set n = n + 1',
                      (e['purpose'], day, e.get('channel') or '', e['action']))
            ls = seq
            applied += 1
        c.execute("insert into consent_meta (k, v) values ('last_seq', ?) on conflict (k) do update set v = excluded.v", (str(ls),))
        c.execute('commit')
    except Exception:
        c.execute('rollback')
        raise
    return {'applied': applied, 'last_seq': ls}


def _day(t):
    import datetime
    return datetime.datetime.fromtimestamp(t / 1000.0, tz=datetime.timezone.utc).strftime('%Y-%m-%d')


def get(req):
    c = _db(req.get('db'))
    ps = [str(p) for p in (req.get('purposes') or [])][:200]
    out = {}
    if ps:
        q = 'select purpose, status, version, at, channel from consent_state where subject_ref = ? and purpose in (%s)' % ','.join('?' * len(ps))
        for p, s, v, t, ch in c.execute(q, [req.get('subject_ref')] + ps):
            out[p] = {'s': s, 'v': v, 't': t, 'ch': ch}
    return {'state': out}


def stats(req):
    c = _db(req.get('db'))
    cur = req.get('purposes') or {}
    since = str(req.get('since_day') or '')
    out = {p: {'events': 0, 'grants': 0, 'withdrawals': 0, 'active': 0, 'withdrawn': 0, 'stale_version': 0, 'channels': {}, 'last_event': None, 'events_30d': 0} for p in cur}
    for p, s, v, n in c.execute('select purpose, status, version, count(*) from consent_state group by purpose, status, version'):
        if p not in out:
            continue
        if s == 'g':
            out[p]['active'] += n
            if v is not None and int(v) < int(cur[p] or 1):
                out[p]['stale_version'] += n
        else:
            out[p]['withdrawn'] += n
    for p, day, ch, act, n in c.execute('select purpose, day, channel, action, n from consent_counter'):
        if p not in out:
            continue
        o = out[p]
        o['events'] += n
        o['grants' if act == 'grant' else 'withdrawals'] += n
        o['channels'][ch] = o['channels'].get(ch, 0) + n
        if day >= since:
            o['events_30d'] += n
    for p, t in c.execute('select purpose, max(at) from consent_state group by purpose'):
        if p in out and t:
            import datetime
            out[p]['last_event'] = datetime.datetime.fromtimestamp(t / 1000.0, tz=datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.000Z')
    rows = c.execute('select count(*) from consent_state').fetchone()[0]
    return {'stats': out, 'last_seq': _last(c), 'rows': rows}


OPS = {
    'consent.apply': apply,
    'consent.get': get,
    'consent.stats': stats,
    'consent.last': last,
}
