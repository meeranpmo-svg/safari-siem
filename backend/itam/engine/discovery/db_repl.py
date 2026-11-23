# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
"""Our own database engines next to GoldenGate (Databases -> Replication & Data Guard), loaded by inv-helper.py.

Three engines, each with its OWN dedicated account (never the read-only monitoring login):
  Data Verify    compares a table on a source and a target database by primary key, in chunks, hashing every row HERE
                 (values are never returned or stored - only primary keys of rows that differ). SELECT-only accounts.
  Change Stream  reads committed changes on chosen schemas from the redo / archived logs with LogMiner (DBMS_LOGMNR,
                 included in every Oracle edition) and returns per-transaction METADATA only: who, from where, which
                 program, which tables, how many rows, DDL text with literals masked. No row values.
  Replication    mines the same way and applies the changes to a target (Oracle or PostgreSQL) in the SAME process:
                 row values exist only in this process's memory. The checkpoint (last applied commit SCN) is a row on the
                 target updated in the SAME transaction as the changes it covers, so a restart never applies a change twice
                 and never skips one.

Transactions are tracked by XID (START / COMMIT / ROLLBACK rows), not with COMMITTED_DATA_ONLY: the next window restarts at
the first change of any tracked transaction still open at the end of this one, and a commit at or below the checkpoint is
skipped - so a window can be cut anywhere (a few log files at a time) without losing or repeating a transaction.

Pure functions (parse_redo, norm, row_hash, keyset_where, plan_statement, ...) are unit-tested without a database.
"""
import datetime
import decimal
import hashlib
import json
import re

IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_$#]{0,127}$")
ORACLE_READ_SAFE = {"CREATE SESSION", "SET CONTAINER", "SELECT ANY DICTIONARY"}
ORACLE_MINER_SAFE = ORACLE_READ_SAFE | {"LOGMINING"}
ORACLE_WRITER_SAFE = {"CREATE SESSION", "SET CONTAINER"}
IN_CHUNK = 500
MAX_KEYS = 1000
NLS = ["alter session set nls_date_format = 'YYYY-MM-DD HH24:MI:SS'",
       "alter session set nls_timestamp_format = 'YYYY-MM-DD HH24:MI:SS.FF6'",
       "alter session set nls_timestamp_tz_format = 'YYYY-MM-DD HH24:MI:SS.FF6 TZH:TZM'",
       "alter session set nls_numeric_characters = '.,'"]


class Refused(Exception):
    """an account, table or request the engine will not use - the message says why"""


def ident(x, what="name"):
    s = str(x or "")
    if not IDENT.match(s):
        raise Refused("invalid %s: %r" % (what, s[:60]))
    return s


def qi(name):
    return '"' + ident(name) + '"'


def ph(engine, i):
    return ":%d" % (i + 1) if engine == "oracle" else "%s"


# ---------------------------------------------------------------------------------------------------------- accounts
def check_account(conn, engine, allowed, label):
    """refuse an account with more than it needs, BEFORE anything else runs"""
    cur = conn.cursor()
    if engine == "oracle":
        cur.execute("select privilege from session_privs")
        extra = sorted({str(r[0]).upper() for r in cur.fetchall()} - set(allowed))
        if extra:
            raise Refused("the %s account holds more than it needs (%s) - not used; give it only what the setup script grants" % (label, ", ".join(extra[:6])))
        return
    cur.execute("select rolsuper, rolcreaterole, rolcreatedb, rolbypassrls from pg_roles where rolname = current_user")
    r = cur.fetchone()
    if r and any(bool(x) for x in r):
        raise Refused("the %s account is a superuser or can create roles / databases - not used" % label)
    try:
        cur.execute("select pg_has_role(current_user, 'pg_read_all_data', 'member') or pg_has_role(current_user, 'pg_write_all_data', 'member')")
        if cur.fetchone()[0]:
            raise Refused("the %s account reads or writes ALL data (pg_read_all_data / pg_write_all_data) - grant only the tables" % label)
    except Refused:
        raise
    except Exception:
        conn.rollback()   # PostgreSQL < 14: those roles do not exist


def read_only(conn, engine):
    cur = conn.cursor()
    try:
        cur.execute("set transaction read only" if engine == "oracle" else "set session characteristics as transaction read only")
    except Exception:
        conn.rollback()


# ---------------------------------------------------------------------------------------------------------- tables
def describe(conn, engine, owner, table):
    """{owner, table, columns:[(name, type)], pk:[names]} with the names exactly as the dictionary has them; the case is
    tried as given, then upper (Oracle) / lower (PostgreSQL)"""
    cur = conn.cursor()
    tries = [(owner, table)] + ([(owner.upper(), table.upper())] if engine == "oracle" else [(owner.lower(), table.lower())])
    for o, t in tries:
        ident(o, "owner"), ident(t, "table")
        if engine == "oracle":
            cur.execute("select column_name, data_type from all_tab_columns where owner = :1 and table_name = :2 order by column_id", [o, t])
        else:
            cur.execute("select column_name, data_type from information_schema.columns where table_schema = %s and table_name = %s order by ordinal_position", (o, t))
        cols = [(str(r[0]), str(r[1])) for r in cur.fetchall()]
        if not cols:
            continue
        if engine == "oracle":
            cur.execute("select cc.column_name from all_constraints c join all_cons_columns cc on cc.owner = c.owner and cc.constraint_name = c.constraint_name "
                        "where c.owner = :1 and c.table_name = :2 and c.constraint_type = 'P' order by cc.position", [o, t])
        else:
            # pg_catalog, not information_schema: the latter hides constraints from an account that only has SELECT
            cur.execute("select a.attname from pg_index i join pg_class t on t.oid = i.indrelid join pg_namespace n on n.oid = t.relnamespace "
                        "join pg_attribute a on a.attrelid = t.oid and a.attnum = any(i.indkey) "
                        "where i.indisprimary and n.nspname = %s and t.relname = %s order by array_position(i.indkey::int2[], a.attnum)", (o, t))
        pk = [str(r[0]) for r in cur.fetchall()]
        for c, _ in cols:
            ident(c, "column")
        return {"owner": o, "table": t, "columns": cols, "pk": pk}
    raise Refused("table %s.%s not found or not readable by this account (grant SELECT on it)" % (owner, table))


LOB_TYPES = re.compile(r"^(CLOB|NCLOB|BLOB|LONG|LONG RAW|BFILE|XMLTYPE)$", re.I)


def compare_columns(src, tgt, exclude=()):
    """columns compared = both sides, case-insensitive, minus excluded; primary key must exist on the source and on both"""
    if not src["pk"]:
        raise Refused("%s.%s has no primary key - rows cannot be matched one to one" % (src["owner"], src["table"]))
    ex = {e.upper() for e in exclude}
    tmap = {c.upper(): c for c, _ in tgt["columns"]}
    pairs, only_src = [], []
    for c, ty in src["columns"]:
        if c.upper() in ex:
            continue
        if c.upper() in tmap:
            pairs.append((c, tmap[c.upper()], ty))
        else:
            only_src.append(c)
    only_tgt = [c for c, _ in tgt["columns"] if c.upper() not in {s.upper() for s, _ in src["columns"]}]
    pk = []
    for p in src["pk"]:
        if p.upper() not in tmap:
            raise Refused("primary key column %s is missing on the target" % p)
        pk.append((p, tmap[p.upper()]))
    pkset = {p.upper() for p, _ in pk}
    data = [(s, t, ty) for s, t, ty in pairs if s.upper() not in pkset]
    return {"pk": pk, "data": data, "only_source": only_src, "only_target": only_tgt}


# ---------------------------------------------------------------------------------------------------------- hashing
def norm(v):
    """one canonical text per value, the same for Oracle and PostgreSQL (NUMBER 1 / numeric 1.0, DATE / timestamp, '' = NULL
    because Oracle stores the empty string as NULL)"""
    if v is None:
        return "\x00"
    if hasattr(v, "read"):
        v = v.read()
    if isinstance(v, bool):
        return "b1" if v else "b0"
    if isinstance(v, int):
        return "n" + str(v)
    if isinstance(v, float):
        v = decimal.Decimal(repr(v))
    if isinstance(v, decimal.Decimal):
        if v == v.to_integral_value():
            return "n" + str(int(v))
        return "n" + format(v.normalize(), "f")
    if isinstance(v, datetime.datetime):
        if v.tzinfo is not None:
            v = v.astimezone(datetime.timezone.utc).replace(tzinfo=None)
        return "t" + v.isoformat(sep=" ")
    if isinstance(v, datetime.date):
        return "t" + v.isoformat() + " 00:00:00"
    if isinstance(v, (bytes, bytearray, memoryview)):
        return "x" + bytes(v).hex()
    s = str(v)
    return "\x00" if s == "" else "s" + s


def row_hash(values):
    return hashlib.sha256("\x1f".join(norm(v) for v in values).encode("utf-8", "surrogatepass")).hexdigest()[:32]


def enc_key(vals):
    """primary key values -> JSON (the cursor and the reported keys)"""
    out = []
    for v in vals:
        if isinstance(v, bool) or v is None or isinstance(v, (int, str)):
            out.append(v)
        elif isinstance(v, float):
            out.append({"t": "n", "v": repr(v)})
        elif isinstance(v, decimal.Decimal):
            out.append({"t": "n", "v": str(v)})
        elif isinstance(v, datetime.datetime):
            out.append({"t": "ts", "v": v.isoformat()})
        elif isinstance(v, datetime.date):
            out.append({"t": "d", "v": v.isoformat()})
        elif isinstance(v, (bytes, bytearray, memoryview)):
            out.append({"t": "x", "v": bytes(v).hex()})
        else:
            out.append(str(v))
    return out


def dec_key(vals):
    out = []
    for v in vals or []:
        if isinstance(v, dict):
            t, s = v.get("t"), v.get("v")
            out.append(decimal.Decimal(s) if t == "n" else datetime.datetime.fromisoformat(s) if t == "ts" else datetime.date.fromisoformat(s) if t == "d" else bytes.fromhex(s) if t == "x" else s)
        else:
            out.append(v)
    return out


def keyset_where(engine, cols, after, start=0):
    """(c1 > a1) OR (c1 = a1 AND c2 > a2) ... - works on both engines (Oracle has no row-value comparison)"""
    parts, binds, i = [], [], start
    for n in range(len(cols)):
        eq = []
        for k in range(n):
            eq.append("%s = %s" % (qi(cols[k]), ph(engine, i)))
            binds.append(after[k])
            i += 1
        eq.append("%s > %s" % (qi(cols[n]), ph(engine, i)))
        binds.append(after[n])
        i += 1
        parts.append("(" + " AND ".join(eq) + ")")
    return "(" + " OR ".join(parts) + ")", binds


def in_list(engine, cols, keys, start=0):
    """(c) IN (...) or (c1, c2) IN ((..), (..)) with binds"""
    binds, i, groups = [], start, []
    for k in keys:
        g = []
        for v in k:
            g.append(ph(engine, i))
            binds.append(v)
            i += 1
        groups.append(g[0] if len(cols) == 1 else "(" + ", ".join(g) + ")")
    left = qi(cols[0]) if len(cols) == 1 else "(" + ", ".join(qi(c) for c in cols) + ")"
    return "%s IN (%s)" % (left, ", ".join(groups)), binds


def select_sql(engine, owner, table, cols, where, order, limit):
    sql = "select %s from %s.%s" % (", ".join(qi(c) for c in cols), qi(owner), qi(table))
    if where:
        sql += " where " + where
    if order:
        sql += " order by " + ", ".join(qi(c) for c in order)
    if limit:
        sql += (" fetch first %d rows only" % int(limit)) if engine == "oracle" else (" limit %d" % int(limit))
    return sql


def fetch_by_keys(conn, engine, owner, table, cols, pkcols, keys):
    cur, out = conn.cursor(), {}
    for i in range(0, len(keys), IN_CHUNK):
        part = keys[i:i + IN_CHUNK]
        w, b = in_list(engine, pkcols, part)
        cur.execute(select_sql(engine, owner, table, cols, w, None, None), b)
        n = len(pkcols)
        for r in cur.fetchall():
            out[tuple(norm(v) for v in r[:n])] = r
    return out


# ---------------------------------------------------------------------------------------------------------- verify
def verify_chunk(src, se, tgt, te, spec, after, limit, phase):
    """forward: the next `limit` source rows after `after` (by primary key), looked up on the target -> missing / different.
    reverse: the next target keys, looked up on the source -> extra on the target. Values never leave this function."""
    cmp = spec["cmp"]
    spk, tpk = [p for p, _ in cmp["pk"]], [t for _, t in cmp["pk"]]
    scols, tcols = spk + [s for s, _, _ in cmp["data"]], tpk + [t for _, t, _ in cmp["data"]]
    conn, eng, own, tab, keycols = (src, se, spec["src"]["owner"], spec["src"]["table"], spk) if phase == "forward" else (tgt, te, spec["tgt"]["owner"], spec["tgt"]["table"], tpk)
    cur = conn.cursor()
    w, b = keyset_where(eng, keycols, dec_key(after)) if after else ("", [])
    cur.execute(select_sql(eng, own, tab, (scols if phase == "forward" else keycols), w, keycols, limit), b)
    rows = cur.fetchall()
    n = len(keycols)
    res = {"rows": len(rows), "missing": [], "different": [], "extra": [], "missing_n": 0, "different_n": 0, "extra_n": 0, "next": enc_key(rows[-1][:n]) if rows else after, "done": len(rows) < limit}
    if not rows:
        res["done"] = True
        return res
    keys = [list(r[:n]) for r in rows]
    if phase == "forward":
        other = fetch_by_keys(tgt, te, spec["tgt"]["owner"], spec["tgt"]["table"], tcols, tpk, keys)
        for r in rows:
            k = tuple(norm(v) for v in r[:n])
            o = other.get(k)
            if o is None:
                res["missing_n"] += 1
                if len(res["missing"]) < MAX_KEYS:
                    res["missing"].append(enc_key(r[:n]))
            elif row_hash(r[n:]) != row_hash(o[n:]):
                res["different_n"] += 1
                if len(res["different"]) < MAX_KEYS:
                    res["different"].append(enc_key(r[:n]))
    else:
        other = fetch_by_keys(src, se, spec["src"]["owner"], spec["src"]["table"], spk, spk, keys)
        for r in rows:
            if tuple(norm(v) for v in r[:n]) not in other:
                res["extra_n"] += 1
                if len(res["extra"]) < MAX_KEYS:
                    res["extra"].append(enc_key(r[:n]))
    return res


def verify_keys(src, se, tgt, te, spec, keys):
    """re-check rows that differed (in-flight changes settle): -> still missing / different / extra, or now equal"""
    cmp = spec["cmp"]
    spk, tpk = [p for p, _ in cmp["pk"]], [t for _, t in cmp["pk"]]
    scols, tcols = spk + [s for s, _, _ in cmp["data"]], tpk + [t for _, t, _ in cmp["data"]]
    K = [dec_key(k) for k in keys]
    a = fetch_by_keys(src, se, spec["src"]["owner"], spec["src"]["table"], scols, spk, K)
    b = fetch_by_keys(tgt, te, spec["tgt"]["owner"], spec["tgt"]["table"], tcols, tpk, K)
    n, out = len(spk), {"missing": [], "different": [], "extra": [], "equal": 0}
    for k in K:
        nk = tuple(norm(v) for v in k)
        x, y = a.get(nk), b.get(nk)
        if x is None and y is None:
            out["equal"] += 1
        elif y is None:
            out["missing"].append(enc_key(k))
        elif x is None:
            out["extra"].append(enc_key(k))
        elif row_hash(x[n:]) != row_hash(y[n:]):
            out["different"].append(enc_key(k))
        else:
            out["equal"] += 1
    return out


# ---------------------------------------------------------------------------------------------------------- SQL_REDO
_TOK = re.compile(r"""\s*(?:("(?:[^"]|"")*")|('(?:[^']|'')*')|([-+]?\d+(?:\.\d+)?(?:[eE][-+]?\d+)?)|([A-Za-z_][A-Za-z0-9_$#]*)|(\S))""")
FUNCS = {"TO_DATE": "date", "TO_TIMESTAMP": "ts", "TO_TIMESTAMP_TZ": "tstz", "HEXTORAW": "raw", "UNISTR": "nstr", "TO_YMINTERVAL": "ym", "TO_DSINTERVAL": "ds"}


def _tokens(s):
    out, i = [], 0
    while i < len(s):
        m = _TOK.match(s, i)
        if not m or m.end() == i:
            break
        i = m.end()
        q, st, nu, w, p = m.groups()
        if q is not None:
            out.append(("id", q[1:-1].replace('""', '"')))
        elif st is not None:
            out.append(("str", st[1:-1].replace("''", "'")))
        elif nu is not None:
            out.append(("num", nu))
        elif w is not None:
            out.append(("w", w.upper(), w))
        elif p is not None:
            out.append(("p", p))
    return out


def _unistr(s):
    return re.sub(r"\\([0-9A-Fa-f]{4})", lambda m: chr(int(m.group(1), 16)), s)


class _P:
    def __init__(self, t):
        self.t, self.i = t, 0

    def peek(self):
        return self.t[self.i] if self.i < len(self.t) else ("eof",)

    def take(self):
        x = self.peek()
        self.i += 1
        return x

    def word(self, w):
        x = self.take()
        if not (x[0] == "w" and x[1] == w):
            raise ValueError("expected %s" % w)

    def punct(self, p):
        x = self.take()
        if not (x[0] == "p" and x[1] == p):
            raise ValueError("expected %r" % p)

    def ident(self):
        x = self.take()
        if x[0] != "id":
            raise ValueError("expected a quoted name")
        return x[1]

    def table(self):
        o = self.ident()
        self.punct(".")
        return o, self.ident()

    def value(self):
        x = self.take()
        if x[0] == "str":
            return ("s", x[1])
        if x[0] == "num":
            return ("n", x[1])
        if x[0] == "w" and x[1] == "NULL":
            return ("null",)
        if x[0] == "w" and x[1] in FUNCS:
            self.punct("(")
            args = []
            while True:
                a = self.take()
                if a[0] not in ("str", "num"):
                    raise ValueError("unsupported function argument")
                args.append(a[1])
                n = self.take()
                if n == ("p", ")"):
                    break
                if n != ("p", ","):
                    raise ValueError("bad function call")
            kind = FUNCS[x[1]]
            if kind == "nstr":
                return ("s", _unistr(args[0]))
            if kind in ("ym", "ds"):
                raise ValueError("interval values are not supported")
            return (kind, args[0]) + tuple(args[1:2])
        raise ValueError("unsupported value %r" % (x[1:2],))

    def end(self):
        x = self.peek()
        if x == ("p", ";"):
            self.take()
        if self.peek()[0] != "eof":
            raise ValueError("unexpected text after the statement")


def parse_redo(sql):
    """LogMiner SQL_REDO (NO_ROWID_IN_STMT) -> {op, owner, table, cols:{name: value}, where:{name: value}}; ValueError for
    anything this engine does not replicate (LOBs, intervals, PL/SQL, unknown shapes) - never a partial apply"""
    p = _P(_tokens(str(sql or "").strip()))
    w = p.take()
    if w[:2] == ("w", "INSERT"):
        p.word("INTO")
        o, t = p.table()
        p.punct("(")
        names = [p.ident()]
        while p.peek() == ("p", ","):
            p.take()
            names.append(p.ident())
        p.punct(")")
        p.word("VALUES")
        p.punct("(")
        vals = [p.value()]
        while p.peek() == ("p", ","):
            p.take()
            vals.append(p.value())
        p.punct(")")
        p.end()
        if len(names) != len(vals):
            raise ValueError("column / value count differ")
        return {"op": "INSERT", "owner": o, "table": t, "cols": dict(zip(names, vals)), "where": {}}
    if w[:2] == ("w", "UPDATE"):
        o, t = p.table()
        p.word("SET")
        cols = {}
        while True:
            n = p.ident()
            p.punct("=")
            cols[n] = p.value()
            if p.peek() == ("p", ","):
                p.take()
                continue
            break
        where = _where(p)
        p.end()
        return {"op": "UPDATE", "owner": o, "table": t, "cols": cols, "where": where}
    if w[:2] == ("w", "DELETE"):
        p.word("FROM")
        o, t = p.table()
        where = _where(p)
        p.end()
        return {"op": "DELETE", "owner": o, "table": t, "cols": {}, "where": where}
    raise ValueError("not an INSERT / UPDATE / DELETE")


def _where(p):
    where = {}
    if p.peek()[:2] != ("w", "WHERE"):
        return where
    p.take()
    while True:
        n = p.ident()
        x = p.peek()
        if x[:2] == ("w", "IS"):
            p.take()
            p.word("NULL")
            where[n] = ("null",)
        else:
            p.punct("=")
            where[n] = p.value()
        if p.peek()[:2] == ("w", "AND"):
            p.take()
            continue
        break
    return where


def _expr(engine, v, i):
    """a parsed value -> (sql expression, binds) for the target"""
    k = v[0]
    if k == "null":
        return "NULL", []
    if engine == "oracle":
        if k == "date":
            return "TO_DATE(%s, %s)" % (ph(engine, i), ph(engine, i + 1)), [v[1], v[2] if len(v) > 2 else "YYYY-MM-DD HH24:MI:SS"]
        if k == "ts":
            return "TO_TIMESTAMP(%s, %s)" % (ph(engine, i), ph(engine, i + 1)), [v[1], v[2] if len(v) > 2 else "YYYY-MM-DD HH24:MI:SS.FF6"]
        if k == "tstz":
            return "TO_TIMESTAMP_TZ(%s, %s)" % (ph(engine, i), ph(engine, i + 1)), [v[1], v[2] if len(v) > 2 else "YYYY-MM-DD HH24:MI:SS.FF6 TZH:TZM"]
        if k == "raw":
            return "HEXTORAW(%s)" % ph(engine, i), [v[1]]
        return ph(engine, i), [v[1]]
    if k == "raw":
        return "decode(%s, 'hex')" % ph(engine, i), [v[1]]
    return ph(engine, i), [v[1]]   # PostgreSQL infers the column type from a text parameter (dates are ISO here)


def plan_statement(engine, change, target, pk, lower=False):
    """one parsed change -> (sql, binds, expect_one_row) for the target table; the WHERE uses the primary key only"""
    nm = (lambda x: x.lower()) if lower else (lambda x: x)
    own, tab = target
    if change["op"] == "INSERT":
        names = list(change["cols"].keys())
        exprs, binds = [], []
        for n in names:
            e, b = _expr(engine, change["cols"][n], len(binds))
            exprs.append(e)
            binds += b
        return ("insert into %s.%s (%s) values (%s)" % (qi(own), qi(tab), ", ".join(qi(nm(n)) for n in names), ", ".join(exprs)), binds, False)
    keyvals = []
    for k in pk:
        if k not in change["where"]:
            raise ValueError("primary key column %s is not in the redo - add supplemental logging: ALTER TABLE %s.%s ADD SUPPLEMENTAL LOG DATA (PRIMARY KEY) COLUMNS" % (k, change["owner"], change["table"]))
        keyvals.append((k, change["where"][k]))
    binds, sets, conds = [], [], []
    if change["op"] == "UPDATE":
        for n, v in change["cols"].items():
            e, b = _expr(engine, v, len(binds))
            sets.append("%s = %s" % (qi(nm(n)), e))
            binds += b
    for k, v in keyvals:
        if v[0] == "null":
            raise ValueError("primary key value is NULL")
        e, b = _expr(engine, v, len(binds))
        conds.append("%s = %s" % (qi(nm(k)), e))
        binds += b
    if change["op"] == "UPDATE":
        if not sets:
            return None
        return ("update %s.%s set %s where %s" % (qi(own), qi(tab), ", ".join(sets), " and ".join(conds)), binds, True)
    return ("delete from %s.%s where %s" % (qi(own), qi(tab), " and ".join(conds)), binds, True)


# ---------------------------------------------------------------------------------------------------------- LogMiner
_MASK_S = re.compile(r"'(?:[^']|'')*'")
_MASK_N = re.compile(r"(?<![A-Za-z_$#:.0-9])\d+(?:\.\d+)?(?![A-Za-z_$#0-9])")


def mask(sql):
    return _MASK_N.sub(":n", _MASK_S.sub("':s'", str(sql or "")))


def program_of(session_info):
    m = re.search(r"OS_program_name=(\S+)", str(session_info or ""))
    return m.group(1)[:120] if m else ""


ARCHIVED_SQL = ("select name, thread#, sequence#, first_change#, next_change# from ("
                "select name, thread#, sequence#, first_change#, next_change#, row_number() over (partition by thread#, sequence# order by dest_id) rn "
                "from v$archived_log where name is not null and deleted = 'NO' and standby_dest = 'NO' and status = 'A' "
                "and next_change# > :1 and resetlogs_change# = (select resetlogs_change# from v$database)) where rn = 1 order by first_change#")
ONLINE_SQL = ("select min(f.member), l.thread#, l.sequence#, l.first_change# from v$log l join v$logfile f on f.group# = l.group# "
              "where l.status in ('CURRENT', 'ACTIVE') or l.archived = 'NO' group by l.thread#, l.sequence#, l.first_change# order by l.first_change#")


def plan_logs(archived, online, start, current, max_files):
    """which log files to mine from `start`: archived first, then online ones not archived yet; at most max_files archived
    (then the window ends where the last of them ends). -> (files, end_scn, gap_message)"""
    arch = [a for a in archived if a[4] > start]
    have = {(a[1], a[2]) for a in arch}
    files, end, gap = [], current, None
    if len(arch) > max_files:
        arch = arch[:max_files]
        end = min(current, max(a[4] for a in arch) - 1)
        files = [a[0] for a in arch]
    else:
        files = [a[0] for a in arch] + [o[0] for o in online if (o[1], o[2]) not in have]
    firsts = [a[3] for a in arch] + [o[3] for o in online if (o[1], o[2]) not in have]
    if not files:
        gap = "no redo log covers SCN %s" % start
    elif min(firsts) > start:
        gap = "the logs needed from SCN %s are no longer on disk (oldest available starts at %s)" % (start, min(firsts))
    return files, end, gap


def start_miner(cur, files, start, end):
    for i, f in enumerate(files):
        cur.execute("begin dbms_logmnr.add_logfile(logfilename => :1, options => :2); end;", [f, 1 if i == 0 else 3])
    cur.execute("begin dbms_logmnr.start_logmnr(startscn => :1, endscn => :2, options => dbms_logmnr.dict_from_online_catalog + dbms_logmnr.no_rowid_in_stmt); end;", [start, end])


def contents_sql(owners, tables, with_redo):
    """v$logmnr_contents for the tracked schemas / tables plus every START / COMMIT / ROLLBACK (transaction boundaries)"""
    binds, cond = [], []
    for o in owners:
        binds.append(ident(o, "owner"))
    ocond = "seg_owner in (%s)" % ", ".join(":%d" % (i + 1) for i in range(len(owners)))
    if tables:
        tl = []
        for o, t in tables:
            binds += [ident(o, "owner"), ident(t, "table")]
            tl.append("(seg_owner = :%d and table_name = :%d)" % (len(binds) - 1, len(binds)))
        cond.append("(" + " or ".join(tl) + ")")
    else:
        cond.append(ocond)
    redo = "sql_redo" if with_redo else "case when operation = 'DDL' then substr(sql_redo, 1, 2000) end"
    sql = ("select scn, to_char(timestamp, 'YYYY-MM-DD\"T\"HH24:MI:SS'), rawtohex(xid), operation, seg_owner, table_name, username, os_username, machine_name, session_info, "
           + redo + ", csf, rollback from v$logmnr_contents where operation in ('START', 'COMMIT', 'ROLLBACK') or "
           "(operation in ('INSERT', 'UPDATE', 'DELETE', 'DDL', 'UNSUPPORTED') and " + cond[0] + ")")
    if not tables:
        binds = binds[:len(owners)]
    return sql, binds


def group_transactions(rows):
    """mined rows (in redo order) -> (committed transactions in commit order, {xid: first tracked SCN} still open).
    Rows: (scn, ts, xid, operation, owner, table, user, os_user, machine, session_info, redo, csf, rollback)."""
    open_tx, done, buf = {}, [], ""
    for r in rows:
        scn, ts, xid, op = r[0], r[1], r[2], str(r[3] or "")
        if op == "START":
            continue
        if op == "COMMIT":
            t = open_tx.pop(xid, None)
            if t:
                t["commit_scn"], t["commit_ts"] = int(scn), ts
                done.append(t)
            continue
        if op == "ROLLBACK":
            open_tx.pop(xid, None)
            continue
        redo = r[10]
        if r[11]:                        # CSF: SQL_REDO continues on the next row
            buf += str(redo or "")
            continue
        if buf:
            redo, buf = buf + str(redo or ""), ""
        t = open_tx.get(xid)
        if t is None:
            t = open_tx[xid] = {"xid": xid, "first_scn": int(scn), "user": r[6] or "", "os_user": r[7] or "", "machine": r[8] or "", "program": program_of(r[9]), "changes": []}
        t["changes"].append({"scn": int(scn), "op": op, "owner": r[4] or "", "table": r[5] or "", "redo": redo, "rollback": bool(r[12])})
    return done, {x: t["first_scn"] for x, t in open_tx.items()}


def summarize_tx(t, mass=1000):
    tabs, ddl, n = {}, [], 0
    for c in t["changes"]:
        k = "%s.%s" % (c["owner"], c["table"])
        if c["op"] in ("INSERT", "UPDATE", "DELETE"):
            d = tabs.setdefault(k, {"INSERT": 0, "UPDATE": 0, "DELETE": 0})
            d[c["op"]] += -1 if c["rollback"] else 1
            n += 1
        elif c["op"] == "DDL":
            ddl.append({"table": k, "sql": mask(c["redo"])[:300]})
        elif c["op"] == "UNSUPPORTED":
            ddl.append({"table": k, "sql": "(unsupported change - LogMiner cannot show it)"})
    return {"xid": t["xid"], "commit_scn": t["commit_scn"], "commit_ts": t["commit_ts"], "user": t["user"], "os_user": t["os_user"], "machine": t["machine"],
            "program": t["program"], "rows": n, "tables": tabs, "ddl": ddl}


def mine(cur, owners, tables, cursor, max_files, with_redo):
    """one LogMiner window from the cursor {commit_scn, restart_scn}; -> (committed tx, new cursor, info)"""
    for s in NLS:
        cur.execute(s)
    cur.execute("select current_scn from v$database")
    current = int(cur.fetchone()[0])
    c, start = int(cursor["commit_scn"]), int(cursor["restart_scn"])
    cur.execute(ARCHIVED_SQL, [start])
    archived = [(r[0], int(r[1]), int(r[2]), int(r[3]), int(r[4])) for r in cur.fetchall()]
    cur.execute(ONLINE_SQL)
    online = [(r[0], int(r[1]), int(r[2]), int(r[3])) for r in cur.fetchall()]
    files, end, gap = plan_logs(archived, online, start, current, max_files)
    info = {"current_scn": current, "window": [start, end], "files": len(files), "gap": gap}
    if gap:
        return [], cursor, info
    start_miner(cur, files, start, end)
    try:
        sql, binds = contents_sql(owners, tables, with_redo)
        cur.execute(sql, binds)
        rows = cur.fetchall()
    finally:
        try:
            cur.execute("begin dbms_logmnr.end_logmnr; end;")
        except Exception:
            pass
    done, still_open = group_transactions(rows)
    done = [t for t in done if c < t["commit_scn"] <= end]
    # every commit up to `end` has now been seen; a tracked transaction still open restarts the next window at its first change
    nxt = {"commit_scn": max(c, end), "restart_scn": min(still_open.values()) if still_open else end}
    info["open_transactions"] = len(still_open)
    try:
        cur.execute("select round((sysdate - cast(scn_to_timestamp(:1) as date)) * 86400) from dual", [end])
        info["lag_s"] = int(cur.fetchone()[0])
    except Exception:
        info["lag_s"] = None
    return done, nxt, info


# ---------------------------------------------------------------------------------------------------------- replication
def read_checkpoint(conn, engine, table, job):
    own, tab = table
    cur = conn.cursor()
    cur.execute("select commit_scn, restart_scn from %s.%s where job_id = %s" % (qi(own), qi(tab), ph(engine, 0)), [job])
    r = cur.fetchone()
    return None if not r else {"commit_scn": int(r[0]), "restart_scn": int(r[1])}


def _vtext(v):
    return v[1] if v and len(v) > 1 else None


def apply_transactions(conn, engine, txs, job, window_restart, final_cursor):
    """apply committed transactions to the target with the checkpoint row updated in the SAME transaction. A checkpoint
    inside the window keeps restart_scn at the window's start (the window is not finished); the last one moves both.
    Conflicts (UPDATE / DELETE finding no row, INSERT finding the key) stop the job unless job.conflict == 'log'.
    PostgreSQL: every statement runs under a savepoint, because one error would otherwise abort the whole batch."""
    cur = conn.cursor()
    tmap = {("%s.%s" % (t["src_owner"], t["src_table"])).upper(): t for t in job["tables"]}
    ck_own, ck_tab = job["checkpoint"]
    lower = engine == "postgres" and job.get("lower_names", True)
    st = {"txns": 0, "rows": 0, "conflicts": [], "stopped": None, "last_commit_ts": None, "last_commit_scn": None}

    def checkpoint(commit_scn, restart_scn, n_tx, n_rows):
        cur.execute("update %s.%s set commit_scn = %s, restart_scn = %s, applied_at = %s, txns = txns + %s, rows_applied = rows_applied + %s where job_id = %s"
                    % (qi(ck_own), qi(ck_tab), ph(engine, 0), ph(engine, 1), "systimestamp" if engine == "oracle" else "now()", ph(engine, 2), ph(engine, 3), ph(engine, 4)),
                    [commit_scn, restart_scn, n_tx, n_rows, job["id"]])
        if cur.rowcount != 1:
            raise Refused("the checkpoint row for job %s is missing on the target - run the setup script" % job["id"])

    def stop(reason, **kw):
        conn.rollback()
        st["stopped"] = dict(kw, reason=reason)
        return st

    def run(sql, binds):
        """-> None when applied, else why it could not be"""
        if engine == "postgres":
            cur.execute("savepoint zyb_row")
        try:
            cur.execute(sql, binds)
            n = cur.rowcount
        except Exception as e:
            if engine == "postgres":
                cur.execute("rollback to savepoint zyb_row")
            if re.search(r"ORA-00001|unique|duplicate key|23505", str(e), re.I):
                return "row already on the target (duplicate key)", None
            return None, str(e)[:300]
        if engine == "postgres":
            cur.execute("release savepoint zyb_row")
        return (n, None)

    pend_tx = pend_rows = 0
    last = None
    for t in txs:
        for c in t["changes"]:
            key = ("%s.%s" % (c["owner"], c["table"])).upper()
            spec = tmap.get(key)
            if spec is None:
                continue
            if c["op"] in ("DDL", "UNSUPPORTED"):
                return stop("ddl" if c["op"] == "DDL" else "unsupported", table=key, commit_scn=t["commit_scn"],
                            detail=mask(c["redo"])[:300] if c["op"] == "DDL" else "a change LogMiner cannot show (LOB / unsupported type)")
            try:
                ch = parse_redo(c["redo"])
                plan = plan_statement(engine, ch, (spec["tgt_owner"], spec["tgt_table"]), spec["pk"], lower)
            except ValueError as e:
                return stop("unsupported", table=key, commit_scn=t["commit_scn"], detail=str(e)[:300])
            if plan is None:
                continue
            sql, binds, one = plan
            n, err = run(sql, binds)
            if err:
                return stop("error", table=key, commit_scn=t["commit_scn"], detail=err)
            why = n if isinstance(n, str) else ("row not found on the target" if one and n != 1 else None)
            if why:
                conflict = {"table": key, "op": c["op"], "commit_scn": t["commit_scn"], "detail": why, "key": {k: _vtext(ch["where"].get(k) or ch["cols"].get(k)) for k in spec["pk"]}}
                if job.get("conflict") == "log":
                    if len(st["conflicts"]) < 200:
                        st["conflicts"].append(conflict)
                    continue
                return stop("conflict", **conflict)
            pend_rows += 1
        pend_tx += 1
        last = t
        if pend_rows >= job.get("batch_rows", 5000):
            checkpoint(t["commit_scn"], window_restart, pend_tx, pend_rows)
            conn.commit()
            st["txns"] += pend_tx
            st["rows"] += pend_rows
            pend_tx = pend_rows = 0
    checkpoint(final_cursor["commit_scn"], final_cursor["restart_scn"], pend_tx, pend_rows)
    conn.commit()
    st["txns"] += pend_tx
    st["rows"] += pend_rows
    if last:
        st["last_commit_ts"], st["last_commit_scn"] = last["commit_ts"], last["commit_scn"]
    return st


def writer_session(conn, engine):
    cur = conn.cursor()
    if engine == "oracle":
        for s in NLS:
            cur.execute(s)


def dumps(o):
    return json.dumps(o, default=str)
