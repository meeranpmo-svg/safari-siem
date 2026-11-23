# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
"""Pure checks of engine/discovery/db_repl.py (run by tests/db-repl.test.js). Prints one JSON line of results."""
import datetime, decimal, importlib.util, json, sys
spec = importlib.util.spec_from_file_location("db_repl", sys.argv[1]); R = importlib.util.module_from_spec(spec); spec.loader.exec_module(R)
out = {}
def check(name, cond):
    out[name] = bool(cond)

# SQL_REDO shapes (NO_ROWID_IN_STMT, our NLS)
ins = R.parse_redo("""insert into "APP"."ORDERS"("ID","CUST","AMT","CREATED","NOTE","IMG") values ('1001','O''Brien','10.5',TO_DATE('2026-10-20 10:00:00', 'YYYY-MM-DD HH24:MI:SS'),NULL,HEXTORAW('0aff'));""")
check("insert", ins["op"] == "INSERT" and ins["cols"]["CUST"] == ("s", "O'Brien") and ins["cols"]["CREATED"] == ("date", "2026-10-20 10:00:00", "YYYY-MM-DD HH24:MI:SS") and ins["cols"]["NOTE"] == ("null",) and ins["cols"]["IMG"] == ("raw", "0aff"))
upd = R.parse_redo("""update "APP"."ORDERS" set "AMT" = '11', "NOTE" = NULL where "ID" = '1001' and "AMT" = '10.5' and "NOTE" IS NULL;""")
check("update", upd["op"] == "UPDATE" and upd["cols"] == {"AMT": ("s", "11"), "NOTE": ("null",)} and upd["where"]["ID"] == ("s", "1001") and upd["where"]["NOTE"] == ("null",))
dele = R.parse_redo("""delete from "APP"."ORDERS" where "ID" = '1001' and "CUST" = 'x';""")
check("delete", dele["op"] == "DELETE" and dele["where"]["ID"] == ("s", "1001"))
uni = R.parse_redo("""insert into "APP"."T"("N") values (UNISTR('\\0645\\062D\\0645\\062F'));""")
check("unistr", uni["cols"]["N"] == ("s", "محمد"))
refused = []
for bad in ["""insert into "APP"."T"("C") values (EMPTY_CLOB());""", "Unsupported", """update "APP"."T" set "A" = 'x' where "B" = 'y' or 1=1;""", """insert into "APP"."T"("A","B") values ('1');"""]:
    try:
        R.parse_redo(bad); refused.append(False)
    except ValueError:
        refused.append(True)
check("refuses_unsupported_and_tampered", all(refused))
# statements for each target: WHERE on the primary key only, binds never inlined
o = R.plan_statement("oracle", upd, ("REP", "ORDERS"), ["ID"])
check("plan_oracle_update", o[0] == 'update "REP"."ORDERS" set "AMT" = :1, "NOTE" = NULL where "ID" = :2' and o[1] == ["11", "1001"] and o[2] is True)
oi = R.plan_statement("oracle", ins, ("REP", "ORDERS"), ["ID"])
check("plan_oracle_insert", 'TO_DATE(:4, :5)' in oi[0] and 'HEXTORAW(:6)' in oi[0] and oi[1][5] == '0aff' and oi[1][3:5] == ["2026-10-20 10:00:00", "YYYY-MM-DD HH24:MI:SS"])
pg = R.plan_statement("postgres", ins, ("rep", "orders"), ["ID"], lower=True)
check("plan_pg_insert", pg[0].startswith('insert into "rep"."orders" ("id", "cust", "amt", "created", "note", "img") values (%s, %s, %s, %s, NULL, decode(%s, \'hex\'))'))
try:
    R.plan_statement("oracle", R.parse_redo("""delete from "APP"."ORDERS" where "CUST" = 'x';"""), ("REP", "ORDERS"), ["ID"]); check("pk_required", False)
except ValueError as e:
    check("pk_required", "SUPPLEMENTAL LOG DATA (PRIMARY KEY)" in str(e))
# hashing: the same row on Oracle and PostgreSQL hashes the same
check("norm_cross_engine", R.row_hash([decimal.Decimal("1.50"), datetime.datetime(2026, 1, 1), "", "x"]) == R.row_hash([1.5, datetime.date(2026, 1, 1), None, "x"]) and R.row_hash([1]) == R.row_hash([decimal.Decimal("1.0")]))
check("norm_detects_change", R.row_hash(["a", 1]) != R.row_hash(["a", 2]) and R.row_hash(["ab", "c"]) != R.row_hash(["a", "bc"]))
k = R.enc_key([decimal.Decimal("12.50"), datetime.datetime(2026, 10, 20, 9, 30), "A", 7])
check("key_roundtrip", R.dec_key(json.loads(json.dumps(k))) == [decimal.Decimal("12.50"), datetime.datetime(2026, 10, 20, 9, 30), "A", 7])
w, b = R.keyset_where("oracle", ["A", "B"], [1, 2])
check("keyset_oracle", w == '(("A" > :1) OR ("A" = :2 AND "B" > :3))' and b == [1, 1, 2])
w2, b2 = R.in_list("postgres", ["A", "B"], [[1, 2], [3, 4]])
check("in_list_pg", w2 == '("A", "B") IN ((%s, %s), (%s, %s))' and b2 == [1, 2, 3, 4])
for badname in ['X"; drop table t; --', "a b", ""]:
    try:
        R.qi(badname); check("ident_refused_" + str(len(badname)), False)
    except R.Refused:
        check("ident_refused_" + str(len(badname)), True)
# which logs to mine
arch = [("/arch/1_10.arc", 1, 10, 100, 200), ("/arch/1_11.arc", 1, 11, 200, 300), ("/arch/1_12.arc", 1, 12, 300, 400)]
onl = [("/redo/g1.log", 1, 13, 400)]
f, e, g = R.plan_logs(arch, onl, 150, 450, 4)
check("logs_all", f == ["/arch/1_10.arc", "/arch/1_11.arc", "/arch/1_12.arc", "/redo/g1.log"] and e == 450 and g is None)
f, e, g = R.plan_logs(arch, onl, 150, 450, 2)
check("logs_capped", f == ["/arch/1_10.arc", "/arch/1_11.arc"] and e == 299 and g is None)
f, e, g = R.plan_logs(arch[1:], onl, 150, 450, 4)
check("logs_gap", g is not None and "no longer on disk" in g)
# transactions by XID: commit, rollback, CSF continuation, open at the end of the window
def row(scn, xid, op, redo=None, csf=0, owner="APP", table="ORDERS", rb=0):
    return (scn, "2026-10-20T10:00:00", xid, op, owner if redo is not None else None, table if redo is not None else None, "APP_USER", "oracle", "erp-app1", "OS_program_name=JDBC Thin Client login_username=APP_USER", redo, csf, rb)
rows = [row(101, "X1", "START"), row(102, "X1", "INSERT", """insert into "APP"."ORDERS"("ID") values ('1');"""),
        row(103, "X2", "INSERT", """insert into "APP"."ORDERS"("ID","NOTE") values ('2','""", csf=1), row(103, "X2", "INSERT", """long text');"""),
        row(104, "X3", "DELETE", """delete from "APP"."ORDERS" where "ID" = '9';"""), row(105, "X1", "COMMIT"), row(106, "X3", "ROLLBACK"), row(107, "X4", "UPDATE", """update "APP"."ORDERS" set "A" = '1' where "ID" = '3';""")]
done, still = R.group_transactions(rows)
check("tx_grouping", [t["xid"] for t in done] == ["X1"] and done[0]["commit_scn"] == 105 and still == {"X2": 103, "X4": 107})
rows2 = rows + [row(108, "X2", "COMMIT")]
done2, _ = R.group_transactions(rows2)
x2 = [t for t in done2 if t["xid"] == "X2"][0]
check("tx_csf_joined", x2["changes"][0]["redo"].endswith("""long text');""") and R.parse_redo(x2["changes"][0]["redo"])["cols"]["NOTE"] == ("s", "long text"))
sm = R.summarize_tx(done[0])
check("summary_no_values", sm["program"] == "JDBC" and sm["tables"] == {"APP.ORDERS": {"INSERT": 1, "UPDATE": 0, "DELETE": 0}} and "redo" not in json.dumps(sm))
check("mask", R.mask("GRANT SELECT ON t TO u IDENTIFIED BY 'Secret1' WHERE id = 42") == "GRANT SELECT ON t TO u IDENTIFIED BY ':s' WHERE id = :n")

# mine() against a fake Oracle cursor: two windows, a transaction open across the boundary is applied once, complete
class Cur:
    def __init__(self, windows):
        self.windows, self.w, self.rows, self.calls = windows, -1, [], []
    def execute(self, sql, binds=None):
        self.calls.append((sql.split()[0:3], binds))
        s = sql.lower()
        if "current_scn from v$database" in s: self.w += 1; self.rows = [(self.windows[self.w]["current"],)]
        elif "from v$archived_log" in s: self.rows = []
        elif "from v$log l" in s: self.rows = [("/redo/g1.log", 1, 13, 50)]
        elif "from v$logmnr_contents" in s: self.rows = self.windows[self.w]["rows"]
        elif "scn_to_timestamp" in s: self.rows = [(4,)]
        else: self.rows = []
    def fetchone(self): return self.rows[0]
    def fetchall(self): return self.rows
w1 = {"current": 200, "rows": [row(110, "A", "INSERT", """insert into "APP"."ORDERS"("ID") values ('1');"""), row(111, "A", "COMMIT"), row(120, "B", "INSERT", """insert into "APP"."ORDERS"("ID") values ('2');""")]}
w2 = {"current": 300, "rows": [row(110, "A", "INSERT", """insert into "APP"."ORDERS"("ID") values ('1');"""), row(111, "A", "COMMIT"), row(120, "B", "INSERT", """insert into "APP"."ORDERS"("ID") values ('2');"""), row(210, "B", "UPDATE", """update "APP"."ORDERS" set "N" = 'x' where "ID" = '2';"""), row(220, "B", "COMMIT")]}
c = Cur([w1, w2])
d1, n1, i1 = R.mine(c, ["APP"], [], {"commit_scn": 100, "restart_scn": 100}, 4, True)
check("mine_w1", [t["xid"] for t in d1] == ["A"] and n1 == {"commit_scn": 200, "restart_scn": 120} and i1["open_transactions"] == 1)
d2, n2, i2 = R.mine(c, ["APP"], [], n1, 4, True)
check("mine_w2_once_and_complete", [t["xid"] for t in d2] == ["B"] and len(d2[0]["changes"]) == 2 and n2 == {"commit_scn": 300, "restart_scn": 300})
check("mine_started_at_restart", [b for (w, b) in c.calls if w[:2] == ["begin", "dbms_logmnr.start_logmnr(startscn"]] == [[100, 200], [120, 300]])
print(json.dumps(out))
