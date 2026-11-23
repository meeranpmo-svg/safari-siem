# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
"""PostgreSQL checks of the engines through the REAL helper ops (inv-helper.py -> db_repl.py). argv: helper path, port."""
import importlib.util, json, sys, decimal, datetime
spec = importlib.util.spec_from_file_location("h", sys.argv[1]); H = importlib.util.module_from_spec(spec); spec.loader.exec_module(H)
R = H._repl()
import pg8000.dbapi
port = int(sys.argv[2])
su = pg8000.dbapi.connect(host="127.0.0.1", port=port, user="zybsu", database="postgres"); su.autocommit = True
c = su.cursor(); c.execute("create database zyb"); su.close()
su = pg8000.dbapi.connect(host="127.0.0.1", port=port, user="zybsu", database="zyb"); su.autocommit = True; c = su.cursor()
for s in ["create schema src", "create schema tgt",
          "create table src.orders (id integer primary key, cust varchar(40), amt numeric(10,2), created date, note text)",
          "create table tgt.orders (id integer primary key, cust varchar(40), amt numeric, created timestamp, note text, extra_col text)",
          "create table tgt.zyb_repl_checkpoint (job_id varchar(64) primary key, commit_scn numeric not null, restart_scn numeric not null, applied_at timestamp, txns numeric default 0, rows_applied numeric default 0)",
          "create role zyb_verify login password 'Verify-Pw-1'", "grant usage on schema src, tgt to zyb_verify", "grant select on src.orders, tgt.orders to zyb_verify",
          "create role zyb_writer login password 'Writer-Pw-1'", "grant usage on schema tgt to zyb_writer", "grant select, insert, update, delete on tgt.orders to zyb_writer",
          "grant select, update on tgt.zyb_repl_checkpoint to zyb_writer",
          "create role zyb_big login createrole password 'Big-Pw-1'", "grant usage on schema src, tgt to zyb_big", "grant select on src.orders, tgt.orders to zyb_big"]:
    c.execute(s)
c.execute("insert into src.orders select g, 'cust' || g, (g % 97) + 0.5, date '2026-01-01' + (g % 300), case when g % 5 = 0 then null else 'n' || g end from generate_series(1, 1000) g")
c.execute("insert into tgt.orders (id, cust, amt, created, note) select id, cust, amt::numeric(12,4), created::timestamp, note from src.orders")
c.execute("delete from tgt.orders where id in (10, 500, 999)")                        # missing on the target
c.execute("update tgt.orders set cust = 'CHANGED' where id = 20")                     # different
c.execute("update tgt.orders set note = 'n77x' where id = 77")                        # different
c.execute("insert into tgt.orders (id, cust, amt, created) values (5000, 'only on target', 1, now())")   # extra
out = {}
def check(n, cond): out[n] = bool(cond)
side = lambda u, p: {"engine": "postgres", "host": "127.0.0.1", "port": port, "username": u, "password": p, "database": "zyb"}

# describe: columns compared, the target-only column reported, numeric(10,2) vs numeric and date vs timestamp compared as values
d = H.op_verify_describe({"src": side("zyb_verify", "Verify-Pw-1"), "tgt": side("zyb_verify", "Verify-Pw-1"), "tables": [{"owner": "src", "table": "orders", "tgt_owner": "tgt", "tgt_table": "orders"}]})
check("describe_ok", d.get("ok") and d["tables"][0]["ok"] and d["tables"][0]["only_target"] == ["extra_col"] and [p for p, _ in d["tables"][0]["cmp"]["pk"]] == ["id"])
spec_ = {"src": d["tables"][0]["src"], "tgt": d["tables"][0]["tgt"], "cmp": d["tables"][0]["cmp"]}
miss, diff, extra, rows, after, calls = [], [], [], 0, None, 0
while True:
    r = H.op_verify_chunk({"src": side("zyb_verify", "Verify-Pw-1"), "tgt": side("zyb_verify", "Verify-Pw-1"), "spec": spec_, "after": after, "limit": 300, "phase": "forward"})
    calls += 1; rows += r["rows"]; miss += r["missing"]; diff += r["different"]; after = r["next"]
    if r["done"]: break
check("forward_chunks", calls == 4 and rows == 1000)
check("forward_found", sorted(k[0] for k in miss) == [10, 500, 999] and sorted(k[0] for k in diff) == [20, 77])
after = None
while True:
    r = H.op_verify_chunk({"src": side("zyb_verify", "Verify-Pw-1"), "tgt": side("zyb_verify", "Verify-Pw-1"), "spec": spec_, "after": after, "limit": 400, "phase": "reverse"})
    extra += r["extra"]; after = r["next"]
    if r["done"]: break
check("reverse_found", [k[0] for k in extra] == [5000])
# an in-flight change settles: row 20 fixed on the target -> the recheck says equal
c.execute("update tgt.orders set cust = 'cust20' where id = 20")
k = H.op_verify_keys({"src": side("zyb_verify", "Verify-Pw-1"), "tgt": side("zyb_verify", "Verify-Pw-1"), "spec": spec_, "keys": diff + miss + extra})
check("recheck", k["equal"] == 1 and [x[0] for x in k["different"]] == [77] and sorted(x[0] for x in k["missing"]) == [10, 500, 999] and [x[0] for x in k["extra"]] == [5000])
# an over-privileged account is refused before anything runs
b = H.op_verify_describe({"src": side("zyb_big", "Big-Pw-1"), "tgt": side("zyb_verify", "Verify-Pw-1"), "tables": [{"owner": "src", "table": "orders"}]})
check("big_refused", b.get("ok") is False and b.get("error_class") == "unsafe")
# verify account cannot write (read-only session + no grant)
conn = H.connect_db(side("zyb_verify", "Verify-Pw-1")); R.read_only(conn, "postgres")
try:
    conn.cursor().execute("delete from tgt.orders where id = 1"); check("verify_cannot_write", False)
except Exception:
    check("verify_cannot_write", True)
conn.close()

# ---- apply to a PostgreSQL target: checkpoint in the same transaction, conflicts
c.execute("insert into tgt.zyb_repl_checkpoint (job_id, commit_scn, restart_scn) values ('REP-0001', 100, 100)")
job = {"id": "REP-0001", "checkpoint": ["tgt", "zyb_repl_checkpoint"], "conflict": "stop", "tables": [{"src_owner": "APP", "src_table": "ORDERS", "tgt_owner": "tgt", "tgt_table": "orders", "pk": ["ID"]}]}
def tx(scn, *redos):
    return {"xid": "X%d" % scn, "commit_scn": scn, "commit_ts": "2026-10-20T10:00:00", "first_scn": scn - 1, "user": "APP", "os_user": "", "machine": "", "program": "",
            "changes": [{"scn": scn - 1, "op": r.split()[0].upper(), "owner": "APP", "table": "ORDERS", "redo": r, "rollback": False} for r in redos]}
txs = [tx(110, """insert into "APP"."ORDERS"("ID","CUST","AMT","CREATED","NOTE") values ('7001','new',' 12.25',TO_DATE('2026-10-20 10:00:00', 'YYYY-MM-DD HH24:MI:SS'),NULL);"""),
       tx(120, """update "APP"."ORDERS" set "CUST" = 'O''Neil' where "ID" = '1' and "CUST" = 'cust1';""", """delete from "APP"."ORDERS" where "ID" = '2' and "CUST" = 'cust2';""")]
w = H.connect_db(side("zyb_writer", "Writer-Pw-1"))
R.check_account(w, "postgres", R.ORACLE_WRITER_SAFE, "replication target")
st = R.apply_transactions(w, "postgres", txs, job, 100, {"commit_scn": 200, "restart_scn": 150})
c.execute("select cust from tgt.orders where id in (1, 2, 7001) order by id"); got = [r[0] for r in c.fetchall()]
c.execute("select commit_scn, restart_scn, txns, rows_applied from tgt.zyb_repl_checkpoint where job_id = 'REP-0001'"); ck = c.fetchone()
check("applied", st["stopped"] is None and st["txns"] == 2 and st["rows"] == 3 and got == ["O'Neil", "new"])
check("checkpoint_moved", [int(x) for x in ck] == [200, 150, 2, 3])
# conflict (stop): an UPDATE finding no row -> the WHOLE batch rolls back, checkpoint unchanged
bad = [tx(210, """insert into "APP"."ORDERS"("ID","CUST") values ('7002','x');"""), tx(220, """update "APP"."ORDERS" set "CUST" = 'y' where "ID" = '424242';""")]
st2 = R.apply_transactions(w, "postgres", bad, job, 150, {"commit_scn": 300, "restart_scn": 300})
c.execute("select count(*) from tgt.orders where id = 7002"); n7002 = c.fetchone()[0]
c.execute("select commit_scn from tgt.zyb_repl_checkpoint where job_id = 'REP-0001'"); ck2 = int(c.fetchone()[0])
check("conflict_stops_and_rolls_back", st2["stopped"]["reason"] == "conflict" and st2["stopped"]["key"] == {"ID": "424242"} and n7002 == 0 and ck2 == 200)
# conflict (log): a duplicate INSERT is recorded, the rows around it are kept (savepoint), checkpoint moves
job["conflict"] = "log"
dup = [tx(230, """insert into "APP"."ORDERS"("ID","CUST") values ('7003','a');""", """insert into "APP"."ORDERS"("ID","CUST") values ('1','dup');""", """insert into "APP"."ORDERS"("ID","CUST") values ('7004','b');""")]
st3 = R.apply_transactions(w, "postgres", dup, job, 200, {"commit_scn": 400, "restart_scn": 400})
c.execute("select count(*) from tgt.orders where id in (7003, 7004)"); kept = c.fetchone()[0]
c.execute("select commit_scn from tgt.zyb_repl_checkpoint where job_id = 'REP-0001'"); ck3 = int(c.fetchone()[0])
check("conflict_log_keeps_others", st3["stopped"] is None and len(st3["conflicts"]) == 1 and "duplicate" in st3["conflicts"][0]["detail"] and kept == 2 and ck3 == 400)
# the checkpoint row missing = refused, nothing applied
c.execute("delete from tgt.zyb_repl_checkpoint")
try:
    R.apply_transactions(w, "postgres", [tx(410, """insert into "APP"."ORDERS"("ID","CUST") values ('7005','z');""")], job, 400, {"commit_scn": 500, "restart_scn": 500}); check("no_checkpoint_refused", False)
except R.Refused:
    w.rollback(); c.execute("select count(*) from tgt.orders where id = 7005"); check("no_checkpoint_refused", c.fetchone()[0] == 0)
# writer with CREATEROLE refused
bw = H.connect_db(side("zyb_big", "Big-Pw-1"))
try:
    R.check_account(bw, "postgres", R.ORACLE_WRITER_SAFE, "replication target"); check("big_writer_refused", False)
except R.Refused:
    check("big_writer_refused", True)
print(json.dumps(out))
