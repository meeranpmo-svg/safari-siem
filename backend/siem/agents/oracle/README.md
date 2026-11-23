# Oracle Database collector (health, performance, audit)

Sends an Oracle Database 12.2 / 18c / **19c** / 21c instance to the SIEM. Source type `oracle-health`: parsers are
`engine/db-audit/oracle-health.js`, `oracle-perf.js` and `oracle-audit.js`, and the rules are `SENTRA-ORA-*` and `SENTRA-ORAP-*`.
The collector runs on the database host every 60 s. It logs in with a **read-only** account and ships gzip NDJSON over
HTTPS. Nothing in the database is changed.

| What | From | Rules |
|---|---|---|
| Instance up / down, listener | `V$INSTANCE`, `V$DATABASE`, `lsnrctl status` | SENTRA-ORA-008 |
| Tablespaces, recovery area, growth forecast | `DBA_TABLESPACE_USAGE_METRICS`, `V$RECOVERY_FILE_DEST`; growth from the collector's own daily samples (needs 7 days) | SENTRA-ORA-009, SENTRA-ORAP-010 |
| RMAN backups, redo / archiving, Data Guard | `V$RMAN_BACKUP_JOB_DETAILS`, `V$LOG*`, `V$ARCHIVE_DEST`, `V$DATAGUARD_STATS` | SENTRA-ORA-007, -010, SENTRA-ORAP-011 |
| **Performance**: load profile (AAS vs CPUs, DB time, executions, redo), efficiency ratios | `V$SYSMETRIC` (60-s interval) | SENTRA-ORAP-001 |
| **Performance**: wait classes and events (commit / single-block read latency) | `V$WAITCLASSMETRIC`, `V$EVENTMETRIC` | SENTRA-ORAP-002, -003 |
| **Performance**: active sessions and the SQL they run (sampled each run) | `V$SESSION` | dashboards |
| **Performance**: blocking chains, long-running calls, execution plan changes | `V$SESSION`, `V$SQL` | SENTRA-ORAP-004, -005, -006 |
| **Performance**: TEMP / UNDO (ORA-01555 risk), SGA / PGA, process & session limits, redo switch rate, ASM, host | `V$TEMPSEG_USAGE`, `V$UNDOSTAT`, `V$SGAINFO`, `V$PGASTAT`, `V$RESOURCE_LIMIT`, `V$ASM_DISKGROUP`, `V$OSSTAT` | SENTRA-ORAP-007, -008, -009 |
| Audit trail: logons, failed logons, grants, user / role changes | `UNIFIED_AUDIT_TRAIL` (what the enabled audit policies record; passwords in SQL text are masked) | SENTRA-ORA-001 … -006 |
| Alert log errors | the alert log (new lines each run) | dashboards |

**Licensing.** Everything above uses views that need no extra Oracle licence. Active Session History and AWR
(`V$ACTIVE_SESSION_HISTORY`, `DBA_HIST_*`) belong to the **Oracle Diagnostics Pack**. The collector never touches them
unless `PACK_ASH=1`; set that only if the database is licensed for the pack.

## Setup (Linux database host)

1. **SIEM**: go to Log Sources, then *Add source*, then *Oracle Database — health & performance*. Note the source id (e.g.
   `ora-prod19c`). Copy the token, which is shown once.
2. **Copy this folder** to the DB host (e.g. `scp -r agents/oracle dbhost:/tmp/sentra-oracle`) and install it:
   ```bash
   sudo bash /tmp/sentra-oracle/install-collector.sh --user oracle      # asks for the token (hidden)
   ```
3. **DBA** creates the monitoring account as SYSDBA. In a container database, do this inside the PDB:
   ```sql
   sqlplus / as sysdba
   SQL> ALTER SESSION SET CONTAINER = PRODPDB1;   -- CDB only
   SQL> @/opt/sentra-oracle/create-monitor-user.sql  -- asks the account name (SENTRA_MON) and password (hidden)
   ```
   Put the password in `/etc/sentra-oracle/db-password` (one line, mode 600, owner oracle). An Oracle wallet with alias
   `SENTRA_MON` works too (`DB_CONNECT=/@SENTRA_MON`, no password file).
4. **Edit** `/etc/sentra-oracle/collector.conf`: set `ORACLE_HOME`, `ORACLE_SID`, `DB_CONNECT`, `SOURCE_ID`, and the SIEM
   certificate (`CA_FILE`).
5. **Test**, then start:
   ```bash
   sudo -u oracle /opt/sentra-oracle/sentra-oracle-collector.sh --test
   sudo systemctl start sentra-oracle-collector
   ```
   `--test` prints what it collected (`instance 1, tablespace 6, load_profile 1, wait_events 12, …`), any query error,
   and the SIEM's answer. A missing grant shows as `ORA-00942`: re-run step 3. `--dry-run` prints the NDJSON and sends
   nothing.

**Audit policies**: 19c has `ORA_LOGON_FAILURES` and `ORA_SECURECONFIG` on by default, which covers failed logons,
grants and user changes. Turning on more policies (e.g. `ORA_ACCOUNT_MGMT`) is the DBA's decision. The collector only
reads the trail.

**Solaris**: run the collector from `oracle`'s crontab (`* * * * * /opt/sentra-oracle/sentra-oracle-collector.sh --once`)
instead of systemd. It uses `/usr/gnu/bin` or `/usr/xpg4/bin` tools when present.

## Operations

* Log: `/var/lib/sentra-oracle/collector.log`, one line per run (records, query errors, batches sent / waiting).
* A batch the SIEM did not accept waits in `/var/lib/sentra-oracle/spool` and is re-sent next run with the same batch id,
  so the SIEM drops repeats. Up to `SPOOL_MAX` batches are kept.
* The token and the password are read from 600 files and never put on a command line. The collector refuses a secret
  file that others can read.
* Remove: `sudo bash install-collector.sh --uninstall`, then as SYSDBA `DROP USER SENTRA_MON CASCADE;`.

Tests: `node --test tests/oracle-collector.test.js` runs the real script against a fake `sqlplus` / `lsnrctl` and a local
ingest endpoint, and parses every shipped line with the SIEM's own Oracle parsers.
