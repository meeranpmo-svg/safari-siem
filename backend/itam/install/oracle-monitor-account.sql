-- oracle-monitor-account.sql - a dedicated, read-only Oracle account for the platform (AI Oracle DBA / database health).
-- Run as a DBA in the database that is monitored: for a multitenant database, connect to the PDB (the same service name you
-- enter in Connections & Setup → Oracle databases). Review it first; change the user name and password.
--
-- What the account can do: log in, and SELECT from the 19 dictionary views listed below - nothing else. It cannot read
-- business tables, change data, change settings or see other schemas' objects beyond the dictionary.
-- The platform checks this itself at every login (session_privs): an account holding any system privilege other than
-- CREATE SESSION / SELECT ANY DICTIONARY / SET CONTAINER is refused and paused before a single query runs.
--
-- What the platform runs: the fixed SELECTs in engine/discovery/inv-helper.py (ORACLE_HEALTH) inside a read-only
-- transaction, each cut off after 10 s (call timeout), one session at a time, every 4 minutes; the two dictionary scans
-- (backup history, invalid objects) once an hour; the performance metrics (load, wait classes, active sessions, host)
-- every pass. The session shows in v$session as MODULE = 'ZYBERON-MONITOR',
-- CLIENT_IDENTIFIER = 'zyberon-itam'. A refused login (wrong / expired password, locked account) pauses the database in
-- the platform until an administrator tests it again, so the platform never locks the account out by retrying.

-- 1. a profile that keeps the account small: at most 2 sessions, idle sessions dropped, locked briefly after bad logins.
--    Keep PASSWORD_LIFE_TIME in line with your password policy: when it expires the platform pauses, it does not retry.
CREATE PROFILE zyb_monitor_prof LIMIT
  SESSIONS_PER_USER      2
  IDLE_TIME              10
  CONNECT_TIME           30
  FAILED_LOGIN_ATTEMPTS  5
  PASSWORD_LOCK_TIME     1/24;

-- 2. the user (no tablespace quota: it can create nothing)
CREATE USER zyb_monitor IDENTIFIED BY "Change-Me-Long-Random-1" PROFILE zyb_monitor_prof
  DEFAULT TABLESPACE users QUOTA 0 ON users;
GRANT CREATE SESSION TO zyb_monitor;

-- 3. exactly the views the platform reads (SELECT only)
GRANT SELECT ON sys.v_$version                 TO zyb_monitor;
GRANT SELECT ON sys.v_$instance                TO zyb_monitor;
GRANT SELECT ON sys.v_$database                TO zyb_monitor;
GRANT SELECT ON sys.v_$session                 TO zyb_monitor;
GRANT SELECT ON sys.v_$parameter               TO zyb_monitor;
GRANT SELECT ON sys.v_$log                     TO zyb_monitor;
GRANT SELECT ON sys.v_$archived_log            TO zyb_monitor;
GRANT SELECT ON sys.v_$log_history             TO zyb_monitor;
GRANT SELECT ON sys.v_$archive_dest            TO zyb_monitor;
GRANT SELECT ON sys.v_$rman_backup_job_details TO zyb_monitor;
GRANT SELECT ON sys.v_$dataguard_stats         TO zyb_monitor;
GRANT SELECT ON sys.v_$recovery_file_dest      TO zyb_monitor;
GRANT SELECT ON sys.v_$diag_alert_ext          TO zyb_monitor;   -- ORA- errors from the alert log (Database Dashboard → Error findings), read hourly
GRANT SELECT ON sys.dba_tablespace_usage_metrics TO zyb_monitor;
GRANT SELECT ON sys.dba_tablespaces            TO zyb_monitor;
GRANT SELECT ON sys.dba_objects                TO zyb_monitor;
-- performance (Database Performance page, AI Oracle DBA): licence-free V$ metric views - no ASH / AWR (Diagnostics Pack)
GRANT SELECT ON sys.v_$sysmetric               TO zyb_monitor;
GRANT SELECT ON sys.v_$waitclassmetric         TO zyb_monitor;
GRANT SELECT ON sys.v_$system_wait_class       TO zyb_monitor;
GRANT SELECT ON sys.v_$osstat                  TO zyb_monitor;
-- (session_privs, which the platform checks first, is readable by every user already)
-- tuning (Databases -> Oracle Tuning; Oracle 12.2+): Top SQL, execution plans, waits, memory, temp/undo, limits, statistics
GRANT SELECT ON sys.v_$sqlstats                TO zyb_monitor;
GRANT SELECT ON sys.v_$sql                     TO zyb_monitor;
GRANT SELECT ON sys.v_$sql_plan                TO zyb_monitor;
GRANT SELECT ON sys.v_$sql_plan_statistics_all TO zyb_monitor;
GRANT SELECT ON sys.v_$eventmetric             TO zyb_monitor;
GRANT SELECT ON sys.v_$event_name              TO zyb_monitor;
-- V$TEMPSEG_USAGE and GV$TEMPSEG_USAGE are public synonyms (for V_$SORT_USAGE / GV_$SORT_USAGE on most versions), so
-- "GRANT SELECT ON sys.gv_$tempseg_usage" fails with ORA-00942: grant on whatever the synonyms point to
BEGIN
  FOR s IN (SELECT DISTINCT table_name FROM dba_synonyms WHERE owner = 'PUBLIC' AND table_owner = 'SYS' AND synonym_name IN ('V$TEMPSEG_USAGE', 'GV$TEMPSEG_USAGE')) LOOP
    EXECUTE IMMEDIATE 'GRANT SELECT ON sys.' || s.table_name || ' TO zyb_monitor';
  END LOOP;
END;
/
GRANT SELECT ON sys.dba_temp_files             TO zyb_monitor;
GRANT SELECT ON sys.v_$undostat                TO zyb_monitor;
GRANT SELECT ON sys.v_$sgainfo                 TO zyb_monitor;
GRANT SELECT ON sys.v_$pgastat                 TO zyb_monitor;
GRANT SELECT ON sys.v_$resource_limit          TO zyb_monitor;
GRANT SELECT ON sys.v_$asm_diskgroup           TO zyb_monitor;
GRANT SELECT ON sys.dba_tab_statistics         TO zyb_monitor;
GRANT SELECT ON sys.dba_users                  TO zyb_monitor;
-- GoldenGate integrated Extract / Replicat (only where GoldenGate runs; harmless otherwise)
GRANT SELECT ON sys.dba_capture                TO zyb_monitor;
GRANT SELECT ON sys.dba_apply                  TO zyb_monitor;
GRANT SELECT ON sys.v_$goldengate_capture      TO zyb_monitor;
GRANT SELECT ON sys.v_$gg_apply_coordinator    TO zyb_monitor;
-- Data Guard (Databases -> Replication & Data Guard): transport, apply, gaps, broker, standby redo logs, NOLOGGING changes
GRANT SELECT ON sys.v_$archive_dest_status      TO zyb_monitor;
GRANT SELECT ON sys.v_$thread                   TO zyb_monitor;   -- RAC: configured instances (a down node stays visible)
GRANT SELECT ON sys.gv_$instance                TO zyb_monitor;   -- RAC: running instances on every node
-- DBA alerts: long-running scheduler jobs, code changes (who: the unified audit trail, AUDIT_VIEWER below)
GRANT SELECT ON sys.dba_scheduler_running_jobs  TO zyb_monitor;
-- Application Connections: database links and what each application user can change (judging a link into this database)
GRANT SELECT ON sys.dba_db_links               TO zyb_monitor;
GRANT SELECT ON sys.dba_role_privs             TO zyb_monitor;
GRANT SELECT ON sys.dba_sys_privs              TO zyb_monitor;
GRANT SELECT ON sys.dba_tab_privs              TO zyb_monitor;
GRANT SELECT ON sys.dba_tables                 TO zyb_monitor;
GRANT SELECT ON sys.v_$dataguard_process        TO zyb_monitor;
GRANT SELECT ON sys.v_$archive_gap              TO zyb_monitor;
GRANT SELECT ON sys.v_$dataguard_status         TO zyb_monitor;
GRANT SELECT ON sys.v_$dg_broker_config         TO zyb_monitor;
GRANT SELECT ON sys.v_$standby_log              TO zyb_monitor;
GRANT SELECT ON sys.v_$datafile                 TO zyb_monitor;
-- Morning Health Check (Databases -> Morning Health Check): ASM space and the standby's managed recovery process
GRANT SELECT ON sys.v_$asm_diskgroup_stat       TO zyb_monitor;
GRANT SELECT ON sys.v_$managed_standby          TO zyb_monitor;
-- Long-Running Queries (Databases -> Long-Running Queries): the sessions holding up a database, on every RAC instance
GRANT SELECT ON sys.gv_$session                 TO zyb_monitor;
GRANT SELECT ON sys.gv_$sql                     TO zyb_monitor;
-- (v$tempseg_usage / gv$tempseg_usage: granted by the synonym block above)
GRANT SELECT ON sys.gv_$process                 TO zyb_monitor;
GRANT SELECT ON sys.gv_$session_longops         TO zyb_monitor;
GRANT SELECT ON sys.gv_$sesstat                 TO zyb_monitor;
GRANT SELECT ON sys.v_$statname                 TO zyb_monitor;
-- Database Audit (Databases -> Database Audit): read the unified audit trail and how auditing is configured. AUDIT_VIEWER
-- is a read-only role (it cannot change or purge the trail); the platform masks SQL literals before they leave it.
GRANT AUDIT_VIEWER TO zyb_monitor;
GRANT SELECT ON sys.v_$option                   TO zyb_monitor;
GRANT SELECT ON sys.dba_audit_mgmt_cleanup_jobs TO zyb_monitor;
GRANT SELECT ON sys.dba_audit_mgmt_last_arch_ts TO zyb_monitor;
-- DIAGNOSTICS PACK ONLY - grant this ONLY if the database is licensed for the Oracle Diagnostics Pack, and switch it on
-- in Databases -> Oracle Tuning -> Settings (the platform records who confirmed the licence):
-- GRANT SELECT ON sys.v_$active_session_history TO zyb_monitor;

-- 4. optional: record every login of the account in the unified audit trail
-- CREATE AUDIT POLICY zyb_monitor_logon ACTIONS LOGON;
-- AUDIT POLICY zyb_monitor_logon BY zyb_monitor;

-- check: should list CREATE SESSION only
-- SELECT privilege FROM dba_sys_privs WHERE grantee = 'ZYB_MONITOR';
-- undo:  DROP USER zyb_monitor; DROP PROFILE zyb_monitor_prof;
