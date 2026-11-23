-- create-monitor-user.sql - the READ-ONLY account the Sentra SIEM Oracle collector logs in with (sentra-oracle-collector.sh).
-- Run as SYSDBA. In a container database run it inside the PDB you monitor:
--     sqlplus / as sysdba
--     SQL> ALTER SESSION SET CONTAINER = <PDB name>;      -- CDB only
--     SQL> @create-monitor-user.sql
-- The account gets CREATE SESSION, SELECT on the system views listed below and the AUDIT_VIEWER role (read the unified
-- audit trail). It cannot change data, users, parameters or audit settings. Oracle Database 12.2 or later (19c tested
-- syntax). The password is asked hidden and never echoed; it must not contain a double quote.
-- Remove later with:  DROP USER SENTRA_MON CASCADE;
set verify off feedback on echo off
accept mon_user default 'SENTRA_MON' prompt 'Monitoring account name [SENTRA_MON]: '
accept mon_pw prompt 'Password for the monitoring account (hidden): ' hide

declare
  n number;
begin
  select count(*) into n from dba_users where username = upper('&mon_user');
  if n = 0 then
    execute immediate 'create user &mon_user identified by "&mon_pw"';
    dbms_output.put_line('created user &mon_user');
  else
    execute immediate 'alter user &mon_user identified by "&mon_pw" account unlock';
    dbms_output.put_line('user &mon_user exists - password reset, account unlocked');
  end if;
end;
/
grant create session to &mon_user;
-- instance, sessions, waits, redo / archive, backups, Data Guard, recovery area, diagnostics location
grant select on sys.v_$instance to &mon_user;
grant select on sys.v_$database to &mon_user;
grant select on sys.v_$session to &mon_user;
grant select on sys.v_$process to &mon_user;
grant select on sys.v_$parameter to &mon_user;
grant select on sys.v_$system_wait_class to &mon_user;
grant select on sys.v_$archived_log to &mon_user;
grant select on sys.v_$log to &mon_user;
grant select on sys.v_$log_history to &mon_user;
grant select on sys.v_$archive_dest to &mon_user;
grant select on sys.v_$rman_backup_job_details to &mon_user;
grant select on sys.v_$dataguard_stats to &mon_user;
grant select on sys.v_$recovery_file_dest to &mon_user;
grant select on sys.v_$diag_info to &mon_user;
-- storage and object health
grant select on sys.dba_tablespace_usage_metrics to &mon_user;
grant select on sys.dba_tablespaces to &mon_user;
grant select on sys.dba_objects to &mon_user;
-- performance (collect-perf.sql): metrics, waits, SQL, temp / undo, memory, limits, ASM, host - no Diagnostics Pack views
grant select on sys.v_$sysmetric to &mon_user;
grant select on sys.v_$waitclassmetric to &mon_user;
grant select on sys.v_$eventmetric to &mon_user;
grant select on sys.v_$event_name to &mon_user;
grant select on sys.v_$sql to &mon_user;
grant select on sys.v_$tempseg_usage to &mon_user;
grant select on sys.dba_temp_files to &mon_user;
grant select on sys.v_$undostat to &mon_user;
grant select on sys.v_$sgainfo to &mon_user;
grant select on sys.v_$pgastat to &mon_user;
grant select on sys.v_$resource_limit to &mon_user;
grant select on sys.v_$asm_diskgroup to &mon_user;
grant select on sys.v_$osstat to &mon_user;
-- ONLY if the database is licensed for the Oracle Diagnostics Pack (then set PACK_ASH=1 in collector.conf):
-- grant select on sys.v_$active_session_history to &mon_user;
-- unified audit trail (logons, failed logons, privilege and account changes - whatever the enabled audit policies record)
grant audit_viewer to &mon_user;

undefine mon_pw
prompt
prompt Done. Test from the DB host:  sqlplus &mon_user@<service>   then   select instance_name, status from v$instance;
