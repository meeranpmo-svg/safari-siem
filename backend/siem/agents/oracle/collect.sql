-- collect.sql - the read-only queries sentra-oracle-collector.sh runs once per interval as the monitoring account.
-- Every row is one JSON object (Oracle 12.2+ JSON_OBJECT) of the shape engine/db-audit/oracle-health.js parses; the
-- collector adds collector / host / instance / db_name / t to each line. Lines starting with '#' are for the collector.
-- Defines set by the collector before @collect.sql: SINCE (unified audit checkpoint, UTC "YYYY-MM-DDTHH24:MI:SS.FF6" or
-- INIT), MAXROWS (audit rows per run), MONUSER (the monitoring account, whose own successful logons are skipped),
-- AUDIT (1 = read the unified audit trail).
-- A query that fails prints its ORA- error and the next one still runs (the collector counts the errors).
whenever sqlerror continue
whenever oserror continue
set pagesize 0 linesize 32767 trimspool on trimout on feedback off heading off echo off verify off tab off
set long 100000 longchunksize 32767 serveroutput off
alter session set nls_numeric_characters = '.,';
alter session set nls_date_format = 'YYYY-MM-DD"T"HH24:MI:SS';

-- for the collector: who and where
select '#META|' || i.instance_name || '|' || d.name || '|' || i.host_name from v$instance i, v$database d;
select '#ALERT|' || value from v$diag_info where name = 'Diag Trace';

-- instance
select json_object('kind' value 'instance', 'status' value i.status, 'database_status' value i.database_status,
  'open_mode' value d.open_mode, 'role' value d.database_role, 'log_mode' value d.log_mode, 'version' value i.version_full,
  'startup_time' value to_char(i.startup_time, 'YYYY-MM-DD"T"HH24:MI:SS'), 'uptime_s' value round((sysdate - i.startup_time) * 86400),
  'db_unique_name' value d.db_unique_name, 'cdb' value d.cdb, 'edition' value i.edition, 'platform' value d.platform_name,
  'archiver' value i.archiver, 'logins' value i.logins, 'shutdown_pending' value i.shutdown_pending)
from v$instance i, v$database d;

-- tablespaces (used / max including autoextend)
select json_object('kind' value 'tablespace', 'name' value m.tablespace_name,
  'used_mb' value round(m.used_space * t.block_size / 1048576), 'max_mb' value round(m.tablespace_size * t.block_size / 1048576),
  'free_mb' value round((m.tablespace_size - m.used_space) * t.block_size / 1048576), 'used_pct' value round(m.used_percent, 1),
  'contents' value t.contents, 'status' value t.status)
from dba_tablespace_usage_metrics m join dba_tablespaces t on t.tablespace_name = m.tablespace_name;

-- sessions
select json_object('kind' value 'sessions', 'total' value count(*),
  'active' value sum(case when status = 'ACTIVE' then 1 else 0 end), 'inactive' value sum(case when status = 'INACTIVE' then 1 else 0 end),
  'blocked' value sum(case when blocking_session is not null then 1 else 0 end),
  'user_sessions' value sum(case when type = 'USER' then 1 else 0 end), 'background' value sum(case when type = 'BACKGROUND' then 1 else 0 end),
  'max_sessions' value (select to_number(value) from v$parameter where name = 'sessions'),
  'processes' value (select count(*) from v$process), 'max_processes' value (select to_number(value) from v$parameter where name = 'processes'))
from v$session;

-- blocking chains: waiter + its blocker, at most 20 (oracle-perf kind "blocking", rule SENTRA-ORAP-004)
select json_object('kind' value 'blocking', 'sid' value s.sid, 'serial' value s.serial#, 'user' value s.username,
  'wait_s' value round(s.wait_time_micro / 1000000), 'event' value s.event, 'wait_class' value s.wait_class, 'sql_id' value s.sql_id,
  'program' value s.program, 'module' value s.module, 'machine' value s.machine,
  'blocker_sid' value s.blocking_session, 'blocker_inst' value s.blocking_instance,
  'final_blocker_sid' value s.final_blocking_session, 'final_blocker_inst' value s.final_blocking_instance,
  'blocker_serial' value b.serial#, 'blocker_user' value b.username, 'blocker_status' value b.status, 'blocker_program' value b.program,
  'blocker_machine' value b.machine, 'blocker_sql_id' value b.sql_id, 'blocker_event' value b.event,
  'blocker_idle_s' value case when b.status = 'INACTIVE' then b.last_call_et end,
  'object' value (select o.owner || '.' || o.object_name from dba_objects o where o.object_id = s.row_wait_obj# and rownum = 1))
from v$session s left join v$session b on b.sid = s.blocking_session
where s.blocking_session is not null and rownum <= 20;

-- top 5 non-idle wait classes since startup
select json_object('kind' value 'wait_class', 'class' value wait_class, 'time_waited_s' value round(time_waited / 100),
  'total_waits' value total_waits, 'pct' value pct, 'rank' value rn)
from (select wait_class, time_waited, total_waits, round(ratio_to_report(time_waited) over () * 100, 1) pct,
             row_number() over (order by time_waited desc) rn
      from v$system_wait_class where wait_class <> 'Idle')
where rn <= 5;

-- redo / archiving (archive figures only in ARCHIVELOG mode - in NOARCHIVELOG every log reads "not archived")
select json_object('kind' value 'redo', 'log_mode' value d.log_mode,
  'archive_lag_s' value case when d.log_mode = 'ARCHIVELOG' then (select round((sysdate - max(completion_time)) * 86400) from v$archived_log where dest_id = 1 and standby_dest = 'NO') end,
  'redo_switches_1h' value (select count(*) from v$log_history where first_time > sysdate - 1/24),
  'unarchived' value case when d.log_mode = 'ARCHIVELOG' then (select count(*) from v$log where archived = 'NO' and status <> 'CURRENT') else 0 end,
  'current_seq' value (select max(sequence#) from v$log where status = 'CURRENT'),
  'last_archived_seq' value (select max(sequence#) from v$archived_log where dest_id = 1),
  'dest_status' value case when d.log_mode = 'ARCHIVELOG' then (select status from v$archive_dest where dest_id = 1) end,
  'dest_error' value case when d.log_mode = 'ARCHIVELOG' then (select error from v$archive_dest where dest_id = 1) end)
from v$database d;

-- last RMAN job (status NONE when there has never been one)
select json_object('kind' value 'backup', 'status' value nvl(j.status, 'NONE'), 'input_type' value j.input_type,
  'start_time' value to_char(j.start_time, 'YYYY-MM-DD"T"HH24:MI:SS'), 'end_time' value to_char(j.end_time, 'YYYY-MM-DD"T"HH24:MI:SS'),
  'age_h' value round((sysdate - nvl(j.end_time, j.start_time)) * 24, 1), 'output_mb' value round(j.output_bytes / 1048576),
  'input_mb' value round(j.input_bytes / 1048576), 'elapsed_s' value j.elapsed_seconds, 'session_key' value j.session_key,
  'output_device_type' value j.output_device_type, 'compression_ratio' value round(j.compression_ratio, 2))
from dual left join (select * from (select status, input_type, start_time, end_time, output_bytes, input_bytes, elapsed_seconds,
                                           session_key, output_device_type, compression_ratio
                                    from v$rman_backup_job_details order by start_time desc) where rownum = 1) j on 1 = 1;

-- Data Guard lag (only where the statistics exist: a standby, or a primary with a configured standby)
select json_object('kind' value 'dataguard', 'role' value (select database_role from v$database),
  'apply_lag_s' value round(max(case when name = 'apply lag' then secs end)), 'transport_lag_s' value round(max(case when name = 'transport lag' then secs end)),
  'protection_mode' value (select protection_mode from v$database))
from (select name, extract(day from to_dsinterval(value)) * 86400 + extract(hour from to_dsinterval(value)) * 3600
                   + extract(minute from to_dsinterval(value)) * 60 + extract(second from to_dsinterval(value)) secs
      from v$dataguard_stats where name in ('apply lag', 'transport lag') and value is not null)
having count(*) > 0;

-- invalid objects
select json_object('kind' value 'invalid_objects', 'count' value (select count(*) from dba_objects where status = 'INVALID'),
  'by_owner' value (select listagg(owner || ':' || n, ', ') within group (order by n desc)
                    from (select owner, count(*) n from dba_objects where status = 'INVALID' group by owner order by n desc fetch first 5 rows only)))
from dual;

-- fast recovery area
select json_object('kind' value 'fra', 'name' value name, 'space_limit_mb' value round(space_limit / 1048576),
  'space_used_mb' value round(space_used / 1048576), 'reclaimable_mb' value round(space_reclaimable / 1048576),
  'used_pct' value round((space_used - space_reclaimable) / space_limit * 100, 1), 'files' value number_of_files)
from v$recovery_file_dest where space_limit > 0;

-- unified audit trail since the last run (passwords in SQL text are masked; the collector's own logons are skipped)
select json_object('kind' value 'unified_audit',
  'EVENT_TIMESTAMP_UTC' value to_char(event_timestamp_utc, 'YYYY-MM-DD"T"HH24:MI:SS.FF6') || 'Z',
  'DBUSERNAME' value dbusername, 'CURRENT_USER' value current_user, 'OS_USERNAME' value os_username, 'USERHOST' value userhost,
  'TERMINAL' value terminal, 'CLIENT_PROGRAM_NAME' value client_program_name, 'ACTION_NAME' value action_name,
  'RETURN_CODE' value return_code, 'OBJECT_SCHEMA' value object_schema, 'OBJECT_NAME' value object_name,
  'SQL_TEXT' value regexp_replace(dbms_lob.substr(sql_text, 500, 1), '(identified[[:space:]]+by[[:space:]]+)("[^"]*"|[^[:space:]]+)', '\1***', 1, 0, 'i'),
  'UNIFIED_AUDIT_POLICIES' value unified_audit_policies, 'SYSTEM_PRIVILEGE_USED' value system_privilege_used,
  'AUTHENTICATION_TYPE' value substr(authentication_type, 1, 300), 'DBID' value dbid, 'SESSIONID' value sessionid,
  'ENTRY_ID' value entry_id, 'STATEMENT_ID' value statement_id, 'AUDIT_TYPE' value audit_type, 'CLIENT_IDENTIFIER' value client_identifier)
from unified_audit_trail
where '&AUDIT' = '1'
  and event_timestamp_utc > case when '&SINCE' = 'INIT' then sys_extract_utc(systimestamp) - interval '15' minute
                                 else to_timestamp('&SINCE', 'YYYY-MM-DD"T"HH24:MI:SS.FF6') end
  and not (dbusername = upper('&MONUSER') and return_code = 0)
order by event_timestamp_utc
fetch first &MAXROWS rows only;
