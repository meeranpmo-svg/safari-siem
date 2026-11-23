-- oracle-tuning.sql - the extra read-only Oracle readings for tuning (Databases -> Oracle Tuning), run by inv-helper.py
-- (op oracle_health) on Oracle 12.2+ (json_object). Blocks:
--   "-- @kit <kind>"  copied VERBATIM from the SIEM collector kit (sentra-siem/agents/oracle/collect-perf.sql / collect-pack.sql)
--                     so the platform connection and the on-server collector send identical records; a test checks it.
--   "-- @own <kind>"  platform-only readings (Top SQL snapshot, stale statistics, GoldenGate integrated processes).
--   "-- @pack <kind>" Oracle Diagnostics Pack ONLY - run only when an administrator has confirmed the licence
--                     (db_health.diagnostics_pack); V$ACTIVE_SESSION_HISTORY is a licensed feature.
--   "-- @heavy"       dictionary scans: once an hour, like backup / invalid objects.
--   "-- @fallback <kind>" run only when <kind> failed (an older or partial GoldenGate dictionary).
-- Licence-free otherwise: V$ views, DBA_* dictionary views - no AWR (DBA_HIST_*), no ASH, no SQL Tuning Advisor.
-- SQL text is cut to 200 characters here and its literals are masked by inv-helper.py before it leaves the platform.

-- @kit wait_events
-- wait events over the last minute: top 10 by time, plus the two latency events the rules watch
select json_object('kind' value 'wait_events', 'event' value event, 'class' value wait_class, 'waits_s' value waits_s, 'avg_ms' value avg_ms,
  'time_s' value time_s, 'fg_waits_s' value fg_waits_s, 'fg_time_s' value fg_time_s, 'rank' value rn, 'watch' value watch, 'top_by' value 'time')
from (select e.name event, e.wait_class, round(m.wait_count / greatest(m.intsize_csec / 100, 1), 3) waits_s,
             round(case when m.wait_count > 0 then m.time_waited * 10 / m.wait_count end, 3) avg_ms,
             round(m.time_waited / greatest(m.intsize_csec, 1), 4) time_s,
             round(m.wait_count_fg / greatest(m.intsize_csec / 100, 1), 3) fg_waits_s, round(m.time_waited_fg / greatest(m.intsize_csec, 1), 4) fg_time_s,
             row_number() over (order by m.time_waited desc) rn,
             case when e.name in ('log file sync', 'db file sequential read') then 1 else 0 end watch
      from v$eventmetric m join v$event_name e on e.event_id = m.event_id
      where e.wait_class <> 'Idle' and m.wait_count > 0)
where rn <= 10 or watch = 1;

-- @kit ash_sql
-- the SQL those active sessions run (top 10 of this capture)
select json_object('kind' value 'ash_sql', 'sql_id' value sql_id, 'count' value c, 'aas' value c, 'pct' value round(ratio_to_report(c) over () * 100, 1),
  'top_event' value top_event, 'module' value module, 'user' value usr, 'captures' value 1, 'rank' value rn)
from (select sql_id, count(*) c, max(module) module, max(username) usr,
             max(case when state <> 'WAITING' then 'ON CPU' else event end) keep (dense_rank last order by seconds_in_wait) top_event,
             row_number() over (order by count(*) desc) rn
      from v$session where status = 'ACTIVE' and type = 'USER' and sql_id is not null and (state <> 'WAITING' or wait_class <> 'Idle')
        and sid <> sys_context('userenv', 'sid')
      group by sql_id)
where rn <= 10;

-- @kit long_query
-- long-running calls (user sessions active for 5+ minutes in one call; at most 20)
select json_object('kind' value 'long_query', 'sid' value s.sid, 'serial' value s.serial#, 'user' value s.username, 'sql_id' value s.sql_id,
  'elapsed_s' value s.last_call_et, 'sql_exec_start' value to_char(s.sql_exec_start, 'YYYY-MM-DD"T"HH24:MI:SS'),
  'state' value s.state, 'event' value s.event, 'wait_class' value s.wait_class, 'program' value s.program, 'module' value s.module, 'machine' value s.machine,
  'sql_text' value (select substr(q.sql_text, 1, 200) from v$sql q where q.sql_id = s.sql_id and rownum = 1))
from v$session s
where s.status = 'ACTIVE' and s.type = 'USER' and s.last_call_et >= 300 and s.sql_id is not null and s.sid <> sys_context('userenv', 'sid')
  and rownum <= 20;

-- @kit plan_change
-- plan changes: a SQL whose newest plan (active in the last 5 minutes) is at least 2x slower per execution than its previous plan
select json_object('kind' value 'plan_change', 'sql_id' value n.sql_id, 'new_plan' value n.ph, 'old_plan' value o.ph,
  'new_ms_exec' value round(n.ms, 2), 'old_ms_exec' value round(o.ms, 2), 'new_execs' value n.ex, 'old_execs' value o.ex,
  'new_last_active' value to_char(n.la, 'YYYY-MM-DD"T"HH24:MI:SS'), 'module' value n.module, 'user' value n.usr,
  'sql_text' value (select substr(q.sql_text, 1, 200) from v$sql q where q.sql_id = n.sql_id and rownum = 1))
from (select sql_id, ph, ex, ms, la, module, usr, row_number() over (partition by sql_id order by la desc) rn, count(*) over (partition by sql_id) np
      from (select sql_id, plan_hash_value ph, sum(executions) ex, sum(elapsed_time) / sum(executions) / 1000 ms, max(last_active_time) la,
                   max(module) module, max(parsing_schema_name) usr
            from v$sql where executions > 0 and plan_hash_value <> 0 group by sql_id, plan_hash_value having sum(executions) >= 5)) n
join (select sql_id, ph, ex, ms, row_number() over (partition by sql_id order by la desc) rn
      from (select sql_id, plan_hash_value ph, sum(executions) ex, sum(elapsed_time) / sum(executions) / 1000 ms, max(last_active_time) la
            from v$sql where executions > 0 and plan_hash_value <> 0 group by sql_id, plan_hash_value having sum(executions) >= 5)) o
  on o.sql_id = n.sql_id and o.rn = 2
where n.rn = 1 and n.np >= 2 and n.la > sysdate - 5/1440 and n.ms >= 2 * o.ms and n.ms >= 10 and rownum <= 10;

-- @kit temp_undo
-- TEMP and UNDO
select json_object('kind' value 'temp_undo',
  'temp_used_mb' value (select round(nvl(sum(u.blocks), 0) * (select to_number(value) from v$parameter where name = 'db_block_size') / 1048576) from v$tempseg_usage u),
  'temp_max_mb' value (select round(sum(greatest(bytes, maxbytes)) / 1048576) from dba_temp_files),
  'temp_used_pct' value (select round(nvl(sum(u.blocks), 0) * (select to_number(value) from v$parameter where name = 'db_block_size')
                                      / nullif((select sum(greatest(bytes, maxbytes)) from dba_temp_files), 0) * 100, 1) from v$tempseg_usage u),
  'temp_top_sql_id' value (select sql_id from (select sql_id, sum(blocks) b from v$tempseg_usage group by sql_id order by b desc) where rownum = 1),
  'temp_top_user' value (select username from (select username, sum(blocks) b from v$tempseg_usage group by username order by b desc) where rownum = 1),
  'undo_tablespace' value (select value from v$parameter where name = 'undo_tablespace'),
  'undo_used_pct' value (select round(used_percent, 1) from dba_tablespace_usage_metrics where tablespace_name = (select upper(value) from v$parameter where name = 'undo_tablespace')),
  'undo_retention_s' value (select to_number(value) from v$parameter where name = 'undo_retention'),
  'tuned_undoretention_s' value (select tuned_undoretention from (select tuned_undoretention from v$undostat order by end_time desc) where rownum = 1),
  'maxquerylen_s' value (select max(maxquerylen) from v$undostat where end_time > sysdate - 1/24),
  'maxquery_sql_id' value (select maxqueryid from (select maxqueryid from v$undostat where end_time > sysdate - 1/24 order by maxquerylen desc) where rownum = 1),
  'ora1555_1h' value (select nvl(sum(ssolderrcnt), 0) from v$undostat where end_time > sysdate - 1/24),
  'nospace_1h' value (select nvl(sum(nospaceerrcnt), 0) from v$undostat where end_time > sysdate - 1/24),
  'unexpired_steals_1h' value (select nvl(sum(unxpstealcnt), 0) from v$undostat where end_time > sysdate - 1/24))
from dual;

-- @kit memory
-- memory (SGA / PGA)
select json_object('kind' value 'memory',
  'sga_max_mb' value (select round(bytes / 1048576) from v$sgainfo where name = 'Maximum SGA Size'),
  'sga_free_mb' value (select round(bytes / 1048576) from v$sgainfo where name = 'Free SGA Memory Available'),
  'buffer_cache_mb' value (select round(bytes / 1048576) from v$sgainfo where name = 'Buffer Cache Size'),
  'shared_pool_mb' value (select round(bytes / 1048576) from v$sgainfo where name = 'Shared Pool Size'),
  'sga_target_mb' value (select round(to_number(value) / 1048576) from v$parameter where name = 'sga_target'),
  'memory_target_mb' value (select round(to_number(value) / 1048576) from v$parameter where name = 'memory_target'),
  'pga_alloc_mb' value (select round(value / 1048576) from v$pgastat where name = 'total PGA allocated'),
  'pga_inuse_mb' value (select round(value / 1048576) from v$pgastat where name = 'total PGA inuse'),
  'pga_max_alloc_mb' value (select round(value / 1048576) from v$pgastat where name = 'maximum PGA allocated'),
  'pga_target_mb' value (select round(value / 1048576) from v$pgastat where name = 'aggregate PGA target parameter'),
  'pga_limit_mb' value (select round(to_number(value) / 1048576) from v$parameter where name = 'pga_aggregate_limit'),
  'pga_over_alloc' value (select value from v$pgastat where name = 'over allocation count'),
  'pga_cache_hit_pct' value (select round(value, 1) from v$pgastat where name = 'cache hit percentage'))
from dual;

-- @kit limits
-- resource limits that can stop new work
select json_object('kind' value 'limits', 'resource' value resource_name, 'current' value current_utilization, 'max_util' value max_utilization,
  'limit' value to_number(trim(limit_value)), 'initial' value trim(initial_allocation))
from v$resource_limit
where resource_name in ('processes', 'sessions', 'transactions', 'parallel_max_servers') and trim(limit_value) not in ('UNLIMITED', '0');

-- @kit redo_rate
-- redo switch rate
select json_object('kind' value 'redo_rate', 'thread' value 1,
  'switches_1h' value (select count(*) from v$log_history where first_time > sysdate - 1/24),
  'switches_24h' value (select count(*) from v$log_history where first_time > sysdate - 1),
  'switches_max_hour_24h' value (select max(c) from (select count(*) c from v$log_history where first_time > sysdate - 1 group by trunc(first_time, 'HH24'))),
  'log_groups' value (select count(*) from v$log), 'log_size_mb' value (select round(max(bytes) / 1048576) from v$log))
from dual;

-- @kit archive_dest
-- archive destinations in use
select json_object('kind' value 'archive_dest', 'dest_id' value dest_id, 'dest_name' value dest_name, 'status' value status, 'target' value target,
  'binding' value binding, 'destination' value destination, 'log_sequence' value log_sequence, 'fail_sequence' value fail_sequence, 'dest_error' value error)
from v$archive_dest where status <> 'INACTIVE';

-- @kit asm
-- ASM disk groups (rows only when the database uses ASM)
select json_object('kind' value 'asm', 'name' value name, 'state' value state, 'type' value type, 'total_mb' value total_mb, 'free_mb' value free_mb,
  'usable_file_mb' value usable_file_mb, 'required_mirror_free_mb' value required_mirror_free_mb, 'offline_disks' value offline_disks)
from v$asm_diskgroup where total_mb > 0;

-- @own sqlstats
-- Top SQL: cumulative V$SQLSTATS for the 200 statements with the most elapsed time; the engine keeps the previous snapshot
-- and sends per-interval deltas (kind sql_delta). V$SQLSTATS is licence-free.
select json_object('kind' value 'sqlstats', 'sql_id' value t.sql_id, 'plan_hash' value t.plan_hash_value, 'executions' value t.executions,
  'elapsed_us' value t.elapsed_time, 'cpu_us' value t.cpu_time, 'buffer_gets' value t.buffer_gets, 'disk_reads' value t.disk_reads,
  'rows_processed' value t.rows_processed, 'sql_text' value substr(t.sql_text, 1, 200),
  'module' value (select max(q.module) from v$sql q where q.sql_id = t.sql_id),
  'user' value (select max(q.parsing_schema_name) from v$sql q where q.sql_id = t.sql_id))
from (select * from v$sqlstats where executions > 0 order by elapsed_time desc) t
where rownum <= 200;

-- @own stats_stale
-- @heavy
-- application tables whose optimizer statistics Oracle marks STALE (largest first, at most 50)
select json_object('kind' value 'stats_stale', 'owner' value owner, 'table_name' value table_name, 'num_rows' value num_rows,
  'last_analyzed' value to_char(last_analyzed, 'YYYY-MM-DD"T"HH24:MI:SS'), 'locked' value stattype_locked)
from (select owner, table_name, num_rows, last_analyzed, stattype_locked from dba_tab_statistics
      where stale_stats = 'YES' and object_type = 'TABLE' and owner not in (select username from dba_users where oracle_maintained = 'Y')
      order by num_rows desc nulls last)
where rownum <= 50;

-- @own gg_capture
-- GoldenGate integrated Extract (capture) processes in this database: status, error and capture lag
select json_object('kind' value 'gg_capture', 'name' value c.capture_name, 'status' value c.status, 'purpose' value c.purpose,
  'error' value substr(c.error_message, 1, 200), 'state' value v.state, 'messages' value v.total_messages_captured,
  'lag_s' value round((sysdate - v.capture_message_create_time) * 86400))
from dba_capture c left join v$goldengate_capture v on v.capture_name = c.capture_name;

-- @own gg_apply
-- GoldenGate integrated Replicat (apply) processes: status, error and apply lag (low watermark)
select json_object('kind' value 'gg_apply', 'name' value a.apply_name, 'status' value a.status, 'purpose' value a.purpose,
  'error' value substr(a.error_message, 1, 200), 'state' value g.state, 'applied' value g.total_applied,
  'lag_s' value round((sysdate - cast(g.lwm_message_create_time as date)) * 86400))
from dba_apply a left join v$gg_apply_coordinator g on g.apply_name = a.apply_name;

-- @fallback gg_apply
-- the same without the lag (V$GG_APPLY_COORDINATOR not readable or a different release)
select json_object('kind' value 'gg_apply', 'name' value apply_name, 'status' value status, 'purpose' value purpose, 'error' value substr(error_message, 1, 200))
from dba_apply;

-- @own sched_jobs
-- scheduler jobs running now and for how long (application schemas; Oracle's own maintenance jobs are left out). In 19c DBMS_JOB
-- jobs run as scheduler jobs too, so they are here.
select json_object('kind' value 'sched_job', 'owner' value j.owner, 'job_name' value j.job_name, 'session_id' value j.session_id,
  'running_instance' value j.running_instance,
  'elapsed_s' value round(extract(day from j.elapsed_time) * 86400 + extract(hour from j.elapsed_time) * 3600 + extract(minute from j.elapsed_time) * 60 + extract(second from j.elapsed_time)))
from dba_scheduler_running_jobs j
where j.owner not in (select username from dba_users where oracle_maintained = 'Y') and rownum <= 50;

-- @own delstats
-- bulk deletes: cumulative rows deleted per DELETE statement in the shared pool (command type 7), application schemas only;
-- the engine sends the difference since the previous pass (kind bulk_delete). Oracle's own schemas are left out.
select json_object('kind' value 'delstats', 'sql_id' value sql_id, 'plan_hash' value plan_hash, 'rows_processed' value rws, 'executions' value execs,
  'user' value usr, 'module' value md, 'sql_text' value txt)
from (select q.sql_id, q.plan_hash_value plan_hash, sum(q.rows_processed) rws, sum(q.executions) execs, max(q.parsing_schema_name) usr, max(q.module) md,
             max(substr(q.sql_text, 1, 200)) txt
      from v$sql q
      where q.command_type = 7 and q.rows_processed > 0 and q.parsing_schema_name not in (select username from dba_users where oracle_maintained = 'Y')
      group by q.sql_id, q.plan_hash_value order by sum(q.rows_processed) desc)
where rownum <= 200;

-- @own code_change
-- @heavy
-- (hourly, like the other dictionary scans; the 65-minute window overlaps the hour so nothing falls between two reads)
-- PL/SQL code and triggers created or changed in the last 65 minutes (application schemas; Oracle's own are left out). A
-- recompile also moves LAST_DDL_TIME. Who did it comes from the unified audit trail (code_change_by) when it is audited.
select json_object('kind' value 'code_change', 'owner' value o.owner, 'name' value o.object_name, 'type' value o.object_type,
  'ddl_time' value to_char(o.last_ddl_time, 'YYYY-MM-DD"T"HH24:MI:SS'), 'created' value case when o.created >= sysdate - 65 / 1440 then 'Y' else 'N' end,
  'status' value o.status)
from dba_objects o
where o.object_type in ('PACKAGE', 'PACKAGE BODY', 'PROCEDURE', 'FUNCTION', 'TRIGGER', 'TYPE', 'TYPE BODY') and o.last_ddl_time >= sysdate - 65 / 1440
  and o.owner not in (select username from dba_users where oracle_maintained = 'Y') and rownum <= 200;

-- @own code_change_by
-- @heavy
-- who created / changed / dropped code or truncated a table in the last 65 minutes (unified audit trail; needs an audit policy
-- on these actions - install/oracle-code-change-audit.sql). SYS, AS SYSDBA and Oracle's own users are filtered by the SIEM.
select json_object('kind' value 'code_change_by', 'user' value a.dbusername, 'os_user' value a.os_username, 'client_host' value a.userhost,
  'action' value a.action_name, 'owner' value a.object_schema, 'name' value a.object_name,
  'at' value to_char(sys_extract_utc(a.event_timestamp), 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
  'sysdba' value case when a.system_privilege_used like '%SYSDBA%' then 'Y' else 'N' end, 'ok' value case when a.return_code = 0 then 'Y' else 'N' end,
  'oracle_user' value (select max(u.oracle_maintained) from dba_users u where u.username = a.dbusername))
from unified_audit_trail a
where a.event_timestamp > systimestamp - interval '65' minute
  and a.action_name in ('CREATE PACKAGE', 'ALTER PACKAGE', 'DROP PACKAGE', 'CREATE PACKAGE BODY', 'ALTER PACKAGE BODY', 'DROP PACKAGE BODY',
    'CREATE PROCEDURE', 'ALTER PROCEDURE', 'DROP PROCEDURE', 'CREATE FUNCTION', 'ALTER FUNCTION', 'DROP FUNCTION',
    'CREATE TRIGGER', 'ALTER TRIGGER', 'DROP TRIGGER', 'CREATE TYPE', 'ALTER TYPE', 'DROP TYPE', 'CREATE TYPE BODY', 'TRUNCATE TABLE')
  and rownum <= 200;

-- @own app_sessions
-- which applications are connected: sessions per service, client machine, program and database user (every RAC instance);
-- the engine compares passes to see an application drop off. Oracle's own users and the monitoring account are left out.
select json_object('kind' value 'app_session', 'service' value nvl(service_name, '?'), 'machine' value nvl(substr(machine, 1, 64), '?'),
  'program' value nvl(substr(program, 1, 64), '?'), 'db_user' value username, 'module' value substr(max(module), 1, 64), 'sessions' value count(*),
  'active' value sum(case when status = 'ACTIVE' then 1 else 0 end), 'max_idle_s' value max(case when status = 'INACTIVE' then last_call_et end),
  'oldest_logon' value to_char(min(logon_time), 'YYYY-MM-DD"T"HH24:MI:SS'), 'instances' value count(distinct inst_id))
from gv$session
where type = 'USER' and username is not null and username not like 'ZYB\_%' escape '\'
  and username not in (select username from dba_users where oracle_maintained = 'Y')
group by service_name, machine, program, username
order by count(*) desc fetch first 150 rows only;

-- @own lsnr_conns
-- @heavy
-- the listener log of the last 65 minutes (V$DIAG_ALERT_EXT, component tnslsnr), counted per service, client address, program
-- and result (0 = connected; 12514 / 12519 / 12520 / 12505 ... = refused). Only listeners that log under this database's
-- diagnostic_dest are visible - a SCAN / grid listener usually is not.
select json_object('kind' value 'lsnr_conn', 'service' value svc, 'client_host' value hst, 'program' value prg, 'code' value rc, 'n' value n,
  'last' value to_char(sys_extract_utc(lst), 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
from (select svc, hst, prg, rc, count(*) n, max(ot) lst
      from (select nvl(regexp_substr(message_text, 'SERVICE_NAME=([^)]*)', 1, 1, 'i', 1), nvl(regexp_substr(message_text, 'SID=([^)]*)', 1, 1, 'i', 1), '?')) svc,
                   nvl(regexp_substr(message_text, '\(ADDRESS=\(PROTOCOL=tcps?\)\(HOST=([^)]*)\)', 1, 1, 'i', 1), '?') hst,
                   nvl(substr(regexp_substr(message_text, 'PROGRAM=([^)]*)', 1, 1, 'i', 1), 1, 64), '?') prg,
                   nvl(regexp_substr(message_text, '\*\s*(\d+)\s*$', 1, 1, null, 1), '?') rc, originating_timestamp ot
            from v$diag_alert_ext
            where component_id = 'tnslsnr' and originating_timestamp > systimestamp - interval '65' minute and message_text like '%establish%')
      group by svc, hst, prg, rc order by count(*) desc)
where rownum <= 300;

-- @own db_links
-- @heavy
-- database links: who owns them, where they point and as which remote user (DBA_DB_LINKS never shows the password)
select json_object('kind' value 'db_link', 'owner' value owner, 'link' value db_link, 'remote_user' value username, 'host' value substr(host, 1, 300),
  'created' value to_char(created, 'YYYY-MM-DD"T"HH24:MI:SS'))
from dba_db_links where rownum <= 200;

-- @own user_write
-- @heavy
-- what each application user can change (so a DB link INTO this database can be judged): DBA-type roles, ANY-table system
-- privileges, tables it owns, write grants on other schemas' tables (direct and through a role it holds directly)
select json_object('kind' value 'user_write', 'db_user' value u.username, 'status' value u.account_status,
  'dba' value (select listagg(r.granted_role, ',') within group (order by r.granted_role) from dba_role_privs r
               where r.grantee = u.username and r.granted_role in ('DBA', 'IMP_FULL_DATABASE', 'DATAPUMP_IMP_FULL_DATABASE', 'EXP_FULL_DATABASE')),
  'any_dml' value (select listagg(p.privilege, ',') within group (order by p.privilege) from dba_sys_privs p
                   where p.grantee = u.username and p.privilege in ('INSERT ANY TABLE', 'UPDATE ANY TABLE', 'DELETE ANY TABLE', 'DROP ANY TABLE', 'ALTER ANY TABLE', 'LOCK ANY TABLE')),
  'own_tables' value (select count(*) from dba_tables t where t.owner = u.username),
  'obj_write' value (select count(distinct g.owner || '.' || g.table_name) from dba_tab_privs g
                     where g.privilege in ('INSERT', 'UPDATE', 'DELETE')
                       and (g.grantee = u.username or g.grantee in (select r2.granted_role from dba_role_privs r2 where r2.grantee = u.username))))
from dba_users u
where u.oracle_maintained = 'N' and u.username not like 'ZYB\_%' escape '\' and rownum <= 500;

-- @own rac_nodes
-- RAC: every configured instance (V$THREAD, enabled threads) joined to the running ones (GV$INSTANCE) - a node whose instance is
-- down has no GV$INSTANCE row, so it is reported NOT RUNNING instead of disappearing. Single-instance databases return nothing.
select json_object('kind' value 'rac_node', 'thread' value t.thread#, 'thread_status' value t.status, 'enabled' value t.enabled,
  'instance_name' value nvl(i.instance_name, t.instance), 'host_name' value i.host_name, 'status' value nvl(i.status, 'NOT RUNNING'),
  'database_status' value i.database_status, 'startup_time' value to_char(i.startup_time, 'YYYY-MM-DD"T"HH24:MI:SS'),
  'db_unique_name' value (select db_unique_name from v$database))
from v$thread t left join gv$instance i on i.thread# = t.thread#
where t.enabled <> 'DISABLED' and (select upper(value) from v$parameter where name = 'cluster_database') = 'TRUE';

-- @own dg_config
-- Data Guard: this database's role and protection, and what a standby depends on (force logging, flashback); also the
-- supplemental logging the Change Stream / own replication need. One row; licence-free (V$DATABASE).
select json_object('kind' value 'dg_config', 'role' value database_role, 'protection_mode' value protection_mode,
  'protection_level' value protection_level, 'switchover_status' value switchover_status, 'broker' value dataguard_broker,
  'force_logging' value force_logging, 'flashback' value flashback_on, 'open_mode' value open_mode, 'db_unique_name' value db_unique_name,
  'fs_failover' value fs_failover_status, 'log_mode' value log_mode, 'supplemental_min' value supplemental_log_data_min,
  'supplemental_pk' value supplemental_log_data_pk,
  'standbys' value (select count(*) from v$archive_dest where target = 'STANDBY' and status <> 'INACTIVE'))
from v$database;

-- @own dg_dest
-- Data Guard redo transport, per standby destination (primary side): status, error, gap, whether redo apply runs, and the
-- standby's open state (DATABASE_MODE: MOUNTED-STANDBY / OPEN_READ-ONLY / OPEN ...) - so a mounted DR database is seen without a login on it
select json_object('kind' value 'dg_dest', 'dest_id' value s.dest_id, 'db_unique_name' value s.db_unique_name, 'status' value s.status,
  'gap_status' value s.gap_status, 'error' value substr(s.error, 1, 200), 'recovery_mode' value s.recovery_mode,
  'protection_mode' value s.protection_mode, 'sync_status' value s.synchronization_status, 'synchronized' value s.synchronized,
  'archived_seq' value s.archived_seq#, 'applied_seq' value s.applied_seq#, 'transmit_mode' value d.transmit_mode, 'affirm' value d.affirm,
  'valid_now' value d.valid_now, 'database_mode' value s.database_mode)
from v$archive_dest_status s join v$archive_dest d on d.dest_id = s.dest_id
where d.target = 'STANDBY' and d.status <> 'INACTIVE';

-- @own dg_applied
-- per standby destination and redo thread: logs shipped vs applied, and how long the oldest shipped-but-not-applied log has
-- waited (0 when everything shipped is applied - an idle database is not "lagging")
select json_object('kind' value 'dg_applied', 'dest_id' value dest_id, 'thread' value thread#, 'last_seq' value max(sequence#),
  'applied_seq' value max(case when applied in ('YES', 'IN-MEMORY') then sequence# end),
  'unapplied' value sum(case when applied in ('YES', 'IN-MEMORY') then 0 else 1 end),
  'unapplied_since_s' value nvl(round((sysdate - min(case when applied in ('YES', 'IN-MEMORY') then null else completion_time end)) * 86400), 0))
from v$archived_log
where dest_id in (select dest_id from v$archive_dest where target = 'STANDBY' and status <> 'INACTIVE')
  and resetlogs_change# = (select resetlogs_change# from v$database) and first_time > sysdate - 7
group by dest_id, thread#;

-- @own dg_stats
-- standby side: transport / apply lag as the standby computes them (empty on a primary)
select json_object('kind' value 'dg_stats', 'name' value name, 'value' value value, 'unit' value unit,
  'time_computed' value time_computed, 'datum_time' value datum_time)
from v$dataguard_stats where value is not null;

-- @own dg_process
-- Data Guard processes, ONE row (counts) so that "no MRP0" is a fact and a missing grant is a missing reading: on a standby
-- MRP0 (redo apply) and RFS (redo receive) must be there
select json_object('kind' value 'dg_process', 'role' value (select database_role from v$database),
  'mrp' value (select count(*) from v$dataguard_process where name like 'MRP%'),
  'rfs' value (select count(*) from v$dataguard_process where lower(role) like 'rfs%'),
  'mrp_action' value (select max(action) from v$dataguard_process where name like 'MRP%'),
  'mrp_thread' value (select max(thread#) from v$dataguard_process where name like 'MRP%'),
  'mrp_sequence' value (select max(sequence#) from v$dataguard_process where name like 'MRP%'))
from dual;

-- @own dg_gap
-- standby side: archived logs the standby is missing
select json_object('kind' value 'dg_gap', 'thread' value thread#, 'low_seq' value low_sequence#, 'high_seq' value high_sequence#)
from v$archive_gap;

-- @own dg_event
-- Data Guard errors in the last hour (V$DATAGUARD_STATUS)
select json_object('kind' value 'dg_event', 'severity' value severity, 'facility' value facility, 'error_code' value error_code,
  'message' value substr(message, 1, 300), 'ts' value to_char(timestamp, 'YYYY-MM-DD"T"HH24:MI:SS'))
from (select * from v$dataguard_status where severity in ('Error', 'Fatal') and timestamp > sysdate - 1/24 order by timestamp desc)
where rownum <= 20;

-- @own dg_broker
-- Data Guard broker members and their status (0 = SUCCESS, otherwise the ORA- error number); empty without the broker
select json_object('kind' value 'dg_broker', 'member' value database, 'dg_role' value dataguard_role, 'redo_source' value redo_source,
  'enabled' value enabled, 'status' value status)
from v$dg_broker_config;

-- @own dg_srl
-- standby redo logs vs online redo logs (SYNC transport and real-time apply need one more SRL group than online groups per thread)
select json_object('kind' value 'dg_srl', 'srl_groups' value (select count(*) from v$standby_log),
  'online_groups' value (select count(*) from v$log), 'threads' value (select count(distinct thread#) from v$log))
from dual;

-- @own dg_nologging
-- datafiles with NOLOGGING (unrecoverable) changes in the last 7 days: those blocks are NOT on the standby
select json_object('kind' value 'dg_nologging', 'files' value count(*), 'last' value to_char(max(unrecoverable_time), 'YYYY-MM-DD"T"HH24:MI:SS'))
from v$datafile where unrecoverable_time > sysdate - 7;

-- @own audit_config
-- @heavy
-- Database Audit: how this database audits (hourly) - unified auditing pure mode, enabled policies, SYS auditing, the trail
-- cleanup job and the last archive timestamp. Needs the AUDIT_VIEWER role (read only).
select json_object('kind' value 'audit_config',
  'unified_pure' value (select max(value) from v$option where parameter = 'Unified Auditing'),
  'audit_trail' value (select max(value) from v$parameter where name = 'audit_trail'),
  'audit_sys_operations' value (select max(value) from v$parameter where name = 'audit_sys_operations'),
  'policies' value (select listagg(policy_name, ',') within group (order by policy_name) from (select distinct policy_name from audit_unified_enabled_policies)),
  'cleanup_jobs' value (select count(*) from dba_audit_mgmt_cleanup_jobs),
  'last_archive' value (select to_char(max(last_archive_ts), 'YYYY-MM-DD"T"HH24:MI:SS') from dba_audit_mgmt_last_arch_ts))
from dual;

-- @pack pack_ash
-- Diagnostics Pack ONLY: last 5 minutes of Active Session History, top 10 SQL / event
select json_object('kind' value 'pack_ash', 'sql_id' value sql_id, 'event' value ev, 'samples' value c, 'rank' value rn)
from (select sql_id, nvl(event, 'ON CPU') ev, count(*) c, row_number() over (order by count(*) desc) rn
      from v$active_session_history where sample_time > systimestamp - interval '5' minute
      group by sql_id, nvl(event, 'ON CPU'))
where rn <= 10;
