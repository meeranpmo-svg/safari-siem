-- collect-perf.sql - PERFORMANCE queries (engine/db-audit/oracle-perf.js kinds), run by sentra-oracle-collector.sh after
-- collect.sql when PERF=1 (default). Licence-free: only V$ metric / session / memory views - NO Active Session History,
-- NO AWR (DBA_HIST_*), which need the Oracle Diagnostics Pack. The Diagnostics Pack query is a separate file
-- (collect-pack.sql) that the collector runs only with PACK_ASH=1 - set it only if the database is licensed for the pack.
-- The collector computes tablespace_growth itself from the tablespace samples it keeps (state/tsgrowth).
whenever sqlerror continue
set pagesize 0 linesize 32767 trimspool on trimout on feedback off heading off echo off verify off tab off long 100000 longchunksize 32767

-- load profile: V$SYSMETRIC 60-second interval (group 2)
select json_object('kind' value 'load_profile', 'scope' value 'instance',
  'aas' value round(max(case when metric_name = 'Average Active Sessions' then value end), 3),
  'db_time_s' value round(max(case when metric_name = 'Database Time Per Sec' then value end) / 100, 3),
  'db_cpu_s' value round(max(case when metric_name = 'CPU Usage Per Sec' then value end) / 100, 3),
  'bg_cpu_s' value round(max(case when metric_name = 'Background CPU Usage Per Sec' then value end) / 100, 3),
  'executions_s' value round(max(case when metric_name = 'Executions Per Sec' then value end), 2),
  'user_calls_s' value round(max(case when metric_name = 'User Calls Per Sec' then value end), 2),
  'transactions_s' value round(max(case when metric_name = 'User Transaction Per Sec' then value end), 2),
  'commits_s' value round(max(case when metric_name = 'User Commits Per Sec' then value end), 2),
  'rollbacks_s' value round(max(case when metric_name = 'User Rollbacks Per Sec' then value end), 2),
  'logical_reads_s' value round(max(case when metric_name = 'Logical Reads Per Sec' then value end), 2),
  'physical_reads_s' value round(max(case when metric_name = 'Physical Reads Per Sec' then value end), 2),
  'physical_writes_s' value round(max(case when metric_name = 'Physical Writes Per Sec' then value end), 2),
  'physical_read_mb_s' value round(max(case when metric_name = 'Physical Read Total Bytes Per Sec' then value end) / 1048576, 3),
  'physical_write_mb_s' value round(max(case when metric_name = 'Physical Write Total Bytes Per Sec' then value end) / 1048576, 3),
  'redo_mb_s' value round(max(case when metric_name = 'Redo Generated Per Sec' then value end) / 1048576, 3),
  'hard_parses_s' value round(max(case when metric_name = 'Hard Parse Count Per Sec' then value end), 2),
  'parses_s' value round(max(case when metric_name = 'Total Parse Count Per Sec' then value end), 2),
  'logons_s' value round(max(case when metric_name = 'Logons Per Sec' then value end), 3),
  'network_mb_s' value round(max(case when metric_name = 'Network Traffic Volume Per Sec' then value end) / 1048576, 3),
  'host_cpu_pct' value round(max(case when metric_name = 'Host CPU Utilization (%)' then value end), 1),
  'os_load' value round(max(case when metric_name = 'Current OS Load' then value end), 2),
  'sessions_cur' value max(case when metric_name = 'Session Count' then value end),
  'cpu_count' value (select to_number(value) from v$parameter where name = 'cpu_count'),
  'interval_s' value round(max(intsize_csec) / 100), 'end_time' value to_char(max(end_time), 'YYYY-MM-DD"T"HH24:MI:SS'))
from v$sysmetric where group_id = 2;

-- efficiency ratios (same interval)
select json_object('kind' value 'efficiency',
  'buffer_cache_hit_pct' value round(max(case when metric_name = 'Buffer Cache Hit Ratio' then value end), 2),
  'library_cache_hit_pct' value round(max(case when metric_name = 'Library Cache Hit Ratio' then value end), 2),
  'soft_parse_pct' value round(max(case when metric_name = 'Soft Parse Ratio' then value end), 2),
  'execute_to_parse_pct' value round(max(case when metric_name = 'Execute Without Parse Ratio' then value end), 2),
  'db_cpu_ratio_pct' value round(max(case when metric_name = 'Database CPU Time Ratio' then value end), 2),
  'db_wait_ratio_pct' value round(max(case when metric_name = 'Database Wait Time Ratio' then value end), 2),
  'pga_cache_hit_pct' value round(max(case when metric_name = 'PGA Cache Hit %' then value end), 2))
from v$sysmetric where group_id = 2;

-- wait classes over the last minute (V$WAITCLASSMETRIC, non-idle)
select json_object('kind' value 'wait_classes', 'class' value n.wait_class,
  'time_s' value round(m.time_waited / greatest(m.intsize_csec, 1), 4), 'waits_s' value round(m.wait_count / greatest(m.intsize_csec / 100, 1), 2),
  'avg_ms' value round(case when m.wait_count > 0 then m.time_waited * 10 / m.wait_count end, 3),
  'dbtime_pct' value round(m.dbtime_in_wait, 2), 'avg_waiters' value round(m.average_waiter_count, 3))
from v$waitclassmetric m join v$system_wait_class n on n.wait_class_id = m.wait_class_id
where n.wait_class <> 'Idle' and m.time_waited > 0;

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

-- active sessions right now (one licence-free capture of V$SESSION, per wait class; this session excluded)
select json_object('kind' value 'active_sessions', 'captures' value 1, 'active_total' value count(*), 'aas' value count(*),
  'cpu_count' value (select to_number(value) from v$parameter where name = 'cpu_count'),
  'top_event' value (select ev from (select case when state <> 'WAITING' then 'ON CPU' else event end ev, count(*) c from v$session
                                     where status = 'ACTIVE' and type = 'USER' and (state <> 'WAITING' or wait_class <> 'Idle') and sid <> sys_context('userenv', 'sid')
                                     group by case when state <> 'WAITING' then 'ON CPU' else event end order by c desc) where rownum = 1),
  'aas_cpu' value sum(case when state <> 'WAITING' then 1 else 0 end),
  'aas_user_i_o' value sum(case when state = 'WAITING' and wait_class = 'User I/O' then 1 else 0 end),
  'aas_system_i_o' value sum(case when state = 'WAITING' and wait_class = 'System I/O' then 1 else 0 end),
  'aas_commit' value sum(case when state = 'WAITING' and wait_class = 'Commit' then 1 else 0 end),
  'aas_concurrency' value sum(case when state = 'WAITING' and wait_class = 'Concurrency' then 1 else 0 end),
  'aas_application' value sum(case when state = 'WAITING' and wait_class = 'Application' then 1 else 0 end),
  'aas_cluster' value sum(case when state = 'WAITING' and wait_class = 'Cluster' then 1 else 0 end),
  'aas_configuration' value sum(case when state = 'WAITING' and wait_class = 'Configuration' then 1 else 0 end),
  'aas_network' value sum(case when state = 'WAITING' and wait_class = 'Network' then 1 else 0 end),
  'aas_administrative' value sum(case when state = 'WAITING' and wait_class = 'Administrative' then 1 else 0 end),
  'aas_scheduler' value sum(case when state = 'WAITING' and wait_class = 'Scheduler' then 1 else 0 end),
  'aas_queueing' value sum(case when state = 'WAITING' and wait_class = 'Queueing' then 1 else 0 end),
  'aas_other' value sum(case when state = 'WAITING' and wait_class = 'Other' then 1 else 0 end))
from v$session where status = 'ACTIVE' and type = 'USER' and (state <> 'WAITING' or wait_class <> 'Idle') and sid <> sys_context('userenv', 'sid');

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

-- long-running calls (user sessions active for 5+ minutes in one call; at most 20)
select json_object('kind' value 'long_query', 'sid' value s.sid, 'serial' value s.serial#, 'user' value s.username, 'sql_id' value s.sql_id,
  'elapsed_s' value s.last_call_et, 'sql_exec_start' value to_char(s.sql_exec_start, 'YYYY-MM-DD"T"HH24:MI:SS'),
  'state' value s.state, 'event' value s.event, 'wait_class' value s.wait_class, 'program' value s.program, 'module' value s.module, 'machine' value s.machine,
  'sql_text' value (select substr(q.sql_text, 1, 200) from v$sql q where q.sql_id = s.sql_id and rownum = 1))
from v$session s
where s.status = 'ACTIVE' and s.type = 'USER' and s.last_call_et >= 300 and s.sql_id is not null and s.sid <> sys_context('userenv', 'sid')
  and rownum <= 20;

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

-- resource limits that can stop new work
select json_object('kind' value 'limits', 'resource' value resource_name, 'current' value current_utilization, 'max_util' value max_utilization,
  'limit' value to_number(trim(limit_value)), 'initial' value trim(initial_allocation))
from v$resource_limit
where resource_name in ('processes', 'sessions', 'transactions', 'parallel_max_servers') and trim(limit_value) not in ('UNLIMITED', '0');

-- redo switch rate
select json_object('kind' value 'redo_rate', 'thread' value 1,
  'switches_1h' value (select count(*) from v$log_history where first_time > sysdate - 1/24),
  'switches_24h' value (select count(*) from v$log_history where first_time > sysdate - 1),
  'switches_max_hour_24h' value (select max(c) from (select count(*) c from v$log_history where first_time > sysdate - 1 group by trunc(first_time, 'HH24'))),
  'log_groups' value (select count(*) from v$log), 'log_size_mb' value (select round(max(bytes) / 1048576) from v$log))
from dual;

-- archive destinations in use
select json_object('kind' value 'archive_dest', 'dest_id' value dest_id, 'dest_name' value dest_name, 'status' value status, 'target' value target,
  'binding' value binding, 'destination' value destination, 'log_sequence' value log_sequence, 'fail_sequence' value fail_sequence, 'dest_error' value error)
from v$archive_dest where status <> 'INACTIVE';

-- ASM disk groups (rows only when the database uses ASM)
select json_object('kind' value 'asm', 'name' value name, 'state' value state, 'type' value type, 'total_mb' value total_mb, 'free_mb' value free_mb,
  'usable_file_mb' value usable_file_mb, 'required_mirror_free_mb' value required_mirror_free_mb, 'offline_disks' value offline_disks)
from v$asm_diskgroup where total_mb > 0;

-- host as Oracle sees it
select json_object('kind' value 'host',
  'num_cpus' value max(case when stat_name = 'NUM_CPUS' then value end), 'num_cpu_cores' value max(case when stat_name = 'NUM_CPU_CORES' then value end),
  'load' value round(max(case when stat_name = 'LOAD' then value end), 2),
  'mem_total_mb' value round(max(case when stat_name = 'PHYSICAL_MEMORY_BYTES' then value end) / 1048576),
  'mem_free_mb' value round(max(case when stat_name = 'FREE_MEMORY_BYTES' then value end) / 1048576),
  'host_cpu_pct' value (select round(value, 1) from v$sysmetric where group_id = 2 and metric_name = 'Host CPU Utilization (%)'))
from v$osstat;
