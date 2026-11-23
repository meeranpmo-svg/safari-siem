-- collect-pack.sql - ORACLE DIAGNOSTICS PACK ONLY. Run by sentra-oracle-collector.sh only when collector.conf has PACK_ASH=1.
-- Querying V$ACTIVE_SESSION_HISTORY is a Diagnostics Pack feature: enable it only where the database is licensed for it,
-- and grant the view to the monitoring account then (see create-monitor-user.sql).
whenever sqlerror continue
set pagesize 0 linesize 32767 trimspool on trimout on feedback off heading off echo off verify off tab off
-- Diagnostics Pack ONLY (PACK_ASH=1): last 5 minutes of Active Session History, top 10 SQL / event
select json_object('kind' value 'pack_ash', 'sql_id' value sql_id, 'event' value ev, 'samples' value c, 'rank' value rn)
from (select sql_id, nvl(event, 'ON CPU') ev, count(*) c, row_number() over (order by count(*) desc) rn
      from v$active_session_history where sample_time > systimestamp - interval '5' minute
      group by sql_id, nvl(event, 'ON CPU'))
where rn <= 10;
