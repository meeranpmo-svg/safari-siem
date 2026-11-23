#!/usr/bin/env bash
# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
# sentra-oracle-collector.sh - Oracle Database health, PERFORMANCE and audit trail -> Sentra SIEM.
# Runs on the database host as the Oracle software owner (it reads the alert log and runs lsnrctl), logs in to the
# database with the READ-ONLY monitoring account (create-monitor-user.sql), runs collect.sql (+ collect-perf.sql), and
# ships the rows as gzip NDJSON over HTTPS to  <SIEM_URL>/ingest/<SOURCE_ID>  with the source's ingest token.
#
#   sentra-oracle-collector.sh --test      one run: connect, query, print what was collected, send it, report the answer
#   sentra-oracle-collector.sh --once      one run (cron:  * * * * *  sentra-oracle-collector.sh --once)
#   sentra-oracle-collector.sh --loop      run every INTERVAL seconds (systemd service)
#   sentra-oracle-collector.sh --dry-run   print the NDJSON, send nothing, keep no state
# Config: /etc/sentra-oracle/collector.conf (or SENTRA_ORA_CONF=...), KEY=value lines, see collector.conf.example.
#
# Secrets: the ingest token and the database password are read from files (mode 600) and are never put on a command
# line: the password goes to sqlplus on stdin, the token to curl in a 600 config file (-K). Nothing is changed in the
# database. A batch that cannot be sent waits in STATE_DIR/spool and is re-sent next run (the SIEM drops repeats by
# batch id). Needs bash 3.2+, curl, gzip, awk, sed (Oracle Linux / RHEL / Solaris 11).
set -u
VERSION=1.1
HERE="$(cd "$(dirname "$0")" && pwd)"
CONF="${SENTRA_ORA_CONF:-/etc/sentra-oracle/collector.conf}"
MODE=once
case "${1:-}" in
  --test) MODE=test ;; --once|'') MODE=once ;; --loop) MODE=loop ;; --dry-run) MODE=dry ;;
  --version) echo "sentra-oracle-collector $VERSION"; exit 0 ;;
  -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
  *) echo "unknown option $1 (use --test, --once, --loop or --dry-run)" >&2; exit 2 ;;
esac
die() { echo "sentra-oracle-collector: $*" >&2; exit 1; }
log() { [ "$MODE" = once ] || [ "$MODE" = loop ] || return 0; echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) $*" >> "$STATE_DIR/collector.log" 2>/dev/null; }

# ---- configuration: KEY=value, only known keys, no shell evaluation
SIEM_URL=''; SOURCE_ID=''; TOKEN_FILE=''; ORACLE_HOME="${ORACLE_HOME:-}"; ORACLE_SID="${ORACLE_SID:-}"; TNS_ADMIN="${TNS_ADMIN:-}"
DB_CONNECT=''; PASSWORD_FILE=''; MON_USER=SENTRA_MON; LISTENER=LISTENER; INTERVAL=60; CA_FILE=''; PIN_PUBKEY=''
STATE_DIR=/var/lib/sentra-oracle; SPOOL_MAX=500; AUDIT=1; AUDIT_MAX_ROWS=2000; PERF=1; PACK_ASH=0; ALERT_LOG=auto; ALLOW_HTTP=0
SQLPLUS_TIMEOUT=50; LSNRCTL=1
[ -r "$CONF" ] || die "config $CONF not readable (copy collector.conf.example there, mode 600)"
while IFS= read -r line || [ -n "$line" ]; do
  line="${line%$'\r'}"; case "$line" in ''|'#'*) continue ;; esac
  k="${line%%=*}"; v="${line#*=}"; k="$(echo "$k" | tr -d ' \t')"
  v="${v#"${v%%[![:space:]]*}"}"; v="${v%"${v##*[![:space:]]}"}"; v="${v#\"}"; v="${v%\"}"
  case "$k" in
    SIEM_URL|SOURCE_ID|TOKEN_FILE|ORACLE_HOME|ORACLE_SID|TNS_ADMIN|DB_CONNECT|PASSWORD_FILE|MON_USER|LISTENER|INTERVAL|CA_FILE|PIN_PUBKEY|STATE_DIR|SPOOL_MAX|AUDIT|AUDIT_MAX_ROWS|PERF|PACK_ASH|ALERT_LOG|ALLOW_HTTP|SQLPLUS_TIMEOUT|LSNRCTL)
      printf -v "$k" '%s' "$v" ;;
    *) echo "sentra-oracle-collector: ignoring unknown setting '$k' in $CONF" >&2 ;;
  esac
done < "$CONF"

case "$SIEM_URL" in https://*) ;; http://*) [ "$ALLOW_HTTP" = 1 ] || die "SIEM_URL must be https://" ;; *) die "SIEM_URL not set" ;; esac
SIEM_URL="${SIEM_URL%/}"
echo "$SOURCE_ID" | grep -Eq '^[A-Za-z0-9_.-]{1,64}$' || die "SOURCE_ID missing or invalid"
[ -n "$ORACLE_HOME" ] && [ -x "$ORACLE_HOME/bin/sqlplus" ] || die "ORACLE_HOME not set or \$ORACLE_HOME/bin/sqlplus not found"
[ -n "$ORACLE_SID" ] || die "ORACLE_SID not set"
[ -n "$DB_CONNECT" ] || die "DB_CONNECT not set (wallet: /@SENTRA_MON   or   SENTRA_MON@//host:1521/service with PASSWORD_FILE)"
for n in INTERVAL SPOOL_MAX AUDIT_MAX_ROWS SQLPLUS_TIMEOUT; do eval "echo \"\$$n\"" | grep -Eq '^[0-9]+$' || die "$n must be a number"; done
[ "$INTERVAL" -ge 30 ] || INTERVAL=30
echo "$MON_USER" | grep -Eq '^[A-Za-z][A-Za-z0-9_$#]{0,127}$' || die "MON_USER invalid"
export ORACLE_HOME ORACLE_SID PATH="$ORACLE_HOME/bin:$PATH"; [ -n "$TNS_ADMIN" ] && export TNS_ADMIN
export NLS_LANG=AMERICAN_AMERICA.AL32UTF8
# Solaris: the GNU / XPG4 tools understand grep -E / -o, tail -c, find -mmin
for d in /usr/xpg4/bin /usr/gnu/bin; do [ -d "$d" ] && PATH="$d:$PATH"; done; export PATH

# a secret file must exist, be readable and not be readable by group / others
secret_ok() { [ -r "$1" ] || die "$2 $1 not readable"; local p; p="$(ls -ln "$1" 2>/dev/null | awk '{print $1}')"; case "$p" in ????------*) ;; *) die "$2 $1 is readable by others - chmod 600 it" ;; esac; }
[ "$MODE" = dry ] || { secret_ok "$TOKEN_FILE" TOKEN_FILE; }
[ -z "$PASSWORD_FILE" ] || secret_ok "$PASSWORD_FILE" PASSWORD_FILE

umask 077
if [ "$MODE" = dry ]; then STATE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/sentra-ora-dry.XXXXXX")"; trap 'rm -rf "$STATE_DIR"' EXIT; fi
mkdir -p "$STATE_DIR/spool" || die "cannot create $STATE_DIR"
[ -w "$STATE_DIR" ] || die "$STATE_DIR not writable by $(id -un)"

# one run at a time (cron overlap); a lock older than 10 minutes is stale
LOCK="$STATE_DIR/lock"
if ! mkdir "$LOCK" 2>/dev/null; then
  if [ -n "$(find "$LOCK" -maxdepth 0 -mmin +10 2>/dev/null)" ]; then rm -rf "$LOCK"; mkdir "$LOCK" 2>/dev/null || exit 0; else [ "$MODE" = test ] && die "another run is in progress ($LOCK)"; exit 0; fi
fi
cleanup() { rm -rf "$LOCK" "$STATE_DIR"/.w.* 2>/dev/null; }
trap 'cleanup; [ "$MODE" = dry ] && rm -rf "$STATE_DIR"' EXIT

json_str() { # JSON string body from stdin (escapes \ " control characters; newline -> \n)
  awk 'BEGIN{ORS=""} { gsub(/\\/,"\\\\"); gsub(/"/,"\\\""); gsub(/\t/,"\\t"); gsub(/\r/,""); gsub(/[\001-\010\013\014\016-\037]/,""); if (NR>1) print "\\n"; print }'
}
safe() { echo "$1" | tr -cd 'A-Za-z0-9._-' | cut -c1-120; }

run_sqlplus() { # $1 = output file; queries on stdin to sqlplus, password never on a command line
  local out="$1" since tmo=''
  since="$(cat "$STATE_DIR/audit.since" 2>/dev/null || true)"; echo "$since" | grep -Eq '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+$' || since=INIT
  command -v timeout >/dev/null 2>&1 && tmo="timeout $SQLPLUS_TIMEOUT"
  {
    if [ -n "$PASSWORD_FILE" ]; then
      local pw user tns
      IFS= read -r pw < "$PASSWORD_FILE" || true; pw="${pw%$'\r'}"
      case "$pw" in *'"'*) echo 'prompt ORA-ASH: the password contains a double quote - not supported'; echo exit; return ;; esac
      user="${DB_CONNECT%%@*}"; tns=''; [ "$user" != "$DB_CONNECT" ] && tns="@${DB_CONNECT#*@}"
      printf 'connect %s/"%s"%s\n' "$user" "$pw" "$tns"; pw=''
    else
      printf 'connect %s\n' "$DB_CONNECT"
    fi
    printf 'define SINCE=%s\ndefine MAXROWS=%s\ndefine MONUSER=%s\ndefine AUDIT=%s\n' "$since" "$AUDIT_MAX_ROWS" "$MON_USER" "$AUDIT"
    printf '@"%s"\n' "$HERE/collect.sql"
    [ "$PERF" = 1 ] && printf '@"%s"\n' "$HERE/collect-perf.sql"
    [ "$PACK_ASH" = 1 ] && printf '@"%s"\n' "$HERE/collect-pack.sql"
    printf 'exit\n'
  } | $tmo "$ORACLE_HOME/bin/sqlplus" -S -L /nolog > "$out" 2>&1
}

# tablespace growth: one sample per tablespace per day kept in state/tsgrowth (day used_mb max_mb), least squares over 30 days
ts_growth() { # stdin: tablespace NDJSON lines; stdout: tablespace_growth NDJSON lines
  local f="$STATE_DIR/tsgrowth" today; today=$(( $(date +%s) / 86400 ))
  awk -v today="$today" -v state="$f" '
    BEGIN { while ((getline l < state) > 0) { split(l, a, " "); if (today - a[1] <= 45) { key = a[2] SUBSEP a[1]; used[key] = a[3]; mx[a[2]] = a[4]; names[a[2]] = 1 } } close(state) }
    { n = $0; nm = ""; u = ""; m = ""
      if (match(n, /"name":"[^"]*"/)) nm = substr(n, RSTART + 8, RLENGTH - 9)
      if (match(n, /"used_mb":[0-9.]+/)) u = substr(n, RSTART + 10, RLENGTH - 10)
      if (match(n, /"max_mb":[0-9.]+/)) m = substr(n, RSTART + 9, RLENGTH - 9)
      if (nm != "" && u != "") { used[nm SUBSEP today] = u; mx[nm] = m; names[nm] = 1 } }
    END {
      printf "" > state
      for (nm in names) {
        sx = sy = sxx = sxy = c = 0; first = today
        for (d = today - 30; d <= today; d++) { k = nm SUBSEP d; if (k in used) { x = d - today; y = used[k] + 0; sx += x; sy += y; sxx += x * x; sxy += x * y; c++; if (d < first) first = d } }
        for (d = today - 45; d <= today; d++) { k = nm SUBSEP d; if (k in used) print d, nm, used[k], mx[nm] > state }
        if (c < 7) continue
        den = c * sxx - sx * sx; if (den == 0) continue
        g = (c * sxy - sx * sy) / den; cur = used[nm SUBSEP today]; if (cur == "") continue
        line = sprintf("{\"kind\":\"tablespace_growth\",\"name\":\"%s\",\"used_mb\":%s,\"max_mb\":%s,\"growth_mb_day\":%.2f,\"history_days\":%d,\"span_days\":%d", nm, cur, (mx[nm] == "" ? "null" : mx[nm]), g, c, today - first)
        if (g > 0 && mx[nm] + 0 > 0) line = line sprintf(",\"days_to_full\":%.1f", (mx[nm] - cur) / g)
        print line "}"
      }
      close(state)
    }'
}

send_file() { # $1 = gz batch; 0 = accepted
  local f="$1" bid cfg resp code ctype tok
  bid="$(basename "$f" .ndjson.gz)"; cfg="$STATE_DIR/.w.curl.$$"; resp="$STATE_DIR/.w.resp.$$"
  IFS= read -r tok < "$TOKEN_FILE" || true; tok="${tok%$'\r'}"
  {
    printf 'header = "X-Sentra-Token: %s"\n' "$tok"
    printf 'header = "X-Sentra-Batch-Id: %s"\n' "$bid"
    printf 'header = "Content-Type: application/x-ndjson"\nheader = "Content-Encoding: gzip"\n'
    printf 'header = "X-Sentra-Agent: sentra-oracle-collector/%s;%s"\n' "$VERSION" "$(safe "$(hostname)")"
  } > "$cfg"; tok=''
  local tls=()
  [ -n "$CA_FILE" ] && tls+=(--cacert "$CA_FILE")
  [ -n "$PIN_PUBKEY" ] && tls+=(--pinnedpubkey "$PIN_PUBKEY")
  code="$(curl -sS -K "$cfg" ${tls[@]+"${tls[@]}"} --max-time 30 -o "$resp" -w '%{http_code} %{content_type}' --data-binary @"$f" "$SIEM_URL/ingest/$SOURCE_ID" 2>"$resp.err")" || code="000 curl:$(head -c 200 "$resp.err" | tr '\n' ' ')"
  rm -f "$cfg"
  ctype="${code#* }"; code="${code%% *}"
  LAST_SEND="HTTP $code $(head -c 300 "$resp" 2>/dev/null | tr '\n' ' ')"
  [ "$code" = 000 ] && LAST_SEND="not sent: ${ctype#curl:}"
  rm -f "$resp" "$resp.err"
  # a 2xx that is not the ingest API's JSON {ok:true} is not a delivery (a proxy / portal page answering instead)
  case "$code" in 2??) case "$ctype" in *json*) echo "$LAST_SEND" | grep -q '"ok":true' && return 0 ;; esac; LAST_SEND="$LAST_SEND (not the SIEM ingest API answer)" ;; esac
  return 1
}

run_once() {
  local out="$STATE_DIR/.w.sql.$$" rec="$STATE_DIR/.w.rec.$$" t host inst dbn diag nerr lasterr now
  now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  run_sqlplus "$out"
  local meta; meta="$(grep '^#META|' "$out" | head -n1)"
  inst="$(safe "$(echo "$meta" | cut -d'|' -f2)")"; dbn="$(safe "$(echo "$meta" | cut -d'|' -f3)")"; host="$(safe "$(echo "$meta" | cut -d'|' -f4)")"
  [ -n "$inst" ] || inst="$(safe "$ORACLE_SID")"; [ -n "$dbn" ] || dbn="$inst"; [ -n "$host" ] || host="$(safe "$(hostname)")"
  host="$(echo "$host" | tr 'A-Z' 'a-z')"
  diag="$(grep '^#ALERT|' "$out" | head -n1 | cut -d'|' -f2-)"
  nerr="$(grep -Ec '^(ORA|SP2|TNS)-[0-9]+' "$out")"; lasterr="$(grep -E '^(ORA|SP2|TNS)-[0-9]+' "$out" | head -n1 | cut -c1-300)"
  local hdr="{\"collector\":\"sentra-oracle-collector/$VERSION\",\"host\":\"$host\",\"instance\":\"$inst\",\"db_name\":\"$dbn\",\"t\":\"$now\","
  grep '^{' "$out" | sed "s|^{|$hdr|" > "$rec"

  # no #META = no session: the database is down / unreachable, or the login failed (not the same thing - only the first is "down")
  if [ -z "$meta" ]; then
    local why; why="$(echo "${lasterr:-no answer from sqlplus}" | json_str)"
    if grep -Eq 'ORA-(01034|27101|01033|01089|12514|12528|12541|12537|03113|03135)' "$out"; then
      echo "${hdr}\"kind\":\"instance\",\"status\":\"DOWN\",\"error\":\"$why\"}" >> "$rec"
    fi
  fi
  # tablespace growth forecast from the samples kept here
  [ "$PERF" = 1 ] && [ "$MODE" != dry ] && grep '"kind":"tablespace"' "$rec" | ts_growth | sed "s|^{|$hdr|" >> "$rec.g" && cat "$rec.g" >> "$rec" 2>/dev/null; rm -f "$rec.g"

  # listener
  if [ "$LSNRCTL" = 1 ] && [ -x "$ORACLE_HOME/bin/lsnrctl" ]; then
    local lo st svc; lo="$("$ORACLE_HOME/bin/lsnrctl" status "$LISTENER" 2>&1 | head -c 20000)"
    if echo "$lo" | grep -q 'The command completed successfully'; then st=READY; else st=DOWN; fi
    svc="$(echo "$lo" | grep -c '^Service "')"
    echo "${hdr}\"kind\":\"listener\",\"listener\":\"$(safe "$LISTENER")\",\"status\":\"$st\",\"services\":$svc$( [ "$st" = DOWN ] && printf ',"output":"%s"' "$(echo "$lo" | tail -n 5 | json_str)" )}" >> "$rec"
  fi

  # alert log: new lines since the last run (first run: only the last 20)
  local al="$ALERT_LOG"
  [ "$al" = auto ] && [ -n "$diag" ] && al="$diag/alert_${ORACLE_SID}.log"
  if [ "$al" != auto ] && [ -r "$al" ]; then
    local size off; size="$(wc -c < "$al" | tr -d ' ')"; off="$(cat "$STATE_DIR/alert.offset" 2>/dev/null || echo '')"
    local new
    if [ -z "$off" ] || ! echo "$off" | grep -Eq '^[0-9]+$' || [ "$off" -gt "$size" ]; then new="$(tail -n 20 "$al")"; else new="$(tail -c +"$((off + 1))" "$al" | tail -n 200)"; fi
    [ "$MODE" = dry ] || echo "$size" > "$STATE_DIR/alert.offset"
    if [ -n "$new" ]; then
      local cnt; cnt="$(echo "$new" | grep -Ec 'ORA-[0-9]{5}')"
      echo "${hdr}\"kind\":\"alertlog\",\"path\":\"$(echo "$al" | json_str)\",\"ora_errors_5m\":$cnt,\"tail\":\"$(echo "$new" | tail -n 20 | json_str)\"}" >> "$rec"
    fi
  fi

  local nrec; nrec="$(wc -l < "$rec" | tr -d ' ')"
  echo "${hdr}\"kind\":\"heartbeat\",\"version\":\"$VERSION\",\"interval_s\":$INTERVAL,\"queries_ok\":$nrec,\"queries_failed\":$nerr,\"perf\":$PERF,\"pack\":$PACK_ASH,\"sqlplus\":\"$( [ -n "$meta" ] && echo connected || echo failed )\",\"spool_files\":$(ls "$STATE_DIR/spool" 2>/dev/null | wc -l | tr -d ' ')$( [ -n "$lasterr" ] && printf ',"last_error":"%s"' "$(echo "$lasterr" | json_str)" )}" >> "$rec"

  if [ "$MODE" = dry ]; then cat "$rec"; rm -f "$out" "$rec"; return 0; fi
  if [ "$MODE" = test ]; then
    echo "== database: $( [ -n "$meta" ] && echo "connected to $inst ($dbn) on $host" || echo "NOT connected: ${lasterr:-no answer from sqlplus}")"
    echo "== records: $(grep -o '"kind":"[a-z_]*"' "$rec" | sort | uniq -c | awk '{gsub(/"kind":|"/,"",$2); printf "%s %s, ", $2, $1}' | sed 's/, $//')"
    [ "$nerr" -gt 0 ] && echo "== $nerr query error(s), first: $lasterr  (a missing grant shows as ORA-00942 - re-run create-monitor-user.sql)"
  fi

  # spool, then advance the audit checkpoint (the rows are safe on disk now), then send everything waiting
  local batch; batch="$STATE_DIR/spool/$(date +%s)-$$-$RANDOM.ndjson.gz"
  gzip -c "$rec" > "$batch.part" && mv "$batch.part" "$batch"
  local last; last="$(grep -o '"EVENT_TIMESTAMP_UTC":"[^"]*"' "$rec" | sed 's/.*:"//; s/Z"$//; s/"$//' | sort | tail -n1)"
  [ -n "$last" ] && echo "$last" > "$STATE_DIR/audit.since"
  rm -f "$out" "$rec"
  # cap the spool (oldest dropped first)
  local nsp; nsp="$(ls "$STATE_DIR/spool" | wc -l | tr -d ' ')"
  if [ "$nsp" -gt "$SPOOL_MAX" ]; then ls "$STATE_DIR/spool" | sort | head -n "$((nsp - SPOOL_MAX))" | while read -r x; do rm -f "$STATE_DIR/spool/$x"; done; log "spool full: dropped $((nsp - SPOOL_MAX)) oldest batch(es)"; fi
  local sent=0 failed=0 f
  for f in $(ls "$STATE_DIR/spool" | sort); do
    case "$f" in *.ndjson.gz) ;; *) continue ;; esac
    if send_file "$STATE_DIR/spool/$f"; then rm -f "$STATE_DIR/spool/$f"; sent=$((sent + 1)); else failed=1; break; fi
  done
  log "records=$nrec errors=$nerr sent=$sent waiting=$(ls "$STATE_DIR/spool" | wc -l | tr -d ' ') ${LAST_SEND:-}"
  if [ "$MODE" = test ]; then
    if [ "$failed" = 0 ]; then echo "== SIEM: $sent batch(es) accepted - ${LAST_SEND:-}"; else echo "== SIEM: NOT delivered - ${LAST_SEND:-} (kept in $STATE_DIR/spool, re-sent next run)"; return 1; fi
  fi
  return 0
}

LAST_SEND=''
if [ "$MODE" = loop ]; then
  while :; do start=$(date +%s); run_once; rm -rf "$LOCK"; el=$(( $(date +%s) - start )); [ "$el" -lt "$INTERVAL" ] && sleep $((INTERVAL - el)); mkdir "$LOCK" 2>/dev/null || true; done
else
  run_once
fi
