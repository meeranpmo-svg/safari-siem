#!/bin/bash
# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
# zyb-sysinfo - write this server's CPU, memory and disk use (and the city temperature) to
# /var/www/sentra/dashboards/sysinfo.json for the portal home page (zyb-home.js).
# Runs every 30 s from zyb-sysinfo.timer (install-sysinfo.sh). Settings: /etc/zyb-sysinfo.conf
# Reads /proc, df and the SIEM's ClickHouse sizes (zyb-siemstats.js, read-only); the temperature comes from api.open-meteo.com (no key) and is cached for 15 minutes.
set -uo pipefail
CITY="Riyadh"; LAT="24.7136"; LON="46.6753"
LOG_PATHS="/var/lib/clickhouse /opt/sentra-siem /var/log"
PROXY=""
OUT=${ZYB_SYSINFO_OUT:-/var/www/sentra/dashboards/sysinfo.json}
CACHE=${ZYB_SYSINFO_CACHE:-/var/cache/zyb-sysinfo}
[ -r /etc/zyb-sysinfo.conf ] && . /etc/zyb-sysinfo.conf
mkdir -p "$CACHE"

jstr() { local s=${1//\\/\\\\}; s=${s//\"/\\\"}; printf '"%s"' "$(printf '%s' "$s" | tr -d '\000-\037')"; }
num() { [[ "$1" =~ ^-?[0-9]+(\.[0-9]+)?$ ]] && printf '%s' "$1" || printf 'null'; }

# CPU: two samples of /proc/stat one second apart
read -r _ u1 n1 s1 i1 w1 q1 sq1 st1 _ < /proc/stat; sleep 1
read -r _ u2 n2 s2 i2 w2 q2 sq2 st2 _ < /proc/stat
busy=$(( (u2+n2+s2+q2+sq2+st2) - (u1+n1+s1+q1+sq1+st1) )); idle=$(( (i2+w2) - (i1+w1) ))
cpu=$(awk -v b="$busy" -v i="$idle" 'BEGIN{t=b+i; printf "%.1f", (t>0?b*100/t:0)}')
iow=$(awk -v w="$(( w2-w1 ))" -v b="$busy" -v i="$idle" 'BEGIN{t=b+i; printf "%.1f", (t>0?w*100/t:0)}')
cores=$(nproc 2>/dev/null || grep -c ^processor /proc/cpuinfo)
read -r l1 l5 l15 _ < /proc/loadavg
model=$(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2- | sed 's/^ *//')

# memory (kB in /proc/meminfo)
mt=$(awk '/^MemTotal:/{print $2}' /proc/meminfo); ma=$(awk '/^MemAvailable:/{print $2}' /proc/meminfo)
st=$(awk '/^SwapTotal:/{print $2}' /proc/meminfo); sf=$(awk '/^SwapFree:/{print $2}' /proc/meminfo)

# disks: the root file system plus every disk that holds a log folder (one entry per mount)
logm=" "; for p in $LOG_PATHS; do [ -e "$p" ] && logm="$logm$(df -P "$p" 2>/dev/null | awk 'NR==2{print $6}') "; done
disks=""; seen=" "
for p in / $LOG_PATHS; do
  [ -e "$p" ] || continue
  line=$(df -P -B1 "$p" 2>/dev/null | awk 'NR==2{print $6" "$2" "$3" "$4}'); [ -n "$line" ] || continue
  set -- $line; mnt=$1
  case "$seen" in *" $mnt "*) continue;; esac; seen="$seen$mnt "
  role=""; [ "$mnt" = "/" ] && role="system"
  case "$logm" in *" $mnt "*) role="${role:+$role+}logs";; esac
  disks="$disks${disks:+,}{\"mount\":$(jstr "$mnt"),\"path\":$(jstr "$p"),\"role\":\"${role:-other}\",\"total\":$2,\"used\":$3,\"avail\":$4}"
done

# weather (cached; skipped quietly when the server has no internet)
W="$CACHE/weather.json"
if [ ! -s "$W" ] || [ -n "$(find "$W" -mmin +15 2>/dev/null)" ]; then
  url="https://api.open-meteo.com/v1/forecast?latitude=$LAT&longitude=$LON&current=temperature_2m,relative_humidity_2m,apparent_temperature,weather_code,wind_speed_10m&timezone=auto"
  if curl -fsS --max-time 6 ${PROXY:+--proxy "$PROXY"} "$url" -o "$W.tmp" 2>/dev/null; then mv "$W.tmp" "$W"; else rm -f "$W.tmp"; touch -d '-10 minutes' "$W" 2>/dev/null || true; fi
fi
weather="null"
if [ -s "$W" ]; then
  cur=$(grep -o '"current":{[^}]*}' "$W" | head -1)
  g() { printf '%s' "$cur" | grep -o "\"$1\":[-0-9.]*" | cut -d: -f2; }
  if [ -n "$cur" ]; then
    weather="{\"city\":$(jstr "$CITY"),\"temp\":$(num "$(g temperature_2m)"),\"feels\":$(num "$(g apparent_temperature)"),\"humidity\":$(num "$(g relative_humidity_2m)"),\"code\":$(num "$(g weather_code)"),\"wind\":$(num "$(g wind_speed_10m)"),\"at\":$(stat -c %Y "$W")}"
  fi
fi
[ "$weather" = "null" ] && weather="{\"city\":$(jstr "$CITY"),\"temp\":null}"

# SIEM log storage and daily log flow (ClickHouse), cached for 2 minutes
SIEMJS=${ZYB_SIEMSTATS:-/usr/local/lib/zyb/zyb-siemstats.js}; SC="$CACHE/siem.json"; siem="null"
# the Node.js the SIEM service itself runs (it is usually not on root's PATH under systemd)
NODE=$(systemctl show -p ExecStart --value sentra-siem 2>/dev/null | sed -n 's/.*argv\[\]=\([^ ;]*\).*/\1/p' | head -n1)
[ -x "${NODE:-}" ] || NODE=$(command -v node || ls /opt/sentra-ai/node/bin/node /opt/sentra-siem/node/bin/node /usr/bin/node /usr/local/bin/node 2>/dev/null | head -1)
if [ ! -x "${NODE:-}" ]; then siem='{"error":"Node.js not found for the log-size reader"}'
elif [ ! -f "$SIEMJS" ]; then siem='{"error":"log-size reader not installed - run the update"}'
else
  if [ ! -s "$SC" ] || [ -n "$(find "$SC" -mmin +2 2>/dev/null)" ]; then
    if timeout 25 "$NODE" "$SIEMJS" > "$SC.tmp" 2>/dev/null && grep -q '^{' "$SC.tmp"; then mv -f "$SC.tmp" "$SC"
    else rm -f "$SC.tmp"; [ -s "$SC" ] && [ -z "$(find "$SC" -mmin +15 2>/dev/null)" ] || printf '{"error":"ClickHouse did not answer within 25 s"}' > "$SC"; fi
  fi
  [ -s "$SC" ] && siem=$(head -c 200000 "$SC")
fi

up=$(cut -d. -f1 /proc/uptime)
os=$(. /etc/os-release 2>/dev/null; printf '%s' "${PRETTY_NAME:-Linux}")
tmp="$OUT.tmp.$$"
mkdir -p "$(dirname "$OUT")"
printf '{"host":%s,"os":%s,"time":%s,"uptime":%s,"cpu":{"pct":%s,"iowait":%s,"cores":%s,"load":[%s,%s,%s],"model":%s},"mem":{"total":%s,"avail":%s,"swap_total":%s,"swap_free":%s},"disks":[%s],"weather":%s,"siem":%s}\n' \
  "$(jstr "$(hostname)")" "$(jstr "$os")" "$(date +%s)" "$up" "$cpu" "$iow" "$cores" "$l1" "$l5" "$l15" "$(jstr "$model")" \
  "$((mt*1024))" "$((ma*1024))" "$((st*1024))" "$((sf*1024))" "$disks" "$weather" "$siem" > "$tmp" && chmod 644 "$tmp" && mv -f "$tmp" "$OUT"
