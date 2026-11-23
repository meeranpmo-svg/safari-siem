#!/bin/bash
# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
# zyb-backup - encrypted backup of the whole platform on this server, nightly (zyb-backup.timer) or on demand
# ("Run backup now" on the Platform Health & Backup page, or: sudo zyb-backup).
# What is saved:
#   settings   /etc/sentra-siem /etc/sentra-itam /etc/zyb* /etc/nginx /etc/clickhouse-server, the platform's systemd units
#   data       SIEM state (/var/lib/sentra-siem/state: alerts, cases, rules, users of the SOC, sources ...), IT Asset
#              Management (/var/lib/sentra-itam: inventory, discovery, audit), the portal (/var/www/sentra) and the
#              portal sync service (/var/www/noc-m365 and its container data folders)
#   programs   /opt/sentra-siem /opt/sentra-itam (for an exact restore without the update package)
#   SIEM logs  the ClickHouse table definitions always; the log events themselves when CH_EVENT_DAYS > 0 (they are large)
# The archive is encrypted (AES-256, key /etc/zyb-backup/backup.key - keep a copy of that key OFF this server: without it
# a backup cannot be restored), checked after writing, kept KEEP_DAYS days (at least KEEP_MIN copies) in DEST and copied
# to the remote target (REMOTE_DIR = a mounted network share / USB disk, or SFTP_TARGET = user@host:/path with a key).
# Credential keys are NOT in that archive: the keys that unseal the stored passwords (IT Asset Management vault key, SIEM
# secrets / Data Optimizer keys) go into a separate small "keys" archive that stays on this server and is never copied to
# the share / SFTP target - so a copied or stolen backup holds the sealed passwords but not the means to open them. Keep
# one copy of the newest keys archive and of the backup key in an offline safe (zyb-restore keys restores it).
# Plaintext ".bak" copies of secrets files are left out.
# Status for the dashboard: /var/lib/zyb-backup/status.json. Settings: /etc/zyb-backup.conf. Restore: zyb-restore.
# Settings from the portal (Platform Health & Backup > Backup settings, admins): the SIEM drops a request file that
# zyb-backup-settings.path watches; "zyb-backup --apply-settings" (root) checks every value again, rewrites only the
# known keys of /etc/zyb-backup.conf and the timer's time, and reports in /var/lib/zyb-backup/settings.json.
set -uo pipefail
DEST=/var/backups/zyb; KEEP_DAYS=14; KEEP_MIN=3; KEY_FILE=/etc/zyb-backup/backup.key
REMOTE_DIR=""; SFTP_TARGET=""; SFTP_KEY=""; CH_EVENT_DAYS=0; CH_DB=siem; VERIFY=1
EXTRA_PATHS=""; EXCLUDE="/var/lib/sentra-siem/spool"
# the keys that unseal stored credentials: kept out of the main archive (see above)
KEY_PATHS="/etc/sentra-itam/discovery-vault.key /etc/sentra-siem-keys/secrets.key /var/lib/sentra-siem/state/dataopt.key"
NODE=""
[ -r /etc/zyb-backup.conf ] && . /etc/zyb-backup.conf
# floors: a portal session (or a stolen one) must not be able to wipe the backup history by setting retention to 1
KEEP_DAYS_MIN=7; KEEP_MIN_MIN=3; REMOTE_ROOTS="/mnt /media /srv /backup"
[[ "$KEEP_DAYS" =~ ^[0-9]+$ ]] && [ "$KEEP_DAYS" -ge "$KEEP_DAYS_MIN" ] || KEEP_DAYS=$KEEP_DAYS_MIN
[[ "$KEEP_MIN" =~ ^[0-9]+$ ]] && [ "$KEEP_MIN" -ge "$KEEP_MIN_MIN" ] || KEEP_MIN=$KEEP_MIN_MIN
[ -x "${NODE:-}" ] || NODE=$(cat /usr/local/lib/zyb/node-path 2>/dev/null); [ -x "${NODE:-}" ] || NODE=$(command -v node || echo /opt/sentra-ai/node/bin/node)
ST=/var/lib/zyb-backup; mkdir -p "$ST" "$DEST"; chmod 700 "$DEST"
CONF_FILE="${ZYB_BACKUP_CONF:-/etc/zyb-backup.conf}"; SREQ="${SETTINGS_REQUEST:-/var/lib/sentra-siem/platform/backup-settings.json}"
TIMER_DROPIN="${ZYB_TIMER_DROPIN:-/etc/systemd/system/zyb-backup.timer.d/schedule.conf}"

# --write-settings / --apply-settings: the current settings for the portal, and settings changed from the portal
schedule_now() { local c; c=$(sed -n 's/^OnCalendar=\*-\*-\* \([0-9][0-9]:[0-9][0-9]\).*/\1/p' "$TIMER_DROPIN" 2>/dev/null | tail -1); [ -n "$c" ] || c=$(systemctl cat zyb-backup.timer 2>/dev/null | sed -n 's/^OnCalendar=\*-\*-\* \([0-9][0-9]:[0-9][0-9]\).*/\1/p' | tail -1); echo "${c:-01:30}"; }
write_settings() {   # write_settings <applied_by> <error> <warnings>
  [ -r "$CONF_FILE" ] && . "$CONF_FILE"
  local fp=""; [ -s "$KEY_FILE" ] && fp=$(sha256sum "$KEY_FILE" | cut -c1-16)
  Z_SCH="$(schedule_now)" Z_KD="$KEEP_DAYS" Z_KM="$KEEP_MIN" Z_RD="$REMOTE_DIR" Z_ST="$SFTP_TARGET" Z_SK="$SFTP_KEY" Z_EV="$CH_EVENT_DAYS" Z_VE="$VERIFY" Z_EX="$EXTRA_PATHS" \
  Z_DEST="$DEST" Z_FP="$fp" Z_BY="${1:-}" Z_ERR="${2:-}" Z_WARN="${3:-}" Z_OUT="$ST/settings.json" Z_MNT="$( [ -n "$REMOTE_DIR" ] && { mountpoint -q "$REMOTE_DIR" 2>/dev/null && echo mounted || { [ -d "$REMOTE_DIR" ] && echo folder || echo missing; }; } )" \
  "$NODE" -e '
    const fs=require("fs"),e=process.env;let p={};try{p=JSON.parse(fs.readFileSync(e.Z_OUT,"utf8"))}catch{}
    const o={schedule:e.Z_SCH,keep_days:+e.Z_KD,keep_min:+e.Z_KM,remote_dir:e.Z_RD,remote_dir_state:e.Z_MNT||"",sftp_target:e.Z_ST,sftp_key:e.Z_SK,events_days:+e.Z_EV,verify:e.Z_VE==="1",
      extra_paths:e.Z_EX,dest:e.Z_DEST,key_fingerprint:e.Z_FP,updated_at:new Date().toISOString(),
      last_apply:e.Z_BY?{at:new Date().toISOString(),by:e.Z_BY,error:e.Z_ERR||"",warnings:e.Z_WARN?e.Z_WARN.split("|").filter(Boolean):[]}:(p.last_apply||null)};
    fs.writeFileSync(e.Z_OUT+".tmp",JSON.stringify(o));fs.chmodSync(e.Z_OUT+".tmp",0o644);fs.renameSync(e.Z_OUT+".tmp",e.Z_OUT);'
}
set_conf() {   # set_conf KEY VALUE  (VALUE already checked: only safe characters)
  if grep -q "^$1=" "$CONF_FILE" 2>/dev/null; then sed -i "s|^$1=.*|$1=\"$2\"|" "$CONF_FILE"; else echo "$1=\"$2\"" >> "$CONF_FILE"; fi
}
if [ "${1:-}" = "--write-settings" ]; then write_settings "" "" ""; exit 0; fi
if [ "${1:-}" = "--apply-settings" ]; then
  [ -f "$SREQ" ] || { write_settings "" "" ""; exit 0; }
  # the request was written by the web side: every value is checked here again, and only these keys can change
  OUT=$("$NODE" -e '
    const fs=require("fs");let r;try{r=JSON.parse(fs.readFileSync(process.argv[1],"utf8").slice(0,20000))}catch{console.log("ERR=request is not valid JSON");process.exit(0)}
    const s=r&&r.settings||{},out=[],err=[],warn=[],P=/^\/[A-Za-z0-9._\/-]+$/,BAD=/^\/(proc|sys|dev|run|boot)(\/|$)|^\/etc\/zyb-backup(\/|$)|\.key$|\.\.|^\/$|^\/\/?$/;
    const num=(k,lo,hi)=>{if(s[k]===undefined)return;const n=Number(s[k]);if(!Number.isInteger(n)||n<lo||n>hi)err.push(k+" must be "+lo+"-"+hi);else out.push(k.toUpperCase()+"="+n)};
    if(s.schedule!==undefined){if(!/^([01]\d|2[0-3]):[0-5]\d$/.test(String(s.schedule)))err.push("time must be HH:MM");else out.push("SCHEDULE="+s.schedule)}
    num("keep_days",7,365);num("keep_min",3,100);
    if(s.events_days!==undefined){const n=Number(s.events_days);if(!Number.isInteger(n)||n<0||n>365)err.push("log days must be 0-365");else out.push("CH_EVENT_DAYS="+n)}
    if(s.verify!==undefined)out.push("VERIFY="+(s.verify===true?1:0));
    if(s.remote_dir!==undefined){const v=String(s.remote_dir).trim();const RR=/^\/(mnt|media|srv|backup)\/[A-Za-z0-9._\/-]+$/;if(v&&(!P.test(v)||BAD.test(v)||!RR.test(v)))err.push("share folder must be under /mnt, /media, /srv or /backup, like /mnt/backup");else out.push("REMOTE_DIR="+v)}
    if(s.sftp_target!==undefined){const v=String(s.sftp_target).trim();if(v&&!/^[A-Za-z0-9._-]{1,64}@[A-Za-z0-9.-]{1,253}:\/[A-Za-z0-9._\/-]*$/.test(v))err.push("SFTP target must look like user@host:/path");else out.push("SFTP_TARGET="+v)}
    if(s.sftp_key!==undefined){const v=String(s.sftp_key).trim();if(v&&(!P.test(v)||BAD.test(v)))err.push("SFTP key must be an absolute path");else{out.push("SFTP_KEY="+v);if(v&&!fs.existsSync(v))warn.push("SFTP key "+v+" does not exist on the server yet")}}
    if(s.extra_paths!==undefined){const L=String(s.extra_paths).split(/[\s,]+/).filter(Boolean);if(L.length>20||L.some(v=>!P.test(v)||BAD.test(v)))err.push("extra folders: absolute paths only, at most 20");else out.push("EXTRA_PATHS="+L.join(" "))}
    if(s.keep_days!==undefined&&s.keep_min!==undefined&&Number(s.keep_min)>Number(s.keep_days)*4)warn.push("keep-at-least is much higher than the days kept");
    const by=String(r.by||"portal").replace(/[^A-Za-z0-9@._ :-]/g,"").slice(0,100);
    console.log("BY="+by);if(err.length)console.log("ERR="+err.join("; "));else out.forEach(l=>console.log("SET "+l));if(warn.length)console.log("WARN="+warn.join("|"));' "$SREQ" 2>&1)
  rm -f "$SREQ"
  BY=$(echo "$OUT" | sed -n 's/^BY=//p' | head -1); ERR=$(echo "$OUT" | sed -n 's/^ERR=//p' | head -1); WARN=$(echo "$OUT" | sed -n 's/^WARN=//p' | head -1)
  if [ -z "$ERR" ]; then
    [ -f "$CONF_FILE" ] || : > "$CONF_FILE"
    cp -p "$CONF_FILE" "$CONF_FILE.bak"
    while IFS= read -r l; do
      kv="${l#SET }"; k="${kv%%=*}"; v="${kv#*=}"
      case "$k" in
        SCHEDULE) mkdir -p "$(dirname "$TIMER_DROPIN")"; printf '[Timer]\nOnCalendar=\nOnCalendar=*-*-* %s\n' "$v" > "$TIMER_DROPIN"; systemctl daemon-reload 2>/dev/null; systemctl restart zyb-backup.timer 2>/dev/null ;;
        KEEP_DAYS|KEEP_MIN|CH_EVENT_DAYS|VERIFY|REMOTE_DIR|SFTP_TARGET|SFTP_KEY|EXTRA_PATHS) set_conf "$k" "$v" ;;
      esac
    done < <(echo "$OUT" | grep '^SET ')
    chmod 600 "$CONF_FILE"
    . "$CONF_FILE"
    [ -n "$REMOTE_DIR" ] && ! mountpoint -q "$REMOTE_DIR" 2>/dev/null && WARN="${WARN:+$WARN|}$REMOTE_DIR is not a mounted share - mount it (e.g. in /etc/fstab) or backups are copied to a local folder only"
    logger -t zyb-backup "settings changed from the portal by ${BY:-portal}"
  fi
  write_settings "${BY:-portal}" "$ERR" "$WARN"
  exit 0
fi
exec 9>"$ST/lock"; flock -n 9 || { echo "a backup is already running"; exit 0; }
T0=$(date +%s); NAME="zyb-backup-$(hostname -s)-$(date +%Y%m%d-%H%M%S)"; WORK=$(mktemp -d /var/tmp/zyb-backup.XXXXXX)
BY="${ZYB_BACKUP_BY:-schedule}"   # "Run backup now": the SIEM writes the user name to REQUEST_FILE (zyb-backup.path starts us)
REQ="${REQUEST_FILE:-/var/lib/sentra-siem/platform/backup-request}"
if [ -e "$REQ" ] || [ -L "$REQ" ]; then R=""; [ -f "$REQ" ] && [ ! -L "$REQ" ] && R="$(head -c 100 "$REQ" 2>/dev/null | tr -cd 'A-Za-z0-9@._ :-')"; BY="${R:-portal}"; rm -f "$REQ"; fi
cleanup() { rm -rf "$WORK" "$WORK.tarerr"; }; trap cleanup EXIT
log() { echo "$(date '+%F %T') $*"; }

status() {   # status <ok:true|false> <error> <file> <size> <remote> <remote_error>
  local next; next=$(systemctl show zyb-backup.timer -p NextElapseUSecRealtime --value 2>/dev/null)
  local remote_cfg=""; [ -n "$REMOTE_DIR" ] && remote_cfg="share $REMOTE_DIR"; [ -n "$SFTP_TARGET" ] && remote_cfg="${remote_cfg:+$remote_cfg + }sftp ${SFTP_TARGET%%:*}"
  local copies; copies=$(ls -1 "$DEST"/zyb-backup-*.enc 2>/dev/null | wc -l); local used; used=$(du -sb "$DEST" 2>/dev/null | cut -f1)
  Z_OK="$1" Z_ERR="$2" Z_FILE="$3" Z_SIZE="${4:-0}" Z_REMOTE="$5" Z_RERR="$6" Z_SEC=$(( $(date +%s) - T0 )) Z_BY="$BY" Z_ITEMS="${ITEMS:-0}" Z_EVD="${CH_EVENT_DAYS:-0}" \
  Z_NEXT="$next" Z_COPIES="${copies:-0}" Z_USED="${used:-0}" Z_DEST="$DEST" Z_KEEPD="$KEEP_DAYS" Z_KEEPM="$KEEP_MIN" Z_RCFG="$remote_cfg" Z_KEY="$KEY_FILE" Z_VER="$VERIFY" Z_ST="$ST/status.json" \
  "$NODE" -e '
    const fs=require("fs"),e=process.env,f=e.Z_ST; let p={}; try{p=JSON.parse(fs.readFileSync(f,"utf8"))}catch{}
    const at=new Date().toISOString(), last={at,ok:e.Z_OK==="true",by:e.Z_BY,file:e.Z_FILE,size:+e.Z_SIZE,seconds:+e.Z_SEC,remote:e.Z_REMOTE,remote_error:e.Z_RERR,error:e.Z_ERR,items:+e.Z_ITEMS,events_days:+e.Z_EVD};
    const o={last,last_ok_at:last.ok?at:(p.last_ok_at||null),next:e.Z_NEXT,copies:+e.Z_COPIES,dest_bytes:+e.Z_USED,
      config:{dest:e.Z_DEST,keep_days:+e.Z_KEEPD,keep_min:+e.Z_KEEPM,remote:e.Z_RCFG,encrypted:true,key_file:e.Z_KEY,events_days:+e.Z_EVD,verify:e.Z_VER==="1"},
      history:[last].concat(Array.isArray(p.history)?p.history:[]).slice(0,30)};
    fs.writeFileSync(f+".tmp",JSON.stringify(o)); fs.chmodSync(f+".tmp",0o644); fs.renameSync(f+".tmp",f);' 2>/dev/null || log "status file not written (node missing?)"
}
fail() { log "FAILED: $1"; status false "$1" "" 0 "" ""; logger -t zyb-backup -p user.crit "backup FAILED: $1"; exit 1; }

[ -s "$KEY_FILE" ] || fail "encryption key $KEY_FILE missing (run install-platform.sh)"
command -v openssl >/dev/null || fail "openssl is not installed"
COMP="gzip"; EXT="tar.gz"; command -v zstd >/dev/null && { COMP="zstd -T0 -6 -q"; EXT="tar.zst"; }
FREE=$(df -P -B1 "$DEST" | awk 'NR==2{print $4}')

# 1. ClickHouse: table definitions (+ events of the last N days)
CHC=""; command -v clickhouse-client >/dev/null && CHC=clickhouse-client
if [ -n "$CHC" ]; then
  CHU=""; CHP=""
  if [ -r /etc/sentra-siem/secrets.json ] && [ -f /opt/sentra-siem/engine/secretfile.js ]; then   # sealed at rest: read through the engine's module
    CHU=$("$NODE" /opt/sentra-siem/engine/secretfile.js get clickhouse.user 2>/dev/null)
    CHP=$("$NODE" /opt/sentra-siem/engine/secretfile.js get clickhouse.password 2>/dev/null)
  fi
  ch() { if [ -n "$CHU" ]; then CLICKHOUSE_PASSWORD="$CHP" $CHC --user "$CHU" "$@"; else $CHC "$@"; fi; }
  mkdir -p "$WORK/clickhouse"
  if tabs=$(ch -q "SELECT name FROM system.tables WHERE database='$CH_DB' AND NOT is_temporary ORDER BY name" 2>/dev/null); then
    : > "$WORK/clickhouse/schema.sql"
    for t in $tabs; do ch -q "SHOW CREATE TABLE \`$CH_DB\`.\`$t\` FORMAT TSVRaw" >> "$WORK/clickhouse/schema.sql" 2>/dev/null && printf ';\n\n' >> "$WORK/clickhouse/schema.sql"; done
    log "ClickHouse: $(echo "$tabs" | wc -w) table definitions"
    if [ "${CH_EVENT_DAYS:-0}" -gt 0 ] 2>/dev/null; then
      ch -q "SELECT * FROM \`$CH_DB\`.events WHERE ts >= now() - INTERVAL $CH_EVENT_DAYS DAY FORMAT Native" 2>"$WORK/ch.err" | $COMP > "$WORK/clickhouse/events-${CH_EVENT_DAYS}d.native.${COMP%% *}" \
        && log "ClickHouse: events of the last $CH_EVENT_DAYS days ($(du -h "$WORK/clickhouse/events-${CH_EVENT_DAYS}d.native.${COMP%% *}" | cut -f1))" \
        || log "ClickHouse events export failed: $(head -c 300 "$WORK/ch.err")"
    fi
  else log "ClickHouse not reachable - table definitions skipped"; fi
fi

# 2. what is installed (for the restore report)
{ echo "host: $(hostname -f 2>/dev/null || hostname)"; echo "date: $(date -u +%FT%TZ)"; echo "os: $(. /etc/os-release; echo "$PRETTY_NAME")"
  for s in sentra-siem sentra-itam clickhouse-server nginx docker; do echo "service $s: $(systemctl is-active "$s" 2>/dev/null)"; done
  command -v docker >/dev/null && docker ps --format 'container {{.Names}}: {{.Image}} {{.Status}}' 2>/dev/null
  [ -f /opt/sentra-siem/package.json ] && echo "sentra-siem: $(grep -m1 '"version"' /opt/sentra-siem/package.json)"
} > "$WORK/MANIFEST.txt"
crontab -l > "$WORK/root-crontab.txt" 2>/dev/null || true

# 3. folders (only those that exist) + container data folders of the portal sync service
P=""; for p in /etc/sentra-siem /etc/sentra-itam /etc/zyb-backup.conf /etc/zyb-health.conf /etc/zyb-sysinfo.conf /etc/nginx /etc/clickhouse-server \
  /var/lib/sentra-siem /var/lib/sentra-itam /var/www/sentra /var/www/noc-m365 /opt/sentra-siem /opt/sentra-itam /usr/local/sbin/zyb-* /usr/local/lib/zyb \
  /etc/sentra-* /var/lib/sentra-* /opt/sentra-* /etc/sentra* /var/lib/sentra* /opt/sentra* /etc/letsencrypt /etc/zyb-svcctl.conf $EXTRA_PATHS; do
  [ -e "$p" ] && case " $P " in *" $p "*) ;; *) P="$P $p";; esac; done
for u in /etc/systemd/system/sentra-* /etc/systemd/system/zyb-* /etc/systemd/system/sentra* /etc/systemd/system/clickhouse*; do [ -e "$u" ] && P="$P $u"; done
if command -v docker >/dev/null; then for c in $(docker ps -a --format '{{.Names}}' 2>/dev/null | grep -E 'noc|m365|portal|sentra' ); do
  for m in $(docker inspect -f '{{range .Mounts}}{{.Source}} {{end}}' "$c" 2>/dev/null); do [ -d "$m" ] && case "$m" in /var/lib/docker/*) ;; *) P="$P $m";; esac; done; done; fi
ITEMS=$(echo "$P" | wc -w)
EX=(); for e in $EXCLUDE; do EX+=(--exclude="$e"); done
for k in $KEY_PATHS /etc/zyb-backup; do EX+=(--exclude="$k" --exclude="${k#/}"); done
EX+=(--exclude='secrets.json.bak*' --exclude='*.json.bak-*' --exclude='config.json.bak-link-itam-*'); EX+=(--exclude='*/node_modules/.cache' --exclude='/var/www/sentra/dashboards/health.json' --exclude='/var/www/sentra/dashboards/sysinfo.json')
NEED=$(du -scb $P "$WORK" 2>/dev/null | tail -1 | cut -f1)
[ -n "$FREE" ] && [ -n "$NEED" ] && [ "$NEED" -gt "$FREE" ] && fail "not enough space in $DEST (need about $((NEED/1048576)) MB, free $((FREE/1048576)) MB)"

# 4. archive → compress → encrypt (streamed: the clear archive never touches the disk)
OUTF="$DEST/$NAME.$EXT.enc"
log "backing up $ITEMS items to $OUTF"
tar -cpf - --warning=no-file-changed --warning=no-file-removed --ignore-failed-read "${EX[@]}" -C "$WORK" . $P 2>"$WORK.tarerr" \
  | $COMP | openssl enc -aes-256-cbc -pbkdf2 -iter 200000 -salt -pass "file:$KEY_FILE" -out "$OUTF.part"
RC=("${PIPESTATUS[@]}")
[ "${RC[0]}" -le 1 ] && [ "${RC[1]}" = 0 ] && [ "${RC[2]}" = 0 ] || { rm -f "$OUTF.part"; fail "archive failed (tar ${RC[0]}, compress ${RC[1]}, encrypt ${RC[2]}): $(grep -v "socket ignored" "$WORK.tarerr" | head -c 300)"; }
mv -f "$OUTF.part" "$OUTF"; chmod 600 "$OUTF"
( cd "$DEST" && sha256sum "$(basename "$OUTF")" > "$(basename "$OUTF").sha256" )
SIZE=$(stat -c %s "$OUTF")

# 4b. the credential keys: a separate archive, local only (never copied to the remote target), newest 3 kept
KF=""; for k in $KEY_PATHS; do [ -f "$k" ] && KF="$KF $k"; done
if [ -n "$KF" ]; then
  KOUT="$DEST/$NAME.keys.enc"
  if tar -cpf - $KF 2>/dev/null | openssl enc -aes-256-cbc -pbkdf2 -iter 200000 -salt -pass "file:$KEY_FILE" -out "$KOUT.part"; then mv -f "$KOUT.part" "$KOUT"; chmod 600 "$KOUT"; log "credential keys saved separately (local only): $(basename "$KOUT")"
  else rm -f "$KOUT.part"; log "WARNING: the credential keys could not be saved separately"; fi
  ls -1t "$DEST"/zyb-backup-*.keys.enc 2>/dev/null | tail -n +4 | xargs -r rm -f
fi

# 5. verify: decrypt + list the whole archive
if [ "$VERIFY" = 1 ]; then
  DEC="gzip -dc"; [ "$EXT" = tar.zst ] && DEC="zstd -dcq"
  N=$(openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -pass "file:$KEY_FILE" -in "$OUTF" | $DEC | tar -tf - 2>/dev/null | wc -l)
  [ "${N:-0}" -gt 10 ] || fail "verification failed: the new archive could not be read back"
  log "verified: $N files"
fi

# 6. remote copy
REMOTE="none"; RERR=""
# safe_copy <file> <dir>: never writes through a link that is already there (a planted symlink would otherwise make root
# overwrite any file with the archive): new file with O_EXCL|O_NOFOLLOW under a random name, then rename into place
safe_copy() { "$NODE" -e '
  const fs=require("fs"),path=require("path"),cr=require("crypto"),K=fs.constants;const [src,dir]=process.argv.slice(1);
  const fin=path.join(dir,path.basename(src)),t=path.join(dir,"."+path.basename(src)+"."+cr.randomBytes(6).toString("hex")+".part");
  const fd=fs.openSync(t,K.O_WRONLY|K.O_CREAT|K.O_EXCL|K.O_NOFOLLOW,0o600),in_=fs.openSync(src,"r"),b=Buffer.alloc(1<<20);
  try{let n;while((n=fs.readSync(in_,b,0,b.length,null))>0)fs.writeSync(fd,b,0,n);fs.fsyncSync(fd)}catch(e){fs.closeSync(fd);fs.unlinkSync(t);throw e}
  fs.closeSync(fd);fs.closeSync(in_);fs.renameSync(t,fin)' "$1" "$2"; }
remote_ok() {   # the real folder must stay under a backup mount root (no symlink out of it)
  local real r; real=$(realpath -e -- "$1" 2>/dev/null) || return 1; [ -d "$real" ] || return 1
  for r in $REMOTE_ROOTS; do case "$real/" in "$r"/?*) return 0;; esac; done; return 1; }
if [ -n "$REMOTE_DIR" ]; then
  if ! remote_ok "$REMOTE_DIR"; then REMOTE="failed"; RERR="$REMOTE_DIR is not a folder under ${REMOTE_ROOTS// /, } (after following links) - not copied"
  elif mountpoint -q "$REMOTE_DIR" 2>/dev/null || [ -d "$REMOTE_DIR" ]; then
    id sentra-siem >/dev/null 2>&1 && runuser -u sentra-siem -- test -w "$REMOTE_DIR" 2>/dev/null && log "WARNING: $REMOTE_DIR is writable by the sentra-siem service account - make it root-only"
    if { safe_copy "$OUTF" "$REMOTE_DIR" && safe_copy "$OUTF.sha256" "$REMOTE_DIR"; } 2>"$WORK/r.err"; then REMOTE="ok"; ls -1t "$REMOTE_DIR"/zyb-backup-*.enc 2>/dev/null | tail -n +$((KEEP_MIN+1)) | while read -r f; do [ -n "$(find "$f" -mtime +"$KEEP_DAYS")" ] && rm -f "$f" "$f.sha256"; done
    else REMOTE="failed"; RERR="copy to $REMOTE_DIR: $(head -c 200 "$WORK/r.err")"; fi
  else REMOTE="failed"; RERR="$REMOTE_DIR is not mounted"; fi
fi
if [ -n "$SFTP_TARGET" ]; then
  K=(); [ -n "$SFTP_KEY" ] && K=(-i "$SFTP_KEY")
  if scp -q -o BatchMode=yes -o ConnectTimeout=20 "${K[@]}" "$OUTF" "$OUTF.sha256" "$SFTP_TARGET/" 2>"$WORK/s.err"; then [ "$REMOTE" = failed ] || REMOTE="ok"
  else REMOTE="failed"; RERR="${RERR:+$RERR; }sftp ${SFTP_TARGET%%:*}: $(head -c 200 "$WORK/s.err")"; fi
fi
[ -n "$RERR" ] && log "remote copy: $RERR"

# 7. retention (keep at least KEEP_MIN)
ls -1t "$DEST"/zyb-backup-*.enc 2>/dev/null | grep -v '\.keys\.enc$' | tail -n +$((KEEP_MIN+1)) | while read -r f; do [ -n "$(find "$f" -mtime +"$KEEP_DAYS")" ] && rm -f "$f" "$f.sha256" && log "removed old $f"; done

status true "" "$(basename "$OUTF")" "$SIZE" "$REMOTE" "$RERR"
write_settings "" "" "" 2>/dev/null || true
logger -t zyb-backup -p user.info "backup ok: $(basename "$OUTF") $((SIZE/1048576)) MB, remote $REMOTE"
log "done: $((SIZE/1048576)) MB in $(( $(date +%s) - T0 )) s, remote copy: $REMOTE"
