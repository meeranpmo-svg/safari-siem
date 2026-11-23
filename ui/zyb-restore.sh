#!/bin/bash
# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
# zyb-restore - list, check and restore the platform backups made by zyb-backup.
#   sudo zyb-restore list                       backups on this server (and on the remote share, if set)
#   sudo zyb-restore verify  <file>             decrypt + read the whole archive, compare the checksum
#   sudo zyb-restore extract <file> [<dir>]     unpack into a folder (default /var/tmp/zyb-restore-<date>) to look at
#                                               or copy single files back - nothing on the server is changed
#   sudo zyb-restore apply   <file>             full restore on this server: stops the platform services, saves the
#                                               current files to /var/backups/zyb/pre-restore-<date>.tar.gz, puts the
#                                               backup's files back, reloads systemd and starts the services again
#   sudo zyb-restore events  <file>             load the SIEM log events saved in the backup back into ClickHouse
#   sudo zyb-restore keys    <file.keys.enc>    put the credential keys back (vault / secrets keys - kept apart from the
#                                               main archive and never copied off the server; take it from your safe copy)
# On a NEW server: install the platform first (same paths), copy /etc/zyb-backup/backup.key from your safe copy, then apply.
# The key: KEY_FILE in /etc/zyb-backup.conf (default /etc/zyb-backup/backup.key), or ZYB_KEY_FILE=<path> zyb-restore ...
set -uo pipefail
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
DEST=/var/backups/zyb; KEY_FILE=/etc/zyb-backup/backup.key; REMOTE_DIR=""; CH_DB=siem
[ -r /etc/zyb-backup.conf ] && . /etc/zyb-backup.conf
KEY_FILE=${ZYB_KEY_FILE:-$KEY_FILE}
die() { echo "!! $*"; exit 1; }
find_file() { local f=$1; [ -f "$f" ] && { echo "$f"; return; }; [ -f "$DEST/$f" ] && { echo "$DEST/$f"; return; }; [ -n "$REMOTE_DIR" ] && [ -f "$REMOTE_DIR/$f" ] && { echo "$REMOTE_DIR/$f"; return; }; die "backup $f not found"; }
dec() { local f=$1; [ -s "$KEY_FILE" ] || die "key $KEY_FILE missing - copy it from your safe copy"; local z="gzip -dc"; case "$f" in *.tar.zst.enc) z="zstd -dcq";; esac
  openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -pass "file:$KEY_FILE" -in "$f" | $z; }
SVCS="sentra-siem sentra-itam zyb-health.timer"

case "${1:-}" in
  list)
    for d in "$DEST" ${REMOTE_DIR:+"$REMOTE_DIR"}; do echo "== $d"; ls -1t "$d"/zyb-backup-*.enc 2>/dev/null | while read -r f; do printf '  %-60s %8s MB  %s\n' "$(basename "$f")" "$(( $(stat -c %s "$f") / 1048576 ))" "$(date -d @"$(stat -c %Y "$f")" '+%F %T')"; done; done ;;
  verify)
    f=$(find_file "${2:?backup file}")
    if [ -f "$f.sha256" ]; then ( cd "$(dirname "$f")" && sha256sum -c "$(basename "$f").sha256" ) || die "checksum does not match"; fi
    n=$(dec "$f" | tar -tf - | wc -l); [ "$n" -gt 10 ] || die "archive unreadable (wrong key?)"
    echo "OK: $n files"; dec "$f" | tar -xOf - ./MANIFEST.txt 2>/dev/null ;;
  extract)
    f=$(find_file "${2:?backup file}"); out=${3:-/var/tmp/zyb-restore-$(date +%Y%m%d-%H%M%S)}; mkdir -p "$out"; chmod 700 "$out"
    dec "$f" | tar -xpf - -C "$out" || die "extract failed"; echo "unpacked into $out (secrets included - delete the folder when done)" ;;
  apply)
    f=$(find_file "${2:?backup file}")
    echo "This replaces the platform's settings, data and programs on $(hostname) with the backup $(basename "$f")."
    read -r -p "Type RESTORE to continue: " a; [ "$a" = RESTORE ] || die "cancelled"
    n=$(dec "$f" | tar -tf - | wc -l); [ "$n" -gt 10 ] || die "archive unreadable (wrong key?)"
    paths=$(dec "$f" | tar -tf - | grep -v '^\./' | cut -d/ -f1-3 | sort -u | grep -E '^(etc|var|opt|usr)/' | sed 's|^|/|')
    pre="$DEST/pre-restore-$(date +%Y%m%d-%H%M%S).tar.gz.enc"   # the current files hold secrets: encrypted like a backup
    echo "saving the current files to $pre"; ( umask 077; tar -czpf - --ignore-failed-read $(for p in $paths; do [ -e "$p" ] && echo "$p"; done) 2>/dev/null | openssl enc -aes-256-cbc -pbkdf2 -iter 200000 -salt -pass "file:$KEY_FILE" -out "$pre" ); chmod 600 "$pre"
    echo "stopping services"; for s in $SVCS; do systemctl stop "$s" 2>/dev/null; done
    dec "$f" | tar -xpf - -C / --exclude='./*' || { echo "!! restore failed - putting the previous files back"; dec "$pre" | tar -xpf - -C /; }
    systemctl daemon-reload; for s in $SVCS nginx; do systemctl start "$s" 2>/dev/null; done; nginx -t 2>/dev/null && systemctl reload nginx
    for s in sentra-siem sentra-itam nginx; do echo "  $s: $(systemctl is-active "$s" 2>/dev/null)"; done
    for k in /etc/sentra-itam/discovery-vault.key; do [ -f "$k" ] || echo "NOTE: $k is not on this server - stored passwords cannot be opened until you run: zyb-restore keys <the .keys.enc file from your safe copy>"; done
    echo "restored. Previous files: $pre (undo: zyb-restore undo $pre)" ;;
  undo)
    f=$(find_file "${2:?pre-restore file}"); read -r -p "Put back the files saved in $(basename "$f")? Type UNDO: " a; [ "$a" = UNDO ] || die "cancelled"
    dec "$f" | tar -xpf - -C / && echo "previous files put back" ;;
  keys)
    f=$(find_file "${2:?keys file}"); case "$f" in *.keys.enc) ;; *) die "give the .keys.enc file";; esac
    tmp=$(mktemp -d); chmod 700 "$tmp"; openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -pass "file:$KEY_FILE" -in "$f" | tar -xpf - -C "$tmp" || { rm -rf "$tmp"; die "cannot read the keys file (wrong backup key?)"; }
    for k in $(cd "$tmp" && find . -type f | sed 's|^\.||'); do
      if [ -f "$k" ] && ! cmp -s "$tmp$k" "$k"; then echo "kept $k (a different key is already there - move it away first if you mean to replace it)"; continue; fi
      install -D -m 600 "$tmp$k" "$k"; case "$k" in /etc/sentra-itam/*) chown sentra-itam:sentra-itam "$k" 2>/dev/null;; /etc/sentra-siem/*|/var/lib/sentra-siem/*) chown sentra-siem:sentra-siem "$k" 2>/dev/null;; esac; echo "restored $k"; done
    rm -rf "$tmp"; echo "restart the services: systemctl restart sentra-itam sentra-siem" ; logger -t zyb-backup -p user.warning "platform restored from $(basename "$f")" ;;
  events)
    f=$(find_file "${2:?backup file}"); command -v clickhouse-client >/dev/null || die "clickhouse-client not found"
    tmp=$(mktemp -d); dec "$f" | tar -xpf - -C "$tmp" ./clickhouse 2>/dev/null; ev=$(ls "$tmp"/clickhouse/events-* 2>/dev/null | head -1); [ -n "$ev" ] || { rm -rf "$tmp"; die "this backup holds no log events (CH_EVENT_DAYS was 0)"; }
    z="gzip -dc"; case "$ev" in *.zstd) z="zstd -dcq";; esac
    $z "$ev" | clickhouse-client -q "INSERT INTO \`$CH_DB\`.events FORMAT Native" && echo "events loaded"; rm -rf "$tmp" ;;
  *) sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//' ;;
esac
