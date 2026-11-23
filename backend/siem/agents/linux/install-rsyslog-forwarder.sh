#!/bin/bash
# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
# Sentra SIEM - configure rsyslog on a Linux host to forward to the SIEM collector.
#
#   sudo ./install-rsyslog-forwarder.sh --collector siem.sentra.local --ca ca.pem         # TLS 6514 (default), peer = collector name
#   sudo ./install-rsyslog-forwarder.sh --collector 10.10.5.20 --plain                # plain TCP 5514: trusted segments only
#     (auth/sudo/sshd logs would cross the network in clear text and the sender cannot be authenticated)
#   sudo ./install-rsyslog-forwarder.sh --collector 10.10.5.20 --web nginx             # + nginx access/error logs
#   ./install-rsyslog-forwarder.sh --collector 10.10.5.20 --web both --dry-run         # print the config only
#   sudo ./install-rsyslog-forwarder.sh --uninstall
#
# Writes /etc/rsyslog.d/60-sentra-siem.conf (+ 61-sentra-siem-webaccess.conf), validates with `rsyslogd -N1`, rolls back
# on failure, restarts rsyslog and sends one test message. Nothing else on the host is changed.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RSYSLOG_D=/etc/rsyslog.d
MAIN_CONF="$RSYSLOG_D/60-sentra-siem.conf"
WEB_CONF="$RSYSLOG_D/61-sentra-siem-webaccess.conf"
CA_DEST=/etc/ssl/sentra-siem/ca.pem

COLLECTOR="" PORT="" TLS=1 CA="" PEER="" WEB="" DRY=0 UNINSTALL=0

die() { echo "error: $*" >&2; exit 1; }
usage() { sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --collector) COLLECTOR="${2:-}"; shift 2 ;;
    --port)      PORT="${2:-}"; shift 2 ;;
    --tls)       TLS=1; shift ;;   # default; kept for compatibility
    --plain)     TLS=0; shift ;;
    --ca)        CA="${2:-}"; shift 2 ;;
    --peer)      PEER="${2:-}"; shift 2 ;;
    --web)       WEB="${2:-}"; shift 2 ;;
    --dry-run)   DRY=1; shift ;;
    --uninstall) UNINSTALL=1; shift ;;
    -h|--help)   usage 0 ;;
    *)           echo "unknown option: $1" >&2; usage 2 ;;
  esac
done

if [ "$UNINSTALL" = 1 ]; then
  [ "$(id -u)" = 0 ] || die "run as root (sudo)"
  rm -f "$MAIN_CONF" "$WEB_CONF"
  rsyslogd -N1 >/dev/null 2>&1 || die "rsyslog config invalid after removal - check /etc/rsyslog.d"
  systemctl restart rsyslog
  echo "sentra-siem forwarding removed (queue files, if any: /var/spool/rsyslog/sentra_siem_fwd*)"
  exit 0
fi

[ -n "$COLLECTOR" ] || { echo "--collector is required" >&2; usage 2; }
[[ "$COLLECTOR" =~ ^[A-Za-z0-9.:-]+$ ]] || die "invalid --collector '$COLLECTOR'"
if [ -z "$PORT" ]; then if [ "$TLS" = 1 ]; then PORT=6514; else PORT=5514; fi; fi
[[ "$PORT" =~ ^[0-9]+$ ]] && [ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ] || die "invalid --port '$PORT'"
case "$WEB" in ""|nginx|apache|both) ;; *) die "--web must be nginx, apache or both" ;; esac
if [ "$TLS" = 1 ]; then
  [ -n "$CA" ] || die "TLS (the default) needs --ca <file> (the CA that issued the SIEM syslog certificate); use --plain only on a trusted segment"
  [ "$DRY" = 1 ] || [ -r "$CA" ] || die "CA file not readable: $CA"
  [ -n "$PEER" ] || PEER="$COLLECTOR"
  [[ "$PEER" =~ ^[A-Za-z0-9.*:-]+$ ]] || die "invalid --peer '$PEER'"
fi

render_main() {
  local tpl="$HERE/60-sentra-siem-forward.conf"
  [ "$TLS" = 1 ] && tpl="$HERE/60-sentra-siem-forward-tls.conf"
  [ -r "$tpl" ] || die "template not found: $tpl"
  sed -e "s|@@COLLECTOR@@|$COLLECTOR|g" -e "s|@@PORT@@|$PORT|g" -e "s|@@CAFILE@@|$CA_DEST|g" -e "s|@@PEER@@|$PEER|g" "$tpl"
}

# keep only the #BEGIN/#END blocks for the chosen web server(s); comment out module(load="imfile") if already loaded
render_web() {
  local tpl="$HERE/61-sentra-siem-webaccess.conf" keep_nginx=0 keep_apache=0 imfile_loaded=0
  [ -r "$tpl" ] || die "template not found: $tpl"
  case "$WEB" in nginx) keep_nginx=1 ;; apache) keep_apache=1 ;; both) keep_nginx=1; keep_apache=1 ;; esac
  if grep -rlsE '^[[:space:]]*(module\(load="imfile"|\$ModLoad[[:space:]]+imfile)' /etc/rsyslog.conf "$RSYSLOG_D" 2>/dev/null \
       | grep -qv "$(basename "$WEB_CONF")"; then imfile_loaded=1; fi
  awk -v n="$keep_nginx" -v a="$keep_apache" -v loaded="$imfile_loaded" '
    /^#BEGIN nginx/  { skip = (n == 0); next }
    /^#BEGIN apache/ { skip = (a == 0); next }
    /^#END /         { skip = 0; next }
    skip             { next }
    /^module\(load="imfile"/ && loaded == 1 { print "# (imfile already loaded elsewhere) " $0; next }
    { print }' "$tpl"
}

if [ "$DRY" = 1 ]; then
  echo "### $MAIN_CONF"; render_main
  if [ -n "$WEB" ]; then echo; echo "### $WEB_CONF"; render_web; fi
  exit 0
fi

[ "$(id -u)" = 0 ] || die "run as root (sudo)"
command -v rsyslogd >/dev/null 2>&1 || die "rsyslog is not installed (apt-get install rsyslog)"
if [ "$TLS" = 1 ] && ! [ -e /usr/lib/x86_64-linux-gnu/rsyslog/lmnsd_gtls.so ] && ! ls /usr/lib*/rsyslog/lmnsd_gtls.so >/dev/null 2>&1; then
  if command -v apt-get >/dev/null 2>&1; then DEBIAN_FRONTEND=noninteractive apt-get install -y -q rsyslog-gnutls >/dev/null
  else die "install the rsyslog-gnutls (Debian/Ubuntu) or rsyslog-gnutls/rsyslog-openssl (RHEL) package first"; fi
fi

TMPD="$(mktemp -d)"; trap 'rm -rf "$TMPD"' EXIT
for f in "$MAIN_CONF" "$WEB_CONF"; do [ -e "$f" ] && cp -p "$f" "$TMPD/$(basename "$f").bak"; done

rollback() {
  echo "rsyslog rejected the new configuration - rolling back" >&2
  rm -f "$MAIN_CONF" "$WEB_CONF"
  for f in "$MAIN_CONF" "$WEB_CONF"; do [ -e "$TMPD/$(basename "$f").bak" ] && cp -p "$TMPD/$(basename "$f").bak" "$f"; done
  exit 1
}

if [ "$TLS" = 1 ]; then
  install -d -m 755 "$(dirname "$CA_DEST")"
  install -m 644 "$CA" "$CA_DEST"
fi
mkdir -p /var/spool/rsyslog
render_main > "$MAIN_CONF"; chmod 644 "$MAIN_CONF"
if [ -n "$WEB" ]; then render_web > "$WEB_CONF"; chmod 644 "$WEB_CONF"; else rm -f "$WEB_CONF"; fi

if ! rsyslogd -N1 > "$TMPD/check.log" 2>&1; then cat "$TMPD/check.log" >&2; rollback; fi
systemctl restart rsyslog
sleep 1
systemctl is-active --quiet rsyslog || { journalctl -u rsyslog -n 20 --no-pager >&2 || true; rollback; }

if [ -n "$WEB" ] && id syslog >/dev/null 2>&1 && ! id -nG syslog | grep -qw adm; then
  echo "warning: user 'syslog' is not in group 'adm' - it may not be able to read web server logs" >&2
fi
if command -v nc >/dev/null 2>&1 && [ "$TLS" = 0 ]; then
  nc -z -w 3 "$COLLECTOR" "$PORT" 2>/dev/null && echo "collector $COLLECTOR:$PORT reachable (TCP)" \
    || echo "warning: $COLLECTOR:$PORT not reachable right now - messages queue in /var/spool/rsyslog (max 1 GB)" >&2
fi
logger -p auth.info -t sentra-siem-test "sentra-siem forwarding test from $(hostname -f 2>/dev/null || hostname)"

cat <<EOF
Done. $MAIN_CONF$([ -n "$WEB" ] && echo " + $WEB_CONF") installed; rsyslog restarted.
Verify on the SIEM:
  - Sources page: this host's IP appears (register it in /etc/sentra-siem/config.json "sources" with type "linux",
    or it lands in the generic syslog-tcp source), status ok, parse error rate ~0 %.
  - Search:  host:$(hostname -s 2>/dev/null || hostname) AND "forwarding test"
Local diagnostics: journalctl -u rsyslog | grep -i sentra_siem   (suspension/resume messages)
EOF
