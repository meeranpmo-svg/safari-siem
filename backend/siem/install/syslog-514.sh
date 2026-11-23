#!/bin/bash
# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
# syslog-514.sh - let devices that can only send syslog to the standard port 514 (classic Cisco IOS, many switches,
# printers, UPS cards) reach the SIEM, which listens on its own port (default 5514, from /etc/sentra-siem/config.json).
#   sudo bash syslog-514.sh            redirect UDP + TCP 514 -> the SIEM syslog port, open 514 in the host firewall
#   sudo bash syslog-514.sh --status   show what is in place (changes nothing)
#   sudo bash syslog-514.sh --remove   take it all out again
# How: a local port redirect (firewalld forward-port when firewalld runs, else iptables nat PREROUTING REDIRECT kept by
# the boot unit sentra-siem-syslog514.service). A redirect keeps the sender's own address, so every registered source still
# matches. The SIEM process itself is not changed and needs no extra privilege. Nothing else is touched.
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
CFG=/etc/sentra-siem/config.json; UNIT=/etc/systemd/system/sentra-siem-syslog514.service; RULES=/usr/local/sbin/sentra-siem-syslog514
say() { echo "==> $*"; }
NODE="$(systemctl show -p ExecStart --value sentra-siem 2>/dev/null | sed -n 's/.*argv\[\]=\([^ ;]*\).*/\1/p' | head -n1)"; [ -x "${NODE:-}" ] || NODE=/opt/sentra-ai/node/bin/node; [ -x "$NODE" ] || NODE="$(command -v node || true)"
PORTS="$( [ -x "${NODE:-}" ] && "$NODE" -e 'let c={};try{c=JSON.parse(require("fs").readFileSync(process.argv[1],"utf8"))}catch(e){};const s=c.syslog||{},u=s.udp||{},t=s.tcp||{};console.log((u.enabled===false?0:(u.port||5514))+" "+(t.enabled===false?0:(t.port||5514)))' "$CFG" 2>/dev/null || echo "5514 5514")"
UDP=${PORTS% *}; TCP=${PORTS#* }
# config.json is writable by the service account and these values are written into a root boot script: numbers only
okport() { [[ "$1" =~ ^[0-9]{1,5}$ ]] && [ "$1" -le 65535 ]; }
okport "$UDP" || { echo "!! syslog UDP port in $CFG is not a number (0-65535): refusing"; exit 1; }
okport "$TCP" || { echo "!! syslog TCP port in $CFG is not a number (0-65535): refusing"; exit 1; }
FWD=0; systemctl is-active --quiet firewalld 2>/dev/null && command -v firewall-cmd >/dev/null && FWD=1

status() {
  echo "  SIEM listens on: UDP ${UDP:-off}, TCP ${TCP:-off}"
  if [ "$FWD" = 1 ]; then echo "  firewalld forward ports: $(firewall-cmd --list-forward-ports 2>/dev/null | tr '\n' ' ')"; echo "  firewalld open ports: $(firewall-cmd --list-ports 2>/dev/null)"
  else echo "  iptables redirects: $(iptables -t nat -S PREROUTING 2>/dev/null | grep -c 'dport 514 .*REDIRECT') rule(s)"; [ -f "$UNIT" ] && echo "  boot unit: $(systemctl is-enabled sentra-siem-syslog514 2>/dev/null)"; command -v ufw >/dev/null && ufw status 2>/dev/null | grep -E '^514' | sed 's/^/  ufw: /'; fi
  ss -lnuH 2>/dev/null | grep -q ":514 " && echo "  !! something else listens on UDP 514 locally (rsyslog?) - it will not see redirected packets from the network, but check it is intended"
}
case "${1:-}" in
  --status) status; exit 0;;
  --remove)
    if [ "$FWD" = 1 ]; then
      for p in udp tcp; do firewall-cmd --permanent --remove-forward-port="port=514:proto=$p:toport=$([ $p = udp ] && echo $UDP || echo $TCP)" >/dev/null 2>&1 || true; firewall-cmd --permanent --remove-port=514/$p >/dev/null 2>&1 || true; done; firewall-cmd --reload >/dev/null
    else
      [ -x "$RULES" ] && "$RULES" remove || true
      systemctl disable --now sentra-siem-syslog514 >/dev/null 2>&1 || true; rm -f "$UNIT" "$RULES"; systemctl daemon-reload
      command -v ufw >/dev/null && { ufw delete allow 514/udp >/dev/null 2>&1 || true; ufw delete allow 514/tcp >/dev/null 2>&1 || true; }
    fi
    say "port 514 redirect removed"; status; exit 0;;
  "") ;;
  *) echo "unknown option $1"; exit 1;;
esac

[ "$UDP" = 514 ] && [ "$TCP" = 514 ] && { say "the SIEM already listens on 514 itself - nothing to do"; exit 0; }
[ "$UDP" = 0 ] && [ "$TCP" = 0 ] && { echo "!! syslog UDP and TCP are both off in $CFG"; exit 1; }
if [ "$FWD" = 1 ]; then
  say "firewalld: forwarding 514 to the SIEM port and opening 514"
  [ "$UDP" != 0 ] && [ "$UDP" != 514 ] && firewall-cmd --permanent --add-forward-port="port=514:proto=udp:toport=$UDP" >/dev/null
  [ "$TCP" != 0 ] && [ "$TCP" != 514 ] && firewall-cmd --permanent --add-forward-port="port=514:proto=tcp:toport=$TCP" >/dev/null
  firewall-cmd --permanent --add-port=514/udp >/dev/null; firewall-cmd --permanent --add-port=514/tcp >/dev/null
  for p in $UDP $TCP; do [ "$p" != 0 ] && firewall-cmd --permanent --add-port=$p/udp >/dev/null && firewall-cmd --permanent --add-port=$p/tcp >/dev/null; done
  firewall-cmd --reload >/dev/null
else
  command -v iptables >/dev/null || { echo "!! neither firewalld nor iptables is available - install iptables (apt-get install iptables / dnf install iptables-nft)"; exit 1; }
  say "iptables: redirecting 514 to the SIEM port (kept across reboots by sentra-siem-syslog514.service)"
  cat > "$RULES" <<EOF
#!/bin/bash
# written by syslog-514.sh - redirect syslog 514 to the SIEM port (UDP $UDP, TCP $TCP); "remove" takes the rules out
act=-A; [ "\${1:-}" = remove ] && act=-D
for spec in "udp $UDP" "tcp $TCP"; do set -- \$spec; [ "\$2" = 0 ] || [ "\$2" = 514 ] && continue
  if [ "\$act" = -A ]; then iptables -t nat -C PREROUTING -p \$1 --dport 514 -j REDIRECT --to-ports \$2 2>/dev/null || iptables -t nat -A PREROUTING -p \$1 --dport 514 -j REDIRECT --to-ports \$2
  else while iptables -t nat -D PREROUTING -p \$1 --dport 514 -j REDIRECT --to-ports \$2 2>/dev/null; do :; done; fi
done
EOF
  chmod 755 "$RULES"
  cat > "$UNIT" <<EOF
[Unit]
Description=Sentra SIEM - accept syslog on port 514 (redirect to the SIEM port)
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$RULES
ExecStop=$RULES remove
[Install]
WantedBy=multi-user.target
EOF
  "$RULES"   # now (idempotent), and at every boot through the unit
  systemctl daemon-reload; systemctl enable sentra-siem-syslog514 >/dev/null
  if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then ufw allow 514/udp >/dev/null; ufw allow 514/tcp >/dev/null; for p in $UDP $TCP; do [ "$p" != 0 ] && ufw allow $p/udp >/dev/null && ufw allow $p/tcp >/dev/null; done; fi
fi
say "done - devices can now send syslog to this server on 514 (UDP / TCP) as well as $UDP"
status
echo "   undo: sudo bash $0 --remove"
