#!/bin/bash
# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
# netops-pam-setup.sh - approved network tasks take the device WRITE account from your PAM (engine/netops/pam.js).
#   sudo bash netops-pam-setup.sh --checkout FILE [--checkin FILE]   install the programs, switch PAM on (required), restart
#   sudo bash netops-pam-setup.sh --test "NETWORK/acc-sw1-admin"     one checkout + check-in; prints the username only
#   sudo bash netops-pam-setup.sh --off                              switch PAM off (stored write logins allowed again)
# The programs are copied to /usr/local/sbin/zyb-pam-checkout / zyb-pam-checkin, owned by root, mode 755 - the SIEM refuses
# programs it could replace itself. Template: install/pam/zyb-pam-example.sh.
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
CFG=/etc/sentra-siem/config.json; CO=/usr/local/sbin/zyb-pam-checkout; CI=/usr/local/sbin/zyb-pam-checkin
NODE="$(command -v node || true)"; [ -n "$NODE" ] || NODE="$(systemctl show -p ExecStart --value sentra-siem 2>/dev/null | sed -n 's/.*argv\[\]=\([^ ;]*\).*/\1/p' | head -n1)"
[ -x "${NODE:-}" ] || { echo "node not found"; exit 1; }
CHECKOUT=""; CHECKIN=""; TEST=""; OFF=0
while [ $# -gt 0 ]; do case "$1" in --checkout) CHECKOUT="${2:-}"; shift;; --checkin) CHECKIN="${2:-}"; shift;; --test) TEST="${2:-}"; shift;; --off) OFF=1;; *) echo "unknown option $1"; exit 1;; esac; shift; done
setcfg() { PAMJSON="$1" "$NODE" -e '
  const fs=require("fs"),f=process.argv[1],c=JSON.parse(fs.readFileSync(f,"utf8"));c.netops=c.netops||{};c.netops.pam=JSON.parse(process.env.PAMJSON);
  const t=f+".tmp-"+process.pid;fs.writeFileSync(t,JSON.stringify(c,null,2)+"\n",{mode:fs.statSync(f).mode&0o777});const st=fs.statSync(f);fs.chownSync(t,st.uid,st.gid);fs.renameSync(t,f);' "$CFG"; }
if [ "$OFF" = 1 ]; then setcfg '{"enabled":false}'; systemctl restart sentra-siem; echo "==> PAM switched off"; exit 0; fi
if [ -n "$CHECKOUT" ]; then
  [ -f "$CHECKOUT" ] || { echo "$CHECKOUT not found"; exit 1; }
  install -m 755 -o root -g root "$CHECKOUT" "$CO"; J="{\"enabled\":true,\"required\":true,\"checkout\":\"$CO\""
  if [ -n "$CHECKIN" ]; then [ -f "$CHECKIN" ] || { echo "$CHECKIN not found"; exit 1; }; install -m 755 -o root -g root "$CHECKIN" "$CI"; J="$J,\"checkin\":\"$CI\""; fi
  setcfg "$J,\"timeout_s\":30}"; systemctl restart sentra-siem; sleep 3
  echo "==> PAM on: approved network tasks check the write account out of the PAM for each run (stored write passwords are not used)"
  echo "    next: AI Network Engineer → device → Credentials → Write account → PAM account reference; test: sudo bash $0 --test <reference>"
fi
if [ -n "$TEST" ]; then
  [ -x "$CO" ] || { echo "no checkout program installed - run with --checkout first"; exit 1; }
  OUT="$(printf '{"action":"checkout","account":"%s","device":"test","ip":"","name":"setup test","reason":"PAM setup test","plan":"TEST","requested_by":"%s","approved_by":"","run_by":"%s"}' "$TEST" "${SUDO_USER:-root}" "${SUDO_USER:-root}" | "$CO")" || { echo "!! checkout failed (see the message above)"; exit 1; }
  printf '%s' "$OUT" | "$NODE" -e 'let d="";process.stdin.on("data",c=>d+=c).on("end",()=>{let j;try{j=JSON.parse(d)}catch(e){console.log("!! the checkout program did not answer JSON");process.exit(1)}
    console.log(j.username&&j.password?"==> checkout OK: username "+j.username+", password received ("+j.password.length+" characters, not shown)"+(j.lease?", lease "+j.lease:""):"!! answer has no username / password");process.exit(j.username&&j.password?0:1)})'
  LEASE="$(printf '%s' "$OUT" | "$NODE" -e 'let d="";process.stdin.on("data",c=>d+=c).on("end",()=>{try{process.stdout.write(String(JSON.parse(d).lease||""))}catch(e){}})')"; unset OUT
  [ -x "$CI" ] && printf '{"action":"checkin","account":"%s","lease":"%s","device":"test","plan":"TEST","outcome":"test"}' "$TEST" "$LEASE" | "$CI" && echo "==> check-in OK"
fi
