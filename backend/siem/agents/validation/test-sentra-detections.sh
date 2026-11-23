#!/bin/bash
# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
# test-sentra-detections.sh - end-to-end detection test for the Sentra SIEM on a Linux TEST server whose syslog
# reaches the SIEM (agents/linux/install-rsyslog-forwarder.sh). Performs real but harmless actions, cleans up, and
# prints the command that checks the alerts on the SIEM server.
#
#   ./test-sentra-detections.sh [--yes]        run as a NORMAL user that may use sudo (not as root)
#
#   1. 25 SSH connection attempts to localhost as a user that does not exist   -> SENTRA-LNX-001
#   2. three rounds of wrong sudo passwords (no password is ever accepted)      -> SENTRA-LNX-004
#   3. sudo to an interactive root shell that exits immediately                 -> SENTRA-LNX-003
#   4. creates and deletes a local user ashval-<random> (no home, no login)     -> SENTRA-IAM-004
# Get a change/test approval first and tell the SOC team: real alerts will be raised.
set -uo pipefail

say() { printf '\033[36m==> %s\033[0m\n' "$*"; }
warn() { printf '\033[33mwarning: %s\033[0m\n' "$*"; }
[ "$(id -u)" != 0 ] || { echo "error: run as a normal user with sudo rights (the sudo tests need a non-root user)"; exit 1; }
command -v ssh >/dev/null || { echo "error: ssh client not installed"; exit 1; }

ID="$(tr -dc 'a-z0-9' </dev/urandom | head -c 6)"
TESTUSER="ashval-$ID"
HOST="$(hostname -s | tr 'A-Z' 'a-z')"
echo
echo "Sentra SIEM - endpoint detection test on $HOST (run $ID)"
echo "This makes REAL changes the SOC will see as alerts: failed SSH and sudo logons, a root shell via sudo, and a"
echo "test user that is created and deleted again."
if [ "${1:-}" != "--yes" ]; then read -r -p 'Is this a test server and is the test approved? (yes/no) ' a; [ "$a" = yes ] || { echo cancelled; exit 1; }; fi

say "your sudo password is needed once (for steps 3 and 4)"
sudo -v || { echo "error: sudo failed"; exit 1; }
START="$(date -u -d '-5 sec' +%Y-%m-%dT%H:%M:%SZ)"
EXPECT=()

say "1. 25 SSH attempts to localhost as the non-existent user $TESTUSER-nouser"
for i in $(seq 1 25); do
  ssh -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
      "$TESTUSER-nouser@127.0.0.1" true </dev/null >/dev/null 2>&1
done
EXPECT+=(SENTRA-LNX-001)

say "2. wrong sudo passwords (3 rounds of 3)"
for r in 1 2 3; do printf 'wrong1\nwrong2\nwrong3\n' | sudo -S -k -p '' true >/dev/null 2>&1; done
EXPECT+=(SENTRA-LNX-004)

say "3. sudo to a root shell that exits at once"
sudo -v && sudo -i </dev/null >/dev/null 2>&1
EXPECT+=(SENTRA-LNX-003)

say "4. creating and deleting test user $TESTUSER"
if sudo useradd -M -s /usr/sbin/nologin -c "sentra-siem validation $ID" "$TESTUSER"; then
  EXPECT+=(SENTRA-IAM-004)
  sudo userdel "$TESTUSER" || warn "could not delete $TESTUSER - delete it by hand: sudo userdel $TESTUSER"
fi

echo
echo "Wait 1-2 minutes, then run this ON THE SIEM SERVER:"
echo
printf '\033[32m  sudo sentra-siem-validate check --host %s --since %s --expect %s\033[0m\n' "$HOST" "$START" "$(IFS=,; echo "${EXPECT[*]}")"
echo
echo "PASS = the SIEM raised that alert. FAIL = check that rsyslog forwards auth logs (agents/linux/README.md)."
