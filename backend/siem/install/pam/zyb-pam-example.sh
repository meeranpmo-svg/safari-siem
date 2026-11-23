#!/bin/bash
# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
# zyb-pam-example.sh - template for the PAM checkout / check-in program used by approved network tasks (engine/netops/pam.js).
# Copy it, fill in ONE of the blocks below for your PAM, and install it with:
#   sudo bash netops-pam-setup.sh --checkout /path/to/your-checkout.sh [--checkin /path/to/your-checkin.sh]
# Contract (one JSON object on stdin, one on stdout, exit 0 on success; print errors on stderr, never the password):
#   checkout in : {"action":"checkout","account":"<PAM reference set on the device>","device","ip","name","reason","plan",
#                  "requested_by","approved_by","run_by"}
#   checkout out: {"username":"...","password":"...","secret":"<enable secret, optional>","lease":"<checkout id, optional>"}
#   checkin  in : {"action":"checkin","account","lease","device","plan","outcome"}      (exit 0, no output needed)
# The PAM's own API user / certificate / token lives in a root-only file read here (e.g. /etc/sentra-siem/pam.env, chmod 600),
# never on the command line. Check every URL and field against your PAM version's API documentation.
set -euo pipefail
IN="$(cat)"
field() { printf '%s' "$IN" | python3 -c 'import json,sys;print(json.load(sys.stdin).get(sys.argv[1],""))' "$1"; }
ACTION="$(field action)"; ACCOUNT="$(field account)"; PLAN="$(field plan)"
[ -f /etc/sentra-siem/pam.env ] && . /etc/sentra-siem/pam.env

if [ "$ACTION" = checkin ]; then
  # Most PAMs release or rotate the password here (e.g. "check in" / "release request"). Nothing to do = exit 0.
  exit 0
fi

# ---- Example A: CyberArk Central Credential Provider (CCP / AIMWebService), client-certificate authentication
#   ACCOUNT format "Safe/Object", e.g. "NETWORK/acc-sw1-admin"; pam.env: CCP_URL, CCP_APPID, CCP_CERT, CCP_KEY
# SAFE="${ACCOUNT%%/*}"; OBJ="${ACCOUNT#*/}"
# J="$(curl -sS --fail --cert "$CCP_CERT" --key "$CCP_KEY" -G "$CCP_URL/AIMWebService/api/Accounts" \
#        --data-urlencode "AppID=$CCP_APPID" --data-urlencode "Safe=$SAFE" --data-urlencode "Object=$OBJ" \
#        --data-urlencode "Reason=platform task $PLAN")"
# printf '%s' "$J" | python3 -c 'import json,sys;j=json.load(sys.stdin);print(json.dumps({"username":j["UserName"],"password":j["Content"]}))'
# exit 0

# ---- Example B: ManageEngine PAM360 REST (AUTHTOKEN of an API user)
#   ACCOUNT format "Resource/Account"; pam.env: PAM360_URL, PAM360_TOKEN
# RES="${ACCOUNT%%/*}"; ACC="${ACCOUNT#*/}"
# IDS="$(curl -sS --fail -H "AUTHTOKEN: $PAM360_TOKEN" -G "$PAM360_URL/restapi/json/v1/resources/getResourceIdAccountId" \
#          --data-urlencode "RESOURCENAME=$RES" --data-urlencode "ACCOUNTNAME=$ACC")"
# RID="$(printf '%s' "$IDS" | python3 -c 'import json,sys;print(json.load(sys.stdin)["operation"]["Details"]["RESOURCEID"])')"
# AID="$(printf '%s' "$IDS" | python3 -c 'import json,sys;print(json.load(sys.stdin)["operation"]["Details"]["ACCOUNTID"])')"
# PW="$(curl -sS --fail -H "AUTHTOKEN: $PAM360_TOKEN" -G "$PAM360_URL/restapi/json/v1/resources/$RID/accounts/$AID/password" \
#          --data-urlencode "INPUT_DATA={\"operation\":{\"Details\":{\"REASON\":\"platform task $PLAN\"}}}")"
# printf '%s' "$PW" | ACC="$ACC" python3 -c 'import json,os,sys;j=json.load(sys.stdin);print(json.dumps({"username":os.environ["ACC"],"password":j["operation"]["Details"]["PASSWORD"]}))'
# exit 0

echo "zyb-pam-example.sh: no PAM block filled in - copy this file and complete one example for your PAM" >&2
exit 2
