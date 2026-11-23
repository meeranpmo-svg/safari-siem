#!/bin/bash
# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
# netops-cli-setup.sh - install the Python tools the AI assistants use for read-only access, in one venv:
#   Netmiko  AI Network Engineer: show commands over SSH (engine/netops/cli.js + cli-helper.py)
#   pypsrp   AI Windows Server / Exchange Server Administrators: read-only PowerShell checks over WinRM
#   pymysql pg8000 oracledb python-tds   Asset Discovery database logins (optional; IT Asset Management)
#            (engine/sysadmin/runner.js + ps-helper.py)
# Run from the repository folder; safe to re-run.
#   sudo bash install/netops-cli-setup.sh                      Python venv /opt/sentra-siem/pyenv + Netmiko + pypsrp: from the bundled
#                                                              wheels (install/vendor/python-wheels-linux-x86_64.tgz, checksum
#                                                              verified, Python 3.10-3.14 on x86_64 Linux with glibc 2.28+ = RHEL 8+;
#                                                              no internet needed),
#                                                              else from PyPI
#   sudo bash install/netops-cli-setup.sh --proxy http://proxy:8080   reach PyPI through a proxy
#   sudo bash install/netops-cli-setup.sh --wheels /path/to/wheels    offline: install from downloaded wheel files
# Offline wheels (on any Linux PC with internet and the SAME Python version as the server, e.g. 3.12 on RHEL 9):
#   pip download -c install/vendor/python-constraints.txt netmiko pypsrp -d wheels
# The bundle is rebuilt by tools/build-python-wheels.sh, which refuses wheels with an open security advisory. Python 3.8 / 3.9
# are not supported: the fixed urllib3 / requests releases need 3.10.
# Nothing here touches network devices. The venv is root-owned and read-only for the sentra-siem service user.
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
HERE="$(cd "$(dirname "$0")/.." && pwd)"; APP=/opt/sentra-siem; VENV=$APP/pyenv; SVC=sentra-siem
PROXY=""; WHEELS=""
while [ $# -gt 0 ]; do case "$1" in --proxy) PROXY="${2:-}"; shift;; --wheels) WHEELS="${2:-}"; shift;; *) echo "unknown option $1"; exit 1;; esac; shift; done
say() { echo "==> $*"; }
# result for the portal: the engine shows this file's reason instead of a generic "not installed"
STATUS=$APP/pyenv-status.json
status() { mkdir -p "$APP"; printf '{"ok":%s,"at":"%s","python":"%s","reason":"%s"}\n' "$1" "$(date -u +%FT%TZ)" "${PY:-}" "$(printf '%s' "$2" | tr '"\\\n' "' /" | cut -c1-400)" > "$STATUS"; chmod 644 "$STATUS"; }
fail() { echo "!! $1"; status false "$1"; exit 1; }

# a Python the bundled wheels fit (3.10-3.14; 3.15 tried): the system python3 when it fits, else a python3.X (RHEL 8's python3 is 3.6,
# RHEL 9's is 3.9 - both too old for the patched urllib3 / requests)
pick() { local c v; for c in python3 python3.14 python3.13 python3.12 python3.11 python3.10 python3.15; do
    c="$(command -v "$c" 2>/dev/null)" || continue
    v="$("$c" -c 'import sys;print("%d%02d"%sys.version_info[:2])' 2>/dev/null)" || continue
    [ "$v" -ge 310 ] && [ "$v" -le 315 ] && { echo "$c"; return 0; }
  done; return 1; }
PY="$(pick || true)"
if [ -z "$PY" ]; then
  # none fits: install a supported Python from the OS repositories when they are reachable (a local mirror / Satellite)
  if command -v dnf >/dev/null; then say "no Python 3.10-3.14 found - trying: dnf install python3.12"; timeout 300 dnf -y -q install python3.12 >/dev/null 2>&1 || timeout 300 dnf -y -q install python3.11 >/dev/null 2>&1 || true
  elif command -v apt-get >/dev/null; then say "no Python 3.10-3.14 found - trying: apt-get install python3"; timeout 300 apt-get -y -qq install python3 python3-venv >/dev/null 2>&1 || true; fi
  PY="$(pick || true)"
fi
[ -n "$PY" ] || fail "no Python 3.10-3.14 on this server (python3 is $(python3 -V 2>&1 || echo missing)). Install one: RHEL 8 / 9: sudo dnf install python3.12 | Ubuntu: sudo apt-get install python3 python3-venv - then run the update again"
PY="$(readlink -f "$PY")"   # the venv links to this path: the real file, not a link in a folder the service cannot enter
runuser -u "$SVC" -- "$PY" -c 'pass' 2>/dev/null || fail "the $SVC user cannot run $PY (a folder on its path is not readable) - install Python in a system location (/usr/bin, /usr/local/bin)"
say "using $("$PY" -V 2>&1) ($PY)"

# an old venv made with an unsuitable Python (or half-made) is replaced
if [ -x "$VENV/bin/python3" ] && ! "$VENV/bin/python3" -c 'import sys;sys.exit(0 if (3,10)<=sys.version_info[:2]<=(3,15) else 1)' 2>/dev/null; then rm -rf "$VENV"; fi
if [ ! -x "$VENV/bin/python3" ]; then
  if ! "$PY" -m venv "$VENV" 2>/dev/null; then
    # no ensurepip (Ubuntu without python3-venv): a venv without pip, then pip from the bundled wheel
    rm -rf "$VENV"; "$PY" -m venv --without-pip "$VENV" 2>/dev/null || fail "could not create a Python venv with $PY: sudo apt-get install python3-venv (or python3.X-venv), then run the update again"
    say "Python venv created without pip (no ensurepip) - pip comes from the bundled wheel"
  else say "Python venv created in $VENV"; fi
fi
[ -z "$PROXY" ] && [ -f /etc/default/sentra-siem ] && PROXY="$(sed -n 's/^HTTPS_PROXY=//p' /etc/default/sentra-siem | tail -n1)"
# --upgrade eager: a venv from an older bundle is brought up to the patched minimums, not left as "already satisfied"
PIP=("$VENV/bin/python3" -m pip install --disable-pip-version-check --no-input -q --upgrade --upgrade-strategy eager)
# the bundled wheels (the server usually has no internet): verified, unpacked to a private temp folder, used when they fit
BUNDLE="$HERE/install/vendor/python-wheels-linux-x86_64.tgz"; CONS="$HERE/install/vendor/python-constraints.txt"
if [ -z "$WHEELS" ] && [ -f "$BUNDLE" ]; then
  if (cd "$(dirname "$BUNDLE")" && sha256sum -c "$(basename "$BUNDLE").sha256" >/dev/null 2>&1); then
    BTMP="$(mktemp -d)"; trap 'rm -rf "$BTMP"' EXIT
    tar -xzf "$BUNDLE" -C "$BTMP" --no-same-owner
    if ! "$VENV/bin/python3" -m pip --version >/dev/null 2>&1; then   # venv without pip: install pip itself from its wheel
      PW="$(ls "$BTMP"/pip-*.whl 2>/dev/null | head -n1)"
      [ -n "$PW" ] && "$VENV/bin/python3" "$PW/pip" install -q --no-index --disable-pip-version-check "$PW" && say "pip installed into the venv from the bundled wheel"
    fi
    if "${PIP[@]}" --no-index --find-links "$BTMP" -c "$BTMP/constraints.txt" netmiko pypsrp pymysql pg8000 python-tds; then
      WHEELS="$BTMP"; say "installed Netmiko, pypsrp and the database drivers from the bundled wheels (offline)"
    else echo "   (the bundled wheels do not fit this server: Python $("$PY" -V 2>&1), $(uname -m) - trying PyPI)"; fi
  else echo "   (bundled wheels checksum mismatch - not used)"; fi
fi
if [ -n "$WHEELS" ] && [ "${WHEELS:-}" = "${BTMP:-none}" ]; then :   # done above
elif [ -n "$WHEELS" ]; then
  [ -d "$WHEELS" ] || { echo "!! $WHEELS is not a folder"; exit 1; }
  "${PIP[@]}" --no-index --find-links "$WHEELS" -c "$CONS" netmiko pypsrp || { status false "offline install from $WHEELS failed"; echo "!! offline install failed - the wheels must match this server's Python ($("$PY" -V 2>&1)) and CPU"; exit 1; }
else
  "${PIP[@]}" ${PROXY:+--proxy "$PROXY"} --upgrade pip >/dev/null 2>&1 || true
  if ! "${PIP[@]}" ${PROXY:+--proxy "$PROXY"} -c "$CONS" netmiko pypsrp; then   # the constraints keep paramiko < 4 (older Cisco IOS) and the patched minimums
    echo "!! could not download Netmiko / pypsrp from PyPI (no internet from this server?)."
    echo "   Use a proxy:   sudo bash $0 --proxy http://proxy.local:8080"
    echo "   or offline:    on a Linux PC with Python $("$PY" -c 'import sys;print("%d.%d"%sys.version_info[:2])'):  pip download -c install/vendor/python-constraints.txt netmiko pypsrp -d wheels"
    echo "                  (add -c install/vendor/python-constraints.txt)  copy the folder here, then: sudo bash $0 --wheels ./wheels"
    status false "the bundled wheels do not fit this server (Python $("$PY" -V 2>&1), $(uname -m)) and PyPI is not reachable - use a proxy or offline wheels (install/netops-cli-setup.sh --proxy / --wheels)"
    exit 1
  fi
fi
# Asset Discovery read-only logins (IT Asset Management, engine/discovery/inv-helper.py): pure-Python database drivers.
# Optional - a failure here only means database logins report "not installed"; SSH logins use paramiko (above).
DBLIBS="pymysql pg8000 oracledb python-tds"
if [ "${WHEELS:-}" = "${BTMP:-none}" ]; then "${PIP[@]}" ${PROXY:+--proxy "$PROXY"} --timeout 15 --retries 1 oracledb >/dev/null 2>&1 || echo "   (Oracle driver not bundled and PyPI not reachable - Oracle database logins in Asset Discovery stay off; the others work)"
elif [ -n "$WHEELS" ]; then "${PIP[@]}" --no-index --find-links "$WHEELS" -c "$CONS" $DBLIBS || echo "   (database drivers not in the wheels folder - database logins in Asset Discovery stay off: pip download $DBLIBS -d wheels)"
else "${PIP[@]}" ${PROXY:+--proxy "$PROXY"} -c "$CONS" $DBLIBS || echo "   (could not download the database drivers - database logins in Asset Discovery stay off until this is re-run)"; fi
chown -R root:root "$VENV"; chmod -R go-w "$VENV"; find "$VENV" -type d -exec chmod 755 {} +

HELPER="$APP/engine/netops/cli-helper.py"; [ -f "$HELPER" ] || HELPER="$HERE/engine/netops/cli-helper.py"
OUT="$(echo '{"op":"version"}' | runuser -u "$SVC" -- env PYTHONDONTWRITEBYTECODE=1 "$VENV/bin/python3" "$HELPER" 2>&1 || true)"
case "$OUT" in
  *'"ok": true'*) say "Netmiko ready for the $SVC user: $(echo "$OUT" | sed 's/[{}"]//g')"; status true "Netmiko installed ($("$VENV/bin/python3" -V 2>&1))"
     # which bundle this venv was built from: update-server.sh re-runs this setup when a newer (patched) bundle arrives
     if [ "${WHEELS:-}" = "${BTMP:-none}" ]; then cut -d' ' -f1 "$BUNDLE.sha256" > "$VENV/.bundle-sha256"; chmod 644 "$VENV/.bundle-sha256"; fi;;
  *) fail "the helper does not run for the $SVC user: $OUT";;
esac
PS="$APP/engine/sysadmin/ps-helper.py"; [ -f "$PS" ] || PS="$HERE/engine/sysadmin/ps-helper.py"
if [ -f "$PS" ]; then
  OUT="$(echo '{"op":"version"}' | runuser -u "$SVC" -- env PYTHONDONTWRITEBYTECODE=1 "$VENV/bin/python3" "$PS" 2>&1 || true)"
  case "$OUT" in *'"ok": true'*) say "pypsrp ready for the $SVC user (AI Windows / Exchange Server Administrators)";; *) echo "!! WinRM helper does not run for the $SVC user: $OUT"; exit 1;; esac
fi
INV=/opt/sentra-itam/engine/discovery/inv-helper.py
if [ -f "$INV" ] && id sentra-itam >/dev/null 2>&1; then
  OUT="$(echo '{"op":"version"}' | runuser -u sentra-itam -- env PYTHONDONTWRITEBYTECODE=1 "$VENV/bin/python3" -I "$INV" 2>&1 || true)"
  case "$OUT" in *'"ok": true'*) say "Asset Discovery logins ready for the sentra-itam user: $(echo "$OUT" | sed 's/.*modules": //; s/[{}"]//g')";; *) echo "   (Asset Discovery login helper does not run for sentra-itam yet: $OUT)";; esac
fi
say "done. Portal: AI Network Engineer > device > Credentials (SSH); AI Windows / Exchange Server Administrator > Logins"
