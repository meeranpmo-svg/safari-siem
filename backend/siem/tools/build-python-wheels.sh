#!/bin/bash
# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
# build-python-wheels.sh - rebuild install/vendor/python-wheels-linux-x86_64.tgz (the offline bundle netops-cli-setup.sh
# installs Netmiko, pypsrp and the database drivers from). Run on any Linux PC with internet and Python >= 3.10:
#   bash tools/build-python-wheels.sh            downloads wheels for CPython 3.10-3.14 on x86_64 Linux, writes the bundle,
#                                                its .sha256 and the file list, then checks every wheel against PyPI's advisories
# Minimum versions live in install/vendor/python-constraints.txt (each line says which advisory it closes). Python 3.8 / 3.9
# are not bundled: the fixed urllib3 / requests / pip releases need 3.10, so a 3.9 bundle could not be made clean.
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"; V="$HERE/install/vendor"; C="$V/python-constraints.txt"
PKGS=(netmiko pypsrp pymysql pg8000 python-tds pip setuptools)
OUT="$(mktemp -d)"; trap 'rm -rf "$OUT"' EXIT
for pv in 3.10 3.11 3.12 3.13 3.14; do
  abi="cp${pv/./}"
  echo "==> CPython $pv"
  python3 -m pip download -q --disable-pip-version-check --only-binary=:all: --implementation cp --python-version "$pv" --abi "$abi" \
    --abi abi3 --abi none --platform manylinux_2_28_x86_64 --platform manylinux_2_17_x86_64 --platform manylinux2014_x86_64 \
    --platform any -c "$C" -d "$OUT" "${PKGS[@]}"
done
cp "$C" "$OUT/constraints.txt"
# advisories: every wheel in the bundle, looked up on PyPI (OSV data); any open advisory stops the build unless it is
# listed as accepted in the constraints file ("# accepted: <id> ...")
FAIL=0
for w in "$OUT"/*.whl; do
  b="$(basename "$w")"; n="${b%%-*}"; v="$(echo "$b" | cut -d- -f2)"
  ids="$(curl -fsS -m 30 "https://pypi.org/pypi/$n/$v/json" | python3 -c 'import json,sys;print(" ".join(x["id"] for x in json.load(sys.stdin).get("vulnerabilities",[]) if not x.get("withdrawn")))')" || { echo "!! advisory lookup failed for $n $v"; FAIL=1; continue; }
  for id in $ids; do grep -q "accepted: .*\b$id\b" "$C" || { echo "!! $n $v: $id"; FAIL=1; }; done
done
[ "$FAIL" = 0 ] || { echo "!! open advisories (or failed lookups) - raise the minimums in $C, or record why one is accepted"; exit 1; }
(cd "$OUT" && ls | sort > "$V/python-wheels-linux-x86_64.txt" && tar --owner=0 --group=0 --sort=name -czf "$V/python-wheels-linux-x86_64.tgz" *)
(cd "$V" && sha256sum python-wheels-linux-x86_64.tgz > python-wheels-linux-x86_64.tgz.sha256)
echo "==> $(grep -c '\.whl$' "$V/python-wheels-linux-x86_64.txt") wheels, no open advisories: $V/python-wheels-linux-x86_64.tgz"
