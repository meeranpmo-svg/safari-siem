#!/bin/bash
# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
# update-discovery.sh - Asset Discovery updates, applied in order (each one skipped when already installed):
#   discovery-ip-mac.patch  IP addresses for user PCs / physical servers, MAC addresses from ARP tables
#   discovery-speed.patch   ports + SNMP probed in parallel per address (a silent address costs one timeout, not ~7 s),
#                           live progress: phase, addresses done / total, devices answering
#   discovery-model.patch   switch model + serial on big stacks (only the ENTITY-MIB columns needed are read), Cisco
#                           model / family from the chassis description or the sysDescr software image when empty
#   discovery-nutanix.patch Nutanix Prism as a discovery source: credential kind, scope method, passive scan step,
#                           hosts classified as servers and VMs as vms (needs engine/discovery/methods/nutanix.js,
#                           copied here when missing)
#   discovery-services.patch active scope methods: database listeners (Oracle, SQL Server, MySQL, PostgreSQL, Db2, MongoDB,
#                           HANA), Solaris / Unix (SSH banner + Solaris ports), storage arrays and NAS (iSCSI, NFS, NDMP;
#                           NetApp, Dell EMC, HPE MSA / 3PAR / Nimble, Pure, Hitachi, Huawei, Synology, QNAP from SNMP)
#                           (needs engine/discovery/methods/services.js, copied here)
#   discovery-logins.patch  read-only LOGINS for the active scope methods: database credentials (Oracle, SQL Server,
#                           MySQL, PostgreSQL: version, edition, instance, databases), an SSH login for Solaris / Unix
#                           (fixed read-only commands: release, CPUs, memory, serial, model) and a NetApp / HPE MSA API
#                           login for storage arrays; passwords only go to trusted SSH keys / certificates (Credentials →
#                           Trust). Needs engine/discovery/methods/login.js + inv-helper.py (copied here) and, for SSH /
#                           databases, the SIEM's Python venv (install/netops-cli-setup.sh in sentra-siem)
#   discovery-catchup.patch brings an engine installed before 9 Oct 2026 to the version the later patches expect: credential
#                           target changes need the secret again, the shared sealer (Virtualization), agent-reported MACs
#                           and agent-key Hyper-V reports are untrusted, the shared SIEM link (log collection, licences)
#   discovery-dbports.patch database listeners on NON-STANDARD ports: the port on each database login is probed, and a
#                           scope can list extra ports per engine (Oracle / SQL Server / ... on site-specific ports)
#   discovery-testport.patch the credential Test names the address:port it tried ("refused at 10.0.0.5:1521 - set Port")
#   discovery-solaris.patch Oracle Solaris (and AIX / HP-UX) recognised from SNMP: server, OS + version + SPARC / x86,
#                           Connect to SIEM over syslog
#   discovery-python.patch  the HTTP inventory sources (vCenter, ESXi, Nutanix, Azure, AWS, CUCM) answered by Python
#                           (pyengine/discovery_sources.py, docs/PYTHON-MIGRATION.md step 5a; config discovery.engine =
#                           "node" switches back, and a missing Python falls back by itself). Needs
#                           engine/discovery/py-methods.js + pyengine/ (copied here)
#   discovery-pyguard.patch a missing Python bridge file can never stop sentra-itam (the plain Node.js methods are used)
#   discovery-pyad.patch    Active Directory read by Python too (pyengine/ad_source.py + ldap_client.py, step 5b)
#   discovery-pysnmp.patch  SNMP device collection read by Python (pyengine/snmp_source.py, step 5c); the sweep probe stays in Node.js
#   sudo bash update-discovery.sh            apply (safe to re-run: already-applied changes are skipped)
#   sudo bash update-discovery.sh --rollback put back the discovery files from before the first run
# Changes files of the installed engine (/opt/sentra-itam/engine/discovery/...) with patches, so local differences on the
# server are kept; when a patch does not fit, nothing more is changed and the reason is printed. Backup first, syntax
# check, restart, automatic restore on any failure.
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib-itam.sh"   # restart only when needed, wait until the API answers
APP=/opt/sentra-itam; SVC=sentra-itam; BK=/var/backups/sentra-itam-discovery
PATCHES="discovery-ip-mac discovery-speed discovery-model discovery-catchup discovery-nutanix discovery-solaris discovery-services discovery-logins discovery-hostlogs discovery-dbports discovery-testport discovery-python discovery-pyguard discovery-pyad discovery-pysnmp discovery-roles"
FILES="engine/discovery/runner.js engine/discovery/methods/snmp.js engine/discovery/vault.js engine/discovery/scopes.js engine/discovery/devices.js engine/discovery/classify.js engine/discovery/index.js engine/discovery/routes.js engine/discovery/siem.js"
NTX=engine/discovery/methods/nutanix.js; SVC_JS=engine/discovery/methods/services.js
LOGIN_JS=engine/discovery/methods/login.js; INV_PY=engine/discovery/inv-helper.py
say() { echo "==> $*"; }; die() { echo "!! $*"; exit 1; }

if [ "${1:-}" = "--rollback" ]; then
  [ -f "$BK/runner.js" ] || die "no backup in $BK"
  for f in $FILES; do b="$BK/$(basename "$f")"; [ -f "$b" ] && cp -p "$b" "$APP/$f"; done
  itam_restart; say "restored the discovery engine from before the first update ($(systemctl is-active "$SVC"))"; exit 0
fi

[ -f "$APP/engine/discovery/runner.js" ] || { say "Asset Discovery is not installed here ($APP) - skipped"; exit 0; }
TMPD="$(mktemp -d)"; trap 'rm -rf "$TMPD"' EXIT
for p in $PATCHES; do [ -f "$HERE/patches/$p.patch" ] || die "missing patches/$p.patch - copy the whole sentra-itam folder"; sed 's/\r$//' "$HERE/patches/$p.patch" > "$TMPD/$p.patch"; done   # a Windows checkout may have added CR
command -v patch >/dev/null || die "the 'patch' tool is missing (sudo apt-get install patch / sudo dnf install patch)"
NODE="$(systemctl show -p ExecStart --value "$SVC" 2>/dev/null | sed -n 's/.*argv\[\]=\([^ ;]*\).*/\1/p' | head -n1)"
[ -x "${NODE:-}" ] || NODE=/opt/sentra-ai/node/bin/node; [ -x "$NODE" ] || NODE="$(command -v node || true)"
[ -x "${NODE:-}" ] || die "could not find the Node.js the service uses"

PRE_FP="$(itam_fp)"
# the Nutanix client the nutanix patch requires (a new file; add-virt.sh installs the same one)
if [ -f "$HERE/../$NTX" ] && ! cmp -s "$HERE/../$NTX" "$APP/$NTX" 2>/dev/null; then
  install -m 644 -o root -g root "$HERE/../$NTX" "$APP/$NTX" && "$NODE" --check "$APP/$NTX" && say "installed $NTX"
fi

if [ -f "$HERE/../$SVC_JS" ] && ! cmp -s "$HERE/../$SVC_JS" "$APP/$SVC_JS" 2>/dev/null; then
  install -m 644 -o root -g root "$HERE/../$SVC_JS" "$APP/$SVC_JS" && "$NODE" --check "$APP/$SVC_JS" && say "installed $SVC_JS"
fi

# the read-only login step + its Python helper that the logins patch requires (new files)
if [ -f "$HERE/../$LOGIN_JS" ] && ! cmp -s "$HERE/../$LOGIN_JS" "$APP/$LOGIN_JS" 2>/dev/null; then
  install -m 644 -o root -g root "$HERE/../$LOGIN_JS" "$APP/$LOGIN_JS" && "$NODE" --check "$APP/$LOGIN_JS" && say "installed $LOGIN_JS"
fi
if [ -f "$HERE/../$INV_PY" ] && ! cmp -s "$HERE/../$INV_PY" "$APP/$INV_PY" 2>/dev/null; then
  install -m 644 -o root -g root "$HERE/../$INV_PY" "$APP/$INV_PY" && say "installed $INV_PY"
fi

# the Python bridge the python patch requires (new files; the add-ons install the same pyengine/)
PYM=engine/discovery/py-methods.js
for f in "$PYM" engine/pyengine.js engine/py-sources.js engine/assets-py.js engine/assets-write.js engine/py-writer.js engine/audit-verify.js engine/ai/guard-py.js; do
  if [ -f "$HERE/../$f" ] && ! cmp -s "$HERE/../$f" "$APP/$f" 2>/dev/null; then install -m 644 -o root -g root "$HERE/../$f" "$APP/$f" && "$NODE" --check "$APP/$f" && say "installed $f"; fi
done
if [ -d "$HERE/../pyengine" ]; then install -d -m 755 -o root -g root "$APP/pyengine"; for f in "$HERE"/../pyengine/*.py; do install -m 644 -o root -g root "$f" "$APP/pyengine/"; done; rm -rf "$APP/pyengine/__pycache__"; fi

# a core file that a patch no longer fits: when it is an UNMODIFIED earlier platform version (its hash is in core-known.txt,
# every version ever shipped - install/gen-core-known.js), it is replaced whole by the current one (backup kept, syntax
# checked, restored on failure). A file someone changed on this server matches nothing and is left alone.
KNOWN="$HERE/core-known.txt"
core_upgrade() { # core_upgrade <engine/rel.js> <patch name>
  local rel="$1" dst="$APP/$1" src="" h
  for s in "$HERE/../$1" "$HERE/../engine-all/${1#engine/}"; do [ -f "$s" ] && { src="$s"; break; }; done
  [ -n "$src" ] && [ -f "$dst" ] && [ -f "$KNOWN" ] || return 1
  if cmp -s <(tr -d '\r' < "$src") <(tr -d '\r' < "$dst"); then say "$2: already installed ($rel is the current version)"; return 0; fi
  h="$(tr -d '\r' < "$dst" | sha256sum | cut -d' ' -f1)"
  grep -q "^$h  $rel\$" "$KNOWN" || return 1
  mkdir -p "$BK"; chmod 700 "$BK"; cp -p "$dst" "$BK/$(basename "$rel").pre-upgrade-$(date +%Y%m%d%H%M%S)"; cp -p "$dst" "$TMPD/core.prev"
  if install -m 644 -o root -g root "$src" "$dst" && "$NODE" --check "$dst"; then say "$2: $rel was an unmodified earlier platform version - replaced with the current one (backup in $BK)"; return 0; fi
  cp -p "$TMPD/core.prev" "$dst"; echo "   $2: the current $rel did not pass the syntax check - kept the previous file"; return 1
}

# optional: inventory "Log collection" judged on each host's own logs (servers sharing one agent / syslog source).
# Applied only when it fits the installed engine exactly; otherwise skipped with a note - it never blocks the update.
MEM=engine/monitoring-membership.js; MEM_P="$HERE/patches/membership-hostlogs.patch"
if [ -f "$APP/$MEM" ] && [ -f "$MEM_P" ]; then
  sed 's/\r$//' "$MEM_P" > "$TMPD/mem.patch"
  if patch -p1 -R --dry-run -s -f -d "$APP" < "$TMPD/mem.patch" >/dev/null 2>&1; then say "membership-hostlogs: already installed"
  elif patch -p1 --dry-run -s -f -d "$APP" < "$TMPD/mem.patch" >/dev/null 2>&1; then
    mkdir -p "$BK"; chmod 700 "$BK"; [ -f "$BK/monitoring-membership.js" ] || cp -p "$APP/$MEM" "$BK/monitoring-membership.js"; cp -p "$APP/$MEM" "$TMPD/mem.prev"
    patch -p1 -f -s --no-backup-if-mismatch -d "$APP" < "$TMPD/mem.patch" && "$NODE" --check "$APP/$MEM" && say "applied membership-hostlogs (log collection per host)" || { cp -p "$TMPD/mem.prev" "$APP/$MEM"; echo "   membership-hostlogs did not apply cleanly - kept the previous file"; }
  elif core_upgrade "$MEM" membership-hostlogs; then :
  else echo "   membership-hostlogs skipped: the installed $MEM was changed on this server (not a version the platform shipped) - kept as it is; send this line to Claude"; fi
fi

# security hardening of two core files (Oct 2026 review), same rule as above: applied only when it fits exactly, never blocks
#   membership-admin-role  the SIEM is told the caller's real role; an operator's retire flags the asset, it does not pause
#                          its log collection
#   http-roles             the role table has no prototype ("constructor" / "__proto__" are not roles)
#   routes-viewer-roles / discovery-roles  every read route says who may call it (ctx.need('viewer')): no change in who may
#                          read; the contract test's list of older routes without a declared role is empty
#   http-access-gate       access gates before every portal route: an engineer job role may call only its own routes
#                          (engine/access-scopes.js, enforced by engine/roles.js); without it the boundary is the browser only
#   findings-python        the built-in AI findings rules run in Python (pyengine/asset_rules.py, step 6b); Node.js answers
#                          when Python is missing or fails
#   assets-python          the asset read routes (/assets, /assets/:id, /lookup, /software, /licences, /cmdb) answered by
#                          Python reading the store, read-only (engine/assets-py.js + pyengine/assets_read.py, step 8c)
#   audit-verify           the audit hash-chain check (GET /audit) on a worker thread: same speed, no longer blocks the engine
#   assets-write           add / edit / retire... / move / assign an asset decided in Python and committed by the engine
#                          (engine/assets-write.js + pyengine/assets_write.py, step 9d); assets.engine = "node" turns it off
#   core-writes            licences, stocktake, AI finding accept / dismiss, CMDB links decided in Python too (engine/py-writer.js
#                          + pyengine/core_write.py, step 9e); writes.engine = "node" turns it off
#   ai-guard-jobs / -main  the AI masking (before a model call) and answer check also run in Python and are compared with
#                          Node.js on every call (engine/ai/guard-py.js + pyengine/ai_guard.py, step 9j-a); ai.guard_engine = "node"
#   discovery-hostip-*     ESXi host IP from vCenter's own record of the host's management VMkernel port (read-only
#                          SOAP, allow-listed calls only) instead of DNS alone - the platform server may not resolve the names
for spec in "membership-admin-role engine/monitoring-membership.js" "http-roles engine/http.js" "http-access-gate engine/http.js" "findings-python engine/findings.js" "assets-python engine/routes.js" "audit-verify engine/routes.js" "assets-write engine/routes.js" "core-writes engine/routes.js" "routes-viewer-roles engine/routes.js" "ai-guard-jobs engine/ai/jobs.js" "ai-guard-main engine/main.js" "discovery-hostip-vcenter engine/discovery/methods/vcenter.js" "discovery-hostip-runner engine/discovery/runner.js"; do
  set -- $spec; PN="$1"; PF="$2"; PP="$HERE/patches/$PN.patch"
  [ -f "$APP/$PF" ] && [ -f "$PP" ] || continue
  sed 's/\r$//' "$PP" > "$TMPD/$PN.patch"
  if patch -p1 -R --dry-run -s -f -d "$APP" < "$TMPD/$PN.patch" >/dev/null 2>&1; then say "$PN: already installed"
  elif patch -p1 --dry-run -s -f -d "$APP" < "$TMPD/$PN.patch" >/dev/null 2>&1; then
    mkdir -p "$BK"; chmod 700 "$BK"; [ -f "$BK/$(basename "$PF").pre-$PN" ] || cp -p "$APP/$PF" "$BK/$(basename "$PF").pre-$PN"; cp -p "$APP/$PF" "$TMPD/$PN.prev"
    patch -p1 -f -s --no-backup-if-mismatch -d "$APP" < "$TMPD/$PN.patch" && "$NODE" --check "$APP/$PF" && say "applied $PN" || { cp -p "$TMPD/$PN.prev" "$APP/$PF"; echo "   $PN did not apply cleanly - kept the previous file"; }
  elif core_upgrade "$PF" "$PN"; then :
  else echo "   $PN skipped: the installed $PF was changed on this server (not a version the platform shipped) - kept as it is; send this line to Claude"; fi
done

# the SIEM link passes the analyst role (a fix no discovery patch carried - HTTP 403 on the SIEM evidence routes)
[ -f "$HERE/fix-siem-role.sh" ] && APP="$APP" NODE="${NODE:-}" bash "$HERE/fix-siem-role.sh"

# newest patch already in the engine (checked newest first: later patches change lines next to earlier ones)
LIST=($PATCHES); START=0
for ((i=${#LIST[@]}-1; i>=0; i--)); do
  if patch -p1 -R --dry-run -s -f -d "$APP" < "$TMPD/${LIST[$i]}.patch" >/dev/null 2>&1; then START=$((i+1)); break; fi
done
for ((i=0; i<START; i++)); do say "${LIST[$i]}: already installed"; done
[ "$START" -lt "${#LIST[@]}" ] || { say "discovery engine is up to date"; itam_restart_if_changed "$PRE_FP"; exit 0; }
say "backup -> $BK"
mkdir -p "$BK"; chmod 700 "$BK"
for f in $FILES; do b="$BK/$(basename "$f")"; [ -f "$b" ] || cp -p "$APP/$f" "$b"; cp -p "$APP/$f" "$b.last"; done   # first-ever copy kept for --rollback
restore() { itam_on_restore "$1"; echo "!! $1 - restoring the previous files"; for f in $FILES; do cp -p "$BK/$(basename "$f").last" "$APP/$f"; done; itam_restart || true; echo "   $SVC: $(systemctl is-active "$SVC")"; exit 1; }

APPLIED=""
for ((i=START; i<${#LIST[@]}; i++)); do
  p="${LIST[$i]}"
  if [ "$p" = "discovery-nutanix" ] && [ ! -f "$APP/$NTX" ]; then
    [ -n "$APPLIED" ] && restore "$NTX is missing"; die "$NTX is missing - copy the whole sentra-itam folder"
  fi
  if [ "$p" = "discovery-logins" ] && [ ! -f "$APP/$LOGIN_JS" ]; then
    [ -n "$APPLIED" ] && restore "$LOGIN_JS is missing"; die "$LOGIN_JS is missing - copy the whole sentra-itam folder"
  fi
  if [ "$p" = "discovery-python" ] && [ ! -f "$APP/engine/discovery/py-methods.js" ]; then
    [ -n "$APPLIED" ] && restore "engine/discovery/py-methods.js is missing"; die "engine/discovery/py-methods.js is missing - copy the whole sentra-itam folder"
  fi
  if ! OUT="$(patch -p1 --dry-run -f -d "$APP" < "$TMPD/$p.patch" 2>&1)"; then
    echo "$OUT" | sed 's/^/   /' | head -n 12
    [ -n "$APPLIED" ] || die "the installed discovery engine differs from the expected version ($p) - nothing was changed. Send this output."
    restore "$p does not fit the installed engine"
  fi
  patch -p1 -f -s --no-backup-if-mismatch -d "$APP" < "$TMPD/$p.patch" || restore "$p failed"
  APPLIED="$APPLIED $p"; say "applied $p"
done
for f in $FILES; do chown root:root "$APP/$f"; chmod 644 "$APP/$f"; "$NODE" --check "$APP/$f" || restore "syntax check failed ($f)"; done
itam_restart_if_changed "$PRE_FP"
systemctl is-active --quiet "$SVC" || { journalctl -u "$SVC" -n 20 --no-pager | tail -n 20; restore "$SVC did not start"; }
say "discovery updated:$APPLIED"
case "$APPLIED" in *discovery-catchup*) echo "   engine brought up to date (credential safety, shared SIEM link, Virtualization sealer, untrusted agent reports)";; esac
case "$APPLIED" in *discovery-python*) echo "   vCenter / ESXi / Nutanix / Azure / AWS / CUCM inventory is read by Python (discovery.engine = \"node\" switches back)";; esac
case "$APPLIED" in *discovery-ip-mac*) echo "   AD / vCenter names resolved through the domain controllers, IPs outside the scanned ranges kept, MACs from SNMP ARP tables";; esac
case "$APPLIED" in *discovery-model*) echo "   switch models and serials read on big Cisco stacks (run the switch scope again to fill them in)";; esac
case "$APPLIED" in *discovery-speed*) echo "   faster scans (ports + SNMP probed in parallel) and live progress on the Asset Discovery page";; esac
case "$APPLIED" in *discovery-services*) echo "   new scope methods: Database listeners, Solaris / Unix servers, Storage arrays and NAS (tick them in a scope; active = pre-scan checklist)";; esac
case "$APPLIED" in *discovery-hostlogs*) echo "   SIEM status per server from its own logs: servers sending through a shared agent / syslog source show Receiving (via that source)";; esac
case "$APPLIED" in *discovery-logins*) echo "   scope logins: Asset Discovery > Credentials > Add (Database login / SSH login / Storage API login), choose them in the scope, run it, then trust the waiting keys under Credentials > Trust and run again";; esac
case "$APPLIED" in *discovery-solaris*) echo "   Oracle Solaris servers recognised (run the scope covering them again)";; esac
case "$APPLIED" in *discovery-nutanix*) echo "   Nutanix Prism: Asset Discovery > Credentials > Add (Nutanix Prism), then tick Nutanix Prism in a scope's methods";; esac
echo "   undo: sudo bash $0 --rollback"
