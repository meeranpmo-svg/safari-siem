#!/bin/bash
# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
# harden-web.sh - the web layer of the corporate hardening (the server layer - SSH, TLS, firewall, kernel - is
# harden-server.sh in sentra-siem/install). Default is a REPORT: nothing changes, and the nginx change it would make is
# printed as a diff. Every change is backed up, tested (nginx -t, service health) and rolled back on failure.
#
#   sudo bash harden-web.sh                          report + the nginx diff it would apply
#   sudo bash harden-web.sh --apply                  nginx: security headers, Content-Security-Policy (dashboards
#                                                    enforced, portal report-only), cross-site POST check in LOG mode,
#                                                    long caching of versioned files, pre-compressed files, timing log;
#                                                    systemd: extra sandboxing for sentra-siem / sentra-itam (health-checked)
#   sudo bash harden-web.sh --apply --enforce-origin      also REFUSE (403) a POST/PUT/PATCH/DELETE from another site
#        [--allow-origin https://login.example.com]       ... except these origins (single sign-on that posts back)
#   sudo bash harden-web.sh --apply --portal-csp enforce  enforce the portal's policy too (after reading the reports)
#   sudo bash harden-web.sh --egress report          log every outbound connection the services make to the internet
#   sudo bash harden-web.sh --egress enforce [--egress-allow 20.190.128.0/18 ...]
#                                                    block them except the allow list - reverts by itself in 10 minutes
#   sudo bash harden-web.sh --egress confirm         keep the enforced egress rules (also after a reboot)
#   sudo bash harden-web.sh --egress-report          which internet addresses each service tried to reach (7 days)
#   sudo bash harden-web.sh --remove                 undo everything this script added
#   options: --no-systemd  --no-restart (drop-ins take effect at the next restart, not health-checked)
#
# Choices (--enforce-origin, --allow-origin, --portal-csp) are remembered in /etc/nginx/zyb-web.env, so a later
# --apply (for example after install-dashboards.sh) keeps them. Re-run --apply after each dashboards install: the
# dashboards' policy is enforced only while the installed build says it is safe (.zyb-static.json "csp":"strict").
set -uo pipefail
# the portal's host name is a setting, never text in this script: ZYB_PORTAL_HOST, else /etc/sentra/portal-host, else the
# brand setting this package was built with (vendor/zyb-org.js, written by tools/brand/apply-brand.js)
ZYB_HOST="${ZYB_PORTAL_HOST:-$(cat /etc/sentra/portal-host 2>/dev/null || true)}"
for _b in "$(cd "$(dirname "$0")" && pwd)/vendor/zyb-org.js" /var/www/sentra/dashboards/vendor/zyb-org.js; do
  [ -n "$ZYB_HOST" ] || ZYB_HOST="$(sed -n 's/.*"portal_host": *"\([^"]*\)".*/\1/p' "$_b" 2>/dev/null | head -n1)"
done
case "$ZYB_HOST" in ''|*[!a-z0-9.-]*) echo "the portal host name is not set - run: echo soc.example.com | sudo tee /etc/sentra/portal-host"; exit 1;; esac
ZYB_HOST_RE="$(printf '%s' "$ZYB_HOST" | sed 's/\./\\./g')"
ETC="${ZYB_ETC:-/etc/nginx}"; DEST="${ZYB_DEST:-/var/www/sentra/dashboards}"; NGX="${ZYB_NGINX:-nginx}"
BK="${ZYB_BACKUP:-/var/backups/zyb-web}"; STAMP=$(date +%Y%m%d-%H%M%S); ENVF="$ETC/zyb-web.env"
SERVICES="${ZYB_SERVICES:-sentra-siem sentra-itam}"; DROPIN=60-zyb-web-harden.conf
[ "${ZYB_TEST:-0}" = 1 ] || [ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
say() { echo "==> $*"; }; note() { echo "    $*"; }; warn() { echo "!!  $*"; }
ng() { $NGX "$@"; }
ng_reload() { if [ -n "${ZYB_RELOAD:-}" ]; then eval "$ZYB_RELOAD"; else systemctl reload nginx; fi; }

APPLY=0; REMOVE=0; SYSD=1; RESTART=1; EGRESS=""; EGREPORT=0; EGALLOW=(); NEW_ALLOW=(); SET_ENF=""; SET_PCSP=""
ENFORCE_ORIGIN=0; PORTAL_CSP=report; ALLOW_ORIGINS=""
[ -f "$ENVF" ] && . "$ENVF"
while [ $# -gt 0 ]; do case "$1" in
  --apply) APPLY=1;; --remove) REMOVE=1;; --no-systemd) SYSD=0;; --no-restart) RESTART=0;;
  --enforce-origin) SET_ENF=1;; --log-origin) SET_ENF=0;;
  --allow-origin) NEW_ALLOW+=("${2:-}"); shift;;
  --portal-csp) SET_PCSP="${2:-}"; shift;;
  --egress) EGRESS="${2:-}"; shift;; --egress-allow) EGALLOW+=("${2:-}"); shift;; --egress-report) EGREPORT=1;;
  *) echo "unknown option $1 (see the top of this file)"; exit 1;;
esac; shift; done
[ -n "$SET_ENF" ] && ENFORCE_ORIGIN=$SET_ENF
case "$SET_PCSP" in "") ;; report|enforce) PORTAL_CSP=$SET_PCSP;; *) echo "--portal-csp report|enforce"; exit 1;; esac
for o in "${NEW_ALLOW[@]}"; do
  [[ "$o" =~ ^https://[A-Za-z0-9.-]+(:[0-9]+)?$ ]] || { echo "--allow-origin takes https://host[:port] only (got '$o')"; exit 1; }
  case " $ALLOW_ORIGINS " in *" $o "*) ;; *) ALLOW_ORIGINS="${ALLOW_ORIGINS:+$ALLOW_ORIGINS }$o";; esac
done
mkdir -p "$BK"; chmod 700 "$BK"

# ---------------------------------------------------------------- facts
SITE="${ZYB_SITE:-}"
[ -n "$SITE" ] || SITE="$(ng -T 2>/dev/null | awk '/^# configuration file /{f=$4; sub(/:$/,"",f)} /server_name[^;]*'"$ZYB_HOST_RE"'/{print f; exit}')"
[ -n "$SITE" ] && SITE="$(readlink -f "$SITE")"
NGV="$(ng -v 2>&1 | sed -n 's|.*nginx/\([0-9.]*\).*|\1|p')"
GZS=0; ng -V 2>&1 | grep -q http_gzip_static_module && GZS=1
CONFD=0; ng -T 2>/dev/null | grep -qE "^\s*include\s+$ETC/conf\.d/\*\.conf" && CONFD=1
TOKENS=0; ng -T 2>/dev/null | grep -v 'ZYB-WEB' | grep -qE '^\s*server_tokens\s' && TOKENS=1
MANIFEST="$DEST/.zyb-static.json"; DCSP=relaxed; DBUILD="(none)"
if [ -f "$MANIFEST" ]; then grep -q '"csp": *"strict"' "$MANIFEST" && DCSP=strict; DBUILD="$(sed -n 's/.*"build": *"\([^"]*\)".*/\1/p' "$MANIFEST")"; fi
vge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n1)" = "$2" ]; }   # version $1 >= $2

POLICY="default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self'; frame-src 'self'; worker-src 'self'; frame-ancestors 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; report-uri /csp-report"
PORTAL_HDR=Content-Security-Policy-Report-Only; [ "$PORTAL_CSP" = enforce ] && PORTAL_HDR=Content-Security-Policy
DASH_HDR=Content-Security-Policy-Report-Only; [ "$DCSP" = strict ] && DASH_HDR=Content-Security-Policy

# ---------------------------------------------------------------- the nginx site transform (python3, one marked line per change)
transform() { # transform <apply|remove> <in> <out>
  MODE="$1" ENF="$ENFORCE_ORIGIN" GZS="$GZS" HOSTRE="$ZYB_HOST_RE" python3 - "$2" "$3" <<'PY'
import os, re, sys
mode, src, dst = os.environ['MODE'], sys.argv[1], sys.argv[2]
lines = open(src).read().split('\n')
M = '# ZYB-WEB'
NOCACHE = '        add_header Cache-Control "no-cache" always;  # ZYB-NOCACHE: browsers re-check (ETag) so updates show without Ctrl+F5'
CACHE_RX = re.compile(r'ZYB-WEBCACHE')
# 1. back to the unhardened file: every line this script wrote ends in "# ZYB-WEB"; the cache line is restored
out = []
INL = ' include snippets/zyb-security-headers.conf; include snippets/zyb-web-headers.conf;'
for l in lines:
    if l.rstrip().endswith(M): continue
    if CACHE_RX.search(l): out.append(NOCACHE); continue
    if l.rstrip().endswith('# ZYB-WEB-INLINE'):
        l = l.replace(INL, '', 1).replace(INL.replace(' include snippets/zyb-security-headers.conf;', ''), '', 1)
        l = re.sub(r'\s*# ZYB-WEB-INLINE$', '', l)
    out.append(l)
lines = out
if mode == 'remove':
    open(dst, 'w').write('\n'.join(lines)); sys.exit(0)

def code(l):  # the line without comments and quoted strings, for brace counting
    l = re.sub(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'', '""', l)
    return l.split('#', 1)[0]
depth, opens = 0, []
blocks = []   # (start, end, depth_inside, header)
stack = []
for i, l in enumerate(lines):
    c = code(l)
    for ch in c:
        if ch == '{':
            stack.append((i, c.strip())); depth += 1
        elif ch == '}':
            if stack:
                s, head = stack.pop(); blocks.append((s, i, depth, head))
            depth -= 1
servers = [b for b in blocks if re.match(r'server\s*\{', b[3])]
ins = {}    # line index -> lines to insert after it
repl = {}
warn = []
def ind(l): return re.match(r'\s*', l).group(0)
def children(s, e, d):  # direct child lines of a block (depth d inside)
    res, dd = [], d
    for j in range(s + 1, e):
        if dd == d: res.append(j)
        for ch in code(lines[j]):
            if ch == '{': dd += 1
            elif ch == '}': dd -= 1
    return res
done = 0
for (s, e, d, head) in servers:
    body = '\n'.join(lines[s:e + 1])
    if not re.search(r'server_name[^;]*' + os.environ['HOSTRE'], body): continue
    kids = children(s, e, d)
    if not any(re.match(r'\s*(listen[^;]*\b(443|ssl)\b|ssl_certificate\s)', lines[j]) for j in kids): continue
    sn = next((j for j in kids if re.match(r'\s*server_name\s', lines[j])), None)
    if sn is None: continue
    pad = ind(lines[sn])
    add = []
    if not any('zyb-security-headers.conf' in lines[j] for j in kids):
        add.append(pad + 'include snippets/zyb-security-headers.conf;  # ZYB-SECHEADERS')
    add.append(pad + 'include snippets/zyb-web-headers.conf;  ' + M)
    if not any(re.match(r'\s*access_log\s', lines[j]) for j in kids):
        add.append(pad + 'access_log /var/log/nginx/access.log;  ' + M)   # an access_log here would otherwise replace the default one
    add.append(pad + 'access_log /var/log/nginx/sentra-timing.log zyb_timing;  ' + M)
    add.append(pad + 'access_log /var/log/nginx/zyb-xorigin.log zyb_timing if=$zyb_xorigin;  ' + M)
    if os.environ.get('ENF') == '1':
        add.append(pad + 'if ($zyb_xorigin) { return 403; }  ' + M)
    add.append(pad + 'location = /csp-report { limit_req zone=zyb_csp burst=20 nodelay; client_max_body_size 16k; client_body_buffer_size 16k; access_log /var/log/nginx/csp-report.log zyb_csp; proxy_pass http://127.0.0.1:9199; }  ' + M)
    ins.setdefault(sn, []).extend(add)
    # locations that set their own add_header stop inheriting the server's: give them the header snippets too
    for (ls, le, ld, lhead) in blocks:
        if not (s < ls and le < e) or not lhead.startswith('location'): continue
        lk = children(ls, le, ld)
        if ls == le:   # one-line location { ... add_header ...; }: the includes go right after its brace
            l1 = lines[ls]
            if re.search(r'\badd_header\s', code(l1)) and 'csp-report' not in l1 and 'zyb-web-headers' not in l1:
                add1 = INL if 'zyb-security-headers.conf' not in l1 else INL.replace(' include snippets/zyb-security-headers.conf;', '')
                if '#' in l1.split('}')[-1]: warn.append('one-line location with add_header and a comment, not covered: ' + l1.strip()[:90])
                else: repl[ls] = l1.replace('{', '{' + add1, 1).rstrip() + '  # ZYB-WEB-INLINE'
            continue
        if not any(re.match(r'\s*add_header\s', lines[j]) for j in lk): continue
        dash = bool(re.search(r'location\s+/dashboards/\s*\{', lhead))
        p2 = ind(lines[lk[0]]) if lk else pad + '    '
        a2 = []
        if not any('zyb-security-headers.conf' in lines[j] for j in lk):
            a2.append(p2 + 'include snippets/zyb-security-headers.conf;  # ZYB-SECHEADERS')
        a2.append(p2 + 'include snippets/' + ('zyb-dash-headers.conf' if dash else 'zyb-web-headers.conf') + ';  ' + M)
        if dash:
            for j in lk:
                if 'ZYB-NOCACHE' in lines[j]:
                    repl[j] = ind(lines[j]) + 'add_header Cache-Control $zyb_cache always;  # ZYB-NOCACHE ZYB-WEBCACHE: versioned files (?v=build) kept a year, everything else re-checked'
            if os.environ.get('GZS') == '1' and not any(re.match(r'\s*gzip_static\s', lines[j]) for j in lk):
                a2.append(p2 + 'gzip_static on;  ' + M)
        ins.setdefault(ls, []).extend(a2)
    done += 1
if not done:
    sys.stderr.write('no TLS server block with server_name ' + os.environ['HOSTRE'].replace('\\\\', '') + ' found\n'); sys.exit(3)
out = []
for i, l in enumerate(lines):
    out.append(repl.get(i, l))
    out.extend(ins.get(i, []))
open(dst, 'w').write('\n'.join(out))
for w in warn: sys.stderr.write('WARN ' + w + '\n')
PY
}

write_snippets() {
  mkdir -p "$ETC/snippets" "$ETC/conf.d"
  if [ ! -f "$ETC/snippets/zyb-security-headers.conf" ]; then  # same file harden-server.sh writes; created here if that has not run
    cat > "$ETC/snippets/zyb-security-headers.conf" <<'NGX'
# security headers for the portal (harden-server.sh / harden-web.sh). Included wherever a location sets its own
# add_header, because nginx stops inheriting add_header in that case.
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "SAMEORIGIN" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()" always;
add_header Content-Security-Policy "frame-ancestors 'self'; object-src 'none'; base-uri 'self'" always;
add_header Cross-Origin-Opener-Policy "same-origin" always;
add_header Strict-Transport-Security "max-age=31536000" always;
NGX
  fi
  cat > "$ETC/snippets/zyb-web-headers.conf" <<NGX
# harden-web.sh: portal pages and API. The policy is $([ "$PORTAL_HDR" = Content-Security-Policy ] && echo ENFORCED || echo "REPORT-ONLY: the browser runs everything and reports what it would block to /csp-report (log: /var/log/nginx/csp-report.log)").
add_header Cross-Origin-Resource-Policy "same-origin" always;
add_header X-Permitted-Cross-Domain-Policies "none" always;
add_header $PORTAL_HDR "$POLICY" always;
NGX
  cat > "$ETC/snippets/zyb-dash-headers.conf" <<NGX
# harden-web.sh: /dashboards/ (build $DBUILD). $([ "$DASH_HDR" = Content-Security-Policy ] && echo "ENFORCED - the build moved every inline script into files (.zyb-static.json csp=strict)" || echo "REPORT-ONLY - the installed build is not marked csp=strict; re-run install-dashboards.sh then harden-web.sh --apply")
add_header Cross-Origin-Resource-Policy "same-origin" always;
add_header X-Permitted-Cross-Domain-Policies "none" always;
add_header $DASH_HDR "$POLICY" always;
NGX
  {
    echo "# harden-web.sh (http level). Remove with harden-web.sh --remove."
    echo "# 1 = a state-changing request (POST/PUT/PATCH/DELETE) whose Origin is another site. No Origin (agents, curl, old"
    echo "#     browsers) is let through: the login check still applies to it. Allowed extra origins: zyb-web-origins.map"
    echo 'map $request_method $zyb_unsafe { default 1; GET 0; HEAD 0; OPTIONS 0; }'
    echo 'map "$zyb_unsafe|$http_origin|$http_host" $zyb_xorigin {'
    echo '    default 1;'
    echo '    "~^0\|" 0;'
    echo '    "~^1\|\|" 0;'
    echo '    "~^1\|https://([^|]+)\|\1$" 0;'
    echo "    include $ETC/zyb-web-origins.map;"
    echo '}'
    echo '# versioned static files (?v=<build>, written by build-static.js) never change: the browser keeps them a year and'
    echo '# stops asking (no login check, no 304 round trip per file). Pages and anything unversioned are re-checked.'
    echo 'map $uri $zyb_static { default 0; "~*\.(?:js|css|woff2?|png|jpe?g|webp|svg|ico)$" 1; }'
    echo 'map "$zyb_static:$arg_v" $zyb_cache { default "no-cache"; "~^1:.+" "private, max-age=31536000, immutable"; }'
    echo "log_format zyb_timing '\$remote_addr - \$remote_user [\$time_local] \"\$request\" \$status \$body_bytes_sent rt=\$request_time urt=\$upstream_response_time ucs=\$upstream_cache_status gz=\$gzip_ratio xo=\$zyb_xorigin origin=\"\$http_origin\" \"\$http_user_agent\"';"
    echo "log_format zyb_csp escape=json '{\"t\":\"\$time_iso8601\",\"ip\":\"\$remote_addr\",\"ua\":\"\$http_user_agent\",\"report\":\"\$request_body\"}';"
    echo 'limit_req_zone $binary_remote_addr zone=zyb_csp:1m rate=30r/m;'
    echo '# the CSP report sink: answers 204; the report itself is written by the /csp-report location (zyb_csp log)'
    echo 'server { listen 127.0.0.1:9199; access_log off; location / { return 204; } }'
    [ "$TOKENS" = 0 ] && echo 'server_tokens off;'
  } > "$ETC/conf.d/zyb-web.conf"
  { echo "# extra origins allowed to POST to the portal (harden-web.sh --allow-origin), one map line each"
    for o in $ALLOW_ORIGINS; do printf '    "~^1\\|%s\\|" 0;\n' "$(printf '%s' "$o" | sed 's/[.]/\\./g')"; done; } > "$ETC/zyb-web-origins.map"
}

probe() { # HTTP status of the portal home, through nginx on this machine
  local host; host="$(sed -n 's/.*server_name[^;]*\b\('"$ZYB_HOST_RE"'\).*/\1/p' "$SITE" | head -n1)"
  curl -sk --noproxy '*' -o /dev/null -w '%{http_code}' --max-time 8 --resolve "${host:-$ZYB_HOST}:${ZYB_PORT:-443}:127.0.0.1" "https://${host:-$ZYB_HOST}:${ZYB_PORT:-443}${1:-/}" 2>/dev/null || echo 000
}

# ---------------------------------------------------------------- systemd
svc_ports() { local pid; pid="$(systemctl show -p MainPID --value "$1" 2>/dev/null)"; [ -n "$pid" ] && [ "$pid" != 0 ] && ss -Hltnp 2>/dev/null | awk -v p="pid=$pid," 'index($0,p){n=split($4,a,":"); print a[n]}' | sort -un | tr '\n' ' '; }
svc_score() { systemd-analyze security "$1" --no-pager 2>/dev/null | tail -n1 | sed 's/^→ //'; }
dropin_text() { cat <<EOF
# harden-web.sh: sandboxing on top of the unit's own (already strict) settings. Undo: harden-web.sh --remove
# Settings older systemd versions do not know are ignored with a warning, never fatal.
[Service]
# other users' processes are invisible in /proc; no System V IPC shared with anything else
ProtectProc=invisible
RemoveIPC=yes
PrivateIPC=yes
# nothing written to disk by the service can be executed: the data directory and temp dirs are mounted noexec
NoExecPaths=/var/lib/$1 /tmp /var/tmp /dev/shm
KeyringMode=private
# a runaway (fork loop, thread leak) is stopped here instead of taking the server with it
TasksMax=1024
EOF
}
harden_unit() {
  local s="$1" dir="/etc/systemd/system/$1.service.d" before after i ok=0 sb sa
  systemctl cat "$s" >/dev/null 2>&1 || { note "$s: not installed - skipped"; return; }
  sb="$(svc_score "$s")"; before="$(svc_ports "$s")"
  mkdir -p "$dir"; [ -f "$dir/$DROPIN" ] && cp -a "$dir/$DROPIN" "$BK/$s.$DROPIN.$STAMP"
  dropin_text "$s" > "$dir/$DROPIN"; systemctl daemon-reload
  if [ "$RESTART" = 0 ]; then note "$s: drop-in written, takes effect at the next restart (not health-checked)"; return; fi
  systemctl restart "$s"
  for i in $(seq 1 30); do sleep 1
    systemctl is-active -q "$s" || continue
    after="$(svc_ports "$s")"; ok=1; for p in $before; do case " $after " in *" $p "*) ;; *) ok=0;; esac; done
    [ "$ok" = 1 ] && break
  done
  if [ "$ok" = 1 ] && sleep 5 && systemctl is-active -q "$s"; then
    sa="$(svc_score "$s")"; say "$s: sandbox tightened, running, listening on ${after:-(no TCP ports)}  exposure: ${sb:-?} -> ${sa:-?}"
  else
    rm -f "$dir/$DROPIN"; systemctl daemon-reload; systemctl restart "$s"
    warn "$s did not come back healthy with the drop-in - removed it and restarted the service as it was"
    journalctl -u "$s" -n 15 --no-pager 2>/dev/null | sed 's/^/    /'
  fi
}

# ---------------------------------------------------------------- egress (nftables, per service user)
EGF=/etc/zyb/egress.nft; EGU=/etc/systemd/system/zyb-egress.service
egress_rules() { # egress_rules <report|enforce>
  local uids="" u ns4="" ns6="" al4="" al6="" a
  for s in $SERVICES; do u="$(id -u "$s" 2>/dev/null)" && uids="${uids:+$uids, }$u"; done
  [ -n "$uids" ] || { echo "no service users ($SERVICES) on this machine" >&2; return 1; }
  for a in $(awk '/^nameserver/{print $2}' /etc/resolv.conf 2>/dev/null); do case "$a" in *:*) ns6="$ns6, $a";; *) ns4="$ns4, $a";; esac; done
  for a in "${EGALLOW[@]}"; do case "$a" in *:*) al6="$al6, $a";; *) al4="$al4, $a";; esac; done
  cat <<EOF
# harden-web.sh egress ($1): outbound connections opened by the platform services ($SERVICES). Internal networks are
# always allowed (the services poll devices there); anything else is logged as "zyb-egress"$([ "$1" = enforce ] && echo " and refused").
table inet zyb_egress
delete table inet zyb_egress
table inet zyb_egress {
  set allow4 { type ipv4_addr; flags interval; elements = { 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16$al4 } }
  set allow6 { type ipv6_addr; flags interval; elements = { ::1/128, fc00::/7, fe80::/10$al6 } }
  # the resolvers in /etc/resolv.conf, for name lookups only
  set dns4 { type ipv4_addr; flags interval; elements = { 127.0.0.0/8$ns4 } }
  set dns6 { type ipv6_addr; flags interval; elements = { ::1/128$ns6 } }
  chain out {
    type filter hook output priority 0; policy accept;
    meta skuid != { $uids } accept
    ct state established,related accept
    oifname "lo" accept
    ip daddr @allow4 accept
    ip6 daddr @allow6 accept
    ip daddr @dns4 meta l4proto { tcp, udp } th dport 53 accept
    ip6 daddr @dns6 meta l4proto { tcp, udp } th dport 53 accept
    limit rate 20/minute log prefix "zyb-egress " flags skuid
$([ "$1" = enforce ] && echo "    reject with icmpx type admin-prohibited")
  }
}
EOF
}
egress() {
  command -v nft >/dev/null || { warn "nft (nftables) is not installed - egress control skipped"; return 1; }
  mkdir -p /etc/zyb
  case "$1" in
    report|enforce)
      egress_rules "$1" > "$EGF.new" || return 1
      nft -c -f "$EGF.new" || { warn "nft rejected the rules - nothing changed"; rm -f "$EGF.new"; return 1; }
      mv "$EGF.new" "$EGF"; nft -f "$EGF"
      cat > "$EGU" <<EOF
[Unit]
Description=Sentra egress rules for the platform services (harden-web.sh)
After=network-pre.target
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/nft -f $EGF
ExecStop=/usr/sbin/nft delete table inet zyb_egress
[Install]
WantedBy=multi-user.target
EOF
      systemctl daemon-reload
      if [ "$1" = report ]; then systemctl enable -q zyb-egress.service; say "egress: REPORT mode - nothing blocked; see harden-web.sh --egress-report in a few days"
      else
        systemctl disable -q zyb-egress.service 2>/dev/null   # a reboot during the trial comes back without the block
        systemctl stop zyb-egress-revert.timer 2>/dev/null
        systemd-run -q --unit zyb-egress-revert --on-active=10min /usr/sbin/nft delete table inet zyb_egress
        say "egress: ENFORCED for a 10-minute trial - check the portal, the SIEM and the integrations now."
        note "keep it: sudo bash harden-web.sh --egress confirm      (otherwise it removes itself at $(date -d '+10 min' +%H:%M))"
      fi;;
    confirm)
      grep -q 'reject with' "$EGF" 2>/dev/null || { warn "no enforced egress rules to confirm (run --egress enforce first)"; return 1; }
      systemctl stop zyb-egress-revert.timer 2>/dev/null; nft list table inet zyb_egress >/dev/null 2>&1 || nft -f "$EGF"
      systemctl enable -q zyb-egress.service; say "egress: enforced rules kept, also after a reboot";;
    off) systemctl stop zyb-egress-revert.timer 2>/dev/null; systemctl disable -q zyb-egress.service 2>/dev/null; nft delete table inet zyb_egress 2>/dev/null; rm -f "$EGU" "$EGF"; systemctl daemon-reload; say "egress rules removed";;
    *) echo "--egress report|enforce|confirm|off"; return 1;;
  esac
}
egress_report() {
  say "outbound connections to the internet by the platform services (last 7 days, from the kernel log)"
  local uid name
  journalctl -k --since -7d --no-pager 2>/dev/null | grep 'zyb-egress ' | sed -n 's/.*DST=\([^ ]*\).*DPT=\([0-9]*\).*UID=\([0-9]*\).*/\3 \1:\2/p' | sort | uniq -c | sort -rn | head -60 |
    while read -r n uid dst; do name="$(getent passwd "$uid" | cut -d: -f1)"; printf '    %-10s %-28s %6s attempts\n' "${name:-$uid}" "$dst" "$n"; done
  note "each address a service needs goes into the allow list: --egress enforce --egress-allow <address/prefix> ..."
  note "Microsoft 365 / Azure addresses change; publish them through the corporate proxy where possible."
}

# ---------------------------------------------------------------- run
if [ "$EGREPORT" = 1 ]; then egress_report; exit 0; fi
if [ -n "$EGRESS" ]; then egress "$EGRESS"; exit $?; fi

if [ "$REMOVE" = 1 ]; then
  if [ -n "$SITE" ] && grep -qE '# ZYB-WEB$|ZYB-WEBCACHE|# ZYB-WEB-INLINE$' "$SITE"; then
    cp -a "$SITE" "$BK/$(basename "$SITE").$STAMP"; transform remove "$SITE" "$SITE.zybweb" && cat "$SITE.zybweb" > "$SITE"; rm -f "$SITE.zybweb"
  fi
  rm -f "$ETC/conf.d/zyb-web.conf" "$ETC/snippets/zyb-web-headers.conf" "$ETC/snippets/zyb-dash-headers.conf" "$ETC/zyb-web-origins.map" "$ENVF"
  if ng -t 2>/dev/null; then ng_reload; say "nginx: web hardening removed (the shared security-header snippet of harden-server.sh is kept)"
  else ng -t; [ -n "$SITE" ] && cp -a "$BK/$(basename "$SITE").$STAMP" "$SITE"; warn "nginx test failed after removal - restored the site file; fix the error above"; fi
  if [ "${ZYB_TEST:-0}" != 1 ]; then
    for s in $SERVICES; do f="/etc/systemd/system/$s.service.d/$DROPIN"; [ -f "$f" ] && { rm -f "$f"; R=1; }; done
    [ "${R:-0}" = 1 ] && { systemctl daemon-reload; for s in $SERVICES; do systemctl try-restart "$s"; done; say "systemd drop-ins removed, services restarted"; }
    command -v nft >/dev/null && nft list table inet zyb_egress >/dev/null 2>&1 && egress off
  fi
  exit 0
fi

echo "################ REPORT ($(hostname)) ################"
say "nginx ${NGV:-?}  ·  portal site: ${SITE:-NOT FOUND}"
note "pre-compressed files (gzip_static): $([ $GZS = 1 ] && echo available || echo 'module not built in - pages compressed per request instead')"
if [ -n "$NGV" ] && vge "$NGV" 1.25.1; then note "HTTP/2: add 'http2 on;' in the portal server block if it is not there"
elif [ -n "$SITE" ] && grep -qE 'listen[^;]*443[^;]*http2' "$SITE"; then note "HTTP/2: on"
else note "HTTP/2: off - 'listen 443 ssl http2;' (nginx ${NGV:-?}) loads the ~60 page files in parallel; not changed by this script because it applies to every site on port 443"; fi
note "conf.d included at http level: $([ $CONFD = 1 ] && echo yes || echo 'NO - the http-level settings cannot be added (nothing will change)')"
[ -n "$SITE" ] && note "headers: $(grep -q 'zyb-security-headers' "$SITE" && echo 'security headers in place' || echo 'security headers missing')$(grep -q '# ZYB-WEB$' "$SITE" && echo ', web hardening in place' || echo ', web hardening not applied')"
say "dashboards build ${DBUILD}: Content-Security-Policy $([ "$DCSP" = strict ] && echo "can be ENFORCED (no inline script left)" || echo "report-only (build not marked strict - run install-dashboards.sh)")"
[ -f "$MANIFEST" ] && ! grep -q '"issues": \[\]' "$MANIFEST" && sed -n '/"issues"/,/]/p' "$MANIFEST" | sed 's/^/    /' | head -12
say "choices: cross-site POST = $([ "$ENFORCE_ORIGIN" = 1 ] && echo REFUSED || echo 'logged only (/var/log/nginx/zyb-xorigin.log)')  ·  portal CSP = $PORTAL_CSP  ·  extra origins = ${ALLOW_ORIGINS:-none}"
[ -f /var/log/nginx/zyb-xorigin.log ] && note "cross-site requests logged so far: $(wc -l < /var/log/nginx/zyb-xorigin.log) (review before --enforce-origin)"
[ -f /var/log/nginx/csp-report.log ] && note "CSP reports so far: $(wc -l < /var/log/nginx/csp-report.log) (review before --portal-csp enforce)"
if [ "${ZYB_TEST:-0}" != 1 ] && [ "$SYSD" = 1 ]; then
  say "systemd services"
  for s in $SERVICES; do systemctl cat "$s" >/dev/null 2>&1 || { note "$s: not installed"; continue; }
    note "$s: $(systemctl is-active "$s")  exposure $(svc_score "$s")  drop-in: $([ -f /etc/systemd/system/$s.service.d/$DROPIN ] && echo in place || echo not applied)"; done
  say "egress: $(nft list table inet zyb_egress 2>/dev/null | grep -q 'reject' && echo ENFORCED || { nft list table inet zyb_egress >/dev/null 2>&1 && echo 'report mode' || echo 'not configured'; })"
fi
[ -n "$SITE" ] || { warn "no nginx site with server_name $ZYB_HOST - nothing to do"; exit 1; }
command -v python3 >/dev/null || { warn "python3 is needed to edit the nginx file safely - install it (apt install python3)"; exit 1; }
[ "$CONFD" = 1 ] || { warn "conf.d is not included in nginx.conf's http block - stopping"; exit 1; }

TMP="$(mktemp)"; trap 'rm -f "$TMP"' EXIT
transform apply "$SITE" "$TMP" || { warn "could not work out the portal server block - nothing changed"; exit 1; }
if [ "$APPLY" = 0 ]; then
  echo; say "the change --apply would make to $SITE:"; diff -u "$SITE" "$TMP" | sed 's/^/    /' | head -80
  echo; say "report only - nothing changed. Re-run with --apply."; exit 0
fi

echo; echo "################ APPLY ################"
BEFORE="$(probe /)"
SAVE="$BK/$STAMP"; mkdir -p "$SAVE"; cp -a "$SITE" "$SAVE/site.conf"
for f in conf.d/zyb-web.conf snippets/zyb-web-headers.conf snippets/zyb-dash-headers.conf snippets/zyb-security-headers.conf zyb-web-origins.map zyb-web.env; do [ -f "$ETC/$f" ] && { mkdir -p "$SAVE/$(dirname "$f")"; cp -a "$ETC/$f" "$SAVE/$f"; }; done
HAD_SEC=0; [ -f "$ETC/snippets/zyb-security-headers.conf" ] && HAD_SEC=1
rollback() {
  cp -a "$SAVE/site.conf" "$SITE"
  for f in conf.d/zyb-web.conf snippets/zyb-web-headers.conf snippets/zyb-dash-headers.conf zyb-web-origins.map zyb-web.env; do if [ -f "$SAVE/$f" ]; then cp -a "$SAVE/$f" "$ETC/$f"; else rm -f "$ETC/$f"; fi; done
  [ "$HAD_SEC" = 0 ] && rm -f "$ETC/snippets/zyb-security-headers.conf"
  ng -t 2>/dev/null && ng_reload; warn "$1 - the previous nginx configuration was restored"; exit 1
}
write_snippets
cat "$TMP" > "$SITE"
ng -t 2>&1 | grep -v 'syntax is ok\|test is successful' | sed 's/^/    /'
ng -t 2>/dev/null || rollback "nginx -t failed"
ng_reload || rollback "nginx reload failed"
sleep 1; AFTER="$(probe /)"
case "$BEFORE" in 2*|3*|401) case "$AFTER" in 2*|3*|401) ;; *) rollback "the portal answered $BEFORE before and $AFTER after the change";; esac;; esac
printf 'ENFORCE_ORIGIN=%s\nPORTAL_CSP=%s\nALLOW_ORIGINS="%s"\n' "$ENFORCE_ORIGIN" "$PORTAL_CSP" "$ALLOW_ORIGINS" > "$ENVF"
say "nginx: hardened and reloaded (portal answered $BEFORE before, $AFTER after)"
note "dashboards CSP: $([ "$DASH_HDR" = Content-Security-Policy ] && echo enforced || echo report-only)  ·  portal CSP: $PORTAL_CSP  ·  cross-site POST: $([ "$ENFORCE_ORIGIN" = 1 ] && echo refused || echo logged)"
note "versioned files cached a year$([ $GZS = 1 ] && echo ', pre-compressed files served')  ·  timing log: /var/log/nginx/sentra-timing.log (rt= request time, urt= backend time)"
note "backup: $SAVE  ·  undo: sudo bash harden-web.sh --remove"

if [ "$SYSD" = 1 ] && [ "${ZYB_TEST:-0}" != 1 ]; then
  echo; say "systemd: extra sandboxing, one service at a time, each health-checked"
  for s in $SERVICES; do harden_unit "$s"; done
fi
echo; say "next: read /var/log/nginx/csp-report.log and zyb-xorigin.log for a week, then --portal-csp enforce and --enforce-origin;"
note "egress: sudo bash harden-web.sh --egress report  (then --egress-report, then --egress enforce)"
