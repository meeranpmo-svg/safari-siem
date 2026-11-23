#!/usr/bin/env python3
# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
"""Read-only inventory logins for Asset Discovery (engine/discovery/methods/login.js).

One JSON request on stdin, one JSON answer on stdout. Credentials only ever arrive on stdin (never argv / env).
  {"op":"version"}                                   which libraries are installed
  {"op":"hostkey","host","port"}                     SSH host key WITHOUT logging in (nothing secret is sent)
  {"op":"ssh_facts","host","port","username","password"|"private_key","fp"}
        logs in ONLY if the server's key matches the trusted fingerprint `fp`, then runs the FIXED command list below.
  {"op":"db","engine":"oracle|mssql|mysql|postgres","host","port","username","password","service"?,"database"?}
        logs in and runs the FIXED read-only queries below (version, edition, instance, database names).
  {"op":"oracle_health","host","port","username","password","service"?}
  {"op":"ssh_services","host","port","username","password"|"private_key","fp"}   processes / listening ports / services (read only)
        logs in to Oracle and runs the FIXED read-only health queries (ORACLE_HEALTH below) for the AI Oracle DBA:
        instance, tablespaces, sessions, blocked sessions, redo/archive, last RMAN job, Data Guard lag, invalid objects,
        recovery area. Same record kinds as the Oracle collector agent (agents/oracle in the SIEM); a query the account may
        not run (no privilege) is skipped and named in "errors" - nothing is guessed.
Nothing here accepts a command or a query from the caller: the lists are constants.
"""
import hashlib
import json
import socket
import sys

TIMEOUT = 15
MAX_OUT = 4000

# fixed, read-only commands (each one alone; failures are normal on the "other" OS and are just empty)
SSH_COMMANDS = [
    ("uname", "uname -a"),
    ("hostname", "hostname"),
    ("release", "head -1 /etc/release 2>/dev/null"),
    ("os_release", "cat /etc/os-release 2>/dev/null"),
    ("platform", "uname -i 2>/dev/null"),
    # distinct physical ids = sockets (grep -c counted one line per logical CPU, so a 2 x 16-core host read as 64 sockets)
    ("sockets", "/usr/sbin/psrinfo -p 2>/dev/null || grep '^physical id' /proc/cpuinfo 2>/dev/null | sort -u | wc -l"),
    ("cores", "grep -m1 '^cpu cores' /proc/cpuinfo 2>/dev/null; /usr/sbin/psrinfo -pv 2>/dev/null | grep -m1 -i 'cores'"),
    ("cpus", "/usr/sbin/psrinfo 2>/dev/null | wc -l; nproc 2>/dev/null"),
    ("memory", "/usr/sbin/prtconf 2>/dev/null | grep -i 'memory size'; grep -i '^MemTotal' /proc/meminfo 2>/dev/null"),
    ("smbios", "/usr/sbin/smbios -t SMB_TYPE_SYSTEM 2>/dev/null | head -20"),
    ("dmi", "cat /sys/class/dmi/id/sys_vendor /sys/class/dmi/id/product_name /sys/class/dmi/id/product_serial 2>/dev/null"),
]

DB_QUERIES = {
    "oracle": [
        ("version", "select banner from v$version where rownum = 1"),
        ("instance", "select instance_name || '|' || host_name || '|' || version from v$instance"),
        ("databases", "select name from v$database"),
    ],
    "mssql": [
        ("version", "select @@version"),
        ("instance", "select cast(serverproperty('MachineName') as varchar(200)) + '|' + isnull(cast(serverproperty('InstanceName') as varchar(200)),'MSSQLSERVER') + '|' + cast(serverproperty('ProductVersion') as varchar(50)) + '|' + cast(serverproperty('Edition') as varchar(200))"),
        ("databases", "select name from sys.databases"),
    ],
    "mysql": [
        ("version", "select concat(version(), ' ', @@version_comment)"),
        ("instance", "select concat(@@hostname, '|', @@port)"),
        ("databases", "show databases"),
    ],
    "postgres": [
        ("version", "select version()"),
        ("instance", "select coalesce(inet_server_addr()::text,'') || '|' || current_setting('server_version')"),
        ("databases", "select datname from pg_database where not datistemplate"),
    ],
}


def out(o):
    sys.stdout.write(json.dumps(o))
    sys.stdout.flush()


def err(kind, msg):
    return {"ok": False, "error_class": kind, "error": str(msg)[:300]}


def classify(e):
    s = (type(e).__name__ + " " + str(e)).lower()
    # the host name does not resolve on this server. python-oracledb wraps EVERY network failure in DPY-6005, so this is
    # tested first - "[Errno -3] Temporary failure in name resolution" used to be reported as a TLS problem
    if "name resolution" in s or "name or service not known" in s or "nodename nor servname" in s or "getaddrinfo" in s \
            or "eai_again" in s or "errno -2]" in s or "errno -3]" in s or "errno 11001" in s:
        return "dns"
    # ORA-28000 account locked, ORA-28001 password expired, ORA-01045 no CREATE SESSION: a login problem, never retried on its own
    if "authentication" in s or "password" in s or "login failed" in s or "access denied" in s or "ora-01017" in s or "28p01" in s or "1045" in s \
            or "ora-28000" in s or "account is locked" in s or "ora-28001" in s:
        return "auth"
    if "needs the ca file" in s or "unknown tls mode" in s:
        return "config"
    # the listener answered but does not know the service / SID that was typed
    if "ora-12514" in s or "ora-12505" in s or "dpy-6001" in s or "dpy-6003" in s:
        return "service"
    # the listener knows the service but will not hand out a session right now (instance starting / restricted, no
    # dispatcher, PROCESSES or SESSIONS reached): temporary on the database side, retried on the next pass
    if "ora-12528" in s or "ora-12526" in s or "ora-12516" in s or "ora-12518" in s or "ora-12519" in s or "ora-12520" in s or "ora-00020" in s or "ora-00018" in s:
        return "busy"
    if "timed out" in s or "timeout" in s:
        return "timeout"
    if "refused" in s or "ora-12541" in s:
        return "refused"
    if "no route" in s or "unreachable" in s:
        return "unreachable"
    # TLS asked for and the server would not, or its certificate did not check out: never fall back to plaintext
    if "certificate" in s or "ssl" in s or "tls" in s or "tcps" in s:
        return "tls"
    if "permission" in s or "insufficient privileges" in s or "ora-00942" in s:
        return "denied"
    return "error"


def fp_of(key):
    return hashlib.sha256(key.asbytes()).hexdigest()


def op_version(_):
    mods = {}
    for m in ("paramiko", "pymysql", "pg8000", "oracledb", "pytds"):
        try:
            mod = __import__(m)
            mods[m] = getattr(mod, "__version__", "yes")
        except Exception:
            mods[m] = None
    return {"ok": True, "python": sys.version.split()[0], "modules": mods}


def transport(host, port):
    import paramiko
    sock = socket.create_connection((host, int(port)), timeout=TIMEOUT)
    t = paramiko.Transport(sock)
    t.banner_timeout = TIMEOUT
    t.start_client(timeout=TIMEOUT)
    return t


def op_hostkey(r):
    try:
        t = transport(r["host"], r.get("port", 22))
        try:
            k = t.get_remote_server_key()
            return {"ok": True, "type": k.get_name(), "fp": fp_of(k)}
        finally:
            t.close()
    except Exception as e:
        return err(classify(e), e)


def op_ssh_facts(r):
    import io
    import paramiko
    want = str(r.get("fp") or "").lower()
    if len(want) != 64:
        return err("hostkey_untrusted", "no trusted host key for this server")
    try:
        t = transport(r["host"], r.get("port", 22))
    except Exception as e:
        return err(classify(e), e)
    try:
        k = t.get_remote_server_key()
        got = fp_of(k)
        if got != want:   # checked BEFORE any credential is sent
            return {"ok": False, "error_class": "hostkey_changed", "error": "the server's SSH host key changed - not logging in", "fp": got, "type": k.get_name()}
        try:
            if r.get("private_key"):
                pk = None
                for cls in (paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.RSAKey):
                    try:
                        pk = cls.from_private_key(io.StringIO(r["private_key"]), password=r.get("password") or None)
                        break
                    except Exception:
                        continue
                if pk is None:
                    return err("config", "the private key could not be read")
                t.auth_publickey(r["username"], pk)
            else:
                t.auth_password(r["username"], r.get("password") or "")
        except Exception as e:
            return err("auth" if "auth" in str(e).lower() or isinstance(e, paramiko.AuthenticationException) else classify(e), e)
        facts = {}
        for name, cmd in SSH_COMMANDS:
            try:
                ch = t.open_session(timeout=TIMEOUT)
                ch.settimeout(TIMEOUT)
                ch.exec_command(cmd)
                buf = b""
                while len(buf) < MAX_OUT:
                    d = ch.recv(4096)
                    if not d:
                        break
                    buf += d
                ch.close()
                facts[name] = buf[:MAX_OUT].decode("utf-8", "replace").strip()
            except Exception:
                facts[name] = ""
        return {"ok": True, "facts": facts}
    finally:
        t.close()


# database SERVER health (Databases -> Database Servers): fixed read-only commands, same trust rule as ssh_facts (the host key
# must match the fingerprint an administrator trusted, checked before the password is sent). Each command alone; a command
# missing on this OS is just empty.
SSH_HEALTH = [
    ("os", "uname -srm; grep -E '^(PRETTY_NAME|VERSION_ID)=' /etc/os-release 2>/dev/null; head -1 /etc/release 2>/dev/null"),
    ("uptime_s", "cat /proc/uptime 2>/dev/null"),
    ("uptime", "uptime"),
    ("load", "cat /proc/loadavg 2>/dev/null"),
    ("ncpu", "nproc 2>/dev/null || /usr/sbin/psrinfo 2>/dev/null | wc -l"),
    ("mem", "grep -E '^(MemTotal|MemAvailable|MemFree|SwapTotal|SwapFree|HugePages_Total|HugePages_Free|HugePages_Rsvd|Hugepagesize):' /proc/meminfo 2>/dev/null"),
    ("thp", "cat /sys/kernel/mm/transparent_hugepage/enabled 2>/dev/null"),
    # Solaris /usr/bin/df has no -P: the XPG4 one does, and plain df -k has the same six columns
    ("df", "df -Pk -x tmpfs -x devtmpfs -x squashfs -x overlay 2>/dev/null || df -Pk 2>/dev/null || /usr/xpg4/bin/df -Pk 2>/dev/null || df -k 2>/dev/null"),
    ("dfi", "df -Pi -x tmpfs -x devtmpfs -x squashfs -x overlay 2>/dev/null"),
    ("oracle", "ps -eo user,args 2>/dev/null | grep -E '[o]ra_pmon_|[a]sm_pmon_|[t]nslsnr|[o]ra_mrp0_|[o]hasd|[c]rsd.bin' | head -60"),
    ("oratab", "cat /etc/oratab /var/opt/oracle/oratab 2>/dev/null | grep -v '^#' | grep ':' | head -40"),
    ("ntp", "(chronyc tracking 2>/dev/null | head -14); (timedatectl show -p NTPSynchronized --value 2>/dev/null); (ntpq -pn 2>/dev/null | head -10)"),
    ("patch", "rpm -qa --last 2>/dev/null | head -1"),
    ("top", "ps -eo pcpu,pmem,user,comm --sort=-pcpu 2>/dev/null | head -6"),
    # services that failed: systemd units (Linux) and SMF services in maintenance / degraded (Solaris; "offline" is usually
    # a service waiting on a dependency, so it is not listed)
    ("svc_failed", "systemctl --failed --no-legend --plain 2>/dev/null | head -20; /usr/bin/svcs -H -o state,fmri 2>/dev/null | grep -E '^(maintenance|degraded)' | head -20"),
    # Solaris has no /proc/meminfo: memory size, free memory (vmstat, KB), swap and the date of the installed "entire" package
    ("sol_mem", "/usr/sbin/prtconf 2>/dev/null | grep -i 'memory size'; /usr/bin/vmstat 1 2 2>/dev/null | tail -1"),
    ("sol_swap", "/usr/sbin/swap -s 2>/dev/null"),
    ("sol_patch", "/usr/bin/pkg info entire 2>/dev/null | grep -iE 'packaging date|version'"),
    # baseline hardening (CIS Oracle Linux / Solaris, judged in pyengine/hardening_rules.py): READ-ONLY reads of settings,
    # no sudo. A file the login may not read (sshd_config is 0600 on recent releases) is empty -> "not checked", never a pass.
    ("h_sshd", "grep -hEv '^[[:space:]]*(#|$)' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null | head -200"),
    ("h_logindefs", "grep -E '^(PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_MIN_LEN|PASS_WARN_AGE|UMASK|ENCRYPT_METHOD)' /etc/login.defs 2>/dev/null"),
    ("h_pwquality", "grep -hEv '^[[:space:]]*(#|$)' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf 2>/dev/null | head -40"),
    ("h_faillock", "grep -hEv '^[[:space:]]*(#|$)' /etc/security/faillock.conf 2>/dev/null | head -20; grep -h 'pam_faillock' /etc/pam.d/system-auth /etc/pam.d/password-auth 2>/dev/null | head -4"),
    ("h_sysctl", "sysctl net.ipv4.ip_forward net.ipv4.conf.all.accept_redirects net.ipv4.conf.all.send_redirects net.ipv4.conf.all.accept_source_route net.ipv4.tcp_syncookies net.ipv4.conf.all.log_martians kernel.randomize_va_space 2>/dev/null"),
    ("h_selinux", "getenforce 2>/dev/null"),
    ("h_firewall", "systemctl is-active firewalld nftables iptables 2>/dev/null; /usr/sbin/svcs -H -o state svc:/network/ipfilter:default 2>/dev/null | sed 's/^/ipfilter /'"),
    ("h_auditd", "systemctl is-active auditd 2>/dev/null; /usr/sbin/svcs -H -o state svc:/system/auditd:default 2>/dev/null | sed 's/^/auditd /'"),
    ("h_services", "for u in telnet.socket rsh.socket rlogin.socket rexec.socket vsftpd.service tftp.socket xinetd.service avahi-daemon.service cups.service rpcbind.service nfs-server.service snmpd.service; do printf '%s %s\\n' \"$u\" \"$(systemctl is-enabled $u 2>/dev/null)\"; done; /usr/bin/svcs -H -o state,fmri svc:/network/telnet:default svc:/network/ftp:default svc:/network/rpc/bind:default svc:/network/finger:default svc:/network/rlogin:default svc:/network/shell:default 2>/dev/null"),
    ("h_uid0", "awk -F: '($3==0){print $1}' /etc/passwd 2>/dev/null"),
    ("h_perms", "ls -ln /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/ssh/sshd_config 2>/dev/null"),
    ("h_tmp", "findmnt -n -o OPTIONS /tmp 2>/dev/null; mount -p 2>/dev/null | awk '$3==\"/tmp\"'"),
    ("h_rsyslog", "systemctl is-active rsyslog syslog-ng 2>/dev/null; grep -hE '^[^#].*@' /etc/rsyslog.conf /etc/rsyslog.d/*.conf /etc/syslog.conf 2>/dev/null | head -5"),
    ("h_solaris", "grep -E '^(CONSOLE|PASSREQ|SYSLOG|RETRIES)=' /etc/default/login 2>/dev/null; grep -E '^(MAXWEEKS|MINWEEKS|PASSLENGTH|HISTORY|MINDIFF)=' /etc/default/passwd 2>/dev/null; grep -E '^(LOCK_AFTER_RETRIES)=' /etc/security/policy.conf 2>/dev/null; /usr/sbin/routeadm -p 2>/dev/null | grep -E 'forwarding' | head -4"),
    ("h_updates", "if command -v dnf >/dev/null 2>&1; then dnf -q -C updateinfo list --security 2>/dev/null | wc -l; elif command -v yum >/dev/null 2>&1; then yum -q -C updateinfo list security 2>/dev/null | wc -l; else echo na; fi"),
]


def _kv_kb(text):
    o = {}
    for line in str(text or "").splitlines():
        k, _, v = line.partition(":")
        p = v.split()
        if p:
            try:
                o[k.strip()] = int(p[0])
            except ValueError:
                pass
    return o


def _df(text):
    out = []
    for line in str(text or "").splitlines()[1:]:
        p = line.split()
        if len(p) < 6 or not p[1].isdigit():
            continue
        try:
            pct = int(p[4].rstrip("%")) if p[4].rstrip("%").isdigit() else None
            out.append({"fs": p[0][:120], "size_kb": int(p[1]), "used_kb": int(p[2]), "avail_kb": int(p[3]), "used_pct": pct, "mount": " ".join(p[5:])[:200]})
        except ValueError:
            continue
    return out


def _patch_date(text):
    """'kernel-5.14.0 Tue 15 Oct 2024 02:01:02 PM +03' -> '2024-10-15'; None when unreadable"""
    import datetime
    t = str(text or "")
    m = _re.search(r"(\d{1,2}) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\w* (\d{4})", t)
    if m:
        d, mon, y = m.group(1), m.group(2), m.group(3)
    else:
        # Solaris pkg: "August 24, 2023 at 06:42:52 PM" or "Tue Jan 16 10:22:11 2024"
        m = _re.search(r"(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\w*\s+(\d{1,2}),?\s+(?:[\d:]+\s+)?(\d{4})", t)
        if not m:
            return None
        mon, d, y = m.group(1), m.group(2), m.group(3)
    try:
        return datetime.datetime.strptime(d + " " + mon + " " + y, "%d %b %Y").date().isoformat()
    except ValueError:
        return None


def parse_ssh_health(f):
    """raw command output -> the server reading (pure; unit-tested). A value a command did not give is None, never 0."""
    f = f or {}
    o = {"os": None, "kernel": None, "uptime_s": None, "load1": None, "load5": None, "load15": None, "ncpu": None,
         "mem_total_mb": None, "mem_avail_mb": None, "swap_total_mb": None, "swap_used_mb": None, "hugepages_total": None, "hugepages_free": None,
         "thp": None, "filesystems": [], "inodes": [], "oracle": {"pmon": [], "asm": [], "listeners": [], "mrp": False, "clusterware": False},
         "oratab": [], "ntp_synced": None, "ntp_offset_ms": None, "last_patch": None, "top": []}
    osr = str(f.get("os") or "")
    pretty = _re.search(r'PRETTY_NAME="?([^"\n]+)', osr)
    first = osr.splitlines()[0].strip() if osr.strip() else ""
    o["kernel"] = first[:120] or None
    rel = [l.strip() for l in osr.splitlines()[1:] if l.strip() and not l.startswith(("PRETTY_NAME", "VERSION_ID"))]
    o["os"] = (pretty.group(1) if pretty else (rel[0] if rel else first))[:120] or None
    try:
        o["uptime_s"] = int(float(str(f.get("uptime_s") or "").split()[0]))
    except Exception:
        m = _re.search(r"up\s+(\d+)\s+day", str(f.get("uptime") or ""))
        o["uptime_s"] = int(m.group(1)) * 86400 if m else None
    la = str(f.get("load") or "").split()
    if len(la) >= 3:
        o["load1"], o["load5"], o["load15"] = (_num(la[0]), _num(la[1]), _num(la[2]))
    else:
        m = _re.search(r"load averages?:\s*([\d.]+),?\s+([\d.]+),?\s+([\d.]+)", str(f.get("uptime") or ""))
        if m:
            o["load1"], o["load5"], o["load15"] = (_num(m.group(1)), _num(m.group(2)), _num(m.group(3)))
    nc = [l.strip() for l in str(f.get("ncpu") or "").splitlines() if l.strip().isdigit()]
    o["ncpu"] = int(nc[0]) if nc else None
    mem = _kv_kb(f.get("mem"))
    mb = lambda k: round(mem[k] / 1024) if k in mem else None
    o["mem_total_mb"], o["mem_avail_mb"] = mb("MemTotal"), mb("MemAvailable") if "MemAvailable" in mem else mb("MemFree")
    o["swap_total_mb"] = mb("SwapTotal")
    if "SwapTotal" in mem and "SwapFree" in mem:
        o["swap_used_mb"] = round((mem["SwapTotal"] - mem["SwapFree"]) / 1024)
    o["hugepages_total"], o["hugepages_free"] = mem.get("HugePages_Total"), mem.get("HugePages_Free")
    t = _re.search(r"\[(\w+)\]", str(f.get("thp") or ""))
    o["thp"] = t.group(1) if t else None
    o["filesystems"] = _df(f.get("df"))[:60]
    o["inodes"] = [{"mount": x["mount"], "used_pct": x["used_pct"]} for x in _df(f.get("dfi")) if x["used_pct"] is not None][:60]
    ora = str(f.get("oracle") or "")
    o["oracle"]["pmon"] = sorted(set(_re.findall(r"ora_pmon_(\S+)", ora)))[:20]
    o["oracle"]["asm"] = sorted(set(_re.findall(r"asm_pmon_(\S+)", ora)))[:5]
    o["oracle"]["listeners"] = sorted(set(m for m in _re.findall(r"tnslsnr\s+(\S+)", ora)))[:10]
    o["oracle"]["mrp"] = "ora_mrp0_" in ora
    o["oracle"]["clusterware"] = "ohasd" in ora or "crsd.bin" in ora
    for line in str(f.get("oratab") or "").splitlines():
        p = line.strip().split(":")
        if len(p) >= 3 and p[0] and p[0] != "*":
            o["oratab"].append({"sid": p[0][:30], "home": p[1][:200], "autostart": p[2][:1].upper() == "Y"})
    ntp = str(f.get("ntp") or "")
    if _re.search(r"Leap status\s*:\s*Normal", ntp) or _re.search(r"^\s*yes\s*$", ntp, _re.M) or _re.search(r"^\*", ntp, _re.M):
        o["ntp_synced"] = True
    elif _re.search(r"Leap status\s*:\s*Not synchronised", ntp) or _re.search(r"^\s*no\s*$", ntp, _re.M):
        o["ntp_synced"] = False
    off = _re.search(r"System time\s*:\s*([\d.]+) seconds (fast|slow)", ntp)
    if off:
        o["ntp_offset_ms"] = round(float(off.group(1)) * 1000, 3)
    o["last_patch"] = _patch_date(f.get("patch"))
    # Solaris: what /proc did not give
    sm = str(f.get("sol_mem") or "")
    if o["mem_total_mb"] is None:
        m = _re.search(r"Memory size:\s*(\d+)\s*(Megabytes|Gigabytes)", sm, _re.I)
        if m:
            o["mem_total_mb"] = int(m.group(1)) * (1024 if m.group(2).lower().startswith("g") else 1)
            vm = [l for l in sm.splitlines() if _re.match(r"^\s*\d", l)]
            p = vm[-1].split() if vm else []
            if len(p) > 4 and p[4].isdigit():
                o["mem_avail_mb"] = round(int(p[4]) / 1024)
    if o["swap_total_mb"] is None:
        m = _re.search(r"=\s*(\d+)k used,\s*(\d+)k available", str(f.get("sol_swap") or ""))
        if m:
            used, avail = int(m.group(1)), int(m.group(2))
            o["swap_total_mb"], o["swap_used_mb"] = round((used + avail) / 1024), round(used / 1024)
    if o["last_patch"] is None:
        m = _re.search(r"Packaging Date:\s*(.+)", str(f.get("sol_patch") or ""), _re.I)
        if m:
            o["last_patch"] = _patch_date(m.group(1).strip())
    o["failed_services"] = []
    for line in str(f.get("svc_failed") or "").splitlines():
        p = line.split()
        if not p:
            continue
        if p[0] in ("maintenance", "degraded") and len(p) > 1:
            o["failed_services"].append({"name": p[1][:120], "state": p[0]})
        elif p[0].endswith((".service", ".mount", ".socket", ".timer", ".target")) or (len(p) > 2 and p[2] == "failed"):
            o["failed_services"].append({"name": p[0][:120], "state": "failed"})
    o["failed_services"] = o["failed_services"][:20]
    o["harden"] = {k[2:]: str(f.get(k) or "")[:6000] for k in f if k.startswith("h_")}
    for line in str(f.get("top") or "").splitlines()[1:6]:
        p = line.split(None, 3)
        if len(p) == 4:
            o["top"].append({"cpu_pct": _num(p[0]), "mem_pct": _num(p[1]), "user": p[2][:32], "command": p[3][:60]})
    return o


def op_ssh_health(r):
    import paramiko
    want = str(r.get("fp") or "").lower()
    if len(want) != 64:
        return err("hostkey_untrusted", "no trusted host key for this server")
    try:
        t = transport(r["host"], r.get("port", 22))
    except Exception as e:
        return err(classify(e), e)
    try:
        k = t.get_remote_server_key()
        if fp_of(k) != want:   # checked BEFORE any credential is sent
            return {"ok": False, "error_class": "hostkey_changed", "error": "the server's SSH host key changed - not logging in", "fp": fp_of(k)}
        try:
            if r.get("private_key"):
                import io
                pk = None
                for cls in (paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.RSAKey):
                    try:
                        pk = cls.from_private_key(io.StringIO(r["private_key"]), password=r.get("password") or None)
                        break
                    except Exception:
                        continue
                if pk is None:
                    return err("config", "the private key could not be read")
                t.auth_publickey(r["username"], pk)
            else:
                t.auth_password(r["username"], r.get("password") or "")
        except Exception as e:
            return err("auth" if "auth" in str(e).lower() or isinstance(e, paramiko.AuthenticationException) else classify(e), e)
        raw = {}
        for name, cmd in SSH_HEALTH:
            try:
                ch = t.open_session(timeout=TIMEOUT)
                ch.settimeout(TIMEOUT)
                ch.exec_command(cmd)
                buf = b""
                while len(buf) < 16000:
                    d = ch.recv(4096)
                    if not d:
                        break
                    buf += d
                ch.close()
                raw[name] = buf[:16000].decode("utf-8", "replace")
            except Exception:
                raw[name] = ""
        return {"ok": True, "server": parse_ssh_health(raw)}
    finally:
        t.close()


def db_tls_context(r):
    """None for tls "off"; else a TLS 1.2+ context. "verify" checks the server certificate (ca_file or system CAs) and
    host name; "require" encrypts but does not check the certificate (no identity check - reported as such)."""
    mode = r.get("tls") or "off"
    if mode == "off":
        return None
    if mode not in ("require", "verify"):
        raise ValueError("unknown tls mode")
    import ssl
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    if mode == "verify":
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.check_hostname = True
        if r.get("ca_file"):
            ctx.load_verify_locations(cafile=r["ca_file"])
        else:
            ctx.load_default_certs()
    else:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def connect_db(r):
    eng, host, port, user, pw = r["engine"], r["host"], int(r["port"]), r["username"], r.get("password") or ""
    ctx = db_tls_context(r)
    if eng == "mysql":
        import pymysql
        if not ctx:
            return pymysql.connect(host=host, port=port, user=user, password=pw, connect_timeout=TIMEOUT, read_timeout=TIMEOUT)
        from pymysql.constants import CLIENT

        class StrictTLS(pymysql.connections.Connection):
            # older PyMySQL carried on in plaintext when the server did not offer TLS: refuse before any login packet
            def _request_authentication(self):
                if not (self.server_capabilities & CLIENT.SSL):
                    raise pymysql.err.OperationalError(2026, "TLS required but the server does not offer it")
                return super()._request_authentication()
        return StrictTLS(host=host, port=port, user=user, password=pw, connect_timeout=TIMEOUT, read_timeout=TIMEOUT, ssl=ctx)
    if eng == "postgres":
        import pg8000.dbapi
        kw = {"ssl_context": ctx} if ctx else {}
        return pg8000.dbapi.connect(host=host, port=port, user=user, password=pw, database=r.get("database") or "postgres", timeout=TIMEOUT, **kw)
    if eng == "oracle":
        import oracledb
        svc = r.get("service") or "ORCL"
        if not ctx:
            return oracledb.connect(user=user, password=pw, dsn=oracledb.makedsn(host, port, service_name=svc), tcp_connect_timeout=TIMEOUT)
        # TCPS (the listener's TLS port, usually 2484); the password never crosses the wire unencrypted
        kw = {"user": user, "password": pw, "host": host, "port": port, "service_name": svc, "protocol": "tcps",
              "tcp_connect_timeout": TIMEOUT, "ssl_server_dn_match": r.get("tls") == "verify", "ssl_context": ctx}
        try:
            return oracledb.connect(**kw)
        except TypeError:   # python-oracledb without ssl_context: TCPS still on; CA from the wallet / system store
            kw.pop("ssl_context")
            return oracledb.connect(**kw)
    if eng == "mssql":
        import pytds
        if not ctx:
            return pytds.connect(server=host, port=port, user=user, password=pw, database=r.get("database") or "master", timeout=TIMEOUT, login_timeout=TIMEOUT)
        # pytds turns TLS on only with a CA file: the whole session (not just the login) is encrypted
        if not r.get("ca_file"):
            raise ValueError("SQL Server TLS needs the CA file of the server certificate (target.ca_file)")
        return pytds.connect(server=host, port=port, user=user, password=pw, database=r.get("database") or "master", timeout=TIMEOUT, login_timeout=TIMEOUT,
                             cafile=r["ca_file"], validate_host=r.get("tls") == "verify", enc_login_only=False)
    raise ValueError("unknown engine")


def op_db(r):
    eng = r.get("engine")
    if eng not in DB_QUERIES:
        return err("config", "unknown database engine")
    lib = {"mysql": "pymysql", "postgres": "pg8000", "oracle": "oracledb", "mssql": "pytds"}[eng]
    try:
        __import__(lib)
    except Exception:
        return err("missing_module", lib + " is not installed on the platform server (run install/netops-cli-setup.sh in the SIEM)")
    try:
        conn = connect_db(r)
    except Exception as e:
        return err(classify(e), e)
    res = {"ok": True, "engine": eng}
    try:
        cur = conn.cursor()
        try:   # belt and braces: the queries are fixed SELECTs, the session is read-only where the engine supports it
            if eng == "postgres":
                cur.execute("set session characteristics as transaction read only")
            elif eng == "mysql":
                cur.execute("set session transaction read only")
        except Exception:
            pass
        for name, q in DB_QUERIES[eng]:
            try:
                cur.execute(q)
                rows = cur.fetchall()
                if name == "databases":
                    res[name] = [str(x[0])[:128] for x in rows[:200]]
                else:
                    res[name] = str(rows[0][0])[:500] if rows else ""
            except Exception as e:
                res[name + "_error"] = classify(e)
                try:
                    conn.rollback()
                except Exception:
                    pass
        return res
    finally:
        try:
            conn.close()
        except Exception:
            pass


# Oracle: the only system privileges a monitoring account may hold. Anything else (DBA, ALTER SYSTEM, any CREATE/ALTER/DROP/
# INSERT/UPDATE/DELETE ... ANY, SELECT ANY TABLE - which reads business data) and the platform refuses to use the account:
# it logs straight out without running a single health query. SELECT_CATALOG_ROLE gives object grants, not system privileges.
ORACLE_SAFE_PRIVS = {"CREATE SESSION", "SELECT ANY DICTIONARY", "SET CONTAINER"}
ORACLE_CALL_TIMEOUT_MS = 10000   # every query is cut off by the server-side call timeout - a slow view never keeps a session busy
ORACLE_HEAVY = ("backup", "invalid_objects", "alert_errors")   # dictionary / alert-log scans: once an hour, not every pass (the engine sends heavy=false)

# fixed, read-only Oracle health queries (plain columns, 11g+; no json_object so older releases work too)
ORACLE_HEALTH = {
    "instance": "select i.instance_name, i.host_name, i.version, i.status, i.database_status, d.open_mode, d.database_role, "
                "d.log_mode, d.name, d.db_unique_name, round((sysdate - i.startup_time) * 86400), "
                "to_char(i.startup_time, 'YYYY-MM-DD\"T\"HH24:MI:SS'), i.archiver, i.logins, "
                "(select banner from v$version where banner like 'Oracle%' and rownum = 1) from v$instance i, v$database d",
    "tablespace": "select m.tablespace_name, round(m.used_space * t.block_size / 1048576), round(m.tablespace_size * t.block_size / 1048576), "
                  "round(m.used_percent, 1), t.contents, t.status from dba_tablespace_usage_metrics m "
                  "join dba_tablespaces t on t.tablespace_name = m.tablespace_name",
    # the SESSIONS parameter comes from its own query block: a scalar subquery beside the aggregates was refused by 19c with
    # ORA-00937 (not a single-group group function) - a query error of ours, never a missing grant
    "sessions": "select s.n, s.active, s.blocked, s.usr, p.value from (select count(*) n, sum(case when status = 'ACTIVE' then 1 else 0 end) active, "
                "sum(case when blocking_session is not null then 1 else 0 end) blocked, sum(case when type = 'USER' then 1 else 0 end) usr from v$session) s "
                "left join (select value from v$parameter where name = 'sessions') p on 1 = 1",
    "blocked": "select s.sid, s.serial#, s.username, s.blocking_session, (select b.username from v$session b where b.sid = s.blocking_session and rownum = 1), "
               "s.seconds_in_wait, s.event, s.sql_id, s.program, s.machine from v$session s where s.blocking_session is not null and rownum <= 20",
    "redo": "select (select log_mode from v$database), (select count(*) from v$log where archived = 'NO' and status <> 'CURRENT'), "
            "(select round((sysdate - max(next_time)) * 86400) from v$archived_log where dest_id = 1), "
            "(select count(*) from v$log_history where first_time > sysdate - 1/24), "
            "(select max(status) from v$archive_dest where dest_id = 1), (select substr(max(error), 1, 200) from v$archive_dest where dest_id = 1) from dual",
    "backup": "select * from (select status, input_type, to_char(start_time, 'YYYY-MM-DD\"T\"HH24:MI:SS'), to_char(end_time, 'YYYY-MM-DD\"T\"HH24:MI:SS'), "
              "round((sysdate - nvl(end_time, start_time)) * 24, 1), round(output_bytes / 1048576), round(elapsed_seconds) "
              "from v$rman_backup_job_details order by start_time desc) where rownum = 1",
    "dataguard": "select name, value from v$dataguard_stats where name in ('apply lag', 'transport lag')",
    "invalid_objects": "select count(*) from dba_objects where status = 'INVALID'",
    "fra": "select name, round(space_limit / 1048576), round(space_used / 1048576), round(space_reclaimable / 1048576), number_of_files from v$recovery_file_dest",
    # ASM disk groups seen from the database instance (_stat: no disk discovery, cheap); usable_file_mb = free space after redundancy
    "asm": "select name, state, type, total_mb, free_mb, usable_file_mb, offline_disks, required_mirror_free_mb from v$asm_diskgroup_stat",
    # archive logs generated in the last 24 h (local destination), and every archive destination in use with its state / error
    "archive_gen": "select count(*), round(sum(blocks * block_size) / 1048576), round((sysdate - max(completion_time)) * 86400) from v$archived_log "
                   "where dest_id = 1 and completion_time > sysdate - 1",
    "archive_dest": "select dest_id, dest_name, status, target, substr(destination, 1, 200), substr(error, 1, 200), binding from v$archive_dest "
                    "where status <> 'INACTIVE' and destination is not null",
    # Data Guard standby: missing archive logs (a gap) and the managed recovery process (no MRP = the standby is not applying)
    "archive_gap": "select count(*), min(low_sequence#), max(high_sequence#) from v$archive_gap",
    "mrp": "select process, status, sequence# from v$managed_standby where process like 'MRP%'",
    # ORA- lines of the last 65 minutes of the alert log (hourly, like the other scans: V$DIAG_ALERT_EXT reads the log file)
    "alert_errors": "select * from (select to_char(sys_extract_utc(originating_timestamp), 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'), substr(message_text, 1, 300) "
                    "from v$diag_alert_ext where originating_timestamp > systimestamp - interval '65' minute "
                    # ORA- errors, plus the network-error blocks (TNS-12535 / 12170 timeouts, the client address) that name the client whose
                    # connection dropped - the evidence that separates a network problem from a database one
                    "and (message_text like '%ORA-%' or message_text like '%TNS-%' or message_text like '%Fatal NI connect error%' or message_text like '%Client address:%') "
                    "order by originating_timestamp desc) where rownum <= 200",
}


ORACLE_ALERT_24H = ("select * from (select to_char(sys_extract_utc(originating_timestamp), 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'), substr(message_text, 1, 300) "
                    "from v$diag_alert_ext where originating_timestamp > systimestamp - interval '26' hour and message_text like '%ORA-%' "
                    "order by originating_timestamp desc) where rownum <= 2000")


# Oracle PERFORMANCE (licence-free V$ metric views only - no ASH / AWR, which need the Diagnostics Pack). Same records
# and field names as the SIEM's Oracle collector (sentra-siem agents/oracle/collect-perf.sql → engine/db-audit/oracle-perf.js),
# so a database added in Connections & Setup fills the Database Performance page and the AI Oracle DBA like an agent would.
ORACLE_SYSMETRIC = {   # V$SYSMETRIC group 2 (60-second interval) metric → (record, field, divisor)
    "Average Active Sessions": ("load_profile", "aas", 1), "Database Time Per Sec": ("load_profile", "db_time_s", 100),
    "CPU Usage Per Sec": ("load_profile", "db_cpu_s", 100), "Background CPU Usage Per Sec": ("load_profile", "bg_cpu_s", 100),
    "Executions Per Sec": ("load_profile", "executions_s", 1), "User Calls Per Sec": ("load_profile", "user_calls_s", 1),
    "User Transaction Per Sec": ("load_profile", "transactions_s", 1), "User Commits Per Sec": ("load_profile", "commits_s", 1),
    "User Rollbacks Per Sec": ("load_profile", "rollbacks_s", 1), "Logical Reads Per Sec": ("load_profile", "logical_reads_s", 1),
    "Physical Reads Per Sec": ("load_profile", "physical_reads_s", 1), "Physical Writes Per Sec": ("load_profile", "physical_writes_s", 1),
    "Physical Read Total Bytes Per Sec": ("load_profile", "physical_read_mb_s", 1048576), "Physical Write Total Bytes Per Sec": ("load_profile", "physical_write_mb_s", 1048576),
    "Redo Generated Per Sec": ("load_profile", "redo_mb_s", 1048576), "Hard Parse Count Per Sec": ("load_profile", "hard_parses_s", 1),
    "Total Parse Count Per Sec": ("load_profile", "parses_s", 1), "Logons Per Sec": ("load_profile", "logons_s", 1),
    "Network Traffic Volume Per Sec": ("load_profile", "network_mb_s", 1048576), "Host CPU Utilization (%)": ("load_profile", "host_cpu_pct", 1),
    "Current OS Load": ("load_profile", "os_load", 1), "Session Count": ("load_profile", "sessions_cur", 1),
    "Buffer Cache Hit Ratio": ("efficiency", "buffer_cache_hit_pct", 1), "Library Cache Hit Ratio": ("efficiency", "library_cache_hit_pct", 1),
    "Soft Parse Ratio": ("efficiency", "soft_parse_pct", 1), "Execute Without Parse Ratio": ("efficiency", "execute_to_parse_pct", 1),
    "Database CPU Time Ratio": ("efficiency", "db_cpu_ratio_pct", 1), "Database Wait Time Ratio": ("efficiency", "db_wait_ratio_pct", 1),
    "PGA Cache Hit %": ("efficiency", "pga_cache_hit_pct", 1),
}
ORACLE_PERF = {
    "sysmetric": "select metric_name, value, intsize_csec, to_char(end_time, 'YYYY-MM-DD\"T\"HH24:MI:SS') from v$sysmetric where group_id = 2",
    "cpu_count": "select value from v$parameter where name = 'cpu_count'",
    "wait_classes": "select n.wait_class, m.time_waited, m.wait_count, m.intsize_csec, m.dbtime_in_wait, m.average_waiter_count "
                    "from v$waitclassmetric m join v$system_wait_class n on n.wait_class_id = m.wait_class_id where n.wait_class <> 'Idle' and m.time_waited > 0",
    # one capture of the active user sessions by wait class (this session excluded) - the licence-free stand-in for ASH
    "active_sessions": "select case when state <> 'WAITING' then 'CPU' else wait_class end, case when state <> 'WAITING' then 'ON CPU' else event end, count(*) "
                       "from v$session where status = 'ACTIVE' and type = 'USER' and (state <> 'WAITING' or wait_class <> 'Idle') and sid <> sys_context('userenv', 'sid') "
                       "group by case when state <> 'WAITING' then 'CPU' else wait_class end, case when state <> 'WAITING' then 'ON CPU' else event end",
    "host": "select stat_name, value from v$osstat where stat_name in ('NUM_CPUS', 'NUM_CPU_CORES', 'LOAD', 'PHYSICAL_MEMORY_BYTES', 'FREE_MEMORY_BYTES')",
}


def oracle_perf_records(rows):
    """rows(name) -> tuples for ORACLE_PERF[name], or None when the query failed; returns the agent-shaped performance
    records. A query that failed gives no record (never a zero): no active sessions is 0, not readable is absent."""
    r2 = lambda v, d=2: None if v is None else round(v, d)
    get = lambda n: rows(n) or []
    recs = []
    cpu = None
    x = get("cpu_count")
    if x:
        cpu = _num(x[0][0])
    lp, ef, interval, end = {}, {}, None, None
    for name, val, ints, et in get("sysmetric"):
        m = ORACLE_SYSMETRIC.get(str(name))
        if not m or _num(val) is None:
            continue
        (lp if m[0] == "load_profile" else ef)[m[1]] = r2(_num(val) / m[2], 3)
        interval, end = _num(ints), et
    if lp:
        lp.update({"kind": "load_profile", "scope": "instance", "cpu_count": cpu, "interval_s": round(interval / 100) if interval else None, "end_time": end})
        recs.append(lp)
    if ef:
        ef["kind"] = "efficiency"
        recs.append(ef)
    for cls, tw, wc, ints, dbt, avgw in get("wait_classes"):
        tw, wc, ints = _num(tw) or 0, _num(wc) or 0, _num(ints) or 0
        recs.append({"kind": "wait_classes", "class": str(cls)[:64], "time_s": r2(tw / max(ints, 1), 4), "waits_s": r2(wc / max(ints / 100.0, 1)),
                     "avg_ms": r2(tw * 10.0 / wc, 3) if wc > 0 else None, "dbtime_pct": r2(_num(dbt)), "avg_waiters": r2(_num(avgw), 3)})
    act = rows("active_sessions")
    if act is not None:
        by, ev, total = {}, {}, 0
        for cls, event, n in act:
            n = int(_num(n) or 0)
            total += n
            k = "aas_" + "".join(ch if ch.isalnum() else "_" for ch in str(cls or "other").lower())
            by[k] = by.get(k, 0) + n
            ev[str(event)] = ev.get(str(event), 0) + n
        rec = {"kind": "active_sessions", "captures": 1, "active_total": total, "aas": total, "cpu_count": cpu,
               "top_event": max(ev, key=ev.get)[:120] if ev else None}
        rec.update(by)
        recs.append(rec)
    hs = {str(k): _num(v) for k, v in get("host")}
    if hs:
        mb = lambda v: None if v is None else round(v / 1048576)
        recs.append({"kind": "host", "num_cpus": hs.get("NUM_CPUS"), "num_cpu_cores": hs.get("NUM_CPU_CORES"), "load": r2(hs.get("LOAD")),
                     "mem_total_mb": mb(hs.get("PHYSICAL_MEMORY_BYTES")), "mem_free_mb": mb(hs.get("FREE_MEMORY_BYTES")), "host_cpu_pct": lp.get("host_cpu_pct")})
    return recs


def _num(v):
    try:
        return None if v is None else float(v)
    except Exception:
        return None


def _interval_s(v):
    """'+00 00:01:05.000' (Data Guard stats) -> 65 seconds; None when empty"""
    try:
        s = str(v or "").strip().lstrip("+")
        if not s:
            return None
        day, _, hms = s.partition(" ")
        h, m, sec = (hms or "0:0:0").split(":")
        return int(day or 0) * 86400 + int(h) * 3600 + int(m) * 60 + int(float(sec))
    except Exception:
        return None


# ---- Oracle tuning readings (oracle-tuning.sql next to this file) ----------------------------------------------------
import os as _os
import re as _re


def load_tuning(path=None):
    """[{name, mode: kit|own|pack|fallback, heavy, sql}] from oracle-tuning.sql; [] when the file is missing"""
    path = path or _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "oracle-tuning.sql")
    try:
        text = open(path, encoding="utf-8").read()
    except Exception:
        return []
    out = []
    for blk in _re.split(r"\n(?=-- @(?:kit|own|pack|fallback) )", "\n" + text):
        m = _re.match(r"\s*-- @(kit|own|pack|fallback) (\w+)", blk)
        if not m:
            continue
        sql = "\n".join(l for l in blk.splitlines() if not l.lstrip().startswith("--")).strip()
        if sql.endswith(";"):
            sql = sql[:-1]
        if sql:
            out.append({"name": m.group(2), "mode": m.group(1), "heavy": "-- @heavy" in blk, "sql": sql})
    return out


_LIT_STR = _re.compile(r"'(?:[^']|'')*'")
_LIT_NUM = _re.compile(r"(?<![A-Za-z_$#:.0-9])\d+(?:\.\d+)?(?![A-Za-z_$#0-9])")


def mask_sql(text):
    """literals out of SQL text before it leaves the platform (PDPL: a WHERE clause can carry an ID number or a name):
    'Ahmed' -> ':s', 1234567890 -> ':n'. Bind variables, names and keywords are kept."""
    if not text:
        return text
    t = _LIT_STR.sub("':s'", str(text))
    return _LIT_NUM.sub(":n", t)


def _version_tuple(v):
    try:
        return tuple(int(x) for x in str(v or "").split(".")[:2])
    except Exception:
        return ()


def tuning_records(cur, heavy, pack, errors):
    """runs oracle-tuning.sql (12.2+): records (sql_text masked) + the raw V$SQLSTATS snapshot for the engine's deltas.
    A failed reading is named in errors (never a zero); a @fallback block runs only when its reading failed."""
    qs = load_tuning()
    has_fb = {q["name"] for q in qs if q["mode"] == "fallback"}
    recs, snap, failed = [], [], set()
    for q in qs:
        if (q["mode"] == "pack" and not pack) or (q["heavy"] and not heavy) or (q["mode"] == "fallback" and q["name"] not in failed):
            continue
        try:
            cur.execute(q["sql"])
            rows = cur.fetchall()
        except Exception as e:
            failed.add(q["name"])
            if q["mode"] == "fallback" or q["name"] not in has_fb:
                ora = _re.search(r"ORA-\d{5}", str(e))   # the code decides the fix: a grant (00942 / 01031) or a query of ours
                errors.append({"query": q["name"], "error": classify(e), "ora": ora.group(0) if ora else ""})
            continue
        for row in rows or []:
            try:   # one JSON document per row; anything else (an unexpected shape) is skipped, never fatal
                doc = row[0] if len(row) == 1 else None
                o = json.loads(doc.read() if hasattr(doc, "read") else doc) if doc is not None else None
            except Exception:
                o = None
            if not isinstance(o, dict):
                continue
            if o.get("sql_text"):
                o["sql_text"] = mask_sql(o["sql_text"])
            (snap if o.get("kind") in ("sqlstats", "delstats") else recs).append(o)   # cumulative counters: the engine sends the deltas
    return recs, snap


ORACLE_PLAN_SQL = "select plan_table_output from table(dbms_xplan.display_cursor(:1, null, 'TYPICAL'))"


def op_oracle_plan(r):
    """the execution plan(s) of one cursor in the shared pool (DBMS_XPLAN.DISPLAY_CURSOR over V$SQL_PLAN - licence-free),
    literals in the predicate section masked"""
    sql_id = str(r.get("sql_id") or "")
    if not _re.fullmatch(r"[0-9a-z]{13}", sql_id):
        return err("config", "sql_id must be the 13-character Oracle SQL_ID")
    try:
        __import__("oracledb")
    except Exception:
        return err("missing_module", "oracledb is not installed on the platform server")
    try:
        conn = connect_db(dict(r, engine="oracle"))
    except Exception as e:
        return err(classify(e), e)
    try:
        try:
            conn.call_timeout = ORACLE_CALL_TIMEOUT_MS
            conn.module = "ZYBERON-MONITOR"
            conn.action = "read-only execution plan"
            conn.client_identifier = "zyberon-itam"
        except Exception:
            pass
        cur = conn.cursor()
        cur.execute("select privilege from session_privs")
        extra = [x for x in sorted({str(y[0]).upper() for y in cur.fetchall()}) if x not in ORACLE_SAFE_PRIVS]
        if extra:
            return err("unsafe", "account holds more than read-only monitoring rights - not used")
        try:
            cur.execute("set transaction read only")
        except Exception:
            pass
        cur.execute(ORACLE_PLAN_SQL, [sql_id])
        lines = [mask_sql(str(x[0] or "")) for x in cur.fetchall()][:600]
        if not lines or any("cannot be found" in l for l in lines[:6]):
            return {"ok": True, "found": False, "lines": lines[:10]}
        return {"ok": True, "found": True, "lines": lines}
    except Exception as e:
        return err(classify(e), e)
    finally:
        try:
            conn.rollback()
        except Exception:
            pass
        try:
            conn.close()
        except Exception:
            pass


# Long-running queries (Databases -> Long-Running Queries), read with the READ-ONLY monitoring login: active user sessions
# whose current call has run at least min_s seconds (not idle waits), plus any session that blocks others (an idle session
# holding locks is the classic cause). RAC: gv$. SQL literals are masked before they leave the platform.
ORACLE_LONG_SQL = (
    "select s.inst_id, s.sid, s.serial#, s.username, s.osuser, s.machine, s.program, s.module, s.sql_id, s.status, s.last_call_et, "
    "to_char(s.sql_exec_start, 'YYYY-MM-DD\"T\"HH24:MI:SS'), s.state, s.wait_class, s.event, s.seconds_in_wait, s.blocking_session, s.blocking_instance, "
    "(select count(*) from gv$session b where b.blocking_session = s.sid and b.blocking_instance = s.inst_id), "
    "(select round(sum(u.blocks) * (select to_number(value) from v$parameter where name = 'db_block_size') / 1048576) from gv$tempseg_usage u where u.inst_id = s.inst_id and u.session_addr = s.saddr), "
    "(select round(max(pr.pga_used_mem) / 1048576) from gv$process pr where pr.inst_id = s.inst_id and pr.addr = s.paddr), "
    "(select dbms_lob.substr(q.sql_fulltext, 500, 1) from gv$sql q where q.inst_id = s.inst_id and q.sql_id = s.sql_id and q.child_number = s.sql_child_number and rownum = 1), "
    "(select max(l.sofar || '|' || l.totalwork || '|' || l.time_remaining || '|' || l.opname) from gv$session_longops l where l.inst_id = s.inst_id and l.sid = s.sid and l.serial# = s.serial# and l.sofar < l.totalwork), "
    "to_char(s.logon_time, 'YYYY-MM-DD\"T\"HH24:MI:SS'), "
    "(select round(st.value / 100) from gv$sesstat st join v$statname sn on sn.statistic# = st.statistic# where st.inst_id = s.inst_id and st.sid = s.sid and sn.name = 'CPU used by this session') "
    "from gv$session s where s.type = 'USER' and s.username is not null "
    "and not (s.inst_id = to_number(sys_context('userenv', 'instance')) and s.sid = to_number(sys_context('userenv', 'sid'))) "
    "and ((s.status = 'ACTIVE' and s.last_call_et >= :1 and (s.state <> 'WAITING' or s.wait_class <> 'Idle')) "
    "  or exists (select 1 from gv$session b where b.blocking_session = s.sid and b.blocking_instance = s.inst_id)) "
    "order by s.last_call_et desc fetch first 100 rows only")


ORACLE_LONG_VIEWS = ["GV$SESSION", "GV$SQL", "GV$TEMPSEG_USAGE", "GV$PROCESS", "GV$SESSION_LONGOPS", "GV$SESSTAT", "V$STATNAME", "V$PARAMETER"]
# the object a GRANT names: GV$TEMPSEG_USAGE is a public synonym for GV$SORT_USAGE (granting on gv_$tempseg_usage is ORA-00942)
ORACLE_GRANT_OBJ = {"GV$TEMPSEG_USAGE": "gv_$sort_usage"}
# TEMP per session is a detail: without it the sessions are still listed (temp_mb null and the page says it was not readable)
ORACLE_LONG_SQL_NOTEMP = ORACLE_LONG_SQL.replace("(select round(sum(u.blocks) * (select to_number(value) from v$parameter where name = 'db_block_size') / 1048576) from gv$tempseg_usage u where u.inst_id = s.inst_id and u.session_addr = s.saddr)", "null")


def op_oracle_long(r):
    try:
        min_s = int(r.get("min_s") or 60)
    except Exception:
        return err("config", "min_s must be a number of seconds")
    if min_s < 5 or min_s > 86400:
        return err("config", "min_s must be 5-86400 seconds")
    try:
        __import__("oracledb")
    except Exception:
        return err("missing_module", "oracledb is not installed on the platform server")
    try:
        conn = connect_db(dict(r, engine="oracle"))
    except Exception as e:
        return err(classify(e), e)
    try:
        try:
            conn.call_timeout = ORACLE_CALL_TIMEOUT_MS
            conn.module = "ZYBERON-MONITOR"
            conn.action = "read-only long-running sessions"
            conn.client_identifier = "zyberon-itam"
        except Exception:
            pass
        cur = conn.cursor()
        cur.execute("select privilege from session_privs")
        extra = [x for x in sorted({str(y[0]).upper() for y in cur.fetchall()}) if x not in ORACLE_SAFE_PRIVS]
        if extra:
            return err("unsafe", "account holds more than read-only monitoring rights - not used")
        try:
            cur.execute("set transaction read only")
        except Exception:
            pass
        notes = []
        try:
            cur.execute(ORACLE_LONG_SQL, [min_s])
        except Exception as e:
            if "ORA-00942" not in str(e) and "ORA-01031" not in str(e):
                raise
            # name the views this account cannot read, with the grants that fix it (ORA-00942 alone says neither)
            missing = []
            for v in ORACLE_LONG_VIEWS:
                try:
                    cur.execute("select 1 from %s where rownum = 0" % v)
                    cur.fetchall()
                except Exception:
                    missing.append(v)
            if not missing:
                raise
            if missing == ["GV$TEMPSEG_USAGE"]:
                cur.execute(ORACLE_LONG_SQL_NOTEMP, [min_s])
                notes.append("TEMP used per session is not readable: as SYSDBA run GRANT SELECT ON sys.gv_$sort_usage TO %s; (or re-run install/oracle-monitor-account.sql)" % str(r.get("username") or "the monitoring user").upper())
                missing = []
            who = str(r.get("username") or "the monitoring user").upper()
            if missing:
                return {"ok": False, "error_class": "grant", "error": "the monitoring account cannot read " + ", ".join(m.lower() for m in missing)
                        + ". As SYSDBA, in the database (the PDB) this login connects to, run: "
                        + " ".join("GRANT SELECT ON sys.%s TO %s;" % (ORACLE_GRANT_OBJ.get(m) or m.lower().replace("$", "_$"), who) for m in missing)
                        + " (or re-run install/oracle-monitor-account.sql)"}
        s = lambda v, n=200: "" if v is None else str(v)[:n]
        out = []
        for x in cur.fetchall():
            lo = None
            if x[22]:
                p = str(x[22]).split("|", 3)
                if len(p) == 4:
                    lo = {"done": _num(p[0]), "total": _num(p[1]), "remaining_s": _num(p[2]), "op": p[3][:80]}
            out.append({"inst_id": _num(x[0]), "sid": _num(x[1]), "serial": _num(x[2]), "username": s(x[3], 128), "osuser": s(x[4], 64), "machine": s(x[5], 120),
                        "program": s(x[6], 80), "module": s(x[7], 80), "sql_id": s(x[8], 13), "status": s(x[9], 12), "elapsed_s": _num(x[10]), "exec_start": s(x[11], 30),
                        "state": s(x[12], 20), "wait_class": s(x[13], 40), "event": s(x[14], 120), "wait_s": _num(x[15]), "blocked_by": _num(x[16]), "blocked_by_inst": _num(x[17]),
                        "blocks": _num(x[18]) or 0, "temp_mb": _num(x[19]), "pga_mb": _num(x[20]), "sql_text": mask_sql(s(x[21], 500)), "longop": lo, "logon": s(x[23], 30),
                        "cpu_s": _num(x[24])})
        return {"ok": True, "min_s": min_s, "sessions": out, "notes": notes}
    except Exception as e:
        return err(classify(e), e)
    finally:
        try:
            conn.rollback()
        except Exception:
            pass
        try:
            conn.close()
        except Exception:
            pass


# Session control (cancel the statement / kill the session) - only AFTER a DBA approver approved it in the platform, and only
# through ZYB_OPS.SESSION_CTL (install/oracle-session-control.sql), which re-checks the session (same user, same SQL_ID, not a
# protected account) inside the database. The control login may hold CREATE SESSION and nothing else (EXECUTE on one procedure
# is an object grant, not a system privilege) - any other privilege and it is not used. op "oracle_ctl_test" checks just that.
ORACLE_CTL_PRIVS = {"CREATE SESSION"}


def _ctl_conn(r):
    conn = connect_db(dict(r, engine="oracle"))
    try:
        conn.call_timeout = 30000
        conn.module = "ZYBERON-CONTROL"
        conn.client_identifier = "zyberon-itam"
    except Exception:
        pass
    cur = conn.cursor()
    cur.execute("select privilege from session_privs")
    extra = [x for x in sorted({str(y[0]).upper() for y in cur.fetchall()}) if x not in ORACLE_CTL_PRIVS]
    cur.execute("select count(*) from all_procedures where owner = 'ZYB_OPS' and object_name = 'SESSION_CTL'")
    has = bool(_num(cur.fetchone()[0]))
    return conn, cur, extra, has


def op_oracle_ctl_test(r):
    try:
        __import__("oracledb")
    except Exception:
        return err("missing_module", "oracledb is not installed on the platform server")
    try:
        conn, cur, extra, has = _ctl_conn(r)
    except Exception as e:
        return err(classify(e), e)
    try:
        if extra:
            return err("unsafe", "the session-control login holds more than CREATE SESSION (" + ", ".join(extra[:8]) + ") - not used. Use the ZYB_CONTROL user from install/oracle-session-control.sql")
        if not has:
            return err("config", "ZYB_OPS.SESSION_CTL is not visible to this login - run install/oracle-session-control.sql as a DBA")
        return {"ok": True}
    finally:
        try:
            conn.close()
        except Exception:
            pass


def op_oracle_ctl(r):
    mode = str(r.get("mode") or "").upper()
    if mode not in ("CANCEL", "KILL"):
        return err("config", "mode must be cancel or kill")
    try:
        inst, sid, serial = int(r.get("inst_id")), int(r.get("sid")), int(r.get("serial"))
    except Exception:
        return err("config", "inst_id, sid and serial must be numbers")
    user, sql_id, ref = str(r.get("target_user") or ""), str(r.get("sql_id") or ""), str(r.get("ref") or "")[:64]
    if not _re.fullmatch(r"[A-Za-z0-9_$#.@-]{1,128}", user):
        return err("config", "the approved user name is not valid")
    if sql_id and not _re.fullmatch(r"[0-9a-z]{13}", sql_id):
        return err("config", "sql_id must be the 13-character Oracle SQL_ID")
    try:
        __import__("oracledb")
    except Exception:
        return err("missing_module", "oracledb is not installed on the platform server")
    try:
        conn, cur, extra, has = _ctl_conn(r)
    except Exception as e:
        return err(classify(e), e)
    try:
        if extra:
            return err("unsafe", "the session-control login holds more than CREATE SESSION - not used")
        if not has:
            return err("config", "ZYB_OPS.SESSION_CTL is not installed - run install/oracle-session-control.sql as a DBA")
        import oracledb
        res = cur.var(oracledb.DB_TYPE_VARCHAR, 400)
        cur.execute("begin zyb_ops.session_ctl(:1, :2, :3, :4, :5, :6, :7, :8); end;", [mode, inst, sid, serial, user, sql_id or None, ref, res])
        return {"ok": True, "result": str(res.getvalue() or "")[:400]}
    except Exception as e:
        return err(classify(e), e)
    finally:
        try:
            conn.close()
        except Exception:
            pass


# Database Audit: new rows of UNIFIED_AUDIT_TRAIL since the engine's cursor (AUDIT_VIEWER role - read only). SQL literals are
# masked before they leave the platform; the monitoring account's own logons / logoffs are left out (they would audit the
# audit). EVENT_TIMESTAMP_UTC (18c+), else EVENT_TIMESTAMP (12.2) - the second is in the session time zone, set to UTC.
AUDIT_COLS = ("dbusername, current_user, os_username, userhost, terminal, client_program_name, action_name, return_code, object_schema, object_name, "
              "dbms_lob.substr(sql_text, 500, 1), unified_audit_policies, system_privilege_used, authentication_type, dbid, sessionid, entry_id, statement_id, audit_type")
AUDIT_NAMES = ["DBUSERNAME", "CURRENT_USER", "OS_USERNAME", "USERHOST", "TERMINAL", "CLIENT_PROGRAM_NAME", "ACTION_NAME", "RETURN_CODE", "OBJECT_SCHEMA", "OBJECT_NAME",
               "SQL_TEXT", "UNIFIED_AUDIT_POLICIES", "SYSTEM_PRIVILEGE_USED", "AUTHENTICATION_TYPE", "DBID", "SESSIONID", "ENTRY_ID", "STATEMENT_ID", "AUDIT_TYPE"]
AUDIT_MAX = 2000
AUDIT_SQL = ("select to_char({ts}, 'YYYY-MM-DD\"T\"HH24:MI:SS.FF6'), " + AUDIT_COLS + " from unified_audit_trail "
             "where {ts} >= to_timestamp(:1, 'YYYY-MM-DD\"T\"HH24:MI:SS.FF6') "
             "and not (dbusername = sys_context('userenv', 'session_user') and action_name in ('LOGON', 'LOGOFF', 'LOGOFF BY CLEANUP') and return_code = 0) "
             "order by {ts} fetch first " + str(AUDIT_MAX) + " rows only")


def op_oracle_audit(r):
    since = str(r.get("since") or "")
    if not _re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d{1,6})?", since):
        return err("config", "since must be an ISO timestamp")
    if "." not in since:
        since += ".000000"
    try:
        __import__("oracledb")
    except Exception:
        return err("missing_module", "oracledb is not installed on the platform server")
    try:
        conn = connect_db(dict(r, engine="oracle"))
    except Exception as e:
        return err(classify(e), e)
    try:
        try:
            conn.call_timeout = 30000
            conn.module = "ZYBERON-MONITOR"
            conn.action = "read-only audit trail"
            conn.client_identifier = "zyberon-itam"
        except Exception:
            pass
        cur = conn.cursor()
        cur.execute("select privilege from session_privs")
        extra = [x for x in sorted({str(y[0]).upper() for y in cur.fetchall()}) if x not in ORACLE_SAFE_PRIVS]
        if extra:
            return err("unsafe", "account holds more than read-only monitoring rights - not used")
        try:
            cur.execute("set transaction read only")
        except Exception:
            pass
        rows, col = None, None
        for c in ("event_timestamp_utc", "event_timestamp"):
            try:
                if c == "event_timestamp":
                    cur.execute("alter session set time_zone = 'UTC'")
                cur.execute(AUDIT_SQL.format(ts=c), [since])
                rows, col = cur.fetchall(), c
                break
            except Exception as e:
                last = e
                try:
                    conn.rollback()
                except Exception:
                    pass
        if rows is None:
            return err(classify(last), last)
        out = []
        for row in rows:
            o = {"kind": "unified_audit", "EVENT_TIMESTAMP_UTC": str(row[0]) + "Z"}
            for name, v in zip(AUDIT_NAMES, row[1:]):
                if v is None or v == "":
                    continue
                o[name] = str(v)[:500]
            if o.get("SQL_TEXT"):
                o["SQL_TEXT"] = mask_sql(o["SQL_TEXT"])
            out.append(o)
        return {"ok": True, "rows": out, "capped": len(out) >= AUDIT_MAX, "column": col}
    except Exception as e:
        return err(classify(e), e)
    finally:
        try:
            conn.rollback()
        except Exception:
            pass
        try:
            conn.close()
        except Exception:
            pass


# ---- personal-data discovery for the AI PDPL Consultant (read-only; VALUES NEVER LEAVE THIS PROCESS) --------------------
# 1. the data dictionary (DBA_TAB_COLUMNS + column comments + DBA_TABLES.num_rows, readable with SELECT ANY DICTIONARY):
#    every column of an application schema whose NAME or COMMENT suggests personal data
# 2. where the login may read the table (only if a DBA granted it - the monitoring account never needs it), up to 50
#    non-null values of the candidate column are tested against the patterns HERE and only the COUNT of matches is returned
PII_NAME = [
    ("national_id", "identity", r"NATIONAL_?ID|NAT_?ID|NIN\b|CIVIL_?ID|ID_?NO|IDENTITY|HAWIYA|HUWIYA"),
    ("iqama", "identity", r"IQAMA|RESIDEN(T|CE)_?(ID|NO|PERMIT)"),
    ("passport", "identity", r"PASSPORT"),
    ("name", "identity", r"(^|_)(FIRST|LAST|FULL|FAMILY|MIDDLE|GIVEN|CUSTOMER|INSURED|MEMBER|PATIENT|EMP|EMPLOYEE|HOLDER)_?NAME|(^|_)NAME_(AR|EN)$"),
    ("birth_date", "identity", r"(^|_)(DOB|BIRTH|DATE_?OF_?BIRTH|BIRTH_?DATE)"),
    ("gender", "identity", r"(^|_)(GENDER|SEX)$"),
    ("nationality", "ethnic", r"NATIONALITY"),
    ("religion", "religious", r"RELIGION"),
    ("mobile", "contact", r"MOBILE|PHONE|TEL(EPHONE)?(_?NO)?$|GSM|CONTACT_?NO"),
    ("email", "contact", r"E_?MAIL"),
    ("address", "contact", r"ADDRESS|ADDR\d?$|STREET|DISTRICT|PO_?BOX|POSTAL|ZIP"),
    ("iban", "financial", r"IBAN|BANK_?ACC|ACCOUNT_?NO|ACCT_?NO"),
    ("card", "financial", r"CARD_?(NO|NUM)|PAN$|CREDIT_?CARD"),
    ("salary", "financial", r"SALARY|INCOME|WAGE"),
    ("health", "health", r"DIAGNOS|ICD|MEDICAL|DISEASE|ILLNESS|CHRONIC|PREGNAN|DISABILIT|PRESCRI|CLAIM_?DIAG|BLOOD|ALLERG|TREATMENT"),
    ("credit", "credit", r"CREDIT_?SCORE|SIMAH|DEFAULT_?FLAG|DELINQU"),
    ("biometric", "biometric", r"FINGERPRINT|BIOMETRIC|FACE_?(ID|IMG|IMAGE)|PHOTO|SIGNATURE_?IMG"),
    ("location", "location", r"LATITUDE|LONGITUDE|GPS|GEO_?LOC"),
    ("criminal", "criminal", r"CRIMINAL|CONVICTION|POLICE_?RECORD"),
    ("vehicle_owner", "identity", r"PLATE_?NO|SEQUENCE_?NO|CHASSIS|VIN$"),
]
PII_VALUE = {
    "national_id": r"1\d{9}", "iqama": r"2\d{9}", "mobile": r"(\+?966|00966|0)?5\d{8}", "email": r"[^@\s]{1,64}@[^@\s]+\.[A-Za-z]{2,}",
    "iban": r"SA\d{22}", "card": r"\d{13,19}", "passport": r"[A-Z]\d{6,9}", "health": r"[A-TV-Z]\d{2}(\.\d{1,4})?",
}
PII_SKIP_OWNERS = "('SYS','SYSTEM','XDB','MDSYS','CTXSYS','ORDSYS','ORDDATA','OLAPSYS','WMSYS','LBACSYS','DVSYS','AUDSYS','GSMADMIN_INTERNAL','DBSNMP','OUTLN','APPQOSSYS','OJVMSYS','DVF','REMOTE_SCHEDULER_AGENT','GGSYS','ANONYMOUS','SI_INFORMTN_SCHEMA','ORACLE_OCM','DIP','XS$NULL','MDDATA','SPATIAL_CSW_ADMIN_USR','SYSBACKUP','SYSDG','SYSKM','SYSRAC','GSMCATUSER','GSMUSER','APEX_PUBLIC_USER','FLOWS_FILES','ZYB_OPS')"
PII_MAX_COLS = 5000


def _luhn(d):
    t = 0
    for i, ch in enumerate(reversed(d)):
        n = int(ch)
        if i % 2:
            n = n * 2 - 9 if n > 4 else n * 2
        t += n
    return t % 10 == 0


def op_oracle_pii_scan(r):
    try:
        __import__("oracledb")
    except Exception:
        return err("missing_module", "oracledb is not installed on the platform server")
    try:
        conn = connect_db(dict(r, engine="oracle"))
    except Exception as e:
        return err(classify(e), e)
    pats = [(k, cat, _re.compile(rx, _re.I)) for k, cat, rx in PII_NAME]
    vals = {k: _re.compile(rx) for k, rx in PII_VALUE.items()}
    ident = _re.compile(r"^[A-Za-z0-9_$#]{1,128}$")
    try:
        try:
            conn.call_timeout = 30000
            conn.module = "ZYBERON-MONITOR"
            conn.action = "read-only personal data discovery"
            conn.client_identifier = "zyberon-itam"
        except Exception:
            pass
        cur = conn.cursor()
        cur.execute("select privilege from session_privs")
        extra = [x for x in sorted({str(y[0]).upper() for y in cur.fetchall()}) if x not in ORACLE_SAFE_PRIVS]
        if extra:
            return err("unsafe", "account holds more than read-only monitoring rights - not used")
        try:
            cur.execute("set transaction read only")
        except Exception:
            pass
        try:
            cur.execute("select owner from dba_users where oracle_maintained = 'Y'")
            skip = {str(x[0]) for x in cur.fetchall()}
        except Exception:
            skip = set()
        cur.execute("select c.owner, c.table_name, c.column_name, c.data_type, t.num_rows, substr(cc.comments, 1, 200) "
                    "from dba_tab_columns c join dba_tables t on t.owner = c.owner and t.table_name = c.table_name "
                    "left join dba_col_comments cc on cc.owner = c.owner and cc.table_name = c.table_name and cc.column_name = c.column_name "
                    "where c.owner not in " + PII_SKIP_OWNERS + " and t.temporary = 'N' and t.nested = 'NO' order by c.owner, c.table_name, c.column_id")
        cols, scanned, truncated = [], 0, False
        for owner, table, column, dtype, num_rows, comment in cur.fetchall():
            owner, table, column = str(owner), str(table), str(column)
            if owner in skip:
                continue
            scanned += 1
            hit = None
            for k, cat, rx in pats:
                if rx.search(column) or (comment and rx.search(str(comment))):
                    hit = (k, cat, "name" if rx.search(column) else "comment")
                    break
            if not hit:
                continue
            cols.append({"owner": owner, "table": table, "column": column, "type": str(dtype), "rows": int(num_rows) if num_rows is not None else None,
                         "kind": hit[0], "category": hit[1], "by": hit[2]})
            if len(cols) >= PII_MAX_COLS:
                truncated = True
                break
        # value confirmation, only where the login can already read the table (never a new grant); counts only
        probed, denied = 0, 0
        for c in cols:
            rx = vals.get(c["kind"])
            if rx is None or probed >= 300 or not all(ident.match(x) for x in (c["owner"], c["table"], c["column"])):
                continue
            if c["type"] not in ("VARCHAR2", "CHAR", "NVARCHAR2", "NCHAR", "NUMBER"):
                continue
            try:
                cur.execute('select "%s" from "%s"."%s" where "%s" is not null and rownum <= 50' % (c["column"], c["owner"], c["table"], c["column"]))
                sample = [str(x[0]).strip() for x in cur.fetchall()]
            except Exception:
                denied += 1
                c["confirmed"] = None
                try:
                    conn.rollback()
                    cur.execute("set transaction read only")
                except Exception:
                    pass
                continue
            probed += 1
            n = sum(1 for v in sample if rx.fullmatch(v) and (c["kind"] != "card" or _luhn(v)))
            c["sampled"], c["matched"] = len(sample), n
            c["confirmed"] = (n * 2 >= len(sample)) if sample else None   # nothing to test: unknown, never "not personal data"
            sample = None
        return {"ok": True, "columns": cols, "scanned_columns": scanned, "truncated": truncated, "probed": probed, "probe_denied": denied}
    except Exception as e:
        return err(classify(e), e)
    finally:
        try:
            conn.rollback()
        except Exception:
            pass
        try:
            conn.close()
        except Exception:
            pass


# ---- personal-data discovery and identity search on SQL Server / PostgreSQL (and Oracle for the search) -------------
# Same rules as oracle_pii_scan: the dictionary (column names, comments, row estimates), then - only where the login can
# already read the table - 50 values tested HERE with only the count of matches returned. A login that can write, own
# or administer is refused before anything is read. db_find answers "how many rows hold this identifier" per column
# (counts only; the identifier is never echoed, logged or stored by the helper).
PII_IDENT = _re.compile(r"^[A-Za-z0-9_$#@ ]{1,128}$")
PII_TEXT = {"postgres": ("character varying", "character", "text", "numeric", "bigint", "integer", "varchar", "char"),
            "mssql": ("varchar", "nvarchar", "char", "nchar", "bigint", "numeric", "decimal", "int"),
            "oracle": ("VARCHAR2", "CHAR", "NVARCHAR2", "NCHAR", "NUMBER")}
PII_NUMERIC = ("numeric", "bigint", "integer", "decimal", "int", "NUMBER")
PII_COLS_SQL = {
    "postgres": "select c.table_schema, c.table_name, c.column_name, c.data_type, st.n_live_tup, left(d.description, 200) "
                "from information_schema.columns c join information_schema.tables t on t.table_schema = c.table_schema and t.table_name = c.table_name and t.table_type = 'BASE TABLE' "
                "left join pg_catalog.pg_stat_user_tables st on st.schemaname = c.table_schema and st.relname = c.table_name "
                "left join pg_catalog.pg_description d on d.objoid = st.relid and d.objsubid = c.ordinal_position "
                "where c.table_schema not in ('pg_catalog', 'information_schema') and c.table_schema not like 'pg_toast%' order by 1, 2, c.ordinal_position",
    "mssql": "select s.name, t.name, c.name, ty.name, (select sum(p.rows) from sys.partitions p where p.object_id = t.object_id and p.index_id in (0, 1)), "
             "cast(ep.value as nvarchar(200)) from sys.tables t join sys.schemas s on s.schema_id = t.schema_id join sys.columns c on c.object_id = t.object_id "
             "join sys.types ty on ty.user_type_id = c.user_type_id left join sys.extended_properties ep on ep.major_id = t.object_id and ep.minor_id = c.column_id and ep.name = 'MS_Description' "
             "where t.is_ms_shipped = 0 order by s.name, t.name, c.column_id",
}
PII_SAFE_SQL = {
    "postgres": "select (select rolsuper or rolcreaterole or rolcreatedb from pg_catalog.pg_roles where rolname = current_user), "
                "(select count(*) from information_schema.table_privileges where grantee = current_user and privilege_type in ('INSERT', 'UPDATE', 'DELETE', 'TRUNCATE'))",
    "mssql": "select isnull(is_srvrolemember('sysadmin'), 0) + isnull(is_rolemember('db_owner'), 0) + isnull(is_rolemember('db_datawriter'), 0) + isnull(is_rolemember('db_ddladmin'), 0), "
             "(select count(*) from fn_my_permissions(NULL, 'DATABASE') where permission_name in ('INSERT', 'UPDATE', 'DELETE', 'ALTER', 'CONTROL', 'TAKE OWNERSHIP'))",
}


def _q(eng, *names):
    if not all(PII_IDENT.match(n or "") and '"' not in n and "]" not in n for n in names):
        raise ValueError("identifier not allowed")
    if eng == "mssql":
        return ".".join("[%s]" % n for n in names)
    return ".".join('"%s"' % n for n in names)


def _pii_open(r):
    eng = r.get("engine")
    conn = connect_db(r)
    cur = conn.cursor()
    if eng == "oracle":
        cur.execute("select privilege from session_privs")
        if [x for x in sorted({str(y[0]).upper() for y in cur.fetchall()}) if x not in ORACLE_SAFE_PRIVS]:
            conn.close()
            return None, None, err("unsafe", "account holds more than read-only monitoring rights - not used")
        try:
            conn.call_timeout = 15000
            cur.execute("set transaction read only")
        except Exception:
            pass
        return conn, cur, None
    cur.execute(PII_SAFE_SQL[eng])
    a, b = cur.fetchone()
    if a or b:
        conn.close()
        return None, None, err("unsafe", "login can write, own or administer this database - not used for personal-data discovery")
    if eng == "postgres":
        cur.execute("set session characteristics as transaction read only")
        cur.execute("set statement_timeout = 15000")
    return conn, cur, None


def op_db_pii_scan(r):
    eng = r.get("engine")
    if eng == "oracle":
        return op_oracle_pii_scan(r)
    if eng not in PII_COLS_SQL:
        return err("config", "no personal-data discovery for this engine")
    try:
        conn, cur, refused = _pii_open(r)
    except Exception as e:
        return err(classify(e), e)
    if refused:
        return refused
    pats = [(k, cat, _re.compile(rx, _re.I)) for k, cat, rx in PII_NAME]
    vals = {k: _re.compile(rx) for k, rx in PII_VALUE.items()}
    try:
        cur.execute(PII_COLS_SQL[eng])
        cols, scanned, truncated = [], 0, False
        for owner, table, column, dtype, rows, comment in cur.fetchall():
            scanned += 1
            column = str(column)
            hit = next(((k, cat, "name" if rx.search(column) else "comment") for k, cat, rx in pats if rx.search(column) or (comment and rx.search(str(comment)))), None)
            if not hit:
                continue
            cols.append({"owner": str(owner), "table": str(table), "column": column, "type": str(dtype), "rows": int(rows) if rows is not None else None, "kind": hit[0], "category": hit[1], "by": hit[2]})
            if len(cols) >= PII_MAX_COLS:
                truncated = True
                break
        probed, denied = 0, 0
        for c in cols:
            rx = vals.get(c["kind"])
            if rx is None or probed >= 300 or c["type"] not in PII_TEXT[eng]:
                continue
            try:
                tbl, col = _q(eng, c["owner"], c["table"]), _q(eng, c["column"])
            except ValueError:
                continue
            try:
                cur.execute(("select top 50 %s from %s where %s is not null" if eng == "mssql" else "select %s from %s where %s is not null limit 50") % (col, tbl, col))
                sample = [str(x[0]).strip() for x in cur.fetchall()]
            except Exception:
                denied += 1
                c["confirmed"] = None
                try:
                    conn.rollback()
                except Exception:
                    pass
                continue
            probed += 1
            n = sum(1 for v in sample if rx.fullmatch(v) and (c["kind"] != "card" or _luhn(v)))
            c["sampled"], c["matched"] = len(sample), n
            c["confirmed"] = (n * 2 >= len(sample)) if sample else None
            sample = None
        return {"ok": True, "engine": eng, "columns": cols, "scanned_columns": scanned, "truncated": truncated, "probed": probed, "probe_denied": denied}
    except Exception as e:
        return err(classify(e), e)
    finally:
        try:
            conn.rollback()
        except Exception:
            pass
        try:
            conn.close()
        except Exception:
            pass


def _variants(kind, value):
    v = _re.sub(r"\s+", "", str(value or ""))
    if kind == "mobile":
        d = _re.sub(r"\D", "", v)
        m = _re.match(r"^(?:00966|966|0)?(5\d{8})$", d)
        return sorted({"0" + m.group(1), "966" + m.group(1), "+966" + m.group(1), "00966" + m.group(1), m.group(1)}) if m else [v]
    if kind == "email":
        return sorted({v, v.lower()})
    if kind in ("passport", "iban"):
        return sorted({v, v.upper()})
    return [v]


def op_db_find(r):
    eng, cols = r.get("engine"), (r.get("columns") or [])[:50]
    if eng not in ("oracle", "postgres", "mssql"):
        return err("config", "no identity search for this engine")
    vs = _variants(r.get("kind"), r.get("value"))
    if not vs or not vs[0] or len(vs[0]) > 120:
        return err("config", "no identifier to search for")
    try:
        conn, cur, refused = _pii_open(r)
    except Exception as e:
        return err(classify(e), e)
    if refused:
        return refused
    out = []
    try:
        for c in cols:
            row = {"owner": c.get("owner"), "table": c.get("table"), "column": c.get("column"), "count": None}
            try:
                tbl, col = _q(eng, c["owner"], c["table"]), _q(eng, c["column"])
            except (ValueError, KeyError):
                row["error"] = "identifier not allowed"
                out.append(row)
                continue
            params = vs
            if c.get("type") in PII_NUMERIC:
                params = [int(x) for x in vs if x.isdigit()]
                if not params:
                    row["count"] = 0
                    out.append(row)
                    continue
            ph = ", ".join((":%d" % (i + 1)) if eng == "oracle" else "%s" for i in range(len(params)))
            try:
                cur.execute("select count(*) from %s where %s in (%s)" % (tbl, col, ph), params)
                row["count"] = int(cur.fetchone()[0])
            except Exception as e:
                m = _re.search(r"(ORA-\d{5}|permission denied|SELECT permission was denied|does not exist|Invalid object name|timeout|canceling statement)", str(e))
                row["error"] = (m.group(1) if m else "query failed")[:80]
                try:
                    conn.rollback()
                    if eng == "oracle":
                        cur.execute("set transaction read only")
                except Exception:
                    pass
            out.append(row)
        return {"ok": True, "engine": eng, "results": out, "variants": len(vs)}
    finally:
        params = vs = None
        try:
            conn.rollback()
        except Exception:
            pass
        try:
            conn.close()
        except Exception:
            pass


# ---- our own engines: Data Verify, Change Stream, Replication (db_repl.py next to this file) ---------------------------
_REPL = []


def _repl():
    """db_repl.py, loaded ONCE per process (a second copy would have its own Refused class and refusals would be missed)"""
    if not _REPL:
        import importlib.util
        spec = importlib.util.spec_from_file_location("db_repl", _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "db_repl.py"))
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        _REPL.append(m)
    return _REPL[0]


def _side(r, key, allowed, label, read_only=True):
    """connect one side ({engine, host, port, username, password, service|database, tls, ca_file}) and check its account"""
    R = _repl()
    d = r.get(key) or {}
    eng = d.get("engine")
    if eng not in ("oracle", "postgres"):
        raise R.Refused("%s: engine must be oracle or postgres" % label)
    conn = connect_db(d)
    try:
        if eng == "oracle":
            try:
                conn.call_timeout = 120000
                conn.module = "ZYBERON-" + label.upper().replace(" ", "-")[:20]
                conn.client_identifier = "zyberon-itam"
            except Exception:
                pass
            try:
                import oracledb
                oracledb.defaults.fetch_decimals = True   # NUMBER as Decimal: 0.1 stays 0.1 when hashed
            except Exception:
                pass
        R.check_account(conn, eng, allowed, label)
        if read_only:
            R.read_only(conn, eng)
    except Exception:
        try:
            conn.close()
        except Exception:
            pass
        raise
    return conn, eng


def _close(*conns):
    for c in conns:
        try:
            c.rollback()
        except Exception:
            pass
        try:
            c.close()
        except Exception:
            pass


def _engine_op(fn):
    def run(r):
        R = _repl()
        try:
            return fn(r, R)
        except R.Refused as e:
            return err("unsafe" if "holds more" in str(e) or "superuser" in str(e) or "ALL data" in str(e) else "refused", e)
        except ImportError as e:
            return err("missing_module", e)
        except Exception as e:
            return err(classify(e), e)
    return run


@_engine_op
def op_verify_describe(r, R):
    src, se = _side(r, "src", R.ORACLE_READ_SAFE, "verify source")
    try:
        tgt, te = _side(r, "tgt", R.ORACLE_READ_SAFE, "verify target")
    except Exception:
        _close(src)
        raise
    try:
        out = []
        for t in (r.get("tables") or [])[:200]:
            try:
                a = R.describe(src, se, t["owner"], t["table"])
                b = R.describe(tgt, te, t.get("tgt_owner") or t["owner"], t.get("tgt_table") or t["table"])
                cmp = R.compare_columns(a, b, t.get("exclude") or [])
                lobs = [c for c, _, ty in cmp["data"] if R.LOB_TYPES.match(ty or "")]
                out.append({"ok": True, "src": {"owner": a["owner"], "table": a["table"]}, "tgt": {"owner": b["owner"], "table": b["table"]},
                            "cmp": {"pk": cmp["pk"], "data": cmp["data"]}, "only_source": cmp["only_source"], "only_target": cmp["only_target"], "lob_columns": lobs})
            except R.Refused as e:
                out.append({"ok": False, "owner": t.get("owner"), "table": t.get("table"), "error": str(e)[:300]})
        return {"ok": True, "tables": out}
    finally:
        _close(src, tgt)


@_engine_op
def op_verify_chunk(r, R):
    src, se = _side(r, "src", R.ORACLE_READ_SAFE, "verify source")
    try:
        tgt, te = _side(r, "tgt", R.ORACLE_READ_SAFE, "verify target")
    except Exception:
        _close(src)
        raise
    try:
        lim = max(100, min(int(r.get("limit") or 20000), 50000))
        res = R.verify_chunk(src, se, tgt, te, r["spec"], r.get("after"), lim, "reverse" if r.get("phase") == "reverse" else "forward")
        return dict(res, ok=True)
    finally:
        _close(src, tgt)


@_engine_op
def op_verify_keys(r, R):
    src, se = _side(r, "src", R.ORACLE_READ_SAFE, "verify source")
    try:
        tgt, te = _side(r, "tgt", R.ORACLE_READ_SAFE, "verify target")
    except Exception:
        _close(src)
        raise
    try:
        return dict(R.verify_keys(src, se, tgt, te, r["spec"], (r.get("keys") or [])[:5000]), ok=True)
    finally:
        _close(src, tgt)


@_engine_op
def op_logminer_read(r, R):
    """Change Stream: one window of committed changes on the tracked schemas - metadata only, no row values"""
    conn, eng = _side(r, "src", R.ORACLE_MINER_SAFE, "change stream", read_only=False)
    try:
        if eng != "oracle":
            raise R.Refused("the Change Stream reads Oracle redo (LogMiner)")
        cur = conn.cursor()
        owners = [R.ident(o, "owner") for o in (r.get("owners") or [])][:50]
        if not owners:
            raise R.Refused("choose at least one schema to follow")
        if not r.get("cursor"):
            cur.execute("select current_scn from v$database")
            n = int(cur.fetchone()[0])
            return {"ok": True, "txns": [], "cursor": {"commit_scn": n, "restart_scn": n}, "info": {"current_scn": n, "started": True}}
        done, nxt, info = R.mine(cur, owners, [(R.ident(o), R.ident(t)) for o, t in (r.get("tables") or [])][:200], r["cursor"], int(r.get("max_files") or 4), False)
        txs = [R.summarize_tx(t) for t in done]
        return {"ok": True, "txns": txs[:2000], "truncated": max(0, len(txs) - 2000), "cursor": nxt, "info": info}
    finally:
        _close(conn)


@_engine_op
def op_repl_status(r, R):
    """Replication readiness: source SCN and supplemental logging per table; target checkpoint row and the writer account"""
    out = {"ok": True}
    src, se = _side(r, "src", R.ORACLE_MINER_SAFE, "replication source", read_only=False)
    try:
        cur = src.cursor()
        cur.execute("select current_scn, supplemental_log_data_min, supplemental_log_data_pk, log_mode from v$database")
        x = cur.fetchone()
        out["source"] = {"current_scn": int(x[0]), "supplemental_min": x[1], "supplemental_pk": x[2], "log_mode": x[3], "tables": []}
        for t in (r.get("job") or {}).get("tables", [])[:200]:
            row = {"table": t["src_owner"] + "." + t["src_table"], "pk_logging": None, "pk": []}
            try:
                cur.execute("select count(*) from dba_log_groups where owner = :1 and table_name = :2 and log_group_type in ('PRIMARY KEY LOGGING', 'ALL COLUMN LOGGING')", [t["src_owner"], t["src_table"]])
                row["pk_logging"] = int(cur.fetchone()[0]) > 0 or str(x[2]).upper() == "YES"
            except Exception as e:
                row["error"] = classify(e)
            try:   # the primary key, from the dictionary (SELECT_CATALOG_ROLE): the replication matches rows on it
                cur.execute("select cc.column_name from dba_constraints c join dba_cons_columns cc on cc.owner = c.owner and cc.constraint_name = c.constraint_name "
                            "where c.owner = :1 and c.table_name = :2 and c.constraint_type = 'P' order by cc.position", [t["src_owner"], t["src_table"]])
                row["pk"] = [str(y[0]) for y in cur.fetchall()]
            except Exception as e:
                row["error"] = classify(e)
            out["source"]["tables"].append(row)
    finally:
        _close(src)
    tgt, te = _side(r, "tgt", R.ORACLE_WRITER_SAFE, "replication target", read_only=False)
    try:
        job = r.get("job") or {}
        try:
            out["checkpoint"] = R.read_checkpoint(tgt, te, job["checkpoint"], job["id"])
        except Exception as e:
            out["checkpoint"] = None
            out["checkpoint_error"] = classify(e)
    finally:
        _close(tgt)
    return out


@_engine_op
def op_repl_cycle(r, R):
    """Replication: mine from the target's checkpoint and apply, in this process only (row values never leave it)"""
    job = r.get("job") or {}
    tgt, te = _side(r, "tgt", R.ORACLE_WRITER_SAFE, "replication target", read_only=False)
    try:
        ck = R.read_checkpoint(tgt, te, job["checkpoint"], job["id"])
        if not ck:
            raise R.Refused("not instantiated: the checkpoint row for %s is not on the target - load the initial copy and insert it (setup script)" % job["id"])
        src, se = _side(r, "src", R.ORACLE_MINER_SAFE, "replication source", read_only=False)
        try:
            owners = sorted({t["src_owner"] for t in job["tables"]})
            tables = [(t["src_owner"], t["src_table"]) for t in job["tables"]]
            done, nxt, info = R.mine(src.cursor(), owners, tables, ck, int(r.get("max_files") or 4), True)
        finally:
            _close(src)
        if info.get("gap"):
            return {"ok": True, "stopped": {"reason": "gap", "detail": info["gap"]}, "info": info, "checkpoint": ck}
        R.writer_session(tgt, te)
        st = R.apply_transactions(tgt, te, done, job, ck["restart_scn"], nxt)
        return {"ok": True, "stats": st, "stopped": st["stopped"], "info": info, "checkpoint_before": ck, "cursor": nxt if not st["stopped"] else None}
    finally:
        _close(tgt)


def oracle_edition(banner):
    """the edition from the V$VERSION banner: EE / SE2 / SE / SEO / XE / PE, '' when the banner does not say"""
    b = str(banner or "")
    for pat, ed in ((r"Enterprise Edition", "EE"), (r"Standard Edition 2", "SE2"), (r"Standard Edition One", "SEO"), (r"Standard Edition", "SE"),
                    (r"Express Edition", "XE"), (r"Personal", "PE"), (r"Free\b", "FREE")):
        if _re.search(pat, b, _re.I):
            return ed
    return ""


def op_oracle_health(r):
    try:
        __import__("oracledb")
    except Exception:
        return err("missing_module", "oracledb is not installed on the platform server (run install/netops-cli-setup.sh in the SIEM)")
    try:
        conn = connect_db(dict(r, engine="oracle"))
    except Exception as e:
        return err(classify(e), e)
    recs, errors = [], []
    try:
        # visible to the DBAs: v$session.module / client_identifier, and in the unified audit trail
        try:
            conn.call_timeout = ORACLE_CALL_TIMEOUT_MS
            conn.module = "ZYBERON-MONITOR"
            conn.action = "read-only health check"
            conn.client_identifier = "zyberon-itam"
        except Exception:
            pass
        cur = conn.cursor()
        try:
            cur.execute("select privilege from session_privs")
            privs = sorted({str(x[0]).upper() for x in cur.fetchall()})
        except Exception as e:
            return err("unsafe", "could not read the account's privileges (session_privs): " + classify(e) + " - not used")
        extra = [x for x in privs if x not in ORACLE_SAFE_PRIVS]
        if extra:
            return err("unsafe", "account holds more than read-only monitoring rights (" + ", ".join(extra[:8]) + ("…" if len(extra) > 8 else "")
                       + ") - not used. Create a dedicated read-only user (install/oracle-monitor-account.sql)")
        try:
            cur.execute("set transaction read only")
        except Exception:
            pass
        heavy = r.get("heavy", True) is not False
        account = ""
        try:   # the account the grants must name (a user name, never the password) - shown in the fix script
            cur.execute("select user from dual")
            account = str(cur.fetchone()[0] or "")[:128]
        except Exception:
            account = ""   # not fatal: the script then says <monitoring user>

        def rows(name, table=ORACLE_HEALTH):
            if not heavy and name in ORACLE_HEAVY:
                return []
            try:
                cur.execute(table[name])
                return cur.fetchall()
            except Exception as e:
                ora = _re.search(r"ORA-\d{5}", str(e))
                errors.append({"query": name, "error": classify(e), "ora": ora.group(0) if ora else ""})
                return [] if table is ORACLE_HEALTH else None

        s = lambda v, n=200: "" if v is None else str(v)[:n]
        x = rows("instance")
        if x:
            i = x[0]
            recs.append({"kind": "instance", "instance": s(i[0], 64), "host": s(i[1], 120), "version": s(i[2], 40), "status": s(i[3], 20),
                         "database_status": s(i[4], 20), "open_mode": s(i[5], 30), "role": s(i[6], 30), "log_mode": s(i[7], 20), "db_name": s(i[8], 64),
                         "db_unique_name": s(i[9], 64), "uptime_s": _num(i[10]), "startup_time": s(i[11], 30), "archiver": s(i[12], 20), "logins": s(i[13], 20),
                         "banner": s(i[14] if len(i) > 14 else "", 200), "edition": oracle_edition(i[14] if len(i) > 14 else "")})
        for t in rows("tablespace")[:200]:
            recs.append({"kind": "tablespace", "name": s(t[0], 64), "used_mb": _num(t[1]), "max_mb": _num(t[2]), "used_pct": _num(t[3]), "contents": s(t[4], 20), "status": s(t[5], 20)})
        x = rows("sessions")
        if x:
            v = x[0]
            recs.append({"kind": "sessions", "total": _num(v[0]), "active": _num(v[1]), "blocked": _num(v[2]), "user_sessions": _num(v[3]), "max_sessions": _num(v[4])})
        for b in rows("blocked"):
            recs.append({"kind": "blocked_session", "sid": s(b[0], 20), "serial": s(b[1], 20), "user": s(b[2], 64), "blocking_sid": s(b[3], 20), "blocking_user": s(b[4], 64),
                         "wait_s": _num(b[5]), "event": s(b[6], 120), "sql_id": s(b[7], 20), "program": s(b[8], 80), "machine": s(b[9], 80)})
        x = rows("redo")
        if x:
            v = x[0]
            recs.append({"kind": "redo", "log_mode": s(v[0], 20), "unarchived": _num(v[1]), "archive_lag_s": _num(v[2]), "redo_switches_1h": _num(v[3]), "dest_status": s(v[4], 20), "dest_error": s(v[5], 200)})
        x = rows("backup")
        if x:
            v = x[0]
            recs.append({"kind": "backup", "status": s(v[0], 30), "input_type": s(v[1], 30), "start_time": s(v[2], 30), "end_time": s(v[3], 30), "age_h": _num(v[4]), "output_mb": _num(v[5]), "elapsed_s": _num(v[6])})
        elif heavy and not any(e["query"] == "backup" for e in errors):
            recs.append({"kind": "backup", "status": "NONE"})
        dg = {str(n): v for n, v in rows("dataguard")}
        if dg:
            recs.append({"kind": "dataguard", "apply_lag_s": _interval_s(dg.get("apply lag")), "transport_lag_s": _interval_s(dg.get("transport lag"))})
        x = rows("invalid_objects")
        if x:
            recs.append({"kind": "invalid_objects", "count": _num(x[0][0])})
        al = rows("alert_errors")
        if al:   # same record as the collector agent's alert-log tail; each line carries its own time so overlapping reads de-duplicate
            lines = [s(a[0], 25) + " " + s(a[1], 300).replace("\n", " ").strip() for a in al]
            recs.append({"kind": "alertlog", "path": "V$DIAG_ALERT_EXT", "ora_errors_5m": sum(1 for l in lines if "ORA-" in l), "tail": "\n".join(lines[:200])})
        for g in rows("asm")[:50]:
            tot, free, usable = _num(g[3]), _num(g[4]), _num(g[5])
            recs.append({"kind": "asm_diskgroup", "name": s(g[0], 64), "state": s(g[1], 20), "type": s(g[2], 10), "total_mb": tot, "free_mb": free, "usable_file_mb": usable,
                         "offline_disks": _num(g[6]), "required_mirror_free_mb": _num(g[7]), "used_pct": round((tot - free) * 100.0 / tot, 1) if tot and free is not None else None})
        x = rows("archive_gen")
        if x:
            recs.append({"kind": "archive", "logs_24h": _num(x[0][0]) or 0, "mb_24h": _num(x[0][1]) or 0, "last_age_s": _num(x[0][2])})
        for d in rows("archive_dest")[:31]:
            recs.append({"kind": "archive_dest", "dest_id": _num(d[0]), "dest_name": s(d[1], 30), "status": s(d[2], 20), "target": s(d[3], 20), "destination": s(d[4], 200), "error": s(d[5], 200), "binding": s(d[6], 20)})
        x = rows("archive_gap")
        if x:
            recs.append({"kind": "archive_gap", "gaps": _num(x[0][0]) or 0, "low_seq": _num(x[0][1]), "high_seq": _num(x[0][2])})
        x = rows("mrp")
        if x is not None and not any(e["query"] == "mrp" for e in errors):
            recs.append({"kind": "mrp", "running": bool(x), "status": s(x[0][1], 20) if x else "", "sequence": _num(x[0][2]) if x else None})
        if r.get("morning"):   # the morning health check: every ORA- line since yesterday morning, grouped by error code
            try:
                cur.execute(ORACLE_ALERT_24H)
                lines = cur.fetchall()
                groups = {}
                for ts, msg in lines:
                    m = _re.search(r"ORA-\d{5}", str(msg or ""))
                    code = m.group(0) if m else "ORA-?"
                    g = groups.setdefault(code, {"code": code, "count": 0, "first": s(ts, 25), "last": s(ts, 25), "sample": s(msg, 300).replace("\n", " ").strip()})
                    g["count"] += 1
                    g["first"] = min(g["first"], s(ts, 25))
                    if s(ts, 25) >= g["last"]:
                        g["last"], g["sample"] = s(ts, 25), s(msg, 300).replace("\n", " ").strip()
                recs.append({"kind": "alertlog_24h", "lines": len(lines), "capped": len(lines) >= 2000, "codes": sorted(groups.values(), key=lambda g: -g["count"])[:50]})
            except Exception as e:
                ora = _re.search(r"ORA-\d{5}", str(e))
                errors.append({"query": "alert_errors_24h", "error": classify(e), "ora": ora.group(0) if ora else ""})
        for f in rows("fra"):
            lim, used = _num(f[1]), _num(f[2])
            if lim:
                recs.append({"kind": "fra", "name": s(f[0], 200), "space_limit_mb": lim, "space_used_mb": used, "reclaimable_mb": _num(f[3]), "files": _num(f[4]),
                             "used_pct": round((used or 0) * 100.0 / lim, 1)})
        if r.get("perf", True) is not False:
            recs.extend(oracle_perf_records(lambda n: rows(n, ORACLE_PERF)))
        snap, tuning = [], None
        ver = next((x.get("version") for x in recs if x.get("kind") == "instance"), None)
        if r.get("tuning", True) is not False:
            if _version_tuple(ver) >= (12, 2) or (ver is None and r.get("tuning_unknown_version", True)):
                more, snap = tuning_records(cur, heavy, r.get("pack") is True, errors)
                recs.extend(more)
                tuning = True
            else:
                tuning = False   # json_object needs 12.2: the tuning readings are not available on this release
        return {"ok": True, "engine": "oracle", "records": recs, "errors": errors, "heavy": heavy, "sqlstats": snap, "tuning": tuning, "version": ver, "account": account}
    finally:
        try:
            conn.rollback()
        except Exception:
            pass
        try:
            conn.close()
        except Exception:
            pass


# what runs on a server (Business Services, engine/service-map.js): fixed read-only commands - processes, listening TCP
# ports, running services, oratab. Same trust rule as ssh_facts (the host key must match the fingerprint an administrator
# trusted, checked before the password is sent). The raw text is returned; engine/service-map.js recognises the products.
SSH_SERVICES = [
    ("hostname", "hostname"),
    ("os", "uname -srm; grep -E '^PRETTY_NAME=' /etc/os-release 2>/dev/null; head -1 /etc/release 2>/dev/null"),
    ("ps", "ps -eo user=,comm=,args= 2>/dev/null | cut -c1-300 | head -600"),
    ("listen", "ss -ltnH 2>/dev/null || netstat -ltn 2>/dev/null || netstat -an -P tcp -f inet 2>/dev/null | grep LISTEN"),
    ("units", "systemctl list-units --type=service --state=running --no-legend --no-pager 2>/dev/null | head -300"),
    ("oratab", "cat /etc/oratab /var/opt/oracle/oratab 2>/dev/null | grep -v '^#' | grep ':' | head -40"),
]


SVC_MAX_OUT = 64000   # a process list is longer than the facts


def op_ssh_services(r):
    import io
    import paramiko
    want = str(r.get("fp") or "").lower()
    if len(want) != 64:
        return err("hostkey_untrusted", "no trusted host key for this server")
    try:
        t = transport(r["host"], r.get("port", 22))
    except Exception as e:
        return err(classify(e), e)
    try:
        k = t.get_remote_server_key()
        if fp_of(k) != want:   # checked BEFORE any credential is sent
            return {"ok": False, "error_class": "hostkey_changed", "error": "the server's SSH host key changed - not logging in", "fp": fp_of(k)}
        try:
            if r.get("private_key"):
                pk = None
                for cls in (paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.RSAKey):
                    try:
                        pk = cls.from_private_key(io.StringIO(r["private_key"]), password=r.get("password") or None)
                        break
                    except Exception:
                        continue
                if pk is None:
                    return err("config", "the private key could not be read")
                t.auth_publickey(r["username"], pk)
            else:
                t.auth_password(r["username"], r.get("password") or "")
        except Exception as e:
            return err("auth" if "auth" in str(e).lower() or isinstance(e, paramiko.AuthenticationException) else classify(e), e)
        facts = {}
        for name, cmd in SSH_SERVICES:
            try:
                ch = t.open_session(timeout=TIMEOUT)
                ch.settimeout(TIMEOUT)
                ch.exec_command(cmd)
                buf = b""
                while len(buf) < SVC_MAX_OUT:
                    d = ch.recv(4096)
                    if not d:
                        break
                    buf += d
                ch.close()
                facts[name] = buf[:SVC_MAX_OUT].decode("utf-8", "replace").strip()
            except Exception:
                facts[name] = ""
        return {"ok": True, "facts": facts}
    finally:
        t.close()


# baseline hardening of a database (Baseline Hardening page, judged in pyengine/hardening_rules.py): FIXED read-only
# SELECTs per engine through the same read-only login Asset Discovery proved on the host. Each query alone: one the login may
# not run comes back as its error code (the page lists the grant to add), never as a pass. Only setting names / values,
# account and role NAMES - no data from any application table.
DB_HARDEN = {
    "oracle": [
        ("params", "select name, value from v$parameter where name in ('remote_os_authent','remote_login_passwordfile','sec_case_sensitive_logon','o7_dictionary_accessibility','audit_trail','audit_sys_operations','sql92_security','global_names','os_roles','remote_os_roles','sec_max_failed_login_attempts','resource_limit')"),
        ("unified", "select value from v$option where parameter = 'Unified Auditing'"),
        ("version", "select banner from v$version where rownum = 1"),
        ("defpwd", "select d.username from dba_users_with_defpwd d join dba_users u on u.username = d.username where u.account_status = 'OPEN'"),
        ("profile", "select resource_name, limit from dba_profiles where profile = 'DEFAULT' and resource_name in ('FAILED_LOGIN_ATTEMPTS','PASSWORD_LIFE_TIME','PASSWORD_REUSE_MAX','PASSWORD_VERIFY_FUNCTION','PASSWORD_LOCK_TIME','PASSWORD_GRACE_TIME','INACTIVE_ACCOUNT_TIME')"),
        ("public_exec", "select table_name from dba_tab_privs where grantee = 'PUBLIC' and privilege = 'EXECUTE' and table_name in ('UTL_FILE','UTL_TCP','UTL_HTTP','UTL_SMTP','UTL_INADDR','DBMS_ADVISOR','DBMS_JAVA')"),
        ("dba_role", "select grantee from dba_role_privs where granted_role = 'DBA' and grantee not in ('SYS','SYSTEM')"),
        ("sample", "select username from dba_users where username in ('SCOTT','HR','OE','SH','PM','IX','BI') and account_status = 'OPEN'"),
    ],
    "mssql": [
        ("configs", "select name, cast(value_in_use as int) from sys.configurations where name in ('xp_cmdshell','clr enabled','clr strict security','Ad Hoc Distributed Queries','Database Mail XPs','Ole Automation Procedures','remote access','remote admin connections','scan for startup procs','cross db ownership chaining','default trace enabled','contained database authentication')"),
        ("server", "select cast(serverproperty('IsIntegratedSecurityOnly') as int), cast(serverproperty('ProductVersion') as nvarchar(50)), cast(serverproperty('ProductLevel') as nvarchar(50)), cast(serverproperty('Edition') as nvarchar(100))"),
        ("sa", "select name, is_disabled from sys.server_principals where sid = 0x01"),
        ("policy", "select name from sys.sql_logins where (is_policy_checked = 0 or is_expiration_checked = 0) and is_disabled = 0 and name not like '##%'"),
        ("sysadmins", "select p.name from sys.server_role_members m join sys.server_principals r on r.principal_id = m.role_principal_id join sys.server_principals p on p.principal_id = m.member_principal_id where r.name = 'sysadmin' and p.name not like 'NT SERVICE\\%' and p.name not like 'NT AUTHORITY\\%'"),
        ("trustworthy", "select name from sys.databases where is_trustworthy_on = 1 and name <> 'msdb'"),
        ("audits", "select name, is_state_enabled from sys.server_audits"),
        ("public_perms", "select permission_name from sys.server_permissions where grantee_principal_id = 2 and permission_name not in ('VIEW ANY DATABASE', 'CONNECT')"),
    ],
    "postgres": [
        ("settings", "select name, setting from pg_settings where name in ('ssl','password_encryption','log_connections','log_disconnections','log_statement','listen_addresses','logging_collector','shared_preload_libraries')"),
        ("version", "select current_setting('server_version')"),
        ("supers", "select rolname from pg_roles where rolsuper"),
        ("hba", "select type, database, user_name, address, auth_method from pg_hba_file_rules"),
        ("extensions", "select extname from pg_extension"),
        ("public_create", "select has_schema_privilege('public', 'public', 'CREATE')"),
    ],
}


# SQL Server / PostgreSQL / MySQL inventory details (engine/db-inventory.js): the server, every database with its size and
# state, and - where the engine records it - the last backup and the replication role. Fixed SELECTs only; a query the
# login may not run is reported per name ("missing privilege"), never guessed.
DB_DETAILS = {
    "mssql": [
        ("server", "select cast(serverproperty('MachineName') as nvarchar(200)), isnull(cast(serverproperty('InstanceName') as nvarchar(200)), 'MSSQLSERVER'), "
                   "cast(serverproperty('ProductVersion') as nvarchar(50)), cast(serverproperty('ProductLevel') as nvarchar(50)), cast(serverproperty('Edition') as nvarchar(200)), "
                   "cast(serverproperty('IsClustered') as int), cast(serverproperty('IsHadrEnabled') as int), cast(serverproperty('Collation') as nvarchar(128))"),
        ("started", "select convert(varchar(19), sqlserver_start_time, 126), cpu_count, physical_memory_kb / 1024 from sys.dm_os_sys_info"),
        ("sessions", "select count(*) from sys.dm_exec_sessions where is_user_process = 1"),
        ("databases", "select d.name, d.state_desc, d.recovery_model_desc, d.compatibility_level, "
                      "(select sum(cast(f.size as bigint)) * 8 / 1024 from sys.master_files f where f.database_id = d.database_id), "
                      "(select convert(varchar(19), max(b.backup_finish_date), 126) from msdb.dbo.backupset b where b.database_name = d.name and b.type = 'D'), "
                      "(select convert(varchar(19), max(b.backup_finish_date), 126) from msdb.dbo.backupset b where b.database_name = d.name and b.type = 'L'), "
                      "d.is_read_only, d.user_access_desc from sys.databases d"),
        ("replication", "select ar.replica_server_name, rs.role_desc, rs.synchronization_health_desc from sys.dm_hadr_availability_replica_states rs "
                        "join sys.availability_replicas ar on ar.replica_id = rs.replica_id where rs.is_local = 1"),
    ],
    "postgres": [
        ("server", "select version(), current_setting('server_version'), inet_server_port(), current_setting('max_connections')::int, "
                   "pg_is_in_recovery(), current_setting('data_directory', true)"),
        ("started", "select to_char(pg_postmaster_start_time() at time zone 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS')"),
        ("sessions", "select count(*) from pg_stat_activity where backend_type = 'client backend'"),
        ("databases", "select d.datname, case when d.datallowconn then 'ONLINE' else 'NO CONNECTIONS' end, pg_encoding_to_char(d.encoding), "
                      "round(pg_database_size(d.datname) / 1048576.0), s.numbackends, s.deadlocks, s.xact_commit + s.xact_rollback "
                      "from pg_database d left join pg_stat_database s on s.datname = d.datname where not d.datistemplate"),
        ("replication", "select application_name, state, sync_state, coalesce(extract(epoch from replay_lag)::int, 0) from pg_stat_replication"),
    ],
    "mysql": [
        ("server", "select version(), @@version_comment, @@hostname, @@port, @@max_connections, @@read_only, @@innodb_version"),
        ("started", "select variable_value from performance_schema.global_status where variable_name = 'Uptime'"),
        ("sessions", "select variable_value from performance_schema.global_status where variable_name = 'Threads_connected'"),
        ("databases", "select s.schema_name, 'ONLINE', s.default_character_set_name, round(coalesce(sum(t.data_length + t.index_length), 0) / 1048576), "
                      "count(t.table_name) from information_schema.schemata s left join information_schema.tables t on t.table_schema = s.schema_name "
                      "group by s.schema_name, s.default_character_set_name"),
        ("replication", "select channel_name, service_state from performance_schema.replication_connection_status"),
    ],
}
DB_DETAILS["oracle"] = [
    ("server", "select i.instance_name, i.host_name, i.version, (select banner from v$version where rownum = 1), i.status, d.database_role, d.open_mode, "
               "d.log_mode, d.name, d.db_unique_name from v$instance i, v$database d"),
    ("started", "select to_char(i.startup_time, 'YYYY-MM-DD\"T\"HH24:MI:SS'), (select value from v$parameter where name = 'cpu_count'), "
                "(select round(sum(value) / 1048576) from v$sga) from v$instance i"),
    ("sessions", "select count(*), (select value from v$parameter where name = 'sessions') from v$session where type = 'USER'"),
    # multitenant: one row per PDB (from the root, or only the PDB the service points at); a non-CDB answers the next query
    ("databases", "select name, open_mode, round(total_size / 1048576), restricted from v$pdbs"),
    ("database_noncdb", "select d.name, d.open_mode, (select round(sum(bytes) / 1048576) from dba_data_files), 'NO' from v$database d"),
    ("backup", "select (select to_char(max(end_time), 'YYYY-MM-DD\"T\"HH24:MI:SS') from v$rman_backup_job_details where status like 'COMPLETED%' and input_type in ('DB FULL', 'DB INCR')), "
               "(select to_char(max(end_time), 'YYYY-MM-DD\"T\"HH24:MI:SS') from v$rman_backup_job_details where status like 'COMPLETED%' and input_type = 'ARCHIVELOG') from dual"),
    ("replication", "select d.db_unique_name, d.database_role, d.protection_mode, (select value from v$dataguard_stats where name = 'apply lag') from v$database d "
                    "where d.database_role <> 'PRIMARY' or exists (select 1 from v$archive_dest where target = 'STANDBY' and status <> 'INACTIVE')"),
]
DB_DETAILS_SYSTEM = {"mssql": {"master", "model", "msdb", "tempdb"}, "postgres": {"postgres"}, "oracle": {"PDB$SEED"},
                     "mysql": {"mysql", "information_schema", "performance_schema", "sys"}}


def op_db_details(r):
    eng = r.get("engine")
    if eng not in DB_DETAILS:
        return err("config", "no inventory read for this engine")
    lib = {"mysql": "pymysql", "postgres": "pg8000", "mssql": "pytds", "oracle": "oracledb"}[eng]
    try:
        __import__(lib)
    except Exception:
        return err("missing_module", lib + " is not installed on the platform server (run install/netops-cli-setup.sh in the SIEM)")
    try:
        conn = connect_db(r)
    except Exception as e:
        t = str(e).lower()
        return err("auth" if "auth" in t or "password" in t or "login failed" in t or "ora-01017" in t or "ora-28000" in t or "ora-28001" in t else classify(e), e)
    res, errors = {"ok": True, "engine": eng}, {}
    try:
        cur = conn.cursor()
        if eng == "oracle":
            # the same rule as Database Health: an account with more than read-only monitoring rights is refused before any query
            try:
                conn.call_timeout = ORACLE_CALL_TIMEOUT_MS
                conn.module = "ZYBERON-MONITOR"
                conn.action = "read-only inventory"
            except Exception:
                pass   # an older driver without these attributes: the queries are still fixed SELECTs
            try:
                cur.execute("select privilege from session_privs")
                extra = [x for x in sorted({str(y[0]).upper() for y in cur.fetchall()}) if x not in ORACLE_SAFE_PRIVS]
            except Exception as e:
                return err("unsafe", "could not read the account's privileges (session_privs): " + classify(e) + " - not used")
            if extra:
                return err("unsafe", "account holds more than read-only monitoring rights (" + ", ".join(extra[:8]) + ") - not used. Create a dedicated read-only user (install/oracle-monitor-account.sql)")
        try:   # the queries are fixed SELECTs; the session is read-only where the engine supports it
            if eng == "postgres":
                cur.execute("set session characteristics as transaction read only")
            elif eng == "mysql":
                cur.execute("set session transaction read only")
            elif eng == "oracle":
                cur.execute("set transaction read only")
        except Exception:
            pass   # an engine / version without a read-only session: the queries are SELECTs regardless
        for name, sql in DB_DETAILS[eng]:
            try:
                cur.execute(sql)
                rows = cur.fetchmany(500)
                res[name] = [[(v if isinstance(v, (int, float)) or v is None else str(v)[:300]) for v in row] for row in rows]
            except Exception as e:
                res[name] = None
                m = _re.search(r"(ORA-\d{5}|permission denied|The SELECT permission was denied|VIEW SERVER STATE|VIEW DATABASE STATE|command denied|does not exist|Invalid object name|Access denied)", str(e))
                errors[name] = (m.group(1) if m else str(e).split("\n")[0])[:160]
                try:
                    conn.rollback()   # postgres: a failed statement aborts the transaction; the next query needs a clean one
                except Exception:
                    pass   # nothing to roll back
        res["errors"] = errors
        res["system"] = sorted(DB_DETAILS_SYSTEM[eng])
        return res
    finally:
        try:
            conn.close()
        except Exception:
            pass   # the server already closed it


def op_db_harden(r):
    eng = r.get("engine")
    if eng not in DB_HARDEN:
        return err("config", "no hardening read for this engine")
    try:
        conn = connect_db(r)
    except Exception as e:
        return err("auth" if "auth" in str(e).lower() or "password" in str(e).lower() or "ORA-01017" in str(e) else classify(e), e)
    out, errors = {}, {}
    try:
        for name, sql in DB_HARDEN[eng]:
            try:
                cur = conn.cursor()
                cur.execute(sql)
                out[name] = [[(v if isinstance(v, (int, float)) or v is None else str(v)[:300]) for v in row] for row in cur.fetchmany(500)]
                cur.close()
            except Exception as e:
                out[name] = None
                m = _re.search(r"(ORA-\d{5}|permission denied|The SELECT permission was denied|VIEW SERVER STATE|does not exist|Invalid object name)", str(e))
                errors[name] = (m.group(1) if m else str(e).split("\n")[0])[:160]
                try:
                    conn.rollback()   # postgres: a failed statement aborts the transaction; the next query needs a clean one
                except Exception:
                    pass
        return {"ok": True, "engine": eng, "results": out, "errors": errors}
    finally:
        try:
            conn.close()
        except Exception:
            pass


def main():
    try:
        r = json.loads(sys.stdin.read() or "{}")
    except Exception:
        out(err("config", "bad request"))
        return
    ops = {"version": op_version, "hostkey": op_hostkey, "ssh_facts": op_ssh_facts, "db": op_db, "oracle_health": op_oracle_health, "oracle_plan": op_oracle_plan, "oracle_long": op_oracle_long, "oracle_ctl_test": op_oracle_ctl_test, "oracle_ctl": op_oracle_ctl, "ssh_health": op_ssh_health, "ssh_services": op_ssh_services, "oracle_audit": op_oracle_audit, "oracle_pii_scan": op_oracle_pii_scan, "db_harden": op_db_harden, "db_details": op_db_details, "db_pii_scan": op_db_pii_scan, "db_find": op_db_find, "verify_describe": op_verify_describe, "verify_chunk": op_verify_chunk, "verify_keys": op_verify_keys, "logminer_read": op_logminer_read, "repl_status": op_repl_status, "repl_cycle": op_repl_cycle}
    fn = ops.get(r.get("op"))
    if not fn:
        out(err("config", "unknown op"))
        return
    try:
        out(fn(r))
    except ImportError as e:
        out(err("missing_module", str(e)))
    except Exception as e:
        out(err(classify(e), e))


if __name__ == "__main__":
    main()
