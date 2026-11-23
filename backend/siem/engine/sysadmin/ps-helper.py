#!/usr/bin/env python3
# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
"""
ps-helper.py - read-only PowerShell checks on Windows / Exchange servers over WinRM for the AI Server Administrators
(engine/sysadmin/runner.js). One JSON request on stdin, one JSON answer on stdout; the password never appears on a
command line or in a log.
  {"op": "version"}                                      -> {"ok": true, "pypsrp": "...", "python": "..."}
  {"op": "render", "check", "params"}                    -> {"ok": true, "script": "..."}         (tests, no network)
  {"op": "certificate", "host", "port"}                  -> {"ok": true, "fingerprint": "AB:CD:..."}   (no login)
  {"op": "run", "host", "port", "ssl", "auth", "username", "password", "pin", "check", "params", "exchange", "timeout"}
       -> {"ok": true, "data": <parsed JSON>, "errors": [...]}
Only checks listed in checks.json run: the request names a check, never a script. Parameters are validated against the
check's own schema and inserted as PowerShell single-quoted literals ('' escaping) or bounded integers.
Over HTTP (5985) the session is encrypted by NTLM / Kerberos message encryption (required); over HTTPS (5986) the
server certificate must match the SHA-256 fingerprint an administrator trusted.
Errors: {"ok": false, "kind": "missing|auth|timeout|refused|certificate|denied|input|exchange|error", "error": "..."}
"""
import hashlib, json, os, re, socket, ssl, sys

HERE = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(HERE, "checks.json"), encoding="utf-8") as _f:
    CHECKS = {c["id"]: c for c in json.load(_f)["checks"]}
EXCHANGE_PRELUDE = ("if (-not (Get-Command Get-ExchangeServer -ErrorAction SilentlyContinue)) { "
                    "try { Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn -ErrorAction Stop } "
                    "catch { throw 'EXCHANGE-SNAPIN: the Exchange Management Shell is not installed on this server' } }\n")


def out(o):
    sys.stdout.write(json.dumps(o, default=str))
    sys.stdout.flush()
    return 0


def fail(kind, msg):
    return out({"ok": False, "kind": kind, "error": str(msg)[:600]})


def lit(v):
    return "'" + str(v).replace("'", "''") + "'"


def render(check_id, params):
    c = CHECKS.get(check_id)
    if not c:
        raise ValueError("unknown check %r" % check_id)
    spec, params, vals = c.get("params") or {}, params or {}, {}
    for k in params:
        if k not in spec:
            raise ValueError("parameter %r is not allowed for %s" % (k, check_id))
    for k, s in spec.items():
        v = params.get(k, s.get("default"))
        if v is None:
            raise ValueError("parameter %r is required" % k)
        t = s["type"]
        if t == "int":
            if isinstance(v, bool) or not re.fullmatch(r"-?\d{1,6}", str(v)) or not (s["min"] <= int(v) <= s["max"]):
                raise ValueError("%s must be a whole number %d-%d" % (k, s["min"], s["max"]))
            vals[k] = str(int(v))
        elif t == "enum":
            if v not in s["values"]:
                raise ValueError("%s must be one of %s" % (k, ", ".join(s["values"])))
            vals[k] = lit(v)
        else:
            if not isinstance(v, str) or not re.fullmatch(s["pattern"], v):
                raise ValueError("%s has an invalid value" % k)
            vals[k] = lit(v)
    script = re.sub(r"\{\{(\w+)\}\}", lambda m: vals[m.group(1)], c["script"])
    return (EXCHANGE_PRELUDE if c["scope"] == "exchange" else "") + "$ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'\n" + script


def peer_fingerprint(host, port, timeout):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as s:
        with ctx.wrap_socket(s, server_hostname=host) as t:
            der = t.getpeercert(binary_form=True)
    h = hashlib.sha256(der).hexdigest().upper()
    return ":".join(h[i:i + 2] for i in range(0, len(h), 2))


def main():
    try:
        req = json.loads(sys.stdin.read() or "{}")
    except Exception as e:
        return fail("input", "bad request: %s" % e)
    op = req.get("op")
    if op == "render":
        try:
            return out({"ok": True, "script": render(req.get("check"), req.get("params"))})
        except ValueError as e:
            return fail("input", e)
    if op == "version":
        try:
            import pypsrp
            return out({"ok": True, "pypsrp": getattr(pypsrp, "__version__", "installed"), "python": sys.version.split()[0]})
        except ImportError:
            return fail("missing", "pypsrp is not installed (run install/sysadmin-setup.sh)")
    host, port, timeout = str(req.get("host") or ""), int(req.get("port") or 5985), float(req.get("timeout") or 30)
    if not re.fullmatch(r"[A-Za-z0-9.:-]{1,253}", host) or not 0 < port < 65536:
        return fail("input", "host and port required")
    if op == "certificate":
        try:
            return out({"ok": True, "fingerprint": peer_fingerprint(host, port, min(timeout, 15))})
        except socket.timeout:
            return fail("timeout", "no answer from %s:%d" % (host, port))
        except ConnectionRefusedError:
            return fail("refused", "nothing listening on %s:%d" % (host, port))
        except Exception as e:
            return fail("error", "could not read the certificate: %s" % e)
    if op != "run":
        return fail("input", "unknown op")
    try:
        script = render(req.get("check"), req.get("params"))
    except ValueError as e:
        return fail("input", e)
    try:
        from pypsrp.client import Client
    except ImportError:
        return fail("missing", "pypsrp is not installed (run install/sysadmin-setup.sh)")
    use_ssl = bool(req.get("ssl"))
    if use_ssl:
        pin = str(req.get("pin") or "").upper()
        if not pin:
            return fail("certificate", "the server's WinRM HTTPS certificate is not trusted yet")
        try:
            fp = peer_fingerprint(host, port, min(timeout, 15))
        except Exception as e:
            return fail("timeout" if isinstance(e, socket.timeout) else "error", "could not reach %s:%d (%s)" % (host, port, e))
        if fp != pin:
            return fail("certificate", "the server presented a DIFFERENT certificate than the trusted one - not logging in. Check it, then trust the new one.")
    # the pin above is checked on its own connection; pypsrp cannot pin the session's certificate, so the session also
    # carries NTLM / Kerberos message encryption (encryption="always" over HTTPS too): a certificate swapped between the
    # check and the session still sees only sealed messages. No Basic auth - the password itself never crosses the wire.
    auth = req.get("auth") if req.get("auth") in ("negotiate", "ntlm", "kerberos") else "negotiate"
    try:
        client = Client(host, port=port, ssl=use_ssl, cert_validation=False, auth=auth, username=str(req.get("username") or ""),
                        password=str(req.get("password") or ""), encryption="always",
                        connection_timeout=timeout, operation_timeout=max(20, int(timeout)), read_timeout=max(30, int(timeout) + 10))
        output, streams, had_errors = client.execute_ps(script)
    except Exception as e:
        m = str(e)
        if type(e).__name__ in ("AuthenticationError", "InvalidCredentialsError") or re.search(r"401|unauthori[sz]ed|logon failure|credentials|failed to authenticate", m, re.I):
            return fail("auth", "login refused: wrong user name / password, or the account may not use WinRM on this server (Remote Management Users)")
        if re.search(r"timed? ?out|timeout", m, re.I):
            return fail("timeout", "no WinRM answer from %s:%d" % (host, port))
        if re.search(r"refused|No route|unreachable", m, re.I):
            return fail("refused", "WinRM is not reachable on %s:%d (Enable-PSRemoting, firewall)" % (host, port))
        return fail("error", "%s: %s" % (type(e).__name__, m[:400]))
    errs = [str(x)[:300] for x in (streams.error or [])][:10]
    if any("EXCHANGE-SNAPIN" in e for e in errs):
        return fail("exchange", "the Exchange Management Shell is not installed on this server - add an Exchange server, not a Windows-only one")
    if had_errors and any(re.search(r"Access is denied|UnauthorizedAccess|PermissionDenied|isn't allowed|not have permission", e, re.I) for e in errs):
        return fail("denied", "access denied for this check: " + errs[0][:240])
    text = (output or "").strip()
    try:
        data = json.loads(text) if text else None
    except ValueError:
        data = text[:20000]
    if had_errors and data is None:
        return fail("error", (errs[0] if errs else "the check failed")[:400])
    return out({"ok": True, "data": data, "errors": errs})


if __name__ == "__main__":
    sys.exit(main())
