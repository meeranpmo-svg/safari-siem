#!/usr/bin/env python3
# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
"""
cli-helper.py - read-only SSH sessions to network devices for the AI Network Engineer (engine/netops/cli.js).
One JSON request on stdin, one JSON answer on stdout. The password never appears on the command line or in a log.
  {"op": "version"}                                   -> {"ok": true, "netmiko": "4.8.0", "paramiko": "...", "python": "..."}
  {"op": "hostkey", "host", "port", "timeout"}        -> {"ok": true, "type": "ssh-rsa", "key": "<base64>", "fingerprint": "SHA256:..."}
       reads the device's SSH host key WITHOUT logging in (no username or password is sent), so an administrator can
       compare the fingerprint before trusting it
  {"op": "run", "host", "port", "device_type", "username", "password", "secret", "known_host": {"type", "key"},
   "commands": [...], "textfsm": false, "timeout"}  -> {"ok": true, "prompt": "sw1#", "results": [{command, output, parsed?}]}
       connects only when the device presents the pinned host key (strict checking, no auto-add); the command list has
       already been checked against the read-only allowlist by cli.js, and is checked again here (show / get only)
  Approved tasks (netops/tasks.js, after a person approved the change plan; the WRITE login is used):
  {"op": "config", ..., "lines": [...]}   -> {"ok": true, "output"}   configuration lines, each checked against CFG_OK below
  {"op": "save", ...}                     -> {"ok": true}             write memory
  {"op": "copy", ..., "src", "image", "md5"} -> {"ok": true, "md5"}   copy <src> flash:<image>, then verify /md5 must match
  {"op": "reload", ..., "minutes" | "cancel": true} -> {"ok": true}   "reload in N" (scheduled) or "reload cancel"
Errors: {"ok": false, "kind": "missing|auth|timeout|hostkey-changed|hostkey-unknown|refused|input|error", "error": "..."}
"""
import base64, hashlib, json, os, re, socket, sys, tempfile


def out(obj):
    sys.stdout.write(json.dumps(obj))
    sys.stdout.flush()


def fail(kind, msg):
    out({"ok": False, "kind": kind, "error": str(msg)[:500]})
    return 0


def fp(key_b64):
    return "SHA256:" + base64.b64encode(hashlib.sha256(base64.b64decode(key_b64)).digest()).decode().rstrip("=")


HOSTKEY_CHANGED = ("the device presented a DIFFERENT SSH host key than the trusted one - not logging in (device replaced "
                   "or re-keyed, or someone in the middle). Check the device, then read and trust the new key.")
SAFE = re.compile(r"^(show|get) [A-Za-z0-9 ./:_\-|]+$")
SAFE_COMWARE = re.compile(r"^display [A-Za-z0-9 ./:_\-|]+$")   # H3C / HPE Comware: "display" is the read-only verb
# the only configuration lines an approved task may push (second check after tasks.js built them)
IFN = r"(?:GigabitEthernet|TenGigabitEthernet|TwentyFiveGigE|FortyGigabitEthernet|HundredGigE|FastEthernet|Ethernet|Gi|Te|Tw|Fo|Hu|Fa|Eth)\d{1,2}(?:/\d{1,3}){1,3}|(?:Port-channel|Po)\d{1,3}"
CFG_OK = [re.compile(x, re.I) for x in (
    r"^vlan \d{1,4}$", r"^no vlan \d{1,4}$", r"^ name [A-Za-z0-9_.-]{1,32}$",
    r"^interface (?:" + IFN + r")$",
    r"^ switchport mode access$", r"^ no switchport mode$", r"^ switchport access vlan \d{1,4}$", r"^ no switchport access vlan$",
    r"^ switchport trunk allowed vlan (?:add|remove) \d{1,4}(?:,\d{1,4}){0,31}$",
    r"^ description [A-Za-z0-9 _.:/()#-]{1,80}$", r"^ no description$", r"^ shutdown$", r"^ no shutdown$",
    r"^boot system flash:[A-Za-z0-9._/-]{1,160}$", r"^no boot system$")]
COPY_SRC = re.compile(r"^(?:tftp|ftp|http|https)://[A-Za-z0-9.-]{1,253}(?::\d{1,5})?/[A-Za-z0-9._/-]{1,200}$")
IMAGE = re.compile(r"^[A-Za-z0-9._-]{1,120}\.bin$")


def main():
    try:
        req = json.loads(sys.stdin.read() or "{}")
    except Exception as e:
        return fail("input", "bad request: %s" % e)
    op = req.get("op")
    try:
        import paramiko
    except ImportError:
        return fail("missing", "Python package paramiko / netmiko is not installed (run install/netops-cli-setup.sh)")
    if op == "version":
        try:
            import netmiko
        except ImportError:
            return fail("missing", "Netmiko is not installed (run install/netops-cli-setup.sh)")
        out({"ok": True, "netmiko": netmiko.__version__, "paramiko": paramiko.__version__, "python": sys.version.split()[0]})
        return 0

    host, port, timeout = str(req.get("host") or ""), int(req.get("port") or 22), float(req.get("timeout") or 20)
    if not host or not (0 < port < 65536):
        return fail("input", "host and port required")

    if op == "hostkey":
        sock = None
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
            t = paramiko.Transport(sock)
            t.start_client(timeout=timeout)
            k = t.get_remote_server_key()
            t.close()
            b = k.get_base64()
            out({"ok": True, "type": k.get_name(), "key": b, "fingerprint": fp(b)})
        except socket.timeout:
            return fail("timeout", "no answer from %s:%d" % (host, port))
        except ConnectionRefusedError:
            return fail("refused", "SSH is not open on %s:%d (connection refused)" % (host, port))
        except Exception as e:
            return fail("error", "could not read the SSH host key: %s" % e)
        finally:
            try:
                sock and sock.close()
            except Exception:
                pass
        return 0

    if op not in ("run", "config", "save", "copy", "reload"):
        return fail("input", "unknown op")
    try:
        from netmiko import ConnectHandler
        from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException
    except ImportError:
        return fail("missing", "Netmiko is not installed (run install/netops-cli-setup.sh)")
    cmds = req.get("commands") or []
    safe = SAFE_COMWARE if req.get("device_type") == "hp_comware" else SAFE
    if op == "run" and (not cmds or len(cmds) > 12 or any(not isinstance(c, str) or not safe.match(c) or len(c) > 200 for c in cmds)):
        return fail("input", "only read-only show / get (display on Comware) commands are allowed")
    lines = req.get("lines") or []
    if op == "config" and (not lines or len(lines) > 200 or any(not isinstance(l, str) or "\n" in l or "\r" in l or not any(r.match(l) for r in CFG_OK) for l in lines)):
        bad_line = next((l for l in lines if not isinstance(l, str) or not any(r.match(l) for r in CFG_OK)), "")
        return fail("input", "configuration line not allowed for an approved task: %r" % str(bad_line)[:80])
    if op == "copy" and (not COPY_SRC.match(str(req.get("src") or "")) or not IMAGE.match(str(req.get("image") or "")) or not re.match(r"^[0-9a-f]{32}$", str(req.get("md5") or ""))):
        return fail("input", "copy needs a tftp/ftp/http(s) source, a .bin image name and the approved MD5")
    if op == "reload" and not req.get("cancel") and not (isinstance(req.get("minutes"), int) and 5 <= req["minutes"] <= 1440):
        return fail("input", "reload: minutes 5-1440, or cancel")
    kh = req.get("known_host") or {}
    if not kh.get("type") or not kh.get("key"):
        return fail("hostkey-unknown", "the device's SSH host key is not trusted yet")
    fd, khf = tempfile.mkstemp(prefix="sentra-kh-")
    try:
        with os.fdopen(fd, "w") as f:
            f.write("%s %s %s\n" % (host if port == 22 else "[%s]:%d" % (host, port), kh["type"], kh["key"]))
        params = dict(device_type=req.get("device_type") or "cisco_ios", host=host, port=port,
                      username=str(req.get("username") or ""), password=str(req.get("password") or ""),
                      secret=str(req.get("secret") or ""), ssh_strict=True, system_host_keys=False,
                      alt_host_keys=True, alt_key_file=khf, use_keys=False, allow_agent=False,
                      conn_timeout=timeout, auth_timeout=timeout, banner_timeout=timeout, fast_cli=False)
        results = []
        with ConnectHandler(**params) as conn:
            if params["secret"]:
                try:
                    conn.enable()
                except Exception as e:
                    results.append({"command": "enable", "error": "enable failed: %s" % str(e)[:200]})
            prompt = conn.find_prompt()
            if op == "config":
                o = conn.send_config_set(lines, read_timeout=float(req.get("read_timeout") or 120), cmd_verify=True)
                if re.search(r"^% (?:Invalid|Incomplete|Ambiguous)|^%.*(?:not allowed|Error)", o, re.M):
                    out({"ok": False, "kind": "error", "error": "the device refused a line: " + next((l for l in o.splitlines() if l.startswith("%")), "")[:200], "output": o[-4000:]})
                    return 0
                out({"ok": True, "prompt": prompt, "output": o[-8000:]})
                return 0
            if op == "save":
                o = conn.save_config()
                out({"ok": True, "output": str(o)[-2000:]})
                return 0
            if op == "copy":
                img = req["image"]
                o = conn.send_command_timing("copy %s flash:%s" % (req["src"], img), read_timeout=60)
                if re.search(r"Destination filename", o):
                    o += conn.send_command_timing("\n", read_timeout=1800, last_read=30)
                if re.search(r"over ?write", o, re.I):
                    conn.send_command_timing("n", read_timeout=30)
                    out({"ok": False, "kind": "error", "error": "flash:%s already exists on the device - not overwritten" % img})
                    return 0
                if re.search(r"%Error|No space|Insufficient", o, re.I):
                    out({"ok": False, "kind": "error", "error": "copy failed: " + next((l for l in o.splitlines() if "%" in l or "space" in l.lower()), o[-200:])[:300]})
                    return 0
                v = conn.send_command("verify /md5 flash:%s" % img, read_timeout=900)
                m = re.search(r"=\s*([0-9a-f]{32})", v)
                if not m or m.group(1) != req["md5"]:
                    out({"ok": False, "kind": "error", "error": "MD5 of flash:%s is %s, approved %s - do not boot this image" % (img, m.group(1) if m else "unknown", req["md5"])})
                    return 0
                out({"ok": True, "md5": m.group(1)})
                return 0
            if op == "reload":
                if req.get("cancel"):
                    o = conn.send_command_timing("reload cancel", read_timeout=30)
                else:
                    o = conn.send_command_timing("reload in %d" % req["minutes"], read_timeout=30)
                    for _ in range(3):
                        if re.search(r"Save\?|\[yes/no\]", o):
                            o += conn.send_command_timing("no", read_timeout=30)   # saved just before by op save
                        elif re.search(r"\[confirm\]", o):
                            o += conn.send_command_timing("\n", read_timeout=30)
                        else:
                            break
                out({"ok": True, "output": o[-2000:]})
                return 0
            for c in cmds:
                try:
                    o = conn.send_command(c, read_timeout=float(req.get("read_timeout") or 60))
                    r = {"command": c, "output": o}
                    if req.get("textfsm"):
                        try:  # parse the output already read - the command is not sent a second time
                            try:
                                from netmiko.utilities import get_structured_data_textfsm as gsd
                            except ImportError:  # Netmiko < 4.3
                                from netmiko.utilities import get_structured_data as gsd
                            p = gsd(o, platform=params["device_type"], command=c)
                            if isinstance(p, list):
                                r["parsed"] = p
                        except Exception:
                            pass
                    results.append(r)
                except Exception as e:
                    results.append({"command": c, "error": str(e)[:300]})
        out({"ok": True, "prompt": prompt, "results": results})
    except NetmikoAuthenticationException:
        return fail("auth", "login refused: wrong username / password, or the account may not log in over SSH")
    except NetmikoTimeoutException as e:
        # Netmiko reports every paramiko SSHException (a refused host key included) as a timeout: look at the cause
        c, seen = e, 0
        while c is not None and seen < 6:
            if isinstance(c, paramiko.BadHostKeyException) or "not found in known_hosts" in str(c):
                return fail("hostkey-changed", HOSTKEY_CHANGED)
            c, seen = c.__cause__ or c.__context__, seen + 1
        first = next((l.strip() for l in str(e).splitlines() if l.strip()), "timeout")
        return fail("timeout", "no SSH answer from %s:%d (%s)" % (host, port, first[:160]))
    except paramiko.BadHostKeyException:
        return fail("hostkey-changed", HOSTKEY_CHANGED)
    except paramiko.SSHException as e:
        if "not found in known_hosts" in str(e):
            return fail("hostkey-changed", HOSTKEY_CHANGED)
        return fail("error", "SSH error: %s" % e)
    except Exception as e:
        return fail("error", "%s: %s" % (type(e).__name__, e))
    finally:
        try:
            os.unlink(khf)
        except Exception:
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
