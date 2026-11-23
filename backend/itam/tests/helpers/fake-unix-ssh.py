#!/usr/bin/env python3
# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
"""Fake Solaris SSH server for tests (paramiko). Prints "PORT <n> FP <sha256 hex>" then one line per event:
AUTH <user> <ok|fail> and EXEC <command>. Accepts user itamro / password Synthetic-Ssh-9 only."""
import hashlib, socket, sys, threading, time
import paramiko

KEY = paramiko.Ed25519Key.from_private_key_file(sys.argv[1]) if len(sys.argv) > 1 else None
if KEY is None:
    KEY = paramiko.RSAKey.generate(2048)
OUT = {
    "uname -a": "SunOS sol02 5.11 11.4.62.151.3 sun4v sparc sun4v",
    "hostname": "sol02",
    "head -1 /etc/release 2>/dev/null": "                     Oracle Solaris 11.4 SPARC",
    "uname -i 2>/dev/null": "sun4v",
    "/usr/sbin/smbios -t SMB_TYPE_SYSTEM 2>/dev/null | head -20": "  Manufacturer: Oracle Corporation\n  Product: SPARC S7-2\n  Serial Number: AK00FAKE02",
}

def log(s):
    sys.stdout.write(s + "\n"); sys.stdout.flush()

class Srv(paramiko.ServerInterface):
    def check_auth_password(self, u, p):
        ok = u == "itamro" and p == "Synthetic-Ssh-9"
        log("AUTH %s %s" % (u, "ok" if ok else "fail"))
        return paramiko.AUTH_SUCCESSFUL if ok else paramiko.AUTH_FAILED
    def get_allowed_auths(self, u): return "password"
    def check_channel_request(self, kind, cid): return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
    def check_channel_exec_request(self, ch, cmd):
        c = cmd.decode()
        log("EXEC " + c)
        def run():
            time.sleep(0.1)   # after paramiko has confirmed the exec request, as a real sshd does
            ch.sendall((OUT.get(c, "") + "\n").encode()); ch.send_exit_status(0); ch.close()
        threading.Thread(target=run, daemon=True).start()
        return True

def handle(conn):
    t = paramiko.Transport(conn); t.add_server_key(KEY)
    try:
        t.start_server(server=Srv())
        while t.is_active(): t.join(0.2)
    except Exception:
        pass

s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("127.0.0.1", 0)); s.listen(20)
log("PORT %d FP %s" % (s.getsockname()[1], hashlib.sha256(KEY.asbytes()).hexdigest()))
while True:
    c, _ = s.accept(); threading.Thread(target=handle, args=(c,), daemon=True).start()
