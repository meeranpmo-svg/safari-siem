#!/usr/bin/env python3
# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
"""Minimal Cisco IOS look-alike SSH server for tests/netops-cli.test.js (paramiko). Prints the port, then serves.
Login ro / pw-ro, enable secret en-secret. Echoes input like IOS, answers a few show commands, refuses anything else."""
import socket, sys, threading
import paramiko

KEY = paramiko.RSAKey.generate(2048)
OUT = {
    "show version": "Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), Version 15.2(7)E8, RELEASE SOFTWARE (fc1)\n"
                    "ROM: Bootstrap program is C2960X boot loader\nSW1 uptime is 12 weeks, 3 days, 4 hours, 5 minutes\n"
                    "System returned to ROM by power-on\nSystem image file is \"flash:c2960x-universalk9-mz.152-7.E8.bin\"\n\n"
                    "cisco WS-C2960X-48FPD-L (APM86XXX) processor (revision B0) with 524288K bytes of memory.\n"
                    "Processor board ID FOC1234X0AB\nModel number                    : WS-C2960X-48FPD-L\n"
                    "System serial number            : FOC1234X0AB\nConfiguration register is 0xF\n",
    "show inventory": "NAME: \"1\", DESCR: \"WS-C2960X-48FPD-L\"\nPID: WS-C2960X-48FPD-L , VID: V05  , SN: FOC1234X0AB\n",
    "show running-config": "Building configuration...\nhostname SW1\nenable secret 9 $9$abcdefg\nusername admin privilege 15 secret 9 $9$zzz\n"
                           "snmp-server community S3cr3tComm RO 10\ntacacs-server key 7 0822455D0A16\nend\n",
}


class Srv(paramiko.ServerInterface):
    def check_auth_password(self, u, p):
        return paramiko.AUTH_SUCCESSFUL if (u, p) == ("ro", "pw-ro") else paramiko.AUTH_FAILED

    def get_allowed_auths(self, u):
        return "password"

    def check_channel_request(self, kind, cid):
        return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(self, *a):
        return True

    def check_channel_shell_request(self, ch):
        return True


def session(sock):
    t = paramiko.Transport(sock)
    t.add_server_key(KEY)
    try:
        t.start_server(server=Srv())
    except Exception:
        return
    ch = t.accept(20)
    if ch is None:
        return
    mode, buf = ">", ""
    ch.send("\r\nSW1>")
    awaiting = False
    try:
        while True:
            d = ch.recv(1024)
            if not d:
                break
            for c in d.decode("latin1"):
                if c in "\r\n":
                    line, buf = buf.strip(), ""
                    if awaiting:
                        awaiting = False
                        if line == "en-secret":
                            mode = "#"
                        else:
                            ch.send("\r\n% Access denied")
                        ch.send("\r\nSW1" + mode)
                        continue
                    ch.send("\r\n")
                    if line == "enable":
                        awaiting = True
                        ch.send("Password: ")
                        continue
                    if line in OUT:
                        if line == "show running-config" and mode != "#":
                            ch.send("% Invalid input detected at '^' marker.\r\n")
                        else:
                            ch.send(OUT[line].replace("\n", "\r\n"))
                    elif line and not line.startswith("terminal "):
                        ch.send("% Invalid input detected at '^' marker.\r\n")
                    ch.send("SW1" + mode)
                else:
                    buf += c
                    if not awaiting:
                        ch.send(c)
    except Exception:
        pass
    finally:
        try:
            t.close()
        except Exception:
            pass


def main():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 0))
    s.listen(8)
    print(s.getsockname()[1], flush=True)
    while True:
        c, _ = s.accept()
        threading.Thread(target=session, args=(c,), daemon=True).start()


if __name__ == "__main__":
    main()
