#!/usr/bin/env python3
# Copyright (c) 2026 Zyberon Information Technology. All rights reserved. Proprietary and confidential - see LICENSE.
# build-agents.py - the agent downloads of the platform (Agents & Downloads page, agents.html), built by install-dashboards.sh
# into <dashboards>/agents/ from the agents in this checkout:
#   sentra-asset-agent.ps1         IT asset agent for Windows, plain PowerShell - nothing to install (remote project sites)
#   sentra-siem-windows-agent.zip  SIEM: Windows event-log forwarder (install-agent.ps1, sentra-agent.ps1, uninstall-agent.ps1)
#   sentra-siem-linux-forwarder.tar.gz   SIEM: rsyslog forwarder for Linux servers
#   itam-agent.zip / itam-agent.tar.gz   IT asset agent (Node.js) for Windows / Linux / macOS where Node.js is present
# and manifest.json with each file's size and SHA-256 (the page shows it; the install commands check it). No secret is in any
# package: the enrolment key / ingest token is created on the platform and handed over separately, once.
#   python3 build-agents.py <stage-dir> <repo-root>
import hashlib, io, json, os, sys, tarfile, time, zipfile

def main(stage, root):
    out = os.path.join(stage, 'agents'); os.makedirs(out, exist_ok=True)
    itam = os.path.join(root, 'backend', 'itam', 'agent'); win = os.path.join(root, 'backend', 'siem', 'agents', 'windows'); lin = os.path.join(root, 'backend', 'siem', 'agents', 'linux')
    items = []
    def rel(base, names):
        return [(os.path.join(base, n), n) for n in names if os.path.isfile(os.path.join(base, n))]
    def walk(base, skip=()):
        res = []
        for d, _, fs in os.walk(base):
            for f in sorted(fs):
                p = os.path.join(d, f); r = os.path.relpath(p, base)
                if r.startswith(skip) or '__pycache__' in r or r.endswith(('.pyc', '.log')): continue
                res.append((p, r))
        return sorted(res, key=lambda x: x[1])
    def zipit(name, files, prefix):
        with zipfile.ZipFile(os.path.join(out, name), 'w', zipfile.ZIP_DEFLATED) as z:
            for p, r in files:
                zi = zipfile.ZipInfo(prefix + '/' + r.replace(os.sep, '/'), date_time=(2026, 1, 1, 0, 0, 0)); zi.compress_type = zipfile.ZIP_DEFLATED; zi.external_attr = 0o644 << 16
                with open(p, 'rb') as fh: z.writestr(zi, fh.read())
    def tarit(name, files, prefix):
        with tarfile.open(os.path.join(out, name), 'w:gz') as t:
            for p, r in files:
                ti = t.gettarinfo(p, prefix + '/' + r.replace(os.sep, '/')); ti.uid = ti.gid = 0; ti.uname = ti.gname = 'root'; ti.mtime = 1767225600
                ti.mode = 0o755 if r.endswith('.sh') else 0o644
                with open(p, 'rb') as fh: t.addfile(ti, fh)
    def add(id_, file, title, platform, kind, needs, purpose):
        p = os.path.join(out, file)
        if not os.path.isfile(p): return
        h = hashlib.sha256(open(p, 'rb').read()).hexdigest()
        items.append({'id': id_, 'file': file, 'title': title, 'platform': platform, 'kind': kind, 'needs': needs, 'purpose': purpose, 'bytes': os.path.getsize(p), 'sha256': h})
    src = os.path.join(itam, 'sentra-asset-agent.ps1')
    if os.path.isfile(src):
        with open(src, 'rb') as a, open(os.path.join(out, 'sentra-asset-agent.ps1'), 'wb') as b: b.write(a.read())
        add('asset-windows', 'sentra-asset-agent.ps1', 'Asset agent for Windows', 'Windows 10 / 11, Windows Server 2016+', 'asset', 'nothing - PowerShell 5.1 is built in',
            'Hardware, OS, installed software and patch level to IT Asset Management - for computers at project sites not on the company network (outbound HTTPS only).')
    w = rel(win, ['install-agent.ps1', 'sentra-agent.ps1', 'uninstall-agent.ps1', 'README.md'])
    if w:
        zipit('sentra-siem-windows-agent.zip', w, 'sentra-siem-windows-agent')
        add('siem-windows', 'sentra-siem-windows-agent.zip', 'SIEM agent for Windows (event logs)', 'Windows Server 2012 R2+, Windows 10 / 11', 'siem', 'nothing - PowerShell 5.1 is built in',
            'Security, System, PowerShell and Sysmon event logs to the SIEM over HTTPS, queued on disk while the platform cannot be reached.')
    l = walk(lin)
    if l:
        tarit('sentra-siem-linux-forwarder.tar.gz', l, 'sentra-siem-linux-forwarder')
        add('siem-linux', 'sentra-siem-linux-forwarder.tar.gz', 'SIEM forwarder for Linux (rsyslog)', 'Linux with rsyslog 8+', 'siem', 'rsyslog (installed on most distributions)',
            'System and authentication logs to the SIEM over TCP / TLS.')
    n = walk(itam, skip=('sentra-asset-agent.ps1',))
    if n:
        zipit('itam-agent.zip', n, 'itam-agent'); tarit('itam-agent.tar.gz', n, 'itam-agent')
        add('asset-node-win', 'itam-agent.zip', 'Asset agent (Node.js) for Windows', 'Windows with Node.js 18+', 'asset', 'Node.js 18 or newer', 'The same inventory as the PowerShell agent, with a local queue - for computers that already have Node.js.')
        add('asset-node-unix', 'itam-agent.tar.gz', 'Asset agent for Linux / macOS', 'Linux, macOS with Node.js 18+', 'asset', 'Node.js 18 or newer', 'Hardware, OS, installed packages and patch level to IT Asset Management (outbound HTTPS only).')
    with open(os.path.join(out, 'manifest.json'), 'w') as fh:
        json.dump({'built': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), 'items': items}, fh, indent=1)
    print('==> agent downloads: %d package(s) in %s' % (len(items), out))
    return 0 if items else 1

if __name__ == '__main__':
    if len(sys.argv) != 3: print('usage: build-agents.py <stage-dir> <repo-root>'); sys.exit(2)
    sys.exit(main(sys.argv[1], sys.argv[2]))
