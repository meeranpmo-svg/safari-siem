# Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
"""The resident Python service - migration step 9a (docs/PYTHON-MIGRATION.md). One long-running process instead of one
process per request: it keeps the stores it has read in memory (store.cached) and brings them up to date on each call
by reading only what the Node.js engine appended (Collection.refresh) - so a read route costs what the work costs, not
a Python start-up and a full read of the store.

  python3 -I pyengine/serve.py <socket path>

It listens on a Unix socket only (no TCP port): the engine creates the socket's folder (mode 0700) and is the only one
that can connect. The engine still does the sign-in, role and request checks; this service only runs the operations of
run.py that READ the store (the device readers, which carry credentials, keep their own process per call). One call at a
time (a lock), so a refresh never runs while another call reads. The process exits when the engine's stdin closes.
  POST /call  {op, ...}  → the operation's JSON answer         GET /health → {ok, python, ops, stores}
Standard library only (Python 3.8+).
"""
import json
import os
import socketserver
import sys
import threading
from http.server import BaseHTTPRequestHandler

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import store  # noqa: E402
import run  # noqa: E402

store.RESIDENT = True
# only the operations that read the store - never a device reader (credentials stay one-process-per-call)
# an explicit list, never a prefix ('virt.' is also the vCenter / Prism readers, which carry credentials); the same list
# as RESIDENT_OPS in engine/pyengine.js - tests/py-resident.test.js compares them
READ_OPS = ['consent.apply', 'consent.get', 'consent.stats', 'consent.last', 'assets.create', 'ai.sanitise_pair', 'ai.validate', 'desk.config', 'desk.patch_request', 'desk.patch_endorse', 'budget.import', 'budget.line', 'budget.remove', 'budget.settings', 'support.put', 'support.verify', 'support.retire', 'support.settings', 'support.import', 'locations.create', 'locations.edit', 'locations.delete', 'ownership.assign', 'ownership.service', 'ownership.import', 'licences.save', 'licences.retire', 'stocktake.open', 'stocktake.scan', 'stocktake.close', 'findings.status', 'cmdb.add', 'assets.edit', 'assets.transition', 'assets.move', 'assets.assign', 'assets.list', 'assets.detail', 'assets.lookup', 'assets.software', 'assets.licences', 'assets.cmdb', 'roles.list', 'roles.me', 'roles.approvers', 'roles.save', 'roles.remove', 'roles.assign',
            'grc.drafts', 'grc.draft', 'grc.drills', 'grc.drill', 'grc.drill_systems', 'grc.drill_summary', 'grc.draft_put', 'grc.draft_status', 'grc.draft_upload', 'grc.draft_delete', 'grc.drill_put', 'grc.drill_result', 'grc.drill_signoff', 'grc.drill_cancel', 'grc.drill_upload', 'grc.drill_delete', 'virtplans.changes', 'virtplans.change',
            'store.read', 'store.verify_audit', 'store.audit_tail']
LOCK = threading.Lock()
MAX_BODY = 4 * 1048576


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, *a):   # quiet: the engine logs
        pass

    def _send(self, code, obj):
        data = json.dumps(obj, separators=(',', ':')).encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path != '/health':
            return self._send(404, {'ok': False, 'error': 'not found'})
        self._send(200, {'ok': True, 'python': sys.version.split()[0], 'ops': READ_OPS, 'stores': len(store._CACHE)})

    def do_POST(self):
        if self.path != '/call':
            return self._send(404, {'ok': False, 'error': 'not found'})
        n = int(self.headers.get('Content-Length') or 0)
        if n <= 0 or n > MAX_BODY:
            return self._send(413 if n > MAX_BODY else 400, {'ok': False, 'error_class': 'protocol', 'error': 'bad request size'})
        try:
            req = json.loads(self.rfile.read(n).decode('utf-8'))
        except ValueError:
            return self._send(400, {'ok': False, 'error_class': 'protocol', 'error': 'the request is not JSON'})
        op = req.get('op') if isinstance(req, dict) else None
        if op not in READ_OPS:
            return self._send(400, {'ok': False, 'error_class': 'config', 'error': 'not a resident operation: %r' % op})
        try:
            with LOCK:
                out = run.OPS[op](req)
        except Exception as e:   # a failing call answers an error; the engine then answers from Node.js
            out = {'ok': False, 'error_class': 'protocol', 'error': '%s: %s' % (type(e).__name__, str(e)[:300])}
        self._send(200, out)


class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


def main():
    path = sys.argv[1]
    os.umask(0o077)
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
    srv = Server(path, Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    sys.stdout.write('ready\n')
    sys.stdout.flush()
    try:
        sys.stdin.read()   # the engine holds our stdin: when it goes, so do we
    finally:
        srv.shutdown()
        try:
            os.unlink(path)
        except OSError:
            pass


if __name__ == '__main__':
    main()
