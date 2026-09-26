#!/usr/bin/env python3
"""Disposable HTTPS alarm receiver for scripts/e2e.sh: appends each POST body to a JSONL file."""
import http.server
import ssl
import sys

OUT = sys.argv[1]


class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        n = min(int(self.headers.get("Content-Length", "0")), 65536)
        body = self.rfile.read(n)
        with open(OUT, "ab") as f:
            f.write(body.replace(b"\n", b" ") + b"\n")
        self.send_response(204)
        self.end_headers()

    def log_message(self, *args):
        pass


srv = http.server.HTTPServer(("0.0.0.0", 8443), Handler)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain("/e2e/pki/alarms.pem", "/e2e/pki/alarms-key.pem")
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
srv.serve_forever()
