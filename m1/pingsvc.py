#!/usr/bin/env python3
"""PingSweeper - a deliberately vulnerable "ping" web tool (OS command injection).
Usage: pingsvc.py <port> [tls-cert.pem [tls-key.pem]]
Serves a form on GET / and runs the target through a shell on GET /ping?ip=...
The shell pipe is intentional: users who chain ; | && get OS command execution.
A handful of hidden paths (robots.txt, backup.php, config.bak, .git/HEAD, admin)
exist for active recon (dirb/gobuster with -x php,html,js,bak).
"""
import html
import os
import ssl
import sys
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

PAGE = """<!DOCTYPE html>
<html><head><title>PingSweeper</title>
<style>body{font-family:monospace;margin:3em;background:#111;color:#8f8}
h1{color:#7c7} input{background:#222;color:#8f8;border:1px solid #464;padding:6px}
button{background:#353;color:#0f0;border:1px solid #464;padding:6px 12px}
pre{background:#0a0a0a;padding:1em;border:1px solid #262;overflow:auto}
.meta{font-size:12px;color:#575;margin-top:2.5em}</style>
</head><body>
<h1>PingSweeper &mdash; network diagnostics</h1>
<form action="/ping" method="get">
  Target IP: <input type="text" name="ip" placeholder="10.10.10.1">
  <button>Ping</button>
</form>
<hr><pre>OUTPUT</pre>
<div class="meta">PingSweeper v1.0 &bull; <a href="/robots.txt">robots</a> &bull; <a href="/index.js">app.js</a></div>
</body></html>"""

# hidden content -> active recon fodder: robots.txt, backup.php, config.bak,
# .git/HEAD, admin/, index.js. Served regardless of extension.
HIDDEN = {
    "/robots.txt": ("text/plain",
        "User-agent: *\r\n"
        "Disallow: /admin\r\n"
        "Disallow: /backup.php\r\n"
        "Disallow: /config.bak\r\n"
        "Disallow: /.git/\r\n"
        "Disallow: /dev\r\n"
        "Disallow: /logs\r\n"
        "Disallow: /temp\r\n"
        "\r\n# the /ping tool trusts its input\r\n".encode()),
    "/backup.php": ("text/html; charset=utf-8",
        b"<!DOCTYPE html><html><head><title>PingSweeper - legacy backup</title></head>"
        b"<body><h1>Legacy backup of the old ping handler</h1>"
        b"<pre>&lt;?php\n"
        b'"  $ip = $_GET[\'ip\'];\n'
        b'"  system("ping -c 3 " . $ip);   // old tool kept as backup\n'
        b"?&gt;</pre>"
        b"<!-- replaced by /ping in v2; the config lives in /config.bak --></body></html>"),
    "/config.bak": ("text/plain",
        b"[ping]\n"
        b"command = ping -c 3 {ip}\n"
        b"timeout = 5\n"
        b"# {ip} is handed to the shell as-is -> served by /ping\n"
        b"\n"
        b"[web]\n"
        b"port = 80\n"
        b"cert = /srv/www/cert.pem\n"
        b"\n"
        b"[admin]\n"
        b"console = /admin.html\n"
        b"default_user = admin\n"
        b"default_pass = admin\n"),
    "/admin.html": ("text/html; charset=utf-8",
        b"<!DOCTYPE html><html><body><h1>Admin console</h1>"
        b"<p>default login: <b>admin</b> / <b>admin</b></p>"
        b"<p>Legacy management UI - the diagnostic tool was moved to <a href=\"/backup.php\">/backup.php</a></p>"
        b"</body></html>"),
    "/admin/login.php": ("text/html; charset=utf-8",
        b"<!DOCTYPE html><html><body><h1>Admin login</h1>"
        b"<p>admin / admin (see <a href=\"/config.bak\">/config.bak</a>)</p></body></html>"),
    "/.git/HEAD": ("text/plain", b"ref: refs/heads/main\n"),
    "/index.js": ("application/javascript; charset=utf-8",
        b"/* PingSweeper front-end */\n"
        b"function ping(ip){ location.href = '/ping?ip=' + encodeURIComponent(ip); }\n"
        b"// legacy handler: see /backup.php\n"),
}

DEFAULT_OUTPUT = ("Enter a Target IP and hit Ping.\n"
                  "The tool accepts one host - try 10.10.10.1.\n"
                  "Authorized diagnostics only.")


class ProxyHandler(BaseHTTPRequestHandler):
    server_version = "PingSweeper/1.0"
    sys_version = ""

    def _render(self, output: str):
        body = PAGE.replace("OUTPUT", html.escape(output))
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body.encode())))
        self.send_header("X-Frame-Options", "DENY")
        self.end_headers()
        self.wfile.write(body.encode())

    def _serve_hidden(self, path: str):
        ctype, body = HIDDEN[path]
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        if path in HIDDEN:
            self._serve_hidden(path)
        elif path == "/ping":
            ip = urllib.parse.parse_qs(parsed.query).get("ip", [""])[0].strip()
            if not ip:
                self._render("Error: missing 'ip' parameter")
                return
            # INTENTIONALLY VULNERABLE: unsanitised input goes straight into a shell
            out = os.popen("ping -c 3 " + ip + " 2>&1").read()
            self._render(out)
        elif path == "/":
            self._render(DEFAULT_OUTPUT)
        else:
            self.send_error(404, "Not Found")   # so dirb/ffuf can see real 404s

    def log_message(self, *args):         # keep stdout clean for the container logs
        pass


if __name__ == "__main__":
    port = int(sys.argv[1])
    cert = sys.argv[2] if len(sys.argv) > 2 else None
    key = sys.argv[3] if len(sys.argv) > 3 else cert
    srv = HTTPServer(("0.0.0.0", port), ProxyHandler)
    if cert:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    print("pingsweeper listening on %d (%s)" % (port, "TLS" if cert else "plain"), flush=True)
    srv.serve_forever()