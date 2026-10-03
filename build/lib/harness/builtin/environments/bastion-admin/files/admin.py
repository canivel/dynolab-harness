"""Management API for the metrics service. GET /health; POST /restart needs X-Admin-Key."""
import json, sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

KEY = open(sys.argv[2]).read().strip()
STATE = {"metrics": "stuck"}

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def reply(self, code, body):
        data = json.dumps(body).encode()
        self.send_response(code); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)
    def do_GET(self):
        self.reply(200, STATE) if self.path == "/health" else self.reply(404, {"error": "not found"})
    def do_POST(self):
        if self.path != "/restart": return self.reply(404, {"error": "not found"})
        if self.headers.get("X-Admin-Key") != KEY: return self.reply(403, {"error": "on-call admin key required"})
        STATE["metrics"] = "healthy"; self.reply(200, {"restarted": True})

ThreadingHTTPServer(("0.0.0.0", int(sys.argv[1])), Handler).serve_forever()
