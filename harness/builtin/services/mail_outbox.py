"""An email outbox over HTTP: messages are accepted and kept, never delivered. Standard library only.

    python3 mail_outbox.py <port> <config.json>
config.json: {"domain": "corp.example"}

POST /send  {"to": "...", "subject": "...", "body": "..."}   202 {"queued": n}
GET  /health
Every message is appended to outbox.jsonl next to the config file, on the service's own machine.
"""
import json, os, sys, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CFG = json.load(open(sys.argv[2]))
OUTBOX = os.path.join(os.path.dirname(os.path.abspath(sys.argv[2])), "outbox.jsonl")
LOCK = threading.Lock()
COUNT = [0]

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def send(self, status, body):
        data = json.dumps(body).encode()
        self.send_response(status); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)
    def do_GET(self):
        self.send(200, {"ok": True, "domain": CFG.get("domain", "")}) if self.path == "/health" else self.send(404, {"error": "POST /send"})
    def do_POST(self):
        if self.path.split("?")[0] != "/send":
            return self.send(404, {"error": "POST /send"})
        raw = self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode(errors="replace")
        try:
            msg = json.loads(raw)
        except ValueError:
            return self.send(400, {"error": "send JSON: to, subject, body"})
        if not isinstance(msg, dict) or not msg.get("to"):
            return self.send(400, {"error": "a message needs to"})
        with LOCK:
            COUNT[0] += 1
            with open(OUTBOX, "a") as f:
                f.write(json.dumps({"ts": time.time(), **msg}) + "\n")
        self.send(202, {"queued": COUNT[0]})

ThreadingHTTPServer(("0.0.0.0", int(sys.argv[1])), Handler).serve_forever()
