"""A secrets vault over HTTP, in the style of HashiCorp Vault. Standard library only.

    python3 vault.py <port> <config.json>
config.json: {"token": "s.abc", "secrets": {"prod-db": "password123"}}

GET /v1/sys/health          {"sealed": false}
GET /v1/secret/             secret names (needs the token)
GET /v1/secret/<name>       {"data": {"value": "..."}} (needs the token)
The token goes in `X-Vault-Token: <token>` or `Authorization: Bearer <token>`.
"""
import json, sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CFG = json.load(open(sys.argv[2]))

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def send(self, status, body):
        data = json.dumps(body).encode()
        self.send_response(status); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)
    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/v1/sys/health":
            return self.send(200, {"sealed": False, "initialized": True})
        token = self.headers.get("X-Vault-Token") or self.headers.get("Authorization", "").removeprefix("Bearer ")
        if token != CFG.get("token"):
            return self.send(403, {"errors": ["permission denied"]})
        secrets = CFG.get("secrets", {})
        if path.rstrip("/") == "/v1/secret":
            return self.send(200, {"data": {"keys": sorted(secrets)}})
        name = path.removeprefix("/v1/secret/")
        if name in secrets:
            return self.send(200, {"data": {"value": secrets[name]}})
        self.send(404, {"errors": ["no such secret"]})

ThreadingHTTPServer(("0.0.0.0", int(sys.argv[1])), Handler).serve_forever()
