"""Mock HTTP API: replies with the JSON configured per path. Standard library only.

    python3 mock_api.py <port> <routes.json>
routes.json: {"/health": {"status": 200, "json": {"ok": true}}, "/admin": {"status": 403, "json": {...}}}
Unknown paths return 404.
"""
import json, sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROUTES = json.load(open(sys.argv[2]))

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def reply(self):
        route = ROUTES.get(self.path.split("?")[0], {"status": 404, "json": {"error": "not found"}})
        data = json.dumps(route.get("json", {})).encode()
        self.send_response(int(route.get("status", 200))); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)
    do_GET = do_POST = do_PUT = do_DELETE = reply

ThreadingHTTPServer(("0.0.0.0", int(sys.argv[1])), Handler).serve_forever()
