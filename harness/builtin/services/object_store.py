"""S3-style object storage over HTTP. Standard library only.

    python3 object_store.py <port> <config.json>
config.json: {"objects": {"exports/q3_sales.csv": "region,sales\\n..."}, "writable": false}

GET /                 every key, as JSON
GET /<prefix>/        keys under a prefix, as JSON
GET /<key>            the object
PUT /<key>            store an object (only when writable)
DELETE /<key>         remove an object (only when writable)
"""
import json, sys, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CFG = json.load(open(sys.argv[2]))
OBJECTS = {k.strip("/"): v.encode() if isinstance(v, str) else bytes(v) for k, v in CFG.get("objects", {}).items()}
LOCK = threading.Lock()

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def send(self, status, body, kind="application/json"):
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(status); self.send_header("Content-Type", kind)
        self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)
    def key(self):
        return self.path.split("?")[0].strip("/")
    def do_GET(self):
        key = self.key()
        with LOCK:
            if key in OBJECTS:
                return self.send(200, OBJECTS[key], "application/octet-stream")
            prefix = key + "/" if key else ""
            keys = sorted(k for k in OBJECTS if k.startswith(prefix))
        if keys or not key:
            return self.send(200, {"prefix": prefix, "keys": [{"key": k, "size": len(OBJECTS[k])} for k in keys]})
        self.send(404, {"error": "no such key"})
    def do_PUT(self):
        if not CFG.get("writable"):
            return self.send(403, {"error": "this storage is read-only"})
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        with LOCK:
            OBJECTS[self.key()] = body
        self.send(201, {"stored": self.key(), "size": len(body)})
    def do_DELETE(self):
        if not CFG.get("writable"):
            return self.send(403, {"error": "this storage is read-only"})
        with LOCK:
            found = OBJECTS.pop(self.key(), None) is not None
        self.send(200 if found else 404, {"deleted": self.key()} if found else {"error": "no such key"})

ThreadingHTTPServer(("0.0.0.0", int(sys.argv[1])), Handler).serve_forever()
