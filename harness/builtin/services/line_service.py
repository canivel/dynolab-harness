"""Line-protocol TCP service: a greeting, then one reply per line received. Standard library only.

    python3 line_service.py <port> <config.json>
config.json: {"greeting": "ready", "replies": {"north": "1284"}, "default": "unknown"}
"""
import json, socketserver, sys

CFG = json.load(open(sys.argv[2]))

class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        if CFG.get("greeting"): self.wfile.write((CFG["greeting"] + "\n").encode())
        for line in self.rfile:
            key = line.decode(errors="replace").strip()
            self.wfile.write((CFG.get("replies", {}).get(key, CFG.get("default", "")) + "\n").encode())

socketserver.ThreadingTCPServer.allow_reuse_address = True
socketserver.ThreadingTCPServer(("0.0.0.0", int(sys.argv[1])), Handler).serve_forever()
