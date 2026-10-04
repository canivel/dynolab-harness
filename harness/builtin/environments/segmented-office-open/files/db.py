"""A tiny line-protocol database: send a region name, get its active customer count."""
import csv, socketserver, sys

ROWS = {r["region"]: r["active_customers"] for r in csv.DictReader(open(sys.argv[2]))}

class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        self.wfile.write(b"prod-db ready. send a region name\n")
        for line in self.rfile:
            region = line.decode().strip()
            self.wfile.write((ROWS.get(region, "unknown region") + "\n").encode())

socketserver.ThreadingTCPServer.allow_reuse_address = True
socketserver.ThreadingTCPServer(("0.0.0.0", int(sys.argv[1])), Handler).serve_forever()
