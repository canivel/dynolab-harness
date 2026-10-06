"""A SQL database (SQLite) queried over HTTP. Standard library only.

    python3 sql_db.py <port> <config.json>
config.json: {"tables": {"customers": "region,active\\nNorth,1284\\n..."}, "password": "optional"}

GET  /health                     {"ok": true}
GET  /tables                     table names and columns
POST /query  {"sql": "SELECT …"} {"columns": [...], "rows": [[...]]}
GET  /query?sql=SELECT…          the same
With a password set, every request except /health needs `Authorization: Bearer <password>`
or `?password=<password>`.
"""
import csv, io, json, sqlite3, sys, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

CFG = json.load(open(sys.argv[2]))
DB = sqlite3.connect(":memory:", check_same_thread=False)
LOCK = threading.Lock()
for name, text in CFG.get("tables", {}).items():
    rows = list(csv.reader(io.StringIO(text.strip())))
    if not rows:
        continue
    cols = ", ".join(f'"{c}"' for c in rows[0])
    DB.execute(f'CREATE TABLE "{name}" ({cols})')
    DB.executemany(f'INSERT INTO "{name}" VALUES ({", ".join("?" * len(rows[0]))})', rows[1:])
DB.commit()

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def send(self, status, body):
        data = json.dumps(body).encode()
        self.send_response(status); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)
    def allowed(self, query):
        pw = CFG.get("password")
        if not pw:
            return True
        return self.headers.get("Authorization", "") == f"Bearer {pw}" or query.get("password", [None])[0] == pw
    def handle_any(self, sql=None):
        url = urlparse(self.path)
        query = parse_qs(url.query)
        if url.path == "/health":
            return self.send(200, {"ok": True})
        if not self.allowed(query):
            return self.send(401, {"error": "authentication required"})
        if url.path == "/tables":
            with LOCK:
                names = [r[0] for r in DB.execute("SELECT name FROM sqlite_master WHERE type='table'")]
                return self.send(200, {n: [c[1] for c in DB.execute(f'PRAGMA table_info("{n}")')] for n in names})
        if url.path != "/query":
            return self.send(404, {"error": "use /query, /tables or /health"})
        sql = sql or query.get("sql", [""])[0]
        try:
            with LOCK:
                cur = DB.execute(sql)
                rows = cur.fetchall()
                DB.commit()
            return self.send(200, {"columns": [d[0] for d in cur.description or []], "rows": rows})
        except sqlite3.Error as e:
            return self.send(400, {"error": str(e)})
    def do_GET(self):
        self.handle_any()
    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode(errors="replace")
        try:
            sql = json.loads(raw).get("sql")
        except (ValueError, AttributeError):
            sql = raw
        self.handle_any(sql or "")

ThreadingHTTPServer(("0.0.0.0", int(sys.argv[1])), Handler).serve_forever()
