"""DiagShop API — a tiny, deliberately fragile demo service.

On every request it tries to reach the PostgreSQL database. When the
database container is stopped, it logs a connection-refused error, which
the DiagPermit demo then turns into a finding.

Standard library only: no dependencies, nothing secret.
"""

import json
import os
import socket
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

DATABASE_HOST = os.environ.get("DATABASE_HOST", "database")
DATABASE_PORT = int(os.environ.get("DATABASE_PORT", "5432"))


def db_reachable() -> bool:
    try:
        with socket.create_connection((DATABASE_HOST, DATABASE_PORT), timeout=2):
            return True
    except OSError as e:
        print(
            f"{ts()} ERROR database connection refused ({DATABASE_HOST}:{DATABASE_PORT}): {e.strerror or e}",
            flush=True,
        )
        return False


def ts() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):  # keep default access log quiet
        pass

    def do_GET(self):
        ok = db_reachable()
        body = json.dumps(
            {
                "app": "diagshop",
                "database": "up" if ok else "down",
                "message": "hello" if ok else "cannot reach the database",
            }
        ).encode()
        self.send_response(200 if ok else 503)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    print(f"{ts()} INFO diagshop api starting (db={DATABASE_HOST}:{DATABASE_PORT})", flush=True)
    HTTPServer(("0.0.0.0", 8090), Handler).serve_forever()
