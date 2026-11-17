"""Local web page. JSON API + static files, bound to 127.0.0.1 by default.

The page lists your inventory, so keep it on localhost: it is a map of what's
vulnerable in your network. The Host check blocks DNS-rebinding from web pages.

The only writes are acknowledgements (POST /api/ack, /api/unack). They take JSON only and
refuse requests another site started (Origin / Sec-Fetch-Site), so a web page you visit
can't acknowledge things behind your back. serve.read_only = true turns them off.
"""

from __future__ import annotations

import json
import re
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from . import acks, db, query

WEB = Path(__file__).resolve().parent / "web"
TYPES = {".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8",
         ".css": "text/css; charset=utf-8", ".svg": "image/svg+xml"}
CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,7}$")
MAX_BODY = 4096


def same_origin(headers, host: str) -> bool:
    """True unless the request came from another site. Browsers send Origin on every POST and
    Sec-Fetch-Site on current versions; a form or fetch() from elsewhere fails one of them.
    Requests with neither (curl, scripts) pass: they had to reach this machine to begin with."""
    site = (headers.get("Sec-Fetch-Site") or "").lower()
    if site and site not in ("same-origin", "none"):
        return False
    origin = headers.get("Origin")
    if origin is None:
        return True
    u = urllib.parse.urlsplit(origin)
    return u.scheme in ("http", "https") and u.netloc.lower() == host


def make_handler(cfg, allowed_hosts: set[str]):
    class H(BaseHTTPRequestHandler):
        server_version = "cvescope"

        def log_message(self, *a):
            pass

        def _send(self, code: int, body: bytes, ctype: str):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy",
                             "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
                             "frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
            self.end_headers()
            self.wfile.write(body)

        def _json(self, obj, code=200):
            self._send(code, json.dumps(obj, default=str).encode(), "application/json")

        def do_POST(self):
            host = (self.headers.get("Host") or "").lower()
            if host not in allowed_hosts:
                return self._send(403, b"bad host", "text/plain")
            if not same_origin(self.headers, host):
                return self._json({"error": "refused: the request came from another site"}, 403)
            if cfg["serve"].get("read_only"):
                return self._json({"error": "this page is read-only (serve.read_only)"}, 403)
            ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
            if ctype != "application/json":
                return self._json({"error": "send JSON"}, 415)
            try:
                n = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                n = -1
            if not 0 < n <= MAX_BODY:
                return self._json({"error": "bad body size"}, 413 if n > MAX_BODY else 400)
            try:
                body = json.loads(self.rfile.read(n))
                if not isinstance(body, dict):
                    raise ValueError
            except ValueError:
                return self._json({"error": "bad JSON"}, 400)
            path = urllib.parse.urlsplit(self.path).path
            cid = str(body.get("cve") or "").upper()
            if not CVE_ID.match(cid):
                return self._json({"error": "bad id"}, 400)
            item = body.get("item")
            if item is not None and not isinstance(item, str):
                return self._json({"error": "bad item"}, 400)
            con = db.connect(cfg.db_path)
            try:
                if path == "/api/ack":
                    note, days = body.get("note") or "", body.get("days")
                    if not isinstance(note, str) or (days is not None and not isinstance(days, int)):
                        return self._json({"error": "bad note or days"}, 400)
                    rows = acks.add(con, cfg, cid, item, note, days=days)
                    return self._json({"ok": True, "items": [r["item_id"] for r in rows]})
                if path == "/api/unack":
                    return self._json({"ok": True, "items": acks.remove(con, cid, item)})
                return self._json({"error": "unknown endpoint"}, 404)
            except ValueError as e:
                return self._json({"error": str(e)}, 400)
            finally:
                con.close()

        def do_GET(self):
            host = (self.headers.get("Host") or "").lower()
            if host not in allowed_hosts:
                return self._send(403, b"bad host", "text/plain")
            u = urllib.parse.urlsplit(self.path)
            qs = {k: v[-1] for k, v in urllib.parse.parse_qs(u.query).items()}
            path = u.path
            if not path.startswith("/api/"):
                name = "index.html" if path in ("/", "") else path.lstrip("/")
                f = (WEB / name).resolve()
                if WEB not in f.parents or not f.is_file():
                    return self._send(404, b"not found", "text/plain")
                return self._send(200, f.read_bytes(), TYPES.get(f.suffix, "application/octet-stream"))
            con = db.connect(cfg.db_path)
            try:
                if path == "/api/summary":
                    return self._json(query.summary(con, cfg))
                if path == "/api/matches":
                    tiers = [t for t in qs.get("tiers", "act,watch").split(",") if t in query.TIER_ORDER]
                    return self._json(query.matches(con, cfg, tiers=tiers or ["act", "watch"],
                                                    include_keyword=qs.get("keyword") == "1",
                                                    item_id=qs.get("item") or None,
                                                    acked="include" if qs.get("acked") == "1" else "hide"))
                if path.startswith("/api/cve/"):
                    cid = path.rsplit("/", 1)[-1].upper()
                    if not CVE_ID.match(cid):
                        return self._json({"error": "bad id"}, 400)
                    d = query.cve_detail(con, cfg, cid)
                    return self._json(d if d else {"error": "not found"}, 200 if d else 404)
                if path == "/api/events":
                    days = max(1, min(365, int(qs.get("days", "7") or 7)))
                    return self._json(query.events(con, cfg, days=days, matched_only=qs.get("all") != "1"))
                if path == "/api/hot":
                    return self._json(query.hot(con, cfg))
                if path == "/api/search":
                    q = (qs.get("q") or "").strip()[:100]
                    return self._json(query.search(con, cfg, q) if len(q) >= 3 else [])
                return self._json({"error": "unknown endpoint"}, 404)
            except ValueError as e:
                return self._json({"error": str(e)}, 400)
            finally:
                con.close()

    return H


def serve(cfg, host: str, port: int):
    names = {host, "127.0.0.1", "localhost"} if host in ("127.0.0.1", "localhost") else {host}
    names |= set(cfg["serve"].get("allowed_hosts") or [])  # e.g. the LAN name if you bind wider
    allowed = {f"{n}:{port}" for n in names}
    httpd = ThreadingHTTPServer((host, port), make_handler(cfg, allowed))
    print(f"cvescope on http://{'127.0.0.1' if host in ('127.0.0.1', '0.0.0.0') else host}:{port}/  (Ctrl+C to stop)")
    if host not in ("127.0.0.1", "localhost", "::1"):
        print("WARNING: listening beyond localhost exposes your inventory and its known holes.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
