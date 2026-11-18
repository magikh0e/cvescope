"""Local web page. JSON API + static files, bound to 127.0.0.1 by default.

The page lists your inventory, so keep it on localhost: it is a map of what's
vulnerable in your network. The Host check blocks DNS-rebinding from web pages.

The writes are acknowledgements (POST /api/ack, /api/unack and their /bulk forms) and
starting a sync (POST /api/sync). They take JSON only and refuse requests another site
started (Origin / Sec-Fetch-Site), so a web page you visit can't acknowledge things or start
syncs behind your back. serve.read_only = true turns all of them off.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from . import acks, db, query, report, synclock, vulnid

WEB = Path(__file__).resolve().parent / "web"
TYPES = {".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8",
         ".css": "text/css; charset=utf-8", ".svg": "image/svg+xml"}
CVE_ID = vulnid.VULN_ID  # CVE IDs and advisory IDs (GHSA-, PSA-, ...)
MAX_BODY = 4096
MAX_BODY_BULK = 256 * 1024  # /api/ack/bulk and /api/unack/bulk: up to acks.BULK_MAX pairs
DRAIN_MAX = 1024 * 1024     # how much of an oversized body gets read and dropped before refusing


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


class SyncRunner:
    """Runs `cvescope sync` in the background for the page's "sync now" button.

    The sync is its own process, the same command a scheduled run uses, so the page stays
    responsive and stopping the server doesn't cut a sync short. It logs to
    <data_dir>/sync-web.log. The sync lock (synclock.py) keeps it from overlapping a scheduled
    or terminal sync: the button refuses while one runs, and the page follows that one instead.
    """

    TAIL = 8          # log lines the page gets
    LINE_MAX = 300

    def __init__(self, cfg, command: list[str] | None = None):
        self.cfg = cfg
        self.command = command     # tests run a stub instead of a real sync
        self.mutex = threading.Lock()
        self.proc = None
        self.started = self.finished = self.exit = None
        self.offset = 0

    @property
    def log_path(self) -> Path:
        return self.cfg.data_dir / "sync-web.log"

    @property
    def err_path(self) -> Path:   # anything printed before the log opens (a bad config, say)
        return self.cfg.data_dir / "sync-web.err"

    def argv(self) -> list[str]:
        if self.command:
            return list(self.command)
        argv = [sys.executable, "-m", "cvescope"]
        if self.cfg.path:
            argv += ["--config", str(Path(self.cfg.path).resolve())]
        return argv + ["--log", str(self.log_path), "sync"]

    def _poll(self):   # with self.mutex held
        if self.proc is not None and self.exit is None:
            code = self.proc.poll()
            if code is not None:
                self.exit, self.finished = code, db.now()

    def _mine(self) -> bool:
        return self.proc is not None and self.exit is None

    def start(self) -> tuple[int, str]:
        with self.mutex:
            self._poll()
            if self._mine():
                return 409, "a sync from this page is already running"
            other = synclock.held(self.cfg.data_dir)
            if other is not None:
                return 409, "a sync is already running" + (f" (started {other['started']})" if other["started"] else "")
            self.offset = self.log_path.stat().st_size if self.log_path.exists() else 0
            env = dict(os.environ)
            # the child imports the same cvescope this server runs, installed or from a checkout
            env["PYTHONPATH"] = os.pathsep.join(filter(None, [str(Path(__file__).resolve().parent.parent),
                                                              env.get("PYTHONPATH")]))
            kw = ({"creationflags": subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP}
                  if sys.platform == "win32" else {"start_new_session": True})
            try:
                with open(self.err_path, "wb") as err:
                    self.proc = subprocess.Popen(self.argv(), stdin=subprocess.DEVNULL, stdout=err, stderr=err,
                                                 env=env, **kw)
            except OSError as e:
                return 500, f"couldn't start the sync: {e}"
            self.started, self.finished, self.exit = db.now(), None, None
            return 202, "started"

    def _lines(self) -> list[str]:
        out: list[str] = []
        for path, start in ((self.log_path, self.offset), (self.err_path, 0)):
            try:
                with open(path, "rb") as f:
                    size = f.seek(0, 2)
                    if size < start:   # the log rotated: this run starts the new file
                        start = 0
                    f.seek(max(start, size - 65536))
                    text = f.read().decode("utf-8", "replace")
            except OSError:
                continue
            out = [ln.strip()[: self.LINE_MAX] for ln in text.splitlines()
                   if ln.strip() and not ln.startswith("=====")][-self.TAIL:]
            if out:
                break
        return out

    def status(self) -> dict:
        with self.mutex:
            self._poll()
            mine = self._mine()
        other = None if mine else synclock.held(self.cfg.data_dir)
        out = {"running": mine or other is not None,
               "by": "page" if mine else ("other" if other is not None else None),
               "started": self.started if mine else (other or {}).get("started"),
               "page": None}
        if self.proc is not None:   # the last sync this page started, running or done
            out["page"] = {"started": self.started, "finished": self.finished, "exit": self.exit,
                           "lines": self._lines()}
        return out


def make_handler(cfg, allowed_hosts: set[str], runner: SyncRunner | None = None):
    runner = runner or SyncRunner(cfg)

    class H(BaseHTTPRequestHandler):
        server_version = "cvescope"
        timeout = 30  # a client that announces a body and never sends it can't hold a thread forever

        def log_message(self, *a):
            pass

        def _send(self, code: int, body: bytes, ctype: str, csp: str | None = None, headers: dict | None = None):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy", csp or
                             "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
                             "frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def _report(self, con, qs):
            fmt = qs.get("format", "html")
            tier = qs.get("tier", "watch")
            if fmt not in report.FORMATS or tier not in report.TIERS:
                return self._json({"error": "bad format or tier"}, 400)
            try:
                days = max(1, min(365, int(qs.get("days", "7") or 7)))
            except ValueError:
                return self._json({"error": "bad days"}, 400)
            host = (qs.get("host") or "")[:200] or None
            tiers = report.TIERS[: report.TIERS.index(tier) + 1]
            d = report.build(con, cfg, tiers=tiers, host=host, days=days, include_keyword=qs.get("keyword") == "1")
            body = report.render(d, fmt).encode("utf-8")
            if fmt == "html":  # self-contained and script-free: inline styles only
                return self._send(200, body, report.MIME[fmt],
                                  csp="default-src 'none'; style-src 'unsafe-inline'; img-src data:; "
                                      "frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
            name = f"cvescope-report-{d['generated'][:10]}.{fmt}"
            return self._send(200, body, report.MIME[fmt], headers={"Content-Disposition": f'attachment; filename="{name}"'})

        def _json(self, obj, code=200):
            self._send(code, json.dumps(obj, default=str).encode(), "application/json")

        def _take_body(self, limit: int) -> tuple[int, bytes]:
            """Read the request body before any check can refuse the request.

            Replying while request data sits unread makes the OS reset the connection when the
            socket closes (Windows does it reliably), so the client got a reset instead of the
            403/413/415. A body over the limit is read and dropped, up to DRAIN_MAX.
            """
            try:
                n = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                self.close_connection = True
                return -1, b""
            if n <= 0:
                return n, b""
            if n <= limit:
                return n, self.rfile.read(n)
            left = min(n, DRAIN_MAX)
            while left > 0:
                chunk = self.rfile.read(min(left, 65536))
                if not chunk:
                    break
                left -= len(chunk)
            self.close_connection = True
            return n, b""

        def do_POST(self):
            path = urllib.parse.urlsplit(self.path).path
            limit = MAX_BODY_BULK if path in ("/api/ack/bulk", "/api/unack/bulk") else MAX_BODY
            n, raw = self._take_body(limit)
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
            if not 0 < n <= limit:
                return self._json({"error": "bad body size"}, 413 if n > limit else 400)
            try:
                body = json.loads(raw)
                if not isinstance(body, dict):
                    raise ValueError
            except ValueError:
                return self._json({"error": "bad JSON"}, 400)
            if limit == MAX_BODY_BULK:
                return self._bulk(path, body)
            if path == "/api/sync":
                code, msg = runner.start()
                return self._json({"ok": True} if code == 202 else {"error": msg}, code)
            cid = vulnid.canon(body.get("cve"))
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

        def _bulk(self, path, body):
            raw = body.get("pairs")
            if not isinstance(raw, list) or not 0 < len(raw) <= acks.BULK_MAX:
                return self._json({"error": f"send 1 to {acks.BULK_MAX} pairs"}, 400)
            pairs = []
            for p in raw:
                cid = vulnid.canon(p.get("cve")) if isinstance(p, dict) else ""
                item = p.get("item") if isinstance(p, dict) else None
                if not CVE_ID.match(cid) or not isinstance(item, str) or not 0 < len(item) <= 300:
                    return self._json({"error": "bad pair"}, 400)
                pairs.append((cid, item))
            note, days = body.get("note") or "", body.get("days")
            if not isinstance(note, str) or (days is not None and (not isinstance(days, int) or isinstance(days, bool))):
                return self._json({"error": "bad note or days"}, 400)
            con = db.connect(cfg.db_path)
            try:
                if path == "/api/ack/bulk":
                    return self._json({"ok": True, "count": len(acks.add_many(con, cfg, pairs, note, days=days))})
                return self._json({"ok": True, "count": acks.remove_many(con, pairs)})
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
            if path == "/api/sync":
                return self._json(runner.status())
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
                if path == "/api/report":
                    return self._report(con, qs)
                if path == "/api/matches":
                    tiers = [t for t in qs.get("tiers", "act,watch").split(",") if t in query.TIER_ORDER]
                    return self._json(query.matches(con, cfg, tiers=tiers or ["act", "watch"],
                                                    include_keyword=qs.get("keyword") == "1",
                                                    item_id=qs.get("item") or None,
                                                    acked="include" if qs.get("acked") == "1" else "hide"))
                if path.startswith("/api/cve/"):
                    cid = vulnid.canon(urllib.parse.unquote(path.rsplit("/", 1)[-1]))
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
