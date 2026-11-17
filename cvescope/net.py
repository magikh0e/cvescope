"""HTTP helpers: conditional GETs for feeds, and a pinned-TLS JSON client for LAN gear.

Nothing here logs request headers, so tokens never reach the console.
"""

from __future__ import annotations

import hashlib
import http.client
import json
import shutil
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from . import __version__

UA = f"cvescope/{__version__}"


class NotModified(Exception):
    pass


class HTTPStatus(Exception):
    def __init__(self, code: int, url: str):
        super().__init__(f"HTTP {code} for {url}")
        self.code = code


def _open(url: str, headers: dict | None = None, timeout: int = 120, tries: int = 3):
    h = {"User-Agent": UA}
    h.update(headers or {})
    last = None
    for i in range(tries):
        try:
            return urllib.request.urlopen(urllib.request.Request(url, headers=h), timeout=timeout)
        except urllib.error.HTTPError as e:
            if e.code == 304:
                raise NotModified() from None
            if e.code in (404, 410, 401, 403):
                raise HTTPStatus(e.code, url) from None
            last = HTTPStatus(e.code, url)
        except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
            last = e
        time.sleep(2 * (i + 1))
    raise last  # type: ignore[misc]


def get(url: str, etag: str | None = None, timeout: int = 120) -> tuple[bytes, str | None]:
    """GET with If-None-Match. Raises NotModified when the etag still matches."""
    headers = {"If-None-Match": etag} if etag else {}
    with _open(url, headers, timeout) as r:
        return r.read(), r.headers.get("ETag")


def download(url: str, dest: Path, etag: str | None = None, timeout: int = 300,
             progress: bool = False) -> str | None:
    """Stream a URL to dest (atomic rename). Returns the new ETag."""
    headers = {"If-None-Match": etag} if etag else {}
    tmp = dest.with_suffix(dest.suffix + ".part")
    with _open(url, headers, timeout) as r, open(tmp, "wb") as f:
        total = int(r.headers.get("Content-Length") or 0)
        done, last_print = 0, 0.0
        while True:
            chunk = r.read(1 << 20)
            if not chunk:
                break
            f.write(chunk)
            done += len(chunk)
            if progress and total and time.time() - last_print > 2:
                print(f"    {done >> 20} / {total >> 20} MB", flush=True)
                last_print = time.time()
        new_etag = r.headers.get("ETag")
    shutil.move(str(tmp), str(dest))
    return new_etag


def exists(url: str) -> bool:
    req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return 200 <= r.status < 400
    except urllib.error.HTTPError:
        return False
    except (urllib.error.URLError, TimeoutError):
        return False


# ---- LAN client with certificate pinning --------------------------------

def _norm_pin(pin: str) -> str:
    return pin.replace(":", "").replace(" ", "").strip().lower()


class PinnedClient:
    """JSON over HTTPS to a self-signed appliance.

    verify_tls=True  -> normal CA validation.
    pin_sha256="..." -> accept only a cert whose SHA-256 (DER) matches, checked
                        BEFORE any request (and so any token) is sent.
    Neither          -> refuses to talk HTTPS, unless allow_insecure=True.
    """

    def __init__(self, base_url: str, pin_sha256: str = "", verify_tls: bool = False,
                 allow_insecure: bool = False, timeout: int = 20):
        u = urllib.parse.urlsplit(base_url.rstrip("/"))
        self.scheme, self.host, self.port = u.scheme, u.hostname, u.port
        self.prefix = u.path
        self.pin = _norm_pin(pin_sha256) if pin_sha256 else ""
        self.verify = verify_tls
        self.insecure = allow_insecure
        self.timeout = timeout
        if self.scheme == "https" and not (self.pin or self.verify or self.insecure):
            raise ValueError(f"{base_url}: set pin_sha256 or verify_tls = true "
                             "(or allow_insecure = true if you accept the risk)")

    def _conn(self):
        if self.scheme == "http":
            return http.client.HTTPConnection(self.host, self.port or 80, timeout=self.timeout)
        ctx = ssl.create_default_context()
        if not self.verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        c = http.client.HTTPSConnection(self.host, self.port or 443, context=ctx, timeout=self.timeout)
        c.connect()
        if self.pin:
            der = c.sock.getpeercert(binary_form=True)
            got = hashlib.sha256(der).hexdigest()
            if got != self.pin:
                c.close()
                raise ssl.SSLError(f"certificate pin mismatch for {self.host} (got {got[:16]}...)")
        return c

    def request(self, method: str, path: str, headers: dict | None = None, body=None):
        c = self._conn()
        try:
            h = {"User-Agent": UA, "Accept": "application/json"}
            h.update(headers or {})
            data = None
            if body is not None:
                data = json.dumps(body).encode()
                h["Content-Type"] = "application/json"
            c.request(method, self.prefix + path, body=data, headers=h)
            r = c.getresponse()
            raw = r.read()
            if r.status >= 400:
                raise HTTPStatus(r.status, f"{self.host}{path}")
            return json.loads(raw) if raw.strip() else None
        finally:
            c.close()

    def get(self, path: str, headers: dict | None = None):
        return self.request("GET", path, headers)


def fingerprint(host: str, port: int = 443) -> str:
    """SHA-256 of a server's certificate, for `cvescope pin`."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    c = http.client.HTTPSConnection(host, port, context=ctx, timeout=15)
    c.connect()
    try:
        return hashlib.sha256(c.sock.getpeercert(binary_form=True)).hexdigest()
    finally:
        c.close()
