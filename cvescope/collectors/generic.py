"""Collectors that work for anything: hand-entered, shell command, dpkg list, JSON endpoint."""

from __future__ import annotations

import re
import subprocess

from .. import net
from . import item, packages, secret


def static(e: dict) -> list[dict]:
    """[[inventory]] type="static", name, vendor, product, version."""
    if not e.get("product") and not e.get("aliases"):
        raise ValueError(f"static item {e.get('name')!r} needs product or aliases")
    return [item(e.get("name") or e["product"], e.get("vendor", ""), e.get("product", ""),
                 e.get("version"))]


def _run(cmd, timeout=60) -> str:
    if isinstance(cmd, str):
        cmd = cmd.split()
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                       encoding="utf-8", errors="replace")
    out = (r.stdout or "") + (r.stderr or "")
    if r.returncode != 0 and not out.strip():
        raise RuntimeError(f"command exited {r.returncode}")
    return out


def command(e: dict) -> list[dict]:
    """Run a command (e.g. over ssh) and pull the version out with a regex.

    command = ["ssh", "web1", "apache2 -v"]
    regex   = 'Apache/([0-9.]+)'
    """
    out = _run(e["command"], e.get("timeout", 60))
    m = re.search(e.get("regex") or r"(\d+\.\d+(?:\.\d+)*\w*)", out)
    if not m:
        raise RuntimeError("version regex did not match the command output")
    ver = m.group(1)
    if e.get("package"):  # let a known package name supply the aliases
        disp, al = packages.PACKAGES.get(e["package"], (e["package"], []))
        return [item(e.get("name") or disp, version=ver, aliases=al,
                     backports=bool(e.get("distro_package", False)))]
    return [item(e.get("name") or e.get("product", "app"), e.get("vendor", ""), e.get("product", ""), ver)]


def dpkg(e: dict) -> list[dict]:
    """Installed packages from a Debian/Ubuntu host, filtered to ones we know how to match.

    command = ["ssh", "web1", "dpkg-query -W -f='${Package} ${Version}\\n'"]
    Distro packages carry backported fixes, so an upstream version inside an affected
    range is shown as "check" (see the distro's tracker) rather than "affected".
    """
    out = _run(e["command"], e.get("timeout", 120))
    host = e.get("name") or e.get("host") or "host"
    want = set(e.get("packages") or packages.PACKAGES)
    items, done = [], set()
    for line in out.splitlines():
        parts = line.strip().split()
        if len(parts) < 2 or parts[0] not in want or parts[0] not in packages.PACKAGES:
            continue
        disp, al = packages.PACKAGES[parts[0]]
        if disp in done:
            continue
        done.add(disp)
        items.append(item(f"{disp} ({host})", version=packages.pkg_version(parts[1]), aliases=al,
                          backports=True, package=parts[0], package_version=parts[1]))
    if not items:
        raise RuntimeError("no known packages in the output")
    return items


def _dig(obj, path: str):
    for part in path.split("."):
        if part == "":
            continue
        obj = obj[int(part)] if isinstance(obj, list) else obj[part]
    return obj


def http_json(e: dict) -> list[dict]:
    """GET a JSON endpoint and read the version at a dotted path.

    url = "https://grafana.lan/api/health"; path = "version"
    Optional: header = "Authorization", token_file/token_env, token_prefix = "Bearer "
    """
    c = net.PinnedClient(e["url"], e.get("pin_sha256", ""), e.get("verify_tls", False),
                         e.get("allow_insecure", False))
    headers = {}
    if e.get("token_file") or e.get("token_env"):
        headers[e.get("header", "Authorization")] = e.get("token_prefix", "Bearer ") + secret(e, "token")
    data = c.get("", headers)
    ver = str(_dig(data, e.get("path", "version")))
    if e.get("regex"):
        m = re.search(e["regex"], ver)
        ver = m.group(1) if m else ver
    return [item(e.get("name") or e.get("product", "app"), e.get("vendor", ""), e.get("product", ""), ver)]
