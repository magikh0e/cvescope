"""Collectors that work for anything: hand-entered, shell command, dpkg list, JSON endpoint."""

from __future__ import annotations

import re
import subprocess

from .. import db, net
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
    """Installed packages from a Debian/Ubuntu host.

    Recommended command (os-release first, then one package per line with its status and source):
      command = ["ssh", "web1", "cat /etc/os-release; echo ---; dpkg-query -W -f='${db:Status-Abbrev} ${Package} ${Version} ${source:Package}\\n'"]

    With the os-release part, each package carries its release ("ubuntu:noble", "debian:12") and
    the distro's own security tracker decides fixed/affected, backports included. Without it,
    in-range hits stay "check". The status column matters: `dpkg-query -W` also lists removed
    packages whose config files remain ("rc"), and only installed ones ("ii", "hi") count.
    packages = "all" adds every source package; by default only the ones in packages.PACKAGES.
    """
    out = _run(e["command"], e.get("timeout", 120))
    return dpkg_items(out, e.get("name") or e.get("host") or "host", e.get("packages"))


def dpkg_items(out: str, host: str, wanted=None, release: str | None = None) -> list[dict]:
    osr_text, sep, pkgs = out.partition("\n---\n") if "\n---\n" in out else ("", "", out)
    if not sep and out.startswith("---\n"):
        pkgs = out[4:]
    release = release or (packages.distro_release(packages.parse_os_release(osr_text)) if osr_text else None)
    everything = wanted == "all"
    want = None if everything else set(wanted or packages.PACKAGES)
    items, done = [], set()
    for line in pkgs.splitlines():
        parts = line.strip().split()
        # optional leading ${db:Status-Abbrev}: "ii" installed, "rc" removed with config left
        if parts and re.fullmatch(r"[uihrp][ncHUFWti][R ]?", parts[0]) and len(parts) >= 3 \
                and parts[2][:1].isdigit():
            if parts[0][1] != "i":
                continue
            parts = parts[1:]
        if len(parts) < 2 or not parts[1][:1].isdigit():
            continue
        name, ver = parts[0], parts[1]
        src = (parts[2] if len(parts) > 2 else packages.SOURCE_OF.get(name, name)).split(":")[0]
        known = packages.PACKAGES.get(name)
        if not everything and (name not in want or not known):
            continue
        disp, al = known if known else (src, [f"*:{db.norm(src)}"])
        key = known[0] if known else src
        if key in done:
            continue
        done.add(key)
        items.append(item(f"{disp} ({host})", version=packages.pkg_version(ver), aliases=al,
                          backports=True, package=name, package_version=ver, source=src, distro=release))
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
