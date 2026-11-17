"""Import service versions from nmap -sV XML output.

cvescope never runs nmap itself: you scan (only networks you're allowed to), it reads the file.

    nmap -sV -oX ~/scans/lan.xml 192.168.1.0/24

    [[inventory]]
    type = "nmap_xml"
    path = "~/scans/*.xml"          # a file, a glob, or a list of either
    hosts = ["192.168.1.0/24"]      # optional filter: CIDRs, IPs or hostnames
    unversioned = false             # true also adds services nmap named but couldn't version
    max_age_days = 30               # ignore scans older than this (0 = no limit)
"""

from __future__ import annotations

import datetime as dt
import glob
import ipaddress
import re
import xml.etree.ElementTree as ET

from .. import db
from ..config import expand
from . import item, packages

# a version string carrying a distro build means fixes may be backported
_DISTRO = re.compile(r"ubuntu|debian|raspbian|red ?hat|rhel|centos|rocky|alma|fedora|\bel\d|deb\d+u\d+|\+deb",
                     re.I)
_VERSION = re.compile(r"\d[\w.\-]*")


def _cpe(c: str):
    """cpe:/a:openbsd:openssh:9.6p1 -> ('a', 'openbsd', 'openssh', '9.6p1')"""
    if c.startswith("cpe:/"):
        p = c[5:].split(":")
    elif c.startswith("cpe:2.3:"):
        p = c[8:].split(":")
    else:
        return None
    p += [""] * (4 - len(p))
    return p[0], p[1], p[2], p[3]


def _files(spec) -> list[str]:
    specs = spec if isinstance(spec, list) else [spec]
    out = []
    for s in specs:
        out += glob.glob(str(expand(s)))
    return sorted(set(out))


def _host_filter(rules):
    nets, names = [], set()
    for r in rules or []:
        try:
            nets.append(ipaddress.ip_network(r, strict=False))
        except ValueError:
            names.add(r.lower())

    def ok(addr: str, hostnames: list[str]) -> bool:
        if not rules:
            return True
        if any(h.lower() in names for h in hostnames):
            return True
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            return addr.lower() in names
        return any(ip in n for n in nets)
    return ok


def _known(product: str):
    """nmap's product name -> (display, aliases) from the shared tables."""
    key = product.lower().strip()
    if key in packages.NMAP:
        return packages.NMAP[key]
    for k, v in packages.NMAP.items():  # "apache httpd" matches "Apache httpd 2.x"
        if key.startswith(k):
            return v
    return None


def parse(path: str) -> tuple[float, list[dict]]:
    """-> (scan start epoch, [service dicts]) for one nmap XML file."""
    with open(path, "rb") as f:
        data = f.read()
    # nmap writes only `<!DOCTYPE nmaprun>`. Any entity declaration means the file isn't plain
    # nmap output, so refuse it rather than rely on the expat build's expansion limits.
    if b"<!ENTITY" in data.upper():
        raise ValueError(f"{path} declares XML entities; not plain nmap output, refusing to parse")
    root = ET.fromstring(data)
    if root.tag != "nmaprun":
        raise ValueError(f"{path} is not nmap XML output")
    started = float(root.get("start") or 0)
    found = []
    for h in root.iter("host"):
        st = h.find("status")
        if st is not None and st.get("state") != "up":
            continue
        addr = next((a.get("addr") for a in h.findall("address") if a.get("addrtype") in ("ipv4", "ipv6")), None)
        if not addr:
            continue
        names = [n.get("name") for n in h.findall("hostnames/hostname") if n.get("name")]
        for p in h.findall("ports/port"):
            state = p.find("state")
            svc = p.find("service")
            if state is None or state.get("state") != "open" or svc is None:
                continue
            if svc.get("method") == "table":  # only a guess from the port number
                continue
            found.append({
                "addr": addr, "hostnames": names, "port": int(p.get("portid") or 0),
                "proto": p.get("protocol"), "name": svc.get("name"), "product": svc.get("product") or "",
                "version": svc.get("version") or "", "extrainfo": svc.get("extrainfo") or "",
                "cpes": [c.text for c in svc.findall("cpe") if c.text],
            })
    return started, found


def nmap_xml(e: dict) -> list[dict]:
    files = _files(e["path"])
    if not files:
        raise RuntimeError(f"no nmap XML matches {e['path']!r}")
    keep = _host_filter(e.get("hosts"))
    max_age = float(e.get("max_age_days", 30) or 0)
    now = dt.datetime.now(dt.timezone.utc).timestamp()
    newest: dict[tuple, tuple[float, dict]] = {}  # (host, product) -> (scan time, service)
    for f in files:
        started, services = parse(f)
        if max_age and started and now - started > max_age * 86400:
            continue
        for s in services:
            if not keep(s["addr"], s["hostnames"]):
                continue
            label = s["product"] or s["name"] or "service"
            k = (s["addr"], label.lower(), s["port"] if not s["product"] else 0)
            if k not in newest or started >= newest[k][0]:
                # the same product on several ports collapses to one item; ports collected below
                prev_ports = newest[k][1].get("ports", []) if k in newest and newest[k][0] == started else []
                s["ports"] = sorted(set(prev_ports + [s["port"]]))
                s["scanned"] = started
                newest[k] = (started, s)

    out = []
    for (_, _, _), (_, s) in sorted(newest.items(), key=lambda kv: (kv[0][0], kv[0][1])):
        host = s["hostnames"][0] if s["hostnames"] else s["addr"]
        mdb = re.search(r"5\.5\.5-(\d[\d.]*)-mariadb", s["version"], re.I)
        if mdb:  # MariaDB reports itself to MySQL clients as "5.5.5-10.6.12-MariaDB"
            s["product"], s["version"], s["cpes"] = "MariaDB", mdb.group(1), []
        app_cpes = [c for c in map(_cpe, s["cpes"]) if c and c[0] == "a"]
        vm = _VERSION.match(s["version"].strip())
        version = vm.group(0).rstrip(".-") if vm else None
        if not version:
            version = next((c[3] for c in app_cpes if c[3]), None)
        if not version and not e.get("unversioned"):
            continue
        aliases = [f"{db.norm(c[1])}:{db.norm(c[2])}" for c in app_cpes if c[2]]
        known = _known(s["product"]) if s["product"] else None
        display = known[0] if known else (s["product"] or s["name"])
        if known:
            aliases += known[1]
        elif s["product"]:
            aliases.append(f"*:{db.norm(s['product'])}")
        if not aliases:
            continue
        distro = bool(_DISTRO.search(f"{s['version']} {s['extrainfo']}"))
        ports = ",".join(str(p) for p in s.get("ports", [s["port"]]))
        out.append(item(f"{display} ({host}:{ports})", version=version, aliases=aliases,
                        backports=distro, host=s["addr"], ports=s.get("ports"),
                        nmap_product=s["product"], nmap_version=s["version"],
                        scanned=dt.datetime.fromtimestamp(s["scanned"], dt.timezone.utc).date().isoformat()
                        if s["scanned"] else None))
    if not out:
        raise RuntimeError("the scan has no open services with a product name nmap could identify "
                           "(was it run with -sV?)")
    return out
