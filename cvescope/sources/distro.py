"""Debian and Ubuntu security trackers: which CVEs each release fixed, in which package version.

Upstream CVE ranges can't tell you whether a distro backported a fix. The distro's own tracker
can, so distro packages (dpkg, osquery deb_packages) get a real affected/fixed answer.

  Debian  OSV export of the Debian security tracker (~80 MB zip, re-fetched only when it changes)
  Ubuntu  Canonical's per-release package OVAL (~2 MB per release)

Only the releases your inventory reports (items with extra.distro such as "debian:12" or
"ubuntu:noble") are kept, plus any listed in sources.distro_releases.
"""

from __future__ import annotations

import bz2
import html
import json
import re
import zipfile

from .. import db, net

DEBIAN_URL = "https://osv-vulnerabilities.storage.googleapis.com/Debian/all.zip"
UBUNTU_URL = "https://security-metadata.canonical.com/oval/com.ubuntu.{}.pkg.oval.xml.bz2"

_UB = re.compile(r'comment="\((CVE-\d{4}-\d+)\) (\S+) package in (\w+) ([^"]*)"')
_NOTE = re.compile(r"note: '([^']+)'")


def wanted(con, cfg) -> set[str]:
    rel = {str(r).lower() for r in (cfg["sources"].get("distro_releases") or [])}
    for (extra,) in con.execute("SELECT extra FROM item"):
        d = json.loads(extra or "{}").get("distro")
        if d:
            rel.add(d.lower())
    return {r for r in rel if r.split(":")[0] in ("debian", "ubuntu") and ":" in r}


def _store(con, releases, rows):
    con.execute(f"DELETE FROM distro_fix WHERE release IN ({','.join('?' * len(releases))})", list(releases))
    con.executemany("INSERT OR REPLACE INTO distro_fix VALUES(?,?,?,?,?)", rows)
    con.commit()


def _debian(con, cfg, releases: set[str]) -> str:
    name = "distro:debian"
    src = db.source_get(con, name)
    same = src["state"].get("releases") == sorted(releases)
    dest = cfg.cache_dir / "debian-osv.zip"
    try:
        etag = net.download(DEBIAN_URL, dest, src["etag"] if same else None, timeout=900)
    except net.NotModified:
        db.source_ok(con, name)
        return "Debian unchanged"
    eco = {f"Debian:{r.split(':', 1)[1]}": r for r in releases}
    rows = []
    with zipfile.ZipFile(dest) as z:
        for n in z.namelist():
            if not n.startswith("DEBIAN-CVE-"):  # one record per CVE; DSA/DLA repeat them
                continue
            d = json.loads(z.read(n))
            cves = [u for u in (d.get("upstream") or []) if u.startswith("CVE-")] or [n[7:-5]]
            for a in d.get("affected") or []:
                e = (a.get("package") or {}).get("ecosystem")
                if e not in eco:
                    continue
                fixed = None
                for r in a.get("ranges") or []:
                    for ev in r.get("events") or []:
                        fixed = ev.get("fixed", fixed)
                urgency = str((a.get("ecosystem_specific") or {}).get("urgency") or "").lower()
                # Debian rates some issues "unimportant": not a security problem for Debian, never patched
                status = "fixed" if fixed else ("minor" if "unimportant" in urgency else "open")
                for c in cves:
                    rows.append((eco[e], a["package"]["name"], c, status, fixed))
    dest.unlink()
    _store(con, releases, rows)
    db.source_ok(con, name, {"releases": sorted(releases)}, etag)
    return f"Debian {', '.join(sorted(r.split(':')[1] for r in releases))}: {len(rows):,} entries"


def _ubuntu(con, cfg, release: str) -> str:
    code = release.split(":", 1)[1]
    name = f"distro:{release}"
    src = db.source_get(con, name)
    try:
        body, etag = net.get(UBUNTU_URL.format(code), src["etag"], timeout=300)
    except net.NotModified:
        db.source_ok(con, name)
        return f"Ubuntu {code} unchanged"
    except net.HTTPStatus as e:
        if e.code == 404:
            raise RuntimeError(f"Canonical publishes no OVAL for Ubuntu '{code}' (end of life?)")
        raise
    text = bz2.decompress(body).decode("utf-8", "replace")
    rows = {}
    for m in _UB.finditer(text):
        cve, pkg, rel, rest = m.group(1), m.group(2), m.group(3), html.unescape(m.group(4))
        if rel != code:
            continue
        if "has been fixed" in rest:
            n = _NOTE.search(rest)
            if n:
                rows[(pkg, cve)] = (release, pkg, cve, "fixed", n.group(1))
        elif "needs fixing" in rest:
            rows[(pkg, cve)] = (release, pkg, cve, "open", None)
        elif "may need fixing" in rest:
            rows.setdefault((pkg, cve), (release, pkg, cve, "maybe", None))
    _store(con, {release}, list(rows.values()))
    db.source_ok(con, name, None, etag)
    return f"Ubuntu {code}: {len(rows):,} entries"


def sync(con, cfg) -> str:
    rel = wanted(con, cfg)
    if not rel:
        return "no Debian/Ubuntu hosts in the inventory"
    out = []
    deb = {r for r in rel if r.startswith("debian:")}
    if deb:
        out.append(_debian(con, cfg, deb))
    for r in sorted(x for x in rel if x.startswith("ubuntu:")):
        out.append(_ubuntu(con, cfg, r))
    return "; ".join(out)
