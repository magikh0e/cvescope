"""Debian and Ubuntu security trackers: which CVEs each release fixed, in which package version.

Upstream CVE ranges can't tell you whether a distro backported a fix. The distro's own tracker
can, so distro packages (dpkg, osquery deb_packages) get a real affected/fixed answer.

  Debian  the security tracker's own JSON (~15 MB gzipped, re-fetched only when it changes)
  Ubuntu  Canonical's per-release package OVAL (~2 MB per release)

Debian used to come from the OSV export of the same tracker. That copy drops the tracker's
"not-affected" notes (code that never shipped in a release reads as "no fix yet") and lags
behind it, so the JSON the tracker's own pages are built from is used instead.

Only the releases your inventory reports (items with extra.distro such as "debian:12" or
"ubuntu:noble") are kept, plus any listed in sources.distro_releases.
"""

from __future__ import annotations

import bz2
import html
import json
import re

from .. import db, net

DEBIAN_URL = "https://security-tracker.debian.org/tracker/data/json"
# os-release gives the number, the tracker keys releases by codename
DEBIAN_CODENAMES = {"10": "buster", "11": "bullseye", "12": "bookworm", "13": "trixie",
                    "14": "forky", "15": "duke"}
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
    con.executemany("INSERT OR REPLACE INTO distro_fix(release, package, cve_id, status, fixed, note) "
                    "VALUES(?,?,?,?,?,?)", rows)
    con.commit()


def debian_status(r: dict) -> tuple[str, str | None, str | None]:
    """One release entry from the tracker JSON -> (status, fixed version, note)."""
    fixed = r.get("fixed_version")
    if r.get("status") == "resolved":
        # fixed_version "0" is the tracker's "<not-affected>": the code never shipped in this release
        return ("notaff", None, None) if fixed in ("0", "", None) else ("fixed", fixed, None)
    urgency = str(r.get("urgency") or "").lower()
    if urgency == "unimportant":  # not a security problem for Debian, never patched
        return "minor", None, None
    status = "maybe" if r.get("status") == "undetermined" else "open"
    why, kind = (r.get("nodsa") or "").strip(), (r.get("nodsa_reason") or "").strip()
    if r.get("next_point_update"):
        note = "a fix is queued for the next point release"
    elif urgency == "end-of-life":
        note = "the package is out of Debian security support"
    elif why and kind == "postponed":
        note = f"postponed by Debian: {why}"
    elif why and kind == "ignored":
        note = f"Debian won't fix it here: {why}"
    elif why:
        note = f"no security update planned: {why}"
    else:
        note = None
    return status, None, note


def debian_rows(data: dict, releases: set[str]) -> tuple[list[tuple], set[str]]:
    """Rows for distro_fix from the tracker JSON, plus the releases the tracker had no data for."""
    code = {}
    for rel in releases:
        v = rel.split(":", 1)[1]
        code[DEBIAN_CODENAMES.get(v, v)] = rel
    rows, seen = [], set()
    for pkg, cves in data.items():
        if not isinstance(cves, dict):
            continue
        for cve, d in cves.items():
            if not cve.startswith("CVE-"):  # TEMP-… ids have no CVE yet
                continue
            for cn, r in ((d or {}).get("releases") or {}).items():
                if cn in code:
                    seen.add(cn)
                    rows.append((code[cn], pkg, cve, *debian_status(r)))
    return rows, {rel for cn, rel in code.items() if cn not in seen}


def _debian(con, cfg, releases: set[str]) -> str:
    name = "distro:debian"
    src = db.source_get(con, name)
    st = src["state"]
    same = st.get("releases") == sorted(releases) and st.get("feed") == "tracker"
    try:
        body, modified = net.get_since(DEBIAN_URL, src["etag"] if same else None, timeout=600)
    except net.NotModified:
        db.source_ok(con, name)
        return "Debian unchanged"
    rows, missing = debian_rows(json.loads(body), releases)
    del body
    _store(con, releases, rows)
    db.source_ok(con, name, {"releases": sorted(releases), "feed": "tracker"}, modified)
    out = f"Debian {', '.join(sorted(r.split(':')[1] for r in releases))}: {len(rows):,} entries"
    if missing:
        out += f" (the tracker has nothing for {', '.join(sorted(missing))}: out of support?)"
    return out


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
                rows[(pkg, cve)] = (release, pkg, cve, "fixed", n.group(1), None)
        elif "needs fixing" in rest:
            rows[(pkg, cve)] = (release, pkg, cve, "open", None, None)
        elif "may need fixing" in rest:
            rows.setdefault((pkg, cve), (release, pkg, cve, "maybe", None, None))
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
