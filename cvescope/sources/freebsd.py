"""FreeBSD VuXML: the vulnerability database `pkg audit` reads (~1.4 MB xz).

It lists, per FreeBSD package name, the version ranges each advisory affects, plus the base
system as the packages "FreeBSD" and "FreeBSD-kernel" (versions like 15.1_6 for 15.1-RELEASE-p6).
OPNsense builds its packages from FreeBSD ports, so its exact package builds and its base
release get a real affected/fixed answer from here instead of upstream version ranges.

Only fetched when the inventory has FreeBSD packages or a FreeBSD base system.
"""

from __future__ import annotations

import json
import lzma
import re
import xml.etree.ElementTree as ET

from .. import db, net

URL = "https://vuxml.freebsd.org/freebsd/vuln.xml.xz"
NS = "{http://www.vuxml.org/apps/vuxml-1}"


def wanted(con) -> bool:
    for (extra,) in con.execute("SELECT extra FROM item"):
        ex = json.loads(extra or "{}")
        if ex.get("pkgdb") == "freebsd" or ex.get("freebsd_base"):
            return True
    return False


def parse(data: bytes) -> list[tuple]:
    """vuln.xml -> rows (package, cve_id, vid, ranges JSON, topic, sa) for entries that name a CVE."""
    # The DOCTYPE declares external entities (vuln/2003.xml, ...). The published file has them
    # inlined already, so drop the declaration rather than let anything try to resolve it.
    data = re.sub(rb"<!DOCTYPE[^\[>]*(?:\[.*?\]\s*)?>", b"", data, count=1, flags=re.S)
    if b"<!ENTITY" in data or b"<!DOCTYPE" in data:
        raise ValueError("unexpected entity declarations in vuln.xml")
    root = ET.fromstring(data)
    rows = []
    for v in root.iter(NS + "vuln"):
        cves = sorted({(c.text or "").strip() for c in v.iter(NS + "cvename")} - {""})
        cves = [c for c in cves if c.startswith("CVE-")]
        affects = v.find(NS + "affects")
        if not cves or affects is None:
            continue
        sa = ", ".join((x.text or "").strip() for x in v.iter(NS + "freebsdsa") if x.text)
        topic = " ".join((v.findtext(NS + "topic") or "").split())[:200]
        for pkg in affects:  # <package> or <system>
            names = [(n.text or "").strip() for n in pkg.findall(NS + "name")]
            ranges = [[[c.tag[len(NS):], (c.text or "").strip()] for c in r] for r in pkg.findall(NS + "range")]
            if not ranges:
                continue
            rj = json.dumps(ranges, separators=(",", ":"))
            for name in filter(None, names):
                for cve in cves:
                    rows.append((name, cve, v.get("vid"), rj, topic, sa))
    return rows


def sync(con, cfg) -> str:
    if not wanted(con):
        return "no FreeBSD or OPNsense packages in the inventory"
    name = "freebsd"
    src = db.source_get(con, name)
    try:
        body, etag = net.get(URL, src["etag"], timeout=300)
    except net.NotModified:
        db.source_ok(con, name)
        return "VuXML unchanged"
    rows = parse(lzma.decompress(body))
    con.execute("DELETE FROM vuxml")
    con.executemany("INSERT OR REPLACE INTO vuxml VALUES(?,?,?,?,?,?)", rows)
    con.commit()
    db.source_ok(con, name, None, etag)
    return f"VuXML: {len(rows):,} package/CVE entries"
