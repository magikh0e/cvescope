"""endoflife.date: the newest release of each release line, per product.

A CVE record can name its fix before that release is out: OpenSSL's records said "fixed in
3.5.10" while 3.5.9 was still the newest 3.5 release. Matching reads these tables to tell an
announced fix from one you can install (match._apply_unreleased).

One bulk download covers every product (~320 KB gzipped, conditional GET), so the request says
nothing about what you run. Products are tied to inventory items through the CPE
vendor:product pairs endoflife.date lists for them.
"""

from __future__ import annotations

import json

from .. import db, net
from .cvelist import _cpe_vp

URL = "https://endoflife.date/api/v1/products/full"
NAME = "endoflife"


def parse(data: dict) -> tuple[list[tuple], list[tuple]]:
    """-> (release lines (product, cycle, latest, latest_date), CPE names (vendor, product, eol product))."""
    cycles, cpes = [], set()
    for p in data.get("result") or []:
        name = p.get("name")
        if not name:
            continue
        for r in p.get("releases") or []:
            latest = r.get("latest") or {}
            if r.get("name") and latest.get("name"):
                cycles.append((name, str(r["name"]), str(latest["name"]), latest.get("date")))
        for i in p.get("identifiers") or []:
            if i.get("type") == "cpe":
                vp = _cpe_vp(str(i.get("id") or ""))
                if vp and db.norm(vp[0]) and db.norm(vp[1]):
                    cpes.add((db.norm(vp[0]), db.norm(vp[1]), name))
    return cycles, sorted(cpes)


def sync(con, cfg) -> str:
    src = db.source_get(con, NAME)
    try:
        body, etag = net.get(URL, src["etag"], compressed=True)
    except net.NotModified:
        db.source_ok(con, NAME)
        return "unchanged"
    data = json.loads(body)
    cycles, cpes = parse(data)
    if not cycles:  # keep the last good copy rather than forget every release
        raise ValueError("the endoflife.date feed listed no releases")
    con.execute("DELETE FROM eol_cycle")
    con.execute("DELETE FROM eol_cpe")
    con.executemany("INSERT OR REPLACE INTO eol_cycle VALUES(?,?,?,?)", cycles)
    con.executemany("INSERT OR REPLACE INTO eol_cpe VALUES(?,?,?)", cpes)
    con.commit()
    db.source_ok(con, NAME, {"generated": data.get("generated_at")}, etag)
    products = len({c[0] for c in cycles})
    return f"{len(cycles):,} release lines for {products:,} products"
