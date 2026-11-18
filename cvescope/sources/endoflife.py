"""endoflife.date: per product, each release line's newest release and when it stops getting fixes.

Two uses:
- A CVE record can name its fix before that release is out: OpenSSL's records said "fixed in
  3.5.10" while 3.5.9 was still the newest 3.5 release. Matching reads the newest releases to
  tell an announced fix from one you can install (match._apply_unreleased).
- An item on a release line past end of life gets no more fixes, whatever its CVE count says
  (eol.py).

One bulk download covers every product (~320 KB gzipped, conditional GET), so the request says
nothing about what you run. Products are tied to inventory items through the CPE
vendor:product pairs endoflife.date lists for them. Data: https://endoflife.date
"""

from __future__ import annotations

import json

from .. import db, net
from .cvelist import _cpe_vp

URL = "https://endoflife.date/api/v1/products/full"
NAME = "endoflife"
PARSER = 2  # bump when parse() keeps more: the next sync refetches instead of trusting the ETag


def _flag(v) -> int | None:
    return None if v is None else int(bool(v))


def parse(data: dict) -> tuple[list[tuple], list[tuple], list[tuple]]:
    """-> (release lines, CPE names (vendor, product, eol product), products (name, label, eoes label, link)).

    A release line is (product, cycle, latest, latest_date, eol_from, is_eol, eoes_from, is_eoes).
    """
    cycles, cpes, products = [], set(), []
    for p in data.get("result") or []:
        name = p.get("name")
        if not name:
            continue
        labels = p.get("labels") or {}
        products.append((name, p.get("label") or name, labels.get("eoes"),
                         (p.get("links") or {}).get("html") or f"https://endoflife.date/{name}"))
        for r in p.get("releases") or []:
            if not r.get("name"):
                continue
            latest = r.get("latest") or {}
            cycles.append((name, str(r["name"]), latest.get("name"), latest.get("date"),
                           r.get("eolFrom"), _flag(r.get("isEol")), r.get("eoesFrom"), _flag(r.get("isEoes"))))
        for i in p.get("identifiers") or []:
            if i.get("type") == "cpe":
                vp = _cpe_vp(str(i.get("id") or ""))
                if vp and db.norm(vp[0]) and db.norm(vp[1]):
                    cpes.add((db.norm(vp[0]), db.norm(vp[1]), name))
    return cycles, sorted(cpes), products


def sync(con, cfg) -> str:
    src = db.source_get(con, NAME)
    etag = src["etag"] if (src.get("state") or {}).get("parser") == PARSER else None
    try:
        body, etag = net.get(URL, etag, compressed=True)
    except net.NotModified:
        db.source_ok(con, NAME)
        return "unchanged"
    data = json.loads(body)
    cycles, cpes, products = parse(data)
    if not cycles:  # keep the last good copy rather than forget every release
        raise ValueError("the endoflife.date feed listed no releases")
    con.execute("DELETE FROM eol_cycle")
    con.execute("DELETE FROM eol_cpe")
    con.execute("DELETE FROM eol_product")
    con.executemany("INSERT OR REPLACE INTO eol_cycle(product, cycle, latest, latest_date, eol_from, is_eol, "
                    "eoes_from, is_eoes) VALUES(?,?,?,?,?,?,?,?)", cycles)
    con.executemany("INSERT OR REPLACE INTO eol_cpe VALUES(?,?,?)", cpes)
    con.executemany("INSERT OR REPLACE INTO eol_product VALUES(?,?,?,?)", products)
    con.commit()
    db.source_ok(con, NAME, {"generated": data.get("generated_at"), "parser": PARSER}, etag)
    return f"{len(cycles):,} release lines for {len(products):,} products"
