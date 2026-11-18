"""OSV.dev advisories for the packages your items name, such as PyPI `homeassistant`.

Home Assistant Core is published on PyPI as `homeassistant`. Its GitHub security advisories
(GHSA, plus PyPA's PYSEC copies) reach OSV.dev listing every release each one affects. Items
carry extra.osv = {"ecosystem": "PyPI", "name": "homeassistant"}; this source asks OSV.dev for
those packages' advisories (one small query per package per sync) and the matcher lets them
decide the CVEs they name.
"""

from __future__ import annotations

import json

from .. import db, net

URL = "https://api.osv.dev/v1/query"


def wanted(con) -> set[tuple[str, str]]:
    out = set()
    for (extra,) in con.execute("SELECT extra FROM item"):
        o = json.loads(extra or "{}").get("osv")
        if isinstance(o, dict) and o.get("ecosystem") and o.get("name"):
            out.add((o["ecosystem"], o["name"]))
    return out


def rows_for(vulns: list[dict], eco: str, name: str) -> list[tuple]:
    rows = []
    for v in vulns:
        cves = sorted({a for a in (v.get("aliases") or []) + [v.get("id") or ""] if a.startswith("CVE-")})
        if not cves:
            continue  # advisories with no CVE can't be tied to a CVE record
        for a in v.get("affected") or []:
            p = a.get("package") or {}
            if p.get("ecosystem") != eco or (p.get("name") or "").lower() != name.lower():
                continue
            ranges, fixed = [], None
            for r in a.get("ranges") or []:
                if r.get("type") not in ("ECOSYSTEM", "SEMVER"):
                    continue
                evs = [[k, e[k]] for e in r.get("events") or [] for k in e]
                fixed = next((val for k, val in reversed(evs) if k == "fixed"), fixed)
                ranges.append(evs)
            for c in cves:
                rows.append((eco, name, c, v.get("id"), json.dumps(a.get("versions") or []),
                             json.dumps(ranges), fixed))
    return rows


def sync(con, cfg) -> str:
    pkgs = wanted(con)
    if not pkgs:
        return "no items name an OSV package"
    rows, counts = [], []
    for eco, name in sorted(pkgs):
        vulns, token = [], None
        for _ in range(20):  # pages
            q = {"package": {"ecosystem": eco, "name": name}}
            if token:
                q["page_token"] = token
            d = net.post_json(URL, q, timeout=120)
            vulns += d.get("vulns") or []
            token = d.get("next_page_token")
            if not token:
                break
        got = rows_for(vulns, eco, name)
        rows += got
        counts.append(f"{name} {len(vulns)} advisories")
    con.execute("DELETE FROM osv_pkg")
    con.executemany("INSERT OR REPLACE INTO osv_pkg VALUES(?,?,?,?,?,?,?)", rows)
    con.commit()
    db.source_ok(con, "osv")
    return "; ".join(counts)
