"""CISA Known Exploited Vulnerabilities: confirmed exploitation in the wild."""

from __future__ import annotations

import json

from .. import db, net

URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NAME = "kev"


def sync(con, cfg) -> str:
    src = db.source_get(con, NAME)
    try:
        body, etag = net.get(URL, src["etag"])
    except net.NotModified:
        db.source_ok(con, NAME)
        return "unchanged"
    data = json.loads(body)
    vulns = data.get("vulnerabilities") or []
    rows, products = [], []
    for v in vulns:
        cid = v.get("cveID")
        if not cid:
            continue
        rows.append((cid, "", {
            "added": v.get("dateAdded"), "due": v.get("dueDate"),
            "name": v.get("vulnerabilityName"), "vendor": v.get("vendorProject"),
            "product": v.get("product"), "ransomware": v.get("knownRansomwareCampaignUse"),
            "action": (v.get("requiredAction") or "")[:400], "notes": (v.get("notes") or "")[:600],
        }))
        nv, np_ = db.norm(v.get("vendorProject")), db.norm(v.get("product"))
        if np_:
            products.append((cid, nv, np_))
    new = db.upsert_signals(con, NAME, rows, db.is_baseline(con, NAME), "kev")
    # KEV names products even for old CVEs whose CVE record says "n/a"
    con.executemany("INSERT OR IGNORE INTO cve_product VALUES(?,?,?)", products)
    con.commit()
    db.source_ok(con, NAME, {"catalog": data.get("catalogVersion")}, etag)
    return f"{len(rows):,} entries, {new} new"
