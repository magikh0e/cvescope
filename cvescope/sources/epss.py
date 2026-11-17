"""FIRST EPSS: daily probability of exploitation in the next 30 days."""

from __future__ import annotations

import csv
import gzip
import io

from .. import db, net

URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
NAME = "epss"


def sync(con, cfg) -> str:
    src = db.source_get(con, NAME)
    try:
        body, etag = net.get(URL, src["etag"])
    except net.NotModified:
        db.source_ok(con, NAME)
        return "unchanged"
    text = gzip.decompress(body).decode("utf-8", "replace")
    lines = text.splitlines()
    date = ""
    if lines and lines[0].startswith("#"):
        for part in lines[0][1:].split(","):
            if part.startswith("score_date:"):
                date = part.split(":", 1)[1][:10]
        lines = lines[1:]
    if src["state"].get("date") == date and date:
        db.source_ok(con, NAME, None, etag)
        return f"already have {date}"
    reader = csv.DictReader(io.StringIO("\n".join(lines)))
    rows = [(r["cve"], float(r["epss"]), float(r["percentile"]), date) for r in reader]

    baseline = db.is_baseline(con, NAME)
    jump = float(cfg["tiers"]["epss_jump"])
    watch = float(cfg["tiers"]["epss_watch_pct"])
    if not baseline:
        # only matched CVEs get EPSS events; the whole list moves a little every day
        matched = {r[0] for r in con.execute("SELECT DISTINCT cve_id FROM match")}
        old = {r[0]: r[1] for r in con.execute("SELECT cve_id, pct FROM epss")}
        for cid, score, pct, _ in rows:
            if cid not in matched:
                continue
            before = old.get(cid, 0.0)
            if pct - before >= jump or (before < watch <= pct):
                db.add_event(con, cid, "epss", {"from": round(before, 4), "to": round(pct, 4),
                                                "score": score})
    con.execute("UPDATE epss SET prev_pct = pct")
    con.executemany(
        "INSERT INTO epss(cve_id,score,pct,prev_pct,date) VALUES(?,?,?,NULL,?) "
        "ON CONFLICT(cve_id) DO UPDATE SET score=excluded.score, pct=excluded.pct, date=excluded.date",
        rows,
    )
    con.commit()
    db.source_ok(con, NAME, {"date": date}, etag)
    return f"{len(rows):,} scores for {date}"
