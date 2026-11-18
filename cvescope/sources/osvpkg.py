"""OSV.dev advisories for the packages your items name: PyPI `homeassistant`, and every
language package an SBOM lists (npm, Maven, Go, crates.io, ...).

Items carry extra.osv = {"ecosystem": "PyPI", "name": "homeassistant"}. Each sync asks OSV.dev
which advisories exist for all of those packages in one batch query (up to 1000 packages per
request), then downloads only advisories it hasn't seen or that changed since. The matcher
lets them decide the CVEs they name.
"""

from __future__ import annotations

import json
import urllib.parse
from concurrent.futures import ThreadPoolExecutor

from .. import db, net, vulnid

URL = "https://api.osv.dev/v1/query"
BATCH_URL = "https://api.osv.dev/v1/querybatch"
VULN_URL = "https://api.osv.dev/v1/vulns/{}"
BATCH = 1000


def wanted(con) -> set[tuple[str, str]]:
    out = set()
    for (extra,) in con.execute("SELECT extra FROM item"):
        o = json.loads(extra or "{}").get("osv")
        if isinstance(o, dict) and o.get("ecosystem") and o.get("name"):
            out.add((o["ecosystem"], o["name"]))
    return out


def rows_for(vulns: list[dict], eco: str, name: str) -> list[tuple]:
    """One row per (CVE, advisory) for this package. An advisory often has one affected block
    per release line (log4j-core 2.0-beta9..2.3.1, 2.4..2.12.2, 2.13.0..2.15.0): all of them
    are merged into the row, so the matcher sees every line."""
    rows = []
    for v in vulns:
        cves = sorted({a for a in (v.get("aliases") or []) + [v.get("id") or ""] if a.startswith("CVE-")})
        if not cves:  # no CVE: filed under its GHSA (or its own ID) and shown as an advisory
            cves = [vulnid.pick([a for a in v.get("aliases") or [] if a.upper().startswith("GHSA-")] + [v.get("id")])]
        versions, ranges = [], []
        for a in v.get("affected") or []:
            p = a.get("package") or {}
            if p.get("ecosystem") != eco or (p.get("name") or "").lower() != name.lower():
                continue
            versions += [x for x in a.get("versions") or [] if x not in versions]
            for r in a.get("ranges") or []:
                if r.get("type") in ("ECOSYSTEM", "SEMVER"):
                    ranges.append([[k, e[k]] for e in r.get("events") or [] for k in e])
        if not versions and not ranges:
            continue
        fixed = next((val for evs in reversed(ranges) for k, val in reversed(evs) if k == "fixed"), None)
        for c in cves:
            rows.append((eco, name, c, v.get("id"), json.dumps(versions), json.dumps(ranges), fixed))
    return rows


def advisory_ids(pkgs: list[tuple[str, str]]) -> dict[tuple[str, str], dict[str, str]]:
    """(ecosystem, name) -> {advisory id: modified}, from batch queries."""
    out: dict[tuple[str, str], dict[str, str]] = {}
    for i in range(0, len(pkgs), BATCH):
        chunk = pkgs[i:i + BATCH]
        d = net.post_json(BATCH_URL, {"queries": [{"package": {"ecosystem": e, "name": n}} for e, n in chunk]},
                          timeout=300)
        for (e, n), res in zip(chunk, d.get("results") or []):
            got = {v["id"]: v.get("modified") or "" for v in res.get("vulns") or [] if v.get("id")}
            token = res.get("next_page_token")
            for _ in range(50):  # a package with more advisories than one page holds
                if not token:
                    break
                more = net.post_json(URL, {"package": {"ecosystem": e, "name": n}, "page_token": token}, timeout=120)
                got.update({v["id"]: v.get("modified") or "" for v in more.get("vulns") or [] if v.get("id")})
                token = more.get("next_page_token")
            out[(e, n)] = got
    return out


def _fetch(vid: str) -> tuple[str, dict]:
    body, _ = net.get(VULN_URL.format(urllib.parse.quote(vid, safe="")), timeout=120)
    return vid, json.loads(body)


SLIM = 2  # bump when _slim keeps more, so cached advisories are fetched again


def _slim(v: dict) -> dict:
    """Keep what rows_for reads, plus what the page shows for an advisory without a CVE."""
    sev = ((v.get("database_specific") or {}).get("severity") or "").upper()
    return {"v": SLIM, "id": v.get("id"), "modified": v.get("modified"), "aliases": v.get("aliases") or [],
            "summary": (v.get("summary") or "")[:300], "details": (v.get("details") or "")[:2000],
            "published": v.get("published"), "severity": {"MODERATE": "MEDIUM"}.get(sev, sev) or None,
            "vector": next((s.get("score") for s in v.get("severity") or [] if str(s.get("type", "")).startswith("CVSS")), None),
            "refs": [r.get("url") for r in v.get("references") or [] if r.get("url")][:10],
            "affected": [{"package": a.get("package") or {}, "ranges": a.get("ranges") or [],
                          "versions": a.get("versions") or []} for a in v.get("affected") or []]}


def advisory_record(vid: str, v: dict) -> dict:
    """An advisory with no CVE, as a row for the cve table."""
    first = (f"https://github.com/advisories/{vid}" if vid.startswith("GHSA-")
             else f"https://osv.dev/vulnerability/{vid}")
    return {"id": vid, "assigner": "GitHub" if vid.startswith("GHSA-") else "OSV.dev",
            "published": v.get("published"), "updated": v.get("modified"), "title": v.get("summary"),
            "description": v.get("details") or v.get("summary"), "severity": v.get("severity"),
            "cvss_vector": v.get("vector"), "refs": [first] + [u for u in v.get("refs") or [] if u != first]}


def sync(con, cfg) -> str:
    pkgs = sorted(wanted(con))
    if not pkgs:
        return "no items name an OSV package"
    ids = advisory_ids(pkgs)
    cached = dict(con.execute("SELECT id, modified FROM osv_vuln WHERE data LIKE ?", (f'%"v":{SLIM},%',)).fetchall())
    mod_of = {vid: mod for got in ids.values() for vid, mod in got.items()}
    need = sorted(vid for vid, mod in mod_of.items() if not mod or cached.get(vid) != mod)
    fetched = 0
    if need:
        with ThreadPoolExecutor(max_workers=8) as pool:
            for vid, v in pool.map(_fetch, need):
                # keep the batch's timestamp: the full advisory spells "modified" with other precision
                con.execute("INSERT OR REPLACE INTO osv_vuln VALUES(?,?,?)",
                            (vid, mod_of.get(vid) or v.get("modified") or "", json.dumps(_slim(v), separators=(",", ":"))))
                fetched += 1
        con.commit()
    keep = {vid for got in ids.values() for vid in got}
    for (vid,) in con.execute("SELECT id FROM osv_vuln").fetchall():
        if vid not in keep:
            con.execute("DELETE FROM osv_vuln WHERE id = ?", (vid,))
    data = {vid: json.loads(d) for vid, d in con.execute("SELECT id, data FROM osv_vuln")}
    rows = []
    for (eco, name), got in ids.items():
        rows += rows_for([data[v] for v in got if v in data], eco, name)
    # advisories filed under their own ID get a record of their own, refreshed every sync
    by_id = {}
    for d in data.values():
        for key in [d.get("id")] + list(d.get("aliases") or []):
            by_id.setdefault(vulnid.canon(key), d)
    db.put_advisories(con, [advisory_record(vid, by_id[vid]) for vid in {r[2] for r in rows}
                            if not vulnid.is_cve(vid) and vid in by_id])
    con.execute("DELETE FROM osv_pkg")
    con.executemany("INSERT OR REPLACE INTO osv_pkg VALUES(?,?,?,?,?,?,?)", rows)
    con.commit()
    db.source_ok(con, "osv")
    with_adv = sum(1 for got in ids.values() if got)
    return (f"{len(pkgs)} package{'s' if len(pkgs) != 1 else ''}, {with_adv} with advisories, "
            f"{len(keep)} advisories ({fetched} downloaded)")
