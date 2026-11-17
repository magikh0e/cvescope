"""CVE List (CVEProject/cvelistV5): the backbone.

First run downloads the full midnight snapshot (~660 MB zip, imported once).
After that it applies the published delta zips: one end-of-day zip per finished
day, then today's latest hourly zip (cumulative since midnight).
CISA's Vulnrichment (SSVC + CPEs) arrives inside these records as an ADP container.
"""

from __future__ import annotations

import datetime as dt
import json
import zipfile
from pathlib import Path

from .. import db, net

REL = "https://github.com/CVEProject/cvelistV5/releases/download"
API_LATEST = "https://api.github.com/repos/CVEProject/cvelistV5/releases/latest"
NAME = "cvelist"

_METRIC_KEYS = ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0")
_SSVC_LEVEL = {"none": 0, "poc": 1, "active": 2}


# ---- record parsing -----------------------------------------------------

def _cpe_vp(cpe: str):
    if cpe.startswith("cpe:2.3:"):
        p = cpe.split(":")
        if len(p) > 4:
            return p[3], p[4]
    elif cpe.startswith("cpe:/"):
        p = cpe[5:].split(":")
        if len(p) > 2:
            return p[1], p[2]
    return None


def parse(rec: dict) -> dict | None:
    md = rec.get("cveMetadata") or {}
    cid = md.get("cveId")
    if not cid:
        return None
    cont = rec.get("containers") or {}
    cna = cont.get("cna") or {}
    adps = cont.get("adp") or []
    state = md.get("state") or "PUBLISHED"

    def en(items):
        for d in items or []:
            if str(d.get("lang", "")).lower().startswith("en"):
                return d.get("value") or ""
        return (items or [{}])[0].get("value", "") if items else ""

    if state == "REJECTED":
        desc = en(cna.get("rejectedReasons"))
    else:
        desc = en(cna.get("descriptions"))

    cvss = ver = vec = sev = None
    for src in [cna] + adps:
        for m in src.get("metrics") or []:
            for k in _METRIC_KEYS:
                if k in m and cvss is None:
                    d = m[k]
                    cvss, vec = d.get("baseScore"), d.get("vectorString")
                    sev = d.get("baseSeverity")
                    ver = k.replace("cvssV", "").replace("_", ".")
        if cvss is not None:
            break

    ssvc = {}
    for a in adps:
        for m in a.get("metrics") or []:
            o = m.get("other") or {}
            if o.get("type") == "ssvc":
                for opt in (o.get("content") or {}).get("options") or []:
                    ssvc.update({k.lower(): str(v).lower() for k, v in opt.items()})

    cwes = []
    for src in [cna] + adps:
        for pt in src.get("problemTypes") or []:
            for d in pt.get("descriptions") or []:
                c = d.get("cweId")
                if c and c not in cwes:
                    cwes.append(c)

    affected, products = [], set()
    for tag, src in [("cna", cna)] + [("adp", a) for a in adps]:
        for a in src.get("affected") or []:
            vendor = a.get("vendor") or ""
            product = a.get("product") or a.get("packageName") or ""
            # git-hash ranges can't be compared to an installed version; dropping them first
            # keeps the semver tail that kernel.org records put after dozens of commits
            vs = [{k: v for k, v in x.items()
                   if k in ("version", "lessThan", "lessThanOrEqual", "status", "versionType")}
                  for x in (a.get("versions") or [])
                  if str(x.get("versionType") or "").lower() != "git"][:200]
            cpes = [c for c in (a.get("cpes") or []) if isinstance(c, str)][:20]
            pkg = a.get("packageName") or ""
            entry = {"src": tag, "v": vendor, "p": product, "ds": a.get("defaultStatus"), "vs": vs, "cpes": cpes}
            if pkg and pkg != product:
                entry["pkg"] = pkg  # e.g. the WordPress plugin slug next to its display name
            affected.append(entry)
            nv, np_ = db.norm(vendor), db.norm(product)
            if np_:
                products.add((nv, np_))
            if pkg and db.norm(pkg) != np_:
                products.add((nv, db.norm(pkg)))
            for c in cpes:
                vp = _cpe_vp(c)
                if vp and db.norm(vp[1]) and vp[1] != "*":
                    products.add((db.norm(vp[0]), db.norm(vp[1])))

    refs = [r.get("url") for r in (cna.get("references") or []) if r.get("url")][:25]
    return {
        "id": cid, "state": state, "assigner": md.get("assignerShortName"),
        "published": md.get("datePublished"), "updated": md.get("dateUpdated"),
        "title": cna.get("title"), "description": (desc or "")[:4000],
        "cvss": cvss, "cvss_version": ver, "cvss_vector": vec, "severity": sev,
        "cwe": ",".join(cwes[:5]) or None,
        "ssvc_exploitation": ssvc.get("exploitation"),
        "ssvc_automatable": ssvc.get("automatable"),
        "ssvc_impact": ssvc.get("technical impact"),
        "noprod": 0 if products else 1,
        "affected": json.dumps(affected, separators=(",", ":")),
        "refs": json.dumps(refs, separators=(",", ":")),
        "_products": products,
    }


_COLS = ("id", "state", "assigner", "published", "updated", "title", "description", "cvss",
         "cvss_version", "cvss_vector", "severity", "cwe", "ssvc_exploitation",
         "ssvc_automatable", "ssvc_impact", "noprod", "affected", "refs")
_INSERT = f"INSERT OR REPLACE INTO cve({','.join(_COLS)}) VALUES({','.join('?' * len(_COLS))})"


def _write(con, rows: list[dict], baseline: bool):
    if not rows:
        return
    if not baseline:
        ids = [(r["id"],) for r in rows]
        old = {}
        q = "SELECT id, ssvc_exploitation FROM cve WHERE id IN (%s)"
        for i in range(0, len(ids), 500):
            chunk = [x[0] for x in ids[i:i + 500]]
            for r in con.execute(q % ",".join("?" * len(chunk)), chunk):
                old[r[0]] = r[1]
        con.executemany("DELETE FROM cve_product WHERE cve_id=?", ids)
        for r in rows:
            if r["state"] != "PUBLISHED":
                continue
            if r["id"] not in old:
                db.add_event(con, r["id"], "new_cve", {"published": r["published"]})
            before = _SSVC_LEVEL.get(old.get(r["id"]) or "none", 0)
            after = _SSVC_LEVEL.get(r["ssvc_exploitation"] or "none", 0)
            if after > before:
                db.add_event(con, r["id"], "ssvc", {"exploitation": r["ssvc_exploitation"]})
    con.executemany(_INSERT, [tuple(r[c] for c in _COLS) for r in rows])
    con.executemany("INSERT OR IGNORE INTO cve_product VALUES(?,?,?)",
                    [(r["id"], v, p) for r in rows for (v, p) in r["_products"]])


def _import_zip(con, zf: zipfile.ZipFile, baseline: bool, label: str) -> int:
    names = [n for n in zf.namelist()
             if n.endswith(".json") and "/CVE-" in "/" + n and "delta" not in n.split("/")[-1].lower()]
    batch, total = [], 0
    for i, n in enumerate(names):
        try:
            rec = json.loads(zf.read(n))
        except (ValueError, KeyError):
            continue
        r = parse(rec)
        if r:
            batch.append(r)
        if len(batch) >= 5000:
            _write(con, batch, baseline)
            con.commit()
            total += len(batch)
            batch = []
            if baseline and total % 50000 == 0:
                print(f"    {label}: {total:,} / {len(names):,}", flush=True)
    _write(con, batch, baseline)
    con.commit()
    return total + len(batch)


# ---- release discovery --------------------------------------------------

def _eod(day: dt.date) -> str:
    d = day.isoformat()
    return f"{REL}/cve_{d}_at_end_of_day/{d}_delta_CVEs_at_end_of_day.zip"


def _hourly(day: dt.date, hour: int) -> str:
    d = day.isoformat()
    return f"{REL}/cve_{d}_{hour:02d}00Z/{d}_delta_CVEs_at_{hour:02d}00Z.zip"


def _baseline(con, cache: Path):
    print("  cvelist: first run, fetching the full CVE List snapshot (~660 MB, one time)")
    body, _ = net.get(API_LATEST)
    rel = json.loads(body)
    asset = next(a for a in rel["assets"] if a["name"].endswith("all_CVEs_at_midnight.zip.zip"))
    day = dt.date.fromisoformat(asset["name"][:10])
    outer = cache / asset["name"]
    if not (outer.exists() and outer.stat().st_size == asset["size"]):
        for old in cache.glob("*_all_CVEs_at_midnight.zip.zip"):
            old.unlink()
        net.download(asset["browser_download_url"], outer, timeout=1800, progress=True)
    inner = cache / "cves.zip"
    print("  cvelist: unpacking")
    with zipfile.ZipFile(outer) as z:
        member = next(n for n in z.namelist() if n.endswith(".zip"))
        with z.open(member) as src, open(inner, "wb") as dst:
            while chunk := src.read(1 << 22):
                dst.write(chunk)
    print("  cvelist: importing records")
    con.execute("DELETE FROM cve")
    con.execute("DELETE FROM cve_product")
    con.execute("UPDATE source SET etag=NULL WHERE name='kev'")  # KEV re-adds its product names
    con.execute("DELETE FROM meta WHERE key='match_done'")  # next match is a quiet baseline too
    with zipfile.ZipFile(inner) as z:
        n = _import_zip(con, z, True, "baseline")
    inner.unlink()
    outer.unlink()  # the import is the copy we keep
    print(f"  cvelist: {n:,} records from the {day} snapshot")
    return {"baseline": day.isoformat(), "done_day": (day - dt.timedelta(days=1)).isoformat(),
            "today": None, "today_hour": -1}


def _apply(con, url: str, cache: Path, baseline: bool) -> int | None:
    tmp = cache / "delta.zip"
    try:
        net.download(url, tmp, timeout=300)
    except net.HTTPStatus as e:
        if e.code == 404:
            return None
        raise
    with zipfile.ZipFile(tmp) as z:
        n = _import_zip(con, z, baseline, "delta")
    tmp.unlink()
    return n


def sync(con, cfg, rebaseline: bool = False) -> str:
    src = db.source_get(con, NAME)
    st = src["state"]
    first = not st.get("baseline") or rebaseline
    if first:
        st = _baseline(con, cfg.cache_dir)
    now = dt.datetime.now(dt.timezone.utc)
    today = now.date()
    done = dt.date.fromisoformat(st["done_day"])
    changed = 0
    day = done + dt.timedelta(days=1)
    while day < today:
        n = _apply(con, _eod(day), cfg.cache_dir, first)
        if n is None:
            # end-of-day zip not published (yet / anymore): fall back to its last hourly
            for h in range(23, -1, -1):
                n = _apply(con, _hourly(day, h), cfg.cache_dir, first)
                if n is not None:
                    break
        if n is None:
            raise RuntimeError(f"no delta for {day}; run `cvescope sync --rebaseline`")
        changed += n
        st["done_day"] = day.isoformat()
        st["today"], st["today_hour"] = None, -1
        db.source_ok(con, NAME, st)
        day += dt.timedelta(days=1)
    for h in range(now.hour, -1, -1):
        if st.get("today") == today.isoformat() and h <= st.get("today_hour", -1):
            break
        n = _apply(con, _hourly(today, h), cfg.cache_dir, first)
        if n is not None:
            changed += n
            st["today"], st["today_hour"] = today.isoformat(), h
            break
    db.source_ok(con, NAME, st)
    total = con.execute("SELECT count(*) FROM cve").fetchone()[0]
    return f"{total:,} CVEs, {changed:,} updated this run"
