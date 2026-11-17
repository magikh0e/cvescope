"""Optional NVD lookup for the few CVEs the CVE List can't settle.

Some records carry no usable version data (older MITRE-era records, vendors that list only their
own rebuilds). NVD's analysts often add CPE ranges with exact fixed versions. cvescope asks NVD
only about matches that are still "check" AND showing up in act now or watch, caches the answer,
and uses it before the description heuristics.

Off by default: each lookup tells NIST a CVE ID you care about.

    [nvd]
    enabled = true
    api_key_env = "NVD_API_KEY"   # or api_key_file; optional, but ten times the rate limit
    max_per_run = 40
"""

from __future__ import annotations

import datetime as dt
import json
import time
import urllib.error
import urllib.parse
import urllib.request

from .. import db, net

URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?"
RECHECK_EMPTY_DAYS = 7     # NVD hasn't analyzed it yet: ask again in a week
RECHECK_DAYS = 60          # analyzed: configurations rarely change after that

def _flatten(cve: dict) -> list[dict]:
    out = []
    for cfg in cve.get("configurations") or []:
        for node in cfg.get("nodes") or []:
            if node.get("negate"):
                continue
            for m in node.get("cpeMatch") or []:
                if not m.get("vulnerable"):
                    continue  # platforms in "running on" configurations
                p = (m.get("criteria") or "").split(":")
                if len(p) < 6:
                    continue
                out.append({"v": p[3], "p": p[4], "ver": p[5],
                            "si": m.get("versionStartIncluding"), "se": m.get("versionStartExcluding"),
                            "ei": m.get("versionEndIncluding"), "ee": m.get("versionEndExcluding")})
    return out


def _key(cfg) -> str | None:
    from ..collectors import secret
    n = cfg.get("nvd") or {}
    if not (n.get("api_key_file") or n.get("api_key_env")):
        return None
    try:
        return secret(n, "api_key")
    except Exception:
        return None


def candidates(con, cfg) -> list[str]:
    """Check-status matches that are visible (act/watch) and not freshly cached."""
    from .. import query
    ids = {m["cve_id"] for m in query.matches(con, cfg, tiers=("act", "watch")) if m["status"] == "check"}
    now = dt.datetime.now(dt.timezone.utc)
    fresh = set()
    for cid, fetched, cpes in con.execute("SELECT cve_id, fetched, cpes FROM nvd_cpe"):
        try:
            age = (now - dt.datetime.fromisoformat(fetched.replace("Z", "+00:00"))).days
        except (ValueError, AttributeError):
            continue
        if age < (RECHECK_DAYS if cpes not in (None, "[]") else RECHECK_EMPTY_DAYS):
            fresh.add(cid)
    return sorted(ids - fresh)


def enrich(con, cfg) -> tuple[int, str]:
    """Fetch NVD data for the candidates. Returns (number fetched, summary line)."""
    todo = candidates(con, cfg)
    limit = int((cfg.get("nvd") or {}).get("max_per_run", 40))
    if not todo:
        return 0, "nothing to look up"
    key = _key(cfg)
    pause = 0.7 if key else 6.5  # NVD: 50 requests / 30 s with a key, 5 without
    headers = {"apiKey": key} if key else {}
    fetched, failed = 0, 0
    for cid in todo[:limit]:
        try:
            req = urllib.request.Request(URL + urllib.parse.urlencode({"cveId": cid}),
                                             headers={"User-Agent": net.UA, **headers})
            with urllib.request.urlopen(req, timeout=60) as r:
                data = json.loads(r.read())
        except urllib.error.HTTPError as e:
            if key and e.code in (403, 404) and "apikey" in (e.headers.get("message") or "").lower():
                key, headers, pause = None, {}, 6.5  # a rejected key: carry on without one
                print("  NVD rejected the API key; continuing without it (slower)")
                time.sleep(pause)
                continue
            failed += 1
            if failed >= 3:
                break
            time.sleep(pause * 4)
            continue
        except Exception:
            failed += 1
            if failed >= 3:
                break
            time.sleep(pause * 4)
            continue
        vulns = data.get("vulnerabilities") or []
        cve = vulns[0]["cve"] if vulns else {}
        con.execute("INSERT OR REPLACE INTO nvd_cpe VALUES(?,?,?,?)",
                    (cid, db.now(), cve.get("vulnStatus"), json.dumps(_flatten(cve), separators=(",", ":"))))
        con.commit()
        fetched += 1
        time.sleep(pause)
    rest = max(0, len(todo) - limit)
    msg = f"{fetched} looked up" + (f", {failed} failed" if failed else "") + (f", {rest} left for next run" if rest else "")
    return fetched, msg
