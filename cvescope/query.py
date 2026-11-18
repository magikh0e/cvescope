"""Read side: tiers, match lists, CVE detail, events. Shared by the CLI, web page and notifier."""

from __future__ import annotations

import datetime as dt
import json
import re

from . import acks, db

TIER_LABEL = {"act": "Act now", "watch": "Watch", "info": "Info"}
TIER_ORDER = {"act": 0, "watch": 1, "info": 2}
STATUS_ORDER = {"affected": 0, "check": 1, "keyword": 2, "not_affected": 3}
SIG_LABEL = {"kev": "KEV", "msf": "Metasploit", "nuclei": "Nuclei", "edb": "Exploit-DB",
             "poc": "GitHub PoC", "local": "archive"}


# Collectors name items "Product (where)": "OpenSSH (h0evpn)", "Linux kernel (VM 100 UnFi)".
# The part in brackets is the host, unless it names a role on the collector's own box.
_TYPE_NAME = {"homeassistant": "Home Assistant", "opnsense": "OPNsense", "unifi": "UniFi", "proxmox": "Proxmox",
              "pihole": "Pi-hole", "osquery": "osquery", "docker": "Docker"}
_ROLE = {"ha add-on", "opnsense base"}
_PAREN = re.compile(r"\(([^()]+)\)\s*$")


def _collector_host(collector: str) -> str:
    typ, _, label = (collector or "").partition(":")
    m = _PAREN.search(label)
    if m:  # "Proxmox VE (PVE1)"
        return m.group(1).strip()
    if not label or "://" in label or re.fullmatch(r"\w+#\d+", label):  # a URL or an unnamed entry
        return _TYPE_NAME.get(typ, typ or "unknown")
    return label


def host_of(name: str, collector: str) -> str:
    """Which machine an item lives on, for grouping and filtering the page."""
    base = _collector_host(collector)
    m = _PAREN.search(name or "")
    if not m:
        return base
    p = m.group(1).strip()
    if p.lower() in _ROLE or p.lower().startswith(base.lower()):
        return base
    return p


def signals_for(con, ids) -> dict[str, dict[str, list]]:
    out: dict[str, dict[str, list]] = {}
    ids = list(ids)
    for i in range(0, len(ids), 500):
        chunk = ids[i:i + 500]
        q = f"SELECT cve_id, source, key, first_seen, data FROM signal WHERE cve_id IN ({','.join('?' * len(chunk))})"
        for r in con.execute(q, chunk):
            d = json.loads(r["data"] or "{}")
            d["key"], d["first_seen"] = r["key"], r["first_seen"]
            out.setdefault(r["cve_id"], {}).setdefault(r["source"], []).append(d)
    return out


def tier(sig: dict, cve: dict, epss_pct, cfg) -> tuple[str, list[str]]:
    """-> (tier, reasons). act = exploited or point-and-shoot; watch = public exploit or likely."""
    why = []
    cvss = cve.get("cvss") or 0
    ssvc = cve.get("ssvc_exploitation")
    msf_exploit = any(m.get("type") == "exploit" for m in sig.get("msf", []))
    if "kev" in sig:
        why.append("exploited in the wild (CISA KEV)")
    if ssvc == "active":
        why.append("CISA SSVC: active exploitation")
    if msf_exploit:
        why.append("Metasploit exploit module")
    if "nuclei" in sig and cvss >= 7:
        why.append("Nuclei template (mass-scannable)")
    if why:
        return "act", why
    if sig.get("msf"):
        why.append("Metasploit auxiliary module")
    if "nuclei" in sig:
        why.append("Nuclei template")
    if "edb" in sig:
        why.append("Exploit-DB")
    if "poc" in sig:
        why.append(f"{len(sig['poc'])} GitHub PoC repo(s)")
    if "local" in sig:
        why.append("in your exploit archive")
    if ssvc == "poc":
        why.append("CISA SSVC: PoC public")
    if epss_pct is not None and epss_pct >= float(cfg["tiers"]["epss_watch_pct"]):
        why.append(f"EPSS top {100 - epss_pct * 100:.0f}%")
    return ("watch" if why else "info"), why


def flag_text(r: dict) -> list[str]:
    return [SIG_LABEL[s] for s in ("kev", "msf", "nuclei", "edb", "poc", "local") if s in r.get("signals", {})]


def matches(con, cfg, tiers=("act", "watch", "info"), include_keyword=False, item_id=None,
            statuses=("affected", "check", "keyword"), limit=None, cve_ids=None,
            acked="hide") -> list[dict]:
    """Matched CVEs with tier and reasons. acked: "hide" drops acknowledged matches (lapsed and
    expired ones stay), "include" keeps them, "only" returns just those."""
    q = ("SELECT m.cve_id, m.item_id, m.status, m.how, m.detail, m.first_seen, i.name AS item_name, "
         "i.version AS item_version, i.extra AS item_extra, i.collector AS item_collector, c.title, c.description, c.cvss, c.severity, "
         "c.published, c.ssvc_exploitation, c.ssvc_automatable, c.ssvc_impact, e.pct AS epss_pct, "
         "e.score AS epss "
         "FROM match m JOIN item i ON i.id=m.item_id JOIN cve c ON c.id=m.cve_id "
         "LEFT JOIN epss e ON e.cve_id=m.cve_id WHERE m.status IN (%s)" % ",".join("?" * len(statuses)))
    args = list(statuses)
    if not include_keyword:
        q += " AND m.status != 'keyword'"
    if item_id:
        q += " AND m.item_id = ?"
        args.append(item_id)
    if cve_ids is not None:
        cve_ids = list(cve_ids)
        if not cve_ids:
            return []
        q += f" AND m.cve_id IN ({','.join('?' * len(cve_ids))})"
        args += cve_ids
    rows = [dict(r) for r in con.execute(q, args)]
    sigs = signals_for(con, {r["cve_id"] for r in rows})
    ack_rows = acks.load(con)
    out = []
    for r in rows:
        s = sigs.get(r["cve_id"], {})
        t, why = tier(s, r, r["epss_pct"], cfg)
        backports = json.loads(r.pop("item_extra") or "{}").get("backports")
        r["host"] = host_of(r["item_name"], r.pop("item_collector"))
        # A "check" on a distro or vendor build (Proxmox kernel, FreeBSD base, a dpkg package no
        # tracker answered) means "upstream says affected, the vendor may have patched it". A PoC
        # or a high EPSS isn't enough to bother anyone with that; real exploitation (act) is.
        if r["status"] == "check" and backports and t != "act":
            continue
        if t not in tiers:
            continue
        r["tier"], r["why"] = t, why
        a = ack_rows.get((r["cve_id"], r["item_id"]))
        if a:
            st, reason = acks.state(a, t, r["status"], acks.evidence_keys(s, r["ssvc_exploitation"]))
            r["ack"] = {"created": a["created"], "until": a["until"], "note": a["note"],
                        "state": st, "reason": reason}
        active = bool(a) and r["ack"]["state"] == "active"
        if (acked == "hide" and active) or (acked == "only" and not active):
            continue
        r["signals"] = {k: len(v) for k, v in s.items()}
        r["description"] = (r["description"] or "")[:400]
        out.append(r)
    out.sort(key=lambda r: (TIER_ORDER[r["tier"]], STATUS_ORDER.get(r["status"], 9),
                            -(r["epss_pct"] or 0), -(r["cvss"] or 0)))
    return out[:limit] if limit else out


def _poc_flags(p: dict, published: str | None) -> list[str]:
    """Heuristics for fake/malicious PoC repos. Shown as warnings, never as a verdict."""
    f = []
    if not p.get("stars") and not p.get("forks"):
        f.append("no stars or forks")
    d = (p.get("description") or "").lower()
    if any(w in d for w in ("download", "release", ".exe", ".zip", "password", "telegram", "contact me",
                            "buy", "private exploit", "sell")):
        f.append("description pushes a download/contact")
    if not d:
        f.append("no description")
    try:
        created = dt.datetime.fromisoformat(p["created"].replace("Z", "+00:00"))
        if published:
            pub = dt.datetime.fromisoformat(published.replace("Z", "+00:00"))
            if (created - pub).days < 2:
                f.append("created within 2 days of disclosure")
    except (KeyError, ValueError, TypeError, AttributeError):
        pass
    return f


def cve_detail(con, cfg, cid: str) -> dict | None:
    r = con.execute("SELECT * FROM cve WHERE id=?", (cid,)).fetchone()
    if not r:
        return None
    d = dict(r)
    d["affected"] = json.loads(d["affected"] or "[]")
    d["refs"] = json.loads(d["refs"] or "[]")
    e = con.execute("SELECT * FROM epss WHERE cve_id=?", (cid,)).fetchone()
    d["epss"] = dict(e) if e else None
    sig = signals_for(con, [cid]).get(cid, {})
    for p in sig.get("poc", []):
        p["flags"] = _poc_flags(p, d.get("published"))
    sig.get("poc", []).sort(key=lambda p: -(p.get("stars") or 0))
    d["signals"] = sig
    d["tier"], d["why"] = tier(sig, d, d["epss"]["pct"] if d["epss"] else None, cfg)
    d["matches"] = [dict(m) for m in con.execute(
        "SELECT m.*, i.name AS item_name, i.version AS item_version FROM match m "
        "JOIN item i ON i.id=m.item_id WHERE m.cve_id=?", (cid,))]
    ack_rows, keys = acks.load(con), acks.evidence_keys(sig, d.get("ssvc_exploitation"))
    for m in d["matches"]:
        m["live"] = m["status"] in acks.LIVE
        a = ack_rows.get((cid, m["item_id"]))
        if a:
            st, reason = acks.state(a, d["tier"], m["status"], keys)
            m["ack"] = {"created": a["created"], "until": a["until"], "note": a["note"],
                        "state": st, "reason": reason}
    d["events"] = [dict(x) for x in con.execute(
        "SELECT ts, kind, detail FROM event WHERE cve_id=? ORDER BY ts DESC LIMIT 50", (cid,))]
    names = item_names(con)
    for e in d["events"]:
        e["summary"] = event_summary(e, names)
    return d


_KIND = {"kev": "added to CISA KEV", "msf": "Metasploit module published", "nuclei": "Nuclei template published",
         "edb": "Exploit-DB entry published", "poc": "new GitHub PoC", "local": "added to your archive",
         "epss": "EPSS jumped", "ssvc": "CISA SSVC exploitation raised", "match": "now matches your inventory",
         "resolved": "no longer affects you", "new_cve": "new CVE", "ack": "acknowledged",
         "unack": "acknowledgement removed"}


def item_names(con) -> dict:
    """item id -> the name you gave it, so history reads "OpenSSH (web01)" not a slug."""
    return {r[0]: r[1] for r in con.execute("SELECT id, name FROM item")}


def event_summary(e: dict, names: dict | None = None) -> str:
    d = json.loads(e.get("detail") or "{}")
    s = _KIND.get(e["kind"], e["kind"])
    if e["kind"] == "epss":
        s += f" {d.get('from', 0) * 100:.0f}% -> {d.get('to', 0) * 100:.0f}%"
    elif e["kind"] == "ssvc":
        s += f" to {d.get('exploitation')}"
    elif e["kind"] in ("match", "resolved"):
        item = d.get("item")
        s += f" ({(names or {}).get(item, item)}, {d.get('status')})"
    elif e["kind"] in ("ack", "unack"):
        item = d.get("item")
        s += f" ({(names or {}).get(item, item)})"
        if d.get("until"):
            s += f" until {d['until']}"
        if d.get("note"):
            s += f": {d['note']}"
    elif e["kind"] == "poc":
        s += f": {d.get('url')}"
    elif e["kind"] in ("msf", "nuclei", "edb"):
        s += f": {d.get('name') or d.get('title') or ''}"
    return s


def events(con, cfg, days=7, matched_only=True, limit=500) -> list[dict]:
    since = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    q = ("SELECT e.*, c.title, c.cvss FROM event e LEFT JOIN cve c ON c.id=e.cve_id "
         "WHERE e.ts >= ? AND e.baseline=0")
    if matched_only:
        q += (" AND e.cve_id IN (SELECT cve_id FROM match WHERE status IN ('affected','check'))"
              " OR (e.ts >= ? AND e.kind='resolved')")
        args = [since, since]
    else:
        q += " AND e.kind != 'new_cve'"
        args = [since]
    q += " ORDER BY e.ts DESC LIMIT ?"
    rows = [dict(r) for r in con.execute(q, args + [limit])]
    names = item_names(con)
    for r in rows:
        r["summary"] = event_summary(r, names)
    return rows


def health(con, cfg, now: dt.datetime | None = None) -> dict:
    """Is the data current? Uses the record each full `cvescope sync` leaves behind."""
    ls = db.meta_get(con, "last_sync") or {}
    finished = ls.get("finished")
    limit = float(cfg["serve"].get("stale_after_hours", 12))
    now = now or dt.datetime.now(dt.timezone.utc)
    age = None
    if finished:
        try:
            age = (now - dt.datetime.fromisoformat(finished.replace("Z", "+00:00"))).total_seconds() / 3600
        except ValueError:
            age = None
    feeds = list(ls.get("failed_feeds") or [])
    collectors = [c.split(":", 1)[-1] for c in ls.get("failed_collectors") or []]
    problems = []
    if not finished:
        problems.append("No full sync recorded yet. Run `cvescope sync`, or check that the scheduled sync is set up.")
    elif age is not None and age > limit:
        problems.append(f"The last full sync finished {age:.0f} hours ago (the limit is {limit:.0f}). "
                        "The scheduled sync may have stopped: check it and its log.")
    if feeds:
        problems.append(f"Feeds that failed in the last sync: {', '.join(feeds)}. Their data is from an older run.")
    if collectors:
        problems.append(f"Collectors that failed in the last sync, so their items show the last known versions: "
                        f"{', '.join(collectors)}.")
    stale = not finished or (age is not None and age > limit)
    return {"finished": finished, "age_hours": age, "stale": stale, "stale_after_hours": limit,
            "failed_feeds": feeds, "failed_collectors": collectors, "problems": problems,
            "level": "bad" if stale else ("warn" if problems else "ok")}


def summary(con, cfg) -> dict:
    items = [dict(r) for r in con.execute("SELECT id,name,version,collector,error,seen,extra FROM item ORDER BY collector, name")]
    ms = matches(con, cfg, acked="include")
    n_acked = sum(1 for m in ms if m.get("ack", {}).get("state") == "active")
    ms = [m for m in ms if m.get("ack", {}).get("state") != "active"]
    per: dict[str, dict] = {}
    for m in ms:
        p = per.setdefault(m["item_id"], {"act": 0, "watch": 0, "info": 0, "affected": 0})
        p[m["tier"]] += 1
        if m["status"] == "affected":
            p["affected"] += 1
    nots = dict(con.execute("SELECT item_id, count(*) FROM match WHERE status='not_affected' GROUP BY item_id").fetchall())
    for it in items:
        it["counts"] = per.get(it["id"], {"act": 0, "watch": 0, "info": 0, "affected": 0})
        it["ruled_out"] = nots.get(it["id"], 0)
        it["extra"] = json.loads(it["extra"] or "{}")
        it["host"] = host_of(it["name"], it["collector"])
    src = [dict(r) for r in con.execute("SELECT name,last_ok,last_try,last_error FROM source ORDER BY name")]
    totals = {"act": 0, "watch": 0, "info": 0, "acked": n_acked}
    for m in ms:
        totals[m["tier"]] += 1
    return {"items": items, "sources": src, "totals": totals, "health": health(con, cfg),
            "read_only": bool(cfg["serve"].get("read_only")),
            "cves": con.execute("SELECT count(*) FROM cve").fetchone()[0],
            "epss_date": (con.execute("SELECT max(date) FROM epss").fetchone() or [None])[0]}


def hot(con, cfg, days=30, limit=60) -> dict:
    """Whole-world view: what got weaponized or exploited lately, matched or not."""
    since = (dt.date.today() - dt.timedelta(days=days)).isoformat()
    kev = [dict(r) for r in con.execute(
        "SELECT s.cve_id, json_extract(s.data,'$.added') AS added, json_extract(s.data,'$.vendor') AS vendor, "
        "json_extract(s.data,'$.product') AS product, json_extract(s.data,'$.name') AS name, "
        "json_extract(s.data,'$.ransomware') AS ransomware, e.pct AS epss_pct "
        "FROM signal s LEFT JOIN epss e ON e.cve_id=s.cve_id WHERE s.source='kev' "
        "AND json_extract(s.data,'$.added') >= ? ORDER BY added DESC LIMIT ?", (since, limit))]
    weap = [dict(r) for r in con.execute(
        "SELECT e.cve_id, e.kind, e.ts, e.detail, c.title, c.cvss FROM event e LEFT JOIN cve c ON c.id=e.cve_id "
        "WHERE e.kind IN ('msf','nuclei','edb') AND e.baseline=0 AND e.ts >= ? ORDER BY e.ts DESC LIMIT ?",
        (since, limit))]
    for w in weap:
        w["summary"] = event_summary(w)
    top = [dict(r) for r in con.execute(
        "SELECT e.cve_id, e.score, e.pct, c.title, c.published FROM epss e JOIN cve c ON c.id=e.cve_id "
        "WHERE c.published >= ? ORDER BY e.score DESC LIMIT 25", (since,))]
    return {"kev": kev, "weaponized": weap, "epss_new": top}


def search(con, cfg, q: str, limit=100) -> list[dict]:
    q = q.strip()
    if q.upper().startswith("CVE-"):
        rows = con.execute("SELECT id,title,description,cvss,published FROM cve WHERE id LIKE ? LIMIT ?",
                           (q.upper() + "%", limit))
    else:
        like = f"%{q}%"
        rows = con.execute(
            "SELECT id,title,description,cvss,published FROM cve WHERE state='PUBLISHED' AND "
            "(title LIKE ? OR description LIKE ?) ORDER BY published DESC LIMIT ?", (like, like, limit))
    out = [dict(r) for r in rows]
    sigs = signals_for(con, [r["id"] for r in out])
    ep = {r[0]: r[1] for r in con.execute(
        f"SELECT cve_id, pct FROM epss WHERE cve_id IN ({','.join('?' * len(out))})", [r["id"] for r in out])} if out else {}
    for r in out:
        r["description"] = (r["description"] or "")[:300]
        r["signals"] = {k: len(v) for k, v in sigs.get(r["id"], {}).items()}
        r["epss_pct"] = ep.get(r["id"])
    return out
