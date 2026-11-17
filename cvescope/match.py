"""Match inventory items against CVE records.

Statuses:
  affected      a product entry matched and the installed version is inside an affected range
  check         product matched but the version can't be decided (no version data, free text,
                or a distro package whose fixes may be backported)
  not_affected  product matched, installed version is outside every affected range
  keyword       an old CVE with no product data mentions one of the item's keywords
"""

from __future__ import annotations

import json
import re

from . import db
from .sources.cvelist import _cpe_vp
from .versions import clean, cmp, desc_max, eval_entry, name_pattern


def _alias(a: str) -> tuple[str, str, bool]:
    vendor, _, product = a.rpartition(":") if ":" in a else ("*", "", a)
    prefix = product.endswith("*")
    vendor = "*" if vendor.strip() in ("*", "") else db.norm(vendor)
    return vendor, db.norm(product.rstrip("*")), prefix


def _vendor_ok(want: str, got: str) -> bool:
    return want == "*" or not got or got == want or got.startswith(want + " ") or want.startswith(got + " ")


def _prod_ok(alias, product: str) -> bool:
    _, p, prefix = alias
    return product == p or (prefix and product.startswith(p))


def _entry_matches(entry: dict, aliases) -> bool:
    v, p = db.norm(entry.get("v")), db.norm(entry.get("p"))
    for al in aliases:
        if p and _prod_ok(al, p) and _vendor_ok(al[0], v):
            return True
        for c in entry.get("cpes") or []:
            vp = _cpe_vp(c)
            if vp and _prod_ok(al, db.norm(vp[1])) and _vendor_ok(al[0], db.norm(vp[0])):
                return True
    return False


def _candidates(con, aliases) -> set[str]:
    out = set()
    for al in aliases:
        vendor, product, prefix = al
        if not product:
            continue
        if prefix:
            rows = con.execute("SELECT cve_id, vendor FROM cve_product WHERE product >= ? AND product < ?",
                               (product, product + "￿"))
        else:
            rows = con.execute("SELECT cve_id, vendor FROM cve_product WHERE product = ?", (product,))
        out.update(cid for cid, v in rows if _vendor_ok(vendor, v))
    return out


def _names(item: dict) -> list:
    names = {re.sub(r"\s*\(.*?\)\s*", " ", item["name"]).strip(), item.get("product") or ""}
    names |= {_alias(a)[1] for a in item["aliases"]}
    return [p for p in (name_pattern(n) for n in names if n) if p]


def _from_description(item: dict, cve_row, how: str, reason: str) -> tuple[str, str, str]:
    ver = clean(item.get("version"))
    if ver:
        top = desc_max(cve_row["description"] or "", item.setdefault("_pats", _names(item)))
        if top and cmp(ver, top) > 0:
            return "not_affected", how, f"no version data; the description names versions up to {top}"
    return "check", how, reason


def evaluate(item: dict, cve_row) -> tuple[str, str, str]:
    """-> (status, how, reason) for one item against one CVE record."""
    aliases = item.setdefault("_aliases", [_alias(a) for a in item["aliases"]])
    raw = [e for e in json.loads(cve_row["affected"] or "[]") if _entry_matches(e, aliases)]
    # CISA's ADP (and kernel.org) split one product into many entries, one range each.
    # Each alone says "affected by default"; together they describe the whole version line.
    groups: dict[tuple, dict] = {}
    for e in raw:
        k = (e.get("src"), db.norm(e.get("v")), db.norm(e.get("p")))
        g = groups.setdefault(k, {"src": e.get("src"), "v": e.get("v"), "p": e.get("p"), "ds": None,
                                  "vs": [], "cpes": []})
        g["vs"].extend(e.get("vs") or [])
        g["cpes"].extend(e.get("cpes") or [])
        if e.get("vs") and (e.get("ds") or "").lower() in ("affected", "unaffected", "unknown"):
            g["ds"] = "affected" if "affected" in (g["ds"], e["ds"].lower()) else e["ds"].lower()
    entries = list(groups.values())
    if not entries:
        return _from_description(item, cve_row, "kev",
                                 "named by CISA KEV; the CVE record has no version data for it")
    results = [eval_entry(e, item.get("version")) for e in entries]
    how = "cpe" if all(not db.norm(e.get("p")) for e in entries) else "product"
    if any(s == "affected" for s, _ in results):
        reason = next(r for s, r in results if s == "affected")
        if (item.get("extra") or {}).get("backports"):
            return "check", how, reason + "; distro package, fixes may be backported"
        return "affected", how, reason
    decided = [r for s, r in results if s == "unaffected"]
    if decided:  # nothing says affected and at least one entry rules this version out
        return "not_affected", how, decided[0]
    return _from_description(item, cve_row, how,
                             next((r for s, r in results if s == "unknown"), "undecided"))


def run(con, cfg) -> str:
    items = []
    for r in con.execute("SELECT * FROM item"):
        d = dict(r)
        d["aliases"] = json.loads(d["aliases"] or "[]")
        d["keywords"] = json.loads(d["keywords"] or "[]")
        d["extra"] = json.loads(d["extra"] or "{}")
        items.append(d)
    if not items:
        return "no inventory items (add [[inventory]] entries to the config)"

    old = {(r["cve_id"], r["item_id"]): dict(r) for r in con.execute("SELECT * FROM match")}
    first_run = db.meta_get(con, "match_done") is None
    t = db.now()
    new_rows: dict[tuple, tuple] = {}

    for it in items:
        aliases = [_alias(a) for a in it["aliases"]]
        cands = _candidates(con, aliases)
        for i in range(0, len(cands), 500):
            chunk = list(cands)[i:i + 500]
            q = (f"SELECT id, affected, description FROM cve WHERE state='PUBLISHED' "
                 f"AND id IN ({','.join('?' * len(chunk))})")
            for row in con.execute(q, chunk):
                status, how, reason = evaluate(it, row)
                new_rows[(row["id"], it["id"])] = (status, how, reason)

    # keyword pass: only CVEs whose record names no product at all (mostly pre-2023 "n/a")
    kw_items = [(it, re.compile(r"\b(?:" + "|".join(re.escape(k) for k in it["keywords"]) + r")\b", re.I))
                for it in items if it["keywords"]]
    if kw_items:
        for cid, desc in con.execute("SELECT id, description FROM cve WHERE noprod=1 AND state='PUBLISHED'"):
            if not desc:
                continue
            for it, rx in kw_items:
                if (cid, it["id"]) not in new_rows and rx.search(desc):
                    new_rows[(cid, it["id"])] = ("keyword", "keyword", "description mentions " + rx.search(desc).group(0))

    con.execute("DELETE FROM match")
    rows = []
    for (cid, iid), (status, how, reason) in new_rows.items():
        prev = old.get((cid, iid))
        live = status in ("affected", "check", "keyword")
        was_live = prev is not None and prev["status"] in ("affected", "check", "keyword")
        first = prev["first_seen"] if prev and was_live == live else t
        rows.append((cid, iid, status, how, reason, first))
        if not first_run and live and not was_live:
            db.add_event(con, cid, "match", {"item": iid, "status": status})
        if not first_run and was_live and not live:
            db.add_event(con, cid, "resolved", {"item": iid, "status": status})
    for (cid, iid), prev in old.items():
        if (cid, iid) not in new_rows and prev["status"] in ("affected", "check") and \
                any(i["id"] == iid for i in items):
            db.add_event(con, cid, "resolved", {"item": iid, "status": "gone"})
    con.executemany("INSERT INTO match VALUES(?,?,?,?,?,?)", rows)
    con.commit()
    db.meta_set(con, "match_done", t)
    counts = {}
    for r in rows:
        counts[r[2]] = counts.get(r[2], 0) + 1
    found = ", ".join(f"{v} {k}" for k, v in sorted(counts.items()))
    if not found and not con.execute("SELECT 1 FROM cve LIMIT 1").fetchone():
        found = "no matches (no CVE records yet: run `cvescope sync` with cvelist enabled)"
    return f"{len(items)} items: " + (found or "no matches")
