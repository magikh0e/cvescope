"""End of life: is the release line an item runs still getting fixes? (data: endoflife.date)

An item past end of life gets no more fixes upstream, so a clean CVE list doesn't mean much:
the next bug stays open. Worked out when the page or a report asks, so "soon" and "since" are
always about today.

Distro and vendor builds are left out (Debian's git 2.47, Ubuntu's OpenSSL 3.0, a Proxmox
kernel): the distro keeps patching its build after upstream stops, so upstream's date doesn't
apply. Items whose version doesn't sit on a line endoflife.date lists aren't judged either.
"""

from __future__ import annotations

import datetime as dt
import json

from .match import _alias, _on_line
from .versions import clean

SOON_DAYS = 90  # "end of life soon": time to plan the upgrade
SOURCE = "https://endoflife.date"


def _today() -> dt.date:
    return dt.date.today()


def _date(s) -> dt.date | None:
    try:
        return dt.date.fromisoformat(str(s)[:10]) if s else None
    except ValueError:
        return None


def _products(con) -> tuple[dict, dict, dict]:
    lines: dict[str, list[dict]] = {}
    for r in con.execute("SELECT product, cycle, eol_from, is_eol, eoes_from, is_eoes FROM eol_cycle"):
        lines.setdefault(r[0], []).append({"line": r[1], "eol_from": r[2], "is_eol": r[3],
                                           "eoes_from": r[4], "is_eoes": r[5]})
    cpe: dict[tuple, list[str]] = {}
    for v, p, prod in con.execute("SELECT vendor, cpe_product, product FROM eol_cpe"):
        cpe.setdefault((v, p), []).append(prod)
    meta = {r[0]: {"label": r[1], "eoes_label": r[2], "link": r[3]}
            for r in con.execute("SELECT name, label, eoes_label, link FROM eol_product")}
    return lines, cpe, meta


def state(line: dict, today: dt.date) -> tuple[str, dt.date | None] | None:
    """('eol', since) / ('soon', on) / None for one release line."""
    eol = _date(line.get("eol_from"))
    if line.get("is_eol") or (eol and eol <= today):
        return "eol", eol
    if eol and (eol - today).days <= SOON_DAYS:
        return "soon", eol
    return None


def describe(label: str, line: dict, st: str, when: dt.date | None, today: dt.date,
             eoes_label: str | None = None) -> str:
    name = f"{label} {line['line']}"
    if st == "soon":
        days = (when - today).days if when else None
        return f"{name} reaches end of life on {when}" + (f" (in {days} days)" if days is not None else "")
    out = f"{name} reached end of life on {when}" if when else f"{name} is past end of life"
    out += ": no more fixes"
    eoes = _date(line.get("eoes_from"))
    if eoes_label and not line.get("is_eoes") and (eoes is None or eoes > today):
        out += f"; {eoes_label} " + (f"runs until {eoes}" if eoes else "is still offered")
    return out


def for_items(con, items: list[dict], today: dt.date | None = None) -> dict[str, dict]:
    """item id -> {state, text, product, line, date, link} for items past or near end of life."""
    today = today or _today()
    lines, cpe, meta = _products(con)
    if not lines or not cpe:
        return {}
    aliases = {i: json.loads(a or "[]") for i, a in con.execute("SELECT id, aliases FROM item")}
    out = {}
    for it in items:
        ex = it.get("extra") or {}
        if isinstance(ex, str):
            ex = json.loads(ex or "{}")
        v = clean(it.get("version"))
        if not v or ex.get("backports"):
            continue
        prods = []
        for vendor, product, prefix in (_alias(a) for a in aliases.get(it["id"], [])):
            if not prefix and vendor != "*":
                prods += [p for p in cpe.get((vendor, product), []) if p not in prods]
        best = None  # the longest release line the version sits on, across the item's products
        for prod in prods:
            for ln in lines.get(prod, []):
                c = clean(ln["line"])
                if c and _on_line(v, c) and (best is None or len(c) > len(clean(best[1]["line"]))):
                    best = (prod, ln)
        if not best:
            continue
        prod, ln = best
        st = state(ln, today)
        if not st:
            continue
        m = meta.get(prod) or {"label": prod, "eoes_label": None, "link": f"{SOURCE}/{prod}"}
        out[it["id"]] = {"state": st[0], "date": st[1].isoformat() if st[1] else None, "product": m["label"],
                         "line": ln["line"], "link": m["link"],
                         "text": describe(m["label"], ln, st[0], st[1], today, m["eoes_label"])}
    return out
