"""Inventory collectors. Each [[inventory]] entry in the config names a `type`.

Types: static, command, dpkg, http_json, nmap_xml, proxmox, pihole, homeassistant, unifi, opnsense.

A collector returns a list of items:
  {name, vendor, product, version, aliases: ["vendor:product", ...], keywords: [...], extra: {}}

Config keys every type accepts:
  name      override the display name (single-item collectors)
  aliases   extra "vendor:product" strings to match on
  keywords  description words, used only for old CVEs that name no product
  enabled   false to skip
"""

from __future__ import annotations

import json
import os
import re
import traceback

from .. import db
from ..config import expand

_SLUG = re.compile(r"[^a-z0-9]+")


def slug(s: str) -> str:
    return _SLUG.sub("-", s.lower()).strip("-")[:60]


def secret(entry: dict, base: str) -> str:
    """Read a credential from <base>_file or <base>_env. Never printed."""
    f = entry.get(f"{base}_file")
    if f:
        p = expand(f)
        return p.read_text(encoding="utf-8-sig").strip()
    e = entry.get(f"{base}_env")
    if e:
        v = os.environ.get(e)
        if v:
            return v.strip()
        raise RuntimeError(f"environment variable {e} is not set")
    if entry.get(base):
        raise RuntimeError(f"put {base} in {base}_file or {base}_env, not inline in the config")
    raise RuntimeError(f"no {base}_file or {base}_env configured")


def item(name, vendor="", product="", version=None, aliases=(), keywords=(), **extra) -> dict:
    al = [a for a in aliases if a]
    if product:
        al.insert(0, f"{db.norm(vendor)}:{db.norm(product)}")
    return {"name": name, "vendor": vendor, "product": product, "version": version,
            "aliases": list(dict.fromkeys(al)), "keywords": list(keywords), "extra": extra}


def _registry():
    from . import appliances, generic, nmap
    return {
        "nmap_xml": nmap.nmap_xml,
        "static": generic.static,
        "command": generic.command,
        "dpkg": generic.dpkg,
        "http_json": generic.http_json,
        "proxmox": appliances.proxmox,
        "pihole": appliances.pihole,
        "homeassistant": appliances.homeassistant,
        "unifi": appliances.unifi,
        "opnsense": appliances.opnsense,
    }


def run(con, cfg, verbose: bool = False) -> list[dict]:
    reg = _registry()
    out: list[dict] = []
    seen_ids: set[str] = set()
    t = db.now()
    for n, entry in enumerate(cfg.get("inventory") or []):
        if entry.get("enabled", True) is False:
            continue
        typ = entry.get("type", "static")
        fn = reg.get(typ)
        label = entry.get("name") or entry.get("url") or entry.get("host") or entry.get("path") or f"{typ}#{n}"
        try:
            if fn is None:
                raise RuntimeError(f"unknown inventory type {typ!r}")
            items = fn(entry)
            err = None
        except Exception as e:
            if verbose:
                traceback.print_exc()
            err = f"{type(e).__name__}: {e}"
            # keep the last known items for this collector so one outage doesn't drop matches
            items = []
            for r in con.execute("SELECT * FROM item WHERE collector=?", (f"{typ}:{label}",)):
                items.append({"name": r["name"], "vendor": r["vendor"], "product": r["product"],
                              "version": r["version"], "aliases": json.loads(r["aliases"]),
                              "keywords": json.loads(r["keywords"]),
                              "extra": json.loads(r["extra"] or "{}"), "_id": r["id"]})
            if not items:
                items = [item(label)]
        for it in items:
            if len(items) == 1 and entry.get("name") and typ not in ("static", "dpkg", "nmap_xml"):
                it["name"] = entry["name"]
            it["aliases"] = list(dict.fromkeys(it["aliases"] + [a.lower() for a in entry.get("aliases", [])]))
            it["keywords"] = list(dict.fromkeys(it["keywords"] + list(entry.get("keywords", []))))
            iid = it.get("_id") or slug(it["name"])
            base, k = iid, 2
            while iid in seen_ids:
                iid, k = f"{base}-{k}", k + 1
            seen_ids.add(iid)
            it["id"], it["collector"], it["error"] = iid, f"{typ}:{label}", err
            out.append(it)
    con.execute("DELETE FROM item")
    con.executemany(
        "INSERT INTO item(id,name,vendor,product,version,collector,aliases,keywords,extra,seen,error) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
        [(i["id"], i["name"], i["vendor"], i["product"], i.get("version"), i["collector"],
          json.dumps(i["aliases"]), json.dumps(i["keywords"]), json.dumps(i.get("extra") or {}),
          t, i.get("error")) for i in out])
    con.commit()
    return out
