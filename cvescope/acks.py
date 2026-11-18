"""Acknowledgements: "I've dealt with this one" for a CVE on one inventory item.

An acknowledged match drops out of act now / watch, the totals and the alerts. It comes back by
itself when:

- its end date passes (the end date is optional), or
- the evidence gets worse than it was when you acknowledged it: a higher tier, a new kind of
  exploitation evidence (added to KEV, a first Metasploit module, SSVC raised), or a "check"
  that became "affected".

More of the same evidence (another GitHub PoC, EPSS moving within its tier) and a new item
version (monthly Windows builds) don't bring it back.
"""

from __future__ import annotations

import datetime as dt
import json

from . import db

TIER_RANK = {"act": 0, "watch": 1, "info": 2}
TIER_LABEL = {"act": "act now", "watch": "watch", "info": "info"}
KEY_LABEL = {"kev": "added to CISA KEV", "msf": "Metasploit module", "msf:exploit": "Metasploit exploit module",
             "nuclei": "Nuclei template", "edb": "Exploit-DB entry", "poc": "GitHub PoC",
             "local": "in your exploit archive", "ssvc:poc": "CISA SSVC: PoC public",
             "ssvc:active": "CISA SSVC: active exploitation"}
LIVE = ("affected", "check", "keyword")
NOTE_MAX = 500


def evidence_keys(sig: dict, ssvc: str | None) -> list[str]:
    """The kinds of exploitation evidence a CVE has right now. sig: source -> list of signals."""
    keys = {k for k, v in sig.items() if v}
    if any(m.get("type") == "exploit" for m in sig.get("msf", [])):
        keys.add("msf:exploit")
    if ssvc in ("poc", "active"):
        keys.add(f"ssvc:{ssvc}")
    return sorted(keys)


def load(con) -> dict[tuple[str, str], dict]:
    return {(r["cve_id"], r["item_id"]): dict(r) for r in con.execute("SELECT * FROM ack")}


def state(ack: dict, tier: str, status: str, keys: list[str],
          today: dt.date | None = None) -> tuple[str, str]:
    """-> ("active" | "expired" | "lapsed", why it's no longer active)."""
    today = today or dt.datetime.now(dt.timezone.utc).date()
    if ack.get("until") and today.isoformat() > ack["until"][:10]:
        return "expired", f"ended {ack['until'][:10]}"
    ev = json.loads(ack.get("evidence") or "{}")
    why = []
    if TIER_RANK.get(tier, 9) < TIER_RANK.get(ev.get("tier"), 9):
        why.append(f"moved up to {TIER_LABEL[tier]}")
    new = [k for k in keys if k not in (ev.get("keys") or [])]
    if "msf:exploit" in new and "msf" in new:
        new.remove("msf")
    why += [KEY_LABEL.get(k, k) for k in new]
    if ev.get("status") == "check" and status == "affected":
        why.append("now confirmed affected")
    return ("lapsed", "; ".join(why)) if why else ("active", "")


def _until(days=None, until=None) -> str | None:
    if until:
        return dt.date.fromisoformat(str(until)[:10]).isoformat()  # ValueError on junk
    if days:
        days = int(days)
        if not 1 <= days <= 3650:
            raise ValueError("days must be between 1 and 3650")
        return (dt.datetime.now(dt.timezone.utc).date() + dt.timedelta(days=days)).isoformat()
    return None


def _pick(rows: list[dict], item_ref: str | None, cve_id: str) -> list[dict]:
    """item_ref: an item id, an item name, or a unique part of a name. None: every row."""
    if not item_ref:
        return rows
    ref = item_ref.strip().lower()
    for test in (lambda r: r["item_id"].lower() == ref, lambda r: (r["item_name"] or "").lower() == ref,
                 lambda r: ref in (r["item_name"] or "").lower()):
        hit = [r for r in rows if test(r)]
        if len(hit) == 1:
            return hit
        if len(hit) > 1:
            raise ValueError(f"'{item_ref}' fits several items for {cve_id}: "
                             + ", ".join(r["item_name"] for r in hit))
    raise ValueError(f"no item matching '{item_ref}' for {cve_id}")


def add(con, cfg, cve_id: str, item_ref: str | None = None, note: str = "",
        days=None, until=None) -> list[dict]:
    """Acknowledge cve_id on one item (or every item it shows up on). Returns the rows acked."""
    from . import query
    note = (note or "").strip()
    if len(note) > NOTE_MAX:
        raise ValueError(f"the note is over {NOTE_MAX} characters")
    end = _until(days, until)
    rows = query.matches(con, cfg, include_keyword=True, cve_ids=[cve_id], acked="include")
    if not rows:
        raise ValueError(f"{cve_id} doesn't show up for anything in your inventory, so there's nothing to acknowledge")
    rows = _pick(rows, item_ref, cve_id)
    sig = query.signals_for(con, [cve_id]).get(cve_id, {})
    t = db.now()
    for r in rows:
        ev = {"tier": r["tier"], "status": r["status"], "keys": evidence_keys(sig, r.get("ssvc_exploitation")),
              "item_version": r.get("item_version")}
        con.execute("INSERT OR REPLACE INTO ack(cve_id, item_id, created, until, note, evidence) VALUES(?,?,?,?,?,?)",
                    (cve_id, r["item_id"], t, end, note, json.dumps(ev)))
        db.add_event(con, cve_id, "ack", {"item": r["item_id"], "note": note, "until": end})
    con.commit()
    return rows


BULK_MAX = 2000  # pairs per bulk call


def _pairs(pairs) -> list[tuple[str, str]]:
    out = list(dict.fromkeys((str(c).strip().upper(), str(i).strip()) for c, i in pairs))
    if not out:
        raise ValueError("nothing selected")
    if len(out) > BULK_MAX:
        raise ValueError(f"{len(out)} selected; acknowledge at most {BULK_MAX} at a time")
    return out


def add_many(con, cfg, pairs, note: str = "", days=None, until=None) -> list[dict]:
    """Acknowledge many (cve_id, item_id) pairs with one note and end date, all or nothing."""
    from . import query
    note = (note or "").strip()
    if len(note) > NOTE_MAX:
        raise ValueError(f"the note is over {NOTE_MAX} characters")
    end = _until(days, until)
    pairs = _pairs(pairs)
    cves = {c for c, _ in pairs}
    live = {(m["cve_id"], m["item_id"]): m for m in query.matches(
        con, cfg, include_keyword=True, cve_ids=cves, acked="include")}
    gone = [f"{c} on {i}" for c, i in pairs if (c, i) not in live]
    if gone:
        raise ValueError(f"{len(gone)} of the {len(pairs)} selected no longer match your inventory "
                         f"(first: {gone[0]}). Reload and try again.")
    sigs = query.signals_for(con, cves)
    t = db.now()
    rows = []
    for c, i in pairs:
        r = live[(c, i)]
        ev = {"tier": r["tier"], "status": r["status"], "keys": evidence_keys(sigs.get(c, {}), r.get("ssvc_exploitation")),
              "item_version": r.get("item_version")}
        con.execute("INSERT OR REPLACE INTO ack(cve_id, item_id, created, until, note, evidence) VALUES(?,?,?,?,?,?)",
                    (c, i, t, end, note, json.dumps(ev)))
        db.add_event(con, c, "ack", {"item": i, "note": note, "until": end})
        rows.append(r)
    con.commit()
    return rows


def remove_many(con, pairs) -> int:
    """Drop the acknowledgements for many (cve_id, item_id) pairs. Returns how many there were."""
    pairs = _pairs(pairs)
    n = 0
    for c, i in pairs:
        if con.execute("DELETE FROM ack WHERE cve_id = ? AND item_id = ?", (c, i)).rowcount:
            db.add_event(con, c, "unack", {"item": i})
            n += 1
    if not n:
        con.rollback()
        raise ValueError("none of the selected are acknowledged")
    con.commit()
    return n


def remove(con, cve_id: str, item_ref: str | None = None) -> list[str]:
    """Drop the acknowledgement(s) for cve_id. Returns the item ids it removed."""
    rows = [dict(r) for r in con.execute(
        "SELECT a.item_id, COALESCE(i.name, a.item_id) AS item_name FROM ack a "
        "LEFT JOIN item i ON i.id = a.item_id WHERE a.cve_id = ?", (cve_id,))]
    if not rows:
        raise ValueError(f"{cve_id} isn't acknowledged")
    rows = _pick(rows, item_ref, cve_id)
    for r in rows:
        con.execute("DELETE FROM ack WHERE cve_id = ? AND item_id = ?", (cve_id, r["item_id"]))
        db.add_event(con, cve_id, "unack", {"item": r["item_id"]})
    con.commit()
    return [r["item_id"] for r in rows]


def list_all(con, cfg) -> list[dict]:
    """Every acknowledgement with its current state; "resolved" when it no longer matches."""
    from . import query
    acks = load(con)
    if not acks:
        return []
    live = {(m["cve_id"], m["item_id"]): m for m in query.matches(
        con, cfg, include_keyword=True, cve_ids={c for c, _ in acks}, acked="include")}
    names = query.item_names(con)
    out = []
    for (cid, iid), a in sorted(acks.items(), key=lambda kv: kv[1]["created"], reverse=True):
        m = live.get((cid, iid))
        st, why = (m["ack"]["state"], m["ack"]["reason"]) if m else ("resolved", "no longer matches your inventory")
        out.append({"cve_id": cid, "item_id": iid, "item_name": names.get(iid, iid), "created": a["created"],
                    "until": a["until"], "note": a["note"], "state": st, "reason": why,
                    "tier": m["tier"] if m else None})
    return out
