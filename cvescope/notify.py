"""Push alerts for changes that touch your inventory: ntfy, Home Assistant, or a webhook.

Only events on matched CVEs are sent, and only at or above notify.min_tier.
Every pending event is marked handled after a run, sent or not, so nothing piles up.
"""

from __future__ import annotations

import json
import urllib.request

from . import net, query
from .collectors import secret

TIER_RANK = {"act": 0, "watch": 1, "info": 2}


def _pending(con, cfg) -> tuple[list[dict], list[int]]:
    ev = [dict(r) for r in con.execute(
        "SELECT * FROM event WHERE notified=0 AND baseline=0 AND kind != 'resolved' ORDER BY ts")]
    ids = [e["id"] for e in ev]
    statuses = ("affected", "check", "keyword") if cfg["notify"].get("keyword_matches") else ("affected", "check")
    cves = {e["cve_id"] for e in ev}
    if not cves:
        return [], ids
    ms = {}
    for m in query.matches(con, cfg, include_keyword=True, statuses=statuses):
        if m["cve_id"] in cves:
            ms.setdefault(m["cve_id"], []).append(m)
    limit = TIER_RANK.get(cfg["notify"].get("min_tier", "act"), 0)
    names = query.item_names(con)
    out = []
    for cid, mlist in ms.items():
        t = mlist[0]["tier"]
        if TIER_RANK[t] > limit:
            continue
        changes = [query.event_summary(e, names) for e in ev if e["cve_id"] == cid]
        out.append({"cve": cid, "tier": t, "why": mlist[0]["why"], "title": mlist[0].get("title"),
                    "items": [f"{m['item_name']} {m.get('item_version') or ''} ({m['status']})".strip() for m in mlist],
                    "changes": list(dict.fromkeys(changes)), "epss_pct": mlist[0].get("epss_pct"),
                    "cvss": mlist[0].get("cvss")})
    out.sort(key=lambda x: (TIER_RANK[x["tier"]], -(x["epss_pct"] or 0)))
    return out, ids


def format_message(alerts: list[dict]) -> tuple[str, str]:
    n_act = sum(1 for a in alerts if a["tier"] == "act")
    n_watch = len(alerts) - n_act
    parts = [f"{n_act} act now"] if n_act else []
    if n_watch:
        parts.append(f"{n_watch} watch")
    title = "cvescope: " + ", ".join(parts)
    lines = []
    for a in alerts[:15]:
        head = f"{a['cve']} [{query.TIER_LABEL[a['tier']]}]"
        if a.get("cvss"):
            head += f" CVSS {a['cvss']}"
        lines.append(head)
        lines.append("  " + "; ".join(a["items"][:3]))
        lines.append("  " + "; ".join(a["changes"][:3]))
    if len(alerts) > 15:
        lines.append(f"...and {len(alerts) - 15} more (cvescope report)")
    return title, "\n".join(lines)


def _post(url: str, body: bytes, headers: dict, pin: str = ""):
    if pin or url.startswith("http://"):
        c = net.PinnedClient(url, pin)
        conn = c._conn()
        try:
            conn.request("POST", c.prefix or "/", body=body, headers={"User-Agent": net.UA, **headers})
            r = conn.getresponse()
            r.read()
            if r.status >= 400:
                raise net.HTTPStatus(r.status, url)
        finally:
            conn.close()
        return
    req = urllib.request.Request(url, data=body, headers={"User-Agent": net.UA, **headers}, method="POST")
    with urllib.request.urlopen(req, timeout=30) as r:
        r.read()


def send(cfg, title: str, message: str, urgent: bool) -> list[str]:
    sent = []
    n = cfg["notify"]
    for ch in n.get("ntfy") or []:
        h = {"Title": title, "Priority": "high" if urgent else "default", "Tags": "warning"}
        if ch.get("token_file") or ch.get("token_env"):
            h["Authorization"] = "Bearer " + secret(ch, "token")
        _post(ch["url"], message.encode(), h, ch.get("pin_sha256", ""))
        sent.append("ntfy")
    for ch in n.get("homeassistant") or []:
        domain, _, svc = ch["service"].partition(".")
        url = ch["url"].rstrip("/") + f"/api/services/{domain}/{svc}"
        h = {"Authorization": "Bearer " + secret(ch, "token"), "Content-Type": "application/json"}
        _post(url, json.dumps({"title": title, "message": message}).encode(), h, ch.get("pin_sha256", ""))
        sent.append("homeassistant")
    for ch in n.get("webhook") or []:
        h = {"Content-Type": "application/json"}
        if ch.get("token_file") or ch.get("token_env"):
            h["Authorization"] = "Bearer " + secret(ch, "token")
        _post(ch["url"], json.dumps({"title": title, "message": message}).encode(), h, ch.get("pin_sha256", ""))
        sent.append("webhook")
    return sent


def run(con, cfg, dry_run: bool = False) -> str:
    alerts, ids = _pending(con, cfg)
    if alerts:
        title, msg = format_message(alerts)
        urgent = any(a["tier"] == "act" for a in alerts)
        if dry_run:
            print(title)
            print(msg)
            return f"{len(alerts)} alert(s) (dry run, nothing sent, events left pending)"
        sent = send(cfg, title, msg, urgent)
        if not sent:
            print(title)
            print(msg)
    if ids and not dry_run:
        con.executemany("UPDATE event SET notified=1 WHERE id=?", [(i,) for i in ids])
        con.commit()
    if not alerts:
        return f"nothing to send ({len(ids)} event(s) checked)"
    return f"{len(alerts)} alert(s) sent via {', '.join(sent) or 'console (no channels configured)'}"


def test(cfg) -> str:
    sent = send(cfg, "cvescope test", "If you can read this, cvescope alerts reach you.", False)
    return "sent via " + ", ".join(sent) if sent else "no channels configured under [notify]"
