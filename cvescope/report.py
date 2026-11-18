"""Reports: what needs doing, what changed, what's acknowledged, and what cvescope can't see.

One report, four outputs:
  html  a self-contained page (no scripts) that prints cleanly to PDF
  md    Markdown for a ticket, a wiki page or a chat message
  csv   one row per finding, for a spreadsheet
  json  everything, for other tools

    cvescope report --format html --out ~/reports/cvescope-%Y-%m-%d.html
    cvescope report --format csv --host web1 --tier info

Everything in a report comes from your own database. Strings from feeds are escaped for the
format they land in (HTML, Markdown, and spreadsheet formulas in CSV).
"""

from __future__ import annotations

import csv
import datetime as dt
import html
import io
import json

from . import __version__, query, vulnid

FORMATS = ("html", "md", "csv", "json")
TIERS = ("act", "watch", "info")


def _link(vid: str, refs: list | None = None) -> str:
    if vid.startswith("CVE-"):
        return f"https://www.cve.org/CVERecord?id={vid}"
    if vid.startswith("GHSA-"):
        return f"https://github.com/advisories/{vid}"
    if refs:
        return refs[0]  # a PSA's forum post, or the advisory's own page
    return f"https://osv.dev/vulnerability/{vid}"


def _clip(s: str, n: int) -> str:
    """At most n characters, cut at a word with an ellipsis rather than mid-word."""
    s = " ".join(str(s).split())
    if len(s) <= n:
        return s
    cut = s[:n - 1].rsplit(" ", 1)[0]
    return cut.rstrip(",;:") + "…"


def _finding(r: dict, refs: dict) -> dict:
    a = r.get("ack") or {}
    return {"id": r["cve_id"], "tier": r["tier"], "why": r.get("why") or [], "status": r["status"],
            "host": r.get("host"), "item": r["item_name"], "version": r.get("item_version"),
            "title": _clip(r.get("title") or r.get("description") or "", 240), "detail": r.get("detail") or "",
            "fix": r.get("fix") or "unknown",
            "cvss": r.get("cvss"), "epss_pct": r.get("epss_pct"), "flags": query.flag_text(r),
            "published": (r.get("published") or "")[:10], "first_seen": (r.get("first_seen") or "")[:10],
            "ack": {"state": a.get("state"), "note": a.get("note"), "until": a.get("until"),
                    "reason": a.get("reason"), "created": (a.get("created") or "")[:10]} if a else None,
            "link": _link(r["cve_id"], refs.get(r["cve_id"]))}


def build(con, cfg, tiers=("act", "watch"), host: str | None = None, days: int = 7,
          include_keyword: bool = False) -> dict:
    """The report as plain data; every renderer works from this."""
    tiers = [t for t in TIERS if t in tiers] or ["act", "watch"]
    want = (host or "").strip().lower() or None
    on_host = (lambda r: (r.get("host") or "").lower() == want) if want else (lambda r: True)
    summ = query.summary(con, cfg)
    items = [it for it in summ["items"] if on_host(it)]
    every = [r for r in query.matches(con, cfg, tiers=TIERS, include_keyword=include_keyword, acked="include")
             if on_host(r)]
    advisory_ids = [r["cve_id"] for r in every if not vulnid.is_cve(r["cve_id"])]
    refs = {}
    if advisory_ids:
        q = f"SELECT id, refs FROM cve WHERE id IN ({','.join('?' * len(advisory_ids))})"
        refs = {i: json.loads(x or "[]") for i, x in con.execute(q, advisory_ids)}
    active = lambda r: (r.get("ack") or {}).get("state") == "active"  # noqa: E731
    findings = [_finding(r, refs) for r in every if r["tier"] in tiers and not active(r)]
    acked = [_finding(r, refs) for r in every if active(r)]
    counts = {t: sum(1 for r in every if r["tier"] == t and not active(r)) for t in TIERS}
    counts["acked"] = len(acked)
    fixes = {k: sum(1 for f in findings if f["fix"] == k) for k in FIX_LABEL}

    by_host: dict[str, dict] = {}
    for it in items:
        h = by_host.setdefault(it["host"], {"host": it["host"], "items": 0, "act": 0, "watch": 0, "info": 0,
                                            "acked": 0, "ruled_out": 0, "errors": 0})
        h["items"] += 1
        h["ruled_out"] += it.get("ruled_out") or 0
        h["errors"] += 1 if it.get("error") else 0
    for r in every:
        h = by_host.get(r.get("host"))
        if h:
            h["acked" if active(r) else r["tier"]] += 1
    hosts = sorted(by_host.values(), key=lambda h: (-h["act"], -h["watch"], -h["info"], h["host"].lower()))

    item_ids = {it["id"] for it in items}
    host_cves = {r["cve_id"] for r in every}
    changes = []
    for e in query.events(con, cfg, days=days):
        try:
            det = json.loads(e.get("detail") or "{}")
        except ValueError:
            det = {}
        if want and det.get("item") not in item_ids and e["cve_id"] not in host_cves:
            continue
        changes.append({"ts": (e.get("ts") or "")[:16].replace("T", " "), "id": e["cve_id"], "kind": e.get("kind"),
                        "summary": e.get("summary") or e.get("kind"), "title": (e.get("title") or "")[:160]})

    blind = [{"item": it["name"], "host": it["host"], "why": it["error"] and f"collector failed: {it['error']}"
              or (it.get("extra") or {}).get("hint") or "no version known"}
             for it in items if it.get("error") or not it.get("version")]
    health = summ.get("health") or {}
    feeds = [{"name": s["name"], "error": s["last_error"]} for s in summ["sources"] if s.get("last_error")]
    ends = sorted(({"item": it["name"], "host": it["host"], "version": it.get("version"), **it["eol"]}
                   for it in items if it.get("eol")),
                  key=lambda x: (x["state"] != "eol", x["host"].lower(), x["item"].lower()))
    credits = [{"label": s["label"], "url": s["url"]} for s in summ["sources"] if s.get("last_ok") and s.get("url")]
    now = dt.datetime.now().astimezone()
    return {"generated": now.isoformat(timespec="minutes"), "version": __version__,
            "scope": {"host": host or None, "tiers": tiers, "days": days, "keyword": include_keyword},
            "counts": counts, "fixes": fixes, "hosts": hosts, "findings": findings, "acknowledged": acked,
            "changes": changes, "blind_spots": blind, "feed_errors": feeds, "end_of_life": ends,
            "credits": credits, "nvd_notice": summ.get("nvd_notice"),
            "health": {"last_sync": health.get("finished"), "problems": health.get("problems") or []},
            "totals": {"items": len(items), "cves_known": summ.get("cves")}}


# ---- renderers ------------------------------------------------------------------------------

_TL = {"act": "Act now", "watch": "Watch", "info": "Info"}
FIX_LABEL = {"available": "fix available", "none": "no fix yet", "wontfix": "no update planned",
             "unknown": "not known"}


def _fix_line(d: dict) -> str:
    """'61 have a fix available, 255 no fix yet, ...' for the findings in the report."""
    parts = [f"{n} {FIX_LABEL[k]}" for k, n in d["fixes"].items() if n]
    return ("Of these findings: " + ", ".join(parts) + ".") if parts else ""


def _pct(p) -> str:
    return "" if p is None else f"{p * 100:.0f}%"


def _scope_line(d: dict) -> str:
    s = d["scope"]
    who = f"host {s['host']}" if s["host"] else f"all {d['totals']['items']} inventory items"
    return (f"{who} · findings: {', '.join(_TL[t] for t in s['tiers'])} · changes: last {s['days']} days"
            + (" · keyword matches included" if s["keyword"] else ""))


def render_json(d: dict) -> str:
    return json.dumps(d, indent=2, default=str)


def _cell(v) -> str:
    """No spreadsheet formulas from feed text: a cell starting with = + - @ gets a leading quote."""
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


def render_csv(d: dict) -> str:
    out = io.StringIO()
    w = csv.writer(out, lineterminator="\n")
    w.writerow(["id", "tier", "status", "host", "item", "version", "title", "why", "detail", "cvss", "epss",
                "exploit_evidence", "published", "first_seen", "acknowledged", "ack_note", "ack_until", "link",
                "fix"])  # new columns go last: spreadsheets built on older reports keep working
    for f in d["findings"] + d["acknowledged"]:
        a = f["ack"] or {}
        w.writerow([_cell(x) for x in (
            f["id"], f["tier"], f["status"], f["host"], f["item"], f["version"], f["title"], "; ".join(f["why"]),
            f["detail"], f["cvss"], _pct(f["epss_pct"]), " ".join(f["flags"]), f["published"], f["first_seen"],
            "yes" if a.get("state") == "active" else (a.get("state") or ""), a.get("note"), a.get("until"), f["link"],
            FIX_LABEL[f["fix"]])])
    return out.getvalue()


def _md(s) -> str:
    """Plain text in a Markdown table cell: no pipes, line breaks or markup characters."""
    s = "" if s is None else str(s)
    for ch in ("\\", "|", "*", "_", "`", "[", "]", "<", ">", "#"):
        s = s.replace(ch, "\\" + ch)
    return " ".join(s.split())


def render_md(d: dict) -> str:
    c = d["counts"]
    out = ["# cvescope report", "",
           f"{_md(_scope_line(d))}  ", f"Generated {d['generated']} by cvescope {d['version']}."
           + (f" Last full sync {d['health']['last_sync']}." if d["health"]["last_sync"] else ""), ""]
    for p in d["health"]["problems"]:
        out.append(f"> **Note:** {_md(p)}")
    out += ["", f"**{c['act']} act now · {c['watch']} watch · {c['info']} info · {c['acked']} acknowledged**", ""]
    if _fix_line(d):
        out += [_md(_fix_line(d)), ""]
    for t in d["scope"]["tiers"]:
        rows = [f for f in d["findings"] if f["tier"] == t]
        out += [f"## {_TL[t]} ({len(rows)})", ""]
        if not rows:
            out += ["Nothing.", ""]
            continue
        out += ["| ID | Host | Item | Title | Why | What cvescope found | Fix | CVSS | EPSS |",
                "|---|---|---|---|---|---|---|---|---|"]
        for f in rows:
            item = f"{f['item']} {f['version'] or ''}".strip()
            out.append(f"| [{_md(f['id'])}]({f['link']}) | {_md(f['host'])} | {_md(item)} | {_md(f['title'])} "
                       f"| {_md('; '.join(f['why']) or f['status'])} "
                       f"| {_md(f['detail'])} | {FIX_LABEL[f['fix']]} "
                       f"| {f['cvss'] if f['cvss'] is not None else ''} | {_pct(f['epss_pct'])} |")
        out.append("")
    out += [f"## End of life ({len(d['end_of_life'])})", ""]
    if d["end_of_life"]:
        out += ["| Host | Item | Version | What | Source |", "|---|---|---|---|---|"]
        out += [f"| {_md(x['host'])} | {_md(x['item'])} | {_md(x['version'] or '')} | {_md(x['text'])} "
                f"| [endoflife.date]({x['link']}) |" for x in d["end_of_life"]]
    else:
        out.append("Nothing you run is past or near end of life (where endoflife.date knows the release line).")
    out += ["", "## Hosts", "", "| Host | Items | Act now | Watch | Info | Acknowledged | Ruled out |",
            "|---|---|---|---|---|---|---|"]
    out += [f"| {_md(h['host'])} | {h['items']} | {h['act']} | {h['watch']} | {h['info']} | {h['acked']} | {h['ruled_out']} |"
            for h in d["hosts"]]
    out += ["", f"## Changed in the last {d['scope']['days']} days ({len(d['changes'])})", ""]
    out += [f"- {e['ts']} **{_md(e['id'])}**: {_md(e['summary'])}" for e in d["changes"][:200]] or ["Nothing changed."]
    out += ["", f"## Acknowledged ({len(d['acknowledged'])})", ""]
    if d["acknowledged"]:
        out += ["| ID | Host | Item | Note | Until |", "|---|---|---|---|---|"]
        out += [f"| [{_md(f['id'])}]({f['link']}) | {_md(f['host'])} | {_md(f['item'])} | {_md(f['ack']['note'])} "
                f"| {_md(f['ack']['until'] or 'no end date')} |" for f in d["acknowledged"]]
    else:
        out.append("Nothing acknowledged.")
    out += ["", "## Blind spots", ""]
    gaps = [f"- {_md(b['item'])} ({_md(b['host'])}): {_md(b['why'])}" for b in d["blind_spots"]]
    gaps += [f"- feed {_md(f['name'])}: {_md(f['error'])}" for f in d["feed_errors"]]
    out += gaps or ["None: every item has a version and every feed is current."]
    if d["credits"]:
        out += ["", "---", "", "Data: " + ", ".join(f"[{_md(c['label'])}]({c['url']})" for c in d["credits"]) + "."]
    if d["nvd_notice"]:
        out += ["", _md(d["nvd_notice"])]
    return "\n".join(out) + "\n"


_CSS = """
:root{--bg:#fff;--fg:#1b2430;--muted:#5d6b7d;--line:#d9e0e8;--act:#c92a2a;--watch:#a86400;--info:#5d6b7d;--ok:#0f8f6a;--link:#0b62b8}
@media (prefers-color-scheme:dark){:root{--bg:#0d1117;--fg:#d7dee8;--muted:#8794a6;--line:#243041;--act:#ff5d5d;--watch:#f2b84b;--info:#8794a6;--ok:#4fd1a5;--link:#7cc4ff}}
@media print{:root{--bg:#fff;--fg:#000;--muted:#444;--line:#bbb;--act:#b00;--watch:#8a5200;--info:#444;--ok:#0a6;--link:#000}
 a{text-decoration:none} section{break-inside:auto} tr{break-inside:avoid} .noprint{display:none}}
*{box-sizing:border-box} body{margin:0;background:var(--bg);color:var(--fg);font:13px/1.45 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:1100px;margin:0 auto;padding:24px 20px 48px} h1{font-size:22px;margin:0 0 4px} h2{font-size:16px;margin:28px 0 8px;border-bottom:1px solid var(--line);padding-bottom:4px}
.muted{color:var(--muted)} a{color:var(--link)} .note{border-left:3px solid var(--watch);padding:4px 10px;margin:8px 0;color:var(--watch)}
.cards{display:flex;gap:10px;flex-wrap:wrap;margin:14px 0} .card{border:1px solid var(--line);border-radius:8px;padding:8px 14px;min-width:120px}
.card b{display:block;font-size:22px} .card.act b{color:var(--act)} .card.watch b{color:var(--watch)} .card.info b{color:var(--info)} .card.ok b{color:var(--ok)}
table{border-collapse:collapse;width:100%;margin:6px 0} th,td{text-align:left;vertical-align:top;padding:5px 8px;border-bottom:1px solid var(--line)}
th{font-size:11px;text-transform:uppercase;letter-spacing:.5px;color:var(--muted)} td.id{font-family:ui-monospace,Consolas,monospace;white-space:nowrap}
td.num{text-align:right;white-space:nowrap} .why{color:var(--muted);font-size:12px}
td.eol.past{color:var(--watch);font-weight:600} td.fix{white-space:nowrap;font-size:12px;color:var(--muted)} td.fix.available{color:var(--ok);font-weight:600} .tier-act td.id a{color:var(--act)} .tier-watch td.id a{color:var(--watch)}
ul{padding-left:18px} li{margin:2px 0} footer{margin-top:32px;font-size:11px;color:var(--muted)}
"""


def render_html(d: dict) -> str:
    e = lambda v: html.escape("" if v is None else str(v), quote=True)  # noqa: E731
    c = d["counts"]
    parts = ["<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">",
             "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">",
             "<meta name=\"referrer\" content=\"no-referrer\">",
             f"<title>cvescope report {e(d['generated'][:10])}</title><style>{_CSS}</style></head><body><main>",
             "<h1>cvescope report</h1>",
             f"<div class=\"muted\">{e(_scope_line(d))}<br>Generated {e(d['generated'])} by cvescope {e(d['version'])}"
             + (f" · last full sync {e(d['health']['last_sync'])}" if d["health"]["last_sync"] else "") + "</div>"]
    parts += [f"<div class=\"note\">{e(p)}</div>" for p in d["health"]["problems"]]
    parts.append("<div class=\"cards\">" + "".join(
        f"<div class=\"card {k}\"><b>{c[n]}</b>{e(label)}</div>"
        for k, n, label in (("act", "act", "act now"), ("watch", "watch", "watch"), ("info", "info", "info"),
                            ("ok", "acked", "acknowledged"))) + "</div>")
    if _fix_line(d):
        parts.append(f"<p class=\"muted\">{e(_fix_line(d))}</p>")
    for t in d["scope"]["tiers"]:
        rows = [f for f in d["findings"] if f["tier"] == t]
        parts.append(f"<section><h2>{e(_TL[t])} ({len(rows)})</h2>")
        if not rows:
            parts.append("<p class=\"muted\">Nothing.</p></section>")
            continue
        parts.append("<table><tr><th>ID</th><th>Host</th><th>Item</th><th>What cvescope found</th><th>Fix</th>"
                     "<th>CVSS</th><th>EPSS</th></tr>")
        for f in rows:
            why = "; ".join(f["why"]) or f["status"]
            lapsed = f" · acknowledgement {f['ack']['state']}: {f['ack']['reason']}" if f["ack"] else ""
            parts.append(
                f"<tr class=\"tier-{e(t)}\"><td class=\"id\"><a href=\"{e(f['link'])}\">{e(f['id'])}</a></td>"
                f"<td>{e(f['host'])}</td><td>{e(f['item'])} {e(f['version'] or '')}</td>"
                f"<td>{e(f['title'])}<div class=\"why\">{e(why)} · {e(f['detail'])}{e(lapsed)}</div></td>"
                f"<td class=\"fix {e(f['fix'])}\">{e(FIX_LABEL[f['fix']])}</td>"
                f"<td class=\"num\">{e(f['cvss'] if f['cvss'] is not None else '')}</td><td class=\"num\">{e(_pct(f['epss_pct']))}</td></tr>")
        parts.append("</table></section>")
    parts.append(f"<section><h2>End of life ({len(d['end_of_life'])})</h2>")
    if d["end_of_life"]:
        parts.append("<table><tr><th>Host</th><th>Item</th><th>Version</th><th>What</th><th>Source</th></tr>")
        parts += [f"<tr><td>{e(x['host'])}</td><td>{e(x['item'])}</td><td>{e(x['version'] or '')}</td>"
                  f"<td class=\"eol {'past' if x['state'] == 'eol' else 'soon'}\">{e(x['text'])}</td>"
                  f"<td><a href=\"{e(x['link'])}\">endoflife.date</a></td></tr>" for x in d["end_of_life"]]
        parts.append("</table>")
    else:
        parts.append("<p class=\"muted\">Nothing you run is past or near end of life "
                     "(where endoflife.date knows the release line).</p>")
    parts.append("</section>")
    parts.append("<section><h2>Hosts</h2><table><tr><th>Host</th><th>Items</th><th>Act now</th><th>Watch</th>"
                 "<th>Info</th><th>Acknowledged</th><th>Ruled out</th></tr>")
    parts += [f"<tr><td>{e(h['host'])}</td>" + "".join(f"<td class=\"num\">{h[k]}</td>" for k in
                                                         ("items", "act", "watch", "info", "acked", "ruled_out")) + "</tr>"
              for h in d["hosts"]]
    parts.append("</table></section>")
    parts.append(f"<section><h2>Changed in the last {d['scope']['days']} days ({len(d['changes'])})</h2>")
    parts.append("<ul>" + "".join(f"<li><span class=\"muted\">{e(x['ts'])}</span> <b>{e(x['id'])}</b>: {e(x['summary'])}</li>"
                                  for x in d["changes"][:300]) + "</ul>" if d["changes"] else "<p class=\"muted\">Nothing changed.</p>")
    parts.append("</section>")
    parts.append(f"<section><h2>Acknowledged ({len(d['acknowledged'])})</h2>")
    if d["acknowledged"]:
        parts.append("<table><tr><th>ID</th><th>Host</th><th>Item</th><th>Note</th><th>Since</th><th>Until</th></tr>")
        parts += [f"<tr><td class=\"id\"><a href=\"{e(f['link'])}\">{e(f['id'])}</a></td><td>{e(f['host'])}</td>"
                  f"<td>{e(f['item'])}</td><td>{e(f['ack']['note'])}</td><td>{e(f['ack']['created'])}</td>"
                  f"<td>{e(f['ack']['until'] or 'no end date')}</td></tr>" for f in d["acknowledged"]]
        parts.append("</table>")
    else:
        parts.append("<p class=\"muted\">Nothing acknowledged.</p>")
    parts.append("</section><section><h2>Blind spots</h2>")
    gaps = [f"<li>{e(b['item'])} <span class=\"muted\">({e(b['host'])})</span>: {e(b['why'])}</li>" for b in d["blind_spots"]]
    gaps += [f"<li>feed {e(f['name'])}: {e(f['error'])}</li>" for f in d["feed_errors"]]
    parts.append("<ul>" + "".join(gaps) + "</ul>" if gaps else
                 "<p class=\"muted\">None: every item has a version and every feed is current.</p>")
    credits = ", ".join(f"<a href=\"{e(c['url'])}\">{e(c['label'])}</a>" for c in d["credits"])
    parts.append("</section><footer>cvescope only knows what its inventory lists; anything not in it isn't in this report. "
                 "https://github.com/magikh0e/cvescope"
                 + (f"<br>Data: {credits}." if credits else "")
                 + (f"<br>{e(d['nvd_notice'])}" if d["nvd_notice"] else "") + "</footer></main></body></html>")
    return "".join(parts)


RENDER = {"html": render_html, "md": render_md, "csv": render_csv, "json": render_json}
MIME = {"html": "text/html; charset=utf-8", "md": "text/markdown; charset=utf-8",
        "csv": "text/csv; charset=utf-8", "json": "application/json"}


def render(d: dict, fmt: str) -> str:
    return RENDER[fmt](d)
