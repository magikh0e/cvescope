"""cvescope command line."""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

from . import __version__, config, db


def _con(cfg):
    return db.connect(cfg.db_path)


def cmd_sync(cfg, a):
    from . import sources
    con = _con(cfg)
    only = a.only.split(",") if a.only else None
    started = db.now()
    # inventory first: the distro source fetches only the releases your hosts run
    if not a.no_inventory and not only:
        cmd_inventory(cfg, a, con=con, quiet=True)
    results = sources.run(con, cfg, only=only, rebaseline=a.rebaseline, verbose=a.verbose)
    if not only or "match" in (only or []):
        from . import match
        print("[match]")
        print("  " + match.run(con, cfg))
        if cfg["nvd"].get("enabled") and not only:
            from .sources import nvd
            print("[nvd]")
            fetched, msg = nvd.enrich(con, cfg)
            print("  " + msg)
            if fetched:
                print("  re-matching with NVD data: " + match.run(con, cfg))
    if not a.no_notify and not only:
        from . import notify
        print("[notify]")
        print("  " + notify.run(con, cfg, dry_run=a.dry_run))
    if not only:
        # the page and `cvescope status` use this to spot a schedule that quietly stopped
        failed_collectors = [r[0] for r in con.execute(
            "SELECT DISTINCT collector FROM item WHERE error IS NOT NULL ORDER BY collector")]
        db.meta_set(con, "last_sync", {
            "started": started, "finished": db.now(), "version": __version__,
            "failed_feeds": sorted(n for n, m in results.items() if m.startswith("ERROR")),
            "failed_collectors": failed_collectors,
        })
    return 0


def cmd_inventory(cfg, a, con=None, quiet=False):
    from . import collectors
    con = con or _con(cfg)
    if not quiet:
        print("[inventory]")
    else:
        print("[inventory]")
    items = collectors.run(con, cfg, verbose=getattr(a, "verbose", False))
    for it in items:
        ver = it.get("version") or "?"
        err = f"   !! {it['error']}" if it.get("error") else ""
        print(f"  {it['name']:<40} {ver:<22} {it['collector']}{err}")
    return 0


def cmd_match(cfg, a):
    from . import match
    con = _con(cfg)
    print(match.run(con, cfg))
    return 0


def cmd_report(cfg, a):
    from . import query
    con = _con(cfg)
    tiers = ["act", "watch", "info"]
    want = tiers[: tiers.index(a.tier) + 1]
    rows = query.matches(con, cfg, tiers=want, include_keyword=a.keyword,
                         acked="include" if a.acked else "hide")
    if not rows:
        print("nothing at or above tier", a.tier)
        return 0
    cur = None
    for r in rows:
        if r["tier"] != cur:
            cur = r["tier"]
            print(f"\n== {query.TIER_LABEL[cur]} ==")
        flags = " ".join(query.flag_text(r))
        if r.get("ack"):
            flags = ("[acked] " if r["ack"]["state"] == "active" else f"[ack {r['ack']['state']}] ") + flags
        epss = f"epss {r['epss_pct'] * 100:.0f}%" if r.get("epss_pct") is not None else ""
        cvss = f"cvss {r['cvss']}" if r.get("cvss") is not None else ""
        print(f"{r['cve_id']:<18} {r['item_name'][:28]:<28} {r['status']:<9} {cvss:<9} {epss:<9} {flags}")
        if a.long:
            print("    " + (r.get("title") or r.get("description") or "")[:150])
    return 0


def cmd_ack(cfg, a):
    from . import acks
    con = _con(cfg)
    cid = a.cve.upper()
    try:
        rows = acks.add(con, cfg, cid, a.item, a.note or "", days=a.days, until=a.until)
    except ValueError as e:
        print(f"cvescope ack: {e}", file=sys.stderr)
        return 1
    a_row = acks.load(con)[(cid, rows[0]["item_id"])]
    for r in rows:
        print(f"acknowledged {cid} on {r['item_name']}"
              + (f" until {a_row['until']}" if a_row["until"] else " (no end date)"))
    print("It comes back if the evidence gets worse. `cvescope unack` takes it back.")
    return 0


def cmd_unack(cfg, a):
    from . import acks, query
    con = _con(cfg)
    cid = a.cve.upper()
    names = query.item_names(con)
    try:
        removed = acks.remove(con, cid, a.item)
    except ValueError as e:
        print(f"cvescope unack: {e}", file=sys.stderr)
        return 1
    for iid in removed:
        print(f"removed the acknowledgement of {cid} on {names.get(iid, iid)}")
    return 0


def cmd_acks(cfg, a):
    from . import acks
    con = _con(cfg)
    rows = acks.list_all(con, cfg)
    if not a.all:
        rows = [r for r in rows if r["state"] != "resolved"]
    if not rows:
        print("nothing acknowledged" + ("" if a.all else " (--all includes resolved ones)"))
        return 0
    for r in rows:
        end = f"until {r['until']}" if r["until"] else "no end date"
        print(f"{r['cve_id']:<18} {r['item_name'][:28]:<28} {r['state']:<8} {r['created'][:10]}  {end:<16}  {r['note']}")
        if r["reason"]:
            print(f"    {'back because' if r['state'] == 'lapsed' else 'note'}: {r['reason']}")
    return 0


def cmd_show(cfg, a):
    from . import query
    con = _con(cfg)
    d = query.cve_detail(con, cfg, a.cve.upper())
    if not d:
        print("not found")
        return 1
    print(json.dumps(d, indent=2, default=str))
    return 0


def cmd_events(cfg, a):
    from . import query
    con = _con(cfg)
    for e in query.events(con, cfg, days=a.days, matched_only=not a.all):
        print(f"{e['ts'][:16]}  {e['kind']:<8} {e['cve_id']:<18} {e.get('summary', '')}")
    return 0


def cmd_status(cfg, a):
    con = _con(cfg)
    from . import query
    print(f"config: {cfg.path or '(none: defaults)'}")
    print(f"data:   {cfg.db_path}")
    h = query.health(con, cfg)
    print(f"last full sync: {h['finished'] or 'never'}"
          + (f" ({h['age_hours']:.1f} h ago)" if h["age_hours"] is not None else ""))
    for line in h["problems"]:
        print(f"  !! {line}")
    for r in con.execute("SELECT name,last_ok,last_try,last_error FROM source ORDER BY name"):
        state = "ok " if not r["last_error"] else "ERR"
        print(f"  {state} {r['name']:<22} last ok {r['last_ok'] or 'never':<22} {r['last_error'] or ''}")
    n = con.execute("SELECT count(*) FROM cve").fetchone()[0]
    m = con.execute("SELECT count(*) FROM match").fetchone()[0]
    i = con.execute("SELECT count(*) FROM item").fetchone()[0]
    print(f"  {n:,} CVEs, {i} inventory items, {m:,} matches")
    return 0


def cmd_serve(cfg, a):
    from . import server
    host = cfg["serve"]["host"]
    port = a.port or int(cfg["serve"]["port"])
    server.serve(cfg, host, port)
    return 0


def cmd_notify(cfg, a):
    from . import notify
    con = _con(cfg)
    if a.test:
        print(notify.test(cfg))
    else:
        print(notify.run(con, cfg, dry_run=a.dry_run))
    return 0


def cmd_pin(cfg, a):
    from . import net
    host, _, port = a.target.partition(":")
    fp = net.fingerprint(host, int(port or 443))
    print(f'pin_sha256 = "{fp}"')
    print("Compare this with the fingerprint shown in the device's own UI before trusting it.")
    return 0


def cmd_init(cfg, a):
    src = Path(__file__).resolve().parent / "config.example.toml"  # shipped inside the package
    dest = Path(a.path) if a.path else config.user_config_dir() / "config.toml"
    if dest.exists():
        print(f"{dest} already exists; not overwriting")
        return 1
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy(src, dest)
    print(f"wrote {dest}: add your inventory, then run `cvescope sync`")
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="cvescope", description=__doc__)
    p.add_argument("--config", "-c", help="path to config.toml")
    p.add_argument("--log", help="append all output to this file (for cron / Task Scheduler runs)")
    p.add_argument("--version", action="version", version=f"cvescope {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("sync", help="pull every feed, refresh inventory, match, notify")
    s.add_argument("--only", help="comma list: cvelist,kev,epss,metasploit,nuclei,exploitdb,github_poc,local_archive,distro,freebsd")
    s.add_argument("--rebaseline", action="store_true", help="re-download the full CVE List")
    s.add_argument("--no-inventory", action="store_true")
    s.add_argument("--no-notify", action="store_true")
    s.add_argument("--dry-run", action="store_true", help="print notifications instead of sending")
    s.add_argument("-v", "--verbose", action="store_true")
    s.set_defaults(fn=cmd_sync)

    s = sub.add_parser("inventory", help="collect versions from your gear")
    s.add_argument("-v", "--verbose", action="store_true")
    s.set_defaults(fn=cmd_inventory)
    sub.add_parser("match", help="re-match CVEs against inventory").set_defaults(fn=cmd_match)

    s = sub.add_parser("report", help="print matched CVEs by tier")
    s.add_argument("--tier", choices=["act", "watch", "info"], default="watch")
    s.add_argument("--keyword", action="store_true", help="include keyword-only matches")
    s.add_argument("-l", "--long", action="store_true")
    s.add_argument("--acked", action="store_true", help="include acknowledged matches")
    s.set_defaults(fn=cmd_report)

    s = sub.add_parser("ack", help="acknowledge a CVE you've dealt with (hides it until the evidence gets worse)")
    s.add_argument("cve")
    s.add_argument("--item", help="item id, name, or part of a name (default: every item it shows up on)")
    s.add_argument("--note", "-m", help="what you did, e.g. 'applied the opt-in fix'")
    g = s.add_mutually_exclusive_group()
    g.add_argument("--days", type=int, help="bring it back after this many days")
    g.add_argument("--until", help="bring it back after this date (YYYY-MM-DD)")
    s.set_defaults(fn=cmd_ack)

    s = sub.add_parser("unack", help="take an acknowledgement back")
    s.add_argument("cve")
    s.add_argument("--item", help="item id, name, or part of a name (default: all of them)")
    s.set_defaults(fn=cmd_unack)

    s = sub.add_parser("acks", help="list acknowledgements and whether they still hold")
    s.add_argument("--all", action="store_true", help="include ones that no longer match anything")
    s.set_defaults(fn=cmd_acks)

    s = sub.add_parser("show", help="everything known about one CVE")
    s.add_argument("cve")
    s.set_defaults(fn=cmd_show)

    s = sub.add_parser("events", help="recent changes")
    s.add_argument("--days", type=int, default=7)
    s.add_argument("--all", action="store_true", help="include CVEs you don't run")
    s.set_defaults(fn=cmd_events)

    sub.add_parser("status", help="feed health").set_defaults(fn=cmd_status)

    s = sub.add_parser("serve", help="local web page")
    s.add_argument("--port", type=int)
    s.set_defaults(fn=cmd_serve)

    s = sub.add_parser("notify", help="send pending alerts")
    s.add_argument("--test", action="store_true", help="send one test message to every channel")
    s.add_argument("--dry-run", action="store_true")
    s.set_defaults(fn=cmd_notify)

    s = sub.add_parser("pin", help="print a host's certificate SHA-256 for pin_sha256")
    s.add_argument("target", help="host[:port]")
    s.set_defaults(fn=cmd_pin)

    s = sub.add_parser("init", help="write a starter config")
    s.add_argument("path", nargs="?")
    s.set_defaults(fn=cmd_init)

    a = p.parse_args(argv)
    log = _open_log(a.log) if a.log else None
    if log:
        # background runs (pythonw, cron) have no console: everything goes to the file
        sys.stdout = sys.stderr = log
        print(f"\n===== cvescope {__version__} {a.cmd} {db.now()} =====", flush=True)
    elif hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    try:
        cfg = config.load(a.config)
        return a.fn(cfg, a)
    except KeyboardInterrupt:
        return 130
    except Exception:
        if not log:
            raise
        import traceback
        traceback.print_exc()
        return 1
    finally:
        if log:
            log.flush()


def _open_log(path: str):
    """Append-mode log file; rotates to <name>.1 once it passes 5 MB."""
    p = config.expand(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    if p.exists() and p.stat().st_size > 5_000_000:
        old = p.with_name(p.name + ".1")
        if old.exists():
            old.unlink()
        p.rename(old)
    return open(p, "a", encoding="utf-8", errors="replace", buffering=1)
