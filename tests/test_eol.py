"""End of life: is the release line an item runs still getting fixes? (endoflife.date)"""

import copy
import datetime as dt
import json
import unittest
from unittest import mock

from cvescope import config, db, eol, notify, query, report, sources
from cvescope.sources import endoflife

TODAY = dt.date(2026, 11, 18)
FEED = {"result": [
    {"name": "openssl", "label": "OpenSSL", "labels": {"eoes": "Premium support"},
     "links": {"html": "https://endoflife.date/openssl"},
     "identifiers": [{"type": "cpe", "id": "cpe:/a:openssl:openssl"}],
     "releases": [{"name": "3.5", "isEol": False, "eolFrom": "2030-04-08", "latest": {"name": "3.5.9"}},
                  {"name": "3.0", "isEol": True, "eolFrom": "2026-09-07", "isEoes": False, "eoesFrom": None,
                   "latest": {"name": "3.0.22"}}]},
    {"name": "opnsense", "label": "OPNsense", "labels": {}, "links": {"html": "https://endoflife.date/opnsense"},
     "identifiers": [{"type": "cpe", "id": "cpe:2.3:a:opnsense:opnsense"}],
     "releases": [{"name": "26.7", "isEol": False, "eolFrom": None}, {"name": "26.1", "isEol": False, "eolFrom": "2027-01-31"}]},
    {"name": "debian", "label": "Debian", "labels": {"eoes": "ELTS"},
     "identifiers": [{"type": "cpe", "id": "cpe:/o:debian:debian_linux"}],
     "releases": [{"name": "11", "isEol": True, "eolFrom": "2026-08-31", "isEoes": False, "eoesFrom": "2031-06-30"}]},
]}
ITEMS = [  # id, name, version, aliases, extra
    ("a", "OpenSSL (fw)", "3.0.13", ["openssl:openssl"], {}),
    ("b", "OpenSSL (web1)", "3.0.13", ["openssl:openssl"], {"backports": True}),   # Ubuntu keeps patching it
    ("c", "OPNsense", "26.1.11", ["opnsense:opnsense"], {}),
    ("d", "OPNsense (new)", "26.7.9", ["opnsense:opnsense"], {}),
    ("e", "Debian 11 (vm1)", "11", ["debian:debian linux"], {}),
    ("f", "OpenSSL (wild)", "3.0.13", ["openssl*"], {}),          # no vendor: not tied to a product
    ("g", "OpenSSL (next)", "4.0.0", ["openssl:openssl"], {}),    # no line listed for it
]


def fresh(nvd=False):
    cfg = config.Config(copy.deepcopy(config.DEFAULTS))
    cfg["nvd"]["enabled"] = nvd
    con = db.connect(":memory:")
    for iid, name, ver, al, ex in ITEMS:
        con.execute("INSERT INTO item(id,name,version,collector,aliases,keywords,extra) VALUES(?,?,?,'x:host1',?,'[]',?)",
                    (iid, name, ver, json.dumps(al), json.dumps(ex)))
    con.commit()
    with mock.patch.object(endoflife.net, "get", lambda url, etag=None, timeout=120, compressed=False:
                           (json.dumps(FEED).encode(), '"e"')):
        endoflife.sync(con, cfg)
    return con, cfg


class EndOfLife(unittest.TestCase):
    def test_states(self):
        self.assertEqual(eol.state({"is_eol": 1, "eol_from": "2026-09-07"}, TODAY), ("eol", dt.date(2026, 9, 7)))
        self.assertEqual(eol.state({"is_eol": 0, "eol_from": "2026-11-01"}, TODAY)[0], "eol")   # feed older than the date
        self.assertEqual(eol.state({"is_eol": 0, "eol_from": "2027-01-31"}, TODAY), ("soon", dt.date(2027, 1, 31)))
        self.assertIsNone(eol.state({"is_eol": 0, "eol_from": "2030-04-08"}, TODAY))
        self.assertIsNone(eol.state({"is_eol": 0, "eol_from": None}, TODAY))

    def test_items(self):
        con, _ = fresh()
        got = eol.for_items(con, [{"id": i, "version": v, "extra": ex} for i, _, v, _, ex in ITEMS], today=TODAY)
        self.assertEqual(sorted(got), ["a", "c", "e"])
        self.assertEqual(got["a"]["text"], "OpenSSL 3.0 reached end of life on 2026-09-07: no more fixes; "
                                           "Premium support is still offered")
        self.assertEqual((got["a"]["state"], got["a"]["link"]), ("eol", "https://endoflife.date/openssl"))
        self.assertEqual(got["c"]["text"], "OPNsense 26.1 reaches end of life on 2027-01-31 (in 74 days)")
        self.assertEqual(got["e"]["text"], "Debian 11 reached end of life on 2026-08-31: no more fixes; ELTS runs until 2031-06-30")
        self.assertEqual(got["e"]["link"], "https://endoflife.date/debian")   # no link in the feed: built from the name

    @mock.patch.object(eol, "_today", lambda: TODAY)
    def test_page_and_reports(self):
        con, cfg = fresh(nvd=True)
        s = query.summary(con, cfg)
        by = {it["id"]: it for it in s["items"]}
        self.assertEqual(by["a"]["eol"]["state"], "eol")
        self.assertIsNone(by["b"]["eol"])
        src = {x["name"]: x for x in s["sources"]}
        self.assertEqual((src["endoflife"]["label"], src["endoflife"]["url"]), ("endoflife.date", "https://endoflife.date/"))
        self.assertEqual(s["nvd_notice"], sources.NVD_NOTICE)
        d = report.build(con, cfg)
        # past end of life first, then by host (fw, vm1)
        self.assertEqual([x["item"] for x in d["end_of_life"]], ["OpenSSL (fw)", "Debian 11 (vm1)", "OPNsense"])
        md = report.render(d, "md")
        self.assertIn("## End of life (", md)
        self.assertIn("OpenSSL 3.0 reached end of life on 2026-09-07", md)
        self.assertIn("Data: [endoflife.date](https://endoflife.date/).", md)
        self.assertIn(sources.NVD_NOTICE, md)
        page = report.render(d, "html")
        self.assertIn('<td class="eol past">OpenSSL 3.0 reached end of life', page)
        self.assertIn('Data: <a href="https://endoflife.date/">endoflife.date</a>.', page)

    def test_feed_credits(self):
        self.assertEqual(sources.credit("distro:ubuntu:noble")["label"], "Ubuntu OVAL (noble)")
        self.assertEqual(sources.credit("distro:debian")["url"], "https://security-tracker.debian.org/")
        self.assertEqual(sources.credit("local:my exploits"),
                         {"label": "your archive: my exploits", "url": None, "what": "files in your own folders that mention a CVE"})
        self.assertEqual(sources.credit("something new"), {"label": "something new", "url": None, "what": ""})

    def test_no_notice_without_the_nvd_lookup(self):
        con, cfg = fresh()
        self.assertIsNone(query.summary(con, cfg)["nvd_notice"])
        self.assertNotIn("NVD API", report.render(report.build(con, cfg), "md"))


class Changes(unittest.TestCase):
    """Reaching end of life (or 90 days from it) is a change: Changes, reports and alerts."""

    def setUp(self):
        self.con, self.cfg = fresh()
        self.items = [{"id": i, "version": v, "extra": ex} for i, _, v, _, ex in ITEMS]

    def kinds(self):
        return [(r["kind"], json.loads(r["detail"])["item"]) for r in self.con.execute("SELECT kind, detail FROM event ORDER BY id")]

    def test_track(self):
        self.assertEqual(eol.track(self.con, self.items, TODAY), 0)      # first time: just remember
        self.assertEqual(self.kinds(), [])
        self.assertEqual(eol.track(self.con, self.items, TODAY), 0)      # nothing moved
        later = dt.date(2027, 2, 1)                                       # OPNsense 26.1 passes its date
        self.assertEqual(eol.track(self.con, self.items, later), 1)
        self.assertEqual(self.kinds(), [("eol", "c")])
        # an item added later that's already past end of life is a change too
        self.con.execute("INSERT INTO item(id,name,version,collector,aliases,keywords,extra) VALUES"
                         "('h','OpenSSL (fw2)','3.0.1','x:host2','[\"openssl:openssl\"]','[]','{}')")
        self.items.append({"id": "h", "version": "3.0.1", "extra": {}})
        self.assertEqual(eol.track(self.con, self.items, later), 1)
        self.assertEqual(self.kinds()[-1], ("eol", "h"))

    def test_no_release_data_no_changes(self):
        self.con.execute("DELETE FROM eol_cycle")
        self.assertEqual(eol.track(self.con, self.items, TODAY), 0)
        self.assertIsNone(db.meta_get(self.con, "eol_seen"))

    def changed(self):
        eol.track(self.con, self.items, TODAY)
        db.meta_set(self.con, "eol_seen", {})     # pretend none of them were flagged last time
        eol.track(self.con, self.items, TODAY)

    def test_listed(self):
        self.changed()
        ev = {e["item"]: e for e in query.events(self.con, self.cfg, days=7)}
        self.assertEqual(sorted(ev), ["a", "c", "e"])
        self.assertEqual(ev["c"]["kind"], "eol_soon")
        self.assertEqual(ev["a"]["summary"], "OpenSSL (fw): OpenSSL 3.0 reached end of life on 2026-09-07: "
                                             "no more fixes; Premium support is still offered")
        ids = {c["id"] for c in report.build(self.con, self.cfg)["changes"]}
        self.assertEqual(ids, {"End of life", "End of life soon"})

    def test_alerts(self):
        self.changed()
        alerts, ids = notify._pending(self.con, self.cfg)
        self.assertEqual((len(alerts), len(ids)), (3, 3))
        title, msg = notify.format_message(alerts)
        self.assertEqual(title, "cvescope: 3 end of life")
        self.assertIn("End of life: OPNsense: OPNsense 26.1 reaches end of life on 2027-01-31 (in 74 days)", msg)
        self.cfg["notify"]["end_of_life"] = False
        alerts, ids = notify._pending(self.con, self.cfg)
        self.assertEqual((alerts, len(ids)), ([], 3))     # still marked as seen once sent


if __name__ == "__main__":
    unittest.main()
