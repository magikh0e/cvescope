"""A CVE record can name its fix before that release ships: endoflife.date says whether it's out."""

import copy
import json
import unittest
from unittest import mock

from cvescope import config, db, match, query
from cvescope.sources import endoflife

FEED = {"generated_at": "2026-11-18T09:37:30+00:00", "result": [
    {"name": "openssl",
     "identifiers": [{"type": "repology", "id": "openssl"}, {"type": "cpe", "id": "cpe:/a:openssl:openssl"},
                     {"type": "cpe", "id": "cpe:2.3:a:openssl:openssl"}],
     "releases": [{"name": "3.6", "latest": {"name": "3.6.5", "date": "2026-09-29"}},
                  {"name": "3.5", "latest": {"name": "3.5.9", "date": "2026-09-29"}},
                  {"name": "1.0.2", "latest": None}]},
    {"name": "freebsd", "identifiers": [{"type": "cpe", "id": "cpe:/o:freebsd:freebsd"}],
     "releases": [{"name": "15.1", "latest": {"name": "15.1", "date": "2026-06-02"}}]},
    {"name": "no-cpe", "identifiers": [{"type": "cpe", "id": "cpe:/a:"}, {"type": "purl", "id": "pkg:x/y"}],
     "releases": []},
]}

AFFECTED = [{"v": "OpenSSL", "p": "OpenSSL",
             "vs": [{"version": "3.5.0", "lessThan": "3.5.10", "status": "affected", "versionType": "semver"}]}]
NOTE = " (not released yet: the newest 3.5 release is 3.5.9)"


class Lines(unittest.TestCase):
    LINES = [("4.1", "4.1.0"), ("3.6", "3.6.5"), ("3.5", "3.5.9"), ("3", "3.6.5")]

    def test_which_line_and_whether_its_out(self):
        u = match.unreleased
        self.assertEqual(u("3.5.10", self.LINES), ("3.5", "3.5.9"))   # the longest line wins over "3"
        self.assertIsNone(u("3.5.9", self.LINES))
        self.assertIsNone(u("3.5.8", self.LINES))
        self.assertEqual(u("3.6.6", self.LINES), ("3.6", "3.6.5"))
        self.assertEqual(u("v1.9.17p3", [("1.9", "1.9.17p2")]), ("1.9", "1.9.17p2"))

    def test_when_the_data_cant_say(self):
        u = match.unreleased
        self.assertIsNone(u("5.0.0", self.LINES))                       # no line it belongs to
        self.assertIsNone(u("9.2.30", [("9", "9.2")]))                  # newest release less precise than the fix
        self.assertIsNone(u("10.0.26100.4652", [("11-24h2-w", "10.0.26100")]))   # Windows lines aren't versions
        self.assertIsNone(u("", self.LINES))


class Feed(unittest.TestCase):
    def test_parse(self):
        cycles, cpes = endoflife.parse(FEED)
        self.assertEqual(cycles, [("openssl", "3.6", "3.6.5", "2026-09-29"), ("openssl", "3.5", "3.5.9", "2026-09-29"),
                                  ("freebsd", "15.1", "15.1", "2026-06-02")])
        self.assertEqual(cpes, [("freebsd", "freebsd", "freebsd"), ("openssl", "openssl", "openssl")])

    def test_sync_keeps_the_last_good_copy(self):
        con = db.connect(":memory:")
        cfg = config.Config(copy.deepcopy(config.DEFAULTS))
        with mock.patch.object(endoflife.net, "get", lambda url, etag=None, timeout=120, compressed=False:
                               (json.dumps(FEED).encode(), '"e1"')):
            self.assertEqual(endoflife.sync(con, cfg), "3 release lines for 2 products")
        self.assertEqual(db.source_get(con, "endoflife")["etag"], '"e1"')
        with mock.patch.object(endoflife.net, "get", lambda url, etag=None, timeout=120, compressed=False:
                               (b'{"result": []}', '"e2"')):
            with self.assertRaises(ValueError):
                endoflife.sync(con, cfg)
        self.assertEqual(con.execute("SELECT COUNT(*) FROM eol_cycle").fetchone()[0], 3)


class Matching(unittest.TestCase):
    def setUp(self):
        self.cfg = config.Config(copy.deepcopy(config.DEFAULTS))
        con = self.con = db.connect(":memory:")
        con.execute("INSERT INTO item(id,name,version,collector,aliases,keywords,extra) VALUES"
                    "('o','OpenSSL (fw)','3.5.9','opnsense:fw','[\"openssl:openssl\"]','[]','{}')")
        con.execute("INSERT INTO cve(id,state,title,published,affected) VALUES('CVE-2026-0101','PUBLISHED','t',"
                    "'2026-11-10',?)", (json.dumps(AFFECTED),))
        con.execute("INSERT INTO cve_product VALUES('CVE-2026-0101','openssl','openssl')")
        cycles, cpes = endoflife.parse(FEED)
        con.executemany("INSERT INTO eol_cycle VALUES(?,?,?,?)", cycles)
        con.executemany("INSERT INTO eol_cpe VALUES(?,?,?)", cpes)
        con.commit()

    def row(self):
        return dict(self.con.execute("SELECT status, how, detail FROM match WHERE cve_id='CVE-2026-0101'").fetchone())

    def test_announced_then_released(self):
        match.run(self.con, self.cfg)
        r = self.row()
        self.assertEqual(r["detail"], "version inside an affected range; fixed in 3.5.10" + NOTE)
        self.assertEqual(match.fix_state(r["status"], r["how"], r["detail"]), "none")
        self.assertEqual([m["fix"] for m in query.matches(self.con, self.cfg, tiers=["act", "watch", "info"])],
                         ["none"])
        # 3.5.10 comes out: fix available, and that's the "a fix is out now" event
        self.con.execute("UPDATE eol_cycle SET latest='3.5.10' WHERE product='openssl' AND cycle='3.5'")
        match.run(self.con, self.cfg)
        r = self.row()
        self.assertEqual(r["detail"], "version inside an affected range; fixed in 3.5.10")
        self.assertEqual(match.fix_state(r["status"], r["how"], r["detail"]), "available")
        self.assertEqual([k for (k,) in self.con.execute("SELECT kind FROM event")], ["fix"])

    def test_no_release_data_changes_nothing(self):
        self.con.execute("DELETE FROM eol_cpe")
        match.run(self.con, self.cfg)
        self.assertEqual(self.row()["detail"], "version inside an affected range; fixed in 3.5.10")

    def test_vendor_paths(self):
        items = [{"id": "o", "aliases": ["openssl:openssl"]}, {"id": "b", "aliases": ["freebsd:freebsd"]}]
        lines = match._release_lines(self.con)
        rows = {
            # VuXML: the port revision is FreeBSD's, the release is OpenSSL's
            ("CVE-1", "o"): ("affected", "vuxml", "FreeBSD VuXML (openssl35): fixed in 3.5.10_1, installed 3.5.9"),
            ("CVE-2", "o"): ("affected", "vuxml", "FreeBSD VuXML (openssl35): fixed in 3.5.9_1, installed 3.5.9"),
            ("CVE-3", "o"): ("affected", "nvd", "NVD: version inside an affected range; fixed in 3.5.10"),
            ("CVE-4", "o"): ("not_affected", "product", "fixed in 3.5.10"),
            ("CVE-5", "o"): ("affected", "osv", "OSV x GHSA-1: fixed in 3.5.10, installed 3.5.9; update available: 3.6.0"),
            # FreeBSD lists 15.1, not its patch levels: it can't rule on 15.1_7
            ("CVE-6", "b"): ("affected", "vuxml", "FreeBSD VuXML (base system): fixed in 15.1_7, installed 15.1_6"),
        }
        before = dict(rows)
        match._apply_unreleased(items, rows, lines)
        self.assertEqual(rows[("CVE-1", "o")][2],
                         "FreeBSD VuXML (openssl35): fixed in 3.5.10_1" + NOTE + ", installed 3.5.9")
        self.assertEqual(match.fix_state(*rows[("CVE-1", "o")]), "none")
        self.assertEqual(rows[("CVE-3", "o")][2], "NVD: version inside an affected range; fixed in 3.5.10" + NOTE)
        for k in ("CVE-2", "CVE-4", "CVE-5"):
            self.assertEqual(rows[(k, "o")], before[(k, "o")])
        self.assertEqual(rows[("CVE-6", "b")], before[("CVE-6", "b")])


if __name__ == "__main__":
    unittest.main()
