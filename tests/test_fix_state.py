import copy
import csv
import io
import json
import unittest

from cvescope import config, db, match, query, report
from cvescope.sources import distro

PV = "1.0-1"


class FixState(unittest.TestCase):
    """fix_state reads the reasons the vendor-data steps write; these run the real steps."""

    def distro_rows(self, entries):
        con = db.connect(":memory:")
        con.execute("INSERT INTO item(id,name,version,collector,aliases,keywords,extra) VALUES('p','pkg','1','dpkg:box','[]','[]',?)",
                    (json.dumps({"distro": "debian:13", "source": "pkg", "package_version": PV, "backports": True}),))
        for i, (status, fixed, note) in enumerate(entries):
            cid = f"CVE-2026-{1000 + i}"
            con.execute("INSERT INTO cve(id,state,published) VALUES(?, 'PUBLISHED', '2026-01-01')", (cid,))
            con.execute("INSERT INTO distro_fix(release,package,cve_id,status,fixed,note) VALUES('debian:13','pkg',?,?,?,?)",
                        (cid, status, fixed, note))
        it = {"id": "p", "extra": json.loads(con.execute("SELECT extra FROM item").fetchone()[0])}
        rows = {}
        match._apply_distro(con, it, rows)
        return [rows[(f"CVE-2026-{1000 + i}", "p")] for i in range(len(entries))]

    def test_distro(self):
        got = self.distro_rows([
            ("fixed", "1.0-2", None),
            ("open", None, None),
            ("open", None, "a fix is queued for the next point release"),
            ("open", None, "postponed by Debian: revisit when fixed upstream"),
            ("open", None, "no security update planned: Minor issue"),
            ("open", None, "Debian won't fix it here: Too intrusive to backport"),
            ("open", None, "the package is out of Debian security support"),
            ("maybe", None, None),
        ])
        self.assertEqual([match.fix_state(*r) for r in got],
                         ["available", "none", "none", "none", "wontfix", "wontfix", "wontfix", "none"])
        self.assertEqual(got[0][2], "Debian 13 fix 1.0-2 is newer than 1.0-1")

    def test_other_vendors(self):
        # the exact reasons test_vuxml, test_advisories, test_homeassistant and test_proxmox_psa pin
        cases = [
            ("affected", "vuxml", "FreeBSD VuXML (openssl35): fixed in 3.5.10, installed 3.5.9", "available"),
            ("affected", "vuxml", "FreeBSD VuXML (curl): installed 8.1.0", "none"),
            ("affected", "osv", "npm advisory GHSA-x: fixed in 2.1.0, installed 2.0.5", "available"),
            ("affected", "osv", "Home Assistant advisory GHSA-y: installed 2026.11.2; update available: 2026.11.3", "available"),
            ("affected", "osv", "npm advisory GHSA-z: installed 2.0.5", "none"),
            ("affected", "psa", "Proxmox PSA-2026-00080-1: fixed in proxmox-kernel-7.0 7.0.14-25, running 7.0.14-24; "
                                "7.0.14-29 is already installed: reboot to run it", "available"),
            ("affected", "product", "version inside an affected range", "unknown"),
            ("check", "product", "no usable version data", "unknown"),
            ("keyword", "keyword", "description mentions nginx", "unknown"),
            ("not_affected", "distro", "Debian 13 fixed it in 1.0-1", "unknown"),
        ]
        for status, how, detail, want in cases:
            self.assertEqual(match.fix_state(status, how, detail), want, detail)

    def test_platform_debian_doesnt_build(self):
        st = distro.debian_status({"status": "open", "urgency": "low", "nodsa": "Arm v7-M not a supported architecture",
                                   "nodsa_reason": "ignored"})
        self.assertEqual(st[0], "notaff")
        (row,) = self.distro_rows([st])
        self.assertEqual(row, ("not_affected", "distro", "Debian 13 isn't affected (only affects a platform Debian "
                                                         "doesn't support: Arm v7-M not a supported architecture)"))
        # an ordinary ignored entry still reads as won't fix
        st = distro.debian_status({"status": "open", "urgency": "low", "nodsa": "Minor issue", "nodsa_reason": "ignored"})
        self.assertEqual(st, ("open", None, "Debian won't fix it here: Minor issue"))


class Surfaces(unittest.TestCase):
    def setUp(self):
        self.cfg = config.Config(copy.deepcopy(config.DEFAULTS))
        self.con = db.connect(":memory:")
        self.con.execute("INSERT INTO cve(id,state,title,cvss,published) VALUES"
                         "('CVE-2026-1','PUBLISHED','one',7.5,'2026-11-01'),('CVE-2026-2','PUBLISHED','two',5.0,'2026-11-01')")
        self.con.execute("INSERT INTO item(id,name,version,collector,extra) VALUES('a','OpenSSL (fw)','3.5.9','opnsense:fw','{}')")
        self.con.execute("INSERT INTO match VALUES('CVE-2026-1','a','affected','vuxml',"
                         "'FreeBSD VuXML (openssl35): fixed in 3.5.10, installed 3.5.9','2026-11-02'),"
                         "('CVE-2026-2','a','affected','product','version inside an affected range','2026-11-02')")
        self.con.commit()

    def test_matches_and_reports(self):
        rows = {r["cve_id"]: r["fix"] for r in query.matches(self.con, self.cfg, tiers=["act", "watch", "info"])}
        self.assertEqual(rows, {"CVE-2026-1": "available", "CVE-2026-2": "unknown"})
        d = report.build(self.con, self.cfg, tiers=["act", "watch", "info"])
        self.assertEqual(d["fixes"], {"available": 1, "none": 0, "wontfix": 0, "unknown": 1})
        table = list(csv.reader(io.StringIO(report.render_csv(d))))
        self.assertEqual(table[0][-1], "fix")                     # appended, so older column positions hold
        self.assertEqual({r[0]: r[-1] for r in table[1:]}, {"CVE-2026-1": "fix available", "CVE-2026-2": "not known"})
        md = report.render_md(d)
        self.assertIn("Of these findings: 1 fix available, 1 not known.", md)
        self.assertIn("| Fix |", md)
        html = report.render_html(d)
        self.assertIn('<td class="fix available">fix available</td>', html)


if __name__ == "__main__":
    unittest.main()
