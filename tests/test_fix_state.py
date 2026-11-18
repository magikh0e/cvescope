import copy
import csv
import io
import json
import unittest

from cvescope import config, db, match, notify, query, report, versions
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


class UpstreamFix(unittest.TestCase):
    """Apps nobody backports to: the CVE record's own range names the release that fixed it."""

    def test_less_than_is_the_fix(self):
        e = {"vs": [{"version": "2.0", "lessThan": "2.47.3", "status": "affected", "versionType": "semver"},
                    {"version": "2.48.0", "lessThan": "2.48.2", "status": "affected", "versionType": "semver"}]}
        self.assertEqual(versions.eval_entry(e, "2.47.1"), ("affected", "version inside an affected range; fixed in 2.47.3"))
        self.assertEqual(versions.eval_entry(e, "2.48.1")[1], "version inside an affected range; fixed in 2.48.2")
        # "<= 2.47.2" says where it stops, not what fixed it
        e = {"vs": [{"version": "0", "lessThanOrEqual": "2.47.2", "status": "affected", "versionType": "semver"}]}
        self.assertEqual(versions.eval_entry(e, "2.47.1")[1], "version inside an affected range")

    def test_listed_fixes_prefer_your_line(self):
        # kernel.org style: fixed per stable line, the rest affected
        e = {"ds": "affected", "vs": [
            {"version": "6.12", "status": "affected"},
            {"version": "0", "lessThan": "6.12", "status": "unaffected", "versionType": "semver"},
            {"version": "6.12.117", "lessThanOrEqual": "6.12.*", "status": "unaffected", "versionType": "semver"},
            {"version": "6.18.61", "lessThanOrEqual": "6.18.*", "status": "unaffected", "versionType": "semver"},
            {"version": "7.3.2", "lessThanOrEqual": "7.3.*", "status": "unaffected", "versionType": "semver"}]}
        self.assertTrue(versions.eval_entry(e, "6.18.40")[1].endswith("; fixed in 6.18.61"))
        self.assertTrue(versions.eval_entry(e, "7.0.14")[1].endswith("; fixed in 7.3.2"))  # no fix on 7.0: next line

    def test_fix_state_and_backports(self):
        self.assertEqual(match.fix_state("affected", "product", "version inside an affected range; fixed in 2.47.3"),
                         "available")
        self.assertEqual(match.fix_state("affected", "nvd", "NVD: version inside an affected range; fixed in 1.2"),
                         "available")
        # a distro build may have the fix backported under an older number: upstream's says nothing
        self.assertEqual(match.fix_state("check", "product", "version inside an affected range; fixed in 2.47.3; "
                                                             "distro package, fixes may be backported"), "unknown")

    def test_nvd_end_excluding(self):
        row = {"nvd": json.dumps([{"v": "videolan", "p": "vlc", "ver": "*", "si": "3.0.0", "ee": "3.0.21"}])}
        it = {"aliases": ["videolan:vlc"], "version": "3.0.20", "extra": {}}
        self.assertEqual(match._from_nvd(it, row), ("affected", "nvd", "NVD: version inside an affected range; fixed in 3.0.21"))


class WindowsRecords(unittest.TestCase):
    """Two record shapes that put a current Windows 11 inside a range it isn't in."""

    WIN = {"name": "Microsoft Windows 11 Home (pc)", "version": "10.0.26200.7462",
           "aliases": ["microsoft:windows 11 version 25h2", "microsoft:windows 11*"],
           "extra": {"display_version": "25H2"}}

    def evaluate(self, entries, item=None):
        it = copy.deepcopy(item or self.WIN)
        return match.evaluate(it, {"affected": json.dumps(entries), "description": "", "published": "2025-03-11",
                                   "nvd": None})

    def test_lab_kit_isnt_the_os(self):
        hlk = [{"src": "cna", "v": "Microsoft", "p": "Windows 11 HLK 22H2",
                "vs": [{"version": "1.0.0", "lessThan": "10.1.22621.5040", "status": "affected", "versionType": "custom"}]}]
        self.assertEqual(match._entry_matches(hlk[0], [match._alias(a) for a in self.WIN["aliases"]]), False)
        os_entry = [{"src": "cna", "v": "Microsoft", "p": "Windows 11 Version 24H2",
                     "vs": [{"version": "10.0.26100.0", "lessThan": "10.0.26100.4061", "status": "affected"}]}]
        self.assertTrue(match._entry_matches(os_entry[0], [match._alias(a) for a in self.WIN["aliases"]]))

    def test_release_names_compare_as_releases(self):
        before_24h2 = [{"src": "cna", "v": "Microsoft, Inc", "p": "Windows 11", "ds": "unaffected",
                        "vs": [{"version": "0", "lessThan": "24H2", "status": "affected", "versionType": "custom"}]}]
        self.assertEqual(self.evaluate(before_24h2)[0], "not_affected")          # 25H2 is past 24H2
        older = dict(self.WIN, extra={"display_version": "23H2"})
        self.assertEqual(self.evaluate(before_24h2, older),
                         ("affected", "product", "version inside an affected range; fixed in 24H2"))
        unknown = dict(self.WIN, extra={})
        self.assertEqual(self.evaluate(before_24h2, unknown)[0], "check")         # no release name: can't tell

    def test_collector_keeps_the_release_name(self):
        from cvescope.collectors import software
        it = software.windows_os({"name": "Microsoft Windows 11 Pro", "build": "26100", "ubr": "2314",
                                  "display_version": "24h2"}, "pc")
        self.assertEqual(it["extra"]["display_version"], "24H2")


class FixLanded(unittest.TestCase):
    """When the vendor ships a fix for something you run, that's an event (and an alert)."""

    def setUp(self):
        self.cfg = config.Config(copy.deepcopy(config.DEFAULTS))
        self.con = db.connect(":memory:")
        self.con.execute("INSERT INTO item(id,name,version,collector,aliases,keywords,extra) VALUES"
                         "('g','glibc (web1)','2.41','dpkg:web1','[]','[]',?)",
                         (json.dumps({"distro": "debian:13", "source": "glibc", "package_version": "2.41-12",
                                      "backports": True}),))
        for cid in ("CVE-2026-0001", "CVE-2026-0002"):
            self.con.execute("INSERT INTO cve(id,state,title,published) VALUES(?, 'PUBLISHED', 't', '2026-01-01')", (cid,))
            self.con.execute("INSERT INTO distro_fix(release,package,cve_id,status) VALUES('debian:13','glibc',?,'open')",
                             (cid,))
        self.con.commit()
        match.run(self.con, self.cfg)   # first run: the baseline, no events

    def events(self):
        return [(r[0], r[1]) for r in self.con.execute("SELECT cve_id, kind FROM event ORDER BY id")]

    def test_open_then_fixed(self):
        self.con.execute("UPDATE distro_fix SET status='fixed', fixed='2.41-12+deb13u1' WHERE cve_id='CVE-2026-0001'")
        match.run(self.con, self.cfg)
        self.assertEqual(self.events(), [("CVE-2026-0001", "fix")])
        e = dict(self.con.execute("SELECT kind, detail FROM event").fetchone())
        self.assertEqual(query.event_summary(e, query.item_names(self.con)),
                         "fix available (glibc (web1)): Debian 13 fix 2.41-12+deb13u1 is newer than 2.41-12")
        match.run(self.con, self.cfg)   # nothing new the second time
        self.assertEqual(len(self.events()), 1)

    def test_alert_threshold(self):
        self.con.execute("UPDATE distro_fix SET status='fixed', fixed='2.41-12+deb13u1' WHERE cve_id='CVE-2026-0001'")
        match.run(self.con, self.cfg)
        alerts, ids = notify._pending(self.con, self.cfg)   # min_tier act: an info-tier fix stays quiet
        self.assertEqual((alerts, len(ids)), ([], 1))
        self.cfg["notify"]["fixes_min_tier"] = "info"
        alerts, _ = notify._pending(self.con, self.cfg)
        self.assertEqual([(a["cve"], a["tier"]) for a in alerts], [("CVE-2026-0001", "info")])
        title, msg = notify.format_message(alerts)
        self.assertEqual(title, "cvescope: 1 info (fix available now)")
        self.assertIn("fix available (glibc (web1)): Debian 13 fix 2.41-12+deb13u1 is newer than 2.41-12", msg)


if __name__ == "__main__":
    unittest.main()
