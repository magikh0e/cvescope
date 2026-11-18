import json
import unittest

from cvescope import db, match
from cvescope.sources import freebsd
from cvescope.versions import pkg_cmp

SAMPLE = b"""<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE vuxml PUBLIC "-//vuxml.org//DTD VuXML 1.1//EN" "http://www.vuxml.org/dtd/vuxml-1/vuxml-11.dtd" [
<!ENTITY vuln-2026 SYSTEM "vuln/2026.xml">
]>
<vuxml xmlns="http://www.vuxml.org/apps/vuxml-1">
  <vuln vid="297e3635-e276-11f1-8135-8447094a420f">
    <topic>OpenSSL -- Multiple vulnerabilities</topic>
    <affects>
      <package><name>openssl</name><range><lt>3.5.10,1</lt></range></package>
      <package><name>openssl30</name><range><lt>3.0.24</lt></range></package>
    </affects>
    <references><cvename>CVE-2026-1</cvename><cvename>CVE-2026-2</cvename></references>
  </vuln>
  <vuln vid="eb5c615d-a173-11ef-9a62-002590c1f29c">
    <topic>FreeBSD -- Multiple issues in the bhyve hypervisor</topic>
    <affects>
      <package><name>FreeBSD</name>
        <range><ge>14.1</ge><lt>14.1_6</lt></range>
        <range><ge>15.1</ge><lt>15.1_7</lt></range>
      </package>
    </affects>
    <references><cvename>CVE-2026-3</cvename><freebsdsa>SA-26:17.bhyve</freebsdsa></references>
  </vuln>
  <vuln vid="3f321a5a-b33b-11ec-80c2-1bb2c6a00592">
    <topic>dnsmasq -- heap use-after-free</topic>
    <affects><package><name>dnsmasq</name><range><lt>2.86_4,1</lt></range></package></affects>
    <references><cvename>CVE-2022-4</cvename></references>
  </vuln>
  <vuln vid="00000000-0000-0000-0000-000000000000">
    <topic>no CVE yet</topic>
    <affects><package><name>sudo</name><range><lt>1.9.18</lt></range></package></affects>
    <references><url>https://example.org</url></references>
  </vuln>
</vuxml>
"""


class PkgCmp(unittest.TestCase):
    def test_orderings_from_pkg_itself(self):
        # straight from the comment in libpkg/pkg_version.c
        for chain in (["2.*", "2pl1", "2alpha3", "2.9f7", "3.*"], ["pl11", "alpha3", "0.1beta2", "0.1"],
                      ["10alpha", "10", "10a", "10b"]):
            for a, b in zip(chain, chain[1:]):
                self.assertEqual(pkg_cmp(a, b), -1, (a, b))
                self.assertEqual(pkg_cmp(b, a), 1, (b, a))
        for a, b in (("10", "10.0.0"), ("0.1beta2", "0.1.b2"), ("1.d2", "1.dev2"), ("10..1", "10.1")):
            self.assertEqual(pkg_cmp(a, b), 0, (a, b))

    def test_epoch_version_revision(self):
        self.assertEqual(pkg_cmp("3.5.10,1", "3.5.99"), 1)          # epoch wins
        self.assertEqual(pkg_cmp("1.9.17p2_4", "1.9.17p2"), 1)      # then revision
        self.assertEqual(pkg_cmp("2.93,1", "2.86_4,1"), 1)
        self.assertEqual(pkg_cmp("10.6.p2,1", "10.6.p1,1"), 1)
        self.assertEqual(pkg_cmp("15.1_6", "15.1_7"), -1)


class Parse(unittest.TestCase):
    def test_rows(self):
        rows = freebsd.parse(SAMPLE)
        got = {(r[0], r[1]): r for r in rows}
        self.assertEqual(len(rows), 6)                             # the CVE-less sudo entry is skipped
        self.assertEqual(json.loads(got[("openssl", "CVE-2026-1")][3]), [[["lt", "3.5.10,1"]]])
        self.assertEqual(got[("FreeBSD", "CVE-2026-3")][5], "SA-26:17.bhyve")

    def test_doctype_without_subset_keeps_the_body(self):
        rows = freebsd.parse(b'<!DOCTYPE vuxml SYSTEM "x.dtd">' + SAMPLE.split(b"]>", 1)[1])
        self.assertEqual(len(rows), 6)

    def test_refuses_entities(self):
        bomb = b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa">]><x>&a;</x>'
        bomb2 = b'<!DOCTYPE a [ ]>\n<!DOCTYPE b [<!ENTITY c "c">]><x/>'   # a second one is refused
        with self.assertRaises(ValueError):
            freebsd.parse(bomb2)
        with self.assertRaises(Exception):  # entity declared in the dropped DOCTYPE: undefined, not expanded
            freebsd.parse(bomb)


class Apply(unittest.TestCase):
    def setUp(self):
        self.con = db.connect(":memory:")
        for cid in ("CVE-2026-1", "CVE-2026-2", "CVE-2026-3", "CVE-2022-4", "CVE-2026-9"):
            self.con.execute("INSERT INTO cve(id,state,published) VALUES(?, 'PUBLISHED', '2026-01-01')", (cid,))
        self.con.executemany("INSERT INTO vuxml VALUES(?,?,?,?,?,?)", freebsd.parse(SAMPLE))

    def test_opnsense_openssl35_uses_the_openssl_entry(self):
        it = {"id": "ssl", "version": "3.5.9",
              "extra": {"pkgdb": "freebsd", "package": "openssl35", "package_version": "3.5.9"}}
        rows = {("CVE-2026-9", "ssl"): ("affected", "product", "upstream")}
        match._apply_vuxml(self.con, it, rows)
        self.assertEqual(rows[("CVE-2026-1", "ssl")],
                         ("affected", "vuxml", "FreeBSD VuXML (openssl35): fixed in 3.5.10, installed 3.5.9"))
        self.assertEqual(rows[("CVE-2026-9", "ssl")][2], "upstream")   # VuXML doesn't list it: upstream stands
        # 3.5.11 without an epoch must not read as older than "3.5.10,1"
        it["extra"]["package_version"] = "3.5.11"
        rows = {("CVE-2026-1", "ssl"): ("affected", "product", "upstream")}
        match._apply_vuxml(self.con, it, rows)
        self.assertEqual(rows[("CVE-2026-1", "ssl")][0], "not_affected")
        self.assertNotIn(("CVE-2026-2", "ssl"), rows)                  # old misses aren't added

    def test_port_revision_and_epoch(self):
        it = {"id": "dns", "extra": {"pkgdb": "freebsd", "package": "dnsmasq", "package_version": "2.93,1"}}
        rows = {("CVE-2022-4", "dns"): ("check", "product", "no usable version data")}
        match._apply_vuxml(self.con, it, rows)
        self.assertEqual(rows[("CVE-2022-4", "dns")],
                         ("not_affected", "vuxml", "FreeBSD VuXML (dnsmasq): fixed in 2.86_4,1, installed 2.93,1"))

    def test_base_system_patch_level(self):
        it = {"id": "base", "version": "15.1-RELEASE-p6", "extra": {"freebsd_base": True, "backports": True}}
        rows = {}
        match._apply_vuxml(self.con, it, rows)
        self.assertEqual(rows[("CVE-2026-3", "base")],
                         ("affected", "vuxml", "FreeBSD VuXML (base system) SA-26:17.bhyve: fixed in 15.1_7, installed 15.1_6"))
        it["version"] = "15.1-RELEASE-p7"
        rows = {("CVE-2026-3", "base"): ("check", "product", "x")}
        match._apply_vuxml(self.con, it, rows)
        self.assertEqual(rows[("CVE-2026-3", "base")][0], "not_affected")
        it["version"] = "14.3-STABLE"                                  # not a release: left alone
        rows = {("CVE-2026-3", "base"): ("check", "product", "x")}
        match._apply_vuxml(self.con, it, rows)
        self.assertEqual(rows[("CVE-2026-3", "base")][0], "check")


if __name__ == "__main__":
    unittest.main()
