import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

from cvescope import db, match
from cvescope.collectors import sbom
from cvescope.sources import osvpkg

CDX = {
    "bomFormat": "CycloneDX", "specVersion": "1.5",
    "metadata": {"component": {"type": "container", "name": "shop-api"}},
    "components": [
        {"type": "operating-system", "name": "debian", "version": "12.4"},
        {"type": "library", "name": "openssl", "version": "3.0.11-1~deb12u2",
         "purl": "pkg:deb/debian/openssl@3.0.11-1~deb12u2?arch=amd64&upstream=openssl"},
        {"type": "library", "name": "libssl3", "version": "3.0.11-1~deb12u2",
         "purl": "pkg:deb/debian/libssl3@3.0.11-1~deb12u2?arch=amd64&distro=debian-12&upstream=openssl"},
        {"type": "library", "name": "lodash", "version": "4.17.15", "purl": "pkg:npm/lodash@4.17.15",
         "components": [{"type": "library", "name": "core", "group": "@babel", "version": "7.0.0",
                         "purl": "pkg:npm/%40babel/core@7.0.0"}]},
        {"type": "library", "group": "org.apache.logging.log4j", "name": "log4j-core", "version": "2.14.1",
         "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
         "cpe": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"},
        {"type": "library", "name": "lodash", "version": "4.17.15", "purl": "pkg:npm/lodash@4.17.15"},  # duplicate
        {"type": "library", "name": "no-version"},
        {"type": "file", "name": "/etc/passwd", "version": "1"},
        {"type": "container", "name": "shop-api", "version": "sha256:abc", "purl": "pkg:oci/shop-api@sha256%3Aabc"},
        {"type": "application", "name": "zlibrary-tool", "version": "1.2"},
    ],
}

SPDX = {
    "spdxVersion": "SPDX-2.3", "name": "web1",
    "packages": [
        {"name": "Django", "versionInfo": "4.2.1",
         "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                           "referenceLocator": "pkg:pypi/Django@4.2.1"}]},
        {"name": "nginx", "versionInfo": "1.24.0",
         "externalRefs": [{"referenceCategory": "SECURITY", "referenceType": "cpe23Type",
                           "referenceLocator": "cpe:2.3:a:f5:nginx:1.24.0:*:*:*:*:*:*:*"},
                          {"referenceCategory": "SECURITY", "referenceType": "cpe23Type",
                           "referenceLocator": "cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*"}]},
    ],
}

SPDX_TV = """SPDXVersion: SPDX-2.3
DocumentName: build-box
PackageName: gin
PackageVersion: v1.9.0
ExternalRef: PACKAGE-MANAGER purl pkg:golang/github.com/gin-gonic/gin@v1.9.0
PackageName: unversioned
"""

CDX_XML = """<?xml version="1.0" encoding="UTF-8"?>
<bom xmlns="http://cyclonedx.org/schema/bom/1.5" version="1">
  <metadata><component type="application"><name>billing</name></component></metadata>
  <components>
    <component type="library"><name>rails</name><version>7.0.4</version><purl>pkg:gem/rails@7.0.4</purl></component>
    <component type="library"><name>serde</name><version>1.0.150</version><purl>pkg:cargo/serde@1.0.150</purl></component>
  </components>
</bom>"""


class Ids(unittest.TestCase):
    def test_purl(self):
        p = sbom.parse_purl("pkg:npm/%40babel/core@7.0.0")
        self.assertEqual((p["type"], p["namespace"], p["name"], p["version"]), ("npm", "@babel", "core", "7.0.0"))
        self.assertEqual(sbom.osv_name(p), ("npm", "@babel/core"))
        self.assertEqual(sbom.osv_name(sbom.parse_purl("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1")),
                         ("Maven", "org.apache.logging.log4j:log4j-core"))
        self.assertEqual(sbom.osv_name(sbom.parse_purl("pkg:golang/github.com/gin-gonic/gin@v1.9.0")),
                         ("Go", "github.com/gin-gonic/gin"))
        self.assertEqual(sbom.osv_name(sbom.parse_purl("pkg:pypi/Django_REST.framework@3.14.0")),
                         ("PyPI", "django-rest-framework"))
        deb = sbom.parse_purl("pkg:deb/debian/libssl3@3.0.11-1~deb12u2?arch=amd64&distro=debian-12&upstream=openssl")
        self.assertEqual((deb["qualifiers"]["distro"], deb["qualifiers"]["upstream"]), ("debian-12", "openssl"))
        self.assertIsNone(sbom.osv_name(deb))
        self.assertIsNone(sbom.parse_purl("not a purl"))

    def test_cpe(self):
        self.assertEqual(sbom.parse_cpe("cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"), ("apache", "log4j"))
        self.assertEqual(sbom.parse_cpe(r"cpe:2.3:a:node\.js:node\.js:18:*:*:*:*:*:*:*"), ("node js", "node js"))
        self.assertEqual(sbom.parse_cpe("cpe:/a:openbsd:openssh:9.6"), ("openbsd", "openssh"))
        self.assertIsNone(sbom.parse_cpe("cpe:2.3:a:*:thing:1:*:*:*:*:*:*:*"))

    def test_release(self):
        self.assertEqual(sbom._release(None, None, "debian-12.4"), "debian:12")
        self.assertEqual(sbom._release(None, None, "ubuntu-22.04"), "ubuntu:jammy")
        self.assertEqual(sbom._release("debian", "12.4", None), "debian:12")
        self.assertIsNone(sbom._release("alpine", "3.19", None))


class Read(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def write(self, name, content):
        p = os.path.join(self.dir, name)
        with open(p, "w", encoding="utf-8") as f:
            f.write(content if isinstance(content, str) else json.dumps(content))
        return p

    def test_cyclonedx_json(self):
        items = {i["name"]: i for i in sbom.sbom({"path": self.write("a.cdx.json", CDX)})}
        got = sbom.sbom({"path": self.write("b.cdx.json", CDX)})
        self.assertEqual(len(got), len(items))                               # openssl + libssl3: one OpenSSL
        self.assertEqual(sorted(items), ["@babel/core (shop-api)", "Debian 12.4 (shop-api)", "OpenSSL (shop-api)",
                                         "lodash (shop-api)", "org.apache.logging.log4j:log4j-core (shop-api)",
                                         "zlibrary-tool (shop-api)"])
        ssl = items["OpenSSL (shop-api)"]["extra"]   # deb: the distro's tracker decides; release from the OS component
        self.assertEqual((ssl["distro"], ssl["source"], ssl["package_version"], ssl["backports"]),
                         ("debian:12", "openssl", "3.0.11-1~deb12u2", True))
        self.assertEqual(items["OpenSSL (shop-api)"]["version"], "3.0.11")
        self.assertEqual(items["lodash (shop-api)"]["extra"]["osv"],
                         {"ecosystem": "npm", "name": "lodash", "label": "npm advisory"})
        self.assertNotIn("*:lodash", items["lodash (shop-api)"]["aliases"])   # OSV is precise; no wildcard guess
        log4j = items["org.apache.logging.log4j:log4j-core (shop-api)"]
        self.assertIn("apache:log4j", log4j["aliases"])
        self.assertEqual(log4j["extra"]["osv"]["name"], "org.apache.logging.log4j:log4j-core")
        self.assertEqual(items["zlibrary-tool (shop-api)"]["aliases"], ["*:zlibrary tool"])
        self.assertEqual(items["Debian 12.4 (shop-api)"]["extra"]["distro"], "debian:12")

    def test_spdx_json_and_tag_value_and_xml(self):
        self.write("web1.spdx.json", SPDX)
        self.write("build.spdx", SPDX_TV)
        self.write("billing.cdx.xml", CDX_XML)
        items = {i["name"]: i for i in sbom.sbom({"path": self.dir})}   # a folder: every SBOM in it
        self.assertEqual(sorted(items), ["Django (web1)", "github.com/gin-gonic/gin (build-box)", "nginx (web1)",
                                         "rails (billing)", "serde (billing)"])
        self.assertEqual(items["Django (web1)"]["extra"]["osv"]["name"], "django")
        self.assertIn("f5:nginx", items["nginx (web1)"]["aliases"])          # first CPE only, plus the known map
        self.assertEqual(items["serde (billing)"]["extra"]["osv"]["ecosystem"], "crates.io")
        # an explicit name files everything under one host
        named = sbom.sbom({"path": os.path.join(self.dir, "*.spdx*"), "name": "ci"})
        self.assertTrue(all(i["name"].endswith("(ci)") for i in named))

    def test_refusals(self):
        bad = self.write("x.xml", '<?xml version="1.0"?><!DOCTYPE bom [<!ENTITY a "aaaa">]><bom>&a;</bom>')
        with self.assertRaises(ValueError):
            sbom.sbom({"path": bad})
        with self.assertRaises(ValueError):
            sbom.sbom({"path": self.write("y.json", {"hello": "world"})})
        with self.assertRaises(FileNotFoundError):
            sbom.sbom({"path": os.path.join(self.dir, "missing-*.json")})


VULNS = {
    "GHSA-p6mc-m468-83gw": {"id": "GHSA-p6mc-m468-83gw", "modified": "2026-01-01T00:00:00Z", "aliases": ["CVE-2020-8203"],
                            "details": "long prose " * 50,
                            "affected": [{"package": {"ecosystem": "npm", "name": "lodash"},
                                          "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.19"}]}]}]},
    "GHSA-old0-0000-0000": {"id": "GHSA-old0-0000-0000", "modified": "2026-01-01T00:00:00Z", "aliases": ["CVE-2019-10744"],
                            "affected": [{"package": {"ecosystem": "npm", "name": "lodash"},
                                          "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.12"}]}]}]},
}


class OsvBatch(unittest.TestCase):
    def setUp(self):
        self.con = db.connect(":memory:")
        for cid in ("CVE-2020-8203", "CVE-2019-10744"):
            self.con.execute("INSERT INTO cve(id,state,published) VALUES(?, 'PUBLISHED', '2020-01-01')", (cid,))
        self.con.execute("INSERT INTO item(id,name,version,collector,aliases,keywords,extra) VALUES"
                         "('lodash-app','lodash (app)','4.17.15','sbom:x','[]','[]',?)",
                         (json.dumps({"osv": {"ecosystem": "npm", "name": "lodash", "label": "npm advisory"}}),))
        self.gets = []

    def fake_post(self, url, payload, timeout=120, tries=3):
        self.assertEqual(url, osvpkg.BATCH_URL)
        self.assertEqual(payload["queries"], [{"package": {"ecosystem": "npm", "name": "lodash"}}])
        # the batch spells "modified" with nanoseconds; the full advisory doesn't
        return {"results": [{"vulns": [{"id": k, "modified": v["modified"].replace("Z", ".123456789Z")}
                                       for k, v in VULNS.items()]}]}

    def fake_get(self, url, etag=None, timeout=120):
        vid = url.rsplit("/", 1)[-1]
        self.gets.append(vid)
        return json.dumps(VULNS[vid]).encode(), None

    def test_batch_cache_and_decision(self):
        with mock.patch.object(osvpkg.net, "post_json", self.fake_post), mock.patch.object(osvpkg.net, "get", self.fake_get):
            self.assertIn("2 advisories (2 downloaded)", osvpkg.sync(self.con, None))
            self.assertIn("(0 downloaded)", osvpkg.sync(self.con, None))      # unchanged: nothing refetched
        self.assertEqual(len(self.gets), 2)
        stored = json.loads(self.con.execute("SELECT data FROM osv_vuln WHERE id='GHSA-p6mc-m468-83gw'").fetchone()[0])
        self.assertNotIn("details", stored)                                    # prose isn't kept
        item = {"id": "lodash-app", "version": "4.17.15",
                "extra": {"osv": {"ecosystem": "npm", "name": "lodash", "label": "npm advisory"}}}
        rows = {}
        match._apply_osv(self.con, item, rows)
        self.assertEqual(rows[("CVE-2020-8203", "lodash-app")],
                         ("affected", "osv", "npm advisory GHSA-p6mc-m468-83gw: fixed in 4.17.19, installed 4.17.15"))
        self.assertEqual(rows[("CVE-2019-10744", "lodash-app")][0], "not_affected")


class MultiLine(unittest.TestCase):
    """An advisory with one affected block per release line (Log4Shell's GHSA has three)."""
    LOG4SHELL = {"id": "GHSA-jfh8-c2jp-5v3q", "modified": "2026-01-01T00:00:00Z", "aliases": ["CVE-2021-44228"],
                 "affected": [{"package": {"ecosystem": "Maven", "name": "org.apache.logging.log4j:log4j-core"},
                               "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": a}, {"fixed": f}]}],
                               "versions": vs}
                              for a, f, vs in (("2.0-beta9", "2.3.1", ["2.0", "2.3"]), ("2.4", "2.12.2", ["2.12.1"]),
                                               ("2.13.0", "2.15.0", []))]}

    def setUp(self):
        self.con = db.connect(":memory:")
        self.con.execute("INSERT INTO cve(id,state,published) VALUES('CVE-2021-44228','PUBLISHED','2021-12-10')")
        rows = osvpkg.rows_for([self.LOG4SHELL], "Maven", "org.apache.logging.log4j:log4j-core")
        self.assertEqual(len(rows), 1)                                        # one row, every line inside
        self.con.executemany("INSERT INTO osv_pkg VALUES(?,?,?,?,?,?,?)", rows)

    def decide(self, ver):
        it = {"id": "l", "version": ver, "extra": {"osv": {"ecosystem": "Maven", "name": "org.apache.logging.log4j:log4j-core",
                                                           "label": "Maven advisory"}}}
        rows = {}
        match._apply_osv(self.con, it, rows)
        return rows[("CVE-2021-44228", "l")]

    def test_each_line(self):
        self.assertEqual(self.decide("2.14.1"),
                         ("affected", "osv", "Maven advisory GHSA-jfh8-c2jp-5v3q: fixed in 2.15.0, installed 2.14.1"))
        self.assertEqual(self.decide("2.12.1")[0], "affected")                 # listed version on the middle line
        self.assertEqual(self.decide("2.12.3")[2],
                         "Maven advisory GHSA-jfh8-c2jp-5v3q: fixed in 2.12.2, installed 2.12.3")
        self.assertEqual(self.decide("2.17.1")[0], "not_affected")
        self.assertIn("outside the affected releases", self.decide("1.2.17")[2])


if __name__ == "__main__":
    unittest.main()
