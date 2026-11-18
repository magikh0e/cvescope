"""Findings without a CVE ID: GitHub/OSV advisories and Proxmox PSAs under their own IDs."""
import copy
import json
import shutil
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from unittest import mock

from cvescope import acks, config, db, match, query, server, vulnid
from cvescope.sources import osvpkg, proxmox_psa

GHSA = "GHSA-x5xx-pv5q-6rcx"  # a GitHub advisory with no CVE
OSV = {
    GHSA: {"id": GHSA, "modified": "2026-02-01T00:00:00Z", "published": "2026-01-15T00:00:00Z",
           "aliases": ["PYSEC-2026-77"], "summary": "Prototype pollution in example-lib",
           "details": "example-lib before 2.1.0 lets crafted input change Object.prototype.",
           "database_specific": {"severity": "MODERATE"},
           "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N"}],
           "references": [{"type": "WEB", "url": "https://example.org/fix"}],
           "affected": [{"package": {"ecosystem": "npm", "name": "example-lib"},
                         "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "2.1.0"}]}]}]},
    "MAL-2026-1234": {"id": "MAL-2026-1234", "modified": "2026-03-01T00:00:00Z", "summary": "Malicious code in example-lib",
                      "affected": [{"package": {"ecosystem": "npm", "name": "example-lib"}, "versions": ["2.0.5"]}]},
}


class Ids(unittest.TestCase):
    def test_canon_and_valid(self):
        self.assertEqual(vulnid.canon(" cve-2024-1234 "), "CVE-2024-1234")
        self.assertEqual(vulnid.canon("ghsa-X5XX-PV5Q-6RCX"), GHSA)
        self.assertEqual(vulnid.canon("psa-2026-00094"), "PSA-2026-00094")
        for good in ("CVE-2024-1234", GHSA, "PSA-2026-00094", "MAL-2026-1234", "PYSEC-2021-19", "GO-2023-1987",
                     "RUSTSEC-2023-0001"):
            self.assertTrue(vulnid.valid(good), good)
        for bad in ("", "nope", "CVE-24-1", "GHSA-aaaa-bbbb-cccc", "../etc/passwd", "CVE-2024-1234<script>"):
            self.assertFalse(vulnid.valid(bad), bad)
        self.assertEqual(vulnid.pick(["PYSEC-2026-77", GHSA]), GHSA)


class OsvAdvisories(unittest.TestCase):
    def setUp(self):
        self.con = db.connect(":memory:")
        self.con.execute("INSERT INTO item(id,name,version,collector,aliases,keywords,extra) VALUES"
                         "('lib','example-lib (app)','2.0.5','sbom:x','[]','[]',?)",
                         (json.dumps({"osv": {"ecosystem": "npm", "name": "example-lib", "label": "npm advisory"}}),))

    def tearDown(self):
        self.con.close()

    def sync(self):
        post = lambda url, payload, timeout=120, tries=3: {"results": [{"vulns": [  # noqa: E731
            {"id": k, "modified": v["modified"]} for k, v in OSV.items()]}]}
        get = lambda url, etag=None, timeout=120: (json.dumps(OSV[url.rsplit("/", 1)[-1]]).encode(), None)  # noqa: E731
        with mock.patch.object(osvpkg.net, "post_json", post), mock.patch.object(osvpkg.net, "get", get):
            return osvpkg.sync(self.con, None)

    def test_records_and_decisions(self):
        self.sync()
        rec = query.cve_detail(self.con, config.Config(copy.deepcopy(config.DEFAULTS)), GHSA)
        self.assertEqual((rec["assigner"], rec["title"], rec["severity"]), ("GitHub", "Prototype pollution in example-lib", "MEDIUM"))
        self.assertEqual(rec["refs"][0], f"https://github.com/advisories/{GHSA}")
        self.assertEqual(rec["cvss_vector"], "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N")
        self.assertEqual(self.con.execute("SELECT noprod FROM cve WHERE id=?", (GHSA,)).fetchone()[0], 0)  # no keyword pass
        it = {"id": "lib", "version": "2.0.5", "extra": {"osv": {"ecosystem": "npm", "name": "example-lib", "label": "npm advisory"}}}
        rows = {}
        match._apply_osv(self.con, it, rows)
        self.assertEqual(rows[(GHSA, "lib")], ("affected", "osv", f"npm advisory {GHSA}: fixed in 2.1.0, installed 2.0.5"))
        self.assertEqual(rows[("MAL-2026-1234", "lib")][0], "affected")          # a malicious release, listed by version
        self.assertNotIn(("PYSEC-2026-77", "lib"), rows)                          # the PYSEC copy files under the GHSA

    def test_records_survive_a_cve_list_rebaseline(self):
        self.sync()
        self.con.execute("DELETE FROM cve")                                       # what a CVE List rebaseline does
        self.sync()
        self.assertIsNotNone(self.con.execute("SELECT 1 FROM cve WHERE id=?", (GHSA,)).fetchone())


PSA_PAGE = """<article data-content="post-900">
Subject: PSA-2026-00100-1: Missing shell quoting in upload error handling<br>
Advisory date: 2026-11-12<br>Packages: libpve-storage-perl<br>
Details:<br>Missing shell quoting while handling transfer failures could allow an attacker to execute commands as root.<br>
Fixed in:<br>- libpve-storage-perl &gt;= 9.1.15<br>ProxmoxSecurityAdvisory
</article>"""


class PsaAdvisories(unittest.TestCase):
    def setUp(self):
        self.con = db.connect(":memory:")
        proxmox_psa.store(self.con, proxmox_psa.parse_page(PSA_PAGE))
        proxmox_psa.put_records(self.con)

    def tearDown(self):
        self.con.close()

    def test_psa_without_cve(self):
        rec = self.con.execute("SELECT assigner, title, description, refs FROM cve WHERE id='PSA-2026-00100'").fetchone()
        self.assertEqual(rec[0], "Proxmox")
        self.assertIn("Missing shell quoting", rec[1])
        self.assertIn("execute commands as root", rec[2])
        self.assertEqual(json.loads(rec[3]), ["https://forum.proxmox.com/posts/900/"])
        host = {"id": "pve", "extra": {"pve_packages": {"libpve-storage-perl": "9.1.14"}, "pve_major": 9}}
        rows = {}
        match._apply_psa(self.con, host, rows)
        self.assertEqual(rows[("PSA-2026-00100", "pve")][0], "affected")
        host["extra"]["pve_packages"]["libpve-storage-perl"] = "9.1.16"
        rows = {}
        match._apply_psa(self.con, host, rows)
        self.assertEqual(rows[("PSA-2026-00100", "pve")][0], "not_affected")


class Http(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.cfg = config.Config(config._merge(copy.deepcopy(config.DEFAULTS), {"data_dir": self.tmp}))
        con = db.connect(self.cfg.db_path)
        db.put_advisories(con, [{"id": GHSA, "assigner": "GitHub", "title": "Prototype pollution", "refs": []}])
        con.execute("INSERT INTO item(id,name,version,collector,aliases,keywords,extra) VALUES"
                    "('lib','example-lib (app)','2.0.5','sbom:x','[]','[]','{}')")
        con.execute("INSERT INTO match VALUES(?, 'lib', 'affected', 'osv', 'x', '2026-11-17')", (GHSA,))
        con.commit()
        con.close()
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.make_handler(self.cfg, set()))
        self.host = f"127.0.0.1:{self.httpd.server_port}"
        self.httpd.RequestHandlerClass = server.make_handler(self.cfg, {self.host})
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def call(self, path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(f"http://{self.host}{path}", data=data, method="POST" if data else "GET",
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"{}")

    def test_detail_ack_and_search(self):
        self.assertEqual(self.call(f"/api/cve/{GHSA.upper()}")[1]["id"], GHSA)   # any case finds it
        self.assertEqual(self.call("/api/cve/NOT-AN-ID%3Cx%3E")[0], 400)
        code, d = self.call("/api/ack", {"cve": GHSA, "item": "lib", "note": "pinned 2.1.0 next deploy"})
        self.assertEqual((code, d["items"]), (200, ["lib"]))
        con = db.connect(self.cfg.db_path)
        self.assertIn((GHSA, "lib"), acks.load(con))
        self.assertEqual([r["id"] for r in query.search(con, self.cfg, "ghsa-x5xx")], [GHSA])
        con.close()


if __name__ == "__main__":
    unittest.main()
