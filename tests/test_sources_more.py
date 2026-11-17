import json
import os
import tempfile
import unittest

from cvescope import db, match
from cvescope.collectors import containers, software, webscan
from cvescope.collectors.appliances import _guest_os
from cvescope.collectors.generic import dpkg_items
from cvescope.versions import dpkg_cmp


class Tmp(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def tearDown(self):
        for f in os.listdir(self.dir):
            os.remove(os.path.join(self.dir, f))
        os.rmdir(self.dir)

    def write(self, name, text):
        p = os.path.join(self.dir, name)
        with open(p, "w", encoding="utf-8") as f:
            f.write(text)
        return p


class Dpkg(unittest.TestCase):
    def test_order(self):
        for a, b in [("1:9.2p1-2+deb12u2", "1:9.2p1-2+deb12u3"), ("1.0~rc1", "1.0"), ("2.0", "1:1.0"),
                     ("23.01+dfsg-11ubuntu0.1~esm1", "23.01+dfsg-11ubuntu0.1"), ("6.8.0-45.45", "6.8.0-48.48"),
                     ("1.0", "1.0+b1")]:
            self.assertEqual(dpkg_cmp(a, b), -1, (a, b))
            self.assertEqual(dpkg_cmp(b, a), 1, (b, a))
        self.assertEqual(dpkg_cmp("1:9.6p1-3ubuntu13.5", "1:9.6p1-3ubuntu13.5"), 0)

    def test_items_carry_release_and_source(self):
        out = ("ID=ubuntu\nID_LIKE=debian\nVERSION_ID=\"24.04\"\nVERSION_CODENAME=noble\n---\n"
               "openssh-server 1:9.6p1-3ubuntu13.5 openssh\nlibssl3t64 3.0.13-0ubuntu3.4 openssl\n"
               "coreutils 9.4-3ubuntu6 coreutils\n")
        items = {i["name"]: i for i in dpkg_items(out, "web1")}
        self.assertEqual(set(items), {"OpenSSH (web1)", "OpenSSL (web1)"})
        ssh = items["OpenSSH (web1)"]["extra"]
        self.assertEqual((ssh["distro"], ssh["source"], ssh["package_version"]),
                         ("ubuntu:noble", "openssh", "1:9.6p1-3ubuntu13.5"))
        self.assertEqual(len(dpkg_items(out, "web1", "all")), 3)


class Distro(unittest.TestCase):
    def setUp(self):
        self.con = db.connect(":memory:")
        for cid, pub in (("CVE-2024-1", "2024-01-01"), ("CVE-2024-2", "2024-02-01"), ("CVE-2024-3", "2024-03-01"),
                         ("CVE-2024-4", "2024-04-01"), ("CVE-2099-5", "2099-01-01")):
            self.con.execute("INSERT INTO cve(id,state,published) VALUES(?, 'PUBLISHED', ?)", (cid, pub))
        self.con.executemany("INSERT INTO distro_fix VALUES(?,?,?,?,?)", [
            ("ubuntu:noble", "openssh", "CVE-2024-1", "fixed", "1:9.6p1-3ubuntu13.3"),
            ("ubuntu:noble", "openssh", "CVE-2024-2", "fixed", "1:9.6p1-3ubuntu13.9"),
            ("ubuntu:noble", "openssh", "CVE-2024-3", "open", None),
        ])
        self.item = {"id": "ssh", "extra": {"distro": "ubuntu:noble", "source": "openssh",
                                            "package_version": "1:9.6p1-3ubuntu13.5"}}

    def test_tracker_decides(self):
        rows = {("CVE-2024-1", "ssh"): ("check", "product", "x"), ("CVE-2024-4", "ssh"): ("check", "product", "x"),
                ("CVE-2099-5", "ssh"): ("check", "product", "x")}
        match._apply_distro(self.con, self.item, rows)
        self.assertEqual(rows[("CVE-2024-1", "ssh")][0], "not_affected")   # fixed in an older build
        self.assertEqual(rows[("CVE-2024-2", "ssh")][0], "affected")       # fix newer than installed
        self.assertEqual(rows[("CVE-2024-3", "ssh")][0], "affected")       # no fix yet
        self.assertEqual(rows[("CVE-2024-4", "ssh")][0], "not_affected")   # not listed, old
        self.assertEqual(rows[("CVE-2099-5", "ssh")][0], "check")          # not listed, too new to judge

    def test_no_data_no_change(self):
        rows = {("CVE-2024-1", "ssh"): ("check", "product", "x")}
        item = dict(self.item, extra=dict(self.item["extra"], distro="debian:12"))
        match._apply_distro(self.con, item, rows)
        self.assertEqual(rows[("CVE-2024-1", "ssh")][0], "check")


class Guests(unittest.TestCase):
    def test_debian_vm(self):
        out = _guest_os({"id": "debian", "name": "Debian GNU/Linux", "version-id": "13",
                         "pretty-name": "Debian GNU/Linux 13 (trixie)", "kernel-release": "6.12.116+deb13-amd64"}, "VM 100 x")
        self.assertEqual(out[0]["extra"]["distro"], "debian:13")
        k = out[1]
        self.assertEqual((k["version"], k["extra"]["source"], k["extra"]["package_version"]),
                         ("6.12.116", "linux", "6.12.116-1"))

    def test_haos(self):
        out = _guest_os({"id": "haos", "version-id": "18.4", "kernel-release": "6.18.58-haos"}, "VM 103")
        self.assertEqual(out[0]["version"], "18.4")
        self.assertIn("home assistant:home assistant operating system", out[0]["aliases"])


class Docker(unittest.TestCase):
    def test_image_parts(self):
        self.assertEqual(containers.image_parts("lscr.io/linuxserver/sonarr:4.0.9@sha256:abc"),
                         ("linuxserver/sonarr", "4.0.9"))
        self.assertEqual(containers.image_parts("localhost:5000/team/app:1.2"), ("team/app", "1.2"))
        self.assertEqual(containers.image_parts("nginx"), ("nginx", ""))

    def test_docker_lines_and_labels(self):
        out = "\n".join(json.dumps(r) for r in [
            {"Image": "grafana/grafana:10.2.3", "Names": "grafana", "Labels": "", "State": "running"},
            {"Image": "vaultwarden/server:latest", "Names": "vw",
             "Labels": "org.opencontainers.image.version=1.32.0,maintainer=x", "State": "running"},
            {"Image": "lscr.io/linuxserver/radarr:latest", "Names": "radarr",
             "Labels": "build_version=Linuxserver.io version:- 5.14.0.9383-ls245 Build-date:- 2024-11-01", "State": "running"},
            {"Image": "nginx:alpine", "Names": "web", "Labels": "", "State": "running"},
            {"Image": "someone/thing:2.1-alpine", "Names": "thing", "Labels": "", "State": "running"},
        ])
        items = {i["name"]: i for i in containers.items_from(containers.parse_ps(out), "vps")}
        self.assertEqual(items["Grafana (grafana @ vps)"]["version"], "10.2.3")
        self.assertEqual(items["Vaultwarden (vw @ vps)"]["version"], "1.32.0")
        self.assertEqual(items["Radarr (radarr @ vps)"]["version"], "5.14.0.9383")
        self.assertEqual(items["nginx (web @ vps)"]["aliases"], [])   # floating tag: listed, not matched
        self.assertEqual(items["thing (thing @ vps)"]["version"], "2.1")
        self.assertIn("*:thing", items["thing (thing @ vps)"]["aliases"])

    def test_podman_array(self):
        out = json.dumps([{"Image": "docker.io/library/redis:7.0.11", "Names": ["cache"], "Labels": {}, "State": "running"}])
        items = containers.items_from(containers.parse_ps(out), "pod")
        self.assertEqual((items[0]["name"], items[0]["version"]), ("Redis (cache @ pod)", "7.0.11"))


class Software(Tmp):
    def test_powershell_export(self):
        p = self.write("PC1.json", json.dumps({
            "host": "PC1",
            "os": {"name": "Microsoft Windows 11 Pro", "build": "26100", "ubr": "2314", "display_version": "24H2"},
            "programs": [{"DisplayName": "7-Zip 24.08 (x64)", "DisplayVersion": "24.08", "Publisher": "Igor Pavlov"},
                         {"DisplayName": "Google Chrome", "DisplayVersion": "131.0.6778.86"},
                         {"DisplayName": "Some Vendor Helper", "DisplayVersion": "1.0"}]}))
        items = {i["name"]: i for i in software.osquery({"path": p})}
        self.assertEqual(items["7-Zip (PC1)"]["version"], "24.08")
        self.assertEqual(items["Google Chrome (PC1)"]["aliases"], ["google:chrome"])
        win = items["Microsoft Windows 11 Pro (PC1)"]
        self.assertEqual(win["version"], "10.0.26100.2314")
        self.assertIn("microsoft:windows 11 version 24h2", win["aliases"])
        self.assertNotIn("Some Vendor Helper (PC1)", items)
        self.assertIn("Some Vendor Helper (PC1)", {i["name"] for i in software.osquery({"path": p, "programs": "all"})})

    def test_osqueryi_array_with_debs(self):
        rows = [{"name": "Ubuntu", "version": "24.04.1 LTS (Noble Numbat)", "major": "24", "minor": "4",
                 "platform": "ubuntu", "codename": "noble"},
                {"name": "openssh-server", "version": "1:9.6p1-3ubuntu13.5", "source": "openssh", "arch": "amd64"},
                {"name": "coreutils", "version": "9.4-3ubuntu6", "source": "coreutils", "arch": "amd64"}]
        p = self.write("box.json", json.dumps(rows))
        items = software.osquery({"path": p})
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["extra"]["distro"], "ubuntu:noble")
        self.assertEqual(items[0]["name"], "OpenSSH (box)")

    def test_daemon_log_differential(self):
        lines = [{"hostIdentifier": "mac1", "action": "added", "columns": {"name": "Firefox.app", "bundle_short_version": "131.0"}},
                 {"hostIdentifier": "mac1", "action": "added", "columns": {"name": "VLC.app", "bundle_short_version": "3.0.20"}},
                 {"hostIdentifier": "mac1", "action": "removed", "columns": {"name": "VLC.app", "bundle_short_version": "3.0.20"}}]
        p = self.write("osqueryd.results.log", "\n".join(json.dumps(x) for x in lines))
        items = {i["name"] for i in software.osquery({"path": p})}
        self.assertEqual(items, {"Firefox (mac1)"})


class WebScan(Tmp):
    def test_wpscan(self):
        p = self.write("blog.json", json.dumps({
            "target_url": "https://blog.example/", "version": {"number": "6.4.2"},
            "main_theme": {"slug": "twentytwentyfour", "version": {"number": "1.0"}},
            "plugins": {"contact-form-7": {"slug": "contact-form-7", "version": {"number": "5.8.4"}},
                        "akismet": {"slug": "akismet", "version": None}}}))
        items = {i["name"]: i for i in webscan.wpscan({"path": p})}
        self.assertEqual(items["WordPress (blog.example)"]["version"], "6.4.2")
        cf7 = items["WP plugin contact-form-7 (blog.example)"]
        self.assertEqual(cf7["version"], "5.8.4")
        self.assertIn("*:contact form 7", cf7["aliases"])
        self.assertNotIn("WP plugin akismet (blog.example)", items)

    def test_whatweb(self):
        p = self.write("site.json", json.dumps([{"target": "https://shop.example/", "plugins": {
            "Apache": {"version": ["2.4.49"]}, "PHP": {"version": ["7.4.3"]}, "JQuery": {"version": ["1.12.4"]},
            "HTTPServer": {"string": ["Apache/2.4.49 (Unix)"]}, "Country": {"string": ["US"]}}}]))
        items = {i["name"]: i for i in webscan.whatweb({"path": p})}
        self.assertEqual(set(items), {"Apache HTTP Server (shop.example)", "PHP (shop.example)", "jQuery (shop.example)"})
        self.assertEqual(items["PHP (shop.example)"]["version"], "7.4.3")


if __name__ == "__main__":
    unittest.main()
