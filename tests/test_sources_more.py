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

    def test_removed_packages_are_skipped(self):
        out = ("ID=ubuntu\nVERSION_CODENAME=noble\n---\n"
               "rc  libssl3 3.0.2-0ubuntu1.18 openssl\n"
               "ii  libssl3t64 3.0.13-0ubuntu3.16 openssl\n"
               "rc  apache2 2.4.58-1ubuntu8.15 apache2\n"
               "hi  openssh-server 1:9.6p1-3ubuntu13.20 openssh\n")
        items = {i["name"]: i for i in dpkg_items(out, "vps")}
        self.assertEqual(set(items), {"OpenSSL (vps)", "OpenSSH (vps)"})   # apache2 is removed
        self.assertEqual(items["OpenSSL (vps)"]["extra"]["package_version"], "3.0.13-0ubuntu3.16")


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


class NoiseRules(unittest.TestCase):
    def setUp(self):
        self.con = db.connect(":memory:")

    def row(self, published):
        self.con.execute("DELETE FROM cve")
        self.con.execute("INSERT INTO cve(id,state,published,description,affected) VALUES('CVE-1','PUBLISHED',?,"
                         "'A flaw in the browser.', ?)",
                         (published, json.dumps([{"src": "cna", "v": "Google", "p": "Chrome",
                                                  "vs": [{"version": "unspecified", "status": "affected"}]}])))
        return self.con.execute("SELECT id, affected, description, published FROM cve").fetchone()

    def test_auto_updating_app_ignores_old_versionless_cve(self):
        it = {"id": "c", "name": "Google Chrome (pc1)", "version": "157.0.1", "aliases": ["google:chrome"],
              "extra": {"auto_updates": True}}
        self.assertEqual(match.evaluate(it, self.row("2021-03-01T00:00:00Z"))[0], "not_affected")
        recent = __import__("datetime").date.today().isoformat()
        self.assertEqual(match.evaluate(it, self.row(recent + "T00:00:00Z"))[0], "check")
        it["extra"] = {}
        self.assertEqual(match.evaluate(it, self.row("2021-03-01T00:00:00Z"))[0], "check")

    def test_backport_check_only_surfaces_when_exploited(self):
        from cvescope import query
        cfg = {"tiers": {"epss_watch_pct": 0.9}}
        con = self.con
        con.execute("INSERT INTO item(id,name,version,extra) VALUES('k','Linux kernel (h)','7.0.14','{\"backports\": true}')")
        for cid in ("CVE-A", "CVE-B"):
            con.execute("INSERT INTO cve(id,state,published) VALUES(?, 'PUBLISHED', '2024-01-01')", (cid,))
            con.execute("INSERT INTO match VALUES(?, 'k', 'check', 'product', 'x', '2024-01-01')", (cid,))
        con.execute("INSERT INTO signal VALUES('CVE-A','kev','','t','t','{}')")   # exploited
        con.execute("INSERT INTO signal VALUES('CVE-B','poc','r','t','t','{}')")  # only a PoC
        ids = {m["cve_id"] for m in query.matches(con, cfg, tiers=("act", "watch", "info"))}
        self.assertEqual(ids, {"CVE-A"})


class Nvd(unittest.TestCase):
    def row(self, cpes):
        con = db.connect(":memory:")
        con.execute("INSERT INTO cve(id,state,published,description,affected) VALUES('CVE-1','PUBLISHED',"
                    "'2021-07-07','A heap out-of-bounds write affecting Linux since v2.6.19-rc1.',?)",
                    (json.dumps([{"src": "cna", "v": "n/a", "p": "Linux Kernel",
                                  "vs": [{"version": "2.6.19-rc1", "lessThan": "unspecified", "status": "affected"}]}]),))
        con.execute("INSERT INTO nvd_cpe VALUES('CVE-1','t','Analyzed',?)", (json.dumps(cpes),))
        return con.execute("SELECT c.id, c.affected, c.description, c.published, n.cpes AS nvd FROM cve c "
                           "LEFT JOIN nvd_cpe n ON n.cve_id=c.id").fetchone()

    def item(self, version):
        return {"id": "k", "name": "Linux kernel (h)", "version": version, "aliases": ["linux:linux kernel"],
                "extra": {"backports": True}}

    def test_old_kernel_cve_ruled_out(self):
        cpes = [{"v": "linux", "p": "linux_kernel", "ver": "*", "si": "2.6.19", "ee": "4.4.267"},
                {"v": "linux", "p": "linux_kernel", "ver": "*", "si": "5.11", "ee": "5.12"},
                {"v": "netapp", "p": "c400_firmware", "ver": "-"}]
        st, how, why = match.evaluate(self.item("7.0.14"), self.row(cpes))
        self.assertEqual((st, how), ("not_affected", "nvd"))
        self.assertIn("5.12", why)
        self.assertEqual(match.evaluate(self.item("5.11.3"), self.row(cpes))[0], "check")  # in range, backports

    def test_no_matching_product_falls_through(self):
        cpes = [{"v": "netapp", "p": "c400_firmware", "ver": "-"}]
        self.assertEqual(match.evaluate(self.item("7.0.14"), self.row(cpes))[0], "check")


class Health(unittest.TestCase):
    def setUp(self):
        self.con = db.connect(":memory:")
        self.cfg = {"serve": {"stale_after_hours": 12}}
        import datetime
        self.now = datetime.datetime(2026, 11, 17, 12, 0, tzinfo=datetime.timezone.utc)

    def test_never_synced(self):
        from cvescope import query
        h = query.health(self.con, self.cfg, self.now)
        self.assertEqual((h["level"], h["stale"]), ("bad", True))

    def test_fresh_and_stale(self):
        from cvescope import query
        db.meta_set(self.con, "last_sync", {"finished": "2026-11-17T10:00:00Z", "failed_feeds": [],
                                            "failed_collectors": []})
        h = query.health(self.con, self.cfg, self.now)
        self.assertEqual((h["level"], round(h["age_hours"])), ("ok", 2))
        db.meta_set(self.con, "last_sync", {"finished": "2026-11-16T20:00:00Z", "failed_feeds": [],
                                            "failed_collectors": []})
        self.assertEqual(query.health(self.con, self.cfg, self.now)["level"], "bad")

    def test_failures_warn(self):
        from cvescope import query
        db.meta_set(self.con, "last_sync", {"finished": "2026-11-17T11:00:00Z", "failed_feeds": ["epss"],
                                            "failed_collectors": ["pihole:pihole2"]})
        h = query.health(self.con, self.cfg, self.now)
        self.assertEqual(h["level"], "warn")
        self.assertEqual(h["failed_collectors"], ["pihole2"])
        self.assertEqual(len(h["problems"]), 2)


class History(unittest.TestCase):
    def test_summaries_read_as_sentences(self):
        from cvescope import query
        con = db.connect(":memory:")
        con.execute("INSERT INTO item(id, name) VALUES('static:web01-openssh', 'OpenSSH (web01)')")
        names = query.item_names(con)
        ev = lambda kind, detail: {"kind": kind, "detail": json.dumps(detail)}
        self.assertEqual(query.event_summary(ev("match", {"item": "static:web01-openssh", "status": "affected"}), names),
                         "now matches your inventory (OpenSSH (web01), affected)")
        # an item that's gone from the inventory keeps its id
        self.assertEqual(query.event_summary(ev("resolved", {"item": "static:old", "status": "gone"}), names),
                         "no longer affects you (static:old, gone)")
        self.assertEqual(query.event_summary(ev("epss", {"from": 0.12, "to": 0.85})), "EPSS jumped 12% -> 85%")
        self.assertEqual(query.event_summary(ev("kev", {})), "added to CISA KEV")


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


class OsqueryLive(unittest.TestCase):
    """Live mode with a fake osqueryi: one canned answer per query."""

    def fake(self, answers):
        def q(sql):
            for key, rows in answers.items():
                if key in sql:
                    return rows
            return []
        return q

    def test_ubuntu_host(self):
        q = self.fake({
            "os_version": [{"name": "Ubuntu", "major": "24", "minor": "4", "platform": "ubuntu",
                            "platform_like": "debian", "codename": "noble"}],
            "deb_packages": [{"name": "openssh-server", "version": "1:9.6p1-3ubuntu13.5", "source": "openssh", "arch": "amd64"}],
            "kernel_info": [{"version": "6.8.0-45-generic"}],
            "system_info": [{"hostname": "box1"}],
        })
        host, rows = software.live_rows({}, q)
        items = {i["name"]: i for i in software._items_for_host(host, rows, False)}
        self.assertEqual(items["OpenSSH (box1)"]["extra"]["distro"], "ubuntu:noble")
        k = items["Linux kernel (box1)"]
        self.assertEqual((k["version"], k["extra"]["package_version"]), ("6.8.0", "6.8.0-45.45"))

    def test_windows_host(self):
        q = self.fake({
            "os_version": [{"name": "Microsoft Windows 11 Pro", "build": "26100", "major": "10", "platform": "windows",
                            "revision": "2314"}],
            "registry": [{"name": "DisplayVersion", "data": "24H2"}],
            "programs": [{"name": "Google Chrome", "version": "131.0.6778.86", "publisher": "Google LLC"}],
        })
        host, rows = software.live_rows({"name": "pc1"}, q)
        items = {i["name"]: i for i in software._items_for_host(host, rows, False)}
        self.assertEqual(items["Microsoft Windows 11 Pro (pc1)"]["version"], "10.0.26100.2314")
        self.assertIn("microsoft:windows 11 version 24h2", items["Microsoft Windows 11 Pro (pc1)"]["aliases"])
        self.assertIn("Google Chrome (pc1)", items)

    def test_mac_homebrew(self):
        q = self.fake({
            "os_version": [{"name": "macOS", "major": "15", "platform": "darwin"}],
            "FROM apps": [{"name": "Firefox.app", "version": "131.0"}],
            "homebrew_packages": [{"name": "openssl@3", "version": "3.4.0"}, {"name": "curl", "version": "8.11.0"}],
        })
        host, rows = software.live_rows({"name": "mac"}, q)
        items = {i["name"]: i for i in software._items_for_host(host, rows, False)}
        self.assertEqual(items["OpenSSL (mac)"]["version"], "3.4.0")
        self.assertFalse(items["curl (mac)"]["extra"].get("backports"))
        self.assertIn("Firefox (mac)", items)


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
