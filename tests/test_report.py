import copy
import csv
import datetime as dt
import io
import json
import os
import shutil
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from contextlib import redirect_stdout
from http.server import ThreadingHTTPServer

from cvescope import acks, cli, config, db, report, server

HOSTILE = '<script>alert(1)</script> | **bold** =HYPERLINK("http://x")'


def make(tmp):
    cfg = config.Config(config._merge(copy.deepcopy(config.DEFAULTS), {"data_dir": tmp}))
    con = db.connect(cfg.db_path)
    con.execute("INSERT INTO cve(id,state,title,cvss,published) VALUES"
                "('CVE-2024-0001','PUBLISHED',?,9.8,'2024-01-01'),"
                "('CVE-2024-0002','PUBLISHED','second',5.0,'2024-02-01'),"
                "('CVE-2024-0003','PUBLISHED','third',7.0,'2024-03-01')", (HOSTILE,))
    con.execute("INSERT INTO item(id,name,version,collector,aliases,keywords,extra,error) VALUES"
                "('ssh-web1','OpenSSH (web1)','9.6p1','dpkg:web1','[]','[]','{}',NULL),"
                "('nginx-web1','nginx (web1)','1.24.0','dpkg:web1','[]','[]','{}',NULL),"
                "('fw','OPNsense','26.7','opnsense:https://192.168.1.1','[]','[]','{}',NULL),"
                "('plex-ct','debian container (CT 110 plex)',NULL,'proxmox:Proxmox VE (pve)','[]','[]',"
                "'{\"hint\":\"no version visible from Proxmox\"}',NULL)")
    con.execute("INSERT INTO match VALUES('CVE-2024-0001','ssh-web1','affected','product','fixed in 9.8p1','2026-11-01'),"
                "('CVE-2024-0002','nginx-web1','affected','product','x','2026-11-02'),"
                "('CVE-2024-0003','fw','affected','product','y','2026-11-03')")
    con.execute("INSERT INTO signal VALUES('CVE-2024-0001','kev','k','2026-01-01','2026-01-01','{}')")
    con.commit()
    acks.add(con, cfg, "CVE-2024-0002", "nginx-web1", "patched in the window", days=30)
    db.add_event(con, "CVE-2024-0003", "match", {"item": "fw", "status": "affected"})
    con.commit()
    return cfg, con


class Build(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.cfg, self.con = make(self.tmp)

    def tearDown(self):
        self.con.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_data(self):
        d = report.build(self.con, self.cfg, tiers=("act", "watch", "info"))
        self.assertEqual(d["counts"], {"act": 1, "watch": 0, "info": 1, "acked": 1})
        self.assertEqual([f["id"] for f in d["findings"]], ["CVE-2024-0001", "CVE-2024-0003"])
        self.assertEqual(d["findings"][0]["why"], ["exploited in the wild (CISA KEV)"])
        self.assertEqual(d["acknowledged"][0]["ack"]["note"], "patched in the window")
        self.assertEqual([h["host"] for h in d["hosts"]][:1], ["web1"])          # most urgent host first
        self.assertEqual(d["blind_spots"], [{"item": "debian container (CT 110 plex)", "host": "CT 110 plex",
                                             "why": "no version visible from Proxmox"}])
        self.assertTrue(any(c["id"] == "CVE-2024-0003" for c in d["changes"]))

    def test_host_and_tiers(self):
        d = report.build(self.con, self.cfg, tiers=("act", "watch"), host="OPNSENSE")  # any case
        self.assertEqual(d["counts"]["info"], 1)
        self.assertEqual(d["findings"], [])                                       # info isn't listed at this tier
        self.assertEqual([h["host"] for h in d["hosts"]], ["OPNsense"])
        self.assertEqual([c["id"] for c in d["changes"]], ["CVE-2024-0003"])

    def test_escaping(self):
        d = report.build(self.con, self.cfg, tiers=("act", "watch", "info"))
        page = report.render_html(d)
        self.assertNotIn("<script>", page)
        self.assertIn("&lt;script&gt;", page)
        md = report.render_md(d)
        self.assertNotIn("<script>", md)
        self.assertIn("\\| \\*\\*bold\\*\\*", md)                                 # no table break, no markup
        rows = list(csv.reader(io.StringIO(report.render_csv(d))))
        self.assertEqual(rows[0][:4], ["id", "tier", "status", "host"])
        self.assertTrue(rows[1][6].startswith("<script>"))                       # text stays text in CSV ...
        cell = report._cell('=HYPERLINK("http://x")')
        self.assertEqual(cell, '\'=HYPERLINK("http://x")')                      # ... and formulas don't run
        self.assertEqual(json.loads(report.render_json(d))["counts"]["act"], 1)
        self.assertEqual(len(rows), 4)                                           # 2 findings + 1 acknowledged

    def test_cli_out_with_date(self):
        out = os.path.join(self.tmp, "reports", "r-%Y-%m-%d.html")
        with redirect_stdout(io.StringIO()) as printed:
            rc = cli.main(["-c", self._cfg_file(), "report", "--format", "html", "--out", out, "--tier", "info"])
        self.assertEqual(rc, 0)
        path = os.path.join(self.tmp, "reports", dt.datetime.now().strftime("r-%Y-%m-%d.html"))
        self.assertTrue(os.path.exists(path), printed.getvalue())
        self.assertIn("1 act now", printed.getvalue())

    def _cfg_file(self):
        p = os.path.join(self.tmp, "c.toml")
        with open(p, "w", encoding="utf-8") as f:
            f.write(f'data_dir = "{self.tmp.replace(chr(92), "/")}"\n')
        return p


class Http(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.cfg, con = make(self.tmp)
        con.close()
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.make_handler(self.cfg, set()))
        self.host = f"127.0.0.1:{self.httpd.server_port}"
        self.httpd.RequestHandlerClass = server.make_handler(self.cfg, {self.host})
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def get(self, q):
        try:
            with urllib.request.urlopen(f"http://{self.host}/api/report?{q}", timeout=10) as r:
                return r.status, dict(r.headers), r.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers), e.read().decode()

    def test_formats(self):
        code, h, body = self.get("format=html&tier=info")
        self.assertEqual(code, 200)
        self.assertIn("default-src 'none'", h["Content-Security-Policy"])        # no scripts, ever
        self.assertNotIn("script-src", h["Content-Security-Policy"])
        self.assertIn("cvescope report", body)
        code, h, body = self.get("format=csv&host=web1&tier=info")
        self.assertIn("attachment", h["Content-Disposition"])
        self.assertTrue(h["Content-Type"].startswith("text/csv"))
        self.assertEqual(len(body.strip().splitlines()), 3)                       # header + finding + acknowledged
        self.assertEqual(self.get("format=exe")[0], 400)
        self.assertEqual(self.get("format=md&tier=nope")[0], 400)
        self.assertEqual(self.get("format=md&days=abc")[0], 400)


if __name__ == "__main__":
    unittest.main()
