import copy
import datetime as dt
import json
import shutil
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

from cvescope import acks, config, db, query, server

TODAY = dt.date(2026, 11, 17)


def ack(tier="act", status="check", keys=("kev",), until=None):
    return {"until": until, "evidence": json.dumps({"tier": tier, "status": status, "keys": list(keys)})}


class State(unittest.TestCase):
    def test_holds_while_nothing_gets_worse(self):
        self.assertEqual(acks.state(ack(), "act", "check", ["kev"], TODAY), ("active", ""))
        # more of the same kind of evidence, or a lower tier, doesn't bring it back
        self.assertEqual(acks.state(ack(tier="watch", keys=["poc"]), "info", "check", ["poc"], TODAY)[0], "active")

    def test_end_date(self):
        self.assertEqual(acks.state(ack(until="2026-11-17"), "act", "check", ["kev"], TODAY)[0], "active")
        self.assertEqual(acks.state(ack(until="2026-11-16"), "act", "check", ["kev"], TODAY),
                         ("expired", "ended 2026-11-16"))

    def test_worse_evidence_lapses(self):
        st, why = acks.state(ack(tier="watch", keys=["poc"]), "act", "check", ["kev", "poc"], TODAY)
        self.assertEqual(st, "lapsed")
        self.assertIn("moved up to act now", why)
        self.assertIn("added to CISA KEV", why)
        self.assertEqual(acks.state(ack(), "act", "affected", ["kev"], TODAY),
                         ("lapsed", "now confirmed affected"))

    def test_first_metasploit_exploit_reads_once(self):
        st, why = acks.state(ack(keys=["kev"]), "act", "check", ["kev", "msf", "msf:exploit"], TODAY)
        self.assertEqual((st, why), ("lapsed", "Metasploit exploit module"))

    def test_evidence_keys(self):
        sig = {"msf": [{"type": "exploit"}], "poc": [{}], "edb": []}
        self.assertEqual(acks.evidence_keys(sig, "active"), ["msf", "msf:exploit", "poc", "ssvc:active"])
        self.assertEqual(acks.evidence_keys({}, "none"), [])


def make_cfg(tmp):
    # deep copy: _merge shares nested tables with DEFAULTS, and these tests flip serve.read_only
    return config.Config(config._merge(copy.deepcopy(config.DEFAULTS), {"data_dir": tmp}))


def seed(con):
    con.execute("INSERT INTO cve(id, state, title, cvss, published, ssvc_exploitation) VALUES"
                "('CVE-2013-3900','PUBLISHED','WinVerifyTrust',5.5,'2013-12-10','active'),"
                "('CVE-2024-0001','PUBLISHED','other',9.8,'2024-01-01',NULL)")
    con.execute("INSERT INTO item(id, name, version, collector, extra) VALUES"
                "('osquery:win-minitop','Windows 11 (minitop)','10.0.26300','osquery:pc','{}'),"
                "('static:web01','Web server (web01)','1.0','static','{}')")
    con.execute("INSERT INTO match VALUES('CVE-2013-3900','osquery:win-minitop','check','product','x','2026-11-17'),"
                "('CVE-2024-0001','static:web01','affected','product','x','2026-11-17'),"
                "('CVE-2024-0001','osquery:win-minitop','not_affected','product','x','2026-11-17')")
    con.execute("INSERT INTO signal VALUES('CVE-2013-3900','kev','k','2026-01-01','2026-01-01','{}')")
    con.commit()


class Flow(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.cfg = make_cfg(self.tmp)
        self.con = db.connect(self.cfg.db_path)
        seed(self.con)

    def tearDown(self):
        self.con.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def ids(self, **kw):
        return {(m["cve_id"], m["item_id"]) for m in query.matches(self.con, self.cfg, **kw)}

    def test_ack_hides_until_new_evidence(self):
        rows = acks.add(self.con, self.cfg, "CVE-2013-3900", "minitop", "applied the opt-in fix")
        self.assertEqual([r["item_id"] for r in rows], ["osquery:win-minitop"])
        self.assertNotIn(("CVE-2013-3900", "osquery:win-minitop"), self.ids())
        self.assertIn(("CVE-2013-3900", "osquery:win-minitop"), self.ids(acked="only"))
        s = query.summary(self.con, self.cfg)
        self.assertEqual((s["totals"]["act"], s["totals"]["info"], s["totals"]["acked"]), (0, 1, 1))
        win = next(i for i in s["items"] if i["id"] == "osquery:win-minitop")
        self.assertEqual(win["counts"]["act"], 0)
        hist = query.cve_detail(self.con, self.cfg, "CVE-2013-3900")
        self.assertEqual(hist["events"][0]["summary"],
                         "acknowledged (Windows 11 (minitop)): applied the opt-in fix")
        self.assertEqual(hist["matches"][0]["ack"]["state"], "active")
        # a Metasploit exploit module shows up: it's back, and says why
        self.con.execute("""INSERT INTO signal VALUES('CVE-2013-3900','msf','m','x','x','{"type":"exploit"}')""")
        m = next(m for m in query.matches(self.con, self.cfg) if m["cve_id"] == "CVE-2013-3900")
        self.assertEqual((m["ack"]["state"], m["ack"]["reason"]), ("lapsed", "Metasploit exploit module"))

    def test_unack_and_listing(self):
        acks.add(self.con, self.cfg, "CVE-2024-0001", days=30)
        self.assertEqual(acks.list_all(self.con, self.cfg)[0]["until"],
                         (dt.datetime.now(dt.timezone.utc).date() + dt.timedelta(days=30)).isoformat())
        self.assertEqual(acks.remove(self.con, "CVE-2024-0001"), ["static:web01"])
        self.assertIn(("CVE-2024-0001", "static:web01"), self.ids())
        self.assertEqual(acks.list_all(self.con, self.cfg), [])

    def test_refusals(self):
        with self.assertRaises(ValueError):  # matches nothing
            acks.add(self.con, self.cfg, "CVE-1999-0001")
        with self.assertRaises(ValueError):  # not_affected on that item
            acks.add(self.con, self.cfg, "CVE-2024-0001", "minitop")
        with self.assertRaises(ValueError):
            acks.add(self.con, self.cfg, "CVE-2024-0001", note="x" * 501)
        with self.assertRaises(ValueError):
            acks.add(self.con, self.cfg, "CVE-2024-0001", until="soon")
        with self.assertRaises(ValueError):
            acks.remove(self.con, "CVE-2024-0001")

    def test_many_at_once(self):
        pairs = [("cve-2013-3900", "osquery:win-minitop"), ("CVE-2024-0001", "static:web01"),
                 ("CVE-2024-0001", "static:web01")]                      # duplicates collapse
        rows = acks.add_many(self.con, self.cfg, pairs, "patch window", days=30)
        self.assertEqual(len(rows), 2)
        self.assertEqual(self.ids(), set())
        self.assertEqual({a["note"] for a in acks.load(self.con).values()}, {"patch window"})
        self.assertEqual(acks.remove_many(self.con, pairs), 2)
        self.assertEqual(len(self.ids()), 2)
        with self.assertRaises(ValueError):                             # nothing left to remove
            acks.remove_many(self.con, pairs)

    def test_many_is_all_or_nothing(self):
        with self.assertRaises(ValueError) as e:                        # not_affected there: refused
            acks.add_many(self.con, self.cfg, [("CVE-2024-0001", "static:web01"),
                                               ("CVE-2024-0001", "osquery:win-minitop")])
        self.assertIn("1 of the 2", str(e.exception))
        self.assertEqual(acks.load(self.con), {})
        with self.assertRaises(ValueError):
            acks.add_many(self.con, self.cfg, [])
        with self.assertRaises(ValueError):
            acks.add_many(self.con, self.cfg, [(f"CVE-2024-{i:04d}", "x") for i in range(acks.BULK_MAX + 1)])

    def test_resolved_when_the_match_goes(self):
        acks.add(self.con, self.cfg, "CVE-2024-0001")
        self.con.execute("UPDATE match SET status='not_affected' WHERE item_id='static:web01'")
        self.assertEqual(acks.list_all(self.con, self.cfg)[0]["state"], "resolved")


class SameOrigin(unittest.TestCase):
    H = "127.0.0.1:8096"

    def test_rules(self):
        ok = server.same_origin
        self.assertTrue(ok({}, self.H))  # curl
        self.assertTrue(ok({"Origin": "http://127.0.0.1:8096", "Sec-Fetch-Site": "same-origin"}, self.H))
        self.assertFalse(ok({"Origin": "https://evil.example"}, self.H))
        self.assertFalse(ok({"Origin": "null"}, self.H))
        self.assertFalse(ok({"Sec-Fetch-Site": "cross-site"}, self.H))
        self.assertFalse(ok({"Sec-Fetch-Site": "same-site", "Origin": "http://127.0.0.1:8096"}, self.H))


class Http(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.cfg = make_cfg(self.tmp)
        con = db.connect(self.cfg.db_path)
        seed(con)
        con.close()
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.make_handler(self.cfg, set()))
        self.host = f"127.0.0.1:{self.httpd.server_port}"
        self.httpd.RequestHandlerClass = server.make_handler(self.cfg, {self.host})
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def post(self, path, body, ctype="application/json", **headers):
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        req = urllib.request.Request(f"http://{self.host}{path}", data=data, method="POST",
                                     headers={"Content-Type": ctype, **headers})
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"{}")

    def get(self, path):
        with urllib.request.urlopen(f"http://{self.host}{path}", timeout=10) as r:
            return json.loads(r.read())

    def test_ack_round_trip(self):
        code, d = self.post("/api/ack", {"cve": "cve-2024-0001", "item": "static:web01", "note": "patched", "days": 7},
                            Origin=f"http://{self.host}", **{"Sec-Fetch-Site": "same-origin"})
        self.assertEqual((code, d["items"]), (200, ["static:web01"]))
        self.assertEqual(self.get("/api/summary")["totals"]["acked"], 1)
        self.assertEqual([m["cve_id"] for m in self.get("/api/matches?tiers=act,watch,info")], ["CVE-2013-3900"])
        self.assertEqual(len(self.get("/api/matches?tiers=act,watch,info&acked=1")), 2)
        self.assertEqual(self.post("/api/unack", {"cve": "CVE-2024-0001"})[0], 200)

    def test_cross_site_and_junk_refused(self):
        body = {"cve": "CVE-2024-0001"}
        self.assertEqual(self.post("/api/ack", body, Origin="https://evil.example")[0], 403)
        self.assertEqual(self.post("/api/ack", body, **{"Sec-Fetch-Site": "cross-site"})[0], 403)
        self.assertEqual(self.post("/api/ack", json.dumps(body).encode(), ctype="text/plain")[0], 415)
        self.assertEqual(self.post("/api/ack", b"x" * 5000)[0], 413)
        self.assertEqual(self.post("/api/ack", {"cve": "nope"})[0], 400)
        self.assertEqual(self.post("/api/ack", {"cve": "CVE-2024-0001", "days": "7"})[0], 400)
        self.assertEqual(self.get("/api/summary")["totals"]["acked"], 0)

    def test_bulk_round_trip(self):
        pairs = [{"cve": "CVE-2013-3900", "item": "osquery:win-minitop"}, {"cve": "CVE-2024-0001", "item": "static:web01"}]
        code, d = self.post("/api/ack/bulk", {"pairs": pairs, "note": "done", "days": 7})
        self.assertEqual((code, d["count"]), (200, 2))
        self.assertEqual(self.get("/api/summary")["totals"]["acked"], 2)
        self.assertEqual(self.post("/api/unack/bulk", {"pairs": pairs})[1]["count"], 2)
        self.assertEqual(self.get("/api/summary")["totals"]["acked"], 0)

    def test_bulk_refusals(self):
        ok = [{"cve": "CVE-2024-0001", "item": "static:web01"}]
        self.assertEqual(self.post("/api/ack/bulk", {"pairs": ok}, Origin="https://evil.example")[0], 403)
        self.assertEqual(self.post("/api/ack/bulk", {"pairs": []})[0], 400)
        self.assertEqual(self.post("/api/ack/bulk", {"pairs": [{"cve": "nope", "item": "x"}]})[0], 400)
        self.assertEqual(self.post("/api/ack/bulk", {"pairs": [{"cve": "CVE-2024-0001"}]})[0], 400)
        self.assertEqual(self.post("/api/ack/bulk", {"pairs": ok, "days": True})[0], 400)
        big = [{"cve": "CVE-2024-0001", "item": "static:web01"}] * (acks.BULK_MAX + 1)
        self.assertEqual(self.post("/api/ack/bulk", {"pairs": big})[0], 400)
        self.assertEqual(self.post("/api/ack", b"x" * 5000)[0], 413)         # single endpoint keeps its small limit
        self.assertEqual(self.get("/api/summary")["totals"]["acked"], 0)
        self.cfg["serve"]["read_only"] = True
        self.assertEqual(self.post("/api/ack/bulk", {"pairs": ok})[0], 403)

    def test_read_only(self):
        self.cfg["serve"]["read_only"] = True
        self.assertEqual(self.post("/api/ack", {"cve": "CVE-2024-0001"})[0], 403)
        self.assertTrue(self.get("/api/summary")["read_only"])
