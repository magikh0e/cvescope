import copy
import datetime as dt
import json
import unittest
from unittest import mock

from cvescope import config, db, match, net
from cvescope.sources import distro

NOW = dt.datetime(2026, 11, 18, 6, 0, tzinfo=dt.timezone.utc)
TRACKER = {
    "CVE-2026-0001": {"packages": [{"name": "openssh", "statuses": [
        {"release_codename": "noble", "status": "not-affected", "description": "see notes"},
        {"release_codename": "jammy", "status": "needed", "description": ""}]}]},
    "CVE-2026-0002": {"packages": [{"name": "git", "statuses": [
        {"release_codename": "noble", "status": "needs-triage", "description": ""}]}]},
    "CVE-2026-0003": {"packages": [{"name": "openssl", "statuses": [
        {"release_codename": "noble", "status": "released", "description": "3.0.13-0ubuntu3.7"}]}]},
}


class UbuntuFresh(unittest.TestCase):
    def setUp(self):
        self.cfg = config.Config(copy.deepcopy(config.DEFAULTS))
        self.con = db.connect(":memory:")
        for cid, pub in (("CVE-2026-0001", "2026-11-10"), ("CVE-2026-0002", "2026-11-15"),
                         ("CVE-2026-0003", "2026-11-12"), ("CVE-2026-0004", "2026-11-16"),
                         ("CVE-2025-0005", "2025-01-01")):
            self.con.execute("INSERT INTO cve(id,state,published) VALUES(?, 'PUBLISHED', ?)", (cid, pub))
        for iid, src, ver in (("ssh", "openssh", "1:9.6p1-3ubuntu13.5"), ("git", "git", "1:2.43.0-1ubuntu7.4"),
                              ("ssl", "openssl", "3.0.13-0ubuntu3.6")):
            self.con.execute("INSERT INTO item(id,name,version,collector,aliases,keywords,extra) VALUES(?,?,?,?,'[]','[]',?)",
                             (iid, iid, "1", "dpkg:box", json.dumps({"distro": "ubuntu:noble", "source": src,
                                                                     "package_version": ver, "backports": True})))
        for cid, iid in (("CVE-2026-0001", "ssh"), ("CVE-2026-0002", "git"), ("CVE-2026-0003", "ssl"),
                         ("CVE-2026-0004", "git"), ("CVE-2025-0005", "ssh")):
            self.con.execute("INSERT INTO match VALUES(?, ?, 'check', 'product', 'x', '2026-11-17')", (cid, iid))
        # OVAL already answered one of them: the tracker isn't asked and OVAL's row wins
        self.con.execute("INSERT INTO distro_fix(release,package,cve_id,status,fixed) "
                         "VALUES('ubuntu:noble','openssh','CVE-2025-0005','fixed','1:9.6p1-3ubuntu13.4')")
        self.con.commit()
        self.calls = []

    def fake_get(self, url, etag=None, timeout=120):
        cid = url.rsplit("/", 1)[-1][:-5]
        self.calls.append(cid)
        if cid not in TRACKER:
            raise net.HTTPStatus(404, url)
        return json.dumps(TRACKER[cid]).encode(), None

    def run_fresh(self, now=NOW):
        with mock.patch.object(distro.net, "get", self.fake_get):
            return distro.ubuntu_fresh(self.con, self.cfg, {"ubuntu:noble"}, now=now)

    def decide(self, iid, cid):
        it = dict(zip(("id", "extra"), self.con.execute("SELECT id, extra FROM item WHERE id=?", (iid,)).fetchone()))
        it["extra"] = json.loads(it["extra"])
        rows = {(cid, iid): ("check", "product", "x")}
        match._apply_distro(self.con, it, rows)
        return rows[(cid, iid)]

    def test_lookups_and_decisions(self):
        out = self.run_fresh()
        self.assertEqual(sorted(self.calls), ["CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0004"])
        self.assertIn("3 answer(s)", out)                       # 0004 isn't in Ubuntu's tracker
        self.assertEqual(self.decide("ssh", "CVE-2026-0001"),
                         ("not_affected", "distro", "Ubuntu noble isn't affected (the tracker marks it not-affected)"))
        self.assertEqual(self.decide("git", "CVE-2026-0002"),
                         ("check", "distro", "Ubuntu noble hasn't decided yet (not triaged)"))
        self.assertEqual(self.decide("ssl", "CVE-2026-0003")[0], "affected")   # fix 3.0.13-0ubuntu3.7 > installed 3.6
        self.assertEqual(self.decide("ssh", "CVE-2025-0005")[0], "not_affected")  # OVAL's answer

    def test_cache(self):
        self.run_fresh()
        self.calls.clear()
        self.run_fresh(NOW + dt.timedelta(hours=2))
        self.assertEqual(self.calls, [])                        # nothing due yet
        self.run_fresh(NOW + dt.timedelta(hours=13))
        self.assertEqual(self.calls, ["CVE-2026-0002"])         # only the untriaged one is rechecked at 12 h
        self.calls.clear()
        self.run_fresh(NOW + dt.timedelta(hours=25))
        self.assertIn("CVE-2026-0004", self.calls)              # not found: retried daily

    def test_settled_answers_stay_settled(self):
        self.run_fresh()
        # what the next match run makes of it: the not-affected one is resolved by the distro step
        self.con.execute("UPDATE match SET status='not_affected', how='distro' WHERE cve_id='CVE-2026-0001'")
        self.run_fresh(NOW + dt.timedelta(hours=2))
        self.assertEqual(self.decide("ssh", "CVE-2026-0001")[0], "not_affected")   # rebuilt from the cache

    def test_statuses(self):
        self.assertEqual(distro._ubuntu_status("released", "1.2-3"), ("fixed", "1.2-3", None))
        self.assertEqual(distro._ubuntu_status("DNE", ""), ("notaff", None, None))
        self.assertEqual(distro._ubuntu_status("deferred", "2026-12-01")[2], "deferred by Ubuntu: 2026-12-01")
        self.assertEqual(distro._ubuntu_status("ignored", "end of life")[2], "Ubuntu won't fix it: end of life")
        self.assertEqual(distro._ubuntu_status("needs-triage", "")[0], "maybe")

    def test_off_by_default(self):
        self.assertFalse(config.DEFAULTS["sources"]["ubuntu_lookup"])


if __name__ == "__main__":
    unittest.main()
