import argparse
import contextlib
import copy
import io
import json
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest import mock

from cvescope import cli, config, server, synclock


def make_cfg(tmp):
    return config.Config(config._merge(copy.deepcopy(config.DEFAULTS), {"data_dir": tmp}))


def wait_for(cond, timeout=15.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if cond():
            return True
        time.sleep(0.05)
    return False


class Lock(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_one_holder_at_a_time(self):
        self.assertIsNone(synclock.held(self.tmp))
        a = synclock.SyncLock(self.tmp)
        self.assertTrue(a.acquire(started="2026-11-17T10:00:00Z"))
        self.assertEqual(synclock.held(self.tmp), {"started": "2026-11-17T10:00:00Z"})
        self.assertFalse(synclock.SyncLock(self.tmp, wait=0).acquire())
        a.release()
        self.assertIsNone(synclock.held(self.tmp))
        with synclock.SyncLock(self.tmp, wait=0) as got:
            self.assertTrue(got)

    def test_waits_out_a_brief_holder(self):
        # held() takes the lock for an instant; a sync starting in that instant must not give up
        a = synclock.SyncLock(self.tmp)
        self.assertTrue(a.acquire())
        threading.Timer(0.4, a.release).start()
        b = synclock.SyncLock(self.tmp, wait=3)
        self.assertTrue(b.acquire())
        b.release()

    def test_a_killed_sync_never_leaves_it_stuck(self):
        code = ("import sys, time; sys.path.insert(0, sys.argv[2]); from cvescope import synclock; "
                "l = synclock.SyncLock(sys.argv[1]); l.acquire(started='x'); print('held', flush=True); time.sleep(60)")
        p = subprocess.Popen([sys.executable, "-c", code, self.tmp, str(Path(__file__).resolve().parent.parent)],
                             stdout=subprocess.PIPE)
        try:
            self.assertEqual(p.stdout.readline().strip(), b"held")
            self.assertEqual(synclock.held(self.tmp), {"started": "x"})
        finally:
            p.kill()
            p.wait()
            p.stdout.close()
        self.assertTrue(wait_for(lambda: synclock.held(self.tmp) is None))

    def test_cli_sync_refuses_while_another_runs(self):
        cfg = make_cfg(self.tmp)
        a = synclock.SyncLock(self.tmp)
        self.assertTrue(a.acquire(started="2026-11-17T10:00:00Z"))
        args = argparse.Namespace(only="match", no_inventory=True, no_notify=True, rebaseline=False, verbose=False,
                                  dry_run=False)
        out = io.StringIO()
        try:
            with contextlib.redirect_stdout(out), mock.patch.object(synclock.SyncLock, "WAIT", 0.2):
                self.assertEqual(cli.cmd_sync(cfg, args), 1)
        finally:
            a.release()
        self.assertIn("another sync is running (started 2026-11-17T10:00:00Z)", out.getvalue())


class Http(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.cfg = make_cfg(self.tmp)
        self.runner = server.SyncRunner(self.cfg, command=[sys.executable, "-c",
                                                           "import time; print('feeds ok', flush=True); time.sleep(0.6)"])
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.make_handler(self.cfg, set()))
        self.host = f"127.0.0.1:{self.httpd.server_port}"
        self.httpd.RequestHandlerClass = server.make_handler(self.cfg, {self.host}, self.runner)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        if self.runner.proc is not None:
            self.runner.proc.wait(timeout=15)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def post(self, body=b"{}", ctype="application/json", **headers):
        req = urllib.request.Request(f"http://{self.host}/api/sync", data=body, method="POST",
                                     headers={"Content-Type": ctype, **headers})
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"{}")

    def status(self):
        with urllib.request.urlopen(f"http://{self.host}/api/sync", timeout=10) as r:
            return json.loads(r.read())

    def test_start_follow_finish(self):
        self.assertEqual(self.status(), {"running": False, "by": None, "started": None, "page": None})
        self.assertEqual(self.post(Origin=f"http://{self.host}", **{"Sec-Fetch-Site": "same-origin"}), (202, {"ok": True}))
        self.assertEqual(self.post()[0], 409)                   # one at a time
        st = self.status()
        self.assertEqual((st["running"], st["by"]), (True, "page"))
        self.assertTrue(wait_for(lambda: not self.status()["running"]))
        page = self.status()["page"]
        self.assertEqual((page["exit"], page["lines"]), (0, ["feeds ok"]))
        self.assertTrue(page["finished"] >= page["started"])

    def test_failure_is_reported(self):
        self.runner.command = [sys.executable, "-c", "import sys; print('config not found'); sys.exit(3)"]
        self.assertEqual(self.post()[0], 202)
        self.assertTrue(wait_for(lambda: not self.status()["running"]))
        self.assertEqual(self.status()["page"]["exit"], 3)
        self.assertEqual(self.status()["page"]["lines"], ["config not found"])

    def test_this_runs_log_lines_only(self):
        log = self.runner.log_path
        log.write_text("old line from yesterday\n", encoding="utf-8")
        self.runner.command = [sys.executable, "-c",
                               f"open({str(log)!r}, 'a').write('===== cvescope sync =====\\n[kev]\\n  12 new\\n')"]
        self.assertEqual(self.post()[0], 202)
        self.assertTrue(wait_for(lambda: not self.status()["running"]))
        self.assertEqual(self.status()["page"]["lines"], ["[kev]", "12 new"])

    def test_a_sync_from_elsewhere_blocks_and_shows(self):
        lock = synclock.SyncLock(self.tmp)
        self.assertTrue(lock.acquire(started="2026-11-17T09:00:00Z"))
        try:
            code, d = self.post()
            self.assertEqual(code, 409)
            self.assertIn("started 2026-11-17T09:00:00Z", d["error"])
            self.assertEqual(self.status(), {"running": True, "by": "other", "started": "2026-11-17T09:00:00Z", "page": None})
        finally:
            lock.release()
        self.assertFalse(self.status()["running"])
        self.assertIsNone(self.runner.proc)

    def test_refusals(self):
        self.assertEqual(self.post(Origin="https://evil.example")[0], 403)
        self.assertEqual(self.post(**{"Sec-Fetch-Site": "cross-site"})[0], 403)
        self.assertEqual(self.post(ctype="text/plain")[0], 415)          # a plain <form> can't start one
        self.assertEqual(self.post(body=b"")[0], 400)
        self.cfg["serve"]["read_only"] = True
        self.assertEqual(self.post()[0], 403)
        self.assertIsNone(self.runner.proc)                              # nothing was started
        self.assertFalse(self.status()["running"])                       # status still readable

    def test_real_command_line(self):
        cfg = make_cfg(self.tmp)
        cfg.path = Path("cvescope.toml")
        argv = server.SyncRunner(cfg).argv()
        self.assertEqual(argv[:3], [sys.executable, "-m", "cvescope"])
        self.assertEqual(argv[3:5], ["--config", str(Path("cvescope.toml").resolve())])   # absolute
        self.assertEqual(argv[5:], ["--log", str(Path(self.tmp) / "sync-web.log"), "sync"])


if __name__ == "__main__":
    unittest.main()
