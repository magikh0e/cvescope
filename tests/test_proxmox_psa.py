import unittest

from cvescope import db, match
from cvescope.sources import proxmox_psa as psa

# Posts in the layouts the thread has used over the years (trimmed from real PSAs).
PAGE = """<html><a href="/threads/x.149331/page-5">5</a><a href="/threads/x.149331/page-6">6</a>
<article class="message" data-content="post-700001"><div class="bbWrapper">
<b>Subject: PSA-2024-00001-1: PixieFAIL EDK2 PXE vulnerabilities</b><br />
<b>Advisory date:</b> 2024-01-24<br /><b>Package(s):</b><br />pve-edk2-firmware<br />
<b>Fixed:</b><br />- pve-edk2-firmware-ovmf 4.2023.08-3 (Proxmox VE 8.x)<br />
- pve-edk2-firmware 4.20230228-4~bpo11+2 (Proxmox VE 7.x)<br />
<b>References:</b><br />CVE-2023-45229<br /></div>ProxmoxSecurityAdvisory<br />Staff member</article>
<article class="message" data-content="post-705345"><div class="bbWrapper">
Subject: PSA-2024-00009-1: Proxmox VE/Mail Gateway API: post-authentication path traversal<br />
Advisory date: 2024-09-23<br />Packages: pve-manager, pmg-api<br />Fixed:<br />- Proxmox VE 8:<br />
pve-manager &gt;= 8.2.7, libpve-storage-perl &gt;= 8.2.5,<br />- Proxmox Mail Gateway 8:<br />
pmg-api &gt;= 8.1.4, libpve-http-server-perl &gt;= 5.1.1<br />- Proxmox Virtual Environment 7:<br />
pve-manager &gt;= 7.4-19<br />References:<br />CVE-2024-21545<br /></div></article>
<article class="message" data-content="post-874674"><div class="bbWrapper">
<b>Subject: PSA-2026-00080-1: kernel TCP Use-After-Free (CVE-2026-98432)</b><br />
<b>Advisory date</b><br />: 2026-10-31<br /><b>Packages</b><br />: proxmox-kernel-*<br />
<b>Fixed in</b><br />: proxmox-kernel-7.0.14-25-pve(-signed)<br />
- proxmox-kernel-6.8.12-41-pve(-signed) (Bookworm based products)<br />
<b>References</b><br />: CVE-2026-98432<br /></div>ProxmoxSecurityAdvisory</article>
<article class="message" data-content="post-875000"><div class="bbWrapper">
Subject: PSA-2026-00012-2: Corosync: DoS via malformed packets&#8203;<br />Advisory date: 2026-04-15<br />
Packages: corosync<br />Fixed in:<br />- corosync &gt;= 3.1.10-pve2 (PVE 9.x)<br />- corosync &gt;= 3.1.10-pve2~bpo12+1<br />
- pve-qemu-kvm &gt;= 11.1.4-1<br />References:<br />- CVE-2026-35091<br />- CVE-2026-35092<br /></div></article>
<article class="message" data-content="post-875546"><div class="bbWrapper">
Subject: PSA-2026-00100-1: Missing shell quoting<br />Advisory date: 2026-11-12<br />
Packages: libpve-storage-perl<br />Fixed in:<br />- libpve-storage-perl &gt;= 9.1.15<br /></div></article>
</html>"""


class Parse(unittest.TestCase):
    def setUp(self):
        self.got = {p["id"]: p for p in psa.parse_page(PAGE)}

    def test_layouts(self):
        g = self.got
        self.assertEqual(psa.last_page(PAGE), 6)
        self.assertEqual(g["PSA-2024-00001"]["fixed"], [["pve-edk2-firmware-ovmf", "4.2023.08-3", 8],
                                                         ["pve-edk2-firmware", "4.20230228-4~bpo11+2", 7]])
        self.assertEqual(g["PSA-2026-00080"]["fixed"], [["kernel:7.0", "7.0.14-25", None], ["kernel:6.8", "6.8.12-41", 8]])
        self.assertEqual(g["PSA-2026-00080"]["date"], "2026-10-31")
        self.assertEqual(g["PSA-2026-00080"]["url"], "https://forum.proxmox.com/posts/874674/")
        # "-pve2" in a version isn't a release line; ~bpo12 (a Debian 12 backport) is Proxmox VE 8
        self.assertEqual(g["PSA-2026-00012"]["fixed"], [["corosync", "3.1.10-pve2", 9],
                                                         ["corosync", "3.1.10-pve2~bpo12+1", 8],
                                                         ["pve-qemu-kvm", "11.1.4-1", None]])
        self.assertEqual((g["PSA-2026-00012"]["rev"], g["PSA-2026-00012"]["cves"]),
                         (2, ["CVE-2026-35091", "CVE-2026-35092"]))
        self.assertEqual(g["PSA-2026-00100"]["cves"], [])  # most PSAs name no CVE

    def test_grouped_by_product(self):
        # fixes listed under "- Proxmox VE 8:" headers, several per line; Mail Gateway's skipped
        self.assertEqual(self.got["PSA-2024-00009"]["fixed"], [["pve-manager", "8.2.7", 8],
                                                                ["libpve-storage-perl", "8.2.5", 8],
                                                                ["pve-manager", "7.4-19", 7]])

    def test_newer_revision_wins(self):
        con = db.connect(":memory:")
        p = list(self.got.values())
        old = [dict(x, rev=1, title="old") for x in p if x["id"] == "PSA-2026-00012"]
        psa.store(con, p)
        psa.store(con, old)  # an older revision read later doesn't overwrite
        self.assertEqual(tuple(con.execute("SELECT rev, title FROM psa WHERE id='PSA-2026-00012'").fetchone()),
                         (2, "Corosync: DoS via malformed packets"))


class FixChoice(unittest.TestCase):
    def test_release_lines(self):
        lines = [("8.2.7", 8), ("7.4-19", 7)]
        self.assertEqual(match._psa_fix("9.2.28", lines, 9), ("8.2.7", False))   # newer than every line
        self.assertEqual(match._psa_fix("8.2.5", lines, 8), ("8.2.7", True))
        self.assertEqual(match._psa_fix("8.2.7", lines, 8), ("8.2.7", False))
        self.assertEqual(match._psa_fix("7.4-18", lines, 7), ("7.4-19", True))
        self.assertIsNone(match._psa_fix("6.4-1", lines, 6))                     # an older line: can't tell
        # the version scheme changed between lines: 4.2026.08 sorts below 4.20230228 but is newer
        self.assertEqual(match._psa_fix("4.2026.08-1", [("4.20230228-4~bpo11+2", 7)], 9),
                         ("4.20230228-4~bpo11+2", False))

    def test_without_a_known_line(self):
        self.assertEqual(match._psa_fix("3.2.0-pve1", [("3.1.10-pve2", None), ("3.1.10-pve2~bpo12+1", None)]),
                         ("3.1.10-pve2~bpo12+1", False))
        self.assertEqual(match._psa_fix("8.2.5", [("8.2.7", 8), ("7.4-19", 7)]), ("8.2.7", True))


class Apply(unittest.TestCase):
    def setUp(self):
        self.con = db.connect(":memory:")
        for cid in ("CVE-2023-45229", "CVE-2024-21545", "CVE-2026-98432", "CVE-2026-35091", "CVE-2026-35092"):
            self.con.execute("INSERT INTO cve(id,state,published) VALUES(?, 'PUBLISHED', '2026-01-01')", (cid,))
        psa.store(self.con, psa.parse_page(PAGE))

    def host(self, **kw):
        ex = {"pve_packages": {"pve-manager": "8.2.5", "corosync": "3.2.0-pve1", "pve-qemu-kvm": "11.1.3-2",
                               "pve-edk2-firmware": "4.2023.08-1", "proxmox-kernel-7.0": "7.0.14-29"},
              "running_kernel": "7.0.14-24-pve", "pve_split": [], "pve_major": 8}
        ex.update(kw)
        return {"id": "pve", "extra": ex}

    def test_host(self):
        rows = {}
        match._apply_psa(self.con, self.host(), rows)
        self.assertEqual(rows[("CVE-2024-21545", "pve")],
                         ("affected", "psa", "Proxmox PSA-2024-00009-1: fixed in pve-manager 8.2.7, installed 8.2.5"))
        # the running kernel is older than the fix, the installed one isn't: reboot
        self.assertEqual(rows[("CVE-2026-98432", "pve")],
                         ("affected", "psa", "Proxmox PSA-2026-00080-1: fixed in proxmox-kernel-7.0 7.0.14-25, "
                                             "running 7.0.14-24; 7.0.14-29 is already installed: reboot to run it"))
        # corosync is fine, but pve-qemu-kvm in the same advisory isn't: affected wins
        self.assertEqual(rows[("CVE-2026-35091", "pve")][0], "affected")
        self.assertIn("pve-qemu-kvm 11.1.4-1", rows[("CVE-2026-35091", "pve")][2])
        # the edk2 fix was only listed for PVE 7 (and PVE 8 shipped a different package): no call
        self.assertNotIn(("CVE-2023-45229", "pve"), rows)

    def test_newer_release_line(self):
        rows = {}
        match._apply_psa(self.con, self.host(pve_major=9, pve_packages={"pve-edk2-firmware": "4.2026.08-1",
                                                                       "pve-manager": "9.2.28"}), rows)
        self.assertEqual(rows[("CVE-2023-45229", "pve")],
                         ("not_affected", "psa", "Proxmox PSA-2024-00001-1: fixed in pve-edk2-firmware "
                                                 "4.20230228-4~bpo11+2 for Proxmox VE 7, installed 4.2026.08-1"))
        self.assertEqual(rows[("CVE-2024-21545", "pve")][2],
                         "Proxmox PSA-2024-00009-1: fixed in pve-manager 8.2.7 for Proxmox VE 8, installed 9.2.28")

    def test_split_out_packages_and_kernel_items(self):
        rows = {}
        match._apply_psa(self.con, self.host(pve_split=["pve-qemu-kvm", "kernel"]), rows)
        self.assertEqual(rows[("CVE-2026-35091", "pve")][0], "not_affected")  # corosync only now
        self.assertNotIn(("CVE-2026-98432", "pve"), rows)                    # the kernel item decides
        kern = {"id": "k", "extra": {"pve_pkg": "kernel", "running": "7.0.14-28-pve",
                                     "kernel_installed": {"7.0": "7.0.14-29"}, "pve_major": 9}}
        match._apply_psa(self.con, kern, rows)
        self.assertEqual(rows[("CVE-2026-98432", "k")],
                         ("not_affected", "psa", "Proxmox PSA-2026-00080-1: fixed in proxmox-kernel-7.0 7.0.14-25, "
                                                 "running 7.0.14-28"))
        qemu = {"id": "q", "extra": {"pve_pkg": "pve-qemu-kvm", "package_version": "11.1.4-1", "pve_major": 9}}
        match._apply_psa(self.con, qemu, rows)
        self.assertEqual(rows[("CVE-2026-35091", "q")][0], "not_affected")

    def test_series_the_advisory_doesnt_cover(self):
        rows = {}
        match._apply_psa(self.con, {"id": "k", "extra": {"pve_pkg": "kernel", "running": "6.17.13-21-pve"}}, rows)
        self.assertEqual(rows, {})


if __name__ == "__main__":
    unittest.main()
