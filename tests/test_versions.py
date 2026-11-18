import unittest

from cvescope.versions import cmp, eval_entry


def E(vs, ds=None):
    return {"vs": vs, "ds": ds}


class Compare(unittest.TestCase):
    def test_order(self):
        for a, b in [("1.2", "1.2.1"), ("1.0rc1", "1.0"), ("1.0.2", "1.0.2k"), ("9.6p1", "9.7p1"),
                     ("2026.5.4", "2026.11.1"), ("v6.5", "6.10"), ("10.6.p2", "10.6.p3")]:
            self.assertEqual(cmp(a, b), -1, (a, b))
            self.assertEqual(cmp(b, a), 1, (b, a))

    def test_equal(self):
        self.assertEqual(cmp("1.2", "1.2.0"), 0)
        self.assertEqual(cmp("v6.5", "6.5"), 0)


class Ranges(unittest.TestCase):
    def test_less_than(self):
        e = E([{"version": "0", "lessThan": "26.1.9", "status": "affected"}], "affected")
        self.assertEqual(eval_entry(e, "26.7.9")[0], "unaffected")  # sloppy defaultStatus
        self.assertEqual(eval_entry(e, "26.1.8")[0], "affected")

    def test_lte_letters(self):
        e = E([{"version": "0", "lessThanOrEqual": "1.9.17p2", "status": "affected"}], "unaffected")
        self.assertEqual(eval_entry(e, "1.9.17p2")[0], "affected")
        self.assertEqual(eval_entry(e, "1.9.17p3")[0], "unaffected")

    def test_honours_unaffected_default_affected(self):
        e = E([{"version": "5.0", "lessThan": "5.0.3", "status": "unaffected"}], "affected")
        self.assertEqual(eval_entry(e, "5.0.1")[0], "unaffected")
        self.assertEqual(eval_entry(e, "6.0")[0], "affected")

    def test_wildcard(self):
        e = E([{"version": "6.1", "status": "affected"},
               {"version": "6.1.80", "lessThanOrEqual": "6.1.*", "status": "unaffected"}], "affected")
        self.assertEqual(eval_entry(e, "6.1.90")[0], "unaffected")
        self.assertEqual(eval_entry(e, "6.1.10")[0], "affected")

    def test_free_text(self):
        self.assertEqual(eval_entry(E([{"version": "Linux Kernel <= 3.1"}]), "3.0")[0], "affected")
        self.assertEqual(eval_entry(E([{"version": "Linux Kernel <= 3.1"}]), "7.0.14")[0], "unaffected")
        self.assertEqual(eval_entry(E([{"version": "before 2.4.60"}]), "2.4.58")[0], "affected")
        self.assertEqual(eval_entry(E([{"version": "2.1 and earlier"}]), "2.2")[0], "unaffected")

    def test_openssl_text(self):
        e = E([{"status": "affected", "version": "Fixed in OpenSSL 1.1.1g (Affected 1.1.1d-1.1.1f)"}])
        self.assertEqual(eval_entry(e, "3.5.9")[0], "unaffected")
        self.assertEqual(eval_entry(e, "1.1.1e")[0], "affected")

    def test_freebsd_patch_levels(self):
        e = E([{"version": "15.1-RELEASE", "lessThan": "p7", "status": "affected", "versionType": "release"},
               {"version": "14.3-RELEASE", "lessThan": "p9", "status": "affected", "versionType": "release"}], "unknown")
        self.assertEqual(eval_entry(e, "15.1-RELEASE-p6")[0], "affected")
        self.assertEqual(eval_entry(e, "15.1-RELEASE-p7")[0], "unaffected")

    def test_default_alone_is_unknown(self):
        self.assertEqual(eval_entry(E([], "affected"), "7.0.14")[0], "unknown")
        self.assertEqual(eval_entry(E([], "unaffected"), "7.0.14")[0], "unknown")

    def test_unknown(self):
        self.assertEqual(eval_entry(E([{"version": "n/a", "status": "affected"}]), "1.0")[0], "unknown")
        self.assertEqual(eval_entry(E([{"version": "0", "lessThan": "2.0"}]), None)[0], "unknown")


class Description(unittest.TestCase):
    def setUp(self):
        from cvescope.versions import name_pattern
        self.p = lambda *n: [name_pattern(x) for x in n]

    def test_heartbleed(self):
        from cvescope.versions import desc_max
        d = ("The (1) TLS and (2) DTLS implementations in OpenSSL 1.0.1 before 1.0.1g do not properly "
             "handle Heartbeat Extension packets")
        self.assertEqual(desc_max(d, self.p("openssl")), "1.0.1g")

    def test_later_is_unsure(self):
        from cvescope.versions import desc_max
        self.assertIsNone(desc_max("Affects OpenSSL 3.0.0 and later.", self.p("openssl")))
        self.assertIsNone(desc_max("A flaw in Linux since v2.6.19-rc1 allows", self.p("linux")))

    def test_protocol_versions_ignored(self):
        from cvescope.versions import desc_max
        self.assertIsNone(desc_max("OpenSSL accepts TLS 1.3 early data", self.p("openssl")))
        self.assertEqual(desc_max("Pi-hole Web v4.3.2 (aka AdminLTE) allows", self.p("pi hole web")), "4.3.2")

    def test_upper_bound_beats_and_above(self):
        from cvescope.versions import desc_max
        d = "Pi-hole's Web interface provides a central location. Versions 4.0 and above, prior to 5.18.3 are vulnerable."
        self.assertEqual(desc_max(d, self.p("web interface")), "5.18.3")  # bound sits in the next sentence
        self.assertEqual(desc_max("For OpenSSL 1.1.0, the crash happens; users should upgrade to 1.1.0d.",
                                  self.p("openssl")), "1.1.0d")
        d2 = "The Pi-hole Web interface in versions 4.0 and above, prior to 5.18.3 allows XSS."
        self.assertEqual(desc_max(d2, self.p("pi hole web")), "5.18.3")

    def test_generic_name_skipped(self):
        from cvescope.versions import name_pattern
        self.assertIsNone(name_pattern("core"))


if __name__ == "__main__":
    unittest.main()


class OtherDistroText(unittest.TestCase):
    def test_distro_release_numbers_are_not_product_versions(self):
        # CVE-2020-14312: dnsmasq's default config as Fedora < 31 and RHEL shipped it
        e = {"p": "dnsmasq", "v": "n/a", "vs": [{"status": "affected", "version": "Fedora version prior to 31"},
                                                {"status": "affected", "version": "all RHEL versions"}]}
        self.assertEqual(eval_entry(e, "2.93")[0], "unknown")

    def test_the_distro_itself_still_counts(self):
        e = {"p": "Fedora", "v": "Fedora Project", "vs": [{"status": "affected", "version": "prior to 31"}]}
        self.assertEqual(eval_entry(e, "30")[0], "affected")


class DefaultStatusWording(unittest.TestCase):
    def test_default_affected_reads_as_affected(self):
        # Jenkins-style record: only the fixed lines are listed, everything else is affected
        e = {"ds": "affected", "vs": [{"version": "2.442", "status": "unaffected"},
                                      {"version": "2.426.3", "lessThan": "2.427", "status": "unaffected"}]}
        st, why = eval_entry(e, "2.441")
        self.assertEqual(st, "affected")
        self.assertNotIn("outside", why)
        self.assertIn("marks the rest affected", why)
