import unittest

from cvescope.query import host_aliases, host_of, merge_hosts


class Hosts(unittest.TestCase):
    def test_host_from_the_item_name(self):
        for name, collector, host in [
            ("OpenSSH (h0evpn)", "dpkg:h0evpn", "h0evpn"),
            ("7-Zip (minitop)", "osquery:osquery#7", "minitop"),               # unnamed collector entry
            ("Linux kernel (PVE1)", "proxmox:Proxmox VE (PVE1)", "PVE1"),
            ("Proxmox VE (PVE1)", "proxmox:Proxmox VE (PVE1)", "PVE1"),
            ("Linux kernel (VM 100 UnFi)", "proxmox:Proxmox VE (PVE2)", "VM 100 UnFi"),   # a guest is its own host
            ("Debian GNU/Linux 13 (trixie) (VM 100 UnFi)", "proxmox:Proxmox VE (PVE2)", "VM 100 UnFi"),
            ("Home Assistant Core", "homeassistant:http://192.168.1.5:8123", "Home Assistant"),
            ("Mosquitto (HA add-on)", "homeassistant:http://192.168.1.5:8123", "Home Assistant"),
            ("ESPHome firmware (Plug 1)", "homeassistant:http://192.168.1.5:8123", "Plug 1"),
            ("FreeBSD (OPNsense base)", "opnsense:https://192.168.1.1", "OPNsense"),
            ("OpenSSL (OPNsense)", "opnsense:https://192.168.1.1", "OPNsense"),
            ("UniFi Network Application", "unifi:https://192.168.1.2", "UniFi"),
            ("Pi-hole FTL (pihole1)", "pihole:pihole1", "pihole1"),
            ("Web server", "static:web01", "web01"),
        ]:
            self.assertEqual(host_of(name, collector), host, (name, collector))


class Merge(unittest.TestCase):
    HOSTS = {"OPNsense", "VM 102 OpnSense", "pihole1", "CT 113 pihole1", "Home Assistant", "VM 103 haos-17.2",
             "UniFi", "VM 100 UnFi", "CT 101 arr-stack", "PVE1"}

    def test_guest_named_like_a_host_joins_it(self):
        m = merge_hosts(self.HOSTS)
        self.assertEqual(m, {"VM 102 OpnSense": "OPNsense", "CT 113 pihole1": "pihole1"})

    def test_aliases_by_name_or_guest_id(self):
        cfg = {"hosts": {"vm 103 HAOS-17.2": "home assistant", "VM 100": "UniFi", "CT 101": "", "x": None}}
        aliases = host_aliases(cfg)
        self.assertEqual(aliases, {"vm 103 haos-17.2": "home assistant", "vm 100": "UniFi"})   # non-text values dropped
        m = merge_hosts(self.HOSTS, aliases)
        self.assertEqual(m["VM 103 haos-17.2"], "Home Assistant")   # the existing host's spelling wins
        self.assertEqual(m["VM 100 UnFi"], "UniFi")
        self.assertNotIn("CT 101 arr-stack", m)                     # empty alias: left alone
        self.assertEqual(merge_hosts({"VM 103 haos-18.0", "Home Assistant"}, {"vm 103": "Home Assistant"}),
                         {"VM 103 haos-18.0": "Home Assistant"})   # survives the VM being renamed

    def test_no_hosts_section(self):
        self.assertEqual(host_aliases({}), {})
        self.assertEqual(host_aliases({"hosts": ["not", "a", "table"]}), {})


if __name__ == "__main__":
    unittest.main()
