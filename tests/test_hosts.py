import unittest

from cvescope.query import host_of


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


if __name__ == "__main__":
    unittest.main()
