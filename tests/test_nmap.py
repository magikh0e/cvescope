import os
import tempfile
import time
import unittest

from cvescope.collectors.nmap import nmap_xml, parse

# trimmed nmap -sV output for a made-up lab network
SCAN = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sV -oX lab.xml 10.9.8.0/24" start="{start}" version="7.95">
<host><status state="up"/><address addr="10.9.8.10" addrtype="ipv4"/>
 <hostnames><hostname name="web01.lab" type="PTR"/></hostnames>
 <ports>
  <port protocol="tcp" portid="22"><state state="open"/>
   <service name="ssh" product="OpenSSH" version="9.6p1 Ubuntu 3ubuntu13.5" extrainfo="Ubuntu Linux; protocol 2.0" method="probed" conf="10">
    <cpe>cpe:/a:openbsd:openssh:9.6p1</cpe><cpe>cpe:/o:linux:linux_kernel</cpe></service></port>
  <port protocol="tcp" portid="80"><state state="open"/>
   <service name="http" product="Apache httpd" version="2.4.49" method="probed" conf="10">
    <cpe>cpe:/a:apache:http_server:2.4.49</cpe></service></port>
  <port protocol="tcp" portid="443"><state state="open"/>
   <service name="http" product="Apache httpd" version="2.4.49" tunnel="ssl" method="probed" conf="10">
    <cpe>cpe:/a:apache:http_server:2.4.49</cpe></service></port>
  <port protocol="tcp" portid="3306"><state state="open"/>
   <service name="mysql" product="MySQL" version="5.5.5-10.6.12-MariaDB-0ubuntu0.22.04.1" method="probed" conf="10">
    <cpe>cpe:/a:mysql:mysql:5.5.5-10.6.12-mariadb-0ubuntu0.22.04.1</cpe></service></port>
  <port protocol="tcp" portid="8080"><state state="open"/>
   <service name="http-proxy" method="table" conf="3"/></port>
  <port protocol="tcp" portid="25"><state state="closed"/>
   <service name="smtp" product="Postfix smtpd" method="probed" conf="10"/></port>
 </ports></host>
<host><status state="up"/><address addr="10.9.8.20" addrtype="ipv4"/>
 <ports>
  <port protocol="tcp" portid="53"><state state="open"/>
   <service name="domain" product="dnsmasq" version="2.85" method="probed" conf="10">
    <cpe>cpe:/a:thekelleys:dnsmasq:2.85</cpe></service></port>
  <port protocol="tcp" portid="9000"><state state="open"/>
   <service name="http" product="Weird Appliance httpd" method="probed" conf="10"/></port>
 </ports></host>
<host><status state="down"/><address addr="10.9.8.30" addrtype="ipv4"/></host>
</nmaprun>
"""


class Nmap(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "lab.xml")
        with open(self.path, "w", encoding="utf-8") as f:
            f.write(SCAN.format(start=int(time.time())))

    def tearDown(self):
        for f in os.listdir(self.dir):
            os.remove(os.path.join(self.dir, f))
        os.rmdir(self.dir)

    def test_parse_skips_closed_down_and_guessed(self):
        _, services = parse(self.path)
        ports = sorted((s["addr"], s["port"]) for s in services)
        self.assertEqual(ports, [("10.9.8.10", 22), ("10.9.8.10", 80), ("10.9.8.10", 443),
                                 ("10.9.8.10", 3306), ("10.9.8.20", 53), ("10.9.8.20", 9000)])

    def test_items(self):
        items = {i["name"]: i for i in nmap_xml({"path": self.path})}
        ssh = items["OpenSSH (web01.lab:22)"]
        self.assertEqual(ssh["version"], "9.6p1")
        self.assertTrue(ssh["extra"]["backports"])          # Ubuntu build
        self.assertIn("openbsd:openssh", ssh["aliases"])
        web = items["Apache HTTP Server (web01.lab:80,443)"]  # two ports, one item
        self.assertEqual(web["version"], "2.4.49")
        self.assertFalse(web["extra"]["backports"])
        self.assertIn("apache:http server", web["aliases"])
        db = items["MariaDB (web01.lab:3306)"]
        self.assertEqual(db["version"], "10.6.12")
        self.assertEqual(items["dnsmasq (10.9.8.20:53)"]["version"], "2.85")
        self.assertNotIn("Weird Appliance httpd (10.9.8.20:9000)", items)  # no version by default

    def test_unversioned_and_host_filter(self):
        items = nmap_xml({"path": self.path, "unversioned": True, "hosts": ["10.9.8.16/28"]})
        names = sorted(i["name"] for i in items)
        self.assertEqual(names, ["Weird Appliance httpd (10.9.8.20:9000)", "dnsmasq (10.9.8.20:53)"])
        weird = next(i for i in items if i["name"].startswith("Weird"))
        self.assertIn("*:weird appliance httpd", weird["aliases"])

    def test_old_scan_ignored(self):
        with open(self.path, "w", encoding="utf-8") as f:
            f.write(SCAN.format(start=int(time.time()) - 90 * 86400))
        with self.assertRaises(RuntimeError):
            nmap_xml({"path": self.path})
        self.assertTrue(nmap_xml({"path": self.path, "max_age_days": 0}))

    def test_refuses_entities(self):
        with open(self.path, "w", encoding="utf-8") as f:
            f.write('<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa">]><nmaprun>&a;</nmaprun>')
        with self.assertRaises(ValueError):
            parse(self.path)


if __name__ == "__main__":
    unittest.main()
