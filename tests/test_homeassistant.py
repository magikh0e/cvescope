import unittest

from cvescope import db, match
from cvescope.collectors.appliances import ha_update_items
from cvescope.sources import osvpkg

VULNS = [
    {"id": "GHSA-5hxg-r395-fqxx", "aliases": ["CVE-2026-64825", "PYSEC-2026-3669"],
     "affected": [{"package": {"ecosystem": "PyPI", "name": "homeassistant"},
                   "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2026.6.0"}]}],
                   "versions": ["2026.5.4", "2026.6.0b1"]}]},
    {"id": "PYSEC-2026-3669", "aliases": ["CVE-2026-64825", "GHSA-5hxg-r395-fqxx"],
     "affected": [{"package": {"ecosystem": "PyPI", "name": "homeassistant"},
                   "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2026.6.0"}]}],
                   "versions": ["2026.5.4", "2026.6.0b1"]}]},
    {"id": "PYSEC-2026-1454", "aliases": ["CVE-2025-65713"],
     "affected": [{"package": {"ecosystem": "PyPI", "name": "homeassistant"},
                   "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2025.8.0"}]}],
                   "versions": ["2025.7.4"]}]},
    {"id": "GHSA-new0-0000-0000", "aliases": ["CVE-2026-99999"],   # no versions list: ranges decide
     "affected": [{"package": {"ecosystem": "PyPI", "name": "homeassistant"},
                   "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "2026.10.0"}, {"fixed": "2026.11.3"}]}]}]},
    {"id": "GHSA-nocv-e000-0000", "aliases": [],                    # no CVE: filed under its own GHSA ID
     "affected": [{"package": {"ecosystem": "PyPI", "name": "homeassistant"}, "versions": ["2026.11.2"]}]},
    {"id": "GHSA-othr-0000-0000", "aliases": ["CVE-2026-11111"],    # another package
     "affected": [{"package": {"ecosystem": "PyPI", "name": "hass-nabucasa"}, "versions": ["2026.11.2"]}]},
]


class Osv(unittest.TestCase):
    def setUp(self):
        self.con = db.connect(":memory:")
        for cid in ("CVE-2026-64825", "CVE-2025-65713", "CVE-2026-99999", "CVE-2026-11111"):
            self.con.execute("INSERT INTO cve(id,state,published) VALUES(?, 'PUBLISHED', '2026-01-01')", (cid,))
        self.con.executemany("INSERT INTO osv_pkg VALUES(?,?,?,?,?,?,?)",
                             osvpkg.rows_for(VULNS, "PyPI", "homeassistant"))
        self.item = {"id": "ha", "version": "2026.11.2", "extra": {
            "osv": {"ecosystem": "PyPI", "name": "homeassistant", "label": "Home Assistant advisory"},
            "latest_version": "2026.11.3"}}

    def test_rows(self):
        rows = osvpkg.rows_for(VULNS, "PyPI", "homeassistant")
        self.assertEqual(sorted({r[2] for r in rows}), ["CVE-2025-65713", "CVE-2026-64825", "CVE-2026-99999",
                                                        "GHSA-nocv-e000-0000"])
        self.assertEqual({r[6] for r in rows if r[2] == "CVE-2026-64825"}, {"2026.6.0"})

    def test_advisories_decide(self):
        rows = {("CVE-2025-65713", "ha"): ("keyword", "keyword", "description mentions Home Assistant")}
        match._apply_osv(self.con, self.item, rows)
        # a keyword-only match the advisory covers is settled
        self.assertEqual(rows[("CVE-2025-65713", "ha")],
                         ("not_affected", "osv", "Home Assistant advisory PYSEC-2026-1454: fixed in 2025.8.0, installed 2026.11.2"))
        # the GHSA is named over its PYSEC copy
        self.assertEqual(rows[("CVE-2026-64825", "ha")][2],
                         "Home Assistant advisory GHSA-5hxg-r395-fqxx: fixed in 2026.6.0, installed 2026.11.2")
        self.assertEqual(rows[("CVE-2026-99999", "ha")],
                         ("affected", "osv", "Home Assistant advisory GHSA-new0-0000-0000: fixed in 2026.11.3, "
                                             "installed 2026.11.2; update available: 2026.11.3"))
        self.assertNotIn(("CVE-2026-11111", "ha"), rows)

    def test_listed_release_is_affected(self):
        item = dict(self.item, version="2026.5.4", extra=dict(self.item["extra"], latest_version=None))
        rows = {}
        match._apply_osv(self.con, item, rows)
        self.assertEqual(rows[("CVE-2026-64825", "ha")][0], "affected")


STATES = [
    {"entity_id": "update.home_assistant_core_update", "attributes": {
        "title": "Home Assistant Core", "installed_version": "2026.11.2", "latest_version": "2026.11.3"}},
    {"entity_id": "update.home_assistant_operating_system_update", "attributes": {
        "title": "Home Assistant Operating System", "installed_version": "18.4", "latest_version": "18.4"}},
    {"entity_id": "update.home_assistant_supervisor_update", "attributes": {
        "title": "Home Assistant Supervisor", "installed_version": "2026.11.0", "latest_version": "2026.11.1"}},
    {"entity_id": "update.mosquitto_broker_update", "attributes": {
        "title": "Mosquitto broker", "installed_version": "6.5.1", "latest_version": "6.5.1",
        "entity_picture": "/api/hassio/addons/core_mosquitto/icon"}},
    {"entity_id": "update.file_editor_update", "attributes": {          # no CVE identity: skipped
        "title": "File editor", "installed_version": "6.3.1", "latest_version": "6.3.1",
        "entity_picture": "/api/hassio/addons/core_configurator/icon"}},
    {"entity_id": "update.athom_plug_firmware", "attributes": {
        "title": "ESPHome", "device_class": "firmware", "installed_version": "2026.10.2",
        "latest_version": "2026.10.2", "friendly_name": "Athom Plug V3 Firmware"}},
    {"entity_id": "update.mushroom_update", "attributes": {"title": None, "installed_version": "v5.3.0"}},
    {"entity_id": "sensor.not_an_update", "attributes": {"installed_version": "1"}},
]


class UpdateEntities(unittest.TestCase):
    def test_items(self):
        core, items = ha_update_items(STATES)
        self.assertEqual(core, {"latest_version": "2026.11.3"})
        got = {i["name"]: i for i in items}
        self.assertEqual(sorted(got), ["ESPHome firmware (Athom Plug V3)", "Home Assistant OS",
                                       "Home Assistant Supervisor", "Mosquitto (HA add-on)"])
        self.assertEqual(got["Home Assistant Supervisor"]["extra"], {"latest_version": "2026.11.1"})
        self.assertEqual(got["Home Assistant OS"]["extra"], {})
        self.assertEqual(got["Mosquitto (HA add-on)"]["extra"]["addon"], "core_mosquitto")
        self.assertIn("esphome:esphome", got["ESPHome firmware (Athom Plug V3)"]["aliases"])

    def test_addons_off(self):
        _, items = ha_update_items(STATES, addons=False)
        self.assertNotIn("Mosquitto (HA add-on)", {i["name"] for i in items})


if __name__ == "__main__":
    unittest.main()
