"""SQLite store. One file, WAL mode, safe to read from the web server while a sync runs."""

from __future__ import annotations

import datetime as dt
import json
import re
import sqlite3
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT);

CREATE TABLE IF NOT EXISTS source(
  name TEXT PRIMARY KEY, last_ok TEXT, last_try TEXT, last_error TEXT,
  etag TEXT, state TEXT);

CREATE TABLE IF NOT EXISTS cve(
  id TEXT PRIMARY KEY, state TEXT, assigner TEXT, published TEXT, updated TEXT,
  title TEXT, description TEXT,
  cvss REAL, cvss_version TEXT, cvss_vector TEXT, severity TEXT, cwe TEXT,
  ssvc_exploitation TEXT, ssvc_automatable TEXT, ssvc_impact TEXT,
  noprod INTEGER DEFAULT 0, affected TEXT, refs TEXT);

-- normalized vendor/product pairs per CVE (from CNA + ADP affected[], CPEs, KEV)
CREATE TABLE IF NOT EXISTS cve_product(
  cve_id TEXT, vendor TEXT, product TEXT,
  PRIMARY KEY(cve_id, vendor, product)) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS ix_cp_product ON cve_product(product, vendor);

-- one row per piece of exploitation evidence: kev, msf, nuclei, edb, poc, local
CREATE TABLE IF NOT EXISTS signal(
  cve_id TEXT, source TEXT, key TEXT, first_seen TEXT, last_seen TEXT, data TEXT,
  PRIMARY KEY(cve_id, source, key)) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS ix_signal_src ON signal(source, first_seen);

CREATE TABLE IF NOT EXISTS epss(
  cve_id TEXT PRIMARY KEY, score REAL, pct REAL, prev_pct REAL, date TEXT) WITHOUT ROWID;

-- distro security trackers: per release + source package, is the CVE fixed and in which version
-- release looks like "debian:12" or "ubuntu:noble"
-- status: fixed | open | maybe | minor (won't be patched, rated unimportant) | notaff (never affected)
-- note: why an open one has no update yet (Debian: no DSA planned, postponed, next point release)
CREATE TABLE IF NOT EXISTS distro_fix(
  release TEXT, package TEXT, cve_id TEXT, status TEXT, fixed TEXT, note TEXT,
  PRIMARY KEY(release, package, cve_id)) WITHOUT ROWID;

-- FreeBSD VuXML (what `pkg audit` reads): affected version ranges per package name and CVE.
-- ranges is JSON: [[["ge","14.1"],["lt","14.1_6"]], ...]; sa names the FreeBSD advisory if any
CREATE TABLE IF NOT EXISTS vuxml(
  package TEXT, cve_id TEXT, vid TEXT, ranges TEXT, topic TEXT, sa TEXT,
  PRIMARY KEY(package, cve_id, vid)) WITHOUT ROWID;

-- OSV.dev advisories for packages an item names (Home Assistant Core = PyPI homeassistant):
-- the releases each advisory affects (versions, JSON list) and its ranges as a fallback
CREATE TABLE IF NOT EXISTS osv_pkg(
  ecosystem TEXT, package TEXT, cve_id TEXT, osv_id TEXT, versions TEXT, ranges TEXT, fixed TEXT,
  PRIMARY KEY(ecosystem, package, cve_id, osv_id)) WITHOUT ROWID;

-- Proxmox security advisories (PSA posts in Proxmox's forum thread): fixed package builds.
-- id is the base id (PSA-2026-00080), rev the latest revision seen; fixed is JSON
-- [[package, version], ...] with kernels as ["kernel:7.0", "7.0.14-25"]
CREATE TABLE IF NOT EXISTS psa(
  id TEXT PRIMARY KEY, rev INTEGER, date TEXT, title TEXT, cves TEXT, fixed TEXT, url TEXT) WITHOUT ROWID;

-- optional NVD CPE ranges for CVEs the CVE List can't settle (see sources/nvd.py)
CREATE TABLE IF NOT EXISTS nvd_cpe(
  cve_id TEXT PRIMARY KEY, fetched TEXT, status TEXT, cpes TEXT) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS item(
  id TEXT PRIMARY KEY, name TEXT, vendor TEXT, product TEXT, version TEXT,
  collector TEXT, aliases TEXT, keywords TEXT, extra TEXT, seen TEXT, error TEXT);

CREATE TABLE IF NOT EXISTS match(
  cve_id TEXT, item_id TEXT, status TEXT, how TEXT, detail TEXT, first_seen TEXT,
  PRIMARY KEY(cve_id, item_id)) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS ix_match_item ON match(item_id);

-- "I've dealt with this one": hides a match until it expires or the evidence gets worse (acks.py)
CREATE TABLE IF NOT EXISTS ack(
  cve_id TEXT, item_id TEXT, created TEXT, until TEXT, note TEXT, evidence TEXT,
  PRIMARY KEY(cve_id, item_id)) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS event(
  id INTEGER PRIMARY KEY, ts TEXT, cve_id TEXT, kind TEXT, detail TEXT,
  baseline INTEGER DEFAULT 0, notified INTEGER DEFAULT 0);
CREATE INDEX IF NOT EXISTS ix_event_ts ON event(ts);
CREATE INDEX IF NOT EXISTS ix_event_cve ON event(cve_id);
"""


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def connect(path: Path | str) -> sqlite3.Connection:
    con = sqlite3.connect(str(path), timeout=60)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA synchronous=NORMAL")
    con.execute("PRAGMA foreign_keys=OFF")
    con.executescript(SCHEMA)
    _migrate(con)
    return con


def _migrate(con) -> None:
    """Columns added after a release. CREATE TABLE IF NOT EXISTS won't add them to an old file."""
    cols = {r[1] for r in con.execute("PRAGMA table_info(distro_fix)")}
    if "note" not in cols:
        con.execute("ALTER TABLE distro_fix ADD COLUMN note TEXT")


_NORM = re.compile(r"[^a-z0-9]+")


def norm(s) -> str:
    """Lowercase, punctuation/underscores to single spaces. 'Pi-hole' -> 'pi hole'."""
    if not s:
        return ""
    s = _NORM.sub(" ", str(s).lower()).strip()
    return "" if s in ("n a", "na", "unknown", "unspecified", "") else s


# ---- source bookkeeping -------------------------------------------------

def source_get(con, name: str) -> dict:
    r = con.execute("SELECT * FROM source WHERE name=?", (name,)).fetchone()
    if not r:
        return {"name": name, "state": {}, "etag": None, "last_ok": None}
    d = dict(r)
    d["state"] = json.loads(d["state"] or "{}")
    return d


def source_ok(con, name: str, state: dict | None = None, etag: str | None = None):
    t = now()
    con.execute(
        "INSERT INTO source(name,last_ok,last_try,last_error,etag,state) VALUES(?,?,?,NULL,?,?) "
        "ON CONFLICT(name) DO UPDATE SET last_ok=excluded.last_ok, last_try=excluded.last_try, "
        "last_error=NULL, etag=COALESCE(excluded.etag, source.etag), "
        "state=COALESCE(excluded.state, source.state)",
        (name, t, t, etag, json.dumps(state) if state is not None else None),
    )
    con.commit()


def source_err(con, name: str, err: str):
    t = now()
    con.execute(
        "INSERT INTO source(name,last_try,last_error) VALUES(?,?,?) "
        "ON CONFLICT(name) DO UPDATE SET last_try=excluded.last_try, last_error=excluded.last_error",
        (name, t, err[:500]),
    )
    con.commit()


def is_baseline(con, name: str) -> bool:
    """True until a source has completed once: its first load records events silently."""
    return source_get(con, name).get("last_ok") is None


# ---- signals + events ---------------------------------------------------

def upsert_signals(con, source: str, rows, baseline: bool, event_kind: str | None = None) -> int:
    """rows: iterable of (cve_id, key, data_dict). Returns number of new signals."""
    t = now()
    existing = {
        (r[0], r[1]) for r in con.execute("SELECT cve_id, key FROM signal WHERE source=?", (source,))
    }
    new_rows, upd_rows, events = [], [], []
    for cve_id, key, data in rows:
        payload = json.dumps(data, separators=(",", ":"))
        if (cve_id, key) in existing:
            upd_rows.append((t, payload, cve_id, source, key))
        else:
            existing.add((cve_id, key))
            new_rows.append((cve_id, source, key, t, t, payload))
            if event_kind and not baseline:  # a feed's first load is history, not news
                events.append((t, cve_id, event_kind, payload, 0))
    con.executemany("INSERT INTO signal VALUES(?,?,?,?,?,?)", new_rows)
    con.executemany(
        "UPDATE signal SET last_seen=?, data=? WHERE cve_id=? AND source=? AND key=?", upd_rows
    )
    con.executemany(
        "INSERT INTO event(ts,cve_id,kind,detail,baseline) VALUES(?,?,?,?,?)", events
    )
    con.commit()
    return len(new_rows)


def add_event(con, cve_id: str, kind: str, detail: dict, baseline: bool = False):
    con.execute(
        "INSERT INTO event(ts,cve_id,kind,detail,baseline) VALUES(?,?,?,?,?)",
        (now(), cve_id, kind, json.dumps(detail, separators=(",", ":")), 1 if baseline else 0),
    )


def meta_get(con, key: str, default=None):
    r = con.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
    return json.loads(r[0]) if r else default


def meta_set(con, key: str, value):
    con.execute(
        "INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (key, json.dumps(value)),
    )
    con.commit()
