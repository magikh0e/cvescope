"""Vulnerability IDs: CVE IDs, and advisory IDs for issues that never got one.

Most findings are keyed by CVE ID. Some real issues have none: many GitHub advisories for
npm/PyPI/Maven packages (GHSA-...), most Proxmox advisories (PSA-...), and other OSV.dev
entries (PYSEC-, GO-, RUSTSEC-, MAL- for malicious packages, ...). Those are stored and shown
under their own ID, in the same tables as CVEs.
"""

from __future__ import annotations

import re

# after canon(): CVE-2024-1234, GHSA-xxxx-xxxx-xxxx (lowercase tail), PSA-2026-00094, MAL-2024-123, ...
VULN_ID = re.compile(r"^(?:CVE-\d{4}-\d{4,7}|GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}|PSA-\d{4}-\d{3,6}|"
                     r"(?!CVE-|GHSA-|PSA-)[A-Z][A-Z0-9]{1,9}-[A-Z0-9][A-Z0-9._:-]{0,59})$")
PREFIX = re.compile(r"^(?:CVE|GHSA|PSA|PYSEC|GO|RUSTSEC|MAL|OSV|GSD|RXSA|BIT|UVI|CGA|ALSA|RHSA)-", re.I)


def canon(s) -> str:
    """How an ID is spelled in the database: upper case, except GHSA's lowercase tail."""
    s = str(s or "").strip()
    if s[:5].upper() == "GHSA-":
        return "GHSA-" + s[5:].lower()
    return s.upper()


def valid(s) -> bool:
    return bool(VULN_ID.match(canon(s)))


def is_cve(s) -> bool:
    return canon(s).startswith("CVE-")


def pick(ids) -> str | None:
    """The ID to file an advisory under when it has no CVE: its GHSA if any, else its own."""
    ids = [canon(i) for i in ids if i]
    return next((i for i in ids if i.startswith("GHSA-")), ids[0] if ids else None)
