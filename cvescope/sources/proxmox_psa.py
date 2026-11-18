"""Proxmox VE security advisories (PSAs): fixed package versions, from Proxmox's forum thread.

Proxmox publishes its advisories only as posts in one forum thread, each in the same layout:

  Subject: PSA-2026-00080-1: kernel TCP Use-After-Free
  Advisory date: 2026-10-31
  Packages: proxmox-kernel-*
  Fixed in: proxmox-kernel-7.0.14-25-pve(-signed)      or   - pve-container >= 6.1.17
  References: CVE-2026-98432

The Proxmox collector records the exact package builds and the running kernel of each host
(the API's apt/versions list), and the matcher compares them with these fixes. The first sync
reads the whole thread; later ones read only the last page and anything after it.
"""

from __future__ import annotations

import html
import json
import re
import time

from .. import db, net

THREAD = "https://forum.proxmox.com/threads/proxmox-virtual-environment-security-advisories.149331/"
POST_URL = "https://forum.proxmox.com/posts/{}/"

_LABELS = (r"(?:Subject|Advisory date|Packages?|Package\(s\)|Details|Fixed in|Fixed|Not Fixed|"
           r"References|Workaround|Mitigation|Credits?)")
_LABEL_LINE = re.compile(r"\s*(" + _LABELS + r")\s*:\s*(.*)$")
_SUBJECT = re.compile(r"Subject:\s*(PSA-(\d{4})-(\d+)-(\d+))\s*:?\s*(.*)")
_KERNEL = re.compile(r"(?:proxmox|pve)-kernel-(\d+\.\d+)\.(\d+)-(\d+)-pve")
_GE = re.compile(r"([a-z0-9][a-z0-9.+\-]*?)\s*>=\s*([0-9][\w.:~+\-]*)", re.I)
_PLAIN = re.compile(r"^-?\s*([a-z][a-z0-9.+\-]*?)\s+([0-9][\w.:~+\-]*)(?:\s|$)", re.I)
_SIGNATURE = re.compile(r"^(ProxmoxSecurityAdvisory|Like|Reply|Report|Staff member)$")
# which Proxmox VE release line a fix is for: "(PVE 9.x)", "(Proxmox VE 7.x)", "in Proxmox VE 8",
# "(Bookworm based products)", or a Debian backport suffix in the version itself (~bpo12 = PVE 8)
_LINE = re.compile(r"(?<![\w.+~\-])(?:Proxmox VE|Proxmox Virtual Environment|PVE)\s*(\d+)", re.I)  # not "-pve2"
_CODENAME = {"buster": 6, "bullseye": 7, "bookworm": 8, "trixie": 9, "forky": 10}
_OTHER_PRODUCT = re.compile(r"\b(?:Proxmox Mail Gateway|PMG|Proxmox Backup Server|PBS|"
                            r"Proxmox Datacenter Manager|PDM)\b", re.I)
_PVE_NAMED = re.compile(r"\b(?:Proxmox VE|Proxmox Virtual Environment)\b|(?<![\w.+~\-])PVE\b", re.I)
PARSER = 2  # bump when parsing changes, so the next sync re-reads the whole thread


def page_url(n: int) -> str:
    return THREAD if n <= 1 else f"{THREAD}page-{n}"


def last_page(raw: str) -> int:
    return max([int(n) for n in re.findall(r"/page-(\d+)", raw)] + [1])


def _text(raw: str) -> str:
    s = re.sub(r"<br\s*/?>", "\n", raw)
    s = re.sub(r"<(script|style)\b.*?</\1>", "", s, flags=re.S)
    s = re.sub(r"<[^>]+>", "\n", s)
    s = html.unescape(s).replace("​", "").replace("\xa0", " ")
    s = re.sub(r"[ \t]+", " ", s)
    s = re.sub(r"\n\s*\n+", "\n", s)
    # older posts put the colon on its own line: "Advisory date\n: 2026-08-10"
    return re.sub(r"(" + _LABELS + r")\s*\n\s*:", r"\1:", s)


def _sections(block: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    cur = None
    for line in block.split("\n"):
        m = _LABEL_LINE.match(line)
        if m:
            cur = m.group(1).lower()
            cur = {"fixed in": "fixed", "package": "packages", "package(s)": "packages"}.get(cur, cur)
            out.setdefault(cur, [])
            if m.group(2).strip():
                out[cur].append(m.group(2).strip())
        elif cur and line.strip():
            if _SIGNATURE.match(line.strip()):
                cur = None
            else:
                out[cur].append(line.strip())
    return out


def _line_of(text: str) -> int | None:
    """The Proxmox VE release line a piece of text names, if any."""
    m = _LINE.search(text)
    if m:
        return int(m.group(1))
    for name, n in _CODENAME.items():
        if re.search(rf"\b{name}\b", text, re.I):
            return n
    m = re.search(r"~bpo(\d+)", text)
    return int(m.group(1)) - 4 if m else None  # Debian 12 backport = Proxmox VE 8


def fixes(lines: list[str]) -> list[list]:
    """'Fixed in' lines -> [[package, version, release line or None], ...].

    Kernels come out as ['kernel:7.0', '7.0.14-25', line]. A header line such as "- Proxmox VE 8:"
    sets the line for the fixes under it; fixes under another product (Mail Gateway, Backup
    Server) are skipped.
    """
    out, ctx, other = [], None, False
    for line in lines:
        bare = line.strip().lstrip("-").strip()
        if bare.endswith(":") and not _GE.search(bare) and not _KERNEL.search(bare):
            # "- Proxmox Mail Gateway 8:" is another product's list; "For Trixie based releases,
            # like Proxmox VE 9, Proxmox Backup Server 4 ...:" is ours
            other = bool(_OTHER_PRODUCT.search(bare)) and not _PVE_NAMED.search(bare)
            ctx = None if other else _line_of(bare)
            continue
        if other:
            continue
        ks = list(_KERNEL.finditer(line))
        for m in ks:
            out.append([f"kernel:{m.group(1)}", f"{m.group(1)}.{m.group(2)}-{m.group(3)}", _line_of(line) or ctx])
        if ks:
            continue
        found = [(m.group(1), m.group(2)) for m in _GE.finditer(line)]
        if not found:
            m = _PLAIN.match(line)
            found = [(m.group(1), m.group(2))] if m else []
        for pkg, ver in found:
            if not (pkg[:1].isalpha() and pkg == pkg.lower()):  # "PVE 9.0", "9.0 >= ...": prose
                continue
            ver = ver.rstrip(".,)")
            km = re.fullmatch(r"(?:proxmox|pve)-kernel-(\d+\.\d+)", pkg)
            here = _line_of(line.replace(ver, "")) or _line_of(ver) or ctx
            out.append([f"kernel:{km.group(1)}" if km else pkg, ver, here])
    return out


def parse_post(text: str, url: str | None = None) -> list[dict]:
    """One post's text -> its advisories (normally one)."""
    out = []
    for blk in re.split(r"(?=Subject:\s*PSA-)", text)[1:]:
        blk = blk[:6000]
        head = _SUBJECT.match(blk)
        if not head:
            continue
        sec = _sections(blk)
        date = next(iter(re.findall(r"\d{4}-\d{2}-\d{2}", " ".join(sec.get("advisory date", [])))), None)
        sig = blk.find("ProxmoxSecurityAdvisory")
        cves = sorted(set(re.findall(r"CVE-\d{4}-\d{4,}", blk[:sig] if sig > 0 else blk)))
        out.append({"id": f"PSA-{head.group(2)}-{head.group(3)}", "rev": int(head.group(4)),
                    "full_id": head.group(1), "title": " ".join(head.group(5).split())[:200],
                    "date": date, "cves": cves, "fixed": fixes(sec.get("fixed", [])), "url": url})
    return out


def parse_page(raw: str) -> list[dict]:
    """A thread page -> advisories, each with a link to its post."""
    marks = list(re.finditer(r'data-content="post-(\d+)"', raw))
    out = []
    for i, m in enumerate(marks):
        end = marks[i + 1].start() if i + 1 < len(marks) else len(raw)
        out += parse_post(_text(raw[m.start():end]), POST_URL.format(m.group(1)))
    return out


def wanted(con) -> bool:
    for (extra,) in con.execute("SELECT extra FROM item"):
        ex = json.loads(extra or "{}")
        if ex.get("pve_packages") or ex.get("pve_pkg"):
            return True
    return False


def store(con, psas: list[dict]) -> None:
    con.executemany(
        "INSERT INTO psa(id, rev, date, title, cves, fixed, url) VALUES(?,?,?,?,?,?,?) "
        "ON CONFLICT(id) DO UPDATE SET rev=excluded.rev, date=excluded.date, title=excluded.title, "
        "cves=excluded.cves, fixed=excluded.fixed, url=excluded.url WHERE excluded.rev >= psa.rev",
        [(p["id"], p["rev"], p["date"], p["title"], json.dumps(p["cves"]), json.dumps(p["fixed"]), p["url"])
         for p in psas])


def sync(con, cfg) -> str:
    if not wanted(con):
        return "no Proxmox hosts with package data in the inventory"
    name = "proxmox"
    src = db.source_get(con, name)
    st = src["state"]
    start = int(st.get("last_page") or 1) if st.get("parser") == PARSER else 1
    raw, _ = net.get(page_url(start), timeout=120)
    psas = parse_page(raw.decode("utf-8", "replace"))
    last = max(start, last_page(raw.decode("utf-8", "replace")))
    for n in range(start + 1, last + 1):  # the whole thread on the first run, new pages after
        time.sleep(1)
        raw, _ = net.get(page_url(n), timeout=120)
        psas += parse_page(raw.decode("utf-8", "replace"))
    if not psas:
        raise RuntimeError("no advisories found in the thread: has the forum's layout changed?")
    if start == 1:
        con.execute("DELETE FROM psa")  # a full read replaces everything
    store(con, psas)
    con.commit()
    db.source_ok(con, name, {"last_page": last, "parser": PARSER})
    total, with_cve = con.execute(
        "SELECT count(*), sum(cves != '[]') FROM psa").fetchone()
    return f"{total} advisories ({with_cve or 0} name CVEs), read {last - start + 1} page(s)"
