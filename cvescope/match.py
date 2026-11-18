"""Match inventory items against CVE records.

Statuses:
  affected      a product entry matched and the installed version is inside an affected range
  check         product matched but the version can't be decided (no version data, free text,
                or a distro package whose fixes may be backported)
  not_affected  product matched, installed version is outside every affected range
  keyword       an old CVE with no product data mentions one of the item's keywords
"""

from __future__ import annotations

import datetime as dt
import functools
import json
import re

from . import db
from .sources.cvelist import _cpe_vp
from .versions import clean, cmp, desc_max, dpkg_cmp, eval_entry, name_pattern, pkg_cmp


def _alias(a: str) -> tuple[str, str, bool]:
    vendor, _, product = a.rpartition(":") if ":" in a else ("*", "", a)
    prefix = product.endswith("*")
    vendor = "*" if vendor.strip() in ("*", "") else db.norm(vendor)
    return vendor, db.norm(product.rstrip("*")), prefix


def _vendor_ok(want: str, got: str) -> bool:
    return want == "*" or not got or got == want or got.startswith(want + " ") or want.startswith(got + " ")


def _prod_ok(alias, product: str) -> bool:
    _, p, prefix = alias
    return product == p or (prefix and product.startswith(p))


def _entry_matches(entry: dict, aliases) -> bool:
    v, p, pkg = db.norm(entry.get("v")), db.norm(entry.get("p")), db.norm(entry.get("pkg"))
    for al in aliases:
        if p and _prod_ok(al, p) and _vendor_ok(al[0], v):
            return True
        if pkg and _prod_ok(al, pkg) and _vendor_ok(al[0], v):
            return True
        for c in entry.get("cpes") or []:
            vp = _cpe_vp(c)
            if vp and _prod_ok(al, db.norm(vp[1])) and _vendor_ok(al[0], db.norm(vp[0])):
                return True
    return False


def _candidates(con, aliases) -> set[str]:
    out = set()
    for al in aliases:
        vendor, product, prefix = al
        if not product:
            continue
        if prefix:
            rows = con.execute("SELECT cve_id, vendor FROM cve_product WHERE product >= ? AND product < ?",
                               (product, product + "￿"))
        else:
            rows = con.execute("SELECT cve_id, vendor FROM cve_product WHERE product = ?", (product,))
        out.update(cid for cid, v in rows if _vendor_ok(vendor, v))
    return out


def _names(item: dict) -> list:
    names = {re.sub(r"\s*\(.*?\)\s*", " ", item["name"]).strip(), item.get("product") or ""}
    names |= {_alias(a)[1] for a in item["aliases"]}
    return [p for p in (name_pattern(n) for n in names if n) if p]


AUTO_UPDATE_DAYS = 365  # an auto-updating app is past any CVE older than this


def _published_days_ago(cve_row) -> int | None:
    try:
        pub = cve_row["published"]
    except (IndexError, KeyError):
        return None
    if not pub:
        return None
    try:
        when = dt.datetime.fromisoformat(pub[:10]).replace(tzinfo=dt.timezone.utc)
    except ValueError:
        return None
    return (dt.datetime.now(dt.timezone.utc) - when).days


def _from_nvd(item: dict, cve_row) -> tuple[str, str, str] | None:
    """NVD CPE ranges (cached by the optional nvd lookup), when they name this product."""
    try:
        raw = cve_row["nvd"]
    except (IndexError, KeyError):
        return None
    ver = clean(item.get("version"))
    if not raw or not ver:
        return None
    aliases = item.setdefault("_aliases", [_alias(a) for a in item["aliases"]])
    hits = [e for e in json.loads(raw)
            if any(_prod_ok(al, db.norm(e["p"])) and _vendor_ok(al[0], db.norm(e["v"])) for al in aliases)]
    affected, decided, fixes = False, False, []
    for e in hits:
        if e["ver"] not in ("*", "-", ""):
            decided = True
            affected |= clean(e["ver"]) is not None and cmp(ver, e["ver"]) == 0
        elif e["ver"] == "*":
            decided = True
            lo = (not e.get("si") or cmp(ver, e["si"]) >= 0) and (not e.get("se") or cmp(ver, e["se"]) > 0)
            hi = (not e.get("ei") or cmp(ver, e["ei"]) <= 0) and (not e.get("ee") or cmp(ver, e["ee"]) < 0)
            affected |= lo and hi
            if e.get("ee") or e.get("ei"):
                fixes.append(e.get("ee") or e.get("ei"))
    if not decided:
        return None
    if affected:
        if (item.get("extra") or {}).get("backports"):
            return "check", "nvd", "NVD: version inside an affected range; distro package, fixes may be backported"
        return "affected", "nvd", "NVD: version inside an affected range"
    top = None
    for f in fixes:
        if top is None or cmp(f, top) > 0:
            top = f
    return "not_affected", "nvd", "NVD: outside every affected range" + (f" (ranges end at {top})" if top else "")


def _from_description(item: dict, cve_row, how: str, reason: str) -> tuple[str, str, str]:
    nvd = _from_nvd(item, cve_row)
    if nvd:
        return nvd
    ver = clean(item.get("version"))
    if ver:
        top = desc_max(cve_row["description"] or "", item.setdefault("_pats", _names(item)))
        if top and cmp(ver, top) > 0:
            return "not_affected", how, f"no version data; the description names versions up to {top}"
    # Browsers, VS Code and the like update themselves within days. A CVE record with no version
    # data that's over a year old is fixed in any build that's still updating.
    if (item.get("extra") or {}).get("auto_updates"):
        age = _published_days_ago(cve_row)
        if age is not None and age > AUTO_UPDATE_DAYS:
            app = re.sub(r"\s*\([^)]*\)$", "", item["name"])
            return ("not_affected", how,
                    f"no version data; {app} updates itself and this CVE is {age // 365} year(s) old")
    return "check", how, reason


def evaluate(item: dict, cve_row) -> tuple[str, str, str]:
    """-> (status, how, reason) for one item against one CVE record."""
    aliases = item.setdefault("_aliases", [_alias(a) for a in item["aliases"]])
    raw = [e for e in json.loads(cve_row["affected"] or "[]") if _entry_matches(e, aliases)]
    # CISA's ADP (and kernel.org) split one product into many entries, one range each.
    # Each alone says "affected by default"; together they describe the whole version line.
    groups: dict[tuple, dict] = {}
    for e in raw:
        k = (e.get("src"), db.norm(e.get("v")), db.norm(e.get("p")))
        g = groups.setdefault(k, {"src": e.get("src"), "v": e.get("v"), "p": e.get("p"), "ds": None,
                                  "vs": [], "cpes": []})
        g["vs"].extend(e.get("vs") or [])
        g["cpes"].extend(e.get("cpes") or [])
        if e.get("vs") and (e.get("ds") or "").lower() in ("affected", "unaffected", "unknown"):
            g["ds"] = "affected" if "affected" in (g["ds"], e["ds"].lower()) else e["ds"].lower()
    entries = list(groups.values())
    if not entries:
        return _from_description(item, cve_row, "kev",
                                 "named by CISA KEV; the CVE record has no version data for it")
    results = [eval_entry(e, item.get("version")) for e in entries]
    how = "cpe" if all(not db.norm(e.get("p")) for e in entries) else "product"
    if any(s == "affected" for s, _ in results):
        reason = next(r for s, r in results if s == "affected")
        if (item.get("extra") or {}).get("backports"):
            return "check", how, reason + "; distro package, fixes may be backported"
        return "affected", how, reason
    decided = [r for s, r in results if s == "unaffected"]
    if decided:  # nothing says affected and at least one entry rules this version out
        return "not_affected", how, decided[0]
    return _from_description(item, cve_row, how,
                             next((r for s, r in results if s == "unknown"), "undecided"))


_RECENT_DAYS = 14  # a distro may not have triaged a CVE this new yet


def _distro_label(release: str) -> str:
    fam, _, ver = release.partition(":")
    return f"{fam.capitalize()} {ver}"


def _apply_distro(con, it: dict, rows: dict) -> None:
    """Let the distro's own tracker decide for distro packages.

    The tracker knows about backported fixes, so its answer replaces the upstream-range guess.
    CVEs it lists for the package are added even if the upstream record didn't name it.
    Upstream matches it doesn't list for this release are treated as not affecting the
    package, unless they're new enough that the distro may not have looked yet.
    """
    ex = it.get("extra") or {}
    release, pkg, pv = ex.get("distro"), ex.get("source") or ex.get("package"), ex.get("package_version")
    if not (release and pkg and pv):
        return
    if not con.execute("SELECT 1 FROM distro_fix WHERE release=? LIMIT 1", (release,)).fetchone():
        return  # no tracker data for this release yet
    label = _distro_label(release)
    listed = {r[0]: (r[1], r[2], r[3]) for r in con.execute(
        "SELECT cve_id, status, fixed, note FROM distro_fix WHERE release=? AND package=?", (release, pkg))}
    known = set()
    ids = list(listed)
    for i in range(0, len(ids), 500):
        chunk = ids[i:i + 500]
        known.update(r[0] for r in con.execute(
            f"SELECT id FROM cve WHERE state='PUBLISHED' AND id IN ({','.join('?' * len(chunk))})", chunk))
    for cve, (status, fixed, note) in listed.items():
        if cve not in known:
            continue
        if status == "fixed":
            if dpkg_cmp(pv, fixed) >= 0:
                rows[(cve, it["id"])] = ("not_affected", "distro", f"{label} fixed it in {fixed}")
            else:
                pro = " (Ubuntu Pro/ESM)" if "esm" in fixed else ""
                rows[(cve, it["id"])] = ("affected", "distro", f"{label} fix {fixed}{pro} is newer than {pv}")
        elif status == "open":
            why = f" ({note})" if note else ""
            rows[(cve, it["id"])] = ("affected", "distro", f"{label} has no fix released yet{why}")
        elif status == "minor":
            rows[(cve, it["id"])] = ("not_affected", "distro", f"{label} rates it unimportant (not patched by design)")
        elif status == "notaff":
            rows[(cve, it["id"])] = ("not_affected", "distro",
                                     f"{label} isn't affected (the tracker marks it not-affected)")
        else:
            why = f" ({note})" if note else ""
            rows[(cve, it["id"])] = ("check", "distro", f"{label} hasn't decided (may need fixing){why}")
    cutoff = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=_RECENT_DAYS)).strftime("%Y-%m-%d")
    stale = [cid for (cid, iid), v in rows.items() if iid == it["id"] and cid not in listed and v[0] == "check"]
    for i in range(0, len(stale), 500):
        chunk = stale[i:i + 500]
        for cid, pub in con.execute(
                f"SELECT id, published FROM cve WHERE id IN ({','.join('?' * len(chunk))})", chunk):
            if (pub or "")[:10] < cutoff:
                rows[(cid, it["id"])] = ("not_affected", "distro",
                                         f"{label} doesn't list it for {pkg} (not affected or not shipped)")


# OPNsense's name for what FreeBSD ports (and so VuXML) call plain "openssl" (the 3.5 LTS)
_PORT_SAME = {"openssl35": "openssl"}
_BASE = re.compile(r"^(\d+\.\d+)-RELEASE(?:-p(\d+))?\b")


def _base_pkgver(v: str) -> str | None:
    """'15.1-RELEASE-p6' -> '15.1_6', the form VuXML uses for the base system."""
    m = _BASE.match(v or "")
    if not m:
        return None
    return m.group(1) + (f"_{m.group(2)}" if m.group(2) else "")


def _no_epoch(v: str) -> str:
    return v.split(",")[0]


def _vuxml_check(ver: str, ranges, alias: bool) -> tuple[bool, str | None]:
    """(version inside a range?, the fix version that applies to it, if one can be named)."""
    fixed = None
    ops = {"lt": lambda c: c < 0, "le": lambda c: c <= 0, "eq": lambda c: c == 0,
           "ge": lambda c: c >= 0, "gt": lambda c: c > 0}
    for r in ranges:
        conds = [(op, _no_epoch(b) if alias else b) for op, b in r if op in ops and b]
        if not conds:
            continue
        if all(ops[op](pkg_cmp(ver, b)) for op, b in conds):
            return True, next((b for op, b in conds if op in ("lt", "le")), None)
        lower_ok = all(ops[op](pkg_cmp(ver, b)) for op, b in conds if op in ("ge", "gt", "eq"))
        if lower_ok:
            fixed = next((b for op, b in conds if op == "lt"), fixed)
    return False, fixed


def _apply_vuxml(con, it: dict, rows: dict) -> None:
    """FreeBSD packages (OPNsense) and FreeBSD base releases: let VuXML decide what it lists.

    A CVE VuXML lists for the package is affected when the installed build is inside one of its
    ranges and not_affected otherwise. VuXML doesn't cover every CVE a port could be hit by, so
    CVEs it doesn't list keep the upstream answer.
    """
    ex = it.get("extra") or {}
    if ex.get("pkgdb") == "freebsd" and ex.get("package") and ex.get("package_version"):
        pkg, ver = ex["package"], ex["package_version"]
        names = [(pkg, False)] + ([(_PORT_SAME[pkg], True)] if pkg in _PORT_SAME else [])
        label = f"FreeBSD VuXML ({pkg})"
    elif ex.get("freebsd_base"):
        ver = _base_pkgver(it.get("version") or "")
        if not ver:
            return
        names = [("FreeBSD", False), ("FreeBSD-kernel", False)]
        label = "FreeBSD VuXML (base system)"
    else:
        return
    found: dict[str, tuple] = {}
    for name, alias in names:
        for cve, ranges, sa in con.execute("SELECT cve_id, ranges, sa FROM vuxml WHERE package=?", (name,)):
            hit, fixed = _vuxml_check(ver, json.loads(ranges), alias)
            prev = found.get(cve)
            if prev is None or (hit and not prev[0]) or (hit == prev[0] and fixed and not prev[1]):
                found[cve] = (hit, fixed, sa)
    if not found:
        return
    ids = list(found)
    known = set()
    for i in range(0, len(ids), 500):
        chunk = ids[i:i + 500]
        known.update(r[0] for r in con.execute(
            f"SELECT id FROM cve WHERE state='PUBLISHED' AND id IN ({','.join('?' * len(chunk))})", chunk))
    for cve, (hit, fixed, sa) in found.items():
        key = (cve, it["id"])
        if cve not in known:
            continue
        adv = f" {sa}" if sa else ""
        if hit:
            fix = f"fixed in {fixed}, " if fixed else ""
            rows[key] = ("affected", "vuxml", f"{label}{adv}: {fix}installed {ver}")
        elif key in rows:  # only overrule an upstream match; don't add thousands of old misses
            why = f"fixed in {fixed}" if fixed else "outside the affected versions"
            rows[key] = ("not_affected", "vuxml", f"{label}{adv}: {why}, installed {ver}")


def _starts_later(a: str, b: str) -> bool:
    """Does an interval introduced at a start at or after one introduced at b? "0" is the start."""
    if b == "0":
        return True
    return a != "0" and cmp(a, b) >= 0


def _osv_check(ver: str, ranges) -> tuple[bool | None, str | None]:
    """OSV events (introduced / fixed / last_affected) against a version.

    -> (inside an affected interval?, the fix for the release line the version is on).
    None when there are no ranges. On "not affected" the fix is that of the closest interval
    below the version, so the reason can say "fixed in 4.19.2".
    """
    if not ranges:
        return None, None
    below = None  # (introduced, fixed) of the highest interval the version is past
    for evs in ranges:
        intro = None
        for k, val in evs:
            if k == "introduced":
                intro = val
            elif k in ("fixed", "last_affected") and intro is not None:
                lo = intro == "0" or cmp(ver, intro) >= 0
                hi = cmp(ver, val) < 0 if k == "fixed" else cmp(ver, val) <= 0
                if lo and hi:
                    return True, val if k == "fixed" else None
                if lo and k == "fixed" and (below is None or _starts_later(intro, below[0])):
                    below = (intro, val)
                intro = None
        if intro is not None and (intro == "0" or cmp(ver, intro) >= 0):
            return True, None  # introduced and never fixed
    return False, below[1] if below else None


def _osv_in_ranges(ver: str, ranges) -> bool | None:
    return _osv_check(ver, ranges)[0]


def _apply_osv(con, it: dict, rows: dict) -> None:
    """Items that name an OSV package (Home Assistant Core): the vendor's advisories decide.

    Every CVE an advisory names gets a row: affected when the installed release is one the
    advisory lists, not_affected otherwise. That also settles keyword-only matches the
    advisories cover. CVEs no advisory names keep the upstream answer.
    """
    ex = it.get("extra") or {}
    o, ver = ex.get("osv"), str(it.get("version") or "")
    if not (isinstance(o, dict) and ver):
        return
    found: dict[str, tuple] = {}
    for cve, oid, versions, ranges, fixed in con.execute(
            "SELECT cve_id, osv_id, versions, ranges, fixed FROM osv_pkg WHERE ecosystem=? AND package=?",
            (o.get("ecosystem"), o.get("name"))):
        vs = json.loads(versions or "[]")
        in_range, line_fix = _osv_check(ver.lstrip("v") if o.get("ecosystem") == "Go" else ver, json.loads(ranges or "[]"))
        listed = ver in vs or ver.lstrip("v") in vs
        if in_range is None and not vs:
            continue
        hit = listed or bool(in_range)
        fixed = line_fix or (fixed if hit or in_range is None else None)
        prev = found.get(cve)
        if prev is None or (hit and not prev[0]) or \
                (hit == prev[0] and oid.startswith("GHSA") and not prev[1].startswith("GHSA")):
            found[cve] = (hit, oid, fixed)
    if not found:
        return
    ids = list(found)
    known = {r[0] for r in con.execute(
        f"SELECT id FROM cve WHERE state='PUBLISHED' AND id IN ({','.join('?' * len(ids))})", ids)}
    label = o.get("label") or f"OSV {o.get('ecosystem')} {o.get('name')}"
    latest = ex.get("latest_version")
    for cve, (hit, oid, fixed) in found.items():
        if cve not in known:
            continue
        if hit:
            fix = f"fixed in {fixed}, " if fixed else ""
            offer = f"; update available: {latest}" if latest and latest != ver else ""
            rows[(cve, it["id"])] = ("affected", "osv", f"{label} {oid}: {fix}installed {ver}{offer}")
        else:
            why = f"fixed in {fixed}" if fixed else "outside the affected releases"
            rows[(cve, it["id"])] = ("not_affected", "osv", f"{label} {oid}: {why}, installed {ver}")


_PVE_KERNEL = re.compile(r"^(\d+\.\d+)\.(\d+)-(\d+)")


def _pve_kernel(release: str | None) -> tuple[str, str] | None:
    """'7.0.14-28-pve' -> ('kernel:7.0', '7.0.14-28'): the series key PSAs use, and the build."""
    m = _PVE_KERNEL.match(release or "")
    return (f"kernel:{m.group(1)}", f"{m.group(1)}.{m.group(2)}-{m.group(3)}") if m else None


def _major(v: str) -> int | None:
    m = re.match(r"(\d+)", v.split(":", 1)[-1])
    return int(m.group(1)) if m else None


def _psa_fix(inst: str, fixes: list[tuple[str, int | None]], line: int | None = None,
             newer_ok: bool = True) -> tuple[str, bool] | None:
    """(the fix that applies to an installed build, is the build older than it?), or None.

    fixes are (version, Proxmox VE release line or None). An advisory can list one fix per
    line (pve-manager 8.2.7 for PVE 8, 7.4-19 for PVE 7), and a package's version scheme can
    change between lines, so fixes tagged for another line are set aside first. If none are
    left and the whole advisory only fixes older lines (newer_ok), the host's line came out
    after it and isn't affected; if the advisory does fix the host's line, just under another
    package name, it can't be told. Among the rest, the fix with the installed build's own
    major version decides.
    """
    key = functools.cmp_to_key(dpkg_cmp)
    if line is not None:
        ours = [v for v, ln in fixes if ln in (None, line)]
        if not ours:
            older = [v for v, ln in fixes if ln is not None and ln < line]
            ok = newer_ok and older and len(older) == len(fixes)
            return (max(older, key=key), False) if ok else None
        fixes = [(v, None) for v in ours]
    fixes = [v for v, _ in fixes]
    mine = _major(inst)
    same = [f for f in fixes if _major(f) == mine]
    if same:
        fix = min(same, key=key)
        return fix, dpkg_cmp(inst, fix) < 0
    if mine is not None and fixes and all((_major(f) or 0) < mine for f in fixes):
        return max(fixes, key=key), False
    return None


def _psa_targets(ex: dict) -> tuple[dict[str, str], dict[str, str]]:
    """(package -> installed build, kernel series -> newest installed build) an item stands for."""
    # pve_major (the host's release line) comes along separately, see _apply_psa
    if ex.get("pve_pkg") == "kernel":
        k = _pve_kernel(ex.get("running"))
        return ({k[0]: k[1]} if k else {}), ex.get("kernel_installed") or {}
    if ex.get("pve_pkg"):
        v = ex.get("package_version")
        return ({ex["pve_pkg"]: v} if v else {}), {}
    pkgs = ex.get("pve_packages") or {}
    split = set(ex.get("pve_split") or [])
    out = {n: v for n, v in pkgs.items() if n not in split}
    kernels = {}
    if pkgs and "kernel" not in split:
        k = _pve_kernel(ex.get("running_kernel"))
        if k:
            out[k[0]] = k[1]
        for n, v in pkgs.items():
            m = re.fullmatch(r"proxmox-kernel-(\d+\.\d+)", n)
            if m:
                kernels[m.group(1)] = v
    return out, kernels


def _apply_psa(con, it: dict, rows: dict) -> None:
    """Proxmox hosts: Proxmox's own advisories (PSAs) decide the CVEs they name.

    For an advisory that fixes a package this item stands for (a host's Proxmox packages, or its
    QEMU / LXC / kernel item): affected when the installed build is older than the fix for its
    line, not_affected otherwise. Kernels compare per series against the RUNNING kernel, so a
    fixed kernel that's installed but not booted yet still counts, with a note to reboot.
    """
    ex = it.get("extra") or {}
    targets, kernels = _psa_targets(ex)
    if not targets:
        return
    line = ex.get("pve_major")
    found: dict[str, tuple] = {}
    for pid, rev, cves, fixed in con.execute("SELECT id, rev, cves, fixed FROM psa"):
        by_pkg: dict[str, list[tuple]] = {}
        for f in json.loads(fixed or "[]"):
            pkg, ver, ln = (list(f) + [None])[:3]
            by_pkg.setdefault(pkg, []).append((ver, ln))
        # does this advisory fix anything on the host's own release line (or untagged)?
        newer_ok = line is not None and all(
            ln is not None and ln < line
            for pkg, fx in by_pkg.items() if not pkg.startswith("kernel:") for _, ln in fx)
        for pkg, inst in targets.items():
            if pkg not in by_pkg:
                continue
            # kernels are matched by series already; release-line tags only matter for packages
            got = _psa_fix(inst, by_pkg[pkg], None if pkg.startswith("kernel:") else line, newer_ok)
            if got is None:
                continue
            fix, hit = got
            fix_line = next((ln for v, ln in by_pkg[pkg] if v == fix), None)
            other_line = fix_line if (line and fix_line and fix_line != line and not pkg.startswith("kernel:")) else None
            for cve in json.loads(cves or "[]") or [pid]:  # no CVE: the PSA is the finding
                prev = found.get(cve)
                if prev is None or (hit and not prev[0]):
                    found[cve] = (hit, f"{pid}-{rev}", pkg, fix, inst, other_line)
    if not found:
        return
    ids = list(found)
    known = {r[0] for r in con.execute(
        f"SELECT id FROM cve WHERE state='PUBLISHED' AND id IN ({','.join('?' * len(ids))})", ids)}
    for cve, (hit, psa, pkg, fix, inst, other_line) in found.items():
        if cve not in known:
            continue
        kernel = pkg.startswith("kernel:")
        name = f"proxmox-kernel-{pkg.split(':', 1)[1]}" if kernel else pkg
        on = f" for Proxmox VE {other_line}" if other_line else ""  # a fix on an older release line
        why = f"Proxmox {psa}: fixed in {name} {fix}{on}, {'running' if kernel else 'installed'} {inst}"
        if hit and kernel:
            have = kernels.get(pkg.split(":", 1)[1])
            if have and dpkg_cmp(have, fix) >= 0:
                why += f"; {have} is already installed: reboot to run it"
        rows[(cve, it["id"])] = ("affected" if hit else "not_affected", "psa", why)


def run(con, cfg) -> str:
    items = []
    for r in con.execute("SELECT * FROM item"):
        d = dict(r)
        d["aliases"] = json.loads(d["aliases"] or "[]")
        d["keywords"] = json.loads(d["keywords"] or "[]")
        d["extra"] = json.loads(d["extra"] or "{}")
        items.append(d)
    if not items:
        return "no inventory items (add [[inventory]] entries to the config)"

    old = {(r["cve_id"], r["item_id"]): dict(r) for r in con.execute("SELECT * FROM match")}
    first_run = db.meta_get(con, "match_done") is None
    t = db.now()
    new_rows: dict[tuple, tuple] = {}

    for it in items:
        aliases = [_alias(a) for a in it["aliases"]]
        cands = _candidates(con, aliases)
        for i in range(0, len(cands), 500):
            chunk = list(cands)[i:i + 500]
            q = (f"SELECT c.id, c.affected, c.description, c.published, n.cpes AS nvd FROM cve c "
                 f"LEFT JOIN nvd_cpe n ON n.cve_id = c.id WHERE c.state='PUBLISHED' "
                 f"AND c.id IN ({','.join('?' * len(chunk))})")
            for row in con.execute(q, chunk):
                status, how, reason = evaluate(it, row)
                new_rows[(row["id"], it["id"])] = (status, how, reason)
        _apply_distro(con, it, new_rows)
        _apply_vuxml(con, it, new_rows)
        _apply_osv(con, it, new_rows)
        _apply_psa(con, it, new_rows)

    # keyword pass: only CVEs whose record names no product at all (mostly pre-2023 "n/a")
    kw_items = [(it, re.compile(r"\b(?:" + "|".join(re.escape(k) for k in it["keywords"]) + r")\b", re.I))
                for it in items if it["keywords"]]
    if kw_items:
        for cid, desc in con.execute("SELECT id, description FROM cve WHERE noprod=1 AND state='PUBLISHED'"):
            if not desc:
                continue
            for it, rx in kw_items:
                if (cid, it["id"]) not in new_rows and rx.search(desc):
                    new_rows[(cid, it["id"])] = ("keyword", "keyword", "description mentions " + rx.search(desc).group(0))

    con.execute("DELETE FROM match")
    rows = []
    for (cid, iid), (status, how, reason) in new_rows.items():
        prev = old.get((cid, iid))
        live = status in ("affected", "check", "keyword")
        was_live = prev is not None and prev["status"] in ("affected", "check", "keyword")
        first = prev["first_seen"] if prev and was_live == live else t
        rows.append((cid, iid, status, how, reason, first))
        if not first_run and live and not was_live:
            db.add_event(con, cid, "match", {"item": iid, "status": status})
        if not first_run and was_live and not live:
            db.add_event(con, cid, "resolved", {"item": iid, "status": status})
    for (cid, iid), prev in old.items():
        if (cid, iid) not in new_rows and prev["status"] in ("affected", "check") and \
                any(i["id"] == iid for i in items):
            db.add_event(con, cid, "resolved", {"item": iid, "status": "gone"})
    con.executemany("INSERT INTO match VALUES(?,?,?,?,?,?)", rows)
    con.commit()
    db.meta_set(con, "match_done", t)
    counts = {}
    for r in rows:
        counts[r[2]] = counts.get(r[2], 0) + 1
    found = ", ".join(f"{v} {k}" for k, v in sorted(counts.items()))
    if not found and not con.execute("SELECT 1 FROM cve LIMIT 1").fetchone():
        found = "no matches (no CVE records yet: run `cvescope sync` with cvelist enabled)"
    return f"{len(items)} items: " + (found or "no matches")
