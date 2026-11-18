"""Version comparison and CVE 5.x affected[] evaluation.

Good enough for appliance and app versions (8.2.4, 2026.11.1, v6.5, 1.0.2k, 2.0rc1, 9.6p1).
Not a distro-package comparator: Debian/Ubuntu backports are flagged by the collector instead.
"""

from __future__ import annotations

import functools
import re

_TOK = re.compile(r"\d+|[a-z]+")
_PRE = {"dev": -4, "snapshot": -4, "alpha": -3, "beta": -2, "pre": -2, "preview": -2, "rc": -1}
_BLANK = {"", "*", "-", "n/a", "na", "unspecified", "unknown", "all", "all versions", "0"}


def clean(v) -> str | None:
    if v is None:
        return None
    s = str(v).strip().lower()
    s = re.sub(r"^(version|ver\.?|release|v)\s*", "", s)
    s = s.split("+")[0].strip()  # build metadata
    if s in _BLANK or not s[:1].isdigit():
        return None
    return s


_ONE = re.compile(r"\d+(?:\.\d+)+[a-z]?\d*(?:p\d+)?")


def _single(v) -> str | None:
    """An exact version, also from 'openssl-1.1.0a' or 'Affects OpenSSL 3.0.4' (one version, no range words)."""
    c = clean(v)
    if c:
        return c
    s = str(v or "").lower()
    found = _ONE.findall(s)
    if len(found) == 1 and not re.search(r"<|>|before|prior|through|later|earlier|since|after|below|above", s):
        return found[0]
    return None


def key(v: str) -> list[tuple]:
    out: list[tuple] = []
    for t in _TOK.findall(v):
        if t.isdigit():
            out.append((3, int(t)))
        elif t in _PRE:
            out.append((0, _PRE[t]))
        else:
            out.append((2, t))  # post-release letter: 1.0.2k, 9.6p1
    return out


def cmp(a: str, b: str) -> int:
    ka, kb = key(clean(a) or a.lower()), key(clean(b) or b.lower())
    for i in range(max(len(ka), len(kb))):
        x = ka[i] if i < len(ka) else None
        y = kb[i] if i < len(kb) else None
        # a missing token equals a trailing zero, beats a pre-release, loses to a letter
        if x is None:
            x = (3, 0) if y[0] == 3 else (1, "")
        if y is None:
            y = (3, 0) if x[0] == 3 else (1, "")
        if x != y:
            return -1 if x < y else 1
    return 0


# free-text ranges some CNAs put in "version": "< 2.3", "before 1.4.2", "1.0 - 1.5", "2.1 and earlier"
_TXT = [
    (re.compile(r"^(?:<|before|prior to|earlier than|below|lower than)\s*v?([0-9][\w.\-]*)$"), "lt"),
    (re.compile(r"^(?:<=|=<|through|up to|up to and including)\s*v?([0-9][\w.\-]*)$"), "lte"),
    (re.compile(r"^v?([0-9][\w.\-]*)\s*(?:and|or)\s*(?:earlier|prior|before|below|lower)(?: versions?)?$"), "lte"),
    (re.compile(r"^v?([0-9][\w.\-]*)\s*(?:-|to|through|~)\s*v?([0-9][\w.\-]*)$"), "range"),
    (re.compile(r"^>=?\s*v?([0-9][\w.\-]*)\s*,?\s*(?:and\s*)?<\s*v?([0-9][\w.\-]*)$"), "ltrange"),
    (re.compile(r"^>=?\s*v?([0-9][\w.\-]*)\s*,?\s*(?:and\s*)?<=\s*v?([0-9][\w.\-]*)$"), "range"),
]


# ---- Debian/Ubuntu package versions (dpkg's own ordering) ---------------

def _dorder(c: str) -> int:
    if not c or c.isdigit():
        return 0
    if c.isalpha():
        return ord(c)
    if c == "~":
        return -1
    return ord(c) + 256


def _verrevcmp(a: str, b: str) -> int:
    i = j = 0
    while i < len(a) or j < len(b):
        first = 0
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            ac = _dorder(a[i]) if i < len(a) else 0
            bc = _dorder(b[j]) if j < len(b) else 0
            if ac != bc:
                return ac - bc
            i += 1
            j += 1
        while i < len(a) and a[i] == "0":
            i += 1
        while j < len(b) and b[j] == "0":
            j += 1
        while i < len(a) and a[i].isdigit() and j < len(b) and b[j].isdigit():
            if not first:
                first = ord(a[i]) - ord(b[j])
            i += 1
            j += 1
        if i < len(a) and a[i].isdigit():
            return 1
        if j < len(b) and b[j].isdigit():
            return -1
        if first:
            return first
    return 0


def dpkg_cmp(a: str, b: str) -> int:
    """Compare two Debian package versions ([epoch:]upstream[-revision]) like dpkg does."""
    def split(v):
        v = v.strip()
        epoch, _, rest = v.partition(":") if ":" in v else ("0", "", v)
        up, _, rev = rest.rpartition("-") if "-" in rest else (rest, "", "")
        return int(epoch or 0), up, rev
    ea, ua, ra = split(a)
    eb, ub, rb = split(b)
    if ea != eb:
        return -1 if ea < eb else 1
    c = _verrevcmp(ua, ub) or _verrevcmp(ra, rb)
    return (c > 0) - (c < 0)


_OP = re.compile(r"(<=|=<|>=|<|>|\bbefore\b|\bprior to\b|\bthrough\b|\bup to\b|\bearlier than\b|\bbelow\b)")


# ---- FreeBSD pkg versions -------------------------------------------------------------
# A port of pkg(8)'s pkg_version_cmp (libpkg/pkg_version.c, BSD-2-Clause; Oliver Eikemeier,
# after Jeremy D. Lea), so VuXML ranges compare exactly the way `pkg audit` compares them.
# ${PORTVERSION}[_${PORTREVISION}][,${PORTEPOCH}]: epoch first, then version, then revision.

_DIG = "0123456789"
_ALPHA = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
_ABASE = 2
_PKG_STAGES = (("pl", 0), ("snap", ord("s") - ord("a") + _ABASE), ("alpha", _ABASE),
               ("beta", 1 + _ABASE), ("pre", ord("p") - ord("a") + _ABASE), ("rc", ord("r") - ord("a") + _ABASE))


def _lead_int(s: str) -> int:
    m = re.match(r"\d+", s)
    return int(m.group()) if m else 0


def _pkg_split(v: str) -> tuple[str, int, int]:
    """'1.9.17p2_4,1' -> ('1.9.17p2', epoch 1, revision 4)."""
    v = v[v.rfind("-") + 1:]
    us = v.rfind("_")
    rev = _lead_int(v[us + 1:]) if us >= 0 else 0
    cm = v.rfind(",", us + 1 if us >= 0 else 0)
    epoch = _lead_int(v[cm + 1:]) if cm >= 0 else 0
    end = us if us >= 0 else (cm if cm >= 0 else len(v))
    return v[:end], epoch, rev


def _pkg_component(s: str, pos: int) -> tuple[tuple[int, int, int], int]:
    n, hasstage, haspl = len(s), False, False
    if pos < n and s[pos] in _DIG:
        j = pos
        while j < n and s[j] in _DIG:
            j += 1
        num, pos = int(s[pos:j]), j
    elif pos < n and s[pos] == "*":
        num = -2
        pos += 1
        while pos < n and s[pos] != "+":
            pos += 1
    else:
        num, hasstage = -1, True
    a = 0
    if pos < n and s[pos] in _ALPHA:
        c = s[pos].lower()
        haspl = True
        if pos + 1 < n and s[pos + 1] in _ALPHA:
            for name, value in _PKG_STAGES:
                end = pos + len(name)
                if s[pos:end].lower() == name and not (end < n and s[end] in _ALPHA):
                    if hasstage:
                        a, pos = value, end
                    else:  # a number then "alpha": a dot goes in between
                        a, haspl = 0, False
                    c = ""
                    break
        if c:  # other words sort by their first letter
            a = ord(c) - ord("a") + _ABASE
            pos += 1
            while pos < n and s[pos] in _ALPHA:
                pos += 1
    pl = 0
    if haspl:
        if pos < n and s[pos] in _DIG:
            j = pos
            while j < n and s[j] in _DIG:
                j += 1
            pl, pos = int(s[pos:j]), j
        else:
            pl = -1
    while pos < n and s[pos] not in _DIG and s[pos] not in _ALPHA and s[pos] not in "+*":
        pos += 1
    return (num, a, pl), pos


def pkg_cmp(a: str, b: str) -> int:
    """FreeBSD package version order: -1, 0 or 1, as pkg(8) decides it."""
    v1, e1, r1 = _pkg_split(a)
    v2, e2, r2 = _pkg_split(b)
    if e1 != e2:
        return -1 if e1 < e2 else 1
    result = 0
    if v1.lower() != v2.lower():
        p1 = p2 = 0
        while result == 0 and (p1 < len(v1) or p2 < len(v2)):
            c1 = c2 = (0, 0, 0)
            block1 = not (p1 < len(v1) and v1[p1] != "+")
            block2 = not (p2 < len(v2) and v2[p2] != "+")
            if not block1:
                c1, p1 = _pkg_component(v1, p1)
            if not block2:
                c2, p2 = _pkg_component(v2, p2)
            if block1 and block2:
                p1 += p1 < len(v1)
                p2 += p2 < len(v2)
            elif c1 != c2:
                result = -1 if c1 < c2 else 1
    if result == 0 and r1 != r2:
        result = -1 if r1 < r2 else 1
    return result


def _text_range(s: str):
    s = s.strip().lower()
    m = _OP.search(s)
    if m and m.start() > 0 and not s[:1].isdigit():
        s = s[m.start():]  # "Linux Kernel <= 3.1" -> "<= 3.1"
    for rx, kind in _TXT:
        m = rx.match(s)
        if not m:
            continue
        if kind == "lt":
            return (None, m.group(1), False)
        if kind == "lte":
            return (None, m.group(1), True)
        if kind == "range":
            return (m.group(1), m.group(2), True)
        if kind == "ltrange":
            return (m.group(1), m.group(2), False)
    return None


_AFFECTED_SPAN = re.compile(r"affected\s*:?\s*v?([0-9][\w.]*)\s*(?:-|to|through)\s*v?([0-9][\w.]*)", re.I)
_FIXED_IN = re.compile(r"fixed in [a-z ]*?v?([0-9][\w.]*)", re.I)


def _text_ranges(s: str):
    """All ranges a free-text version field describes, as (lo, hi, inclusive) tuples."""
    # OpenSSL: "Fixed in OpenSSL 1.1.1g (Affected 1.1.1d-1.1.1f). Fixed in 1.0.2u (Affected 1.0.2-1.0.2t)"
    spans = _AFFECTED_SPAN.findall(s)
    if spans:
        return [(lo, hi.rstrip("."), True) for lo, hi in spans]
    one = _text_range(s)
    return [one] if one else []


def _in(ver: str, lo: str | None, hi: str | None, inclusive: bool) -> bool | None:
    """None = can't tell (unparseable bound)."""
    lo_c = clean(lo) if lo else None
    wild = bool(hi) and hi != "*" and hi.endswith("*")  # "6.1.*" = every 6.1.x
    hi_c = clean(hi.rstrip("*").rstrip(".")) if hi and hi != "*" else None
    if hi and hi != "*" and hi_c is None:
        return None
    if lo_c and cmp(ver, lo_c) < 0:
        return False
    if hi_c is None:
        return True
    if wild:
        n = len(key(hi_c))
        head = ".".join(str(t[1]) for t in key(ver)[:n])
        return cmp(head, hi_c) <= 0
    c = cmp(ver, hi_c)
    return c <= 0 if inclusive else c < 0


# ---- last resort: versions named in the description ----------------------
# Old records (and many MITRE-era ones) say "n/a" for versions but the text reads
# "OpenSSL 1.0.1 before 1.0.1g ...". If every version named right after the product
# is older than what's installed, the CVE almost certainly predates it.

_DESC_VER = re.compile(r"(?<![\w/.\-])v?(\d{1,4}(?:\.\d+){1,3}(?:[a-z]\d*)?)(?![\w]*\.\d)")
_LATER = re.compile(r"\b(?:and|or) (?:later|above|newer|higher|greater|after)\b|\bonwards?\b|"
                    r"\bsince (?:version |v)?\d|\bstarting (?:with|from|in)\b|\ball versions\b|"
                    r"\bthrough the (?:current|latest)\b|>=|\bor greater\b", re.I)
_NOT_PRODUCT = re.compile(r"\b(?:http/|https/|tls\s?v?|ssl\s?v?|ipv|rfc\s?|cvss:?\s?|smb\s?v?|snmp\s?v?|"
                          r"oauth\s?|ntlm\s?v?|python\s?|php\s?|java\s?|node(?:\.js)?\s?|gpl\s?v?)$", re.I)
_GENERIC = {"core", "web", "os", "server", "client", "app", "application", "network", "firmware"}


def name_pattern(name: str) -> re.Pattern | None:
    words = [w for w in re.split(r"[^a-z0-9]+", name.lower()) if w]
    if not words or (len(words) == 1 and (len(words[0]) < 4 or words[0] in _GENERIC)):
        return None
    return re.compile(r"\b" + r"[\s\-_]*".join(map(re.escape, words)) + r"\b", re.I)


_UPPER = re.compile(r"(?:prior to|before|through|up to and including|up to|earlier than|until|"
                    r"upgrade to|update to|fixed in|<=?)\s*"
                    r"(?:versions?\s+|v)?(\d{1,4}(?:\.\d+){1,3}(?:[a-z]\d*)?)", re.I)
_SENT = re.compile(r"(?<=[.!?])\s+|\n+")


def _max(vs):
    best = None
    for v in vs:
        if best is None or cmp(v, best) > 0:
            best = v
    return best


def desc_max(desc: str, patterns) -> str | None:
    """Highest version the description pins on the product, or None if unsure.

    Looks only at sentences that name the product. An explicit upper bound
    ("prior to 5.18.3", "before 1.0.1g", "through 2.4") wins; otherwise open-ended
    wording ("and later", "since") means we can't tell.
    """
    if not desc:
        return None
    allsents = _SENT.split(desc)
    keep = set()
    for i, s in enumerate(allsents):
        if any(rx.search(s) for rx in patterns):
            keep.update((i, i + 1))  # "...manage your Pi-hole. Versions 4.0 and above, prior to 5.18.3 are..."
    sents = [allsents[i] for i in sorted(keep) if i < len(allsents)]
    if not sents:
        return None
    text = " ".join(sents)
    bounds = [m.group(1) for m in _UPPER.finditer(text)]
    if bounds:
        return _max(bounds)
    if _LATER.search(text):
        return None
    found = []
    for s in sents:
        for v in _DESC_VER.finditer(s):
            if _NOT_PRODUCT.search(s[: v.start()].rstrip()[-8:]):  # "TLS 1.3", "HTTP/1.1"
                continue
            found.append(v.group(1))
    return _max(found)


# "Fedora version prior to 31", "all RHEL versions": a distro's own release numbers, not the
# product's. They describe how that distro shipped it, so they say nothing about your build.
_DISTRO_WORDS = re.compile(r"\b(?:fedora|rhel|red hat|enterprise linux|centos|rocky linux|almalinux|"
                           r"ubuntu|debian|suse|sles|opensuse|amazon linux|alpine|oracle linux)\b", re.I)


_cmp_key = functools.cmp_to_key(lambda a, b: cmp(a, b))


def _fixed_in(v: str | None) -> str:
    """The suffix match.fix_state looks for: "; fixed in <version>"."""
    return f"; fixed in {v}" if v else ""


def _next_fixed(entry: dict, ver: str) -> str | None:
    """For records that list fixed versions and mark the rest affected (kernel.org, Jenkins):
    the first fixed release after `ver`, preferring one on the same major.minor line."""
    later = []
    for r in entry.get("vs") or []:
        v = r.get("version")
        if (r.get("status") or "").lower() != "unaffected" or (r.get("versionType") or "").lower() == "git":
            continue
        if isinstance(v, str) and clean(v) and cmp(v, ver) > 0:
            later.append(v.strip())
    if not later:
        return None
    line = key(ver)[:2]
    same = [v for v in later if key(clean(v))[:2] == line]
    return min(same or later, key=_cmp_key)


def eval_entry(entry: dict, version: str | None) -> tuple[str, str]:
    """Evaluate one compact affected[] entry for an installed version.

    Returns (status, reason) with status in affected | unaffected | unknown.
    """
    ver = clean(version)
    if ver is None:
        return "unknown", "no installed version"
    hits: list[str] = []
    fixes: list[str] = []      # upper bounds of the affected ranges this version is in
    parseable = False
    listed_unaffected = False
    other_distro_ok = bool(_DISTRO_WORDS.search(f"{entry.get('v') or ''} {entry.get('p') or ''}"))
    for r in entry.get("vs") or []:
        if (r.get("status") or "").lower() == "unaffected":
            listed_unaffected = True
        st = (r.get("status") or "affected").lower()
        if (r.get("versionType") or "").lower() == "git":
            continue
        start = r.get("version")
        lt, lte = r.get("lessThan"), r.get("lessThanOrEqual")
        # FreeBSD style: version "14.3-RELEASE", lessThan "p7" = 14.3-RELEASE before patch 7
        for name, val in (("lt", lt), ("lte", lte)):
            if isinstance(val, str) and re.fullmatch(r"p\d+", val.strip().lower()) and start:
                fixed = f"{start}-{val.strip()}"
                lt, lte = (fixed, None) if name == "lt" else (None, fixed)
        if lt is None and lte is None:
            if _DISTRO_WORDS.search(str(start or "")) and not other_distro_ok:
                continue
            rngs = _text_ranges(str(start or ""))
            if rngs:
                outs = [_in(ver, lo, hi, inc) for lo, hi, inc in rngs]
                res = None if all(o is None for o in outs) else any(bool(o) for o in outs)
            elif _single(start):
                res = cmp(ver, _single(start)) == 0
            else:
                res = None
        else:
            res = _in(ver, start, lte if lte is not None else lt, lte is not None)
        if res is None:
            continue
        parseable = True
        if res:
            hits.append(st)
            # "< 2.47.3" names the release that fixed it; "<= 2.47.2" or "<= *" doesn't
            if st == "affected" and lte is None and isinstance(lt, str) and clean(lt) and cmp(lt, ver) > 0:
                fixes.append(lt.strip())
    if "unaffected" in hits:
        return "unaffected", "version listed as unaffected"
    if "affected" in hits:
        return "affected", "version inside an affected range" + _fixed_in(min(fixes, key=_cmp_key) if fixes else None)
    if not parseable:
        # defaultStatus alone says nothing about *your* version
        return "unknown", "no usable version data"
    ds = (entry.get("ds") or "").lower()
    if ds == "affected" and not listed_unaffected:
        # Many CNAs write defaultStatus "affected" next to a single "0 .. < fixed" range.
        # Read literally that would flag every newer version; they mean "older than fixed".
        return "unaffected", "outside every affected range"
    if ds in ("affected", "unaffected"):
        # e.g. Jenkins lists only fixed/unaffected versions and marks everything else affected
        if ds == "affected":
            return ds, ("not among the versions the record lists as fixed or unaffected; it marks the rest affected"
                        + _fixed_in(_next_fixed(entry, ver)))
        return ds, "outside every listed range; the record marks the rest unaffected"
    return "unaffected", "outside every listed range"
