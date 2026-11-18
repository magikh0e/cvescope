"""SBOM import: CycloneDX (JSON or XML) and SPDX (JSON or tag-value) files.

Generate one with syft, trivy, cdxgen or your build, point the collector at it, and every
component becomes an inventory item:

  - its CPE (when the SBOM has one) gives the "vendor:product" the CVE List is matched on;
  - Debian/Ubuntu packages (purl pkg:deb/... with a distro, or the SBOM's operating-system
    component) are checked against the distro's own security tracker, backports included;
  - language packages (PyPI, npm, Maven, Go, crates.io, RubyGems, NuGet, Packagist, Hex, Pub)
    are checked against their ecosystem's advisories on OSV.dev.

    [[inventory]]
    type = "sbom"
    path = "~/sboms/web1.cdx.json"   # a file, a folder (every .json/.xml/.spdx in it) or a glob
    name = "web1"                    # optional: the host they run on (default: each SBOM's own name)

cvescope never runs a scanner: it reads the files you give it.
"""

from __future__ import annotations

import glob
import json
import os
import re
import urllib.parse
import xml.etree.ElementTree as ET

from .. import db
from ..config import expand
from . import item, packages

# purl type -> OSV.dev ecosystem
PURL_OSV = {"pypi": "PyPI", "npm": "npm", "maven": "Maven", "golang": "Go", "cargo": "crates.io",
            "gem": "RubyGems", "nuget": "NuGet", "composer": "Packagist", "hex": "Hex", "pub": "Pub"}
UBUNTU_CODENAMES = {"18.04": "bionic", "20.04": "focal", "22.04": "jammy", "24.04": "noble",
                    "24.10": "oracular", "25.04": "plucky", "25.10": "questing", "26.04": "resolute"}
SKIP_TYPES = {"file", "data", "machine-learning-model", "cryptographic-asset"}
SKIP_PURL = {"oci", "docker"}  # the image itself, not software in it
MAX_COMPONENTS = 5000


# ---- identifiers --------------------------------------------------------------------------

def parse_purl(s: str) -> dict | None:
    """pkg:type/namespace/name@version?qualifiers#subpath -> parts (percent-decoded)."""
    if not isinstance(s, str) or not s.startswith("pkg:"):
        return None
    rest = s[4:].split("#", 1)[0]
    rest, _, query = rest.partition("?")
    rest, _, version = rest.partition("@")
    parts = [urllib.parse.unquote(p) for p in rest.strip("/").split("/") if p]
    if len(parts) < 2:
        return None
    q = {k.lower(): urllib.parse.unquote(v) for k, _, v in (kv.partition("=") for kv in query.split("&") if kv)}
    return {"type": parts[0].lower(), "namespace": "/".join(parts[1:-1]), "name": parts[-1],
            "version": urllib.parse.unquote(version) or None, "qualifiers": q}


def osv_name(p: dict) -> tuple[str, str] | None:
    """purl parts -> (OSV ecosystem, package name as OSV spells it)."""
    eco = PURL_OSV.get(p["type"])
    if not eco:
        return None
    ns, name = p["namespace"], p["name"]
    if p["type"] == "pypi":  # PEP 503 normal form
        return eco, re.sub(r"[-_.]+", "-", name).lower()
    if p["type"] == "npm":
        return eco, f"{ns}/{name}" if ns else name   # "@scope/name"
    if p["type"] == "maven":
        return (eco, f"{ns}:{name}") if ns else None
    if p["type"] in ("golang", "composer"):
        return eco, f"{ns}/{name}" if ns else name
    return eco, name


def parse_cpe(s: str) -> tuple[str, str] | None:
    """CPE 2.3 or 2.2 -> (vendor, product), or None for "*" / "-" / malformed."""
    if not isinstance(s, str):
        return None
    if s.startswith("cpe:2.3:"):
        f = re.split(r"(?<!\\):", s)
        vendor, product = (f[3], f[4]) if len(f) > 4 else ("", "")
    elif s.startswith("cpe:/"):
        f = s[5:].split(":")
        vendor, product = (f[1], f[2]) if len(f) > 2 else ("", "")
    else:
        return None
    vendor, product = (urllib.parse.unquote(x.replace("\\", "")) for x in (vendor, product))
    if vendor in ("", "*", "-") or product in ("", "*", "-"):
        return None
    return db.norm(vendor), db.norm(product)


def _release(os_name: str | None, os_version: str | None, qualifier: str | None) -> str | None:
    """distro qualifier "debian-12" / "ubuntu-22.04", or the SBOM's OS component -> "debian:12"."""
    fam, ver = None, None
    if qualifier:
        m = re.match(r"([a-z]+)-([\w.]+)", qualifier.lower())
        if m:
            fam, ver = m.group(1), m.group(2)
    elif os_name and os_version:
        fam, ver = os_name.lower(), str(os_version)
    if fam == "debian" and ver and ver.split(".")[0].isdigit():
        return f"debian:{ver.split('.')[0]}"
    if fam == "ubuntu" and ver:
        code = UBUNTU_CODENAMES.get(".".join(ver.split(".")[:2]), ver if ver.isalpha() else None)
        return f"ubuntu:{code}" if code else None
    return None


# ---- readers: every format ends up as a list of plain components ---------------------------
# component = {"name", "version", "group", "type", "purl", "cpe"}

def _cdx_json(d: dict) -> tuple[str | None, list[dict]]:
    meta = (d.get("metadata") or {}).get("component") or {}
    out = []

    def walk(comps):
        for c in comps or []:
            if isinstance(c, dict):
                out.append({"name": c.get("name"), "version": c.get("version"), "group": c.get("group"),
                            "type": c.get("type"), "purl": c.get("purl"), "cpe": c.get("cpe")})
                walk(c.get("components"))
    walk(d.get("components"))
    return meta.get("name"), out


def _spdx_json(d: dict) -> tuple[str | None, list[dict]]:
    out = []
    for p in d.get("packages") or []:
        if not isinstance(p, dict):
            continue
        refs = p.get("externalRefs") or []
        purl = next((r.get("referenceLocator") for r in refs if r.get("referenceType") == "purl"), None)
        cpe = next((r.get("referenceLocator") for r in refs
                    if r.get("referenceType") in ("cpe23Type", "cpe22Type")), None)
        kind = "operating-system" if str(p.get("primaryPackagePurpose") or "").upper() == "OPERATING-SYSTEM" else None
        out.append({"name": p.get("name"), "version": p.get("versionInfo"), "group": None,
                    "type": kind, "purl": purl, "cpe": cpe})
    return d.get("name"), out


def _spdx_tv(text: str) -> tuple[str | None, list[dict]]:
    doc, out, cur = None, [], None
    for line in text.splitlines():
        k, sep, v = line.partition(":")
        if not sep:
            continue
        k, v = k.strip(), v.strip()
        if k == "DocumentName":
            doc = v
        elif k == "PackageName":
            cur = {"name": v, "version": None, "group": None, "type": None, "purl": None, "cpe": None}
            out.append(cur)
        elif cur is not None and k == "PackageVersion":
            cur["version"] = v
        elif cur is not None and k == "PrimaryPackagePurpose" and v.upper() == "OPERATING-SYSTEM":
            cur["type"] = "operating-system"
        elif cur is not None and k == "ExternalRef":
            f = v.split()
            if len(f) >= 3 and f[1] == "purl" and not cur["purl"]:
                cur["purl"] = f[2]
            elif len(f) >= 3 and f[1] in ("cpe23Type", "cpe22Type") and not cur["cpe"]:
                cur["cpe"] = f[2]
    return doc, out


def _cdx_xml(data: bytes) -> tuple[str | None, list[dict]]:
    # SBOM generators don't declare entities; one that does isn't a plain SBOM, so refuse it
    # rather than rely on the expat build's expansion limits.
    if b"<!ENTITY" in data.upper() or b"<!DOCTYPE" in data.upper():
        raise ValueError("declares a DOCTYPE or XML entities; not a plain CycloneDX file, refusing to parse")
    root = ET.fromstring(data)
    ns = root.tag[:root.tag.index("}") + 1] if root.tag.startswith("{") else ""
    if root.tag != ns + "bom":
        raise ValueError("not a CycloneDX BOM")

    def comp(el):
        return {"name": el.findtext(ns + "name"), "version": el.findtext(ns + "version"),
                "group": el.findtext(ns + "group"), "type": el.get("type"),
                "purl": el.findtext(ns + "purl"), "cpe": el.findtext(ns + "cpe")}
    meta = root.find(f"{ns}metadata/{ns}component")
    top = root.find(ns + "components")
    out = [comp(c) for c in top.iter(ns + "component")] if top is not None else []
    return (meta.findtext(ns + "name") if meta is not None else None), out


def read(path: str) -> tuple[str | None, list[dict]]:
    """One SBOM file -> (its own name, components). Format is detected from the content."""
    with open(path, "rb") as f:
        data = f.read()
    head = data.lstrip()[:1]
    if head == b"<":
        return _cdx_xml(data)
    if head in (b"{", b"["):
        d = json.loads(data)
        if isinstance(d, dict) and (d.get("bomFormat") == "CycloneDX" or "components" in d):
            return _cdx_json(d)
        if isinstance(d, dict) and (d.get("spdxVersion") or "packages" in d):
            return _spdx_json(d)
        raise ValueError("JSON that is neither CycloneDX nor SPDX")
    text = data.decode("utf-8", "replace")
    if "SPDXVersion:" in text:
        return _spdx_tv(text)
    raise ValueError("not a CycloneDX or SPDX file")


# ---- components -> items ---------------------------------------------------------------------

def items_for(label: str, comps: list[dict]) -> list[dict]:
    os_comp = next((c for c in comps if (c.get("type") or "").lower() == "operating-system"), None)
    os_name, os_ver = (os_comp.get("name"), os_comp.get("version")) if os_comp else (None, None)
    out, seen, shown = [], set(), set()
    if os_comp and os_name and os_ver:
        rel = _release(os_name, os_ver, None)
        gid = str(os_name).lower()
        out.append(item(f"{os_name.capitalize() if gid in ('debian', 'ubuntu') else os_name} {os_ver} ({label})",
                        gid, f"{gid} linux" if gid in ("debian", "ubuntu") else gid, str(os_ver),
                        guest_os=True, **({"distro": rel} if rel else {})))
    for c in comps:
        name, ver = str(c.get("name") or "").strip(), str(c.get("version") or "").strip()
        if not name or not ver or (c.get("type") or "").lower() in SKIP_TYPES | {"operating-system"}:
            continue
        p = parse_purl(c.get("purl") or "")
        if p and p["type"] in SKIP_PURL:
            continue
        key = (p["type"] if p else "", (p or {}).get("namespace") or c.get("group") or "", name.lower(), ver)
        if key in seen:
            continue
        seen.add(key)
        if len(out) >= MAX_COMPONENTS:
            raise ValueError(f"over {MAX_COMPONENTS} components; split the SBOM")
        extra = {"sbom": True}
        if c.get("purl"):
            extra["purl"] = c["purl"]
        aliases = []
        known = packages.PACKAGES.get(name.lower())
        disp = known[0] if known else name
        if known:
            aliases += known[1]
        cpe = parse_cpe(c.get("cpe") or "")
        if cpe:
            aliases.append(f"{cpe[0]}:{cpe[1]}")
            extra["cpe"] = c["cpe"]
        version = ver
        o = osv_name(p) if p else None
        if o:
            extra["osv"] = {"ecosystem": o[0], "name": o[1], "label": f"{o[0]} advisory"}
        elif p and p["type"] == "deb":
            rel = _release(os_name, os_ver, p["qualifiers"].get("distro"))
            src = p["qualifiers"].get("upstream") or packages.SOURCE_OF.get(name, name)
            src = src.split("@")[0].split(" ")[0]
            extra.update(backports=True, package=name, package_version=ver, source=src,
                         **({"distro": rel} if rel else {}))
            version = packages.pkg_version(ver)
            if not known:
                aliases.append(f"*:{db.norm(src)}")
        elif not known and not cpe:
            aliases.append(f"*:{db.norm(name)}")  # nothing better to go on: any vendor's product of that name
        if p and p["namespace"] and not known and p["type"] in ("maven", "npm", "composer", "golang"):
            sep = ":" if p["type"] == "maven" else "/"
            disp = f"{p['namespace']}{sep}{p['name']}"
        if (disp.lower(), version) in shown:  # libssl3 and openssl: one OpenSSL, as the dpkg collector does
            continue
        shown.add((disp.lower(), version))
        out.append(item(f"{disp} ({label})", version=version, aliases=aliases, **extra))
    return out


def _files(path: str) -> list[str]:
    p = str(expand(path))
    if os.path.isdir(p):
        return sorted(os.path.join(p, f) for f in os.listdir(p)
                      if f.lower().endswith((".json", ".xml", ".spdx", ".cdx")) and os.path.isfile(os.path.join(p, f)))
    hits = sorted(glob.glob(p))
    if not hits:
        raise FileNotFoundError(f"no SBOM at {path}")
    return hits


def sbom(e: dict) -> list[dict]:
    """path (file, folder or glob) [, name]. CycloneDX JSON/XML or SPDX JSON/tag-value."""
    out = []
    for f in _files(e["path"]):
        doc, comps = read(f)
        label = e.get("name") or doc or os.path.splitext(os.path.basename(f))[0]
        out += items_for(label, comps)
    if not out:
        raise RuntimeError("no components with a name and a version in the SBOM")
    return out
