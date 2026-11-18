"""Installed-software lists from endpoints: osquery (live or saved results) or a PowerShell export.

Live: cvescope runs osqueryi on the host (locally, or over ssh) with per-OS default queries.
    [[inventory]]
    type = "osquery"
    name = "laptop"                 # optional; default is the host's own hostname
    command_prefix = ["ssh", "box"] # optional; omit to query this machine
    osqueryi = "/usr/bin/osqueryi"  # optional; found on PATH or in the usual install dirs
    queries = ["SELECT ..."]        # optional; replaces the per-OS defaults

Saved results:
    [[inventory]]
    type = "osquery"
    path = "~/inventory/*.json"     # files, a glob, or a list
    programs = "known"              # "all" also adds programs cvescope has no name mapping for

Accepted files (format is detected per file):
  - `osqueryi --json "<query>"` output: a JSON array of rows
  - osqueryd result logs: JSON lines with hostIdentifier + columns (differential) or snapshot
  - examples/windows-inventory.ps1 output: {"host", "os", "programs"}

Useful queries: os_version; programs (Windows); apps (macOS); deb_packages / rpm_packages (Linux).
Debian/Ubuntu package rows plus an os_version row get the distro tracker treatment, like dpkg.
"""

from __future__ import annotations

import json
import re
import shlex
import shutil
from pathlib import Path

from .. import db
from . import item, packages
from .generic import _run, dpkg_items
from .nmap import _files

# program display names (lowercased, version/arch noise removed) -> (display, aliases)
PROGRAMS: list[tuple[re.Pattern, str, list[str]]] = [(re.compile(rx), d, a) for rx, d, a in [
    (r"^google chrome$", "Google Chrome", ["google:chrome"]),
    (r"^(mozilla )?firefox", "Firefox", ["mozilla:firefox"]),
    (r"^(mozilla )?thunderbird", "Thunderbird", ["mozilla:thunderbird"]),
    # Chromium Edge only: plain "Microsoft Edge" in old records is EdgeHTML, retired in 2021
    (r"^microsoft edge$", "Microsoft Edge", ["microsoft:microsoft edge chromium based", "microsoft:edge chromium"]),
    (r"^7-zip", "7-Zip", ["7 zip:7 zip", "igor pavlov:7 zip"]),
    (r"^winrar", "WinRAR", ["rarlab:winrar"]),
    (r"^notepad\+\+", "Notepad++", ["notepad plus plus:notepad", "don ho:notepad"]),
    (r"^vlc media player|^vlc$", "VLC", ["videolan:vlc media player", "videolan:vlc"]),
    (r"^putty", "PuTTY", ["putty:putty", "simon tatham:putty"]),
    (r"^winscp", "WinSCP", ["winscp:winscp"]),
    (r"^filezilla", "FileZilla", ["filezilla:filezilla client", "filezilla project:filezilla client"]),
    (r"^wireshark", "Wireshark", ["wireshark:wireshark", "wireshark foundation:wireshark"]),
    (r"^openvpn", "OpenVPN", packages.PACKAGES["openvpn"][1]),
    (r"^wireguard", "WireGuard", ["wireguard:wireguard for windows", "wireguard:wireguard"]),
    (r"^python \d", "Python", ["python:python", "python software foundation:cpython"]),
    (r"^node\.?js", "Node.js", ["nodejs:node js", "openjs foundation:node js"]),
    (r"^git$", "Git", ["git scm:git", "git:git", "git for windows:git for windows"]),
    (r"^(microsoft )?visual studio code", "VS Code", ["microsoft:visual studio code"]),
    (r"^(oracle vm )?virtualbox", "VirtualBox", ["oracle:vm virtualbox", "oracle:virtualbox"]),
    (r"^vmware workstation", "VMware Workstation", ["vmware:workstation", "vmware:workstation pro"]),
    (r"^docker desktop", "Docker Desktop", ["docker:docker desktop", "docker:desktop"]),
    (r"^teamviewer", "TeamViewer", ["teamviewer:teamviewer", "teamviewer:remote"]),
    (r"^anydesk", "AnyDesk", ["anydesk:anydesk"]),
    (r"^zoom", "Zoom", ["zoom:zoom workplace", "zoom video communications:zoom workplace", "zoom:zoom"]),
    (r"^adobe acrobat", "Adobe Acrobat", ["adobe:acrobat reader", "adobe:acrobat", "adobe:acrobat reader dc"]),
    (r"^keepassxc", "KeePassXC", ["keepassxc:keepassxc"]),
    (r"^keepass", "KeePass", ["keepass:keepass", "dominik reichl:keepass"]),
    (r"^obs studio", "OBS Studio", ["obsproject:obs studio"]),
    (r"^nmap", "Nmap", ["nmap:nmap"]),
    (r"^ultravnc", "UltraVNC", ["uvnc:ultravnc"]),
    (r"^tightvnc", "TightVNC", ["tightvnc:tightvnc"]),
    (r"^(realvnc|vnc server)", "RealVNC", ["realvnc:vnc server"]),
    (r"^plex media server", "Plex Media Server", packages.APPS["plex media server"][1]),
    (r"^qbittorrent", "qBittorrent", ["qbittorrent:qbittorrent"]),
    (r"^libreoffice", "LibreOffice", ["libreoffice:libreoffice", "the document foundation:libreoffice"]),
    (r"^gimp", "GIMP", ["gimp:gimp"]),
    (r"^inkscape", "Inkscape", ["inkscape:inkscape"]),
    (r"^audacity", "Audacity", ["audacityteam:audacity"]),
    (r"^blender", "Blender", ["blender:blender"]),
    (r"^(cisco anyconnect|cisco secure client)", "Cisco Secure Client", ["cisco:secure client",
                                                                          "cisco:anyconnect secure mobility client"]),
    (r"^forticlient", "FortiClient", ["fortinet:forticlient", "fortinet:forticlientwindows"]),
    (r"^globalprotect", "GlobalProtect", ["palo alto networks:globalprotect app"]),
    (r"^citrix workspace", "Citrix Workspace", ["citrix:workspace app", "citrix:workspace"]),
    (r"^(ivanti secure access client|pulse secure)", "Ivanti Secure Access Client", ["ivanti:secure access client"]),
    (r"^signal", "Signal", ["signal:signal desktop"]),
    (r"^telegram desktop", "Telegram Desktop", ["telegram:telegram desktop"]),
    (r"^bitwarden", "Bitwarden", ["bitwarden:bitwarden", "bitwarden:desktop"]),
    (r"^openssl", "OpenSSL", ["openssl:openssl"]),
]]

_NOISE = re.compile(r"\s*\((x64|x86|64-bit|32-bit|amd64|arm64|user|machine|[a-z]{2}-[a-z]{2}|x64 [a-z-]+)\)|"
                    r"\s+v?\d+(\.\d+)+.*$|\.app$|\s+(x64|x86|64-bit|32-bit)$", re.I)


def clean_name(name: str) -> str:
    prev = None
    s = name.strip()
    while prev != s:
        prev, s = s, _NOISE.sub("", s).strip()
    return s.lower()


# apps that update themselves in the background: an old CVE without version data is long fixed
AUTO_UPDATING = {"Google Chrome", "Microsoft Edge", "Firefox", "Thunderbird", "VS Code", "Signal",
                 "Telegram Desktop", "Bitwarden"}


def program_item(name: str, version: str, host: str, everything: bool, publisher: str = ""):
    key = clean_name(name)
    if not key or not version:
        return None
    for rx, disp, aliases in PROGRAMS:
        if rx.search(key):
            extra = {"auto_updates": True} if disp in AUTO_UPDATING else {}
            return item(f"{disp} ({host})", version=version, aliases=aliases, program=name, publisher=publisher,
                        **extra)
    if everything:
        return item(f"{name} ({host})", version=version, aliases=[f"*:{db.norm(key)}"], program=name,
                    publisher=publisher)
    return None


def windows_os(os_row: dict, host: str):
    """{'name': 'Microsoft Windows 11 Pro', 'build': '26100', 'ubr': '2314', 'display_version': '24H2'}"""
    name = os_row.get("name") or os_row.get("Caption") or ""
    build = str(os_row.get("build") or os_row.get("BuildNumber") or "")
    ubr = str(os_row.get("ubr") or os_row.get("revision") or os_row.get("UBR") or "")
    dv = str(os_row.get("display_version") or os_row.get("DisplayVersion") or "").lower()
    if not build:
        return None
    m = re.search(r"windows (server )?(\d+)", name, re.I)
    aliases = []
    if m and m.group(1):
        aliases += [f"microsoft:windows server {m.group(2)}", f"microsoft:windows server {m.group(2)}*"]
    elif m:
        aliases += [f"microsoft:windows {m.group(2)} version {dv}"] if dv else []
        aliases += [f"microsoft:windows {m.group(2)}*"]
    version = f"10.0.{build}.{ubr}" if ubr else f"10.0.{build}"
    # records sometimes bound Windows by release ("before 24H2") instead of build: match.py
    # compares those against this
    return item(f"{name} ({host})", version=version, aliases=aliases, backports=not ubr,
                note=None if ubr else "no update revision (UBR): matches stay 'check'",
                display_version=dv.upper() or None)


def _rows_from_file(path: str) -> dict[str, list[dict]]:
    """-> {host: rows}. Rows keep their own keys; the caller sorts them out."""
    text = Path(path).read_text(encoding="utf-8-sig").strip()
    stem = Path(path).stem
    if text.startswith("{") and '"programs"' in text[:5000] and "\n{" not in text:
        d = json.loads(text)  # windows-inventory.ps1
        host = d.get("host") or stem
        rows = [dict(r, _table="programs") for r in d.get("programs") or []]
        if d.get("os"):
            rows.append(dict(d["os"], _table="windows_os"))
        return {host: rows}
    if text.startswith("["):
        data = json.loads(text)
        return {stem: data if isinstance(data, list) else [data]}
    hosts: dict[str, dict[str, dict]] = {}
    for line in text.splitlines():  # osqueryd result log
        line = line.strip()
        if not line.startswith("{"):
            continue
        ev = json.loads(line)
        host = ev.get("hostIdentifier") or stem
        bucket = hosts.setdefault(host, {})
        if "snapshot" in ev:
            for r in ev["snapshot"]:
                bucket[json.dumps(r, sort_keys=True)] = r
        elif "columns" in ev:
            k = json.dumps(ev["columns"], sort_keys=True)
            if ev.get("action") == "removed":
                bucket.pop(k, None)
            else:
                bucket[k] = ev["columns"]
    return {h: list(b.values()) for h, b in hosts.items()}


def _items_for_host(host: str, rows: list[dict], everything: bool) -> list[dict]:
    out = []
    osr = next((r for r in rows if "platform" in r and ("major" in r or "codename" in r)), None)
    release = None
    if osr and osr.get("platform") in ("ubuntu", "debian", "raspbian"):
        release = packages.distro_release({"ID": osr.get("platform"), "VERSION_CODENAME": osr.get("codename", ""),
                                           "VERSION_ID": str(osr.get("major", ""))})
    win = next((r for r in rows if r.get("_table") == "windows_os"), None) or \
        (osr if osr and str(osr.get("platform", "")).lower() == "windows" else None)
    if win:
        w = windows_os(win, host)
        if w:
            out.append(w)
    # deb_packages also lists removed packages with config left ("deinstall ok config-files")
    debs = [r for r in rows if "source" in r and "arch" in r and "version" in r
            and str(r.get("status") or "installed").split()[-1:] == ["installed"]]
    if debs:
        text = "\n".join(f"{r['name']} {r['version']} {r.get('source') or r['name']}" for r in debs)
        try:
            out += dpkg_items(text, host, "all" if everything else None, release=release)
        except RuntimeError:
            pass
    for r in rows:
        if r is osr or r is win or r in debs or r.get("_table") == "kernel" or ("source" in r and "arch" in r):
            continue
        name = r.get("name") or r.get("DisplayName") or r.get("bundle_name") or ""
        ver = str(r.get("version") or r.get("DisplayVersion") or r.get("bundle_short_version") or "").strip()
        if "release" in r and "arch" in r:  # rpm_packages: upstream part only, distro may backport
            known = packages.PACKAGES.get(name)
            if known and ver:
                out.append(item(f"{known[0]} ({host})", version=ver, aliases=known[1], backports=True,
                                package=name, package_version=f"{ver}-{r['release']}"))
            continue
        if r.get("_table") == "homebrew":  # upstream builds: package names map directly
            known = packages.PACKAGES.get(name.split("@")[0].lower())
            if known and ver:
                out.append(item(f"{known[0]} ({host})", version=ver, aliases=known[1], package=name))
                continue
        it = program_item(name, ver, host, everything, r.get("publisher") or r.get("Publisher") or "")
        if it:
            out.append(it)
    kern = next((r for r in rows if r.get("_table") == "kernel"), None)
    if kern and osr:
        from .appliances import _guest_os
        plat = str(osr.get("platform") or "").lower()
        ver_id = (f"{osr.get('major', '')}.{int(osr.get('minor') or 0):02d}" if plat == "ubuntu"
                  else str(osr.get("major", "")))
        info = {"id": plat, "version-id": ver_id, "version-codename": osr.get("codename", ""),
                "kernel-release": kern.get("version", "")}
        out += [k for k in _guest_os(info, host) if k["name"].startswith("Linux kernel")]
    return out


def osquery(e: dict) -> list[dict]:
    """File mode (`path`) reads saved results; live mode (no `path`) runs osqueryi itself."""
    everything = e.get("programs", "known") == "all"
    out = []
    if e.get("path"):
        files = _files(e["path"])
        if not files:
            raise RuntimeError(f"no files match {e['path']!r}")
        by_host: dict[str, list[dict]] = {}
        for f in files:
            for host, rows in _rows_from_file(f).items():
                by_host.setdefault(e.get("host") or host, []).extend(rows)
        for host, rows in by_host.items():
            out += _items_for_host(host, rows, everything)
    else:
        host, rows = live_rows(e)
        out = _items_for_host(host, rows, everything)
    # one item per display name per host (the same app is often registered twice)
    seen, uniq = set(), []
    for it in out:
        if it["name"] not in seen:
            seen.add(it["name"])
            uniq.append(it)
    if not uniq:
        raise RuntimeError("no software cvescope can match in the osquery results")
    return uniq


# ---- live mode: run osqueryi (locally or over ssh) -----------------------
# osquery reads the host's own state. Nothing here touches the network beyond the ssh hop.

_OSQUERYI = ["osqueryi", r"C:\Program Files\osquery\osqueryi.exe", "/usr/local/bin/osqueryi",
             "/opt/osquery/bin/osqueryi"]
_WIN_CV = ("SELECT name, data FROM registry WHERE key = "
           "'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion' "
           "AND name IN ('UBR', 'DisplayVersion')")
QUERIES = {
    "windows": [("programs", "SELECT name, version, publisher FROM programs")],
    "darwin": [("apps", "SELECT name, bundle_short_version AS version FROM apps"),
               ("homebrew", "SELECT name, version FROM homebrew_packages")],
    "deb": [("deb", "SELECT name, version, source, arch, status FROM deb_packages")],
    "rpm": [("rpm", "SELECT name, version, release, arch FROM rpm_packages")],
}


def _runner(e: dict):
    prefix = list(e.get("command_prefix") or [])
    exe = e.get("osqueryi")
    if not exe:
        if prefix:
            exe = "osqueryi"
        else:
            exe = next((p for p in _OSQUERYI if shutil.which(p) or Path(p).is_file()), None)
            if not exe:
                raise RuntimeError('osqueryi not found: set osqueryi = "/path/to/osqueryi"')

    def q(sql: str) -> list[dict]:
        args = [exe, "--json", sql]
        out = _run(prefix + [shlex.join(args)] if prefix else args, e.get("timeout", 120))
        i = out.find("[")  # osqueryi can print warnings before the JSON
        return json.loads(out[i:out.rfind("]") + 1]) if i >= 0 else []
    return q


def _family(osr: dict) -> str | None:
    plat = str(osr.get("platform") or "").lower()
    like = f"{plat} {str(osr.get('platform_like') or '').lower()}"
    if plat in ("windows", "darwin"):
        return plat
    if "debian" in like or plat in ("ubuntu", "raspbian"):
        return "deb"
    if any(x in like for x in ("rhel", "fedora", "centos", "suse", "rocky", "alma", "amzn")):
        return "rpm"
    return None


def live_rows(e: dict, q=None) -> tuple[str, list[dict]]:
    """Run the per-OS queries through osqueryi and return (host, rows)."""
    q = q or _runner(e)
    osr = (q("SELECT * FROM os_version") or [{}])[0]
    fam = _family(osr)
    rows = [osr]
    if fam == "windows":
        reg = {r.get("name"): r.get("data") for r in q(_WIN_CV)}
        rows[0] = dict(osr, _table="windows_os", ubr=osr.get("revision") or reg.get("UBR") or "",
                       display_version=reg.get("DisplayVersion") or "")
    queries = [("custom", s) for s in e["queries"]] if e.get("queries") else QUERIES.get(fam, [])
    for table, sql in queries:
        rows += [dict(r, _table=table) if table == "homebrew" else r for r in q(sql)]
    if fam in ("deb", "rpm"):
        rows += [dict(r, _table="kernel") for r in q("SELECT version FROM kernel_info")]
    host = e.get("name")
    if not host:
        info = q("SELECT hostname FROM system_info")
        host = (info[0].get("hostname") if info else None) or "host"
    return host, rows
