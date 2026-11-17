"""Collectors that ask homelab gear for its own version over its API. All read-only."""

from __future__ import annotations

import base64
import json

from .. import db, net
from ..config import expand
from . import item, packages, secret


def _client(e: dict) -> net.PinnedClient:
    return net.PinnedClient(e["url"], e.get("pin_sha256", ""), e.get("verify_tls", False),
                            e.get("allow_insecure", False))


# ---- Proxmox VE ---------------------------------------------------------

PVE_PACKAGES = {
    "pve-qemu-kvm": ("QEMU", ["qemu:qemu"]),
    "lxc-pve": ("LXC", ["linuxcontainers:lxc", "canonical:lxc"]),
    "proxmox-backup-client": ("Proxmox Backup Client", ["proxmox:backup client", "proxmox:proxmox backup client"]),
    "corosync": ("Corosync", ["corosync:corosync"]),
}


def proxmox(e: dict) -> list[dict]:
    """url, token_file (user@realm!id=secret; PVEAuditor is enough), pin_sha256.
    packages = true also adds QEMU, LXC and the running kernel."""
    c = _client(e)
    tok = secret(e, "token")
    if " " in tok:  # "host user@realm!id=secret" lines, one per host
        host = c.host
        lines = [l.split() for l in tok.splitlines() if l.strip()]
        tok = next((l[-1] for l in lines if l[0] == host), lines[0][-1])
    h = {"Authorization": "PVEAPIToken=" + tok}
    v = c.get("/api2/json/version", h)["data"]
    nodes = [n["node"] for n in c.get("/api2/json/nodes", h)["data"]]
    label = e.get("name") or f"Proxmox VE ({', '.join(nodes) or c.host})"
    out = [item(label, "proxmox", "virtual environment", v["version"],
                aliases=["proxmox:proxmox virtual environment", "proxmox:proxmox ve", "proxmox:pve manager",
                         "proxmox:pve*", "proxmox:proxmox ve*"],
                keywords=["Proxmox VE", "Proxmox Virtual Environment"], host=c.host)]
    if e.get("guests", True):
        out += _pve_guests(c, h)
    if e.get("packages") and nodes:
        apt = c.get(f"/api2/json/nodes/{nodes[0]}/apt/versions", h)["data"]
        for p in apt:
            name = p.get("Package")
            if p.get("RunningKernel"):
                kv = p["RunningKernel"].split("-")[0]
                out.append(item(f"Linux kernel ({nodes[0]})", "linux", "linux kernel", kv,
                                aliases=["linux:linux"], backports=True, running=p["RunningKernel"]))
            if name in PVE_PACKAGES:
                disp, al = PVE_PACKAGES[name]
                out.append(item(f"{disp} ({nodes[0]})", version=packages.pkg_version(p["Version"]),
                                aliases=al, backports=True, package=name))
    return out


def _guest_os(info: dict, label: str) -> list[dict]:
    """QEMU guest agent get-osinfo -> OS item (+ kernel item for Linux guests)."""
    gid = (info.get("id") or "").lower()
    ver = info.get("version-id") or info.get("version") or ""
    pretty = info.get("pretty-name") or info.get("name") or gid
    kr = info.get("kernel-release") or ""
    out = []
    if gid == "freebsd":
        out.append(item(f"{pretty} ({label})", "freebsd", "freebsd", kr or ver, backports=True))
    elif gid == "haos":
        out.append(item(f"Home Assistant OS ({label})", "home assistant", "operating system", ver,
                        aliases=["home assistant:home assistant operating system", "home assistant:os"]))
    elif gid in ("debian", "ubuntu"):
        code = (info.get("version-codename") or "").lower()
        release = f"debian:{ver.split('.')[0]}" if gid == "debian" else (f"ubuntu:{code}" if code else None)
        out.append(item(f"{pretty} ({label})", gid, f"{gid} linux", ver, guest_os=True, distro=release))
    elif gid == "mswindows":
        name = info.get("name") or "Windows"
        out.append(item(f"{pretty} ({label})", "microsoft", db.norm(name.replace("Microsoft ", "")),
                        f"10.0.{kr}" if kr.isdigit() else ver, backports=True,
                        note="build revision unknown: check Windows Update"))
    else:
        out.append(item(f"{pretty} ({label})", version=ver or None, aliases=[f"*:{db.norm(info.get('name') or gid)}"]))
    if kr and gid not in ("freebsd", "mswindows"):
        up = kr.split("-")[0].split("+")[0]
        extra = {"backports": True, "running": kr}
        if gid == "debian":
            extra.update(distro=f"debian:{ver.split('.')[0]}", source="linux",
                         package_version=f"{up}-1")  # agent reports no Debian revision: assume the first
        elif gid == "ubuntu" and kr.count("-") >= 2:
            abi = kr.split("-")[1]
            extra.update(distro=out[0]["extra"].get("distro"), source="linux", package_version=f"{up}-{abi}.{abi}")
        out.append(item(f"Linux kernel ({label})", "linux", "linux kernel", up, aliases=["linux:linux"], **extra))
    return out



def _pve_guests(c, h) -> list[dict]:
    """Every VM and container. VMs with the guest agent report their OS; containers only a type."""
    out = []
    for g in c.get("/api2/json/cluster/resources?type=vm", h).get("data") or []:
        kind = "VM" if g["type"] == "qemu" else "CT"
        label = f"{kind} {g['vmid']} {g.get('name') or ''}".strip()
        base = f"/api2/json/nodes/{g['node']}/{g['type']}/{g['vmid']}"
        info = None
        if g["type"] == "qemu" and g.get("status") == "running":
            try:
                info = c.get(base + "/agent/get-osinfo", h)["data"]["result"]
            except Exception:
                info = None  # no agent, agent not running, or no permission
        if info:
            out += _guest_os(info, label)
            continue
        try:
            ostype = c.get(base + "/config", h)["data"].get("ostype") or "unknown"
        except Exception:
            ostype = "unknown"
        out.append(item(f"{ostype} {'container' if kind == 'CT' else 'VM'} ({label})", guest=True,
                        status=g.get("status"),
                        hint="no version visible from Proxmox: add a dpkg or osquery collector for it"))
    return out


# ---- Pi-hole v6 ---------------------------------------------------------

def pihole(e: dict) -> list[dict]:
    """url, password_file (or password_env), pin_sha256. Logs in, reads versions, logs out."""
    c = _client(e)
    pw = secret(e, "password")
    s = c.request("POST", "/api/auth", body={"password": pw}).get("session") or {}
    if not s.get("valid"):
        raise RuntimeError("Pi-hole login failed")
    sid = s.get("sid")
    try:
        v = c.get("/api/info/version", {"X-FTL-SID": sid}).get("version") or {}
    finally:
        if sid:
            try:
                c.request("DELETE", "/api/auth", {"X-FTL-SID": sid})
            except Exception:
                pass
    host = e.get("name") or c.host

    def ver(part):
        loc = (v.get(part) or {}).get("local") or {}
        rem = (v.get(part) or {}).get("remote") or {}
        return loc.get("version"), rem.get("version")

    out = []
    for part, disp, product, al in (
        ("core", "Pi-hole core", "pi-hole", ["pi hole:pi hole", "pi hole:pihole", "pihole:pi hole", "pi hole:core"]),
        ("ftl", "Pi-hole FTL", "ftl", ["pi hole:ftldns", "pi hole:ftl dns", "pi hole:pi hole ftl"]),
        ("web", "Pi-hole web", "web", ["pi hole:adminlte", "pi hole:web interface", "pi hole:pi hole web"]),
    ):
        cur, latest = ver(part)
        out.append(item(f"{disp} ({host})", "pi-hole", product, cur, aliases=al,
                        keywords=["Pi-hole"] if part == "core" else [], latest=latest))
    return out


# ---- Home Assistant -----------------------------------------------------

def homeassistant(e: dict) -> list[dict]:
    """url, token_file or token_env (long-lived access token). Supervisor info and
    add-ons need an admin token through the hassio proxy; skipped quietly when refused."""
    c = _client(e)
    h = {"Authorization": "Bearer " + secret(e, "token")}
    cfg = c.get("/api/config", h)
    out = [item(e.get("name") or "Home Assistant Core", "home assistant", "home assistant core",
                cfg.get("version"),
                aliases=["home assistant:core", "home assistant:home assistant",
                         "home assistant:homeassistant", "home assistant:home assistant*"],
                keywords=["Home Assistant"])]
    try:
        osv = (c.get("/api/hassio/os/info", h).get("data") or {}).get("version")
        if osv:
            out.append(item("Home Assistant OS", "home assistant", "operating system", osv,
                            aliases=["home assistant:home assistant operating system", "home assistant:os"]))
        if e.get("addons", True):
            for a in (c.get("/api/hassio/addons", h).get("data") or {}).get("addons") or []:
                key = (a.get("name") or "").lower().replace("-", " ")
                for app, (disp, al) in packages.APPS.items():
                    if app in key:
                        out.append(item(f"{disp} (HA add-on)", version=a.get("version"), aliases=al,
                                        addon=a.get("slug"), addon_version=True))
                        break
    except net.HTTPStatus:
        pass
    return out


# ---- UniFi Network ------------------------------------------------------

def unifi(e: dict) -> list[dict]:
    """url (UniFi OS console or server, e.g. https://192.168.1.1), apikey_file, pin_sha256.
    devices = true (default) adds each adopted device with its firmware."""
    c = _client(e)
    h = {"X-API-KEY": secret(e, "apikey")}
    info = c.get("/proxy/network/integration/v1/info", h)
    out = [item(e.get("name") or "UniFi Network Application", "ubiquiti", "unifi network application",
                info.get("applicationVersion"),
                aliases=["ubiquiti:unifi network", "ubiquiti:unifi network server",
                         "ubiquiti:unifi network controller", "ubiquiti:unifi controller", "ui:unifi network*"],
                keywords=["UniFi Network"])]
    if e.get("devices", True):
        for s in c.get("/proxy/network/integration/v1/sites", h).get("data") or []:
            devs = c.get(f"/proxy/network/integration/v1/sites/{s['id']}/devices?limit=200", h)
            for d in devs.get("data") or []:
                model = d.get("model") or "device"
                feats = [f.lower() for f in d.get("features") or []]
                kind = ("unifi access point*" if "accesspoint" in feats else
                        "unifi switch*" if "switching" in feats else "unifi*")
                out.append(item(f"UniFi {model} ({d.get('name') or d.get('ipAddress')})", "ubiquiti",
                                f"unifi {model}", d.get("firmwareVersion"),
                                aliases=[f"ubiquiti:{kind}", f"ubiquiti:{model.lower()}*"], model=model))
    return out


# ---- OPNsense -----------------------------------------------------------

OPN_PACKAGES = [
    "openssh-portable", "unbound", "dnsmasq", "suricata", "lighttpd", "strongswan", "openvpn",
    "curl", "sudo", "php83", "php84", "php82", "squid", "haproxy", "frr", "bind918", "bind920",
    "ntp", "samba", "kea", "wireguard-tools", "openssl3",
]


def _opn_creds(e: dict) -> tuple[str, str]:
    if e.get("credentials_json"):
        d = json.loads(expand(e["credentials_json"]).read_text(encoding="utf-8"))
        if e.get("profile"):
            d = d[e["profile"]]
        return d["api_key"], d["api_secret"]
    return secret(e, "key"), secret(e, "secret")


def opnsense(e: dict) -> list[dict]:
    """url, key_file + secret_file (or credentials_json [+ profile]), pin_sha256.
    packages = true (default) adds the base-system daemons that matter (OpenSSH, Unbound, ...)."""
    c = _client(e)
    k, s = _opn_creds(e)
    h = {"Authorization": "Basic " + base64.b64encode(f"{k}:{s}".encode()).decode()}
    info = c.get("/api/core/firmware/info", h)
    ver = packages.pkg_version(info.get("product_version") or (info.get("product") or {}).get("product_version", ""))
    out = [item(e.get("name") or "OPNsense", "opnsense", "opnsense", ver,
                aliases=["deciso:opnsense", "opnsense:core", "deciso b v:opnsense"], keywords=["OPNsense"])]
    try:
        si = c.get("/api/diagnostics/system/system_information", h)
        for line in si.get("versions") or []:
            if line.startswith("FreeBSD "):
                # keep "15.1-RELEASE-p6": FreeBSD advisories are written against patch levels
                out.append(item("FreeBSD (OPNsense base)", "freebsd", "freebsd", line.split()[1],
                                backports=True, full=line))
            elif line.startswith("OpenSSL "):
                out.append(item("OpenSSL (OPNsense)", "openssl", "openssl", line.split()[1]))
    except net.HTTPStatus:
        pass
    if e.get("packages", True):
        installed = {p["name"]: p["version"] for p in info.get("package") or []
                     if str(p.get("installed")) == "1"}
        seen = set()
        for name in OPN_PACKAGES:
            if name in installed and name in packages.PACKAGES:
                disp, al = packages.PACKAGES[name]
                if disp in seen:
                    continue
                seen.add(disp)
                out.append(item(f"{disp} (OPNsense)", version=packages.pkg_version(installed[name]),
                                aliases=al, package=name, package_version=installed[name]))
    return out
