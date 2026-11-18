"""Feed registry. Each source is a function (con, cfg) -> one-line summary."""

from __future__ import annotations

import time
import traceback

from .. import db
from . import cvelist, distro, endoflife, epss, exploits, freebsd, kev, osvpkg, proxmox_psa

SOURCES = {
    "cvelist": cvelist.sync,
    "kev": kev.sync,
    "epss": epss.sync,
    "metasploit": exploits.metasploit,
    "nuclei": exploits.nuclei,
    "exploitdb": exploits.exploitdb,
    "github_poc": exploits.github_poc,
    "local_archive": exploits.local_archive,
    "distro": distro.sync,
    "freebsd": freebsd.sync,
    "osv": osvpkg.sync,
    "proxmox": proxmox_psa.sync,
    "endoflife": endoflife.sync,
}

# Who each feed's data comes from: (label, link, what it is). The page's feed list, the CVE
# detail and reports credit the sources by this.
CREDITS = {
    "cvelist": ("CVE List", "https://www.cve.org/",
                "CVE records from the CVE Program, with CISA's Vulnrichment (SSVC, CVSS, CPEs)"),
    "kev": ("CISA KEV", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            "CISA's Known Exploited Vulnerabilities catalog"),
    "epss": ("FIRST EPSS", "https://www.first.org/epss/", "Exploit Prediction Scoring System scores from FIRST"),
    "metasploit": ("Metasploit", "https://github.com/rapid7/metasploit-framework", "Metasploit Framework module metadata"),
    "nuclei": ("Nuclei templates", "https://github.com/projectdiscovery/nuclei-templates",
               "ProjectDiscovery's Nuclei templates"),
    "exploitdb": ("Exploit-DB", "https://www.exploit-db.com/", "the Exploit Database index"),
    "github_poc": ("PoC-in-GitHub", "https://github.com/nomi-sec/PoC-in-GitHub", "nomi-sec's index of GitHub PoC repos"),
    "local_archive": ("your archive", None, "your own folders"),
    "distro": ("Debian / Ubuntu trackers", "https://security-tracker.debian.org/",
               "Debian's security tracker and Ubuntu's OVAL feed"),
    "freebsd": ("FreeBSD VuXML", "https://vuxml.freebsd.org/", "FreeBSD's vulnerability database (what pkg audit reads)"),
    "osv": ("OSV.dev", "https://osv.dev/", "the OSV open source vulnerability database"),
    "proxmox": ("Proxmox VE advisories", "https://forum.proxmox.com/threads/proxmox-virtual-environment-"
                "security-advisories.149331/", "Proxmox's security advisories (PSAs)"),
    "endoflife": ("endoflife.date", "https://endoflife.date/", "release and end-of-life dates"),
}
# NVD's terms of use ask every product that uses its API to show this
NVD_NOTICE = "This product uses the NVD API but is not endorsed or certified by the NVD."


def credit(name: str) -> dict:
    """Label, link and description for a feed's row in the source table (some feeds keep one per part)."""
    if name == "distro:debian":
        label, url, what = ("Debian security tracker", "https://security-tracker.debian.org/",
                            "fixed package versions per Debian release")
    elif name.startswith("distro:ubuntu:"):
        label, url, what = (f"Ubuntu OVAL ({name.split(':', 2)[2]})", "https://security-metadata.canonical.com/oval/",
                            "fixed package versions per Ubuntu release")
    elif name.startswith("local:"):
        label, url, what = f"your archive: {name[6:]}", None, "files in your own folders that mention a CVE"
    else:
        label, url, what = CREDITS.get(name, (name, None, ""))
    return {"label": label, "url": url, "what": what}


def enabled(cfg) -> list[str]:
    s = cfg["sources"]
    out = []
    for name in SOURCES:
        v = s.get(name, True)
        if name == "local_archive":
            if v:
                out.append(name)
        elif v:
            out.append(name)
    return out


def run(con, cfg, only: list[str] | None = None, rebaseline: bool = False,
        verbose: bool = False) -> dict[str, str]:
    results = {}
    for name in enabled(cfg):
        if only and name not in only:
            continue
        t = time.time()
        print(f"[{name}]", flush=True)
        try:
            if name == "cvelist":
                msg = SOURCES[name](con, cfg, rebaseline=rebaseline)
            else:
                msg = SOURCES[name](con, cfg)
            results[name] = msg
            print(f"  {msg} ({time.time() - t:.0f}s)", flush=True)
        except Exception as e:  # one broken feed must not stop the others
            con.rollback()
            err = f"{type(e).__name__}: {e}"
            db.source_err(con, name, err)
            results[name] = "ERROR " + err
            print(f"  ERROR {err}", flush=True)
            if verbose:
                traceback.print_exc()
    return results
