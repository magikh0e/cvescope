"""Web-app versions from scanner output you produced yourself (cvescope doesn't run scanners).

    wpscan --url https://blog.example --enumerate vp,vt --format json -o blog.json
    [[inventory]]
    type = "wpscan"
    path = "~/scans/wpscan/*.json"

    whatweb --log-json=site.json https://example.org
    [[inventory]]
    type = "whatweb"
    path = "~/scans/whatweb/*.json"
"""

from __future__ import annotations

import json
import re
import urllib.parse
from pathlib import Path

from .. import db
from . import item, packages
from .nmap import _files

_V = re.compile(r"\d+(?:\.\d+)+[a-z]?\d*")

# WhatWeb plugin names -> (display, aliases)
WHATWEB = {
    "apache": packages.PACKAGES["apache2"], "nginx": packages.PACKAGES["nginx"],
    "lighttpd": packages.PACKAGES["lighttpd"], "microsoft-iis": packages.NMAP["microsoft iis httpd"],
    "php": packages.PACKAGES["php"], "openssl": packages.PACKAGES["openssl"],
    "wordpress": ("WordPress", ["wordpress:wordpress"]), "drupal": ("Drupal", ["drupal:drupal core", "drupal:drupal"]),
    "joomla": ("Joomla!", ["joomla:joomla", "joomla project:joomla"]), "jquery": ("jQuery", ["jquery:jquery"]),
    "jquery-ui": ("jQuery UI", ["jquery:jquery ui"]), "bootstrap": ("Bootstrap", ["getbootstrap:bootstrap", "bootstrap:bootstrap"]),
    "moodle": ("Moodle", ["moodle:moodle"]), "phpmyadmin": ("phpMyAdmin", ["phpmyadmin:phpmyadmin"]),
    "apache-tomcat": packages.NMAP["apache tomcat"], "jetty": packages.NMAP["jetty"],
    "varnish": ("Varnish", ["varnish cache:varnish cache", "varnish software:varnish cache"]),
    "openresty": packages.NMAP["openresty web app server"], "grafana": packages.APPS["grafana"],
    "gitlab": ("GitLab", ["gitlab:gitlab"]), "roundcube": ("Roundcube Webmail", ["roundcube:roundcube webmail"]),
    "confluence": ("Confluence", ["atlassian:confluence data center", "atlassian:confluence server"]),
    "jira": ("Jira", ["atlassian:jira server", "atlassian:jira software data center"]),
    "magento": ("Magento", ["adobe:commerce", "magento:magento"]), "prestashop": ("PrestaShop", ["prestashop:prestashop"]),
    "typo3": ("TYPO3", ["typo3:typo3"]), "mediawiki": ("MediaWiki", ["mediawiki:mediawiki", "wikimedia foundation:mediawiki"]),
    "nextcloud": ("Nextcloud Server", ["nextcloud:nextcloud server"]),
}


def _site(url: str) -> str:
    return urllib.parse.urlsplit(url).netloc or url


def _slug_aliases(slug: str) -> list[str]:
    n = db.norm(slug)
    out = [f"*:{n}"]
    if len(n) >= 5:
        out.append(f"*:{n}*")  # "elementor" -> "Elementor Website Builder - More than ..."
    return out


def wpscan(e: dict) -> list[dict]:
    """WordPress core, the active theme and every plugin WPScan found, with versions."""
    files = _files(e["path"])
    if not files:
        raise RuntimeError(f"no WPScan JSON matches {e['path']!r}")
    out = []
    for f in files:
        d = json.loads(Path(f).read_text(encoding="utf-8-sig"))
        site = _site(d.get("target_url") or d.get("effective_url") or Path(f).stem)
        core = (d.get("version") or {}).get("number")
        if core:
            out.append(item(f"WordPress ({site})", "wordpress", "wordpress", core, site=site))
        themes = [d.get("main_theme")] + list((d.get("themes") or {}).values())
        for kind, entries in (("plugin", (d.get("plugins") or {}).values()), ("theme", themes)):
            for p in entries:
                if not p:
                    continue
                slug = p.get("slug") or ""
                ver = ((p.get("version") or {}) or {}).get("number")
                if not slug or not ver:
                    continue
                out.append(item(f"WP {kind} {slug} ({site})", version=ver, aliases=_slug_aliases(slug),
                                site=site, slug=slug, wp_kind=kind))
    if not out:
        raise RuntimeError("no versioned WordPress components in the WPScan output")
    return out


def _whatweb_records(text: str) -> list[dict]:
    text = text.strip()
    if text.startswith("["):
        data = json.loads(text.rstrip(",\n ") if not text.endswith("]") else text)
        return [r for r in data if isinstance(r, dict)]
    recs = []
    for line in text.splitlines():  # some versions write one object per line
        line = line.strip().rstrip(",")
        if line.startswith("{"):
            recs.append(json.loads(line))
    return recs


def whatweb(e: dict) -> list[dict]:
    files = _files(e["path"])
    if not files:
        raise RuntimeError(f"no WhatWeb JSON matches {e['path']!r}")
    out, seen = [], set()
    for f in files:
        for rec in _whatweb_records(Path(f).read_text(encoding="utf-8-sig")):
            site = _site(rec.get("target") or "")
            for plugin, data in (rec.get("plugins") or {}).items():
                versions = [v for v in (data or {}).get("version") or [] if _V.search(str(v))]
                if not versions:
                    continue
                ver = _V.search(str(versions[0])).group(0)
                key = plugin.lower()
                disp, aliases = WHATWEB.get(key) or (plugin, [f"*:{db.norm(plugin)}"])
                name = f"{disp} ({site})"
                if name in seen:
                    continue
                seen.add(name)
                out.append(item(name, version=ver, aliases=aliases, site=site, whatweb_plugin=plugin))
    if not out:
        raise RuntimeError("no versioned components in the WhatWeb output")
    return out
