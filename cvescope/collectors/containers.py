"""Running containers from Docker or Podman, locally or over ssh. Read-only (`ps` only).

    [[inventory]]
    type = "docker"
    name = "vps"
    command_prefix = ["ssh", "vps"]   # omit for the local engine
    engine = "docker"                 # or "podman"
    all = false                       # true also lists stopped containers

The app inside each container is named from its image (grafana/grafana -> Grafana) and its
version comes from the tag, or the image's version label when the tag is "latest".
Packages inside the image are out of scope: use an SBOM tool for those.
"""

from __future__ import annotations

import json
import re
import shlex

from .. import db
from . import item, packages
from .generic import _run

_FLOATING = {"", "latest", "stable", "main", "master", "edge", "nightly", "release", "lts", "develop", "dev"}
_VER = re.compile(r"^(?:version-)?v?(\d+(?:\.\d+)*(?:[a-z]\d*)?)")
_LSIO = re.compile(r"version:-\s*v?(\d[\w.]*)", re.I)

# image repo (registry stripped) or its last path segment -> (display, aliases)
IMAGES: dict[str, tuple[str, list[str]]] = {
    "grafana/grafana": packages.APPS["grafana"], "grafana/grafana-oss": packages.APPS["grafana"],
    "nginx": packages.PACKAGES["nginx"], "nginxinc/nginx-unprivileged": packages.PACKAGES["nginx"],
    "httpd": packages.PACKAGES["apache2"], "tomcat": packages.NMAP["apache tomcat"],
    "postgres": packages.NMAP["postgresql db"], "mysql": packages.NMAP["mysql"],
    "mariadb": packages.APPS["mariadb"], "redis": packages.NMAP["redis key-value store"],
    "mongo": packages.NMAP["mongodb"], "memcached": ("Memcached", ["memcached:memcached"]),
    "traefik": ("Traefik", ["traefik:traefik", "traefiklabs:traefik"]), "caddy": packages.NMAP["caddy httpd"],
    "haproxy": packages.PACKAGES["haproxy"], "eclipse-mosquitto": packages.PACKAGES["mosquitto"],
    "nodered/node-red": packages.APPS["node red"], "koenkk/zigbee2mqtt": packages.APPS["zigbee2mqtt"],
    "home-assistant/home-assistant": ("Home Assistant Core", ["home assistant:home assistant core", "home assistant:core"]),
    "homeassistant/home-assistant": ("Home Assistant Core", ["home assistant:home assistant core", "home assistant:core"]),
    "esphome/esphome": packages.APPS["esphome"],
    "portainer/portainer-ce": packages.APPS["portainer"], "portainer/portainer": packages.APPS["portainer"],
    "vaultwarden/server": packages.APPS["vaultwarden"], "jellyfin/jellyfin": packages.APPS["jellyfin"],
    "plexinc/pms-docker": packages.APPS["plex media server"], "gitea/gitea": ("Gitea", ["gitea:gitea"]),
    "nextcloud": ("Nextcloud Server", ["nextcloud:nextcloud server"]), "wordpress": ("WordPress", ["wordpress:wordpress"]),
    "jenkins/jenkins": ("Jenkins", ["jenkins project:jenkins", "jenkins:jenkins"]),
    "minio/minio": ("MinIO", ["minio:minio"]), "louislam/uptime-kuma": ("Uptime Kuma", ["louislam:uptime kuma"]),
    "n8nio/n8n": ("n8n", ["n8n:n8n", "n8n io:n8n"]), "adguard/adguardhome": packages.APPS["adguard home"],
    "elasticsearch": ("Elasticsearch", ["elastic:elasticsearch"]), "kibana": ("Kibana", ["elastic:kibana"]),
    "keycloak/keycloak": ("Keycloak", ["red hat:keycloak", "keycloak:keycloak"]),
    "authelia/authelia": ("Authelia", ["authelia:authelia"]), "influxdb": packages.APPS["influxdb"],
    "rabbitmq": ("RabbitMQ", ["vmware:rabbitmq", "broadcom:rabbitmq", "pivotal software:rabbitmq"]),
    "gitlab/gitlab-ce": ("GitLab", ["gitlab:gitlab"]), "gitlab/gitlab-ee": ("GitLab", ["gitlab:gitlab"]),
    "sonarqube": ("SonarQube", ["sonarsource:sonarqube"]), "registry": ("Docker Registry", ["docker:distribution"]),
    "blakeblackshear/frigate": packages.APPS["frigate"], "jc21/nginx-proxy-manager": ("Nginx Proxy Manager", ["jc21:nginx proxy manager"]),
    "sonarr": ("Sonarr", ["sonarr:sonarr"]), "radarr": ("Radarr", ["radarr:radarr"]), "prowlarr": ("Prowlarr", ["prowlarr:prowlarr"]),
    "qbittorrent": ("qBittorrent", ["qbittorrent:qbittorrent"]), "transmission": ("Transmission", ["transmissionbt:transmission"]),
    "syncthing/syncthing": ("Syncthing", ["syncthing:syncthing"]), "syncthing": ("Syncthing", ["syncthing:syncthing"]),
}


def image_parts(ref: str) -> tuple[str, str]:
    """'lscr.io/linuxserver/sonarr:4.0.9@sha256:..' -> ('linuxserver/sonarr', '4.0.9')"""
    ref = ref.split("@")[0]
    first, _, rest = ref.partition("/")
    if rest and ("." in first or ":" in first or first == "localhost"):
        ref = rest  # drop the registry host
    name, _, tag = ref.rpartition(":") if ":" in ref.rsplit("/", 1)[-1] else (ref, "", "")
    if name.startswith("library/"):
        name = name[8:]
    return name.lower(), tag


def _labels(raw) -> dict:
    if isinstance(raw, dict):
        return raw
    out = {}
    for part in str(raw or "").split(","):
        k, sep, v = part.partition("=")
        if sep:
            out[k.strip()] = v.strip()
    return out


def version_of(tag: str, labels: dict) -> str | None:
    if tag.lower() not in _FLOATING:
        m = _VER.match(tag)
        if m:
            return m.group(1)
    for k in ("org.opencontainers.image.version", "org.label-schema.version", "version"):
        m = _VER.match(str(labels.get(k) or ""))
        if m:
            return m.group(1)
    m = _LSIO.search(str(labels.get("build_version") or ""))  # linuxserver.io images
    return m.group(1) if m else None


def parse_ps(out: str) -> list[dict]:
    """docker ps --format '{{json .}}' (JSON lines) or podman ps --format json (array)."""
    out = out.strip()
    if not out:
        return []
    rows = json.loads(out) if out.startswith("[") else [json.loads(ln) for ln in out.splitlines() if ln.strip().startswith("{")]
    res = []
    for r in rows:
        names = r.get("Names")
        res.append({"image": r.get("Image") or "", "name": ",".join(names) if isinstance(names, list) else (names or ""),
                    "labels": _labels(r.get("Labels")), "state": r.get("State") or r.get("Status") or ""})
    return res


def items_from(containers: list[dict], host: str) -> list[dict]:
    out, seen = [], set()
    for c in containers:
        repo, tag = image_parts(c["image"])
        known = IMAGES.get(repo) or IMAGES.get(repo.rsplit("/", 1)[-1])
        last = repo.rsplit("/", 1)[-1]
        disp, aliases = known if known else (last, [f"*:{db.norm(last)}"])
        ver = version_of(tag, c["labels"])
        key = (disp, ver, c["name"])
        if key in seen:
            continue
        seen.add(key)
        extra = {"image": c["image"], "container": c["name"], "state": c["state"],
                 "unmapped_image": None if known else repo}
        if not ver:
            # every CVE for the product would show up as "check": list it, match nothing
            aliases, extra["hint"] = [], "floating tag and no version label: pin a version tag to match it"
        out.append(item(f"{disp} ({c['name'] or repo} @ {host})", version=ver, aliases=aliases, **extra))
    return out


def docker(e: dict) -> list[dict]:
    eng = e.get("engine", "docker")
    args = [eng, "ps", "--no-trunc", "--format", "json" if eng == "podman" else "{{json .}}"]
    if e.get("all"):
        args.append("-a")
    prefix = list(e.get("command_prefix") or [])
    cmd = prefix + [shlex.join(args)] if prefix else args  # ssh needs one quoted remote command
    host = e.get("name") or (prefix[-1] if prefix else "local")
    items = items_from(parse_ps(_run(cmd, e.get("timeout", 60))), host)
    if not items:
        raise RuntimeError(f"{eng} reports no containers")
    return items
