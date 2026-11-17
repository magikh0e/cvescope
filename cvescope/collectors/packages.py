"""Package name -> how CVE records name the product.

Aliases are "vendor:product" in normalized form (lowercase, punctuation -> space).
A leading "*:" matches any vendor; a trailing "*" is a prefix match.
Add to this freely: it's the main thing that decides match quality.
"""

from __future__ import annotations

import re

# package names (Debian/Ubuntu, FreeBSD/OPNsense, Alpine) -> (display name, aliases)
PACKAGES: dict[str, tuple[str, list[str]]] = {}


def _add(names, display, aliases):
    for n in names:
        PACKAGES[n] = (display, aliases)


_add(["openssh-server", "openssh-client", "openssh", "openssh-portable"], "OpenSSH",
     ["openbsd:openssh", "openssh:openssh"])
_add(["openssl", "libssl3", "libssl3t64", "libssl1.1", "openssl3"], "OpenSSL", ["openssl:openssl"])
_add(["apache2", "httpd", "apache24"], "Apache HTTP Server",
     ["apache software foundation:apache http server", "apache:http server",
      "apache software foundation:http server"])
_add(["nginx", "nginx-core", "nginx-full"], "nginx",
     ["f5:nginx", "nginx:nginx", "f5:nginx open source", "f5:nginx oss", "f5:nginx plus"])
_add(["sudo"], "sudo", ["sudo project:sudo", "todd miller:sudo", "sudo:sudo"])
_add(["bash"], "Bash", ["gnu:bash"])
_add(["libc6", "glibc", "libc-bin"], "glibc", ["gnu:glibc", "gnu:gnu c library", "gnu:c library"])
_add(["curl", "libcurl4", "libcurl4t64"], "curl", ["haxx:curl", "curl:curl", "haxx:libcurl"])
_add(["unbound"], "Unbound", ["nlnet labs:unbound", "nlnetlabs:unbound"])
_add(["dnsmasq", "dnsmasq-base"], "dnsmasq", ["thekelleys:dnsmasq", "dnsmasq:dnsmasq"])
_add(["wireguard-tools", "wireguard-go"], "WireGuard tools", ["wireguard:wireguard tools", "wireguard:wireguard"])
_add(["docker-ce", "docker.io", "docker-engine"], "Docker Engine",
     ["docker:docker", "docker:docker engine", "docker:engine", "moby project:moby", "mobyproject:moby"])
_add(["containerd", "containerd.io"], "containerd", ["linux foundation:containerd", "containerd:containerd"])
_add(["runc"], "runc", ["linux foundation:runc", "opencontainers:runc", "opencontainers:runc"])
_add(["fail2ban", "py311-fail2ban"], "fail2ban", ["fail2ban:fail2ban"])
_add(["libapache2-mod-security2", "modsecurity", "ap24-mod_security"], "ModSecurity",
     ["trustwave:modsecurity", "owasp:modsecurity"])
_add(["suricata"], "Suricata", ["oisf:suricata"])
_add(["strongswan"], "strongSwan", ["strongswan:strongswan"])
_add(["openvpn"], "OpenVPN", ["openvpn:openvpn", "openvpn:openvpn community"])
_add(["samba"], "Samba", ["samba:samba"])
_add(["xz-utils", "xz", "liblzma5"], "XZ Utils", ["tukaani:xz", "tukaani project:xz"])
_add(["systemd"], "systemd", ["systemd project:systemd", "freedesktop:systemd", "systemd:systemd"])
_add(["policykit-1", "polkitd", "polkit"], "polkit", ["polkit project:polkit", "freedesktop:polkit"])
_add(["ntp", "ntpsec"], "NTP", ["ntp:ntp"])
_add(["chrony"], "chrony", ["chrony project:chrony", "tuxfamily:chrony"])
_add(["lighttpd"], "lighttpd", ["lighttpd:lighttpd"])
_add(["haproxy"], "HAProxy", ["haproxy:haproxy"])
_add(["squid"], "Squid", ["squid cache:squid", "squid:squid"])
_add(["bind9", "bind918", "bind920"], "BIND 9", ["isc:bind", "isc:bind 9", "isc:bind9"])
_add(["kea", "isc-kea-dhcp4-server"], "Kea DHCP", ["isc:kea"])
_add(["zlib1g", "zlib"], "zlib", ["zlib:zlib", "gnu:zlib"])
_add(["libexpat1", "expat"], "libexpat", ["libexpat project:libexpat", "libexpat:libexpat"])
_add(["libxml2"], "libxml2", ["xmlsoft:libxml2", "gnome:libxml2"])
_add(["sqlite3", "libsqlite3-0", "sqlite3-tcl"], "SQLite", ["sqlite:sqlite"])
_add(["exim4", "exim4-daemon-light"], "Exim", ["exim:exim"])
_add(["postfix"], "Postfix", ["postfix:postfix"])
_add(["mosquitto"], "Mosquitto", ["eclipse:mosquitto", "eclipse foundation:eclipse mosquitto"])
_add(["php", "php8.1", "php8.2", "php8.3", "php8.4", "php83", "php84"], "PHP",
     ["php:php", "php group:php"])
_add(["git"], "Git", ["git scm:git", "git:git"])
_add(["frr"], "FRRouting", ["frrouting:frrouting", "linux foundation:frrouting"])
_add(["dropbear", "dropbear-bin"], "Dropbear SSH", ["dropbear ssh project:dropbear ssh", "matt johnston:dropbear ssh"])
_add(["cups"], "CUPS", ["openprinting:cups", "apple:cups"])
_add(["avahi-daemon", "avahi"], "Avahi", ["avahi:avahi"])
_add(["rsync"], "rsync", ["samba:rsync", "rsync:rsync"])

# common add-on / app names (Home Assistant add-ons, containers) -> aliases
APPS: dict[str, tuple[str, list[str]]] = {
    "mosquitto": ("Mosquitto", ["eclipse:mosquitto", "eclipse foundation:eclipse mosquitto"]),
    "node red": ("Node-RED", ["openjs foundation:node red", "nodered:node red", "node red:node red"]),
    "esphome": ("ESPHome", ["esphome:esphome"]),
    "zigbee2mqtt": ("Zigbee2MQTT", ["koenkk:zigbee2mqtt", "zigbee2mqtt:zigbee2mqtt"]),
    "mariadb": ("MariaDB", ["mariadb:mariadb", "mariadb:server", "mariadb:mariadb server"]),
    "adguard home": ("AdGuard Home", ["adguard:adguard home", "adguardteam:adguardhome"]),
    "nginx": ("nginx", PACKAGES["nginx"][1]),
    "samba": ("Samba", PACKAGES["samba"][1]),
    "grafana": ("Grafana", ["grafana:grafana", "grafana labs:grafana"]),
    "influxdb": ("InfluxDB", ["influxdata:influxdb"]),
    "frigate": ("Frigate", ["blakeblackshear:frigate", "frigate:frigate"]),
    "music assistant": ("Music Assistant", ["music assistant:music assistant"]),
    "matter server": ("Matter Server", ["home assistant:python matter server"]),
    "plex media server": ("Plex Media Server", ["plex:media server", "plex:plex media server"]),
    "jellyfin": ("Jellyfin", ["jellyfin:jellyfin"]),
    "vaultwarden": ("Vaultwarden", ["dani garcia:vaultwarden", "vaultwarden:vaultwarden"]),
    "portainer": ("Portainer", ["portainer:portainer"]),
}


# nmap -sV product names (lowercase) -> (display name, aliases). Prefix match is allowed,
# so "apache httpd" also covers "Apache httpd 2.4" style strings.
NMAP: dict[str, tuple[str, list[str]]] = {
    "openssh": PACKAGES["openssh"],
    "dropbear sshd": PACKAGES["dropbear"],
    "apache httpd": PACKAGES["apache2"],
    "nginx": PACKAGES["nginx"],
    "lighttpd": PACKAGES["lighttpd"],
    "dnsmasq": PACKAGES["dnsmasq"],
    "isc bind": PACKAGES["bind9"],
    "unbound": PACKAGES["unbound"],
    "samba smbd": PACKAGES["samba"],
    "exim smtpd": PACKAGES["exim4"],
    "postfix smtpd": PACKAGES["postfix"],
    "squid http proxy": PACKAGES["squid"],
    "haproxy http proxy": PACKAGES["haproxy"],
    "openvpn": PACKAGES["openvpn"],
    "mosquitto": PACKAGES["mosquitto"],
    "cups": PACKAGES["cups"],
    "microsoft iis httpd": ("Microsoft IIS", ["microsoft:internet information services", "microsoft:iis"]),
    "apache tomcat": ("Apache Tomcat", ["apache software foundation:apache tomcat", "apache:tomcat"]),
    "jetty": ("Jetty", ["eclipse:jetty", "eclipse foundation:eclipse jetty"]),
    "mysql": ("MySQL", ["oracle:mysql", "oracle:mysql server", "mysql:mysql"]),
    "mariadb": APPS["mariadb"],
    "postgresql db": ("PostgreSQL", ["postgresql:postgresql", "postgresql global development group:postgresql"]),
    "redis key-value store": ("Redis", ["redis:redis", "redis labs:redis"]),
    "mongodb": ("MongoDB", ["mongodb:mongodb", "mongodb:mongodb server"]),
    "elasticsearch rest api": ("Elasticsearch", ["elastic:elasticsearch"]),
    "proftpd": ("ProFTPD", ["proftpd:proftpd", "proftpd project:proftpd"]),
    "vsftpd": ("vsftpd", ["beasts:vsftpd", "vsftpd project:vsftpd"]),
    "pure-ftpd": ("Pure-FTPd", ["pureftpd:pure ftpd"]),
    "caddy httpd": ("Caddy", ["caddyserver:caddy"]),
    "openresty web app server": ("OpenResty", ["openresty:openresty"]),
    "miniupnp": ("MiniUPnP", ["miniupnp project:miniupnpd", "miniupnp:miniupnpd"]),
    "vmware esxi": ("VMware ESXi", ["vmware:esxi"]),
}


def pkg_version(v: str) -> str:
    """Upstream part of a distro version: '1:9.6p1-3ubuntu13.5' -> '9.6p1', '3.0.18,1' -> '3.0.18'."""
    v = v.strip()
    v = re.sub(r"^\d+:", "", v)          # Debian epoch
    v = v.split(",")[0]                  # FreeBSD port epoch
    v = re.sub(r"_\d+$", "", v)          # FreeBSD port revision
    v = re.sub(r"-[^-]*$", "", v) if "-" in v else v  # Debian revision
    v = re.sub(r"\+(dfsg|ds|really).*$", "", v)
    return v
