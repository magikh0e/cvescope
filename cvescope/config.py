"""Config loading. One TOML file; everything has a default except the inventory."""

from __future__ import annotations

import os
import sys
import tomllib
from pathlib import Path

DEFAULTS = {
    "data_dir": "",
    "tiers": {
        # EPSS percentile (0-1) that lifts a match from "info" to "watch"
        "epss_watch_pct": 0.90,
        # alert when a matched CVE's EPSS percentile rises this much between updates
        "epss_jump": 0.25,
    },
    "sources": {
        "cvelist": True,
        "kev": True,
        "epss": True,
        "metasploit": True,
        "nuclei": True,
        "exploitdb": True,
        "github_poc": True,
        "local_archive": [],
        "distro": True,
        "distro_releases": [],
    },
    "notify": {
        "min_tier": "act",
        "keyword_matches": False,
        "ntfy": [],
        "homeassistant": [],
        "webhook": [],
    },
    # stale_after_hours: warn on the page when the last full sync is older than this
    "serve": {"host": "127.0.0.1", "port": 8096, "stale_after_hours": 12},
    "nvd": {"enabled": False, "max_per_run": 40},
    "inventory": [],
}


def user_config_dir() -> Path:
    if sys.platform == "win32":
        return Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming")) / "cvescope"
    return Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "cvescope"


def user_data_dir() -> Path:
    if sys.platform == "win32":
        return Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local")) / "cvescope"
    return Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share")) / "cvescope"


def find_config(explicit: str | None) -> Path | None:
    if explicit:
        return Path(explicit).expanduser()
    env = os.environ.get("CVESCOPE_CONFIG")
    if env:
        return Path(env).expanduser()
    for p in (Path.cwd() / "cvescope.toml", user_config_dir() / "config.toml"):
        if p.exists():
            return p
    return None


def _merge(base: dict, over: dict) -> dict:
    out = dict(base)
    for k, v in over.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge(out[k], v)
        else:
            out[k] = v
    return out


def expand(path: str) -> Path:
    return Path(os.path.expandvars(os.path.expanduser(path)))


class Config(dict):
    path: Path | None = None

    @property
    def data_dir(self) -> Path:
        d = self.get("data_dir") or ""
        p = expand(d) if d else user_data_dir()
        p.mkdir(parents=True, exist_ok=True)
        return p

    @property
    def db_path(self) -> Path:
        return self.data_dir / "cvescope.db"

    @property
    def cache_dir(self) -> Path:
        p = self.data_dir / "cache"
        p.mkdir(parents=True, exist_ok=True)
        return p


def load(explicit: str | None = None) -> Config:
    path = find_config(explicit)
    raw: dict = {}
    if path is not None:
        if not path.exists():
            raise SystemExit(f"config not found: {path}")
        with open(path, "rb") as f:
            raw = tomllib.load(f)
    cfg = Config(_merge(DEFAULTS, raw))
    cfg.path = path
    return cfg
