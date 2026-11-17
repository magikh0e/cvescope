"""Feed registry. Each source is a function (con, cfg) -> one-line summary."""

from __future__ import annotations

import time
import traceback

from .. import db
from . import cvelist, distro, epss, exploits, kev

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
}


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
