"""One sync at a time.

`cvescope sync` holds an exclusive OS lock on <data_dir>/sync.lock while it runs, whoever
started it: cron, Task Scheduler, a terminal or the page. The OS drops the lock when the
process exits, however it exits, so a sync that crashed or was killed never leaves it stuck.

The file itself holds the holder's start time for the page to show. On Windows the lock sits
on one byte far past the end of the file (locking past EOF is allowed there), because
Windows locks are mandatory and a lock on byte 0 would stop anyone reading that start time.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

NAME = "sync.lock"
_WIN_BYTE = 1 << 30   # Windows: the locked byte, well past anything the file will hold


def _lock(f) -> bool:
    try:
        if sys.platform == "win32":
            import msvcrt
            f.seek(_WIN_BYTE)
            msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        return True
    except OSError:
        return False


def _unlock(f) -> None:
    try:
        if sys.platform == "win32":
            import msvcrt
            f.seek(_WIN_BYTE)
            msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)
    except OSError:
        pass


class SyncLock:
    """with SyncLock(data_dir) as got: ... (got is False when another sync holds it)."""

    WAIT = 3.0   # seconds to keep trying: covers a status probe holding it for a moment (held())

    def __init__(self, data_dir: Path, wait: float | None = None):
        self.path = Path(data_dir) / NAME
        self.wait = self.WAIT if wait is None else wait
        self.f = None

    def acquire(self, started: str | None = None) -> bool:
        f = open(self.path, "a+b")
        deadline = time.monotonic() + self.wait
        while not _lock(f):
            if time.monotonic() >= deadline:
                f.close()
                return False
            time.sleep(0.2)
        self.f = f
        f.seek(0)
        f.truncate()
        f.write(json.dumps({"started": started}).encode())
        f.flush()
        return True

    def release(self) -> None:
        if self.f is None:
            return
        try:
            self.f.seek(0)
            self.f.truncate()
        except OSError:
            pass
        _unlock(self.f)
        self.f.close()
        self.f = None

    def __enter__(self) -> bool:
        return self.acquire()

    def __exit__(self, *exc) -> None:
        self.release()


def held(data_dir: Path) -> dict | None:
    """None when no sync is running, else {"started": <when, if the holder wrote it>}.

    Checking means taking the lock for an instant and letting go. A sync that starts in that
    instant waits for it (SyncLock.wait) instead of giving up.
    """
    p = Path(data_dir) / NAME
    if not p.exists():
        return None
    with open(p, "a+b") as f:
        if _lock(f):
            _unlock(f)
            return None
        f.seek(0)
        try:
            info = json.loads(f.read(4096) or b"{}")
        except ValueError:   # caught mid-write
            info = {}
    return {"started": info.get("started") if isinstance(info, dict) else None}
