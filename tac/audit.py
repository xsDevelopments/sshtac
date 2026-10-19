"""Append-only JSONL audit log, readable as an incident timeline.

~/.local/state/tac/audit-<session>-<UTC timestamp>.jsonl (respects
XDG_STATE_HOME), directory 0700, file 0600, created exclusively and never
followed through a symlink.

Never log secret values: callers pass redacted text only, and placeholder
*names* but not their values.
"""

from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def state_dir() -> Path:
    base = os.environ.get("XDG_STATE_HOME") or str(Path.home() / ".local" / "state")
    return Path(base) / "tac"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


class AuditLog:
    def __init__(self, session: str, directory: Path | None = None):
        d = directory or state_dir()
        d.mkdir(parents=True, mode=0o700, exist_ok=True)
        os.chmod(d, 0o700)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        self.path = d / f"audit-{session}-{stamp}.jsonl"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(self.path, flags, 0o600)
        self._f = os.fdopen(fd, "a", encoding="utf-8")
        self._lock = threading.Lock()
        self._seq = 0
        self.session = session

    def event(self, kind: str, **fields: Any) -> None:
        with self._lock:
            if self._f.closed:
                return
            self._seq += 1
            rec = {"ts": _now(), "seq": self._seq, "session": self.session, "event": kind, **fields}
            self._f.write(json.dumps(rec, ensure_ascii=False, default=str) + "\n")
            self._f.flush()

    def close(self) -> None:
        with self._lock:
            if not self._f.closed:
                self._f.close()
