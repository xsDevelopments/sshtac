"""The API key file: ~/.config/sshtac/api_key, next to config.toml.

Kept out of config.toml on purpose, so the config can be shared or committed
without leaking the key. Like ssh with private keys, sshtac refuses a key file
that other users can read.

The file holds just the key (a `ANTHROPIC_API_KEY=` prefix, quotes and
`#` comment lines are tolerated).
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

from sshtac import config


class KeyFileError(Exception):
    pass


def path() -> Path:
    return config.config_path().parent / "api_key"


def read(p: Path | None = None) -> str | None:
    """The key, or None if there is no key file. Raises KeyFileError if the
    file exists but isn't safe to use."""
    p = p or path()
    try:
        st = os.stat(p)
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(st.st_mode):
        raise KeyFileError(f"{p} is not a regular file")
    if st.st_uid != os.getuid():
        raise KeyFileError(f"{p} belongs to another user")
    if st.st_mode & 0o077:
        raise KeyFileError(f"{p} can be read by other users; fix it with: chmod 600 {p}")
    for line in p.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("ANTHROPIC_API_KEY="):
            line = line.split("=", 1)[1]
        return line.strip().strip("'\"") or None
    return None


def write(key: str, p: Path | None = None) -> Path:
    """Write the key with mode 0600, atomically (never briefly readable)."""
    p = p or path()
    p.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = p.with_name(f".api_key.{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        with os.fdopen(fd, "w") as f:
            f.write(key.strip() + "\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, p)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    os.chmod(p, 0o600)
    return p


def remove(p: Path | None = None) -> bool:
    p = p or path()
    try:
        p.unlink()
        return True
    except FileNotFoundError:
        return False
