"""Private runtime directory for sockets and temp files.

$XDG_RUNTIME_DIR/tac/ when available, else /tmp/tac-$UID/, with one
subdirectory per tac tmux server (`tmux -L <name>`): session names are only
unique within a server, so two servers can both have a `tac-local`.

Each directory must be a real directory (not a symlink), owned by us, mode
0700 — anything else in a shared /tmp could be an attacker's, so we refuse
rather than fix it up.
"""

from __future__ import annotations

import os
import re
import stat
from pathlib import Path

_SESSION_RE = re.compile(r"[A-Za-z0-9_-]{1,64}")


class RuntimeDirError(Exception):
    pass


def base_dir() -> Path:
    xdg = os.environ.get("XDG_RUNTIME_DIR")
    if xdg and os.path.isdir(xdg):
        return Path(xdg) / "tac"
    return Path(f"/tmp/tac-{os.getuid()}")


def _check(path: Path) -> None:
    st = os.lstat(path)
    if not stat.S_ISDIR(st.st_mode):
        raise RuntimeDirError(f"{path} exists and is not a directory (symlink?)")
    if st.st_uid != os.getuid():
        raise RuntimeDirError(f"{path} is owned by uid {st.st_uid}, not us")
    if st.st_mode & 0o077:
        raise RuntimeDirError(f"{path} has mode {oct(st.st_mode & 0o777)}; expected 0700")


def ensure_dir(path: Path | None = None) -> Path:
    path = path or base_dir()
    try:
        os.mkdir(path, 0o700)
    except FileExistsError:
        pass
    _check(path)
    return path


def check_session_name(name: str) -> str:
    if not _SESSION_RE.fullmatch(name):
        raise ValueError(f"bad session name {name!r}")
    return name


def server_dir(tmux_socket: str, base: Path | None = None) -> Path:
    """Create (if needed) and return the private dir for one tmux server."""
    root = ensure_dir(base or base_dir())
    return ensure_dir(root / check_session_name(tmux_socket))


def socket_path(tmux_socket: str, session: str, base: Path | None = None) -> Path:
    return server_dir(tmux_socket, base) / f"{check_session_name(session)}.sock"
