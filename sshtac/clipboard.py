"""Getting text onto your computer's clipboard.

Two routes, used together:
- a local clipboard tool (xclip, xsel, wl-copy, pbcopy). Works in any terminal,
  including VTE ones (xfce4-terminal, GNOME Terminal, sshTIK) that ignore
  OSC 52, as long as sshtac runs on the machine whose clipboard you want.
- OSC 52, which tmux sends to the terminal for its own copies. Works over SSH,
  but only in terminals that support it.

tmux runs the tool for mouse and copy-mode copies (its copy-command option);
the core runs the same command for the copy keys.
"""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import sys
from typing import Mapping

TIMEOUT = 5


def detect(env: Mapping[str, str] | None = None) -> str | None:
    """A shell command that reads stdin into the clipboard, or None."""
    env = os.environ if env is None else env
    path = env.get("PATH")
    if sys.platform == "darwin" and shutil.which("pbcopy", path=path):
        return "pbcopy"
    if env.get("WAYLAND_DISPLAY") and shutil.which("wl-copy", path=path):
        return f"WAYLAND_DISPLAY={shlex.quote(env['WAYLAND_DISPLAY'])} wl-copy"
    if env.get("DISPLAY"):
        # Pin DISPLAY: tmux runs this with the server's environment, which may
        # come from an older start.
        display = f"DISPLAY={shlex.quote(env['DISPLAY'])}"
        if shutil.which("xclip", path=path):
            return f"{display} xclip -selection clipboard -in"
        if shutil.which("xsel", path=path):
            return f"{display} xsel --clipboard --input"
    return None


def command(setting: str, env: Mapping[str, str] | None = None) -> str | None:
    """The copy command for the [tmux] clipboard setting."""
    if setting == "auto":
        return detect(env)
    if setting in ("osc52", "off"):
        return None
    return setting  # your own command, e.g. "xclip -selection primary"


def tmux_command(cmd: str) -> str:
    # xclip and wl-copy stay in the background holding the selection; with
    # their output detached, tmux doesn't wait for them. Grouped, so a command
    # with its own redirection (`cat > file`) keeps it.
    return f"{{ {cmd}\n}} >/dev/null 2>&1"


def copy(cmd: str, text: str) -> None:
    """Run the copy command with `text` on stdin. Raises OSError or
    subprocess.SubprocessError on failure."""
    subprocess.run(
        ["/bin/sh", "-c", cmd],
        input=text.encode("utf-8"),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=TIMEOUT,
        check=True,
    )
